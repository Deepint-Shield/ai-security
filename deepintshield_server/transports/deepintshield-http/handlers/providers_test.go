package handlers

import (
	"context"
	"encoding/json"
	"testing"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

func TestResolveProviderKeyChanges_MatchesExistingKeyByName(t *testing.T) {
	oldKeys := []schemas.Key{
		{
			ID:      "stored-key-id",
			Name:    "openai-primary",
			Value:   *schemas.NewEnvVar("sk-old"),
			Enabled: deepintshield.Ptr(true),
		},
	}
	payloadKeys := []schemas.Key{
		{
			ID:    "",
			Name:  "openai-primary",
			Value: *schemas.NewEnvVar("sk-new"),
		},
	}

	keysToAdd, keysToDelete, keysToUpdate := resolveProviderKeyChanges(oldKeys, payloadKeys)

	require.Empty(t, keysToAdd)
	require.Empty(t, keysToDelete)
	require.Len(t, keysToUpdate, 1)
	assert.Equal(t, "stored-key-id", keysToUpdate[0].ID)
	assert.Equal(t, "openai-primary", keysToUpdate[0].Name)
}

func TestResolveProviderKeyChanges_GeneratesIDForNewKey(t *testing.T) {
	payloadKeys := []schemas.Key{
		{
			Name:  "new-key",
			Value: *schemas.NewEnvVar("sk-new"),
		},
	}

	keysToAdd, keysToDelete, keysToUpdate := resolveProviderKeyChanges(nil, payloadKeys)

	require.Len(t, keysToAdd, 1)
	require.Empty(t, keysToDelete)
	require.Empty(t, keysToUpdate)
	assert.NotEmpty(t, keysToAdd[0].ID)
	require.NotNil(t, keysToAdd[0].Enabled)
	assert.True(t, *keysToAdd[0].Enabled)
}

type mockTenantModelsManager struct {
	models          []string
	unfilteredModel []string
	reloadCalls     int
}

func (m *mockTenantModelsManager) ReloadProvider(context.Context, schemas.ModelProvider) (*tables.TableProvider, error) {
	m.reloadCalls++
	return nil, nil
}

func (m *mockTenantModelsManager) RemoveProvider(context.Context, schemas.ModelProvider) error {
	return nil
}

func (m *mockTenantModelsManager) GetModelsForProvider(schemas.ModelProvider) []string {
	return append([]string(nil), m.models...)
}

func (m *mockTenantModelsManager) GetUnfilteredModelsForProvider(schemas.ModelProvider) []string {
	return append([]string(nil), m.unfilteredModel...)
}

type mockTenantProviderStore struct {
	configstore.ConfigStore
	providers   map[schemas.ModelProvider]tables.TableProvider
	configs     map[schemas.ModelProvider]configstore.ProviderConfig
	modelPrices []tables.TableModelPricing
}

func (m *mockTenantProviderStore) GetProvider(_ context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error) {
	providerInfo, ok := m.providers[provider]
	if !ok {
		return nil, configstore.ErrNotFound
	}
	copyProvider := providerInfo
	return &copyProvider, nil
}

func (m *mockTenantProviderStore) GetProviders(_ context.Context) ([]tables.TableProvider, error) {
	providers := make([]tables.TableProvider, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, provider)
	}
	return providers, nil
}

func (m *mockTenantProviderStore) GetProviderConfig(_ context.Context, provider schemas.ModelProvider) (*configstore.ProviderConfig, error) {
	config, ok := m.configs[provider]
	if !ok {
		return nil, configstore.ErrNotFound
	}
	copyConfig := config
	return &copyConfig, nil
}

func (m *mockTenantProviderStore) AddProvider(_ context.Context, provider schemas.ModelProvider, config configstore.ProviderConfig, _ ...*gorm.DB) error {
	if m.configs == nil {
		m.configs = map[schemas.ModelProvider]configstore.ProviderConfig{}
	}
	m.configs[provider] = config
	return nil
}

func (m *mockTenantProviderStore) UpdateProvider(_ context.Context, provider schemas.ModelProvider, config configstore.ProviderConfig, _ ...*gorm.DB) error {
	if m.configs == nil {
		m.configs = map[schemas.ModelProvider]configstore.ProviderConfig{}
	}
	m.configs[provider] = config
	return nil
}

func (m *mockTenantProviderStore) GetModelPrices(context.Context) ([]tables.TableModelPricing, error) {
	return append([]tables.TableModelPricing(nil), m.modelPrices...), nil
}

func TestUpdateProvider_PartialSavePreservesExistingKeys(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantProviderStore{
		configs: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {
				Keys: []schemas.Key{
					{
						ID:      "existing-key-id",
						Name:    "openai-primary",
						Value:   *schemas.NewEnvVar("sk-live"),
						Enabled: deepintshield.Ptr(true),
					},
				},
				NetworkConfig:            &schemas.DefaultNetworkConfig,
				ConcurrencyAndBufferSize: &schemas.DefaultConcurrencyAndBufferSize,
			},
		},
	}

	handler := &ProviderHandler{
		dbStore:       store,
		inMemoryStore: &lib.Config{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/providers/openai")
	ctx.Request.SetBodyString(`{"send_back_raw_request":true}`)
	ctx.SetUserValue("provider", "openai")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.updateProvider(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	require.Len(t, store.configs[schemas.OpenAI].Keys, 1)
	assert.Equal(t, "existing-key-id", store.configs[schemas.OpenAI].Keys[0].ID)
	assert.Equal(t, "openai-primary", store.configs[schemas.OpenAI].Keys[0].Name)
	assert.True(t, store.configs[schemas.OpenAI].SendBackRawRequest)

	var resp ProviderResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "existing-key-id", resp.Keys[0].ID)
	assert.True(t, resp.SendBackRawRequest)
}

func TestUpdateProvider_ExplicitEmptyKeysDeletesKeys(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantProviderStore{
		configs: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {
				Keys: []schemas.Key{
					{
						ID:      "existing-key-id",
						Name:    "openai-primary",
						Value:   *schemas.NewEnvVar("sk-live"),
						Enabled: deepintshield.Ptr(true),
					},
				},
				NetworkConfig:            &schemas.DefaultNetworkConfig,
				ConcurrencyAndBufferSize: &schemas.DefaultConcurrencyAndBufferSize,
			},
		},
	}

	handler := &ProviderHandler{
		dbStore:       store,
		inMemoryStore: &lib.Config{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/providers/openai")
	ctx.Request.SetBodyString(`{"keys":[]}`)
	ctx.SetUserValue("provider", "openai")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.updateProvider(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Empty(t, store.configs[schemas.OpenAI].Keys)

	var resp ProviderResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Empty(t, resp.Keys)
}

func TestListModels_TenantScopedRequestUsesDatabaseModels(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantProviderStore{
		providers: map[schemas.ModelProvider]tables.TableProvider{
			schemas.OpenAI: {
				Name: "openai",
				Models: []tables.TableModel{
					{Name: "db-model"},
				},
			},
		},
		configs: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {},
		},
	}

	handler := &ProviderHandler{
		dbStore:       store,
		inMemoryStore: &lib.Config{},
		modelsManager: &mockTenantModelsManager{models: []string{"shared-model"}},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/models?provider=openai")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.listModels(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var resp ListModelsResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	require.Len(t, resp.Models, 1)
	assert.Equal(t, "db-model", resp.Models[0].Name)
	assert.Equal(t, "openai", resp.Models[0].Provider)
	assert.Equal(t, 1, resp.Total)
}

func TestListModels_TenantScopedRequestFallsBackToDiscoveredModels(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantProviderStore{
		providers: map[schemas.ModelProvider]tables.TableProvider{
			schemas.OpenAI: {
				Name: "openai",
			},
		},
		configs: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {},
		},
	}
	modelsManager := &mockTenantModelsManager{models: []string{"gpt-4o-mini"}}

	handler := &ProviderHandler{
		dbStore:       store,
		inMemoryStore: &lib.Config{},
		modelsManager: modelsManager,
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/models?provider=openai")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.listModels(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var resp ListModelsResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	require.Len(t, resp.Models, 1)
	assert.Equal(t, "gpt-4o-mini", resp.Models[0].Name)
	assert.Equal(t, 1, modelsManager.reloadCalls)
}

func TestListModels_TenantScopedRequestUsesUnfilteredCatalogWhenRequested(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantProviderStore{
		providers: map[schemas.ModelProvider]tables.TableProvider{
			schemas.OpenAI: {
				Name: "openai",
				Models: []tables.TableModel{
					{Name: "gpt-4o-mini"},
				},
			},
		},
		configs: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {},
		},
	}
	modelsManager := &mockTenantModelsManager{
		models:          []string{"gpt-4o-mini"},
		unfilteredModel: []string{"gpt-4o", "gpt-4o-mini", "gpt-4.1"},
	}

	handler := &ProviderHandler{
		dbStore:       store,
		inMemoryStore: &lib.Config{},
		modelsManager: modelsManager,
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/models?provider=openai&unfiltered=true&limit=10")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.listModels(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var resp ListModelsResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	require.Len(t, resp.Models, 3)
	assert.Equal(t, []string{"gpt-4.1", "gpt-4o", "gpt-4o-mini"}, []string{
		resp.Models[0].Name,
		resp.Models[1].Name,
		resp.Models[2].Name,
	})
}

func TestListBaseModels_TenantScopedRequestUsesDatabaseModels(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantProviderStore{
		providers: map[schemas.ModelProvider]tables.TableProvider{
			schemas.OpenAI: {
				Name: "openai",
				Models: []tables.TableModel{
					{Name: "gpt-4o-mini"},
				},
			},
		},
		configs: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {},
		},
		modelPrices: []tables.TableModelPricing{
			{
				Model:     "gpt-4o-mini",
				BaseModel: "gpt-4o-mini",
				Provider:  "openai",
				Mode:      "chat",
			},
		},
	}

	handler := &ProviderHandler{
		dbStore:       store,
		inMemoryStore: &lib.Config{},
		modelsManager: &mockTenantModelsManager{models: []string{"shared-model"}},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/models/base")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.listBaseModels(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var resp ListBaseModelsResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, []string{"gpt-4o-mini"}, resp.Models)
	assert.Equal(t, 1, resp.Total)
}
