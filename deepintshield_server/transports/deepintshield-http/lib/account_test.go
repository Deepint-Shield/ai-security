package lib

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tenantAwareMockConfigStore struct {
	*MockConfigStore
	tenantProviders map[string]map[schemas.ModelProvider]configstore.ProviderConfig
}

func (m *tenantAwareMockConfigStore) GetProviderConfig(ctx context.Context, provider schemas.ModelProvider) (*configstore.ProviderConfig, error) {
	if tenantID, ok := ctx.Value(schemas.DeepIntShieldContextKeyTenantID).(string); ok {
		if providers, ok := m.tenantProviders[tenantID]; ok {
			if config, ok := providers[provider]; ok {
				cloned := config
				return &cloned, nil
			}
		}
	}

	return nil, configstore.ErrNotFound
}

func TestBaseAccountGetKeysForProviderPrefersTenantScopedConfig(t *testing.T) {
	mockStore := &tenantAwareMockConfigStore{
		MockConfigStore: NewMockConfigStore(),
		tenantProviders: map[string]map[schemas.ModelProvider]configstore.ProviderConfig{
			"alice@example.com": {
				schemas.Anthropic: {
					Keys: []schemas.Key{
						{
							ID:    "tenant-anthropic-key",
							Name:  "Tenant Anthropic Key",
							Value: *schemas.NewEnvVar("sk-ant-tenant"),
						},
					},
				},
			},
		},
	}

	account := NewBaseAccount(&Config{
		ConfigStore: mockStore,
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.Anthropic: {
				Keys: []schemas.Key{
					{
						ID:    "global-anthropic-key",
						Name:  "Global Anthropic Key",
						Value: *schemas.NewEnvVar("sk-ant-global"),
					},
				},
			},
		},
	})

	ctx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	keys, err := account.GetKeysForProvider(ctx, schemas.Anthropic)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "tenant-anthropic-key", keys[0].ID)
	assert.Equal(t, "sk-ant-tenant", keys[0].Value.GetValue())
}

func TestBaseAccountGetConfigForProviderAllowsMissingStandardProvider(t *testing.T) {
	account := NewBaseAccount(&Config{
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{},
	})

	config, err := account.GetConfigForProvider(schemas.Anthropic)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, schemas.DefaultNetworkConfig, config.NetworkConfig)
	assert.Equal(t, schemas.DefaultConcurrencyAndBufferSize, config.ConcurrencyAndBufferSize)
}

func TestBaseAccountGetConfigForProviderRejectsMissingCustomProvider(t *testing.T) {
	account := NewBaseAccount(&Config{
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{},
	})

	_, err := account.GetConfigForProvider(schemas.ModelProvider("custom-anthropic"))
	require.ErrorIs(t, err, ErrNotFound)
}
