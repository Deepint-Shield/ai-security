package handlers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

type mockMCPRuntimeClient struct {
	clients []schemas.MCPClient
}

func (m *mockMCPRuntimeClient) GetMCPClients() ([]schemas.MCPClient, error) {
	return append([]schemas.MCPClient(nil), m.clients...), nil
}

type mockTenantMCPStore struct {
	configstore.ConfigStore
	mcpConfig            *schemas.MCPConfig
	mcpClientByID        *configstoreTables.TableMCPClient
	getMCPConfigCalled   bool
	getMCPClientByIDCall int
	updateCalls          []configstoreTables.TableMCPClient
}

func (m *mockTenantMCPStore) GetMCPConfig(context.Context) (*schemas.MCPConfig, error) {
	m.getMCPConfigCalled = true
	return m.mcpConfig, nil
}

func (m *mockTenantMCPStore) GetMCPClientByID(context.Context, string) (*configstoreTables.TableMCPClient, error) {
	m.getMCPClientByIDCall++
	if m.mcpClientByID == nil {
		return nil, configstore.ErrNotFound
	}
	copyClient := *m.mcpClientByID
	return &copyClient, nil
}

func (m *mockTenantMCPStore) UpdateMCPClientConfig(_ context.Context, _ string, clientConfig *configstoreTables.TableMCPClient) error {
	m.updateCalls = append(m.updateCalls, *clientConfig)
	return nil
}

func (m *mockTenantMCPStore) GetClientConfig(context.Context) (*configstore.ClientConfig, error) {
	return &configstore.ClientConfig{}, nil
}

type mockMCPManager struct {
	updated []*schemas.MCPClientConfig
}

func (m *mockMCPManager) AddMCPClient(context.Context, *schemas.MCPClientConfig) error { return nil }

func (m *mockMCPManager) RemoveMCPClient(context.Context, string) error { return nil }

func (m *mockMCPManager) ReconnectMCPClient(context.Context, string) error { return nil }

func (m *mockMCPManager) UpdateMCPClient(_ context.Context, _ string, updatedConfig *schemas.MCPClientConfig) error {
	m.updated = append(m.updated, updatedConfig)
	return nil
}

func TestGetMCPClients_TenantScopedRequestUsesDatabaseConfig(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantMCPStore{
		mcpConfig: &schemas.MCPConfig{
			ClientConfigs: []*schemas.MCPClientConfig{
				{
					ID:               "tenant-client",
					Name:             "Tenant Client",
					ConnectionType:   schemas.MCPConnectionTypeSSE,
					ConnectionString: schemas.NewEnvVar("https://tenant.example.com"),
				},
			},
		},
	}

	handler := &MCPHandler{
		client: &mockMCPRuntimeClient{},
		store: &lib.Config{
			ConfigStore: store,
			MCPConfig: &schemas.MCPConfig{
				ClientConfigs: []*schemas.MCPClientConfig{
					{
						ID:               "shared-client",
						Name:             "Shared Client",
						ConnectionType:   schemas.MCPConnectionTypeSTDIO,
						ConnectionString: schemas.NewEnvVar("shared-secret"),
					},
				},
			},
		},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/mcp/clients")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.getMCPClients(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	require.True(t, store.getMCPConfigCalled)

	var resp struct {
		Clients []MCPClientResponse `json:"clients"`
		Count   int                 `json:"count"`
	}
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	require.Len(t, resp.Clients, 1)
	assert.Equal(t, 1, resp.Count)
	assert.Equal(t, "Tenant Client", resp.Clients[0].Config.Name)
	assert.NotEqual(t, "Shared Client", resp.Clients[0].Config.Name)
}

func TestUpdateMCPClient_TenantScopedRequestUsesDatabaseConfig(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockTenantMCPStore{
		mcpClientByID: &configstoreTables.TableMCPClient{
			ClientID:         "tenant-client",
			Name:             "Tenant Client",
			ConnectionType:   string(schemas.MCPConnectionTypeSSE),
			ConnectionString: schemas.NewEnvVar("https://tenant.example.com"),
			AuthType:         string(schemas.MCPAuthTypeHeaders),
			Headers: map[string]schemas.EnvVar{
				"Authorization": *schemas.NewEnvVar("tenant-secret"),
			},
			ToolsToExecute: []string{"lookup"},
		},
	}
	manager := &mockMCPManager{}

	handler := &MCPHandler{
		store: &lib.Config{
			ConfigStore: store,
			MCPConfig: &schemas.MCPConfig{
				ClientConfigs: []*schemas.MCPClientConfig{
					{
						ID:               "tenant-client",
						Name:             "Shared Client",
						ConnectionType:   schemas.MCPConnectionTypeSTDIO,
						ConnectionString: schemas.NewEnvVar("shared-secret"),
						Headers: map[string]schemas.EnvVar{
							"Authorization": *schemas.NewEnvVar("shared-secret"),
						},
					},
				},
			},
		},
		mcpManager: manager,
	}

	body, err := json.Marshal(&configstoreTables.TableMCPClient{
		Name:               "tenantclientupdated",
		ToolsToExecute:     []string{"lookup"},
		ToolsToAutoExecute: []string{},
	})
	require.NoError(t, err)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/mcp/client/tenant-client")
	ctx.Request.SetBody(body)
	ctx.SetUserValue("id", "tenant-client")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	// requireMCPClientWriteAccess (added after this test was written)
	// now consults the cached auth user. Without these two keys
	// cachedAuthUserFromCtx returns nil and the handler short-circuits
	// with 401. System-admin role takes the fast path through the gate.
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserID, "alice-user-id")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserRole, configstoreTables.UserRoleAdmin)

	handler.updateMCPClient(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	require.Len(t, manager.updated, 1)
	require.GreaterOrEqual(t, store.getMCPClientByIDCall, 2)

	authHeader := manager.updated[0].Headers["Authorization"]
	assert.Equal(t, schemas.MCPConnectionTypeSSE, manager.updated[0].ConnectionType)
	assert.Equal(t, "tenant-secret", authHeader.GetValue())
	assert.Equal(t, "tenantclientupdated", manager.updated[0].Name)
}
