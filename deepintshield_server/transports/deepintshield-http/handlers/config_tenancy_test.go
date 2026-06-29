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

type mockTenantConfigStore struct {
	configstore.ConfigStore
	clientConfig        *configstore.ClientConfig
	updatedClientConfig *configstore.ClientConfig
	frameworkConfig     *configstoreTables.TableFrameworkConfig
	authConfig          *configstore.AuthConfig
	proxyConfig         *configstoreTables.GlobalProxyConfig
	restartRequired     *configstoreTables.RestartRequiredConfig
}

func (m *mockTenantConfigStore) GetClientConfig(context.Context) (*configstore.ClientConfig, error) {
	if m == nil || m.clientConfig == nil {
		return nil, nil
	}
	cfg := *m.clientConfig
	return &cfg, nil
}

func (m *mockTenantConfigStore) UpdateClientConfig(_ context.Context, cfg *configstore.ClientConfig) error {
	if m == nil || cfg == nil {
		return nil
	}
	copyCfg := *cfg
	m.updatedClientConfig = &copyCfg
	return nil
}

func (m *mockTenantConfigStore) GetFrameworkConfig(context.Context) (*configstoreTables.TableFrameworkConfig, error) {
	if m == nil || m.frameworkConfig == nil {
		return nil, nil
	}
	cfg := *m.frameworkConfig
	return &cfg, nil
}

func (m *mockTenantConfigStore) GetAuthConfig(context.Context) (*configstore.AuthConfig, error) {
	if m == nil || m.authConfig == nil {
		return nil, nil
	}
	cfg := *m.authConfig
	return &cfg, nil
}

func (m *mockTenantConfigStore) GetProxyConfig(context.Context) (*configstoreTables.GlobalProxyConfig, error) {
	if m == nil || m.proxyConfig == nil {
		return nil, nil
	}
	cfg := *m.proxyConfig
	return &cfg, nil
}

func (m *mockTenantConfigStore) GetRestartRequiredConfig(context.Context) (*configstoreTables.RestartRequiredConfig, error) {
	if m == nil || m.restartRequired == nil {
		return nil, nil
	}
	cfg := *m.restartRequired
	return &cfg, nil
}

type mockTenantConfigManager struct {
	updateAuthConfigCalls     int
	reloadClientConfigCalls   int
	reloadPricingManagerCalls int
	forceReloadPricingCalls   int
	updateDropExcessCalls     int
	updateMCPConfigCalls      int
	reloadPluginCalls         int
	removePluginCalls         int
	reloadProxyConfigCalls    int
	reloadHeaderFilterCalls   int
}

func (m *mockTenantConfigManager) UpdateAuthConfig(context.Context, *configstore.AuthConfig) error {
	m.updateAuthConfigCalls++
	return nil
}

func (m *mockTenantConfigManager) ReloadClientConfigFromConfigStore(context.Context) error {
	m.reloadClientConfigCalls++
	return nil
}

func (m *mockTenantConfigManager) ReloadPricingManager(context.Context) error {
	m.reloadPricingManagerCalls++
	return nil
}

func (m *mockTenantConfigManager) ForceReloadPricing(context.Context) error {
	m.forceReloadPricingCalls++
	return nil
}

func (m *mockTenantConfigManager) UpdateDropExcessRequests(context.Context, bool) {
	m.updateDropExcessCalls++
}

func (m *mockTenantConfigManager) UpdateMCPToolManagerConfig(context.Context, int, int, string, *bool, int) error {
	m.updateMCPConfigCalls++
	return nil
}

func (m *mockTenantConfigManager) ReloadPlugin(context.Context, string, *string, any, *schemas.PluginPlacement, *int) error {
	m.reloadPluginCalls++
	return nil
}

func (m *mockTenantConfigManager) RemovePlugin(context.Context, string) error {
	m.removePluginCalls++
	return nil
}

func (m *mockTenantConfigManager) ReloadProxyConfig(context.Context, *configstoreTables.GlobalProxyConfig) error {
	m.reloadProxyConfigCalls++
	return nil
}

func (m *mockTenantConfigManager) ReloadHeaderFilterConfig(context.Context, *configstoreTables.GlobalHeaderFilterConfig) error {
	m.reloadHeaderFilterCalls++
	return nil
}

func TestConfigHandler_UpdateConfig_TenantScopedDoesNotMutateSharedRuntime(t *testing.T) {
	SetLogger(&mockLogger{})

	globalConfig := lib.DefaultClientConfig
	globalConfig.InitialPoolSize = 100
	globalConfig.DropExcessRequests = false
	globalConfig.LogRetentionDays = 7

	tenantConfig := globalConfig
	tenantConfig.InitialPoolSize = 200

	store := &mockTenantConfigStore{
		clientConfig: &tenantConfig,
	}
	manager := &mockTenantConfigManager{}
	handler := NewConfigHandler(manager, &lib.Config{
		ConfigStore:  store,
		ClientConfig: globalConfig,
	})

	payloadConfig := tenantConfig
	payloadConfig.DropExcessRequests = true

	body, err := json.Marshal(map[string]any{
		"client_config":    payloadConfig,
		"framework_config": map[string]any{},
	})
	require.NoError(t, err)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/config")
	ctx.Request.SetBody(body)
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.updateConfig(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	require.NotNil(t, store.updatedClientConfig)

	assert.True(t, store.updatedClientConfig.DropExcessRequests)
	assert.Equal(t, 200, store.updatedClientConfig.InitialPoolSize)

	assert.False(t, handler.store.ClientConfig.DropExcessRequests)
	assert.Equal(t, 100, handler.store.ClientConfig.InitialPoolSize)

	assert.Zero(t, manager.updateDropExcessCalls)
	assert.Zero(t, manager.reloadClientConfigCalls)
	assert.Zero(t, manager.reloadPricingManagerCalls)
	assert.Zero(t, manager.updateMCPConfigCalls)
	assert.Zero(t, manager.reloadPluginCalls)
	assert.Zero(t, manager.removePluginCalls)
	assert.Zero(t, manager.reloadHeaderFilterCalls)
	assert.Zero(t, manager.updateAuthConfigCalls)
}

func TestConfigHandler_GetConfig_TenantScopedFallsBackToSharedClientConfig(t *testing.T) {
	SetLogger(&mockLogger{})

	globalConfig := lib.DefaultClientConfig
	globalConfig.InitialPoolSize = 123
	globalConfig.LogRetentionDays = 7

	handler := NewConfigHandler(&mockTenantConfigManager{}, &lib.Config{
		ConfigStore:  &mockTenantConfigStore{},
		ClientConfig: globalConfig,
	})

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/config")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	handler.getConfig(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	var resp map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))

	var clientConfig configstore.ClientConfig
	require.NoError(t, json.Unmarshal(resp["client_config"], &clientConfig))
	assert.Equal(t, 123, clientConfig.InitialPoolSize)
	assert.Equal(t, 7, clientConfig.LogRetentionDays)
}
