package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/network"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/encrypt"
	"github.com/deepint-shield/ai-security/framework/modelcatalog"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/plugins/litellmcompat"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

// securityHeaders is the list of headers that cannot be configured in allowlist/denylist
// These headers are always blocked for security reasons regardless of user configuration
var securityHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"host",
	"content-length",
	"connection",
	"transfer-encoding",
	"x-api-key",
	"x-goog-api-key",
	"x-bf-api-key",
	"x-bf-vk",
}

// ConfigManager is the interface for the config manager
type ConfigManager interface {
	UpdateAuthConfig(ctx context.Context, authConfig *configstore.AuthConfig) error
	ReloadClientConfigFromConfigStore(ctx context.Context) error
	ReloadPricingManager(ctx context.Context) error
	ForceReloadPricing(ctx context.Context) error
	UpdateDropExcessRequests(ctx context.Context, value bool)
	UpdateMCPToolManagerConfig(ctx context.Context, maxAgentDepth int, toolExecutionTimeoutInSeconds int, codeModeBindingLevel string, cacheEnabled *bool, cacheTTLSeconds int) error
	ReloadPlugin(ctx context.Context, name string, path *string, pluginConfig any, placement *schemas.PluginPlacement, order *int) error
	RemovePlugin(ctx context.Context, name string) error
	ReloadProxyConfig(ctx context.Context, config *configstoreTables.GlobalProxyConfig) error
	ReloadHeaderFilterConfig(ctx context.Context, config *configstoreTables.GlobalHeaderFilterConfig) error
}

// ConfigHandler manages runtime configuration updates for DeepIntShield.
// It provides endpoints to update and retrieve settings persisted via the ConfigStore backed by sql database.
type ConfigHandler struct {
	store         *lib.Config
	configManager ConfigManager
}

// NewConfigHandler creates a new handler for configuration management.
// It requires the DeepIntShield client, a logger, and the config store.
func NewConfigHandler(configManager ConfigManager, store *lib.Config) *ConfigHandler {
	return &ConfigHandler{
		configManager: configManager,
		store:         store,
	}
}

// RegisterRoutes registers the configuration-related routes.
// It adds the `PUT /api/config` endpoint.
func (h *ConfigHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/config", lib.ChainMiddlewares(h.getConfig, middlewares...))
	r.PUT("/api/config", lib.ChainMiddlewares(h.updateConfig, middlewares...))
	r.GET("/api/version", lib.ChainMiddlewares(h.getVersion, middlewares...))
	r.GET("/api/proxy-config", lib.ChainMiddlewares(h.getProxyConfig, middlewares...))
	r.PUT("/api/proxy-config", lib.ChainMiddlewares(h.updateProxyConfig, middlewares...))
	r.POST("/api/pricing/force-sync", lib.ChainMiddlewares(h.forceSyncPricing, middlewares...))
	// Per-workspace Logs Settings - overrides the tenant-global config.
	// Scoped by X-Active-Workspace-Id; absence → 400 so the UI never
	// silently writes to a NULL workspace.
	r.GET("/api/workspace-logging", lib.ChainMiddlewares(h.getWorkspaceLogging, middlewares...))
	r.PUT("/api/workspace-logging", lib.ChainMiddlewares(h.updateWorkspaceLogging, middlewares...))
	r.DELETE("/api/workspace-logging", lib.ChainMiddlewares(h.deleteWorkspaceLogging, middlewares...))
	// Per-workspace MCP Settings - overrides the tenant-global MCP knobs.
	// Same X-Active-Workspace-Id scoping as logging.
	r.GET("/api/workspace-mcp", lib.ChainMiddlewares(h.getWorkspaceMCP, middlewares...))
	r.PUT("/api/workspace-mcp", lib.ChainMiddlewares(h.updateWorkspaceMCP, middlewares...))
	r.DELETE("/api/workspace-mcp", lib.ChainMiddlewares(h.deleteWorkspaceMCP, middlewares...))
}

// getVersion handles GET /api/version - Get the current version
func (h *ConfigHandler) getVersion(ctx *fasthttp.RequestCtx) {
	SendJSON(ctx, version)
}

// getConfig handles GET /config - Get the current configuration
func (h *ConfigHandler) getConfig(ctx *fasthttp.RequestCtx) {
	var mapConfig = make(map[string]any)
	tenantScoped := h.store.ConfigStore != nil && tenantctx.TenantIDFromContext(ctx) != ""

	useDBConfig := string(ctx.QueryArgs().Peek("from_db")) == "true" ||
		tenantScoped

	if useDBConfig {
		if h.store.ConfigStore == nil {
			SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
			return
		}
		cc, err := h.store.ConfigStore.GetClientConfig(ctx)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError,
				fmt.Sprintf("failed to fetch config from db: %v", err))
			return
		}
		if cc != nil {
			mapConfig["client_config"] = *cc
		} else if tenantScoped {
			mapConfig["client_config"] = h.store.ClientConfig
		}
		// Fetching framework config
		fc, err := h.store.ConfigStore.GetFrameworkConfig(ctx)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to fetch framework config from db: %v", err))
			return
		}
		normalizedFrameworkConfig, _, _ := lib.ResolveFrameworkPricingConfig(fc, nil)
		mapConfig["framework_config"] = *normalizedFrameworkConfig
	} else {
		mapConfig["client_config"] = h.store.ClientConfig
		normalizedFrameworkConfig, _, _ := lib.ResolveFrameworkPricingConfig(nil, h.store.FrameworkConfig)
		mapConfig["framework_config"] = *normalizedFrameworkConfig
	}
	if h.store.ConfigStore != nil {
		// Fetching governance config
		authConfig, err := h.store.ConfigStore.GetAuthConfig(ctx)
		if err != nil {
			logger.Warn("failed to get auth config from store: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get auth config from store: %v", err))
			return
		}
		// Getting username and password from auth config
		// This username password is for the dashboard authentication
		if authConfig != nil {
			// For password, return EnvVar structure with redacted value
			// If from env, preserve env_var reference but clear value
			// If not from env, show <redacted> as the value
			var passwordEnvVar *schemas.EnvVar
			if authConfig.AdminPassword != nil && authConfig.AdminPassword.IsFromEnv() {
				passwordEnvVar = &schemas.EnvVar{
					Val:     "",
					EnvVar:  authConfig.AdminPassword.EnvVar,
					FromEnv: true,
				}
			} else {
				passwordEnvVar = &schemas.EnvVar{
					Val:     "<redacted>",
					EnvVar:  "",
					FromEnv: false,
				}
			}
			mapConfig["auth_config"] = map[string]any{
				"admin_username":            authConfig.AdminUserName,
				"admin_password":            passwordEnvVar,
				"is_enabled":                authConfig.IsEnabled,
				"disable_auth_on_inference": authConfig.DisableAuthOnInference,
			}
		} else {
			// No auth config exists yet, return default empty EnvVar values
			mapConfig["auth_config"] = map[string]any{
				"admin_username":            &schemas.EnvVar{Val: "", EnvVar: "", FromEnv: false},
				"admin_password":            &schemas.EnvVar{Val: "", EnvVar: "", FromEnv: false},
				"is_enabled":                false,
				"disable_auth_on_inference": true,
			}
		}
	} else {
		mapConfig["auth_config"] = map[string]any{
			"admin_username":            &schemas.EnvVar{Val: "", EnvVar: "", FromEnv: false},
			"admin_password":            &schemas.EnvVar{Val: "", EnvVar: "", FromEnv: false},
			"is_enabled":                false,
			"disable_auth_on_inference": true,
		}
	}
	mapConfig["is_db_connected"] = h.store.ConfigStore != nil
	mapConfig["is_cache_connected"] = h.store.VectorStore != nil
	mapConfig["is_logs_connected"] = h.store.LogsStore != nil
	// Fetching proxy config
	if h.store.ConfigStore != nil {
		proxyConfig, err := h.store.ConfigStore.GetProxyConfig(ctx)
		if err != nil {
			logger.Warn("failed to get proxy config from store: %v", err)
		} else if proxyConfig != nil {
			// Redact password if present
			if proxyConfig.Password != "" {
				proxyConfig.Password = "<redacted>"
			}
			mapConfig["proxy_config"] = proxyConfig
		}
		// Fetching restart required config
		restartConfig, err := h.store.ConfigStore.GetRestartRequiredConfig(ctx)
		if err != nil {
			logger.Warn("failed to get restart required config from store: %v", err)
		} else if restartConfig != nil {
			mapConfig["restart_required"] = restartConfig
		}
	}
	SendJSON(ctx, mapConfig)
}

// updateConfig updates the core configuration settings.
// Currently, it supports hot-reloading of the `drop_excess_requests` setting.
// Note that settings like `prometheus_labels` cannot be changed at runtime.
func (h *ConfigHandler) updateConfig(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Config store not initialized")
		return
	}
	tenantScoped := tenantctx.TenantIDFromContext(ctx) != ""
	applyRuntimeChanges := !tenantScoped

	payload := struct {
		ClientConfig    configstore.ClientConfig               `json:"client_config"`
		FrameworkConfig configstoreTables.TableFrameworkConfig `json:"framework_config"`
		AuthConfig      *configstore.AuthConfig                `json:"auth_config"`
	}{}

	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Validating framework config
	if payload.FrameworkConfig.PricingURL != nil && *payload.FrameworkConfig.PricingURL != modelcatalog.DefaultPricingURL {
		// Checking the accessibility of the pricing URL
		resp, err := http.Get(*payload.FrameworkConfig.PricingURL)
		if err != nil {
			logger.Warn("failed to check the accessibility of the pricing URL: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to check the accessibility of the pricing URL: %v", err))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logger.Warn("failed to check the accessibility of the pricing URL: %v", resp.StatusCode)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to check the accessibility of the pricing URL: %v", resp.StatusCode))
			return
		}
	}

	// Checking the pricing sync interval
	if payload.FrameworkConfig.PricingSyncInterval != nil && *payload.FrameworkConfig.PricingSyncInterval <= 0 {
		logger.Warn("pricing sync interval must be greater than 0")
		SendError(ctx, fasthttp.StatusBadRequest, "pricing sync interval must be greater than 0")
		return
	}

	// Get current config with proper locking
	currentConfig := h.store.ClientConfig
	if tenantScoped {
		storedConfig, err := h.store.ConfigStore.GetClientConfig(ctx)
		if err != nil {
			logger.Warn("failed to get tenant-scoped client config from store: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get tenant-scoped client config from store: %v", err))
			return
		}
		if storedConfig != nil {
			currentConfig = *storedConfig
		}
	}
	updatedConfig := currentConfig

	var restartReasons []string

	if payload.ClientConfig.DropExcessRequests != currentConfig.DropExcessRequests {
		if applyRuntimeChanges {
			h.configManager.UpdateDropExcessRequests(ctx, payload.ClientConfig.DropExcessRequests)
		}
		updatedConfig.DropExcessRequests = payload.ClientConfig.DropExcessRequests
	}

	if payload.ClientConfig.MCPCodeModeBindingLevel != "" {
		if payload.ClientConfig.MCPCodeModeBindingLevel != string(schemas.CodeModeBindingLevelServer) && payload.ClientConfig.MCPCodeModeBindingLevel != string(schemas.CodeModeBindingLevelTool) {
			logger.Warn("mcp_code_mode_binding_level must be 'server' or 'tool'")
			SendError(ctx, fasthttp.StatusBadRequest, "mcp_code_mode_binding_level must be 'server' or 'tool'")
			return
		}
	}

	shouldReloadMCPToolManagerConfig := false

	// Only process MCPAgentDepth if explicitly provided (> 0) and different from current
	if payload.ClientConfig.MCPAgentDepth > 0 && payload.ClientConfig.MCPAgentDepth != currentConfig.MCPAgentDepth {
		updatedConfig.MCPAgentDepth = payload.ClientConfig.MCPAgentDepth
		shouldReloadMCPToolManagerConfig = true
	}

	// Only process MCPToolExecutionTimeout if explicitly provided (> 0) and different from current
	if payload.ClientConfig.MCPToolExecutionTimeout > 0 && payload.ClientConfig.MCPToolExecutionTimeout != currentConfig.MCPToolExecutionTimeout {
		updatedConfig.MCPToolExecutionTimeout = payload.ClientConfig.MCPToolExecutionTimeout
		shouldReloadMCPToolManagerConfig = true
	}

	if payload.ClientConfig.MCPCodeModeBindingLevel != "" && payload.ClientConfig.MCPCodeModeBindingLevel != currentConfig.MCPCodeModeBindingLevel {
		updatedConfig.MCPCodeModeBindingLevel = payload.ClientConfig.MCPCodeModeBindingLevel
		shouldReloadMCPToolManagerConfig = true
	}

	// MCPCacheEnabled is a *bool - only reload when it's explicitly set in the
	// payload AND its value actually changes vs. the current config.
	if payload.ClientConfig.MCPCacheEnabled != nil {
		curEnabled := true
		if currentConfig.MCPCacheEnabled != nil {
			curEnabled = *currentConfig.MCPCacheEnabled
		}
		if *payload.ClientConfig.MCPCacheEnabled != curEnabled {
			updatedConfig.MCPCacheEnabled = payload.ClientConfig.MCPCacheEnabled
			shouldReloadMCPToolManagerConfig = true
		}
	}

	if payload.ClientConfig.MCPCacheTTLSeconds > 0 && payload.ClientConfig.MCPCacheTTLSeconds != currentConfig.MCPCacheTTLSeconds {
		updatedConfig.MCPCacheTTLSeconds = payload.ClientConfig.MCPCacheTTLSeconds
		shouldReloadMCPToolManagerConfig = true
	}

	// Only reload MCP tool manager config if MCP is configured
	if shouldReloadMCPToolManagerConfig && h.store.MCPConfig != nil && applyRuntimeChanges {
		if err := h.configManager.UpdateMCPToolManagerConfig(ctx, updatedConfig.MCPAgentDepth, updatedConfig.MCPToolExecutionTimeout, updatedConfig.MCPCodeModeBindingLevel, updatedConfig.MCPCacheEnabled, updatedConfig.MCPCacheTTLSeconds); err != nil {
			logger.Warn(fmt.Sprintf("failed to update mcp tool manager config: %v", err))
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to update mcp tool manager config: %v", err))
			return
		}
		// Mirror the change into the in-memory config block that plugins read
		// via closure (the mcpcache plugin's EnabledFn captures this struct).
		// Without this mutation the toggle would only take effect after a
		// gateway restart.
		if h.store.MCPConfig.ToolManagerConfig != nil {
			h.store.MCPConfig.ToolManagerConfig.CacheEnabled = updatedConfig.MCPCacheEnabled
			if updatedConfig.MCPCacheTTLSeconds > 0 {
				h.store.MCPConfig.ToolManagerConfig.CacheTTLSeconds = updatedConfig.MCPCacheTTLSeconds
			}
		}
	}

	if !slices.Equal(payload.ClientConfig.PrometheusLabels, currentConfig.PrometheusLabels) {
		updatedConfig.PrometheusLabels = payload.ClientConfig.PrometheusLabels
		restartReasons = append(restartReasons, "Prometheus labels")
	}

	if !slices.Equal(payload.ClientConfig.AllowedOrigins, currentConfig.AllowedOrigins) {
		updatedConfig.AllowedOrigins = payload.ClientConfig.AllowedOrigins
		restartReasons = append(restartReasons, "Allowed origins")
	}

	if !slices.Equal(payload.ClientConfig.AllowedHeaders, currentConfig.AllowedHeaders) {
		updatedConfig.AllowedHeaders = payload.ClientConfig.AllowedHeaders
		restartReasons = append(restartReasons, "Allowed headers")
	}

	// Only update InitialPoolSize if explicitly provided (> 0) to avoid clearing stored value
	if payload.ClientConfig.InitialPoolSize > 0 {
		if payload.ClientConfig.InitialPoolSize != currentConfig.InitialPoolSize {
			restartReasons = append(restartReasons, "Initial pool size")
		}
		updatedConfig.InitialPoolSize = payload.ClientConfig.InitialPoolSize
	}

	if payload.ClientConfig.EnableLogging != currentConfig.EnableLogging {
		restartReasons = append(restartReasons, "Logging enabled")
	}
	updatedConfig.EnableLogging = payload.ClientConfig.EnableLogging

	if payload.ClientConfig.DisableContentLogging != currentConfig.DisableContentLogging {
		restartReasons = append(restartReasons, "Content logging")
	}
	updatedConfig.DisableContentLogging = payload.ClientConfig.DisableContentLogging
	updatedConfig.DisableDBPingsInHealth = payload.ClientConfig.DisableDBPingsInHealth
	updatedConfig.AllowDirectKeys = payload.ClientConfig.AllowDirectKeys

	updatedConfig.EnforceAuthOnInference = payload.ClientConfig.EnforceAuthOnInference
	// Sync deprecated columns to match new field so they stay consistent in the DB
	updatedConfig.EnforceGovernanceHeader = payload.ClientConfig.EnforceAuthOnInference
	updatedConfig.EnforceSCIMAuth = payload.ClientConfig.EnforceAuthOnInference

	// Only update MaxRequestBodySizeMB if explicitly provided (> 0) to avoid clearing stored value
	if payload.ClientConfig.MaxRequestBodySizeMB > 0 {
		if payload.ClientConfig.MaxRequestBodySizeMB != currentConfig.MaxRequestBodySizeMB {
			restartReasons = append(restartReasons, "Max request body size")
		}
		updatedConfig.MaxRequestBodySizeMB = payload.ClientConfig.MaxRequestBodySizeMB
	}

	// Handle LiteLLM compat plugin toggle
	if payload.ClientConfig.EnableLiteLLMFallbacks != currentConfig.EnableLiteLLMFallbacks {
		if applyRuntimeChanges && payload.ClientConfig.EnableLiteLLMFallbacks {
			// Load and register the litellmcompat plugin
			if err := h.configManager.ReloadPlugin(ctx, "litellmcompat", nil, &litellmcompat.Config{Enabled: true}, nil, nil); err != nil {
				logger.Warn(fmt.Sprintf("failed to load litellmcompat plugin: %v", err))
			}
		} else if applyRuntimeChanges {
			// Remove the litellmcompat plugin
			disabledCtx := context.WithValue(ctx, PluginDisabledKey, true)
			if err := h.configManager.RemovePlugin(disabledCtx, "litellmcompat"); err != nil {
				logger.Warn("failed to remove litellmcompat plugin: %v", err)
			}
		}
	}
	updatedConfig.EnableLiteLLMFallbacks = payload.ClientConfig.EnableLiteLLMFallbacks
	// Only update MCP fields if explicitly provided (non-zero) to avoid clearing stored values
	if payload.ClientConfig.MCPAgentDepth > 0 {
		updatedConfig.MCPAgentDepth = payload.ClientConfig.MCPAgentDepth
	}
	if payload.ClientConfig.MCPToolExecutionTimeout > 0 {
		updatedConfig.MCPToolExecutionTimeout = payload.ClientConfig.MCPToolExecutionTimeout
	}
	// Only update MCPCodeModeBindingLevel if payload is non-empty to avoid clearing stored value
	if payload.ClientConfig.MCPCodeModeBindingLevel != "" {
		updatedConfig.MCPCodeModeBindingLevel = payload.ClientConfig.MCPCodeModeBindingLevel
	}

	// Only update AsyncJobResultTTL if explicitly provided (> 0) to avoid clearing stored value
	if payload.ClientConfig.AsyncJobResultTTL > 0 {
		updatedConfig.AsyncJobResultTTL = payload.ClientConfig.AsyncJobResultTTL
	}

	// Handle RequiredHeaders changes (no restart needed - governance plugin reads via pointer)
	updatedConfig.RequiredHeaders = payload.ClientConfig.RequiredHeaders

	// Handle LoggingHeaders changes (no restart needed - logging plugin reads via pointer)
	updatedConfig.LoggingHeaders = payload.ClientConfig.LoggingHeaders

	// Toggle whether deleted virtual keys should appear in logs filter data.
	updatedConfig.HideDeletedVirtualKeysInFilters = payload.ClientConfig.HideDeletedVirtualKeysInFilters

	// Handle HeaderFilterConfig changes
	if !headerFilterConfigEqual(payload.ClientConfig.HeaderFilterConfig, currentConfig.HeaderFilterConfig) {
		// Validate that no security headers are in the allowlist or denylist
		if err := validateHeaderFilterConfig(payload.ClientConfig.HeaderFilterConfig); err != nil {
			logger.Warn("invalid header filter config: %v", err)
			SendError(ctx, fasthttp.StatusBadRequest, err.Error())
			return
		}
		updatedConfig.HeaderFilterConfig = payload.ClientConfig.HeaderFilterConfig
		if applyRuntimeChanges {
			if err := h.configManager.ReloadHeaderFilterConfig(ctx, payload.ClientConfig.HeaderFilterConfig); err != nil {
				logger.Warn("failed to reload header filter config: %v", err)
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to reload header filter config: %v", err))
				return
			}
		}
	}

	// Validate LogRetentionDays
	if payload.ClientConfig.LogRetentionDays < 1 {
		logger.Warn("log_retention_days must be at least 1")
		SendError(ctx, fasthttp.StatusBadRequest, "log_retention_days must be at least 1")
		return
	}
	updatedConfig.LogRetentionDays = payload.ClientConfig.LogRetentionDays

	// Update the store with the new config
	if applyRuntimeChanges {
		h.store.ClientConfig = updatedConfig
	}

	if err := h.store.ConfigStore.UpdateClientConfig(ctx, &updatedConfig); err != nil {
		logger.Warn("failed to save configuration: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to save configuration: %v", err))
		return
	}
	// Reloading client config from config store
	if applyRuntimeChanges {
		if err := h.configManager.ReloadClientConfigFromConfigStore(ctx); err != nil {
			logger.Warn("failed to reload client config from config store: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to reload client config from config store: %v", err))
			return
		}
	}
	// Fetching existing framework config
	frameworkConfig, err := h.store.ConfigStore.GetFrameworkConfig(ctx)
	if err != nil {
		logger.Warn("failed to get framework config from store: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get framework config from store: %v", err))
		return
	}
	// if framework config is nil, we will use the default pricing config
	if frameworkConfig == nil {
		frameworkConfig = &configstoreTables.TableFrameworkConfig{
			ID:                  0,
			PricingURL:          deepintshield.Ptr(modelcatalog.DefaultPricingURL),
			PricingSyncInterval: deepintshield.Ptr(int64(modelcatalog.DefaultPricingSyncInterval.Seconds())),
		}
	}
	// Handling individual nil cases
	if frameworkConfig.PricingURL == nil {
		frameworkConfig.PricingURL = deepintshield.Ptr(modelcatalog.DefaultPricingURL)
	}
	if frameworkConfig.PricingSyncInterval == nil {
		frameworkConfig.PricingSyncInterval = deepintshield.Ptr(int64(modelcatalog.DefaultPricingSyncInterval.Seconds()))
	}
	// Updating framework config
	shouldReloadFrameworkConfig := false
	if payload.FrameworkConfig.PricingURL != nil && *payload.FrameworkConfig.PricingURL != *frameworkConfig.PricingURL {
		// Checking the accessibility of the pricing URL
		resp, err := http.Get(*payload.FrameworkConfig.PricingURL)
		if err != nil {
			logger.Warn("failed to check the accessibility of the pricing URL: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to check the accessibility of the pricing URL: %v", err))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			logger.Warn("failed to check the accessibility of the pricing URL: %v", resp.StatusCode)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to check the accessibility of the pricing URL: %v", resp.StatusCode))
			return
		}
		frameworkConfig.PricingURL = payload.FrameworkConfig.PricingURL
		shouldReloadFrameworkConfig = true
	}
	if payload.FrameworkConfig.PricingSyncInterval != nil {
		syncInterval := int64(*payload.FrameworkConfig.PricingSyncInterval)
		if syncInterval != *frameworkConfig.PricingSyncInterval {
			frameworkConfig.PricingSyncInterval = &syncInterval
			shouldReloadFrameworkConfig = true
		}
	}
	// Reload config if required
	if shouldReloadFrameworkConfig {
		// Saving framework config
		if err := h.store.ConfigStore.UpdateFrameworkConfig(ctx, frameworkConfig); err != nil {
			logger.Warn("failed to save framework configuration: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to save framework configuration: %v", err))
			return
		}
		if applyRuntimeChanges {
			var syncDuration time.Duration
			if frameworkConfig.PricingSyncInterval != nil {
				syncDuration = time.Duration(*frameworkConfig.PricingSyncInterval) * time.Second
			} else {
				syncDuration = modelcatalog.DefaultPricingSyncInterval
			}
			h.store.FrameworkConfig = &framework.FrameworkConfig{
				Pricing: &modelcatalog.Config{
					PricingURL:          frameworkConfig.PricingURL,
					PricingSyncInterval: &syncDuration,
				},
			}
			// Reloading pricing manager
			h.configManager.ReloadPricingManager(ctx)
		}
	}
	// Checking auth config and trying to update if required
	if payload.AuthConfig != nil && applyRuntimeChanges {
		// Getting current governance config
		authConfig, err := h.store.ConfigStore.GetAuthConfig(ctx)
		if err != nil {
			if !errors.Is(err, configstore.ErrNotFound) {
				logger.Warn("failed to get auth config from store: %v", err)
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get auth config from store: %v", err))
				return
			}
		}

		// Check if auth config has changed
		authChanged := false
		if authConfig == nil {
			// No existing config, any enabled state is a change
			if payload.AuthConfig.IsEnabled {
				authChanged = true
			}
		} else {
			// Compare with existing config using value comparison (not pointer comparison)
			// Password is considered changed only if it's NOT redacted and has a value
			// (IsRedacted() returns true for <redacted>, asterisk patterns, and env var references)
			passwordChanged := payload.AuthConfig.AdminPassword != nil &&
				!payload.AuthConfig.AdminPassword.IsRedacted() &&
				payload.AuthConfig.AdminPassword.GetValue() != ""
			usernameChanged := payload.AuthConfig.AdminUserName != nil &&
				!payload.AuthConfig.AdminUserName.Equals(authConfig.AdminUserName)
			if payload.AuthConfig.IsEnabled != authConfig.IsEnabled ||
				usernameChanged ||
				passwordChanged {
				authChanged = true
			}
		}

		if payload.AuthConfig.IsEnabled {
			// Initialize nil pointers to empty EnvVar to prevent nil-pointer dereference
			if payload.AuthConfig.AdminUserName == nil {
				payload.AuthConfig.AdminUserName = &schemas.EnvVar{}
			}
			if payload.AuthConfig.AdminPassword == nil {
				payload.AuthConfig.AdminPassword = &schemas.EnvVar{}
			}

			// Validate env variables are set if referenced
			if payload.AuthConfig.AdminUserName.IsFromEnv() && payload.AuthConfig.AdminUserName.GetValue() == "" {
				SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("environment variable %s is not set", payload.AuthConfig.AdminUserName.EnvVar))
				return
			}
			if payload.AuthConfig.AdminPassword.IsFromEnv() && payload.AuthConfig.AdminPassword.GetValue() == "" {
				SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("environment variable %s is not set", payload.AuthConfig.AdminPassword.EnvVar))
				return
			}

			if authConfig == nil && (payload.AuthConfig.AdminUserName.GetValue() == "" || payload.AuthConfig.AdminPassword.GetValue() == "") {
				SendError(ctx, fasthttp.StatusBadRequest, "auth username and password must be provided")
				return
			}
			// Fetching current Auth config
			if payload.AuthConfig.AdminUserName.GetValue() != "" {
				if payload.AuthConfig.AdminPassword.IsRedacted() {
					if authConfig == nil || authConfig.AdminPassword.GetValue() == "" {
						SendError(ctx, fasthttp.StatusBadRequest, "auth password must be provided")
						return
					}
					// Assuming that password hasn't been changed
					payload.AuthConfig.AdminPassword = authConfig.AdminPassword
				} else {
					// Password has been changed
					// We will hash the password
					hashedPassword, err := encrypt.Hash(payload.AuthConfig.AdminPassword.GetValue())
					if err != nil {
						logger.Warn("failed to hash password: %v", err)
						SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to hash password: %v", err))
						return
					}
					// Preserve env-var metadata when storing hashed password
					payload.AuthConfig.AdminPassword = &schemas.EnvVar{
						Val:     hashedPassword,
						FromEnv: payload.AuthConfig.AdminPassword.IsFromEnv(),
						EnvVar:  payload.AuthConfig.AdminPassword.EnvVar,
					}
				}
			}
			// Save auth config - this handles both first-time creation and updates
			err = h.configManager.UpdateAuthConfig(ctx, payload.AuthConfig)
			if err != nil {
				logger.Warn("failed to update auth config: %v", err)
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to update auth config: %v", err))
				return
			}
		} else if authConfig != nil {
			// Auth is being disabled but there's an existing config - preserve credentials and update disabled state
			if payload.AuthConfig.AdminPassword == nil || payload.AuthConfig.AdminPassword.IsRedacted() || payload.AuthConfig.AdminPassword.GetValue() == "" {
				payload.AuthConfig.AdminPassword = authConfig.AdminPassword
			}
			if payload.AuthConfig.AdminUserName == nil || payload.AuthConfig.AdminUserName.GetValue() == "" {
				payload.AuthConfig.AdminUserName = authConfig.AdminUserName
			}
			err = h.configManager.UpdateAuthConfig(ctx, payload.AuthConfig)
			if err != nil {
				logger.Warn("failed to update auth config: %v", err)
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to update auth config: %v", err))
				return
			}
		}

		// Flush all existing sessions if auth details have been changed
		if authChanged {
			if err := h.store.ConfigStore.FlushSessions(ctx); err != nil {
				logger.Warn("updated auth config but failed to flush existing sessions, please restart the server: %v", err)
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("updated auth config but failed to flush existing sessions, please restart the server: %v", err))
				return
			}
		}
		// Note: AuthMiddleware is updated via ServerCallbacks.UpdateAuthConfig (handled by DeepIntShieldHTTPServer)
	}

	// Set restart required flag if any restart-requiring configs changed
	if len(restartReasons) > 0 && applyRuntimeChanges {
		reason := fmt.Sprintf("%s settings have been updated. A restart is required for changes to take full effect.", strings.Join(restartReasons, ", "))
		if err := h.store.ConfigStore.SetRestartRequiredConfig(ctx, &configstoreTables.RestartRequiredConfig{
			Required: true,
			Reason:   reason,
		}); err != nil {
			logger.Warn("failed to set restart required config: %v", err)
		}
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "configuration updated successfully",
	})
}

// forceSyncPricing triggers an immediate pricing sync and resets the pricing sync timer
func (h *ConfigHandler) forceSyncPricing(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}

	if err := h.configManager.ForceReloadPricing(ctx); err != nil {
		logger.Warn("failed to force pricing sync: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to force pricing sync: %v", err))
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "pricing sync triggered",
	})
}

// getProxyConfig handles GET /api/proxy-config - Get the current proxy configuration
func (h *ConfigHandler) getProxyConfig(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	proxyConfig, err := h.store.ConfigStore.GetProxyConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get proxy config: %v", err))
		return
	}
	if proxyConfig == nil {
		// Return default empty config
		SendJSON(ctx, configstoreTables.GlobalProxyConfig{
			Enabled: false,
			Type:    network.GlobalProxyTypeHTTP,
		})
		return
	}
	// Redact password if present
	if proxyConfig.Password != "" {
		proxyConfig.Password = "<redacted>"
	}
	SendJSON(ctx, proxyConfig)
}

// updateProxyConfig handles PUT /api/proxy-config - Update the proxy configuration
func (h *ConfigHandler) updateProxyConfig(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "config store not initialized")
		return
	}

	var payload configstoreTables.GlobalProxyConfig
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid request format: %v", err))
		return
	}

	// Validate proxy config
	if payload.Enabled {
		// Validate proxy type
		switch payload.Type {
		case network.GlobalProxyTypeHTTP:
			// HTTP proxy is supported
			// Make sure the URL is provided
			if payload.URL == "" {
				SendError(ctx, fasthttp.StatusBadRequest, "proxy URL is required when proxy is enabled")
				return
			}
			// Validate timeout if provided
			if payload.Timeout < 0 {
				SendError(ctx, fasthttp.StatusBadRequest, "proxy timeout must be non-negative")
				return
			}
		case network.GlobalProxyTypeSOCKS5, network.GlobalProxyTypeTCP:
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("proxy type %s is not yet supported", payload.Type))
			return
		default:
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid proxy type: %s", payload.Type))
			return
		}

		// Validate URL is provided when enabled
		if payload.URL == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "proxy URL is required when proxy is enabled")
			return
		}

		// Validate timeout if provided
		if payload.Timeout < 0 {
			SendError(ctx, fasthttp.StatusBadRequest, "proxy timeout must be non-negative")
			return
		}
	}

	// Handle password - if it's "<redacted>", keep the existing password
	if payload.Password == "<redacted>" {
		existingConfig, err := h.store.ConfigStore.GetProxyConfig(ctx)
		if err != nil && !errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get existing proxy config: %v", err))
			return
		}
		if existingConfig != nil {
			payload.Password = existingConfig.Password
		} else {
			payload.Password = ""
		}
	}

	// Save proxy config
	if err := h.store.ConfigStore.UpdateProxyConfig(ctx, &payload); err != nil {
		logger.Warn("failed to save proxy configuration: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to save proxy configuration: %v", err))
		return
	}

	// Pulling the proxy config from the config store
	newProxyConfig, err := h.store.ConfigStore.GetProxyConfig(ctx)
	if err != nil {
		logger.Warn("failed to get proxy config from store: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get proxy config from store: %v", err))
		return
	}
	if newProxyConfig == nil {
		newProxyConfig = &configstoreTables.GlobalProxyConfig{
			Enabled:       false,
			Type:          network.GlobalProxyTypeHTTP,
			URL:           "",
			Username:      "",
			Password:      "",
			NoProxy:       "",
			Timeout:       0,
			SkipTLSVerify: false,
		}
	}

	// Reload proxy config in the server
	if err := h.configManager.ReloadProxyConfig(ctx, newProxyConfig); err != nil {
		logger.Warn("failed to reload proxy config: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to reload proxy config: %v", err))
		return
	}

	// Set restart required flag for proxy config changes
	if err := h.store.ConfigStore.SetRestartRequiredConfig(ctx, &configstoreTables.RestartRequiredConfig{
		Required: true,
		Reason:   "Proxy configuration has been updated. A restart is required for all changes to take full effect.",
	}); err != nil {
		logger.Warn("failed to set restart required config: %v", err)
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "proxy configuration updated successfully",
	})
}

// headerFilterConfigEqual compares two GlobalHeaderFilterConfig for equality
func headerFilterConfigEqual(a, b *configstoreTables.GlobalHeaderFilterConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return slices.Equal(a.Allowlist, b.Allowlist) && slices.Equal(a.Denylist, b.Denylist)
}

// validateHeaderFilterConfig validates that no security headers are in the allowlist or denylist
// and that wildcard patterns use valid syntax (only trailing * is supported).
// Returns an error if any security headers are found or patterns are invalid.
func validateHeaderFilterConfig(config *configstoreTables.GlobalHeaderFilterConfig) error {
	if config == nil {
		return nil
	}

	// Validate pattern syntax and normalize entries (trim, lowercase, drop empties)
	filteredAllow := config.Allowlist[:0]
	for _, header := range config.Allowlist {
		h := strings.ToLower(strings.TrimSpace(header))
		if h == "" {
			continue
		}
		if idx := strings.Index(h, "*"); idx != -1 && idx != len(h)-1 {
			return fmt.Errorf("invalid pattern %q: wildcard (*) is only supported at the end of a pattern", h)
		}
		filteredAllow = append(filteredAllow, h)
	}
	config.Allowlist = filteredAllow
	filteredDeny := config.Denylist[:0]
	for _, header := range config.Denylist {
		h := strings.ToLower(strings.TrimSpace(header))
		if h == "" {
			continue
		}
		if idx := strings.Index(h, "*"); idx != -1 && idx != len(h)-1 {
			return fmt.Errorf("invalid pattern %q: wildcard (*) is only supported at the end of a pattern", h)
		}
		filteredDeny = append(filteredDeny, h)
	}
	config.Denylist = filteredDeny

	var foundSecurityHeaders []string

	// Check allowlist for security headers (including wildcard patterns)
	for _, header := range config.Allowlist {
		headerLower := strings.ToLower(strings.TrimSpace(header))
		if strings.Contains(headerLower, "*") {
			for _, secHeader := range securityHeaders {
				if lib.HeaderMatchesPattern(headerLower, secHeader) && !slices.Contains(foundSecurityHeaders, secHeader) {
					foundSecurityHeaders = append(foundSecurityHeaders, secHeader)
				}
			}
			continue
		}
		if slices.Contains(securityHeaders, headerLower) {
			foundSecurityHeaders = append(foundSecurityHeaders, headerLower)
		}
	}

	// Check denylist for security headers (including wildcard patterns)
	for _, header := range config.Denylist {
		headerLower := strings.ToLower(strings.TrimSpace(header))
		if strings.Contains(headerLower, "*") {
			for _, secHeader := range securityHeaders {
				if lib.HeaderMatchesPattern(headerLower, secHeader) && !slices.Contains(foundSecurityHeaders, secHeader) {
					foundSecurityHeaders = append(foundSecurityHeaders, secHeader)
				}
			}
			continue
		}
		if slices.Contains(securityHeaders, headerLower) && !slices.Contains(foundSecurityHeaders, headerLower) {
			foundSecurityHeaders = append(foundSecurityHeaders, headerLower)
		}
	}

	if len(foundSecurityHeaders) > 0 {
		return fmt.Errorf("the following headers are not allowed to be configured: %s. These headers are security headers and are always blocked", strings.Join(foundSecurityHeaders, ", "))
	}

	return nil
}

// workspaceLoggingDTO mirrors the per-workspace Logs Settings shape sent to/
// from the admin UI. Fields are 1:1 with the workspace_logging_settings table
// columns the configstore exposes - we keep the DTO in this package so a
// future store-layer rename can stay opaque to the handler.
type workspaceLoggingDTO struct {
	WorkspaceID                     string   `json:"workspace_id"`
	EnableLogging                   bool     `json:"enable_logging"`
	DisableContentLogging           bool     `json:"disable_content_logging"`
	LogRetentionDays                int      `json:"log_retention_days"`
	HideDeletedVirtualKeysInFilters bool     `json:"hide_deleted_virtual_keys_in_filters"`
	LoggingHeaders                  []string `json:"logging_headers"`
	IsOverride                      bool     `json:"is_override"` // true when a stored override exists, false when defaults
}

// activeWorkspaceID resolves the workspace the UI is currently scoped to.
// The Logs Settings page MUST always operate against a specific workspace
// (the user's selection from the sidebar workspace switcher) - falling back
// to "no scope" would silently let an admin write a row that no runtime
// path can reach.
func activeWorkspaceIDFromRequest(ctx *fasthttp.RequestCtx) string {
	if v := lib.ActiveWorkspaceHeader(ctx); v != "" {
		return v
	}
	if v := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); v != "" {
		return v
	}
	return ""
}

// ossGlobalWorkspaceID is the constant key used for workspace-scoped config
// (logging, MCP) in the open-source single-tenant build, where dashboard auth
// is disabled and there are no workspaces. It makes those settings behave as
// gateway-global instead of 400-ing on a missing X-Active-Workspace-Id.
const ossGlobalWorkspaceID = "default"

// resolveWorkspaceID returns the request's workspace id, or - in the OSS no-auth
// single-tenant build - the constant global key so workspace-scoped config
// persists and loads without a workspace or a sidebar switcher. When auth is
// enabled, behavior is unchanged (callers still 400 on a missing workspace).
func (h *ConfigHandler) resolveWorkspaceID(ctx *fasthttp.RequestCtx) string {
	if id := activeWorkspaceIDFromRequest(ctx); id != "" {
		return id
	}
	if h.store.ConfigStore != nil {
		if cfg, err := h.store.ConfigStore.GetAuthConfig(ctx); err == nil && (cfg == nil || !cfg.IsEnabled) {
			return ossGlobalWorkspaceID
		}
	}
	return ""
}

// getWorkspaceLogging GET /api/workspace-logging - returns the workspace's
// override row if one exists, otherwise returns the tenant-global default
// values from CoreConfig with is_override=false so the UI can render
// "inheriting defaults" semantics without a second round-trip.
func (h *ConfigHandler) getWorkspaceLogging(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	workspaceID := h.resolveWorkspaceID(ctx)
	if workspaceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "X-Active-Workspace-Id header (or workspace_id query) is required")
		return
	}
	stored, err := h.store.ConfigStore.GetWorkspaceLoggingSettings(ctx, workspaceID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to load workspace logging settings: %v", err))
		return
	}
	if stored != nil {
		SendJSON(ctx, workspaceLoggingDTO{
			WorkspaceID:                     stored.WorkspaceID,
			EnableLogging:                   stored.EnableLogging,
			DisableContentLogging:           stored.DisableContentLogging,
			LogRetentionDays:                stored.LogRetentionDays,
			HideDeletedVirtualKeysInFilters: stored.HideDeletedVirtualKeysInFilters,
			LoggingHeaders:                  stored.LoggingHeaders,
			IsOverride:                      true,
		})
		return
	}
	// No row → return the tenant-global defaults so the UI can show the
	// inherited state without a separate /config call.
	defaults := workspaceLoggingDTO{
		WorkspaceID:      workspaceID,
		EnableLogging:    true,
		LogRetentionDays: 365,
		LoggingHeaders:   []string{},
		IsOverride:       false,
	}
	defaults.EnableLogging = h.store.ClientConfig.EnableLogging
	defaults.DisableContentLogging = h.store.ClientConfig.DisableContentLogging
	defaults.HideDeletedVirtualKeysInFilters = h.store.ClientConfig.HideDeletedVirtualKeysInFilters
	if h.store.ClientConfig.LogRetentionDays > 0 {
		defaults.LogRetentionDays = h.store.ClientConfig.LogRetentionDays
	}
	if len(h.store.ClientConfig.LoggingHeaders) > 0 {
		defaults.LoggingHeaders = append([]string(nil), h.store.ClientConfig.LoggingHeaders...)
	}
	SendJSON(ctx, defaults)
}

// updateWorkspaceLogging PUT /api/workspace-logging - creates or replaces
// the override row for the active workspace. After writing, invalidates the
// in-process cache so the next inference request sees the new settings
// without a restart.
func (h *ConfigHandler) updateWorkspaceLogging(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	workspaceID := h.resolveWorkspaceID(ctx)
	if workspaceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "X-Active-Workspace-Id header (or workspace_id query) is required")
		return
	}
	var payload workspaceLoggingDTO
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	if payload.LogRetentionDays < 1 {
		payload.LogRetentionDays = 1
	}
	headers := payload.LoggingHeaders
	if headers == nil {
		headers = []string{}
	}
	err := h.store.ConfigStore.UpsertWorkspaceLoggingSettings(ctx, &configstore.WorkspaceLoggingSettings{
		WorkspaceID:                     workspaceID,
		EnableLogging:                   payload.EnableLogging,
		DisableContentLogging:           payload.DisableContentLogging,
		LogRetentionDays:                payload.LogRetentionDays,
		HideDeletedVirtualKeysInFilters: payload.HideDeletedVirtualKeysInFilters,
		LoggingHeaders:                  headers,
	})
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to save workspace logging settings: %v", err))
		return
	}
	// Force readers to refresh - the next /v1/evaluate (or log write) under
	// this workspace will reload the row from DB exactly once.
	configstore.InvalidateWorkspaceLoggingSettings(workspaceID)
	SendJSON(ctx, workspaceLoggingDTO{
		WorkspaceID:                     workspaceID,
		EnableLogging:                   payload.EnableLogging,
		DisableContentLogging:           payload.DisableContentLogging,
		LogRetentionDays:                payload.LogRetentionDays,
		HideDeletedVirtualKeysInFilters: payload.HideDeletedVirtualKeysInFilters,
		LoggingHeaders:                  headers,
		IsOverride:                      true,
	})
}

// deleteWorkspaceLogging DELETE /api/workspace-logging - removes the
// override so this workspace falls back to tenant-global defaults. Used by
// a future "Reset to defaults" button on the page.
func (h *ConfigHandler) deleteWorkspaceLogging(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	workspaceID := h.resolveWorkspaceID(ctx)
	if workspaceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "X-Active-Workspace-Id header (or workspace_id query) is required")
		return
	}
	if err := h.store.ConfigStore.DeleteWorkspaceLoggingSettings(ctx, workspaceID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to delete workspace logging settings: %v", err))
		return
	}
	configstore.InvalidateWorkspaceLoggingSettings(workspaceID)
	SendJSON(ctx, map[string]any{"status": "reset", "workspace_id": workspaceID})
}

// workspaceMCPDTO mirrors the per-workspace MCP Settings shape sent to and
// from the admin UI. Field names are 1:1 with workspace_mcp_settings columns
// so a future rename in the store layer stays opaque to the handler.
type workspaceMCPDTO struct {
	WorkspaceID             string `json:"workspace_id"`
	AgentDepth              int    `json:"agent_depth"`
	ToolExecutionTimeoutSec int    `json:"tool_execution_timeout_sec"`
	ToolSyncIntervalMinutes int    `json:"tool_sync_interval_minutes"`
	CodeModeBindingLevel    string `json:"code_mode_binding_level"`
	CacheEnabled            bool   `json:"cache_enabled"`
	CacheTTLSeconds         int    `json:"cache_ttl_seconds"`
	IsOverride              bool   `json:"is_override"` // true when a stored override exists, false when defaults
}

// getWorkspaceMCP GET /api/workspace-mcp - returns the workspace's MCP
// override row, or the tenant-global defaults from CoreConfig with
// is_override=false so the UI can render "inheriting defaults" semantics
// without a second round-trip.
func (h *ConfigHandler) getWorkspaceMCP(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	workspaceID := h.resolveWorkspaceID(ctx)
	if workspaceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "X-Active-Workspace-Id header (or workspace_id query) is required")
		return
	}
	stored, err := h.store.ConfigStore.GetWorkspaceMCPSettings(ctx, workspaceID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to load workspace MCP settings: %v", err))
		return
	}
	if stored != nil {
		SendJSON(ctx, workspaceMCPDTO{
			WorkspaceID:             stored.WorkspaceID,
			AgentDepth:              stored.AgentDepth,
			ToolExecutionTimeoutSec: stored.ToolExecutionTimeoutSec,
			ToolSyncIntervalMinutes: stored.ToolSyncIntervalMinutes,
			CodeModeBindingLevel:    stored.CodeModeBindingLevel,
			CacheEnabled:            stored.CacheEnabled,
			CacheTTLSeconds:         stored.CacheTTLSeconds,
			IsOverride:              true,
		})
		return
	}
	// No row → return tenant-global defaults pulled from CoreConfig so the
	// UI shows the inherited state without a separate /config call.
	defaults := workspaceMCPDTO{
		WorkspaceID:             workspaceID,
		AgentDepth:              10,
		ToolExecutionTimeoutSec: 30,
		ToolSyncIntervalMinutes: 10,
		CodeModeBindingLevel:    "server",
		CacheEnabled:            true,
		CacheTTLSeconds:         300,
		IsOverride:              false,
	}
	cc := h.store.ClientConfig
	if cc.MCPAgentDepth > 0 {
		defaults.AgentDepth = cc.MCPAgentDepth
	}
	if cc.MCPToolExecutionTimeout > 0 {
		defaults.ToolExecutionTimeoutSec = cc.MCPToolExecutionTimeout
	}
	if cc.MCPToolSyncInterval >= 0 {
		defaults.ToolSyncIntervalMinutes = cc.MCPToolSyncInterval
	}
	if strings.TrimSpace(cc.MCPCodeModeBindingLevel) != "" {
		defaults.CodeModeBindingLevel = cc.MCPCodeModeBindingLevel
	}
	if cc.MCPCacheEnabled != nil {
		defaults.CacheEnabled = *cc.MCPCacheEnabled
	}
	if cc.MCPCacheTTLSeconds > 0 {
		defaults.CacheTTLSeconds = cc.MCPCacheTTLSeconds
	}
	SendJSON(ctx, defaults)
}

// updateWorkspaceMCP PUT /api/workspace-mcp - creates or replaces the
// override row for the active workspace. Invalidates the in-process cache
// so the next MCP call observes the new settings without a restart.
func (h *ConfigHandler) updateWorkspaceMCP(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	workspaceID := h.resolveWorkspaceID(ctx)
	if workspaceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "X-Active-Workspace-Id header (or workspace_id query) is required")
		return
	}
	var payload workspaceMCPDTO
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}
	err := h.store.ConfigStore.UpsertWorkspaceMCPSettings(ctx, &configstore.WorkspaceMCPSettings{
		WorkspaceID:             workspaceID,
		AgentDepth:              payload.AgentDepth,
		ToolExecutionTimeoutSec: payload.ToolExecutionTimeoutSec,
		ToolSyncIntervalMinutes: payload.ToolSyncIntervalMinutes,
		CodeModeBindingLevel:    payload.CodeModeBindingLevel,
		CacheEnabled:            payload.CacheEnabled,
		CacheTTLSeconds:         payload.CacheTTLSeconds,
	})
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to save workspace MCP settings: %v", err))
		return
	}
	configstore.InvalidateWorkspaceMCPSettings(workspaceID)
	// Re-read the stored row so the response reflects any clamp/normalize
	// that the store layer applied (binding-level fallback, min-1 depth).
	stored, _ := h.store.ConfigStore.GetWorkspaceMCPSettings(ctx, workspaceID)
	if stored != nil {
		SendJSON(ctx, workspaceMCPDTO{
			WorkspaceID:             stored.WorkspaceID,
			AgentDepth:              stored.AgentDepth,
			ToolExecutionTimeoutSec: stored.ToolExecutionTimeoutSec,
			ToolSyncIntervalMinutes: stored.ToolSyncIntervalMinutes,
			CodeModeBindingLevel:    stored.CodeModeBindingLevel,
			CacheEnabled:            stored.CacheEnabled,
			CacheTTLSeconds:         stored.CacheTTLSeconds,
			IsOverride:              true,
		})
		return
	}
	SendJSON(ctx, map[string]any{"status": "saved", "workspace_id": workspaceID})
}

// deleteWorkspaceMCP DELETE /api/workspace-mcp - removes the override so
// the workspace falls back to tenant-global defaults.
func (h *ConfigHandler) deleteWorkspaceMCP(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "config store not available")
		return
	}
	workspaceID := h.resolveWorkspaceID(ctx)
	if workspaceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "X-Active-Workspace-Id header (or workspace_id query) is required")
		return
	}
	if err := h.store.ConfigStore.DeleteWorkspaceMCPSettings(ctx, workspaceID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to delete workspace MCP settings: %v", err))
		return
	}
	configstore.InvalidateWorkspaceMCPSettings(workspaceID)
	SendJSON(ctx, map[string]any{"status": "reset", "workspace_id": workspaceID})
}
