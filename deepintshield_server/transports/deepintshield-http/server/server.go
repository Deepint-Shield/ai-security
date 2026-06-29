// Package server provides the HTTP server for DeepIntShield.
package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/agentic"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/modelcatalog"
	dynamicPlugins "github.com/deepint-shield/ai-security/framework/plugins"
	"github.com/deepint-shield/ai-security/framework/tracing"
	"github.com/deepint-shield/ai-security/plugins/governance"
	"github.com/deepint-shield/ai-security/plugins/logging"
	"github.com/deepint-shield/ai-security/plugins/telemetry"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/handlers"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/integrations"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	bfws "github.com/deepint-shield/ai-security/transports/deepintshield-http/websocket"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

// Constants
const (
	DefaultHost           = "localhost"
	DefaultPort           = "8080"
	DefaultAppDir         = "" // Empty string means use OS-specific config directory
	DefaultLogLevel       = string(schemas.LogLevelInfo)
	DefaultLogOutputStyle = string(schemas.LoggerOutputTypeJSON)
)

var enterprisePlugins = []string{
	"datadog",
}

type providerModelStore interface {
	ReplaceProviderModels(ctx context.Context, provider schemas.ModelProvider, modelNames []string) error
}

// ServerCallbacks is a interface that defines the callbacks for the server.
type ServerCallbacks interface {
	// Plugins callbacks
	ReloadPlugin(ctx context.Context, name string, path *string, pluginConfig any, placement *schemas.PluginPlacement, order *int) error
	RemovePlugin(ctx context.Context, name string) error
	GetPluginStatus(ctx context.Context) map[string]schemas.PluginStatus
	// Auth related callbacks
	UpdateAuthConfig(ctx context.Context, authConfig *configstore.AuthConfig) error
	ReloadClientConfigFromConfigStore(ctx context.Context) error
	// Pricing related callbacks
	ReloadPricingManager(ctx context.Context) error
	ForceReloadPricing(ctx context.Context) error
	// Proxy related callbacks
	ReloadProxyConfig(ctx context.Context, config *tables.GlobalProxyConfig) error
	// Client config related callbacks
	ReloadHeaderFilterConfig(ctx context.Context, config *tables.GlobalHeaderFilterConfig) error
	UpdateDropExcessRequests(ctx context.Context, value bool)
	// Governance related callbacks
	GetGovernanceData(ctx context.Context) *governance.GovernanceData
	ReloadTeam(ctx context.Context, id string) (*tables.TableTeam, error)
	RemoveTeam(ctx context.Context, id string) error
	ReloadCustomer(ctx context.Context, id string) (*tables.TableCustomer, error)
	RemoveCustomer(ctx context.Context, id string) error
	// Virtual key related callbacks
	ReloadVirtualKey(ctx context.Context, id string) (*tables.TableVirtualKey, error)
	RemoveVirtualKey(ctx context.Context, id string) error
	// Provider related callbacks
	GetModelsForProvider(provider schemas.ModelProvider) []string
	GetUnfilteredModelsForProvider(provider schemas.ModelProvider) []string
	ReloadModelConfig(ctx context.Context, id string) (*tables.TableModelConfig, error)
	RemoveModelConfig(ctx context.Context, id string) error
	ReloadProvider(ctx context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error)
	RemoveProvider(ctx context.Context, provider schemas.ModelProvider) error
	ReloadRoutingRule(ctx context.Context, id string) error
	RemoveRoutingRule(ctx context.Context, id string) error
	// MCP related callbacks
	AddMCPClient(ctx context.Context, clientConfig *schemas.MCPClientConfig) error
	RemoveMCPClient(ctx context.Context, id string) error
	UpdateMCPClient(ctx context.Context, id string, updatedConfig *schemas.MCPClientConfig) error
	UpdateMCPToolManagerConfig(ctx context.Context, maxAgentDepth int, toolExecutionTimeoutInSeconds int, codeModeBindingLevel string, cacheEnabled *bool, cacheTTLSeconds int) error
	ReconnectMCPClient(ctx context.Context, id string) error
	// Logging related callbacks
	NewLogEntryAdded(ctx context.Context, logEntry *logstore.Log) error
}

// DeepIntShieldHTTPServer represents a HTTP server instance.
type DeepIntShieldHTTPServer struct {
	Ctx    *schemas.DeepIntShieldContext
	cancel context.CancelFunc

	Version   string
	UIContent embed.FS

	Port   string
	Host   string
	AppDir string

	LogLevel        string
	LogOutputStyle  string
	LogsCleaner     *logstore.LogsCleaner
	AsyncJobCleaner *logstore.AsyncJobCleaner

	Client *deepintshield.DeepIntShield
	Config *lib.Config

	Server *fasthttp.Server
	Router *router.Router

	WebSocketHandler   *handlers.WebSocketHandler
	MCPServerHandler   *handlers.MCPServerHandler
	devPprofHandler    *handlers.DevPprofHandler
	IntegrationHandler *handlers.IntegrationHandler
	// MCPInferenceHandler is exposed so RegisterAPIRoutes can wire the
	// Agentic PEP runtime into the tool execution path after it has
	// been constructed.
	MCPInferenceHandler *handlers.MCPInferenceHandler
	// CompletionHandler is exposed so RegisterAPIRoutes can wire the
	// integration hooks after it has been constructed.
	CompletionHandler *handlers.CompletionHandler

	AuthMiddleware    *handlers.AuthMiddleware
	TracingMiddleware *handlers.TracingMiddleware
	WSTicketStore     *handlers.WSTicketStore

	wsPool *bfws.Pool
}

var logger schemas.Logger

// SetLogger sets the logger for the server.
func SetLogger(l schemas.Logger) {
	logger = l
}

// NewDeepIntShieldHTTPServer creates a new instance of DeepIntShieldHTTPServer.
func NewDeepIntShieldHTTPServer(version string, uiContent embed.FS) *DeepIntShieldHTTPServer {
	return &DeepIntShieldHTTPServer{
		Version:        version,
		UIContent:      uiContent,
		Port:           DefaultPort,
		Host:           DefaultHost,
		AppDir:         DefaultAppDir,
		LogLevel:       DefaultLogLevel,
		LogOutputStyle: DefaultLogOutputStyle,
	}
}

type GovernanceInMemoryStore struct {
	Config *lib.Config
}

func (s *GovernanceInMemoryStore) GetConfiguredProviders() map[schemas.ModelProvider]configstore.ProviderConfig {
	// Use read lock for thread-safe access - no need to copy on hot path
	s.Config.Mu.RLock()
	defer s.Config.Mu.RUnlock()
	return s.Config.Providers
}

// AddMCPClient adds a new MCP client to the in-memory store
func (s *DeepIntShieldHTTPServer) AddMCPClient(ctx context.Context, clientConfig *schemas.MCPClientConfig) error {
	if err := s.Config.AddMCPClient(ctx, clientConfig); err != nil {
		return err
	}
	if err := s.MCPServerHandler.SyncAllMCPServers(ctx); err != nil {
		logger.Warn("failed to sync MCP servers after adding client: %v", err)
	}
	return nil
}

// ReconnectMCPClient reconnects an MCP client to the in-memory store
func (s *DeepIntShieldHTTPServer) ReconnectMCPClient(ctx context.Context, id string) error {
	// Check if client is registered in DeepIntShield (can be not registered if client initialization failed)
	if clients, err := s.Client.GetMCPClients(); err == nil && len(clients) > 0 {
		for _, client := range clients {
			if client.Config.ID == id {
				if err := s.Client.ReconnectMCPClient(id); err != nil {
					return err
				}
				return nil
			}
		}
	}
	// Config exists in store, but not in DeepIntShield (can happen if client initialization failed)
	clientConfig, err := s.Config.GetMCPClient(id)
	if err != nil {
		return err
	}
	if err := s.Client.AddMCPClient(clientConfig); err != nil {
		return err
	}
	if err := s.MCPServerHandler.SyncAllMCPServers(ctx); err != nil {
		logger.Warn("failed to sync MCP servers after adding client: %v", err)
	}
	return nil
}

// UpdateMCPClient updates an MCP client in the in-memory store
func (s *DeepIntShieldHTTPServer) UpdateMCPClient(ctx context.Context, id string, updatedConfig *schemas.MCPClientConfig) error {
	if err := s.Config.UpdateMCPClient(ctx, id, updatedConfig); err != nil {
		return err
	}
	if err := s.MCPServerHandler.SyncAllMCPServers(ctx); err != nil {
		logger.Warn("failed to sync MCP servers after editing client: %v", err)
	}
	return nil
}

// NewLogEntryAdded broadcasts a new log entry to websocket clients and records
// immutable audit events for committed runtime request logs.
func (s *DeepIntShieldHTTPServer) NewLogEntryAdded(ctx context.Context, logEntry *logstore.Log) error {
	if s.WebSocketHandler == nil {
		if auditStore, ok := s.Config.LogsStore.(logstore.AuditLogStore); ok {
			return handlers.PersistAuditLogForRequestLog(ctx, auditStore, logEntry)
		}
		return nil
	}
	s.WebSocketHandler.BroadcastLogUpdate(logEntry)
	if auditStore, ok := s.Config.LogsStore.(logstore.AuditLogStore); ok {
		return handlers.PersistAuditLogForRequestLog(ctx, auditStore, logEntry)
	}
	return nil
}

// NewMCPToolLogEntryAdded broadcasts a new MCP tool log entry to websocket
// clients and records immutable audit events for committed tool executions.
func (s *DeepIntShieldHTTPServer) NewMCPToolLogEntryAdded(ctx context.Context, logEntry *logstore.MCPToolLog) error {
	if s.WebSocketHandler != nil {
		s.WebSocketHandler.BroadcastMCPLogUpdate(logEntry)
	}
	if auditStore, ok := s.Config.LogsStore.(logstore.AuditLogStore); ok {
		return handlers.PersistAuditLogForMCPToolLog(ctx, auditStore, logEntry)
	}
	return nil
}

// RemoveMCPClient removes an MCP client from the in-memory store
func (s *DeepIntShieldHTTPServer) RemoveMCPClient(ctx context.Context, id string) error {
	if err := s.Config.RemoveMCPClient(ctx, id); err != nil {
		return err
	}
	if err := s.MCPServerHandler.SyncAllMCPServers(ctx); err != nil {
		logger.Warn("failed to sync MCP servers after removing client: %v", err)
	}
	return nil
}

// ExecuteChatMCPTool executes an MCP tool call and returns the result as a chat message.
func (s *DeepIntShieldHTTPServer) ExecuteChatMCPTool(ctx context.Context, toolCall *schemas.ChatAssistantMessageToolCall) (*schemas.ChatMessage, *schemas.DeepIntShieldError) {
	deepintshieldCtx := schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
	return s.Client.ExecuteChatMCPTool(deepintshieldCtx, toolCall)
}

// ExecuteResponsesMCPTool executes an MCP tool call and returns the result as a responses message.
func (s *DeepIntShieldHTTPServer) ExecuteResponsesMCPTool(ctx context.Context, toolCall *schemas.ResponsesToolMessage) (*schemas.ResponsesMessage, *schemas.DeepIntShieldError) {
	deepintshieldCtx := schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
	return s.Client.ExecuteResponsesMCPTool(deepintshieldCtx, toolCall)
}

func (s *DeepIntShieldHTTPServer) GetAvailableMCPTools(ctx context.Context) []schemas.ChatTool {
	return s.Client.GetAvailableMCPTools(ctx)
}

// markPluginDisabled marks a plugin as disabled in the plugin status
func (s *DeepIntShieldHTTPServer) markPluginDisabled(name string) error {
	return s.Config.UpdatePluginStatus(name, schemas.PluginStatusDisabled)
}

// getGovernancePluginName returns the governance plugin name from context or default
func (s *DeepIntShieldHTTPServer) getGovernancePluginName() string {
	if name, ok := s.Ctx.Value(schemas.DeepIntShieldContextKeyGovernancePluginName).(string); ok && name != "" {
		return name
	}
	return governance.PluginName
}

// getGovernancePlugin safely retrieves the governance plugin with proper locking.
// It acquires a read lock, finds the plugin, releases the lock, performs type assertion,
// and returns the BaseGovernancePlugin implementation or an error.
func (s *DeepIntShieldHTTPServer) getGovernancePlugin() (governance.BaseGovernancePlugin, error) {
	// Use type-safe finder from Config
	return lib.FindPluginAs[governance.BaseGovernancePlugin](s.Config, s.getGovernancePluginName())
}

// ReloadVirtualKey reloads a virtual key from the in-memory store
func (s *DeepIntShieldHTTPServer) ReloadVirtualKey(ctx context.Context, id string) (*tables.TableVirtualKey, error) {
	// Load relationships for response
	preloadedVk, err := s.Config.ConfigStore.RetryOnNotFound(ctx, func(ctx context.Context) (any, error) {
		preloadedVk, err := s.Config.ConfigStore.GetVirtualKey(ctx, id)
		if err != nil {
			return nil, err
		}
		return preloadedVk, nil
	}, lib.DBLookupMaxRetries, lib.DBLookupDelay)
	if err != nil {
		logger.Error("failed to load virtual key: %v", err)
		return nil, err
	}
	if preloadedVk == nil {
		logger.Error("virtual key not found")
		return nil, fmt.Errorf("virtual key not found")
	}
	// Type assertion (should never happen)
	virtualKey, ok := preloadedVk.(*tables.TableVirtualKey)
	if !ok {
		logger.Error("virtual key type assertion failed")
		return nil, fmt.Errorf("virtual key type assertion failed")
	}
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return nil, err
	}
	governancePlugin.GetGovernanceStore().UpdateVirtualKeyInMemory(virtualKey, nil, nil, nil)
	s.MCPServerHandler.SyncVKMCPServer(virtualKey)
	return virtualKey, nil
}

// RemoveVirtualKey removes a virtual key from the in-memory store
func (s *DeepIntShieldHTTPServer) RemoveVirtualKey(ctx context.Context, id string) error {
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return err
	}
	preloadedVk, err := s.Config.ConfigStore.GetVirtualKey(ctx, id)
	if err != nil {
		if !errors.Is(err, configstore.ErrNotFound) {
			return err
		}
	}
	if preloadedVk == nil {
		// This could be broadcast message from other server, so we will just clean up in-memory store
		governancePlugin.GetGovernanceStore().DeleteVirtualKeyInMemory(id)
		return nil
	}
	governancePlugin.GetGovernanceStore().DeleteVirtualKeyInMemory(id)
	s.MCPServerHandler.DeleteVKMCPServer(preloadedVk.Value)
	return nil
}

// ReloadTeam reloads a team from the in-memory store
func (s *DeepIntShieldHTTPServer) ReloadTeam(ctx context.Context, id string) (*tables.TableTeam, error) {
	// Load relationships for response
	preloadedTeam, err := s.Config.ConfigStore.GetTeam(ctx, id)
	if err != nil {
		logger.Error("failed to load relationships for created team: %v", err)
		return nil, err
	}
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return nil, err
	}
	// Add to in-memory store
	governancePlugin.GetGovernanceStore().UpdateTeamInMemory(preloadedTeam, nil)
	return preloadedTeam, nil
}

// RemoveTeam removes a team from the in-memory store
func (s *DeepIntShieldHTTPServer) RemoveTeam(ctx context.Context, id string) error {
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return err
	}
	preloadedTeam, err := s.Config.ConfigStore.GetTeam(ctx, id)
	if err != nil {
		if !errors.Is(err, configstore.ErrNotFound) {
			return err
		}
	}
	if preloadedTeam == nil {
		// At-least deleting from in-memory store to avoid conflicts
		governancePlugin.GetGovernanceStore().DeleteTeamInMemory(id)
		return nil
	}
	governancePlugin.GetGovernanceStore().DeleteTeamInMemory(id)
	return nil
}

// ReloadCustomer reloads a customer from the in-memory store
func (s *DeepIntShieldHTTPServer) ReloadCustomer(ctx context.Context, id string) (*tables.TableCustomer, error) {
	preloadedCustomer, err := s.Config.ConfigStore.GetCustomer(ctx, id)
	if err != nil {
		return nil, err
	}
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return nil, err
	}
	// Add to in-memory store
	governancePlugin.GetGovernanceStore().UpdateCustomerInMemory(preloadedCustomer, nil)
	return preloadedCustomer, nil
}

// RemoveCustomer removes a customer from the in-memory store
func (s *DeepIntShieldHTTPServer) RemoveCustomer(ctx context.Context, id string) error {
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return err
	}
	preloadedCustomer, err := s.Config.ConfigStore.GetCustomer(ctx, id)
	if err != nil {
		if !errors.Is(err, configstore.ErrNotFound) {
			return err
		}
	}
	if preloadedCustomer == nil {
		// At-least deleting from in-memory store to avoid conflicts
		governancePlugin.GetGovernanceStore().DeleteCustomerInMemory(id)
		return nil
	}
	governancePlugin.GetGovernanceStore().DeleteCustomerInMemory(id)
	return nil
}

// ReloadModelConfig reloads a model config from the database into in-memory store
// If usage was modified (e.g., reset due to config change), syncs it back to DB
func (s *DeepIntShieldHTTPServer) ReloadModelConfig(ctx context.Context, id string) (*tables.TableModelConfig, error) {
	preloadedMC, err := s.Config.ConfigStore.GetModelConfigByID(ctx, id)
	if err != nil {
		logger.Error("failed to load model config: %v", err)
		return nil, err
	}
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return nil, err
	}
	// Update in memory and get back the potentially modified model config
	updatedMC := governancePlugin.GetGovernanceStore().UpdateModelConfigInMemory(preloadedMC)
	if updatedMC == nil {
		return preloadedMC, nil
	}

	// Sync updated usage values back to database if they changed
	if updatedMC.Budget != nil && preloadedMC.Budget != nil {
		if updatedMC.Budget.CurrentUsage != preloadedMC.Budget.CurrentUsage {
			if err := s.Config.ConfigStore.UpdateBudgetUsage(ctx, updatedMC.Budget.ID, updatedMC.Budget.CurrentUsage); err != nil {
				logger.Error("failed to sync budget usage to database: %v", err)
			}
		}
	}
	if updatedMC.RateLimit != nil && preloadedMC.RateLimit != nil {
		tokenUsageChanged := updatedMC.RateLimit.TokenCurrentUsage != preloadedMC.RateLimit.TokenCurrentUsage
		requestUsageChanged := updatedMC.RateLimit.RequestCurrentUsage != preloadedMC.RateLimit.RequestCurrentUsage
		if tokenUsageChanged || requestUsageChanged {
			if err := s.Config.ConfigStore.UpdateRateLimitUsage(ctx, updatedMC.RateLimit.ID, updatedMC.RateLimit.TokenCurrentUsage, updatedMC.RateLimit.RequestCurrentUsage); err != nil {
				logger.Error("failed to sync rate limit usage to database: %v", err)
			}
		}
	}

	return updatedMC, nil
}

// RemoveModelConfig removes a model config from the in-memory store
func (s *DeepIntShieldHTTPServer) RemoveModelConfig(ctx context.Context, id string) error {
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return err
	}
	governancePlugin.GetGovernanceStore().DeleteModelConfigInMemory(id)
	return nil
}

func (s *DeepIntShieldHTTPServer) ReloadProvider(ctx context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error) {
	if s.Config == nil || s.Config.ConfigStore == nil {
		return nil, fmt.Errorf("config store not found")
	}
	if s.Config.ModelCatalog == nil {
		return nil, fmt.Errorf("pricing manager not found")
	}
	if s.Client == nil {
		return nil, fmt.Errorf("deepintshield client not found")
	}

	// Load provider from DB
	providerInfo, err := s.Config.ConfigStore.GetProvider(ctx, provider)
	if err != nil {
		logger.Error("failed to load provider: %v", err)
		return nil, err
	}

	// Initialize updatedProvider
	updatedProvider := providerInfo

	// Sync model level budgets in governance plugin (if governance is enabled)
	if s.Config.IsPluginLoaded(s.getGovernancePluginName()) {
		governancePlugin, err := s.getGovernancePlugin()
		if err != nil {
			logger.Warn("governance plugin found but failed to get: %v", err)
		} else {
			// Update in memory and get back the potentially modified provider
			govUpdated := governancePlugin.GetGovernanceStore().UpdateProviderInMemory(providerInfo)
			if govUpdated != nil {
				updatedProvider = govUpdated
			}

			// Sync updated usage values back to database if they changed
			if updatedProvider.Budget != nil && providerInfo.Budget != nil {
				if updatedProvider.Budget.CurrentUsage != providerInfo.Budget.CurrentUsage {
					if err := s.Config.ConfigStore.UpdateBudgetUsage(ctx, updatedProvider.Budget.ID, updatedProvider.Budget.CurrentUsage); err != nil {
						logger.Error("failed to sync budget usage to database: %v", err)
					}
				}
			}
			if updatedProvider.RateLimit != nil && providerInfo.RateLimit != nil {
				tokenUsageChanged := updatedProvider.RateLimit.TokenCurrentUsage != providerInfo.RateLimit.TokenCurrentUsage
				requestUsageChanged := updatedProvider.RateLimit.RequestCurrentUsage != providerInfo.RateLimit.RequestCurrentUsage
				if tokenUsageChanged || requestUsageChanged {
					if err := s.Config.ConfigStore.UpdateRateLimitUsage(ctx, updatedProvider.RateLimit.ID, updatedProvider.RateLimit.TokenCurrentUsage, updatedProvider.RateLimit.RequestCurrentUsage); err != nil {
						logger.Error("failed to sync rate limit usage to database: %v", err)
					}
				}
			}
		}
	}

	// Syncing models (this part always runs regardless of governance)
	if err := s.Config.ModelCatalog.SetProviderPricingOverrides(provider, providerInfo.PricingOverrides); err != nil {
		logger.Warn("failed to refresh pricing overrides for provider %s: %v", provider, err)
	}

	bfCtx := schemas.NewDeepIntShieldContext(ctx, time.Now().Add(15*time.Second))
	bfCtx.SetValue(schemas.DeepIntShieldContextKeySkipPluginPipeline, true)
	bfCtx.SetValue(schemas.DeepIntShieldContextKeyValidateKeys, true) // Validate keys during provider add/update
	defer bfCtx.Cancel()

	allModels, deepintshieldErr := s.Client.ListModelsRequest(bfCtx, &schemas.DeepIntShieldListModelsRequest{
		Provider: provider,
	})
	if allModels != nil && len(allModels.KeyStatuses) > 0 && s.Config.ConfigStore != nil {
		s.updateKeyStatus(ctx, allModels.KeyStatuses)
	}
	if deepintshieldErr != nil {
		if len(deepintshieldErr.ExtraFields.KeyStatuses) > 0 && s.Config.ConfigStore != nil {
			s.updateKeyStatus(ctx, deepintshieldErr.ExtraFields.KeyStatuses)
		}

		logger.Warn("failed to update provider model catalog: failed to list all models: %s. We are falling back onto the static datasheet", deepintshield.GetErrorMessage(deepintshieldErr))
		// In case of error, we return an empty list of models, and fallback onto the static datasheet
		allModels = &schemas.DeepIntShieldListModelsResponse{
			Data: make([]schemas.Model, 0),
		}
	}
	// Getting allowed models from all provider keys
	providerKeys, err := s.Config.ConfigStore.GetKeysByProvider(ctx, string(provider))
	if err != nil {
		return nil, fmt.Errorf("failed to update provider model catalog: failed to get keys by provider: %s", err)
	}
	modelsInKeys := make([]schemas.Model, 0)
	for _, key := range providerKeys {
		for _, model := range key.Models {
			modelsInKeys = append(modelsInKeys, schemas.Model{
				ID: string(provider) + "/" + model,
			})
		}
	}
	s.Config.ModelCatalog.UpsertModelDataForProvider(provider, allModels, modelsInKeys)
	unfilteredModelData, listModelsErr := s.Client.ListModelsRequest(bfCtx, &schemas.DeepIntShieldListModelsRequest{
		Provider:   provider,
		Unfiltered: true,
	})
	if listModelsErr != nil {
		logger.Error("failed to list unfiltered models for provider %s: %v: falling back onto the static datasheet", provider, deepintshield.GetErrorMessage(listModelsErr))
	} else {
		s.Config.ModelCatalog.UpsertUnfilteredModelDataForProvider(provider, unfilteredModelData)
	}
	if modelStore, ok := s.Config.ConfigStore.(providerModelStore); ok {
		modelNames := discoveredProviderModelNames(provider, allModels, modelsInKeys)
		if err := modelStore.ReplaceProviderModels(ctx, provider, modelNames); err != nil {
			logger.Warn("failed to persist discovered models for provider %s: %v", provider, err)
		}
	}
	return updatedProvider, nil
}

// RemoveProvider removes a provider from the in-memory store
func (s *DeepIntShieldHTTPServer) RemoveProvider(ctx context.Context, provider schemas.ModelProvider) error {
	err := s.Client.RemoveProvider(provider)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		logger.Error("failed to remove provider from client: %v", err)
		return err
	}
	err = s.Config.RemoveProvider(ctx, provider)
	if err != nil && !errors.Is(err, lib.ErrNotFound) {
		logger.Error("failed to remove provider from config: %v. Client and config may be out of sync, please restart deepintshield", err)
		return fmt.Errorf("failed to remove provider from config: %w. Client and config may be out of sync, please restart deepintshield", err)
	}
	governancePlugin, err := s.getGovernancePlugin()
	if err != nil {
		return err
	}
	governancePlugin.GetGovernanceStore().DeleteProviderInMemory(string(provider))
	if s.Config == nil || s.Config.ModelCatalog == nil {
		return fmt.Errorf("pricing manager not found")
	}
	s.Config.ModelCatalog.DeleteModelDataForProvider(provider)
	s.Config.ModelCatalog.DeleteProviderPricingOverrides(provider)

	return nil
}

// GetGovernanceData returns the governance data
func (s *DeepIntShieldHTTPServer) GetGovernanceData(ctx context.Context) *governance.GovernanceData {
	// Use type-safe finder from Config
	governancePlugin, err := lib.FindPluginAs[governance.BaseGovernancePlugin](s.Config, s.getGovernancePluginName())
	if err != nil {
		return nil
	}

	return governancePlugin.GetGovernanceStore().GetGovernanceData(ctx)
}

func discoveredProviderModelNames(
	provider schemas.ModelProvider,
	modelData *schemas.DeepIntShieldListModelsResponse,
	allowedModels []schemas.Model,
) []string {
	modelNames := make([]string, 0)
	seen := make(map[string]struct{})

	appendModel := func(modelID string) {
		parsedProvider, parsedModel := schemas.ParseModelString(modelID, "")
		if parsedProvider != provider || parsedModel == "" {
			return
		}
		if _, exists := seen[parsedModel]; exists {
			return
		}
		seen[parsedModel] = struct{}{}
		modelNames = append(modelNames, parsedModel)
	}

	if modelData != nil {
		for _, model := range modelData.Data {
			appendModel(model.ID)
		}
	}
	for _, model := range allowedModels {
		appendModel(model.ID)
	}

	return modelNames
}

// ReloadRoutingRule reloads a routing rule from the database into the governance store
func (s *DeepIntShieldHTTPServer) ReloadRoutingRule(ctx context.Context, id string) error {
	governancePluginName := governance.PluginName
	if name, ok := s.Ctx.Value(schemas.DeepIntShieldContextKeyGovernancePluginName).(string); ok && name != "" {
		governancePluginName = name
	}
	governancePlugin, err := lib.FindPluginAs[governance.BaseGovernancePlugin](s.Config, governancePluginName)
	if err != nil {
		return fmt.Errorf("governance plugin not found: %w", err)
	}
	// Get the governance store from the plugin
	store := governancePlugin.GetGovernanceStore()
	rule, err := s.Config.ConfigStore.GetRoutingRule(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get routing rule from config store: %w", err)
	}
	// Update the rule in the store (this updates the in-memory cache)
	if err := store.UpdateRoutingRuleInMemory(rule); err != nil {
		return fmt.Errorf("failed to update routing rule in store: %w", err)
	}
	return nil
}

// RemoveRoutingRule removes a routing rule from the governance store
func (s *DeepIntShieldHTTPServer) RemoveRoutingRule(ctx context.Context, id string) error {
	governancePluginName := governance.PluginName
	if name, ok := s.Ctx.Value(schemas.DeepIntShieldContextKeyGovernancePluginName).(string); ok && name != "" {
		governancePluginName = name
	}
	governancePlugin, err := lib.FindPluginAs[governance.BaseGovernancePlugin](s.Config, governancePluginName)
	if err != nil {
		return fmt.Errorf("governance plugin not found: %w", err)
	}
	// Get the governance store from the plugin
	store := governancePlugin.GetGovernanceStore()
	// Delete the rule from the store (this removes from in-memory cache)
	if err := store.DeleteRoutingRuleInMemory(id); err != nil {
		return fmt.Errorf("failed to delete routing rule from store: %w", err)
	}
	return nil
}

// ReloadClientConfigFromConfigStore reloads the client config from config store
func (s *DeepIntShieldHTTPServer) ReloadClientConfigFromConfigStore(ctx context.Context) error {
	if s.Config == nil || s.Config.ConfigStore == nil {
		return fmt.Errorf("config store not found")
	}
	config, err := s.Config.ConfigStore.GetClientConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to get client config: %v", err)
	}
	s.Config.ClientConfig = *config
	// Reloading config in deepintshield client
	if s.Client != nil {
		account := lib.NewBaseAccount(s.Config)
		var mcpConfig *schemas.MCPConfig
		if s.Config.MCPConfig != nil {
			mcpConfig = s.Config.MCPConfig
		}
		s.Client.ReloadConfig(schemas.DeepIntShieldConfig{
			Account:            account,
			InitialPoolSize:    s.Config.ClientConfig.InitialPoolSize,
			DropExcessRequests: s.Config.ClientConfig.DropExcessRequests,
			LLMPlugins:         s.Config.GetLoadedLLMPlugins(),
			MCPPlugins:         s.Config.GetLoadedMCPPlugins(),
			MCPConfig:          mcpConfig,
			Logger:             logger,
		})
	}
	return nil
}

// UpdateAuthConfig updates auth config in the config store and updates the AuthMiddleware's in-memory config
func (s *DeepIntShieldHTTPServer) UpdateAuthConfig(ctx context.Context, authConfig *configstore.AuthConfig) error {
	if authConfig == nil {
		return fmt.Errorf("auth config is nil")
	}
	if s.Config == nil || s.Config.ConfigStore == nil {
		return fmt.Errorf("config store not found")
	}
	// Allow disabling auth without credentials, but require them when enabling
	if authConfig.IsEnabled && (authConfig.AdminUserName == nil || authConfig.AdminUserName.GetValue() == "" || authConfig.AdminPassword == nil || authConfig.AdminPassword.GetValue() == "") {
		return fmt.Errorf("username and password are required when auth is enabled")
	}
	// Update the config store
	if err := s.Config.ConfigStore.UpdateAuthConfig(ctx, authConfig); err != nil {
		return err
	}
	// Update the AuthMiddleware's in-memory config
	if s.AuthMiddleware != nil {
		// Fetch the updated config from the store to ensure we have the latest
		updatedAuthConfig, err := s.Config.ConfigStore.GetAuthConfig(ctx)
		if err != nil {
			logger.Warn("failed to get auth config from store after update: %v", err)
			// Still update with what we have
			s.AuthMiddleware.UpdateAuthConfig(authConfig)
		} else {
			s.AuthMiddleware.UpdateAuthConfig(updatedAuthConfig)
		}
	}
	return nil
}

// UpdateDropExcessRequests updates excess requests config
func (s *DeepIntShieldHTTPServer) UpdateDropExcessRequests(ctx context.Context, value bool) {
	if s.Config == nil {
		return
	}
	s.Client.UpdateDropExcessRequests(value)
}

// UpdateMCPToolManagerConfig updates the MCP tool manager config
func (s *DeepIntShieldHTTPServer) UpdateMCPToolManagerConfig(ctx context.Context, maxAgentDepth int, toolExecutionTimeoutInSeconds int, codeModeBindingLevel string, cacheEnabled *bool, cacheTTLSeconds int) error {
	if s.Config == nil {
		return fmt.Errorf("config not found")
	}
	return s.Client.UpdateToolManagerConfig(maxAgentDepth, toolExecutionTimeoutInSeconds, codeModeBindingLevel, cacheEnabled, cacheTTLSeconds)
}

// reloadObservabilityPlugins reloads all observability plugins in the tracing middleware
func (s *DeepIntShieldHTTPServer) reloadObservabilityPlugins() {
	observabilityPlugins := s.CollectObservabilityPlugins()
	// Always update the tracing middleware, even with empty slice, to clear stale plugins
	s.TracingMiddleware.SetObservabilityPlugins(observabilityPlugins)
}

// ReloadPricingManager reloads the pricing manager
func (s *DeepIntShieldHTTPServer) ReloadPricingManager(ctx context.Context) error {
	if s.Config == nil || s.Config.ModelCatalog == nil {
		return fmt.Errorf("pricing manager not found")
	}
	if s.Config.FrameworkConfig == nil || s.Config.FrameworkConfig.Pricing == nil {
		return fmt.Errorf("framework config not found")
	}
	return s.Config.ModelCatalog.ReloadPricing(ctx, s.Config.FrameworkConfig.Pricing)
}

// ForceReloadPricing triggers an immediate pricing sync and resets the sync timer
func (s *DeepIntShieldHTTPServer) ForceReloadPricing(ctx context.Context) error {
	if s.Config == nil {
		return fmt.Errorf("server config not initialized")
	}
	if s.Config.ModelCatalog == nil {
		if s.Config.FrameworkConfig == nil || s.Config.FrameworkConfig.Pricing == nil {
			return fmt.Errorf("framework pricing config not initialized")
		}
		// Create a new model catalog
		modelCatalog, err := modelcatalog.Init(ctx, s.Config.FrameworkConfig.Pricing, s.Config.ConfigStore, nil, logger)
		if err != nil {
			return fmt.Errorf("failed to initialize new model catalog: %w", err)
		}
		s.Config.ModelCatalog = modelCatalog
		for provider, providerConfig := range s.Config.Providers {
			if err := s.Config.ModelCatalog.SetProviderPricingOverrides(provider, providerConfig.PricingOverrides); err != nil {
				logger.Warn("failed to seed pricing overrides for provider %s: %v", provider, err)
			}
		}
	} else {
		if err := s.Config.ModelCatalog.ForceReloadPricing(ctx); err != nil {
			return fmt.Errorf("failed to force reload pricing: %w", err)
		}
		// Fetching keys for all providers and allowed models first
		// Based on allowed models we will set the data in the model catalog
		for provider, providerConfig := range s.Config.Providers {
			bfCtx := schemas.NewDeepIntShieldContext(ctx, time.Now().Add(15*time.Second))
			bfCtx.SetValue(schemas.DeepIntShieldContextKeySkipPluginPipeline, true)
			modelData, listModelsErr := s.Client.ListModelsRequest(bfCtx, &schemas.DeepIntShieldListModelsRequest{
				Provider: provider,
			})
			if listModelsErr != nil {
				logger.Error("failed to list models for provider %s: %v: falling back onto the static datasheet", provider, deepintshield.GetErrorMessage(listModelsErr))
			}
			allowedModels := make([]schemas.Model, 0)
			for _, key := range providerConfig.Keys {
				for _, model := range key.Models {
					allowedModels = append(allowedModels, schemas.Model{
						ID: string(provider) + "/" + model,
					})
				}
			}
			s.Config.ModelCatalog.UpsertModelDataForProvider(provider, modelData, allowedModels)
			unfilteredModelData, listModelsErr := s.Client.ListModelsRequest(bfCtx, &schemas.DeepIntShieldListModelsRequest{
				Provider:   provider,
				Unfiltered: true,
			})
			if listModelsErr != nil {
				logger.Error("failed to list unfiltered models for provider %s: %v: falling back onto the static datasheet", provider, deepintshield.GetErrorMessage(listModelsErr))
			} else {
				s.Config.ModelCatalog.UpsertUnfilteredModelDataForProvider(provider, unfilteredModelData)
			}
			bfCtx.Cancel()
		}
	}
	return nil
}

// ReloadProxyConfig reloads the proxy configuration
func (s *DeepIntShieldHTTPServer) ReloadProxyConfig(ctx context.Context, config *tables.GlobalProxyConfig) error {
	if s.Config == nil {
		return fmt.Errorf("config not found")
	}
	// Store the proxy config in memory for use by components that need it
	s.Config.ProxyConfig = config
	logger.Info("proxy configuration reloaded: enabled=%t, type=%s", config.Enabled, config.Type)
	return nil
}

// ReloadHeaderFilterConfig reloads the header filter configuration
func (s *DeepIntShieldHTTPServer) ReloadHeaderFilterConfig(ctx context.Context, config *tables.GlobalHeaderFilterConfig) error {
	if s.Config == nil {
		return fmt.Errorf("config not found")
	}
	// Store the raw header filter config in ClientConfig
	s.Config.ClientConfig.HeaderFilterConfig = config
	// Compile into optimized matcher for O(1) per-request lookups
	s.Config.SetHeaderMatcher(lib.NewHeaderMatcher(config))
	allowlistLen := 0
	denylistLen := 0
	if config != nil {
		allowlistLen = len(config.Allowlist)
		denylistLen = len(config.Denylist)
	}
	logger.Info("header filter configuration reloaded: allowlist=%d, denylist=%d", allowlistLen, denylistLen)
	return nil
}

// GetModelsForProvider returns all models for a specific provider from the model catalog
func (s *DeepIntShieldHTTPServer) GetModelsForProvider(provider schemas.ModelProvider) []string {
	if s.Config == nil || s.Config.ModelCatalog == nil {
		return []string{}
	}
	return s.Config.ModelCatalog.GetModelsForProvider(provider)
}

// GetUnfilteredModelsForProvider returns all unfiltered models for a specific provider from the model catalog
func (s *DeepIntShieldHTTPServer) GetUnfilteredModelsForProvider(provider schemas.ModelProvider) []string {
	if s.Config == nil || s.Config.ModelCatalog == nil {
		return []string{}
	}
	return s.Config.ModelCatalog.GetUnfilteredModelsForProvider(provider)
}

// GetPluginStatus returns the status of all plugins
// Delegates to Config for centralized plugin status management
func (s *DeepIntShieldHTTPServer) GetPluginStatus(ctx context.Context) map[string]schemas.PluginStatus {
	return s.Config.GetPluginStatus()
}

// Helper to update error status
// Uses UpdatePluginOverallStatus to create the status entry if it doesn't exist,
// ensuring plugins that were never loaded can still have their error status tracked.
// Always returns the original error so the actual failure reason is surfaced to the user.
func (s *DeepIntShieldHTTPServer) updatePluginErrorStatus(name, step string, originalErr error) error {
	logs := []string{fmt.Sprintf("error %s plugin %s: %v", step, name, originalErr)}
	s.Config.UpdatePluginOverallStatus(name, name, schemas.PluginStatusError, logs, []schemas.PluginType{})
	return originalErr
}

// SyncLoadedPlugin syncs a loaded plugin to the DeepIntShield client and updates the plugin status
func (s *DeepIntShieldHTTPServer) SyncLoadedPlugin(ctx context.Context, name string, plugin schemas.BasePlugin, placement *schemas.PluginPlacement, order *int) error {
	// Tag the plugin with the caller's workspace (if any) before registering
	// so the request-time pipeline can route requests for that workspace to
	// this instance. Empty workspace = global instance (config.json / system
	// bootstrap path), which the pipeline applies to every workspace that
	// hasn't saved its own override.
	plugin = wrapPluginWithCallerWorkspace(ctx, plugin)
	// 2. Register (replaces same (name, workspace) slot atomically)
	if err := s.Config.ReloadPlugin(plugin); err != nil {
		return s.updatePluginErrorStatus(plugin.GetName(), "registering", err)
	}
	// 2b. Set order info and re-sort. Placement/order is per-name (applies
	// to all workspace copies); the workspace tag doesn't affect ordering.
	s.Config.SetPluginOrderInfo(plugin.GetName(), placement, order)
	s.Config.SortAndRebuildPlugins()
	// 3. Update DeepIntShield client
	if err := s.Client.ReloadPlugin(plugin, InferPluginTypes(plugin)); err != nil {
		return s.updatePluginErrorStatus(plugin.GetName(), "reloading deepintshield config for", err)
	}
	// 3b. Sync plugin execution order from config to core
	s.Client.ReorderPlugins(s.Config.GetPluginOrder())
	// 4. Special handling for observability plugins
	if _, ok := plugin.(schemas.ObservabilityPlugin); ok {
		s.reloadObservabilityPlugins()
	}
	// 5. Update plugin status
	s.Config.UpdatePluginOverallStatus(plugin.GetName(), name, schemas.PluginStatusActive,
		[]string{fmt.Sprintf("plugin %s reloaded successfully", name)}, InferPluginTypes(plugin))
	return nil
}

// wrapPluginWithCallerWorkspace returns plugin tagged with the workspace
// from the request context (via tenantctx). Returns plugin unchanged when
// the context carries no workspace - that's the config.json / bootstrap
// path and should land as a global instance.
func wrapPluginWithCallerWorkspace(ctx context.Context, plugin schemas.BasePlugin) schemas.BasePlugin {
	if plugin == nil {
		return plugin
	}
	// Read straight off the schemas context key so we don't import tenantctx
	// here (the configstore already does the same trick in resolveEffectiveWorkspaceID).
	ws, _ := ctx.Value(schemas.DeepIntShieldContextKeyWorkspaceID).(string)
	return dynamicPlugins.WrapWithWorkspace(plugin, ws)
}

// ReloadPlugin reloads a plugin with new instance and updates DeepIntShield core.
// The plugin is checked for LLM and MCP interfaces independently and registered
// to the appropriate arrays based on which interfaces it implements.
func (s *DeepIntShieldHTTPServer) ReloadPlugin(ctx context.Context, name string, path *string, pluginConfig any, placement *schemas.PluginPlacement, order *int) error {
	logger.Debug("reloading plugin %s", name)
	// 1. Instantiate new version
	plugin, err := InstantiatePlugin(ctx, name, path, pluginConfig, s.Config)
	if err != nil {
		return s.updatePluginErrorStatus(name, "loading", err)
	}
	return s.SyncLoadedPlugin(ctx, name, plugin, placement, order)
}

// RemovePlugin removes a plugin from the server.
// The plugin is removed from both LLM and MCP arrays independently if it exists in them.
func (s *DeepIntShieldHTTPServer) RemovePlugin(ctx context.Context, displayName string) error {
	// Get the actual plugin name from the display name
	name, ok := s.Config.GetPluginNameByDisplayName(displayName)
	if !ok {
		return dynamicPlugins.ErrPluginNotFound
	}

	// Check if plugin implements ObservabilityPlugin before removal
	var isObservability bool
	var err error
	var plugin schemas.BasePlugin
	if plugin, err = s.Config.FindPluginByName(name); err == nil {
		_, isObservability = plugin.(schemas.ObservabilityPlugin)
	}

	// 1. Unregister from config. Target the workspace-scoped instance when
	// the caller's request carries a workspace; falls back to the global
	// (untagged) instance otherwise. Without this scoping, disabling a
	// plugin in one workspace would yank it out from under every other
	// workspace that shares the same plugin name.
	callerWS, _ := ctx.Value(schemas.DeepIntShieldContextKeyWorkspaceID).(string)
	if err := s.Config.UnregisterWorkspacePlugin(name, strings.TrimSpace(callerWS)); err != nil {
		return err
	}

	// 2. Update DeepIntShield client
	if err := s.Client.RemovePlugin(name, InferPluginTypes(plugin)); err != nil {
		logger.Warn("failed to reload deepintshield config after plugin removal: %v", err)
	}

	// 3. Reload observability plugins if necessary
	if isObservability {
		s.reloadObservabilityPlugins()
	}

	// 4. Update status
	if isDisabled, _ := ctx.Value(handlers.PluginDisabledKey).(bool); isDisabled {
		s.markPluginDisabled(name)
	} else {
		s.Config.DeletePluginOverallStatus(name)
	}

	return nil
}

// RegisterInferenceRoutes initializes the routes for the inference handler
func (s *DeepIntShieldHTTPServer) RegisterInferenceRoutes(ctx context.Context, middlewares ...schemas.DeepIntShieldHTTPMiddleware) error {
	middlewares = append(middlewares, handlers.RequireValidVirtualKeyMiddleware(s.Config.ConfigStore))

	// Initialize WebSocket pool and handler before integrations so it can be wired through
	s.wsPool = bfws.NewPool(s.Config.WebSocketConfig.Pool)
	wsResponsesHandler := handlers.NewWSResponsesHandler(s.Client, s.Config, s.wsPool)

	inferenceHandler := handlers.NewInferenceHandler(s.Client, s.Config)
	s.CompletionHandler = inferenceHandler
	s.IntegrationHandler = handlers.NewIntegrationHandler(s.Client, s.Config, wsResponsesHandler)
	mcpInferenceHandler := handlers.NewMCPInferenceHandler(s.Client, s.Config)
	s.MCPInferenceHandler = mcpInferenceHandler
	mcpServerHandler, err := handlers.NewMCPServerHandler(ctx, s.Config, s)
	if err != nil {
		return fmt.Errorf("failed to initialize mcp server handler: %v", err)
	}
	s.MCPServerHandler = mcpServerHandler
	asyncHandler := handlers.NewAsyncHandler(s.Client, s.Config)
	s.IntegrationHandler.RegisterRoutes(s.Router, middlewares...)
	inferenceHandler.RegisterRoutes(s.Router, middlewares...)
	asyncHandler.RegisterRoutes(s.Router, middlewares...)
	mcpInferenceHandler.RegisterRoutes(s.Router, middlewares...)
	s.MCPServerHandler.RegisterRoutes(s.Router, middlewares...)
	return nil
}

// RegisterAPIRoutes initializes the routes for the DeepIntShield HTTP server.
func (s *DeepIntShieldHTTPServer) RegisterAPIRoutes(ctx context.Context, callbacks ServerCallbacks, middlewares ...schemas.DeepIntShieldHTTPMiddleware) error {
	var err error
	// Initializing plugin specific handlers
	var loggingHandler *handlers.LoggingHandler
	loggerPlugin, _ := lib.FindPluginAs[*logging.LoggerPlugin](s.Config, logging.PluginName)
	if loggerPlugin != nil {
		loggingHandler = handlers.NewLoggingHandler(loggerPlugin.GetPluginLogManager(), s, s.Config, s.Config.ConfigStore)
	}
	var governanceHandler *handlers.GovernanceHandler
	governancePluginName := governance.PluginName
	if name, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernancePluginName).(string); ok && name != "" {
		governancePluginName = name
	}
	governancePlugin, _ := lib.FindPluginAs[schemas.LLMPlugin](s.Config, governancePluginName)
	if governancePlugin != nil {
		governanceHandler, err = handlers.NewGovernanceHandler(callbacks, s.Config.ConfigStore)
		if err != nil {
			return fmt.Errorf("failed to initialize governance handler: %v", err)
		}
	}
	// Websocket handler needs to go below UI handler
	logger.Debug("initializing websocket server")
	if s.WebSocketHandler == nil {
		s.WebSocketHandler = handlers.NewWebSocketHandler(s.Ctx, s.Config.ClientConfig.AllowedOrigins)
	}
	if loggerPlugin != nil {
		loggerPlugin.SetLogCallback(func(ctx context.Context, logEntry *logstore.Log) {
			err := s.NewLogEntryAdded(ctx, logEntry)
			if err != nil {
				logger.Error("failed to add log entry: %v", err)
			}
		})
		loggerPlugin.SetMCPToolLogCallback(func(ctx context.Context, logEntry *logstore.MCPToolLog) {
			err := s.NewMCPToolLogEntryAdded(ctx, logEntry)
			if err != nil {
				logger.Error("failed to add MCP tool log entry: %v", err)
			}
		})
	}
	// Start WebSocket heartbeat
	s.WebSocketHandler.StartHeartbeat()
	// Adding telemetry middleware
	// Chaining all middlewares
	// lib.ChainMiddlewares chains multiple middlewares together
	healthHandler := handlers.NewHealthHandler(s.Config)
	providerHandler := handlers.NewProviderHandler(callbacks, s.Config, s.Client)
	mcpHandler := handlers.NewMCPHandler(callbacks, s.Client, s.Config)
	configHandler := handlers.NewConfigHandler(callbacks, s.Config)
	pluginsHandler := handlers.NewPluginsHandler(callbacks, s.Config.ConfigStore)
	sessionHandler := handlers.NewSessionHandler(s.Config.ConfigStore, s.Config.LogsStore, s.WSTicketStore)
	legalHandler := handlers.NewLegalHandler(s.Config.ConfigStore)
	workspaceHandler := handlers.NewWorkspaceHandler(s.Config.ConfigStore)

	// Register the workspace API key resolver hook so `dis_ws_*` bearer
	// tokens get resolved into workspace context inside
	// ConvertToDeepIntShieldContext. The resolver is hash-cached + async-
	// last-used-touched in lib.workspaceapikey, so the hot-path cost is
	// bounded to ~100ns once warm.
	{
		store := s.Config.ConfigStore
		lib.SetWorkspaceKeyResolver(func(ctx context.Context, bearer string) *lib.WorkspaceContext {
			return lib.ResolveWorkspaceFromBearer(ctx, store, bearer)
		})
	}
	promptsHandler := handlers.NewPromptsHandler(s.Config.ConfigStore)
	auditLogsHandler := handlers.NewAuditLogsHandler(s.Config.LogsStore)
	var guardrailsHandler *handlers.GuardrailsHandler
	if evidenceStore, ok := s.Config.LogsStore.(logstore.GuardrailEvidenceStore); ok {
		guardRuntimeTimeout := 3 * time.Second
		if rawTimeout := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_TIMEOUT_MS")); rawTimeout != "" {
			if timeoutMs, err := strconv.Atoi(rawTimeout); err == nil && timeoutMs > 0 {
				guardRuntimeTimeout = time.Duration(timeoutMs) * time.Millisecond
			}
		}
		guardrailsHandler = handlers.NewGuardrailsHandler(
			s.Config.ConfigStore,
			evidenceStore,
			strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_URL")),
			strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_GRPC_TARGET")),
			strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_SHARED_SECRET")),
			!strings.EqualFold(strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_PREFER_GRPC")), "false"),
			guardRuntimeTimeout,
		)
	}

	// ── Basic agentic Policy Decision Point (open source) ──────────────────────
	// Standalone /decide endpoint backed by ABAC rules (Rego + typed-AST), an
	// in-process decision cache, and an async hash-chained audit pipeline. The
	// premium agentic IP (broker, observability/Langfuse/OTLP exporters,
	// post-decision cache, grants, ReBAC) is intentionally absent: the runtime is
	// constructed with just the decision logic + decision cache + audit sink.
	agenticAuditSink := agentic.NewAsyncAudit(
		agentic.StoreAuditWriter{Store: s.Config.ConfigStore},
		8192, 2,
	)
	agenticAuditMode := agentic.AuditModeFromEnv()
	agenticAuditSink.EnableDurability(agenticAuditMode, agentic.AuditSpillPath())
	agenticRuntime := agentic.NewRuntime(200000, agenticAuditSink, 30*time.Second)
	agenticRuntime.SetAuditMode(agenticAuditMode)
	// Pre-warm the in-memory views so the first decision per tenant lands warm:
	// VK identity scopes, policy-target index, and the published policy + tool
	// tiering bundles.
	agenticVKResolver := agentic.NewVKResolver()
	if err := agenticVKResolver.PreWarm(ctx, s.Config.ConfigStore); err != nil {
		logger.Warn("agentic VK resolver pre-warm failed: " + err.Error())
	}
	agenticRuntime.SetVKResolver(agenticVKResolver)
	agenticPolicyTargets := agentic.NewPolicyTargetResolver()
	if err := agenticPolicyTargets.PreWarm(ctx, s.Config.ConfigStore); err != nil {
		logger.Warn("agentic policy-target pre-warm failed: " + err.Error())
	}
	agenticRuntime.SetPolicyTargetResolver(agenticPolicyTargets)
	prewarmAgenticRuntime(ctx, agenticRuntime, s.Config.ConfigStore)
	agenticSecurityHandler := handlers.NewAgenticSecurityHandler(s.Config.ConfigStore, agenticRuntime)

	// Going ahead with API handlers
	healthHandler.RegisterRoutes(s.Router, middlewares...)
	providerHandler.RegisterRoutes(s.Router, middlewares...)
	mcpHandler.RegisterRoutes(s.Router, middlewares...)
	configHandler.RegisterRoutes(s.Router, middlewares...)
	if pluginsHandler != nil {
		pluginsHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if sessionHandler != nil {
		sessionHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if legalHandler != nil {
		legalHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if workspaceHandler != nil {
		workspaceHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if promptsHandler != nil {
		promptsHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if auditLogsHandler != nil {
		auditLogsHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if guardrailsHandler != nil {
		guardrailsHandler.RegisterRoutes(s.Router, middlewares...)
		// Seed the deterministic default guardrail policy (PII + regex) for the
		// inference tenant at startup so the guardrails plugin enforces on the
		// FIRST request - tenantHasEnabledPolicies is true from t0 - and the
		// guardrail analytics populate without anyone opening the config page.
		// Idempotent and concurrency-safe; same partition the inference path and
		// the config page resolve, so one default policy serves all of them.
		guardrailsHandler.EnsureDefaultPolicyAtStartup(ctx)
	}
	if agenticSecurityHandler != nil {
		agenticSecurityHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if governanceHandler != nil {
		// Wire key health provider when load balancer is enabled
		if s.Client != nil {
			if tracker := s.Client.GetKeyLoadTracker(); tracker != nil {
				governanceHandler.SetKeyHealthProvider(func() []handlers.KeyHealthInfo {
					coreHealth := tracker.GetAllKeyHealth()
					result := make([]handlers.KeyHealthInfo, len(coreHealth))
					for i, h := range coreHealth {
						result[i] = handlers.KeyHealthInfo{
							KeyID:          h.KeyID,
							ActiveRequests: h.ActiveRequests,
							TotalRequests:  h.TotalRequests,
							TotalTokens:    h.TotalTokens,
							ErrorCount:     h.ErrorCount,
							CircuitState:   h.CircuitState,
							LastError:      h.LastError,
						}
					}
					return result
				})
			}
		}
		governanceHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if loggingHandler != nil {
		loggingHandler.RegisterRoutes(s.Router, middlewares...)
	}
	if s.WebSocketHandler != nil {
		s.WebSocketHandler.RegisterRoutes(s.Router, middlewares...)
	}
	// Register dev pprof handler only in dev mode
	if handlers.IsDevMode() {
		logger.Info("dev mode enabled, registering pprof endpoints")
		s.devPprofHandler = handlers.NewDevPprofHandler()
		s.devPprofHandler.RegisterRoutes(s.Router, middlewares...)
	}
	// Add Prometheus /metrics endpoint
	prometheusPlugin, err := lib.FindPluginAs[*telemetry.PrometheusPlugin](s.Config, telemetry.PluginName)
	if err == nil && prometheusPlugin.GetRegistry() != nil {
		// Use the plugin's dedicated registry if available
		metricsHandler := fasthttpadaptor.NewFastHTTPHandler(promhttp.HandlerFor(prometheusPlugin.GetRegistry(), promhttp.HandlerOpts{}))
		s.Router.GET("/metrics", lib.ChainMiddlewares(metricsHandler, middlewares...))
	} else {
		logger.Warn("prometheus plugin not found or registry is nil, skipping metrics endpoint")
	}
	// 404 handler
	s.Router.NotFound = func(ctx *fasthttp.RequestCtx) {
		handlers.SendError(ctx, fasthttp.StatusNotFound, "Route not found: "+string(ctx.Path()))
	}
	return nil
}

// agenticPrewarmReader is the slice of the configstore the agentic pre-warmer
// reads: every tenant's published policies + the tool tiering rows.
type agenticPrewarmReader interface {
	ListAgenticPolicies(ctx context.Context) ([]tables.TableAgenticPolicy, error)
	ListAgenticToolTiering(ctx context.Context) ([]tables.TableAgenticToolTiering, error)
}

// prewarmAgenticRuntime loads every tenant's published policies + tool tiering
// into the runtime so the very first decision after server start serves from a
// warm in-memory bundle. It is the OSS equivalent of the (premium) prewarm.go,
// kept here in the transport layer because the visual-definition → CompiledPolicy
// translator lives in the handlers package.
func prewarmAgenticRuntime(ctx context.Context, rt *agentic.Runtime, reader agenticPrewarmReader) {
	if rt == nil || reader == nil {
		return
	}
	// Tool tiering is shared across tenants (read-only); load it first.
	if tiers, err := reader.ListAgenticToolTiering(ctx); err == nil {
		tierMap := make(map[string]agentic.ToolTier, len(tiers))
		for _, t := range tiers {
			tierMap[t.ToolName] = agentic.ToolTier{
				Sensitivity:       t.Sensitivity,
				FailPosture:       t.FailPosture,
				RevocationPath:    t.RevocationPath,
				Obligations:       t.Obligations,
				Enforce:           t.Enforce,
				RecoveryCost:      t.RecoveryCost,
				ActionClass:       t.ActionClass,
				ArgsSchema:        t.ArgsSchema,
				IntegrityPosture:  agentic.NormalizePosture(t.IntegrityPosture),
				PinnedFingerprint: t.PinnedFingerprint,
			}
		}
		rt.LoadToolTiering(tierMap)
	}

	policies, err := reader.ListAgenticPolicies(ctx)
	if err != nil || len(policies) == 0 {
		return
	}
	byTenant := make(map[string][]*tables.TableAgenticPolicy)
	for i := range policies {
		row := &policies[i]
		if !row.Enabled || row.Status != tables.AgenticPolicyStatusPublished {
			continue
		}
		byTenant[row.TenantID] = append(byTenant[row.TenantID], row)
	}
	for tenantID, rows := range byTenant {
		set := agentic.PolicySet{}
		var snippets []string
		for _, row := range rows {
			c, regoSrc, ok := handlers.CompileAgenticPolicyRow(row)
			if !ok {
				continue
			}
			c.Tenant = row.TenantID
			c.Version = row.PolicyVersion
			c.Enabled = row.Enabled
			set.Policies = append(set.Policies, c)
			if row.PolicyVersion > set.Version {
				set.Version = row.PolicyVersion
			}
			if rg := strings.TrimSpace(regoSrc); rg != "" {
				snippets = append(snippets, rg)
			} else {
				snippets = append(snippets, c.CompileRego())
			}
		}
		if len(snippets) > 0 {
			set.Rego = agentic.CompileRegoModules(snippets)
		}
		rt.LoadPolicySet(tenantID, set)
	}
}

// RegisterUIRoutes registers the UI handler with the specified router
func (s *DeepIntShieldHTTPServer) RegisterUIRoutes(middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// WARNING: This UI handler needs to be registered after all the other handlers
	handlers.NewUIHandler(s.UIContent).RegisterRoutes(s.Router, middlewares...)
}

// GetAllRedactedKeys gets all redacted keys from the config store
func (s *DeepIntShieldHTTPServer) GetAllRedactedKeys(ctx context.Context, ids []string) []schemas.Key {
	if s.Config == nil || s.Config.ConfigStore == nil {
		return nil
	}
	redactedKeys, err := s.Config.ConfigStore.GetAllRedactedKeys(ctx, ids)
	if err != nil {
		logger.Error("failed to get all redacted keys: %v", err)
		return nil
	}
	return redactedKeys
}

// GetAllRedactedVirtualKeys gets all redacted virtual keys from the config store
func (s *DeepIntShieldHTTPServer) GetAllRedactedVirtualKeys(ctx context.Context, ids []string) []tables.TableVirtualKey {
	if s.Config == nil || s.Config.ConfigStore == nil {
		return nil
	}
	virtualKeys, err := s.Config.ConfigStore.GetRedactedVirtualKeys(ctx, ids)
	if err != nil {
		logger.Error("failed to get all redacted virtual keys: %v", err)
		return nil
	}
	return virtualKeys
}

// GetAllRedactedRoutingRules gets all redacted routing rules from the config store
func (s *DeepIntShieldHTTPServer) GetAllRedactedRoutingRules(ctx context.Context, ids []string) []tables.TableRoutingRule {
	if s.Config == nil || s.Config.ConfigStore == nil {
		return nil
	}
	routingRules, err := s.Config.ConfigStore.GetRedactedRoutingRules(ctx, ids)
	if err != nil {
		logger.Error("failed to get all redacted routing rules: %v", err)
		return nil
	}
	return routingRules
}

// PrepareCommonMiddlewares gets the common middlewares for the DeepIntShield HTTP server
func (s *DeepIntShieldHTTPServer) PrepareCommonMiddlewares() []schemas.DeepIntShieldHTTPMiddleware {
	commonMiddlewares := []schemas.DeepIntShieldHTTPMiddleware{}
	// Preparing middlewares
	// Initializing prometheus plugin
	prometheusPlugin, err := lib.FindPluginAs[*telemetry.PrometheusPlugin](s.Config, telemetry.PluginName)
	if err == nil {
		commonMiddlewares = append(commonMiddlewares, prometheusPlugin.HTTPMiddleware)
	} else {
		logger.Warn("prometheus plugin not found, skipping telemetry middleware")
	}
	if auditStore, ok := s.Config.LogsStore.(logstore.AuditLogStore); ok {
		commonMiddlewares = append(commonMiddlewares, handlers.AuditLogsMiddleware(auditStore, s.Config.ConfigStore))
	}
	return commonMiddlewares
}

// Bootstrap initializes the DeepIntShield HTTP server with all necessary components.
// It:
// 1. Initializes Prometheus collectors for monitoring
// 2. Reads and parses configuration from the specified config file
// 3. Initializes the DeepIntShield client with the configuration
// 4. Sets up HTTP routes for text and chat completions
//
// The server exposes the following endpoints:
//   - POST /v1/text/completions: For text completion requests
//   - POST /v1/chat/completions: For chat completion requests
//   - GET /metrics: For Prometheus metrics
func (s *DeepIntShieldHTTPServer) Bootstrap(ctx context.Context) error {
	var err error
	s.Ctx, s.cancel = schemas.NewDeepIntShieldContextWithCancel(ctx)
	handlers.SetVersion(s.Version)
	configDir := GetDefaultConfigDir(s.AppDir)

	// Ensure app directory exists
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create app directory %s: %v", configDir, err)
	}
	// Initialize high-performance configuration store with dedicated database
	s.Config, err = lib.LoadConfig(ctx, configDir)
	if err != nil {
		return fmt.Errorf("failed to load config %v", err)
	}
	if s.Config.KVStore != nil {
		integrations.RegisterKVDecoders(s.Config.KVStore)
	}
	// Initialize WebSocket handler early so plugins can wire event broadcasters during Init.
	// Log callbacks are registered later in RegisterAPIRoutes when logging plugin is available.
	s.WebSocketHandler = handlers.NewWebSocketHandler(s.Ctx, s.Config.ClientConfig.AllowedOrigins)
	s.Config.EventBroadcaster = s.WebSocketHandler.BroadcastEvent
	// Initializing plugin loader
	s.Config.PluginLoader = &dynamicPlugins.SharedObjectPluginLoader{}
	// Initialize log retention cleaner if log store is configured
	if s.Config.LogsStore != nil {
		// If log retention days remains 0, then we wont be initializing the log retention cleaner
		logRetentionDays := 0
		if s.Config.ConfigStore != nil {
			// Get logs store config from config store
			clientConfig, err := s.Config.ConfigStore.GetClientConfig(ctx)
			if err != nil {
				logger.Warn("failed to get logs store config: %v", err)
				// So we wont be initializing the log retention cleaner
			}
			if clientConfig != nil {
				logRetentionDays = clientConfig.LogRetentionDays
			}
		} else {
			// We will check if the config file has the log retention days set
			logRetentionDays = s.Config.ClientConfig.LogRetentionDays
		}
		logger.Info("log retention days: %d", logRetentionDays)
		if logRetentionDays > 0 {
			// Type assert to get RDBLogStore (which implements LogRetentionManager)
			if rdbStore, ok := s.Config.LogsStore.(logstore.LogRetentionManager); ok {
				cleanerConfig := logstore.CleanerConfig{
					RetentionDays: logRetentionDays,
				}
				s.LogsCleaner = logstore.NewLogsCleaner(rdbStore, cleanerConfig, logger)
				s.LogsCleaner.StartCleanupRoutine()
				logger.Info("log retention cleaner initialized with %d days retention",
					logRetentionDays)
			}
		}
	}
	// Initialize async job cleaner if log store is configured
	if s.Config.LogsStore != nil {
		s.AsyncJobCleaner = logstore.NewAsyncJobCleaner(s.Config.LogsStore, logger)
		s.AsyncJobCleaner.StartCleanupRoutine()
	}
	// Load all plugins
	if err := s.LoadPlugins(ctx); err != nil {
		return fmt.Errorf("failed to instantiate plugins: %v", err)
	}

	// Initialize async job executor (requires LogsStore + governance plugin)
	if s.Config.LogsStore != nil {
		governancePlugin, govErr := lib.FindPluginAs[governance.BaseGovernancePlugin](s.Config, s.getGovernancePluginName())
		if govErr == nil {
			s.Config.AsyncJobExecutor = logstore.NewAsyncJobExecutor(s.Config.LogsStore, governancePlugin.GetGovernanceStore(), logger)
			logger.Info("async job executor initialized")
		}
	}

	tableMCPConfig := s.Config.MCPConfig
	var mcpConfig *schemas.MCPConfig
	if tableMCPConfig != nil {
		mcpConfig = s.Config.MCPConfig
		if mcpConfig != nil {
			mcpConfig.FetchNewRequestIDFunc = func(ctx *schemas.DeepIntShieldContext) string {
				return uuid.New().String()
			}
		}
	}
	// Initialize deepintshield client
	// Create account backed by the high-performance store (all processing is done in LoadFromDatabase)
	// The account interface now benefits from ultra-fast config access times via in-memory storage
	account := lib.NewBaseAccount(s.Config)
	// Configure key selector: when load balancer is enabled, use strategy-aware selector;
	// otherwise use the default WeightedRandomKeySelector (no wrapper, no overhead).
	var keySelector schemas.KeySelector
	var keyLoadTracker *deepintshield.KeyLoadTracker
	if s.Config.ClientConfig.LoadBalancerEnabled {
		keyLoadTracker = deepintshield.NewKeyLoadTracker()
		strategySelector := deepintshield.NewStrategyAwareKeySelector(keyLoadTracker)
		keySelector = strategySelector.KeySelectorFunc()
		logger.Info("LLM Load Balancer enabled - using strategy-aware key selector")
	}

	s.Client, err = deepintshield.Init(ctx, schemas.DeepIntShieldConfig{
		Account:            account,
		InitialPoolSize:    s.Config.ClientConfig.InitialPoolSize,
		DropExcessRequests: s.Config.ClientConfig.DropExcessRequests,
		LLMPlugins:         s.Config.GetLoadedLLMPlugins(),
		MCPPlugins:         s.Config.GetLoadedMCPPlugins(),
		MCPConfig:          mcpConfig,
		Logger:             logger,
		KVStore:            s.Config.KVStore,
		KeySelector:        keySelector,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize deepintshield: %v", err)
	}

	// Set the load tracker on the client (nil when feature is disabled - all tracker calls are no-ops)
	if keyLoadTracker != nil {
		s.Client.SetKeyLoadTracker(keyLoadTracker)
	}

	logger.Info("deepintshield client initialized")
	// Sync plugin execution order from config to core (defensive - Init receives sorted list,
	// but this ensures order consistency if the loading path changes in the future)
	s.Client.ReorderPlugins(s.Config.GetPluginOrder())
	// List all models and add to model catalog with per-provider status tracking
	logger.Info("listing all models and adding to model catalog")
	if s.Config.ModelCatalog != nil {
		// Fetching keys for all providers and allowed models first
		// Based on allowed models we will set the data in the model catalog
		for provider, providerConfig := range s.Config.Providers {
			bfCtx := schemas.NewDeepIntShieldContext(ctx, time.Now().Add(15*time.Second))
			bfCtx.SetValue(schemas.DeepIntShieldContextKeySkipPluginPipeline, true)

			modelData, listModelsErr := s.Client.ListModelsRequest(bfCtx, &schemas.DeepIntShieldListModelsRequest{
				Provider: provider,
			})
			if modelData != nil && len(modelData.KeyStatuses) > 0 && s.Config.ConfigStore != nil {
				s.updateKeyStatus(ctx, modelData.KeyStatuses)
			}
			if listModelsErr != nil {
				if len(listModelsErr.ExtraFields.KeyStatuses) > 0 && s.Config.ConfigStore != nil {
					s.updateKeyStatus(ctx, listModelsErr.ExtraFields.KeyStatuses)
				}
				logger.Error("failed to list models for provider %s: %v: falling back onto the static datasheet", provider, deepintshield.GetErrorMessage(listModelsErr))
			}
			allowedModels := make([]schemas.Model, 0)
			for _, key := range providerConfig.Keys {
				for _, model := range key.Models {
					allowedModels = append(allowedModels, schemas.Model{
						ID: string(provider) + "/" + model,
					})
				}
			}
			s.Config.ModelCatalog.UpsertModelDataForProvider(provider, modelData, allowedModels)
			unfilteredModelData, listModelsErr := s.Client.ListModelsRequest(bfCtx, &schemas.DeepIntShieldListModelsRequest{
				Provider:   provider,
				Unfiltered: true,
			})
			if listModelsErr != nil {
				logger.Error("failed to list unfiltered models for provider %s: %v: falling back onto the static datasheet", provider, deepintshield.GetErrorMessage(listModelsErr))
			} else {
				s.Config.ModelCatalog.UpsertUnfilteredModelDataForProvider(provider, unfilteredModelData)
			}
			bfCtx.Cancel()
		}
	}

	logger.Info("models added to catalog")
	s.Config.SetDeepIntShieldClient(s.Client)
	// Initialize routes
	s.Router = router.New()
	commonMiddlewares := s.PrepareCommonMiddlewares()
	apiMiddlewares := commonMiddlewares
	inferenceMiddlewares := commonMiddlewares
	if s.Config.ConfigStore == nil {
		logger.Error("auth middleware requires config store, skipping auth middleware initialization")
	} else {
		s.WSTicketStore = handlers.NewWSTicketStore()
		s.AuthMiddleware, err = handlers.InitAuthMiddleware(s.Config.ConfigStore, s.WSTicketStore)
		if err != nil {
			s.WSTicketStore.Stop()
			s.WSTicketStore = nil
			return fmt.Errorf("failed to initialize auth middleware: %v", err)
		}
		if ctx.Value(schemas.DeepIntShieldContextKeyIsEnterprise) == nil {
			apiMiddlewares = append(apiMiddlewares, s.AuthMiddleware.APIMiddleware())
		}
	}
	// Register routes
	err = s.RegisterAPIRoutes(s.Ctx, s, apiMiddlewares...)
	if err != nil {
		if s.WSTicketStore != nil {
			s.WSTicketStore.Stop()
			s.WSTicketStore = nil
		}
		return fmt.Errorf("failed to initialize routes: %v", err)
	}
	// Registering inference routes
	if ctx.Value(schemas.DeepIntShieldContextKeyIsEnterprise) == nil && s.AuthMiddleware != nil {
		inferenceMiddlewares = append(inferenceMiddlewares, s.AuthMiddleware.InferenceMiddleware())
	}
	// Registering inference middlewares
	inferenceMiddlewares = append([]schemas.DeepIntShieldHTTPMiddleware{handlers.TransportInterceptorMiddleware(s.Config)}, inferenceMiddlewares...)
	// Curating observability plugins
	observabilityPlugins := s.CollectObservabilityPlugins()
	// This enables the central streaming accumulator for both use cases
	// Initializing tracer with embedded streaming accumulator
	traceStore := tracing.NewTraceStore(60*time.Minute, logger)
	tracer := tracing.NewTracer(traceStore, s.Config.ModelCatalog, logger)
	s.Client.SetTracer(tracer)
	// Always add tracing middleware when tracer is enabled - it creates traces and sets traceID in context
	// The observability plugins are optional (can be empty if only logging is enabled)
	s.TracingMiddleware = handlers.NewTracingMiddleware(tracer, observabilityPlugins)
	inferenceMiddlewares = append([]schemas.DeepIntShieldHTTPMiddleware{s.TracingMiddleware.Middleware()}, inferenceMiddlewares...)
	err = s.RegisterInferenceRoutes(s.Ctx, inferenceMiddlewares...)
	if err != nil {
		if s.WSTicketStore != nil {
			s.WSTicketStore.Stop()
			s.WSTicketStore = nil
		}
		return fmt.Errorf("failed to initialize inference routes: %v", err)
	}

	// Wire the integration cache/usage hooks across the compat surfaces. In
	// the open-source build these are no-op closures (the agentic runtime
	// that consumed them is part of the commercial build), but the wiring is
	// retained so the integration plumbing stays intact.
	if s.IntegrationHandler != nil && s.CompletionHandler != nil {
		s.IntegrationHandler.SetAgenticCacheBridgeHook(s.CompletionHandler.AgenticCacheBridgeHook())
		s.IntegrationHandler.SetAgenticLLMUsageHook(s.CompletionHandler.AgenticLLMUsageHook())
	}

	// Register UI handler
	s.RegisterUIRoutes()
	// Prefilter sits as the outermost middleware (after SecurityHeaders so
	// even dropped responses get hardened headers). Rejects oversize bodies,
	// banned UAs, path-injection probes, malformed JSON on /v1/*, and IP
	// burst floods - all without entering the plugin pipeline.
	prefilterCfg := handlers.LoadPrefilterConfig(s.Config.ClientConfig.MaxRequestBodySizeMB * 1024 * 1024)
	// Create fasthttp server instance
	s.Server = &fasthttp.Server{
		Handler: handlers.SecurityHeadersMiddleware()(
			handlers.PrefilterMiddleware(prefilterCfg)(
				handlers.CorsMiddleware(s.Config)(
					handlers.RequestDecompressionMiddleware(s.Config)(s.Router.Handler),
				),
			),
		),
		MaxRequestBodySize: s.Config.ClientConfig.MaxRequestBodySizeMB * 1024 * 1024,
		ReadBufferSize:     1024 * 64, // 64kb
	}
	return nil
}

// Start starts the HTTP server at the specified host and port
// Also watches signals and errors
func (s *DeepIntShieldHTTPServer) Start() error {
	// Printing plugin status in a table
	for _, pluginStatus := range s.Config.GetPluginStatus() {
		logger.Info("plugin status: %s - %s", pluginStatus.Name, pluginStatus.Status)
	}
	// Per-(provider, region) connection prewarm. Fires HEAD requests against
	// every known provider base URL at startup so the first real inference
	// doesn't pay for DNS resolve + TCP+TLS handshake (~100-300ms cold).
	// Opt out: DEEPINTSHIELD_DISABLE_PREWARM=true.
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("DEEPINTSHIELD_DISABLE_PREWARM")), "true") {
		go s.runProviderPrewarm()
	}
	// Create channels for signal and error handling
	sigChan := make(chan os.Signal, 1)
	errChan := make(chan error, 1)
	// Watching for signals
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	// Start server in a goroutine
	serverAddr := net.JoinHostPort(s.Host, s.Port)
	ln, err := net.Listen("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener on %s: %v", serverAddr, err)
	}
	go func() {
		logger.Info("successfully started deepintshield, serving UI on http://%s:%s", s.Host, s.Port)
		if err := s.Server.Serve(ln); err != nil {
			errChan <- err
		}
	}()
	// Wait for either termination signal or server error
	select {
	case sig := <-sigChan:
		logger.Info("received signal %v, initiating graceful shutdown...", sig)
		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Perform graceful shutdown
		if err := s.Server.Shutdown(); err != nil {
			logger.Error("error during graceful shutdown: %v", err)
		} else {
			logger.Info("server gracefully shutdown")
		}
		// Cancelling main context
		if s.cancel != nil {
			s.cancel()
		}
		// Wait for shutdown to complete or timeout
		done := make(chan struct{})
		go func() {
			defer close(done)
			logger.Info("shutting down deepintshield client...")
			s.Client.Shutdown()
			logger.Info("deepintshield client shutdown completed")
			logger.Info("cleaning up storage engines...")
			// Cleanup server-specific components
			if s.LogsCleaner != nil {
				logger.Info("stopping log retention cleaner...")
				s.LogsCleaner.StopCleanupRoutine()
			}
			if s.AsyncJobCleaner != nil {
				logger.Info("stopping async job cleaner...")
				s.AsyncJobCleaner.StopCleanupRoutine()
			}
			if s.WSTicketStore != nil {
				logger.Info("stopping ws ticket store...")
				s.WSTicketStore.Stop()
			}
			if s.devPprofHandler != nil {
				logger.Info("stopping dev pprof handler...")
				s.devPprofHandler.Cleanup()
			}
			if s.wsPool != nil {
				logger.Info("closing websocket connection pool...")
				s.wsPool.Close()
			}
			// Cleanup Config and all its background components
			if s.Config != nil {
				s.Config.Close(shutdownCtx)
			}
			logger.Info("storage engines cleanup completed")
		}()
		select {
		case <-done:
			logger.Info("cleanup completed")
		case <-shutdownCtx.Done():
			logger.Warn("cleanup timed out after 30 seconds")
		}

	case err := <-errChan:
		if s.wsPool != nil {
			s.wsPool.Close()
		}
		return err
	}
	return nil
}
