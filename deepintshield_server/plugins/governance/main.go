// Package governance provides comprehensive governance plugin for DeepIntShield
package governance

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/network"
	"github.com/deepint-shield/ai-security/core/providers/gemini"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/mcpcatalog"
	"github.com/deepint-shield/ai-security/framework/modelcatalog"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/google/uuid"
)

// PluginName is the name of the governance plugin
const PluginName = "governance"

const (
	governanceRejectedContextKey    schemas.DeepIntShieldContextKey = "bf-governance-rejected"
	governanceIsCacheReadContextKey schemas.DeepIntShieldContextKey = "bf-governance-is-cache-read"
	governanceIsBatchContextKey     schemas.DeepIntShieldContextKey = "bf-governance-is-batch"

	VirtualKeyPrefix = "sk-bf-"
)

// Config is the configuration for the governance plugin
type Config struct {
	IsVkMandatory   *bool     `json:"is_vk_mandatory"`
	RequiredHeaders *[]string `json:"required_headers"` // Pointer to live config slice; changes are reflected immediately without restart
	// IsMCPMandatory enforces that agent-to-tool traffic flows through
	// the DeepintShield MCP gateway (`deepintshield_server/core/mcp/`)
	// rather than direct HTTP-to-HTTP between agents. Closes the
	// residual A-to-A gap surfaced in the initial security review (see
	// COMPLIANCE_GAP_ANALYSIS.md §3 + Critical Gap #10).
	//
	// Today this field is read by the plugin runtime but the deny path
	// is not yet wired into PreLLMHook - enforcement requires reliably
	// detecting "is this call MCP-routed?" from the request context,
	// which needs an MCP-marker context key set by the MCP transport
	// path. Tracked as Phase 2 follow-up of SSO_IMPLEMENTATION_PLAN.md.
	IsMCPMandatory *bool `json:"is_mcp_mandatory,omitempty"`
}

type InMemoryStore interface {
	GetConfiguredProviders() map[schemas.ModelProvider]configstore.ProviderConfig
}

type BaseGovernancePlugin interface {
	GetName() string
	HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error)
	HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error
	PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error)
	PostLLMHook(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, err *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error)
	PreMCPHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, error)
	PostMCPHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError, error)
	Cleanup() error
	GetGovernanceStore() GovernanceStore
}

// GovernancePlugin implements the main governance plugin with hierarchical budget system
type GovernancePlugin struct {
	ctx         context.Context
	cancelFunc  context.CancelFunc
	wg          sync.WaitGroup // Track active goroutines
	cleanupOnce sync.Once      // Ensure cleanup happens only once

	// Core components with clear separation of concerns
	store    GovernanceStore // Pure data access layer
	resolver *BudgetResolver // Pure decision engine for hierarchical governance
	tracker  *UsageTracker   // Business logic owner (updates, resets, persistence)
	engine   *RoutingEngine  // Routing engine for dynamic routing

	// Dependencies
	configStore  configstore.ConfigStore
	modelCatalog *modelcatalog.ModelCatalog
	mcpCatalog   *mcpcatalog.MCPCatalog
	logger       schemas.Logger

	// Transport dependencies
	inMemoryStore InMemoryStore

	cfgMutex sync.RWMutex

	isVkMandatory   *bool
	requiredHeaders *[]string // pointer to live config slice; lowercased at check time
}

// Init initializes and returns a governance plugin instance.
//
// It wires the core components (store, resolver, tracker), performs a best-effort
// startup reset of expired limits when a persistent `configstore.ConfigStore` is
// provided, and establishes a cancellable plugin context used by background work.
//
// Behavior and defaults:
//   - Enables all governance features with optimized defaults.
//   - If `configStore` is nil, the plugin will use an in-memory LocalGovernanceStore
//     (no persistence). Init constructs a LocalGovernanceStore internally when
//     configStore is nil.
//   - If `modelCatalog` is nil, cost calculation is skipped.
//   - `config.IsVkMandatory` controls whether `x-bf-vk` is required in PreLLMHook.
//   - `inMemoryStore` is used by TransportInterceptor to validate configured providers
//     and build provider-prefixed models; it may be nil. When nil, transport-level
//     provider validation/routing is skipped and existing model strings are left
//     unchanged. This is safe and recommended when using the plugin directly from
//     the Go SDK without the HTTP transport.
//
// Parameters:
//   - ctx: base context for the plugin; a child context with cancel is created.
//   - config: plugin flags; may be nil.
//   - logger: logger used by all subcomponents.
//   - configStore: configuration store used for persistence; may be nil.
//   - governanceConfig: initial/seed governance configuration for the store.
//   - modelCatalog: optional model catalog to compute request cost.
//   - inMemoryStore: provider registry used for routing/validation in transports.
//
// Returns:
//   - *GovernancePlugin on success.
//   - error if the governance store fails to initialize.
//
// Side effects:
//   - Logs warnings when optional dependencies are missing.
//   - May perform startup resets via the usage tracker when `configStore` is non-nil.
//
// Alternative entry point:
//   - Use InitFromStore to inject a custom GovernanceStore implementation instead
//     of constructing a LocalGovernanceStore internally.
func Init(
	ctx context.Context,
	config *Config,
	logger schemas.Logger,
	configStore configstore.ConfigStore,
	governanceConfig *configstore.GovernanceConfig,
	modelCatalog *modelcatalog.ModelCatalog,
	mcpCatalog *mcpcatalog.MCPCatalog,
	inMemoryStore InMemoryStore,
) (*GovernancePlugin, error) {
	if configStore == nil {
		logger.Warn("governance plugin requires config store to persist data, running in memory only mode")
	}
	if modelCatalog == nil {
		logger.Warn("governance plugin requires model catalog to calculate cost, all LLM cost calculations will be skipped.")
	}
	if mcpCatalog == nil {
		logger.Warn("governance plugin requires MCP catalog to calculate cost, all MCP cost calculations will be skipped.")
	}

	// Handle nil config - use safe defaults
	var isVkMandatory *bool
	var requiredHeaders *[]string
	if config != nil {
		isVkMandatory = config.IsVkMandatory
		requiredHeaders = config.RequiredHeaders
	}

	governanceStore, err := NewLocalGovernanceStore(ctx, logger, configStore, governanceConfig, modelCatalog)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize governance store: %w", err)
	}
	// Initialize components in dependency order with fixed, optimal settings
	// Resolver (pure decision engine for hierarchical governance, depends only on store)
	resolver := NewBudgetResolver(governanceStore, modelCatalog, logger)

	// 3. Tracker (business logic owner, depends on store and resolver)
	tracker := NewUsageTracker(ctx, governanceStore, resolver, configStore, logger)

	// 4. Perform startup reset check for any expired limits from downtime
	// Use distributed lock to prevent race condition when multiple instances boot simultaneously
	if configStore != nil {
		lockManager := configstore.NewDistributedLockManager(configStore, logger, configstore.WithDefaultTTL(30*time.Second))
		lock, err := lockManager.NewLock("governance_startup_reset")
		if err != nil {
			logger.Warn("failed to create governance startup reset lock: %v", err)
		} else {
			// Acquire the lock
			lockAcquired := true
			if err := lock.LockWithRetry(ctx, 10); err != nil {
				logger.Warn("failed to acquire governance startup reset lock, skipping startup reset: %v", err)
				lockAcquired = false
			}
			// Only run startup resets if we successfully acquired the lock
			if lockAcquired {
				defer func() {
					if err := lock.Unlock(ctx); err != nil && !errors.Is(err, configstore.ErrLockNotHeld) {
						logger.Warn("failed to release governance startup reset lock: %v", err)
					}
				}()
				if err := tracker.PerformStartupResets(ctx); err != nil {
					logger.Warn("startup reset failed: %v", err)
					// Continue initialization even if startup reset fails (non-critical)
				}
			}
		}
	}

	// 5. Routing engine (dynamically routing requests based on routing rules)
	engine, err := NewRoutingEngine(governanceStore, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize routing engine: %w", err)
	}

	ctx, cancelFunc := context.WithCancel(ctx)
	plugin := &GovernancePlugin{
		ctx:             ctx,
		cancelFunc:      cancelFunc,
		store:           governanceStore,
		resolver:        resolver,
		tracker:         tracker,
		engine:          engine,
		configStore:     configStore,
		modelCatalog:    modelCatalog,
		mcpCatalog:      mcpCatalog,
		logger:          logger,
		isVkMandatory:   isVkMandatory,
		cfgMutex:        sync.RWMutex{},
		requiredHeaders: requiredHeaders,
		inMemoryStore:   inMemoryStore,
	}
	return plugin, nil
}

// InitFromStore initializes and returns a governance plugin instance with a custom store.
//
// This constructor allows providing a custom GovernanceStore implementation instead of
// creating a new LocalGovernanceStore. Use this when you need to:
//   - Inject a custom store implementation for testing
//   - Use a pre-configured store instance
//   - Integrate with non-standard storage backends
//
// Parameters are the same as Init, except governanceConfig is replaced by governanceStore.
// The governanceStore must not be nil, or an error is returned.
//
// See Init documentation for details on other parameters and behavior.
func InitFromStore(
	ctx context.Context,
	config *Config,
	logger schemas.Logger,
	governanceStore GovernanceStore,
	configStore configstore.ConfigStore,
	modelCatalog *modelcatalog.ModelCatalog,
	mcpCatalog *mcpcatalog.MCPCatalog,
	inMemoryStore InMemoryStore,
) (*GovernancePlugin, error) {
	if configStore == nil {
		logger.Warn("governance plugin requires config store to persist data, running in memory only mode")
	}
	if modelCatalog == nil {
		logger.Warn("governance plugin requires model catalog to calculate cost, all cost calculations will be skipped.")
	}
	if mcpCatalog == nil {
		logger.Warn("governance plugin requires MCP catalog to calculate cost, all MCP cost calculations will be skipped.")
	}
	if governanceStore == nil {
		return nil, fmt.Errorf("governance store is nil")
	}
	// Handle nil config - use safe defaults
	var isVkMandatory *bool
	var requiredHeaders *[]string
	if config != nil {
		isVkMandatory = config.IsVkMandatory
		requiredHeaders = config.RequiredHeaders
	}
	resolver := NewBudgetResolver(governanceStore, modelCatalog, logger)
	tracker := NewUsageTracker(ctx, governanceStore, resolver, configStore, logger)
	engine, err := NewRoutingEngine(governanceStore, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize routing engine: %w", err)
	}
	// Perform startup reset check for any expired limits from downtime
	// Use distributed lock to prevent race condition when multiple instances boot simultaneously
	if configStore != nil {
		lockManager := configstore.NewDistributedLockManager(configStore, logger, configstore.WithDefaultTTL(30*time.Second))
		lock, err := lockManager.NewLock("governance_startup_reset")
		if err != nil {
			logger.Warn("failed to create governance startup reset lock: %v", err)
		} else if err := lock.Lock(ctx); err != nil {
			logger.Warn("failed to acquire governance startup reset lock, skipping startup reset: %v", err)
		} else {
			defer lock.Unlock(ctx)
			if err := tracker.PerformStartupResets(ctx); err != nil {
				logger.Warn("startup reset failed: %v", err)
				// Continue initialization even if startup reset fails (non-critical)
			}
		}
	}
	ctx, cancelFunc := context.WithCancel(ctx)
	plugin := &GovernancePlugin{
		ctx:             ctx,
		cancelFunc:      cancelFunc,
		store:           governanceStore,
		resolver:        resolver,
		tracker:         tracker,
		engine:          engine,
		configStore:     configStore,
		modelCatalog:    modelCatalog,
		mcpCatalog:      mcpCatalog,
		logger:          logger,
		inMemoryStore:   inMemoryStore,
		isVkMandatory:   isVkMandatory,
		cfgMutex:        sync.RWMutex{},
		requiredHeaders: requiredHeaders,
	}
	return plugin, nil
}

// GetName returns the name of the plugin
func (p *GovernancePlugin) GetName() string {
	return PluginName
}

// UpdateEnforceAuthOnInference updates the enforce auth on inference config
func (p *GovernancePlugin) UpdateEnforceAuthOnInference(enforceAuthOnInference bool) {
	p.cfgMutex.Lock()
	defer p.cfgMutex.Unlock()
	p.isVkMandatory = deepintshield.Ptr(enforceAuthOnInference)
}

// HTTPTransportPreHook intercepts requests before they are processed (governance decision point)
// It modifies the request in-place and returns nil to continue, or an HTTPResponse to short-circuit.
// Optimized to skip unnecessary operations: only unmarshals/marshals when needed
func (p *GovernancePlugin) HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	virtualKeyValue := parseVirtualKeyFromHTTPRequest(req)
	hasRoutingRules := p.store.HasRoutingRules(ctx)

	// If no virtual key and no routing rules configured, skip all processing
	if virtualKeyValue == nil && !hasRoutingRules {
		return nil, nil
	}

	// If no body, check if large payload mode is active for read-only governance
	if len(req.Body) == 0 {
		isLargePayload, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool)
		if !isLargePayload {
			return nil, nil
		}
		return p.governLargePayload(ctx, req, virtualKeyValue, hasRoutingRules)
	}

	// Only unmarshal if we have VK or routing rules
	var payload map[string]any
	var virtualKey *configstoreTables.TableVirtualKey
	var ok bool
	var needsMarshal bool

	contentType := req.CaseInsensitiveHeaderLookup("Content-Type")
	isMultipart := strings.HasPrefix(strings.ToLower(contentType), "multipart/form-data")

	var err error
	if isMultipart {
		payload, err = network.ParseMultipartFormFields(contentType, req.Body)
		if err != nil {
			p.logger.Warn("failed to parse multipart form in governance plugin: %v", err)
			return nil, nil
		}
	} else {
		err = sonic.Unmarshal(req.Body, &payload)
		if err != nil {
			p.logger.Error("failed to unmarshal request body: %v", err)
			return nil, nil
		}
	}

	// Process virtual key if provided
	if virtualKeyValue != nil {
		virtualKey, ok = p.store.GetVirtualKey(ctx, *virtualKeyValue)
		if !ok || virtualKey == nil || !virtualKey.IsActive {
			return nil, nil
		}
		if ctx != nil && virtualKey.TenantID != "" && ctx.Value(schemas.DeepIntShieldContextKeyTenantID) == nil {
			ctx.SetValue(schemas.DeepIntShieldContextKeyTenantID, virtualKey.TenantID)
		}
	}

	//1. Apply routing rules only if we have rules or matched decision
	var routingDecision *RoutingDecision
	if hasRoutingRules {
		var err error
		payload, routingDecision, err = p.applyRoutingRules(ctx, req, payload, virtualKey)
		if err != nil {
			return nil, err
		}
		// Mark for marshal if a routing rule matched
		if routingDecision != nil {
			needsMarshal = true
		}
	}

	// Process virtual key if provided
	if virtualKey != nil {
		//2. Load balance provider
		payload, err = p.loadBalanceProvider(ctx, req, payload, virtualKey)
		if err != nil {
			return nil, err
		}
		//3. Add MCP tools
		headers, err := p.addMCPIncludeTools(nil, virtualKey)
		if err != nil {
			p.logger.Error("failed to add MCP include tools: %v", err)
			return nil, nil
		}
		for header, value := range headers {
			req.Headers[header] = value
		}
		needsMarshal = true
	}

	// Only marshal if something changed (VK processing or routing decision matched)
	if needsMarshal {
		if err := network.SerializePayloadToRequest(req, payload, isMultipart, contentType); err != nil {
			p.logger.Error("failed to serialize request body in governance plugin: %v", err)
			return nil, nil
		}
	}

	return nil, nil
}

// governLargePayload handles read-only governance for large payload requests.
// The request body is streaming and cannot be modified, so we build a synthetic payload
// from pre-extracted metadata and run VK validation, routing rules, and load balancing.
// Any model changes are propagated via the metadata in context (not body rewriting).
func (p *GovernancePlugin) governLargePayload(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, virtualKeyValue *string, hasRoutingRules bool) (*schemas.HTTPResponse, error) {
	metadata, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMetadata).(*schemas.LargePayloadMetadata)
	if metadata == nil || metadata.Model == "" {
		return nil, nil
	}

	// Build synthetic payload from metadata - only the model field is needed
	payload := map[string]any{
		"model": metadata.Model,
	}
	originalModel := metadata.Model

	// Process virtual key if provided
	var virtualKey *configstoreTables.TableVirtualKey
	if virtualKeyValue != nil {
		vk, ok := p.store.GetVirtualKey(ctx, *virtualKeyValue)
		if !ok || vk == nil || !vk.IsActive {
			return nil, nil
		}
		virtualKey = vk
		if ctx != nil && virtualKey.TenantID != "" && ctx.Value(schemas.DeepIntShieldContextKeyTenantID) == nil {
			ctx.SetValue(schemas.DeepIntShieldContextKeyTenantID, virtualKey.TenantID)
		}
	}

	// Apply routing rules (read-only: decisions still affect downstream evaluation)
	if hasRoutingRules {
		var err error
		payload, _, err = p.applyRoutingRules(ctx, req, payload, virtualKey)
		if err != nil {
			return nil, err
		}
	}

	// Process virtual key: load balance + MCP tool headers
	if virtualKey != nil {
		var err error
		payload, err = p.loadBalanceProvider(ctx, req, payload, virtualKey)
		if err != nil {
			return nil, err
		}
		// MCP tool headers - header-only, no body needed
		headers, err := p.addMCPIncludeTools(nil, virtualKey)
		if err != nil {
			p.logger.Error("failed to add MCP include tools: %v", err)
			return nil, nil
		}
		for header, value := range headers {
			req.Headers[header] = value
		}
	}

	// Propagate model changes to metadata so downstream hydration picks up
	// the load-balanced/routed model (e.g., provider prefix added by LB).
	if newModel, ok := payload["model"].(string); ok && newModel != originalModel {
		metadata.Model = newModel
	}

	// No body serialization - large payload body streams through unchanged
	return nil, nil
}

// HTTPTransportPostHook intercepts requests after they are processed (governance decision point)
// It modifies the response in-place and returns nil to continue
func (p *GovernancePlugin) HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	return nil
}

// HTTPTransportStreamChunkHook passes through streaming chunks unchanged
func (p *GovernancePlugin) HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, chunk *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	return chunk, nil
}

// loadBalanceProvider loads balances the provider for the request
// Parameters:
//   - req: The HTTP request
//   - body: The request body
//   - virtualKey: The virtual key configuration
//
// Returns:
//   - map[string]any: The updated request body
//   - error: Any error that occurred during processing
func (p *GovernancePlugin) loadBalanceProvider(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, body map[string]any, virtualKey *configstoreTables.TableVirtualKey) (map[string]any, error) {
	// Check if the request has a model field
	modelValue, hasModel := body["model"]
	isGeminiPath := strings.Contains(req.Path, "/genai")
	isBedrockPath := strings.Contains(req.Path, "/bedrock")
	if !hasModel {
		// For genai integration, model is present in URL path instead of the request body
		if isGeminiPath {
			modelValue = req.CaseInsensitivePathParamLookup("model")
		} else if isBedrockPath {
			// For bedrock integration, model is present in URL path as modelId
			rawModelID := req.CaseInsensitivePathParamLookup("modelId")
			if rawModelID == "" {
				return body, nil
			}
			// URL-decode the modelId (Bedrock model IDs may be URL-encoded, e.g. anthropic%2Fclaude-3-5-sonnet)
			decoded, err := url.PathUnescape(rawModelID)
			if err != nil {
				decoded = rawModelID
			}
			modelValue = decoded
		} else {
			return body, nil
		}
	}
	modelStr, ok := modelValue.(string)
	if !ok || modelStr == "" {
		return body, nil
	}
	var genaiRequestSuffix string
	// Remove Google GenAI API endpoint suffixes if present
	if isGeminiPath {
		for _, sfx := range gemini.GeminiRequestSuffixPaths {
			if before, ok := strings.CutSuffix(modelStr, sfx); ok {
				modelStr = before
				genaiRequestSuffix = sfx
				break
			}
		}
	}
	// Check if model already has provider prefix (contains "/")
	if strings.Contains(modelStr, "/") {
		provider, _ := schemas.ParseModelString(modelStr, "")
		// Checking valid provider when store is available; if store is nil,
		// assume the prefixed model should be left unchanged.
		if p.inMemoryStore != nil {
			if _, ok := p.inMemoryStore.GetConfiguredProviders()[provider]; ok {
				return body, nil
			}
		} else {
			return body, nil
		}
	}

	ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Loading balance provider for model %s", modelStr))

	// Get provider configs for this virtual key
	providerConfigs := virtualKey.ProviderConfigs
	if len(providerConfigs) == 0 {
		ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("No provider configs on virtual key %s for model %s, skipping load balancing", virtualKey.Name, modelStr))
		// No provider configs, continue without modification
		return body, nil
	}

	var configuredProviders []string
	for _, pc := range providerConfigs {
		configuredProviders = append(configuredProviders, pc.Provider)
	}
	p.logger.Debug("[Governance] Virtual key has %d provider configs: %v", len(providerConfigs), configuredProviders)
	ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Load balancing model %s across %d configured providers: %v", modelStr, len(providerConfigs), configuredProviders))

	allowedProviderConfigs := make([]configstoreTables.TableVirtualKeyProviderConfig, 0)
	for _, config := range providerConfigs {
		// Delegate model allowance check to model catalog
		// This handles all cross-provider logic (OpenRouter, Vertex, Groq, Bedrock)
		// and provider-prefixed allowed_models entries
		isProviderAllowed := false
		if p.modelCatalog != nil {
			isProviderAllowed = p.modelCatalog.IsModelAllowedForProvider(schemas.ModelProvider(config.Provider), modelStr, config.AllowedModels)
		} else {
			// Fallback when model catalog is not available: simple string matching
			if len(config.AllowedModels) == 0 {
				// No restrictions, allow all models
				isProviderAllowed = true
			} else {
				isProviderAllowed = slices.Contains(config.AllowedModels, modelStr)
			}
		}

		if isProviderAllowed {
			// Check if the provider's budget or rate limits are violated using resolver helper methods
			if p.resolver.isProviderBudgetViolated(ctx, virtualKey, config) {
				ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Provider %s excluded: budget limit violated", config.Provider))
				continue
			}
			if p.resolver.isProviderRateLimitViolated(ctx, virtualKey, config) {
				ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Provider %s excluded: rate limit violated", config.Provider))
				continue
			}
			allowedProviderConfigs = append(allowedProviderConfigs, config)
		} else {
			ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Provider %s excluded: model %s not in allowed models list", config.Provider, modelStr))
		}
	}

	var allowedProviders []string
	for _, pc := range allowedProviderConfigs {
		allowedProviders = append(allowedProviders, pc.Provider)
	}
	p.logger.Debug("[Governance] Allowed providers after filtering: %v", allowedProviders)
	ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Allowed providers after filtering: %v", allowedProviders))

	if len(allowedProviderConfigs) == 0 {
		ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("No eligible providers remaining after filtering for model %s, skipping load balancing", modelStr))
		// TODO: Send proper error if (overall VK budget/rate limit) or (all provider budgets/rate limits) are violated
		// No allowed provider configs, continue without modification
		return body, nil
	}
	// Weighted random selection from allowed providers for the main model
	totalWeight := 0.0
	for _, config := range allowedProviderConfigs {
		totalWeight += getWeight(config.Weight)
	}
	// Generate random number between 0 and totalWeight
	randomValue := rand.Float64() * totalWeight
	// Select provider based on weighted random selection
	var selectedProvider schemas.ModelProvider
	currentWeight := 0.0
	for _, config := range allowedProviderConfigs {
		currentWeight += getWeight(config.Weight)
		if randomValue <= currentWeight {
			selectedProvider = schemas.ModelProvider(config.Provider)
			break
		}
	}
	// Fallback: if no provider was selected (shouldn't happen but guard against FP issues)
	if selectedProvider == "" && len(allowedProviderConfigs) > 0 {
		selectedProvider = schemas.ModelProvider(allowedProviderConfigs[0].Provider)
	}

	p.logger.Debug("[Governance] Selected provider: %s", selectedProvider)
	ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Selected provider %s for model %s (from %d eligible: %v)", selectedProvider, modelStr, len(allowedProviderConfigs), allowedProviders))

	// For genai integration, model is present in URL path instead of the request body
	if isGeminiPath {
		newModelWithRequestSuffix := string(selectedProvider) + "/" + modelStr + genaiRequestSuffix
		ctx.SetValue("model", newModelWithRequestSuffix)
	} else if isBedrockPath {
		// For bedrock integration, model is present in URL path as modelId
		ctx.SetValue("modelId", string(selectedProvider)+"/"+modelStr)
	} else {
		var err error
		refinedModel := modelStr
		// Refine the model for the selected provider
		if p.modelCatalog != nil {
			refinedModel, err = p.modelCatalog.RefineModelForProvider(selectedProvider, modelStr)
			if err != nil {
				return body, err
			}
		}
		// Update the model field in the request body
		body["model"] = string(selectedProvider) + "/" + refinedModel
	}
	// Append governance to routing engines used
	schemas.AppendToContextList(ctx, schemas.DeepIntShieldContextKeyRoutingEnginesUsed, schemas.RoutingEngineGovernance)

	// Fallback chain resolution. Two paths:
	//
	//   1. Operator-defined chain - `virtualKey.FallbackChain` is an ordered
	//      list of {provider, model}. When set, this wins: the operator
	//      knows their cost / quality preferences better than the load
	//      balancer's auto-derivation. The primary attempt itself is still
	//      whatever loadBalanceProvider just chose; the chain runs only on
	//      failure.
	//
	//   2. Auto-derived fallbacks (legacy path) - when no operator chain is
	//      set, build fallbacks from the other allowed provider configs
	//      (kept stable for backward compatibility).
	//
	// In both cases we skip injection if the caller already set
	// `body["fallbacks"]` - request-level fallbacks always win.
	_, hasFallbacks := body["fallbacks"]
	if !hasFallbacks && len(virtualKey.FallbackChain) > 0 {
		fallbacks := make([]string, 0, len(virtualKey.FallbackChain))
		for _, entry := range virtualKey.FallbackChain {
			prov := strings.TrimSpace(entry.Provider)
			model := strings.TrimSpace(entry.Model)
			if prov == "" || model == "" {
				continue
			}
			// Skip a chain entry that exactly matches the primary so we
			// don't immediately retry the same call.
			if prov == string(selectedProvider) && model == modelStr {
				continue
			}
			fallbacks = append(fallbacks, prov+"/"+model)
		}
		if len(fallbacks) > 0 {
			body["fallbacks"] = fallbacks
			ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Operator fallback chain applied (%d entries): %v", len(fallbacks), fallbacks))
		}
	} else if !hasFallbacks && len(allowedProviderConfigs) > 1 {
		// Sort allowed provider configs by weight (descending)
		sort.Slice(allowedProviderConfigs, func(i, j int) bool {
			return getWeight(allowedProviderConfigs[i].Weight) > getWeight(allowedProviderConfigs[j].Weight)
		})

		// Filter out the selected provider and create fallbacks array
		fallbacks := make([]string, 0, len(allowedProviderConfigs)-1)
		for _, config := range allowedProviderConfigs {
			if config.Provider != string(selectedProvider) {
				var err error
				refinedModel := modelStr
				if p.modelCatalog != nil {
					refinedModel, err = p.modelCatalog.RefineModelForProvider(schemas.ModelProvider(config.Provider), modelStr)
					if err != nil {
						// Skip fallback if model refinement fails
						p.logger.Warn("failed to refine model for fallback, skipping fallback in governance plugin: %v", err)
						continue
					}
				}
				fallbacks = append(fallbacks, string(schemas.ModelProvider(config.Provider))+"/"+refinedModel)
			}
		}

		// Add fallbacks to request body
		body["fallbacks"] = fallbacks
		ctx.AppendRoutingEngineLog(schemas.RoutingEngineGovernance, fmt.Sprintf("Added %d fallback providers: %v", len(fallbacks), fallbacks))
	}

	return body, nil
}

// applyRoutingRules evaluates routing rules and returns both the modified payload AND the routing decision
// This allows the caller to determine if marshaling is necessary (only if decision != nil or payload changed)
// Parameters:
//   - ctx: DeepIntShield context
//   - req: HTTP request
//   - body: Request body (may be modified if routing rule matches)
//   - virtualKey: Virtual key configuration (may be nil)
//
// Returns:
//   - map[string]any: The potentially modified request body
//   - *RoutingDecision: The matched routing decision (nil if no rule matched)
//   - error: Any error that occurred during evaluation
func (p *GovernancePlugin) applyRoutingRules(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, body map[string]any, virtualKey *configstoreTables.TableVirtualKey) (map[string]any, *RoutingDecision, error) {
	// Check if the request has a model field
	modelValue, hasModel := body["model"]
	isGeminiPath := strings.Contains(req.Path, "/genai")
	isBedrockPath := strings.Contains(req.Path, "/bedrock")
	if !hasModel {
		// For genai integration, model is present in URL path
		if isGeminiPath {
			modelValue = req.CaseInsensitivePathParamLookup("model")
		} else if isBedrockPath {
			// For bedrock integration, model is present in URL path as modelId
			rawModelID := req.CaseInsensitivePathParamLookup("modelId")
			if rawModelID == "" {
				return body, nil, nil
			}
			// URL-decode the modelId (Bedrock model IDs may be URL-encoded)
			decoded, err := url.PathUnescape(rawModelID)
			if err != nil {
				decoded = rawModelID
			}
			modelValue = decoded
		} else {
			return body, nil, nil
		}
	}

	modelStr, ok := modelValue.(string)
	if !ok || modelStr == "" {
		return body, nil, nil
	}

	var genaiRequestSuffix string
	if strings.Contains(req.Path, "/genai") {
		for _, sfx := range gemini.GeminiRequestSuffixPaths {
			if before, ok := strings.CutSuffix(modelStr, sfx); ok {
				modelStr = before
				genaiRequestSuffix = sfx
				break
			}
		}
	}

	// Parse provider and model from modelStr (format: "provider/model" or just "model")
	provider, model := schemas.ParseModelString(modelStr, "")

	// Extract normalized request type from context (set by HTTP middleware)
	requestType := ""
	if val := ctx.Value(schemas.DeepIntShieldContextKeyHTTPRequestType); val != nil {
		if requestTypeEnum, ok := val.(schemas.RequestType); ok {
			requestType = string(requestTypeEnum)
		} else if requestTypeStr, ok := val.(string); ok {
			requestType = requestTypeStr
		}
	}

	// Build routing context
	routingCtx := &RoutingContext{
		VirtualKey:               virtualKey,
		Provider:                 provider,
		Model:                    model,
		RequestType:              requestType,
		Headers:                  req.Headers,
		QueryParams:              req.Query,
		BudgetAndRateLimitStatus: p.store.GetBudgetAndRateLimitStatus(ctx, model, provider, virtualKey, nil, nil, nil),
	}

	p.logger.Debug("[HTTPTransport] Built routing context: provider=%s, model=%s, requestType=%s, vk=%v, headerCount=%d, paramCount=%d",
		provider, model, requestType, virtualKey != nil, len(req.Headers), len(req.Query))
	ctx.AppendRoutingEngineLog(schemas.RoutingEngineRoutingRule, fmt.Sprintf("Evaluating routing rules for model=%s, provider=%s, requestType=%s", model, provider, requestType))

	// Evaluate routing rules
	decision, err := p.engine.EvaluateRoutingRules(ctx, routingCtx)
	if err != nil {
		p.logger.Error("failed to evaluate routing rules: %v", err)
		ctx.AppendRoutingEngineLog(schemas.RoutingEngineRoutingRule, fmt.Sprintf("Routing rule evaluation error: %v", err))
		return body, nil, nil
	}

	// If a routing rule matched, apply the decision
	if decision != nil {
		p.logger.Debug("[Governance] Routing rule matched: %s", decision.MatchedRuleName)

		// Update model in request body
		if strings.Contains(req.Path, "/genai") {
			// For genai, model is in URL path
			newModel := decision.Model + genaiRequestSuffix
			// Add provider prefix if present (because there can be other routing rules down stream that can add the provider)
			if decision.Provider != "" {
				newModel = decision.Provider + "/" + newModel
			}
			ctx.SetValue("model", newModel)
		} else if isBedrockPath {
			// For bedrock, model is in URL path as modelId
			// Set new modelId in context so bedrockPreCallback picks it up via ctx.UserValue("modelId")
			newModel := decision.Model
			if decision.Provider != "" {
				newModel = decision.Provider + "/" + newModel
			}
			ctx.SetValue("modelId", newModel)
		} else {
			// For regular requests, update in body
			newModel := decision.Model
			// Add provider prefix if present (because there can be other routing rules down stream that can add the provider)
			if decision.Provider != "" {
				newModel = decision.Provider + "/" + newModel
			}
			body["model"] = newModel
		}
		// Append routing-rule to routing engines used
		schemas.AppendToContextList(ctx, schemas.DeepIntShieldContextKeyRoutingEnginesUsed, schemas.RoutingEngineRoutingRule)

		// Add fallbacks if present
		if len(decision.Fallbacks) > 0 {
			body["fallbacks"] = decision.Fallbacks
		}

		// Pin specific API key by ID if the routing rule specifies one
		if decision.KeyID != "" {
			ctx.SetValue(schemas.DeepIntShieldContextKeyAPIKeyID, decision.KeyID)
		}

		p.logger.Debug("[Governance] Applied routing decision: provider=%s, model=%s, keyID=%s, fallbacks=%v", decision.Provider, decision.Model, decision.KeyID, decision.Fallbacks)
	}

	return body, decision, nil
}

// addMCPIncludeTools adds the x-bf-mcp-include-tools header to the request headers
// Parameters:
//   - headers: The request headers
//   - virtualKey: The virtual key configuration
//
// Returns:
//   - map[string]string: The updated request headers
//   - error: Any error that occurred during processing
func (p *GovernancePlugin) addMCPIncludeTools(headers map[string]string, virtualKey *configstoreTables.TableVirtualKey) (map[string]string, error) {
	if len(virtualKey.MCPConfigs) > 0 {
		if headers == nil {
			headers = make(map[string]string)
		}
		executeOnlyTools := make([]string, 0)
		for _, vkMcpConfig := range virtualKey.MCPConfigs {
			if len(vkMcpConfig.ToolsToExecute) == 0 {
				// No tools specified in virtual key config - skip this client entirely
				continue
			}
			// Handle wildcard in virtual key config - allow all tools from this client
			if slices.Contains(vkMcpConfig.ToolsToExecute, "*") {
				// Virtual key uses wildcard - use client-specific wildcard
				executeOnlyTools = append(executeOnlyTools, fmt.Sprintf("%s-*", vkMcpConfig.MCPClient.Name))
				continue
			}

			for _, tool := range vkMcpConfig.ToolsToExecute {
				if tool != "" {
					// Add the tool - client config filtering will be handled by mcp.go
					executeOnlyTools = append(executeOnlyTools, fmt.Sprintf("%s-%s", vkMcpConfig.MCPClient.Name, tool))
				}
			}
		}

		// Set even when empty to exclude tools when no tools are present in the virtual key config
		headers["x-bf-mcp-include-tools"] = strings.Join(executeOnlyTools, ",")
	}

	return headers, nil
}

// validateRequiredHeaders checks that all configured required headers are present in the request.
// Headers are compared case-insensitively (both sides lowercased).
// Returns a DeepIntShieldError with status 400 if any required headers are missing, or nil if all present.
func (p *GovernancePlugin) validateRequiredHeaders(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldError {
	if p.requiredHeaders == nil || len(*p.requiredHeaders) == 0 {
		return nil
	}
	headers, _ := ctx.Value(schemas.DeepIntShieldContextKeyRequestHeaders).(map[string]string)
	if headers == nil {
		headers = map[string]string{}
	}
	var missing []string
	for _, h := range *p.requiredHeaders {
		if _, ok := headers[strings.ToLower(h)]; !ok {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		return &schemas.DeepIntShieldError{
			Type:       deepintshield.Ptr("missing_required_headers"),
			StatusCode: deepintshield.Ptr(400),
			Error: &schemas.ErrorField{
				Message: fmt.Sprintf("missing required headers: %s", strings.Join(missing, ", ")),
			},
		}
	}
	return nil
}

// evaluateGovernanceRequest is a common function that handles virtual key validation
// and governance evaluation logic. It returns the evaluation result and a DeepIntShieldError
// if the request should be rejected, or nil if allowed.
//
// Parameters:
//   - ctx: The DeepIntShield context
//   - evaluationRequest: The evaluation request with VirtualKey, Provider, Model, and RequestID
//
// Returns:
//   - *EvaluationResult: The governance evaluation result
//   - *schemas.DeepIntShieldError: The error to return if request is not allowed, nil if allowed
func (p *GovernancePlugin) evaluateGovernanceRequest(ctx *schemas.DeepIntShieldContext, evaluationRequest *EvaluationRequest, requestType schemas.RequestType) (*EvaluationResult, *schemas.DeepIntShieldError) {
	// Check if authentication is mandatory (either VK or user auth)
	// Checking if the virtual key is valid or not
	isVirtualKeyValid := false
	if evaluationRequest.VirtualKey != "" {
		vk, exists := p.store.GetVirtualKey(ctx, evaluationRequest.VirtualKey)
		if exists {
			isVirtualKeyValid = true
			if ctx != nil && vk != nil && vk.TenantID != "" && ctx.Value(schemas.DeepIntShieldContextKeyTenantID) == nil {
				ctx.SetValue(schemas.DeepIntShieldContextKeyTenantID, vk.TenantID)
			}
			// Workspace-scope enforcement + auto-derivation. There are
			// three relevant input states:
			//   1. Both the workspace API key and the VK are scoped:
			//      they must agree → 403 on mismatch.
			//   2. Only the workspace API key is scoped (VK is org-wide):
			//      the request inherits the workspace from the API key.
			//      No-op here - the resolver already stamped ctx.
			//   3. Only the VK is scoped (no workspace API key - VK-only
			//      traffic): we auto-stamp ctx with the VK's workspace
			//      so downstream consumers (guardrail attachment, logs,
			//      analytics) see a consistent scope without callers
			//      needing to also issue a workspace API key.
			// State (3) is the meaningful behaviour change - without it
			// workspace-scoped guardrails would only fire for traffic
			// that bothers with the new credential type.
			if ctx != nil && vk != nil && vk.WorkspaceID != nil && *vk.WorkspaceID != "" {
				vkWS := *vk.WorkspaceID
				if reqWS, ok := ctx.Value(schemas.DeepIntShieldContextKeyWorkspaceID).(string); ok && reqWS != "" {
					if reqWS != vkWS {
						return nil, &schemas.DeepIntShieldError{
							Type:       deepintshield.Ptr("workspace_scope_mismatch"),
							StatusCode: deepintshield.Ptr(403),
							Error: &schemas.ErrorField{
								Message: "Virtual key is scoped to a different workspace than the API key in use.",
							},
						}
					}
				} else {
					// Legacy VK-only path - adopt the VK's workspace as
					// the request's workspace context. Doesn't grant
					// extra power; the VK is the source of truth.
					ctx.SetValue(schemas.DeepIntShieldContextKeyWorkspaceID, vkWS)
				}
			}
		}
	}
	p.cfgMutex.RLock()
	if p.isVkMandatory != nil && *p.isVkMandatory && evaluationRequest.VirtualKey == "" {
		message := "virtual key is required. Provide a virtual key via the x-bf-vk header."
		p.cfgMutex.RUnlock()
		return nil, &schemas.DeepIntShieldError{
			Type:       deepintshield.Ptr("virtual_key_required"),
			StatusCode: deepintshield.Ptr(401),
			Error: &schemas.ErrorField{
				Message: message,
			},
		}
	}
	if p.isVkMandatory != nil && *p.isVkMandatory && !isVirtualKeyValid {
		p.cfgMutex.RUnlock()
		return nil, &schemas.DeepIntShieldError{
			Type:       deepintshield.Ptr(string(DecisionVirtualKeyNotFound)),
			StatusCode: deepintshield.Ptr(403),
			Error: &schemas.ErrorField{
				Message: "Virtual key not found.",
			},
		}
	}
	p.cfgMutex.RUnlock()

	// First evaluate model and provider checks (applies even when virtual keys are disabled or not present)
	result := p.resolver.EvaluateModelAndProviderRequest(ctx, evaluationRequest.Provider, evaluationRequest.Model)

	// Check user-level governance (enterprise-only, runs before VK checks)
	if result.Decision == DecisionAllow {
		result = p.resolver.EvaluateUserRequest(ctx, evaluationRequest.UserID, evaluationRequest)
	}

	// If model/provider checks passed, evaluate virtual key
	if result.Decision == DecisionAllow && evaluationRequest.VirtualKey != "" {
		if evaluationRequest.UserID != "" {
			// User auth present: only use VK for routing/filtering (skip rate limits and budgets)
			result = p.resolver.EvaluateVirtualKeyFiltering(ctx, evaluationRequest.VirtualKey, evaluationRequest.Provider, evaluationRequest.Model, requestType)
		} else {
			// No user auth: full VK governance (routing + limits)
			result = p.resolver.EvaluateVirtualKeyRequest(ctx, evaluationRequest.VirtualKey, evaluationRequest.Provider, evaluationRequest.Model, requestType)
		}
	}

	// Mark request as rejected in context if not allowed
	if result.Decision != DecisionAllow {
		if ctx != nil {
			if _, ok := ctx.Value(governanceRejectedContextKey).(bool); !ok {
				ctx.SetValue(governanceRejectedContextKey, true)
			}
		}
	}

	// Handle decision
	switch result.Decision {
	case DecisionAllow:
		return result, nil

	case DecisionVirtualKeyNotFound, DecisionVirtualKeyBlocked, DecisionModelBlocked, DecisionProviderBlocked:
		return result, &schemas.DeepIntShieldError{
			Type:       deepintshield.Ptr(string(result.Decision)),
			StatusCode: deepintshield.Ptr(403),
			Error: &schemas.ErrorField{
				Message: result.Reason,
			},
		}

	case DecisionRateLimited, DecisionTokenLimited, DecisionRequestLimited:
		return result, &schemas.DeepIntShieldError{
			Type:       deepintshield.Ptr(string(result.Decision)),
			StatusCode: deepintshield.Ptr(429),
			Error: &schemas.ErrorField{
				Message: result.Reason,
			},
		}

	case DecisionBudgetExceeded:
		return result, &schemas.DeepIntShieldError{
			Type:       deepintshield.Ptr(string(result.Decision)),
			StatusCode: deepintshield.Ptr(402),
			Error: &schemas.ErrorField{
				Message: result.Reason,
			},
		}

	default:
		// Fallback to deny for unknown decisions
		return result, &schemas.DeepIntShieldError{
			Type: deepintshield.Ptr(string(result.Decision)),
			Error: &schemas.ErrorField{
				Message: "Governance decision error",
			},
		}
	}
}

// PreLLMHook intercepts requests before they are processed (governance decision point)
// Parameters:
//   - ctx: The DeepIntShield context
//   - req: The DeepIntShield request to be processed
//
// Returns:
//   - *schemas.DeepIntShieldRequest: The processed request
//   - *schemas.LLMPluginShortCircuit: The plugin short circuit if the request is not allowed
//   - error: Any error that occurred during processing
func (p *GovernancePlugin) PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	// If its skip key selection - in that case we need to skip virtual key selection too
	if deepintshield.GetBoolFromContext(ctx, schemas.DeepIntShieldContextKeySkipKeySelection) {
		return req, nil, nil
	}
	// Validate required headers are present
	if headerErr := p.validateRequiredHeaders(ctx); headerErr != nil {
		return req, &schemas.LLMPluginShortCircuit{Error: headerErr}, nil
	}
	// Extract governance headers and virtual key using utility functions
	virtualKeyValue := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyVirtualKey)
	// Extract user ID for enterprise user-level governance
	userID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceUserID)
	// Getting provider and mode from the request
	provider, model, _ := req.GetRequestFields()
	// Create request context for evaluation
	evaluationRequest := &EvaluationRequest{
		VirtualKey: virtualKeyValue,
		Provider:   provider,
		Model:      model,
		UserID:     userID,
	}
	// Evaluate governance using common function
	_, deepintshieldError := p.evaluateGovernanceRequest(ctx, evaluationRequest, req.RequestType)
	// Convert DeepIntShieldError to LLMPluginShortCircuit if needed
	if deepintshieldError != nil {
		return req, &schemas.LLMPluginShortCircuit{
			Error: deepintshieldError,
		}, nil
	}

	return req, nil, nil
}

// PostLLMHook processes the response and updates usage tracking (business logic execution)
// Parameters:
//   - ctx: The DeepIntShield context
//   - result: The DeepIntShield response to be processed
//   - err: The DeepIntShield error to be processed
//
// Returns:
//   - *schemas.DeepIntShieldResponse: The processed response
//   - *schemas.DeepIntShieldError: The processed error
//   - error: Any error that occurred during processing
func (p *GovernancePlugin) PostLLMHook(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, err *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	if _, ok := ctx.Value(governanceRejectedContextKey).(bool); ok {
		return result, err, nil
	}

	// Extract request type, provider, and model
	requestType, provider, model := deepintshield.GetResponseFields(result, err)

	// Extract governance information
	virtualKey := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyVirtualKey)
	requestID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyRequestID)
	// Extract user ID for enterprise user-level governance
	userID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceUserID)

	// Extract cache and batch flags from context
	isCacheRead := false
	isBatch := false
	if val := ctx.Value(governanceIsCacheReadContextKey); val != nil {
		if b, ok := val.(bool); ok {
			isCacheRead = b
		}
	}
	if val := ctx.Value(governanceIsBatchContextKey); val != nil {
		if b, ok := val.(bool); ok {
			isBatch = b
		}
	}

	if requestType == schemas.ListModelsRequest && result != nil && result.ListModelsResponse != nil && virtualKey != "" {
		// filter models which are not supported on this virtual key
		result.ListModelsResponse.Data = p.filterModelsForVirtualKey(ctx, result.ListModelsResponse.Data, virtualKey)
	}

	isFinalChunk := deepintshield.IsFinalChunk(ctx)

	// Always process usage tracking (with or without virtual key)
	// When user auth is present, skip VK usage tracking to avoid double-counting
	effectiveVK := virtualKey
	if userID != "" {
		effectiveVK = ""
	}
	// If effectiveVK is empty, it will be passed as empty string to postHookWorker
	// The tracker will handle empty virtual keys gracefully by only updating provider-level and model-level usage
	if model != "" {
		trackingCtx := p.newUsageTrackingContext(ctx)
		p.wg.Add(1)
		go func(trackingCtx context.Context) {
			defer p.wg.Done()
			defer safegoroutine.Recover(p.logger, "governance.post-hook-worker")
			p.postHookWorker(trackingCtx, result, provider, model, requestType, effectiveVK, requestID, userID, isCacheRead, isBatch, isFinalChunk)
		}(trackingCtx)
	}

	return result, err, nil
}

// PreMCPHook intercepts MCP tool execution requests before they are processed (governance decision point)
// Parameters:
//   - ctx: The DeepIntShield context
//   - req: The DeepIntShield MCP request to be processed
//
// Returns:
//   - *schemas.DeepIntShieldMCPRequest: The processed request
//   - *schemas.MCPPluginShortCircuit: The plugin short circuit if the request is not allowed
//   - error: Any error that occurred during processing
func (p *GovernancePlugin) PreMCPHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	toolName := req.GetToolName()

	// Skip governance for codemode tools
	if deepintshield.IsCodemodeTool(toolName) {
		return req, nil, nil
	}

	// Validate required headers are present
	if headerErr := p.validateRequiredHeaders(ctx); headerErr != nil {
		return req, &schemas.MCPPluginShortCircuit{Error: headerErr}, nil
	}

	// Extract governance headers and virtual key using utility functions
	virtualKeyValue := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyVirtualKey)
	// Extract user ID for enterprise user-level governance
	userID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceUserID)

	// Create request context for evaluation (MCP requests don't have provider/model)
	evaluationRequest := &EvaluationRequest{
		VirtualKey: virtualKeyValue,
		UserID:     userID,
	}

	// Evaluate governance using common function
	_, deepintshieldError := p.evaluateGovernanceRequest(ctx, evaluationRequest, schemas.MCPToolExecutionRequest)

	// Convert DeepIntShieldError to MCPPluginShortCircuit if needed
	if deepintshieldError != nil {
		return req, &schemas.MCPPluginShortCircuit{
			Error: deepintshieldError,
		}, nil
	}

	return req, nil, nil
}

// PostMCPHook processes the MCP response and updates usage tracking (business logic execution)
// Parameters:
//   - ctx: The DeepIntShield context
//   - resp: The DeepIntShield MCP response to be processed
//   - deepintshieldErr: The DeepIntShield error to be processed
//
// Returns:
//   - *schemas.DeepIntShieldMCPResponse: The processed response
//   - *schemas.DeepIntShieldError: The processed error
//   - error: Any error that occurred during processing
func (p *GovernancePlugin) PostMCPHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError, error) {
	if _, ok := ctx.Value(governanceRejectedContextKey).(bool); ok {
		return resp, deepintshieldErr, nil
	}

	// Extract governance information
	virtualKey := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyVirtualKey)
	requestID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyRequestID)
	userID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceUserID)

	// When user auth is present, skip VK usage tracking to avoid double-counting
	if userID != "" {
		virtualKey = ""
	}

	// Skip if no virtual key
	if virtualKey == "" {
		return resp, deepintshieldErr, nil
	}

	// Determine if request was successful
	success := (resp != nil && deepintshieldErr == nil)

	// Skip usage tracking for codemode tools
	if success && resp != nil && deepintshield.IsCodemodeTool(resp.ExtraFields.ToolName) {
		return resp, deepintshieldErr, nil
	}

	// Calculate MCP tool cost from catalog if available
	var toolCost float64
	if success && resp != nil && p.mcpCatalog != nil && resp.ExtraFields.ClientName != "" && resp.ExtraFields.ToolName != "" {
		// Use separate client name and tool name fields
		if pricingEntry, ok := p.mcpCatalog.GetPricingData(resp.ExtraFields.ClientName, resp.ExtraFields.ToolName); ok {
			toolCost = pricingEntry.CostPerExecution
			p.logger.Debug("MCP tool cost for %s.%s: $%.6f", resp.ExtraFields.ClientName, resp.ExtraFields.ToolName, toolCost)
		}
	}

	// Create usage update for tracker (business logic) - MCP requests track request count and tool cost
	usageUpdate := &UsageUpdate{
		VirtualKey:   virtualKey,
		Success:      success,
		Cost:         toolCost,
		RequestID:    requestID,
		IsStreaming:  false,
		IsFinalChunk: true,
		HasUsageData: toolCost > 0, // Has usage data if we have a cost
	}

	// Queue usage update asynchronously using tracker
	trackingCtx := p.newUsageTrackingContext(ctx)
	p.wg.Add(1)
	go func(trackingCtx context.Context) {
		defer p.wg.Done()
		defer safegoroutine.Recover(p.logger, "governance.usage-update-async")
		p.tracker.UpdateUsage(trackingCtx, usageUpdate)
	}(trackingCtx)

	return resp, deepintshieldErr, nil
}

// Cleanup shuts down all components gracefully
func (p *GovernancePlugin) Cleanup() error {
	var cleanupErr error
	p.cleanupOnce.Do(func() {
		if p.cancelFunc != nil {
			p.cancelFunc()
		}
		p.wg.Wait() // Wait for all background workers to complete
		if err := p.tracker.Cleanup(); err != nil {
			cleanupErr = err
		}
	})
	return cleanupErr
}

// postHookWorker is a worker function that processes the response and updates usage tracking
// It is used to avoid blocking the main thread when updating usage tracking
// Handles both cases: with virtual key and without virtual key (empty string)
// When virtualKey is empty, the tracker will only update provider-level and model-level usage
// Parameters:
//   - result: The DeepIntShield response to be processed
//   - provider: The provider of the request
//   - model: The model of the request
//   - requestType: The type of the request
//   - virtualKey: The virtual key of the request (empty string if not present)
//   - requestID: The request ID
//   - userID: The user ID for enterprise user-level governance (empty string if not present)
//   - isCacheRead: Whether the request is a cache read
//   - isBatch: Whether the request is a batch request
//   - isFinalChunk: Whether the request is the final chunk
func (p *GovernancePlugin) postHookWorker(ctx context.Context, result *schemas.DeepIntShieldResponse, provider schemas.ModelProvider, model string, requestType schemas.RequestType, virtualKey, requestID, userID string, _, _, isFinalChunk bool) {
	// Determine if request was successful
	success := (result != nil)

	// Streaming detection
	isStreaming := deepintshield.IsStreamRequestType(requestType)

	if !isStreaming || (isStreaming && isFinalChunk) {
		var cost float64
		if p.modelCatalog != nil && result != nil {
			cost = p.modelCatalog.CalculateCost(result)
		}
		tokensUsed := 0
		if result != nil {
			switch {
			case result.TextCompletionResponse != nil && result.TextCompletionResponse.Usage != nil:
				tokensUsed = result.TextCompletionResponse.Usage.TotalTokens
			case result.ChatResponse != nil && result.ChatResponse.Usage != nil:
				tokensUsed = result.ChatResponse.Usage.TotalTokens
			case result.ResponsesResponse != nil && result.ResponsesResponse.Usage != nil:
				tokensUsed = result.ResponsesResponse.Usage.TotalTokens
			case result.ResponsesStreamResponse != nil && result.ResponsesStreamResponse.Response != nil && result.ResponsesStreamResponse.Response.Usage != nil:
				tokensUsed = result.ResponsesStreamResponse.Response.Usage.TotalTokens
			case result.EmbeddingResponse != nil && result.EmbeddingResponse.Usage != nil:
				tokensUsed = result.EmbeddingResponse.Usage.TotalTokens
			case result.SpeechResponse != nil && result.SpeechResponse.Usage != nil:
				tokensUsed = result.SpeechResponse.Usage.TotalTokens
			case result.SpeechStreamResponse != nil && result.SpeechStreamResponse.Usage != nil:
				tokensUsed = result.SpeechStreamResponse.Usage.TotalTokens
			case result.TranscriptionResponse != nil && result.TranscriptionResponse.Usage != nil && result.TranscriptionResponse.Usage.TotalTokens != nil:
				tokensUsed = *result.TranscriptionResponse.Usage.TotalTokens
			case result.TranscriptionStreamResponse != nil && result.TranscriptionStreamResponse.Usage != nil && result.TranscriptionStreamResponse.Usage.TotalTokens != nil:
				tokensUsed = *result.TranscriptionStreamResponse.Usage.TotalTokens
			}
		}
		// Create usage update for tracker (business logic)
		usageUpdate := &UsageUpdate{
			VirtualKey:   virtualKey,
			Provider:     provider,
			Model:        model,
			Success:      success,
			TokensUsed:   int64(tokensUsed),
			Cost:         cost,
			RequestID:    requestID,
			UserID:       userID,
			IsStreaming:  isStreaming,
			IsFinalChunk: isFinalChunk,
			HasUsageData: tokensUsed > 0,
		}

		// Queue usage update asynchronously using tracker
		// UpdateUsage handles empty virtual keys gracefully by only updating provider-level and model-level usage
		p.tracker.UpdateUsage(ctx, usageUpdate)
	}
}

func (p *GovernancePlugin) newUsageTrackingContext(ctx *schemas.DeepIntShieldContext) context.Context {
	if ctx == nil {
		return p.ctx
	}

	tenantID, _ := ctx.Value(schemas.DeepIntShieldContextKeyTenantID).(string)
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return p.ctx
	}

	return context.WithValue(p.ctx, schemas.DeepIntShieldContextKeyTenantID, tenantID)
}

// GetGovernanceStore returns the governance store
func (p *GovernancePlugin) GetGovernanceStore() GovernanceStore {
	return p.store
}

// GenerateVirtualKey is a helper function
func GenerateVirtualKey() string {
	return VirtualKeyPrefix + uuid.NewString()
}
