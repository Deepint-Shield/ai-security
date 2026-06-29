// Package deepintshield provides the core implementation of the DeepIntShield system.
// DeepIntShield is a unified interface for interacting with various AI model providers,
// managing concurrent requests, and handling provider-specific configurations.
package deepintshield

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"

	"github.com/deepint-shield/ai-security/core/mcp"
	"github.com/deepint-shield/ai-security/core/mcp/codemode/starlark"
	"github.com/deepint-shield/ai-security/core/providers/anthropic"
	"github.com/deepint-shield/ai-security/core/providers/azure"
	"github.com/deepint-shield/ai-security/core/providers/bedrock"
	"github.com/deepint-shield/ai-security/core/providers/cerebras"
	"github.com/deepint-shield/ai-security/core/providers/cohere"
	"github.com/deepint-shield/ai-security/core/providers/elevenlabs"
	"github.com/deepint-shield/ai-security/core/providers/fireworks"
	"github.com/deepint-shield/ai-security/core/providers/gemini"
	"github.com/deepint-shield/ai-security/core/providers/groq"
	"github.com/deepint-shield/ai-security/core/providers/huggingface"
	"github.com/deepint-shield/ai-security/core/providers/mistral"
	"github.com/deepint-shield/ai-security/core/providers/nebius"
	"github.com/deepint-shield/ai-security/core/providers/ollama"
	"github.com/deepint-shield/ai-security/core/providers/openai"
	"github.com/deepint-shield/ai-security/core/providers/opencode"
	"github.com/deepint-shield/ai-security/core/providers/openrouter"
	"github.com/deepint-shield/ai-security/core/providers/parasail"
	"github.com/deepint-shield/ai-security/core/providers/perplexity"
	"github.com/deepint-shield/ai-security/core/providers/replicate"
	"github.com/deepint-shield/ai-security/core/providers/runway"
	"github.com/deepint-shield/ai-security/core/providers/sgl"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/providers/vertex"
	"github.com/deepint-shield/ai-security/core/providers/vllm"
	"github.com/deepint-shield/ai-security/core/providers/xai"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// ChannelMessage represents a message passed through the request channel.
// It contains the request, response and error channels, and the request type.
type ChannelMessage struct {
	schemas.DeepIntShieldRequest
	Context        *schemas.DeepIntShieldContext
	Response       chan *schemas.DeepIntShieldResponse
	ResponseStream chan chan *schemas.DeepIntShieldStreamChunk
	Err            chan schemas.DeepIntShieldError
}

// DeepIntShield manages providers and maintains specified open channels for concurrent processing.
// It handles request routing, provider management, and response processing.
type DeepIntShield struct {
	ctx                 *schemas.DeepIntShieldContext
	cancel              context.CancelFunc
	account             schemas.Account                     // account interface
	llmPlugins          atomic.Pointer[[]schemas.LLMPlugin] // list of llm plugins
	mcpPlugins          atomic.Pointer[[]schemas.MCPPlugin] // list of mcp plugins
	providers           atomic.Pointer[[]schemas.Provider]  // list of providers
	requestQueues       sync.Map                            // provider request queues (thread-safe), stores *ProviderQueue
	waitGroups          sync.Map                            // wait groups for each provider (thread-safe)
	providerMutexes     sync.Map                            // mutexes for each provider to prevent concurrent updates (thread-safe)
	channelMessagePool  sync.Pool                           // Pool for ChannelMessage objects, initial pool size is set in Init
	responseChannelPool sync.Pool                           // Pool for response channels, initial pool size is set in Init
	errorChannelPool    sync.Pool                           // Pool for error channels, initial pool size is set in Init
	responseStreamPool  sync.Pool                           // Pool for response stream channels, initial pool size is set in Init
	pluginPipelinePool  sync.Pool                           // Pool for PluginPipeline objects
	deepintshieldRequestPool  sync.Pool                           // Pool for DeepIntShieldRequest objects
	mcpRequestPool      sync.Pool                           // Pool for DeepIntShieldMCPRequest objects
	oauth2Provider      schemas.OAuth2Provider              // OAuth provider instance
	logger              schemas.Logger                      // logger instance, default logger is used if not provided
	tracer              atomic.Value                        // tracer for distributed tracing (stores schemas.Tracer, NoOpTracer if not configured)
	MCPManager          mcp.MCPManagerInterface             // MCP integration manager (nil if MCP not configured)
	mcpInitOnce         sync.Once                           // Ensures MCP manager is initialized only once
	dropExcessRequests  atomic.Bool                         // If true, in cases where the queue is full, requests will not wait for the queue to be empty and will be dropped instead.
	keySelector         schemas.KeySelector                 // Custom key selector function
	kvStore             schemas.KVStore                     // optional KV store for session stickiness (nil = disabled)
	keyLoadTracker      *KeyLoadTracker                     // per-key load metrics and circuit breaker (nil when load balancer disabled)
}

// ProviderQueue wraps a provider's request channel with lifecycle management
// to prevent "send on closed channel" panics during provider removal/update.
// Producers must check the closing flag or select on the done channel before sending.
type ProviderQueue struct {
	queue      chan *ChannelMessage // the actual request queue channel
	done       chan struct{}        // closed to signal shutdown to producers
	closing    uint32               // atomic: 0 = open, 1 = closing
	signalOnce sync.Once
	closeOnce  sync.Once
}

func isLargePayloadPassthrough(ctx *schemas.DeepIntShieldContext) bool {
	if ctx == nil {
		return false
	}
	// Large payload mode intentionally skips JSON->DeepIntShield input materialization.
	// Example: a 400MB multipart/audio upload sets Input=nil by design; strict
	// non-nil validation here would reject valid passthrough requests.
	isLargePayload, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool)
	if !isLargePayload {
		return false
	}
	// Verify reader is present (flag and reader are always set together by middleware)
	reader := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadReader)
	return reader != nil
}

func normalizedModelRestrictionVariants(model string) []string {
	model = strings.TrimSpace(model)
	if model == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var variants []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		variants = append(variants, value)
	}

	add(model)

	current := model
	for {
		_, stripped := schemas.ParseModelString(current, "")
		if stripped == current {
			break
		}
		add(stripped)
		current = stripped
	}

	return variants
}

func keySupportsRequestedModel(allowedModels []string, requestedModel string) bool {
	requestVariants := normalizedModelRestrictionVariants(requestedModel)
	if len(requestVariants) == 0 {
		return false
	}

	for _, allowedModel := range allowedModels {
		for _, allowedVariant := range normalizedModelRestrictionVariants(allowedModel) {
			if slices.Contains(requestVariants, allowedVariant) {
				return true
			}
		}
	}

	return false
}

// signalClosing signals the closing of the provider queue.
// This is lock-free: uses atomic store and sync.Once to safely signal shutdown.
func (pq *ProviderQueue) signalClosing() {
	pq.signalOnce.Do(func() {
		atomic.StoreUint32(&pq.closing, 1)
		close(pq.done)
	})
}

// closeQueue closes the provider queue.
// Protected by sync.Once to prevent double-close.
func (pq *ProviderQueue) closeQueue() {
	pq.closeOnce.Do(func() {
		close(pq.queue)
	})
}

// isClosing returns true if the provider queue is closing.
// Uses atomic load for lock-free checking.
func (pq *ProviderQueue) isClosing() bool {
	return atomic.LoadUint32(&pq.closing) == 1
}

// PluginPipeline encapsulates the execution of plugin PreHooks and PostHooks, tracks how many plugins ran, and manages short-circuiting and error aggregation.
type PluginPipeline struct {
	llmPlugins []schemas.LLMPlugin
	mcpPlugins []schemas.MCPPlugin
	logger     schemas.Logger
	tracer     schemas.Tracer

	// Number of PreHooks that were executed (used to determine which PostHooks to run in reverse order)
	executedPreHooks int
	// Errors from PreHooks and PostHooks
	preHookErrors  []error
	postHookErrors []error

	// Streaming post-hook timing accumulation (for aggregated spans)
	postHookTimings     map[string]*pluginTimingAccumulator // keyed by plugin name
	postHookPluginOrder []string                            // order in which post-hooks ran (for nested span creation)
	chunkCount          int
}

// pluginTimingAccumulator accumulates timing information for a plugin across streaming chunks
type pluginTimingAccumulator struct {
	totalDuration time.Duration
	invocations   int
	errors        int
}

// workspaceFromContext returns the request's workspace_id, or "" when none is
// set (request bypasses workspace scoping - typically a system / bootstrap
// call). Read straight off the schemas context key so the core package
// doesn't have to import framework/tenantctx (which would create a cycle).
func workspaceFromContext(ctx *schemas.DeepIntShieldContext) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(schemas.DeepIntShieldContextKeyWorkspaceID).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// shouldRunPluginForRequestWorkspace applies the "most-specific match wins"
// dispatch rule from schemas.WorkspaceScoped at the moment of a single
// plugin call, instead of as an upfront slice filter. Per-call evaluation
// is required because the request's workspace_id is only stamped onto ctx
// once the governance plugin's PreLLMHook runs - an upfront filter on the
// whole slice would see workspaceFromContext == "" and drop every
// workspace-tagged instance, leaving the gateway running on the empty-
// config global semantic_cache (the bug that masked hallucination metrics).
//
// Behaviour:
//   - global plugin (no workspace tag): run, unless a same-named workspace-
//     tagged sibling matches the request's workspace, in which case the
//     tagged sibling shadows this one and we skip
//   - workspace-tagged plugin: run only when its tag matches the request's
//     workspace
//
// Pre-hook and post-hook both call this with the same ctx; the workspace
// in ctx is stable from PreLLMHook (governance stamps it) through
// PostLLMHook, so the per-plugin decision is consistent across the two
// loops and the post-hook runs the exact set the pre-hook ran.
func shouldRunPluginForRequestWorkspace[P schemas.BasePlugin](plugin P, all []P, requestWS string) bool {
	entryWS := ""
	if ws, ok := any(plugin).(schemas.WorkspaceScoped); ok {
		entryWS = ws.WorkspaceID()
	}
	if entryWS == "" {
		if requestWS == "" {
			return true
		}
		name := plugin.GetName()
		for _, other := range all {
			if any(other) == any(plugin) {
				continue
			}
			if other.GetName() != name {
				continue
			}
			otherWS := ""
			if ws, ok := any(other).(schemas.WorkspaceScoped); ok {
				otherWS = ws.WorkspaceID()
			}
			if otherWS == requestWS {
				return false
			}
		}
		return true
	}
	return entryWS == requestWS
}

// tracerWrapper wraps a Tracer to ensure atomic.Value stores consistent types.
// This is necessary because atomic.Value.Store() panics if called with values
// of different concrete types, even if they implement the same interface.
type tracerWrapper struct {
	tracer schemas.Tracer
}

// INITIALIZATION

// Init initializes a new DeepIntShield instance with the given configuration.
// It sets up the account, plugins, object pools, and initializes providers.
// Returns an error if initialization fails.
// Initial Memory Allocations happens here as per the initial pool size.
func Init(ctx context.Context, config schemas.DeepIntShieldConfig) (*DeepIntShield, error) {
	if config.Account == nil {
		return nil, fmt.Errorf("account is required to initialize DeepIntShield")
	}

	if config.Logger == nil {
		config.Logger = NewDefaultLogger(schemas.LogLevelInfo)
	}
	providerUtils.SetLogger(config.Logger)

	// Initialize tracer (use NoOpTracer if not provided)
	tracer := config.Tracer
	if tracer == nil {
		tracer = schemas.DefaultTracer()
	}

	deepintshieldCtx, cancel := schemas.NewDeepIntShieldContextWithCancel(ctx)
	deepintshield := &DeepIntShield{
		ctx:            deepintshieldCtx,
		cancel:         cancel,
		account:        config.Account,
		llmPlugins:     atomic.Pointer[[]schemas.LLMPlugin]{},
		mcpPlugins:     atomic.Pointer[[]schemas.MCPPlugin]{},
		requestQueues:  sync.Map{},
		waitGroups:     sync.Map{},
		keySelector:    config.KeySelector,
		oauth2Provider: config.OAuth2Provider,
		logger:         config.Logger,
		kvStore:        config.KVStore,
	}
	deepintshield.tracer.Store(&tracerWrapper{tracer: tracer})
	if config.LLMPlugins == nil {
		config.LLMPlugins = make([]schemas.LLMPlugin, 0)
	}
	if config.MCPPlugins == nil {
		config.MCPPlugins = make([]schemas.MCPPlugin, 0)
	}
	deepintshield.llmPlugins.Store(&config.LLMPlugins)
	deepintshield.mcpPlugins.Store(&config.MCPPlugins)

	// Initialize providers slice
	deepintshield.providers.Store(&[]schemas.Provider{})

	deepintshield.dropExcessRequests.Store(config.DropExcessRequests)

	if deepintshield.keySelector == nil {
		deepintshield.keySelector = WeightedRandomKeySelector
	}

	// Initialize object pools
	deepintshield.channelMessagePool = sync.Pool{
		New: func() interface{} {
			return &ChannelMessage{}
		},
	}
	deepintshield.responseChannelPool = sync.Pool{
		New: func() interface{} {
			return make(chan *schemas.DeepIntShieldResponse, 1)
		},
	}
	deepintshield.errorChannelPool = sync.Pool{
		New: func() interface{} {
			return make(chan schemas.DeepIntShieldError, 1)
		},
	}
	deepintshield.responseStreamPool = sync.Pool{
		New: func() interface{} {
			return make(chan chan *schemas.DeepIntShieldStreamChunk, 1)
		},
	}
	deepintshield.pluginPipelinePool = sync.Pool{
		New: func() interface{} {
			return &PluginPipeline{
				preHookErrors:  make([]error, 0),
				postHookErrors: make([]error, 0),
			}
		},
	}
	deepintshield.deepintshieldRequestPool = sync.Pool{
		New: func() interface{} {
			return &schemas.DeepIntShieldRequest{}
		},
	}
	deepintshield.mcpRequestPool = sync.Pool{
		New: func() interface{} {
			return &schemas.DeepIntShieldMCPRequest{}
		},
	}
	// Prewarm pools with multiple objects
	for range config.InitialPoolSize {
		// Create and put new objects directly into pools
		deepintshield.channelMessagePool.Put(&ChannelMessage{})
		deepintshield.responseChannelPool.Put(make(chan *schemas.DeepIntShieldResponse, 1))
		deepintshield.errorChannelPool.Put(make(chan schemas.DeepIntShieldError, 1))
		deepintshield.responseStreamPool.Put(make(chan chan *schemas.DeepIntShieldStreamChunk, 1))
		deepintshield.pluginPipelinePool.Put(&PluginPipeline{
			preHookErrors:  make([]error, 0),
			postHookErrors: make([]error, 0),
		})
		deepintshield.deepintshieldRequestPool.Put(&schemas.DeepIntShieldRequest{})
		deepintshield.mcpRequestPool.Put(&schemas.DeepIntShieldMCPRequest{})
	}

	providerKeys, err := deepintshield.account.GetConfiguredProviders()
	if err != nil {
		return nil, err
	}

	// Initialize MCP manager if configured
	if config.MCPConfig != nil {
		deepintshield.mcpInitOnce.Do(func() {
			// Set up plugin pipeline provider functions for executeCode tool hooks
			mcpConfig := *config.MCPConfig
			mcpConfig.PluginPipelineProvider = func() interface{} {
				return deepintshield.getPluginPipeline()
			}
			mcpConfig.ReleasePluginPipeline = func(pipeline interface{}) {
				if pp, ok := pipeline.(*PluginPipeline); ok {
					deepintshield.releasePluginPipeline(pp)
				}
			}
			// Create Starlark CodeMode for code execution
			var codeModeConfig *mcp.CodeModeConfig
			if mcpConfig.ToolManagerConfig != nil {
				codeModeConfig = &mcp.CodeModeConfig{
					BindingLevel:         mcpConfig.ToolManagerConfig.CodeModeBindingLevel,
					ToolExecutionTimeout: mcpConfig.ToolManagerConfig.ToolExecutionTimeout,
				}
			}
			codeMode := starlark.NewStarlarkCodeMode(codeModeConfig, deepintshield.logger)
			deepintshield.MCPManager = mcp.NewMCPManager(deepintshieldCtx, mcpConfig, deepintshield.oauth2Provider, deepintshield.logger, codeMode)
			deepintshield.logger.Info("MCP integration initialized successfully")
		})
	}

	// Create buffered channels for each provider and start workers
	for _, providerKey := range providerKeys {
		if strings.TrimSpace(string(providerKey)) == "" {
			deepintshield.logger.Warn("provider key is empty, skipping init")
			continue
		}

		config, err := deepintshield.account.GetConfigForProvider(providerKey)
		if err != nil {
			deepintshield.logger.Warn("failed to get config for provider, skipping init: %v", err)
			continue
		}
		if config == nil {
			deepintshield.logger.Warn("config is nil for provider %s, skipping init", providerKey)
			continue
		}

		// Lock the provider mutex during initialization
		providerMutex := deepintshield.getProviderMutex(providerKey)
		providerMutex.Lock()
		err = deepintshield.prepareProvider(providerKey, config)
		providerMutex.Unlock()

		if err != nil {
			deepintshield.logger.Warn("failed to prepare provider %s: %v", providerKey, err)
		}
	}
	return deepintshield, nil
}

// SetTracer sets the tracer for the DeepIntShield instance.
func (deepintshield *DeepIntShield) SetTracer(tracer schemas.Tracer) {
	if tracer == nil {
		// Fall back to no-op tracer if not provided
		tracer = schemas.DefaultTracer()
	}
	deepintshield.tracer.Store(&tracerWrapper{tracer: tracer})
}

// getTracer returns the tracer from atomic storage with type assertion.
func (deepintshield *DeepIntShield) getTracer() schemas.Tracer {
	return deepintshield.tracer.Load().(*tracerWrapper).tracer
}

// SetKeyLoadTracker sets the key load tracker for the DeepIntShield instance.
// This enables per-key load tracking, circuit breaker, and advanced key selection strategies.
// When set to nil, all tracker operations become no-ops.
func (deepintshield *DeepIntShield) SetKeyLoadTracker(tracker *KeyLoadTracker) {
	deepintshield.keyLoadTracker = tracker
}

// GetKeyLoadTracker returns the key load tracker (may be nil if load balancer is disabled).
func (deepintshield *DeepIntShield) GetKeyLoadTracker() *KeyLoadTracker {
	return deepintshield.keyLoadTracker
}

// ReloadConfig reloads the config from DB
// Currently we update account, drop excess requests, and plugin lists
// We will keep on adding other aspects as required
func (deepintshield *DeepIntShield) ReloadConfig(config schemas.DeepIntShieldConfig) error {
	deepintshield.dropExcessRequests.Store(config.DropExcessRequests)
	return nil
}

// PUBLIC API METHODS

// ListModelsRequest sends a list models request to the specified provider.
func (deepintshield *DeepIntShield) ListModelsRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "list models request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ListModelsRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for list models request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ListModelsRequest,
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ListModelsRequest
	deepintshieldReq.ListModelsRequest = req

	resp, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}

	return resp.ListModelsResponse, nil
}

// ListAllModels lists all models from all configured providers.
// It accumulates responses from all providers with a limit of 1000 per provider to get all results.
func (deepintshield *DeepIntShield) ListAllModels(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		req = &schemas.DeepIntShieldListModelsRequest{}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	providerKeys, err := deepintshield.GetConfiguredProviders()
	if err != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: err.Error(),
				Error:   err,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ListModelsRequest,
			},
		}
	}

	startTime := time.Now()

	// Result structure for collecting provider responses
	type providerResult struct {
		provider    schemas.ModelProvider
		models      []schemas.Model
		keyStatuses []schemas.KeyStatus
		err         *schemas.DeepIntShieldError
	}

	results := make(chan providerResult, len(providerKeys))
	var wg sync.WaitGroup

	// Launch concurrent requests for all providers
	for _, providerKey := range providerKeys {
		if strings.TrimSpace(string(providerKey)) == "" {
			continue
		}

		wg.Add(1)
		go func(providerKey schemas.ModelProvider) {
			defer wg.Done()

			providerCtx := schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
			providerCtx.SetValue(schemas.DeepIntShieldContextKeyRequestID, uuid.New().String())

			providerModels := make([]schemas.Model, 0)
			var providerKeyStatuses []schemas.KeyStatus
			var providerErr *schemas.DeepIntShieldError

			// Create request for this provider with limit of 1000
			providerRequest := &schemas.DeepIntShieldListModelsRequest{
				Provider:   providerKey,
				PageSize:   schemas.DefaultPageSize,
				Unfiltered: req.Unfiltered,
			}

			iterations := 0
			for {
				// check for context cancellation
				select {
				case <-ctx.Done():
					deepintshield.logger.Warn("context cancelled for provider %s", providerKey)
					return
				default:
				}

				iterations++
				if iterations > schemas.MaxPaginationRequests {
					deepintshield.logger.Warn("reached maximum pagination requests (%d) for provider %s, please increase the page size", schemas.MaxPaginationRequests, providerKey)
					break
				}

				response, deepintshieldErr := deepintshield.ListModelsRequest(providerCtx, providerRequest)
				if deepintshieldErr != nil {
					// Skip logging "no keys found" and "not supported" errors as they are expected when a provider is not configured
					if !strings.Contains(deepintshieldErr.Error.Message, "no keys found") &&
						!strings.Contains(deepintshieldErr.Error.Message, "not supported") {
						providerErr = deepintshieldErr
						deepintshield.logger.Warn("failed to list models for provider %s: %s", providerKey, GetErrorMessage(deepintshieldErr))
					}
					// Collect key statuses from error (failure case)
					if len(deepintshieldErr.ExtraFields.KeyStatuses) > 0 {
						providerKeyStatuses = append(providerKeyStatuses, deepintshieldErr.ExtraFields.KeyStatuses...)
					}
					break
				}

				if response == nil || len(response.Data) == 0 {
					break
				}

				providerModels = append(providerModels, response.Data...)

				if len(response.KeyStatuses) > 0 {
					providerKeyStatuses = append(providerKeyStatuses, response.KeyStatuses...)
				}

				// Check if there are more pages
				if response.NextPageToken == "" {
					break
				}

				// Set the page token for the next request
				providerRequest.PageToken = response.NextPageToken
			}

			results <- providerResult{
				provider:    providerKey,
				models:      providerModels,
				keyStatuses: providerKeyStatuses,
				err:         providerErr,
			}
		}(providerKey)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)

	// Accumulate all models and key statuses from all providers
	allModels := make([]schemas.Model, 0)
	allKeyStatuses := make([]schemas.KeyStatus, 0)
	var firstError *schemas.DeepIntShieldError

	for result := range results {
		if len(result.models) > 0 {
			allModels = append(allModels, result.models...)
		}
		if len(result.keyStatuses) > 0 {
			allKeyStatuses = append(allKeyStatuses, result.keyStatuses...)
		}
		if result.err != nil && firstError == nil {
			firstError = result.err
		}
	}

	// If we couldn't get any models from any provider, return the first error
	if len(allModels) == 0 && firstError != nil {
		// Attach all key statuses to the error
		firstError.ExtraFields.KeyStatuses = allKeyStatuses
		return nil, firstError
	}

	// Sort models alphabetically by ID
	sort.Slice(allModels, func(i, j int) bool {
		return allModels[i].ID < allModels[j].ID
	})

	// Return aggregated response with accumulated latency and key statuses
	response := &schemas.DeepIntShieldListModelsResponse{
		Data:        allModels,
		KeyStatuses: allKeyStatuses,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.ListModelsRequest,
			Latency:     time.Since(startTime).Milliseconds(),
		},
	}

	response = response.ApplyPagination(req.PageSize, req.PageToken)

	return response, nil
}

// TextCompletionRequest sends a text completion request to the specified provider.
func (deepintshield *DeepIntShield) TextCompletionRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "text completion request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.TextCompletionRequest,
			},
		}
	}
	if (req.Input == nil || (req.Input.PromptStr == nil && req.Input.PromptArray == nil)) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt not provided for text completion request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.TextCompletionRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}
	// Preparing request
	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.TextCompletionRequest
	deepintshieldReq.TextCompletionRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	//TODO: Release the response
	return response.TextCompletionResponse, nil
}

// TextCompletionStreamRequest sends a streaming text completion request to the specified provider.
func (deepintshield *DeepIntShield) TextCompletionStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "text completion stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.TextCompletionStreamRequest,
			},
		}
	}
	if (req.Input == nil || (req.Input.PromptStr == nil && req.Input.PromptArray == nil)) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "text not provided for text completion stream request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.TextCompletionStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}
	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.TextCompletionStreamRequest
	deepintshieldReq.TextCompletionRequest = req
	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

func (deepintshield *DeepIntShield) makeChatCompletionRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "chat completion request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ChatCompletionRequest,
			},
		}
	}
	if req.Input == nil && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "chats not provided for chat completion request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ChatCompletionRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ChatCompletionRequest
	deepintshieldReq.ChatRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}

	return response.ChatResponse, nil
}

// ChatCompletionRequest sends a chat completion request to the specified provider.
func (deepintshield *DeepIntShield) ChatCompletionRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	// If ctx is nil, use the deepintshield context (defensive check for mcp agent mode)
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	response, err := deepintshield.makeChatCompletionRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	// Check if we should enter agent mode
	if deepintshield.MCPManager != nil {
		return deepintshield.MCPManager.CheckAndExecuteAgentForChatRequest(
			ctx,
			req,
			response,
			deepintshield.makeChatCompletionRequest,
			deepintshield.executeMCPToolWithHooks,
		)
	}

	return response, nil
}

// ChatCompletionStreamRequest sends a chat completion stream request to the specified provider.
func (deepintshield *DeepIntShield) ChatCompletionStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "chat completion stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ChatCompletionStreamRequest,
			},
		}
	}
	if req.Input == nil && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "chats not provided for chat completion request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ChatCompletionStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ChatCompletionStreamRequest
	deepintshieldReq.ChatRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

func (deepintshield *DeepIntShield) makeResponsesRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "responses request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ResponsesRequest,
			},
		}
	}
	// In large payload mode, Input is intentionally nil - body streams directly to upstream
	if req.Input == nil {
		isLargePayload, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool)
		if !isLargePayload {
			return nil, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Message: "responses not provided for responses request",
				},
				ExtraFields: schemas.DeepIntShieldErrorExtraFields{
					RequestType:    schemas.ResponsesRequest,
					Provider:       req.Provider,
					ModelRequested: req.Model,
				},
			}
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ResponsesRequest
	deepintshieldReq.ResponsesRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ResponsesResponse, nil
}

// ResponsesRequest sends a responses request to the specified provider.
func (deepintshield *DeepIntShield) ResponsesRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	// If ctx is nil, use the deepintshield context (defensive check for mcp agent mode)
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	response, err := deepintshield.makeResponsesRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	// Check if we should enter agent mode
	if deepintshield.MCPManager != nil {
		return deepintshield.MCPManager.CheckAndExecuteAgentForResponsesRequest(
			ctx,
			req,
			response,
			deepintshield.makeResponsesRequest,
			deepintshield.executeMCPToolWithHooks,
		)
	}

	return response, nil
}

// ResponsesStreamRequest sends a responses stream request to the specified provider.
func (deepintshield *DeepIntShield) ResponsesStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "responses stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ResponsesStreamRequest,
			},
		}
	}
	// In large payload mode, Input is intentionally nil - body streams directly to upstream
	if req.Input == nil {
		isLargePayload, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool)
		if !isLargePayload {
			return nil, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Message: "responses not provided for responses stream request",
				},
				ExtraFields: schemas.DeepIntShieldErrorExtraFields{
					RequestType:    schemas.ResponsesStreamRequest,
					Provider:       req.Provider,
					ModelRequested: req.Model,
				},
			}
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ResponsesStreamRequest
	deepintshieldReq.ResponsesRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

// CountTokensRequest sends a count tokens request to the specified provider.
func (deepintshield *DeepIntShield) CountTokensRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "count tokens request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.CountTokensRequest,
			},
		}
	}
	if req.Input == nil && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "input not provided for count tokens request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.CountTokensRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.CountTokensRequest
	deepintshieldReq.CountTokensRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}

	return response.CountTokensResponse, nil
}

// EmbeddingRequest sends an embedding request to the specified provider.
func (deepintshield *DeepIntShield) EmbeddingRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "embedding request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.EmbeddingRequest,
			},
		}
	}
	if (req.Input == nil || (req.Input.Text == nil && req.Input.Texts == nil && req.Input.Embedding == nil && req.Input.Embeddings == nil)) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "embedding input not provided for embedding request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.EmbeddingRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.EmbeddingRequest
	deepintshieldReq.EmbeddingRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	//TODO: Release the response
	return response.EmbeddingResponse, nil
}

// RerankRequest sends a rerank request to the specified provider.
func (deepintshield *DeepIntShield) RerankRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "rerank request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.RerankRequest,
			},
		}
	}
	if strings.TrimSpace(req.Query) == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "query not provided for rerank request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.RerankRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}
	if len(req.Documents) == 0 {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "documents not provided for rerank request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.RerankRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}
	for i, doc := range req.Documents {
		if strings.TrimSpace(doc.Text) == "" {
			return nil, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Message: fmt.Sprintf("document text is empty at index %d", i),
				},
				ExtraFields: schemas.DeepIntShieldErrorExtraFields{
					RequestType:    schemas.RerankRequest,
					Provider:       req.Provider,
					ModelRequested: req.Model,
				},
			}
		}
	}
	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.RerankRequest
	deepintshieldReq.RerankRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.RerankResponse, nil
}

// SpeechRequest sends a speech request to the specified provider.
func (deepintshield *DeepIntShield) SpeechRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "speech request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.SpeechRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Input == "") && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "speech input not provided for speech request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.SpeechRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.SpeechRequest
	deepintshieldReq.SpeechRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	//TODO: Release the response
	return response.SpeechResponse, nil
}

// SpeechStreamRequest sends a speech stream request to the specified provider.
func (deepintshield *DeepIntShield) SpeechStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "speech stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.SpeechStreamRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Input == "") && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "speech input not provided for speech stream request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.SpeechStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.SpeechStreamRequest
	deepintshieldReq.SpeechRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

// TranscriptionRequest sends a transcription request to the specified provider.
func (deepintshield *DeepIntShield) TranscriptionRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "transcription request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.TranscriptionRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.File == nil) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "transcription input not provided for transcription request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.TranscriptionRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.TranscriptionRequest
	deepintshieldReq.TranscriptionRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	//TODO: Release the response
	return response.TranscriptionResponse, nil
}

// TranscriptionStreamRequest sends a transcription stream request to the specified provider.
func (deepintshield *DeepIntShield) TranscriptionStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "transcription stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.TranscriptionStreamRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.File == nil) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "transcription input not provided for transcription stream request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.TranscriptionStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.TranscriptionStreamRequest
	deepintshieldReq.TranscriptionRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

// ImageGenerationRequest sends an image generation request to the specified provider.
func (deepintshield *DeepIntShield) ImageGenerationRequest(ctx *schemas.DeepIntShieldContext,
	req *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "image generation request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ImageGenerationRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Prompt == "") && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt not provided for image generation request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageGenerationRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ImageGenerationRequest
	deepintshieldReq.ImageGenerationRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	if response == nil || response.ImageGenerationResponse == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "received nil response from provider",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageGenerationRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	return response.ImageGenerationResponse, nil
}

// ImageGenerationStreamRequest sends an image generation stream request to the specified provider.
func (deepintshield *DeepIntShield) ImageGenerationStreamRequest(ctx *schemas.DeepIntShieldContext,
	req *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "image generation stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ImageGenerationStreamRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Prompt == "") && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt not provided for image generation stream request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageGenerationStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ImageGenerationStreamRequest
	deepintshieldReq.ImageGenerationRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

// ImageEditRequest sends an image edit request to the specified provider.
func (deepintshield *DeepIntShield) ImageEditRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "image edit request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ImageEditRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Images == nil || len(req.Input.Images) == 0) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "images not provided for image edit request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageEditRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}
	// Prompt is not required when type is background_removal
	if (req.Params == nil || req.Params.Type == nil || *req.Params.Type != "background_removal") &&
		(req.Input == nil || req.Input.Prompt == "") && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt not provided for image edit request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageEditRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ImageEditRequest
	deepintshieldReq.ImageEditRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}

	if response == nil || response.ImageGenerationResponse == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "received nil response from provider",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageEditRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	return response.ImageGenerationResponse, nil
}

// ImageEditStreamRequest sends an image edit stream request to the specified provider.
func (deepintshield *DeepIntShield) ImageEditStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "image edit stream request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ImageEditStreamRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Images == nil || len(req.Input.Images) == 0) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "images not provided for image edit stream request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageEditStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}
	// Prompt is not required when type is background_removal
	if (req.Params == nil || req.Params.Type == nil || *req.Params.Type != "background_removal") &&
		(req.Input == nil || req.Input.Prompt == "") && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt not provided for image edit stream request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageEditStreamRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ImageEditStreamRequest
	deepintshieldReq.ImageEditRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

// ImageVariationRequest sends an image variation request to the specified provider.
func (deepintshield *DeepIntShield) ImageVariationRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "image variation request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ImageVariationRequest,
			},
		}
	}
	if (req.Input == nil || req.Input.Image.Image == nil || len(req.Input.Image.Image) == 0) && !isLargePayloadPassthrough(ctx) {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "image not provided for image variation request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageVariationRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ImageVariationRequest
	deepintshieldReq.ImageVariationRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}

	if response == nil || response.ImageGenerationResponse == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "received nil response from provider",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.ImageVariationRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	return response.ImageGenerationResponse, nil
}

// VideoGenerationRequest sends a video generation request to the specified provider.
func (deepintshield *DeepIntShield) VideoGenerationRequest(ctx *schemas.DeepIntShieldContext,
	req *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video generation request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoGenerationRequest,
			},
		}
	}
	if req.Input == nil || req.Input.Prompt == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt not provided for video generation request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.VideoGenerationRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.VideoGenerationRequest
	deepintshieldReq.VideoGenerationRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	if response == nil || response.VideoGenerationResponse == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "received nil response from provider",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    schemas.VideoGenerationRequest,
				Provider:       req.Provider,
				ModelRequested: req.Model,
			},
		}
	}

	return response.VideoGenerationResponse, nil
}

func (deepintshield *DeepIntShield) VideoRetrieveRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video retrieve request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRetrieveRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for video retrieve request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRetrieveRequest,
			},
		}
	}
	if req.ID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video_id is required for video retrieve request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRetrieveRequest,
				Provider:    req.Provider,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.VideoRetrieveRequest
	deepintshieldReq.VideoRetrieveRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	if response == nil || response.VideoGenerationResponse == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "received nil response from provider",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRetrieveRequest,
				Provider:    req.Provider,
			},
		}
	}
	return response.VideoGenerationResponse, nil
}

// VideoDownloadRequest downloads video content from the provider.
func (deepintshield *DeepIntShield) VideoDownloadRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video download request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoDownloadRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for video download request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoDownloadRequest,
			},
		}
	}
	if req.ID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video_id is required for video download request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoDownloadRequest,
				Provider:    req.Provider,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.VideoDownloadRequest
	deepintshieldReq.VideoDownloadRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.VideoDownloadResponse, nil
}

func (deepintshield *DeepIntShield) VideoRemixRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video remix request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRemixRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for video remix request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRemixRequest,
			},
		}
	}
	if req.ID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video_id is required for video remix request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRemixRequest,
				Provider:    req.Provider,
			},
		}
	}
	if req.Input == nil || req.Input.Prompt == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "prompt is required for video remix request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRemixRequest,
				Provider:    req.Provider,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.VideoRemixRequest
	deepintshieldReq.VideoRemixRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	if response == nil || response.VideoGenerationResponse == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "received nil response from provider",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoRemixRequest,
				Provider:    req.Provider,
			},
		}
	}
	return response.VideoGenerationResponse, nil
}

func (deepintshield *DeepIntShield) VideoListRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video list request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoListRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for video list request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoListRequest,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.VideoListRequest
	deepintshieldReq.VideoListRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.VideoListResponse, nil
}

func (deepintshield *DeepIntShield) VideoDeleteRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video delete request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoDeleteRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for video delete request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoDeleteRequest,
			},
		}
	}
	if req.ID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "video_id is required for video delete request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.VideoDeleteRequest,
				Provider:    req.Provider,
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.VideoDeleteRequest
	deepintshieldReq.VideoDeleteRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.VideoDeleteResponse, nil
}

// BatchCreateRequest creates a new batch job for asynchronous processing.
func (deepintshield *DeepIntShield) BatchCreateRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch create request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for batch create request",
			},
		}
	}
	if req.InputFileID == "" && len(req.Requests) == 0 {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "either input_file_id or requests is required for batch create request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	provider := deepintshield.getProviderByKey(req.Provider)
	if provider == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider not found for batch create request",
			},
		}
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.BatchCreateRequest
	deepintshieldReq.BatchCreateRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.BatchCreateResponse, nil
}

// BatchListRequest lists batch jobs for the specified provider.
func (deepintshield *DeepIntShield) BatchListRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch list request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for batch list request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.BatchListRequest
	deepintshieldReq.BatchListRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.BatchListResponse, nil
}

// BatchRetrieveRequest retrieves a specific batch job.
func (deepintshield *DeepIntShield) BatchRetrieveRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch retrieve request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for batch retrieve request",
			},
		}
	}
	if req.BatchID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch_id is required for batch retrieve request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.BatchRetrieveRequest
	deepintshieldReq.BatchRetrieveRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.BatchRetrieveResponse, nil
}

// BatchCancelRequest cancels a batch job.
func (deepintshield *DeepIntShield) BatchCancelRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch cancel request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for batch cancel request",
			},
		}
	}
	if req.BatchID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch_id is required for batch cancel request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.BatchCancelRequest
	deepintshieldReq.BatchCancelRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.BatchCancelResponse, nil
}

// BatchDeleteRequest deletes a batch job.
func (deepintshield *DeepIntShield) BatchDeleteRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch delete request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for batch delete request",
			},
		}
	}
	if req.BatchID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch_id is required for batch delete request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.BatchDeleteRequest
	deepintshieldReq.BatchDeleteRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.BatchDeleteResponse, nil
}

// BatchResultsRequest retrieves results from a completed batch job.
func (deepintshield *DeepIntShield) BatchResultsRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch results request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.BatchResultsRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for batch results request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.BatchResultsRequest,
			},
		}
	}
	if req.BatchID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "batch_id is required for batch results request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.BatchResultsRequest,
				Provider:    req.Provider,
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.BatchResultsRequest
	deepintshieldReq.BatchResultsRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.BatchResultsResponse, nil
}

// FileUploadRequest uploads a file to the specified provider.
func (deepintshield *DeepIntShield) FileUploadRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file upload request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.FileUploadRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for file upload request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.FileUploadRequest,
			},
		}
	}
	if len(req.File) == 0 {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file content is required for file upload request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.FileUploadRequest,
				Provider:    req.Provider,
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.FileUploadRequest
	deepintshieldReq.FileUploadRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.FileUploadResponse, nil
}

// FileListRequest lists files from the specified provider.
func (deepintshield *DeepIntShield) FileListRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file list request is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.FileListRequest,
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for file list request",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.FileListRequest,
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.FileListRequest
	deepintshieldReq.FileListRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.FileListResponse, nil
}

// FileRetrieveRequest retrieves file metadata from the specified provider.
func (deepintshield *DeepIntShield) FileRetrieveRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file retrieve request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for file retrieve request",
			},
		}
	}
	if req.FileID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file_id is required for file retrieve request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.FileRetrieveRequest
	deepintshieldReq.FileRetrieveRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.FileRetrieveResponse, nil
}

// FileDeleteRequest deletes a file from the specified provider.
func (deepintshield *DeepIntShield) FileDeleteRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file delete request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for file delete request",
			},
		}
	}
	if req.FileID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file_id is required for file delete request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.FileDeleteRequest
	deepintshieldReq.FileDeleteRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.FileDeleteResponse, nil
}

// FileContentRequest downloads file content from the specified provider.
func (deepintshield *DeepIntShield) FileContentRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file content request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for file content request",
			},
		}
	}
	if req.FileID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file_id is required for file content request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.FileContentRequest
	deepintshieldReq.FileContentRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.FileContentResponse, nil
}

func (deepintshield *DeepIntShield) Passthrough(
	ctx *schemas.DeepIntShieldContext,
	provider schemas.ModelProvider,
	req *schemas.DeepIntShieldPassthroughRequest,
) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		sc := fasthttp.StatusBadRequest
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			StatusCode:           &sc,
			Error:                &schemas.ErrorField{Message: "passthrough request is nil"},
		}
	}

	req.Provider = provider

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.PassthroughRequest
	deepintshieldReq.PassthroughRequest = req

	resp, deepintshieldErr := deepintshield.handleRequest(ctx, deepintshieldReq)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}
	if resp == nil || resp.PassthroughResponse == nil {
		sc := fasthttp.StatusBadGateway
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			StatusCode:           &sc,
			Error:                &schemas.ErrorField{Message: "provider returned nil passthrough response"},
		}
	}
	return resp.PassthroughResponse, nil
}

func (deepintshield *DeepIntShield) PassthroughStream(
	ctx *schemas.DeepIntShieldContext,
	provider schemas.ModelProvider,
	req *schemas.DeepIntShieldPassthroughRequest,
) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if req == nil {
		sc := fasthttp.StatusBadRequest
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			StatusCode:           &sc,
			Error:                &schemas.ErrorField{Message: "passthrough request is nil"},
		}
	}

	req.Provider = provider

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.PassthroughStreamRequest
	deepintshieldReq.PassthroughRequest = req

	return deepintshield.handleStreamRequest(ctx, deepintshieldReq)
}

// ExecuteChatMCPTool executes an MCP tool call and returns the result as a chat message.
// This is the main public API for manual MCP tool execution in Chat format.
//
// Parameters:
//   - ctx: Execution context
//   - toolCall: The tool call to execute (from assistant message)
//
// Returns:
//   - *schemas.ChatMessage: Tool message with execution result
//   - *schemas.DeepIntShieldError: Any execution error
func (deepintshield *DeepIntShield) ExecuteChatMCPTool(ctx *schemas.DeepIntShieldContext, toolCall *schemas.ChatAssistantMessageToolCall) (*schemas.ChatMessage, *schemas.DeepIntShieldError) {
	// Handle nil context early to prevent issues downstream
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	// Validate toolCall is not nil
	if toolCall == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "toolCall cannot be nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ChatCompletionRequest,
			},
		}
	}

	// Get MCP request from pool and populate
	mcpRequest := deepintshield.getMCPRequest()
	mcpRequest.RequestType = schemas.MCPRequestTypeChatToolCall
	mcpRequest.ChatAssistantMessageToolCall = toolCall
	defer deepintshield.releaseMCPRequest(mcpRequest)

	// Execute with common handler
	result, err := deepintshield.handleMCPToolExecution(ctx, mcpRequest, schemas.ChatCompletionRequest)
	if err != nil {
		return nil, err
	}

	// Validate and extract chat message from result
	if result == nil || result.ChatMessage == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "MCP tool execution returned nil chat message",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ChatCompletionRequest,
			},
		}
	}

	return result.ChatMessage, nil
}

// ExecuteResponsesMCPTool executes an MCP tool call and returns the result as a responses message.
// This is the main public API for manual MCP tool execution in Responses format.
//
// Parameters:
//   - ctx: Execution context
//   - toolCall: The tool call to execute (from assistant message)
//
// Returns:
//   - *schemas.ResponsesMessage: Tool message with execution result
//   - *schemas.DeepIntShieldError: Any execution error
func (deepintshield *DeepIntShield) ExecuteResponsesMCPTool(ctx *schemas.DeepIntShieldContext, toolCall *schemas.ResponsesToolMessage) (*schemas.ResponsesMessage, *schemas.DeepIntShieldError) {
	// Handle nil context early to prevent issues downstream
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	// Validate toolCall is not nil
	if toolCall == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "toolCall cannot be nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ResponsesRequest,
			},
		}
	}

	// Get MCP request from pool and populate
	mcpRequest := deepintshield.getMCPRequest()
	mcpRequest.RequestType = schemas.MCPRequestTypeResponsesToolCall
	mcpRequest.ResponsesToolMessage = toolCall
	defer deepintshield.releaseMCPRequest(mcpRequest)

	// Execute with common handler
	result, err := deepintshield.handleMCPToolExecution(ctx, mcpRequest, schemas.ResponsesRequest)
	if err != nil {
		return nil, err
	}

	// Validate and extract responses message from result
	if result == nil || result.ResponsesMessage == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "MCP tool execution returned nil responses message",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: schemas.ResponsesRequest,
			},
		}
	}

	return result.ResponsesMessage, nil
}

// ContainerCreateRequest creates a new container.
func (deepintshield *DeepIntShield) ContainerCreateRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container create request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container create request",
			},
		}
	}
	if req.Name == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "name is required for container create request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerCreateRequest
	deepintshieldReq.ContainerCreateRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerCreateResponse, nil
}

// ContainerListRequest lists containers.
func (deepintshield *DeepIntShield) ContainerListRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container list request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container list request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerListRequest
	deepintshieldReq.ContainerListRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerListResponse, nil
}

// ContainerRetrieveRequest retrieves a specific container.
func (deepintshield *DeepIntShield) ContainerRetrieveRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container retrieve request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container retrieve request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container retrieve request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerRetrieveRequest
	deepintshieldReq.ContainerRetrieveRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerRetrieveResponse, nil
}

// ContainerDeleteRequest deletes a container.
func (deepintshield *DeepIntShield) ContainerDeleteRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container delete request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container delete request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container delete request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerDeleteRequest
	deepintshieldReq.ContainerDeleteRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerDeleteResponse, nil
}

// ContainerFileCreateRequest creates a file in a container.
func (deepintshield *DeepIntShield) ContainerFileCreateRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container file create request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container file create request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container file create request",
			},
		}
	}
	if len(req.File) == 0 && (req.FileID == nil || strings.TrimSpace(*req.FileID) == "") && (req.Path == nil || strings.TrimSpace(*req.Path) == "") {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "one of file, file_id, or path is required for container file create request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerFileCreateRequest
	deepintshieldReq.ContainerFileCreateRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerFileCreateResponse, nil
}

// ContainerFileListRequest lists files in a container.
func (deepintshield *DeepIntShield) ContainerFileListRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container file list request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container file list request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container file list request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerFileListRequest
	deepintshieldReq.ContainerFileListRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerFileListResponse, nil
}

// ContainerFileRetrieveRequest retrieves a file from a container.
func (deepintshield *DeepIntShield) ContainerFileRetrieveRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container file retrieve request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container file retrieve request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container file retrieve request",
			},
		}
	}
	if req.FileID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file_id is required for container file retrieve request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerFileRetrieveRequest
	deepintshieldReq.ContainerFileRetrieveRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerFileRetrieveResponse, nil
}

// ContainerFileContentRequest retrieves the content of a file from a container.
func (deepintshield *DeepIntShield) ContainerFileContentRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container file content request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container file content request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container file content request",
			},
		}
	}
	if req.FileID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file_id is required for container file content request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerFileContentRequest
	deepintshieldReq.ContainerFileContentRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerFileContentResponse, nil
}

// ContainerFileDeleteRequest deletes a file from a container.
func (deepintshield *DeepIntShield) ContainerFileDeleteRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	if req == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container file delete request is nil",
			},
		}
	}
	if req.Provider == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "provider is required for container file delete request",
			},
		}
	}
	if req.ContainerID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "container_id is required for container file delete request",
			},
		}
	}
	if req.FileID == "" {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "file_id is required for container file delete request",
			},
		}
	}
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshieldReq := deepintshield.getDeepIntShieldRequest()
	deepintshieldReq.RequestType = schemas.ContainerFileDeleteRequest
	deepintshieldReq.ContainerFileDeleteRequest = req

	response, err := deepintshield.handleRequest(ctx, deepintshieldReq)
	if err != nil {
		return nil, err
	}
	return response.ContainerFileDeleteResponse, nil
}

// RemovePlugin removes a plugin from the server.
func (deepintshield *DeepIntShield) RemovePlugin(name string, pluginTypes []schemas.PluginType) error {
	for _, pluginType := range pluginTypes {
		switch pluginType {
		case schemas.PluginTypeLLM:
			err := deepintshield.removeLLMPlugin(name)
			if err != nil {
				return err
			}
		case schemas.PluginTypeMCP:
			err := deepintshield.removeMCPPlugin(name)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// removeLLMPlugin removes an LLM plugin from the server.
func (deepintshield *DeepIntShield) removeLLMPlugin(name string) error {
	for {
		oldPlugins := deepintshield.llmPlugins.Load()
		if oldPlugins == nil {
			return nil
		}
		var pluginToCleanup schemas.LLMPlugin
		found := false
		// Create new slice without the plugin to remove
		newPlugins := make([]schemas.LLMPlugin, 0, len(*oldPlugins))
		for _, p := range *oldPlugins {
			if p.GetName() == name {
				pluginToCleanup = p
				deepintshield.logger.Debug("removing LLM plugin %s", name)
				found = true
			} else {
				newPlugins = append(newPlugins, p)
			}
		}
		if !found {
			return nil
		}
		// Atomic compare-and-swap
		if deepintshield.llmPlugins.CompareAndSwap(oldPlugins, &newPlugins) {
			// Cleanup the old plugin
			err := pluginToCleanup.Cleanup()
			if err != nil {
				deepintshield.logger.Warn("failed to cleanup old LLM plugin %s: %v", pluginToCleanup.GetName(), err)
			}
			return nil
		}
		// Retrying as swapping did not work
	}
}

// removeMCPPlugin removes an MCP plugin from the server.
func (deepintshield *DeepIntShield) removeMCPPlugin(name string) error {
	for {
		oldPlugins := deepintshield.mcpPlugins.Load()
		if oldPlugins == nil {
			return nil
		}
		var pluginToCleanup schemas.MCPPlugin
		found := false
		// Create new slice without the plugin to remove
		newPlugins := make([]schemas.MCPPlugin, 0, len(*oldPlugins))
		for _, p := range *oldPlugins {
			if p.GetName() == name {
				pluginToCleanup = p
				deepintshield.logger.Debug("removing MCP plugin %s", name)
				found = true
			} else {
				newPlugins = append(newPlugins, p)
			}
		}
		if !found {
			return nil
		}
		// Atomic compare-and-swap
		if deepintshield.mcpPlugins.CompareAndSwap(oldPlugins, &newPlugins) {
			// Cleanup the old plugin
			err := pluginToCleanup.Cleanup()
			if err != nil {
				deepintshield.logger.Warn("failed to cleanup old MCP plugin %s: %v", pluginToCleanup.GetName(), err)
			}
			return nil
		}
		// Retrying as swapping did not work
	}
}

// ReloadPlugin reloads a plugin with new instance
// During the reload - it's stop the world phase where we take a global lock on the plugin mutex
func (deepintshield *DeepIntShield) ReloadPlugin(plugin schemas.BasePlugin, pluginTypes []schemas.PluginType) error {
	for _, pluginType := range pluginTypes {
		switch pluginType {
		case schemas.PluginTypeLLM:
			llmPlugin, ok := plugin.(schemas.LLMPlugin)
			if !ok {
				return fmt.Errorf("plugin %s is not an LLMPlugin", plugin.GetName())
			}
			err := deepintshield.reloadLLMPlugin(llmPlugin)
			if err != nil {
				return err
			}
		case schemas.PluginTypeMCP:
			mcpPlugin, ok := plugin.(schemas.MCPPlugin)
			if !ok {
				return fmt.Errorf("plugin %s is not an MCPPlugin", plugin.GetName())
			}
			err := deepintshield.reloadMCPPlugin(mcpPlugin)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// reloadLLMPlugin reloads an LLM plugin with new instance
func (deepintshield *DeepIntShield) reloadLLMPlugin(plugin schemas.LLMPlugin) error {
	for {
		var pluginToCleanup schemas.LLMPlugin
		found := false
		oldPlugins := deepintshield.llmPlugins.Load()

		// Create new slice with replaced plugin or initialize empty slice
		var newPlugins []schemas.LLMPlugin
		if oldPlugins == nil {
			// Initialize new empty slice for the first plugin
			newPlugins = make([]schemas.LLMPlugin, 0)
		} else {
			newPlugins = make([]schemas.LLMPlugin, len(*oldPlugins))
			copy(newPlugins, *oldPlugins)
		}

		for i, p := range newPlugins {
			if p.GetName() == plugin.GetName() {
				// Cleaning up old plugin before replacing it
				pluginToCleanup = p
				deepintshield.logger.Debug("replacing LLM plugin %s with new instance", plugin.GetName())
				newPlugins[i] = plugin
				found = true
				break
			}
		}
		if !found {
			// This means that user is adding a new plugin
			deepintshield.logger.Debug("adding new LLM plugin %s", plugin.GetName())
			newPlugins = append(newPlugins, plugin)
		}
		// Atomic compare-and-swap
		if deepintshield.llmPlugins.CompareAndSwap(oldPlugins, &newPlugins) {
			// Cleanup the old plugin
			if found && pluginToCleanup != nil {
				err := pluginToCleanup.Cleanup()
				if err != nil {
					deepintshield.logger.Warn("failed to cleanup old LLM plugin %s: %v", pluginToCleanup.GetName(), err)
				}
			}
			return nil
		}
		// Retrying as swapping did not work
	}
}

// reloadMCPPlugin reloads an MCP plugin with new instance
func (deepintshield *DeepIntShield) reloadMCPPlugin(plugin schemas.MCPPlugin) error {
	for {
		var pluginToCleanup schemas.MCPPlugin
		found := false
		oldPlugins := deepintshield.mcpPlugins.Load()
		if oldPlugins == nil {
			return nil
		}
		// Create new slice with replaced plugin
		newPlugins := make([]schemas.MCPPlugin, len(*oldPlugins))
		copy(newPlugins, *oldPlugins)
		for i, p := range newPlugins {
			if p.GetName() == plugin.GetName() {
				// Cleaning up old plugin before replacing it
				pluginToCleanup = p
				deepintshield.logger.Debug("replacing MCP plugin %s with new instance", plugin.GetName())
				newPlugins[i] = plugin
				found = true
				break
			}
		}
		if !found {
			// This means that user is adding a new plugin
			deepintshield.logger.Debug("adding new MCP plugin %s", plugin.GetName())
			newPlugins = append(newPlugins, plugin)
		}
		// Atomic compare-and-swap
		if deepintshield.mcpPlugins.CompareAndSwap(oldPlugins, &newPlugins) {
			// Cleanup the old plugin
			if found && pluginToCleanup != nil {
				err := pluginToCleanup.Cleanup()
				if err != nil {
					deepintshield.logger.Warn("failed to cleanup old MCP plugin %s: %v", pluginToCleanup.GetName(), err)
				}
			}
			return nil
		}
		// Retrying as swapping did not work
	}
}

// ReorderPlugins reorders all plugin slices (LLM, MCP) to match the given
// base plugin name ordering. This should be called after SortAndRebuildPlugins
// on the config layer to sync the core's execution order.
// Plugins not in the ordering are appended at the end (defensive).
func (deepintshield *DeepIntShield) ReorderPlugins(orderedNames []string) {
	pos := make(map[string]int, len(orderedNames))
	for i, name := range orderedNames {
		pos[name] = i
	}
	reorderAtomicSlice(&deepintshield.llmPlugins, pos)
	reorderAtomicSlice(&deepintshield.mcpPlugins, pos)
}

// pluginWithName is satisfied by both LLMPlugin and MCPPlugin.
type pluginWithName interface {
	GetName() string
}

// reorderAtomicSlice atomically reorders the plugin slice stored behind ptr
// so that plugins appear in the order given by pos (name → position).
// Uses CAS retry for lock-free safety.
func reorderAtomicSlice[T pluginWithName](ptr *atomic.Pointer[[]T], pos map[string]int) {
	for {
		old := ptr.Load()
		if old == nil || len(*old) == 0 {
			return
		}
		reordered := make([]T, len(*old))
		copy(reordered, *old)
		sort.SliceStable(reordered, func(i, j int) bool {
			iPos, iOk := pos[reordered[i].GetName()]
			jPos, jOk := pos[reordered[j].GetName()]
			if !iOk && !jOk {
				return false
			}
			if !iOk {
				return false
			}
			if !jOk {
				return true
			}
			return iPos < jPos
		})
		if ptr.CompareAndSwap(old, &reordered) {
			return
		}
	}
}

// GetConfiguredProviders returns the configured providers.
//
// Returns:
//   - []schemas.ModelProvider: List of configured providers
//   - error: Any error that occurred during the retrieval process
//
// Example:
//
//	providers, err := deepintshield.GetConfiguredProviders()
//	if err != nil {
//		return nil, err
//	}
//	fmt.Println(providers)
func (deepintshield *DeepIntShield) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	providers := deepintshield.providers.Load()
	if providers == nil {
		return nil, fmt.Errorf("no providers configured")
	}
	modelProviders := make([]schemas.ModelProvider, len(*providers))
	for i, provider := range *providers {
		modelProviders[i] = provider.GetProviderKey()
	}
	return modelProviders, nil
}

// RemoveProvider removes a provider from the server.
// This method gracefully stops all workers for the provider,
// closes the request queue, and removes the provider from the providers slice.
//
// Parameters:
//   - providerKey: The provider to remove
//
// Returns:
//   - error: Any error that occurred during the removal process
func (deepintshield *DeepIntShield) RemoveProvider(providerKey schemas.ModelProvider) error {
	deepintshield.logger.Info("Removing provider %s", providerKey)
	providerMutex := deepintshield.getProviderMutex(providerKey)
	providerMutex.Lock()
	defer providerMutex.Unlock()

	// Step 1: Load the ProviderQueue and verify provider exists
	pqValue, exists := deepintshield.requestQueues.Load(providerKey)
	if !exists {
		return fmt.Errorf("provider %s not found in request queues", providerKey)
	}
	pq := pqValue.(*ProviderQueue)

	// Step 2: Signal closing to producers (prevents new sends)
	// This must happen before closing the queue to avoid "send on closed channel" panics
	pq.signalClosing()
	deepintshield.logger.Debug("signaled closing for provider %s", providerKey)

	// Step 3: Now safe to close the queue (no new producers can send)
	pq.closeQueue()
	deepintshield.logger.Debug("closed request queue for provider %s", providerKey)

	// Step 4: Wait for all workers to finish processing in-flight requests
	waitGroup, exists := deepintshield.waitGroups.Load(providerKey)
	if exists {
		waitGroup.(*sync.WaitGroup).Wait()
		deepintshield.logger.Debug("all workers for provider %s have stopped", providerKey)
	}

	// Step 5: Remove the provider from the request queues
	deepintshield.requestQueues.Delete(providerKey)

	// Step 6: Remove the provider from the wait groups
	deepintshield.waitGroups.Delete(providerKey)

	// Step 7: Remove the provider from the providers slice
	replacementAttempts := 0
	maxReplacementAttempts := 100 // Prevent infinite loops in high-contention scenarios
	for {
		replacementAttempts++
		if replacementAttempts > maxReplacementAttempts {
			return fmt.Errorf("failed to replace provider %s in providers slice after %d attempts", providerKey, maxReplacementAttempts)
		}
		oldPtr := deepintshield.providers.Load()
		var oldSlice []schemas.Provider
		if oldPtr != nil {
			oldSlice = *oldPtr
		}
		// Create new slice without the old provider of this key
		// Use exact capacity to avoid allocations
		if len(oldSlice) == 0 {
			return fmt.Errorf("provider %s not found in providers slice", providerKey)
		}
		newSlice := make([]schemas.Provider, 0, len(oldSlice)-1)
		for _, existingProvider := range oldSlice {
			if existingProvider.GetProviderKey() != providerKey {
				newSlice = append(newSlice, existingProvider)
			}
		}
		if deepintshield.providers.CompareAndSwap(oldPtr, &newSlice) {
			deepintshield.logger.Debug("successfully removed provider instance for %s in providers slice", providerKey)
			break
		}
		// Retrying as swapping did not work (likely due to concurrent modification)
	}

	deepintshield.logger.Info("successfully removed provider %s", providerKey)
	schemas.UnregisterKnownProvider(providerKey)
	return nil
}

// UpdateProvider dynamically updates a provider with new configuration.
// This method gracefully recreates the provider instance with updated settings,
// stops existing workers, creates a new queue with updated settings,
// and starts new workers with the updated provider and concurrency configuration.
//
// Parameters:
//   - providerKey: The provider to update
//
// Returns:
//   - error: Any error that occurred during the update process
//
// Note: This operation will temporarily pause request processing for the specified provider
// while the transition occurs. In-flight requests will complete before workers are stopped.
// Buffered requests in the old queue will be transferred to the new queue to prevent loss.
func (deepintshield *DeepIntShield) UpdateProvider(providerKey schemas.ModelProvider) error {
	deepintshield.logger.Info(fmt.Sprintf("Updating provider configuration for provider %s", providerKey))
	// Get the updated configuration from the account
	providerConfig, err := deepintshield.account.GetConfigForProvider(providerKey)
	if err != nil {
		return fmt.Errorf("failed to get updated config for provider %s: %v", providerKey, err)
	}
	if providerConfig == nil {
		return fmt.Errorf("config is nil for provider %s", providerKey)
	}
	// Lock the provider to prevent concurrent access during update
	providerMutex := deepintshield.getProviderMutex(providerKey)
	providerMutex.Lock()
	defer providerMutex.Unlock()

	// Check if provider currently exists
	oldPqValue, exists := deepintshield.requestQueues.Load(providerKey)
	if !exists {
		deepintshield.logger.Debug("provider %s not currently active, initializing with new configuration", providerKey)
		// If provider doesn't exist, just prepare it with new configuration
		return deepintshield.prepareProvider(providerKey, providerConfig)
	}

	oldPq := oldPqValue.(*ProviderQueue)

	deepintshield.logger.Debug("gracefully stopping existing workers for provider %s", providerKey)

	// Step 1: Create new ProviderQueue with updated buffer size
	newPq := &ProviderQueue{
		queue:      make(chan *ChannelMessage, providerConfig.ConcurrencyAndBufferSize.BufferSize),
		done:       make(chan struct{}),
		signalOnce: sync.Once{},
		closeOnce:  sync.Once{},
	}

	// Step 2: Atomically replace the queue FIRST (new producers immediately get the new queue)
	// This minimizes the window where requests fail during the update
	deepintshield.requestQueues.Store(providerKey, newPq)
	deepintshield.logger.Debug("stored new queue for provider %s, new producers will use it", providerKey)

	// Step 3: Signal old queue is closing to producers that already have a reference
	// Only in-flight producers with the old reference will see this
	oldPq.signalClosing()
	deepintshield.logger.Debug("signaled closing for old queue of provider %s", providerKey)

	// Step 4: Transfer any buffered requests from old queue to new queue
	// This prevents request loss during the transition
	transferredCount := 0
	var transferWaitGroup sync.WaitGroup
	for {
		select {
		case msg := <-oldPq.queue:
			select {
			case newPq.queue <- msg:
				transferredCount++
			default:
				// New queue is full, handle this request in a goroutine
				// This is unlikely with proper buffer sizing but provides safety
				transferWaitGroup.Add(1)
				go func(m *ChannelMessage) {
					defer transferWaitGroup.Done()
					select {
					case newPq.queue <- m:
						// Message successfully transferred
					case <-time.After(5 * time.Second):
						deepintshield.logger.Warn("Failed to transfer buffered request to new queue within timeout")
						// Send error response to avoid hanging the client
						provider, model, _ := m.DeepIntShieldRequest.GetRequestFields()
						select {
						case m.Err <- schemas.DeepIntShieldError{
							IsDeepIntShieldError: false,
							Error: &schemas.ErrorField{
								Message: "request failed during provider concurrency update",
							},
							ExtraFields: schemas.DeepIntShieldErrorExtraFields{
								RequestType:    m.RequestType,
								Provider:       provider,
								ModelRequested: model,
							},
						}:
						case <-time.After(1 * time.Second):
							// If we can't send the error either, just log and continue
							deepintshield.logger.Warn("Failed to send error response during transfer timeout")
						}
					}
				}(msg)
				goto transferComplete
			}
		default:
			// No more buffered messages
			goto transferComplete
		}
	}

transferComplete:
	// Wait for all transfer goroutines to complete
	transferWaitGroup.Wait()
	if transferredCount > 0 {
		deepintshield.logger.Info("transferred %d buffered requests to new queue for provider %s", transferredCount, providerKey)
	}

	// Step 5: Close the old queue to signal workers to stop
	oldPq.closeQueue()
	deepintshield.logger.Debug("closed old request queue for provider %s", providerKey)

	// Step 6: Wait for all existing workers to finish processing in-flight requests
	waitGroup, exists := deepintshield.waitGroups.Load(providerKey)
	if exists {
		waitGroup.(*sync.WaitGroup).Wait()
		deepintshield.logger.Debug("all workers for provider %s have stopped", providerKey)
	}

	// Step 7: Create new wait group for the updated workers
	deepintshield.waitGroups.Store(providerKey, &sync.WaitGroup{})

	// Step 8: Create provider instance
	provider, err := deepintshield.createBaseProvider(providerKey, providerConfig)
	if err != nil {
		return fmt.Errorf("failed to create provider instance for %s: %v", providerKey, err)
	}

	// Step 8.5: Atomically replace the provider in the providers slice
	// This must happen before starting new workers to prevent stale reads
	deepintshield.logger.Debug("atomically replacing provider instance in providers slice for %s", providerKey)

	replacementAttempts := 0
	maxReplacementAttempts := 100 // Prevent infinite loops in high-contention scenarios

	for {
		replacementAttempts++
		if replacementAttempts > maxReplacementAttempts {
			return fmt.Errorf("failed to replace provider %s in providers slice after %d attempts", providerKey, maxReplacementAttempts)
		}

		oldPtr := deepintshield.providers.Load()
		var oldSlice []schemas.Provider
		if oldPtr != nil {
			oldSlice = *oldPtr
		}

		// Create new slice without the old provider of this key
		// Use exact capacity to avoid allocations
		newSlice := make([]schemas.Provider, 0, len(oldSlice))
		oldProviderFound := false

		for _, existingProvider := range oldSlice {
			if existingProvider.GetProviderKey() != providerKey {
				newSlice = append(newSlice, existingProvider)
			} else {
				oldProviderFound = true
			}
		}

		// Add the new provider
		newSlice = append(newSlice, provider)

		if deepintshield.providers.CompareAndSwap(oldPtr, &newSlice) {
			if oldProviderFound {
				deepintshield.logger.Debug("successfully replaced existing provider instance for %s in providers slice", providerKey)
			} else {
				deepintshield.logger.Debug("successfully added new provider instance for %s to providers slice", providerKey)
			}
			break
		}
		// Retrying as swapping did not work (likely due to concurrent modification)
	}

	// Step 9: Start new workers with updated concurrency
	deepintshield.logger.Debug("starting %d new workers for provider %s with buffer size %d",
		providerConfig.ConcurrencyAndBufferSize.Concurrency,
		providerKey,
		providerConfig.ConcurrencyAndBufferSize.BufferSize)

	waitGroupValue, _ := deepintshield.waitGroups.Load(providerKey)
	currentWaitGroup := waitGroupValue.(*sync.WaitGroup)

	for range providerConfig.ConcurrencyAndBufferSize.Concurrency {
		currentWaitGroup.Add(1)
		go deepintshield.requestWorker(provider, providerConfig, newPq)
	}

	deepintshield.logger.Info("successfully updated provider configuration for provider %s", providerKey)
	return nil
}

// GetDropExcessRequests returns the current value of DropExcessRequests
func (deepintshield *DeepIntShield) GetDropExcessRequests() bool {
	return deepintshield.dropExcessRequests.Load()
}

// UpdateDropExcessRequests updates the DropExcessRequests setting at runtime.
// This allows for hot-reloading of this configuration value.
func (deepintshield *DeepIntShield) UpdateDropExcessRequests(value bool) {
	deepintshield.dropExcessRequests.Store(value)
	deepintshield.logger.Info("drop_excess_requests updated to: %v", value)
}

// getProviderMutex gets or creates a mutex for the given provider
func (deepintshield *DeepIntShield) getProviderMutex(providerKey schemas.ModelProvider) *sync.RWMutex {
	mutexValue, _ := deepintshield.providerMutexes.LoadOrStore(providerKey, &sync.RWMutex{})
	return mutexValue.(*sync.RWMutex)
}

// MCP PUBLIC API

// RegisterMCPTool registers a typed tool handler with the MCP integration.
// This allows developers to easily add custom tools that will be available
// to all LLM requests processed by this DeepIntShield instance.
//
// Parameters:
//   - name: Unique tool name
//   - description: Human-readable tool description
//   - handler: Function that handles tool execution
//   - toolSchema: DeepIntShield tool schema for function calling
//
// Returns:
//   - error: Any registration error
//
// Example:
//
//	type EchoArgs struct {
//	    Message string `json:"message"`
//	}
//
//	err := deepintshield.RegisterMCPTool("echo", "Echo a message",
//	    func(args EchoArgs) (string, error) {
//	        return args.Message, nil
//	    }, toolSchema)
func (deepintshield *DeepIntShield) RegisterMCPTool(name, description string, handler func(args any) (string, error), toolSchema schemas.ChatTool) error {
	if deepintshield.MCPManager == nil {
		return fmt.Errorf("MCP is not configured in this DeepIntShield instance")
	}

	return deepintshield.MCPManager.RegisterTool(name, description, handler, toolSchema)
}

// IMPORTANT: Running the MCP client management operations (GetMCPClients, AddMCPClient, RemoveMCPClient, EditMCPClientTools)
// may temporarily increase latency for incoming requests while the operations are being processed.
// These operations involve network I/O and connection management that require mutex locks
// which can block briefly during execution.

// GetMCPClients returns all MCP clients managed by the DeepIntShield instance.
//
// Returns:
//   - []schemas.MCPClient: List of all MCP clients
//   - error: Any retrieval error
func (deepintshield *DeepIntShield) GetMCPClients() ([]schemas.MCPClient, error) {
	if deepintshield.MCPManager == nil {
		return nil, fmt.Errorf("MCP is not configured in this DeepIntShield instance")
	}

	clients := deepintshield.MCPManager.GetClients()
	clientsInConfig := make([]schemas.MCPClient, 0, len(clients))

	for _, client := range clients {
		tools := make([]schemas.ChatToolFunction, 0, len(client.ToolMap))
		for _, tool := range client.ToolMap {
			if tool.Function != nil {
				// Create a deep copy (for name) of the tool function to avoid modifying the original
				toolFunction := schemas.ChatToolFunction{}
				toolFunction.Name = tool.Function.Name
				toolFunction.Description = tool.Function.Description
				toolFunction.Parameters = tool.Function.Parameters
				toolFunction.Strict = tool.Function.Strict
				// Remove the client prefix from the tool name
				toolFunction.Name = strings.TrimPrefix(toolFunction.Name, client.ExecutionConfig.Name+"-")
				tools = append(tools, toolFunction)
			}
		}

		sort.Slice(tools, func(i, j int) bool {
			return tools[i].Name < tools[j].Name
		})

		clientsInConfig = append(clientsInConfig, schemas.MCPClient{
			Config: client.ExecutionConfig,
			Tools:  tools,
			State:  client.State,
		})
	}

	return clientsInConfig, nil
}

// GetAvailableTools returns the available tools for the given context.
//
// Returns:
//   - []schemas.ChatTool: List of available tools
func (deepintshield *DeepIntShield) GetAvailableMCPTools(ctx context.Context) []schemas.ChatTool {
	if deepintshield.MCPManager == nil {
		return nil
	}
	return deepintshield.MCPManager.GetAvailableTools(ctx)
}

// AddMCPClient adds a new MCP client to the DeepIntShield instance.
// This allows for dynamic MCP client management at runtime.
//
// Parameters:
//   - config: MCP client configuration
//
// Returns:
//   - error: Any registration error
//
// Example:
//
//	err := deepintshield.AddMCPClient(schemas.MCPClientConfig{
//	    Name: "my-mcp-client",
//	    ConnectionType: schemas.MCPConnectionTypeHTTP,
//	    ConnectionString: &url,
//	})
func (deepintshield *DeepIntShield) AddMCPClient(config *schemas.MCPClientConfig) error {
	if deepintshield.MCPManager == nil {
		// Use sync.Once to ensure thread-safe initialization
		deepintshield.mcpInitOnce.Do(func() {
			// Initialize with empty config - client will be added via AddClient below
			mcpConfig := schemas.MCPConfig{
				ClientConfigs: []*schemas.MCPClientConfig{},
			}
			// Set up plugin pipeline provider functions for executeCode tool hooks
			mcpConfig.PluginPipelineProvider = func() interface{} {
				return deepintshield.getPluginPipeline()
			}
			mcpConfig.ReleasePluginPipeline = func(pipeline interface{}) {
				if pp, ok := pipeline.(*PluginPipeline); ok {
					deepintshield.releasePluginPipeline(pp)
				}
			}
			// Create Starlark CodeMode for code execution (with default config)
			codeMode := starlark.NewStarlarkCodeMode(nil, deepintshield.logger)
			deepintshield.MCPManager = mcp.NewMCPManager(deepintshield.ctx, mcpConfig, deepintshield.oauth2Provider, deepintshield.logger, codeMode)
		})
	}

	// Handle case where initialization succeeded elsewhere but manager is still nil
	if deepintshield.MCPManager == nil {
		return fmt.Errorf("MCP manager is not initialized")
	}

	return deepintshield.MCPManager.AddClient(config)
}

// RemoveMCPClient removes an MCP client from the DeepIntShield instance.
// This allows for dynamic MCP client management at runtime.
//
// Parameters:
//   - id: ID of the client to remove
//
// Returns:
//   - error: Any removal error
//
// Example:
//
//	err := deepintshield.RemoveMCPClient("my-mcp-client-id")
//	if err != nil {
//	    log.Fatalf("Failed to remove MCP client: %v", err)
//	}
func (deepintshield *DeepIntShield) RemoveMCPClient(id string) error {
	if deepintshield.MCPManager == nil {
		return fmt.Errorf("MCP is not configured in this DeepIntShield instance")
	}

	return deepintshield.MCPManager.RemoveClient(id)
}

// SetMCPManager sets the MCP manager for this DeepIntShield instance.
// This allows injecting a custom MCP manager implementation (e.g., for enterprise features).
//
// Parameters:
//   - manager: The MCP manager to set (must implement MCPManagerInterface)
func (deepintshield *DeepIntShield) SetMCPManager(manager mcp.MCPManagerInterface) {
	deepintshield.MCPManager = manager
}

// UpdateMCPClient updates the MCP client.
// This allows for dynamic MCP client tool management at runtime.
//
// Parameters:
//   - id: ID of the client to edit
//   - updatedConfig: Updated MCP client configuration
//
// Returns:
//   - error: Any edit error
//
// Example:
//
//	err := deepintshield.UpdateMCPClient("my-mcp-client-id", schemas.MCPClientConfig{
//	    Name:           "my-mcp-client-name",
//	    ToolsToExecute: []string{"tool1", "tool2"},
//	})
func (deepintshield *DeepIntShield) UpdateMCPClient(id string, updatedConfig *schemas.MCPClientConfig) error {
	if deepintshield.MCPManager == nil {
		return fmt.Errorf("MCP is not configured in this DeepIntShield instance")
	}

	return deepintshield.MCPManager.UpdateClient(id, updatedConfig)
}

// ReconnectMCPClient attempts to reconnect an MCP client if it is disconnected.
//
// Parameters:
//   - id: ID of the client to reconnect
//
// Returns:
//   - error: Any reconnection error
func (deepintshield *DeepIntShield) ReconnectMCPClient(id string) error {
	if deepintshield.MCPManager == nil {
		return fmt.Errorf("MCP is not configured in this DeepIntShield instance")
	}

	return deepintshield.MCPManager.ReconnectClient(id)
}

// UpdateToolManagerConfig updates the tool manager config for the MCP manager.
// This allows for hot-reloading of the tool manager config at runtime.
func (deepintshield *DeepIntShield) UpdateToolManagerConfig(maxAgentDepth int, toolExecutionTimeoutInSeconds int, codeModeBindingLevel string, cacheEnabled *bool, cacheTTLSeconds int) error {
	if deepintshield.MCPManager == nil {
		return fmt.Errorf("MCP is not configured in this DeepIntShield instance")
	}

	deepintshield.MCPManager.UpdateToolManagerConfig(&schemas.MCPToolManagerConfig{
		MaxAgentDepth:        maxAgentDepth,
		ToolExecutionTimeout: time.Duration(toolExecutionTimeoutInSeconds) * time.Second,
		CodeModeBindingLevel: schemas.CodeModeBindingLevel(codeModeBindingLevel),
		CacheEnabled:         cacheEnabled,
		CacheTTLSeconds:      cacheTTLSeconds,
	})
	return nil
}

// PROVIDER MANAGEMENT

// createBaseProvider creates a provider based on the base provider type
func (deepintshield *DeepIntShield) createBaseProvider(providerKey schemas.ModelProvider, config *schemas.ProviderConfig) (schemas.Provider, error) {
	// Determine which provider type to create
	targetProviderKey := providerKey

	if config.CustomProviderConfig != nil {
		// Validate custom provider config
		if config.CustomProviderConfig.BaseProviderType == "" {
			return nil, fmt.Errorf("custom provider config missing base provider type")
		}

		// Validate that base provider type is supported
		if !IsSupportedBaseProvider(config.CustomProviderConfig.BaseProviderType) {
			return nil, fmt.Errorf("unsupported base provider type: %s", config.CustomProviderConfig.BaseProviderType)
		}

		// Automatically set the custom provider key to the provider name
		config.CustomProviderConfig.CustomProviderKey = string(providerKey)

		targetProviderKey = config.CustomProviderConfig.BaseProviderType
	}

	switch targetProviderKey {
	case schemas.OpenAI:
		return openai.NewOpenAIProvider(config, deepintshield.logger), nil
	case schemas.Anthropic:
		return anthropic.NewAnthropicProvider(config, deepintshield.logger), nil
	case schemas.Bedrock:
		return bedrock.NewBedrockProvider(config, deepintshield.logger)
	case schemas.Cohere:
		return cohere.NewCohereProvider(config, deepintshield.logger)
	case schemas.Azure:
		return azure.NewAzureProvider(config, deepintshield.logger)
	case schemas.Vertex:
		return vertex.NewVertexProvider(config, deepintshield.logger)
	case schemas.Mistral:
		return mistral.NewMistralProvider(config, deepintshield.logger), nil
	case schemas.Ollama:
		return ollama.NewOllamaProvider(config, deepintshield.logger)
	case schemas.Groq:
		return groq.NewGroqProvider(config, deepintshield.logger)
	case schemas.SGL:
		return sgl.NewSGLProvider(config, deepintshield.logger)
	case schemas.Parasail:
		return parasail.NewParasailProvider(config, deepintshield.logger)
	case schemas.Perplexity:
		return perplexity.NewPerplexityProvider(config, deepintshield.logger)
	case schemas.Cerebras:
		return cerebras.NewCerebrasProvider(config, deepintshield.logger)
	case schemas.Gemini:
		return gemini.NewGeminiProvider(config, deepintshield.logger), nil
	case schemas.OpenRouter:
		return openrouter.NewOpenRouterProvider(config, deepintshield.logger), nil
	case schemas.Elevenlabs:
		return elevenlabs.NewElevenlabsProvider(config, deepintshield.logger), nil
	case schemas.Nebius:
		return nebius.NewNebiusProvider(config, deepintshield.logger)
	case schemas.HuggingFace:
		return huggingface.NewHuggingFaceProvider(config, deepintshield.logger), nil
	case schemas.XAI:
		return xai.NewXAIProvider(config, deepintshield.logger)
	case schemas.Replicate:
		return replicate.NewReplicateProvider(config, deepintshield.logger)
	case schemas.VLLM:
		return vllm.NewVLLMProvider(config, deepintshield.logger)
	case schemas.Runway:
		return runway.NewRunwayProvider(config, deepintshield.logger)
	case schemas.Fireworks:
		return fireworks.NewFireworksProvider(config, deepintshield.logger)
	case schemas.OpencodeGo:
		return opencode.NewOpencodeGoProvider(config, deepintshield.logger)
	case schemas.OpencodeZen:
		return opencode.NewOpencodeZenProvider(config, deepintshield.logger)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", targetProviderKey)
	}
}

// prepareProvider sets up a provider with its configuration, keys, and worker channels.
// It initializes the request queue and starts worker goroutines for processing requests.
// Note: This function assumes the caller has already acquired the appropriate mutex for the provider.
func (deepintshield *DeepIntShield) prepareProvider(providerKey schemas.ModelProvider, config *schemas.ProviderConfig) error {
	// Create ProviderQueue with lifecycle management
	pq := &ProviderQueue{
		queue:      make(chan *ChannelMessage, config.ConcurrencyAndBufferSize.BufferSize),
		done:       make(chan struct{}),
		signalOnce: sync.Once{},
		closeOnce:  sync.Once{},
	}

	deepintshield.requestQueues.Store(providerKey, pq)

	// Start specified number of workers
	deepintshield.waitGroups.Store(providerKey, &sync.WaitGroup{})

	provider, err := deepintshield.createBaseProvider(providerKey, config)
	if err != nil {
		return fmt.Errorf("failed to create provider for the given key: %v", err)
	}

	waitGroupValue, _ := deepintshield.waitGroups.Load(providerKey)
	currentWaitGroup := waitGroupValue.(*sync.WaitGroup)

	// Atomically append provider to the providers slice
	for {
		oldPtr := deepintshield.providers.Load()
		var oldSlice []schemas.Provider
		if oldPtr != nil {
			oldSlice = *oldPtr
		}
		newSlice := make([]schemas.Provider, len(oldSlice)+1)
		copy(newSlice, oldSlice)
		newSlice[len(oldSlice)] = provider
		if deepintshield.providers.CompareAndSwap(oldPtr, &newSlice) {
			break
		}
	}

	schemas.RegisterKnownProvider(providerKey)

	for range config.ConcurrencyAndBufferSize.Concurrency {
		currentWaitGroup.Add(1)
		go deepintshield.requestWorker(provider, config, pq)
	}

	return nil
}

// getProviderQueue returns the ProviderQueue for a given provider key.
// If the queue doesn't exist, it creates one at runtime and initializes the provider,
// given the provider config is provided in the account interface implementation.
// This function uses read locks to prevent race conditions during provider updates.
// Callers must check the closing flag or select on the done channel before sending.
func (deepintshield *DeepIntShield) getProviderQueue(providerKey schemas.ModelProvider) (*ProviderQueue, error) {
	// Use read lock to allow concurrent reads but prevent concurrent updates
	providerMutex := deepintshield.getProviderMutex(providerKey)
	providerMutex.RLock()

	if pqValue, exists := deepintshield.requestQueues.Load(providerKey); exists {
		pq := pqValue.(*ProviderQueue)
		providerMutex.RUnlock()
		return pq, nil
	}

	// Provider doesn't exist, need to create it
	// Upgrade to write lock for creation
	providerMutex.RUnlock()
	providerMutex.Lock()
	defer providerMutex.Unlock()

	// Double-check after acquiring write lock (another goroutine might have created it)
	if pqValue, exists := deepintshield.requestQueues.Load(providerKey); exists {
		pq := pqValue.(*ProviderQueue)
		return pq, nil
	}
	deepintshield.logger.Debug(fmt.Sprintf("Creating new request queue for provider %s at runtime", providerKey))
	config, err := deepintshield.account.GetConfigForProvider(providerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get config for provider: %v", err)
	}
	if config == nil {
		return nil, fmt.Errorf("config is nil for provider %s", providerKey)
	}
	if err := deepintshield.prepareProvider(providerKey, config); err != nil {
		return nil, err
	}
	pqValue, ok := deepintshield.requestQueues.Load(providerKey)
	if !ok {
		return nil, fmt.Errorf("request queue not found for provider %s", providerKey)
	}
	pq := pqValue.(*ProviderQueue)
	return pq, nil
}

// GetProviderByKey returns the provider instance for the given provider key.
// Returns nil if no provider with the given key exists.
func (deepintshield *DeepIntShield) GetProviderByKey(providerKey schemas.ModelProvider) schemas.Provider {
	return deepintshield.getProviderByKey(providerKey)
}

// SelectKeyForProvider selects an API key for the given provider and model.
// Used by WebSocket handlers that need a key for upstream connections.
func (deepintshield *DeepIntShield) SelectKeyForProvider(ctx *schemas.DeepIntShieldContext, providerKey schemas.ModelProvider, model string) (schemas.Key, error) {
	if ctx == nil {
		ctx = deepintshield.ctx
	}
	baseProvider := providerKey
	if config, err := deepintshield.account.GetConfigForProvider(providerKey); err == nil && config != nil &&
		config.CustomProviderConfig != nil && config.CustomProviderConfig.BaseProviderType != "" {
		baseProvider = config.CustomProviderConfig.BaseProviderType
	}
	return deepintshield.selectKeyFromProviderForModel(ctx, schemas.WebSocketResponsesRequest, providerKey, model, baseProvider)
}

// WSStreamHooks holds the post-hook runner and cleanup function returned by RunStreamPreHooks.
// Call PostHookRunner for each streaming chunk, setting StreamEndIndicator on the final chunk.
// Call Cleanup when done to release the pipeline back to the pool.
// If ShortCircuitResponse is non-nil, a plugin short-circuited with a cached response -
// the caller should write this response to the client and skip the upstream call.
type WSStreamHooks struct {
	PostHookRunner       schemas.PostHookRunner
	Cleanup              func()
	ShortCircuitResponse *schemas.DeepIntShieldResponse
}

// RunStreamPreHooks acquires a plugin pipeline, sets up tracing context, runs PreLLMHooks,
// and returns a PostHookRunner for per-chunk post-processing.
// Used by WebSocket handlers that bypass the normal inference path but still need plugin hooks.
func (deepintshield *DeepIntShield) RunStreamPreHooks(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*WSStreamHooks, *schemas.DeepIntShieldError) {
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	if _, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string); !ok {
		ctx.SetValue(schemas.DeepIntShieldContextKeyRequestID, uuid.New().String())
	}

	tracer := deepintshield.getTracer()
	ctx.SetValue(schemas.DeepIntShieldContextKeyTracer, tracer)

	// Create a trace so the logging plugin can accumulate streaming chunks.
	// The traceID is used as the accumulator key in ProcessStreamingChunk.
	if _, ok := ctx.Value(schemas.DeepIntShieldContextKeyTraceID).(string); !ok {
		traceID := tracer.CreateTrace("")
		if traceID != "" {
			ctx.SetValue(schemas.DeepIntShieldContextKeyTraceID, traceID)
		}
	}

	// Mark as streaming context so RunPostLLMHooks uses accumulated timing
	ctx.SetValue(schemas.DeepIntShieldContextKeyStreamStartTime, time.Now())

	pipeline := deepintshield.getPluginPipeline()

	cleanup := func() {
		if traceID, ok := ctx.Value(schemas.DeepIntShieldContextKeyTraceID).(string); ok && traceID != "" {
			tracer.CleanupStreamAccumulator(traceID)
		}
		deepintshield.releasePluginPipeline(pipeline)
	}

	preReq, shortCircuit, preCount := pipeline.RunLLMPreHooks(ctx, req)
	if preReq == nil && shortCircuit == nil {
		cleanup()
		return nil, newDeepIntShieldErrorFromMsg("deepintshield request after plugin hooks cannot be nil")
	}
	if shortCircuit != nil {
		if shortCircuit.Error != nil {
			_, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, nil, shortCircuit.Error, preCount)
			cleanup()
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return nil, shortCircuit.Error
		}
		if shortCircuit.Response != nil {
			resp, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, shortCircuit.Response, nil, preCount)
			cleanup()
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return &WSStreamHooks{
				Cleanup:              func() {},
				ShortCircuitResponse: resp,
			}, nil
		}
	}

	postHookRunner := func(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, err *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
		return pipeline.RunPostLLMHooks(ctx, result, err, preCount)
	}

	return &WSStreamHooks{
		PostHookRunner: postHookRunner,
		Cleanup:        cleanup,
	}, nil
}

// getProviderByKey retrieves a provider instance from the providers array by its provider key.
// Returns the provider if found, or nil if no provider with the given key exists.
func (deepintshield *DeepIntShield) getProviderByKey(providerKey schemas.ModelProvider) schemas.Provider {
	providers := deepintshield.providers.Load()
	if providers == nil {
		return nil
	}
	// Checking if provider is in the memory
	for _, provider := range *providers {
		if provider.GetProviderKey() == providerKey {
			return provider
		}
	}
	// Could happen when provider is not initialized yet, check if provider config exists in account and if so, initialize it
	config, err := deepintshield.account.GetConfigForProvider(providerKey)
	if err != nil || config == nil {
		if slices.Contains(dynamicallyConfigurableProviders, providerKey) {
			deepintshield.logger.Info(fmt.Sprintf("initializing provider %s with default config", providerKey))
			// If no config found, use default config
			config = &schemas.ProviderConfig{
				NetworkConfig:            schemas.DefaultNetworkConfig,
				ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
			}
		} else {
			return nil
		}
	}
	// Lock the provider mutex to avoid races
	providerMutex := deepintshield.getProviderMutex(providerKey)
	providerMutex.Lock()
	defer providerMutex.Unlock()
	// Double-check after acquiring the lock
	providers = deepintshield.providers.Load()
	if providers != nil {
		for _, p := range *providers {
			if p.GetProviderKey() == providerKey {
				return p
			}
		}
	}
	// Preparing provider
	if err := deepintshield.prepareProvider(providerKey, config); err != nil {
		return nil
	}
	// Return newly prepared provider without recursion
	providers = deepintshield.providers.Load()
	if providers != nil {
		for _, p := range *providers {
			if p.GetProviderKey() == providerKey {
				return p
			}
		}
	}
	return nil
}

// CORE INTERNAL LOGIC

// shouldTryFallbacks handles the primary error and returns true if we should proceed with fallbacks, false if we should return immediately
func (deepintshield *DeepIntShield) shouldTryFallbacks(req *schemas.DeepIntShieldRequest, primaryErr *schemas.DeepIntShieldError) bool {
	// If no primary error, we succeeded
	if primaryErr == nil {
		deepintshield.logger.Debug("no primary error, we should not try fallbacks")
		return false
	}

	// Handle request cancellation
	if primaryErr.Error != nil && primaryErr.Error.Type != nil && *primaryErr.Error.Type == schemas.RequestCancelled {
		deepintshield.logger.Debug("request cancelled, we should not try fallbacks")
		return false
	}

	// Check if this is a short-circuit error that doesn't allow fallbacks
	// Note: AllowFallbacks = nil is treated as true (allow fallbacks by default)
	if primaryErr.AllowFallbacks != nil && !*primaryErr.AllowFallbacks {
		deepintshield.logger.Debug("allowFallbacks is false, we should not try fallbacks")
		return false
	}

	// If no fallbacks configured, return primary error
	_, _, fallbacks := req.GetRequestFields()
	if len(fallbacks) == 0 {
		deepintshield.logger.Debug("no fallbacks configured, we should not try fallbacks")
		return false
	}

	// Should proceed with fallbacks
	return true
}

// prepareFallbackRequest creates a fallback request and validates the provider config
// Returns the fallback request or nil if this fallback should be skipped
func (deepintshield *DeepIntShield) prepareFallbackRequest(req *schemas.DeepIntShieldRequest, fallback schemas.Fallback) *schemas.DeepIntShieldRequest {
	// Check if we have config for this fallback provider
	_, err := deepintshield.account.GetConfigForProvider(fallback.Provider)
	if err != nil {
		deepintshield.logger.Warn("config not found for provider %s, skipping fallback: %v", fallback.Provider, err)
		return nil
	}

	// Create a new request with the fallback provider and model
	fallbackReq := *req

	if req.TextCompletionRequest != nil {
		tmp := *req.TextCompletionRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.TextCompletionRequest = &tmp
	}

	if req.ChatRequest != nil {
		tmp := *req.ChatRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.ChatRequest = &tmp
	}

	if req.ResponsesRequest != nil {
		tmp := *req.ResponsesRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.ResponsesRequest = &tmp
	}

	if req.CountTokensRequest != nil {
		tmp := *req.CountTokensRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.CountTokensRequest = &tmp
	}

	if req.EmbeddingRequest != nil {
		tmp := *req.EmbeddingRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.EmbeddingRequest = &tmp
	}
	if req.RerankRequest != nil {
		tmp := *req.RerankRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.RerankRequest = &tmp
	}

	if req.SpeechRequest != nil {
		tmp := *req.SpeechRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.SpeechRequest = &tmp
	}

	if req.TranscriptionRequest != nil {
		tmp := *req.TranscriptionRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.TranscriptionRequest = &tmp
	}
	if req.ImageGenerationRequest != nil {
		tmp := *req.ImageGenerationRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.ImageGenerationRequest = &tmp
	}
	if req.VideoGenerationRequest != nil {
		tmp := *req.VideoGenerationRequest
		tmp.Provider = fallback.Provider
		tmp.Model = fallback.Model
		fallbackReq.VideoGenerationRequest = &tmp
	}
	return &fallbackReq
}

// shouldContinueWithFallbacks processes errors from fallback attempts
// Returns true if we should continue with more fallbacks, false if we should stop
func (deepintshield *DeepIntShield) shouldContinueWithFallbacks(fallback schemas.Fallback, fallbackErr *schemas.DeepIntShieldError) bool {
	if fallbackErr.Error.Type != nil && *fallbackErr.Error.Type == schemas.RequestCancelled {
		return false
	}

	// Check if it was a short-circuit error that doesn't allow fallbacks
	if fallbackErr.AllowFallbacks != nil && !*fallbackErr.AllowFallbacks {
		return false
	}

	deepintshield.logger.Debug(fmt.Sprintf("Fallback provider %s failed: %s", fallback.Provider, fallbackErr.Error.Message))
	return true
}

// handleRequest handles the request to the provider based on the request type
// It handles plugin hooks, request validation, response processing, and fallback providers.
// If the primary provider fails, it will try each fallback provider in order until one succeeds.
// It is the wrapper for all non-streaming public API methods.
func (deepintshield *DeepIntShield) handleRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
	defer deepintshield.releaseDeepIntShieldRequest(req)
	provider, model, fallbacks := req.GetRequestFields()
	if err := validateRequest(req); err != nil {
		err.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, err
	}

	// Handle nil context early to prevent blocking
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	deepintshield.logger.Debug(fmt.Sprintf("primary provider %s with model %s and %d fallbacks", provider, model, len(fallbacks)))

	// Try the primary provider first
	ctx.SetValue(schemas.DeepIntShieldContextKeyFallbackIndex, 0)
	// Ensure request ID is set in context before PreHooks
	if _, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string); !ok {
		requestID := uuid.New().String()
		ctx.SetValue(schemas.DeepIntShieldContextKeyRequestID, requestID)
	}
	primaryResult, primaryErr := deepintshield.tryRequest(ctx, req)
	if primaryErr != nil {
		if primaryErr.Error != nil {
			deepintshield.logger.Debug(fmt.Sprintf("primary provider %s with model %s returned error: %s", provider, model, primaryErr.Error.Message))
		} else {
			deepintshield.logger.Debug(fmt.Sprintf("primary provider %s with model %s returned error: %v", provider, model, primaryErr))
		}
		if len(fallbacks) > 0 {
			deepintshield.logger.Debug(fmt.Sprintf("check if we should try %d fallbacks", len(fallbacks)))
		}
	}

	// Check if we should proceed with fallbacks
	shouldTryFallbacks := deepintshield.shouldTryFallbacks(req, primaryErr)
	if !shouldTryFallbacks {
		if primaryErr != nil {
			primaryErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
				RawRequest:     primaryErr.ExtraFields.RawRequest,
				RawResponse:    primaryErr.ExtraFields.RawResponse,
				KeyStatuses:    primaryErr.ExtraFields.KeyStatuses,
			}
		}
		return primaryResult, primaryErr
	}

	// Try fallbacks in order
	for i, fallback := range fallbacks {
		ctx.SetValue(schemas.DeepIntShieldContextKeyFallbackIndex, i+1)
		deepintshield.logger.Debug(fmt.Sprintf("trying fallback provider %s with model %s", fallback.Provider, fallback.Model))
		ctx.SetValue(schemas.DeepIntShieldContextKeyFallbackRequestID, uuid.New().String())
		clearCtxForFallback(ctx)

		// Start span for fallback attempt
		tracer := deepintshield.getTracer()
		spanCtx, handle := tracer.StartSpan(ctx, fmt.Sprintf("fallback.%s.%s", fallback.Provider, fallback.Model), schemas.SpanKindFallback)
		tracer.SetAttribute(handle, schemas.AttrProviderName, string(fallback.Provider))
		tracer.SetAttribute(handle, schemas.AttrRequestModel, fallback.Model)
		tracer.SetAttribute(handle, "fallback.index", i+1)
		ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanCtx.Value(schemas.DeepIntShieldContextKeySpanID))

		fallbackReq := deepintshield.prepareFallbackRequest(req, fallback)
		if fallbackReq == nil {
			deepintshield.logger.Debug(fmt.Sprintf("fallback provider %s with model %s is nil", fallback.Provider, fallback.Model))
			tracer.SetAttribute(handle, "error", "fallback request preparation failed")
			tracer.EndSpan(handle, schemas.SpanStatusError, "fallback request preparation failed")
			continue
		}

		// Try the fallback provider
		result, fallbackErr := deepintshield.tryRequest(ctx, fallbackReq)
		if fallbackErr == nil {
			deepintshield.logger.Debug(fmt.Sprintf("successfully used fallback provider %s with model %s", fallback.Provider, fallback.Model))
			tracer.EndSpan(handle, schemas.SpanStatusOk, "")
			return result, nil
		}

		// End span with error status
		if fallbackErr.Error != nil {
			tracer.SetAttribute(handle, "error", fallbackErr.Error.Message)
		}
		tracer.EndSpan(handle, schemas.SpanStatusError, "fallback failed")

		// Check if we should continue with more fallbacks
		if !deepintshield.shouldContinueWithFallbacks(fallback, fallbackErr) {
			fallbackErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       fallback.Provider,
				ModelRequested: fallback.Model,
				RawRequest:     fallbackErr.ExtraFields.RawRequest,
				RawResponse:    fallbackErr.ExtraFields.RawResponse,
				KeyStatuses:    fallbackErr.ExtraFields.KeyStatuses,
			}
			return nil, fallbackErr
		}
	}

	if primaryErr != nil {
		primaryErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
			RawRequest:     primaryErr.ExtraFields.RawRequest,
			RawResponse:    primaryErr.ExtraFields.RawResponse,
			KeyStatuses:    primaryErr.ExtraFields.KeyStatuses,
		}
	}

	// All providers failed, return the original error
	return nil, primaryErr
}

// handleStreamRequest handles the stream request to the provider based on the request type
// It handles plugin hooks, request validation, response processing, and fallback providers.
// If the primary provider fails, it will try each fallback provider in order until one succeeds.
// It is the wrapper for all streaming public API methods.
func (deepintshield *DeepIntShield) handleStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	defer deepintshield.releaseDeepIntShieldRequest(req)

	provider, model, fallbacks := req.GetRequestFields()

	if err := validateRequest(req); err != nil {
		err.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		err.StatusCode = schemas.Ptr(fasthttp.StatusBadRequest)
		return nil, err
	}

	// Handle nil context early to prevent blocking
	if ctx == nil {
		ctx = deepintshield.ctx
	}

	// Try the primary provider first
	ctx.SetValue(schemas.DeepIntShieldContextKeyFallbackIndex, 0)
	// Ensure request ID is set in context before PreHooks
	if _, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string); !ok {
		requestID := uuid.New().String()
		ctx.SetValue(schemas.DeepIntShieldContextKeyRequestID, requestID)
	}
	primaryResult, primaryErr := deepintshield.tryStreamRequest(ctx, req)

	// Check if we should proceed with fallbacks
	shouldTryFallbacks := deepintshield.shouldTryFallbacks(req, primaryErr)
	if !shouldTryFallbacks {
		if primaryErr != nil {
			primaryErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
				RawRequest:     primaryErr.ExtraFields.RawRequest,
				RawResponse:    primaryErr.ExtraFields.RawResponse,
				KeyStatuses:    primaryErr.ExtraFields.KeyStatuses,
			}
		}
		return primaryResult, primaryErr
	}

	// Try fallbacks in order
	for i, fallback := range fallbacks {
		ctx.SetValue(schemas.DeepIntShieldContextKeyFallbackIndex, i+1)
		ctx.SetValue(schemas.DeepIntShieldContextKeyFallbackRequestID, uuid.New().String())
		clearCtxForFallback(ctx)

		// Start span for fallback attempt
		tracer := deepintshield.getTracer()
		spanCtx, handle := tracer.StartSpan(ctx, fmt.Sprintf("fallback.%s.%s", fallback.Provider, fallback.Model), schemas.SpanKindFallback)
		tracer.SetAttribute(handle, schemas.AttrProviderName, string(fallback.Provider))
		tracer.SetAttribute(handle, schemas.AttrRequestModel, fallback.Model)
		tracer.SetAttribute(handle, "fallback.index", i+1)
		ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanCtx.Value(schemas.DeepIntShieldContextKeySpanID))

		fallbackReq := deepintshield.prepareFallbackRequest(req, fallback)
		if fallbackReq == nil {
			tracer.SetAttribute(handle, "error", "fallback request preparation failed")
			tracer.EndSpan(handle, schemas.SpanStatusError, "fallback request preparation failed")
			continue
		}

		// Try the fallback provider
		result, fallbackErr := deepintshield.tryStreamRequest(ctx, fallbackReq)
		if fallbackErr == nil {
			deepintshield.logger.Debug(fmt.Sprintf("successfully used fallback provider %s with model %s", fallback.Provider, fallback.Model))
			tracer.EndSpan(handle, schemas.SpanStatusOk, "")
			return result, nil
		}

		// End span with error status
		if fallbackErr.Error != nil {
			tracer.SetAttribute(handle, "error", fallbackErr.Error.Message)
		}
		tracer.EndSpan(handle, schemas.SpanStatusError, "fallback failed")

		// Check if we should continue with more fallbacks
		if !deepintshield.shouldContinueWithFallbacks(fallback, fallbackErr) {
			fallbackErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       fallback.Provider,
				ModelRequested: fallback.Model,
				RawRequest:     fallbackErr.ExtraFields.RawRequest,
				RawResponse:    fallbackErr.ExtraFields.RawResponse,
				KeyStatuses:    fallbackErr.ExtraFields.KeyStatuses,
			}
			return nil, fallbackErr
		}
	}

	if primaryErr != nil {
		primaryErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
			RawRequest:     primaryErr.ExtraFields.RawRequest,
			RawResponse:    primaryErr.ExtraFields.RawResponse,
			KeyStatuses:    primaryErr.ExtraFields.KeyStatuses,
		}
	}

	// All providers failed, return the original error
	return nil, primaryErr
}

// tryRequest is a generic function that handles common request processing logic
// It consolidates queue setup, plugin pipeline execution, enqueue logic, and response handling
func (deepintshield *DeepIntShield) tryRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
	provider, model, _ := req.GetRequestFields()
	pq, err := deepintshield.getProviderQueue(provider)
	if err != nil {
		deepintshieldErr := newDeepIntShieldError(err)
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	}

	// Add MCP tools to request if MCP is configured and requested
	if deepintshield.MCPManager != nil {
		req = deepintshield.MCPManager.AddToolsToRequest(ctx, req)
	}

	tracer := deepintshield.getTracer()
	if tracer == nil {
		return nil, newDeepIntShieldErrorFromMsg("tracer not found in context")
	}

	// Store tracer in context BEFORE calling requestHandler, so streaming goroutines
	// have access to it for completing deferred spans when the stream ends.
	// The streaming goroutine captures the context when it starts, so these values
	// must be set before requestHandler() is called.
	ctx.SetValue(schemas.DeepIntShieldContextKeyTracer, tracer)

	pipeline := deepintshield.getPluginPipeline()
	defer deepintshield.releasePluginPipeline(pipeline)

	preReq, shortCircuit, preCount := pipeline.RunLLMPreHooks(ctx, req)
	if shortCircuit != nil {
		// Handle short-circuit with response (success case)
		if shortCircuit.Response != nil {
			resp, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, shortCircuit.Response, nil, preCount)
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return resp, nil
		}
		// Handle short-circuit with error
		if shortCircuit.Error != nil {
			resp, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, nil, shortCircuit.Error, preCount)
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return resp, nil
		}
	}
	if preReq == nil {
		deepintshieldErr := newDeepIntShieldErrorFromMsg("deepintshield request after plugin hooks cannot be nil")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	}

	msg := deepintshield.getChannelMessage(*preReq)
	msg.Context = ctx

	// Check if provider is closing before attempting to send (lock-free atomic check)
	// This prevents "send on closed channel" panics during provider removal/update
	if pq.isClosing() {
		deepintshield.releaseChannelMessage(msg)
		deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	}

	// Use select with done channel to detect shutdown during send
	select {
	case pq.queue <- msg:
		// Message was sent successfully
	case <-pq.done:
		deepintshield.releaseChannelMessage(msg)
		deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	case <-ctx.Done():
		deepintshield.releaseChannelMessage(msg)
		deepintshieldErr := newDeepIntShieldErrorFromMsg("request cancelled while waiting for queue space")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	default:
		if deepintshield.dropExcessRequests.Load() {
			deepintshield.releaseChannelMessage(msg)
			deepintshield.logger.Warn("request dropped: queue is full, please increase the queue size or set dropExcessRequests to false")
			deepintshieldErr := newDeepIntShieldErrorFromMsg("request dropped: queue is full")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		}
		// Re-check closing flag before blocking send (lock-free atomic check)
		if pq.isClosing() {
			deepintshield.releaseChannelMessage(msg)
			deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		}
		select {
		case pq.queue <- msg:
			// Message was sent successfully
		case <-pq.done:
			deepintshield.releaseChannelMessage(msg)
			deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		case <-ctx.Done():
			deepintshield.releaseChannelMessage(msg)
			deepintshieldErr := newDeepIntShieldErrorFromMsg("request cancelled while waiting for queue space")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		}
	}

	var result *schemas.DeepIntShieldResponse
	var resp *schemas.DeepIntShieldResponse
	pluginCount := len(*deepintshield.llmPlugins.Load())
	select {
	case result = <-msg.Response:
		resp, deepintshieldErr := pipeline.RunPostLLMHooks(msg.Context, result, nil, pluginCount)
		if deepintshieldErr != nil {
			deepintshield.releaseChannelMessage(msg)
			return nil, deepintshieldErr
		}
		deepintshield.releaseChannelMessage(msg)
		// Checking if need to drop raw messages
		// This we use for requests like containers, container files, skills etc.
		if drop, ok := ctx.Value(schemas.DeepIntShieldContextKeyRawRequestResponseForLogging).(bool); ok && drop && resp != nil {
			extraField := resp.GetExtraFields()
			extraField.RawRequest = nil
			extraField.RawResponse = nil
		}
		return resp, nil
	case deepintshieldErrVal := <-msg.Err:
		deepintshieldErrPtr := &deepintshieldErrVal
		resp, deepintshieldErrPtr = pipeline.RunPostLLMHooks(msg.Context, nil, deepintshieldErrPtr, pluginCount)
		deepintshield.releaseChannelMessage(msg)
		// Drop raw request/response on error path too
		if drop, ok := ctx.Value(schemas.DeepIntShieldContextKeyRawRequestResponseForLogging).(bool); ok && drop {
			if deepintshieldErrPtr != nil {
				deepintshieldErrPtr.ExtraFields.RawRequest = nil
				deepintshieldErrPtr.ExtraFields.RawResponse = nil
			}
			if resp != nil {
				extraField := resp.GetExtraFields()
				extraField.RawRequest = nil
				extraField.RawResponse = nil
			}
		}
		if deepintshieldErrPtr != nil {
			return nil, deepintshieldErrPtr
		}
		return resp, nil
	case <-ctx.Done():
		deepintshield.releaseChannelMessage(msg)
		provider, model, _ := req.GetRequestFields()
		deepintshieldErr := &schemas.DeepIntShieldError{
			IsDeepIntShieldError: true,
			Error: &schemas.ErrorField{
				Type:    schemas.Ptr(schemas.RequestCancelled),
				Message: fmt.Sprintf("request timed out waiting for provider response: %v", ctx.Err()),
				Error:   ctx.Err(),
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			},
		}
		return nil, deepintshieldErr
	}
}

// tryStreamRequest is a generic function that handles common request processing logic
// It consolidates queue setup, plugin pipeline execution, enqueue logic, and response handling
func (deepintshield *DeepIntShield) tryStreamRequest(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	provider, model, _ := req.GetRequestFields()
	pq, err := deepintshield.getProviderQueue(provider)
	if err != nil {
		deepintshieldErr := newDeepIntShieldError(err)
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	}

	// Add MCP tools to request if MCP is configured and requested
	if req.RequestType != schemas.SpeechStreamRequest && req.RequestType != schemas.TranscriptionStreamRequest && deepintshield.MCPManager != nil {
		req = deepintshield.MCPManager.AddToolsToRequest(ctx, req)
	}

	tracer := deepintshield.getTracer()
	if tracer == nil {
		return nil, newDeepIntShieldErrorFromMsg("tracer not found in context")
	}

	// Store tracer in context BEFORE calling RunLLMPreHooks, so plugins and streaming goroutines
	// have access to it for completing deferred spans when the stream ends.
	// The streaming goroutine captures the context when it starts, so these values
	// must be set before requestHandler() is called.
	ctx.SetValue(schemas.DeepIntShieldContextKeyTracer, tracer)

	// Ensure traceID exists so the logging plugin can create a stream accumulator
	// in PreLLMHook and accumulate chunks in PostLLMHook. For HTTP handler requests the
	// tracing middleware already sets this; for WebSocket bridge and Go SDK callers it
	// may be absent.
	if _, ok := ctx.Value(schemas.DeepIntShieldContextKeyTraceID).(string); !ok {
		traceID := tracer.CreateTrace("")
		if traceID != "" {
			ctx.SetValue(schemas.DeepIntShieldContextKeyTraceID, traceID)
		}
	}

	pipeline := deepintshield.getPluginPipeline()
	defer deepintshield.releasePluginPipeline(pipeline)

	preReq, shortCircuit, preCount := pipeline.RunLLMPreHooks(ctx, req)
	if shortCircuit != nil {
		// Handle short-circuit with response (success case)
		if shortCircuit.Response != nil {
			resp, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, shortCircuit.Response, nil, preCount)
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return newDeepIntShieldMessageChan(resp), nil
		}
		// Handle short-circuit with stream
		if shortCircuit.Stream != nil {
			outputStream := make(chan *schemas.DeepIntShieldStreamChunk)

			// Create a post hook runner cause pipeline object is put back in the pool on defer
			pipelinePostHookRunner := func(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, err *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
				return pipeline.RunPostLLMHooks(ctx, result, err, preCount)
			}

			go func() {
				defer close(outputStream)

				for streamMsg := range shortCircuit.Stream {
					if streamMsg == nil {
						continue
					}

					deepintshieldResponse := &schemas.DeepIntShieldResponse{}
					if streamMsg.DeepIntShieldTextCompletionResponse != nil {
						deepintshieldResponse.TextCompletionResponse = streamMsg.DeepIntShieldTextCompletionResponse
					}
					if streamMsg.DeepIntShieldChatResponse != nil {
						deepintshieldResponse.ChatResponse = streamMsg.DeepIntShieldChatResponse
					}
					if streamMsg.DeepIntShieldResponsesStreamResponse != nil {
						deepintshieldResponse.ResponsesStreamResponse = streamMsg.DeepIntShieldResponsesStreamResponse
					}
					if streamMsg.DeepIntShieldSpeechStreamResponse != nil {
						deepintshieldResponse.SpeechStreamResponse = streamMsg.DeepIntShieldSpeechStreamResponse
					}
					if streamMsg.DeepIntShieldTranscriptionStreamResponse != nil {
						deepintshieldResponse.TranscriptionStreamResponse = streamMsg.DeepIntShieldTranscriptionStreamResponse
					}
					if streamMsg.DeepIntShieldImageGenerationStreamResponse != nil {
						deepintshieldResponse.ImageGenerationStreamResponse = streamMsg.DeepIntShieldImageGenerationStreamResponse
					}

					// Run post hooks on the stream message
					processedResponse, processedError := pipelinePostHookRunner(ctx, deepintshieldResponse, streamMsg.DeepIntShieldError)

					// Build the client-facing chunk via the shared helper, which strips raw
					// request/response fields when in logging-only mode without mutating the
					// shared processedResponse or processedError objects.
					streamResponse := providerUtils.BuildClientStreamChunk(ctx, processedResponse, processedError)

					// Send the processed message to the output stream
					outputStream <- streamResponse

					//TODO: Release the processed response immediately after use
				}
			}()

			return outputStream, nil
		}
		// Handle short-circuit with error
		if shortCircuit.Error != nil {
			resp, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, nil, shortCircuit.Error, preCount)
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return newDeepIntShieldMessageChan(resp), nil
		}
	}
	if preReq == nil {
		deepintshieldErr := newDeepIntShieldErrorFromMsg("deepintshield request after plugin hooks cannot be nil")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	}

	msg := deepintshield.getChannelMessage(*preReq)
	msg.Context = ctx

	// Check if provider is closing before attempting to send (lock-free atomic check)
	// This prevents "send on closed channel" panics during provider removal/update
	if pq.isClosing() {
		deepintshield.releaseChannelMessage(msg)
		deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	}

	// Use select with done channel to detect shutdown during send
	select {
	case pq.queue <- msg:
		// Message was sent successfully
	case <-pq.done:
		deepintshield.releaseChannelMessage(msg)
		deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	case <-ctx.Done():
		deepintshield.releaseChannelMessage(msg)
		deepintshieldErr := newDeepIntShieldErrorFromMsg("request cancelled while waiting for queue space")
		deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			RequestType:    req.RequestType,
			Provider:       provider,
			ModelRequested: model,
		}
		return nil, deepintshieldErr
	default:
		if deepintshield.dropExcessRequests.Load() {
			deepintshield.releaseChannelMessage(msg)
			deepintshield.logger.Warn("request dropped: queue is full, please increase the queue size or set dropExcessRequests to false")
			deepintshieldErr := newDeepIntShieldErrorFromMsg("request dropped: queue is full")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		}
		// Re-check closing flag before blocking send (lock-free atomic check)
		if pq.isClosing() {
			deepintshield.releaseChannelMessage(msg)
			deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		}
		select {
		case pq.queue <- msg:
			// Message was sent successfully
		case <-pq.done:
			deepintshield.releaseChannelMessage(msg)
			deepintshieldErr := newDeepIntShieldErrorFromMsg("provider is shutting down")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		case <-ctx.Done():
			deepintshield.releaseChannelMessage(msg)
			deepintshieldErr := newDeepIntShieldErrorFromMsg("request cancelled while waiting for queue space")
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider,
				ModelRequested: model,
			}
			return nil, deepintshieldErr
		}
	}

	select {
	case stream := <-msg.ResponseStream:
		deepintshield.releaseChannelMessage(msg)
		return stream, nil
	case deepintshieldErrVal := <-msg.Err:
		if deepintshieldErrVal.Error != nil {
			deepintshield.logger.Debug("error while executing stream request: %s", deepintshieldErrVal.Error.Message)
		} else {
			deepintshield.logger.Debug("error while executing stream request: %+v", deepintshieldErrVal)
		}
		// Marking final chunk
		ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
		// On error we will complete post-hooks
		recoveredResp, recoveredErr := pipeline.RunPostLLMHooks(ctx, nil, &deepintshieldErrVal, len(*deepintshield.llmPlugins.Load()))
		deepintshield.releaseChannelMessage(msg)
		if recoveredErr != nil {
			return nil, recoveredErr
		}
		if recoveredResp != nil {
			return newDeepIntShieldMessageChan(recoveredResp), nil
		}
		return nil, &deepintshieldErrVal
	}
}

// executeRequestWithRetries is a generic function that handles common request processing logic
// It consolidates retry logic, backoff calculation, and error handling
// It is not a deepintshield method because interface methods in go cannot be generic
func executeRequestWithRetries[T any](
	ctx *schemas.DeepIntShieldContext,
	config *schemas.ProviderConfig,
	requestHandler func() (T, *schemas.DeepIntShieldError),
	requestType schemas.RequestType,
	providerKey schemas.ModelProvider,
	model string,
	req *schemas.DeepIntShieldRequest,
	logger schemas.Logger,
) (T, *schemas.DeepIntShieldError) {
	var result T
	var deepintshieldError *schemas.DeepIntShieldError
	var attempts int

	for attempts = 0; attempts <= config.NetworkConfig.MaxRetries; attempts++ {
		ctx.SetValue(schemas.DeepIntShieldContextKeyNumberOfRetries, attempts)
		if attempts > 0 {
			// Log retry attempt
			var retryMsg string
			if deepintshieldError != nil && deepintshieldError.Error != nil {
				retryMsg = deepintshieldError.Error.Message
			} else if deepintshieldError != nil && deepintshieldError.StatusCode != nil {
				retryMsg = fmt.Sprintf("status=%d", *deepintshieldError.StatusCode)
				if deepintshieldError.Type != nil {
					retryMsg += ", type=" + *deepintshieldError.Type
				}
			}
			logger.Debug("retrying request (attempt %d/%d) for model %s: %s", attempts, config.NetworkConfig.MaxRetries, model, retryMsg)

			// Calculate and apply backoff
			backoff := calculateBackoff(attempts-1, config)
			logger.Debug("sleeping for %s before retry", backoff)

			time.Sleep(backoff)
		}

		logger.Debug("attempting %s request for provider %s", requestType, providerKey)

		// Start span for LLM call (or retry attempt)
		tracer, ok := ctx.Value(schemas.DeepIntShieldContextKeyTracer).(schemas.Tracer)
		if !ok || tracer == nil {
			logger.Error("tracer not found in context of executeRequestWithRetries")
			return result, newDeepIntShieldErrorFromMsg("tracer not found in context")
		}
		var spanName string
		var spanKind schemas.SpanKind
		if attempts > 0 {
			spanName = fmt.Sprintf("retry.attempt.%d", attempts)
			spanKind = schemas.SpanKindRetry
		} else {
			spanName = "llm.call"
			spanKind = schemas.SpanKindLLMCall
		}
		spanCtx, handle := tracer.StartSpan(ctx, spanName, spanKind)
		tracer.SetAttribute(handle, schemas.AttrProviderName, string(providerKey))
		tracer.SetAttribute(handle, schemas.AttrRequestModel, model)
		tracer.SetAttribute(handle, "request.type", string(requestType))
		if attempts > 0 {
			tracer.SetAttribute(handle, "retry.count", attempts)
		}

		// Add context-related attributes (selected key, virtual key, team, customer, etc.)
		if selectedKeyID, ok := ctx.Value(schemas.DeepIntShieldContextKeySelectedKeyID).(string); ok && selectedKeyID != "" {
			tracer.SetAttribute(handle, schemas.AttrSelectedKeyID, selectedKeyID)
		}
		if selectedKeyName, ok := ctx.Value(schemas.DeepIntShieldContextKeySelectedKeyName).(string); ok && selectedKeyName != "" {
			tracer.SetAttribute(handle, schemas.AttrSelectedKeyName, selectedKeyName)
		}
		if virtualKeyID, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID).(string); ok && virtualKeyID != "" {
			tracer.SetAttribute(handle, schemas.AttrVirtualKeyID, virtualKeyID)
		}
		if virtualKeyName, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyName).(string); ok && virtualKeyName != "" {
			tracer.SetAttribute(handle, schemas.AttrVirtualKeyName, virtualKeyName)
		}
		if teamID, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceTeamID).(string); ok && teamID != "" {
			tracer.SetAttribute(handle, schemas.AttrTeamID, teamID)
		}
		if teamName, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceTeamName).(string); ok && teamName != "" {
			tracer.SetAttribute(handle, schemas.AttrTeamName, teamName)
		}
		if customerID, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceCustomerID).(string); ok && customerID != "" {
			tracer.SetAttribute(handle, schemas.AttrCustomerID, customerID)
		}
		if customerName, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceCustomerName).(string); ok && customerName != "" {
			tracer.SetAttribute(handle, schemas.AttrCustomerName, customerName)
		}
		if fallbackIndex, ok := ctx.Value(schemas.DeepIntShieldContextKeyFallbackIndex).(int); ok {
			tracer.SetAttribute(handle, schemas.AttrFallbackIndex, fallbackIndex)
		}
		tracer.SetAttribute(handle, schemas.AttrNumberOfRetries, attempts)

		// Populate LLM request attributes (messages, parameters, etc.)
		if req != nil {
			tracer.PopulateLLMRequestAttributes(handle, req)
		}

		// Update context with span ID
		ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanCtx.Value(schemas.DeepIntShieldContextKeySpanID))

		// Record stream start time for TTFT calculation (only for streaming requests)
		// This is also used by RunPostLLMHooks to detect streaming mode
		if IsStreamRequestType(requestType) {
			streamStartTime := time.Now()
			ctx.SetValue(schemas.DeepIntShieldContextKeyStreamStartTime, streamStartTime)
		}

		// Attempt the request
		result, deepintshieldError = requestHandler()

		// Check if result is a streaming channel - if so, defer span completion
		if _, isStreamChan := any(result).(chan *schemas.DeepIntShieldStreamChunk); isStreamChan {
			// For streaming requests, store the span handle in TraceStore keyed by trace ID
			// This allows the provider's streaming goroutine to retrieve it later
			if traceID, ok := ctx.Value(schemas.DeepIntShieldContextKeyTraceID).(string); ok && traceID != "" {
				tracer.StoreDeferredSpan(traceID, handle)
			}
			// Don't end the span here - it will be ended when streaming completes
		} else {
			// Populate LLM response attributes for non-streaming responses
			if resp, ok := any(result).(*schemas.DeepIntShieldResponse); ok {
				tracer.PopulateLLMResponseAttributes(handle, resp, deepintshieldError)
			}

			// End span with appropriate status
			if deepintshieldError != nil {
				if deepintshieldError.Error != nil {
					tracer.SetAttribute(handle, "error", deepintshieldError.Error.Message)
				}
				if deepintshieldError.StatusCode != nil {
					tracer.SetAttribute(handle, "status_code", *deepintshieldError.StatusCode)
				}
				tracer.EndSpan(handle, schemas.SpanStatusError, "request failed")
			} else {
				tracer.EndSpan(handle, schemas.SpanStatusOk, "")
			}
		}

		logger.Debug("request %s for provider %s completed", requestType, providerKey)

		// Check if successful or if we should retry
		if deepintshieldError == nil ||
			deepintshieldError.IsDeepIntShieldError ||
			(deepintshieldError.Error != nil && deepintshieldError.Error.Type != nil && *deepintshieldError.Error.Type == schemas.RequestCancelled) {
			break
		}

		// Check if we should retry based on status code or error message
		shouldRetry := false

		if deepintshieldError.Error != nil && (deepintshieldError.Error.Message == schemas.ErrProviderDoRequest || deepintshieldError.Error.Message == schemas.ErrProviderNetworkError) {
			shouldRetry = true
			logger.Debug("detected request HTTP/network error, will retry: %s", deepintshieldError.Error.Message)
		}

		// Retry if status code or error object indicates rate limiting
		if (deepintshieldError.StatusCode != nil && retryableStatusCodes[*deepintshieldError.StatusCode]) ||
			(deepintshieldError.Error != nil &&
				(IsRateLimitErrorMessage(deepintshieldError.Error.Message) ||
					(deepintshieldError.Error.Type != nil && IsRateLimitErrorMessage(*deepintshieldError.Error.Type)))) {
			shouldRetry = true
			logger.Debug("detected rate limit error in message, will retry: %s", deepintshieldError.Error.Message)
		}

		if !shouldRetry {
			break
		}
	}

	// Add retry information to error
	if attempts > 0 {
		logger.Debug("request failed after %d %s", attempts, map[bool]string{true: "attempts", false: "attempt"}[attempts > 1])
	}

	return result, deepintshieldError
}

// requestWorker handles incoming requests from the queue for a specific provider.
// It manages retries, error handling, and response processing.
func (deepintshield *DeepIntShield) requestWorker(provider schemas.Provider, config *schemas.ProviderConfig, pq *ProviderQueue) {
	defer func() {
		if waitGroupValue, ok := deepintshield.waitGroups.Load(provider.GetProviderKey()); ok {
			waitGroup := waitGroupValue.(*sync.WaitGroup)
			waitGroup.Done()
		}
	}()

	for req := range pq.queue {
		_, model, _ := req.DeepIntShieldRequest.GetRequestFields()

		var result *schemas.DeepIntShieldResponse
		var stream chan *schemas.DeepIntShieldStreamChunk
		var deepintshieldError *schemas.DeepIntShieldError
		var err error

		// Determine the base provider type for key requirement checks
		baseProvider := provider.GetProviderKey()
		if cfg := config.CustomProviderConfig; cfg != nil && cfg.BaseProviderType != "" {
			baseProvider = cfg.BaseProviderType
		}
		req.Context.SetValue(schemas.DeepIntShieldContextKeyIsCustomProvider, !IsStandardProvider(baseProvider))

		// Per-tenant network config (PER_TENANT_NETWORK_CONFIG): stamp the
		// caller-tenant's resolved network settings (timeout, stream-idle, base
		// URL) on the request context so they apply to this request without
		// rebuilding the shared per-type provider. No-op when the flag is off.
		if perTenantNetworkConfigEnabled {
			deepintshield.applyTenantNetworkConfig(req.Context, provider.GetProviderKey())
		}

		// Determine whether this provider attempt should capture raw payloads.
		// logging-only mode (store_raw_request_response=true, send_back_raw_*=false):
		//   sets DeepIntShieldContextKeySendBackRaw* = true so providers capture via the unified
		//   ShouldSendBackRaw* path, and sets DeepIntShieldContextKeyRawRequestResponseForLogging
		//   so the payload is stripped before the response reaches the client.
		// full send-back mode (send_back_raw_request/response=true):
		//   DeepIntShieldContextKeySendBackRaw* are set as before; stripping flag stays false.
		// Always set both flags explicitly so stale values from a previous provider
		// attempt (e.g. first attempt was logging-only, fallback is full send-back)
		// cannot leak into the new attempt on a reused context.
		existingSendBackReq, _ := req.Context.Value(schemas.DeepIntShieldContextKeySendBackRawRequest).(bool)
		existingSendBackResp, _ := req.Context.Value(schemas.DeepIntShieldContextKeySendBackRawResponse).(bool)
		loggingOnly := config.StoreRawRequestResponse &&
			!config.SendBackRawRequest && !existingSendBackReq &&
			!config.SendBackRawResponse && !existingSendBackResp
		req.Context.SetValue(schemas.DeepIntShieldContextKeyRawRequestResponseForLogging, loggingOnly)
		if loggingOnly {
			// Enable capture via the standard flags so ShouldSendBackRaw* needs only one check.
			req.Context.SetValue(schemas.DeepIntShieldContextKeySendBackRawRequest, true)
			req.Context.SetValue(schemas.DeepIntShieldContextKeySendBackRawResponse, true)
		}

		key := schemas.Key{}
		var keys []schemas.Key
		if providerRequiresKey(baseProvider, config.CustomProviderConfig) {
			// ListModels needs all enabled/supported keys so providers can aggregate
			// and report per-key statuses (KeyStatuses).
			if req.RequestType == schemas.ListModelsRequest {
				keys, err = deepintshield.getAllSupportedKeys(req.Context, provider.GetProviderKey(), baseProvider)
				if err != nil {
					deepintshield.logger.Debug("error getting supported keys for list models: %v", err)
					req.Err <- schemas.DeepIntShieldError{
						IsDeepIntShieldError: false,
						Error: &schemas.ErrorField{
							Message: err.Error(),
							Error:   err,
						},
						ExtraFields: schemas.DeepIntShieldErrorExtraFields{
							Provider:       provider.GetProviderKey(),
							ModelRequested: model,
							RequestType:    req.RequestType,
						},
					}
					continue
				}
			} else {
				// Determine if this is a multi-key batch/file/container operation
				// BatchCreate, FileUpload, ContainerCreate, ContainerFileCreate use single key; other batch/file/container ops use multiple keys
				isMultiKeyBatchOp := isBatchRequestType(req.RequestType) && req.RequestType != schemas.BatchCreateRequest
				isMultiKeyFileOp := isFileRequestType(req.RequestType) && req.RequestType != schemas.FileUploadRequest
				isMultiKeyContainerOp := isContainerRequestType(req.RequestType) && req.RequestType != schemas.ContainerCreateRequest && req.RequestType != schemas.ContainerFileCreateRequest

				if isMultiKeyBatchOp || isMultiKeyFileOp || isMultiKeyContainerOp {
					var modelPtr *string
					if model != "" {
						modelPtr = &model
					}
					keys, err = deepintshield.getKeysForBatchAndFileOps(req.Context, provider.GetProviderKey(), baseProvider, modelPtr, isMultiKeyBatchOp)
					if err != nil {
						deepintshield.logger.Debug("error getting keys for batch/file operation: %v", err)
						req.Err <- schemas.DeepIntShieldError{
							IsDeepIntShieldError: false,
							Error: &schemas.ErrorField{
								Message: err.Error(),
								Error:   err,
							},
							ExtraFields: schemas.DeepIntShieldErrorExtraFields{
								Provider:       provider.GetProviderKey(),
								ModelRequested: model,
								RequestType:    req.RequestType,
							},
						}
						continue
					}
				} else {
					// Use the custom provider name for actual key selection, but pass base provider type for key validation
					// Start span for key selection
					keyTracer := deepintshield.getTracer()
					keySpanCtx, keyHandle := keyTracer.StartSpan(req.Context, "key.selection", schemas.SpanKindInternal)
					keyTracer.SetAttribute(keyHandle, schemas.AttrProviderName, string(provider.GetProviderKey()))
					keyTracer.SetAttribute(keyHandle, schemas.AttrRequestModel, model)

					key, err = deepintshield.selectKeyFromProviderForModel(req.Context, req.RequestType, provider.GetProviderKey(), model, baseProvider)
					if err != nil {
						keyTracer.SetAttribute(keyHandle, "error", err.Error())
						keyTracer.EndSpan(keyHandle, schemas.SpanStatusError, err.Error())
						deepintshield.logger.Debug("error selecting key for model %s: %v", model, err)
						req.Err <- schemas.DeepIntShieldError{
							IsDeepIntShieldError: false,
							Error: &schemas.ErrorField{
								Message: err.Error(),
								Error:   err,
							},
							ExtraFields: schemas.DeepIntShieldErrorExtraFields{
								Provider:       provider.GetProviderKey(),
								ModelRequested: model,
								RequestType:    req.RequestType,
							},
						}
						continue
					}
					keyTracer.SetAttribute(keyHandle, "key.id", key.ID)
					keyTracer.SetAttribute(keyHandle, "key.name", key.Name)
					keyTracer.EndSpan(keyHandle, schemas.SpanStatusOk, "")
					// Update context with span ID for subsequent operations
					req.Context.SetValue(schemas.DeepIntShieldContextKeySpanID, keySpanCtx.Value(schemas.DeepIntShieldContextKeySpanID))
					req.Context.SetValue(schemas.DeepIntShieldContextKeySelectedKeyID, key.ID)
					req.Context.SetValue(schemas.DeepIntShieldContextKeySelectedKeyName, key.Name)
				}
			}
		}

		// Track active requests for load balancer (no-op when tracker is nil / feature disabled)
		if key.ID != "" {
			deepintshield.keyLoadTracker.IncrementActive(key.ID)
		}

		// Create plugin pipeline for streaming requests outside retry loop to prevent leaks
		var postHookRunner schemas.PostHookRunner
		var pipeline *PluginPipeline
		if IsStreamRequestType(req.RequestType) {
			pipeline = deepintshield.getPluginPipeline()
			postHookRunner = func(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, err *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
				resp, deepintshieldErr := pipeline.RunPostLLMHooks(ctx, result, err, len(*deepintshield.llmPlugins.Load()))
				if deepintshieldErr != nil {
					return nil, deepintshieldErr
				}
				return resp, nil
			}
			// Store a finalizer callback to create aggregated post-hook spans at stream end
			// This closure captures the pipeline reference and releases it after finalization
			postHookSpanFinalizer := func(ctx context.Context) {
				pipeline.FinalizeStreamingPostHookSpans(ctx)
				// Release the pipeline AFTER finalizing spans (not before streaming completes)
				deepintshield.releasePluginPipeline(pipeline)
			}
			req.Context.SetValue(schemas.DeepIntShieldContextKeyPostHookSpanFinalizer, postHookSpanFinalizer)
		}

		// Execute request with retries
		if IsStreamRequestType(req.RequestType) {
			stream, deepintshieldError = executeRequestWithRetries(req.Context, config, func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
				return deepintshield.handleProviderStreamRequest(provider, req, key, postHookRunner)
			}, req.RequestType, provider.GetProviderKey(), model, &req.DeepIntShieldRequest, deepintshield.logger)
		} else {
			result, deepintshieldError = executeRequestWithRetries(req.Context, config, func() (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
				return deepintshield.handleProviderRequest(provider, req, key, keys)
			}, req.RequestType, provider.GetProviderKey(), model, &req.DeepIntShieldRequest, deepintshield.logger)
		}

		// Release pipeline immediately for non-streaming requests only
		// For streaming, the pipeline is released in the postHookSpanFinalizer after streaming completes
		// Exception: if streaming request has an error, release immediately since finalizer won't be called
		if pipeline != nil && (!IsStreamRequestType(req.RequestType) || deepintshieldError != nil) {
			deepintshield.releasePluginPipeline(pipeline)
		}

		// Record load balancer metrics (no-op when tracker is nil / feature disabled)
		if key.ID != "" {
			deepintshield.keyLoadTracker.DecrementActive(key.ID)
			if deepintshieldError != nil {
				deepintshield.keyLoadTracker.RecordError(key.ID)
			} else {
				// Non-streaming responses carry usage inline; pull total_tokens
				// so the load-balancer dashboard reflects real token throughput.
				// Streaming usage is delivered later via the deferred-usage
				// channel; the postHookSpanFinalizer is responsible for that.
				deepintshield.keyLoadTracker.RecordSuccess(key.ID, int64(result.GetTotalTokens()))
			}
		}

		if deepintshieldError != nil {
			deepintshieldError.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				Provider:       provider.GetProviderKey(),
				ModelRequested: model,
				RequestType:    req.RequestType,
				RawRequest:     deepintshieldError.ExtraFields.RawRequest,
				RawResponse:    deepintshieldError.ExtraFields.RawResponse,
				KeyStatuses:    deepintshieldError.ExtraFields.KeyStatuses,
			}

			// Send error with context awareness to prevent deadlock
			select {
			case req.Err <- *deepintshieldError:
				// Error sent successfully
			case <-req.Context.Done():
				// Client no longer listening, log and continue
				deepintshield.logger.Debug("Client context cancelled while sending error response")
			case <-time.After(5 * time.Second):
				// Timeout to prevent indefinite blocking
				deepintshield.logger.Warn("Timeout while sending error response, client may have disconnected")
			}
		} else {
			if IsStreamRequestType(req.RequestType) {
				// Send stream with context awareness to prevent deadlock
				select {
				case req.ResponseStream <- stream:
					// Stream sent successfully
				case <-req.Context.Done():
					// Client no longer listening, log and continue
					deepintshield.logger.Debug("Client context cancelled while sending stream response")
				case <-time.After(5 * time.Second):
					// Timeout to prevent indefinite blocking
					deepintshield.logger.Warn("Timeout while sending stream response, client may have disconnected")
				}
			} else {
				// Send response with context awareness to prevent deadlock
				select {
				case req.Response <- result:
					// Response sent successfully
				case <-req.Context.Done():
					// Client no longer listening, log and continue
					deepintshield.logger.Debug("Client context cancelled while sending response")
				case <-time.After(5 * time.Second):
					// Timeout to prevent indefinite blocking
					deepintshield.logger.Warn("Timeout while sending response, client may have disconnected")
				}
			}
		}
	}

	// deepintshield.logger.Debug("worker for provider %s exiting...", provider.GetProviderKey())
}

// handleProviderRequest handles the request to the provider based on the request type
// key is used for single-key operations, keys is used for batch/file operations that need multiple keys
func (deepintshield *DeepIntShield) handleProviderRequest(provider schemas.Provider, req *ChannelMessage, key schemas.Key, keys []schemas.Key) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
	response := &schemas.DeepIntShieldResponse{}
	switch req.RequestType {
	case schemas.ListModelsRequest:
		listModelsResponse, deepintshieldError := provider.ListModels(req.Context, keys, req.DeepIntShieldRequest.ListModelsRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ListModelsResponse = listModelsResponse
	case schemas.TextCompletionRequest:
		textCompletionResponse, deepintshieldError := provider.TextCompletion(req.Context, key, req.DeepIntShieldRequest.TextCompletionRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.TextCompletionResponse = textCompletionResponse
	case schemas.ChatCompletionRequest:
		chatCompletionResponse, deepintshieldError := provider.ChatCompletion(req.Context, key, req.DeepIntShieldRequest.ChatRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ChatResponse = chatCompletionResponse
	case schemas.ResponsesRequest:
		responsesResponse, deepintshieldError := provider.Responses(req.Context, key, req.DeepIntShieldRequest.ResponsesRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ResponsesResponse = responsesResponse
	case schemas.CountTokensRequest:
		countTokensResponse, deepintshieldError := provider.CountTokens(req.Context, key, req.DeepIntShieldRequest.CountTokensRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.CountTokensResponse = countTokensResponse
	case schemas.EmbeddingRequest:
		embeddingResponse, deepintshieldError := provider.Embedding(req.Context, key, req.DeepIntShieldRequest.EmbeddingRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.EmbeddingResponse = embeddingResponse
	case schemas.RerankRequest:
		rerankResponse, deepintshieldError := provider.Rerank(req.Context, key, req.DeepIntShieldRequest.RerankRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.RerankResponse = rerankResponse
	case schemas.SpeechRequest:
		speechResponse, deepintshieldError := provider.Speech(req.Context, key, req.DeepIntShieldRequest.SpeechRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		speechResponse.BackfillParams(req.DeepIntShieldRequest.SpeechRequest)
		response.SpeechResponse = speechResponse
	case schemas.TranscriptionRequest:
		transcriptionResponse, deepintshieldError := provider.Transcription(req.Context, key, req.DeepIntShieldRequest.TranscriptionRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.TranscriptionResponse = transcriptionResponse
	case schemas.ImageGenerationRequest:
		imageResponse, deepintshieldError := provider.ImageGeneration(req.Context, key, req.DeepIntShieldRequest.ImageGenerationRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		imageResponse.BackfillParams(&req.DeepIntShieldRequest)
		response.ImageGenerationResponse = imageResponse
	case schemas.ImageEditRequest:
		imageEditResponse, deepintshieldError := provider.ImageEdit(req.Context, key, req.DeepIntShieldRequest.ImageEditRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		imageEditResponse.BackfillParams(&req.DeepIntShieldRequest)
		response.ImageGenerationResponse = imageEditResponse
	case schemas.ImageVariationRequest:
		imageVariationResponse, deepintshieldError := provider.ImageVariation(req.Context, key, req.DeepIntShieldRequest.ImageVariationRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		imageVariationResponse.BackfillParams(&req.DeepIntShieldRequest)
		response.ImageGenerationResponse = imageVariationResponse
	case schemas.VideoGenerationRequest:
		videoGenerationResponse, deepintshieldError := provider.VideoGeneration(req.Context, key, req.DeepIntShieldRequest.VideoGenerationRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		videoGenerationResponse.BackfillParams(&req.DeepIntShieldRequest)
		response.VideoGenerationResponse = videoGenerationResponse
	case schemas.VideoRetrieveRequest:
		videoRetrieveResponse, deepintshieldError := provider.VideoRetrieve(req.Context, key, req.DeepIntShieldRequest.VideoRetrieveRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.VideoGenerationResponse = videoRetrieveResponse
	case schemas.VideoDownloadRequest:
		videoDownloadResponse, deepintshieldError := provider.VideoDownload(req.Context, key, req.DeepIntShieldRequest.VideoDownloadRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.VideoDownloadResponse = videoDownloadResponse
	case schemas.VideoListRequest:
		videoListResponse, deepintshieldError := provider.VideoList(req.Context, key, req.DeepIntShieldRequest.VideoListRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.VideoListResponse = videoListResponse
	case schemas.VideoDeleteRequest:
		videoDeleteResponse, deepintshieldError := provider.VideoDelete(req.Context, key, req.DeepIntShieldRequest.VideoDeleteRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.VideoDeleteResponse = videoDeleteResponse
	case schemas.VideoRemixRequest:
		videoRemixResponse, deepintshieldError := provider.VideoRemix(req.Context, key, req.DeepIntShieldRequest.VideoRemixRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.VideoGenerationResponse = videoRemixResponse
	case schemas.FileUploadRequest:
		fileUploadResponse, deepintshieldError := provider.FileUpload(req.Context, key, req.DeepIntShieldRequest.FileUploadRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.FileUploadResponse = fileUploadResponse
	case schemas.FileListRequest:
		fileListResponse, deepintshieldError := provider.FileList(req.Context, keys, req.DeepIntShieldRequest.FileListRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.FileListResponse = fileListResponse
	case schemas.FileRetrieveRequest:
		fileRetrieveResponse, deepintshieldError := provider.FileRetrieve(req.Context, keys, req.DeepIntShieldRequest.FileRetrieveRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.FileRetrieveResponse = fileRetrieveResponse
	case schemas.FileDeleteRequest:
		fileDeleteResponse, deepintshieldError := provider.FileDelete(req.Context, keys, req.DeepIntShieldRequest.FileDeleteRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.FileDeleteResponse = fileDeleteResponse
	case schemas.FileContentRequest:
		fileContentResponse, deepintshieldError := provider.FileContent(req.Context, keys, req.DeepIntShieldRequest.FileContentRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.FileContentResponse = fileContentResponse
	case schemas.BatchCreateRequest:
		batchCreateResponse, deepintshieldError := provider.BatchCreate(req.Context, key, req.DeepIntShieldRequest.BatchCreateRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.BatchCreateResponse = batchCreateResponse
	case schemas.BatchListRequest:
		batchListResponse, deepintshieldError := provider.BatchList(req.Context, keys, req.DeepIntShieldRequest.BatchListRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.BatchListResponse = batchListResponse
	case schemas.BatchRetrieveRequest:
		batchRetrieveResponse, deepintshieldError := provider.BatchRetrieve(req.Context, keys, req.DeepIntShieldRequest.BatchRetrieveRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.BatchRetrieveResponse = batchRetrieveResponse
	case schemas.BatchCancelRequest:
		batchCancelResponse, deepintshieldError := provider.BatchCancel(req.Context, keys, req.DeepIntShieldRequest.BatchCancelRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.BatchCancelResponse = batchCancelResponse
	case schemas.BatchDeleteRequest:
		batchDeleteResponse, deepintshieldError := provider.BatchDelete(req.Context, keys, req.DeepIntShieldRequest.BatchDeleteRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.BatchDeleteResponse = batchDeleteResponse
	case schemas.BatchResultsRequest:
		batchResultsResponse, deepintshieldError := provider.BatchResults(req.Context, keys, req.DeepIntShieldRequest.BatchResultsRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.BatchResultsResponse = batchResultsResponse
	case schemas.ContainerCreateRequest:
		containerCreateResponse, deepintshieldError := provider.ContainerCreate(req.Context, key, req.DeepIntShieldRequest.ContainerCreateRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerCreateResponse = containerCreateResponse
	case schemas.ContainerListRequest:
		containerListResponse, deepintshieldError := provider.ContainerList(req.Context, keys, req.DeepIntShieldRequest.ContainerListRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerListResponse = containerListResponse
	case schemas.ContainerRetrieveRequest:
		containerRetrieveResponse, deepintshieldError := provider.ContainerRetrieve(req.Context, keys, req.DeepIntShieldRequest.ContainerRetrieveRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerRetrieveResponse = containerRetrieveResponse
	case schemas.ContainerDeleteRequest:
		containerDeleteResponse, deepintshieldError := provider.ContainerDelete(req.Context, keys, req.DeepIntShieldRequest.ContainerDeleteRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerDeleteResponse = containerDeleteResponse
	case schemas.ContainerFileCreateRequest:
		containerFileCreateResponse, deepintshieldError := provider.ContainerFileCreate(req.Context, key, req.DeepIntShieldRequest.ContainerFileCreateRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerFileCreateResponse = containerFileCreateResponse
	case schemas.ContainerFileListRequest:
		containerFileListResponse, deepintshieldError := provider.ContainerFileList(req.Context, keys, req.DeepIntShieldRequest.ContainerFileListRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerFileListResponse = containerFileListResponse
	case schemas.ContainerFileRetrieveRequest:
		containerFileRetrieveResponse, deepintshieldError := provider.ContainerFileRetrieve(req.Context, keys, req.DeepIntShieldRequest.ContainerFileRetrieveRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerFileRetrieveResponse = containerFileRetrieveResponse
	case schemas.ContainerFileContentRequest:
		containerFileContentResponse, deepintshieldError := provider.ContainerFileContent(req.Context, keys, req.DeepIntShieldRequest.ContainerFileContentRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerFileContentResponse = containerFileContentResponse
	case schemas.ContainerFileDeleteRequest:
		containerFileDeleteResponse, deepintshieldError := provider.ContainerFileDelete(req.Context, keys, req.DeepIntShieldRequest.ContainerFileDeleteRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.ContainerFileDeleteResponse = containerFileDeleteResponse
	case schemas.PassthroughRequest:
		passthroughResponse, deepintshieldError := provider.Passthrough(req.Context, key, req.DeepIntShieldRequest.PassthroughRequest)
		if deepintshieldError != nil {
			return nil, deepintshieldError
		}
		response.PassthroughResponse = passthroughResponse
	default:
		_, model, _ := req.DeepIntShieldRequest.GetRequestFields()
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: fmt.Sprintf("unsupported request type: %s", req.RequestType),
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider.GetProviderKey(),
				ModelRequested: model,
			},
		}
	}
	return response, nil
}

// handleProviderStreamRequest handles the stream request to the provider based on the request type
func (deepintshield *DeepIntShield) handleProviderStreamRequest(provider schemas.Provider, req *ChannelMessage, key schemas.Key, postHookRunner schemas.PostHookRunner) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	switch req.RequestType {
	case schemas.TextCompletionStreamRequest:
		return provider.TextCompletionStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.TextCompletionRequest)
	case schemas.ChatCompletionStreamRequest:
		return provider.ChatCompletionStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.ChatRequest)
	case schemas.ResponsesStreamRequest:
		return provider.ResponsesStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.ResponsesRequest)
	case schemas.SpeechStreamRequest:
		return provider.SpeechStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.SpeechRequest)
	case schemas.TranscriptionStreamRequest:
		return provider.TranscriptionStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.TranscriptionRequest)
	case schemas.ImageGenerationStreamRequest:
		return provider.ImageGenerationStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.ImageGenerationRequest)
	case schemas.ImageEditStreamRequest:
		return provider.ImageEditStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.ImageEditRequest)
	case schemas.PassthroughStreamRequest:
		return provider.PassthroughStream(req.Context, postHookRunner, key, req.DeepIntShieldRequest.PassthroughRequest)
	default:
		_, model, _ := req.DeepIntShieldRequest.GetRequestFields()
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: fmt.Sprintf("unsupported request type: %s", req.RequestType),
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType:    req.RequestType,
				Provider:       provider.GetProviderKey(),
				ModelRequested: model,
			},
		}
	}
}

// handleMCPToolExecution is the common handler for MCP tool execution with plugin pipeline support.
// It handles pre-hooks, execution, post-hooks, and error handling for both Chat and Responses formats.
//
// Parameters:
//   - ctx: Execution context
//   - mcpRequest: The MCP request to execute (already populated with tool call)
//   - requestType: The request type for error reporting (ChatCompletionRequest or ResponsesRequest)
//
// Returns:
//   - *schemas.DeepIntShieldMCPResponse: The MCP response after all hooks
//   - *schemas.DeepIntShieldError: Any execution error
func (deepintshield *DeepIntShield) handleMCPToolExecution(ctx *schemas.DeepIntShieldContext, mcpRequest *schemas.DeepIntShieldMCPRequest, requestType schemas.RequestType) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError) {
	if deepintshield.MCPManager == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "MCP is not configured in this DeepIntShield instance",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: requestType,
			},
		}
	}

	// Ensure request ID exists for hooks/tracing consistency
	if _, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string); !ok {
		ctx.SetValue(schemas.DeepIntShieldContextKeyRequestID, uuid.New().String())
	}

	// Get plugin pipeline for MCP hooks
	pipeline := deepintshield.getPluginPipeline()
	defer deepintshield.releasePluginPipeline(pipeline)

	// Run pre-hooks
	preReq, shortCircuit, preCount := pipeline.RunMCPPreHooks(ctx, mcpRequest)

	// Handle short-circuit cases
	if shortCircuit != nil {
		// Handle short-circuit with response (success case)
		if shortCircuit.Response != nil {
			finalMcpResp, deepintshieldErr := pipeline.RunMCPPostHooks(ctx, shortCircuit.Response, nil, preCount)
			if deepintshieldErr != nil {
				return nil, deepintshieldErr
			}
			return finalMcpResp, nil
		}
		// Handle short-circuit with error
		if shortCircuit.Error != nil {
			// Capture post-hook results to respect transformations or recovery
			finalResp, finalErr := pipeline.RunMCPPostHooks(ctx, nil, shortCircuit.Error, preCount)
			// Return post-hook error if present (post-hook may have transformed the error)
			if finalErr != nil {
				return nil, finalErr
			}
			// Return post-hook response if present (post-hook may have recovered from error)
			if finalResp != nil {
				return finalResp, nil
			}
			// Fall back to original short-circuit error if post-hooks returned nil/nil
			return nil, shortCircuit.Error
		}
	}

	if preReq == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "MCP request after plugin hooks cannot be nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: requestType,
			},
		}
	}

	// Execute tool with modified request
	result, err := deepintshield.MCPManager.ExecuteToolCall(ctx, preReq)

	// Prepare MCP response and error for post-hooks
	var mcpResp *schemas.DeepIntShieldMCPResponse
	var deepintshieldErr *schemas.DeepIntShieldError

	if err != nil {
		deepintshieldErr = &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: err.Error(),
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: requestType,
			},
		}
	} else if result == nil {
		deepintshieldErr = &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: "tool execution returned nil result",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				RequestType: requestType,
			},
		}
	} else {
		// Use the MCP response directly
		mcpResp = result
	}

	// Run post-hooks
	finalResp, finalErr := pipeline.RunMCPPostHooks(ctx, mcpResp, deepintshieldErr, preCount)

	if finalErr != nil {
		return nil, finalErr
	}

	return finalResp, nil
}

// executeMCPToolWithHooks is a wrapper around handleMCPToolExecution that matches the signature
// expected by the agent's executeToolFunc parameter. It runs MCP plugin hooks before and after
// tool execution to enable logging, telemetry, and other plugin functionality.
func (deepintshield *DeepIntShield) executeMCPToolWithHooks(ctx *schemas.DeepIntShieldContext, request *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPResponse, error) {
	// Defensive check: context must be non-nil to prevent panics in plugin hooks
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	if request == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	// Determine request type from the MCP request - explicitly handle all known types
	var requestType schemas.RequestType
	switch request.RequestType {
	case schemas.MCPRequestTypeChatToolCall:
		requestType = schemas.ChatCompletionRequest
	case schemas.MCPRequestTypeResponsesToolCall:
		requestType = schemas.ResponsesRequest
	default:
		// Return error for unknown/unsupported request types instead of silently defaulting
		return nil, fmt.Errorf("unsupported MCP request type: %s", request.RequestType)
	}

	resp, deepintshieldErr := deepintshield.handleMCPToolExecution(ctx, request, requestType)
	if deepintshieldErr != nil {
		return nil, fmt.Errorf("%s", GetErrorMessage(deepintshieldErr))
	}
	return resp, nil
}

// PLUGIN MANAGEMENT

// RunLLMPreHooks executes PreHooks in order, tracks how many ran, and returns the final request, any short-circuit decision, and the count.
func (p *PluginPipeline) RunLLMPreHooks(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, int) {
	// If the skip plugin pipeline flag is set, skip the plugin pipeline
	if skipPluginPipeline, ok := ctx.Value(schemas.DeepIntShieldContextKeySkipPluginPipeline).(bool); ok && skipPluginPipeline {
		return req, nil, 0
	}
	stopChain := schemas.TrackLatencyPhase(ctx, schemas.LatencyPhasePluginChainPre)
	defer stopChain()
	var shortCircuit *schemas.LLMPluginShortCircuit
	var err error
	ctx.BlockRestrictedWrites()
	defer ctx.UnblockRestrictedWrites()
	for i, plugin := range p.llmPlugins {
		// Workspace dispatch is evaluated per-plugin rather than as an
		// upfront slice filter. The governance plugin's PreLLMHook is what
		// stamps workspace_id onto ctx (from the request's virtual key);
		// any earlier filter would see an empty workspace_id and drop every
		// workspace-tagged instance, breaking cost-opt / hallucination /
		// other per-workspace plugin behavior on VK-only auth flows.
		if !shouldRunPluginForRequestWorkspace(plugin, p.llmPlugins, workspaceFromContext(ctx)) {
			continue
		}
		pluginName := plugin.GetName()
		p.logger.Debug("running pre-hook for plugin %s", pluginName)
		// Start span for this plugin's PreLLMHook
		spanCtx, handle := p.tracer.StartSpan(ctx, fmt.Sprintf("plugin.%s.prehook", sanitizeSpanName(pluginName)), schemas.SpanKindPlugin)
		// Update pluginCtx with span context for nested operations
		if spanCtx != nil {
			if spanID, ok := spanCtx.Value(schemas.DeepIntShieldContextKeySpanID).(string); ok {
				ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanID)
			}
		}

		pluginStart := time.Now()
		req, shortCircuit, err = plugin.PreLLMHook(ctx, req)
		schemas.RecordLatencyPhase(ctx, schemas.LatencyPhase("plugin_pre_"+pluginName), time.Since(pluginStart))

		// End span with appropriate status
		if err != nil {
			p.tracer.SetAttribute(handle, "error", err.Error())
			p.tracer.EndSpan(handle, schemas.SpanStatusError, err.Error())
			p.preHookErrors = append(p.preHookErrors, err)
			p.logger.Warn("error in PreLLMHook for plugin %s: %s", pluginName, err.Error())
		} else if shortCircuit != nil {
			p.tracer.SetAttribute(handle, "short_circuit", true)
			p.tracer.EndSpan(handle, schemas.SpanStatusOk, "short-circuit")
		} else {
			p.tracer.EndSpan(handle, schemas.SpanStatusOk, "")
		}

		p.executedPreHooks = i + 1
		if shortCircuit != nil {
			return req, shortCircuit, p.executedPreHooks // short-circuit: only plugins up to and including i ran
		}
	}
	return req, nil, p.executedPreHooks
}

// RunPostLLMHooks executes PostHooks in reverse order for the plugins whose PreLLMHook ran.
// Accepts the response and error, and allows plugins to transform either (e.g., recover from error, or invalidate a response).
// Returns the final response and error after all hooks. If both are set, error takes precedence unless error is nil.
// runFrom is the count of plugins whose PreHooks ran; PostHooks will run in reverse from index (runFrom - 1) down to 0
// For streaming requests, it accumulates timing per plugin instead of creating individual spans per chunk.
func (p *PluginPipeline) RunPostLLMHooks(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError, runFrom int) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError) {
	// If the skip plugin pipeline flag is set, skip the plugin pipeline
	if skipPluginPipeline, ok := ctx.Value(schemas.DeepIntShieldContextKeySkipPluginPipeline).(bool); ok && skipPluginPipeline {
		return resp, deepintshieldErr
	}
	// Defensive: ensure count is within valid bounds
	if runFrom < 0 {
		runFrom = 0
	}
	if runFrom > len(p.llmPlugins) {
		runFrom = len(p.llmPlugins)
	}
	// Detect streaming mode - if StreamStartTime is set, we're in a streaming context
	isStreaming := ctx.Value(schemas.DeepIntShieldContextKeyStreamStartTime) != nil
	stopChain := schemas.TrackLatencyPhase(ctx, schemas.LatencyPhasePluginChainPost)
	defer stopChain()
	ctx.BlockRestrictedWrites()
	defer ctx.UnblockRestrictedWrites()
	var err error
	for i := runFrom - 1; i >= 0; i-- {
		plugin := p.llmPlugins[i]
		// Re-apply the per-plugin workspace dispatch so we run the post-
		// hook only for plugins whose pre-hook ran. Workspace_id on ctx is
		// stable from PreLLMHook through PostLLMHook (governance stamps it
		// once, no other plugin touches it), so this decision agrees with
		// the pre-hook loop for every i.
		if !shouldRunPluginForRequestWorkspace(plugin, p.llmPlugins, workspaceFromContext(ctx)) {
			continue
		}
		pluginName := plugin.GetName()
		p.logger.Debug("running post-hook for plugin %s", pluginName)
		if isStreaming {
			// For streaming: accumulate timing, don't create individual spans per chunk
			start := time.Now()
			resp, deepintshieldErr, err = plugin.PostLLMHook(ctx, resp, deepintshieldErr)
			duration := time.Since(start)

			p.accumulatePluginTiming(pluginName, duration, err != nil)
			if err != nil {
				p.postHookErrors = append(p.postHookErrors, err)
				p.logger.Warn("error in PostLLMHook for plugin %s: %v", pluginName, err)
			}
		} else {
			// For non-streaming: create span per plugin (existing behavior)
			spanCtx, handle := p.tracer.StartSpan(ctx, fmt.Sprintf("plugin.%s.posthook", sanitizeSpanName(pluginName)), schemas.SpanKindPlugin)
			// Update pluginCtx with span context for nested operations
			if spanCtx != nil {
				if spanID, ok := spanCtx.Value(schemas.DeepIntShieldContextKeySpanID).(string); ok {
					ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanID)
				}
			}
			resp, deepintshieldErr, err = plugin.PostLLMHook(ctx, resp, deepintshieldErr)
			// End span with appropriate status
			if err != nil {
				p.tracer.SetAttribute(handle, "error", err.Error())
				p.tracer.EndSpan(handle, schemas.SpanStatusError, err.Error())
				p.postHookErrors = append(p.postHookErrors, err)
				p.logger.Warn("error in PostLLMHook for plugin %s: %v", pluginName, err)
			} else {
				p.tracer.EndSpan(handle, schemas.SpanStatusOk, "")
			}
		}
		// If a plugin recovers from an error (sets deepintshieldErr to nil and sets resp), allow that
		// If a plugin invalidates a response (sets resp to nil and sets deepintshieldErr), allow that
	}
	// Increment chunk count for streaming
	if isStreaming {
		p.chunkCount++
	}
	// Final logic: if both are set, error takes precedence, unless error is nil
	if deepintshieldErr != nil {
		if resp != nil && deepintshieldErr.StatusCode == nil && deepintshieldErr.Error != nil && deepintshieldErr.Error.Type == nil &&
			deepintshieldErr.Error.Message == "" && deepintshieldErr.Error.Error == nil {
			// Defensive: treat as recovery if error is empty
			return resp, nil
		}
		return resp, deepintshieldErr
	}
	return resp, nil
}

// RunMCPPreHooks executes MCP PreHooks in order for all registered MCP plugins.
// Returns the modified request, any short-circuit decision, and the count of hooks that ran.
// If a plugin short-circuits, only PostHooks for plugins up to and including that plugin will run.
func (p *PluginPipeline) RunMCPPreHooks(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, int) {
	// If the skip plugin pipeline flag is set, skip the plugin pipeline
	if skipPluginPipeline, ok := ctx.Value(schemas.DeepIntShieldContextKeySkipPluginPipeline).(bool); ok && skipPluginPipeline {
		return req, nil, 0
	}
	var shortCircuit *schemas.MCPPluginShortCircuit
	var err error
	ctx.BlockRestrictedWrites()
	defer ctx.UnblockRestrictedWrites()
	for i, plugin := range p.mcpPlugins {
		// Per-plugin workspace dispatch - same rationale as RunLLMPreHooks.
		if !shouldRunPluginForRequestWorkspace(plugin, p.mcpPlugins, workspaceFromContext(ctx)) {
			continue
		}
		pluginName := plugin.GetName()
		p.logger.Debug("running MCP pre-hook for plugin %s", pluginName)
		// Start span for this plugin's PreMCPHook
		spanCtx, handle := p.tracer.StartSpan(ctx, fmt.Sprintf("plugin.%s.mcp_prehook", sanitizeSpanName(pluginName)), schemas.SpanKindPlugin)
		// Update pluginCtx with span context for nested operations
		if spanCtx != nil {
			if spanID, ok := spanCtx.Value(schemas.DeepIntShieldContextKeySpanID).(string); ok {
				ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanID)
			}
		}

		req, shortCircuit, err = plugin.PreMCPHook(ctx, req)

		// End span with appropriate status
		if err != nil {
			p.tracer.SetAttribute(handle, "error", err.Error())
			p.tracer.EndSpan(handle, schemas.SpanStatusError, err.Error())
			p.preHookErrors = append(p.preHookErrors, err)
			p.logger.Warn("error in PreMCPHook for plugin %s: %s", pluginName, err.Error())
		} else if shortCircuit != nil {
			p.tracer.SetAttribute(handle, "short_circuit", true)
			p.tracer.EndSpan(handle, schemas.SpanStatusOk, "short-circuit")
		} else {
			p.tracer.EndSpan(handle, schemas.SpanStatusOk, "")
		}

		p.executedPreHooks = i + 1
		if shortCircuit != nil {
			return req, shortCircuit, p.executedPreHooks // short-circuit: only plugins up to and including i ran
		}
	}
	return req, nil, p.executedPreHooks
}

// RunMCPPostHooks executes MCP PostHooks in reverse order for the plugins whose PreMCPHook ran.
// Accepts the MCP response and error, and allows plugins to transform either (e.g., recover from error, or invalidate a response).
// Returns the final MCP response and error after all hooks. If both are set, error takes precedence unless error is nil.
// runFrom is the count of plugins whose PreHooks ran; PostHooks will run in reverse from index (runFrom - 1) down to 0
func (p *PluginPipeline) RunMCPPostHooks(ctx *schemas.DeepIntShieldContext, mcpResp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError, runFrom int) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError) {
	// If the skip plugin pipeline flag is set, skip the plugin pipeline
	if skipPluginPipeline, ok := ctx.Value(schemas.DeepIntShieldContextKeySkipPluginPipeline).(bool); ok && skipPluginPipeline {
		return mcpResp, deepintshieldErr
	}
	// Defensive: ensure count is within valid bounds
	if runFrom < 0 {
		runFrom = 0
	}
	if runFrom > len(p.mcpPlugins) {
		runFrom = len(p.mcpPlugins)
	}
	ctx.BlockRestrictedWrites()
	defer ctx.UnblockRestrictedWrites()
	var err error
	for i := runFrom - 1; i >= 0; i-- {
		plugin := p.mcpPlugins[i]
		// Per-plugin workspace dispatch - same rationale as RunPostLLMHooks.
		if !shouldRunPluginForRequestWorkspace(plugin, p.mcpPlugins, workspaceFromContext(ctx)) {
			continue
		}
		pluginName := plugin.GetName()
		p.logger.Debug("running MCP post-hook for plugin %s", pluginName)
		// Create span per plugin
		spanCtx, handle := p.tracer.StartSpan(ctx, fmt.Sprintf("plugin.%s.mcp_posthook", sanitizeSpanName(pluginName)), schemas.SpanKindPlugin)
		// Update pluginCtx with span context for nested operations
		if spanCtx != nil {
			if spanID, ok := spanCtx.Value(schemas.DeepIntShieldContextKeySpanID).(string); ok {
				ctx.SetValue(schemas.DeepIntShieldContextKeySpanID, spanID)
			}
		}

		mcpResp, deepintshieldErr, err = plugin.PostMCPHook(ctx, mcpResp, deepintshieldErr)

		// End span with appropriate status
		if err != nil {
			p.tracer.SetAttribute(handle, "error", err.Error())
			p.tracer.EndSpan(handle, schemas.SpanStatusError, err.Error())
			p.postHookErrors = append(p.postHookErrors, err)
			p.logger.Warn("error in PostMCPHook for plugin %s: %v", pluginName, err)
		} else {
			p.tracer.EndSpan(handle, schemas.SpanStatusOk, "")
		}
		// If a plugin recovers from an error (sets deepintshieldErr to nil and sets mcpResp), allow that
		// If a plugin invalidates a response (sets mcpResp to nil and sets deepintshieldErr), allow that
	}
	// Final logic: if both are set, error takes precedence, unless error is nil
	if deepintshieldErr != nil {
		if mcpResp != nil && deepintshieldErr.StatusCode == nil && deepintshieldErr.Error != nil && deepintshieldErr.Error.Type == nil &&
			deepintshieldErr.Error.Message == "" && deepintshieldErr.Error.Error == nil {
			// Defensive: treat as recovery if error is empty
			return mcpResp, nil
		}
		return mcpResp, deepintshieldErr
	}
	return mcpResp, nil
}

// resetPluginPipeline resets a PluginPipeline instance for reuse
func (p *PluginPipeline) resetPluginPipeline() {
	p.executedPreHooks = 0
	p.preHookErrors = p.preHookErrors[:0]
	p.postHookErrors = p.postHookErrors[:0]
	// Reset streaming timing accumulation
	p.chunkCount = 0
	if p.postHookTimings != nil {
		clear(p.postHookTimings)
	}
	p.postHookPluginOrder = p.postHookPluginOrder[:0]
}

// accumulatePluginTiming accumulates timing for a plugin during streaming
func (p *PluginPipeline) accumulatePluginTiming(pluginName string, duration time.Duration, hasError bool) {
	if p.postHookTimings == nil {
		p.postHookTimings = make(map[string]*pluginTimingAccumulator)
	}
	timing, ok := p.postHookTimings[pluginName]
	if !ok {
		timing = &pluginTimingAccumulator{}
		p.postHookTimings[pluginName] = timing
		// Track order on first occurrence (first chunk)
		p.postHookPluginOrder = append(p.postHookPluginOrder, pluginName)
	}
	timing.totalDuration += duration
	timing.invocations++
	if hasError {
		timing.errors++
	}
}

// FinalizeStreamingPostHookSpans creates aggregated spans for each plugin after streaming completes.
// This should be called once at the end of streaming to create one span per plugin with average timing.
// Spans are nested to mirror the pre-hook hierarchy (each post-hook is a child of the previous one).
func (p *PluginPipeline) FinalizeStreamingPostHookSpans(ctx context.Context) {
	if p.postHookTimings == nil || len(p.postHookPluginOrder) == 0 {
		return
	}

	// Collect handles and timing info to end spans in reverse order
	type spanInfo struct {
		handle    schemas.SpanHandle
		hasErrors bool
	}
	spans := make([]spanInfo, 0, len(p.postHookPluginOrder))
	currentCtx := ctx

	// Start spans in execution order (nested: each is a child of the previous)
	for _, pluginName := range p.postHookPluginOrder {
		timing, ok := p.postHookTimings[pluginName]
		if !ok || timing.invocations == 0 {
			continue
		}

		// Create span as child of the previous span (nested hierarchy)
		newCtx, handle := p.tracer.StartSpan(currentCtx, fmt.Sprintf("plugin.%s.posthook", sanitizeSpanName(pluginName)), schemas.SpanKindPlugin)
		if handle == nil {
			continue
		}

		// Calculate average duration in milliseconds
		avgMs := float64(timing.totalDuration.Milliseconds()) / float64(timing.invocations)

		// Set aggregated attributes
		p.tracer.SetAttribute(handle, schemas.AttrPluginInvocations, timing.invocations)
		p.tracer.SetAttribute(handle, schemas.AttrPluginAvgDurationMs, avgMs)
		p.tracer.SetAttribute(handle, schemas.AttrPluginTotalDurationMs, timing.totalDuration.Milliseconds())

		if timing.errors > 0 {
			p.tracer.SetAttribute(handle, schemas.AttrPluginErrorCount, timing.errors)
		}

		spans = append(spans, spanInfo{handle: handle, hasErrors: timing.errors > 0})
		currentCtx = newCtx
	}

	// End spans in reverse order (innermost first, like unwinding a call stack)
	for i := len(spans) - 1; i >= 0; i-- {
		if spans[i].hasErrors {
			p.tracer.EndSpan(spans[i].handle, schemas.SpanStatusError, "some invocations failed")
		} else {
			p.tracer.EndSpan(spans[i].handle, schemas.SpanStatusOk, "")
		}
	}
}

// GetChunkCount returns the number of chunks processed during streaming
func (p *PluginPipeline) GetChunkCount() int {
	return p.chunkCount
}

// getPluginPipeline gets a PluginPipeline from the pool and configures it
func (deepintshield *DeepIntShield) getPluginPipeline() *PluginPipeline {
	pipeline := deepintshield.pluginPipelinePool.Get().(*PluginPipeline)
	pipeline.llmPlugins = *deepintshield.llmPlugins.Load()
	pipeline.mcpPlugins = *deepintshield.mcpPlugins.Load()
	pipeline.logger = deepintshield.logger
	pipeline.tracer = deepintshield.getTracer()
	return pipeline
}

// releasePluginPipeline returns a PluginPipeline to the pool
func (deepintshield *DeepIntShield) releasePluginPipeline(pipeline *PluginPipeline) {
	pipeline.resetPluginPipeline()
	deepintshield.pluginPipelinePool.Put(pipeline)
}

// POOL & RESOURCE MANAGEMENT

// getChannelMessage gets a ChannelMessage from the pool and configures it with the request.
// It also gets response and error channels from their respective pools.
func (deepintshield *DeepIntShield) getChannelMessage(req schemas.DeepIntShieldRequest) *ChannelMessage {
	// Get channels from pool
	responseChan := deepintshield.responseChannelPool.Get().(chan *schemas.DeepIntShieldResponse)
	errorChan := deepintshield.errorChannelPool.Get().(chan schemas.DeepIntShieldError)

	// Clear any previous values to avoid leaking between requests
	select {
	case <-responseChan:
	default:
	}
	select {
	case <-errorChan:
	default:
	}

	// Get message from pool and configure it
	msg := deepintshield.channelMessagePool.Get().(*ChannelMessage)
	msg.DeepIntShieldRequest = req
	msg.Response = responseChan
	msg.Err = errorChan

	// Conditionally allocate ResponseStream for streaming requests only
	if IsStreamRequestType(req.RequestType) {
		responseStreamChan := deepintshield.responseStreamPool.Get().(chan chan *schemas.DeepIntShieldStreamChunk)
		// Clear any previous values to avoid leaking between requests
		select {
		case <-responseStreamChan:
		default:
		}
		msg.ResponseStream = responseStreamChan
	}

	return msg
}

// releaseChannelMessage returns a ChannelMessage and its channels to their respective pools.
func (deepintshield *DeepIntShield) releaseChannelMessage(msg *ChannelMessage) {
	// Put channels back in pools
	deepintshield.responseChannelPool.Put(msg.Response)
	deepintshield.errorChannelPool.Put(msg.Err)

	// Return ResponseStream to pool if it was used
	if msg.ResponseStream != nil {
		// Drain any remaining channels to prevent memory leaks
		select {
		case <-msg.ResponseStream:
		default:
		}
		deepintshield.responseStreamPool.Put(msg.ResponseStream)
	}

	// Release of DeepIntShield Request is handled in handle methods as they are required for fallbacks

	// Clear references and return to pool
	msg.Response = nil
	msg.ResponseStream = nil
	msg.Err = nil
	deepintshield.channelMessagePool.Put(msg)
}

// resetDeepIntShieldRequest resets a DeepIntShieldRequest instance for reuse
func resetDeepIntShieldRequest(req *schemas.DeepIntShieldRequest) {
	req.RequestType = ""
	req.ListModelsRequest = nil
	req.TextCompletionRequest = nil
	req.ChatRequest = nil
	req.ResponsesRequest = nil
	req.CountTokensRequest = nil
	req.EmbeddingRequest = nil
	req.RerankRequest = nil
	req.SpeechRequest = nil
	req.TranscriptionRequest = nil
	req.ImageGenerationRequest = nil
	req.ImageEditRequest = nil
	req.ImageVariationRequest = nil
	req.VideoGenerationRequest = nil
	req.VideoRetrieveRequest = nil
	req.VideoDownloadRequest = nil
	req.VideoListRequest = nil
	req.VideoRemixRequest = nil
	req.VideoDeleteRequest = nil
	req.FileUploadRequest = nil
	req.FileListRequest = nil
	req.FileRetrieveRequest = nil
	req.FileDeleteRequest = nil
	req.FileContentRequest = nil
	req.BatchCreateRequest = nil
	req.BatchListRequest = nil
	req.BatchRetrieveRequest = nil
	req.BatchCancelRequest = nil
	req.BatchDeleteRequest = nil
	req.BatchResultsRequest = nil
	req.ContainerCreateRequest = nil
	req.ContainerListRequest = nil
	req.ContainerRetrieveRequest = nil
	req.ContainerDeleteRequest = nil
	req.ContainerFileCreateRequest = nil
	req.ContainerFileListRequest = nil
	req.ContainerFileRetrieveRequest = nil
	req.ContainerFileContentRequest = nil
	req.ContainerFileDeleteRequest = nil
	req.PassthroughRequest = nil
}

// getDeepIntShieldRequest gets a DeepIntShieldRequest from the pool
func (deepintshield *DeepIntShield) getDeepIntShieldRequest() *schemas.DeepIntShieldRequest {
	req := deepintshield.deepintshieldRequestPool.Get().(*schemas.DeepIntShieldRequest)
	return req
}

// releaseDeepIntShieldRequest returns a DeepIntShieldRequest to the pool
func (deepintshield *DeepIntShield) releaseDeepIntShieldRequest(req *schemas.DeepIntShieldRequest) {
	resetDeepIntShieldRequest(req)
	deepintshield.deepintshieldRequestPool.Put(req)
}

// resetMCPRequest resets a DeepIntShieldMCPRequest instance for reuse
func resetMCPRequest(req *schemas.DeepIntShieldMCPRequest) {
	req.RequestType = ""
	req.ChatAssistantMessageToolCall = nil
	req.ResponsesToolMessage = nil
}

// getMCPRequest gets a DeepIntShieldMCPRequest from the pool
func (deepintshield *DeepIntShield) getMCPRequest() *schemas.DeepIntShieldMCPRequest {
	req := deepintshield.mcpRequestPool.Get().(*schemas.DeepIntShieldMCPRequest)
	return req
}

// releaseMCPRequest returns a DeepIntShieldMCPRequest to the pool
func (deepintshield *DeepIntShield) releaseMCPRequest(req *schemas.DeepIntShieldMCPRequest) {
	resetMCPRequest(req)
	deepintshield.mcpRequestPool.Put(req)
}

// getAllSupportedKeys retrieves all valid keys for a ListModels request.
// allowing the provider to aggregate results from multiple keys.
func (deepintshield *DeepIntShield) getAllSupportedKeys(ctx *schemas.DeepIntShieldContext, providerKey schemas.ModelProvider, baseProviderType schemas.ModelProvider) ([]schemas.Key, error) {
	// Check if key has been set in the context explicitly
	if ctx != nil {
		key, ok := ctx.Value(schemas.DeepIntShieldContextKeyDirectKey).(schemas.Key)
		if ok {
			// If a direct key is specified, return it as a single-element slice
			return []schemas.Key{key}, nil
		}
	}

	keys, err := deepintshield.account.GetKeysForProvider(ctx, providerKey)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found for provider: %v", providerKey)
	}

	// Filter keys for ListModels - only check if key has a value
	var supportedKeys []schemas.Key
	for _, k := range keys {
		// Skip disabled keys (default enabled when nil)
		if k.Enabled != nil && !*k.Enabled {
			continue
		}
		if strings.TrimSpace(k.Value.GetValue()) != "" || CanProviderKeyValueBeEmpty(baseProviderType) {
			supportedKeys = append(supportedKeys, k)
		}
	}

	deepintshield.logger.Debug("[DeepIntShield] Provider %s: %d enabled keys found", providerKey, len(supportedKeys))

	if len(supportedKeys) == 0 {
		return nil, fmt.Errorf("no valid keys found for provider: %v", providerKey)
	}

	return supportedKeys, nil
}

// getKeysForBatchAndFileOps retrieves keys for batch and file operations with model filtering.
// For batch operations, only keys with UseForBatchAPI enabled are included.
// Model filtering: if model is specified and key has model restrictions, only include if model is in list.
func (deepintshield *DeepIntShield) getKeysForBatchAndFileOps(ctx *schemas.DeepIntShieldContext, providerKey schemas.ModelProvider, baseProviderType schemas.ModelProvider, model *string, isBatchOp bool) ([]schemas.Key, error) {
	// Check if key has been set in the context explicitly
	if ctx != nil {
		key, ok := ctx.Value(schemas.DeepIntShieldContextKeyDirectKey).(schemas.Key)
		if ok {
			// If a direct key is specified, return it as a single-element slice
			return []schemas.Key{key}, nil
		}
	}

	keys, err := deepintshield.account.GetKeysForProvider(ctx, providerKey)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found for provider: %v", providerKey)
	}

	var filteredKeys []schemas.Key
	for _, k := range keys {
		// Skip disabled keys
		if k.Enabled != nil && !*k.Enabled {
			continue
		}

		// For batch operations, only include keys with UseForBatchAPI enabled
		if isBatchOp && (k.UseForBatchAPI == nil || !*k.UseForBatchAPI) {
			continue
		}

		// Model filtering logic:
		// - If model is nil or empty → include all keys (no model filter)
		// - If model is specified:
		//   - If key.Models is empty → include key (supports all models)
		//   - If key.Models is non-empty → only include if model is in list
		if model != nil && *model != "" && len(k.Models) > 0 {
			if !keySupportsRequestedModel(k.Models, *model) {
				continue
			}
		}

		// Check key value (or if provider allows empty keys or has Azure Entra ID credentials)
		if strings.TrimSpace(k.Value.GetValue()) != "" || CanProviderKeyValueBeEmpty(baseProviderType) {
			filteredKeys = append(filteredKeys, k)
		}
	}

	if len(filteredKeys) == 0 {
		modelStr := ""
		if model != nil {
			modelStr = *model
		}
		if isBatchOp {
			return nil, fmt.Errorf("no batch-enabled keys found for provider: %v and model: %s", providerKey, modelStr)
		}
		return nil, fmt.Errorf("no keys found for provider: %v and model: %s", providerKey, modelStr)
	}

	// Sort keys by ID for deterministic pagination order across requests
	sort.Slice(filteredKeys, func(i, j int) bool {
		return filteredKeys[i].ID < filteredKeys[j].ID
	})

	return filteredKeys, nil
}

// selectKeyFromProviderForModel selects an appropriate API key for a given provider and model.
// It uses weighted random selection if multiple keys are available.
func (deepintshield *DeepIntShield) selectKeyFromProviderForModel(ctx *schemas.DeepIntShieldContext, requestType schemas.RequestType, providerKey schemas.ModelProvider, model string, baseProviderType schemas.ModelProvider) (schemas.Key, error) {
	// Check if key has been set in the context explicitly
	if ctx != nil {
		key, ok := ctx.Value(schemas.DeepIntShieldContextKeyDirectKey).(schemas.Key)
		if ok {
			return key, nil
		}
	}
	// Check if key skipping is allowed
	if skipKeySelection, ok := ctx.Value(schemas.DeepIntShieldContextKeySkipKeySelection).(bool); ok && skipKeySelection && isKeySkippingAllowed(providerKey) {
		return schemas.Key{}, nil
	}
	// Get keys for provider
	keys, err := deepintshield.account.GetKeysForProvider(ctx, providerKey)
	if err != nil {
		return schemas.Key{}, err
	}
	// Check if no keys found
	if len(keys) == 0 {
		return schemas.Key{}, fmt.Errorf("no keys found for provider: %v and model: %s", providerKey, model)
	}

	// For batch API operations, filter keys to only include those with UseForBatchAPI enabled
	if isBatchRequestType(requestType) || isFileRequestType(requestType) {
		var batchEnabledKeys []schemas.Key
		for _, k := range keys {
			if k.UseForBatchAPI != nil && *k.UseForBatchAPI {
				batchEnabledKeys = append(batchEnabledKeys, k)
			}
		}
		if len(batchEnabledKeys) == 0 {
			return schemas.Key{}, fmt.Errorf("no config found for batch APIs. Please enable 'Use for Batch APIs' on at least one key for provider: %v", providerKey)
		}
		keys = batchEnabledKeys
	}

	// filter out keys which don't support the model, if the key has no models, it is supported for all models
	var supportedKeys []schemas.Key

	// Skip model check conditions
	// We can improve these conditions in the future
	skipModelCheck := (model == "" && (isFileRequestType(requestType) || isBatchRequestType(requestType) || isContainerRequestType(requestType) || isModellessVideoRequestType(requestType) || isPassthroughRequestType(requestType))) || requestType == schemas.ListModelsRequest
	if skipModelCheck {
		// When skipping model check: just verify keys are enabled and have values
		for _, k := range keys {
			// Skip disabled keys
			if k.Enabled != nil && !*k.Enabled {
				continue
			}
			if strings.TrimSpace(k.Value.GetValue()) != "" || CanProviderKeyValueBeEmpty(baseProviderType) {
				supportedKeys = append(supportedKeys, k)
			}
		}
	} else {
		// When NOT skipping model check: do full model/deployment filtering
		for _, key := range keys {
			// Skip disabled keys
			if key.Enabled != nil && !*key.Enabled {
				continue
			}
			hasValue := strings.TrimSpace(key.Value.GetValue()) != "" || CanProviderKeyValueBeEmpty(baseProviderType)
			modelSupported := (len(key.Models) == 0 && hasValue) || (hasValue && keySupportsRequestedModel(key.Models, model))
			// Additional deployment checks for Azure, Bedrock and Vertex
			deploymentSupported := true
			if baseProviderType == schemas.Azure && key.AzureKeyConfig != nil {
				// For Azure, check if deployment exists for this model
				if len(key.AzureKeyConfig.Deployments) > 0 {
					_, deploymentSupported = key.AzureKeyConfig.Deployments[model]
				}
			} else if baseProviderType == schemas.Bedrock && key.BedrockKeyConfig != nil {
				// For Bedrock, check if deployment exists for this model
				if len(key.BedrockKeyConfig.Deployments) > 0 {
					_, deploymentSupported = key.BedrockKeyConfig.Deployments[model]
				}
			} else if baseProviderType == schemas.Vertex && key.VertexKeyConfig != nil {
				// For Vertex, check if deployment exists for this model
				if len(key.VertexKeyConfig.Deployments) > 0 {
					_, deploymentSupported = key.VertexKeyConfig.Deployments[model]
				}
			} else if baseProviderType == schemas.Replicate && key.ReplicateKeyConfig != nil {
				// For Replicate, check if deployment exists for this model
				if len(key.ReplicateKeyConfig.Deployments) > 0 {
					_, deploymentSupported = key.ReplicateKeyConfig.Deployments[model]
				}
			} else if baseProviderType == schemas.VLLM && key.VLLMKeyConfig != nil {
				// For VLLM, check if model name matches the key's configured model
				if key.VLLMKeyConfig.ModelName != "" {
					deploymentSupported = (key.VLLMKeyConfig.ModelName == model)
				}
			}

			if modelSupported && deploymentSupported {
				supportedKeys = append(supportedKeys, key)
			}
		}
	}
	if len(supportedKeys) == 0 {
		if baseProviderType == schemas.Azure || baseProviderType == schemas.Bedrock || baseProviderType == schemas.Vertex || baseProviderType == schemas.Replicate || baseProviderType == schemas.VLLM {
			return schemas.Key{}, fmt.Errorf("no keys found that support model/deployment: %s", model)
		}
		return schemas.Key{}, fmt.Errorf("no keys found that support model: %s", model)
	}

	// Circuit breaker: filter out keys with open circuits (only when tracker is active).
	// We keep at least one key available - if all keys are circuit-broken, we let them through
	// to allow recovery. Explicit key pins (below) bypass this filter.
	if deepintshield.keyLoadTracker != nil && len(supportedKeys) > 1 {
		var healthyKeys []schemas.Key
		for _, key := range supportedKeys {
			if !deepintshield.keyLoadTracker.IsCircuitOpen(key.ID) {
				healthyKeys = append(healthyKeys, key)
			}
		}
		if len(healthyKeys) > 0 {
			supportedKeys = healthyKeys
		}
		// If all keys are circuit-broken, keep all of them (allow recovery probes)
	}

	// Key ID takes priority over key name when both are present
	if ctx != nil {
		if keyID, ok := ctx.Value(schemas.DeepIntShieldContextKeyAPIKeyID).(string); ok {
			if keyID = strings.TrimSpace(keyID); keyID != "" {
				for _, key := range supportedKeys {
					if key.ID == keyID {
						return key, nil
					}
				}
				return schemas.Key{}, fmt.Errorf("no supported key found with id %q for provider: %v and model: %s", keyID, providerKey, model)
			}
		}
		if keyName, ok := ctx.Value(schemas.DeepIntShieldContextKeyAPIKeyName).(string); ok {
			if keyName = strings.TrimSpace(keyName); keyName != "" {
				for _, key := range supportedKeys {
					if key.Name == keyName {
						return key, nil
					}
				}
				return schemas.Key{}, fmt.Errorf("no supported key found with name %q for provider: %v and model: %s", keyName, providerKey, model)
			}
		}
	}

	if len(supportedKeys) == 1 {
		return supportedKeys[0], nil
	}

	// Session stickiness: on the first request for a session ID, the randomly
	// selected key is persisted in the KV store. Subsequent requests reuse it as
	// long as the key remains valid. The sticky-key lookup/selection in this block
	// occurs before executeRequestWithRetries, so the same sticky key is
	// intentionally applied for the entire session including all retry attempts-
	// the selected key is persisted in KV and reused across retries rather than
	// re-selected on each attempt.
	sessionID := ""
	if ctx != nil {
		if id, ok := ctx.Value(schemas.DeepIntShieldContextKeySessionID).(string); ok && id != "" {
			sessionID = id
		}
	}

	fallbackIndex := 0
	if ctx != nil {
		fallbackIndex, _ = ctx.Value(schemas.DeepIntShieldContextKeyFallbackIndex).(int)
	}
	stickinessActive := sessionID != "" && deepintshield.kvStore != nil && fallbackIndex == 0

	if stickinessActive {
		kvKey := buildSessionKey(providerKey, sessionID, model)
		ttl, _ := ctx.Value(schemas.DeepIntShieldContextKeySessionTTL).(time.Duration)
		if ttl <= 0 {
			ttl = schemas.DefaultSessionStickyTTL
		}

		// Try to retrieve existing cached key
		if cachedKey, found, stale := getCachedKeyFromStore(deepintshield.kvStore, kvKey, supportedKeys); found {
			// Refresh TTL so active sessions do not expire.
			err := deepintshield.kvStore.SetWithTTL(kvKey, cachedKey.ID, ttl)
			if err != nil {
				deepintshield.logger.Warn("error setting session cache for provider=%s key_id=%s: %s", providerKey, cachedKey.ID, err.Error())
			}
			return cachedKey, nil
		} else if stale {
			if _, err := deepintshield.kvStore.Delete(kvKey); err != nil {
				deepintshield.logger.Warn("error deleting stale session cache for provider=%s: %s", providerKey, err.Error())
			}
		}

		// No cached key found (or stale entry deleted), select a new one
		selectedKey, err := deepintshield.keySelector(ctx, supportedKeys, providerKey, model)
		if err != nil {
			return schemas.Key{}, err
		}

		// Atomically set the key only if not already set (first-write-wins)
		wasSet, err := deepintshield.kvStore.SetNXWithTTL(kvKey, selectedKey.ID, ttl)
		if err != nil {
			deepintshield.logger.Warn("error setting session cache for provider=%s key_id=%s: %s", providerKey, selectedKey.ID, err.Error())
			return selectedKey, nil
		}

		if wasSet {
			return selectedKey, nil
		}

		// Another concurrent request won the race, re-read the current key
		if currentKey, found, stale := getCachedKeyFromStore(deepintshield.kvStore, kvKey, supportedKeys); found {
			return currentKey, nil
		} else if stale {
			if _, err := deepintshield.kvStore.Delete(kvKey); err != nil {
				deepintshield.logger.Warn("error deleting stale session cache for provider=%s: %s", providerKey, err.Error())
			}
			return selectedKey, nil
		}

		// Fallback: if we can't read the current key, use what we selected
		// (shouldn't happen in normal operation, but defensive)
		return selectedKey, nil
	}

	selectedKey, err := deepintshield.keySelector(ctx, supportedKeys, providerKey, model)
	if err != nil {
		return schemas.Key{}, err
	}

	return selectedKey, nil
}

// getCachedKeyFromStore retrieves a key ID from the KV store and looks it up in supportedKeys.
// Returns the matching Key, found (true if key exists in supportedKeys), and stale (true if
// KV contains an ID but it is not in supportedKeys-caller should delete before SetNXWithTTL).
func getCachedKeyFromStore(kvStore schemas.KVStore, kvKey string, supportedKeys []schemas.Key) (schemas.Key, bool, bool) {
	raw, err := kvStore.Get(kvKey)
	if err != nil {
		return schemas.Key{}, false, false
	}

	var cachedKeyID string
	switch v := raw.(type) {
	case string:
		cachedKeyID = v
	case []byte:
		var s string
		if err := sonic.Unmarshal(v, &s); err == nil {
			cachedKeyID = s
		} else {
			cachedKeyID = string(v)
		}
	}

	if cachedKeyID != "" {
		for _, k := range supportedKeys {
			if k.ID == cachedKeyID {
				return k, true, false
			}
		}
		return schemas.Key{}, false, true
	}

	return schemas.Key{}, false, false
}

func WeightedRandomKeySelector(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, providerKey schemas.ModelProvider, model string) (schemas.Key, error) {
	// Use a weighted random selection based on key weights
	totalWeight := 0
	for _, key := range keys {
		totalWeight += int(key.Weight * 100) // Convert float to int for better performance
	}

	// If all keys have zero weight, fall back to uniform random selection
	if totalWeight == 0 {
		return keys[rand.Intn(len(keys))], nil
	}

	// Use global thread-safe random (Go 1.20+) - no allocation, no syscall
	randomValue := rand.Intn(totalWeight)

	// Select key based on weight
	currentWeight := 0
	for _, key := range keys {
		currentWeight += int(key.Weight * 100)
		if randomValue < currentWeight {
			return key, nil
		}
	}

	// Fallback to first key if something goes wrong
	return keys[0], nil
}

// Shutdown gracefully stops all workers when triggered.
// It closes all request channels and waits for workers to exit.
func (deepintshield *DeepIntShield) Shutdown() {
	deepintshield.logger.Info("closing all request channels...")
	// Cancel the context if not already done
	if deepintshield.ctx.Err() == nil && deepintshield.cancel != nil {
		deepintshield.cancel()
	}
	// ALWAYS close all provider queues to signal workers to stop,
	// even if context was already cancelled. This prevents goroutine leaks.
	// Use the ProviderQueue lifecycle: signal closing, then close the queue
	deepintshield.requestQueues.Range(func(key, value interface{}) bool {
		pq := value.(*ProviderQueue)
		// Signal closing to producers (uses sync.Once internally)
		pq.signalClosing()
		// Close the queue to signal workers (uses sync.Once internally)
		pq.closeQueue()
		return true
	})

	// Wait for all workers to exit
	deepintshield.waitGroups.Range(func(key, value interface{}) bool {
		waitGroup := value.(*sync.WaitGroup)
		waitGroup.Wait()
		return true
	})

	// Cleanup MCP manager
	if deepintshield.MCPManager != nil {
		err := deepintshield.MCPManager.Cleanup()
		if err != nil {
			deepintshield.logger.Warn("Error cleaning up MCP manager: %s", err.Error())
		}
	}

	// Stop the tracerWrapper to clean up background goroutines
	if tracerWrapper := deepintshield.tracer.Load().(*tracerWrapper); tracerWrapper != nil && tracerWrapper.tracer != nil {
		tracerWrapper.tracer.Stop()
	}

	// Cleanup plugins
	if llmPlugins := deepintshield.llmPlugins.Load(); llmPlugins != nil {
		for _, plugin := range *llmPlugins {
			err := plugin.Cleanup()
			if err != nil {
				deepintshield.logger.Warn(fmt.Sprintf("Error cleaning up LLM plugin: %s", err.Error()))
			}
		}
	}
	if mcpPlugins := deepintshield.mcpPlugins.Load(); mcpPlugins != nil {
		for _, plugin := range *mcpPlugins {
			err := plugin.Cleanup()
			if err != nil {
				deepintshield.logger.Warn(fmt.Sprintf("Error cleaning up MCP plugin: %s", err.Error()))
			}
		}
	}
	deepintshield.logger.Info("all request channels closed")
}
