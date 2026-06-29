// Package logging provides a GORM-based logging plugin for DeepIntShield.
// This plugin stores comprehensive logs of all requests and responses with search,
// filter, and pagination capabilities.
package logging

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/mcp"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/mcpcatalog"
	"github.com/deepint-shield/ai-security/framework/modelcatalog"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/deepint-shield/ai-security/framework/streaming"
)

const (
	PluginName = "logging"
)

// mcpLogStartTimeCtxKey is stamped on the context during PreMCPHook so PostMCPHook
// can compute the wall-time latency breakdown (total_wall, mcp_tool_call,
// platform_overhead) for the MCP log's metadata.
const mcpLogStartTimeCtxKey schemas.DeepIntShieldContextKey = "_dis_mcp_log_start_time"

// LogOperation represents the type of logging operation
type LogOperation string

const (
	LogOperationCreate       LogOperation = "create"
	LogOperationUpdate       LogOperation = "update"
	LogOperationStreamUpdate LogOperation = "stream_update"
)

// UpdateLogData contains data for log entry updates
type UpdateLogData struct {
	Status                 string
	TokenUsage             *schemas.DeepIntShieldLLMUsage
	Cost                   *float64        // Cost in dollars from pricing plugin
	CacheSavings           *float64        // Cost avoided by serving the response from cache
	ListModelsOutput       []schemas.Model // For list models requests
	ChatOutput             *schemas.ChatMessage
	ResponsesOutput        []schemas.ResponsesMessage
	EmbeddingOutput        []schemas.EmbeddingData
	RerankOutput           []schemas.RerankResult
	ErrorDetails           *schemas.DeepIntShieldError
	SpeechOutput           *schemas.DeepIntShieldSpeechResponse          // For non-streaming speech responses
	TranscriptionOutput    *schemas.DeepIntShieldTranscriptionResponse   // For non-streaming transcription responses
	ImageGenerationOutput  *schemas.DeepIntShieldImageGenerationResponse // For non-streaming image generation responses
	VideoGenerationOutput  *schemas.DeepIntShieldVideoGenerationResponse // For non-streaming video generation responses
	VideoRetrieveOutput    *schemas.DeepIntShieldVideoGenerationResponse // For non-streaming video retrieve responses
	VideoDownloadOutput    *schemas.DeepIntShieldVideoDownloadResponse   // For non-streaming video download responses
	VideoListOutput        *schemas.DeepIntShieldVideoListResponse       // For non-streaming video list responses
	VideoDeleteOutput      *schemas.DeepIntShieldVideoDeleteResponse     // For non-streaming video delete responses
	RawRequest             interface{}
	RawResponse            interface{}
	IsLargePayloadRequest  bool // When true, RawRequest is a truncated preview string (skip sonic.Marshal)
	IsLargePayloadResponse bool // When true, RawResponse is a truncated preview string (skip sonic.Marshal)
}

// applyLargePayloadPreviews reads large payload/response preview strings from context
// and overrides RawRequest/RawResponse on updateData for truncated logging.
func applyLargePayloadPreviews(ctx *schemas.DeepIntShieldContext, updateData *UpdateLogData) {
	if isLargePayload, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool); ok && isLargePayload {
		if preview, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadRequestPreview).(string); ok && preview != "" {
			updateData.RawRequest = preview
			updateData.IsLargePayloadRequest = true
		}
	}
	if isLargeResponse, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); ok && isLargeResponse {
		if preview, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadResponsePreview).(string); ok && preview != "" {
			updateData.RawResponse = preview
			updateData.IsLargePayloadResponse = true
		}
	}
}

func applyLargePayloadPreviewsToEntry(ctx *schemas.DeepIntShieldContext, entry *logstore.Log) {
	if ctx == nil || entry == nil {
		return
	}

	updateData := &UpdateLogData{}
	applyLargePayloadPreviews(ctx, updateData)

	if updateData.IsLargePayloadRequest {
		entry.IsLargePayloadRequest = true
		if preview, ok := updateData.RawRequest.(string); ok {
			entry.RawRequest = preview
		}
	}
	if updateData.IsLargePayloadResponse {
		entry.IsLargePayloadResponse = true
		if preview, ok := updateData.RawResponse.(string); ok {
			entry.RawResponse = preview
		}
	}
}

func providerLatencyForMetadata(result *schemas.DeepIntShieldResponse) int64 {
	if result == nil {
		return 0
	}
	extraFields := result.GetExtraFields()
	if extraFields.CacheDebug != nil && extraFields.CacheDebug.CacheHit {
		return 0
	}
	if extraFields.Latency <= 0 {
		return 0
	}
	return extraFields.Latency
}

func applyLatencyBreakdownMetadata(entry *logstore.Log, ctx context.Context, result *schemas.DeepIntShieldResponse) {
	if entry == nil || ctx == nil {
		return
	}

	phaseBreakdown := schemas.GetLatencyBreakdownMilliseconds(ctx)
	totalWallMs := schemas.RequestWallLatencyMilliseconds(ctx)
	providerLatencyMs := providerLatencyForMetadata(result)
	if len(phaseBreakdown) == 0 && totalWallMs <= 0 && providerLatencyMs <= 0 {
		return
	}

	if entry.MetadataParsed == nil {
		entry.MetadataParsed = make(map[string]interface{})
	}

	breakdown := make(map[string]interface{}, len(phaseBreakdown)+3)
	// Sum tracked non-provider phases so platform_overhead represents the
	// residual (request unmarshal, response marshal, fasthttp framework,
	// provider client construction, etc.) instead of double-counting
	// plugin_chain_pre / cache_lookup_direct / guardrail_* - which already
	// appear as their own tiles. Dashboard arithmetic now adds up cleanly:
	//   total_wall = provider + sum(tracked) + platform_overhead.
	var trackedNonProviderMs int64
	for phase, durationMs := range phaseBreakdown {
		breakdown[phase] = durationMs
		if phase != string(schemas.LatencyPhaseProvider) {
			trackedNonProviderMs += durationMs
		}
	}
	if totalWallMs > 0 {
		breakdown["total_wall"] = totalWallMs
		platformOverheadMs := totalWallMs - providerLatencyMs - trackedNonProviderMs
		if platformOverheadMs < 0 {
			platformOverheadMs = 0
		}
		breakdown["platform_overhead"] = platformOverheadMs
	}
	if providerLatencyMs > 0 {
		breakdown["provider"] = providerLatencyMs
	} else if result != nil {
		extraFields := result.GetExtraFields()
		if extraFields.CacheDebug != nil && extraFields.CacheDebug.CacheHit {
			breakdown["provider"] = int64(0)
		}
	}

	entry.MetadataParsed["latency_breakdown_ms"] = breakdown
}

func (p *LoggerPlugin) enqueueLogEntryWithTiming(phaseCtx context.Context, asyncCtx context.Context, entry *logstore.Log, callback func(entry *logstore.Log)) {
	stop := schemas.TrackLatencyPhase(phaseCtx, schemas.LatencyPhaseLoggingEnqueue)
	p.enqueueLogEntry(asyncCtx, entry, callback)
	stop()
}

func (p *LoggerPlugin) scheduleDeferredUsageUpdate(ctx *schemas.DeepIntShieldContext, requestID string, usageAlreadyPresent bool) {
	if usageAlreadyPresent || ctx == nil {
		return
	}
	updateCtx := asyncLoggingContext(ctx)

	deferredChan, ok := ctx.Value(schemas.DeepIntShieldContextKeyDeferredUsage).(<-chan *schemas.DeepIntShieldLLMUsage)
	if !ok || deferredChan == nil {
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer safegoroutine.Recover(p.logger, "logging.deferred-usage-update")
		// Large-response phase B closes this channel after trailing usage extraction completes.
		deferredUsage, chanOpen := <-deferredChan
		if !chanOpen || deferredUsage == nil {
			return
		}

		// Acquire semaphore - drop if all slots busy to prevent unbounded goroutines
		// from exhausting DB connections when Postgres is slow
		select {
		case p.deferredUsageSem <- struct{}{}:
			defer func() { <-p.deferredUsageSem }()
		default:
			p.logger.Warn("deferred usage update dropped for request %s: semaphore full", requestID)
			return
		}

		usageUpdates := map[string]interface{}{
			"prompt_tokens":     deferredUsage.PromptTokens,
			"completion_tokens": deferredUsage.CompletionTokens,
			"total_tokens":      deferredUsage.TotalTokens,
		}
		tempEntry := &logstore.Log{TokenUsageParsed: deferredUsage}
		if serErr := tempEntry.SerializeFields(); serErr == nil {
			usageUpdates["token_usage"] = tempEntry.TokenUsage
		}
		if updErr := p.store.Update(updateCtx, requestID, usageUpdates); updErr != nil {
			p.logger.Warn("failed to update deferred usage for request %s: %v", requestID, updErr)
		}
	}()
}

// RecalculateCostResult represents summary stats from a cost backfill operation
type RecalculateCostResult struct {
	TotalMatched int64 `json:"total_matched"`
	Updated      int   `json:"updated"`
	Skipped      int   `json:"skipped"`
	Remaining    int64 `json:"remaining"`
}

// LogMessage represents a message in the logging queue
type LogMessage struct {
	Operation          LogOperation
	RequestID          string                             // Unique ID for the request
	ParentRequestID    string                             // Unique ID for the parent request (used for fallback requests)
	NumberOfRetries    int                                // Number of retries
	FallbackIndex      int                                // Fallback index
	SelectedKeyID      string                             // Selected key ID
	SelectedKeyName    string                             // Selected key name
	VirtualKeyID       string                             // Virtual key ID
	VirtualKeyName     string                             // Virtual key name
	RoutingEnginesUsed []string                           // List of routing engines used
	RoutingRuleID      string                             // Routing rule ID
	RoutingRuleName    string                             // Routing rule name
	Timestamp          time.Time                          // Of the preHook/postHook call
	Latency            int64                              // For latency updates
	InitialData        *InitialLogData                    // For create operations
	SemanticCacheDebug *schemas.DeepIntShieldCacheDebug   // For semantic cache operations
	UpdateData         *UpdateLogData                     // For update operations
	StreamResponse     *streaming.ProcessedStreamResponse // For streaming delta updates
	RoutingEngineLogs  string                             // Formatted routing engine decision logs
}

// InitialLogData contains data for initial log entry creation
type InitialLogData struct {
	Status                 string
	Provider               string
	Model                  string
	Object                 string
	InputHistory           []schemas.ChatMessage
	ResponsesInputHistory  []schemas.ResponsesMessage
	Params                 interface{}
	SpeechInput            *schemas.SpeechInput
	TranscriptionInput     *schemas.TranscriptionInput
	ImageGenerationInput   *schemas.ImageGenerationInput
	VideoGenerationInput   *schemas.VideoGenerationInput
	Tools                  []schemas.ChatTool
	RoutingEngineUsed      []string
	Metadata               map[string]interface{}
	PassthroughRequestBody string // Raw body for passthrough requests (UTF-8)
}

// LogCallback is a function that gets called when a new log entry is created
type LogCallback func(ctx context.Context, logEntry *logstore.Log)

// MCPToolLogCallback is a function that gets called when a new MCP tool log entry is created or updated.
// The context carries tenant and actor information needed by downstream consumers.
type MCPToolLogCallback func(ctx context.Context, entry *logstore.MCPToolLog)

type Config struct {
	DisableContentLogging *bool     `json:"disable_content_logging"`
	LoggingHeaders        *[]string `json:"logging_headers"` // Pointer to live config slice; changes are reflected immediately without restart
}

// LoggerPlugin implements the schemas.LLMPlugin and schemas.MCPPlugin interfaces
type LoggerPlugin struct {
	ctx                   context.Context
	store                 logstore.LogStore
	disableContentLogging *bool
	loggingHeaders        *[]string // Pointer to live config slice for headers to capture in metadata
	pricingManager        *modelcatalog.ModelCatalog
	mcpCatalog            *mcpcatalog.MCPCatalog // MCP catalog for tool cost calculation
	mu                    sync.Mutex
	done                  chan struct{}
	cleanupOnce           sync.Once // Ensures cleanup only runs once
	wg                    sync.WaitGroup
	logger                schemas.Logger
	logCallback           LogCallback
	mcpToolLogCallback    MCPToolLogCallback // Callback for MCP tool log entries
	droppedRequests       atomic.Int64
	cleanupTicker         *time.Ticker          // Ticker for cleaning up old processing logs
	logMsgPool            sync.Pool             // Pool for reusing LogMessage structs
	updateDataPool        sync.Pool             // Pool for reusing UpdateLogData structs
	pendingLogs           sync.Map              // Maps requestID -> *PendingLogData (PreLLMHook input data awaiting PostLLMHook)
	writeQueue            chan *writeQueueEntry // Buffered channel for batch write queue
	closed                atomic.Bool           // Set during cleanup to prevent sends on closed writeQueue
	deferredUsageSem      chan struct{}         // Limits concurrent deferred usage DB updates
}

// Init creates new logger plugin with given log store
func Init(ctx context.Context, config *Config, logger schemas.Logger, logsStore logstore.LogStore, pricingManager *modelcatalog.ModelCatalog, mcpCatalog *mcpcatalog.MCPCatalog) (*LoggerPlugin, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if logsStore == nil {
		return nil, fmt.Errorf("logs store cannot be nil")
	}
	if pricingManager == nil {
		logger.Warn("logging plugin requires model catalog to calculate cost, all LLM cost calculations will be skipped.")
	}
	if mcpCatalog == nil {
		logger.Warn("logging plugin requires MCP catalog to calculate cost, all MCP cost calculations will be skipped.")
	}

	// Bridge the store into the global registry so async workers in other
	// plugins (specifically the hallucination eval worker pool) can patch
	// log rows with late-arriving scores via logstore.GetGlobalLogStore().
	logstore.SetGlobalLogStore(logsStore)

	plugin := &LoggerPlugin{
		ctx:                   ctx,
		store:                 logsStore,
		pricingManager:        pricingManager,
		mcpCatalog:            mcpCatalog,
		disableContentLogging: config.DisableContentLogging,
		loggingHeaders:        config.LoggingHeaders,
		done:                  make(chan struct{}),
		logger:                logger,
		writeQueue:            make(chan *writeQueueEntry, writeQueueCapacity),
		deferredUsageSem:      make(chan struct{}, maxDeferredUsageConcurrency),
		logMsgPool: sync.Pool{
			New: func() interface{} {
				return &LogMessage{}
			},
		},
		updateDataPool: sync.Pool{
			New: func() interface{} {
				return &UpdateLogData{}
			},
		},
	}

	// Prewarm the pools for better performance at startup
	for range 1000 {
		plugin.logMsgPool.Put(&LogMessage{})
		plugin.updateDataPool.Put(&UpdateLogData{})
	}

	// Start cleanup ticker (runs every 1 minute)
	plugin.cleanupTicker = time.NewTicker(1 * time.Minute)
	plugin.wg.Add(1)
	go plugin.cleanupWorker()

	// Start the batch writer goroutine (single writer for all DB writes)
	plugin.wg.Add(1)
	go plugin.batchWriter()

	return plugin, nil
}

// cleanupWorker periodically removes old processing logs
func (p *LoggerPlugin) cleanupWorker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.cleanupTicker.C:
			p.cleanupOldProcessingLogs()
		case <-p.done:
			return
		}
	}
}

// cleanupOldProcessingLogs removes processing logs older than 30 minutes
// and stale pending log entries from the in-memory map
func (p *LoggerPlugin) cleanupOldProcessingLogs() {
	// Calculate timestamp for 30 minutes ago in UTC to match log entry timestamps
	thirtyMinutesAgo := time.Now().UTC().Add(-1 * 30 * time.Minute)

	// Delete LLM processing logs older than 30 minutes
	if err := p.store.Flush(p.ctx, thirtyMinutesAgo); err != nil {
		p.logger.Warn("failed to cleanup old processing LLM logs: %v", err)
	}

	// Delete MCP tool processing logs older than 30 minutes
	if err := p.store.FlushMCPToolLogs(p.ctx, thirtyMinutesAgo); err != nil {
		p.logger.Warn("failed to cleanup old processing MCP tool logs: %v", err)
	}

	// Clean up stale pending log entries (requests where PostLLMHook never fired)
	p.cleanupStalePendingLogs()
}

// SetLogCallback sets a callback function that will be called for each log entry
func (p *LoggerPlugin) SetLogCallback(callback LogCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logCallback = callback
}

// GetName returns the name of the plugin
func (p *LoggerPlugin) GetName() string {
	return PluginName
}

// HTTPTransportPreHook is not used for this plugin
func (p *LoggerPlugin) HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPostHook is not used for this plugin
func (p *LoggerPlugin) HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	return nil
}

// HTTPTransportStreamChunkHook passes through streaming chunks unchanged
func (p *LoggerPlugin) HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, chunk *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	return chunk, nil
}

// contentLoggingDisabled is the workspace-aware replacement for the inline
// `p.disableContentLogging == nil || !*p.disableContentLogging` check used
// across PreLLMHook / PostLLMHook / operations.go. Resolution order:
//
//  1. Workspace override (in-memory atomic snapshot - lock-free read)
//  2. Plugin-level default (the tenant-global flag from CoreConfig)
//
// Returns true when content should NOT be logged. Accepts the broader
// context.Context so the same helper works for the LLM-hook paths (which
// hold *schemas.DeepIntShieldContext) and the async post-eval / streaming
// paths that detach to a plain context.
//
// Performance contract: zero DB RTT on the hot path. The cache fills on
// first request per workspace via a single coalesced load; every subsequent
// call is an atomic.Pointer load + map lookup (~20ns). Scales linearly with
// active workspaces, not active requests.
func (p *LoggerPlugin) contentLoggingDisabled(ctx context.Context) bool {
	if wsID := workspaceIDFromContext(ctx); wsID != "" {
		if override, fresh := configstore.LookupWorkspaceLoggingSettings(wsID); fresh && override != nil {
			return override.DisableContentLogging
		}
		// Cache miss → refresh asynchronously so the next request lands on
		// a warm entry. We deliberately DO NOT block here - paying a DB
		// round-trip on the first request after a process restart would
		// undo the zero-latency promise. The plugin default applies until
		// the snapshot fills (≤1 RTT later).
		if p.ctx != nil {
			go func(workspaceID string) {
				defer safegoroutine.Recover(p.logger, "logging.workspace-override-warm")
				_, _ = configstore.ResolveWorkspaceLoggingSettings(p.ctx, workspaceID)
			}(wsID)
		}
	}
	return p.disableContentLogging != nil && *p.disableContentLogging
}

// loggingHeadersForContext returns the active headers-to-capture list,
// preferring a workspace override when one is cached. Falls back to the
// plugin-wide pointer when no override applies. The returned slice is
// read-only - callers must NOT mutate it (the snapshot's slice is shared
// with other in-flight requests).
func (p *LoggerPlugin) loggingHeadersForContext(ctx context.Context) []string {
	if wsID := workspaceIDFromContext(ctx); wsID != "" {
		if override, fresh := configstore.LookupWorkspaceLoggingSettings(wsID); fresh && override != nil {
			return override.LoggingHeaders
		}
	}
	if p.loggingHeaders == nil {
		return nil
	}
	return *p.loggingHeaders
}

// captureLoggingHeaders extracts configured logging headers and x-bf-lh-* prefixed headers
// from the request context. Returns a new metadata map, or nil if no headers were captured.
// System entries (e.g. isAsyncRequest) should be set AFTER calling this so they take precedence.
func (p *LoggerPlugin) captureLoggingHeaders(ctx *schemas.DeepIntShieldContext) map[string]interface{} {
	allHeaders, _ := ctx.Value(schemas.DeepIntShieldContextKeyRequestHeaders).(map[string]string)
	if allHeaders == nil {
		return nil
	}

	var metadata map[string]interface{}

	// Check configured logging headers - workspace-scoped override wins
	// when present, otherwise the plugin's tenant-global list applies.
	for _, h := range p.loggingHeadersForContext(ctx) {
		key := strings.ToLower(h)
		if val, ok := allHeaders[key]; ok {
			if metadata == nil {
				metadata = make(map[string]interface{})
			}
			metadata[key] = val
		}
	}

	// Check x-bf-lh-* prefixed headers
	for key, val := range allHeaders {
		if labelName, ok := strings.CutPrefix(key, "x-bf-lh-"); ok && labelName != "" {
			if metadata == nil {
				metadata = make(map[string]interface{})
			}
			metadata[labelName] = val
		}
	}

	return metadata
}

// PreLLMHook is called before a request is processed - FULLY ASYNC, NO DATABASE I/O
// Parameters:
//   - ctx: The DeepIntShield context
//   - req: The DeepIntShield request
//
// Returns:
//   - *schemas.DeepIntShieldRequest: The processed request
//   - *schemas.LLMPluginShortCircuit: The plugin short circuit if the request is not allowed
//   - error: Any error that occurred during processing
func (p *LoggerPlugin) PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	if ctx == nil {
		// Log error but don't fail the request
		p.logger.Error("context is nil in PreLLMHook")
		return req, nil, nil
	}

	// Extract request ID from context
	requestID, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string)
	if !ok || requestID == "" {
		// Log error but don't fail the request
		p.logger.Error("request-id not found in context or is empty")
		return req, nil, nil
	}

	createdTimestamp := time.Now().UTC()

	// If request type is streaming we create a stream accumulator via the tracer
	// Skip for passthrough streams - they carry raw bytes, not LLM response chunks
	if deepintshield.IsStreamRequestType(req.RequestType) && req.RequestType != schemas.PassthroughStreamRequest {
		tracer, traceID, err := deepintshield.GetTracerFromContext(ctx)
		if err == nil && tracer != nil && traceID != "" {
			tracer.CreateStreamAccumulator(traceID, createdTimestamp)
		}
	}

	provider, model, _ := req.GetRequestFields()

	initialData := &InitialLogData{
		Provider: string(provider),
		Model:    model,
		Object:   string(req.RequestType),
	}

	if !p.contentLoggingDisabled(ctx) {
		inputHistory, responsesInputHistory := p.extractInputHistory(req)
		initialData.InputHistory = inputHistory
		initialData.ResponsesInputHistory = responsesInputHistory

		switch req.RequestType {
		case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
			initialData.Params = req.TextCompletionRequest.Params
		case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
			initialData.Params = req.ChatRequest.Params
			initialData.Tools = req.ChatRequest.Params.Tools
		case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
			initialData.Params = req.ResponsesRequest.Params

			var tools []schemas.ChatTool
			for _, tool := range req.ResponsesRequest.Params.Tools {
				tools = append(tools, *tool.ToChatTool())
			}
			initialData.Tools = tools
		case schemas.EmbeddingRequest:
			initialData.Params = req.EmbeddingRequest.Params
		case schemas.RerankRequest:
			initialData.Params = req.RerankRequest.Params
		case schemas.SpeechRequest, schemas.SpeechStreamRequest:
			initialData.Params = req.SpeechRequest.Params
			initialData.SpeechInput = req.SpeechRequest.Input
		case schemas.TranscriptionRequest, schemas.TranscriptionStreamRequest:
			initialData.Params = req.TranscriptionRequest.Params
			input := req.TranscriptionRequest.Input
			if input != nil {
				reqThreshold, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadRequestThreshold).(int64)
				if reqThreshold > 0 && int64(len(input.File)) > reqThreshold {
					// Strip binary file content when it exceeds the large payload threshold
					// to avoid serializing multi-MB audio into the log database.
					logInput := *input
					logInput.File = nil
					initialData.TranscriptionInput = &logInput
				} else {
					initialData.TranscriptionInput = input
				}
			}
		case schemas.ImageGenerationRequest, schemas.ImageGenerationStreamRequest:
			initialData.Params = req.ImageGenerationRequest.Params
			initialData.ImageGenerationInput = req.ImageGenerationRequest.Input
		case schemas.VideoGenerationRequest:
			initialData.Params = req.VideoGenerationRequest.Params
			initialData.VideoGenerationInput = req.VideoGenerationRequest.Input
		case schemas.VideoRemixRequest:
			initialData.Params = &schemas.VideoLogParams{
				VideoID: req.VideoRemixRequest.ID,
			}
			initialData.VideoGenerationInput = req.VideoRemixRequest.Input
		case schemas.VideoRetrieveRequest:
			initialData.Params = &schemas.VideoLogParams{
				VideoID: req.VideoRetrieveRequest.ID,
			}
		case schemas.VideoDownloadRequest:
			initialData.Params = &schemas.VideoLogParams{
				VideoID: req.VideoDownloadRequest.ID,
			}
		case schemas.VideoDeleteRequest:
			initialData.Params = &schemas.VideoLogParams{
				VideoID: req.VideoDeleteRequest.ID,
			}
		case schemas.PassthroughRequest, schemas.PassthroughStreamRequest:
			initialData.Params = &schemas.PassthroughLogParams{
				Method:   req.PassthroughRequest.Method,
				Path:     req.PassthroughRequest.Path,
				RawQuery: req.PassthroughRequest.RawQuery,
			}
			if len(req.PassthroughRequest.Body) > 0 {
				ct := strings.ToLower(req.PassthroughRequest.SafeHeaders["content-type"])
				if strings.Contains(ct, "application/json") {
					initialData.PassthroughRequestBody = string(req.PassthroughRequest.Body)
				}
			}
		}
	}

	// Capture configured logging headers and x-bf-lh-* headers into metadata first
	initialData.Metadata = p.captureLoggingHeaders(ctx)

	// System entries are set after so they take precedence over dynamic header values
	if isAsync, ok := ctx.Value(schemas.DeepIntShieldIsAsyncRequest).(bool); ok && isAsync {
		if initialData.Metadata == nil {
			initialData.Metadata = make(map[string]interface{})
		}
		initialData.Metadata["isAsyncRequest"] = true
	}

	// Queue the log creation message (non-blocking) - Using sync.Pool
	logMsg := p.getLogMessage()
	logMsg.Operation = LogOperationCreate

	// If fallback request ID is present, use it instead of the primary request ID
	// Determine effective request ID (fallback override)
	effectiveRequestID := requestID
	var parentRequestID string
	fallbackRequestID, ok := ctx.Value(schemas.DeepIntShieldContextKeyFallbackRequestID).(string)
	if ok && fallbackRequestID != "" {
		effectiveRequestID = fallbackRequestID
		parentRequestID = requestID
	}

	fallbackIndex := deepintshield.GetIntFromContext(ctx, schemas.DeepIntShieldContextKeyFallbackIndex)
	asyncCtx := asyncLoggingContext(ctx)
	// Get routing engines array
	routingEngines := []string{}
	if engines, ok := ctx.Value(schemas.DeepIntShieldContextKeyRoutingEnginesUsed).([]string); ok {
		routingEngines = engines
	}

	initialData.RoutingEngineUsed = routingEngines
	initialData.Status = "processing"

	// Store input data in pendingLogs for later combination with PostLLMHook output.
	// No DB write here - the write is deferred to PostLLMHook to halve total writes.
	pending := &PendingLogData{
		RequestID:          effectiveRequestID,
		ParentRequestID:    parentRequestID,
		TenantID:           tenantIDFromContext(asyncCtx),
		Timestamp:          createdTimestamp,
		FallbackIndex:      fallbackIndex,
		RoutingEnginesUsed: routingEngines,
		InitialData:        initialData,
		CreatedAt:          time.Now(),
		Status:             "processing",
	}
	p.pendingLogs.Store(effectiveRequestID, pending)
	// Call callback synchronously for immediate UI feedback (WebSocket "processing" notification).
	// The entry does not exist in the DB yet - it will be written when PostLLMHook fires.
	p.mu.Lock()
	callback := p.logCallback
	p.mu.Unlock()
	if callback != nil {
		callback(asyncCtx, buildInitialLogEntry(pending))
	}
	return req, nil, nil
}

// PostLLMHook is called after a response is received - FULLY ASYNC, NO DATABASE I/O
// Parameters:
//   - ctx: The DeepIntShield context
//   - result: The DeepIntShield response to be processed
//   - deepintshieldErr: The DeepIntShield error to be processed
//
// Returns:
//   - *schemas.DeepIntShieldResponse: The processed response
//   - *schemas.DeepIntShieldError: The processed error
//   - error: Any error that occurred during processing
func (p *LoggerPlugin) PostLLMHook(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	if ctx == nil {
		// Log error but don't fail the request
		p.logger.Error("context is nil in PostLLMHook")
		return result, deepintshieldErr, nil
	}
	requestID, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string)
	if !ok || requestID == "" {
		p.logger.Error("request-id not found in context or is empty")
		return result, deepintshieldErr, nil
	}
	// If fallback request ID is present, use it instead of the primary request ID
	fallbackRequestID, ok := ctx.Value(schemas.DeepIntShieldContextKeyFallbackRequestID).(string)
	if ok && fallbackRequestID != "" {
		requestID = fallbackRequestID
	}
	asyncCtx := asyncLoggingContext(ctx)
	selectedKeyID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeySelectedKeyID)
	selectedKeyName := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeySelectedKeyName)
	virtualKeyID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)
	virtualKeyName := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyName)
	routingRuleID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceRoutingRuleID)
	routingRuleName := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceRoutingRuleName)
	numberOfRetries := deepintshield.GetIntFromContext(ctx, schemas.DeepIntShieldContextKeyNumberOfRetries)

	requestType, _, _ := deepintshield.GetResponseFields(result, deepintshieldErr)

	isFinalChunk := deepintshield.IsFinalChunk(ctx)

	var tracer schemas.Tracer
	var traceID string
	if deepintshield.IsStreamRequestType(requestType) && requestType != schemas.PassthroughStreamRequest {
		var err error
		tracer, traceID, err = deepintshield.GetTracerFromContext(ctx)
		if err != nil {
			p.logger.Debug("tracer not available in logging plugin posthook: %v", err)
			// Continue with nil tracer - the rest of the code handles this gracefully
			// via `if tracer != nil && traceID != ""` guards
		}
	}

	// For non-final streaming chunks, process the accumulator synchronously
	// and skip the write queue entirely. The accumulator work (ProcessStreamingChunk)
	// is fast (mutex + append). Only final chunks, errors, and non-streaming
	// responses need a DB write.
	if deepintshield.IsStreamRequestType(requestType) && requestType != schemas.PassthroughStreamRequest && !isFinalChunk && result != nil && deepintshieldErr == nil {
		if tracer != nil && traceID != "" {
			tracer.ProcessStreamingChunk(traceID, false, result, deepintshieldErr)
		}
		return result, deepintshieldErr, nil
	}
	// Extract routing engine logs from context before entering goroutine
	routingEngineLogs := formatRoutingEngineLogs(ctx.GetRoutingEngineLogs())

	// Retrieve pending input data from PreLLMHook
	pendingVal, hasPending := p.pendingLogs.LoadAndDelete(requestID)
	if !hasPending {
		// If we have an error (e.g., cancellation/timeout), still write a minimal error entry
		// so the error is visible in logs. Without PreLLMHook's DB insert, silently returning
		// here means the error is completely lost.
		if deepintshieldErr != nil {
			p.logger.Warn("no pending log data found for request %s, writing minimal error entry", requestID)
			entry := &logstore.Log{
				ID:        requestID,
				TenantID:  tenantIDFromContext(asyncCtx),
				Provider:  string(deepintshieldErr.ExtraFields.Provider),
				Model:     deepintshieldErr.ExtraFields.ModelRequested,
				Status:    "error",
				Stream:    deepintshield.IsStreamRequestType(requestType),
				Timestamp: time.Now().UTC(),
				CreatedAt: time.Now().UTC(),
			}
			if data, err := sonic.Marshal(deepintshieldErr); err == nil {
				entry.ErrorDetails = string(data)
			}
			entry.ErrorDetailsParsed = deepintshieldErr
			applyLargePayloadPreviewsToEntry(ctx, entry)
			p.enqueueLogEntryWithTiming(ctx, asyncCtx, entry, p.makePostWriteCallback(asyncCtx, nil))
		} else {
			p.logger.Warn("no pending log data found for request %s, skipping log write", requestID)
		}
		return result, deepintshieldErr, nil
	}

	pending := pendingVal.(*PendingLogData)

	// Build the complete log entry with input (from PreLLMHook) + output (from PostLLMHook)
	entry := buildCompleteLogEntryFromPending(pending)
	// Apply common output fields.
	// Use total wall time (request entry → exit) as the primary latency so the
	// AI Logs column reflects overall gateway latency, not just provider RTT.
	// Fall back to provider-reported latency when wall time is unavailable.
	latency := schemas.RequestWallLatencyMilliseconds(ctx)
	if latency <= 0 && result != nil {
		latency = result.GetExtraFields().Latency
	}
	applyOutputFieldsToEntry(entry, selectedKeyID, selectedKeyName, virtualKeyID, virtualKeyName, routingRuleID, routingRuleName, numberOfRetries, latency)
	entry.MetadataParsed = pending.InitialData.Metadata
	entry.RoutingEngineLogs = routingEngineLogs
	applyLatencyBreakdownMetadata(entry, ctx, result)

	// Branch based on response type to populate output-specific fields

	// Path A: Error with nil result
	if result == nil && deepintshieldErr != nil {
		entry.Status = "error"
		if deepintshield.IsStreamRequestType(requestType) {
			entry.Stream = true
		}
		// Serialize error details immediately since deepintshieldErr may be released
		// back to the pool before the async batch writer processes this entry.
		// Also set ErrorDetailsParsed for UI callback (JSON serialization uses this field).
		if data, err := sonic.Marshal(deepintshieldErr); err == nil {
			entry.ErrorDetails = string(data)
		}
		entry.ErrorDetailsParsed = deepintshieldErr
		if !p.contentLoggingDisabled(ctx) {
			if deepintshieldErr.ExtraFields.RawRequest != nil {
				rawReqBytes, err := sonic.Marshal(deepintshieldErr.ExtraFields.RawRequest)
				if err == nil {
					entry.RawRequest = string(rawReqBytes)
				}
			}

			if deepintshieldErr.ExtraFields.RawResponse != nil {
				rawRespBytes, err := sonic.Marshal(deepintshieldErr.ExtraFields.RawResponse)
				if err == nil {
					entry.RawResponse = string(rawRespBytes)
				}
			}
		}
		applyLargePayloadPreviewsToEntry(ctx, entry)
		p.enqueueLogEntryWithTiming(ctx, asyncCtx, entry, p.makePostWriteCallback(asyncCtx, nil))
		p.scheduleDeferredUsageUpdate(ctx, requestID, entry.TokenUsageParsed != nil)
		return result, deepintshieldErr, nil
	}

	// Path B: Streaming final chunk
	if deepintshield.IsStreamRequestType(requestType) {
		var streamResponse *streaming.ProcessedStreamResponse
		if requestType != schemas.PassthroughStreamRequest && tracer != nil && traceID != "" {
			accResult := tracer.ProcessStreamingChunk(traceID, isFinalChunk, result, deepintshieldErr)
			if accResult != nil {
				streamResponse = convertToProcessedStreamResponse(accResult, requestType)
			}
		}

		if deepintshieldErr != nil {
			entry.Status = "error"
			entry.Stream = true
			if data, err := sonic.Marshal(deepintshieldErr); err == nil {
				entry.ErrorDetails = string(data)
			}
			entry.ErrorDetailsParsed = deepintshieldErr
		} else if streamResponse == nil {
			// tracer or traceID not available, or accumulator returned nil - still write what we have
			entry.Status = "success"
			entry.Stream = true
		} else if isFinalChunk {
			// Apply streaming output fields to the entry
			entry.Stream = true
			p.applyStreamingOutputToEntry(ctx, entry, streamResponse)
		}
		// Backfill passthrough status_code from response (streaming path)
		if result != nil && result.PassthroughResponse != nil {
			if params, ok := entry.ParamsParsed.(*schemas.PassthroughLogParams); ok {
				params.StatusCode = result.PassthroughResponse.StatusCode
			}
			// Flip status for passthrough error responses (4xx/5xx from provider)
			if isPassthroughErrorResponse(result) {
				entry.Status = "error"
			}
		}
		applyLargePayloadPreviewsToEntry(ctx, entry)

		if requestType != schemas.PassthroughStreamRequest && tracer != nil && traceID != "" {
			tracer.CleanupStreamAccumulator(traceID)
		}

		p.enqueueLogEntryWithTiming(ctx, asyncCtx, entry, p.makePostWriteCallback(asyncCtx, nil))
		p.scheduleDeferredUsageUpdate(ctx, requestID, entry.TokenUsageParsed != nil)
		return result, deepintshieldErr, nil
	}

	// Path C: Non-streaming response
	if deepintshieldErr != nil {
		entry.Status = "error"
		// Serialize error details immediately since deepintshieldErr may be released
		// back to the pool before the async batch writer processes this entry.
		// Also set ErrorDetailsParsed for UI callback (JSON serialization uses this field).
		if data, err := sonic.Marshal(deepintshieldErr); err == nil {
			entry.ErrorDetails = string(data)
		}
		entry.ErrorDetailsParsed = deepintshieldErr
	} else if result != nil {
		entry.Status = "success"
		p.applyNonStreamingOutputToEntry(entry, result)
		// Flip status for passthrough error responses (4xx/5xx from provider)
		if isPassthroughErrorResponse(result) {
			entry.Status = "error"
		}
	}
	applyLargePayloadPreviewsToEntry(ctx, entry)

	// Calculate cost
	var cacheDebug *schemas.DeepIntShieldCacheDebug
	if result != nil {
		cacheDebug = result.GetExtraFields().CacheDebug
	}
	entry.CacheDebugParsed = cacheDebug

	p.enqueueLogEntryWithTiming(ctx, asyncCtx, entry, p.makePostWriteCallback(asyncCtx, func(updatedEntry *logstore.Log) {
		updatedEntry.SelectedKey = &schemas.Key{
			ID:   updatedEntry.SelectedKeyID,
			Name: updatedEntry.SelectedKeyName,
		}
		if updatedEntry.VirtualKeyID != nil && updatedEntry.VirtualKeyName != nil {
			updatedEntry.VirtualKey = &tables.TableVirtualKey{
				ID:   *updatedEntry.VirtualKeyID,
				Name: *updatedEntry.VirtualKeyName,
			}
		}
		if updatedEntry.RoutingRuleID != nil && updatedEntry.RoutingRuleName != nil {
			updatedEntry.RoutingRule = &tables.TableRoutingRule{
				ID:   *updatedEntry.RoutingRuleID,
				Name: *updatedEntry.RoutingRuleName,
			}
		}
	}))
	p.scheduleDeferredUsageUpdate(ctx, requestID, entry.TokenUsageParsed != nil)
	return result, deepintshieldErr, nil
}

// Cleanup is called when the plugin is being shut down
func (p *LoggerPlugin) Cleanup() error {
	p.cleanupOnce.Do(func() {
		// Stop the cleanup ticker
		if p.cleanupTicker != nil {
			p.cleanupTicker.Stop()
		}
		// Signal the cleanup worker to stop
		close(p.done)
		// Close write queue FIRST - batchWriter drains remaining entries and exits.
		// THEN set closed flag - this prevents panics from sends-on-closed-channel
		// in enqueueLogEntry (the defer/recover there catches the race window).
		close(p.writeQueue)
		p.closed.Store(true)
		// Wait for the cleanup worker and batch writer to finish
		p.wg.Wait()
		// Note: Accumulator cleanup is handled by the tracer, not the logging plugin
		// GORM handles connection cleanup automatically
	})
	return nil
}

// MCP Plugin Interface Implementation

// SetMCPToolLogCallback sets a callback function that will be called for each MCP tool log entry
func (p *LoggerPlugin) SetMCPToolLogCallback(callback MCPToolLogCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mcpToolLogCallback = callback
}

// PreMCPHook is called before an MCP tool execution - creates initial log entry
// Parameters:
//   - ctx: The DeepIntShield context
//   - req: The MCP request containing tool call information
//
// Returns:
//   - *schemas.DeepIntShieldMCPRequest: The unmodified request
//   - *schemas.MCPPluginShortCircuit: nil (no short-circuiting)
//   - error: nil (errors are logged but don't fail the request)
func (p *LoggerPlugin) PreMCPHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if ctx == nil {
		p.logger.Error("context is nil in PreMCPHook")
		return req, nil, nil
	}

	requestID, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string)
	if !ok || requestID == "" {
		p.logger.Error("request-id not found in context or is empty in PreMCPHook")
		return req, nil, nil
	}

	// Get parent request ID if this MCP call is part of a larger LLM request (using the MCP agent original request ID)
	parentRequestID, _ := ctx.Value(schemas.DeepIntShieldMCPAgentOriginalRequestID).(string)

	createdTimestamp := time.Now().UTC()
	// Stash wall-time start so PostMCPHook can compute the latency breakdown
	// (total_wall, mcp_tool_call, platform_overhead).
	ctx.SetValue(mcpLogStartTimeCtxKey, createdTimestamp)

	// Extract tool name and arguments from the request
	var toolName string
	var serverLabel string

	fullToolName := req.GetToolName()
	arguments := req.GetToolArguments()
	// Skip execution for codemode tools
	if deepintshield.IsCodemodeTool(fullToolName) {
		return req, nil, nil
	}

	// Extract server label from tool name (format: {client}-{tool_name})
	// The first part before hyphen is the client/server label
	if fullToolName != "" {
		if idx := strings.Index(fullToolName, "-"); idx > 0 {
			serverLabel = fullToolName[:idx]
			toolName = fullToolName[idx+1:]
		} else {
			toolName = fullToolName
		}
		switch toolName {
		case mcp.ToolTypeListToolFiles, mcp.ToolTypeReadToolFile, mcp.ToolTypeExecuteToolCode:
			if serverLabel == "" {
				serverLabel = "codemode"
			}
		}
	}

	// Get virtual key information from context - using same method as normal LLM logging
	virtualKeyID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)
	virtualKeyName := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyName)
	asyncCtx := asyncLoggingContext(ctx)

	go func() {
		defer safegoroutine.Recover(p.logger, "logging.mcp-tool-log-create")
		entry := &logstore.MCPToolLog{
			ID:          requestID,
			TenantID:    tenantIDFromContext(asyncCtx),
			Timestamp:   createdTimestamp,
			ToolName:    toolName,
			ServerLabel: serverLabel,
			Status:      "processing",
			CreatedAt:   createdTimestamp,
		}
		// Stamp workspace_id at write-time. Without this the
		// dashboard's MCP Activity page (which joins by tenant_id +
		// workspace_id) misses every row, since "" never equals the
		// active workspace UUID. The pre-existing legacy fix only
		// covered the LLM-side logs path; this brings MCP tool logs
		// in line.
		if workspaceID := workspaceIDFromContext(asyncCtx); workspaceID != "" {
			entry.WorkspaceID = &workspaceID
		}

		if parentRequestID != "" {
			entry.LLMRequestID = &parentRequestID
		}

		if virtualKeyID != "" {
			entry.VirtualKeyID = &virtualKeyID
		}
		if virtualKeyName != "" {
			entry.VirtualKeyName = &virtualKeyName
		}

		// Set arguments if content logging is enabled
		if !p.contentLoggingDisabled(ctx) {
			entry.ArgumentsParsed = arguments
		}

		// Capture configured logging headers and x-bf-lh-* headers into metadata
		entry.MetadataParsed = p.captureLoggingHeaders(ctx)

		if err := p.store.CreateMCPToolLog(asyncCtx, entry); err != nil {
			p.logger.Warn("Failed to insert initial MCP tool log entry for request %s: %v", requestID, err)
		} else {
			// Capture callback under lock, then call it outside the critical section
			p.mu.Lock()
			callback := p.mcpToolLogCallback
			p.mu.Unlock()

			if callback != nil {
				callback(asyncCtx, entry)
			}
		}
	}()

	return req, nil, nil
}

// PostMCPHook is called after an MCP tool execution - updates the log entry with results
// Parameters:
//   - ctx: The DeepIntShield context
//   - resp: The MCP response containing tool execution result
//   - deepintshieldErr: Any error that occurred during execution
//
// Returns:
//   - *schemas.DeepIntShieldMCPResponse: The unmodified response
//   - *schemas.DeepIntShieldError: The unmodified error
//   - error: nil (errors are logged but don't fail the request)
func (p *LoggerPlugin) PostMCPHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError, error) {
	if ctx == nil {
		p.logger.Error("context is nil in PostMCPHook")
		return resp, deepintshieldErr, nil
	}

	// Skip logging for codemode tools (executeToolCode, listToolFiles, readToolFile)
	// We check the tool name from the response instead of context flags
	if resp != nil && deepintshield.IsCodemodeTool(resp.ExtraFields.ToolName) {
		return resp, deepintshieldErr, nil
	}

	requestID, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestID).(string)
	if !ok || requestID == "" {
		p.logger.Error("request-id not found in context or is empty in PostMCPHook")
		return resp, deepintshieldErr, nil
	}

	// Extract virtual key ID and name from context (set by governance plugin)
	virtualKeyID := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)
	virtualKeyName := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyName)

	// Read the start time stamped by PreMCPHook so the breakdown reflects gateway-side wall time.
	startTime, _ := ctx.Value(mcpLogStartTimeCtxKey).(time.Time)

	asyncCtx := asyncLoggingContext(ctx)

	go func() {
		defer safegoroutine.Recover(p.logger, "logging.mcp-tool-log-update")
		updates := make(map[string]interface{})

		// Update virtual key ID and name if they are set (from governance plugin)
		if virtualKeyID != "" {
			updates["virtual_key_id"] = virtualKeyID
		}
		if virtualKeyName != "" {
			updates["virtual_key_name"] = virtualKeyName
		}

		// Get latency from response ExtraFields
		var toolCallLatencyMs float64
		if resp != nil {
			toolCallLatencyMs = float64(resp.ExtraFields.Latency)
			updates["latency"] = toolCallLatencyMs
			// Surface whether the response was served from the mcpcache plugin
			// so the MCP Activity column can show Hit / Miss.
			cacheHit := resp.ExtraFields.CacheHit
			updates["cache_hit"] = cacheHit
		}

		// Build the latency breakdown the same way AI Logs surfaces it. Phases:
		// - mcp_tool_call: upstream tool execution time (from resp.ExtraFields.Latency)
		// - total_wall:    wall-clock time the MCP request spent inside the gateway
		// - platform_overhead: total_wall minus the tool call (covers plugin chain incl. guardrails)
		// Guardrail-stage latencies are persisted as part of GuardrailDecision records and the
		// drawer joins them in via /api/guardrails/traces, so we don't double-count here.
		breakdown := map[string]float64{}
		if toolCallLatencyMs > 0 {
			breakdown["mcp_tool_call"] = toolCallLatencyMs
		}
		if !startTime.IsZero() {
			totalWallMs := float64(time.Since(startTime).Microseconds()) / 1000.0
			if totalWallMs > 0 {
				breakdown["total_wall"] = totalWallMs
				platformOverhead := totalWallMs - toolCallLatencyMs
				if platformOverhead > 0 {
					breakdown["platform_overhead"] = platformOverhead
				}
			}
		}
		if len(breakdown) > 0 {
			// Merge with the logging headers captured at PreMCPHook so we don't drop them.
			merged := p.captureLoggingHeaders(ctx)
			if merged == nil {
				merged = map[string]interface{}{}
			}
			merged["latency_breakdown_ms"] = breakdown
			tempEntry := &logstore.MCPToolLog{}
			tempEntry.MetadataParsed = merged
			if err := tempEntry.SerializeFields(); err == nil && tempEntry.Metadata != "" {
				updates["metadata"] = tempEntry.Metadata
			}
		}

		// Calculate MCP tool cost from catalog if available
		var toolCost float64
		success := (resp != nil && deepintshieldErr == nil)
		if success && resp != nil && p.mcpCatalog != nil && resp.ExtraFields.ClientName != "" && resp.ExtraFields.ToolName != "" {
			// Use separate client name and tool name fields
			if pricingEntry, ok := p.mcpCatalog.GetPricingData(resp.ExtraFields.ClientName, resp.ExtraFields.ToolName); ok {
				toolCost = pricingEntry.CostPerExecution
				updates["cost"] = toolCost
				p.logger.Debug("MCP tool cost for %s.%s: $%.6f", resp.ExtraFields.ClientName, resp.ExtraFields.ToolName, toolCost)
			}
		}

		if deepintshieldErr != nil {
			updates["status"] = "error"
			// Serialize error details
			tempEntry := &logstore.MCPToolLog{}
			tempEntry.ErrorDetailsParsed = deepintshieldErr
			if err := tempEntry.SerializeFields(); err == nil {
				updates["error_details"] = tempEntry.ErrorDetails
			}
		} else if resp != nil {
			updates["status"] = "success"
			// Store result if content logging is enabled
			if !p.contentLoggingDisabled(ctx) {
				var result interface{}
				if resp.ChatMessage != nil {
					// For ChatMessage, try to parse the content as JSON if it's a string
					if resp.ChatMessage.Content != nil && resp.ChatMessage.Content.ContentStr != nil {
						contentStr := *resp.ChatMessage.Content.ContentStr
						var parsedContent interface{}
						if err := sonic.Unmarshal([]byte(contentStr), &parsedContent); err == nil {
							// Content is valid JSON, use parsed version
							result = parsedContent
						} else {
							// Content is not valid JSON or failed to parse, store the whole message
							result = resp.ChatMessage
						}
					} else {
						result = resp.ChatMessage
					}
				} else if resp.ResponsesMessage != nil {
					result = resp.ResponsesMessage
				}
				if result != nil {
					tempEntry := &logstore.MCPToolLog{}
					tempEntry.ResultParsed = result
					if err := tempEntry.SerializeFields(); err == nil {
						updates["result"] = tempEntry.Result
					}
				}
			}
		} else {
			updates["status"] = "error"
			tempEntry := &logstore.MCPToolLog{}
			tempEntry.ErrorDetailsParsed = &schemas.DeepIntShieldError{
				IsDeepIntShieldError: true,
				Error: &schemas.ErrorField{
					Message: "MCP tool execution returned nil response",
				},
			}
			if err := tempEntry.SerializeFields(); err == nil {
				updates["error_details"] = tempEntry.ErrorDetails
			}
		}

		processingErr := retryOnNotFound(asyncCtx, func() error {
			return p.store.UpdateMCPToolLog(asyncCtx, requestID, updates)
		})
		if processingErr != nil {
			p.logger.Warn("failed to process MCP tool log update for request %s: %v", requestID, processingErr)
		} else {
			// Capture callback under lock, then perform DB I/O and invoke callback outside critical section
			p.mu.Lock()
			callback := p.mcpToolLogCallback
			p.mu.Unlock()

			if callback != nil {
				if updatedEntry, getErr := p.store.FindMCPToolLog(asyncCtx, requestID); getErr == nil {
					callback(asyncCtx, updatedEntry)
				} else {
					p.logger.Warn("failed to find updated entry for callback: %v", getErr)
				}
			}
		}
	}()

	return resp, deepintshieldErr, nil
}
