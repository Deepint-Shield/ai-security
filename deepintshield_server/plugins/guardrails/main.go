package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeengine"
	"github.com/google/uuid"
)

const (
	PluginName            = "guardrails"
	defaultHydrationTTL   = 30 * time.Second
	defaultRuntimeTimeout = 3 * time.Second
	defaultPersistenceTTL = 5 * time.Second
	defaultTenantID       = "default"
	defaultWorkers        = 4
	defaultQueueSize      = 512
)

type Config struct {
	HTTPURL              string `json:"http_url,omitempty"`
	GRPCTarget           string `json:"grpc_target,omitempty"`
	SharedSecret         string `json:"shared_secret,omitempty"`
	PreferGRPC           *bool  `json:"prefer_grpc,omitempty"`
	UseEmbeddedRuntime   *bool  `json:"use_embedded_runtime,omitempty"`
	HydrationTTLSeconds  int    `json:"hydration_ttl_seconds,omitempty"`
	RuntimeTimeoutMs     int    `json:"runtime_timeout_ms,omitempty"`
	AsyncPersistence     *bool  `json:"async_persistence,omitempty"`
	PersistenceWorkers   int    `json:"persistence_workers,omitempty"`
	PersistenceQueueSize int    `json:"persistence_queue_size,omitempty"`
	FailOpen             *bool  `json:"fail_open,omitempty"`

	// Embedded runtime tuning. Ignored when a network runtime is in use.
	EmbeddedAdapterTimeoutMs    int            `json:"embedded_adapter_timeout_ms,omitempty"`
	EmbeddedRAGChunkParallelism int            `json:"embedded_rag_chunk_parallelism,omitempty"`
	EmbeddedTimeoutsByCategory  map[string]int `json:"embedded_timeouts_by_category,omitempty"`

	// SpeculativeInputGuards lets the provider call start in parallel with
	// input-guard evaluation: PreLLMHook spawns the guard eval as a goroutine
	// and returns immediately so the model dispatch is not blocked. PostLLMHook
	// then waits on the guard verdict before releasing the model response -
	// allow paths see net latency = max(guards, model) instead of sum.
	//
	// Safety tradeoffs (operator must opt in):
	//   * "deny" paths waste one model call (response discarded, replaced by
	//     guardrail_blocked error).
	//   * "allow_with_redaction" on the input cannot rewrite what the model
	//     already saw - speculative mode converts an input-redact verdict to a
	//     deny so no unsafe content reaches the model output unsanitized.
	// Default: false (preserve existing strict sequencing).
	SpeculativeInputGuards *bool `json:"speculative_input_guards,omitempty"`

	// AsyncPostGuardsWhenNoSync fires PostLLMHook evaluation in a background
	// goroutine when the tenant's output policies are all in shadow/async mode
	// (no sync gate or redactor). Safe by default - only kicks in when no
	// applicable policy can block or rewrite the response. Defaults to true.
	AsyncPostGuardsWhenNoSync *bool `json:"async_post_guards_when_no_sync,omitempty"`
}

type guardRuntime interface {
	Evaluate(ctx context.Context, request *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error)
	RefreshTenant(ctx context.Context, request *runtimeapi.RefreshTenantRequest) (*runtimeapi.RefreshTenantResponse, error)
	Close() error
}

// fastOnlyRuntime is an optional capability - only the embedded runtime
// implements it. When present, PreLLMHook uses it to do a sub-ms sync
// pre-flight before launching speculative dispatch, so a regex/card
// deny short-circuits before the upstream model call ever starts.
type fastOnlyRuntime interface {
	EvaluateFastOnly(ctx context.Context, request *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error)
}

type Store interface {
	ListGuardrailProviders(ctx context.Context) ([]tables.TableGuardrailProvider, error)
	ListGuardrailPolicies(ctx context.Context) ([]tables.TableGuardrailPolicy, error)
	GetGuardrailPolicyVersion(ctx context.Context, id string) (*tables.TableGuardrailPolicyVersion, error)
	ListGuardrailPolicyVersions(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyVersion, error)
	ListGuardrailPolicyProviderBindings(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyProviderBinding, error)
	ListGuardrailMCPToolPolicies(ctx context.Context, policyID string) ([]tables.TableGuardrailMCPToolPolicy, error)
	GetGuardrailRAGSettings(ctx context.Context) (*tables.TableGuardrailRAGSettings, error)
	ListGuardrailRAGSources(ctx context.Context) ([]tables.TableGuardrailRAGSource, error)
}

type controlStore = Store

type tenantHydrationState struct {
	Revision  string
	ExpiresAt time.Time
	Bundle    runtimeapi.TenantBundle
}

type guardrailPersistenceTask struct {
	tenantID string
	trace    *logstore.GuardrailTrace
	decision *logstore.GuardrailDecision
	findings []*logstore.GuardrailFinding
}

// hydrationInflight deduplicates concurrent hydration requests for the same tenant.
// When multiple requests arrive at TTL expiry, only one goroutine performs the
// actual DB queries and runtime refresh; others block and share the result.
type hydrationInflight struct {
	done chan struct{}
	err  error
}

// policyExecutionEntry mirrors the execution-mode metadata for one
// guardrail policy. The runtime engine itself doesn't know about
// sync/async/shadow - the plugin captures it during hydration and
// applies it on the result side, so we don't fork the runtime API.
type policyExecutionEntry struct {
	mode        string
	shadowUntil *time.Time
}

type Plugin struct {
	logger         schemas.Logger
	store          controlStore
	evidenceStore  logstore.GuardrailEvidenceStore
	runtimeClient  guardRuntime
	hydrationTTL   time.Duration
	runtimeTimeout time.Duration
	persistTimeout time.Duration
	failOpen       bool
	asyncPersist   bool

	// speculativeInputGuards lets PreLLMHook return immediately while guard
	// evaluation runs in a goroutine; PostLLMHook waits on the verdict. See
	// Config.SpeculativeInputGuards for the full semantics.
	speculativeInputGuards bool
	// asyncPostGuardsWhenNoSync lets PostLLMHook fire-and-forget the runtime
	// call when no sync output policy could block or rewrite the response.
	asyncPostGuardsWhenNoSync bool

	mu             sync.RWMutex
	tenantCache    map[string]tenantHydrationState
	inflight       map[string]*hydrationInflight
	policyModes    map[string]map[string]policyExecutionEntry
	persistQueue   chan guardrailPersistenceTask
	persistWorkers sync.WaitGroup

	// evalCache is the in-memory TTL+LRU cache layered in front of
	// runtimeClient.Evaluate. Sized via globalEvalCacheConfig (bridged from
	// the semantic_cache plugin's Cost Optimization → Advanced settings).
	// Always non-nil; the enabled flag and TTL come from globalEvalCacheConfig
	// so the workspace switch can toggle behavior without a restart.
	evalCache *evalCache
}

func Init(_ context.Context, config *Config, logger schemas.Logger, store controlStore, evidenceStore logstore.GuardrailEvidenceStore) (*Plugin, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if store == nil {
		return nil, fmt.Errorf("guardrail control store is required")
	}
	if evidenceStore == nil {
		return nil, fmt.Errorf("guardrail evidence store is required")
	}
	resolved := resolveConfig(config)
	client, mode, err := newGuardRuntime(resolved)
	if err != nil {
		return nil, err
	}
	logger.Info("[Guardrails] runtime mode=%s (overhead-min path: %s)", mode, runtimeModeHint(mode))
	plugin := &Plugin{
		logger:                    logger,
		store:                     store,
		evidenceStore:             evidenceStore,
		runtimeClient:             client,
		hydrationTTL:              resolved.hydrationTTL(),
		runtimeTimeout:            resolved.runtimeTimeout(),
		persistTimeout:            defaultPersistenceTTL,
		failOpen:                  resolved.failOpen(),
		asyncPersist:              resolved.asyncPersistence(),
		speculativeInputGuards:    resolved.speculativeInputGuards(),
		asyncPostGuardsWhenNoSync: resolved.asyncPostGuardsWhenNoSync(),
		tenantCache:               make(map[string]tenantHydrationState),
		inflight:                  make(map[string]*hydrationInflight),
		policyModes:               make(map[string]map[string]policyExecutionEntry),
		evalCache:                 newEvalCache(effectiveEvalCacheConfig().maxEntries),
	}
	if plugin.asyncPersist {
		plugin.persistQueue = make(chan guardrailPersistenceTask, resolved.persistenceQueueSize())
		for range resolved.persistenceWorkers() {
			plugin.persistWorkers.Add(1)
			go plugin.persistenceWorker()
		}
	}
	return plugin, nil
}

func (p *Plugin) GetName() string {
	return PluginName
}

func (p *Plugin) Cleanup() error {
	if p == nil {
		return nil
	}
	if p.persistQueue != nil {
		close(p.persistQueue)
		p.persistWorkers.Wait()
	}
	if p.runtimeClient == nil {
		return nil
	}
	return p.runtimeClient.Close()
}

// guardrailsMultimodalEnabled gates the multimodal guardrail extension
// (GUARDRAILS_MULTIMODAL). Evaluated once at process start. Default OFF: when
// off, only the original text/chat/responses/passthrough request types are
// guarded and behavior is byte-for-byte identical to before this feature - the
// primary guarantee that gating in new modalities cannot break existing flows.
// When on, image/audio/video/embedding/rerank request types are also evaluated,
// guarding the text they already carry (prompt, TTS input, transcript). The
// binary-modality extraction (OCR/STT/keyframe) is layered on in later phases.
var guardrailsMultimodalEnabled = os.Getenv("GUARDRAILS_MULTIMODAL") == "true"

func shouldEvaluateLLMGuardrails(requestType schemas.RequestType) bool {
	switch requestType {
	case schemas.TextCompletionRequest,
		schemas.TextCompletionStreamRequest,
		schemas.ChatCompletionRequest,
		schemas.ChatCompletionStreamRequest,
		schemas.ResponsesRequest,
		schemas.ResponsesStreamRequest,
		schemas.PassthroughRequest,
		schemas.PassthroughStreamRequest:
		return true
	}
	if guardrailsMultimodalEnabled {
		switch requestType {
		case schemas.ImageGenerationRequest,
			schemas.ImageGenerationStreamRequest,
			schemas.ImageEditRequest,
			schemas.ImageEditStreamRequest,
			schemas.ImageVariationRequest,
			schemas.SpeechRequest,
			schemas.SpeechStreamRequest,
			schemas.TranscriptionRequest,
			schemas.TranscriptionStreamRequest,
			schemas.EmbeddingRequest,
			schemas.RerankRequest,
			schemas.VideoGenerationRequest,
			schemas.VideoRemixRequest:
			return true
		}
	}
	return false
}

func (p *Plugin) PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	if ctx == nil || req == nil {
		return req, nil, nil
	}
	if !shouldEvaluateLLMGuardrails(req.RequestType) {
		return req, nil, nil
	}
	if err := validateLiveRequestGuardrails(ctx); err != nil {
		return req, &schemas.LLMPluginShortCircuit{Error: invalidGuardrailRequestError(err)}, nil
	}
	// Defensive: make sure the latency-breakdown tracker exists before we
	// record guardrail_input. The transport layer normally sets it via
	// EnsureLatencyTracking, but PreLLMHook may run before that on certain
	// custom transports / plugin orderings. Idempotent - no-op if already set.
	schemas.EnsureLatencyTracking(ctx, time.Now())
	requestID := guardrailRequestID(ctx)
	actor := resolveActorFromContext(ctx)
	tenantID := actor.TenantID
	if tenantID == "" {
		tenantID = defaultTenantID
	}
	if err := p.hydrateTenantIfNeeded(ctx, tenantID, false); err != nil {
		if shortCircuit := p.runtimeFailureLLMShortCircuit(err); shortCircuit != nil {
			return req, shortCircuit, nil
		}
	}
	provider, model, _ := req.GetRequestFields()
	ctx.SetValue(guardrailRequestTypeKey, string(req.RequestType))
	evalRequest := &runtimeapi.EvaluateRequest{
		TenantID:  tenantID,
		RequestID: requestID,
		Stage:     runtimeapi.StageInput,
		Model:     model,
		Provider:  string(provider),
		Actor:     buildActor(ctx),
		Metadata: runtimeMetadata(ctx, map[string]any{
			"request_type": req.RequestType,
			"model":        model,
			"provider":     string(provider),
		}),
	}
	evalRequest.Policies, evalRequest.Metadata = p.attachRuntimePolicies(ctx, runtimeapi.StageInput, evalRequest.Metadata)
	// Early-exit gate: when there are no request-level policies AND
	// neither the resolving virtual key nor the tenant has any
	// enabled policies, skip the runtime RPC entirely. This is the
	// fastest possible path for unguarded VKs and fresh tenants -
	// saves a network round-trip + JSON encode/decode + runtime CPU
	// on every inference request.
	//
	// The gate is checked BEFORE building Content so unguarded VKs never pay
	// the (potentially base64-decode + sha256 + extraction) cost of
	// extractRequestInput/extractRequestAttachments only to discard it.
	//
	// The VK hint (`__bf_vk_has_guards`) is stamped on the request
	// context by the VK auth middleware (Phase 22). Tenant-level
	// policies are checked via the existing hydration cache.
	if len(evalRequest.Policies) == 0 &&
		!actor.HasGuards &&
		!p.tenantHasEnabledPolicies(tenantID) {
		return req, nil, nil
	}
	evalRequest.Content = runtimeapi.Content{
		Input:       extractRequestInput(req),
		Attachments: extractRequestAttachments(req),
	}
	// Speculative dispatch: when enabled and the request is non-streaming,
	// kick off the guard evaluation in a goroutine and return immediately.
	// The provider call then runs in parallel; PostLLMHook waits on the
	// future before releasing the response. Net latency on the allow path
	// becomes max(guards, model) instead of guards + model.
	//
	// Disabled for streaming (no clean way to discard first-token chunks
	// once they hit the wire) and skipped when the decision cache already
	// holds the verdict (the sync path is sub-microsecond there).
	cacheKey := decisionCacheKey(evalRequest)
	if cached, ok := globalDecisionCache.get(cacheKey); ok {
		return p.finalizeInputDecision(ctx, req, evalRequest, cached, tenantID, requestID, provider, model)
	}
	// Fuzzy cache: near-duplicate prompts under the same VK + policy version
	// reuse the prior verdict. Doubles hit rate on templated chat traffic
	// over the exact decisionCache alone. Skipped when the exact cache key
	// was empty (e.g. zero-content payload).
	policyVersion := firstPolicyVersionID(evalRequest.Policies)
	if cached := globalFuzzyCache.lookup(evalRequest, actor.VirtualKeyID, policyVersion, evalRequest.Content.Input); cached != nil {
		return p.finalizeInputDecision(ctx, req, evalRequest, cached, tenantID, requestID, provider, model)
	}
	if p.speculativeInputGuards && !isStreamingRequest(req.RequestType) {
		// Pre-flight: sub-ms sync evaluation of fast policies (portkey
		// checks + local rules), skipping provider bindings entirely.
		// When fast policies already deny, short-circuit immediately -
		// the upstream model call never starts, AI Logs records ~3ms
		// guard_input and 0ms provider, and the wall-time matches the
		// block_path budget the dashboard expects. Without this, a
		// regex-blocked request still paid the full upstream RTT
		// because speculative dispatch fired the model call in
		// parallel with the eval.
		if fast, ok := p.runtimeClient.(fastOnlyRuntime); ok {
			fastCtx, fastCancel := context.WithTimeout(ctx, p.runtimeTimeout)
			fastResp, fastErr := fast.EvaluateFastOnly(fastCtx, evalRequest)
			fastCancel()
			if fastErr == nil && fastResp != nil {
				if fastResp.Decision == "deny" {
					// Hard block before the model call.
					globalDecisionCache.put(cacheKey, fastResp)
					globalFuzzyCache.store(evalRequest, actor.VirtualKeyID, policyVersion, evalRequest.Content.Input, fastResp, 0)
					return p.finalizeInputDecision(ctx, req, evalRequest, fastResp, tenantID, requestID, provider, model)
				}
				// Allow path: when the request's policy set has no provider-
				// bound policies (e.g. VK attached only to regex card
				// policies), the slow eval has nothing to add. Take the
				// fast verdict as final, cache it, and skip the speculative
				// goroutine - avoids re-running every regex card twice.
				if !p.tenantHasProviderBoundPolicies(tenantID, runtimeapi.StageInput) && !requestHasProviderBoundPolicies(evalRequest.Policies) {
					globalDecisionCache.put(cacheKey, fastResp)
					globalFuzzyCache.store(evalRequest, actor.VirtualKeyID, policyVersion, evalRequest.Content.Input, fastResp, 0)
					return p.finalizeInputDecision(ctx, req, evalRequest, fastResp, tenantID, requestID, provider, model)
				}
			}
		}
		future := &speculativeInputFuture{
			Done:      make(chan struct{}),
			StartedAt: time.Now(),
			requestID: requestID,
			provider:  string(provider),
			model:     model,
			input:     evalRequest.Content.Input,
			actor:     evalRequest.Actor,
			stage:     runtimeapi.StageInput,
			policies:  evalRequest.Policies,
		}
		ctx.SetValue(speculativeInputResultKey, future)
		go p.runSpeculativeInputEval(ctx, evalRequest, future, cacheKey)
		return req, nil, nil
	}
	result, err := p.evaluateRuntime(ctx, evalRequest)
	if err != nil {
		if shortCircuit := p.runtimeFailureLLMShortCircuit(err); shortCircuit != nil {
			return req, shortCircuit, nil
		}
		return req, nil, nil
	}
	globalDecisionCache.put(cacheKey, result)
	globalFuzzyCache.store(evalRequest, actor.VirtualKeyID, policyVersion, evalRequest.Content.Input, result, 0)
	return p.finalizeInputDecision(ctx, req, evalRequest, result, tenantID, requestID, provider, model)
}

// finalizeInputDecision applies the verdict produced by either the sync or
// speculative path: persists the raw result, applies execution-mode
// downgrades, optionally rewrites the input on redact, and short-circuits on
// deny. Extracted so the speculative path can reuse the post-eval logic
// without duplication.
func (p *Plugin) finalizeInputDecision(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, evalRequest *runtimeapi.EvaluateRequest, result *runtimeapi.EvaluateResponse, tenantID, requestID string, provider schemas.ModelProvider, model string) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	p.persistEvaluation(ctx, runtimeapi.StageInput, requestID, evalRequest.Actor, string(provider), model, evalRequest.Content.Input, "", "", nil, evalRequest.Policies, result)
	outcome := p.applyExecutionModes(tenantID, result)
	setGuardrailResponseHeaders(ctx, outcome.headerStatus, outcome.headerMode)
	effective := outcome.effective
	if effective.Decision == "allow_with_redaction" && strings.TrimSpace(effective.SanitizedInput) != "" {
		_ = rewriteRequestInput(req, effective.SanitizedInput)
	}
	if shortCircuit := p.shortCircuitForLLMDecision(effective, runtimeapi.StageInput); shortCircuit != nil {
		return req, shortCircuit, nil
	}
	return req, nil, nil
}

// runSpeculativeInputEval executes the runtime evaluation on a background
// goroutine and stores the result in the future. Called from PreLLMHook so
// PostLLMHook can collect the verdict after the provider call returns.
// Uses a detached context (cloned tenant/request scope) so a client cancel
// of the parent doesn't tear down the eval mid-flight.
func (p *Plugin) runSpeculativeInputEval(ctx *schemas.DeepIntShieldContext, evalRequest *runtimeapi.EvaluateRequest, future *speculativeInputFuture, cacheKey string) {
	defer safegoroutine.Recover(p.logger, "guardrails.speculative-input")
	result, err := p.evaluateRuntime(ctx, evalRequest)
	if err == nil && result != nil && cacheKey != "" {
		globalDecisionCache.put(cacheKey, result)
	}
	future.finish(result, err)
}

func (p *Plugin) PostLLMHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	// Release the per-request stream accumulator on the error/cancel/timeout
	// termination path that returns early below (resp == nil or deepintshieldErr set).
	// The normal final chunk (resp != nil, no error) instead flows through to
	// accumulateStreamOutput, which scans the full window THEN deletes - so we
	// must NOT delete here for that path or the final scan would lose its window.
	if guardrailsStreamAccumulate && ctx != nil && (resp == nil || deepintshieldErr != nil) {
		deleteStreamAccumulator(guardrailRequestID(ctx))
	}
	if ctx == nil || resp == nil || deepintshieldErr != nil {
		return resp, deepintshieldErr, nil
	}
	// Same defensive EnsureLatencyTracking as PreLLMHook - covers the case
	// where PreLLMHook didn't run (e.g. cache short-circuit upstream) but
	// PostLLMHook still needs to record guardrail_output.
	schemas.EnsureLatencyTracking(ctx, time.Now())
	// Speculative-dispatch barrier: collect the input-guard verdict that
	// was kicked off in PreLLMHook. If the verdict denies (or wanted
	// redaction we can no longer apply), discard the model response and
	// return guardrail_blocked. We pay only the *gap* between guard and
	// model completion times; the model wait we'd have paid anyway.
	if future, ok := ctx.Value(speculativeInputResultKey).(*speculativeInputFuture); ok && future != nil {
		ctx.SetValue(speculativeInputResultKey, nil)
		if guardErr := p.collectSpeculativeInputVerdict(ctx, future); guardErr != nil {
			return nil, guardErr, nil
		}
	}
	extra := resp.GetExtraFields()
	if !shouldEvaluateLLMGuardrails(extra.RequestType) {
		return resp, deepintshieldErr, nil
	}
	ctx.SetValue(guardrailRequestTypeKey, string(extra.RequestType))
	requestID := guardrailRequestID(ctx)
	actor := resolveActorFromContext(ctx)
	tenantID := actor.TenantID
	if tenantID == "" {
		tenantID = defaultTenantID
	}
	if err := p.hydrateTenantIfNeeded(ctx, tenantID, false); err != nil {
		if guardErr := p.runtimeFailureDeepIntShieldError(err); guardErr != nil {
			return nil, guardErr, nil
		}
		return resp, deepintshieldErr, nil
	}
	provider := string(extra.Provider)
	model := strings.TrimSpace(extra.ModelRequested)
	if model == "" {
		switch {
		case resp.ChatResponse != nil:
			model = resp.ChatResponse.Model
		case resp.TextCompletionResponse != nil:
			model = resp.TextCompletionResponse.Model
		case resp.ResponsesResponse != nil:
			model = resp.ResponsesResponse.Model
		case resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Response != nil:
			model = resp.ResponsesStreamResponse.Response.Model
		}
	}
	outputText := extractResponseOutput(resp)
	// Incremental streaming-output guarding: when enabled, accumulate the
	// streamed deltas and evaluate the growing window so cross-chunk violations
	// are caught. Cadence-skipped chunks are released immediately (no guard
	// call → flat streaming latency). Default-off keeps the per-delta path.
	if guardrailsStreamAccumulate && isStreamingRequest(extra.RequestType) {
		var scanNow bool
		outputText, scanNow = p.accumulateStreamOutput(ctx, requestID, streamChunkDelta(resp))
		if !scanNow {
			return resp, deepintshieldErr, nil
		}
	}
	evalRequest := &runtimeapi.EvaluateRequest{
		TenantID:  tenantID,
		RequestID: requestID,
		Stage:     runtimeapi.StageOutput,
		Model:     model,
		Provider:  provider,
		Actor:     buildActor(ctx),
		Content: runtimeapi.Content{
			Output: outputText,
		},
		Metadata: runtimeMetadata(ctx, map[string]any{
			"request_type": extra.RequestType,
			"model":        model,
			"provider":     provider,
		}),
	}
	evalRequest.Policies, evalRequest.Metadata = p.attachRuntimePolicies(ctx, runtimeapi.StageOutput, evalRequest.Metadata)
	// Same early-exit gate as PreLLMHook - see line ~228 comment. Checked
	// BEFORE building the response Attachments so unguarded VKs never pay the
	// base64-decode + sha256 cost of extractResponseAttachments.
	if len(evalRequest.Policies) == 0 &&
		!actor.HasGuards &&
		!p.tenantHasEnabledPolicies(tenantID) {
		return resp, deepintshieldErr, nil
	}
	evalRequest.Content.Attachments = extractResponseAttachments(resp)
	// Async post-guards fast path: when no applicable output policy is in
	// sync mode (i.e. nothing can block or redact), the runtime call is
	// observation-only. Detach it from the request path so the response is
	// released immediately. Findings still land in the audit store via the
	// persistence queue, preserving the shadow/async telemetry contract.
	if p.asyncPostGuardsWhenNoSync && !p.tenantHasSyncPoliciesForStage(tenantID, runtimeapi.StageOutput) && !p.hasRequestSyncPolicies(evalRequest.Policies) {
		p.spawnAsyncOutputEval(ctx, evalRequest, requestID, provider, model, outputText)
		return resp, deepintshieldErr, nil
	}
	result, err := p.evaluateRuntime(ctx, evalRequest)
	if err != nil {
		if guardErr := p.runtimeFailureDeepIntShieldError(err); guardErr != nil {
			return nil, guardErr, nil
		}
		return resp, deepintshieldErr, nil
	}
	outcome := p.applyExecutionModes(tenantID, result)
	setGuardrailResponseHeaders(ctx, outcome.headerStatus, outcome.headerMode)
	effective := outcome.effective
	if effective.Decision == "allow_with_redaction" && strings.TrimSpace(effective.SanitizedOutput) != "" {
		rewriteResponseOutput(resp, effective.SanitizedOutput)
	}
	p.persistEvaluation(ctx, runtimeapi.StageOutput, requestID, evalRequest.Actor, provider, model, "", outputText, "", nil, evalRequest.Policies, result)
	if guardErr := p.errorForDecision(effective, runtimeapi.StageOutput); guardErr != nil {
		return nil, guardErr, nil
	}
	return resp, deepintshieldErr, nil
}

func (p *Plugin) PreMCPHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if ctx == nil || req == nil {
		return req, nil, nil
	}
	if err := validateLiveRequestGuardrails(ctx); err != nil {
		return req, &schemas.MCPPluginShortCircuit{Error: invalidGuardrailRequestError(err)}, nil
	}
	requestID := guardrailRequestID(ctx)
	tenantID := guardrailTenantID(ctx)
	if err := p.hydrateTenantIfNeeded(ctx, tenantID, false); err != nil {
		if shortCircuit := p.runtimeFailureMCPShortCircuit(err); shortCircuit != nil {
			return req, shortCircuit, nil
		}
	}
	mcpCtx := buildMCPContext(req)
	evalRequest := &runtimeapi.EvaluateRequest{
		TenantID:  tenantID,
		RequestID: requestID,
		Stage:     runtimeapi.StageMCP,
		Actor:     buildActor(ctx),
		Content: runtimeapi.Content{
			ToolInput: extractMCPInput(req),
		},
		MCP: mcpCtx,
		Metadata: runtimeMetadata(ctx, map[string]any{
			"request_type": schemas.MCPToolExecutionRequest,
		}),
	}
	evalRequest.Policies, evalRequest.Metadata = p.attachRuntimePolicies(ctx, runtimeapi.StageMCP, evalRequest.Metadata)
	result, err := p.evaluateRuntime(ctx, evalRequest)
	if err != nil {
		if shortCircuit := p.runtimeFailureMCPShortCircuit(err); shortCircuit != nil {
			return req, shortCircuit, nil
		}
		return req, nil, nil
	}
	p.persistEvaluation(ctx, runtimeapi.StageMCP, requestID, evalRequest.Actor, "", "", extractMCPInput(req), "", mcpCtx.ToolName, mcpCtx, evalRequest.Policies, result)
	outcome := p.applyExecutionModes(tenantID, result)
	setGuardrailResponseHeaders(ctx, outcome.headerStatus, outcome.headerMode)
	if shortCircuit := p.shortCircuitForMCPDecision(outcome.effective, runtimeapi.StageMCP); shortCircuit != nil {
		return req, shortCircuit, nil
	}
	return req, nil, nil
}

func (p *Plugin) PostMCPHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError, error) {
	if ctx == nil || resp == nil || deepintshieldErr != nil {
		return resp, deepintshieldErr, nil
	}
	requestID := guardrailRequestID(ctx)
	tenantID := guardrailTenantID(ctx)
	if err := p.hydrateTenantIfNeeded(ctx, tenantID, false); err != nil {
		if guardErr := p.runtimeFailureDeepIntShieldError(err); guardErr != nil {
			return nil, guardErr, nil
		}
		return resp, deepintshieldErr, nil
	}
	mcpCtx := &runtimeapi.MCPContext{
		ServerLabel: strings.TrimSpace(resp.ExtraFields.ClientName),
		ToolName:    strings.TrimSpace(resp.ExtraFields.ToolName),
	}
	evalRequest := &runtimeapi.EvaluateRequest{
		TenantID:  tenantID,
		RequestID: requestID,
		Stage:     runtimeapi.StageMCP,
		Actor:     buildActor(ctx),
		Content: runtimeapi.Content{
			ToolInput: extractMCPOutput(resp),
		},
		MCP: mcpCtx,
		Metadata: runtimeMetadata(ctx, map[string]any{
			"request_type": schemas.MCPToolExecutionRequest,
		}),
	}
	evalRequest.Policies, evalRequest.Metadata = p.attachRuntimePolicies(ctx, runtimeapi.StageMCP, evalRequest.Metadata)
	result, err := p.evaluateRuntime(ctx, evalRequest)
	if err != nil {
		if guardErr := p.runtimeFailureDeepIntShieldError(err); guardErr != nil {
			return nil, guardErr, nil
		}
		return resp, deepintshieldErr, nil
	}
	outcome := p.applyExecutionModes(tenantID, result)
	setGuardrailResponseHeaders(ctx, outcome.headerStatus, outcome.headerMode)
	effective := outcome.effective
	if effective.Decision == "allow_with_redaction" && strings.TrimSpace(effective.SanitizedOutput) != "" {
		rewriteMCPResponseOutput(resp, effective.SanitizedOutput)
	}
	p.persistEvaluation(ctx, runtimeapi.StageMCP, requestID, evalRequest.Actor, "", "", "", extractMCPOutput(resp), mcpCtx.ToolName, mcpCtx, evalRequest.Policies, result)
	if guardErr := p.errorForDecision(effective, runtimeapi.StageMCP); guardErr != nil {
		return nil, guardErr, nil
	}
	return resp, deepintshieldErr, nil
}

func resolveConfig(config *Config) *Config {
	resolved := &Config{}
	if config != nil {
		*resolved = *config
	}
	if strings.TrimSpace(resolved.HTTPURL) == "" {
		resolved.HTTPURL = strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_URL"))
	}
	if strings.TrimSpace(resolved.GRPCTarget) == "" {
		resolved.GRPCTarget = strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_GRPC_TARGET"))
	}
	if strings.TrimSpace(resolved.SharedSecret) == "" {
		resolved.SharedSecret = strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_SHARED_SECRET"))
	}
	return resolved
}

// newGuardRuntime returns the active runtime and a short mode label
// ("embedded", "grpc", "http") for startup logging. Embedded is preferred
// whenever it is selected - explicitly or by default - and is also chosen as
// an automatic fallback when no network endpoint is configured.
func newGuardRuntime(config *Config) (guardRuntime, string, error) {
	if config == nil {
		config = resolveConfig(nil)
	}
	noNetworkConfigured := strings.TrimSpace(config.HTTPURL) == "" && strings.TrimSpace(config.GRPCTarget) == ""
	if config.useEmbeddedRuntime() || noNetworkConfigured {
		return runtimeengine.NewWith(runtimeengine.Config{
			AdapterTimeoutMs:      config.EmbeddedAdapterTimeoutMs,
			RAGChunkParallelism:   config.EmbeddedRAGChunkParallelism,
			PerCategoryTimeoutsMs: config.EmbeddedTimeoutsByCategory,
		}), "embedded", nil
	}
	client, err := runtimeapi.NewClient(runtimeapi.ClientConfig{
		HTTPURL:      strings.TrimSpace(config.HTTPURL),
		GRPCTarget:   strings.TrimSpace(config.GRPCTarget),
		SharedSecret: strings.TrimSpace(config.SharedSecret),
		Timeout:      config.runtimeTimeout(),
		PreferGRPC:   config.preferGRPC(),
	})
	if err != nil {
		return nil, "", err
	}
	if client == nil {
		return nil, "", fmt.Errorf("guard runtime client is not configured")
	}
	mode := "http"
	if config.preferGRPC() && strings.TrimSpace(config.GRPCTarget) != "" {
		mode = "grpc"
	}
	return client, mode, nil
}

// runtimeModeHint maps the chosen runtime mode to a short operator-facing
// hint about latency cost so a misconfiguration (e.g. forgetting to scrub
// DEEPINTSHIELD_GUARD_URL on a single-binary deploy) is obvious in logs.
func runtimeModeHint(mode string) string {
	switch mode {
	case "embedded":
		return "in-process, no RPC hop"
	case "grpc":
		return "remote gRPC - set DEEPINTSHIELD_GUARD_USE_EMBEDDED_RUNTIME=true to skip the hop in single-binary deploys"
	case "http":
		return "remote HTTP - gRPC preferred when available; embedded preferred for single-binary deploys"
	default:
		return mode
	}
}

func (c *Config) preferGRPC() bool {
	if c != nil && c.PreferGRPC != nil {
		return *c.PreferGRPC
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_PREFER_GRPC")), "false") {
		return false
	}
	return true
}

func (c *Config) useEmbeddedRuntime() bool {
	if c != nil && c.UseEmbeddedRuntime != nil {
		return *c.UseEmbeddedRuntime
	}
	return envBool("DEEPINTSHIELD_GUARD_USE_EMBEDDED_RUNTIME", true)
}

func (c *Config) hydrationTTL() time.Duration {
	if c != nil && c.HydrationTTLSeconds > 0 {
		return time.Duration(c.HydrationTTLSeconds) * time.Second
	}
	return defaultHydrationTTL
}

func (c *Config) runtimeTimeout() time.Duration {
	if c != nil && c.RuntimeTimeoutMs > 0 {
		return time.Duration(c.RuntimeTimeoutMs) * time.Millisecond
	}
	return defaultRuntimeTimeout
}

func (c *Config) failOpen() bool {
	if c != nil && c.FailOpen != nil {
		return *c.FailOpen
	}
	return true
}

func (c *Config) asyncPersistence() bool {
	if c != nil && c.AsyncPersistence != nil {
		return *c.AsyncPersistence
	}
	return envBool("DEEPINTSHIELD_GUARD_ASYNC_PERSISTENCE", true)
}

func (c *Config) persistenceWorkers() int {
	if c != nil && c.PersistenceWorkers > 0 {
		return c.PersistenceWorkers
	}
	return envInt("DEEPINTSHIELD_GUARD_PERSISTENCE_WORKERS", defaultWorkers)
}

func (c *Config) persistenceQueueSize() int {
	if c != nil && c.PersistenceQueueSize > 0 {
		return c.PersistenceQueueSize
	}
	return envInt("DEEPINTSHIELD_GUARD_PERSISTENCE_QUEUE_SIZE", defaultQueueSize)
}

func (c *Config) speculativeInputGuards() bool {
	if c != nil && c.SpeculativeInputGuards != nil {
		return *c.SpeculativeInputGuards
	}
	// Default ON for non-streaming requests so guardrail + provider-adapter
	// time (now up to 10s for cold-start ML detectors) doesn't add to the
	// hot path. PreLLMHook returns immediately, the model call and the
	// guard evaluation race in parallel, and PostLLMHook waits on the
	// guard verdict before releasing the response. Net inference latency
	// becomes max(model, guards) instead of guards + model.
	// Override with DEEPINTSHIELD_GUARD_SPECULATIVE_INPUT_GUARDS=false to
	// force the sync path (useful for strict-block SLAs where serving a
	// model response that will be discarded on deny costs more than waiting).
	return envBool("DEEPINTSHIELD_GUARD_SPECULATIVE_INPUT_GUARDS", true)
}

func (c *Config) asyncPostGuardsWhenNoSync() bool {
	if c != nil && c.AsyncPostGuardsWhenNoSync != nil {
		return *c.AsyncPostGuardsWhenNoSync
	}
	return envBool("DEEPINTSHIELD_GUARD_ASYNC_POST_GUARDS", true)
}

func envBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return fallback
		}
		value = (value * 10) + int(r-'0')
	}
	if value <= 0 {
		return fallback
	}
	return value
}

func (p *Plugin) hydrateTenantIfNeeded(ctx context.Context, tenantID string, force bool) error {
	if p == nil || p.runtimeClient == nil {
		return fmt.Errorf("guard runtime client is not configured")
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = defaultTenantID
	}

	// Fast path: TTL still valid, no work needed.
	if !force {
		p.mu.RLock()
		state, ok := p.tenantCache[tenantID]
		p.mu.RUnlock()
		if ok && time.Now().UTC().Before(state.ExpiresAt) {
			return nil
		}
	}

	// Singleflight: if another goroutine is already hydrating this tenant,
	// wait for its result instead of issuing duplicate DB queries.
	p.mu.Lock()
	if flight, ok := p.inflight[tenantID]; ok {
		p.mu.Unlock()
		<-flight.done
		return flight.err
	}
	flight := &hydrationInflight{done: make(chan struct{})}
	p.inflight[tenantID] = flight
	p.mu.Unlock()

	err := p.doHydrateTenant(ctx, tenantID, force)
	flight.err = err
	close(flight.done)

	p.mu.Lock()
	delete(p.inflight, tenantID)
	p.mu.Unlock()

	return err
}

func (p *Plugin) doHydrateTenant(ctx context.Context, tenantID string, force bool) error {
	bundle, err := p.buildTenantBundle(ctx, tenantID)
	if err != nil {
		return err
	}
	if !force {
		p.mu.RLock()
		state, ok := p.tenantCache[tenantID]
		p.mu.RUnlock()
		if ok && state.Revision == bundle.Revision && time.Now().UTC().Before(state.ExpiresAt) {
			return nil
		}
	}
	refreshCtx, cancel := context.WithTimeout(context.Background(), p.runtimeTimeout)
	defer cancel()
	if _, err := p.runtimeClient.RefreshTenant(refreshCtx, &runtimeapi.RefreshTenantRequest{
		TenantID: tenantID,
		Bundle:   bundle,
	}); err != nil {
		return err
	}
	modes, err := p.loadPolicyExecutionModes(ctx)
	if err != nil {
		// A failure here only loses the per-policy mode index - every
		// policy reverts to sync (the safe default). Log and proceed
		// so the runtime refresh itself is not blocked.
		p.logger.Warn("[Guardrails] failed to load policy execution modes: %v", err)
		modes = nil
	}
	p.mu.Lock()
	p.tenantCache[tenantID] = tenantHydrationState{
		Revision:  bundle.Revision,
		ExpiresAt: time.Now().UTC().Add(p.hydrationTTL),
		Bundle:    bundle,
	}
	p.policyModes[tenantID] = modes
	p.mu.Unlock()
	return nil
}

// tenantHasEnabledPolicies returns true when the cached hydration for
// the tenant indicates at least one policy is configured. Read-only
// access via the existing tenantCache mutex; pure-memory cost on the
// hot path. Used by PreLLMHook / PostLLMHook to skip the runtime RPC
// for tenants with no guardrails.
//
// Returns true when either:
//   - the tenant's bundle has at least one policy, OR
//   - the cache has not yet been populated (defensive: avoid
//     accidentally bypassing the runtime before the first hydration
//     completes).
func (p *Plugin) tenantHasEnabledPolicies(tenantID string) bool {
	if tenantID == "" {
		// No tenant scope yet (e.g. legacy single-tenant deployment) -
		// fall through to the runtime; it will resolve the default tenant.
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	state, ok := p.tenantCache[tenantID]
	if !ok {
		// Not yet hydrated - let the runtime decide.
		return true
	}
	if len(state.Bundle.Policies) > 0 {
		return true
	}
	if modes, ok := p.policyModes[tenantID]; ok && len(modes) > 0 {
		return true
	}
	return false
}

// loadPolicyExecutionModes builds the tenant's policyID → execution mode
// map. Read directly from the control store rather than the runtime
// bundle because PolicyBundle is the runtime engine's contract, and we
// don't want to leak our enforcement-orchestration concept into it.
func (p *Plugin) loadPolicyExecutionModes(ctx context.Context) (map[string]policyExecutionEntry, error) {
	policies, err := p.store.ListGuardrailPolicies(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]policyExecutionEntry, len(policies))
	for _, pol := range policies {
		mode := strings.ToLower(strings.TrimSpace(pol.ExecutionMode))
		if mode == "" {
			mode = tables.GuardrailExecutionModeSync
		}
		var shadowUntil *time.Time
		if pol.ShadowUntil != nil {
			t := *pol.ShadowUntil
			shadowUntil = &t
		}
		out[pol.ID] = policyExecutionEntry{mode: mode, shadowUntil: shadowUntil}
	}
	return out, nil
}

// effectivePolicyMode returns a policy's execution mode, snapping shadow
// rollouts back to sync once their TTL has elapsed. This is the single
// source of truth - every code path that needs to know "how should I
// treat this finding?" must go through here.
func (p *Plugin) effectivePolicyMode(tenantID, policyID string) string {
	if p == nil {
		return tables.GuardrailExecutionModeSync
	}
	p.mu.RLock()
	tenantModes := p.policyModes[tenantID]
	entry, ok := tenantModes[policyID]
	p.mu.RUnlock()
	if !ok {
		return tables.GuardrailExecutionModeSync
	}
	if entry.mode == tables.GuardrailExecutionModeShadow && entry.shadowUntil != nil && time.Now().UTC().After(*entry.shadowUntil) {
		return tables.GuardrailExecutionModeSync
	}
	if entry.mode == "" {
		return tables.GuardrailExecutionModeSync
	}
	return entry.mode
}

func (p *Plugin) buildTenantBundle(ctx context.Context, tenantID string) (runtimeapi.TenantBundle, error) {
	providers, err := p.store.ListGuardrailProviders(ctx)
	if err != nil {
		return runtimeapi.TenantBundle{}, err
	}
	policies, err := p.store.ListGuardrailPolicies(ctx)
	if err != nil {
		return runtimeapi.TenantBundle{}, err
	}

	bundle := runtimeapi.TenantBundle{
		TenantID:    tenantID,
		RefreshedAt: time.Now().UTC(),
		Providers:   make([]runtimeapi.ProviderConfig, 0, len(providers)),
		Policies:    make([]runtimeapi.PolicyBundle, 0, len(policies)),
		Metadata: map[string]any{
			"source": "deepintshield_server",
		},
	}
	providerBindingsByPolicy := make(map[string][]runtimeapi.PolicyProviderBinding)
	mcpPolicies := make([]runtimeapi.MCPToolPolicy, 0)

	for _, provider := range providers {
		if !provider.Enabled {
			continue
		}
		bundle.Providers = append(bundle.Providers, runtimeapi.ProviderConfig{
			ID:             provider.ID,
			Name:           provider.Name,
			ProviderType:   provider.ProviderType,
			Mode:           provider.Mode,
			Enabled:        provider.Enabled,
			Region:         provider.Region,
			Endpoint:       provider.Endpoint,
			Credentials:    provider.Credentials,
			ConnectionMeta: provider.ConnectionMeta,
		})
	}

	// Resolve per-policy data (version, bindings, MCP tool policies) concurrently.
	// Each policy's lookups are independent, so parallelism reduces total DB wait time
	// from O(N * queryTime) to O(queryTime) with N goroutines.
	enabledPolicies := make([]tables.TableGuardrailPolicy, 0, len(policies))
	for _, policy := range policies {
		if policy.Enabled {
			enabledPolicies = append(enabledPolicies, policy)
		}
	}

	type policyResult struct {
		bundle      runtimeapi.PolicyBundle
		bindings    []runtimeapi.PolicyProviderBinding
		mcpPolicies []runtimeapi.MCPToolPolicy
		err         error
	}
	results := make([]policyResult, len(enabledPolicies))
	var policyWg sync.WaitGroup
	for i, policy := range enabledPolicies {
		policyWg.Add(1)
		go func(idx int, pol tables.TableGuardrailPolicy) {
			defer policyWg.Done()
			defer safegoroutine.Recover(p.logger, "guardrails.policy-evaluator")
			version, err := p.resolvePolicyVersion(ctx, &pol)
			if err != nil {
				results[idx].err = err
				return
			}
			if version == nil {
				return
			}
			bindings, err := p.store.ListGuardrailPolicyProviderBindings(ctx, pol.ID)
			if err != nil {
				results[idx].err = err
				return
			}
			// Build a quick provider-type lookup for the bundle so we can
			// stamp ProviderType on each explicit binding. Without this,
			// computeEngineSource - which only sees the cached bundle, not
			// the original `bundle.Providers` slice - can't tell that a
			// binding's ProviderID corresponds to a deepintshield_models
			// adapter, and clean Allow rows under an AI Models wrapper VK
			// silently classify as "policy" on AI Logs's Engine column.
			providerTypeByID := make(map[string]string, len(bundle.Providers))
			for _, prov := range bundle.Providers {
				providerTypeByID[prov.ID] = prov.ProviderType
			}
			compiledBindings := make([]runtimeapi.PolicyProviderBinding, 0, len(bindings))
			for _, binding := range bindings {
				if !binding.Enabled {
					continue
				}
				compiledBindings = append(compiledBindings, runtimeapi.PolicyProviderBinding{
					ProviderID:   binding.ProviderID,
					ProviderType: providerTypeByID[binding.ProviderID],
					Stage:        binding.Stage,
					Priority:     binding.Priority,
					Enabled:      binding.Enabled,
				})
			}
			// No auto-bind fallback: a policy with zero explicit provider
			// bindings is a pure regex/local-check policy and must NOT
			// silently inherit every workspace provider. The previous
			// fallback fanned dev_policy out to the deepintshield_models
			// wrapper sidecar - on the allow path that adapter call eats
			// the policy's timeout_ms (~150ms) before falling through, and
			// surfaces as `guardrail_input ≈ 150ms` on regex-only VKs. The
			// canonical way to attach a provider remains the explicit
			// guardrail_policy_provider_bindings row written by the UI
			// when an operator selects an AI Models / Bedrock / Azure
			// adapter for the policy.
			sort.SliceStable(compiledBindings, func(i, j int) bool {
				return compiledBindings[i].Priority < compiledBindings[j].Priority
			})

			toolPolicies, err := p.store.ListGuardrailMCPToolPolicies(ctx, pol.ID)
			if err != nil {
				results[idx].err = err
				return
			}
			var mcps []runtimeapi.MCPToolPolicy
			for _, tp := range toolPolicies {
				mcps = append(mcps, runtimeapi.MCPToolPolicy{
					PolicyID:          tp.PolicyID,
					ServerLabel:       tp.ServerLabel,
					ToolName:          tp.ToolName,
					ActionClass:       tp.ActionClass,
					ApprovalNeeded:    tp.ApprovalNeeded,
					AllowedDomains:    tp.AllowedDomains,
					AllowedIdentities: tp.AllowedIdentities,
				})
			}

			metadata := runtimePolicyMetadata(pol)
			results[idx].bindings = compiledBindings
			results[idx].mcpPolicies = mcps
			results[idx].bundle = runtimeapi.PolicyBundle{
				PolicyID:         pol.ID,
				PolicyVersionID:  version.ID,
				Name:             pol.Name,
				DomainPackID:     optionalString(pol.DomainPackID),
				Scope:            pol.Scope,
				EnforcementMode:  pol.EnforcementMode,
				Enabled:          pol.Enabled,
				IsDefault:        pol.IsDefault,
				TimeoutMs:        pol.TimeoutMs,
				Metadata:         metadata,
				Definition:       version.Definition,
				ProviderBindings: compiledBindings,
			}
		}(i, policy)
	}
	policyWg.Wait()

	// Merge results in original order (deterministic).
	for _, result := range results {
		if result.err != nil {
			return runtimeapi.TenantBundle{}, result.err
		}
		if result.bundle.PolicyID == "" {
			continue // version was nil, policy skipped
		}
		providerBindingsByPolicy[result.bundle.PolicyID] = result.bindings
		mcpPolicies = append(mcpPolicies, result.mcpPolicies...)
		bundle.Policies = append(bundle.Policies, result.bundle)
	}

	bundle.MCPToolPolicies = mcpPolicies
	bundle.Metadata["provider_count"] = len(bundle.Providers)
	bundle.Metadata["policy_count"] = len(bundle.Policies)
	bundle.Metadata["mcp_policy_count"] = len(bundle.MCPToolPolicies)
	if settings, err := p.store.GetGuardrailRAGSettings(ctx); err == nil && settings != nil {
		bundle.Metadata["rag_settings"] = pluginRAGSettingsMetadata(settings)
	}
	if sources, err := p.store.ListGuardrailRAGSources(ctx); err == nil && len(sources) > 0 {
		bundle.Metadata["rag_sources"] = pluginRAGSourcesMetadata(sources)
	}

	revision, err := tenantBundleRevision(bundle)
	if err != nil {
		return runtimeapi.TenantBundle{}, err
	}
	bundle.Revision = revision
	return bundle, nil
}

func (p *Plugin) resolvePolicyVersion(ctx context.Context, policy *tables.TableGuardrailPolicy) (*tables.TableGuardrailPolicyVersion, error) {
	if policy == nil {
		return nil, nil
	}
	if policy.ActiveVersionID != nil && strings.TrimSpace(*policy.ActiveVersionID) != "" {
		version, err := p.store.GetGuardrailPolicyVersion(ctx, *policy.ActiveVersionID)
		if err != nil || version != nil {
			return version, err
		}
	}
	versions, err := p.store.ListGuardrailPolicyVersions(ctx, policy.ID)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, nil
	}
	sort.SliceStable(versions, func(i, j int) bool {
		if versions[i].Version == versions[j].Version {
			return versions[i].CreatedAt.After(versions[j].CreatedAt)
		}
		return versions[i].Version > versions[j].Version
	})
	return &versions[0], nil
}

// tenantBundleRevision computes a structural hash from policy version IDs and
// provider IDs rather than marshaling the entire bundle to JSON. This is O(N)
// in the number of policies+providers vs O(bundle-size) for a full marshal,
// and produces no temporary allocations beyond the hash state.
func tenantBundleRevision(bundle runtimeapi.TenantBundle) (string, error) {
	h := sha256.New()
	h.Write([]byte(bundle.TenantID))
	for _, prov := range bundle.Providers {
		h.Write([]byte(prov.ID))
		h.Write([]byte(prov.ProviderType))
		if prov.Enabled {
			h.Write([]byte("1"))
		} else {
			h.Write([]byte("0"))
		}
	}
	for _, pol := range bundle.Policies {
		h.Write([]byte(pol.PolicyID))
		h.Write([]byte(pol.PolicyVersionID))
		h.Write([]byte(pol.EnforcementMode))
		if pol.Enabled {
			h.Write([]byte("1"))
		} else {
			h.Write([]byte("0"))
		}
		// Include TimeoutMs so a column-only edit (no new policy version)
		// triggers re-hydration and the runtime engine picks up the change.
		// Without this, raising timeout_ms on an existing policy used to be
		// invisible until the policy version was bumped - that's how the
		// "context deadline exceeded" entries kept appearing after the
		// 150 → 10000 ms migration ran but the runtime still served from a
		// cached bundle with the old value.
		h.Write([]byte(strconv.Itoa(pol.TimeoutMs)))
		// Same footgun rationale as TimeoutMs: an async→sync (or any other)
		// execution_mode flip from a migration or admin edit MUST invalidate
		// the cached bundle, otherwise applyExecutionModes keeps using the
		// stale mode from policyModes. The "mode=async on a sync wrapper"
		// header surfaced exactly this - the bundle revision hadn't changed
		// because the hash ignored ExecutionMode.
		if mode, ok := pol.Metadata["execution_mode"].(string); ok {
			h.Write([]byte(mode))
		}
	}
	for _, mcp := range bundle.MCPToolPolicies {
		h.Write([]byte(mcp.PolicyID))
		h.Write([]byte(mcp.ServerLabel))
		h.Write([]byte(mcp.ToolName))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func pluginRAGSettingsMetadata(settings *tables.TableGuardrailRAGSettings) map[string]any {
	if settings == nil {
		return nil
	}
	return map[string]any{
		"runtime_enforcement_enabled":  settings.RuntimeEnforcementEnabled,
		"async_scanning_enabled":       settings.AsyncScanningEnabled,
		"precomputed_scores_enabled":   settings.PrecomputedScoresEnabled,
		"policy_cache_enabled":         settings.PolicyCacheEnabled,
		"citation_enforcement_enabled": settings.CitationEnforcementEnabled,
		"shadow_mode_enabled":          settings.ShadowModeEnabled,
		"evidence_exports_enabled":     settings.EvidenceExportsEnabled,
		"default_action":               settings.DefaultAction,
		"max_runtime_latency_ms":       settings.MaxRuntimeLatencyMs,
		"last_rules_sync_at":           settings.LastRulesSyncAt,
		"last_scan_at":                 settings.LastScanAt,
	}
}

func pluginRAGSourcesMetadata(sources []tables.TableGuardrailRAGSource) map[string]any {
	result := make(map[string]any, len(sources))
	for _, source := range sources {
		result[source.ID] = map[string]any{
			"id":                source.ID,
			"name":              source.Name,
			"source_name":       source.Name,
			"connector":         source.Connector,
			"index_name":        source.IndexName,
			"owner":             source.Owner,
			"sensitivity":       source.Sensitivity,
			"retention_class":   source.RetentionClass,
			"trust_level":       source.TrustLevel,
			"trust_score":       pluginRAGTrustScore(source.TrustLevel),
			"tenant":            source.Tenant,
			"app_name":          source.AppName,
			"acl_tags":          append([]string(nil), source.ACLTags...),
			"labels":            append([]string(nil), source.Labels...),
			"document_count":    source.DocumentCount,
			"chunk_count":       source.ChunkCount,
			"health":            source.Health,
			"source_health":     source.Health,
			"quarantined":       source.Quarantined,
			"quarantine_reason": source.QuarantineReason,
			"last_scan_at":      source.LastScanAt,
		}
	}
	return result
}

func pluginRAGTrustScore(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "trusted":
		return 90
	case "medium", "monitored":
		return 70
	case "low", "untrusted":
		return 45
	default:
		return 80
	}
}

func (p *Plugin) evaluateRuntime(ctx context.Context, request *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	evalCtx, cancel := context.WithTimeout(ctx, p.runtimeTimeout)
	defer cancel()
	stop := trackGuardrailPhase(evalCtx, request)
	defer stop()

	// Eval cache fast path. Workspace switch + TTL + per-VK scope come from
	// the package-level atomic config (bridged from semantic_cache plugin on
	// every reload). Cache key bakes in policy_version + actor_role + vk_id
	// so a hit is always semantically safe to return; an out-of-scope VK
	// bypasses the cache entirely so a non-opted-in VK can never read or
	// write the shared store.
	cacheCfg := effectiveEvalCacheConfig()
	vkID, _ := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)
	cacheActive := cacheCfg.enabled && p.evalCache != nil && cacheCfg.vkAllowed(vkID)
	var cacheKey string
	if cacheActive {
		cacheKey = evalCacheKey(ctx, request)
		if cacheKey != "" {
			if cached := p.evalCache.lookup(cacheKey); cached != nil {
				return cached, nil
			}
		}
	}

	resp, err := p.runtimeClient.Evaluate(evalCtx, request)
	if err == nil && resp != nil && cacheKey != "" && cacheActive {
		p.evalCache.store(cacheKey, resp, cacheCfg.ttl)
	}
	return resp, err
}

// guardrailExecutionOutcome captures the post-mode-resolution view of an
// evaluation: what the request path should see (effective), and what the
// audit trail should record. The runtime engine produces a single
// aggregated decision; we re-aggregate using only sync findings so that
// shadow/async findings can be logged without blocking traffic.
type guardrailExecutionOutcome struct {
	effective    *runtimeapi.EvaluateResponse
	headerStatus string
	headerMode   string
	hadShadow    bool
	hadAsync     bool
	hadSync      bool
}

// applyExecutionModes splits findings by their source policy's execution
// mode, recomputes the effective decision from sync findings only, and
// stamps each finding's Details with its mode for the audit record.
//
// The runtime is unchanged - we treat its result as advisory and decide
// here whether each finding actually gates the request. This keeps the
// runtime contract narrow (it just evaluates) while letting the plugin
// layer own the operational rollout policy.
func (p *Plugin) applyExecutionModes(tenantID string, raw *runtimeapi.EvaluateResponse) guardrailExecutionOutcome {
	outcome := guardrailExecutionOutcome{
		effective:    raw,
		headerStatus: "pass",
		headerMode:   tables.GuardrailExecutionModeSync,
	}
	if raw == nil {
		return outcome
	}
	if len(raw.Findings) == 0 {
		// No findings - nothing to partition. Decision is whatever the
		// runtime returned (almost always "allow") and headerStatus
		// stays "pass".
		return outcome
	}
	syncFindings := make([]runtimeapi.Finding, 0, len(raw.Findings))
	nonEnforcingFindings := make([]runtimeapi.Finding, 0)
	worstNonEnforcingOutcome := ""
	worstNonEnforcingMode := ""
	for _, finding := range raw.Findings {
		mode := p.effectivePolicyMode(tenantID, finding.PolicyID)
		// Stamp every finding with the mode under which it was
		// recorded, so persistence and downstream consumers can tell
		// shadow/async hits apart from real enforcement.
		stamped := finding
		stamped.Details = cloneGuardrailMetadata(finding.Details)
		if stamped.Details == nil {
			stamped.Details = make(map[string]any, 1)
		}
		stamped.Details["execution_mode"] = mode
		switch mode {
		case tables.GuardrailExecutionModeAsync, tables.GuardrailExecutionModeShadow:
			nonEnforcingFindings = append(nonEnforcingFindings, stamped)
			if mode == tables.GuardrailExecutionModeShadow {
				outcome.hadShadow = true
			} else {
				outcome.hadAsync = true
			}
			if outcomeRank(stamped.Outcome) > outcomeRank(worstNonEnforcingOutcome) {
				worstNonEnforcingOutcome = stamped.Outcome
				worstNonEnforcingMode = mode
			}
		default:
			outcome.hadSync = true
			syncFindings = append(syncFindings, stamped)
		}
	}

	// Build the effective response: sync findings drive the gating
	// decision; non-enforcing findings ride along in Findings (so the
	// audit trail is complete) and in Metadata (so downstream readers
	// can spot them without scanning).
	effective := *raw
	effective.Findings = append([]runtimeapi.Finding{}, syncFindings...)
	effective.Findings = append(effective.Findings, nonEnforcingFindings...)
	if len(syncFindings) == 0 {
		// No sync findings means there is nothing to enforce. Override
		// the runtime's aggregated decision back to allow, and drop
		// any sanitized payload - redaction must never be applied
		// from a shadow/async policy because that would mutate the
		// request path while supposedly being non-enforcing.
		effective.Decision = "allow"
		effective.Reason = "Allowed: matching guardrails are in shadow or async mode"
		effective.SanitizedInput = ""
		effective.SanitizedOutput = ""
		effective.Redactions = nil
		effective.ApprovalRequired = false
	} else {
		decision, approval, reason := recomputeDecisionFromFindings(syncFindings, raw.Redactions)
		effective.Decision = decision
		effective.Reason = reason
		effective.ApprovalRequired = approval
		// If the sync subset doesn't itself want redaction, also
		// strip sanitized content. A redact outcome from a shadow
		// policy would otherwise silently rewrite the payload.
		if decision != "allow_with_redaction" {
			effective.SanitizedInput = ""
			effective.SanitizedOutput = ""
			effective.Redactions = nil
		}
	}
	if effective.Metadata == nil {
		effective.Metadata = make(map[string]any, 2)
	}
	if outcome.hadShadow || outcome.hadAsync {
		effective.Metadata["non_enforcing_finding_count"] = len(nonEnforcingFindings)
		effective.Metadata["worst_non_enforcing_outcome"] = worstNonEnforcingOutcome
		effective.Metadata["worst_non_enforcing_mode"] = worstNonEnforcingMode
	}
	outcome.effective = &effective

	// Header status reflects what the *user* should see:
	//   - blocked       → a sync policy denied/sandboxed.
	//   - redacted      → a sync policy redacted.
	//   - blocked-shadow → shadow/async would have blocked, but didn't.
	//   - flagged       → shadow/async produced a non-zero finding short of block.
	//   - pass          → nothing fired.
	switch effective.Decision {
	case "deny", "sandbox":
		outcome.headerStatus = "blocked"
	case "allow_with_redaction":
		outcome.headerStatus = "redacted"
	default:
		switch normalizedNonEnforcingOutcome(worstNonEnforcingOutcome) {
		case "deny", "sandbox":
			outcome.headerStatus = "blocked-shadow"
		case "redact":
			outcome.headerStatus = "redacted-shadow"
		case "":
			outcome.headerStatus = "pass"
		default:
			outcome.headerStatus = "flagged"
		}
	}
	switch {
	case outcome.hadSync && (outcome.hadShadow || outcome.hadAsync):
		outcome.headerMode = "mixed"
	case outcome.hadShadow:
		outcome.headerMode = tables.GuardrailExecutionModeShadow
	case outcome.hadAsync:
		outcome.headerMode = tables.GuardrailExecutionModeAsync
	default:
		outcome.headerMode = tables.GuardrailExecutionModeSync
	}
	return outcome
}

// recomputeDecisionFromFindings mirrors the runtime engine's decision
// aggregation so we can re-derive an "as if only these findings fired"
// decision after dropping shadow/async ones. Kept structurally close to
// the engine version on purpose; if the engine's rules drift we'll need
// to update both in lockstep.
func recomputeDecisionFromFindings(findings []runtimeapi.Finding, redactions []string) (string, bool, string) {
	severityRank := map[string]int{"allow": 0, "redact": 1, "sandbox": 2, "deny": 3}
	bestRank := 0
	bestSummary := ""
	for _, finding := range findings {
		outcome := normalizedNonEnforcingOutcome(finding.Outcome)
		if rank := severityRank[outcome]; rank > bestRank {
			bestRank = rank
			bestSummary = finding.Summary
		}
	}
	switch bestRank {
	case severityRank["deny"]:
		return "deny", false, bestSummary
	case severityRank["sandbox"]:
		return "sandbox", false, bestSummary
	case severityRank["redact"]:
		return "allow_with_redaction", false, bestSummary
	default:
		if len(redactions) > 0 {
			return "allow_with_redaction", false, "Content was sanitized by runtime redaction rules"
		}
		return "allow", false, "No guardrail violations detected"
	}
}

func normalizedNonEnforcingOutcome(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "block", "deny", "approval", "human_approval", "review":
		return "deny"
	case "sandbox":
		return "sandbox"
	case "redact", "allow_with_redaction":
		return "redact"
	default:
		return "allow"
	}
}

func outcomeRank(value string) int {
	switch normalizedNonEnforcingOutcome(value) {
	case "deny":
		return 3
	case "sandbox":
		return 2
	case "redact":
		return 1
	default:
		return 0
	}
}

// setGuardrailResponseHeaders piggybacks on the existing provider
// response-header forwarding mechanism (see GenericRouter.sendSuccess
// and friends, which copy DeepIntShieldContextKeyProviderResponseHeaders
// onto the outgoing fasthttp response). Reusing it means we don't need
// a new transport-layer hook.
func setGuardrailResponseHeaders(ctx *schemas.DeepIntShieldContext, status, mode string) {
	if ctx == nil || strings.TrimSpace(status) == "" {
		return
	}
	headers, _ := ctx.Value(schemas.DeepIntShieldContextKeyProviderResponseHeaders).(map[string]string)
	if headers == nil {
		headers = make(map[string]string, 2)
	}
	headers["x-deepintshield-guardrail-status"] = status
	if strings.TrimSpace(mode) != "" {
		headers["x-deepintshield-guardrail-mode"] = mode
	}
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, headers)
}

func trackGuardrailPhase(ctx context.Context, request *runtimeapi.EvaluateRequest) func() {
	if request == nil {
		return func() {}
	}
	switch request.Stage {
	case runtimeapi.StageInput:
		return schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseGuardrailInput)
	case runtimeapi.StageOutput:
		return schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseGuardrailOutput)
	case runtimeapi.StageMCP:
		return schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseGuardrailMCP)
	default:
		return func() {}
	}
}

func (p *Plugin) runtimeFailureLLMShortCircuit(err error) *schemas.LLMPluginShortCircuit {
	if p.failOpen {
		p.logger.Warn("[Guardrails] fail-open runtime error: %v", err)
		return nil
	}
	return &schemas.LLMPluginShortCircuit{Error: p.runtimeFailureDeepIntShieldError(err)}
}

func (p *Plugin) runtimeFailureMCPShortCircuit(err error) *schemas.MCPPluginShortCircuit {
	if p.failOpen {
		p.logger.Warn("[Guardrails] fail-open runtime error: %v", err)
		return nil
	}
	return &schemas.MCPPluginShortCircuit{Error: p.runtimeFailureDeepIntShieldError(err)}
}

func (p *Plugin) runtimeFailureDeepIntShieldError(err error) *schemas.DeepIntShieldError {
	if p.failOpen {
		p.logger.Warn("[Guardrails] fail-open runtime error: %v", err)
		return nil
	}
	status := 503
	allowFallbacks := false
	errType := "guardrail_runtime_unavailable"
	code := "guardrail_runtime_unavailable"
	return &schemas.DeepIntShieldError{
		IsDeepIntShieldError: true,
		StatusCode:           &status,
		AllowFallbacks:       &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errType,
			Code:    &code,
			Message: fmt.Sprintf("Guard runtime unavailable: %v", err),
			Error:   err,
		},
	}
}

func invalidGuardrailRequestError(err error) *schemas.DeepIntShieldError {
	status := 400
	allowFallbacks := false
	errType := "guardrail_request_not_allowed"
	code := "guardrail_request_not_allowed"
	message := "Raw input_guardrails/output_guardrails are restricted to the test lab simulation flow"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		message = err.Error()
	}
	return &schemas.DeepIntShieldError{
		IsDeepIntShieldError: true,
		StatusCode:           &status,
		AllowFallbacks:       &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errType,
			Code:    &code,
			Message: message,
			Error:   err,
		},
	}
}

func (p *Plugin) shortCircuitForLLMDecision(result *runtimeapi.EvaluateResponse, stage string) *schemas.LLMPluginShortCircuit {
	if result == nil {
		return nil
	}
	if deepintshieldErr := p.errorForDecision(result, stage); deepintshieldErr != nil {
		return &schemas.LLMPluginShortCircuit{Error: deepintshieldErr}
	}
	return nil
}

func (p *Plugin) shortCircuitForMCPDecision(result *runtimeapi.EvaluateResponse, stage string) *schemas.MCPPluginShortCircuit {
	if result == nil {
		return nil
	}
	if deepintshieldErr := p.errorForDecision(result, stage); deepintshieldErr != nil {
		return &schemas.MCPPluginShortCircuit{Error: deepintshieldErr}
	}
	return nil
}

func (p *Plugin) errorForDecision(result *runtimeapi.EvaluateResponse, stage string) *schemas.DeepIntShieldError {
	if result == nil {
		return nil
	}
	status := 403
	allowFallbacks := false
	var errType string
	var code string
	switch result.Decision {
	case "deny", "sandbox":
		errType = "guardrail_blocked"
		code = "guardrail_blocked"
	default:
		return nil
	}
	message := strings.TrimSpace(result.Reason)
	if message == "" {
		message = "Request blocked by DeepIntShield runtime guardrails"
	}
	return &schemas.DeepIntShieldError{
		IsDeepIntShieldError: true,
		StatusCode:           &status,
		AllowFallbacks:       &allowFallbacks,
		Error: &schemas.ErrorField{
			Type:    &errType,
			Code:    &code,
			Message: message,
		},
	}
}

// resolveEvaluatedPolicies returns the policy set the engine actually evaluated
// for this request, mirroring the in-engine resolution: request-attached policies
// take precedence (header-injected), then VK-bound policies via the context's
// guardrailPolicyIDsFromContext list, and finally the tenant's matched/default
// policies when no VK is in play. Callers pass the same context/request shape
// that hit Evaluate, so the persisted engine_source matches what the engine ran.
//
// Why this exists: persistEvaluation only ever saw `evalRequest.Policies` (the
// header-attached set), which is empty for the standard VK flow - the VK's
// policy IDs get attached via metadata["requested_policy_ids"] and resolved
// inside the engine. Without this resolver, computeEngineSource(nil) returned
// "" for every VK-bound Allow request, and AI Logs's Engine column fell back
// to the legacy join (decision.policy_id → bindings) - which only matches when
// findings fired, so clean Allow rows under an AI Models wrapper VK showed up
// as "Policy" instead of "AI Models".
func (p *Plugin) resolveEvaluatedPolicies(ctx context.Context, tenantID string, stage string, requestPolicies []runtimeapi.PolicyBundle) []runtimeapi.PolicyBundle {
	if len(requestPolicies) > 0 {
		return requestPolicies
	}
	if p == nil || tenantID == "" {
		return nil
	}
	// Read policy IDs from the raw context value rather than via the DIS-typed
	// helper. The async post-guard path detaches to a plain context.Context,
	// so a *schemas.DeepIntShieldContext assertion would fail and skip the
	// resolver entirely - leaving the output decision row with no engine tag.
	requestedIDs, _ := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs).([]string)
	if len(requestedIDs) == 0 {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	state, ok := p.tenantCache[tenantID]
	if !ok {
		return nil
	}
	normalizedStage := runtimeapi.NormalizeStage(stage)
	idSet := make(map[string]struct{}, len(requestedIDs))
	for _, id := range requestedIDs {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		idSet[trimmed] = struct{}{}
	}
	resolved := make([]runtimeapi.PolicyBundle, 0, len(idSet))
	for _, policy := range state.Bundle.Policies {
		if !policy.Enabled {
			continue
		}
		if !policyAppliesToStage(policy, normalizedStage) {
			continue
		}
		if _, ok := idSet[strings.TrimSpace(policy.PolicyID)]; !ok {
			continue
		}
		resolved = append(resolved, policy)
	}
	return resolved
}

// policyAppliesToStage mirrors the engine's stage-matching contract: prefer
// the policy's metadata.scopes array (the UI's multi-scope picker writes here)
// and fall back to policy.Scope (the legacy single-stage column). Without this,
// a policy attached to ["input","output","action","mcp","rag"] showed Scope=input
// in the bundle and the plugin's resolver excluded it from output-stage
// classification - the output decision row landed with policy_id=” and
// engine_source=”, which the AI Logs query then rolled up as "policy" (the
// legacy join's NULL-provider branch) and the page rendered "Mixed" for
// wrapper-only VKs.
func policyAppliesToStage(policy runtimeapi.PolicyBundle, stage string) bool {
	normalizedStage := runtimeapi.NormalizeStage(stage)
	if rawScopes, ok := policy.Metadata["scopes"]; ok {
		for _, scope := range toStringSliceForScopes(rawScopes) {
			if runtimeapi.NormalizeStage(scope) == normalizedStage {
				return true
			}
		}
		// metadata.scopes is authoritative when present - fall through to
		// the legacy column only when the metadata field is missing.
		return false
	}
	return runtimeapi.NormalizeStage(policy.Scope) == normalizedStage
}

func toStringSliceForScopes(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// computeEngineSource classifies the evaluated-policy set into one of the engine-column
// tags surfaced on the AI Logs Engine column. "ai_model" when every enabled policy is
// bound to a deepintshield_models provider, "policy" when none are, "mixed" when both
// kinds fired, "" when no policies evaluated. Persisted on the decision row so the
// classifier can answer correctly even on Allow-with-no-findings (policy_id stays empty
// in that case, which used to collapse every clean Allow into "Policy").
func computeEngineSource(policies []runtimeapi.PolicyBundle) string {
	var hasAI, hasPolicy bool
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		isAI := false
		for _, binding := range policy.ProviderBindings {
			if !binding.Enabled {
				continue
			}
			if binding.ProviderType == "deepintshield_models" {
				isAI = true
				break
			}
		}
		if isAI {
			hasAI = true
		} else {
			hasPolicy = true
		}
	}
	switch {
	case hasAI && hasPolicy:
		return "mixed"
	case hasAI:
		return "ai_model"
	case hasPolicy:
		return "policy"
	}
	return ""
}

func (p *Plugin) persistEvaluation(ctx context.Context, stage, requestID string, actor runtimeapi.Actor, provider, model, inputSummary, outputSummary, resourceID string, mcpCtx *runtimeapi.MCPContext, policies []runtimeapi.PolicyBundle, result *runtimeapi.EvaluateResponse) {
	if p == nil || p.evidenceStore == nil || result == nil {
		return
	}
	task := p.buildPersistenceTask(ctx, stage, requestID, actor, provider, model, inputSummary, outputSummary, resourceID, mcpCtx, policies, result)
	if task == nil {
		return
	}
	p.storeCacheSnapshot(ctx, stage, task, result)
	if !p.asyncPersist || p.persistQueue == nil {
		p.persistEvaluationTask(*task)
		return
	}
	select {
	case p.persistQueue <- *task:
	default:
		go p.persistEvaluationTask(*task)
	}
}

func (p *Plugin) buildPersistenceTask(ctx context.Context, stage, requestID string, actor runtimeapi.Actor, provider, model, inputSummary, outputSummary, resourceID string, mcpCtx *runtimeapi.MCPContext, policies []runtimeapi.PolicyBundle, result *runtimeapi.EvaluateResponse) *guardrailPersistenceTask {
	if p == nil || result == nil {
		return nil
	}
	traceID := uuid.NewString()
	trace := &logstore.GuardrailTrace{
		ID:            traceID,
		RequestID:     requestID,
		Stage:         stage,
		ActorType:     actor.Type,
		ActorID:       actor.ID,
		Model:         model,
		Provider:      provider,
		InputSummary:  truncateGuardrailText(inputSummary, 2000),
		OutputSummary: truncateGuardrailText(outputSummary, 2000),
		Decision:      result.Decision,
		DecisionChain: append([]string(nil), result.DecisionChain...),
		Metadata: map[string]any{
			"stage":       stage,
			"actor_role":  actor.Role,
			"customer_id": actor.CustomerID,
			"team_id":     actor.TeamID,
		},
	}
	// Stamp the request type (set on ctx by the Pre/Post hooks) into the trace
	// metadata so the Multimodal analytics tab can classify the trace's modality.
	if dsCtx, ok := ctx.(*schemas.DeepIntShieldContext); ok {
		if rt, ok := dsCtx.Value(guardrailRequestTypeKey).(string); ok && rt != "" {
			trace.Metadata["request_type"] = rt
		}
	}
	if mcpCtx != nil {
		trace.Metadata["server_label"] = mcpCtx.ServerLabel
		trace.Metadata["tool_name"] = mcpCtx.ToolName
		trace.Metadata["action_class"] = mcpCtx.ActionClass
		trace.Metadata["domains"] = mcpCtx.Domains
	}
	// `policies` here is the request-attached set (header injections, mostly
	// empty for normal VK traffic). The engine's actual evaluated set also
	// includes the VK's bound policies via metadata["requested_policy_ids"].
	// Resolve them now so engine_source reflects what the engine ran - without
	// this, every VK-bound Allow with no findings persisted engine_source=""
	// and AI Logs's Engine column fell back to "Policy" via the legacy join.
	tenantIDForEngine := ""
	if dsCtx, ok := ctx.(*schemas.DeepIntShieldContext); ok {
		tenantIDForEngine = guardrailTenantID(dsCtx)
	}
	evaluatedPolicies := p.resolveEvaluatedPolicies(ctx, tenantIDForEngine, stage, policies)
	decision := &logstore.GuardrailDecision{
		ID:               uuid.NewString(),
		RequestID:        requestID,
		TraceID:          traceID,
		Stage:            stage,
		Decision:         result.Decision,
		Reason:           truncateGuardrailText(result.Reason, 2000),
		ApprovalRequired: result.ApprovalRequired,
		LatencyMs:        result.LatencyMs,
		Redactions:       append([]string(nil), result.Redactions...),
		DecisionChain:    append([]string(nil), result.DecisionChain...),
		EngineSource:     computeEngineSource(evaluatedPolicies),
	}
	if len(result.Findings) > 0 {
		decision.PolicyID = result.Findings[0].PolicyID
		decision.PolicyVersionID = result.Findings[0].PolicyVersionID
	} else if len(evaluatedPolicies) > 0 {
		// Stamp the first evaluated policy on Allow-no-findings rows so the
		// existing legacy join still classifies correctly even if a future
		// refactor drops engine_source. Picks the first VK-bound policy; with
		// multiple bindings the engine_source string is the source of truth.
		decision.PolicyID = evaluatedPolicies[0].PolicyID
		decision.PolicyVersionID = evaluatedPolicies[0].PolicyVersionID
	}
	findings := make([]*logstore.GuardrailFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		findings = append(findings, &logstore.GuardrailFinding{
			ID:              uuid.NewString(),
			RequestID:       requestID,
			TraceID:         traceID,
			Stage:           stage,
			PolicyID:        finding.PolicyID,
			PolicyVersionID: finding.PolicyVersionID,
			ProviderID:      finding.ProviderID,
			Category:        finding.Category,
			Severity:        finding.Severity,
			Confidence:      finding.Confidence,
			Outcome:         finding.Outcome,
			Summary:         truncateGuardrailText(finding.Summary, 2000),
			ActorType:       actor.Type,
			ActorID:         actor.ID,
			ResourceType:    guardrailResourceType(stage, mcpCtx),
			ResourceID:      resourceID,
			Details:         cloneGuardrailMetadata(finding.Details),
		})
	}
	return &guardrailPersistenceTask{
		tenantID: guardrailTenantIDContext(ctx),
		trace:    trace,
		decision: decision,
		findings: findings,
	}
}

func (p *Plugin) storeCacheSnapshot(ctx context.Context, stage string, task *guardrailPersistenceTask, result *runtimeapi.EvaluateResponse) {
	deepintshieldCtx, ok := ctx.(*schemas.DeepIntShieldContext)
	if !ok || deepintshieldCtx == nil || task == nil || task.trace == nil || task.decision == nil || result == nil {
		return
	}

	snapshot, _ := CacheSnapshotFromContext(deepintshieldCtx)
	if snapshot == nil {
		snapshot = &CacheSnapshot{}
	}

	stageSnapshot := &CacheStageSnapshot{
		Trace:           *task.trace,
		Decision:        *task.decision,
		Findings:        cloneGuardrailFindings(task.findings),
		SanitizedInput:  strings.TrimSpace(result.SanitizedInput),
		SanitizedOutput: strings.TrimSpace(result.SanitizedOutput),
	}

	switch runtimeapi.NormalizeStage(stage) {
	case runtimeapi.StageOutput:
		snapshot.Output = stageSnapshot
	default:
		snapshot.Input = stageSnapshot
	}

	deepintshieldCtx.SetValue(guardrailCacheSnapshotKey, snapshot)
}

func cloneGuardrailFindings(findings []*logstore.GuardrailFinding) []logstore.GuardrailFinding {
	if len(findings) == 0 {
		return nil
	}
	cloned := make([]logstore.GuardrailFinding, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		copyFinding := *finding
		copyFinding.Details = cloneGuardrailMetadata(copyFinding.Details)
		cloned = append(cloned, copyFinding)
	}
	return cloned
}

func (p *Plugin) persistenceWorker() {
	defer p.persistWorkers.Done()
	for task := range p.persistQueue {
		p.persistEvaluationTask(task)
	}
}

func (p *Plugin) persistEvaluationTask(task guardrailPersistenceTask) {
	// Called both from the worker pool and inline `go p.persistEvaluationTask(...)`
	// when the queue is full. Either way it runs detached, so a panic here
	// would otherwise crash the gateway.
	defer safegoroutine.Recover(p.logger, "guardrails.persist-evaluation")
	if p == nil || p.evidenceStore == nil {
		return
	}
	persistCtx, cancel := context.WithTimeout(guardrailPersistenceContext(task.tenantID), p.persistTimeout)
	defer cancel()
	if err := p.evidenceStore.CreateGuardrailTrace(persistCtx, task.trace); err != nil {
		p.logger.Warn("[Guardrails] failed to persist trace: %v", err)
		return
	}
	if err := p.evidenceStore.CreateGuardrailDecision(persistCtx, task.decision); err != nil {
		p.logger.Warn("[Guardrails] failed to persist decision: %v", err)
		return
	}
	for _, finding := range task.findings {
		if err := p.evidenceStore.CreateGuardrailFinding(persistCtx, finding); err != nil {
			p.logger.Warn("[Guardrails] failed to persist finding: %v", err)
		}
	}
}

func guardrailPersistenceContext(tenantID string) context.Context {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = defaultTenantID
	}
	return context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
}

func guardrailTenantIDContext(ctx context.Context) string {
	if ctx == nil {
		return defaultTenantID
	}
	if tenantID, ok := ctx.Value(schemas.DeepIntShieldContextKeyTenantID).(string); ok {
		if trimmed := strings.TrimSpace(tenantID); trimmed != "" {
			return trimmed
		}
	}
	return defaultTenantID
}

func guardrailResourceType(stage string, mcpCtx *runtimeapi.MCPContext) string {
	if mcpCtx != nil && strings.TrimSpace(mcpCtx.ToolName) != "" {
		return "mcp_tool"
	}
	return stage
}

func guardrailRequestedAction(result *runtimeapi.EvaluateResponse, mcpCtx *runtimeapi.MCPContext) string {
	if mcpCtx != nil && strings.TrimSpace(mcpCtx.ActionClass) != "" {
		return mcpCtx.ActionClass
	}
	return result.Decision
}

func buildActor(ctx *schemas.DeepIntShieldContext) runtimeapi.Actor {
	actor := runtimeapi.Actor{
		Type: "service_account",
		ID:   strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)),
		Role: strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserRole)),
	}
	if userID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserID)); userID != "" {
		actor.Type = "human_user"
		actor.ID = userID
	}
	if actor.ID == "" {
		actor.ID = "anonymous"
	}
	actor.CustomerID = strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceCustomerID))
	actor.TeamID = strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceTeamID))
	return actor
}

func buildMCPContext(req *schemas.DeepIntShieldMCPRequest) *runtimeapi.MCPContext {
	if req == nil {
		return nil
	}
	fullToolName := strings.TrimSpace(req.GetToolName())
	serverLabel := ""
	toolName := fullToolName
	if idx := strings.Index(fullToolName, "-"); idx > 0 {
		serverLabel = fullToolName[:idx]
		toolName = fullToolName[idx+1:]
	}
	return &runtimeapi.MCPContext{
		ServerLabel: serverLabel,
		ToolName:    toolName,
		ActionClass: inferMCPActionClass(toolName),
	}
}

func (p *Plugin) attachRuntimePolicies(ctx *schemas.DeepIntShieldContext, stage string, metadata map[string]any) ([]runtimeapi.PolicyBundle, map[string]any) {
	requestPolicies, mode, err := requestAttachedPolicies(ctx, stage)
	if err != nil {
		requestPolicies = nil
		mode = requestGuardrailsModeMerge
	}
	requestedPolicyIDs := guardrailPolicyIDsFromContext(ctx)
	virtualKeyID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID))
	// Skip tenant-hydrated policy merging when a VK is in play AND that VK
	// has explicitly-attached guardrails. The VK's explicit policy bindings
	// are the COMPLETE set for that VK; tenant fallback would otherwise run
	// unrelated policies (e.g. a regex dev_policy firing on a VK that only
	// opted into the AI Models wrapper).
	//
	// CRUCIAL CARVE-OUT: when the VK has NO attached guardrails we do NOT
	// skip - the deterministic DEFAULT policy (IsDefault, the always-on
	// PII/regex baseline) must still apply so an out-of-the-box VK gets the
	// same protection the `deepintshield` SDK expects on every inference path
	// (chat / RAG / agent / MCP). The engine's selectDefaultPolicies path
	// only runs the IsDefault baseline here - non-default tenant policies are
	// still gated behind explicit VK attachment - so a bare VK is protected
	// without silently inheriting every workspace policy.
	//
	// __bf_vk_has_guards is stamped by the VK auth middleware and is true
	// only when len(vk.GuardrailPolicies) > 0.
	vkHasAttachedGuards := deepintshield.GetBoolFromContext(ctx, schemas.DeepIntShieldContextKey("__bf_vk_has_guards"))
	if virtualKeyID != "" && vkHasAttachedGuards {
		if metadata == nil {
			metadata = make(map[string]any, 1)
		}
		metadata["skip_tenant_guardrails"] = true
	}
	if mode != requestGuardrailsModeReplace {
		if len(requestedPolicyIDs) > 0 {
			if metadata == nil {
				metadata = make(map[string]any, 2)
			}
			metadata["requested_policy_ids"] = requestedPolicyIDs
			// Policies requested by ID are resolved and merged WITH the tenant's
			// configured policies downstream. Signal that here so the merge still
			// happens when no inline policies are supplied (the early return below).
			metadata["merge_tenant_policies"] = true
		}
	}
	if mode == requestGuardrailsModeReplace && len(requestPolicies) > 0 {
		return requestPolicies, metadata
	}
	if len(requestPolicies) == 0 {
		return nil, metadata
	}
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata["merge_tenant_policies"] = true
	return requestPolicies, metadata
}

func runtimeMetadata(ctx *schemas.DeepIntShieldContext, base map[string]any) map[string]any {
	metadata := make(map[string]any, len(base)+8)
	for key, value := range base {
		metadata[key] = value
	}
	if headers := requestHeaders(ctx); len(headers) > 0 {
		metadata["request_headers"] = headers
		if app := firstRequestHeader(headers, "x-bf-app", "x-app-id", "x-application-id"); app != "" {
			metadata["app"] = app
		}
		if domainPackID := firstRequestHeader(headers, "x-bf-domain-pack", "x-domain-pack"); domainPackID != "" {
			metadata["domain_pack_id"] = domainPackID
		}
		if domainPackIDs := splitRequestHeader(headers, "x-bf-domain-packs", "x-domain-packs"); len(domainPackIDs) > 0 {
			metadata["domain_pack_ids"] = domainPackIDs
		}
	}
	if tenantID := guardrailTenantID(ctx); tenantID != "" {
		metadata["tenant_id"] = tenantID
		metadata["workspace_id"] = tenantID
		metadata["workspace"] = tenantID
	}
	if route := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyURLPath)); route != "" {
		metadata["route"] = route
		metadata["url_path"] = route
	}
	if customerID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceCustomerID)); customerID != "" {
		metadata["customer_id"] = customerID
	}
	if teamID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceTeamID)); teamID != "" {
		metadata["team_id"] = teamID
	}
	if virtualKeyID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)); virtualKeyID != "" {
		metadata["virtual_key_id"] = virtualKeyID
	}
	if virtualKeyName := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyName)); virtualKeyName != "" {
		metadata["virtual_key_name"] = virtualKeyName
	}
	if actorRole := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserRole)); actorRole != "" {
		metadata["actor_role"] = actorRole
	}
	return metadata
}

func guardrailPolicyIDsFromContext(ctx *schemas.DeepIntShieldContext) []string {
	if ctx == nil {
		return nil
	}
	rawPolicyIDs, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs).([]string)
	if !ok || len(rawPolicyIDs) == 0 {
		return nil
	}
	policyIDs := make([]string, 0, len(rawPolicyIDs))
	seen := make(map[string]struct{}, len(rawPolicyIDs))
	for _, policyID := range rawPolicyIDs {
		trimmedPolicyID := strings.TrimSpace(policyID)
		if trimmedPolicyID == "" {
			continue
		}
		if _, ok := seen[trimmedPolicyID]; ok {
			continue
		}
		seen[trimmedPolicyID] = struct{}{}
		policyIDs = append(policyIDs, trimmedPolicyID)
	}
	return policyIDs
}

func runtimePolicyMetadata(policy tables.TableGuardrailPolicy) map[string]any {
	metadata := cloneGuardrailMetadata(policy.Metadata)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	// Pass execution mode through to the runtime bundle metadata so
	// downstream observability can surface mode-tagged findings even
	// before the runtime engine itself starts honoring the field.
	mode := strings.ToLower(strings.TrimSpace(policy.ExecutionMode))
	if mode == "" {
		mode = tables.GuardrailExecutionModeSync
	}
	metadata["execution_mode"] = mode
	if policy.ShadowUntil != nil {
		metadata["shadow_until"] = policy.ShadowUntil.UTC().Format(time.RFC3339)
	}
	return metadata
}

func firstRequestHeader(headers map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(headers[strings.ToLower(strings.TrimSpace(key))]); value != "" {
			return value
		}
	}
	return ""
}

func splitRequestHeader(headers map[string]string, keys ...string) []string {
	for _, key := range keys {
		raw := strings.TrimSpace(headers[strings.ToLower(strings.TrimSpace(key))])
		if raw == "" {
			continue
		}
		parts := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == '\n'
		})
		result := make([]string, 0, len(parts))
		seen := make(map[string]struct{}, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			key := strings.ToLower(trimmed)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, trimmed)
		}
		return result
	}
	return nil
}

func cloneGuardrailMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	copy := make(map[string]any, len(metadata))
	for key, value := range metadata {
		copy[key] = value
	}
	return copy
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func inferMCPActionClass(toolName string) string {
	toolName = strings.ToLower(strings.TrimSpace(toolName))
	switch {
	case strings.Contains(toolName, "delete"), strings.Contains(toolName, "drop"), strings.Contains(toolName, "remove"):
		return "destructive"
	case strings.Contains(toolName, "exec"), strings.Contains(toolName, "shell"), strings.Contains(toolName, "code"):
		return "exec"
	case strings.Contains(toolName, "http"), strings.Contains(toolName, "fetch"), strings.Contains(toolName, "web"), strings.Contains(toolName, "network"):
		return "network"
	case strings.Contains(toolName, "write"), strings.Contains(toolName, "create"), strings.Contains(toolName, "update"), strings.Contains(toolName, "edit"):
		return "write"
	default:
		return "read"
	}
}

func extractRequestInput(req *schemas.DeepIntShieldRequest) string {
	switch {
	case req == nil:
		return ""
	case req.ChatRequest != nil:
		return chatMessagesText(req.ChatRequest.Input)
	case req.ResponsesRequest != nil:
		return responsesMessagesText(req.ResponsesRequest.Input, req.ResponsesRequest.Params)
	case req.TextCompletionRequest != nil && req.TextCompletionRequest.Input != nil:
		if req.TextCompletionRequest.Input.PromptStr != nil {
			return *req.TextCompletionRequest.Input.PromptStr
		}
		return strings.Join(req.TextCompletionRequest.Input.PromptArray, "\n")
	case req.PassthroughRequest != nil:
		return string(req.PassthroughRequest.Body)
	case req.ImageGenerationRequest != nil:
		var parts []string
		if req.ImageGenerationRequest.Input != nil {
			parts = append(parts, req.ImageGenerationRequest.Input.Prompt)
		}
		if req.ImageGenerationRequest.Params != nil && req.ImageGenerationRequest.Params.NegativePrompt != nil {
			parts = append(parts, *req.ImageGenerationRequest.Params.NegativePrompt)
		}
		return joinGuardrailText(parts)
	case req.ImageEditRequest != nil:
		var parts []string
		if req.ImageEditRequest.Input != nil {
			parts = append(parts, req.ImageEditRequest.Input.Prompt)
			// Source images may carry embedded text (PNG/JPEG metadata,
			// watermarks, rendered text) that the bounded, cached attachment
			// extractor surfaces - catching text-in-image injection/PII in the
			// asset being edited. Binary pixels themselves are a later phase.
			// Bounded by image count (maxRequestAttachments) AND an aggregate
			// emitted-text ceiling so a request with many images cannot blow up
			// the guard payload or wall-time.
			extracted := 0
			for i, img := range req.ImageEditRequest.Input.Images {
				if i >= maxRequestAttachments || extracted >= maxImageEditExtractText {
					break
				}
				t := extractAttachmentBytesText(img.Image)
				if t == "" {
					continue
				}
				if extracted+len(t) > maxImageEditExtractText {
					t = t[:maxImageEditExtractText-extracted]
				}
				extracted += len(t)
				parts = append(parts, t)
			}
		}
		if req.ImageEditRequest.Params != nil && req.ImageEditRequest.Params.NegativePrompt != nil {
			parts = append(parts, *req.ImageEditRequest.Params.NegativePrompt)
		}
		return joinGuardrailText(parts)
	case req.ImageVariationRequest != nil:
		// Image variation has no text prompt - only a source image. Surface any
		// text embedded in that image; the raw bytes never reach json.Marshal.
		var parts []string
		if req.ImageVariationRequest.Input != nil {
			if t := extractAttachmentBytesText(req.ImageVariationRequest.Input.Image.Image); t != "" {
				parts = append(parts, t)
			}
		}
		return joinGuardrailText(parts)
	case req.SpeechRequest != nil:
		var parts []string
		if req.SpeechRequest.Input != nil {
			parts = append(parts, req.SpeechRequest.Input.Input)
		}
		if req.SpeechRequest.Params != nil {
			parts = append(parts, req.SpeechRequest.Params.Instructions)
		}
		return joinGuardrailText(parts)
	case req.EmbeddingRequest != nil && req.EmbeddingRequest.Input != nil:
		if req.EmbeddingRequest.Input.Text != nil {
			return *req.EmbeddingRequest.Input.Text
		}
		return joinGuardrailText(req.EmbeddingRequest.Input.Texts)
	case req.RerankRequest != nil:
		parts := []string{req.RerankRequest.Query}
		for _, d := range req.RerankRequest.Documents {
			parts = append(parts, d.Text)
		}
		return joinGuardrailText(parts)
	case req.VideoGenerationRequest != nil:
		var parts []string
		if req.VideoGenerationRequest.Input != nil {
			parts = append(parts, req.VideoGenerationRequest.Input.Prompt)
		}
		if req.VideoGenerationRequest.Params != nil && req.VideoGenerationRequest.Params.NegativePrompt != nil {
			parts = append(parts, *req.VideoGenerationRequest.Params.NegativePrompt)
		}
		return joinGuardrailText(parts)
	case req.VideoRemixRequest != nil:
		// Remix carries only the prompt (Input is *VideoGenerationInput, no
		// Params). Input.InputReference is a base64 data-URL of the source
		// video/image - binary, intentionally not inlined into the guard text
		// (which is why an explicit case is required: the json.Marshal default
		// would otherwise serialize that base64 blob into Content.Input).
		var parts []string
		if req.VideoRemixRequest.Input != nil {
			parts = append(parts, req.VideoRemixRequest.Input.Prompt)
		}
		return joinGuardrailText(parts)
	case req.TranscriptionRequest != nil:
		// The audio payload carries no request-side text; the transcript is
		// produced on the response and guarded via extractResponseOutput.
		// Speech-to-text extraction of the input audio is a later phase.
		return ""
	default:
		raw, _ := json.Marshal(req)
		return string(raw)
	}
}

// joinGuardrailText concatenates the non-empty parts with newlines, trimming the
// result. Used to assemble the text payload extracted from multimodal requests
// (image/audio/video prompts) into a single string for guardrail evaluation.
func joinGuardrailText(parts []string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}

// guardrailRequestTypeKey stashes the request type on the context so the
// async persistence path (buildPersistenceTask) can stamp it into the trace
// metadata. The Multimodal analytics tab classifies a trace's modality from
// metadata.request_type, so without this the tab would never populate.
const guardrailRequestTypeKey schemas.DeepIntShieldContextKey = "deepintshield-guardrail-request-type"

// guardrailsModalityInlineBytes controls whether raw attachment bytes are
// inlined into the guard EvaluateRequest (GUARDRAILS_MODALITY_INLINE_BYTES).
// Default OFF: attachments carry only kind/MIME/content-hash metadata, keeping
// the guard payload small. Operators turn it on (together with the guard's
// DEEPINTSHIELD_GUARD_MODALITY_EXTRACT) when they want the centralized,
// horizontally-scalable guard service to run heavy extraction over the bytes.
var guardrailsModalityInlineBytes = os.Getenv("GUARDRAILS_MODALITY_INLINE_BYTES") == "true"

// maxRequestAttachments bounds how many binary artifacts are forwarded to the
// guard per request, keeping payload and extraction work predictable.
const maxRequestAttachments = 16

// maxImageEditExtractText caps the aggregate text extracted from all source
// images of a single image-edit request, so a request bundling many images
// cannot inflate the guard payload or wall-time without bound.
const maxImageEditExtractText = 1 * 1024 * 1024

// extractRequestAttachments collects the binary artifacts carried by the
// dedicated multimodal request types (image-edit source images, transcription
// audio, image-generation reference images) into the guard Attachments
// contract. Each attachment is fingerprinted (sha256) for dedup; raw bytes are
// inlined only when guardrailsModalityInlineBytes is set. Returns nil when the
// multimodal feature is off - the common case, zero allocation/overhead.
//
// Chat request attachments are intentionally NOT duplicated here: their text is
// already folded into Content.Input inline by chatMessagesText, so forwarding
// them again would double the extraction work.
func extractRequestAttachments(req *schemas.DeepIntShieldRequest) []runtimeapi.Attachment {
	if !guardrailsMultimodalEnabled || req == nil {
		return nil
	}
	var out []runtimeapi.Attachment
	add := func(kind string, data []byte) {
		if len(data) == 0 || len(out) >= maxRequestAttachments {
			return
		}
		sum := sha256.Sum256(data)
		att := runtimeapi.Attachment{
			Kind: kind,
			Role: runtimeapi.AttachmentRoleInput,
			Hash: hex.EncodeToString(sum[:]),
		}
		if guardrailsModalityInlineBytes {
			att.Data = data
		}
		out = append(out, att)
	}

	switch {
	case req.ImageEditRequest != nil && req.ImageEditRequest.Input != nil:
		for _, img := range req.ImageEditRequest.Input.Images {
			add(runtimeapi.AttachmentKindImage, img.Image)
		}
	case req.ImageVariationRequest != nil && req.ImageVariationRequest.Input != nil:
		add(runtimeapi.AttachmentKindImage, req.ImageVariationRequest.Input.Image.Image)
	case req.TranscriptionRequest != nil && req.TranscriptionRequest.Input != nil:
		add(runtimeapi.AttachmentKindAudio, req.TranscriptionRequest.Input.File)
	}
	return out
}

// extractResponseAttachments collects the generated binary artifacts on the
// output side - image-generation images (whole or streamed partial/final
// events), TTS audio (whole or stream deltas), generated video - into the guard
// Attachments contract (Role=output) so the modality detector stage can inspect
// them before the artifact is released (Phase 4 generated-artifact output
// guarding). Streamed artifacts arrive as multiple chunks; the sha256 dedup
// cache drops exact repeats so duplicate frames aren't re-guarded. Returns nil
// when the multimodal feature is off.
//
// base64 payloads are decoded to bytes for hashing/dedup; raw bytes are only
// inlined into the guard request when guardrailsModalityInlineBytes is set.
// URL-only artifacts are forwarded by reference (Ref) without fetching.
func extractResponseAttachments(resp *schemas.DeepIntShieldResponse) []runtimeapi.Attachment {
	if !guardrailsMultimodalEnabled || resp == nil {
		return nil
	}
	var out []runtimeapi.Attachment
	addBytes := func(kind string, data []byte) {
		if len(data) == 0 || len(out) >= maxRequestAttachments {
			return
		}
		sum := sha256.Sum256(data)
		att := runtimeapi.Attachment{
			Kind: kind,
			Role: runtimeapi.AttachmentRoleOutput,
			Hash: hex.EncodeToString(sum[:]),
		}
		if guardrailsModalityInlineBytes {
			att.Data = data
		}
		out = append(out, att)
	}
	addB64 := func(kind, b64 string) {
		if b64 = strings.TrimSpace(b64); b64 == "" {
			return
		}
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			addBytes(kind, decoded)
		}
	}
	addRef := func(kind, ref string) {
		if ref = strings.TrimSpace(ref); ref == "" || len(out) >= maxRequestAttachments {
			return
		}
		out = append(out, runtimeapi.Attachment{Kind: kind, Role: runtimeapi.AttachmentRoleOutput, Ref: ref})
	}

	switch {
	case resp.ImageGenerationResponse != nil:
		for _, d := range resp.ImageGenerationResponse.Data {
			if d.B64JSON != "" {
				addB64(runtimeapi.AttachmentKindImage, d.B64JSON)
			} else if d.URL != "" {
				addRef(runtimeapi.AttachmentKindImage, d.URL)
			}
		}
	case resp.ImageGenerationStreamResponse != nil:
		// Streamed image events arrive as multiple chunks (partial frames then a
		// completed event). The sha256 dedup cache drops exact repeats; partial
		// frames are distinct images and are guarded as they arrive. Error
		// events carry no artifact.
		r := resp.ImageGenerationStreamResponse
		if r.Error == nil {
			if r.B64JSON != "" {
				addB64(runtimeapi.AttachmentKindImage, r.B64JSON)
			} else if r.URL != "" {
				addRef(runtimeapi.AttachmentKindImage, r.URL)
			}
		}
	case resp.SpeechResponse != nil:
		if len(resp.SpeechResponse.Audio) > 0 {
			addBytes(runtimeapi.AttachmentKindAudio, resp.SpeechResponse.Audio)
		} else if resp.SpeechResponse.AudioBase64 != nil {
			addB64(runtimeapi.AttachmentKindAudio, *resp.SpeechResponse.AudioBase64)
		}
	case resp.SpeechStreamResponse != nil:
		// Audio deltas arrive as multiple byte slices; each is guarded (dedup
		// drops exact repeats) so cross-chunk audio content is covered.
		if len(resp.SpeechStreamResponse.Audio) > 0 {
			addBytes(runtimeapi.AttachmentKindAudio, resp.SpeechStreamResponse.Audio)
		}
	case resp.VideoGenerationResponse != nil:
		for _, v := range resp.VideoGenerationResponse.Videos {
			switch {
			case v.Base64Data != nil && *v.Base64Data != "":
				addB64(runtimeapi.AttachmentKindVideo, *v.Base64Data)
			case v.URL != nil && *v.URL != "":
				addRef(runtimeapi.AttachmentKindVideo, *v.URL)
			}
		}
	}
	return out
}

func extractResponseOutput(resp *schemas.DeepIntShieldResponse) string {
	switch {
	case resp == nil:
		return ""
	case resp.TextCompletionResponse != nil:
		if len(resp.TextCompletionResponse.Choices) > 0 && resp.TextCompletionResponse.Choices[0].TextCompletionResponseChoice != nil && resp.TextCompletionResponse.Choices[0].TextCompletionResponseChoice.Text != nil {
			return *resp.TextCompletionResponse.Choices[0].TextCompletionResponseChoice.Text
		}
	case resp.ChatResponse != nil:
		if len(resp.ChatResponse.Choices) > 0 && resp.ChatResponse.Choices[0].ChatNonStreamResponseChoice != nil && resp.ChatResponse.Choices[0].ChatNonStreamResponseChoice.Message != nil {
			return chatMessagesText([]schemas.ChatMessage{*resp.ChatResponse.Choices[0].ChatNonStreamResponseChoice.Message})
		}
	case resp.ResponsesResponse != nil:
		return responsesMessagesOnlyText(resp.ResponsesResponse.Output)
	case resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Delta != nil:
		return strings.TrimSpace(*resp.ResponsesStreamResponse.Delta)
	case resp.TranscriptionResponse != nil:
		// Speech-to-text output: the transcript is plain text and is guarded
		// directly. This is the response side of a TranscriptionRequest.
		return resp.TranscriptionResponse.Text
	case resp.TranscriptionStreamResponse != nil:
		if resp.TranscriptionStreamResponse.Delta != nil {
			return strings.TrimSpace(*resp.TranscriptionStreamResponse.Delta)
		}
		return resp.TranscriptionStreamResponse.Text
	case resp.ImageGenerationResponse != nil:
		// The binary images are guarded via output Attachments; the
		// safety-relevant text here is the provider's revised prompt(s).
		var parts []string
		for _, d := range resp.ImageGenerationResponse.Data {
			parts = append(parts, d.RevisedPrompt)
		}
		return joinGuardrailText(parts)
	case resp.VideoGenerationResponse != nil:
		// Video bytes/URLs are guarded via output Attachments; the echoed
		// prompt is the safety-relevant text.
		return joinGuardrailText([]string{resp.VideoGenerationResponse.Prompt})
	case resp.ImageGenerationStreamResponse != nil:
		// Streamed image events carry the revised prompt on the completed
		// event; the image bytes are guarded via output Attachments.
		return joinGuardrailText([]string{resp.ImageGenerationStreamResponse.RevisedPrompt})
	case resp.SpeechResponse != nil,
		resp.SpeechStreamResponse != nil,
		resp.EmbeddingResponse != nil,
		resp.RerankResponse != nil:
		// Generated-artifact / vector responses carry binary or numeric data,
		// not safety-relevant text. Return empty so the default json.Marshal
		// fallback below never serializes binary payloads (audio/image base64)
		// into the guard input. The artifacts themselves are guarded via the
		// output Attachments contract (extractResponseAttachments).
		return ""
	}
	raw, _ := json.Marshal(resp)
	return string(raw)
}

func extractMCPInput(req *schemas.DeepIntShieldMCPRequest) string {
	if req == nil {
		return ""
	}
	if req.ChatAssistantMessageToolCall != nil {
		return req.ChatAssistantMessageToolCall.Function.Arguments
	}
	if req.ResponsesToolMessage != nil && req.ResponsesToolMessage.Arguments != nil {
		return *req.ResponsesToolMessage.Arguments
	}
	raw, _ := json.Marshal(req.GetToolArguments())
	return string(raw)
}

func extractMCPOutput(resp *schemas.DeepIntShieldMCPResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatMessage != nil {
		return chatMessagesText([]schemas.ChatMessage{*resp.ChatMessage})
	}
	if resp.ResponsesMessage != nil {
		return responsesMessagesOnlyText([]schemas.ResponsesMessage{*resp.ResponsesMessage})
	}
	raw, _ := json.Marshal(resp)
	return string(raw)
}

func rewriteRequestInput(req *schemas.DeepIntShieldRequest, sanitized string) bool {
	switch {
	case req == nil:
		return false
	case req.TextCompletionRequest != nil && req.TextCompletionRequest.Input != nil && req.TextCompletionRequest.Input.PromptStr != nil:
		req.TextCompletionRequest.Input.PromptStr = schemas.Ptr(sanitized)
		return true
	case req.ChatRequest != nil && len(req.ChatRequest.Input) == 1:
		req.ChatRequest.Input[0].Content = &schemas.ChatMessageContent{ContentStr: schemas.Ptr(sanitized)}
		return true
	case req.ResponsesRequest != nil && len(req.ResponsesRequest.Input) == 1:
		req.ResponsesRequest.Input[0].Content = &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr(sanitized)}
		return true
	default:
		return false
	}
}

func rewriteResponseOutput(resp *schemas.DeepIntShieldResponse, sanitized string) {
	switch {
	case resp == nil:
		return
	case resp.TextCompletionResponse != nil && len(resp.TextCompletionResponse.Choices) > 0:
		if resp.TextCompletionResponse.Choices[0].TextCompletionResponseChoice == nil {
			resp.TextCompletionResponse.Choices[0].TextCompletionResponseChoice = &schemas.TextCompletionResponseChoice{}
		}
		resp.TextCompletionResponse.Choices[0].TextCompletionResponseChoice.Text = schemas.Ptr(sanitized)
	case resp.ChatResponse != nil && len(resp.ChatResponse.Choices) > 0:
		choice := &resp.ChatResponse.Choices[0]
		if choice.ChatNonStreamResponseChoice == nil {
			choice.ChatNonStreamResponseChoice = &schemas.ChatNonStreamResponseChoice{Message: &schemas.ChatMessage{Role: schemas.ChatMessageRoleAssistant}}
		}
		if choice.ChatNonStreamResponseChoice.Message == nil {
			choice.ChatNonStreamResponseChoice.Message = &schemas.ChatMessage{Role: schemas.ChatMessageRoleAssistant}
		}
		choice.ChatNonStreamResponseChoice.Message.Content = &schemas.ChatMessageContent{ContentStr: schemas.Ptr(sanitized)}
	case resp.ResponsesResponse != nil && len(resp.ResponsesResponse.Output) > 0:
		resp.ResponsesResponse.Output[0].Content = &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr(sanitized)}
	case resp.ResponsesStreamResponse != nil:
		resp.ResponsesStreamResponse.Delta = schemas.Ptr(sanitized)
	}
}

func rewriteMCPResponseOutput(resp *schemas.DeepIntShieldMCPResponse, sanitized string) {
	if resp == nil {
		return
	}
	if resp.ChatMessage != nil {
		resp.ChatMessage.Content = &schemas.ChatMessageContent{ContentStr: schemas.Ptr(sanitized)}
	}
	if resp.ResponsesMessage != nil {
		resp.ResponsesMessage.Content = &schemas.ResponsesMessageContent{ContentStr: schemas.Ptr(sanitized)}
	}
}

func chatMessagesText(messages []schemas.ChatMessage) string {
	parts := make([]string, 0, len(messages))
	lastIdx := len(messages) - 1
	for idx, message := range messages {
		if message.Content == nil {
			continue
		}
		if message.Content.ContentStr != nil {
			parts = append(parts, strings.TrimSpace(*message.Content.ContentStr))
			continue
		}
		extractAttachments := idx == lastIdx
		for _, block := range message.Content.ContentBlocks {
			if block.Text != nil {
				parts = append(parts, strings.TrimSpace(*block.Text))
			}
			if block.Refusal != nil {
				parts = append(parts, strings.TrimSpace(*block.Refusal))
			}
			if !extractAttachments {
				continue
			}
			if block.File != nil {
				parts = append(parts, chatInputFileText(block.File)...)
			}
			if block.ImageURLStruct != nil {
				if v := extractAttachmentText(block.ImageURLStruct.URL); v != "" {
					parts = append(parts, v)
				}
			}
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func chatInputFileText(file *schemas.ChatInputFile) []string {
	if file == nil {
		return nil
	}
	out := make([]string, 0, 4)
	if file.Filename != nil {
		if v := strings.TrimSpace(*file.Filename); v != "" {
			out = append(out, v)
		}
	}
	if file.FileURL != nil {
		if v := strings.TrimSpace(*file.FileURL); v != "" {
			out = append(out, v)
		}
	}
	if file.FileData != nil {
		if v := extractAttachmentText(*file.FileData); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func responsesInputFileText(file *schemas.ResponsesInputMessageContentBlockFile) []string {
	if file == nil {
		return nil
	}
	out := make([]string, 0, 4)
	if file.Filename != nil {
		if v := strings.TrimSpace(*file.Filename); v != "" {
			out = append(out, v)
		}
	}
	if file.FileURL != nil {
		if v := strings.TrimSpace(*file.FileURL); v != "" {
			out = append(out, v)
		}
	}
	if file.FileData != nil {
		if v := extractAttachmentText(*file.FileData); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func responsesMessagesText(messages []schemas.ResponsesMessage, params *schemas.ResponsesParameters) string {
	parts := make([]string, 0, len(messages)+1)
	if params != nil && params.Instructions != nil {
		parts = append(parts, strings.TrimSpace(*params.Instructions))
	}
	parts = append(parts, responsesMessagesOnlyText(messages))
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func responsesMessagesOnlyText(messages []schemas.ResponsesMessage) string {
	parts := make([]string, 0, len(messages))
	lastIdx := len(messages) - 1
	for idx, message := range messages {
		if message.Content == nil {
			if message.Output != nil && message.Output.ResponsesToolCallOutputStr != nil {
				parts = append(parts, strings.TrimSpace(*message.Output.ResponsesToolCallOutputStr))
			}
			continue
		}
		if message.Content.ContentStr != nil {
			parts = append(parts, strings.TrimSpace(*message.Content.ContentStr))
			continue
		}
		extractAttachments := idx == lastIdx
		for _, block := range message.Content.ContentBlocks {
			if block.Text != nil {
				parts = append(parts, strings.TrimSpace(*block.Text))
			}
			if block.ResponsesOutputMessageContentRefusal != nil {
				parts = append(parts, strings.TrimSpace(block.ResponsesOutputMessageContentRefusal.Refusal))
			}
			if block.ResponsesOutputMessageContentRenderedContent != nil {
				parts = append(parts, strings.TrimSpace(block.ResponsesOutputMessageContentRenderedContent.RenderedContent))
			}
			if !extractAttachments {
				continue
			}
			if block.ResponsesInputMessageContentBlockFile != nil {
				parts = append(parts, responsesInputFileText(block.ResponsesInputMessageContentBlockFile)...)
			}
			if block.ResponsesInputMessageContentBlockImage != nil && block.ResponsesInputMessageContentBlockImage.ImageURL != nil {
				if v := extractAttachmentText(*block.ResponsesInputMessageContentBlockImage.ImageURL); v != "" {
					parts = append(parts, v)
				}
			}
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func guardrailRequestID(ctx *schemas.DeepIntShieldContext) string {
	if requestID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyRequestID)); requestID != "" {
		return requestID
	}
	return uuid.NewString()
}

func guardrailTenantID(ctx *schemas.DeepIntShieldContext) string {
	tenantID := strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyTenantID))
	if tenantID == "" {
		return defaultTenantID
	}
	return tenantID
}

func truncateGuardrailText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}
