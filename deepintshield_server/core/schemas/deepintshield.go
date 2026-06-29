// Package schemas defines the core schemas and types used by the DeepIntShield system.
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const (
	DefaultInitialPoolSize = 5000
)

type KeySelector func(ctx *DeepIntShieldContext, keys []Key, providerKey ModelProvider, model string) (Key, error)

// KeySelectionStrategy defines the algorithm used for load-balanced key selection.
type KeySelectionStrategy string

const (
	KeySelectionWeightedRandom KeySelectionStrategy = "weighted_random"
	KeySelectionRoundRobin     KeySelectionStrategy = "round_robin"
	KeySelectionLeastLoad      KeySelectionStrategy = "least_load"
)

// DeepIntShieldConfig represents the configuration for initializing a DeepIntShield instance.
// It contains the necessary components for setting up the system including account details,
// plugins, logging, and initial pool size.
type DeepIntShieldConfig struct {
	Account            Account
	LLMPlugins         []LLMPlugin
	MCPPlugins         []MCPPlugin
	OAuth2Provider     OAuth2Provider
	Logger             Logger
	Tracer             Tracer      // Tracer for distributed tracing (nil = NoOpTracer)
	InitialPoolSize    int         // Initial pool size for sync pools in DeepIntShield. Higher values will reduce memory allocations but will increase memory usage.
	DropExcessRequests bool        // If true, in cases where the queue is full, requests will not wait for the queue to be empty and will be dropped instead.
	MCPConfig          *MCPConfig  // MCP (Model Context Protocol) configuration for tool integration
	KeySelector        KeySelector // Custom key selector function
	KVStore            KVStore     // shared KV store for clustering/session stickiness; nil = disabled
}

// ModelProvider represents the different AI model providers supported by DeepIntShield.
type ModelProvider string

const (
	OpenAI      ModelProvider = "openai"
	Azure       ModelProvider = "azure"
	Anthropic   ModelProvider = "anthropic"
	Bedrock     ModelProvider = "bedrock"
	Cohere      ModelProvider = "cohere"
	Vertex      ModelProvider = "vertex"
	Mistral     ModelProvider = "mistral"
	Ollama      ModelProvider = "ollama"
	Groq        ModelProvider = "groq"
	SGL         ModelProvider = "sgl"
	Parasail    ModelProvider = "parasail"
	Perplexity  ModelProvider = "perplexity"
	Cerebras    ModelProvider = "cerebras"
	Gemini      ModelProvider = "gemini"
	OpenRouter  ModelProvider = "openrouter"
	Elevenlabs  ModelProvider = "elevenlabs"
	HuggingFace ModelProvider = "huggingface"
	Nebius      ModelProvider = "nebius"
	XAI         ModelProvider = "xai"
	Replicate   ModelProvider = "replicate"
	VLLM        ModelProvider = "vllm"
	Runway      ModelProvider = "runway"
	Fireworks   ModelProvider = "fireworks"
	OpencodeGo  ModelProvider = "opencode-go"
	OpencodeZen ModelProvider = "opencode-zen"
)

// SupportedBaseProviders is the list of base providers allowed for custom providers.
var SupportedBaseProviders = []ModelProvider{
	Anthropic,
	Bedrock,
	Cohere,
	Gemini,
	OpenAI,
	HuggingFace,
	Replicate,
}

// StandardProviders is the list of all built-in (non-custom) providers.
var StandardProviders = []ModelProvider{
	Anthropic,
	Azure,
	Bedrock,
	Cerebras,
	Cohere,
	Gemini,
	Groq,
	Mistral,
	Ollama,
	OpenAI,
	Parasail,
	Perplexity,
	SGL,
	Vertex,
	OpenRouter,
	Elevenlabs,
	HuggingFace,
	Nebius,
	XAI,
	Replicate,
	VLLM,
	Runway,
	Fireworks,
	OpencodeGo,
	OpencodeZen,
}

// RequestType represents the type of request being made to a provider.
type RequestType string

const (
	ListModelsRequest            RequestType = "list_models"
	TextCompletionRequest        RequestType = "text_completion"
	TextCompletionStreamRequest  RequestType = "text_completion_stream"
	ChatCompletionRequest        RequestType = "chat_completion"
	ChatCompletionStreamRequest  RequestType = "chat_completion_stream"
	ResponsesRequest             RequestType = "responses"
	ResponsesStreamRequest       RequestType = "responses_stream"
	EmbeddingRequest             RequestType = "embedding"
	SpeechRequest                RequestType = "speech"
	SpeechStreamRequest          RequestType = "speech_stream"
	TranscriptionRequest         RequestType = "transcription"
	TranscriptionStreamRequest   RequestType = "transcription_stream"
	ImageGenerationRequest       RequestType = "image_generation"
	ImageGenerationStreamRequest RequestType = "image_generation_stream"
	ImageEditRequest             RequestType = "image_edit"
	ImageEditStreamRequest       RequestType = "image_edit_stream"
	ImageVariationRequest        RequestType = "image_variation"
	VideoGenerationRequest       RequestType = "video_generation"
	VideoRetrieveRequest         RequestType = "video_retrieve"
	VideoDownloadRequest         RequestType = "video_download"
	VideoDeleteRequest           RequestType = "video_delete"
	VideoListRequest             RequestType = "video_list"
	VideoRemixRequest            RequestType = "video_remix"
	BatchCreateRequest           RequestType = "batch_create"
	BatchListRequest             RequestType = "batch_list"
	BatchRetrieveRequest         RequestType = "batch_retrieve"
	BatchCancelRequest           RequestType = "batch_cancel"
	BatchResultsRequest          RequestType = "batch_results"
	BatchDeleteRequest           RequestType = "batch_delete"
	FileUploadRequest            RequestType = "file_upload"
	FileListRequest              RequestType = "file_list"
	FileRetrieveRequest          RequestType = "file_retrieve"
	FileDeleteRequest            RequestType = "file_delete"
	FileContentRequest           RequestType = "file_content"
	ContainerCreateRequest       RequestType = "container_create"
	ContainerListRequest         RequestType = "container_list"
	ContainerRetrieveRequest     RequestType = "container_retrieve"
	ContainerDeleteRequest       RequestType = "container_delete"
	ContainerFileCreateRequest   RequestType = "container_file_create"
	ContainerFileListRequest     RequestType = "container_file_list"
	ContainerFileRetrieveRequest RequestType = "container_file_retrieve"
	ContainerFileContentRequest  RequestType = "container_file_content"
	ContainerFileDeleteRequest   RequestType = "container_file_delete"
	RerankRequest                RequestType = "rerank"
	CountTokensRequest           RequestType = "count_tokens"
	MCPToolExecutionRequest      RequestType = "mcp_tool_execution"
	PassthroughRequest           RequestType = "passthrough"
	PassthroughStreamRequest     RequestType = "passthrough_stream"
	UnknownRequest               RequestType = "unknown"
	WebSocketResponsesRequest    RequestType = "websocket_responses"
	RealtimeRequest              RequestType = "realtime"
)

// DeepIntShieldContextKey is a type for context keys used in DeepIntShield.
type DeepIntShieldContextKey string

// DeepIntShieldContextKeyRequestType is a context key for the request type.
const (
	DeepIntShieldContextKeySessionToken                                       DeepIntShieldContextKey = "deepintshield-session-token"               // string (session token for authentication - set by auth middleware)
	DeepIntShieldContextKeyVirtualKey                                         DeepIntShieldContextKey = "x-bf-vk"                                   // string
	DeepIntShieldContextKeyAPIKeyName                                         DeepIntShieldContextKey = "x-bf-api-key"                              // string (explicit key name selection)
	DeepIntShieldContextKeyAPIKeyID                                           DeepIntShieldContextKey = "x-bf-api-key-id"                           // string (explicit key ID selection, takes priority over name)
	DeepIntShieldContextKeyRequestID                                          DeepIntShieldContextKey = "request-id"                                // string
	DeepIntShieldContextKeyFallbackRequestID                                  DeepIntShieldContextKey = "fallback-request-id"                       // string
	DeepIntShieldContextKeyDirectKey                                          DeepIntShieldContextKey = "deepintshield-direct-key"                  // Key struct
	DeepIntShieldContextKeySelectedKeyID                                      DeepIntShieldContextKey = "deepintshield-selected-key-id"             // string (to store the selected key ID (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeySelectedKeyName                                    DeepIntShieldContextKey = "deepintshield-selected-key-name"           // string (to store the selected key name (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceVirtualKeyID                             DeepIntShieldContextKey = "deepintshield-governance-virtual-key-id"   // string (to store the virtual key ID (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceVirtualKeyName                           DeepIntShieldContextKey = "deepintshield-governance-virtual-key-name" // string (to store the virtual key name (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceVirtualKeyCacheKey                       DeepIntShieldContextKey = "deepintshield-governance-virtual-key-cache-key"
	DeepIntShieldContextKeyGovernanceVirtualKeyCacheEnabled                   DeepIntShieldContextKey = "deepintshield-governance-virtual-key-cache-enabled"
	DeepIntShieldContextKeyGovernanceVirtualKeySemanticCacheEnabled           DeepIntShieldContextKey = "deepintshield-governance-virtual-key-semantic-cache-enabled"
	DeepIntShieldContextKeyGovernanceVirtualKeyCacheScopeMode                 DeepIntShieldContextKey = "deepintshield-governance-virtual-key-cache-scope-mode"
	DeepIntShieldContextKeyGovernanceVirtualKeyCacheMetadataScopeKeys         DeepIntShieldContextKey = "deepintshield-governance-virtual-key-cache-metadata-scope-keys"
	DeepIntShieldContextKeyGovernanceVirtualKeyCacheAllowSemanticWhenUnscoped DeepIntShieldContextKey = "deepintshield-governance-virtual-key-cache-allow-semantic-when-unscoped"
	DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs                       DeepIntShieldContextKey = "deepintshield-governance-guardrail-policy-ids" // []string (attached guardrail policy IDs from governance virtual key selection)
	DeepIntShieldContextKeyGovernanceTeamID                                   DeepIntShieldContextKey = "deepintshield-governance-team-id"              // string (to store the team ID (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceTeamName                                 DeepIntShieldContextKey = "deepintshield-governance-team-name"            // string (to store the team name (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceCustomerID                               DeepIntShieldContextKey = "deepintshield-governance-customer-id"          // string (to store the customer ID (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceCustomerName                             DeepIntShieldContextKey = "deepintshield-governance-customer-name"        // string (to store the customer name (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceUserID                                   DeepIntShieldContextKey = "deepintshield-governance-user-id"              // string (to store the user ID (set by enterprise governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceRoutingRuleID                            DeepIntShieldContextKey = "deepintshield-governance-routing-rule-id"      // string (to store the routing rule ID (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceRoutingRuleName                          DeepIntShieldContextKey = "deepintshield-governance-routing-rule-name"    // string (to store the routing rule name (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernanceIncludeOnlyKeys                          DeepIntShieldContextKey = "bf-governance-include-only-keys"               // []string (to store the include-only key IDs for provider config routing (set by deepintshield governance plugin - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyNumberOfRetries                                    DeepIntShieldContextKey = "deepintshield-number-of-retries"               // int (to store the number of retries (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyFallbackIndex                                      DeepIntShieldContextKey = "deepintshield-fallback-index"                  // int (to store the fallback index (set by deepintshield - DO NOT SET THIS MANUALLY)) 0 for primary, 1 for first fallback, etc.
	DeepIntShieldContextKeyStreamEndIndicator                                 DeepIntShieldContextKey = "deepintshield-stream-end-indicator"            // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyStreamIdleTimeout                                  DeepIntShieldContextKey = "deepintshield-stream-idle-timeout"             // time.Duration (per-chunk idle timeout for streaming)
	DeepIntShieldContextKeySkipKeySelection                                   DeepIntShieldContextKey = "deepintshield-skip-key-selection"              // bool (will pass an empty key to the provider)
	DeepIntShieldContextKeyExtraHeaders                                       DeepIntShieldContextKey = "deepintshield-extra-headers"                   // map[string][]string
	DeepIntShieldContextKeyURLPath                                            DeepIntShieldContextKey = "deepintshield-extra-url-path"                  // string
	DeepIntShieldContextKeyUseRawRequestBody                                  DeepIntShieldContextKey = "deepintshield-use-raw-request-body"
	DeepIntShieldContextKeySendBackRawRequest                                 DeepIntShieldContextKey = "deepintshield-send-back-raw-request"                    // bool
	DeepIntShieldContextKeySendBackRawResponse                                DeepIntShieldContextKey = "deepintshield-send-back-raw-response"                   // bool
	DeepIntShieldContextKeyIntegrationType                                    DeepIntShieldContextKey = "deepintshield-integration-type"                         // integration used in gateway (e.g. openai, anthropic, bedrock, etc.)
	DeepIntShieldContextKeyIsResponsesToChatCompletionFallback                DeepIntShieldContextKey = "deepintshield-is-responses-to-chat-completion-fallback" // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldMCPAgentOriginalRequestID                                    DeepIntShieldContextKey = "deepintshield-mcp-agent-original-request-id"            // string (to store the original request ID for MCP agent mode)
	DeepIntShieldContextKeyParentMCPRequestID                                 DeepIntShieldContextKey = "bf-parent-mcp-request-id"                               // string (parent request ID for nested tool calls from executeCode)
	DeepIntShieldContextKeyStructuredOutputToolName                           DeepIntShieldContextKey = "deepintshield-structured-output-tool-name"              // string (to store the name of the structured output tool (set by deepintshield))
	DeepIntShieldContextKeyUserAgent                                          DeepIntShieldContextKey = "deepintshield-user-agent"                               // string (set by deepintshield)
	DeepIntShieldContextKeyTraceID                                            DeepIntShieldContextKey = "deepintshield-trace-id"                                 // string (trace ID for distributed tracing - set by tracing middleware)
	DeepIntShieldContextKeySpanID                                             DeepIntShieldContextKey = "deepintshield-span-id"                                  // string (current span ID for child span creation - set by tracer)
	DeepIntShieldContextKeyParentSpanID                                       DeepIntShieldContextKey = "deepintshield-parent-span-id"                           // string (parent span ID from W3C traceparent header - set by tracing middleware)
	DeepIntShieldContextKeyStreamStartTime                                    DeepIntShieldContextKey = "deepintshield-stream-start-time"                        // time.Time (start time for streaming TTFT calculation - set by deepintshield)
	DeepIntShieldContextKeyTracer                                             DeepIntShieldContextKey = "deepintshield-tracer"                                   // Tracer (tracer instance for completing deferred spans - set by deepintshield)
	DeepIntShieldContextKeyDeferTraceCompletion                               DeepIntShieldContextKey = "deepintshield-defer-trace-completion"                   // bool (signals trace completion should be deferred for streaming - set by streaming handlers)
	DeepIntShieldContextKeyTraceCompleter                                     DeepIntShieldContextKey = "deepintshield-trace-completer"                          // func() (callback to complete trace after streaming - set by tracing middleware)
	DeepIntShieldContextKeyPostHookSpanFinalizer                              DeepIntShieldContextKey = "deepintshield-posthook-span-finalizer"                  // func(context.Context) (callback to finalize post-hook spans after streaming - set by deepintshield)
	DeepIntShieldContextKeyAccumulatorID                                      DeepIntShieldContextKey = "deepintshield-accumulator-id"                           // string (ID for streaming accumulator lookup - set by tracer for accumulator operations)
	DeepIntShieldContextKeySkipDBUpdate                                       DeepIntShieldContextKey = "deepintshield-skip-db-update"                           // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyGovernancePluginName                               DeepIntShieldContextKey = "governance-plugin-name"                                 // string (name of the governance plugin that processed the request - set by deepintshield)
	DeepIntShieldContextKeyIsEnterprise                                       DeepIntShieldContextKey = "is-enterprise"                                          // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyAvailableProviders                                 DeepIntShieldContextKey = "available-providers"                                    // []ModelProvider (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyRawRequestResponseForLogging                       DeepIntShieldContextKey = "deepintshield-raw-request-response-for-logging"         // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyRetryDBFetch                                       DeepIntShieldContextKey = "deepintshield-retry-db-fetch"                           // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyIsCustomProvider                                   DeepIntShieldContextKey = "deepintshield-is-custom-provider"                       // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyHTTPRequestType                                    DeepIntShieldContextKey = "deepintshield-http-request-type"                        // RequestType (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeyPassthroughExtraParams                             DeepIntShieldContextKey = "deepintshield-passthrough-extra-params"                 // bool
	DeepIntShieldContextKeyRoutingEnginesUsed                                 DeepIntShieldContextKey = "deepintshield-routing-engines-used"                     // []string (set by deepintshield - DO NOT SET THIS MANUALLY) - list of routing engines used ("routing-rule", "governance", "loadbalancing", etc.)
	DeepIntShieldContextKeyRoutingEngineLogs                                  DeepIntShieldContextKey = "deepintshield-routing-engine-logs"                      // []RoutingEngineLogEntry (set by deepintshield - DO NOT SET THIS MANUALLY) - list of routing engine log entries
	DeepIntShieldContextKeySkipPluginPipeline                                 DeepIntShieldContextKey = "deepintshield-skip-plugin-pipeline"                     // bool - skip plugin pipeline for the request
	DeepIntShieldIsAsyncRequest                                               DeepIntShieldContextKey = "deepintshield-is-async-request"                         // bool (set by deepintshield - DO NOT SET THIS MANUALLY)) - whether the request is an async request (only used in gateway)
	DeepIntShieldContextKeyRequestHeaders                                     DeepIntShieldContextKey = "deepintshield-request-headers"                          // map[string]string (all request headers with lowercased keys)
	DeepIntShieldContextKeySkipListModelsGovernanceFiltering                  DeepIntShieldContextKey = "deepintshield-skip-list-models-governance-filtering"    // bool (set by deepintshield - DO NOT SET THIS MANUALLY))
	DeepIntShieldContextKeySCIMClaims                                         DeepIntShieldContextKey = "scim_claims"
	DeepIntShieldContextKeyUserID                                             DeepIntShieldContextKey = "user_id"
	DeepIntShieldContextKeyUserRole                                           DeepIntShieldContextKey = "user_role"
	DeepIntShieldContextKeyTenantID                                           DeepIntShieldContextKey = "tenant_id"
	// DeepIntShieldContextKeyActiveTenantID carries the *3-tier* tenant the
	// dashboard's scope switcher selected (X-Active-Tenant-Id header). It
	// MUST be a separate key from DeepIntShieldContextKeyTenantID because
	// the legacy tenant_id is the email-keyed partition that the GORM
	// tenant-scoping callback uses to filter every read - overwriting it
	// with the new UUID nukes the partition match and 401s the next session
	// reload. Permission helpers (CanManageTenant / CanReadWorkspace /
	// applyActiveScopeOverride) read this instead. Empty / unset means
	// "use the session's home tenant".
	DeepIntShieldContextKeyActiveTenantID DeepIntShieldContextKey = "active_tenant_id"
	// DeepIntShieldContextKeyWorkspaceID is the workspace the current
	// request is scoped to, resolved by the workspace API key middleware
	// (or by VK.workspace_id when present). Empty string / unset means the
	// request is org-wide (legacy behaviour).
	DeepIntShieldContextKeyWorkspaceID DeepIntShieldContextKey = "workspace_id"
	// DeepIntShieldContextKeyWorkspaceAPIKeyID is the ID of the workspace
	// API key that authenticated the request. Set only when a dis_ws_*
	// bearer token was used; useful for audit logging and async
	// last_used_at writes.
	DeepIntShieldContextKeyWorkspaceAPIKeyID               DeepIntShieldContextKey = "workspace_api_key_id"
	DeepIntShieldContextKeyTargetUserID                    DeepIntShieldContextKey = "target_user_id"
	DeepIntShieldContextKeyIsAzureUserAgent                DeepIntShieldContextKey = "deepintshield-is-azure-user-agent" // bool (set by deepintshield - DO NOT SET THIS MANUALLY)) - whether the request is an Azure user agent (only used in gateway)
	DeepIntShieldContextKeyVideoOutputRequested            DeepIntShieldContextKey = "deepintshield-video-output-requested"
	DeepIntShieldContextKeyValidateKeys                    DeepIntShieldContextKey = "deepintshield-validate-keys"                      // bool (triggers additional key validation during provider add/update)
	DeepIntShieldContextKeyProviderResponseHeaders         DeepIntShieldContextKey = "deepintshield-provider-response-headers"          // map[string]string (set by provider handlers for response header forwarding)
	DeepIntShieldContextKeyLargePayloadMode                DeepIntShieldContextKey = "deepintshield-large-payload-mode"                 // bool (set by deepintshield - DO NOT SET THIS MANUALLY)) indicates large payload streaming mode is active
	DeepIntShieldContextKeyLargePayloadReader              DeepIntShieldContextKey = "deepintshield-large-payload-reader"               // io.Reader (set by deepintshield - DO NOT SET THIS MANUALLY)) upstream reader for large payloads
	DeepIntShieldContextKeyLargePayloadContentLength       DeepIntShieldContextKey = "deepintshield-large-payload-content-length"       // int (set by deepintshield - DO NOT SET THIS MANUALLY)) content length for large payloads
	DeepIntShieldContextKeyLargePayloadContentType         DeepIntShieldContextKey = "deepintshield-large-payload-content-type"         // string (set by enterprise - DO NOT SET THIS MANUALLY)) original content type for large payload passthrough
	DeepIntShieldContextKeyLargePayloadMetadata            DeepIntShieldContextKey = "deepintshield-large-payload-metadata"             // *LargePayloadMetadata (set by deepintshield - DO NOT SET THIS MANUALLY)) routing metadata for large payloads
	DeepIntShieldContextKeyLargePayloadRequestThreshold    DeepIntShieldContextKey = "deepintshield-large-payload-request-threshold"    // int64 (set by enterprise - DO NOT SET THIS MANUALLY)) request threshold used by transport heuristics
	DeepIntShieldContextKeyLargeResponseMode               DeepIntShieldContextKey = "deepintshield-large-response-mode"                // bool (set by deepintshield - DO NOT SET THIS MANUALLY)) indicates large response streaming mode is active
	DeepIntShieldContextKeyLargePayloadRequestPreview      DeepIntShieldContextKey = "deepintshield-large-payload-request-preview"      // string (set by deepintshield - DO NOT SET THIS MANUALLY)) truncated request body preview for logging
	DeepIntShieldContextKeyLargePayloadResponsePreview     DeepIntShieldContextKey = "deepintshield-large-payload-response-preview"     // string (set by deepintshield - DO NOT SET THIS MANUALLY)) truncated response body preview for logging
	DeepIntShieldContextKeyLargeResponseReader             DeepIntShieldContextKey = "deepintshield-large-response-reader"              // io.ReadCloser (set by deepintshield - DO NOT SET THIS MANUALLY)) upstream reader for large responses
	DeepIntShieldContextKeyLargeResponseContentLength      DeepIntShieldContextKey = "deepintshield-large-response-content-length"      // int (set by deepintshield - DO NOT SET THIS MANUALLY)) content length for large responses
	DeepIntShieldContextKeyLargeResponseContentType        DeepIntShieldContextKey = "deepintshield-large-response-content-type"        // string (set by deepintshield - DO NOT SET THIS MANUALLY)) upstream content type for large responses
	DeepIntShieldContextKeyLargeResponseContentDisposition DeepIntShieldContextKey = "deepintshield-large-response-content-disposition" // string (set by deepintshield - DO NOT SET THIS MANUALLY)) downstream content disposition for large responses
	DeepIntShieldContextKeyLargeResponseThreshold          DeepIntShieldContextKey = "deepintshield-large-response-threshold"           // int64 (set by enterprise - DO NOT SET THIS MANUALLY)) threshold for response streaming
	DeepIntShieldContextKeyLargePayloadPrefetchSize        DeepIntShieldContextKey = "deepintshield-large-payload-prefetch-size"        // int (set by enterprise - DO NOT SET THIS MANUALLY)) prefetch buffer size for metadata extraction from large responses
	DeepIntShieldContextKeyDeferredUsage                   DeepIntShieldContextKey = "deepintshield-deferred-usage"                     // chan *DeepIntShieldLLMUsage (set by provider Phase B - delivers usage after response streaming completes)
	DeepIntShieldContextKeyDeferredLargePayloadMetadata    DeepIntShieldContextKey = "deepintshield-deferred-large-payload-metadata"    // <-chan *LargePayloadMetadata (set by enterprise Phase B request - delivers metadata after body streaming)
	DeepIntShieldContextKeySSEReaderFactory                DeepIntShieldContextKey = "deepintshield-sse-reader-factory"                 // *providerUtils.SSEReaderFactory (set by enterprise - replaces default bufio.Scanner SSE readers with streaming readers)
	DeepIntShieldContextKeyRequestStartTime                DeepIntShieldContextKey = "deepintshield-request-start-time"                 // time.Time request start time used for internal latency auditing
	DeepIntShieldContextKeyLatencyBreakdown                DeepIntShieldContextKey = "deepintshield-latency-breakdown"                  // *LatencyBreakdown internal request-phase timing accumulator
	DeepIntShieldContextKeySessionID                       DeepIntShieldContextKey = "deepintshield-session-id"                         // string session ID for the request (session stickiness)
	DeepIntShieldContextKeySessionTTL                      DeepIntShieldContextKey = "deepintshield-session-ttl"                        // time.Duration session TTL for the request (session stickiness)
	DeepIntShieldContextKeyKeySelectionStrategy            DeepIntShieldContextKey = "deepintshield-key-selection-strategy"             // KeySelectionStrategy (set by governance resolver from VK provider config)
	DeepIntShieldContextKeyKeyLoadTracker                  DeepIntShieldContextKey = "deepintshield-key-load-tracker"                   // *KeyLoadTracker (set by transport layer when load balancer is enabled)
	// Per-tenant network config (feature-flagged via PER_TENANT_NETWORK_CONFIG).
	// Set by the request worker from the tenant-scoped resolved provider config so
	// that timeout/base-url/transport apply per tenant without rebuilding the shared
	// provider. Absent (and ignored) when the flag is off - preserves prior behavior.
	DeepIntShieldContextKeyRequestTimeout DeepIntShieldContextKey = "deepintshield-request-timeout" // time.Duration (per-request provider timeout; enforced via client.DoTimeout at the request chokepoint)
	DeepIntShieldContextKeyTenantBaseURL  DeepIntShieldContextKey = "deepintshield-tenant-base-url" // string (per-tenant provider base URL override; read by buildRequestURL before the baked value)
	DeepIntShieldContextKeyHTTPClient     DeepIntShieldContextKey = "deepintshield-http-client"     // *fasthttp.Client (per-(tenant,provider) client for transport-bound fields; substituted at the chokepoint)
)

const (
	// DefaultLargePayloadRequestThresholdBytes is the default request-size heuristic
	// used by transport guards when no enterprise threshold is present on context.
	DefaultLargePayloadRequestThresholdBytes = 10 * 1024 * 1024 // 10MB
)

// RoutingEngine constants
const (
	RoutingEngineGovernance    = "governance"
	RoutingEngineRoutingRule   = "routing-rule"
	RoutingEngineLoadbalancing = "loadbalancing"
)

// RoutingEngineLogEntry represents a log entry from a routing engine
// format: [timestamp] [engine] - message
type RoutingEngineLogEntry struct {
	Engine    string // e.g., "governance", "routing-rule", "openrouter"
	Message   string // Human-readable decision/action message
	Timestamp int64  // Unix milliseconds
}

// NOTE: for custom plugin implementation dealing with streaming short circuit,
// make sure to mark DeepIntShieldContextKeyStreamEndIndicator as true at the end of the stream.

// LargePayloadMetadata holds routing-relevant metadata selectively extracted from large payloads.
// This is used when the full request body is too large to parse (e.g., 400MB video upload).
// Only small routing/observability fields are extracted; the body itself streams through unchanged.
type LargePayloadMetadata struct {
	ResponseModalities []string // e.g., ["AUDIO"] for speech, ["IMAGE"] for image generation
	SpeechConfig       bool     // true if generationConfig.speechConfig is present
	Model              string   // model extracted without full body parsing (openai/anthropic multipart/json)
	StreamRequested    *bool    // stream flag when available in request payload metadata
}

//* Request Structs

// Fallback represents a fallback model to be used if the primary model is not available.
type Fallback struct {
	Provider ModelProvider `json:"provider"`
	Model    string        `json:"model"`
}

// DeepIntShieldRequest is the request struct for all deepintshield requests.
// only ONE of the following fields should be set:
// - ListModelsRequest
// - TextCompletionRequest
// - ChatRequest
// - ResponsesRequest
// - CountTokensRequest
// - EmbeddingRequest
// - RerankRequest
// - SpeechRequest
// - TranscriptionRequest
// - ImageGenerationRequest
// NOTE: DeepIntShield Request is submitted back to pool after every use so DO NOT keep references to this struct after use, especially in go routines.
type DeepIntShieldRequest struct {
	RequestType RequestType

	ListModelsRequest            *DeepIntShieldListModelsRequest
	TextCompletionRequest        *DeepIntShieldTextCompletionRequest
	ChatRequest                  *DeepIntShieldChatRequest
	ResponsesRequest             *DeepIntShieldResponsesRequest
	CountTokensRequest           *DeepIntShieldResponsesRequest
	EmbeddingRequest             *DeepIntShieldEmbeddingRequest
	RerankRequest                *DeepIntShieldRerankRequest
	SpeechRequest                *DeepIntShieldSpeechRequest
	TranscriptionRequest         *DeepIntShieldTranscriptionRequest
	ImageGenerationRequest       *DeepIntShieldImageGenerationRequest
	ImageEditRequest             *DeepIntShieldImageEditRequest
	ImageVariationRequest        *DeepIntShieldImageVariationRequest
	VideoGenerationRequest       *DeepIntShieldVideoGenerationRequest
	VideoRetrieveRequest         *DeepIntShieldVideoRetrieveRequest
	VideoDownloadRequest         *DeepIntShieldVideoDownloadRequest
	VideoListRequest             *DeepIntShieldVideoListRequest
	VideoRemixRequest            *DeepIntShieldVideoRemixRequest
	VideoDeleteRequest           *DeepIntShieldVideoDeleteRequest
	FileUploadRequest            *DeepIntShieldFileUploadRequest
	FileListRequest              *DeepIntShieldFileListRequest
	FileRetrieveRequest          *DeepIntShieldFileRetrieveRequest
	FileDeleteRequest            *DeepIntShieldFileDeleteRequest
	FileContentRequest           *DeepIntShieldFileContentRequest
	BatchCreateRequest           *DeepIntShieldBatchCreateRequest
	BatchListRequest             *DeepIntShieldBatchListRequest
	BatchRetrieveRequest         *DeepIntShieldBatchRetrieveRequest
	BatchCancelRequest           *DeepIntShieldBatchCancelRequest
	BatchResultsRequest          *DeepIntShieldBatchResultsRequest
	BatchDeleteRequest           *DeepIntShieldBatchDeleteRequest
	ContainerCreateRequest       *DeepIntShieldContainerCreateRequest
	ContainerListRequest         *DeepIntShieldContainerListRequest
	ContainerRetrieveRequest     *DeepIntShieldContainerRetrieveRequest
	ContainerDeleteRequest       *DeepIntShieldContainerDeleteRequest
	ContainerFileCreateRequest   *DeepIntShieldContainerFileCreateRequest
	ContainerFileListRequest     *DeepIntShieldContainerFileListRequest
	ContainerFileRetrieveRequest *DeepIntShieldContainerFileRetrieveRequest
	ContainerFileContentRequest  *DeepIntShieldContainerFileContentRequest
	ContainerFileDeleteRequest   *DeepIntShieldContainerFileDeleteRequest
	PassthroughRequest           *DeepIntShieldPassthroughRequest
}

// GetRequestFields returns the provider, model, and fallbacks from the request.
func (br *DeepIntShieldRequest) GetRequestFields() (provider ModelProvider, model string, fallbacks []Fallback) {
	switch {
	case br.ListModelsRequest != nil:
		return br.ListModelsRequest.Provider, "", nil
	case br.TextCompletionRequest != nil:
		return br.TextCompletionRequest.Provider, br.TextCompletionRequest.Model, br.TextCompletionRequest.Fallbacks
	case br.ChatRequest != nil:
		return br.ChatRequest.Provider, br.ChatRequest.Model, br.ChatRequest.Fallbacks
	case br.ResponsesRequest != nil:
		return br.ResponsesRequest.Provider, br.ResponsesRequest.Model, br.ResponsesRequest.Fallbacks
	case br.CountTokensRequest != nil:
		return br.CountTokensRequest.Provider, br.CountTokensRequest.Model, br.CountTokensRequest.Fallbacks
	case br.EmbeddingRequest != nil:
		return br.EmbeddingRequest.Provider, br.EmbeddingRequest.Model, br.EmbeddingRequest.Fallbacks
	case br.RerankRequest != nil:
		return br.RerankRequest.Provider, br.RerankRequest.Model, br.RerankRequest.Fallbacks
	case br.SpeechRequest != nil:
		return br.SpeechRequest.Provider, br.SpeechRequest.Model, br.SpeechRequest.Fallbacks
	case br.TranscriptionRequest != nil:
		return br.TranscriptionRequest.Provider, br.TranscriptionRequest.Model, br.TranscriptionRequest.Fallbacks
	case br.ImageGenerationRequest != nil:
		return br.ImageGenerationRequest.Provider, br.ImageGenerationRequest.Model, br.ImageGenerationRequest.Fallbacks
	case br.ImageEditRequest != nil:
		return br.ImageEditRequest.Provider, br.ImageEditRequest.Model, br.ImageEditRequest.Fallbacks
	case br.ImageVariationRequest != nil:
		return br.ImageVariationRequest.Provider, br.ImageVariationRequest.Model, br.ImageVariationRequest.Fallbacks
	case br.VideoGenerationRequest != nil:
		return br.VideoGenerationRequest.Provider, br.VideoGenerationRequest.Model, br.VideoGenerationRequest.Fallbacks
	case br.VideoRetrieveRequest != nil:
		return br.VideoRetrieveRequest.Provider, "", nil
	case br.VideoDownloadRequest != nil:
		return br.VideoDownloadRequest.Provider, "", nil
	case br.VideoListRequest != nil:
		return br.VideoListRequest.Provider, "", nil
	case br.VideoDeleteRequest != nil:
		return br.VideoDeleteRequest.Provider, "", nil
	case br.VideoRemixRequest != nil:
		return br.VideoRemixRequest.Provider, "", nil
	case br.FileUploadRequest != nil:
		if br.FileUploadRequest.Model != nil {
			return br.FileUploadRequest.Provider, *br.FileUploadRequest.Model, nil
		}
		return br.FileUploadRequest.Provider, "", nil
	case br.FileListRequest != nil:
		if br.FileListRequest.Model != nil {
			return br.FileListRequest.Provider, *br.FileListRequest.Model, nil
		}
		return br.FileListRequest.Provider, "", nil
	case br.FileRetrieveRequest != nil:
		if br.FileRetrieveRequest.Model != nil {
			return br.FileRetrieveRequest.Provider, *br.FileRetrieveRequest.Model, nil
		}
		return br.FileRetrieveRequest.Provider, "", nil
	case br.FileDeleteRequest != nil:
		if br.FileDeleteRequest.Model != nil {
			return br.FileDeleteRequest.Provider, *br.FileDeleteRequest.Model, nil
		}
		return br.FileDeleteRequest.Provider, "", nil
	case br.FileContentRequest != nil:
		if br.FileContentRequest.Model != nil {
			return br.FileContentRequest.Provider, *br.FileContentRequest.Model, nil
		}
		return br.FileContentRequest.Provider, "", nil
	case br.BatchCreateRequest != nil:
		if br.BatchCreateRequest.Model != nil {
			return br.BatchCreateRequest.Provider, *br.BatchCreateRequest.Model, nil
		}
		return br.BatchCreateRequest.Provider, "", nil
	case br.BatchListRequest != nil:
		if br.BatchListRequest.Model != nil {
			return br.BatchListRequest.Provider, *br.BatchListRequest.Model, nil
		}
		return br.BatchListRequest.Provider, "", nil
	case br.BatchRetrieveRequest != nil:
		if br.BatchRetrieveRequest.Model != nil {
			return br.BatchRetrieveRequest.Provider, *br.BatchRetrieveRequest.Model, nil
		}
		return br.BatchRetrieveRequest.Provider, "", nil
	case br.BatchCancelRequest != nil:
		if br.BatchCancelRequest.Model != nil {
			return br.BatchCancelRequest.Provider, *br.BatchCancelRequest.Model, nil
		}
		return br.BatchCancelRequest.Provider, "", nil
	case br.BatchResultsRequest != nil:
		if br.BatchResultsRequest.Model != nil {
			return br.BatchResultsRequest.Provider, *br.BatchResultsRequest.Model, nil
		}
		return br.BatchResultsRequest.Provider, "", nil
	case br.BatchDeleteRequest != nil:
		if br.BatchDeleteRequest.Model != nil {
			return br.BatchDeleteRequest.Provider, *br.BatchDeleteRequest.Model, nil
		}
		return br.BatchDeleteRequest.Provider, "", nil
	case br.ContainerCreateRequest != nil:
		return br.ContainerCreateRequest.Provider, "", nil
	case br.ContainerListRequest != nil:
		return br.ContainerListRequest.Provider, "", nil
	case br.ContainerRetrieveRequest != nil:
		return br.ContainerRetrieveRequest.Provider, "", nil
	case br.ContainerDeleteRequest != nil:
		return br.ContainerDeleteRequest.Provider, "", nil
	case br.ContainerFileCreateRequest != nil:
		return br.ContainerFileCreateRequest.Provider, "", nil
	case br.ContainerFileListRequest != nil:
		return br.ContainerFileListRequest.Provider, "", nil
	case br.ContainerFileRetrieveRequest != nil:
		return br.ContainerFileRetrieveRequest.Provider, "", nil
	case br.ContainerFileContentRequest != nil:
		return br.ContainerFileContentRequest.Provider, "", nil
	case br.ContainerFileDeleteRequest != nil:
		return br.ContainerFileDeleteRequest.Provider, "", nil
	case br.PassthroughRequest != nil:
		return br.PassthroughRequest.Provider, br.PassthroughRequest.Model, nil
	}
	return "", "", nil
}

func (br *DeepIntShieldRequest) SetProvider(provider ModelProvider) {
	switch {
	case br.ListModelsRequest != nil:
		br.ListModelsRequest.Provider = provider
	case br.TextCompletionRequest != nil:
		br.TextCompletionRequest.Provider = provider
	case br.ChatRequest != nil:
		br.ChatRequest.Provider = provider
	case br.ResponsesRequest != nil:
		br.ResponsesRequest.Provider = provider
	case br.CountTokensRequest != nil:
		br.CountTokensRequest.Provider = provider
	case br.EmbeddingRequest != nil:
		br.EmbeddingRequest.Provider = provider
	case br.RerankRequest != nil:
		br.RerankRequest.Provider = provider
	case br.SpeechRequest != nil:
		br.SpeechRequest.Provider = provider
	case br.TranscriptionRequest != nil:
		br.TranscriptionRequest.Provider = provider
	case br.ImageGenerationRequest != nil:
		br.ImageGenerationRequest.Provider = provider
	case br.ImageEditRequest != nil:
		br.ImageEditRequest.Provider = provider
	case br.ImageVariationRequest != nil:
		br.ImageVariationRequest.Provider = provider
	case br.VideoGenerationRequest != nil:
		br.VideoGenerationRequest.Provider = provider
	case br.VideoRetrieveRequest != nil:
		br.VideoRetrieveRequest.Provider = provider
	case br.VideoDownloadRequest != nil:
		br.VideoDownloadRequest.Provider = provider
	case br.VideoListRequest != nil:
		br.VideoListRequest.Provider = provider
	case br.VideoDeleteRequest != nil:
		br.VideoDeleteRequest.Provider = provider
	case br.VideoRemixRequest != nil:
		br.VideoRemixRequest.Provider = provider
	}
}

func (br *DeepIntShieldRequest) SetModel(model string) {
	switch {
	case br.TextCompletionRequest != nil:
		br.TextCompletionRequest.Model = model
	case br.ChatRequest != nil:
		br.ChatRequest.Model = model
	case br.ResponsesRequest != nil:
		br.ResponsesRequest.Model = model
	case br.CountTokensRequest != nil:
		br.CountTokensRequest.Model = model
	case br.EmbeddingRequest != nil:
		br.EmbeddingRequest.Model = model
	case br.RerankRequest != nil:
		br.RerankRequest.Model = model
	case br.SpeechRequest != nil:
		br.SpeechRequest.Model = model
	case br.TranscriptionRequest != nil:
		br.TranscriptionRequest.Model = model
	case br.ImageGenerationRequest != nil:
		br.ImageGenerationRequest.Model = model
	case br.ImageEditRequest != nil:
		br.ImageEditRequest.Model = model
	case br.ImageVariationRequest != nil:
		br.ImageVariationRequest.Model = model
	case br.VideoGenerationRequest != nil:
		br.VideoGenerationRequest.Model = model
	}
}

func (br *DeepIntShieldRequest) SetFallbacks(fallbacks []Fallback) {
	switch {
	case br.TextCompletionRequest != nil:
		br.TextCompletionRequest.Fallbacks = fallbacks
	case br.ChatRequest != nil:
		br.ChatRequest.Fallbacks = fallbacks
	case br.ResponsesRequest != nil:
		br.ResponsesRequest.Fallbacks = fallbacks
	case br.CountTokensRequest != nil:
		br.CountTokensRequest.Fallbacks = fallbacks
	case br.EmbeddingRequest != nil:
		br.EmbeddingRequest.Fallbacks = fallbacks
	case br.RerankRequest != nil:
		br.RerankRequest.Fallbacks = fallbacks
	case br.SpeechRequest != nil:
		br.SpeechRequest.Fallbacks = fallbacks
	case br.TranscriptionRequest != nil:
		br.TranscriptionRequest.Fallbacks = fallbacks
	case br.ImageGenerationRequest != nil:
		br.ImageGenerationRequest.Fallbacks = fallbacks
	case br.ImageEditRequest != nil:
		br.ImageEditRequest.Fallbacks = fallbacks
	case br.ImageVariationRequest != nil:
		br.ImageVariationRequest.Fallbacks = fallbacks
	case br.VideoGenerationRequest != nil:
		br.VideoGenerationRequest.Fallbacks = fallbacks
	}
}

func (br *DeepIntShieldRequest) SetRawRequestBody(rawRequestBody []byte) {
	switch {
	case br.TextCompletionRequest != nil:
		br.TextCompletionRequest.RawRequestBody = rawRequestBody
	case br.ChatRequest != nil:
		br.ChatRequest.RawRequestBody = rawRequestBody
	case br.ResponsesRequest != nil:
		br.ResponsesRequest.RawRequestBody = rawRequestBody
	case br.CountTokensRequest != nil:
		br.CountTokensRequest.RawRequestBody = rawRequestBody
	case br.EmbeddingRequest != nil:
		br.EmbeddingRequest.RawRequestBody = rawRequestBody
	case br.RerankRequest != nil:
		br.RerankRequest.RawRequestBody = rawRequestBody
	case br.SpeechRequest != nil:
		br.SpeechRequest.RawRequestBody = rawRequestBody
	case br.TranscriptionRequest != nil:
		br.TranscriptionRequest.RawRequestBody = rawRequestBody
	case br.ImageGenerationRequest != nil:
		br.ImageGenerationRequest.RawRequestBody = rawRequestBody
	case br.ImageEditRequest != nil:
		br.ImageEditRequest.RawRequestBody = rawRequestBody
	case br.ImageVariationRequest != nil:
		br.ImageVariationRequest.RawRequestBody = rawRequestBody
	case br.VideoGenerationRequest != nil:
		br.VideoGenerationRequest.RawRequestBody = rawRequestBody
	case br.VideoRemixRequest != nil:
		br.VideoRemixRequest.RawRequestBody = rawRequestBody
	}
}

type MCPRequestType string

const (
	MCPRequestTypeChatToolCall      MCPRequestType = "chat_tool_call"      // Chat API format
	MCPRequestTypeResponsesToolCall MCPRequestType = "responses_tool_call" // Responses API format
)

// DeepIntShieldMCPRequest is the request struct for all MCP requests.
// only ONE of the following fields should be set:
// - ChatAssistantMessageToolCall
// - ResponsesToolMessage
type DeepIntShieldMCPRequest struct {
	RequestType MCPRequestType

	*ChatAssistantMessageToolCall
	*ResponsesToolMessage
}

func (r *DeepIntShieldMCPRequest) GetToolName() string {
	if r.ChatAssistantMessageToolCall != nil {
		if r.ChatAssistantMessageToolCall.Function.Name != nil {
			return *r.ChatAssistantMessageToolCall.Function.Name
		}
	}
	if r.ResponsesToolMessage != nil {
		if r.ResponsesToolMessage.Name != nil {
			return *r.ResponsesToolMessage.Name
		}
	}
	return ""
}

func (r *DeepIntShieldMCPRequest) GetToolArguments() interface{} {
	if r.ChatAssistantMessageToolCall != nil {
		return r.ChatAssistantMessageToolCall.Function.Arguments
	}
	if r.ResponsesToolMessage != nil {
		return r.ResponsesToolMessage.Arguments
	}
	return nil
}

//* Response Structs

// DeepIntShieldResponse represents the complete result from any deepintshield request.
type DeepIntShieldResponse struct {
	ListModelsResponse            *DeepIntShieldListModelsResponse
	TextCompletionResponse        *DeepIntShieldTextCompletionResponse
	ChatResponse                  *DeepIntShieldChatResponse
	ResponsesResponse             *DeepIntShieldResponsesResponse
	ResponsesStreamResponse       *DeepIntShieldResponsesStreamResponse
	CountTokensResponse           *DeepIntShieldCountTokensResponse
	EmbeddingResponse             *DeepIntShieldEmbeddingResponse
	RerankResponse                *DeepIntShieldRerankResponse
	SpeechResponse                *DeepIntShieldSpeechResponse
	SpeechStreamResponse          *DeepIntShieldSpeechStreamResponse
	TranscriptionResponse         *DeepIntShieldTranscriptionResponse
	TranscriptionStreamResponse   *DeepIntShieldTranscriptionStreamResponse
	ImageGenerationResponse       *DeepIntShieldImageGenerationResponse
	ImageGenerationStreamResponse *DeepIntShieldImageGenerationStreamResponse
	VideoGenerationResponse       *DeepIntShieldVideoGenerationResponse
	VideoDownloadResponse         *DeepIntShieldVideoDownloadResponse
	VideoListResponse             *DeepIntShieldVideoListResponse
	VideoDeleteResponse           *DeepIntShieldVideoDeleteResponse
	FileUploadResponse            *DeepIntShieldFileUploadResponse
	FileListResponse              *DeepIntShieldFileListResponse
	FileRetrieveResponse          *DeepIntShieldFileRetrieveResponse
	FileDeleteResponse            *DeepIntShieldFileDeleteResponse
	FileContentResponse           *DeepIntShieldFileContentResponse
	BatchCreateResponse           *DeepIntShieldBatchCreateResponse
	BatchListResponse             *DeepIntShieldBatchListResponse
	BatchRetrieveResponse         *DeepIntShieldBatchRetrieveResponse
	BatchCancelResponse           *DeepIntShieldBatchCancelResponse
	BatchResultsResponse          *DeepIntShieldBatchResultsResponse
	BatchDeleteResponse           *DeepIntShieldBatchDeleteResponse
	ContainerCreateResponse       *DeepIntShieldContainerCreateResponse
	ContainerListResponse         *DeepIntShieldContainerListResponse
	ContainerRetrieveResponse     *DeepIntShieldContainerRetrieveResponse
	ContainerDeleteResponse       *DeepIntShieldContainerDeleteResponse
	ContainerFileCreateResponse   *DeepIntShieldContainerFileCreateResponse
	ContainerFileListResponse     *DeepIntShieldContainerFileListResponse
	ContainerFileRetrieveResponse *DeepIntShieldContainerFileRetrieveResponse
	ContainerFileContentResponse  *DeepIntShieldContainerFileContentResponse
	ContainerFileDeleteResponse   *DeepIntShieldContainerFileDeleteResponse
	PassthroughResponse           *DeepIntShieldPassthroughResponse
}

func (r *DeepIntShieldResponse) GetExtraFields() *DeepIntShieldResponseExtraFields {
	switch {
	case r.ListModelsResponse != nil:
		return &r.ListModelsResponse.ExtraFields
	case r.TextCompletionResponse != nil:
		return &r.TextCompletionResponse.ExtraFields
	case r.ChatResponse != nil:
		return &r.ChatResponse.ExtraFields
	case r.ResponsesResponse != nil:
		return &r.ResponsesResponse.ExtraFields
	case r.ResponsesStreamResponse != nil:
		return &r.ResponsesStreamResponse.ExtraFields
	case r.CountTokensResponse != nil:
		return &r.CountTokensResponse.ExtraFields
	case r.EmbeddingResponse != nil:
		return &r.EmbeddingResponse.ExtraFields
	case r.RerankResponse != nil:
		return &r.RerankResponse.ExtraFields
	case r.SpeechResponse != nil:
		return &r.SpeechResponse.ExtraFields
	case r.SpeechStreamResponse != nil:
		return &r.SpeechStreamResponse.ExtraFields
	case r.TranscriptionResponse != nil:
		return &r.TranscriptionResponse.ExtraFields
	case r.TranscriptionStreamResponse != nil:
		return &r.TranscriptionStreamResponse.ExtraFields
	case r.ImageGenerationResponse != nil:
		return &r.ImageGenerationResponse.ExtraFields
	case r.ImageGenerationStreamResponse != nil:
		return &r.ImageGenerationStreamResponse.ExtraFields
	case r.FileUploadResponse != nil:
		return &r.FileUploadResponse.ExtraFields
	case r.FileListResponse != nil:
		return &r.FileListResponse.ExtraFields
	case r.FileRetrieveResponse != nil:
		return &r.FileRetrieveResponse.ExtraFields
	case r.FileDeleteResponse != nil:
		return &r.FileDeleteResponse.ExtraFields
	case r.FileContentResponse != nil:
		return &r.FileContentResponse.ExtraFields
	case r.VideoGenerationResponse != nil:
		return &r.VideoGenerationResponse.ExtraFields
	case r.VideoDownloadResponse != nil:
		return &r.VideoDownloadResponse.ExtraFields
	case r.VideoListResponse != nil:
		return &r.VideoListResponse.ExtraFields
	case r.VideoDeleteResponse != nil:
		return &r.VideoDeleteResponse.ExtraFields
	case r.BatchCreateResponse != nil:
		return &r.BatchCreateResponse.ExtraFields
	case r.BatchListResponse != nil:
		return &r.BatchListResponse.ExtraFields
	case r.BatchRetrieveResponse != nil:
		return &r.BatchRetrieveResponse.ExtraFields
	case r.BatchCancelResponse != nil:
		return &r.BatchCancelResponse.ExtraFields
	case r.BatchDeleteResponse != nil:
		return &r.BatchDeleteResponse.ExtraFields
	case r.BatchResultsResponse != nil:
		return &r.BatchResultsResponse.ExtraFields
	case r.ContainerCreateResponse != nil:
		return &r.ContainerCreateResponse.ExtraFields
	case r.ContainerListResponse != nil:
		return &r.ContainerListResponse.ExtraFields
	case r.ContainerRetrieveResponse != nil:
		return &r.ContainerRetrieveResponse.ExtraFields
	case r.ContainerDeleteResponse != nil:
		return &r.ContainerDeleteResponse.ExtraFields
	case r.ContainerFileCreateResponse != nil:
		return &r.ContainerFileCreateResponse.ExtraFields
	case r.ContainerFileListResponse != nil:
		return &r.ContainerFileListResponse.ExtraFields
	case r.ContainerFileRetrieveResponse != nil:
		return &r.ContainerFileRetrieveResponse.ExtraFields
	case r.ContainerFileContentResponse != nil:
		return &r.ContainerFileContentResponse.ExtraFields
	case r.ContainerFileDeleteResponse != nil:
		return &r.ContainerFileDeleteResponse.ExtraFields
	case r.PassthroughResponse != nil:
		return &r.PassthroughResponse.ExtraFields
	}

	return &DeepIntShieldResponseExtraFields{}
}

// GetTotalTokens returns the total token count from whichever sub-response is
// populated, or 0 if usage is absent. Used by the LLM Load Balancer to track
// per-key token throughput; non-token shapes (file/batch/container/video list
// ops) return 0.
func (r *DeepIntShieldResponse) GetTotalTokens() int {
	if r == nil {
		return 0
	}
	switch {
	case r.ChatResponse != nil && r.ChatResponse.Usage != nil:
		return r.ChatResponse.Usage.TotalTokens
	case r.TextCompletionResponse != nil && r.TextCompletionResponse.Usage != nil:
		return r.TextCompletionResponse.Usage.TotalTokens
	case r.ResponsesResponse != nil && r.ResponsesResponse.Usage != nil:
		return r.ResponsesResponse.Usage.TotalTokens
	case r.EmbeddingResponse != nil && r.EmbeddingResponse.Usage != nil:
		return r.EmbeddingResponse.Usage.TotalTokens
	case r.RerankResponse != nil && r.RerankResponse.Usage != nil:
		return r.RerankResponse.Usage.TotalTokens
	case r.SpeechResponse != nil && r.SpeechResponse.Usage != nil:
		return r.SpeechResponse.Usage.TotalTokens
	case r.TranscriptionResponse != nil && r.TranscriptionResponse.Usage != nil && r.TranscriptionResponse.Usage.TotalTokens != nil:
		return *r.TranscriptionResponse.Usage.TotalTokens
	case r.ImageGenerationResponse != nil && r.ImageGenerationResponse.Usage != nil:
		return r.ImageGenerationResponse.Usage.TotalTokens
	case r.CountTokensResponse != nil && r.CountTokensResponse.TotalTokens != nil:
		return *r.CountTokensResponse.TotalTokens
	}
	return 0
}

// DeepIntShieldMCPResponse is the response struct for all MCP responses.
// only ONE of the following fields should be set:
// - ChatMessage
// - ResponsesMessage
type DeepIntShieldMCPResponse struct {
	ChatMessage      *ChatMessage
	ResponsesMessage *ResponsesMessage
	ExtraFields      DeepIntShieldMCPResponseExtraFields
}

// DeepIntShieldResponseExtraFields contains additional fields in a response.
type DeepIntShieldResponseExtraFields struct {
	RequestType        RequestType                      `json:"request_type"`
	Provider           ModelProvider                    `json:"provider,omitempty"`
	ModelRequested     string                           `json:"model_requested,omitempty"`
	ModelDeployment    string                           `json:"model_deployment,omitempty"` // only present for providers which use model deployments (e.g. Azure, Bedrock)
	Latency            int64                            `json:"latency"`                    // in milliseconds (for streaming responses this will be each chunk latency, and the last chunk latency will be the total latency)
	ChunkIndex         int                              `json:"chunk_index"`                // used for streaming responses to identify the chunk index, will be 0 for non-streaming responses
	RawRequest         interface{}                      `json:"raw_request,omitempty"`
	RawResponse        interface{}                      `json:"raw_response,omitempty"`
	CacheDebug         *DeepIntShieldCacheDebug         `json:"cache_debug,omitempty"`
	CascadeDebug       *DeepIntShieldCascadeDebug       `json:"cascade_debug,omitempty"`        // populated when cascade routing is enabled
	BatchDebug         *DeepIntShieldBatchDebug         `json:"batch_debug,omitempty"`          // populated when the request is batch-eligible
	ReasoningDebug     *DeepIntShieldReasoningDebug     `json:"reasoning_debug,omitempty"`      // populated when reasoning throttling fires (or samples)
	CompressionDebug   *DeepIntShieldCompressionDebug   `json:"compression_debug,omitempty"`    // populated when prompt compression fires
	RagDebug           *DeepIntShieldRagDebug           `json:"rag_debug,omitempty"`            // populated when RAG context trimming runs
	SummarizationDebug *DeepIntShieldSummarizationDebug `json:"summarization_debug,omitempty"`  // populated when conversation summarization replaces old turns
	TTFTDebug          *DeepIntShieldTTFTDebug          `json:"ttft_debug,omitempty"`           // populated when TTFT prompt-structure optimization fires
	ParallelToolsDebug *DeepIntShieldParallelToolsDebug `json:"parallel_tools_debug,omitempty"` // populated when an agent batch had its tool calls classified for parallel dispatch
	ConsistencyDebug   *DeepIntShieldConsistencyDebug   `json:"consistency_debug,omitempty"`    // populated when the Response Consistency engine served a cached answer (cache hit)

	// Hallucination Control - proactive mitigation telemetry. Set in
	// PostLLMHook by the semantic_cache plugin when one or more
	// mitigations were applied to the request. The logger plugin maps
	// these into dedicated columns on the logs table so the dashboard
	// can plot uptake + improvement over time.
	HallucinationControlApplied     bool              `json:"hallucination_control_applied,omitempty"`     // true when at least one technique fired
	HallucinationControlTechniques  string            `json:"hallucination_control_techniques,omitempty"`  // comma-separated technique ids that were applied
	HallucinationControlStrictness  string            `json:"hallucination_control_strictness,omitempty"`  // "low" | "medium" | "high"
	HallucinationControlImprovement float64           `json:"hallucination_control_improvement,omitempty"` // 0..1 heuristic - hedge + citation density on the response
	ParseErrors                     []BatchError      `json:"parse_errors,omitempty"`                      // errors encountered while parsing JSONL batch results
	LiteLLMCompat                   bool              `json:"litellm_compat,omitempty"`
	ProviderResponseHeaders         map[string]string `json:"provider_response_headers,omitempty"` // HTTP response headers from the provider (filtered to exclude transport-level headers)
}

// DeepIntShieldCascadeDebug carries cascade routing signal output. Stamped by
// the semantic_cache plugin's PostLLMHook when CascadeRoutingEnabled is true so
// downstream (SDK retry helper, dashboard, audit log) can act on it without
// re-scoring.
type DeepIntShieldCascadeDebug struct {
	Score           float64 `json:"score"`                   // 0..1 confidence; -1 means signal unavailable
	Source          string  `json:"source"`                  // "logprob" | "self_eval" | "schema_validation"
	Threshold       float64 `json:"threshold"`               // configured escalation threshold
	NeedsEscalation bool    `json:"needs_escalation"`        // true when score < threshold
	ParallelMode    bool    `json:"parallel_mode,omitempty"` // when true, caller fired cheap+strong in parallel
}

// DeepIntShieldBatchDebug carries batch-eligibility output. Stamped by the
// semantic_cache plugin when BatchRoutingEnabled is true and the request
// matches eligibility rules - surfaces a "this could be batched" signal to
// the dashboard and audit log without changing the request's sync lifecycle.
type DeepIntShieldBatchDebug struct {
	Eligible            bool   `json:"eligible"`                        // true when the request matched batch routing rules
	Provider            string `json:"provider,omitempty"`              // provider whose batch tier would apply
	EstimatedSavingsPct int    `json:"estimated_savings_pct,omitempty"` // typically 50 (provider batch-tier discount)
}

// DeepIntShieldReasoningDebug carries reasoning-effort throttling output for
// reasoning-capable models (OpenAI o-series, Claude extended thinking, Gemini
// Deep Think). Stamped by the semantic_cache plugin in PreLLMHook when
// ReasoningThrottleEnabled is true and the model is on the whitelist.
//
// Downstream (pricing.go) reads this to compute an *estimated* savings figure
// for the dashboard. The estimate uses industry-known effort multipliers
// (high ≈ 12× low) and the provider-reported reasoning_tokens - it's
// directionally accurate but not a measured A/B comparison.
type DeepIntShieldReasoningDebug struct {
	Applied        bool   `json:"applied"`                   // true when the gateway rewrote reasoning.effort
	OriginalEffort string `json:"original_effort,omitempty"` // caller's effort (or workspace fallback) before rewrite
	AppliedEffort  string `json:"applied_effort,omitempty"`  // effort the gateway forwarded upstream
	TaskType       string `json:"task_type,omitempty"`       // task-type label that drove the decision (empty = default fallback)
	MaxTokensCap   int    `json:"max_tokens_cap,omitempty"`  // configured reasoning.max_tokens cap (0 = no cap)
	Sampled        bool   `json:"sampled,omitempty"`         // true when the request was passed through at the caller's effort for drift monitoring
}

// DeepIntShieldParallelToolsDebug carries parallel-tool-execution telemetry
// for an agent step where the model returned multiple tool calls. Stamped
// by the MCP agent loop after classifying each tool call as parallel-safe
// or sequential and dispatching accordingly.
//
// Numbers are measured: total_tools = the count returned in the model's
// response; parallel_count = how many we fanned out concurrently;
// sequential_count = how many ran one-at-a-time because they were tagged
// unsafe-for-parallel (state-mutating, billing, inventory, etc.).
//
// Latency-saved estimate = the difference between observed wall-clock
// fan-out time and the sum of per-tool durations - directional, not exact,
// since some serial work overlapped with each goroutine's own wait.
type DeepIntShieldParallelToolsDebug struct {
	Applied                bool `json:"applied"`                            // true when classification ran on this step
	TotalTools             int  `json:"total_tools,omitempty"`              // tool calls in the model's response
	ParallelCount          int  `json:"parallel_count,omitempty"`           // dispatched concurrently
	SequentialCount        int  `json:"sequential_count,omitempty"`         // dispatched one-at-a-time
	WallClockMs            int  `json:"wall_clock_ms,omitempty"`            // observed fan-out wall time
	SerialEstimateMs       int  `json:"serial_estimate_ms,omitempty"`       // sum of per-tool durations (what serial execution would have cost)
	LatencySavedMs         int  `json:"latency_saved_ms,omitempty"`         // SerialEstimateMs − WallClockMs, clamped ≥ 0
	UnknownToolsSerialized int  `json:"unknown_tools_serialized,omitempty"` // tools not in the safety registry that fell back to sequential
}

// DeepIntShieldTTFTDebug carries Time-to-First-Token optimisation output.
// Stamped by the semantic_cache plugin's PreLLMHook when the request was
// reorganized to put static content (system messages, tool definitions, RAG
// corpus, conversation history) at the prompt's stable head and the dynamic
// latest user turn at the tail - maximising provider-side prompt-cache
// prefix length.
//
// Numbers reported here are measured: count of messages physically reordered,
// tokens in the now-stable prefix. The dollar impact lands in the existing
// `prompt_cache_savings` column (more stable prefix → bigger cache hits)
// - no double-counting.
type DeepIntShieldTTFTDebug struct {
	Applied            bool `json:"applied"`                        // true when the gateway reordered the messages
	MessagesReordered  int  `json:"messages_reordered,omitempty"`   // count of messages that moved positions
	StablePrefixTokens int  `json:"stable_prefix_tokens,omitempty"` // estimated tokens in the now-stable prefix (system + tools + RAG)
	Sampled            bool `json:"sampled,omitempty"`              // drift-sample pass-through (original order forwarded)
}

// DeepIntShieldSummarizationDebug carries conversation-summarization output.
// Stamped by the semantic_cache plugin's PreLLMHook when an active session
// crosses the configured turn / token threshold and the gateway swapped older
// turns for a structured summary. Numbers are measured: original token count
// comes from the messages we replaced; saved tokens = original − summary.
type DeepIntShieldSummarizationDebug struct {
	Applied         bool   `json:"applied"`                    // true when the gateway swapped old turns for a summary
	TurnsSummarized int    `json:"turns_summarized,omitempty"` // count of messages collapsed into the summary
	TurnsKept       int    `json:"turns_kept,omitempty"`       // count of recent turns preserved verbatim
	OriginalTokens  int    `json:"original_tokens,omitempty"`  // pre-summarize tokens in the replaced span
	SummaryTokens   int    `json:"summary_tokens,omitempty"`   // tokens in the inserted summary message
	SavedTokens     int    `json:"saved_tokens,omitempty"`     // original − summary
	SummarizerModel string `json:"summarizer_model,omitempty"` // model used to produce the summary
	CacheHit        bool   `json:"cache_hit,omitempty"`        // true when the summary came from the session-summary LRU
	Sampled         bool   `json:"sampled,omitempty"`          // drift-sample pass-through (original history forwarded)
	AsyncKickoff    bool   `json:"async_kickoff,omitempty"`    // true when the request triggered an async summary build for the next turn
}

// DeepIntShieldRagDebug carries RAG context-trimming output. Stamped by the
// semantic_cache plugin's PreLLMHook when the request matched a RAG-shaped
// prompt (XML/markdown chunks detected), the workspace switch is on, and
// the per-VK scope permits it. Numbers are measured (not projected): chunk
// counts come from the detector, the reranker reports per-chunk scores,
// and trimmed-token counts are computed from the actual dropped text.
type DeepIntShieldRagDebug struct {
	Applied         bool    `json:"applied"`                     // true when the gateway rewrote the prompt
	ChunksDetected  int     `json:"chunks_detected,omitempty"`   // chunks found by the detector
	ChunksKept      int     `json:"chunks_kept,omitempty"`       // chunks forwarded after reranking
	TrimmedTokens   int     `json:"trimmed_tokens,omitempty"`    // tokens removed by dropping low-relevance chunks
	OriginalTokens  int     `json:"original_tokens,omitempty"`   // total chunk tokens before trim
	Threshold       float64 `json:"threshold,omitempty"`         // top_score − threshold cutoff used
	TopScore        float64 `json:"top_score,omitempty"`         // highest reranker score (sanity check)
	RerankLatencyMs int     `json:"rerank_latency_ms,omitempty"` // wall time spent in the reranker call (0 on cache hit)
	Reranker        string  `json:"reranker,omitempty"`          // model id that produced the scores
	CacheHit        bool    `json:"cache_hit,omitempty"`         // true when scores came from the LRU
	Sampled         bool    `json:"sampled,omitempty"`           // drift-sample pass-through (untrimmed)
}

// DeepIntShieldCompressionDebug carries prompt-compression output (LLMLingua-2
// / RECOMP). Stamped by the semantic_cache plugin in PreLLMHook when the
// feature is enabled and the prompt is a viable candidate (long enough,
// supported provider, not a code/tool-heavy request, VK in scope).
//
// Downstream (pricing.go) reads this to attribute *measured* savings: we
// know the exact token delta (original − compressed) and multiply by the
// model's input rate. Unlike the reasoning estimate, this one is exact.
type DeepIntShieldCompressionDebug struct {
	Applied              bool    `json:"applied"`                          // true when the gateway rewrote the prompt
	OriginalTokens       int     `json:"original_tokens,omitempty"`        // tokens in the pre-compression prompt (counted by the compressor)
	CompressedTokens     int     `json:"compressed_tokens,omitempty"`      // tokens after compression
	TargetRate           float64 `json:"target_rate,omitempty"`            // configured compression target (0..1; "keep this fraction")
	AchievedRate         float64 `json:"achieved_rate,omitempty"`          // compressed/original; differs from target when the model couldn't drop more without breaking syntax
	CacheHit             bool    `json:"cache_hit,omitempty"`              // true when the compressed prompt was served from the LRU prefix cache
	Sampled              bool    `json:"sampled,omitempty"`                // drift-monitoring pass-through; original prompt sent unchanged
	CompressionLatencyMs int     `json:"compression_latency_ms,omitempty"` // wall time spent inside the compression call (0 on cache hits)
}

// DeepIntShieldConsistencyDebug carries Response-Consistency-Engine output.
// Stamped by the response_consistency plugin's PreLLMHook when it serves a
// cached answer (exact / semantic / pinned hit) and short-circuits the LLM
// call. The plugin ships in-process with no pricing catalog, so it carries the
// *avoided token counts* (prompt tokens from the incoming request + completion
// tokens estimated from the cached answer) rather than a dollar figure.
//
// Downstream (pricing.go CalculateConsistencySavings) prices these at the
// model's base input/output rates to attribute the cost the cache hit avoided -
// making RCE the 7th cost-optimization source folded into cache_savings,
// windowed + workspace-scoped like every other source.
type DeepIntShieldConsistencyDebug struct {
	Applied                 bool   `json:"applied"`                             // true when the engine served a cached answer (full LLM call avoided)
	Source                  string `json:"source,omitempty"`                    // "exact" | "semantic" | "pinned"
	Model                   string `json:"model,omitempty"`                     // model the avoided call would have used (drives pricing)
	AvoidedPromptTokens     int    `json:"avoided_prompt_tokens,omitempty"`     // prompt tokens that would have been billed on the avoided call
	AvoidedCompletionTokens int    `json:"avoided_completion_tokens,omitempty"` // estimated completion tokens of the avoided call
}

type DeepIntShieldMCPResponseExtraFields struct {
	ClientName string `json:"client_name"`
	ToolName   string `json:"tool_name"`
	Latency    int64  `json:"latency"`             // in milliseconds
	CacheHit   bool   `json:"cache_hit,omitempty"` // true when the response was served from the mcpcache plugin
}

// DeepIntShieldCacheDebug represents debug information about the cache.
type DeepIntShieldCacheDebug struct {
	CacheHit bool `json:"cache_hit"`

	CacheID                   *string `json:"cache_id,omitempty"`
	HitType                   *string `json:"hit_type,omitempty"`
	EffectiveCacheKey         *string `json:"effective_cache_key,omitempty"`
	ScopeType                 *string `json:"scope_type,omitempty"`
	ScopeValueHash            *string `json:"scope_value_hash,omitempty"`
	ScopeSource               *string `json:"scope_source,omitempty"`
	SemanticSuppressedReason  *string `json:"semantic_suppressed_reason,omitempty"`
	GuardrailReused           *bool   `json:"guardrail_reused,omitempty"`
	GuardrailCacheSource      *string `json:"guardrail_cache_source,omitempty"`
	GuardrailFingerprintMatch *bool   `json:"guardrail_fingerprint_match,omitempty"`

	// Semantic cache only (provider, model, and input tokens will be present for semantic cache, even if cache is not hit)
	ProviderUsed *string `json:"provider_used,omitempty"`
	ModelUsed    *string `json:"model_used,omitempty"`
	InputTokens  *int    `json:"input_tokens,omitempty"`

	// Semantic cache only (only when cache is hit)
	Threshold  *float64 `json:"threshold,omitempty"`
	Similarity *float64 `json:"similarity,omitempty"`
}

const (
	RequestCancelled = "request_cancelled"
	RequestTimedOut  = "request_timed_out"
)

// DeepIntShieldStreamChunk represents a stream of responses from the DeepIntShield system.
// Either DeepIntShieldResponse or DeepIntShieldError will be non-nil.
type DeepIntShieldStreamChunk struct {
	*DeepIntShieldTextCompletionResponse
	*DeepIntShieldChatResponse
	*DeepIntShieldResponsesStreamResponse
	*DeepIntShieldSpeechStreamResponse
	*DeepIntShieldTranscriptionStreamResponse
	*DeepIntShieldImageGenerationStreamResponse
	*DeepIntShieldPassthroughResponse
	*DeepIntShieldError
}

// MarshalJSON implements custom JSON marshaling for DeepIntShieldStreamChunk.
// This ensures that only the non-nil embedded struct is marshaled,
func (bs DeepIntShieldStreamChunk) MarshalJSON() ([]byte, error) {
	if bs.DeepIntShieldTextCompletionResponse != nil {
		return Marshal(bs.DeepIntShieldTextCompletionResponse)
	} else if bs.DeepIntShieldChatResponse != nil {
		return Marshal(bs.DeepIntShieldChatResponse)
	} else if bs.DeepIntShieldResponsesStreamResponse != nil {
		return Marshal(bs.DeepIntShieldResponsesStreamResponse)
	} else if bs.DeepIntShieldSpeechStreamResponse != nil {
		return Marshal(bs.DeepIntShieldSpeechStreamResponse)
	} else if bs.DeepIntShieldTranscriptionStreamResponse != nil {
		return Marshal(bs.DeepIntShieldTranscriptionStreamResponse)
	} else if bs.DeepIntShieldImageGenerationStreamResponse != nil {
		return Marshal(bs.DeepIntShieldImageGenerationStreamResponse)
	} else if bs.DeepIntShieldPassthroughResponse != nil {
		return Marshal(bs.DeepIntShieldPassthroughResponse)
	} else if bs.DeepIntShieldError != nil {
		return Marshal(bs.DeepIntShieldError)
	}
	// Return empty object if both are nil (shouldn't happen in practice)
	return []byte("{}"), nil
}

// DeepIntShieldError represents an error from the DeepIntShield system.
//
// PLUGIN DEVELOPERS: When creating DeepIntShieldError in PreLLMHook or PostLLMHook, you can set AllowFallbacks:
// - AllowFallbacks = &true: DeepIntShield will try fallback providers if available
// - AllowFallbacks = &false: DeepIntShield will return this error immediately, no fallbacks
// - AllowFallbacks = nil: Treated as true by default (fallbacks allowed for resilience)
type DeepIntShieldError struct {
	EventID              *string                       `json:"event_id,omitempty"`
	Type                 *string                       `json:"type,omitempty"`
	IsDeepIntShieldError bool                          `json:"is_deepintshield_error"`
	StatusCode           *int                          `json:"status_code,omitempty"`
	Error                *ErrorField                   `json:"error"`
	AllowFallbacks       *bool                         `json:"-"` // Optional: Controls fallback behavior (nil = true by default)
	StreamControl        *StreamControl                `json:"-"` // Optional: Controls stream behavior
	ExtraFields          DeepIntShieldErrorExtraFields `json:"extra_fields"`
}

// StreamControl represents stream control options.
type StreamControl struct {
	LogError   *bool `json:"log_error,omitempty"`   // Optional: Controls logging of error
	SkipStream *bool `json:"skip_stream,omitempty"` // Optional: Controls skipping of stream chunk
}

// ErrorField represents detailed error information.
type ErrorField struct {
	Type    *string     `json:"type,omitempty"`
	Code    *string     `json:"code,omitempty"`
	Message string      `json:"message"`
	Error   error       `json:"-"`
	Param   interface{} `json:"param,omitempty"`
	EventID *string     `json:"event_id,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for ErrorField.
// It converts the Error field (error interface) to a string.
func (e *ErrorField) MarshalJSON() ([]byte, error) {
	type Alias ErrorField
	aux := &struct {
		Error *string `json:"error,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}

	if e.Error != nil {
		errStr := e.Error.Error()
		aux.Error = &errStr
	}

	return json.Marshal(aux)
}

func (e *ErrorField) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Type    *string     `json:"type,omitempty"`
		Code    interface{} `json:"code,omitempty"`
		Message string      `json:"message"`
		Error   *string     `json:"error,omitempty"`
		Param   interface{} `json:"param,omitempty"`
		EventID *string     `json:"event_id,omitempty"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	e.Type = aux.Type
	e.Message = aux.Message
	e.Param = aux.Param
	e.EventID = aux.EventID
	if aux.Error != nil {
		e.Error = errors.New(*aux.Error)
	}
	if aux.Code != nil {
		switch v := aux.Code.(type) {
		case string:
			e.Code = &v
		case float64:
			s := strconv.FormatInt(int64(v), 10)
			e.Code = &s
		default:
			s := fmt.Sprint(aux.Code)
			e.Code = &s
		}
	}
	return nil
}

// DeepIntShieldErrorExtraFields contains additional fields in an error response.
type DeepIntShieldErrorExtraFields struct {
	Provider       ModelProvider `json:"provider,omitempty"`
	ModelRequested string        `json:"model_requested,omitempty"`
	RequestType    RequestType   `json:"request_type,omitempty"`
	RawRequest     interface{}   `json:"raw_request,omitempty"`
	RawResponse    interface{}   `json:"raw_response,omitempty"`
	LiteLLMCompat  bool          `json:"litellm_compat,omitempty"`
	KeyStatuses    []KeyStatus   `json:"key_statuses,omitempty"`
}
