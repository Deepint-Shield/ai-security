// Package semanticcache provides semantic caching integration for DeepIntShield plugin.
// This plugin caches responses using both direct hash matching (xxhash) and semantic similarity search (embeddings).
// It supports configurable caching behavior via the VectorStore abstraction, with TTL management and streaming response handling.
package semanticcache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/framework/vectorstore"
	"github.com/deepint-shield/ai-security/plugins/guardrails"
)

// Config contains configuration for the semantic cache plugin.
// The VectorStore abstraction handles the underlying storage implementation and its defaults.
// Only specify values you want to override from the semantic cache defaults.
type Config struct {
	// Embedding Model settings - REQUIRED for semantic caching
	Provider       schemas.ModelProvider  `json:"provider"`
	Keys           []schemas.Key          `json:"keys"`
	EmbeddingModel string                 `json:"embedding_model,omitempty"` // Model to use for generating embeddings (optional)
	NetworkConfig  *schemas.NetworkConfig `json:"network_config,omitempty"`  // Override provider endpoint (e.g. base_url) for local/in-cluster embedding servers. Falls back to schemas.DefaultNetworkConfig when nil.

	// Plugin behavior settings
	CleanUpOnShutdown    bool          `json:"cleanup_on_shutdown,omitempty"`    // Clean up cache on shutdown (default: false)
	TTL                  time.Duration `json:"ttl,omitempty"`                    // Time-to-live for cached responses (default: 5min)
	Threshold            float64       `json:"threshold,omitempty"`              // Cosine similarity threshold for semantic matching (default: 0.8)
	VectorStoreNamespace string        `json:"vector_store_namespace,omitempty"` // Namespace for vector store (optional)
	Dimension            int           `json:"dimension"`                        // Dimension for vector store

	// Per-feature virtual-key scopes - when non-empty, the listed VK IDs are
	// the only ones that get the feature; everyone else falls through as
	// though the feature were disabled. Empty (the default) = applies to all
	// virtual keys.
	SemanticCacheVKScope []string `json:"semantic_cache_vk_scope,omitempty"` // empty = all VKs; non-empty = only these VK IDs
	PromptCacheVKScope   []string `json:"prompt_cache_vk_scope,omitempty"`   // empty = all VKs; non-empty = only these VK IDs

	// Advanced caching behavior
	DefaultCacheKey              string                 `json:"default_cache_key,omitempty"`              // Default cache key used when no per-request key is provided (optional, deterministic fallback key is used otherwise)
	ConversationHistoryThreshold int                    `json:"conversation_history_threshold,omitempty"` // Skip caching for requests with more than this number of messages in the conversation history (default: 3)
	CacheByModel                 *bool                  `json:"cache_by_model,omitempty"`                 // Include model in cache key (default: true)
	CacheByProvider              *bool                  `json:"cache_by_provider,omitempty"`              // Include provider in cache key (default: true)
	ExcludeSystemPrompt          *bool                  `json:"exclude_system_prompt,omitempty"`          // Exclude system prompt in cache key (default: false)
	AutoScopeEnabled             *bool                  `json:"auto_scope_enabled,omitempty"`
	AutoScopeMode                AutoScopeMode          `json:"auto_scope_mode,omitempty"`
	SharedVKPolicy               SharedVirtualKeyPolicy `json:"shared_vk_policy,omitempty"`
	ScopeSignalOrder             []string               `json:"scope_signal_order,omitempty"`
	MetadataScopeKeys            []string               `json:"metadata_scope_keys,omitempty"`

	// Provider-native prompt caching (separate mechanism from semantic caching above).
	// When enabled, the gateway passes through provider cache hints (Anthropic
	// `cache_control` blocks, OpenAI `prompt_cache_key`) on outbound requests so the
	// provider can reuse KV state for the static prefix. When disabled, those hints are
	// stripped before forwarding. This is a workspace-level switch; no per-request flag.
	//
	// Provider charges and the existing cost/savings plumbing already handle the
	// resulting `cached_read_tokens` / `cached_write_tokens` returned by the provider -
	// this config only controls whether the gateway emits/keeps the hints in the first place.
	PromptCacheEnabled         *bool    `json:"prompt_cache_enabled,omitempty"`           // Master switch (default: true)
	PromptCacheProviders       []string `json:"prompt_cache_providers,omitempty"`         // Providers to honor markers for (default: ["anthropic","openai","bedrock"])
	PromptCacheAnthropicTTL    string   `json:"prompt_cache_anthropic_ttl,omitempty"`     // "5m" (default, no write premium) or "1h" (2x premium)
	PromptCacheGoogleTTL       string   `json:"prompt_cache_google_ttl,omitempty"`        // Gemini context cache TTL: "5m", "1h" (default), "6h", "24h"
	PromptCacheMinStaticTokens int      `json:"prompt_cache_min_static_tokens,omitempty"` // Skip marking prefixes below this token count (default: 1024; Gemini needs ~32768)
	PromptCacheBreakpoints     []string `json:"prompt_cache_breakpoints,omitempty"`       // Which static portions to mark: "system", "tools", "large_blocks" (default: ["system","tools"])

	// Embedding-via-VK - when EmbeddingViaVKEnabled is true the semantic
	// cache stops calling the local huggingface sidecar and routes embedding
	// generation through EmbeddingVKID (an operator-chosen workspace VK).
	// The provider's embedding endpoint (e.g. OpenAI text-embedding-3-small)
	// generates the vector; the gateway's governance plugin resolves the
	// VK's API key at request time. Lets fresh workspaces get a working
	// semantic cache without running the embedding sidecar container.
	//
	// Zero-latency design: embedding generation is fired in the same async
	// path as the legacy sidecar - direct-match lookup runs synchronously
	// against the hash bucket, vector lookup runs async after embedding
	// completes. Cold-miss requests see no added wall-clock latency.
	EmbeddingViaVKEnabled *bool  `json:"embedding_via_vk_enabled,omitempty"`
	EmbeddingVKID         string `json:"embedding_vk_id,omitempty"`
	EmbeddingViaVKModel   string `json:"embedding_via_vk_model,omitempty"` // e.g. "text-embedding-3-small"

	// Basic hallucination control - proactive, prompt/parameter-only mitigation
	// applied in PreLLMHook (zero added round-trips, zero added latency). The
	// ML-backed faithfulness/citation scoring is a premium feature and is not
	// part of the open-source build.
	HallucinationControlEnabled    *bool    `json:"hallucination_control_enabled,omitempty"`
	HallucinationControlTechniques []string `json:"hallucination_control_techniques,omitempty"` // grounding_directive | anti_fabrication | citation_required | uncertainty_ack | temperature_clamp
	HallucinationControlStrictness string   `json:"hallucination_control_strictness,omitempty"` // low | medium (default) | high
	HallucinationControlVKScope    []string `json:"hallucination_control_vk_scope,omitempty"`   // empty = all VKs
	HallucinationControlTempCap    float64  `json:"hallucination_control_temp_cap,omitempty"`   // upper bound for temperature_clamp; default 0.4
}

// UnmarshalJSON implements custom JSON unmarshaling for semantic cache Config.
// It supports TTL parsing from both string durations ("1m", "1hr") and numeric seconds for configurable cache behavior.
func (c *Config) UnmarshalJSON(data []byte) error {
	// Define a temporary struct to avoid infinite recursion
	type TempConfig struct {
		Provider                            string                           `json:"provider"`
		Keys                                []schemas.Key                    `json:"keys"`
		EmbeddingModel                      string                           `json:"embedding_model,omitempty"`
		NetworkConfig                       *schemas.NetworkConfig           `json:"network_config,omitempty"`
		CleanUpOnShutdown                   bool                             `json:"cleanup_on_shutdown,omitempty"`
		Dimension                           int                              `json:"dimension"`
		TTL                                 interface{}                      `json:"ttl,omitempty"`
		Threshold                           float64                          `json:"threshold,omitempty"`
		VectorStoreNamespace                string                           `json:"vector_store_namespace,omitempty"`
		SemanticCacheVKScope         []string               `json:"semantic_cache_vk_scope,omitempty"`
		PromptCacheVKScope           []string               `json:"prompt_cache_vk_scope,omitempty"`
		DefaultCacheKey              string                 `json:"default_cache_key,omitempty"`
		ConversationHistoryThreshold int                    `json:"conversation_history_threshold,omitempty"`
		CacheByModel                 *bool                  `json:"cache_by_model,omitempty"`
		CacheByProvider              *bool                  `json:"cache_by_provider,omitempty"`
		ExcludeSystemPrompt          *bool                  `json:"exclude_system_prompt,omitempty"`
		AutoScopeEnabled             *bool                  `json:"auto_scope_enabled,omitempty"`
		AutoScopeMode                AutoScopeMode          `json:"auto_scope_mode,omitempty"`
		SharedVKPolicy               SharedVirtualKeyPolicy `json:"shared_vk_policy,omitempty"`
		ScopeSignalOrder             []string               `json:"scope_signal_order,omitempty"`
		MetadataScopeKeys            []string               `json:"metadata_scope_keys,omitempty"`
		TTLSeconds                   *int                   `json:"ttl_seconds,omitempty"`
		PromptCacheEnabled           *bool                  `json:"prompt_cache_enabled,omitempty"`
		PromptCacheProviders         []string               `json:"prompt_cache_providers,omitempty"`
		PromptCacheAnthropicTTL      string                 `json:"prompt_cache_anthropic_ttl,omitempty"`
		PromptCacheGoogleTTL         string                 `json:"prompt_cache_google_ttl,omitempty"`
		PromptCacheMinStaticTokens   int                    `json:"prompt_cache_min_static_tokens,omitempty"`
		PromptCacheBreakpoints       []string               `json:"prompt_cache_breakpoints,omitempty"`
		EmbeddingViaVKEnabled        *bool                  `json:"embedding_via_vk_enabled,omitempty"`
		EmbeddingVKID                string                 `json:"embedding_vk_id,omitempty"`
		EmbeddingViaVKModel          string                 `json:"embedding_via_vk_model,omitempty"`
		HallucinationControlEnabled    *bool    `json:"hallucination_control_enabled,omitempty"`
		HallucinationControlTechniques []string `json:"hallucination_control_techniques,omitempty"`
		HallucinationControlStrictness string   `json:"hallucination_control_strictness,omitempty"`
		HallucinationControlVKScope    []string `json:"hallucination_control_vk_scope,omitempty"`
		HallucinationControlTempCap    float64  `json:"hallucination_control_temp_cap,omitempty"`
	}

	var temp TempConfig
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set simple fields
	c.Provider = schemas.ModelProvider(temp.Provider)
	c.Keys = temp.Keys
	c.EmbeddingModel = temp.EmbeddingModel
	c.NetworkConfig = temp.NetworkConfig
	c.CleanUpOnShutdown = temp.CleanUpOnShutdown
	c.Dimension = temp.Dimension
	c.CacheByModel = temp.CacheByModel
	c.CacheByProvider = temp.CacheByProvider
	c.VectorStoreNamespace = temp.VectorStoreNamespace
	c.SemanticCacheVKScope = temp.SemanticCacheVKScope
	c.PromptCacheVKScope = temp.PromptCacheVKScope
	c.ConversationHistoryThreshold = temp.ConversationHistoryThreshold
	c.Threshold = temp.Threshold
	c.DefaultCacheKey = temp.DefaultCacheKey
	c.ExcludeSystemPrompt = temp.ExcludeSystemPrompt
	c.AutoScopeEnabled = temp.AutoScopeEnabled
	c.AutoScopeMode = temp.AutoScopeMode
	c.SharedVKPolicy = temp.SharedVKPolicy
	c.ScopeSignalOrder = temp.ScopeSignalOrder
	c.MetadataScopeKeys = temp.MetadataScopeKeys
	c.PromptCacheEnabled = temp.PromptCacheEnabled
	c.PromptCacheProviders = temp.PromptCacheProviders
	c.PromptCacheAnthropicTTL = temp.PromptCacheAnthropicTTL
	c.PromptCacheGoogleTTL = temp.PromptCacheGoogleTTL
	c.PromptCacheMinStaticTokens = temp.PromptCacheMinStaticTokens
	c.PromptCacheBreakpoints = temp.PromptCacheBreakpoints
	c.EmbeddingViaVKEnabled = temp.EmbeddingViaVKEnabled
	c.EmbeddingVKID = temp.EmbeddingVKID
	c.EmbeddingViaVKModel = temp.EmbeddingViaVKModel
	c.HallucinationControlEnabled = temp.HallucinationControlEnabled
	c.HallucinationControlTechniques = temp.HallucinationControlTechniques
	c.HallucinationControlStrictness = temp.HallucinationControlStrictness
	c.HallucinationControlVKScope = temp.HallucinationControlVKScope
	c.HallucinationControlTempCap = temp.HallucinationControlTempCap
	// Handle TTL field with custom parsing for VectorStore-backed cache behavior
	if temp.TTL != nil {
		switch v := temp.TTL.(type) {
		case string:
			// Try parsing as duration string (e.g., "1m", "1hr") for semantic cache TTL
			duration, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("failed to parse TTL duration string '%s': %w", v, err)
			}
			c.TTL = duration
		case int:
			// Handle integer seconds for semantic cache TTL
			c.TTL = time.Duration(v) * time.Second
		default:
			// Try converting to string and parsing as number for semantic cache TTL
			ttlStr := fmt.Sprintf("%v", v)
			if seconds, err := strconv.ParseFloat(ttlStr, 64); err == nil {
				c.TTL = time.Duration(seconds * float64(time.Second))
			} else {
				return fmt.Errorf("unsupported TTL type: %T (value: %v)", v, v)
			}
		}
	} else if temp.TTLSeconds != nil {
		c.TTL = time.Duration(*temp.TTLSeconds) * time.Second
	}

	return nil
}

// StreamChunk represents a single chunk from a streaming response
type StreamChunk struct {
	Timestamp    time.Time                      // When chunk was received
	Response     *schemas.DeepIntShieldResponse // The actual response chunk
	FinishReason *string                        // If this is the final chunk
}

// StreamAccumulator manages accumulation of streaming chunks for caching
type StreamAccumulator struct {
	RequestID      string                 // The request ID
	Chunks         []*StreamChunk         // All chunks for this stream
	IsComplete     bool                   // Whether the stream is complete
	HasError       bool                   // Whether any chunk in the stream had an error
	FinalTimestamp time.Time              // When the stream completed
	Embedding      []float32              // Embedding for the original request
	Metadata       map[string]interface{} // Metadata for caching
	TTL            time.Duration          // TTL for this cache entry
	mu             sync.Mutex             // Protects chunk operations
}

// Plugin implements the schemas.LLMPlugin interface for semantic caching.
// It caches responses using a two-tier approach: direct hash matching for exact requests
// and semantic similarity search for related content. The plugin supports configurable caching behavior
// via the VectorStore abstraction, including TTL management and streaming response handling.
//
// Fields:
//   - store: VectorStore instance for semantic cache operations
//   - config: Plugin configuration including semantic cache and caching settings
//   - logger: Logger instance for plugin operations
type Plugin struct {
	store              vectorstore.VectorStore
	config             *Config
	logger             schemas.Logger
	client             *deepintshield.DeepIntShield
	requestKeyProvider RequestKeyProvider
	streamAccumulators sync.Map // Track stream accumulators by request ID
	waitGroup          sync.WaitGroup
	cleanupCancel      context.CancelFunc
	stage              pluginStage
	guardrailReuse     guardrails.CacheReuseProvider
	evidenceStore      logstore.GuardrailEvidenceStore
	// Embedding LRU - keyed on (provider, model, text), holds the raw vector
	// returned by the embedding sidecar / VK. Eliminates the per-call HTTP
	// RTT for prompts already seen (templated chat, retry storms, paraphrase
	// clusters). Nil-safe: lookup short-circuits when nil.
	embeddingCache *embeddingCache
	// Direct-gate L1 - in-process, bounded, TTL'd cache in front of the
	// remote exact-hash GetAll lookup. The direct gate's query is a pure
	// equality match → at most one immutable row, so it read-through caches
	// perfectly: only the first store-hit per key pays the ~180 ms vector-
	// store RTT, every identical repeat serves from a ~80 ns map read. Nil
	// when disabled (env). Isolation + ZDR safety: see direct_l1.go.
	directL1 *directL1Cache
}

// Plugin constants
const (
	PluginName                  string        = "semantic_cache"
	DefaultVectorStoreNamespace string        = "DeepIntShieldSemanticCachePlugin"
	PluginLoggerPrefix          string        = "[Semantic Cache]"
	CacheConnectionTimeout      time.Duration = 5 * time.Second
	CreateNamespaceTimeout      time.Duration = 30 * time.Second
	CacheSetTimeout             time.Duration = 30 * time.Second
	// Default cache TTL - used when the operator hasn't set a workspace-level
	// TTL. Bumped from 5m → 60m because:
	//   * chat-assistant / RAG / FAQ corpora are stable for hours, not minutes
	//   * the cost-savings curve is roughly linear in TTL up to ~1d
	//   * vector store is capped on entry count, not memory pressure, so a
	//     longer TTL doesn't blow up RAM (oldest entries evict naturally)
	// Strict workspaces (privacy-bound tenants) can still set a shorter
	// TTL explicitly - this only changes the unset-default.
	DefaultCacheTTL                     time.Duration = 60 * time.Minute
	DefaultCacheThreshold               float64       = 0.8
	DefaultConversationHistoryThreshold int           = 3
	ExpiredCacheFlushInterval           time.Duration = 15 * time.Minute
	DefaultTenantID                     string        = "global"
)

var SelectFields = []string{"request_hash", "original_request_hash", "response", "stream_chunks", "expires_at", "cache_key", "provider", "model", "scope_type", "scope_source", "scope_value_hash", "guardrail_fingerprint", "guardrail_snapshot"}

var VectorStoreProperties = map[string]vectorstore.VectorStoreProperties{
	"request_hash": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The hash of the request",
	},
	"original_request_hash": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The hash of the original request before guardrail input rewriting",
	},
	"response": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The response from the provider",
	},
	"stream_chunks": {
		DataType:    vectorstore.VectorStorePropertyTypeStringArray,
		Description: "The stream chunks from the provider",
	},
	"expires_at": {
		DataType:    vectorstore.VectorStorePropertyTypeInteger,
		Description: "The expiration time of the cache entry",
	},
	"cache_key": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The cache key from the request",
	},
	"provider": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The provider used for the request",
	},
	"model": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The model used for the request",
	},
	"tenant_id": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The tenant that owns the cache entry",
	},
	"params_hash": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The hash of the parameters used for the request",
	},
	"from_deepintshield_semantic_cache_plugin": {
		DataType:    vectorstore.VectorStorePropertyTypeBoolean,
		Description: "Whether the cache entry was created by the DeepIntShieldSemanticCachePlugin",
	},
	"scope_type": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The resolved cache scope type",
	},
	"scope_source": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The signal source used to resolve the cache scope",
	},
	"scope_value_hash": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The hashed value used for cache scope isolation",
	},
	"guardrail_fingerprint": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "The guardrail fingerprint required for direct cache reuse without guardrail runtime evaluation",
	},
	"guardrail_snapshot": {
		DataType:    vectorstore.VectorStorePropertyTypeString,
		Description: "A compact snapshot of guardrail evidence reused for direct cache hits",
	},
}

type PluginAccount struct {
	provider           schemas.ModelProvider
	keys               []schemas.Key
	requestKeyProvider RequestKeyProvider
	networkConfig      *schemas.NetworkConfig
}

type RequestKeyProvider interface {
	GetKeysForProvider(ctx context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error)
}

func (pa *PluginAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{pa.provider}, nil
}

// GetKeysForProvider returns live provider keys when a requestKeyProvider is wired
// (so rotations through the ConfigStore take effect without restarting the gateway).
// Falls back to the static keys captured at plugin Init when the live source is
// unavailable or returns nothing usable.
func (pa *PluginAccount) GetKeysForProvider(ctx context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	if pa.requestKeyProvider != nil {
		if keys, err := pa.requestKeyProvider.GetKeysForProvider(ctx, providerKey); err == nil && len(keys) > 0 {
			return keys, nil
		}
	}
	return pa.keys, nil
}

func (pa *PluginAccount) GetConfigForProvider(providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	networkConfig := schemas.DefaultNetworkConfig
	// Only apply the embedding-sidecar's networkConfig to the embedding
	// provider itself. The previous code returned the sidecar URL for every
	// provider including openai, which made the cost-opt recursive
	// ChatCompletionRequest (summarizer / hallucination eval) POST to
	// http://deepintshield-models:8093 - the local huggingface embedding
	// container - instead of api.openai.com. The local container has no
	// chat-completion route so the request hung indefinitely and surfaced
	// as "context deadline exceeded" without any clue that we'd misrouted
	// the call. networkConfig is only meaningful for the provider whose
	// sidecar we configured; every other provider should use the standard
	// network defaults (api.openai.com, api.anthropic.com, etc.).
	if pa.networkConfig != nil && providerKey == pa.provider {
		networkConfig = *pa.networkConfig
	}
	return &schemas.ProviderConfig{
		NetworkConfig:            networkConfig,
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
	}, nil
}

// Dependencies is a list of dependencies that the plugin requires.
var Dependencies []framework.FrameworkDependency = []framework.FrameworkDependency{framework.FrameworkDependencyVectorStore}

// ProvidersWithEmbeddingSupport lists all providers that support embedding operations.
// Providers not in this list will return UnsupportedOperationError for embedding requests.
var ProvidersWithEmbeddingSupport = map[schemas.ModelProvider]bool{
	schemas.OpenAI:      true,
	schemas.Azure:       true,
	schemas.Bedrock:     true,
	schemas.Cohere:      true,
	schemas.Gemini:      true,
	schemas.Vertex:      true,
	schemas.Mistral:     true,
	schemas.Ollama:      true,
	schemas.Nebius:      true,
	schemas.HuggingFace: true,
	schemas.SGL:         true,
}

const (
	CacheKey          schemas.DeepIntShieldContextKey = "semantic_cache_key"        // To set or cache key fallback for a request
	CacheTTLKey       schemas.DeepIntShieldContextKey = "semantic_cache_ttl"        // To explicitly set the TTL for a request
	CacheThresholdKey schemas.DeepIntShieldContextKey = "semantic_cache_threshold"  // To explicitly set the threshold for a request
	CacheTypeKey      schemas.DeepIntShieldContextKey = "semantic_cache_cache_type" // To explicitly set the cache type for a request
	CacheNoStoreKey   schemas.DeepIntShieldContextKey = "semantic_cache_no_store"   // To explicitly disable storing the response in the cache

	// context keys for internal usage
	requestIDKey              schemas.DeepIntShieldContextKey = "semantic_cache_request_id"
	requestHashKey            schemas.DeepIntShieldContextKey = "semantic_cache_request_hash"
	requestEmbeddingKey       schemas.DeepIntShieldContextKey = "semantic_cache_embedding"
	requestEmbeddingTokensKey schemas.DeepIntShieldContextKey = "semantic_cache_embedding_tokens"
	requestParamsHashKey      schemas.DeepIntShieldContextKey = "semantic_cache_params_hash"
	requestModelKey           schemas.DeepIntShieldContextKey = "semantic_cache_model"
	requestProviderKey        schemas.DeepIntShieldContextKey = "semantic_cache_provider"
	requestStartTimeKey       schemas.DeepIntShieldContextKey = "semantic_cache_request_start_time"
	cacheLookupAttemptedKey   schemas.DeepIntShieldContextKey = "semantic_cache_lookup_attempted"
	isCacheHitKey             schemas.DeepIntShieldContextKey = "semantic_cache_is_cache_hit"
	cacheHitTypeKey           schemas.DeepIntShieldContextKey = "semantic_cache_cache_hit_type"
)

type CacheType string

const (
	CacheTypeDirect   CacheType = "direct"
	CacheTypeSemantic CacheType = "semantic"
)

// Init creates a new semantic cache plugin instance with the provided configuration.
// It uses the VectorStore abstraction for cache operations and returns a configured plugin.
//
// The VectorStore handles the underlying storage implementation and its defaults.
// The plugin only sets defaults for its own behavior (TTL, cache key generation, etc.).
//
// Parameters:
//   - config: Semantic cache and plugin configuration (cache key can be inferred when missing)
//   - logger: Logger instance for the plugin
//   - store: VectorStore instance for cache operations
//
// Returns:
//   - schemas.LLMPlugin: A configured semantic cache plugin instance
//   - error: Any error that occurred during plugin initialization
func Init(ctx context.Context, config *Config, logger schemas.Logger, store vectorstore.VectorStore, requestKeyProviders ...RequestKeyProvider) (schemas.LLMPlugin, error) {
	return initWithStage(ctx, config, logger, store, pluginStageCombined, nil, nil, requestKeyProviders...)
}

func InitDirectGate(ctx context.Context, config *Config, logger schemas.Logger, store vectorstore.VectorStore, evidenceStore logstore.GuardrailEvidenceStore, guardrailReuse guardrails.CacheReuseProvider, requestKeyProviders ...RequestKeyProvider) (schemas.LLMPlugin, error) {
	return initWithStage(ctx, config, logger, store, pluginStageDirectGate, evidenceStore, guardrailReuse, requestKeyProviders...)
}

func InitSemanticLookup(ctx context.Context, config *Config, logger schemas.Logger, store vectorstore.VectorStore, requestKeyProviders ...RequestKeyProvider) (schemas.LLMPlugin, error) {
	return initWithStage(ctx, config, logger, store, pluginStageSemanticLookup, nil, nil, requestKeyProviders...)
}

func initWithStage(ctx context.Context, config *Config, logger schemas.Logger, store vectorstore.VectorStore, stage pluginStage, evidenceStore logstore.GuardrailEvidenceStore, guardrailReuse guardrails.CacheReuseProvider, requestKeyProviders ...RequestKeyProvider) (schemas.LLMPlugin, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	// Set plugin-specific defaults
	if config.VectorStoreNamespace == "" {
		logger.Debug(PluginLoggerPrefix + " Vector store namespace is not set, using default of " + DefaultVectorStoreNamespace)
		config.VectorStoreNamespace = DefaultVectorStoreNamespace
	}
	if config.TTL == 0 {
		logger.Debug(PluginLoggerPrefix + " TTL is not set, using default of 5 minutes")
		config.TTL = DefaultCacheTTL
	}
	if config.Threshold == 0 {
		logger.Debug(PluginLoggerPrefix + " Threshold is not set, using default of " + strconv.FormatFloat(DefaultCacheThreshold, 'f', -1, 64))
		config.Threshold = DefaultCacheThreshold
	}
	if config.ConversationHistoryThreshold == 0 {
		logger.Debug(PluginLoggerPrefix + " Conversation history threshold is not set, using default of " + strconv.Itoa(DefaultConversationHistoryThreshold))
		config.ConversationHistoryThreshold = DefaultConversationHistoryThreshold
	}
	if config.Dimension <= 0 {
		// Derive the vector-store dimension from the embedding model instead of
		// the old default of 1, which silently creates a 1-d namespace that
		// rejects every real (768/1536/…) embedding and breaks all KNN search.
		//
		// The basis must be the model that actually produces the PRIMARY stored
		// vectors. When embedding-via-VK is enabled and reachable, that's the VK
		// model (e.g. text-embedding-3-small → 1536); otherwise it's the local
		// embedding model that the sidecar fallback produces (e.g. BGE → 768).
		// Picking the wrong one creates a namespace that rejects the vectors it's
		// actually fed (the 768-vs-1536 mismatch that broke semantic search).
		dimModel := config.EmbeddingModel
		// The VK (cloud) embedding model only governs the dimension when the
		// embedding actually runs through it. A local-sidecar provider
		// (huggingface/local) ignores viaVK and embeds on the sidecar (see
		// generateEmbedding), so its dimension MUST come from the configured HF
		// model (MiniLM 384 / BGE 768) — deriving it from the VK model here would
		// recreate the namespace at the wrong size and reject every vector.
		if !isLocalSidecarEmbeddingProvider(config.Provider) &&
			config.EmbeddingViaVKEnabled != nil && *config.EmbeddingViaVKEnabled &&
			strings.TrimSpace(config.EmbeddingVKID) != "" {
			if m := strings.TrimSpace(config.EmbeddingViaVKModel); m != "" {
				dimModel = m
			} else {
				dimModel = "text-embedding-3-small" // VK-path default (see generateEmbedding)
			}
		}
		derived := embeddingModelDimension(dimModel)
		logger.Warn(fmt.Sprintf("%s Dimension is not set; derived %d from embedding model %q for namespace creation",
			PluginLoggerPrefix, derived, dimModel))
		config.Dimension = derived
	}

	// Suffix the namespace with the embedding dimension. A single RediSearch
	// index has ONE fixed DIM, but different workspaces sharing the default
	// namespace can run different-dimension embedding backends (local BGE 768
	// vs VK text-embedding-3-small 1536). Whichever workspace Init'd first used
	// to win and lock the index at its dimension, silently breaking KNN for
	// every workspace on the other dimension. Giving each dimension its own
	// index removes the collision; cross-workspace data isolation still comes
	// from the cache_key metadata filter, not the namespace.
	config.VectorStoreNamespace = fmt.Sprintf("%s_d%d", config.VectorStoreNamespace, config.Dimension)

	// Set cache behavior defaults
	if config.CacheByModel == nil {
		config.CacheByModel = deepintshield.Ptr(true)
	}
	if config.CacheByProvider == nil {
		config.CacheByProvider = deepintshield.Ptr(true)
	}
	if config.AutoScopeEnabled == nil {
		config.AutoScopeEnabled = deepintshield.Ptr(true)
	}
	if config.AutoScopeMode == "" {
		config.AutoScopeMode = AutoScopeModeConservative
	}
	if config.SharedVKPolicy == "" {
		config.SharedVKPolicy = SharedVirtualKeyPolicyExactOnlyWhenUnscoped
	}
	if len(config.ScopeSignalOrder) == 0 {
		config.ScopeSignalOrder = append([]string(nil), DefaultScopeSignalOrder...)
	}
	if len(config.MetadataScopeKeys) == 0 {
		config.MetadataScopeKeys = append([]string(nil), DefaultMetadataScopeKeys...)
	}

	plugin := &Plugin{
		store:              store,
		config:             config,
		logger:             logger,
		streamAccumulators: sync.Map{},
		waitGroup:          sync.WaitGroup{},
		stage:              stage,
		evidenceStore:      evidenceStore,
		guardrailReuse:     guardrailReuse,
		embeddingCache:     newEmbeddingCache(defaultEmbeddingCacheSize),
	}
	plugin.directL1 = newDirectL1CacheFromEnv()
	if len(requestKeyProviders) > 0 {
		plugin.requestKeyProvider = requestKeyProviders[0]
	}

	if stage != pluginStageDirectGate {
		// Validate that the embedding provider, when set, supports embeddings.
		// We allow Provider == "" (no embedding sidecar configured): the
		// semantic search path will fall back to direct search, but the
		// recursive client we initialize below still routes summarizer /
		// hallucination calls through governance-resolved VKs.
		if config.Provider != "" && deepintshield.IsStandardProvider(config.Provider) && !ProvidersWithEmbeddingSupport[config.Provider] {
			return nil, fmt.Errorf("provider '%s' does not support embedding operations required for semantic cache. Supported providers: openai, azure, bedrock, cohere, gemini, vertex, mistral, ollama, nebius, huggingface, sgl. Note: custom providers based on embedding-capable providers are also supported", config.Provider)
		}
		// Pick a sane Account.provider for the initialized client. Falling
		// back to OpenAI is just the seed for the Account interface - the
		// recursive ChatCompletionRequest sets the actual provider per-call
		// and governance resolves the VK's keys at request time via
		// requestKeyProvider. The previous code skipped this init entirely
		// when config.Keys was empty (the common dev-workspace shape where
		// the local huggingface/ollama embedding sidecar handles its own
		// auth via networkConfig), which left plugin.client nil and made
		// the async summarizer worker silently drop every job.
		accountProvider := config.Provider
		if accountProvider == "" {
			accountProvider = schemas.OpenAI
		}
		if config.Provider == "" || len(config.Keys) == 0 {
			logger.Warn(PluginLoggerPrefix + " Provider and keys are not configured for the embedding sidecar; semantic search will fall back to direct search, but recursive cost-opt LLM calls (summarizer / hallucination eval) will still run via per-request VK resolution")
		}
		deepintshield, err := deepintshield.Init(ctx, schemas.DeepIntShieldConfig{
			Logger: logger,
			Account: &PluginAccount{
				provider:           accountProvider,
				keys:               config.Keys,
				requestKeyProvider: plugin.requestKeyProvider,
				networkConfig:      config.NetworkConfig,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize deepintshield for semantic cache: %w", err)
		}
		plugin.client = deepintshield
	}

	createCtx, cancel := context.WithTimeout(ctx, CreateNamespaceTimeout)
	defer cancel()
	if err := store.CreateNamespace(createCtx, config.VectorStoreNamespace, config.Dimension, VectorStoreProperties); err != nil {
		return nil, fmt.Errorf("failed to create namespace for semantic cache: %w", err)
	}

	if stage != pluginStageSemanticLookup {
		plugin.startBackgroundMaintenance()
	}

	return plugin, nil
}

// GetName returns the canonical name of the semantic cache plugin.
// This name is used for plugin identification and logging purposes.
//
// Returns:
//   - string: The plugin name for semantic cache
func (plugin *Plugin) GetName() string {
	if plugin.stage == pluginStageDirectGate {
		return DirectGatePluginName
	}
	return PluginName
}

// HTTPTransportPreHook is not used for this plugin
func (plugin *Plugin) HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPostHook is not used for this plugin
func (plugin *Plugin) HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	return nil
}

// HTTPTransportStreamChunkHook passes through streaming chunks unchanged
func (plugin *Plugin) HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, chunk *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	return chunk, nil
}

// PreLLMHook is called before a request is processed by DeepIntShield.
// It performs a two-stage cache lookup: first direct hash matching, then semantic similarity search.
// Uses UUID-based keys for entries stored in the VectorStore.
//
// Parameters:
//   - ctx: Pointer to the schemas.DeepIntShieldContext
//   - req: The incoming DeepIntShield request
//
// Returns:
//   - *schemas.DeepIntShieldRequest: The original request
//   - *schemas.DeepIntShieldResponse: Cached response if found, nil otherwise
//   - error: Any error that occurred during cache lookup
func (plugin *Plugin) PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	// Basic hallucination control is a request mutation (system-prompt
	// injection + temperature clamp) that must happen before the request
	// leaves the gateway. It runs on the non-direct-gate stages (direct-gate's
	// cache-hit short-circuit means no provider call fires, so there's nothing
	// to influence). Internally gated + per-VK scoped; a no-op when disabled.
	if plugin.stage != pluginStageDirectGate {
		plugin.applyHallucinationControl(ctx, req)
	}
	if plugin.stage == pluginStageDirectGate {
		return plugin.preLLMHookDirectGate(ctx, req)
	}
	if plugin.stage == pluginStageSemanticLookup {
		return plugin.preLLMHookSemanticLookup(ctx, req)
	}

	schemas.EnsureLatencyTracking(ctx, time.Now())
	if _, ok := ctx.Value(requestStartTimeKey).(time.Time); !ok {
		ctx.SetValue(requestStartTimeKey, time.Now())
	}

	provider, model, _ := req.GetRequestFields()

	// Honor the workspace-level Provider Prompt Caching switch. The SDK injects
	// cache_control / prompt_cache_key on every request; here we either pass them
	// through (fast path, no allocations) or strip them before the request leaves
	// the gateway. Stripping happens BEFORE the semantic cache lookup so the cache
	// key is computed against the cleaned request and stays stable across switch
	// toggles.
	plugin.stripProviderPromptCacheHints(req, provider)

	// Stamp the workspace-configured cache TTL onto the markers we kept, so the
	// gateway - not the client/SDK - is the single source of truth for cache
	// duration (and thus cost). No-op unless the provider is Anthropic and a TTL
	// is configured; reads only the in-memory config, so it adds no per-request
	// I/O and piggybacks on the same request walk the strip path already performs.
	plugin.applyProviderPromptCacheTTL(req, provider)

	if !plugin.shouldUseCacheForLookup(ctx, provider) {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping semantic cache lookup because cache is disabled for the selected or candidate API key(s)")
		return req, nil, nil
	}
	cachePlan := plugin.resolveCachePlan(ctx, req)
	cacheKey := cachePlan.CacheKey
	if cacheKey == "" {
		plugin.logger.Debug(PluginLoggerPrefix + " No cache key available, continuing without caching")
		return req, nil, nil
	}

	if plugin.isConversationHistoryThresholdExceeded(req) {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping caching for request with conversation history threshold exceeded")
		return req, nil, nil
	}

	// Generate UUID for this request
	requestID := uuid.New().String()

	// Store request ID, model, and provider in context for PostLLMHook
	ctx.SetValue(requestIDKey, requestID)
	ctx.SetValue(requestModelKey, model)
	ctx.SetValue(requestProviderKey, provider)
	ctx.SetValue(cacheLookupAttemptedKey, true)

	performDirectSearch, performSemanticSearch := true, true
	if ctx.Value(CacheTypeKey) != nil {
		cacheTypeVal, ok := ctx.Value(CacheTypeKey).(CacheType)
		if !ok {
			plugin.logger.Warn(PluginLoggerPrefix + " Cache type is not a CacheType, using all available cache types")
		} else {
			performDirectSearch = cacheTypeVal == CacheTypeDirect
			performSemanticSearch = cacheTypeVal == CacheTypeSemantic
		}
	}
	if !cachePlan.SemanticAllowed {
		performSemanticSearch = false
	}

	if performDirectSearch {
		stopLookup := schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseCacheLookupDirect)
		shortCircuit, err := plugin.performDirectSearch(ctx, req, cacheKey)
		stopLookup()
		if err != nil {
			plugin.logger.Warn(PluginLoggerPrefix + " Direct search failed: " + err.Error())
			// Don't return - continue to semantic search fallback
			shortCircuit = nil // Ensure we don't use an invalid shortCircuit
		}

		if shortCircuit != nil {
			return req, shortCircuit, nil
		}
	}

	if performSemanticSearch && plugin.client != nil {
		if req.EmbeddingRequest != nil || req.TranscriptionRequest != nil {
			plugin.logger.Debug(PluginLoggerPrefix + " Skipping semantic search for embedding/transcription input")
			// For vector stores that require vectors, set a zero vector placeholder
			// This allows direct hash matching to work without the overhead of generating embeddings
			if plugin.store.RequiresVectors() && plugin.config.Dimension > 0 {
				zeroVector := make([]float32, plugin.config.Dimension)
				ctx.SetValue(requestEmbeddingKey, zeroVector)
				plugin.logger.Debug(PluginLoggerPrefix + " Using zero vector placeholder for embedding/transcription request storage")
			}
			return req, nil, nil
		}

		// Try semantic search as fallback
		stopLookup := schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseCacheLookupSemantic)
		shortCircuit, err := plugin.performSemanticSearch(ctx, req, cacheKey)
		stopLookup()
		if err != nil {
			return req, nil, nil
		}

		if shortCircuit != nil {
			return req, shortCircuit, nil
		}
	} else if !performSemanticSearch && plugin.store.RequiresVectors() && plugin.client != nil {
		// Vector store requires vectors but we're in direct-only mode
		// Generate embeddings for storage purposes (not for searching)
		if req.EmbeddingRequest != nil || req.TranscriptionRequest != nil {
			plugin.logger.Debug(PluginLoggerPrefix + " Skipping embedding generation for embedding/transcription input")
			// For vector stores that require vectors, set a zero vector placeholder
			// This allows direct hash matching to work without the overhead of generating embeddings
			if plugin.config.Dimension > 0 {
				zeroVector := make([]float32, plugin.config.Dimension)
				ctx.SetValue(requestEmbeddingKey, zeroVector)
				plugin.logger.Debug(PluginLoggerPrefix + " Using zero vector placeholder for embedding/transcription request storage")
			}
			return req, nil, nil
		}

		// Use zero vector for direct-only cache type to prevent semantic search matches
		// This preserves cache type isolation - direct-only entries won't be found by semantic search
		if plugin.config.Dimension > 0 {
			zeroVector := make([]float32, plugin.config.Dimension)
			ctx.SetValue(requestEmbeddingKey, zeroVector)
			plugin.logger.Debug(PluginLoggerPrefix + " Using zero vector for direct-only cache storage (preserves isolation)")
		}
	}

	return req, nil, nil
}

// PostLLMHook is called after a response is received from a provider.
// It caches responses in the VectorStore using UUID-based keys with unified metadata structure
// including provider, model, request hash, and TTL. Handles both single and streaming responses.
//
// The function performs the following operations:
// 1. Checks configurable caching behavior and skips caching for unsuccessful responses if configured
// 2. Retrieves the request hash and ID from the context (set during PreLLMHook)
// 3. Marshals the response for storage
// 4. Stores the unified cache entry in the VectorStore asynchronously (non-blocking)
//
// The VectorStore Add operation runs in a separate goroutine to avoid blocking the response.
// The function gracefully handles errors and continues without caching if any step fails,
// ensuring that response processing is never interrupted by caching issues.
//
// Parameters:
//   - ctx: Pointer to the schemas.DeepIntShieldContext containing the request hash and ID
//   - res: The response from the provider to be cached
//   - deepintshieldErr: The error from the provider, if any (used for success determination)
//
// Returns:
//   - *schemas.DeepIntShieldResponse: The original response, unmodified
//   - *schemas.DeepIntShieldError: The original error, unmodified
//   - error: Any error that occurred during caching preparation (always nil as errors are handled gracefully)
func (plugin *Plugin) PostLLMHook(ctx *schemas.DeepIntShieldContext, res *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	if plugin.stage == pluginStageDirectGate {
		return plugin.postLLMHookDirectGate(ctx, res, deepintshieldErr)
	}
	if plugin.stage == pluginStageSemanticLookup {
		return res, deepintshieldErr, nil
	}

	if deepintshieldErr != nil {
		return res, deepintshieldErr, nil
	}

	// Basic hallucination-control scoring: a pure-regex improvement pass over
	// the response text (no network, nanoseconds-per-MB). No-op unless control
	// was applied to this request in PreLLMHook.
	stampHallucinationControl(ctx, res)

	// Skip caching for large payloads - body is too large to materialize for cache storage
	if isLargePayload, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool); ok && isLargePayload {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping semantic cache for large payload request")
		return res, nil, nil
	}
	if isLargeResponse, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); ok && isLargeResponse {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping semantic cache for large payload response")
		return res, nil, nil
	}

	isCacheHit := ctx.Value(isCacheHitKey)
	if isCacheHit != nil {
		isCacheHitValue, ok := isCacheHit.(bool)
		if ok && isCacheHitValue {
			return res, nil, nil
		}
	}

	// Check if caching is explicitly disabled
	noStore := ctx.Value(CacheNoStoreKey)
	if noStore != nil {
		noStoreValue, ok := noStore.(bool)
		if ok && noStoreValue {
			plugin.logger.Debug(PluginLoggerPrefix + " Caching is explicitly disabled for this request, continuing without caching")
			return res, nil, nil
		}
	}

	cachePlan := plugin.resolveCachePlan(ctx, nil)
	cacheKey := cachePlan.CacheKey
	if cacheKey == "" {
		return res, nil, nil
	}

	if attempted, ok := ctx.Value(cacheLookupAttemptedKey).(bool); ok && attempted {
		extraFields := res.GetExtraFields()
		if extraFields.CacheDebug == nil {
			extraFields.CacheDebug = &schemas.DeepIntShieldCacheDebug{CacheHit: false}
		} else if !extraFields.CacheDebug.CacheHit {
			extraFields.CacheDebug.CacheHit = false
		}
		plugin.populateCacheDebugScope(extraFields.CacheDebug, ctx, cachePlan)
	}

	// Get the request ID from context
	requestID, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return res, nil, nil
	}
	// Check cache type to optimize embedding handling
	var embedding []float32
	var hash string
	var shouldStoreEmbeddings = cachePlan.SemanticAllowed
	var shouldStoreHash = true

	if ctx.Value(CacheTypeKey) != nil {
		cacheTypeVal, ok := ctx.Value(CacheTypeKey).(CacheType)
		if ok {
			if cacheTypeVal == CacheTypeDirect {
				// For direct-only caching, skip embedding operations entirely
				// unless the vector store requires vectors for all entries
				if plugin.store.RequiresVectors() {
					// Vector stores like Qdrant and Pinecone require vectors for all entries
					// Keep embeddings enabled for storage, but lookups will still use direct hash matching
					plugin.logger.Debug(PluginLoggerPrefix + " Vector store requires vectors, keeping embedding generation enabled for storage")
				} else {
					shouldStoreEmbeddings = false
					plugin.logger.Debug(PluginLoggerPrefix + " Skipping embedding operations for direct-only cache type")
				}
			} else if cacheTypeVal == CacheTypeSemantic {
				shouldStoreHash = false
				plugin.logger.Debug(PluginLoggerPrefix + " Skipping hash operations for semantic cache type")
			}
		}
	}

	if shouldStoreHash {
		// Get the hash from context
		hash, ok = ctx.Value(requestHashKey).(string)
		if !ok {
			plugin.logger.Warn(PluginLoggerPrefix + " Hash is not a string. Continuing without caching")
			return res, nil, nil
		}
	}

	extraFields := res.GetExtraFields()
	requestType := extraFields.RequestType

	// Get embedding from context if available and needed
	// For embedding/transcription requests, we still need to retrieve the zero vector placeholder
	// if the vector store requires vectors for all entries
	isEmbeddingOrTranscription := requestType == schemas.EmbeddingRequest || requestType == schemas.TranscriptionRequest
	needsEmbedding := shouldStoreEmbeddings && !isEmbeddingOrTranscription
	needsZeroVector := isEmbeddingOrTranscription && plugin.store.RequiresVectors()

	if needsEmbedding || needsZeroVector {
		embeddingValue := ctx.Value(requestEmbeddingKey)
		if embeddingValue != nil {
			embedding, ok = embeddingValue.([]float32)
			if !ok {
				plugin.logger.Warn(PluginLoggerPrefix + " Embedding is not a []float32, continuing without caching")
				return res, nil, nil
			}
		}
		// Note: embedding can be nil for direct cache hits or when semantic search is disabled
		// This is fine - we can still cache using direct hash matching (unless store requires vectors)
	}

	// Defend the vector index from a dimension mismatch. The namespace is sized
	// once (for the VK model when embedding-via-VK is on, else the local model),
	// but the per-request embedding can come from a different backend - e.g. the
	// sidecar fallback produces a 768-d BGE vector when the 1536-d VK call fails.
	// Storing that into a differently-sized index leaves an unsearchable vector
	// that quietly breaks KNN. Drop the mismatch and store hash-only instead.
	if len(embedding) > 0 && plugin.config.Dimension > 0 && len(embedding) != plugin.config.Dimension {
		plugin.logger.Warn(fmt.Sprintf("%s embedding dim %d != namespace dim %d; storing hash-only to avoid index corruption",
			PluginLoggerPrefix, len(embedding), plugin.config.Dimension))
		embedding = nil
	}

	// Get the provider from context
	provider, ok := ctx.Value(requestProviderKey).(schemas.ModelProvider)
	if !ok {
		plugin.logger.Warn(PluginLoggerPrefix + " Provider is not a schemas.ModelProvider, continuing without caching")
		return res, nil, nil
	}
	if !plugin.shouldStoreCacheForResult(ctx, provider) {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping semantic cache write because cache is disabled for the selected API key")
		return res, nil, nil
	}

	// Get the model from context
	model, ok := ctx.Value(requestModelKey).(string)
	if !ok {
		plugin.logger.Warn(PluginLoggerPrefix + " Model is not a string, continuing without caching")
		return res, nil, nil
	}

	isFinalChunk := deepintshield.IsFinalChunk(ctx)

	// Get the input tokens from context (can be nil if not set)
	inputTokens, ok := ctx.Value(requestEmbeddingTokensKey).(int)
	if ok {
		isStreamRequest := deepintshield.IsStreamRequestType(requestType)

		if !isStreamRequest || (isStreamRequest && isFinalChunk) {
			if extraFields.CacheDebug == nil {
				extraFields.CacheDebug = &schemas.DeepIntShieldCacheDebug{}
			}
			extraFields.CacheDebug.CacheHit = false
			extraFields.CacheDebug.ProviderUsed = deepintshield.Ptr(string(plugin.config.Provider))
			extraFields.CacheDebug.ModelUsed = deepintshield.Ptr(plugin.config.EmbeddingModel)
			extraFields.CacheDebug.InputTokens = &inputTokens
			plugin.populateCacheDebugScope(extraFields.CacheDebug, ctx, cachePlan)
		}
	}

	cacheTTL := plugin.config.TTL

	ttlValue := ctx.Value(CacheTTLKey)
	if ttlValue != nil {
		// Get the request TTL from the context
		ttl, ok := ttlValue.(time.Duration)
		if !ok {
			plugin.logger.Warn(PluginLoggerPrefix + " TTL is not a time.Duration, using default TTL")
		} else {
			cacheTTL = ttl
		}
	}

	// Get metadata from context BEFORE goroutine to avoid race conditions
	// when the same context is reused across multiple requests
	paramsHash, _ := ctx.Value(requestParamsHashKey).(string)

	// Cache everything in a unified VectorEntry asynchronously to avoid blocking the response
	plugin.waitGroup.Add(1)
	go func() {
		defer plugin.waitGroup.Done()
		defer safegoroutine.Recover(plugin.logger, "semanticcache.async-cache-write")
		// Create a background context with timeout for the cache operation
		cacheCtx, cancel := context.WithTimeout(context.Background(), CacheSetTimeout)
		defer cancel()

		// Build unified metadata with provider, model, and all params
		unifiedMetadata := plugin.buildUnifiedMetadata(provider, model, paramsHash, hash, cachePlan, plugin.tenantIDFromContext(ctx), cacheTTL)

		// Handle streaming vs non-streaming responses
		// Pass nil for embedding if we're in direct-only mode to optimize storage
		embeddingToStore := embedding
		if !shouldStoreEmbeddings {
			embeddingToStore = nil
		}

		if deepintshield.IsStreamRequestType(requestType) {
			if err := plugin.addStreamingResponse(cacheCtx, requestID, res, deepintshieldErr, embeddingToStore, unifiedMetadata, cacheTTL, isFinalChunk); err != nil {
				plugin.logger.Warn("%s Failed to cache streaming response: %v", PluginLoggerPrefix, err)
			}
		} else {
			if err := plugin.addSingleResponse(cacheCtx, requestID, res, embeddingToStore, unifiedMetadata, cacheTTL); err != nil {
				plugin.logger.Warn("%s Failed to cache single response: %v", PluginLoggerPrefix, err)
			}
		}
	}()

	return res, nil, nil
}

// WaitForPendingOperations blocks until all pending cache operations (goroutines) complete.
// This is useful in tests to ensure cache entries are stored before checking for cache hits.
func (plugin *Plugin) WaitForPendingOperations() {
	plugin.waitGroup.Wait()
}

// Cleanup performs cleanup operations for the semantic cache plugin.
// It removes all cached entries created by this plugin from the VectorStore only if CleanUpOnShutdown is true.
// Identifies cache entries by the presence of semantic cache-specific fields (request_hash, cache_key).
//
// The function performs the following operations:
// 1. Checks if cleanup is enabled via CleanUpOnShutdown config
// 2. Retrieves all entries and filters client-side to identify cache entries
// 3. Deletes all matching cache entries from the VectorStore in batches
//
// This method should be called when shutting down the application to ensure
// proper resource cleanup if configured to do so.
//
// Returns:
//   - error: Any error that occurred during cleanup operations
func (plugin *Plugin) Cleanup() error {
	if plugin.cleanupCancel != nil {
		plugin.cleanupCancel()
	}
	plugin.waitGroup.Wait()

	// Clean up old stream accumulators first
	plugin.cleanupOldStreamAccumulators()

	// Shutdown the internal DeepIntShield client used for embeddings
	if plugin.client != nil {
		plugin.client.Shutdown()
	}

	// Only clean up cache entries if configured to do so
	if !plugin.config.CleanUpOnShutdown {
		plugin.logger.Debug(PluginLoggerPrefix + " Cleanup on shutdown is disabled, skipping cache cleanup")
		return nil
	}

	// Clean up all cache entries created by this plugin
	ctx, cancel := context.WithTimeout(context.Background(), CacheSetTimeout)
	defer cancel()

	plugin.logger.Debug(PluginLoggerPrefix + " Starting cleanup of cache entries...")

	// Delete all cache entries created by this plugin
	queries := []vectorstore.Query{
		{
			Field:    "from_deepintshield_semantic_cache_plugin",
			Operator: vectorstore.QueryOperatorEqual,
			Value:    true,
		},
	}

	results, err := plugin.store.DeleteAll(ctx, plugin.config.VectorStoreNamespace, queries)
	if err != nil {
		return fmt.Errorf("failed to delete cache entries: %w", err)
	}

	for _, result := range results {
		if result.Status == vectorstore.DeleteStatusError {
			plugin.logger.Warn("%s Failed to delete cache entry: %s", PluginLoggerPrefix, result.Error)
		}
	}
	plugin.logger.Info("%s Cleanup completed - deleted all cache entries", PluginLoggerPrefix)

	if err := plugin.store.DeleteNamespace(ctx, plugin.config.VectorStoreNamespace); err != nil {
		return fmt.Errorf("failed to delete namespace: %w", err)
	}

	return nil
}

// Public Methods for External Use

// ClearCacheForKey deletes cache entries for a specific cache key.
// Uses the unified VectorStore interface for deletion of all entries with the given cache key.
//
// Parameters:
//   - cacheKey: The specific cache key to delete
//
// Returns:
//   - error: Any error that occurred during cache key deletion
func (plugin *Plugin) ClearCacheForKey(cacheKey string) error {
	return plugin.ClearCacheForKeyWithContext(context.Background(), cacheKey)
}

func (plugin *Plugin) ClearCacheForKeyWithContext(ctx context.Context, cacheKey string) error {
	// Delete all entries with "cache_key" equal to the given cacheKey
	queries := []vectorstore.Query{
		{
			Field:    "cache_key",
			Operator: vectorstore.QueryOperatorEqual,
			Value:    cacheKey,
		},
		{
			Field:    "from_deepintshield_semantic_cache_plugin",
			Operator: vectorstore.QueryOperatorEqual,
			Value:    true,
		},
	}
	queries = plugin.appendExplicitTenantQuery(ctx, queries)

	deleteCtx, cancel := context.WithTimeout(context.Background(), CacheSetTimeout)
	defer cancel()
	results, err := plugin.store.DeleteAll(deleteCtx, plugin.config.VectorStoreNamespace, queries)
	if err != nil {
		plugin.logger.Warn("%s Failed to delete cache entries for key '%s': %v", PluginLoggerPrefix, cacheKey, err)
		return err
	}

	for _, result := range results {
		if result.Status == vectorstore.DeleteStatusError {
			plugin.logger.Warn("%s Failed to delete cache entry for key %s: %s", PluginLoggerPrefix, result.ID, result.Error)
		}
	}

	plugin.logger.Debug(fmt.Sprintf("%s Deleted all cache entries for key %s", PluginLoggerPrefix, cacheKey))

	return nil
}

// ClearCacheForRequestID deletes cache entries for a specific request ID.
// Uses the unified VectorStore interface to delete the single entry by its UUID.
//
// Parameters:
//   - requestID: The UUID-based request ID to delete cache entries for
//
// Returns:
//   - error: Any error that occurred during cache key deletion
func (plugin *Plugin) ClearCacheForRequestID(requestID string) error {
	return plugin.ClearCacheForRequestIDWithContext(context.Background(), requestID)
}

func (plugin *Plugin) ClearCacheForRequestIDWithContext(ctx context.Context, requestID string) error {
	// With the unified VectorStore interface, we delete the single entry by its UUID
	deleteCtx, cancel := context.WithTimeout(context.Background(), CacheSetTimeout)
	defer cancel()
	explicitTenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if explicitTenantID != "" {
		result, err := plugin.store.GetChunk(deleteCtx, plugin.config.VectorStoreNamespace, requestID)
		if err != nil {
			plugin.logger.Warn("%s Failed to fetch cache entry %s before tenant-scoped deletion: %v", PluginLoggerPrefix, requestID, err)
			return err
		}
		storedTenantID, _ := result.Properties["tenant_id"].(string)
		if strings.TrimSpace(storedTenantID) != explicitTenantID {
			plugin.logger.Debug(fmt.Sprintf("%s Cache entry %s does not belong to tenant %s; skipping delete", PluginLoggerPrefix, requestID, explicitTenantID))
			return nil
		}
	}
	if err := plugin.store.Delete(deleteCtx, plugin.config.VectorStoreNamespace, requestID); err != nil {
		plugin.logger.Warn("%s Failed to delete cache entry: %v", PluginLoggerPrefix, err)
		return err
	}

	plugin.logger.Debug(fmt.Sprintf("%s Deleted cache entry for key %s", PluginLoggerPrefix, requestID))

	return nil
}

func (plugin *Plugin) tenantIDFromContext(ctx context.Context) string {
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if tenantID == "" {
		return DefaultTenantID
	}
	return tenantID
}

func (plugin *Plugin) appendTenantFilter(ctx context.Context, queries []vectorstore.Query) []vectorstore.Query {
	return append(queries, vectorstore.Query{
		Field:    "tenant_id",
		Operator: vectorstore.QueryOperatorEqual,
		Value:    plugin.tenantIDFromContext(ctx),
	})
}

func (plugin *Plugin) appendExplicitTenantQuery(ctx context.Context, queries []vectorstore.Query) []vectorstore.Query {
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if tenantID == "" {
		return queries
	}
	return append(queries, vectorstore.Query{
		Field:    "tenant_id",
		Operator: vectorstore.QueryOperatorEqual,
		Value:    tenantID,
	})
}

func (plugin *Plugin) startBackgroundMaintenance() {
	maintenanceCtx, cancel := context.WithCancel(context.Background())
	plugin.cleanupCancel = cancel

	go func() {
		defer safegoroutine.Recover(plugin.logger, "semanticcache.background-maintenance")
		ticker := time.NewTicker(ExpiredCacheFlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-maintenanceCtx.Done():
				return
			case <-ticker.C:
				flushCtx, flushCancel := context.WithTimeout(context.Background(), CacheSetTimeout)
				if err := plugin.flushExpiredEntries(flushCtx); err != nil {
					plugin.logger.Warn("%s Failed to flush expired cache entries: %v", PluginLoggerPrefix, err)
				}
				flushCancel()
				plugin.cleanupOldStreamAccumulators()
				plugin.directL1.purgeExpired()
			}
		}
	}()
}

func (plugin *Plugin) flushExpiredEntries(ctx context.Context) error {
	queries := []vectorstore.Query{
		{
			Field:    "from_deepintshield_semantic_cache_plugin",
			Operator: vectorstore.QueryOperatorEqual,
			Value:    true,
		},
		{
			Field:    "expires_at",
			Operator: vectorstore.QueryOperatorLessThanOrEqual,
			Value:    time.Now().Unix(),
		},
	}

	results, err := plugin.store.DeleteAll(ctx, plugin.config.VectorStoreNamespace, queries)
	if err != nil {
		return err
	}
	for _, result := range results {
		if result.Status == vectorstore.DeleteStatusError {
			plugin.logger.Warn("%s Failed to delete expired cache entry %s: %s", PluginLoggerPrefix, result.ID, result.Error)
		}
	}
	return nil
}
