package semanticcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// normalizeText applies consistent normalization to text inputs for better cache hit rates.
// It converts text to lowercase and trims whitespace to reduce cache misses due to minor variations.
func normalizeText(text string) string {
	return strings.ToLower(strings.TrimSpace(text))
}

// ─────────────────────────────────────────────────────────────────────────────
// Embedding LRU - in-process cache for prompt → vector. The semantic lookup
// path embeds the inbound prompt on every miss, paying a 5-20 ms sidecar
// round-trip for text that was already embedded 100 ms ago (templated chat
// traffic, retry storms, paraphrase clusters). LRU here turns those repeats
// into a single map lookup. Sized at 1024 entries (~12 MB for 768-dim float32)
// per plugin instance - cheap and bounded.
//
// Why not memoize at the sidecar layer too? The sidecar already caches its
// own model state, but every call still pays the HTTP RTT. The in-process
// LRU eliminates that hop entirely.
//
// Correctness: vectors are deterministic for a given (model, text) pair, so
// caching them is safe so long as the model identifier is part of the key.
// Eviction is best-effort LRU (oldest createdAt) - good enough for the
// chat-assistant traffic shape where a small set of hot prefixes dominate.
// ─────────────────────────────────────────────────────────────────────────────

const defaultEmbeddingCacheSize = 1024

type embeddingCacheEntry struct {
	vector      []float32
	inputTokens int
	createdAt   time.Time
}

type embeddingCache struct {
	mu         sync.RWMutex
	entries    map[string]*embeddingCacheEntry
	maxEntries int
}

func newEmbeddingCache(maxEntries int) *embeddingCache {
	if maxEntries <= 0 {
		maxEntries = defaultEmbeddingCacheSize
	}
	return &embeddingCache{
		entries:    make(map[string]*embeddingCacheEntry, 256),
		maxEntries: maxEntries,
	}
}

func embeddingCacheKey(provider, model, text string) string {
	h := sha256.New()
	h.Write([]byte(provider))
	h.Write([]byte{0})
	h.Write([]byte(model))
	h.Write([]byte{0})
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *embeddingCache) lookup(key string) ([]float32, int, bool) {
	if c == nil || key == "" {
		return nil, 0, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, 0, false
	}
	return entry.vector, entry.inputTokens, true
}

func (c *embeddingCache) store(key string, vector []float32, inputTokens int) {
	if c == nil || key == "" || len(vector) == 0 {
		return
	}
	// Defensive copy so callers can't mutate cached vectors in place. Vectors
	// flow back through generateEmbedding into the vector store's Add path
	// which may further normalise / quantise - without the copy, those edits
	// would corrupt the cache.
	v := make([]float32, len(vector))
	copy(v, vector)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		var oldestKey string
		var oldestAt time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.createdAt.Before(oldestAt) {
				oldestKey, oldestAt = k, e.createdAt
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &embeddingCacheEntry{
		vector:      v,
		inputTokens: inputTokens,
		createdAt:   time.Now(),
	}
}

// generateEmbedding generates an embedding for the given text using the
// configured provider. Two paths:
//
//  1. **Default (embedding sidecar)** - uses plugin.config.Provider +
//     plugin.config.EmbeddingModel, hitting the local huggingface/ollama
//     deepintshield_models sidecar. Sub-100ms warm latency.
//
//  2. **Via VK** - when embedding_via_vk_enabled is true and
//     embedding_vk_id is set, the call is routed through the operator-
//     chosen workspace VK (e.g. an OpenAI VK + text-embedding-3-small).
//     Governance resolves the VK's API key at request time via the
//     PluginAccount's requestKeyProvider chain so the cost-opt feature
//     works without standing up the sidecar container.
//
// The VK path keeps the zero-latency contract because embedding calls are
// already async with respect to the inbound LLM request: PreLLMHook's
// cache lookup is direct-hash first (sub-µs), and the embedding-based
// vector lookup runs only when the direct-hash misses. The extra ~100ms
// of an OpenAI embedding call lands on the next request's vector lookup,
// not the current one's hot path.
// embeddingCallTimeout bounds a single embedding request on the cache path so a
// slow/unreachable embedding backend fails open fast (degrade to direct search)
// rather than stalling the response. Warm embedding latency is sub-second.
const embeddingCallTimeout = 5 * time.Second

// isLocalSidecarEmbeddingProvider reports whether the configured embedding
// "provider" is really the in-cluster deepintshield-models embedding sidecar
// rather than an external cloud embedding API. In this platform the
// `huggingface` provider is SERVED BY that local sidecar (BGE / MiniLM over an
// OpenAI-compatible /v1/embeddings) — it needs no external API key and no VK.
// Treating it as local lets generateEmbedding go straight to the sidecar, which
// is the zero-latency, always-available path and the one the namespace
// dimension was created for.
func isLocalSidecarEmbeddingProvider(provider schemas.ModelProvider) bool {
	switch strings.ToLower(strings.TrimSpace(string(provider))) {
	case "huggingface", "hf", "local", "sidecar":
		return true
	default:
		return false
	}
}

func (plugin *Plugin) generateEmbedding(ctx *schemas.DeepIntShieldContext, text string) ([]float32, int, error) {
	provider := plugin.config.Provider
	model := plugin.config.EmbeddingModel

	// Local sidecar provider (huggingface/local): the embedding backend is the
	// in-cluster deepintshield-models service — no external API, no VK to
	// resolve — so route straight to it. This is the zero-latency PRIMARY path:
	// it skips the cloud-embedding attempt (e.g. a viaVK OpenAI call on a project
	// with no embedding entitlement) that otherwise stalls the cache path for
	// seconds and leaves it without vectors (→ 0 semantic-cache hits). The
	// sidecar serves the configured HF model at the same dimension the namespace
	// was created for (MiniLM 384 / BGE 768), so vectors stay KNN-consistent.
	if isLocalSidecarEmbeddingProvider(provider) {
		m := strings.TrimSpace(model)
		if m == "" {
			m = defaultLocalEmbeddingModel
		}
		return plugin.embedViaLocalSidecar(ctx, m, text)
	}

	viaVK := plugin.config.EmbeddingViaVKEnabled != nil && *plugin.config.EmbeddingViaVKEnabled &&
		strings.TrimSpace(plugin.config.EmbeddingVKID) != ""
	if viaVK {
		// Stamp the operator-chosen embedding VK so requestKeyProvider can
		// resolve the workspace's openai/gemini/etc keys via governance.
		ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID, plugin.config.EmbeddingVKID)
		// Default provider for the VK path is OpenAI text-embedding-3-small
		// (cheapest cloud embedding endpoint with acceptable quality).
		// Operators who configure a Gemini / Cohere / Voyage VK can use
		// those by selecting them in the dropdown.
		provider = schemas.OpenAI
		if mdl := strings.TrimSpace(plugin.config.EmbeddingViaVKModel); mdl != "" {
			model = mdl
		} else {
			model = "text-embedding-3-small"
		}
	}

	vec, tok, err := plugin.embedOnce(ctx, provider, model, text)
	if err == nil {
		return vec, tok, nil
	}

	// The provider embedding path failed. Two real, recurring failure modes
	// make this the common case rather than the exception, and both silently
	// drop the semantic / coalescing cache to 0 hits (no vector → nothing to
	// store → KNN finds nothing) along with the cost-opt savings:
	//
	//   1. embedding-via-VK points at a model blocked by a model-whitelist
	//      guardrail (e.g. an OWASP LLM03 supply-chain card) or an account
	//      without the embedding entitlement → 403.
	//   2. the configured huggingface embedding provider speaks the HF
	//      Inference "feature-extraction" API, which the local
	//      OpenAI-compatible embedding sidecar does not serve → 404.
	//
	// Fall back to the local OpenAI-compatible embedding sidecar over direct
	// HTTP - the same free, always-available backend the compression / rerank
	// / hallucination features already use. The fallback vector space differs
	// from the provider's, but every entry past this point is re-embedded by
	// the same fallback model, so the cache stays internally consistent (and
	// the namespace dimension is derived from this same model at Init).
	fbModel := strings.TrimSpace(plugin.config.EmbeddingModel)
	if fbModel == "" {
		fbModel = defaultLocalEmbeddingModel
	}
	if viaVK {
		// Clear the VK stamp so the fallback doesn't re-resolve the blocked
		// embedding VK; the local sidecar needs no credentials.
		ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID, "")
	}
	svec, stok, serr := plugin.embedViaLocalSidecar(ctx, fbModel, text)
	if serr != nil {
		// Both paths failed - surface a combined error so the caller degrades
		// to direct (hash) search instead of stalling.
		return nil, 0, fmt.Errorf("provider embedding failed (%v); local sidecar fallback failed (%v)", err, serr)
	}
	if plugin.logger != nil {
		plugin.logger.Warn("%s provider embedding failed (%v); served from local sidecar %s to keep the cache warm",
			PluginLoggerPrefix, err, fbModel)
	}
	return svec, stok, nil
}

// defaultLocalEmbeddingModel is the local OpenAI-compatible embedding sidecar's
// default model (BGE-base, 768-dim). Used as the fallback embedding model and
// as the dimension basis when neither is configured.
const defaultLocalEmbeddingModel = "BAAI/bge-base-en-v1.5"

// defaultEmbeddingSidecarEndpoint mirrors the compression / rerank sidecar
// default - the local OpenAI-compatible embedding service.
const defaultEmbeddingSidecarEndpoint = "http://deepintshield-models:8093"

var (
	embeddingSidecarHTTPOnce sync.Once
	embeddingSidecarHTTP     *http.Client
)

// embeddingSidecarClient returns a shared HTTP client for the local embedding
// sidecar. Connection reuse matters: the cache path can fan out many embedding
// calls to a single host, so we keep idle conns warm (mirrors compressionClient).
func embeddingSidecarClient() *http.Client {
	embeddingSidecarHTTPOnce.Do(func() {
		embeddingSidecarHTTP = &http.Client{
			Timeout: embeddingCallTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 64,
				MaxConnsPerHost:     128,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		}
	})
	return embeddingSidecarHTTP
}

// embeddingSidecarEndpoint resolves the local embedding sidecar base URL from
// the embedding provider's NetworkConfig, falling back to the hardcoded default.
func (plugin *Plugin) embeddingSidecarEndpoint() string {
	if plugin.config.NetworkConfig != nil {
		if u := strings.TrimSpace(plugin.config.NetworkConfig.BaseURL); u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return defaultEmbeddingSidecarEndpoint
}

// embedViaLocalSidecar generates an embedding by calling the local
// OpenAI-compatible embedding sidecar (/v1/embeddings) over direct HTTP,
// bypassing the provider abstraction. This is the reliable local embedding
// path: the huggingface provider speaks the HF Inference feature-extraction
// API the sidecar does not serve, and a blocked/unentitled openai VK is gated
// by the guard - both leave the cache without vectors. The sidecar is the same
// backend the compression / rerank features already use.
func (plugin *Plugin) embedViaLocalSidecar(ctx *schemas.DeepIntShieldContext, model, text string) ([]float32, int, error) {
	cacheKey := embeddingCacheKey("sidecar", model, text)
	if plugin.embeddingCache != nil {
		if v, tok, ok := plugin.embeddingCache.lookup(cacheKey); ok {
			return v, tok, nil
		}
	}

	payload, err := json.Marshal(map[string]any{"model": model, "input": text})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal sidecar embedding request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), embeddingCallTimeout)
	defer cancel()
	endpoint := plugin.embeddingSidecarEndpoint() + "/v1/embeddings"
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build sidecar embedding request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := embeddingSidecarClient().Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("sidecar embedding request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, 0, fmt.Errorf("sidecar embedding returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var parsed struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, 0, fmt.Errorf("failed to decode sidecar embedding response: %w", err)
	}
	if len(parsed.Data) == 0 || len(parsed.Data[0].Embedding) == 0 {
		return nil, 0, fmt.Errorf("sidecar embedding returned no vectors")
	}
	vec := parsed.Data[0].Embedding
	plugin.embeddingCache.store(cacheKey, vec, parsed.Usage.TotalTokens)
	return vec, parsed.Usage.TotalTokens, nil
}

// embeddingModelDimension returns the output dimension for a known embedding
// model so the vector-store namespace can be created at the right size even
// when the operator leaves `dimension` unset. Defaults to 768 (BGE-base, the
// local sidecar default) rather than a degenerate 1, which silently breaks
// every KNN search.
func embeddingModelDimension(model string) int {
	m := strings.ToLower(strings.TrimSpace(model))
	switch {
	case m == "":
		return 768
	case strings.Contains(m, "text-embedding-3-large"):
		return 3072
	case strings.Contains(m, "text-embedding-3-small"),
		strings.Contains(m, "text-embedding-ada-002"),
		strings.Contains(m, "ada-002"):
		return 1536
	case strings.Contains(m, "bge-large"), strings.Contains(m, "bge-m3"):
		return 1024
	case strings.Contains(m, "bge-small"), strings.Contains(m, "minilm"), strings.Contains(m, "all-minilm"):
		return 384
	case strings.Contains(m, "bge-base"), strings.Contains(m, "bge"):
		return 768
	case strings.Contains(m, "text-embedding-004"), strings.Contains(m, "embedding-001"), strings.Contains(m, "gemini"):
		return 768
	case strings.Contains(m, "nomic-embed"), strings.Contains(m, "mpnet"):
		return 768
	default:
		// Unknown model: assume the local sidecar default rather than 1.
		return 768
	}
}

// embedOnce generates an embedding for (provider, model, text) against the
// resolved backend: an in-process LRU lookup first, then a single bounded
// EmbeddingRequest, decoding whichever embedding shape the provider returns.
// Split out of generateEmbedding so the embedding-via-VK path can retry on a
// different backend (the local sidecar) without re-deriving provider/model.
func (plugin *Plugin) embedOnce(ctx *schemas.DeepIntShieldContext, provider schemas.ModelProvider, model, text string) ([]float32, int, error) {
	// In-process LRU keyed on (provider, model, text). Saves the sidecar /
	// network RTT on every repeat - measured at ~5-15 ms per hit on the
	// templated chat workload. Cache lookup is a single RWMutex.RLock + map
	// read so it costs ~50 ns on a miss, ~80 ns on a hit; cheap enough to
	// always run even before the request is paid for. Keying on provider+model
	// keeps the VK and sidecar vector spaces from colliding on fallback.
	cacheKey := embeddingCacheKey(string(provider), model, text)
	if plugin.embeddingCache != nil {
		if v, tok, ok := plugin.embeddingCache.lookup(cacheKey); ok {
			return v, tok, nil
		}
	}
	// Create embedding request
	embeddingReq := &schemas.DeepIntShieldEmbeddingRequest{
		Provider: provider,
		Model:    model,
		Input: &schemas.EmbeddingInput{
			Text: &text,
		},
	}

	// Generate embedding using deepintshield client. Bound the call so a slow or
	// unreachable embedding backend (e.g. an unconfigured ollama / sidecar)
	// fails OPEN fast - the cache degrades to direct (hash) search - instead of
	// inheriting the request's full deadline and stalling the response ~30s.
	embCtx, cancel := schemas.NewDeepIntShieldContextWithTimeout(ctx, embeddingCallTimeout)
	defer cancel()
	response, err := plugin.client.EmbeddingRequest(embCtx, embeddingReq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate embedding: %v", err)
	}

	// Extract the first embedding from response
	if len(response.Data) == 0 {
		return nil, 0, fmt.Errorf("no embeddings returned from provider")
	}

	// Get the embedding from the first data item
	embedding := response.Data[0].Embedding
	inputTokens := 0
	if response.Usage != nil {
		inputTokens = response.Usage.TotalTokens
	}

	if embedding.EmbeddingStr != nil {
		// decode embedding.EmbeddingStr to []float32
		var vals []float32
		if err := json.Unmarshal([]byte(*embedding.EmbeddingStr), &vals); err != nil {
			return nil, 0, fmt.Errorf("failed to parse string embedding: %w", err)
		}
		plugin.embeddingCache.store(cacheKey, vals, inputTokens)
		return vals, inputTokens, nil
	} else if embedding.EmbeddingArray != nil {
		plugin.embeddingCache.store(cacheKey, embedding.EmbeddingArray, inputTokens)
		return embedding.EmbeddingArray, inputTokens, nil
	} else if len(embedding.Embedding2DArray) > 0 {
		// Flatten 2D array into single embedding
		var flattened []float32
		for _, arr := range embedding.Embedding2DArray {
			flattened = append(flattened, arr...)
		}
		plugin.embeddingCache.store(cacheKey, flattened, inputTokens)
		return flattened, inputTokens, nil
	}

	return nil, 0, fmt.Errorf("embedding data is not in expected format")
}

// generateRequestHash creates an xxhash of the request for semantic cache key generation.
// It normalizes the request by including all relevant fields that affect the response:
// - Input (chat completion, text completion, etc.)
// - Parameters (temperature, max_tokens, tools, etc.)
// - Provider (if CacheByProvider is true)
// - Model (if CacheByModel is true)
//
// Note: Fallbacks are excluded as they only affect error handling, not the actual response.
//
// Parameters:
//   - req: The DeepIntShield request to hash for semantic cache key generation
//
// Returns:
//   - string: Hexadecimal representation of the xxhash
//   - error: Any error that occurred during request normalization or hashing
func (plugin *Plugin) generateRequestHash(req *schemas.DeepIntShieldRequest) (string, error) {
	// Create a hash input structure that includes both input and parameters
	hashInput := struct {
		Input  interface{} `json:"input"`
		Params interface{} `json:"params,omitempty"`
		Stream bool        `json:"stream,omitempty"`
	}{
		Input:  plugin.getNormalizedInputForCaching(req),
		Stream: deepintshield.IsStreamRequestType(req.RequestType),
	}

	switch req.RequestType {
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		hashInput.Params = req.TextCompletionRequest.Params
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		hashInput.Params = req.ChatRequest.Params
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		hashInput.Params = req.ResponsesRequest.Params
	case schemas.SpeechRequest, schemas.SpeechStreamRequest:
		if req.SpeechRequest != nil {
			hashInput.Params = req.SpeechRequest.Params
		}
	case schemas.EmbeddingRequest:
		hashInput.Params = req.EmbeddingRequest.Params
	case schemas.TranscriptionRequest, schemas.TranscriptionStreamRequest:
		hashInput.Params = req.TranscriptionRequest.Params
	case schemas.ImageGenerationRequest, schemas.ImageGenerationStreamRequest:
		hashInput.Params = req.ImageGenerationRequest.Params
	}

	// Marshal to JSON with deeply sorted keys for deterministic hashing
	// MarshalDeeplySorted handles OrderedMap and nested map[string]interface{} correctly
	jsonData, err := schemas.MarshalDeeplySorted(hashInput)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request for hashing: %w", err)
	}

	// Generate hash based on configured algorithm
	hash := xxhash.Sum64(jsonData)
	return fmt.Sprintf("%x", hash), nil
}

// extractTextForEmbedding extracts meaningful text from different input types for embedding generation.
// Returns the text to embed and metadata for storage.
//
// Text serialization format (for cache consistency):
//   - Chat API: "role: content"
//   - Responses API: "role: msgType: content" (when msgType is present), "role: content" (when msgType is empty)
//
// Note: Format updated to conditionally include msgType to avoid double colons and maintain consistency.
func (plugin *Plugin) extractTextForEmbedding(req *schemas.DeepIntShieldRequest) (string, string, error) {
	metadata := map[string]interface{}{}

	attachments := []string{}

	// Add parameters as metadata if present - handle segregated parameters
	metadata["stream"] = deepintshield.IsStreamRequestType(req.RequestType)

	// Extract parameters based on request type
	switch req.RequestType {
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		if req.TextCompletionRequest != nil && req.TextCompletionRequest.Params != nil {
			plugin.extractTextCompletionParametersToMetadata(req.TextCompletionRequest.Params, metadata)
		}
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		if req.ChatRequest != nil && req.ChatRequest.Params != nil {
			plugin.extractChatParametersToMetadata(req.ChatRequest.Params, metadata)
		}
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		if req.ResponsesRequest != nil && req.ResponsesRequest.Params != nil {
			plugin.extractResponsesParametersToMetadata(req.ResponsesRequest.Params, metadata)
		}
	case schemas.SpeechRequest, schemas.SpeechStreamRequest:
		if req.SpeechRequest != nil && req.SpeechRequest.Params != nil {
			plugin.extractSpeechParametersToMetadata(req.SpeechRequest.Params, metadata)
		}
	case schemas.EmbeddingRequest:
		if req.EmbeddingRequest != nil && req.EmbeddingRequest.Params != nil {
			plugin.extractEmbeddingParametersToMetadata(req.EmbeddingRequest.Params, metadata)
		}
	case schemas.TranscriptionRequest, schemas.TranscriptionStreamRequest:
		if req.TranscriptionRequest != nil && req.TranscriptionRequest.Params != nil {
			plugin.extractTranscriptionParametersToMetadata(req.TranscriptionRequest.Params, metadata)
		}
	case schemas.ImageGenerationRequest, schemas.ImageGenerationStreamRequest:
		if req.ImageGenerationRequest != nil && req.ImageGenerationRequest.Params != nil {
			plugin.extractImageGenerationParametersToMetadata(req.ImageGenerationRequest.Params, metadata)
		}
	}

	switch {
	case req.TextCompletionRequest != nil:
		metadataHash, err := getMetadataHash(metadata)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
		}

		var textContent string
		if req.TextCompletionRequest.Input.PromptStr != nil {
			textContent = normalizeText(*req.TextCompletionRequest.Input.PromptStr)
		} else if len(req.TextCompletionRequest.Input.PromptArray) > 0 {
			textContent = normalizeText(strings.Join(req.TextCompletionRequest.Input.PromptArray, " "))
		}
		return textContent, metadataHash, nil

	case req.ChatRequest != nil:
		reqInput, ok := plugin.getInputForCaching(req).([]schemas.ChatMessage)
		if !ok {
			return "", "", fmt.Errorf("failed to cast request input to chat messages")
		}

		// Serialize chat messages for embedding
		var textParts []string
		for _, msg := range reqInput {
			// Extract content as string
			// Content can be nil for messages like assistant tool-call messages
			var content string
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					content = *msg.Content.ContentStr
				} else if msg.Content.ContentBlocks != nil {
					// For content blocks, extract text parts
					var blockTexts []string
					for _, block := range msg.Content.ContentBlocks {
						if block.Text != nil {
							blockTexts = append(blockTexts, *block.Text)
						}
						if block.ImageURLStruct != nil && block.ImageURLStruct.URL != "" {
							attachments = append(attachments, block.ImageURLStruct.URL)
						}
					}
					content = strings.Join(blockTexts, " ")
				}
			}

			if content != "" {
				textParts = append(textParts, fmt.Sprintf("%s: %s", msg.Role, normalizeText(content)))
			}
		}

		if len(textParts) == 0 {
			return "", "", fmt.Errorf("no text content found in chat messages")
		}

		if len(attachments) > 0 {
			metadata["attachments"] = attachments
		}

		metadataHash, err := getMetadataHash(metadata)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
		}

		return strings.Join(textParts, "\n"), metadataHash, nil

	case req.ResponsesRequest != nil:
		reqInput, ok := plugin.getInputForCaching(req).([]schemas.ResponsesMessage)
		if !ok {
			return "", "", fmt.Errorf("failed to cast request input to responses messages")
		}

		// Serialize chat messages for embedding
		var textParts []string
		for _, msg := range reqInput {
			// Extract content as string
			// Content can be nil for messages like assistant tool-call messages
			var content string
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					content = normalizeText(*msg.Content.ContentStr)
				} else if msg.Content.ContentBlocks != nil {
					// For content blocks, extract text parts
					var blockTexts []string
					for _, block := range msg.Content.ContentBlocks {
						if block.Text != nil {
							blockTexts = append(blockTexts, normalizeText(*block.Text))
						}
						if block.ResponsesInputMessageContentBlockImage != nil && block.ResponsesInputMessageContentBlockImage.ImageURL != nil {
							attachments = append(attachments, *block.ResponsesInputMessageContentBlockImage.ImageURL)
						}
						if block.ResponsesInputMessageContentBlockFile != nil && block.ResponsesInputMessageContentBlockFile.FileURL != nil {
							attachments = append(attachments, *block.ResponsesInputMessageContentBlockFile.FileURL)
						}
					}
					content = strings.Join(blockTexts, " ")
				}
			}

			role := ""
			msgType := ""
			if msg.Role != nil {
				role = string(*msg.Role)
			}
			if msg.Type != nil {
				msgType = string(*msg.Type)
			}

			if content != "" {
				if msgType != "" {
					textParts = append(textParts, fmt.Sprintf("%s: %s: %s", role, msgType, content))
				} else {
					textParts = append(textParts, fmt.Sprintf("%s: %s", role, content))
				}
			}
		}

		if len(textParts) == 0 {
			return "", "", fmt.Errorf("no text content found in chat messages")
		}

		if len(attachments) > 0 {
			metadata["attachments"] = attachments
		}

		metadataHash, err := getMetadataHash(metadata)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
		}

		return strings.Join(textParts, "\n"), metadataHash, nil

	case req.SpeechRequest != nil:
		if req.SpeechRequest.Input.Input != "" {
			metadataHash, err := getMetadataHash(metadata)
			if err != nil {
				return "", "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
			}

			return req.SpeechRequest.Input.Input, metadataHash, nil
		}
		return "", "", fmt.Errorf("no input text found in speech request")

	case req.EmbeddingRequest != nil:
		metadataHash, err := getMetadataHash(metadata)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
		}

		texts := req.EmbeddingRequest.Input.Texts

		if len(texts) == 0 && req.EmbeddingRequest.Input.Text != nil {
			texts = []string{*req.EmbeddingRequest.Input.Text}
		}

		var text string
		for _, t := range texts {
			text += t + " "
		}

		return strings.TrimSpace(text), metadataHash, nil

	case req.TranscriptionRequest != nil:
		// Skip semantic caching for transcription requests
		return "", "", fmt.Errorf("transcription requests are not supported for semantic caching")

	case req.ImageGenerationRequest != nil:
		if req.ImageGenerationRequest.Input == nil || req.ImageGenerationRequest.Input.Prompt == "" {
			return "", "", fmt.Errorf("no prompt found in image generation request")
		}
		metadataHash, err := getMetadataHash(metadata)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
		}
		return normalizeText(req.ImageGenerationRequest.Input.Prompt), metadataHash, nil

	default:
		return "", "", fmt.Errorf("unsupported input type for semantic caching")
	}
}

func getMetadataHash(metadata map[string]interface{}) (string, error) {
	// Use MarshalDeeplySorted for deterministic hashing - plain json.Marshal
	// doesn't guarantee key ordering since Go maps have random iteration order
	metadataJSON, err := schemas.MarshalDeeplySorted(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata for metadata hash: %w", err)
	}
	return fmt.Sprintf("%x", xxhash.Sum64(metadataJSON)), nil
}

// buildUnifiedMetadata constructs the unified metadata structure for VectorEntry
func (plugin *Plugin) buildUnifiedMetadata(provider schemas.ModelProvider, model string, paramsHash string, requestHash string, cachePlan cacheResolution, tenantID string, ttl time.Duration) map[string]interface{} {
	unifiedMetadata := make(map[string]interface{})

	// Top-level fields (outside params)
	unifiedMetadata["provider"] = string(provider)
	unifiedMetadata["model"] = model
	unifiedMetadata["request_hash"] = requestHash
	unifiedMetadata["cache_key"] = cachePlan.CacheKey
	unifiedMetadata["tenant_id"] = tenantID
	unifiedMetadata["from_deepintshield_semantic_cache_plugin"] = true
	if cachePlan.ScopeType != "" {
		unifiedMetadata["scope_type"] = cachePlan.ScopeType
	}
	if cachePlan.ScopeSource != "" {
		unifiedMetadata["scope_source"] = cachePlan.ScopeSource
	}
	if cachePlan.ScopeValueHash != "" {
		unifiedMetadata["scope_value_hash"] = cachePlan.ScopeValueHash
	}

	// Calculate expiration timestamp (current time + TTL)
	expiresAt := time.Now().Add(ttl).Unix()
	unifiedMetadata["expires_at"] = expiresAt

	// Individual param fields will be stored as params_* by the vectorstore
	// We pass the params map to the vectorstore, and it handles the individual field storage
	if paramsHash != "" {
		unifiedMetadata["params_hash"] = paramsHash
	}

	return unifiedMetadata
}

func (plugin *Plugin) populateCacheDebugScope(cacheDebug *schemas.DeepIntShieldCacheDebug, ctx context.Context, cachePlan cacheResolution) {
	if cacheDebug == nil {
		return
	}
	if cachePlan.CacheKey == "" {
		cachePlan, _ = plugin.cachePlanFromContext(ctx)
	}
	if cachePlan.CacheKey != "" {
		cacheDebug.EffectiveCacheKey = deepintshield.Ptr(cachePlan.CacheKey)
	}
	if cachePlan.ScopeType != "" {
		cacheDebug.ScopeType = deepintshield.Ptr(cachePlan.ScopeType)
	}
	if cachePlan.ScopeSource != "" {
		cacheDebug.ScopeSource = deepintshield.Ptr(cachePlan.ScopeSource)
	}
	if cachePlan.ScopeValueHash != "" {
		cacheDebug.ScopeValueHash = deepintshield.Ptr(cachePlan.ScopeValueHash)
	}
	if cachePlan.SemanticSuppressedReason != "" {
		cacheDebug.SemanticSuppressedReason = deepintshield.Ptr(cachePlan.SemanticSuppressedReason)
	}
}

func (plugin *Plugin) populateGuardrailReuseDebug(cacheDebug *schemas.DeepIntShieldCacheDebug, ctx context.Context) {
	if cacheDebug == nil || ctx == nil {
		return
	}
	if reused, ok := ctx.Value(guardrailReusedKey).(bool); ok && reused {
		cacheDebug.GuardrailReused = deepintshield.Ptr(true)
		cacheDebug.GuardrailCacheSource = deepintshield.Ptr("direct_cache_guardrail_snapshot")
		cacheDebug.GuardrailFingerprintMatch = deepintshield.Ptr(true)
	}
}

// addSingleResponse stores a single (non-streaming) response in unified VectorEntry format
func (plugin *Plugin) addSingleResponse(ctx context.Context, responseID string, res *schemas.DeepIntShieldResponse, embedding []float32, metadata map[string]interface{}, ttl time.Duration) error {
	// Marshal response as string
	responseData, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Add response field to metadata
	metadata["response"] = string(responseData)
	metadata["stream_chunks"] = []string{}

	// Store unified entry using new VectorStore interface
	if err := plugin.store.Add(ctx, plugin.config.VectorStoreNamespace, responseID, embedding, metadata); err != nil {
		return fmt.Errorf("failed to store unified cache entry: %w", err)
	}

	plugin.logger.Debug(fmt.Sprintf("%s Successfully cached single response with ID: %s", PluginLoggerPrefix, responseID))
	return nil
}

// addStreamingResponse handles streaming response storage by accumulating chunks
func (plugin *Plugin) addStreamingResponse(ctx context.Context, responseID string, res *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError, embedding []float32, metadata map[string]interface{}, ttl time.Duration, isFinalChunk bool) error {
	// Create accumulator if it doesn't exist
	accumulator := plugin.getOrCreateStreamAccumulator(responseID, embedding, metadata, ttl)

	// Create chunk from current response
	chunk := &StreamChunk{
		Timestamp: time.Now(),
		Response:  res,
	}

	// Check for finish reason or set error finish reason
	if deepintshieldErr != nil {
		// Error case - mark as final chunk with error
		chunk.FinishReason = deepintshield.Ptr("error")
	} else if res != nil && res.ChatResponse != nil && len(res.ChatResponse.Choices) > 0 {
		choice := res.ChatResponse.Choices[0]
		if choice.ChatStreamResponseChoice != nil {
			chunk.FinishReason = choice.FinishReason
		}
	}

	// Add chunk to accumulator synchronously to maintain order
	if err := plugin.addStreamChunk(responseID, chunk, isFinalChunk); err != nil {
		return fmt.Errorf("failed to add stream chunk: %w", err)
	}

	// Check if this is the final chunk and gate final processing to ensure single invocation
	accumulator.mu.Lock()
	// Check for completion: either FinishReason is present, there's an error, or token usage exists
	alreadyComplete := accumulator.IsComplete

	// Track if any chunk has an error
	if deepintshieldErr != nil {
		accumulator.HasError = true
	}

	if isFinalChunk && !alreadyComplete {
		accumulator.IsComplete = true
		accumulator.FinalTimestamp = chunk.Timestamp
	}
	accumulator.mu.Unlock()

	// If this is the final chunk and hasn't been processed yet, process accumulated chunks
	// Note: processAccumulatedStream will check for errors and skip caching if any errors occurred
	if isFinalChunk && !alreadyComplete {
		if processErr := plugin.processAccumulatedStream(ctx, responseID); processErr != nil {
			plugin.logger.Warn("%s Failed to process accumulated stream for request %s: %v", PluginLoggerPrefix, responseID, processErr)
		}
	}

	return nil
}

// getInputForCaching extracts request input for hashing/embedding without normalization.
// For Chat/Responses requests, it filters out system messages if configured but returns shallow copies.
// For other request types, it returns direct references to the input.
func (plugin *Plugin) getInputForCaching(req *schemas.DeepIntShieldRequest) interface{} {
	switch req.RequestType {
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		return req.TextCompletionRequest.Input
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		originalMessages := req.ChatRequest.Input
		filteredMessages := make([]schemas.ChatMessage, 0, len(originalMessages))
		for _, msg := range originalMessages {
			// Skip system messages if configured to exclude them
			if plugin.config.ExcludeSystemPrompt != nil && *plugin.config.ExcludeSystemPrompt && msg.Role == schemas.ChatMessageRoleSystem {
				continue
			}
			filteredMessages = append(filteredMessages, msg)
		}
		return filteredMessages
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		originalMessages := req.ResponsesRequest.Input
		filteredMessages := make([]schemas.ResponsesMessage, 0, len(originalMessages))
		for _, msg := range originalMessages {
			// Skip system messages if configured to exclude them
			if plugin.config.ExcludeSystemPrompt != nil && *plugin.config.ExcludeSystemPrompt && msg.Role != nil && *msg.Role == schemas.ResponsesInputMessageRoleSystem {
				continue
			}
			filteredMessages = append(filteredMessages, msg)
		}
		return filteredMessages
	case schemas.SpeechRequest, schemas.SpeechStreamRequest:
		return req.SpeechRequest.Input.Input
	case schemas.EmbeddingRequest:
		return req.EmbeddingRequest.Input
	case schemas.TranscriptionRequest, schemas.TranscriptionStreamRequest:
		return req.TranscriptionRequest.Input
	case schemas.ImageGenerationRequest, schemas.ImageGenerationStreamRequest:
		return req.ImageGenerationRequest.Input
	default:
		return nil
	}
}

// getNormalizedInputForCaching returns a copy of req.Input for hashing/embedding. The input is normalized.
// It applies text normalization (lowercase + trim) and optionally removes system messages.
func (plugin *Plugin) getNormalizedInputForCaching(req *schemas.DeepIntShieldRequest) interface{} {
	switch req.RequestType {
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		// Create a deep copy of the input to avoid mutating the original request
		copiedInput := schemas.TextCompletionInput{}
		if req.TextCompletionRequest.Input.PromptStr != nil {
			copiedPromptStr := *req.TextCompletionRequest.Input.PromptStr
			copiedInput.PromptStr = &copiedPromptStr
		} else if len(req.TextCompletionRequest.Input.PromptArray) > 0 {
			copiedPromptArray := make([]string, len(req.TextCompletionRequest.Input.PromptArray))
			copy(copiedPromptArray, req.TextCompletionRequest.Input.PromptArray)
			copiedInput.PromptArray = copiedPromptArray
		}

		if copiedInput.PromptStr != nil {
			normalizedText := normalizeText(*copiedInput.PromptStr)
			copiedInput.PromptStr = &normalizedText
		} else if len(copiedInput.PromptArray) > 0 {
			// Create a copy of the PromptArray and normalize each element
			normalizedPromptArray := make([]string, len(copiedInput.PromptArray))
			copy(normalizedPromptArray, copiedInput.PromptArray)
			for i, prompt := range normalizedPromptArray {
				normalizedPromptArray[i] = normalizeText(prompt)
			}
			copiedInput.PromptArray = normalizedPromptArray
		}
		return copiedInput
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		originalMessages := req.ChatRequest.Input
		normalizedMessages := make([]schemas.ChatMessage, 0, len(originalMessages))

		for _, msg := range originalMessages {
			// Skip system messages if configured to exclude them
			if plugin.config.ExcludeSystemPrompt != nil && *plugin.config.ExcludeSystemPrompt && msg.Role == schemas.ChatMessageRoleSystem {
				continue
			}

			// Create a deep copy of the message with normalized content
			normalizedMsg := schemas.DeepCopyChatMessage(msg)

			// Normalize message content
			// Content can be nil for messages like assistant tool-call messages
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					normalizedContent := normalizeText(*msg.Content.ContentStr)
					normalizedMsg.Content.ContentStr = &normalizedContent
				} else if msg.Content.ContentBlocks != nil {
					// Create a copy of content blocks with normalized text
					normalizedBlocks := make([]schemas.ChatContentBlock, len(msg.Content.ContentBlocks))
					for i, block := range msg.Content.ContentBlocks {
						normalizedBlocks[i] = block
						if block.Text != nil {
							normalizedText := normalizeText(*block.Text)
							normalizedBlocks[i].Text = &normalizedText
						}
					}
					normalizedMsg.Content.ContentBlocks = normalizedBlocks
				}
			}

			normalizedMessages = append(normalizedMessages, normalizedMsg)
		}
		return normalizedMessages
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		originalMessages := req.ResponsesRequest.Input
		normalizedMessages := make([]schemas.ResponsesMessage, 0, len(originalMessages))

		for _, msg := range originalMessages {
			// Skip system messages if configured to exclude them
			if plugin.config.ExcludeSystemPrompt != nil && *plugin.config.ExcludeSystemPrompt && msg.Role != nil && *msg.Role == schemas.ResponsesInputMessageRoleSystem {
				continue
			}

			// Create a deep copy of the message with normalized content
			normalizedMsg := schemas.DeepCopyResponsesMessage(msg)

			// Create a deep copy of the Content to avoid modifying the original
			if msg.Content != nil {
				if msg.Content.ContentStr != nil {
					normalizedText := normalizeText(*msg.Content.ContentStr)
					normalizedMsg.Content.ContentStr = &normalizedText
				} else if msg.Content.ContentBlocks != nil {
					// Create a copy of content blocks with normalized text
					normalizedBlocks := make([]schemas.ResponsesMessageContentBlock, len(msg.Content.ContentBlocks))
					for i, block := range msg.Content.ContentBlocks {
						normalizedBlocks[i] = block
						if block.Text != nil {
							normalizedText := normalizeText(*block.Text)
							normalizedBlocks[i].Text = &normalizedText
						}
					}
					normalizedMsg.Content.ContentBlocks = normalizedBlocks
				}
			}

			normalizedMessages = append(normalizedMessages, normalizedMsg)
		}
		return normalizedMessages
	case schemas.SpeechRequest, schemas.SpeechStreamRequest:
		return normalizeText(req.SpeechRequest.Input.Input)
	case schemas.EmbeddingRequest:
		// Create a deep copy of the input to avoid mutating the original request
		copiedInput := schemas.EmbeddingInput{}
		if req.EmbeddingRequest.Input.Text != nil {
			copiedText := *req.EmbeddingRequest.Input.Text
			copiedInput.Text = &copiedText
		} else if len(req.EmbeddingRequest.Input.Texts) > 0 {
			copiedTexts := make([]string, len(req.EmbeddingRequest.Input.Texts))
			copy(copiedTexts, req.EmbeddingRequest.Input.Texts)
			copiedInput.Texts = copiedTexts
		} else if req.EmbeddingRequest.Input.Embedding != nil {
			copiedEmbedding := make([]int, len(req.EmbeddingRequest.Input.Embedding))
			copy(copiedEmbedding, req.EmbeddingRequest.Input.Embedding)
			copiedInput.Embedding = copiedEmbedding
		} else if req.EmbeddingRequest.Input.Embeddings != nil {
			copiedEmbeddings := make([][]int, len(req.EmbeddingRequest.Input.Embeddings))
			copy(copiedEmbeddings, req.EmbeddingRequest.Input.Embeddings)
			copiedInput.Embeddings = copiedEmbeddings
		}
		if copiedInput.Text != nil {
			normalizedText := normalizeText(*copiedInput.Text)
			copiedInput.Text = &normalizedText
		} else if len(copiedInput.Texts) > 0 {
			normalizedTexts := make([]string, len(copiedInput.Texts))
			for i, text := range copiedInput.Texts {
				normalizedTexts[i] = normalizeText(text)
			}
			copiedInput.Texts = normalizedTexts
		}
		return copiedInput
	case schemas.TranscriptionRequest, schemas.TranscriptionStreamRequest:
		return req.TranscriptionRequest.Input
	case schemas.ImageGenerationRequest, schemas.ImageGenerationStreamRequest:
		if req.ImageGenerationRequest != nil && req.ImageGenerationRequest.Input != nil {
			return &schemas.ImageGenerationInput{
				Prompt: normalizeText(req.ImageGenerationRequest.Input.Prompt),
			}
		}
		return nil
	default:
		return nil
	}
}

// removeField removes the first occurrence of target from the slice.
func removeField(arr []string, target string) []string {
	for i, v := range arr {
		if v == target {
			// remove element at index i
			return append(arr[:i], arr[i+1:]...)
		}
	}
	return arr // unchanged if target not found
}

// extractChatParametersToMetadata extracts Chat API parameters into metadata map
func (plugin *Plugin) extractChatParametersToMetadata(params *schemas.ChatParameters, metadata map[string]interface{}) {
	if params.ToolChoice != nil {
		if params.ToolChoice.ChatToolChoiceStr != nil {
			metadata["tool_choice"] = *params.ToolChoice.ChatToolChoiceStr
		} else if params.ToolChoice.ChatToolChoiceStruct != nil && params.ToolChoice.ChatToolChoiceStruct.Function != nil && params.ToolChoice.ChatToolChoiceStruct.Function.Name != "" {
			metadata["tool_choice"] = params.ToolChoice.ChatToolChoiceStruct.Function.Name
		}
	}
	if params.Temperature != nil {
		metadata["temperature"] = *params.Temperature
	}
	if params.TopP != nil {
		metadata["top_p"] = *params.TopP
	}
	if params.MaxCompletionTokens != nil {
		metadata["max_tokens"] = *params.MaxCompletionTokens
	}
	if params.Stop != nil {
		metadata["stop_sequences"] = params.Stop
	}
	if params.PresencePenalty != nil {
		metadata["presence_penalty"] = *params.PresencePenalty
	}
	if params.FrequencyPenalty != nil {
		metadata["frequency_penalty"] = *params.FrequencyPenalty
	}
	if params.ParallelToolCalls != nil {
		metadata["parallel_tool_calls"] = *params.ParallelToolCalls
	}
	if params.User != nil {
		metadata["user"] = *params.User
	}
	if params.LogitBias != nil {
		metadata["logit_bias"] = *params.LogitBias
	}
	if params.LogProbs != nil {
		metadata["logprobs"] = *params.LogProbs
	}
	if params.Modalities != nil {
		metadata["modalities"] = params.Modalities
	}
	if params.PromptCacheKey != nil {
		metadata["prompt_cache_key"] = *params.PromptCacheKey
	}
	if params.Reasoning != nil && params.Reasoning.Enabled != nil {
		metadata["reasoning_enabled"] = *params.Reasoning.Enabled
	}
	if params.Reasoning != nil && params.Reasoning.Effort != nil {
		metadata["reasoning_effort"] = *params.Reasoning.Effort
	}
	if params.ResponseFormat != nil {
		metadata["response_format"] = params.ResponseFormat
	}
	if params.SafetyIdentifier != nil {
		metadata["safety_identifier"] = *params.SafetyIdentifier
	}
	if params.Seed != nil {
		metadata["seed"] = *params.Seed
	}
	if params.ServiceTier != nil {
		metadata["service_tier"] = *params.ServiceTier
	}
	if params.Store != nil {
		metadata["store"] = *params.Store
	}
	if params.TopLogProbs != nil {
		metadata["top_logprobs"] = *params.TopLogProbs
	}
	if params.Verbosity != nil {
		metadata["verbosity"] = *params.Verbosity
	}
	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
	if len(params.Tools) > 0 {
		tools := make([]interface{}, len(params.Tools))
		for i, t := range params.Tools {
			tools[i] = t
		}
		if toolsJSON, err := schemas.MarshalDeeplySorted(tools); err != nil {
			plugin.logger.Warn("%s Failed to marshal tools for metadata: %v", PluginLoggerPrefix, err)
		} else {
			toolHash := xxhash.Sum64(toolsJSON)
			metadata["tools_hash"] = fmt.Sprintf("%x", toolHash)
		}
	}
}

// extractResponsesParametersToMetadata extracts Responses API parameters into metadata map
func (plugin *Plugin) extractResponsesParametersToMetadata(params *schemas.ResponsesParameters, metadata map[string]interface{}) {
	if params.ToolChoice != nil {
		if params.ToolChoice.ResponsesToolChoiceStr != nil {
			metadata["tool_choice"] = *params.ToolChoice.ResponsesToolChoiceStr
		} else if params.ToolChoice.ResponsesToolChoiceStruct != nil && params.ToolChoice.ResponsesToolChoiceStruct.Name != nil {
			metadata["tool_choice"] = *params.ToolChoice.ResponsesToolChoiceStruct.Name
		}
	}
	if params.Temperature != nil {
		metadata["temperature"] = *params.Temperature
	}
	if params.TopP != nil {
		metadata["top_p"] = *params.TopP
	}
	if params.MaxOutputTokens != nil {
		metadata["max_tokens"] = *params.MaxOutputTokens
	}
	if params.ParallelToolCalls != nil {
		metadata["parallel_tool_calls"] = *params.ParallelToolCalls
	}
	if params.Background != nil {
		metadata["background"] = *params.Background
	}
	if params.Conversation != nil {
		metadata["conversation"] = *params.Conversation
	}
	if params.Include != nil {
		metadata["include"] = params.Include
	}
	if params.Instructions != nil {
		metadata["instructions"] = *params.Instructions
	}
	if params.MaxToolCalls != nil {
		metadata["max_tool_calls"] = *params.MaxToolCalls
	}
	if params.PreviousResponseID != nil {
		metadata["previous_response_id"] = *params.PreviousResponseID
	}
	if params.PromptCacheKey != nil {
		metadata["prompt_cache_key"] = *params.PromptCacheKey
	}
	if params.Reasoning != nil {
		if params.Reasoning.Effort != nil {
			metadata["reasoning_effort"] = *params.Reasoning.Effort
		}
		if params.Reasoning.MaxTokens != nil {
			metadata["reasoning_max_tokens"] = *params.Reasoning.MaxTokens
		}
		if params.Reasoning.Summary != nil {
			metadata["reasoning_summary"] = *params.Reasoning.Summary
		}
	}
	if params.SafetyIdentifier != nil {
		metadata["safety_identifier"] = *params.SafetyIdentifier
	}
	if params.ServiceTier != nil {
		metadata["service_tier"] = *params.ServiceTier
	}
	if params.Store != nil {
		metadata["store"] = *params.Store
	}
	if params.Text != nil {
		if params.Text.Verbosity != nil {
			metadata["text_verbosity"] = *params.Text.Verbosity
		}
		if params.Text.Format != nil {
			metadata["text_format_type"] = params.Text.Format.Type
		}
	}
	if params.TopLogProbs != nil {
		metadata["top_logprobs"] = *params.TopLogProbs
	}
	if params.Truncation != nil {
		metadata["truncation"] = *params.Truncation
	}
	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
	if len(params.Tools) > 0 {
		tools := make([]interface{}, len(params.Tools))
		for i, t := range params.Tools {
			tools[i] = t
		}
		if toolsJSON, err := schemas.MarshalDeeplySorted(tools); err != nil {
			plugin.logger.Warn("%s Failed to marshal tools for metadata: %v", PluginLoggerPrefix, err)
		} else {
			toolHash := xxhash.Sum64(toolsJSON)
			metadata["tools_hash"] = fmt.Sprintf("%x", toolHash)
		}
	}
}

// extractTextCompletionParametersToMetadata extracts Text Completion parameters into metadata map
func (plugin *Plugin) extractTextCompletionParametersToMetadata(params *schemas.TextCompletionParameters, metadata map[string]interface{}) {
	if params.Temperature != nil {
		metadata["temperature"] = *params.Temperature
	}
	if params.TopP != nil {
		metadata["top_p"] = *params.TopP
	}
	if params.MaxTokens != nil {
		metadata["max_tokens"] = *params.MaxTokens
	}
	if params.Stop != nil {
		metadata["stop_sequences"] = params.Stop
	}
	if params.PresencePenalty != nil {
		metadata["presence_penalty"] = *params.PresencePenalty
	}
	if params.FrequencyPenalty != nil {
		metadata["frequency_penalty"] = *params.FrequencyPenalty
	}
	if params.User != nil {
		metadata["user"] = *params.User
	}
	if params.BestOf != nil {
		metadata["best_of"] = *params.BestOf
	}
	if params.Echo != nil {
		metadata["echo"] = *params.Echo
	}
	if params.LogitBias != nil {
		metadata["logit_bias"] = *params.LogitBias
	}
	if params.LogProbs != nil {
		metadata["logprobs"] = *params.LogProbs
	}
	if params.N != nil {
		metadata["n"] = *params.N
	}
	if params.Seed != nil {
		metadata["seed"] = *params.Seed
	}
	if params.Suffix != nil {
		metadata["suffix"] = *params.Suffix
	}
	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
}

// extractSpeechParametersToMetadata extracts Speech parameters into metadata map
func (plugin *Plugin) extractSpeechParametersToMetadata(params *schemas.SpeechParameters, metadata map[string]interface{}) {
	if params == nil {
		return
	}

	if params.Speed != nil {
		metadata["speed"] = *params.Speed
	}
	if params.ResponseFormat != "" {
		metadata["response_format"] = params.ResponseFormat
	}
	if params.Instructions != "" {
		metadata["instructions"] = params.Instructions
	}
	// Check if VoiceConfig.Voice is non-nil before accessing it
	if params.VoiceConfig.Voice != nil {
		metadata["voice"] = *params.VoiceConfig.Voice
	}
	if len(params.VoiceConfig.MultiVoiceConfig) > 0 {
		flattenedVC := make([]string, len(params.VoiceConfig.MultiVoiceConfig))
		for i, vc := range params.VoiceConfig.MultiVoiceConfig {
			flattenedVC[i] = fmt.Sprintf("%s:%s", vc.Speaker, vc.Voice)
		}
		metadata["multi_voice_count"] = flattenedVC
	}
	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
}

// extractEmbeddingParametersToMetadata extracts Embedding parameters into metadata map
func (plugin *Plugin) extractEmbeddingParametersToMetadata(params *schemas.EmbeddingParameters, metadata map[string]interface{}) {
	if params.EncodingFormat != nil {
		metadata["encoding_format"] = *params.EncodingFormat
	}
	if params.Dimensions != nil {
		metadata["dimensions"] = *params.Dimensions
	}
	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
}

// extractTranscriptionParametersToMetadata extracts Transcription parameters into metadata map
func (plugin *Plugin) extractTranscriptionParametersToMetadata(params *schemas.TranscriptionParameters, metadata map[string]interface{}) {
	if params.Language != nil {
		metadata["language"] = *params.Language
	}
	if params.ResponseFormat != nil {
		metadata["response_format"] = *params.ResponseFormat
	}
	if params.Prompt != nil {
		metadata["prompt"] = *params.Prompt
	}
	if params.Format != nil {
		metadata["file_format"] = *params.Format
	}
	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
}

// extractImageGenerationParametersToMetadata extracts Image Generation parameters into metadata map
func (plugin *Plugin) extractImageGenerationParametersToMetadata(params *schemas.ImageGenerationParameters, metadata map[string]interface{}) {
	if params == nil {
		return
	}

	if params.N != nil {
		metadata["n"] = *params.N
	}
	if params.Background != nil {
		metadata["background"] = *params.Background
	}
	if params.Moderation != nil {
		metadata["moderation"] = *params.Moderation
	}
	if params.PartialImages != nil {
		metadata["partial_images"] = *params.PartialImages
	}
	if params.Size != nil {
		metadata["size"] = *params.Size
	}
	if params.Quality != nil {
		metadata["quality"] = *params.Quality
	}
	if params.OutputCompression != nil {
		metadata["output_compression"] = *params.OutputCompression
	}
	if params.OutputFormat != nil {
		metadata["output_format"] = *params.OutputFormat
	}
	if params.Style != nil {
		metadata["style"] = *params.Style
	}
	if params.ResponseFormat != nil {
		metadata["response_format"] = *params.ResponseFormat
	}
	if params.Seed != nil {
		metadata["seed"] = *params.Seed
	}
	if params.NegativePrompt != nil {
		metadata["negative_prompt"] = *params.NegativePrompt
	}
	if params.NumInferenceSteps != nil {
		metadata["num_inference_steps"] = *params.NumInferenceSteps
	}
	if params.User != nil {
		metadata["user"] = *params.User
	}

	if len(params.ExtraParams) > 0 {
		maps.Copy(metadata, params.ExtraParams)
	}
}

func (plugin *Plugin) isConversationHistoryThresholdExceeded(req *schemas.DeepIntShieldRequest) bool {
	switch {
	case req.ChatRequest != nil:
		input, ok := plugin.getInputForCaching(req).([]schemas.ChatMessage)
		if !ok {
			return false
		}
		if len(input) > plugin.config.ConversationHistoryThreshold {
			return true
		}
		return false
	case req.ResponsesRequest != nil:
		input, ok := plugin.getInputForCaching(req).([]schemas.ResponsesMessage)
		if !ok {
			return false
		}
		if len(input) > plugin.config.ConversationHistoryThreshold {
			return true
		}
		return false
	default:
		return false
	}
}
