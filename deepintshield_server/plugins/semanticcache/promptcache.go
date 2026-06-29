package semanticcache

import (
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// Provider-native prompt caching (Anthropic `cache_control`, Bedrock `cachePoint`,
// OpenAI `prompt_cache_key`) is governed by a workspace-level switch on the
// semantic cache plugin's config. The SDK injects these markers on every request;
// the gateway either passes them through unchanged or strips them here based on
// workspace policy.
//
// Performance: the fast path (cache enabled + provider allow-listed) returns
// immediately without walking the request, so this hook adds essentially zero
// latency in the common case. The strip path is O(messages + content_blocks +
// tools) with no allocations beyond reassigning pointer fields to nil.

const (
	promptCacheDefaultEnabled       = true
	promptCacheDefaultMinTokens     = 1024
	promptCacheDefaultAnthropicTTL  = "5m"
	promptCacheExtendedAnthropicTTL = "1h"
	promptCacheProviderAnthropic    = "anthropic"
	promptCacheProviderOpenAI       = "openai"
	promptCacheProviderBedrock      = "bedrock"
	promptCacheProviderGoogle       = "google"
)

var defaultPromptCacheProviders = []string{promptCacheProviderAnthropic, promptCacheProviderOpenAI, promptCacheProviderBedrock}

// isPromptCacheEnabledForProvider reports whether the gateway should keep the
// SDK-emitted prompt-cache markers for an outbound request to `provider`.
//
// Workspace-level resolution rules (cheap, all in-memory):
//  1. If `PromptCacheEnabled` is nil → default ON (covers existing deployments
//     that haven't set the field).
//  2. If false → strip for every provider.
//  3. If `PromptCacheProviders` is empty → use the default allow-list.
//  4. Otherwise honor only providers explicitly listed.
func (plugin *Plugin) isPromptCacheEnabledForProvider(provider schemas.ModelProvider) bool {
	if plugin == nil || plugin.config == nil {
		return promptCacheDefaultEnabled
	}
	if plugin.config.PromptCacheEnabled != nil && !*plugin.config.PromptCacheEnabled {
		return false
	}
	providers := plugin.config.PromptCacheProviders
	if len(providers) == 0 {
		providers = defaultPromptCacheProviders
	}
	target := strings.ToLower(strings.TrimSpace(string(provider)))
	if target == "" {
		return false
	}
	for _, p := range providers {
		if strings.ToLower(strings.TrimSpace(p)) == target {
			return true
		}
	}
	return false
}

// stripProviderPromptCacheHints scrubs Anthropic `cache_control`, Bedrock
// `cachePoint`, and OpenAI `prompt_cache_key` markers from the outbound request
// when the workspace switch is off or the provider isn't allow-listed.
//
// Fast-path early return: this function is called on every LLM request before
// the semantic cache lookup, so it MUST be allocation-free and short-circuit
// the moment we know we're keeping the markers.
func (plugin *Plugin) stripProviderPromptCacheHints(req *schemas.DeepIntShieldRequest, provider schemas.ModelProvider) {
	if req == nil {
		return
	}
	if plugin.isPromptCacheEnabledForProvider(provider) {
		return
	}

	// Strip chat completion request shape.
	if req.ChatRequest != nil {
		stripChatRequestPromptCacheHints(req.ChatRequest)
	}

	// Strip responses API request shape.
	if req.ResponsesRequest != nil {
		stripResponsesRequestPromptCacheHints(req.ResponsesRequest)
	}
}

func stripChatRequestPromptCacheHints(req *schemas.DeepIntShieldChatRequest) {
	for i := range req.Input {
		stripChatMessageCacheHints(&req.Input[i])
	}
	if req.Params != nil {
		// OpenAI prompt-cache partitioning hint.
		req.Params.PromptCacheKey = nil
		req.Params.PromptCacheRetention = nil
		for i := range req.Params.Tools {
			req.Params.Tools[i].CacheControl = nil
		}
		// Gemini context cache reference. The gateway's Gemini provider reads
		// `cached_content` (and the alternate camelCase `cachedContent`) from
		// ExtraParams and maps it to Gemini's CachedContent field on the
		// outbound request. Clearing both spellings here suffices to strip the
		// hint before it reaches the provider.
		if req.Params.ExtraParams != nil {
			delete(req.Params.ExtraParams, "cached_content")
			delete(req.Params.ExtraParams, "cachedContent")
		}
	}
}

func stripChatMessageCacheHints(msg *schemas.ChatMessage) {
	if msg == nil || msg.Content == nil {
		return
	}
	for i := range msg.Content.ContentBlocks {
		block := &msg.Content.ContentBlocks[i]
		block.CacheControl = nil
		block.CachePoint = nil
	}
}

func stripResponsesRequestPromptCacheHints(req *schemas.DeepIntShieldResponsesRequest) {
	if req == nil {
		return
	}
	if req.Params != nil {
		req.Params.PromptCacheKey = nil
	}
	// Responses API messages can carry cache_control on several block types;
	// the schema exposes them at the message and content levels. We delegate
	// to a single message walker so callers don't need to know the shape.
	for i := range req.Input {
		stripResponsesMessageCacheHints(&req.Input[i])
	}
}

func stripResponsesMessageCacheHints(msg *schemas.ResponsesMessage) {
	if msg == nil {
		return
	}
	// function_call / function_call_output carry cache_control directly on the message envelope.
	msg.CacheControl = nil
	if msg.Content == nil {
		return
	}
	for i := range msg.Content.ContentBlocks {
		msg.Content.ContentBlocks[i].CacheControl = nil
	}
}

// applyProviderPromptCacheTTL makes the gateway the single source of truth for
// the prompt-cache duration. The SDK injects cache_control markers but always
// with the 5m default (providers/anthropic.py never forwards a TTL); a raw HTTP
// client may inject any TTL it likes. So that the workspace-level setting governs
// cost regardless of who built the request, this stamps the configured TTL onto
// the markers we keep.
//
// Only Anthropic exposes a gateway-controllable per-request TTL: its cache_control
// blocks carry a `ttl` field. The other providers can't be governed here -
// OpenAI caching is automatic with no TTL knob, Bedrock cachePoint blocks are
// TTL-less, and Gemini's context-cache TTL is fixed when the cached-content
// resource is created inside the SDK and never travels through the gateway as a
// request field. For those, this is a no-op by design.
//
// Performance: it walks the same O(messages + content_blocks + tools) structures
// as the strip path and only when the provider is Anthropic AND a TTL is
// configured, so the common case (no TTL set, or non-Anthropic) does zero work.
// It reads only the already-swapped in-memory config - no DB hit, no blocking I/O.
func (plugin *Plugin) applyProviderPromptCacheTTL(req *schemas.DeepIntShieldRequest, provider schemas.ModelProvider) {
	if req == nil {
		return
	}
	// A TTL only matters when we're keeping the markers for this provider; if the
	// strip path already removed them, there is nothing to stamp.
	if !plugin.isPromptCacheEnabledForProvider(provider) {
		return
	}
	if strings.ToLower(strings.TrimSpace(string(provider))) != promptCacheProviderAnthropic {
		return
	}

	ttl, configured := plugin.resolveAnthropicCacheTTL()
	if !configured {
		// No workspace opinion - leave whatever the client/SDK supplied untouched.
		return
	}

	if req.ChatRequest != nil {
		applyChatRequestCacheTTL(req.ChatRequest, ttl)
	}
	if req.ResponsesRequest != nil {
		applyResponsesRequestCacheTTL(req.ResponsesRequest, ttl)
	}
}

// resolveAnthropicCacheTTL normalizes the workspace-configured Anthropic cache
// TTL into the pointer to stamp onto cache_control.ttl:
//   - configured == false → caller leaves markers untouched (field unset).
//   - ttl == nil           → normalize to Anthropic's implicit 5m default, i.e.
//     drop any TTL a client injected (5m carries no write premium and is what
//     the API assumes when the field is absent).
//   - ttl == &"1h"         → stamp the 1h extended TTL (2x write premium).
//
// Unknown/invalid values are treated as the safe 5m default but still
// authoritative, so a stray injected "1h" is normalized away rather than honored.
func (plugin *Plugin) resolveAnthropicCacheTTL() (ttl *string, configured bool) {
	if plugin == nil || plugin.config == nil {
		return nil, false
	}
	switch strings.ToLower(strings.TrimSpace(plugin.config.PromptCacheAnthropicTTL)) {
	case "":
		return nil, false
	case promptCacheExtendedAnthropicTTL:
		extended := promptCacheExtendedAnthropicTTL
		return &extended, true
	default: // "5m" and any unexpected value
		return nil, true
	}
}

func applyChatRequestCacheTTL(req *schemas.DeepIntShieldChatRequest, ttl *string) {
	for i := range req.Input {
		msg := &req.Input[i]
		if msg.Content == nil {
			continue
		}
		for j := range msg.Content.ContentBlocks {
			applyCacheControlTTL(msg.Content.ContentBlocks[j].CacheControl, ttl)
		}
	}
	if req.Params != nil {
		for i := range req.Params.Tools {
			applyCacheControlTTL(req.Params.Tools[i].CacheControl, ttl)
		}
	}
}

func applyResponsesRequestCacheTTL(req *schemas.DeepIntShieldResponsesRequest, ttl *string) {
	for i := range req.Input {
		msg := &req.Input[i]
		applyCacheControlTTL(msg.CacheControl, ttl)
		if msg.Content == nil {
			continue
		}
		for j := range msg.Content.ContentBlocks {
			applyCacheControlTTL(msg.Content.ContentBlocks[j].CacheControl, ttl)
		}
	}
}

// applyCacheControlTTL stamps ttl onto an existing cache_control marker. It never
// creates a marker where the client/SDK didn't place one - the SDK decides WHERE
// to cache (which prefixes); the gateway only governs HOW LONG. A nil ttl clears
// the field, normalizing the block to Anthropic's 5m default. The pointer is
// shared across blocks intentionally: Go strings are immutable, so aliasing is
// safe and keeps this to a single allocation per request.
func applyCacheControlTTL(cc *schemas.CacheControl, ttl *string) {
	if cc == nil {
		return
	}
	cc.TTL = ttl
}
