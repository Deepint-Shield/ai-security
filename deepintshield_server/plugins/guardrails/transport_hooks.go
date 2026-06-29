package guardrails

import (
	"github.com/deepint-shield/ai-security/core/schemas"
)

// HTTPTransportPreHook is a no-op for guardrails. LLM-level enforcement
// happens in PreLLMHook where we have the parsed prompt. The transport
// pre-hook would only see opaque bytes.
func (p *Plugin) HTTPTransportPreHook(_ *schemas.DeepIntShieldContext, _ *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}

// HTTPTransportPostHook is a no-op for guardrails. PostLLMHook already
// covers non-streaming response evaluation.
func (p *Plugin) HTTPTransportPostHook(_ *schemas.DeepIntShieldContext, _ *schemas.HTTPRequest, _ *schemas.HTTPResponse) error {
	return nil
}

// HTTPTransportStreamChunkHook runs the token-level output guard on every
// streamed chunk. The fast path is dominant: when the VK has no guards
// enabled we return the chunk unchanged after a single map lookup. When
// guards are enabled, we append the chunk's text to a rolling buffer and
// run a small, high-precision regex set against it.
//
// On a match, the chunk is suppressed and a synthetic finish_reason=
// "content_filter" chunk is emitted so the SDK sees a clean stream end.
// Subsequent chunks are also suppressed via the terminated flag - once a
// secret/token leak is detected, we never serve more bytes.
func (p *Plugin) HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, _ *schemas.HTTPRequest, chunk *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	if chunk == nil || !hasStreamGuardsEnabled(ctx) {
		return chunk, nil
	}
	state := streamStateFor(ctx)
	if state == nil {
		return chunk, nil
	}
	if state.terminated {
		// Already cut the stream on a prior match - drop everything that
		// follows so partial output of a deny verdict can't leak.
		return nil, nil
	}
	text := extractChunkText(chunk)
	if text == "" {
		return chunk, nil
	}
	state.append(text)
	matched, category := state.scan()
	if !matched {
		return chunk, nil
	}
	state.mu.Lock()
	state.terminated = true
	state.hits = dedupeAppend(state.hits, category)
	state.mu.Unlock()
	setGuardrailResponseHeaders(ctx, "blocked", "stream")
	return truncationChunk(category), nil
}
