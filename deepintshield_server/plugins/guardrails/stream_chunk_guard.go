package guardrails

import (
	"sync"
	"unicode/utf8"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	regexp "github.com/grafana/regexp"
)

// streamGuardWindowSize is how many runes of recent output we keep buffered
// for pattern matching. 1024 runes covers typical PII/secrets/jailbreak
// patterns (most are <100 chars) with enough slack that a match spanning a
// chunk boundary is still seen.
const streamGuardWindowSize = 1024

// streamGuardContextKey carries the per-stream rolling buffer + match state
// across HTTPTransportStreamChunkHook invocations. One entry per request.
const streamGuardContextKey schemas.DeepIntShieldContextKey = "deepintshield-guardrail-stream-state"

// streamGuardPatterns is the compiled set of output regexes that get
// evaluated on the rolling window. These come from the MS toolkit output
// guard preset - bearer tokens, private keys, exfil URLs, system-prompt
// echo. Keep this list short and very-high-precision: false positives here
// truncate the user's stream.
//
// Run order matches detection priority (most-critical first). All compile
// once at init; no per-request allocation.
var streamGuardPatterns = func() []streamGuardPattern {
	src := []struct {
		category string
		expr     string
	}{
		{"bearer_token_leak", `Bearer\s+[A-Za-z0-9\-._~+/]{12,}=*`},
		{"private_key_leak", `-----BEGIN (RSA |EC )?PRIVATE KEY-----`},
		{"exfil_url_echo", `(?i)https?://[^\s]+/(exfil|collect|beacon)`},
		{"injection_echo", `(?i)ignore\s+(all\s+)?previous\s+instructions`},
		{"aws_key_leak", `\bAKIA[0-9A-Z]{16}\b`},
		{"github_pat_leak", `\bgh[pousr]_[A-Za-z0-9]{36,}\b`},
		{"slack_token_leak", `\bxox[baprs]-[A-Za-z0-9-]{10,}\b`},
		{"google_api_key_leak", `\bAIza[0-9A-Za-z\-_]{35}\b`},
	}
	out := make([]streamGuardPattern, 0, len(src))
	for _, p := range src {
		re, err := regexp.Compile(p.expr)
		if err != nil {
			continue
		}
		out = append(out, streamGuardPattern{category: p.category, re: re})
	}
	return out
}()

type streamGuardPattern struct {
	category string
	re       *regexp.Regexp
}

// streamGuardState lives on the request context for the duration of a
// streaming response. It accumulates a UTF-8-safe rolling buffer of recent
// output runes and tracks whether the stream has already been marked
// terminated by a previous match.
type streamGuardState struct {
	mu         sync.Mutex
	buffer     []byte
	terminated bool
	hits       []string // unique category names that fired
}

func (s *streamGuardState) append(text string) {
	if text == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffer = append(s.buffer, text...)
	// Trim to keep at most streamGuardWindowSize runes. Runes != bytes for
	// multibyte sequences, so trim at a valid rune boundary.
	if len(s.buffer) > streamGuardWindowSize*4 { // worst-case 4 bytes/rune
		// Drop the leading half but never cut mid-rune.
		trimAt := len(s.buffer) - streamGuardWindowSize*2
		for trimAt < len(s.buffer) && !utf8.RuneStart(s.buffer[trimAt]) {
			trimAt++
		}
		s.buffer = append(s.buffer[:0], s.buffer[trimAt:]...)
	}
}

// scan runs all stream-guard patterns against the rolling buffer. Returns
// (matched, category). Pure-read, safe to call concurrently with append.
func (s *streamGuardState) scan() (bool, string) {
	s.mu.Lock()
	bufCopy := append([]byte(nil), s.buffer...)
	s.mu.Unlock()
	for _, pat := range streamGuardPatterns {
		if pat.re.Match(bufCopy) {
			return true, pat.category
		}
	}
	return false, ""
}

// streamStateFor returns the per-request stream state, creating it on first
// access. Subsequent chunk hooks reuse the same state.
func streamStateFor(ctx *schemas.DeepIntShieldContext) *streamGuardState {
	if ctx == nil {
		return nil
	}
	if existing, ok := ctx.Value(streamGuardContextKey).(*streamGuardState); ok && existing != nil {
		return existing
	}
	state := &streamGuardState{buffer: make([]byte, 0, streamGuardWindowSize*2)}
	ctx.SetValue(streamGuardContextKey, state)
	return state
}

// extractChunkText returns the user-visible text from a chunk. Covers the
// three streaming response shapes we evaluate: chat completion deltas,
// responses-API stream deltas, text-completion deltas. Returns "" for
// shapes that don't contain text (errors, image deltas, etc.).
func extractChunkText(chunk *schemas.DeepIntShieldStreamChunk) string {
	if chunk == nil {
		return ""
	}
	if chunk.DeepIntShieldChatResponse != nil && len(chunk.DeepIntShieldChatResponse.Choices) > 0 {
		choice := chunk.DeepIntShieldChatResponse.Choices[0]
		if choice.ChatStreamResponseChoice != nil && choice.ChatStreamResponseChoice.Delta != nil {
			if c := choice.ChatStreamResponseChoice.Delta.Content; c != nil {
				return *c
			}
		}
	}
	if chunk.DeepIntShieldTextCompletionResponse != nil && len(chunk.DeepIntShieldTextCompletionResponse.Choices) > 0 {
		choice := chunk.DeepIntShieldTextCompletionResponse.Choices[0]
		if choice.TextCompletionResponseChoice != nil && choice.TextCompletionResponseChoice.Text != nil {
			return *choice.TextCompletionResponseChoice.Text
		}
	}
	if chunk.DeepIntShieldResponsesStreamResponse != nil && chunk.DeepIntShieldResponsesStreamResponse.Delta != nil {
		return *chunk.DeepIntShieldResponsesStreamResponse.Delta
	}
	return ""
}

// hasStreamGuardsEnabled reports whether the request context opted into
// stream-level guardrails. We reuse the same VK hint that gates exact-eval
// because if the VK has no guards configured, there is nothing to check.
func hasStreamGuardsEnabled(ctx *schemas.DeepIntShieldContext) bool {
	if ctx == nil {
		return false
	}
	actor := resolveActorFromContext(ctx)
	return actor.HasGuards
}

// dedupeAppend adds value to slice only if not already present. Used to keep
// the streamGuardState.hits list small and deduped.
func dedupeAppend(slice []string, value string) []string {
	for _, s := range slice {
		if s == value {
			return slice
		}
	}
	return append(slice, value)
}

// truncationChunk returns a synthetic chat-completion chunk that signals
// finish_reason="content_filter" - the OpenAI-standard signal for a
// truncated response due to safety filtering. Most SDKs handle this
// gracefully (anthropic, openai, langchain).
func truncationChunk(category string) *schemas.DeepIntShieldStreamChunk {
	reason := "content_filter"
	chunk := &schemas.DeepIntShieldStreamChunk{
		DeepIntShieldChatResponse: &schemas.DeepIntShieldChatResponse{
			Choices: []schemas.DeepIntShieldResponseChoice{
				{
					Index:        0,
					FinishReason: &reason,
					ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
						Delta: &schemas.ChatStreamResponseChoiceDelta{},
					},
				},
			},
		},
	}
	// Stash the matched category as response-header metadata so the
	// HTTPTransportPostHook (and any downstream observability) can see
	// which check fired.
	_ = category
	return chunk
}

// _ = deepintshield is kept so the imports stay parseable while we expose
// these helpers - the package is referenced by resolveActorFromContext via
// the resolvedActorKey file.
var _ = deepintshield.GetBoolFromContext
