package modelcatalog

import (
	"regexp"
	"strings"
)

// canonicalizeModelName collapses provider-suffixed model identifiers down to a
// stable family name so an unversioned request (e.g. "claude-opus-4-5",
// "gpt-4o-mini", "gemini-2.5-flash") can fall back to the dated/snapshot
// pricing row that providers actually publish ("claude-opus-4-5-20251101",
// "gpt-4o-mini-2024-07-18", "gemini-2.5-flash-002"). The result is provider-
// agnostic: it strips trailing date stamps, snapshot indices, preview/latest
// tags, and Vertex's "@version" suffix, then lower-cases the result so the
// alias index hits regardless of casing.
//
// Examples:
//
//	claude-opus-4-5-20251101         -> claude-opus-4-5
//	claude-opus-4-5@20251101         -> claude-opus-4-5
//	gpt-4o-mini-2024-07-18           -> gpt-4o-mini
//	gpt-4o-mini-preview-2024-09-30   -> gpt-4o-mini-preview
//	gemini-2.5-flash-002             -> gemini-2.5-flash
//	gemini-2.5-flash-preview-09-2025 -> gemini-2.5-flash-preview
//	claude-3-5-sonnet-latest         -> claude-3-5-sonnet
//	anthropic/claude-opus-4-5        -> claude-opus-4-5
//	openai/gpt-4o-mini               -> gpt-4o-mini
//	anthropic.claude-opus-4-5        -> claude-opus-4-5
//
// The function is intentionally idempotent: canonicalize(canonicalize(x)) == canonicalize(x).
func canonicalizeModelName(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return ""
	}

	// Strip Vertex's "@version" suffix first - it never carries model family
	// information.
	if idx := strings.IndexByte(m, '@'); idx >= 0 {
		m = m[:idx]
	}

	// Strip provider prefixes. "anthropic/foo", "openai/foo", and
	// "anthropic.foo" (Bedrock) all converge on "foo".
	if idx := strings.IndexAny(m, "/"); idx >= 0 {
		m = m[idx+1:]
	}
	// Bedrock-style "anthropic.claude-…": only collapse when the dotted
	// prefix is a known provider tag, otherwise leave the dot in place
	// (some model family names use dots - e.g. "phi-3.5-mini").
	for _, prefix := range []string{"anthropic.", "amazon.", "meta.", "mistral.", "cohere.", "ai21."} {
		if strings.HasPrefix(m, prefix) {
			m = m[len(prefix):]
			break
		}
	}

	// Drop transient release-channel suffixes.
	for _, suffix := range []string{"-latest", "-stable", "-experimental"} {
		if strings.HasSuffix(m, suffix) {
			m = strings.TrimSuffix(m, suffix)
			break
		}
	}

	// Strip trailing date / snapshot stamps. Order matters: longer first.
	m = canonicalDateSuffixRe.ReplaceAllString(m, "")
	return strings.TrimRight(m, "-_")
}

// canonicalDateSuffixRe matches the trailing date / snapshot patterns that
// providers tack onto pinned model versions:
//
//	-2024-07-18      (OpenAI snapshot)
//	-20251101        (Anthropic / Bedrock dated)
//	-09-2025         (Gemini month-year preview)
//	-002, -001       (Gemini numeric snapshot)
//	-v1, -v2         (Cohere style version tag)
//
// Anchored at end-of-string so model families with embedded numbers
// (e.g. "claude-3-5-sonnet", "gpt-4o-mini") aren't mangled.
var canonicalDateSuffixRe = regexp.MustCompile(
	`(?:-(?:\d{4}-\d{2}-\d{2}|\d{8}|\d{2}-\d{4}|\d{3,4}|v\d{1,3}))$`,
)

// canonicalAliasKey is the alias-index key for the canonicalized form.
// Same shape as makeKey so the lookup is symmetrical: callers reuse the
// canonicalized model + the request's provider + mode.
func canonicalAliasKey(model, provider, mode string) string {
	return makeKey(canonicalizeModelName(model), strings.ToLower(strings.TrimSpace(provider)), mode)
}
