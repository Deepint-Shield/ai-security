package modelcatalog

import "testing"

// TestCanonicalizeModelNameAcrossProviders pins the cross-provider model-name
// canonicalization rules so the alias index keeps resolving dated /
// snapshotted / provider-prefixed model strings down to a single family key.
// If a provider ships a new tag style and any of these break, the cost /
// savings columns will silently go blank for that model - these assertions
// are the smoke alarm.
func TestCanonicalizeModelNameAcrossProviders(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// Anthropic - dated snapshots.
		{"anthropic dated", "claude-opus-4-5-20251101", "claude-opus-4-5"},
		{"anthropic plain stays plain", "claude-opus-4-5", "claude-opus-4-5"},
		{"anthropic provider prefix", "anthropic/claude-opus-4-5", "claude-opus-4-5"},
		{"anthropic latest channel", "claude-3-5-sonnet-latest", "claude-3-5-sonnet"},

		// Bedrock - "anthropic.foo" provider prefix.
		{"bedrock claude", "anthropic.claude-opus-4-5-20251101", "claude-opus-4-5"},
		{"bedrock mistral", "mistral.mistral-large-2407", "mistral-large"},

		// Vertex - "@version" suffix.
		{"vertex anthropic", "claude-opus-4-5@20251101", "claude-opus-4-5"},
		{"vertex provider prefix", "anthropic/claude-opus-4-5@20251101", "claude-opus-4-5"},

		// OpenAI - full ISO dated snapshot.
		{"openai dated", "gpt-4o-mini-2024-07-18", "gpt-4o-mini"},
		{"openai plain stays plain", "gpt-4o-mini", "gpt-4o-mini"},
		{"openai provider prefix", "openai/gpt-4o-mini", "gpt-4o-mini"},

		// Gemini - month-year preview, numeric snapshot.
		{"gemini month-year", "gemini-2.5-flash-preview-09-2025", "gemini-2.5-flash-preview"},
		{"gemini numeric snapshot", "gemini-2.5-flash-002", "gemini-2.5-flash"},
		{"gemini plain stays plain", "gemini-2.5-flash", "gemini-2.5-flash"},

		// Idempotence: re-canonicalizing must be a no-op.
		{"idempotent anthropic", "claude-opus-4-5", "claude-opus-4-5"},
		{"idempotent openai", "gpt-4o-mini", "gpt-4o-mini"},

		// Empty / whitespace stays empty (no panic, no allocation regression).
		{"empty", "", ""},
		{"whitespace", "   ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := canonicalizeModelName(c.input); got != c.want {
				t.Fatalf("canonicalizeModelName(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

// (End-to-end alias-fallback behavior is exercised indirectly through
// pricing_test.go / overrides_test.go. The canonicalization table above is
// the surface that's most likely to drift as new provider release tags appear,
// so that's where the regression net belongs.)
