package handlers

import (
	"testing"
)

// TestRecommendedSemanticCacheDefaultsCoversEveryTab is the regression guard for
// fresh-workspace seeding. The OSS build ships the deterministic cache features
// (provider prompt caching, exact/semantic cache, request coalescing, guardrail
// decision cache); each must arrive set on a new workspace's config_plugins row
// so the operator doesn't open the dashboard to a half-configured form. The
// premium cost-optimization knobs (compression / RAG re-rank / summarization /
// TTFT / parallel-tools / cascade / hallucination-eval) are not seeded here.
func TestRecommendedSemanticCacheDefaultsCoversEveryTab(t *testing.T) {
	seed := recommendedSemanticCacheDefaults()

	mustBeTrue := []string{
		"prompt_cache_enabled",
		"coalescing_enabled",
		"guardrail_cache_enabled",
	}
	for _, k := range mustBeTrue {
		v, ok := seed[k]
		if !ok {
			t.Errorf("seed missing key %q", k)
			continue
		}
		b, ok := v.(bool)
		if !ok || !b {
			t.Errorf("seed key %q = %v, want true", k, v)
		}
	}

	mustEqual := map[string]any{
		"provider":        "huggingface",
		"embedding_model": "BAAI/bge-base-en-v1.5",
		"ttl_seconds":     3600,
		"threshold":       0.70,
		"cache_by_model":  false,
	}
	for k, want := range mustEqual {
		got, ok := seed[k]
		if !ok {
			t.Errorf("seed missing key %q", k)
			continue
		}
		if got != want {
			t.Errorf("seed[%q] = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}

	mustBeSlice := map[string]int{
		"prompt_cache_providers":   4, // anthropic, openai, bedrock, google
		"prompt_cache_breakpoints": 2, // system, tools
	}
	for k, wantLen := range mustBeSlice {
		v, ok := seed[k]
		if !ok {
			t.Errorf("seed missing key %q", k)
			continue
		}
		switch arr := v.(type) {
		case []string:
			if len(arr) != wantLen {
				t.Errorf("seed[%q] len = %d, want %d", k, len(arr), wantLen)
			}
		case []any:
			if len(arr) != wantLen {
				t.Errorf("seed[%q] len = %d, want %d", k, len(arr), wantLen)
			}
		default:
			t.Errorf("seed[%q] = %T, want []string or []any", k, v)
		}
	}
}
