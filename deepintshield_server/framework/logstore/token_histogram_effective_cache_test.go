package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTokenHistogram_UsesGatewayCacheHitsAsEffectiveCachedPromptTokens(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	baseTime := time.Date(2026, time.April, 14, 21, 0, 0, 0, time.UTC)

	entries := []*Log{
		{
			ID:               "token-hist-provider-cache",
			Timestamp:        baseTime,
			Object:           "chat.completion",
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			Status:           "success",
			PromptTokens:     100,
			CompletionTokens: 20,
			TotalTokens:      120,
			CachedReadTokens: 30,
		},
		{
			ID:               "token-hist-gateway-hit",
			Timestamp:        baseTime.Add(5 * time.Minute),
			Object:           "chat.completion",
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			Status:           "success",
			PromptTokens:     80,
			CompletionTokens: 10,
			TotalTokens:      90,
			CachedReadTokens: 0,
			CacheDebugParsed: &schemas.DeepIntShieldCacheDebug{
				CacheHit: true,
				HitType:  schemas.Ptr("direct"),
			},
		},
	}

	for _, entry := range entries {
		require.NoError(t, store.Create(ctx, entry))
	}

	start := baseTime.Add(-time.Hour)
	end := baseTime.Add(time.Hour)
	result, err := store.GetTokenHistogram(ctx, SearchFilters{
		StartTime: &start,
		EndTime:   &end,
	}, 3600)
	require.NoError(t, err)
	require.Len(t, result.Buckets, 3)

	target := result.Buckets[1]
	assert.EqualValues(t, 100, target.PromptTokens)
	assert.EqualValues(t, 20, target.CompletionTokens)
	assert.EqualValues(t, 120, target.TotalTokens)
	assert.EqualValues(t, 30, target.CachedReadTokens)
	assert.EqualValues(t, 110, target.EffectiveCachedPromptTokens)
}
