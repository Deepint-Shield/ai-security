package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedCacheAwareMetricLogs(t *testing.T, store *RDBLogStore, now time.Time) {
	t.Helper()

	normalCost := 0.0002
	cacheSavings := 0.0002

	entries := []*Log{
		{
			ID:               "cache-aware-normal",
			Timestamp:        now,
			Object:           "chat.completion",
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			Status:           "success",
			PromptTokens:     12,
			CompletionTokens: 34,
			TotalTokens:      46,
			Cost:             &normalCost,
		},
		{
			ID:               "cache-aware-hit",
			Timestamp:        now.Add(5 * time.Minute),
			Object:           "chat.completion",
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			Status:           "success",
			PromptTokens:     80,
			CompletionTokens: 120,
			TotalTokens:      200,
			CacheSavings:     &cacheSavings,
			CacheDebugParsed: &schemas.DeepIntShieldCacheDebug{
				CacheHit: true,
				HitType:  schemas.Ptr("direct"),
			},
		},
	}

	for _, entry := range entries {
		require.NoError(t, store.Create(context.Background(), entry))
	}
}

func TestSearchLogs_ProjectsCacheMetadataAndUsesCacheAwareTokenSorting(t *testing.T) {
	store := newTestSQLiteStore(t)
	baseTime := time.Date(2026, time.April, 15, 9, 0, 0, 0, time.UTC)
	seedCacheAwareMetricLogs(t, store, baseTime)

	start := baseTime.Add(-time.Hour)
	end := baseTime.Add(time.Hour)
	result, err := store.SearchLogs(context.Background(), SearchFilters{
		StartTime: &start,
		EndTime:   &end,
	}, PaginationOptions{
		Limit:  10,
		SortBy: "tokens",
		Order:  "desc",
	})
	require.NoError(t, err)
	require.Len(t, result.Logs, 2)

	assert.Equal(t, "cache-aware-normal", result.Logs[0].ID)
	assert.Equal(t, "cache-aware-hit", result.Logs[1].ID)
	require.NotNil(t, result.Logs[1].CacheDebugParsed)
	assert.True(t, result.Logs[1].CacheDebugParsed.CacheHit)
	require.NotNil(t, result.Logs[1].CacheSavings)
	assert.Equal(t, 0.0002, *result.Logs[1].CacheSavings)
}

func TestGetStats_UsesZeroTokensForGatewayCacheHits(t *testing.T) {
	store := newTestSQLiteStore(t)
	baseTime := time.Date(2026, time.April, 15, 9, 0, 0, 0, time.UTC)
	seedCacheAwareMetricLogs(t, store, baseTime)

	start := baseTime.Add(-time.Hour)
	end := baseTime.Add(time.Hour)
	stats, err := store.GetStats(context.Background(), SearchFilters{
		StartTime: &start,
		EndTime:   &end,
	})
	require.NoError(t, err)

	assert.EqualValues(t, 2, stats.TotalRequests)
	assert.EqualValues(t, 46, stats.TotalTokens)
	assert.InDelta(t, 0.0002, stats.TotalCost, 0.0000001)
}

func TestGetProviderTokenHistogram_UsesZeroTokensForGatewayCacheHits(t *testing.T) {
	store := newTestSQLiteStore(t)
	baseTime := time.Date(2026, time.April, 15, 9, 0, 0, 0, time.UTC)
	seedCacheAwareMetricLogs(t, store, baseTime)

	start := baseTime.Add(-time.Hour)
	end := baseTime.Add(time.Hour)
	result, err := store.GetProviderTokenHistogram(context.Background(), SearchFilters{
		StartTime: &start,
		EndTime:   &end,
	}, 3600)
	require.NoError(t, err)
	require.Len(t, result.Buckets, 3)

	providerStats := result.Buckets[1].ByProvider["openai"]
	assert.EqualValues(t, 12, providerStats.PromptTokens)
	assert.EqualValues(t, 34, providerStats.CompletionTokens)
	assert.EqualValues(t, 46, providerStats.TotalTokens)
}

func TestGetModelRankings_UsesZeroTokensForGatewayCacheHits(t *testing.T) {
	store := newTestSQLiteStore(t)
	baseTime := time.Date(2026, time.April, 15, 9, 0, 0, 0, time.UTC)
	seedCacheAwareMetricLogs(t, store, baseTime)

	start := baseTime.Add(-time.Hour)
	end := baseTime.Add(time.Hour)
	result, err := store.GetModelRankings(context.Background(), SearchFilters{
		StartTime: &start,
		EndTime:   &end,
	})
	require.NoError(t, err)
	require.Len(t, result.Rankings, 1)

	ranking := result.Rankings[0]
	assert.Equal(t, "gpt-4o-mini", ranking.Model)
	assert.EqualValues(t, 2, ranking.TotalRequests)
	assert.EqualValues(t, 46, ranking.TotalTokens)
	assert.InDelta(t, 0.0002, ranking.TotalCost, 0.0000001)
}
