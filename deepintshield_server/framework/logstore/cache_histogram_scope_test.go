package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCacheHistogram_TracksScopeAndSuppressionCounts(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "tenant-cache-analytics")
	baseTime := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)

	logs := []*Log{
		{
			ID:        "cache-log-user-hit",
			Timestamp: baseTime,
			Object:    "chat.completion",
			Provider:  "openai",
			Model:     "gpt-4o-mini",
			Status:    "success",
			CacheDebugParsed: &schemas.DeepIntShieldCacheDebug{
				CacheHit:    true,
				HitType:     schemas.Ptr("direct"),
				ScopeType:   schemas.Ptr("user"),
				ScopeSource: schemas.Ptr("governance_user_id"),
			},
		},
		{
			ID:        "cache-log-explicit-hit",
			Timestamp: baseTime.Add(5 * time.Minute),
			Object:    "chat.completion",
			Provider:  "openai",
			Model:     "gpt-4o-mini",
			Status:    "success",
			CacheDebugParsed: &schemas.DeepIntShieldCacheDebug{
				CacheHit:    true,
				HitType:     schemas.Ptr("semantic"),
				ScopeType:   schemas.Ptr("virtual_key"),
				ScopeSource: schemas.Ptr("explicit_cache_key"),
			},
		},
		{
			ID:        "cache-log-suppressed-miss",
			Timestamp: baseTime.Add(10 * time.Minute),
			Object:    "chat.completion",
			Provider:  "openai",
			Model:     "gpt-4o-mini",
			Status:    "success",
			CacheDebugParsed: &schemas.DeepIntShieldCacheDebug{
				CacheHit:                 false,
				ScopeType:                schemas.Ptr("virtual_key"),
				ScopeSource:              schemas.Ptr("virtual_key"),
				SemanticSuppressedReason: schemas.Ptr("unscoped_shared_virtual_key"),
			},
		},
	}

	for _, entry := range logs {
		require.NoError(t, store.Create(ctx, entry))
	}

	result, err := store.GetCacheHistogram(ctx, SearchFilters{}, 3600)
	require.NoError(t, err)
	require.Len(t, result.Buckets, 1)

	bucket := result.Buckets[0]
	assert.Equal(t, baseTime, bucket.Timestamp)
	assert.EqualValues(t, 3, bucket.CacheRequests)
	assert.EqualValues(t, 2, bucket.CacheHits)
	assert.EqualValues(t, 1, bucket.CacheMisses)
	assert.EqualValues(t, 1, bucket.DirectHits)
	assert.EqualValues(t, 1, bucket.SemanticHits)
	assert.EqualValues(t, 1, bucket.UserScopeHits)
	assert.EqualValues(t, 1, bucket.VirtualKeyScopeHits)
	assert.EqualValues(t, 1, bucket.AutoScopedHits)
	assert.EqualValues(t, 1, bucket.ExplicitOverrideHits)
	assert.EqualValues(t, 1, bucket.SemanticSuppressions)
}
