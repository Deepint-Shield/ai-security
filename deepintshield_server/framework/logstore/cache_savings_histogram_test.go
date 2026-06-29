package logstore

import (
	"context"
	"testing"
	"time"
)

func TestGetCostHistogram_IncludesCacheSavingsFromCacheHits(t *testing.T) {
	store := newTestSQLiteStore(t)
	ctx := context.Background()
	baseTime := time.Date(2026, time.April, 14, 20, 0, 0, 0, time.UTC)

	cacheOnlySavings := 1.25
	actualCost := 0.40
	actualCostSavings := 0.10

	entries := []*Log{
		{
			ID:           "log-cache-hit",
			Timestamp:    baseTime,
			Object:       "chat.completion",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			Status:       "success",
			CacheSavings: &cacheOnlySavings,
		},
		{
			ID:           "log-paid-request",
			Timestamp:    baseTime.Add(10 * time.Minute),
			Object:       "chat.completion",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			Status:       "success",
			Cost:         &actualCost,
			CacheSavings: &actualCostSavings,
		},
	}

	for _, entry := range entries {
		if err := store.Create(ctx, entry); err != nil {
			t.Fatalf("Create(%s) error = %v", entry.ID, err)
		}
	}

	start := baseTime.Add(-time.Hour)
	end := baseTime.Add(time.Hour)
	result, err := store.GetCostHistogram(ctx, SearchFilters{
		StartTime: &start,
		EndTime:   &end,
	}, 3600)
	if err != nil {
		t.Fatalf("GetCostHistogram() error = %v", err)
	}

	if len(result.Buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(result.Buckets))
	}

	target := result.Buckets[1]
	if target.TotalCost != actualCost {
		t.Fatalf("expected total cost %.2f, got %.2f", actualCost, target.TotalCost)
	}
	if target.CacheSavings != cacheOnlySavings+actualCostSavings {
		t.Fatalf("expected cache savings %.2f, got %.2f", cacheOnlySavings+actualCostSavings, target.CacheSavings)
	}
	if target.ByModel["gpt-4o-mini"] != actualCost {
		t.Fatalf("expected by-model cost %.2f, got %.2f", actualCost, target.ByModel["gpt-4o-mini"])
	}
	if target.ByModelCacheSavings["gpt-4o-mini"] != cacheOnlySavings+actualCostSavings {
		t.Fatalf(
			"expected by-model cache savings %.2f, got %.2f",
			cacheOnlySavings+actualCostSavings,
			target.ByModelCacheSavings["gpt-4o-mini"],
		)
	}
}
