package logging

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
)

func TestApplyLatencyBreakdownMetadata_UsesProviderLatencyOnMiss(t *testing.T) {
	ctx, cancel := schemas.NewDeepIntShieldContextWithCancel(context.Background())
	defer cancel()

	schemas.EnsureLatencyTracking(ctx, time.Now().Add(-40*time.Millisecond))
	schemas.RecordLatencyPhase(ctx, schemas.LatencyPhaseCacheLookupDirect, 2*time.Millisecond)
	schemas.RecordLatencyPhase(ctx, schemas.LatencyPhaseGuardrailInput, 5*time.Millisecond)

	entry := &logstore.Log{}
	result := &schemas.DeepIntShieldResponse{
		ChatResponse: &schemas.DeepIntShieldChatResponse{},
	}
	result.GetExtraFields().Latency = 31

	applyLatencyBreakdownMetadata(entry, ctx, result)

	rawBreakdown, ok := entry.MetadataParsed["latency_breakdown_ms"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected latency_breakdown_ms metadata to be present")
	}
	if provider := rawBreakdown["provider"]; provider != int64(31) {
		t.Fatalf("expected provider latency to be 31ms, got %#v", provider)
	}
}

func TestApplyLatencyBreakdownMetadata_UsesZeroProviderLatencyOnCacheHit(t *testing.T) {
	ctx, cancel := schemas.NewDeepIntShieldContextWithCancel(context.Background())
	defer cancel()

	schemas.EnsureLatencyTracking(ctx, time.Now().Add(-8*time.Millisecond))
	schemas.RecordLatencyPhase(ctx, schemas.LatencyPhaseCacheLookupDirect, 3*time.Millisecond)

	entry := &logstore.Log{}
	result := &schemas.DeepIntShieldResponse{
		ChatResponse: &schemas.DeepIntShieldChatResponse{},
	}
	result.GetExtraFields().Latency = 4
	result.GetExtraFields().CacheDebug = &schemas.DeepIntShieldCacheDebug{CacheHit: true}

	applyLatencyBreakdownMetadata(entry, ctx, result)

	rawBreakdown, ok := entry.MetadataParsed["latency_breakdown_ms"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected latency_breakdown_ms metadata to be present")
	}
	if provider := rawBreakdown["provider"]; provider != int64(0) {
		t.Fatalf("expected provider latency to be 0ms for cache hit, got %#v", provider)
	}
	if _, exists := rawBreakdown[string(schemas.LatencyPhaseCacheLookupDirect)]; !exists {
		t.Fatalf("expected direct cache lookup phase to be included in metadata")
	}
}
