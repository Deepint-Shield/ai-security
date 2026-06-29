package schemas

import (
	"context"
	"testing"
	"time"
)

func TestLatencyBreakdownTracksPhasesAndWallTime(t *testing.T) {
	ctx, cancel := NewDeepIntShieldContextWithCancel(context.Background())
	defer cancel()

	start := time.Now().Add(-25 * time.Millisecond)
	EnsureLatencyTracking(ctx, start)
	RecordLatencyPhase(ctx, LatencyPhaseCacheLookupDirect, 2*time.Millisecond)
	RecordLatencyPhase(ctx, LatencyPhaseGuardrailInput, 3*time.Millisecond)
	RecordLatencyPhase(ctx, LatencyPhaseGuardrailInput, 4*time.Millisecond)

	breakdown := GetLatencyBreakdownMilliseconds(ctx)
	if breakdown[string(LatencyPhaseCacheLookupDirect)] != 2 {
		t.Fatalf("expected direct cache lookup phase to equal 2ms, got %d", breakdown[string(LatencyPhaseCacheLookupDirect)])
	}
	if breakdown[string(LatencyPhaseGuardrailInput)] != 7 {
		t.Fatalf("expected guardrail input phase to equal 7ms, got %d", breakdown[string(LatencyPhaseGuardrailInput)])
	}

	if wall := RequestWallLatencyMilliseconds(ctx); wall < 20 {
		t.Fatalf("expected request wall latency to be >= 20ms, got %d", wall)
	}
}

func TestTrackLatencyPhaseRecordsMinimumMillisecond(t *testing.T) {
	ctx, cancel := NewDeepIntShieldContextWithCancel(context.Background())
	defer cancel()

	EnsureLatencyTracking(ctx, time.Now())
	stop := TrackLatencyPhase(ctx, LatencyPhaseLoggingEnqueue)
	time.Sleep(500 * time.Microsecond)
	stop()

	breakdown := GetLatencyBreakdownMilliseconds(ctx)
	if breakdown[string(LatencyPhaseLoggingEnqueue)] < 1 {
		t.Fatalf("expected logging enqueue phase to be at least 1ms, got %d", breakdown[string(LatencyPhaseLoggingEnqueue)])
	}
}
