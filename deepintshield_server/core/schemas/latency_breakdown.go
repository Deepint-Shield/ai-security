package schemas

import (
	"context"
	"sync"
	"time"
)

type LatencyPhase string

const (
	LatencyPhaseCacheLookupDirect   LatencyPhase = "cache_lookup_direct"
	LatencyPhaseCacheLookupSemantic LatencyPhase = "cache_lookup_semantic"
	LatencyPhaseCoalescingWait      LatencyPhase = "coalescing_wait"
	LatencyPhaseGuardrailInput      LatencyPhase = "guardrail_input"
	LatencyPhaseGuardrailOutput     LatencyPhase = "guardrail_output"
	LatencyPhaseGuardrailMCP        LatencyPhase = "guardrail_mcp"
	LatencyPhaseProvider            LatencyPhase = "provider"
	LatencyPhaseLoggingEnqueue      LatencyPhase = "logging_enqueue"
	// Plugin chain dispatch - measured around the entire PreLLM / PostLLM
	// plugin loop. Cache lookup, guardrail in/out, and logging enqueue
	// nest inside these brackets; this phase exposes the *remainder*
	// (governance + telemetry + tracer span overhead + JSON marshaling
	// inside plugins). With these phases recorded, "platform overhead"
	// in the dashboard becomes the residual after subtracting tracked
	// phases instead of an opaque catch-all.
	LatencyPhasePluginChainPre  LatencyPhase = "plugin_chain_pre"
	LatencyPhasePluginChainPost LatencyPhase = "plugin_chain_post"
)

type LatencyBreakdown struct {
	mu     sync.Mutex
	phases map[LatencyPhase]time.Duration
}

func EnsureLatencyTracking(ctx *DeepIntShieldContext, now time.Time) {
	if ctx == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if _, ok := ctx.Value(DeepIntShieldContextKeyRequestStartTime).(time.Time); !ok {
		ctx.SetValue(DeepIntShieldContextKeyRequestStartTime, now)
	}
	if _, ok := ctx.Value(DeepIntShieldContextKeyLatencyBreakdown).(*LatencyBreakdown); !ok {
		ctx.SetValue(DeepIntShieldContextKeyLatencyBreakdown, &LatencyBreakdown{
			phases: make(map[LatencyPhase]time.Duration),
		})
	}
}

func TrackLatencyPhase(ctx context.Context, phase LatencyPhase) func() {
	start := time.Now()
	return func() {
		RecordLatencyPhase(ctx, phase, time.Since(start))
	}
}

func RecordLatencyPhase(ctx context.Context, phase LatencyPhase, duration time.Duration) {
	if ctx == nil || duration <= 0 {
		return
	}
	tracker, ok := ctx.Value(DeepIntShieldContextKeyLatencyBreakdown).(*LatencyBreakdown)
	if !ok || tracker == nil {
		return
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.phases == nil {
		tracker.phases = make(map[LatencyPhase]time.Duration)
	}
	tracker.phases[phase] += duration
}

func GetLatencyBreakdownMilliseconds(ctx context.Context) map[string]int64 {
	if ctx == nil {
		return nil
	}
	tracker, ok := ctx.Value(DeepIntShieldContextKeyLatencyBreakdown).(*LatencyBreakdown)
	if !ok || tracker == nil {
		return nil
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.phases) == 0 {
		return nil
	}
	result := make(map[string]int64, len(tracker.phases))
	for phase, duration := range tracker.phases {
		ms := duration.Milliseconds()
		if ms < 1 {
			ms = 1
		}
		result[string(phase)] = ms
	}
	return result
}

func RequestWallLatencyMilliseconds(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	startTime, ok := ctx.Value(DeepIntShieldContextKeyRequestStartTime).(time.Time)
	if !ok || startTime.IsZero() {
		return 0
	}
	elapsed := time.Since(startTime).Milliseconds()
	if elapsed < 1 {
		return 1
	}
	return elapsed
}
