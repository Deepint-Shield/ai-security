package guardrails

import (
	"context"
	"strings"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func TestAccumulateStreamOutputCadenceAndStreamEnd(t *testing.T) {
	prev := guardrailsStreamAccumulate
	guardrailsStreamAccumulate = true
	defer func() { guardrailsStreamAccumulate = prev }()

	p := &Plugin{}
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	const rid = "stream-test-cadence"

	// Small delta below the scan cadence → released without scanning.
	text, scan := p.accumulateStreamOutput(ctx, rid, "hello ")
	if scan {
		t.Fatalf("small first delta should be cadence-skipped, got scan=true")
	}
	if text != "hello " {
		t.Fatalf("accumulator should hold the first delta, got %q", text)
	}

	// Cross the cadence threshold → scan now, window contains both deltas.
	big := strings.Repeat("x", streamAccumScanEveryN)
	text, scan = p.accumulateStreamOutput(ctx, rid, big)
	if !scan {
		t.Fatalf("crossing the cadence threshold should trigger a scan")
	}
	if !strings.HasPrefix(text, "hello ") || !strings.Contains(text, big) {
		t.Fatalf("accumulated window must contain prior + current deltas")
	}

	// Final chunk always scans and cleans up the accumulator.
	ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
	_, scan = p.accumulateStreamOutput(ctx, rid, "!")
	if !scan {
		t.Fatalf("final chunk must always scan")
	}
	streamAccumMu.Lock()
	_, present := streamAccums[rid]
	streamAccumMu.Unlock()
	if present {
		t.Fatalf("accumulator must be deleted after the stream end")
	}
}

func TestStreamChunkDeltaExtractsChatDelta(t *testing.T) {
	content := "partial answer"
	resp := &schemas.DeepIntShieldResponse{
		ChatResponse: &schemas.DeepIntShieldChatResponse{
			Choices: []schemas.DeepIntShieldResponseChoice{
				{ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
					Delta: &schemas.ChatStreamResponseChoiceDelta{Content: &content},
				}},
			},
		},
	}
	if got := streamChunkDelta(resp); got != "partial answer" {
		t.Fatalf("expected chat stream delta content, got %q", got)
	}
}

func TestStreamAccumulatorSlidingWindowRetainsTail(t *testing.T) {
	prev := guardrailsStreamAccumulate
	guardrailsStreamAccumulate = true
	defer func() { guardrailsStreamAccumulate = prev }()

	p := &Plugin{}
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	const rid = "stream-test-sliding"
	defer deleteStreamAccumulator(rid)

	// Overflow the window with filler, then send a LATE marker. A tail-drop
	// (freeze) bug would never scan the marker; a true sliding window keeps it.
	chunk := strings.Repeat("y", streamAccumScanEveryN)
	for i := 0; i < (streamAccumMaxBytes/len(chunk))+10; i++ {
		p.accumulateStreamOutput(ctx, rid, chunk)
	}
	text, scan := p.accumulateStreamOutput(ctx, rid, "LATE_VIOLATION_MARKER")

	if len(text) > streamAccumMaxBytes+streamAccumScanEveryN {
		t.Fatalf("window must stay bounded near %d, got %d", streamAccumMaxBytes, len(text))
	}
	if !strings.Contains(text, "LATE_VIOLATION_MARKER") {
		t.Fatalf("sliding window must retain the most-recent (tail) content for scanning")
	}
	_ = scan
}
