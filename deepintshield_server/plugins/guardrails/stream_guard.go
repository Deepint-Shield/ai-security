package guardrails

import (
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// guardrailsStreamAccumulate gates incremental streaming-output guarding
// (GUARDRAILS_STREAM_ACCUMULATE). Default OFF: each streaming chunk is evaluated
// exactly as before (per-delta), so behavior is unchanged. When ON, streamed
// output deltas are accumulated per request and the guard evaluates the growing
// window on a character cadence, so a violation split across chunk boundaries
// (PII or a banned phrase straddling token edges) is caught - the "incremental
// scan + late-cancel" mode from the multimodal plan. It cannot retract tokens
// already on the wire, but a deny cuts the remainder of the stream.
var guardrailsStreamAccumulate = os.Getenv("GUARDRAILS_STREAM_ACCUMULATE") == "true"

const (
	// streamAccumMaxBytes caps the accumulated window per request as a sliding
	// window: once full, the oldest bytes scroll out as new deltas arrive, so
	// memory and scan cost stay bounded while the most-recent content (where a
	// late violation would appear) is always retained and scanned.
	streamAccumMaxBytes = 256 * 1024
	// streamAccumScanEveryN is the re-scan cadence: the guard runs once per this
	// many newly-accumulated characters (plus always on the final chunk). This
	// keeps streaming latency flat - the guard is not invoked per token.
	streamAccumScanEveryN = 512
	// streamAccumTTL / streamAccumMaxEntries bound the accumulator registry so
	// abandoned streams (client disconnects before the end marker) cannot leak.
	streamAccumTTL        = 5 * time.Minute
	streamAccumMaxEntries = 4096
)

type streamAccumulator struct {
	mu          sync.Mutex
	buf         strings.Builder
	lastScanLen int
	updated     time.Time
}

var (
	streamAccumMu sync.Mutex
	streamAccums  = map[string]*streamAccumulator{}
)

func getStreamAccumulator(requestID string) *streamAccumulator {
	streamAccumMu.Lock()
	defer streamAccumMu.Unlock()
	if a := streamAccums[requestID]; a != nil {
		return a
	}
	if len(streamAccums) >= streamAccumMaxEntries {
		sweepStreamAccumsLocked()
	}
	a := &streamAccumulator{updated: time.Now()}
	streamAccums[requestID] = a
	return a
}

func deleteStreamAccumulator(requestID string) {
	streamAccumMu.Lock()
	delete(streamAccums, requestID)
	streamAccumMu.Unlock()
}

// sweepStreamAccumsLocked evicts accumulators idle longer than the TTL, and if
// still at capacity sheds the least-recently-updated entries (most likely
// stalled/abandoned) down to a target - preserving the hot, actively-streaming
// windows instead of wiping every active stream. Caller must hold streamAccumMu.
func sweepStreamAccumsLocked() {
	cutoff := time.Now().Add(-streamAccumTTL)
	for k, a := range streamAccums {
		a.mu.Lock()
		idle := a.updated.Before(cutoff)
		a.mu.Unlock()
		if idle {
			delete(streamAccums, k)
		}
	}
	if len(streamAccums) < streamAccumMaxEntries {
		return
	}
	type accumAge struct {
		key     string
		updated time.Time
	}
	ages := make([]accumAge, 0, len(streamAccums))
	for k, a := range streamAccums {
		a.mu.Lock()
		ages = append(ages, accumAge{k, a.updated})
		a.mu.Unlock()
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].updated.Before(ages[j].updated) })
	target := streamAccumMaxEntries * 3 / 4
	for i := 0; i < len(ages) && len(streamAccums) > target; i++ {
		delete(streamAccums, ages[i].key)
	}
}

// accumulateStreamOutput appends a chunk's delta to the per-request window and
// reports the text the guard should evaluate plus whether to evaluate it now.
//   - scanNow == false → cadence skip: release this chunk without a guard call.
//   - scanNow == true  → evaluate the returned accumulated window.
//
// The window is always scanned on the final chunk (StreamEndIndicator), after
// which the accumulator is discarded.
func (p *Plugin) accumulateStreamOutput(ctx *schemas.DeepIntShieldContext, requestID, delta string) (text string, scanNow bool) {
	streamEnd := false
	if v, ok := ctx.Value(schemas.DeepIntShieldContextKeyStreamEndIndicator).(bool); ok && v {
		streamEnd = true
	}

	a := getStreamAccumulator(requestID)
	a.mu.Lock()
	if delta != "" {
		a.buf.WriteString(delta)
		// Sliding window: when the buffer exceeds the cap, retain the most
		// recent bytes (drop the oldest prefix) rather than freezing the prefix
		// and dropping new deltas - otherwise a violation late in a long stream
		// would never be scanned. Cut on a UTF-8 rune boundary so detector input
		// is never corrupted, and shift lastScanLen down by the dropped amount so
		// the cadence keeps firing on the retained tail.
		if a.buf.Len() > streamAccumMaxBytes {
			s := a.buf.String()
			drop := len(s) - streamAccumMaxBytes
			for drop < len(s) && !utf8.RuneStart(s[drop]) {
				drop++
			}
			kept := s[drop:]
			a.buf.Reset()
			a.buf.WriteString(kept)
			if a.lastScanLen > drop {
				a.lastScanLen -= drop
			} else {
				a.lastScanLen = 0
			}
		}
	}
	a.updated = time.Now()
	cur := a.buf.String()
	scan := streamEnd || (len(cur)-a.lastScanLen) >= streamAccumScanEveryN
	if scan {
		a.lastScanLen = len(cur)
	}
	a.mu.Unlock()

	if streamEnd {
		deleteStreamAccumulator(requestID)
	}
	return cur, scan
}

// streamChunkDelta extracts the incremental text carried by a single streaming
// response chunk across the streamed response shapes. Unlike
// extractResponseOutput (which reads finalized non-stream choices), this reads
// the per-chunk Delta - including chat stream deltas, which the non-stream path
// does not surface.
func streamChunkDelta(resp *schemas.DeepIntShieldResponse) string {
	switch {
	case resp == nil:
		return ""
	case resp.ResponsesStreamResponse != nil && resp.ResponsesStreamResponse.Delta != nil:
		return *resp.ResponsesStreamResponse.Delta
	case resp.TranscriptionStreamResponse != nil:
		if resp.TranscriptionStreamResponse.Delta != nil {
			return *resp.TranscriptionStreamResponse.Delta
		}
		return resp.TranscriptionStreamResponse.Text
	case resp.ImageGenerationStreamResponse != nil:
		// Image stream events carry text only as the revised prompt on the
		// completed event; the image bytes are guarded via output Attachments.
		return resp.ImageGenerationStreamResponse.RevisedPrompt
	case resp.ChatResponse != nil:
		var parts []string
		for _, c := range resp.ChatResponse.Choices {
			if c.ChatStreamResponseChoice != nil && c.ChatStreamResponseChoice.Delta != nil {
				d := c.ChatStreamResponseChoice.Delta
				if d.Content != nil {
					parts = append(parts, *d.Content)
				}
				if d.Refusal != nil {
					parts = append(parts, *d.Refusal)
				}
			} else if c.ChatNonStreamResponseChoice != nil && c.ChatNonStreamResponseChoice.Message != nil {
				parts = append(parts, chatMessagesText([]schemas.ChatMessage{*c.ChatNonStreamResponseChoice.Message}))
			}
		}
		return joinGuardrailText(parts)
	}
	// Text-completion streams carry per-chunk text in the standard choice
	// shape that extractResponseOutput already reads.
	return extractResponseOutput(resp)
}
