package mcp

import (
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// classifiedToolCalls is the result of running the safety + dependency
// heuristics over a batch of tool calls. Preserves the original order so
// the indexOf helper can map back to per-tool duration slots.
type classifiedToolCalls struct {
	all               []schemas.ChatAssistantMessageToolCall // in original order
	parallel          []schemas.ChatAssistantMessageToolCall
	sequential        []schemas.ChatAssistantMessageToolCall
	unknownSerialized int
}

// indexOf returns the original position of a tool call in the batch.
// Used to write per-tool duration into the right slot of perToolDuration.
func (c classifiedToolCalls) indexOf(target schemas.ChatAssistantMessageToolCall) int {
	for i, tc := range c.all {
		if equalStringPtr(tc.ID, target.ID) && equalStringPtr(tc.Function.Name, target.Function.Name) {
			return i
		}
	}
	return -1
}

func equalStringPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func toolNameOrEmpty(name *string) string {
	if name == nil {
		return ""
	}
	return *name
}

// classifyToolCallsForParallel splits a batch into parallel-safe vs
// sequential subsets based on the operator-configured safety registry plus
// the optional argument-name heuristic.
//
//   - Registry lookup by exact name, then by `server-*` wildcard. Unknown
//     tools use cfg.DefaultSafe.
//   - Argument-name heuristic (cfg.HeuristicArgs=true): if two tool calls
//     reference the same JSON-argument key, we conservatively serialize
//     them - that's the "output of A feeds B" pattern the spec calls out.
//
// Returns the classification + counts. Operation is read-only on the
// inputs; safe to call from the hot path.
func classifyToolCallsForParallel(toolCalls []schemas.ChatAssistantMessageToolCall, cfg ParallelToolConfig) ([]schemas.ChatAssistantMessageToolCall, []schemas.ChatAssistantMessageToolCall, classifiedToolCalls) {
	result := classifiedToolCalls{
		all:        toolCalls,
		parallel:   make([]schemas.ChatAssistantMessageToolCall, 0, len(toolCalls)),
		sequential: make([]schemas.ChatAssistantMessageToolCall, 0),
	}
	if len(toolCalls) <= 1 {
		// Single-tool batches don't benefit from parallel dispatch - keep
		// them on the parallel path so the existing fast-path stays simple.
		result.parallel = append(result.parallel, toolCalls...)
		return result.parallel, result.sequential, result
	}

	// Phase 1 - apply the safety registry.
	for _, tc := range toolCalls {
		safe, known := isToolSafeForParallel(cfg, toolNameOrEmpty(tc.Function.Name))
		if !known {
			result.unknownSerialized++
		}
		if safe {
			result.parallel = append(result.parallel, tc)
		} else {
			result.sequential = append(result.sequential, tc)
		}
	}

	// Phase 2 - argument-name heuristic. If two tools in the parallel-safe
	// bucket share an argument name, conservatively move the second one to
	// the sequential bucket. Cheap and directionally correct; operators
	// who want stricter dependency tracking should tag explicitly in the
	// registry rather than rely on this.
	if cfg.HeuristicArgs && len(result.parallel) >= 2 {
		seen := map[string]bool{}
		newParallel := make([]schemas.ChatAssistantMessageToolCall, 0, len(result.parallel))
		for _, tc := range result.parallel {
			args := extractArgKeys(tc.Function.Arguments)
			conflict := false
			for _, key := range args {
				if seen[key] {
					conflict = true
					break
				}
			}
			if conflict {
				result.sequential = append(result.sequential, tc)
				continue
			}
			for _, key := range args {
				seen[key] = true
			}
			newParallel = append(newParallel, tc)
		}
		result.parallel = newParallel
	}

	return result.parallel, result.sequential, result
}

// extractArgKeys is a cheap JSON-object key extractor. Arguments is a JSON
// string per OpenAI's tool-call schema; we parse it to a generic map and
// return the top-level keys. Failure-to-parse returns no keys - the
// heuristic then treats the call as having no shared args.
func extractArgKeys(arguments string) []string {
	s := strings.TrimSpace(arguments)
	if s == "" {
		return nil
	}
	var m map[string]any
	if err := sonic.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ParallelToolsDebugContextKey carries the per-step debug stamp from the
// agent loop to the semantic_cache plugin's PostLLMHook. Exported so the
// plugin can read it without circular imports.
const ParallelToolsDebugContextKey = schemas.DeepIntShieldContextKey("parallel-tools-decision")

// ParallelToolsDecision is the materialized telemetry for one agent step.
// Lives in core/mcp so the agent loop can build it without depending on the
// semanticcache plugin; the plugin reads it from context and copies onto
// the response. Mirrors DeepIntShieldParallelToolsDebug shape.
type ParallelToolsDecision struct {
	Applied                bool
	TotalTools             int
	ParallelCount          int
	SequentialCount        int
	WallClockMs            int
	SerialEstimateMs       int
	LatencySavedMs         int
	UnknownToolsSerialized int
}

// recordParallelToolsDebug computes the final telemetry numbers + stashes
// them on context for PostLLMHook pickup. Wall-clock = time since fan-out
// started; serial estimate = sum of per-tool durations. The difference
// (clamped to ≥ 0) is the savings.
func recordParallelToolsDebug(ctx *schemas.DeepIntShieldContext, enabled bool, classified classifiedToolCalls, stepStart time.Time, perToolDuration []time.Duration) {
	if ctx == nil {
		return
	}
	wallMs := int(time.Since(stepStart) / time.Millisecond)
	var serialMs int
	for _, d := range perToolDuration {
		serialMs += int(d / time.Millisecond)
	}
	savedMs := serialMs - wallMs
	if savedMs < 0 {
		savedMs = 0
	}
	dec := ParallelToolsDecision{
		Applied:                enabled,
		TotalTools:             len(classified.all),
		ParallelCount:          len(classified.parallel),
		SequentialCount:        len(classified.sequential),
		WallClockMs:            wallMs,
		SerialEstimateMs:       serialMs,
		LatencySavedMs:         savedMs,
		UnknownToolsSerialized: classified.unknownSerialized,
	}
	ctx.SetValue(ParallelToolsDebugContextKey, dec)
}
