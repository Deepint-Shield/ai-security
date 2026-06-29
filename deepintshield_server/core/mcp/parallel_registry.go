package mcp

import (
	"strings"
	"sync/atomic"
)

// ─────────────────────────────────────────────────────────────────────────────
// Parallel-tool safety registry.
//
// The agent loop already dispatches auto-executable tool calls in parallel
// via goroutines. Without a safety check, that's a bug for state-mutating
// tools - running two "create_order" calls concurrently can double-charge.
//
// This registry lets operators tag specific tools (or whole MCP servers) as
// safe / unsafe for parallel dispatch. Tools NOT in the registry use the
// configured default (sequential is the safer choice).
//
// Wire-up: the semantic_cache plugin bridges its Parallel-Tools config into
// this package via SetGlobalParallelToolConfig on every plugin reload - same
// pattern as mcpcache.SetGlobalToolTTLs and guardrails.SetGlobalEvalCacheConfig.
// Lock-free reads on the agent hot path via atomic.Pointer.
// ─────────────────────────────────────────────────────────────────────────────

// ParallelToolConfig is the live snapshot used by the agent loop. Empty
// `Safety` map + DefaultSafe=true reproduces the pre-feature behaviour
// (everything parallel) - useful for opt-in customers who haven't enumerated
// their tools yet.
type ParallelToolConfig struct {
	Enabled       bool            // feature switch from the workspace config
	DefaultSafe   bool            // when true, unknown tools dispatch in parallel (legacy behaviour). When false, unknown tools serialize.
	Safety        map[string]bool // tool name (with optional `server-tool` namespacing) → safe-for-parallel
	HeuristicArgs bool            // when true, also serialize when two tool calls share an argument name (output-of-A-feeds-B heuristic)
}

var globalParallelToolConfig atomic.Pointer[ParallelToolConfig]

// SetGlobalParallelToolConfig is called from the bootstrap on every
// semantic_cache plugin (re)load. Atomic swap - no agent-loop lock.
func SetGlobalParallelToolConfig(cfg ParallelToolConfig) {
	// Defensive copy of the map so concurrent readers don't see partial state.
	safety := make(map[string]bool, len(cfg.Safety))
	for k, v := range cfg.Safety {
		safety[strings.TrimSpace(k)] = v
	}
	snapshot := ParallelToolConfig{
		Enabled:       cfg.Enabled,
		DefaultSafe:   cfg.DefaultSafe,
		Safety:        safety,
		HeuristicArgs: cfg.HeuristicArgs,
	}
	globalParallelToolConfig.Store(&snapshot)
}

// effectiveParallelToolConfig returns the live config, or a legacy-permissive
// default (everything parallel) when nothing has been bridged in yet.
func effectiveParallelToolConfig() ParallelToolConfig {
	if cfg := globalParallelToolConfig.Load(); cfg != nil {
		return *cfg
	}
	return ParallelToolConfig{
		Enabled:     false, // off by default - agent loop falls through to its existing parallel path
		DefaultSafe: true,
	}
}

// isToolSafeForParallel returns (safe, known). When known is false the
// caller should consult cfg.DefaultSafe.
func isToolSafeForParallel(cfg ParallelToolConfig, toolName string) (bool, bool) {
	name := strings.TrimSpace(toolName)
	if name == "" {
		return cfg.DefaultSafe, false
	}
	if v, ok := cfg.Safety[name]; ok {
		return v, true
	}
	// Try a `*` wildcard match by namespace (server-*) - operators tag a
	// whole server as unsafe with one entry instead of every tool.
	if dash := strings.Index(name, "-"); dash > 0 {
		ns := name[:dash] + "-*"
		if v, ok := cfg.Safety[ns]; ok {
			return v, true
		}
	}
	return cfg.DefaultSafe, false
}
