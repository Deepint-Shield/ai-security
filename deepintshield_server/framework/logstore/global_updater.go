package logstore

import "sync/atomic"

// globalLogStore exposes a lock-free pointer to the live LogStore so plugins
// outside the logging plugin (specifically the hallucination async worker
// pool) can patch existing log rows with late-arriving scores. The logger
// plugin sets this on Init; readers nil-check before calling.
//
// Why an atomic.Pointer + global vs. dependency injection:
// the hallucination worker pool is owned by the semantic_cache plugin,
// which initializes before the logger plugin in some bootstrap orderings.
// Plumbing the store through Init args means changing every plugin's
// constructor; the atomic pointer pattern matches the bridge approach
// already in use for mcpcache.SetGlobalToolTTLs and
// guardrails.SetGlobalEvalCacheConfig.
var globalLogStore atomic.Pointer[LogStore]

// SetGlobalLogStore is called by the logging plugin Init. Replaces the
// previous pointer atomically - no readers can see partial state.
func SetGlobalLogStore(s LogStore) {
	if s == nil {
		return
	}
	globalLogStore.Store(&s)
}

// GetGlobalLogStore returns the live store or nil. Always nil-check before
// dereferencing - when the logging plugin isn't loaded (e.g. test contexts
// without a config store), this returns nil and callers should no-op.
func GetGlobalLogStore() LogStore {
	if p := globalLogStore.Load(); p != nil {
		return *p
	}
	return nil
}
