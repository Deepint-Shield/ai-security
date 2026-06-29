package configstore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Workspace-scoped logs settings on the hot path.
//
// The logging plugin needs to know "should this request's body be persisted?"
// on every single inference call. A DB round-trip per request would push
// guardrail-eval latency back into the multi-ms range we just spent effort
// removing. So we resolve workspace overrides against an in-memory snapshot:
//
//   - Snapshot is an atomic.Pointer[workspaceLoggingSnapshot]. Reads are
//     lock-free; writes do a copy-on-write swap.
//   - Lookups by workspace ID are O(1) (map read).
//   - On first access for a workspace whose row hasn't been loaded yet, we
//     fall through to the DB and prime the cache. The TTL keeps stale entries
//     from rotting if an admin updates the row through a back-channel.
//   - The Upsert handler invalidates the swap so the next call rebuilds.
//
// Concurrent updates are coalesced by sync.Once-on-key - a hot workspace
// hit by N concurrent requests during a swap window only refreshes the row
// once. This keeps a thundering herd from saturating the DB under burst.

// Default TTL for cached snapshots. Aggressive enough that an admin's edit
// becomes visible to in-flight traffic within ~30s without polling, slow
// enough that a workspace under sustained load doesn't keep the DB warm.
const workspaceLoggingCacheTTL = 30 * time.Second

type workspaceLoggingEntry struct {
	settings *WorkspaceLoggingSettings // nil = no override row exists; defaults apply
	loadedAt time.Time
}

type workspaceLoggingSnapshot struct {
	byID map[string]*workspaceLoggingEntry
}

var (
	workspaceLoggingPtr   atomic.Pointer[workspaceLoggingSnapshot]
	workspaceLoggingLoad  sync.Map // map[workspaceID]*sync.Once - coalesces concurrent first-loads
	workspaceLoggingStore atomic.Pointer[ConfigStore]
)

// RegisterWorkspaceLoggingStore is called once at boot so the cache knows
// where to fetch overrides on a miss. The logging plugin doesn't import
// configstore directly so we expose this as a free function.
func RegisterWorkspaceLoggingStore(store ConfigStore) {
	if store == nil {
		return
	}
	workspaceLoggingStore.Store(&store)
	// Initialize an empty snapshot so the first reader doesn't see nil.
	if workspaceLoggingPtr.Load() == nil {
		workspaceLoggingPtr.Store(&workspaceLoggingSnapshot{byID: map[string]*workspaceLoggingEntry{}})
	}
}

// LookupWorkspaceLoggingSettings returns the override for `workspaceID` from
// the in-memory cache. Returns (nil, true) when we KNOW no override exists,
// (settings, true) when an override was cached, and (nil, false) when we
// haven't loaded this workspace yet. Callers that want a guaranteed read
// (with DB fallback) should use ResolveWorkspaceLoggingSettings instead.
func LookupWorkspaceLoggingSettings(workspaceID string) (*WorkspaceLoggingSettings, bool) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, true // no workspace context → no override
	}
	snap := workspaceLoggingPtr.Load()
	if snap == nil {
		return nil, false
	}
	entry, ok := snap.byID[workspaceID]
	if !ok {
		return nil, false
	}
	if time.Since(entry.loadedAt) > workspaceLoggingCacheTTL {
		return entry.settings, false // stale - caller should refresh
	}
	return entry.settings, true
}

// ResolveWorkspaceLoggingSettings reads from the cache and falls through to
// the DB on a miss. Safe to call from the hot path: only the very first call
// per workspace (or a call past the TTL) actually touches the DB; everything
// else is an atomic map read. Concurrent first-callers for the same workspace
// share a sync.Once so the DB sees one query at most.
func ResolveWorkspaceLoggingSettings(ctx context.Context, workspaceID string) (*WorkspaceLoggingSettings, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, nil
	}
	if settings, fresh := LookupWorkspaceLoggingSettings(workspaceID); fresh {
		return settings, nil
	}
	// Coalesce concurrent first-loads for the same workspace.
	onceVal, _ := workspaceLoggingLoad.LoadOrStore(workspaceID, &sync.Once{})
	once := onceVal.(*sync.Once)
	var loadErr error
	once.Do(func() {
		storePtr := workspaceLoggingStore.Load()
		if storePtr == nil {
			return
		}
		store := *storePtr
		settings, err := store.GetWorkspaceLoggingSettings(ctx, workspaceID)
		if err != nil {
			loadErr = err
			// Drop the once so a follow-up call can retry - leaving a
			// failed-once in place would permanently mask the override.
			workspaceLoggingLoad.Delete(workspaceID)
			return
		}
		writeWorkspaceLoggingEntry(workspaceID, settings)
	})
	if loadErr != nil {
		return nil, loadErr
	}
	if settings, fresh := LookupWorkspaceLoggingSettings(workspaceID); fresh {
		return settings, nil
	}
	return nil, nil
}

// InvalidateWorkspaceLoggingSettings is called by the upsert/delete handlers
// to force the next reader to reload from the DB. We blow away the once for
// this workspace and remove the cache entry; the next ResolveWorkspaceLoggingSettings
// call will re-query.
func InvalidateWorkspaceLoggingSettings(workspaceID string) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return
	}
	workspaceLoggingLoad.Delete(workspaceID)
	snap := workspaceLoggingPtr.Load()
	if snap == nil {
		return
	}
	if _, ok := snap.byID[workspaceID]; !ok {
		return
	}
	next := &workspaceLoggingSnapshot{byID: make(map[string]*workspaceLoggingEntry, len(snap.byID))}
	for id, entry := range snap.byID {
		if id == workspaceID {
			continue
		}
		next.byID[id] = entry
	}
	workspaceLoggingPtr.Store(next)
}

// writeWorkspaceLoggingEntry performs a copy-on-write update of the snapshot
// map. settings==nil is a valid value - it means "we checked the DB and there
// is no override for this workspace", which the hot path can still cache to
// avoid repeated misses.
func writeWorkspaceLoggingEntry(workspaceID string, settings *WorkspaceLoggingSettings) {
	for {
		old := workspaceLoggingPtr.Load()
		var oldMap map[string]*workspaceLoggingEntry
		if old != nil {
			oldMap = old.byID
		}
		next := &workspaceLoggingSnapshot{byID: make(map[string]*workspaceLoggingEntry, len(oldMap)+1)}
		for id, entry := range oldMap {
			next.byID[id] = entry
		}
		next.byID[workspaceID] = &workspaceLoggingEntry{
			settings: settings,
			loadedAt: time.Now(),
		}
		if workspaceLoggingPtr.CompareAndSwap(old, next) {
			return
		}
	}
}
