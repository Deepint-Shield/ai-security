package configstore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Workspace-scoped MCP settings on the hot path.
//
// MCP tool execution gates depend on these values (timeout, agent depth,
// cache TTL) on every tool call. A DB round-trip per call would burn the
// latency we just optimised out, so resolution goes through an in-memory
// atomic snapshot identical in shape to the workspace_logging cache.

const workspaceMCPCacheTTL = 30 * time.Second

type workspaceMCPEntry struct {
	settings *WorkspaceMCPSettings // nil = no override row; defaults apply
	loadedAt time.Time
}

type workspaceMCPSnapshot struct {
	byID map[string]*workspaceMCPEntry
}

var (
	workspaceMCPPtr   atomic.Pointer[workspaceMCPSnapshot]
	workspaceMCPLoad  sync.Map // map[workspaceID]*sync.Once
	workspaceMCPStore atomic.Pointer[ConfigStore]
)

// RegisterWorkspaceMCPStore is called once at boot so the cache can resolve
// misses against the DB. The MCP plugin doesn't import configstore directly
// so we expose this as a free function.
func RegisterWorkspaceMCPStore(store ConfigStore) {
	if store == nil {
		return
	}
	workspaceMCPStore.Store(&store)
	if workspaceMCPPtr.Load() == nil {
		workspaceMCPPtr.Store(&workspaceMCPSnapshot{byID: map[string]*workspaceMCPEntry{}})
	}
}

// LookupWorkspaceMCPSettings returns the override for workspaceID from the
// in-memory cache. Returns (nil, true) when we KNOW no override exists,
// (settings, true) when an override was cached, and (nil, false) when we
// haven't loaded this workspace yet.
func LookupWorkspaceMCPSettings(workspaceID string) (*WorkspaceMCPSettings, bool) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, true
	}
	snap := workspaceMCPPtr.Load()
	if snap == nil {
		return nil, false
	}
	entry, ok := snap.byID[workspaceID]
	if !ok {
		return nil, false
	}
	if time.Since(entry.loadedAt) > workspaceMCPCacheTTL {
		return entry.settings, false
	}
	return entry.settings, true
}

// ResolveWorkspaceMCPSettings reads from the cache and falls through to the
// DB on a miss. Safe to call from the hot path: only the very first call per
// workspace (or one past the TTL) actually queries.
func ResolveWorkspaceMCPSettings(ctx context.Context, workspaceID string) (*WorkspaceMCPSettings, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, nil
	}
	if settings, fresh := LookupWorkspaceMCPSettings(workspaceID); fresh {
		return settings, nil
	}
	onceVal, _ := workspaceMCPLoad.LoadOrStore(workspaceID, &sync.Once{})
	once := onceVal.(*sync.Once)
	var loadErr error
	once.Do(func() {
		storePtr := workspaceMCPStore.Load()
		if storePtr == nil {
			return
		}
		store := *storePtr
		settings, err := store.GetWorkspaceMCPSettings(ctx, workspaceID)
		if err != nil {
			loadErr = err
			workspaceMCPLoad.Delete(workspaceID)
			return
		}
		writeWorkspaceMCPEntry(workspaceID, settings)
	})
	if loadErr != nil {
		return nil, loadErr
	}
	if settings, fresh := LookupWorkspaceMCPSettings(workspaceID); fresh {
		return settings, nil
	}
	return nil, nil
}

// InvalidateWorkspaceMCPSettings drops the cache entry so the next reader
// reloads from the DB. Called by upsert/delete handlers so admin edits
// become visible without a process restart.
func InvalidateWorkspaceMCPSettings(workspaceID string) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return
	}
	workspaceMCPLoad.Delete(workspaceID)
	snap := workspaceMCPPtr.Load()
	if snap == nil {
		return
	}
	if _, ok := snap.byID[workspaceID]; !ok {
		return
	}
	next := &workspaceMCPSnapshot{byID: make(map[string]*workspaceMCPEntry, len(snap.byID))}
	for id, entry := range snap.byID {
		if id == workspaceID {
			continue
		}
		next.byID[id] = entry
	}
	workspaceMCPPtr.Store(next)
}

func writeWorkspaceMCPEntry(workspaceID string, settings *WorkspaceMCPSettings) {
	for {
		old := workspaceMCPPtr.Load()
		var oldMap map[string]*workspaceMCPEntry
		if old != nil {
			oldMap = old.byID
		}
		next := &workspaceMCPSnapshot{byID: make(map[string]*workspaceMCPEntry, len(oldMap)+1)}
		for id, entry := range oldMap {
			next.byID[id] = entry
		}
		next.byID[workspaceID] = &workspaceMCPEntry{
			settings: settings,
			loadedAt: time.Now(),
		}
		if workspaceMCPPtr.CompareAndSwap(old, next) {
			return
		}
	}
}
