package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// sessionCacheEntry stores the resolved identity from a validated session.
type sessionCacheEntry struct {
	userID   string
	userRole string
	tenantID string
	validAt  time.Time
}

// vkCacheEntry stores the resolved virtual-key identity plus a few
// pre-computed hints that let the downstream plugin chain (governance,
// guardrails, MCP) early-exit without their own per-request DB lookups.
type vkCacheEntry struct {
	vkValue      string
	tenantID     string
	workspaceID  string // pinning workspace, "" = tenant-wide
	hasGuards    bool   // any guardrail policy bound to this VK / tenant
	hasMCPConfig bool   // any MCP client referenced by this VK
	validAt      time.Time
}

// authCache is a simple TTL-based cache for session and virtual-key lookups,
// eliminating 1-2 DB round-trips on the hot path of every authenticated request.
//
// Design choices:
//   - Uses SHA-256 of token/key as map key (no plaintext secrets in memory).
//   - Fixed maximum capacity with LRU-style eviction (periodic sweep).
//   - Single global instance per gateway process is fine because the hot-path
//     read (session/VK validation) far outnumbers writes (login/VK CRUD).
//
// membershipCacheEntry stores a "user X has org membership on tenant Y"
// answer (positive or negative) so the active-scope tenant override
// avoids a DB round-trip on every dashboard request.
type membershipCacheEntry struct {
	allowed bool
	validAt time.Time
}

// workspaceCacheEntry stores the (org_id, tenant_id) tuple for a
// workspace_id so permission checks can derive the parent tenant
// without a DB load. Workspaces change rarely; a 60-s TTL is plenty.
type workspaceCacheEntry struct {
	orgID    string // governance_orgs.id (Phase 19 - top of the hierarchy)
	tenantID string // organizations.id (the tenant)
	validAt  time.Time
}

type authCache struct {
	mu          sync.RWMutex
	sessions    map[string]sessionCacheEntry
	virtualKeys map[string]vkCacheEntry
	memberships map[string]membershipCacheEntry
	workspaces  map[string]workspaceCacheEntry
	ttl         time.Duration
	maxSize     int
}

var globalAuthCache = newAuthCache(60*time.Second, 512)

func newAuthCache(ttl time.Duration, maxSize int) *authCache {
	return &authCache{
		sessions:    make(map[string]sessionCacheEntry, 64),
		virtualKeys: make(map[string]vkCacheEntry, 64),
		memberships: make(map[string]membershipCacheEntry, 64),
		workspaces:  make(map[string]workspaceCacheEntry, 64),
		ttl:         ttl,
		maxSize:     maxSize,
	}
}

func cacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// getSession returns a cached session entry if it exists and has not expired.
func (c *authCache) getSession(token string) (sessionCacheEntry, bool) {
	key := cacheKey(token)
	c.mu.RLock()
	entry, ok := c.sessions[key]
	c.mu.RUnlock()
	if !ok || time.Since(entry.validAt) > c.ttl {
		return sessionCacheEntry{}, false
	}
	return entry, true
}

// putSession stores a validated session entry.
func (c *authCache) putSession(token string, entry sessionCacheEntry) {
	key := cacheKey(token)
	entry.validAt = time.Now()
	c.mu.Lock()
	if len(c.sessions) >= c.maxSize {
		c.evictSessionsLocked()
	}
	c.sessions[key] = entry
	c.mu.Unlock()
}

// invalidateSession removes a session from the cache (e.g., on logout).
func (c *authCache) invalidateSession(token string) {
	key := cacheKey(token)
	c.mu.Lock()
	delete(c.sessions, key)
	c.mu.Unlock()
}

// getVirtualKey returns a cached VK entry if it exists and has not expired.
func (c *authCache) getVirtualKey(keyValue string) (vkCacheEntry, bool) {
	key := cacheKey(keyValue)
	c.mu.RLock()
	entry, ok := c.virtualKeys[key]
	c.mu.RUnlock()
	if !ok || time.Since(entry.validAt) > c.ttl {
		return vkCacheEntry{}, false
	}
	return entry, true
}

// putVirtualKey stores a validated VK entry.
func (c *authCache) putVirtualKey(keyValue string, entry vkCacheEntry) {
	key := cacheKey(keyValue)
	entry.validAt = time.Now()
	c.mu.Lock()
	if len(c.virtualKeys) >= c.maxSize {
		c.evictVirtualKeysLocked()
	}
	c.virtualKeys[key] = entry
	c.mu.Unlock()
}

// evictSessionsLocked removes expired entries; if still over capacity, drops
// the oldest half. Must be called with c.mu held.
func (c *authCache) evictSessionsLocked() {
	now := time.Now()
	for k, v := range c.sessions {
		if now.Sub(v.validAt) > c.ttl {
			delete(c.sessions, k)
		}
	}
	if len(c.sessions) >= c.maxSize {
		// Drop roughly half (cheapest eviction without a heap)
		i := 0
		half := len(c.sessions) / 2
		for k := range c.sessions {
			if i >= half {
				break
			}
			delete(c.sessions, k)
			i++
		}
	}
}

// evictVirtualKeysLocked mirrors evictSessionsLocked for VK entries.
func (c *authCache) evictVirtualKeysLocked() {
	now := time.Now()
	for k, v := range c.virtualKeys {
		if now.Sub(v.validAt) > c.ttl {
			delete(c.virtualKeys, k)
		}
	}
	if len(c.virtualKeys) >= c.maxSize {
		i := 0
		half := len(c.virtualKeys) / 2
		for k := range c.virtualKeys {
			if i >= half {
				break
			}
			delete(c.virtualKeys, k)
			i++
		}
	}
}

// getMembership returns a cached "user has membership on tenant" answer
// if it exists and has not expired. Used by applyActiveScopeOverride to
// avoid a DB round-trip on every dashboard request that ships the
// X-Active-Tenant-Id header.
func (c *authCache) getMembership(userID, tenantID string) (bool, bool) {
	if userID == "" || tenantID == "" {
		return false, false
	}
	key := userID + "|" + tenantID
	c.mu.RLock()
	entry, ok := c.memberships[key]
	c.mu.RUnlock()
	if !ok || time.Since(entry.validAt) > c.ttl {
		return false, false
	}
	return entry.allowed, true
}

// getWorkspaceParents returns the cached (orgID, tenantID) for a
// workspace_id. Used by CanManageWorkspaceByID to skip the workspace-row
// load when the workspace was looked up recently.
func (c *authCache) getWorkspaceParents(workspaceID string) (string, string, bool) {
	if workspaceID == "" {
		return "", "", false
	}
	c.mu.RLock()
	entry, ok := c.workspaces[workspaceID]
	c.mu.RUnlock()
	if !ok || time.Since(entry.validAt) > c.ttl {
		return "", "", false
	}
	return entry.orgID, entry.tenantID, true
}

// putWorkspaceParents records the (orgID, tenantID) for a workspace_id.
func (c *authCache) putWorkspaceParents(workspaceID, orgID, tenantID string) {
	if workspaceID == "" {
		return
	}
	c.mu.Lock()
	if len(c.workspaces) >= c.maxSize {
		now := time.Now()
		for k, v := range c.workspaces {
			if now.Sub(v.validAt) > c.ttl {
				delete(c.workspaces, k)
			}
		}
		if len(c.workspaces) >= c.maxSize {
			i := 0
			half := len(c.workspaces) / 2
			for k := range c.workspaces {
				if i >= half {
					break
				}
				delete(c.workspaces, k)
				i++
			}
		}
	}
	c.workspaces[workspaceID] = workspaceCacheEntry{
		orgID:    orgID,
		tenantID: tenantID,
		validAt:  time.Now(),
	}
	c.mu.Unlock()
}

// putMembership records a positive or negative membership answer.
func (c *authCache) putMembership(userID, tenantID string, allowed bool) {
	if userID == "" || tenantID == "" {
		return
	}
	key := userID + "|" + tenantID
	c.mu.Lock()
	if len(c.memberships) >= c.maxSize {
		// Cheap eviction: drop expired, then drop half if still full.
		now := time.Now()
		for k, v := range c.memberships {
			if now.Sub(v.validAt) > c.ttl {
				delete(c.memberships, k)
			}
		}
		if len(c.memberships) >= c.maxSize {
			i := 0
			half := len(c.memberships) / 2
			for k := range c.memberships {
				if i >= half {
					break
				}
				delete(c.memberships, k)
				i++
			}
		}
	}
	c.memberships[key] = membershipCacheEntry{allowed: allowed, validAt: time.Now()}
	c.mu.Unlock()
}
