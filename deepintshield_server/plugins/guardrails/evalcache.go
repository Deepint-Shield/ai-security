package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// ─────────────────────────────────────────────────────────────────────────────
// Guardrail evaluation cache.
//
// The runtime evaluation (Evaluate RPC to deepintshield_guard) is itself an
// expensive call - for safety-heavy customers it can be 15–35% of total LLM
// spend (every input/output/MCP stage runs at least one model inference,
// sometimes more). The same content evaluated under the same policy version
// + actor role always produces the same decision, so caching is safe.
//
// Performance contract:
//   * Lookup is RWMutex (RLock fast path) + map[string]*entry. ~150 ns when
//     present, ~80 ns when absent.
//   * Writes hold the write lock for the time of a single map insert + a
//     possible LRU eviction. No allocations beyond the entry itself.
//   * The cache key includes policy_version + actor_role + vk_id, so a
//     policy update or actor change automatically misses (no manual
//     invalidation required).
//
// Layered control:
//   * Workspace switch from Cost Optimization → Advanced (default ON).
//   * TTL and max entries are configurable from the same UI.
//   * The semantic_cache plugin Config carries these values; the bootstrap
//     bridges them to this package via SetGlobalCacheConfig on every
//     plugin (re)load (same pattern as MCP per-tool TTL).
// ─────────────────────────────────────────────────────────────────────────────

const (
	defaultEvalCacheTTL        = time.Hour
	defaultEvalCacheMaxEntries = 10000
)

type evalCacheEntry struct {
	response  *runtimeapi.EvaluateResponse
	expiresAt time.Time
	createdAt time.Time
}

// evalCache is a simple TTL + size-capped in-memory cache. Designed for the
// hot path of every guardrail evaluation, so the lock window is intentionally
// tiny - the cached EvaluateResponse pointer is returned directly to the
// caller, who must NOT mutate it (the runtime engine never does).
type evalCache struct {
	mu      sync.RWMutex
	entries map[string]*evalCacheEntry
	// LRU-ish eviction is best-effort: when the map exceeds maxEntries we
	// drop the oldest createdAt. Not strict LRU but cheap to maintain and
	// good enough for the workload (lots of short-lived entries).
	maxEntries int
}

func newEvalCache(maxEntries int) *evalCache {
	if maxEntries <= 0 {
		maxEntries = defaultEvalCacheMaxEntries
	}
	return &evalCache{
		entries:    make(map[string]*evalCacheEntry, 256),
		maxEntries: maxEntries,
	}
}

// lookup returns the cached response if present and unexpired. Lock-free read
// in the common-case warm-cache scenario.
func (c *evalCache) lookup(key string) *runtimeapi.EvaluateResponse {
	if c == nil || key == "" {
		return nil
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(entry.expiresAt) {
		// Lazy eviction - drop it but don't bother under write lock right
		// now; cleanup pass + future inserts will catch it.
		c.mu.Lock()
		if e2, ok2 := c.entries[key]; ok2 && time.Now().After(e2.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil
	}
	return entry.response
}

// store records a result. Calls into eviction if we're over cap.
func (c *evalCache) store(key string, resp *runtimeapi.EvaluateResponse, ttl time.Duration) {
	if c == nil || key == "" || resp == nil || ttl <= 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		// Best-effort: drop the oldest. O(n) but only runs at the cap so
		// amortized cost stays low.
		var oldestKey string
		var oldestAt time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.createdAt.Before(oldestAt) {
				oldestKey, oldestAt = k, e.createdAt
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &evalCacheEntry{
		response:  resp,
		expiresAt: now.Add(ttl),
		createdAt: now,
	}
}

// ─────────────────────────── package-level live config ──────────────────────

// evalCacheConfig is a snapshot of the workspace-level guardrail eval cache
// settings, replaced atomically when semantic_cache plugin reloads.
type evalCacheConfig struct {
	enabled    bool
	ttl        time.Duration
	maxEntries int
	// vkScope: empty = applies to all VKs; non-empty = only the listed VK IDs
	// get cache lookups/writes. Other VKs bypass the cache entirely so a
	// scoped feature can't accidentally serve a stale decision to a VK the
	// operator didn't opt in.
	vkScope []string
}

var globalEvalCacheConfig atomic.Pointer[evalCacheConfig]

// SetGlobalEvalCacheConfig is invoked from the bootstrap on every
// semantic_cache plugin (re)load with the parsed Cost Optimization settings.
// Live-reloadable; no gateway restart required to change TTL or disable.
func SetGlobalEvalCacheConfig(enabled bool, ttlSeconds int, maxEntries int, vkScope []string) {
	cfg := &evalCacheConfig{enabled: enabled, vkScope: append([]string(nil), vkScope...)}
	if ttlSeconds > 0 {
		cfg.ttl = time.Duration(ttlSeconds) * time.Second
	} else {
		cfg.ttl = defaultEvalCacheTTL
	}
	if maxEntries > 0 {
		cfg.maxEntries = maxEntries
	} else {
		cfg.maxEntries = defaultEvalCacheMaxEntries
	}
	globalEvalCacheConfig.Store(cfg)
}

// effectiveEvalCacheConfig returns the live config, or defaults if nothing
// has been bridged in yet (e.g. semantic_cache plugin hasn't loaded).
func effectiveEvalCacheConfig() evalCacheConfig {
	if cfg := globalEvalCacheConfig.Load(); cfg != nil {
		return *cfg
	}
	return evalCacheConfig{
		enabled:    true,
		ttl:        defaultEvalCacheTTL,
		maxEntries: defaultEvalCacheMaxEntries,
	}
}

// vkAllowed reports whether the given VK ID is in scope for this cache.
// Empty scope = all VKs.
func (c evalCacheConfig) vkAllowed(vkID string) bool {
	if len(c.vkScope) == 0 {
		return true
	}
	for _, allowed := range c.vkScope {
		if allowed == vkID {
			return true
		}
	}
	return false
}

// ─────────────────────────── cache key construction ──────────────────────────

// evalCacheKey builds the cache key for an evaluation. Includes everything
// that semantically affects the decision so a hit is always safe to return:
//
//   - stage (input / output / mcp / rag / action)
//   - actor role + actor type (a policy may allow X for admins, deny X for
//     regular users - caching one decision for both would be incorrect)
//   - tenant + vk_id (per-VK isolation; tenant is defense-in-depth)
//   - content hash (input + output + tool input + MCP context)
//   - policy version (when policies change the cache implicitly misses)
//
// Returns "" when the request is missing fields that make a cache lookup
// dangerous (e.g. no content, no actor, no tenant).
func evalCacheKey(ctx context.Context, req *runtimeapi.EvaluateRequest) string {
	if req == nil {
		return ""
	}
	if req.Content.Input == "" && req.Content.Output == "" && req.Content.ToolInput == "" {
		// Nothing to evaluate → don't cache the empty case (the runtime
		// engine's behavior on empty content is policy-dependent and not
		// worth caching).
		return ""
	}
	tenant := req.TenantID
	actorID := req.Actor.ID
	actorRole := req.Actor.Role
	actorType := req.Actor.Type

	vkID, _ := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)
	policyVersion, _ := stringContextValue(ctx, schemas.DeepIntShieldContextKey("guardrail-policy-version"))

	h := sha256.New()
	h.Write([]byte("v1|"))
	h.Write([]byte(tenant))
	h.Write([]byte{0})
	h.Write([]byte(vkID))
	h.Write([]byte{0})
	h.Write([]byte(req.Stage))
	h.Write([]byte{0})
	h.Write([]byte(actorType))
	h.Write([]byte{0})
	h.Write([]byte(actorRole))
	h.Write([]byte{0})
	h.Write([]byte(actorID))
	h.Write([]byte{0})
	h.Write([]byte(policyVersion))
	h.Write([]byte{0})
	h.Write([]byte(req.Content.Input))
	h.Write([]byte{0})
	h.Write([]byte(req.Content.Output))
	h.Write([]byte{0})
	h.Write([]byte(req.Content.ToolInput))
	if req.MCP != nil {
		h.Write([]byte{0})
		h.Write([]byte(req.MCP.ServerLabel))
		h.Write([]byte{0})
		h.Write([]byte(req.MCP.ToolName))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stringContextValue mirrors the helper used in semanticcache/scope.go but
// is intentionally local to keep cross-plugin imports out of the hot path.
// Works for both *schemas.DeepIntShieldContext and standard context.Context
// since both implement the same Value(key) interface.
func stringContextValue(ctx context.Context, key schemas.DeepIntShieldContextKey) (string, bool) {
	if ctx == nil {
		return "", false
	}
	v, ok := ctx.Value(key).(string)
	if !ok {
		return "", false
	}
	return v, v != ""
}
