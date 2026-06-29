package guardrails

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// decisionCacheTTL is how long a guard decision stays valid for an
// identical (tenant, stage, policy-set, input) tuple. 10 minutes - the
// key includes the policy_version_id, so a policy edit invalidates only
// that policy's entries via the changed version ID, NOT via TTL. The
// only thing TTL guards against is content-side staleness (e.g. an
// operator hot-edits a regex card without bumping the version), which
// is rare and already explicit in the audit. 60 s used to be the value
// here, picked to mirror the auth cache - but the auth cache decision
// is much faster to recompute (one DB hop), while a detector-batch
// re-run costs 200–2000 ms. Raising TTL to 10 minutes turns repeat /
// templated prompt traffic into a sub-ms block, which is the dominant
// pattern on chatbot deployments.
const decisionCacheTTL = 10 * time.Minute

// decisionCacheCap caps the in-memory entry count. Sized for scale: a
// busy gateway tenant serving 100 RPS with a 10-minute TTL needs room
// for ~60k entries before eviction kicks in. 65 536 fits in <100 MB on
// the heap (each entry is a small struct + the EvaluateResponse pointer)
// and keeps hit-rate high across the full TTL window instead of churning
// at the previous 4 096 ceiling. The eviction strategy is the same cheap
// "drop expired then drop half" pattern used by the auth cache
// (see handlers/auth_cache.go).
const decisionCacheCap = 65536

// decisionCacheEntry stores a serialised guard decision keyed by the
// content hash. We keep the runtime response intact so callers can
// short-circuit the entire RPC (network + JSON encode + JSON decode +
// runtime CPU) and the per-stage persistence path with one in-memory
// hit.
type decisionCacheEntry struct {
	resp    *runtimeapi.EvaluateResponse
	validAt time.Time
}

// decisionCache is the global in-process cache for guard decisions.
// Concurrency: a single RWMutex covers the map; cache hits are read-only
// and lock-free for parallel callers, writes are O(1).
type decisionCache struct {
	mu      sync.RWMutex
	entries map[string]decisionCacheEntry
}

var globalDecisionCache = &decisionCache{
	entries: make(map[string]decisionCacheEntry, 256),
}

// decisionCacheKey produces a stable key from the request shape that
// affects the decision: tenant + stage + the set of policy IDs the
// runtime will run + the actual content. We hash the input rather than
// store it raw so the cache doesn't retain prompt content beyond the
// validity window.
//
// Excluded from the key on purpose: requestID (changes per request),
// metadata (request-specific, doesn't affect the verdict), actor.IP
// (changes per request, doesn't affect verdict).
func decisionCacheKey(req *runtimeapi.EvaluateRequest) string {
	if req == nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(req.TenantID))
	h.Write([]byte{'|'})
	h.Write([]byte(req.Stage))
	h.Write([]byte{'|'})
	for i := range req.Policies {
		// Include both PolicyID and PolicyVersionID so a policy roll
		// invalidates the cache for that policy without flushing the
		// entire tenant.
		h.Write([]byte(req.Policies[i].PolicyID))
		h.Write([]byte{':'})
		h.Write([]byte(req.Policies[i].PolicyVersionID))
		h.Write([]byte{','})
	}
	h.Write([]byte{'|'})
	h.Write([]byte(req.Content.Input))
	h.Write([]byte{'|'})
	h.Write([]byte(req.Content.Output))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *decisionCache) get(key string) (*runtimeapi.EvaluateResponse, bool) {
	if key == "" {
		return nil, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Since(entry.validAt) > decisionCacheTTL {
		return nil, false
	}
	return entry.resp, true
}

func (c *decisionCache) put(key string, resp *runtimeapi.EvaluateResponse) {
	if key == "" || resp == nil {
		return
	}
	// Don't cache inconclusive / failed evaluations - they may be
	// transient and should be retried by the runtime.
	if resp.Decision == "" {
		return
	}
	c.mu.Lock()
	if len(c.entries) >= decisionCacheCap {
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.validAt) > decisionCacheTTL {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= decisionCacheCap {
			i := 0
			half := len(c.entries) / 2
			for k := range c.entries {
				if i >= half {
					break
				}
				delete(c.entries, k)
				i++
			}
		}
	}
	c.entries[key] = decisionCacheEntry{resp: resp, validAt: time.Now()}
	c.mu.Unlock()
}
