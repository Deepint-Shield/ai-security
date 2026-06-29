// L1 decision cache.
//
// Backend: github.com/Yiling-J/theine-go - a real W-TinyLFU implementation
// per the build spec ("L1 decision cache: In-process W-TinyLFU,
// high hit-ratio admission policy, nanosecond lookups").
//
// W-TinyLFU's TinyLFU admission filter beats vanilla LRU on adversarial
// scan workloads (e.g. a red-team corpus that probes a thousand unique
// tool calls in sequence won't evict the warm decisions that real
// agents are hitting). Lookup is O(1) and concurrency is sharded
// internally so the hot path doesn't contend on a single mutex.
package agentic

import (
	"sync/atomic"
	"time"

	"github.com/Yiling-J/theine-go"
)

// DecisionCache holds in-process verdicts keyed on the semantic CacheKey
// derived from the DelegationContext. TTL is bounded by the revocation
// SLA, so a cached ALLOW can never outlive the promised invalidation
// window (§2.5 of the spec).
type DecisionCache struct {
	cache  *theine.Cache[string, Decision]
	hits   atomic.Uint64
	misses atomic.Uint64
}

// NewDecisionCache returns a W-TinyLFU cache with the configured
// capacity. maxSize <= 0 disables the cache so callers can opt out.
func NewDecisionCache(maxSize int) *DecisionCache {
	if maxSize <= 0 {
		return &DecisionCache{cache: nil}
	}
	c, err := theine.NewBuilder[string, Decision](int64(maxSize)).Build()
	if err != nil {
		// Bounded by an integer cap - should never realistically fail.
		// Return a disabled cache rather than panicking on the hot path.
		return &DecisionCache{cache: nil}
	}
	return &DecisionCache{cache: c}
}

// Get returns a cached Decision if present and not expired. Misses
// increment a counter that's exposed via Stats() for the Overview
// dashboard's cache-hit tile.
func (c *DecisionCache) Get(key string) (Decision, bool) {
	if c == nil || c.cache == nil {
		return Decision{}, false
	}
	dec, ok := c.cache.Get(key)
	if !ok {
		c.misses.Add(1)
		return Decision{}, false
	}
	c.hits.Add(1)
	dec.CacheHit = true
	return dec, true
}

// Put inserts a Decision under the given TTL. The TTL upper bound MUST
// be the revocation SLA - callers compute
// min(token.exp, policy.ttl, REVOCATION_SLA) before calling Put.
//
// A zero TTL falls back to a 30 s default to make sure we never accept
// an unbounded entry by accident.
func (c *DecisionCache) Put(key string, decision Decision, ttl time.Duration) {
	if c == nil || c.cache == nil {
		return
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	// W-TinyLFU's SetWithTTL accepts a weight; every decision is weight 1
	// because the cache is sized in entries, not bytes.
	c.cache.SetWithTTL(key, decision, 1, ttl)
}

// InvalidateTenant clears every entry - wired to CAEP/SSF revocation
// pushes. theine doesn't expose a "delete by predicate" but the cache
// key includes tenant, so a full clear when tenant is unknown is the
// conservative invariant the spec calls for.
func (c *DecisionCache) InvalidateTenant(tenant string) {
	if c == nil || c.cache == nil {
		return
	}
	// Without a per-tenant index theine forces a full flush, which is
	// the conservative choice: erring on the side of more invalidation
	// is always safer than less.
	//
	// theine's Range holds a per-shard read lock across the callback while
	// Delete wants that shard's write lock, so deleting *inside* Range
	// self-deadlocks on any non-empty shard. Collect the keys under Range,
	// then delete them after Range has released its locks.
	var keys []string
	c.cache.Range(func(k string, _ Decision) bool {
		keys = append(keys, k)
		return true
	})
	for _, k := range keys {
		c.cache.Delete(k)
	}
}

// CacheStats is the JSON shape the Overview dashboard's "cache hit %"
// tile reads.
type CacheStats struct {
	Hits   uint64 `json:"hits"`
	Misses uint64 `json:"misses"`
	Size   int    `json:"size"`
}

// Stats returns a snapshot of the counters.
func (c *DecisionCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	st := CacheStats{
		Hits:   c.hits.Load(),
		Misses: c.misses.Load(),
	}
	if c.cache != nil {
		st.Size = int(c.cache.Len())
	}
	return st
}
