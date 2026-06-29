package semanticcache

// Direct-gate L1 cache.
//
// The direct gate (performGuardrailAwareDirectSearch) resolves an exact-hash
// cache hit with a pure equality query against the remote vector store:
//
//	{tenant_id, cache_key, original_request_hash, params_hash,
//	 guardrail_fingerprint, from_deepintshield_semantic_cache_plugin, provider?, model?}
//
// That set uniquely identifies at most one stored row, and the row is immutable
// for the life of its TTL. So it is a textbook read-through L1: the same key
// always maps to the same SearchResult until the backing row is evicted/TTL'd,
// and any guardrail-policy change rotates `guardrail_fingerprint` (hence the
// key), so a stale ALLOW can never be served across a policy edit.
//
// Latency: a remote GetAll round-trip is ~150–200 ms; an L1 hit is one
// RWMutex.RLock + map read (~80 ns). On a burst of identical requests
// (templated chat, retry storms, the exact-cache repeat loop) only the first
// store-hit per key pays the RTT - every identical repeat serves from L1.
//
// Isolation: the key is derived from the fully-qualified filter set, which
// includes tenant_id and (via cache_key) the workspace scope, so there is no
// cross-tenant / cross-workspace / cross-policy bleed - the same guarantees the
// remote query already enforces, reproduced byte-for-byte in the key.
//
// ZDR / zero-retention: L1 only ever holds rows that already live in the
// durable vector store, and population is skipped for no-store requests
// (CacheNoStoreKey). A zero-data-retention request writes nothing to the store
// and is never populated here, so its content never lands in-process.
//
// Memory is bounded by maxEntries with nearest-expiry eviction (mirrors the
// embeddingCache idiom); expired entries are swept by background maintenance.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security/framework/vectorstore"
)

const (
	defaultDirectL1Size = 10000
	defaultDirectL1TTL  = 5 * time.Minute
)

// newDirectL1CacheFromEnv builds the L1 cache with operator-tunable knobs,
// keeping it inert when explicitly disabled. Defaults are on - the L1 is a pure
// read-through accelerator with no behavioural change, so it is safe by default.
//
//	DEEPINTSHIELD_SEMCACHE_DIRECT_L1_ENABLED      "false"/"0" → disabled (nil)
//	DEEPINTSHIELD_SEMCACHE_DIRECT_L1_MAX_ENTRIES  int, default 10000
//	DEEPINTSHIELD_SEMCACHE_DIRECT_L1_TTL_SECONDS  int, default 300
func newDirectL1CacheFromEnv() *directL1Cache {
	if v := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_SEMCACHE_DIRECT_L1_ENABLED")); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil && !enabled {
			return nil
		}
	}
	maxEntries := defaultDirectL1Size
	if v := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_SEMCACHE_DIRECT_L1_MAX_ENTRIES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxEntries = n
		}
	}
	ttl := defaultDirectL1TTL
	if v := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_SEMCACHE_DIRECT_L1_TTL_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = time.Duration(n) * time.Second
		}
	}
	return newDirectL1Cache(maxEntries, ttl)
}

type directL1Entry struct {
	result    vectorstore.SearchResult
	expiresAt time.Time
}

type directL1Cache struct {
	mu         sync.RWMutex
	entries    map[string]*directL1Entry
	maxEntries int
	ttl        time.Duration
}

func newDirectL1Cache(maxEntries int, ttl time.Duration) *directL1Cache {
	if maxEntries <= 0 {
		maxEntries = defaultDirectL1Size
	}
	if ttl <= 0 {
		ttl = defaultDirectL1TTL
	}
	return &directL1Cache{
		entries:    make(map[string]*directL1Entry, 256),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// directL1Key hashes the namespace + stream flag + the full ordered filter set
// into a stable cache key. The filter order is fixed by the single call site in
// performGuardrailAwareDirectSearch, so the key is deterministic; including the
// stream flag keeps the streaming / non-streaming select-field variants apart.
func directL1Key(namespace string, stream bool, filters []vectorstore.Query) string {
	h := sha256.New()
	h.Write([]byte(namespace))
	h.Write([]byte{0})
	if stream {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	for _, q := range filters {
		h.Write([]byte(q.Field))
		h.Write([]byte{0})
		h.Write([]byte(directL1ValueString(q.Value)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// directL1ValueString renders a filter value deterministically. The direct-gate
// filters only ever carry string / bool values, but we handle the common scalar
// shapes defensively so a future filter can't silently collide.
func directL1ValueString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return ""
	}
}

// lookup returns the cached result for key, or ok=false on a miss or an expired
// entry (lazily ignored; the background sweep reclaims it).
func (c *directL1Cache) lookup(key string) (vectorstore.SearchResult, bool) {
	if c == nil || key == "" {
		return vectorstore.SearchResult{}, false
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return vectorstore.SearchResult{}, false
	}
	return cloneSearchResult(entry.result), true
}

// store inserts result under key with the cache TTL, evicting the entry nearest
// expiry when at capacity (mirrors embeddingCache's oldest-createdAt eviction).
func (c *directL1Cache) store(key string, result vectorstore.SearchResult) {
	if c == nil || key == "" {
		return
	}
	cached := cloneSearchResult(result)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		var oldestKey string
		var oldestAt time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.expiresAt.Before(oldestAt) {
				oldestKey, oldestAt = k, e.expiresAt
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &directL1Entry{result: cached, expiresAt: time.Now().Add(c.ttl)}
}

// purgeExpired drops every expired entry. Safe to call from the background
// maintenance loop - deleting during a builtin-map range is permitted (this is
// not a theine cache, so there is no Range+Delete self-deadlock to avoid).
func (c *directL1Cache) purgeExpired() {
	if c == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

// cloneSearchResult shallow-copies the result and its Properties map so cached
// rows are never mutated in place by a downstream reader (the property values
// are immutable scalars / JSON strings, so a top-level copy is sufficient).
func cloneSearchResult(in vectorstore.SearchResult) vectorstore.SearchResult {
	out := vectorstore.SearchResult{ID: in.ID, Score: in.Score}
	if in.Properties != nil {
		props := make(map[string]interface{}, len(in.Properties))
		for k, v := range in.Properties {
			props[k] = v
		}
		out.Properties = props
	}
	return out
}
