// Package cache defines the abstraction every in-process TTL cache in
// the platform should target so individual call sites stay agnostic
// of whether the cache is a process-local map or a distributed
// backend (Redis / Memcached / a future shared L2).
//
// Why this matters for scalability: today every cache entry
// (sessions, memberships, workspaces, VKs, guard decisions) lives in
// process memory. With multiple replicas behind a load balancer, each
// pod cold-starts independently, cache invalidations don't propagate
// across pods, and total cache memory scales linearly with replica
// count. Routing the existing call sites through this interface lets
// us swap in a Redis-backed implementation later without touching
// each cache's call sites.
//
// Migration plan:
//  1. (this commit) Define the interface and a baseline in-memory
//     implementation that mirrors the existing TTL-map shape.
//  2. (follow-up) Refactor globalAuthCache / globalDecisionCache /
//     etc. to construct themselves through `cache.New(...)` and
//     consume the interface.
//  3. (follow-up) Add `cache.NewRedis(addr, opts...)` as an alternate
//     constructor; switch via env config.
//
// The interface is intentionally minimal: Get / Set with TTL,
// per-key invalidation, and a process-id signature so distributed
// implementations can ignore self-issued invalidations.
package cache

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrMiss is returned by Get when the key is absent or expired.
// Callers should treat it the same way they'd treat a cold cache -
// fall through to the source of truth and Set the result.
var ErrMiss = errors.New("cache miss")

// Cache is the universal TTL cache shape used across the gateway.
// Implementations MUST be safe for concurrent use.
type Cache interface {
	// Get returns the value stored under key, or ErrMiss when the key
	// is absent / expired. Callers should not type-assert against
	// nil - a successful Get always returns non-nil for the value
	// pointer (subject to what was previously Set).
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores value under key with the given TTL. ttl <= 0 means
	// "no expiry"; callers should still pass a sensible TTL because
	// the in-memory implementation evicts under capacity pressure
	// regardless.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes the key (idempotent). Used to invalidate after
	// the underlying entity changes (e.g. a workspace rename should
	// Delete the cached workspace lookup).
	Delete(ctx context.Context, key string) error

	// Close releases backend resources. For the in-memory backend
	// this is a no-op; for Redis it closes the pool.
	Close() error
}

// Options configure cache instantiation. Defaults are chosen to match
// the platform's existing in-memory caches so a v1 migration is a
// drop-in replacement.
type Options struct {
	// MaxEntries caps the in-memory cache size. Ignored by remote
	// backends (they manage capacity server-side). 0 = 4096.
	MaxEntries int
	// DefaultTTL is applied when Set is called with ttl <= 0.
	// 0 = 60 s, matching the platform's auth cache default.
	DefaultTTL time.Duration
	// Now is overridable for tests.
	Now func() time.Time
}

func (o *Options) applyDefaults() {
	if o.MaxEntries <= 0 {
		o.MaxEntries = 4096
	}
	if o.DefaultTTL <= 0 {
		o.DefaultTTL = 60 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// New returns the default in-memory implementation. To use a
// distributed backend, swap to NewRedis (TODO follow-up).
func New(opts Options) Cache {
	opts.applyDefaults()
	return newMemCache(opts)
}

// memCache is the baseline in-memory implementation. Mirrors the TTL
// + half-eviction strategy used by handlers/auth_cache.go so existing
// behaviour is preserved when call sites migrate.
type memCache struct {
	mu      sync.RWMutex
	entries map[string]memEntry
	opts    Options
}

type memEntry struct {
	value   []byte
	expires time.Time
}

func newMemCache(opts Options) *memCache {
	return &memCache{
		entries: make(map[string]memEntry, opts.MaxEntries/8),
		opts:    opts,
	}
}

func (m *memCache) Get(_ context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, ErrMiss
	}
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok || m.opts.Now().After(e.expires) {
		return nil, ErrMiss
	}
	// Defensive copy so callers can't mutate the cached bytes.
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out, nil
}

func (m *memCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = m.opts.DefaultTTL
	}
	m.mu.Lock()
	if len(m.entries) >= m.opts.MaxEntries {
		m.evictLocked()
	}
	stored := make([]byte, len(value))
	copy(stored, value)
	m.entries[key] = memEntry{value: stored, expires: m.opts.Now().Add(ttl)}
	m.mu.Unlock()
	return nil
}

func (m *memCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.entries, key)
	m.mu.Unlock()
	return nil
}

func (m *memCache) Close() error { return nil }

// evictLocked: drop expired entries first, then half the cache if
// still over capacity. Same pattern as the existing auth caches.
// Caller must hold m.mu.
func (m *memCache) evictLocked() {
	now := m.opts.Now()
	for k, v := range m.entries {
		if now.After(v.expires) {
			delete(m.entries, k)
		}
	}
	if len(m.entries) >= m.opts.MaxEntries {
		i := 0
		half := len(m.entries) / 2
		for k := range m.entries {
			if i >= half {
				break
			}
			delete(m.entries, k)
			i++
		}
	}
}
