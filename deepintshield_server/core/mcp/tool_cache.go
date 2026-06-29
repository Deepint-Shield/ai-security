package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// MCPToolResultCache memoises tool-call responses for tools the
// operator has explicitly marked as deterministic. Most tools cannot
// be cached safely - `get_current_weather` returns different data
// every minute, `read_file` invalidates on filesystem change. We
// only cache where the operator has opted in via the per-tool
// `cacheable` flag (set on TableMCPClient → tools_to_execute config).
//
// Why opt-in:
//   - False positives are catastrophic (stale data leaks into LLM
//     responses, may persist via downstream caching).
//   - The set of "actually deterministic" tools is small in practice
//     (lookup tools, schema introspection, doc fetchers) - opt-in
//     captures real wins without surprising users.
//
// Cache key: SHA-256 of (server_label + tool_name + canonicalised
// arguments JSON). TTL is 60 s by default - short enough that even
// "deterministic" tools that change rarely don't serve stale data
// for a meaningful window.
//
// Capacity: 8192 entries with the same evict-half-on-pressure
// strategy as the rest of the platform's caches. Plenty for the
// typical mid-size deployment; a Redis-backed swap is the next step
// for multi-replica clusters (interface mirrors framework/cache).

const (
	mcpToolCacheTTL = 60 * time.Second
	mcpToolCacheCap = 8192
)

type mcpToolCacheEntry struct {
	result  []byte // serialised tool result (full MCP response body)
	validAt time.Time
}

// MCPToolResultCache is concurrency-safe and lock-free on hits.
type MCPToolResultCache struct {
	mu      sync.RWMutex
	entries map[string]mcpToolCacheEntry
}

// GlobalMCPToolResultCache is the process-wide singleton. Tool
// invocation paths consult it before issuing the underlying RPC.
var GlobalMCPToolResultCache = &MCPToolResultCache{entries: make(map[string]mcpToolCacheEntry, 256)}

// MCPToolCacheKey produces the cache key for a (server, tool, args)
// tuple. Args are hashed (not stored raw) so the cache doesn't retain
// arbitrary tool input beyond the validity window.
func MCPToolCacheKey(serverLabel, toolName string, argsJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(serverLabel))
	h.Write([]byte{'|'})
	h.Write([]byte(toolName))
	h.Write([]byte{'|'})
	h.Write(argsJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached tool result, or nil + false on miss /
// expiry. Callers should fall through to the underlying RPC and
// `Put` the response on success.
func (c *MCPToolResultCache) Get(key string) ([]byte, bool) {
	if key == "" {
		return nil, false
	}
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Since(e.validAt) > mcpToolCacheTTL {
		return nil, false
	}
	// Defensive copy so callers can't mutate cached bytes.
	out := make([]byte, len(e.result))
	copy(out, e.result)
	return out, true
}

// Put stores a tool result. No-op if either argument is empty.
func (c *MCPToolResultCache) Put(key string, result []byte) {
	if key == "" || len(result) == 0 {
		return
	}
	c.mu.Lock()
	if len(c.entries) >= mcpToolCacheCap {
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.validAt) > mcpToolCacheTTL {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= mcpToolCacheCap {
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
	stored := make([]byte, len(result))
	copy(stored, result)
	c.entries[key] = mcpToolCacheEntry{result: stored, validAt: time.Now()}
	c.mu.Unlock()
}

// Invalidate drops a specific entry. Used when the operator updates
// the tool's `cacheable` flag from true→false or otherwise wants to
// flush a particular cached response.
func (c *MCPToolResultCache) Invalidate(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}
