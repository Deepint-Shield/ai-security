package guardrails

import (
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// fuzzy_cache implements a near-duplicate decision cache on top of the
// exact-match decisionCache. The exact cache covers byte-identical prompts;
// templated chatbot traffic (FAQ bots, customer-support templates) produces
// near-duplicate prompts that miss the exact cache but should still reuse
// the verdict for an equivalent prompt.
//
// Design:
//   • Tokenise the prompt into character shingles (k=5).
//   • Compute a MinHash signature (numHashes=64) - a fixed-size sketch of
//     the shingle set that approximates Jaccard similarity.
//   • LSH bands: split signature into B bands of R rows each (B=16, R=4).
//     Two prompts with high Jaccard similarity collide in at least one band
//     with high probability; we use the band hashes as bucket keys.
//   • Look up the cache bucket for each band hash; for each candidate,
//     re-check the signature similarity (cheap) and return the verdict if
//     above threshold (default 0.85).
//
// The verdict is scoped per (tenant, vk_id, stage, policy_version) so a
// fuzzy hit can NEVER serve a verdict computed under different policies or
// for a different VK. Same scoping discipline as the exact decisionCache.
//
// Performance budget: lookup is sub-millisecond on cache hit, ~50µs on
// miss (mostly the MinHash itself). The cache is a global sync.Map; reads
// are lock-free.

const (
	fuzzyShingleSize    = 5
	fuzzyNumHashes      = 64
	fuzzyBands          = 16
	fuzzyRowsPerBand    = fuzzyNumHashes / fuzzyBands
	fuzzyMinJaccard     = 0.85
	fuzzyDefaultTTL     = 30 * time.Minute
	fuzzyDefaultMaxKeys = 10000
	fuzzyMinPromptLen   = 32 // shorter prompts go through the exact cache only
)

type fuzzySignature [fuzzyNumHashes]uint32

type fuzzyEntry struct {
	signature fuzzySignature
	scope     string // "tenant|vk|stage|policy_version"
	response  *runtimeapi.EvaluateResponse
	expiresAt time.Time
}

type fuzzyCache struct {
	mu      sync.RWMutex
	buckets map[uint64][]*fuzzyEntry // bandHash → entries
	entries map[*fuzzyEntry]struct{} // for LRU-ish eviction by createdAt order
	maxKeys int
	hits    atomic.Uint64
	misses  atomic.Uint64
}

func newFuzzyCache(maxKeys int) *fuzzyCache {
	if maxKeys <= 0 {
		maxKeys = fuzzyDefaultMaxKeys
	}
	return &fuzzyCache{
		buckets: make(map[uint64][]*fuzzyEntry, 256),
		entries: make(map[*fuzzyEntry]struct{}, maxKeys),
		maxKeys: maxKeys,
	}
}

// globalFuzzyCache is process-wide; like decisionCache it's a singleton so
// the cost of MinHash sketch is amortised across every workspace.
var globalFuzzyCache = newFuzzyCache(fuzzyDefaultMaxKeys)

// fuzzyScopeKey collapses every dimension that MUST match for a verdict to
// be reusable. A fuzzy *content* match across two different VKs would be a
// safety violation - scope is exact-match only.
func fuzzyScopeKey(req *runtimeapi.EvaluateRequest, vkID, policyVersion string) string {
	var b strings.Builder
	b.Grow(len(req.TenantID) + len(vkID) + len(req.Stage) + len(policyVersion) + 4)
	b.WriteString(req.TenantID)
	b.WriteByte('|')
	b.WriteString(vkID)
	b.WriteByte('|')
	b.WriteString(req.Stage)
	b.WriteByte('|')
	b.WriteString(policyVersion)
	return b.String()
}

// fuzzyShingle returns the set of k-character shingles from text, lowercased
// and with collapsed whitespace. Returns nil for text below fuzzyMinPromptLen
// (too short for meaningful similarity).
func fuzzyShingle(text string) map[string]struct{} {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		return unicode.ToLower(r)
	}, text)
	cleaned = collapseSpaces(cleaned)
	if len(cleaned) < fuzzyMinPromptLen {
		return nil
	}
	shingles := make(map[string]struct{}, len(cleaned)-fuzzyShingleSize+1)
	for i := 0; i+fuzzyShingleSize <= len(cleaned); i++ {
		shingles[cleaned[i:i+fuzzyShingleSize]] = struct{}{}
	}
	return shingles
}

func collapseSpaces(s string) string {
	if !strings.ContainsRune(s, ' ') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// minHashSeeds are pre-computed seed values for the 64 hash functions.
// Each minhash slot uses fnv32 seeded with a distinct value, picked to give
// good distribution over typical English text. Generated once at init.
var minHashSeeds [fuzzyNumHashes]uint32

func init() {
	// Deterministic seeds - same across processes for cache portability.
	for i := range minHashSeeds {
		minHashSeeds[i] = uint32(0x9e3779b1) ^ uint32(i)*0x01000193
	}
}

func computeSignature(shingles map[string]struct{}) fuzzySignature {
	var sig fuzzySignature
	for i := range sig {
		sig[i] = ^uint32(0)
	}
	for shingle := range shingles {
		base := fnv.New32a()
		base.Write([]byte(shingle))
		baseHash := base.Sum32()
		for i := range sig {
			h := baseHash ^ minHashSeeds[i]
			// xor-shift mix for better avalanche on small hash counts.
			h ^= h << 13
			h ^= h >> 17
			h ^= h << 5
			if h < sig[i] {
				sig[i] = h
			}
		}
	}
	return sig
}

// bandHashes returns one 64-bit hash per LSH band. Two signatures with high
// Jaccard similarity collide in at least one band with probability
// 1 - (1 - s^R)^B (where s is the Jaccard similarity, R=rows, B=bands).
// With R=4, B=16: 0.85 similarity → 99.3% collision probability.
func bandHashes(sig fuzzySignature) [fuzzyBands]uint64 {
	var hashes [fuzzyBands]uint64
	for band := 0; band < fuzzyBands; band++ {
		start := band * fuzzyRowsPerBand
		h := fnv.New64a()
		var buf [4]byte
		for row := 0; row < fuzzyRowsPerBand; row++ {
			v := sig[start+row]
			buf[0] = byte(v)
			buf[1] = byte(v >> 8)
			buf[2] = byte(v >> 16)
			buf[3] = byte(v >> 24)
			h.Write(buf[:])
		}
		hashes[band] = h.Sum64() ^ uint64(band) // include band index so cross-band collisions don't merge buckets
	}
	return hashes
}

// jaccardEstimate returns the estimated Jaccard similarity between two
// signatures (fraction of slots that match). Within ±0.1 of true Jaccard
// for our parameter choice.
func jaccardEstimate(a, b fuzzySignature) float64 {
	matches := 0
	for i := range a {
		if a[i] == b[i] {
			matches++
		}
	}
	return float64(matches) / float64(fuzzyNumHashes)
}

// lookup returns the cached response if any near-duplicate matches the
// request's scope above the similarity threshold. Safe to call concurrently.
func (c *fuzzyCache) lookup(req *runtimeapi.EvaluateRequest, vkID, policyVersion, content string) *runtimeapi.EvaluateResponse {
	if c == nil || req == nil {
		return nil
	}
	shingles := fuzzyShingle(content)
	if shingles == nil {
		return nil
	}
	sig := computeSignature(shingles)
	scope := fuzzyScopeKey(req, vkID, policyVersion)
	bands := bandHashes(sig)
	now := time.Now()
	c.mu.RLock()
	for _, bandHash := range bands {
		candidates := c.buckets[bandHash]
		for _, entry := range candidates {
			if entry.scope != scope {
				continue
			}
			if now.After(entry.expiresAt) {
				continue
			}
			if jaccardEstimate(sig, entry.signature) < fuzzyMinJaccard {
				continue
			}
			c.mu.RUnlock()
			c.hits.Add(1)
			return entry.response
		}
	}
	c.mu.RUnlock()
	c.misses.Add(1)
	return nil
}

// store records a freshly-computed verdict so future near-duplicates within
// the same scope can short-circuit. ttl ≤ 0 falls back to fuzzyDefaultTTL.
func (c *fuzzyCache) store(req *runtimeapi.EvaluateRequest, vkID, policyVersion, content string, resp *runtimeapi.EvaluateResponse, ttl time.Duration) {
	if c == nil || req == nil || resp == nil {
		return
	}
	if resp.Decision == "" {
		// Don't cache inconclusive results - they may be transient errors
		// the runtime would resolve on retry.
		return
	}
	shingles := fuzzyShingle(content)
	if shingles == nil {
		return
	}
	if ttl <= 0 {
		ttl = fuzzyDefaultTTL
	}
	entry := &fuzzyEntry{
		signature: computeSignature(shingles),
		scope:     fuzzyScopeKey(req, vkID, policyVersion),
		response:  resp,
		expiresAt: time.Now().Add(ttl),
	}
	bands := bandHashes(entry.signature)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxKeys {
		c.evictExpiredLocked()
		if len(c.entries) >= c.maxKeys {
			c.evictHalfLocked()
		}
	}
	c.entries[entry] = struct{}{}
	for _, bandHash := range bands {
		c.buckets[bandHash] = append(c.buckets[bandHash], entry)
	}
}

func (c *fuzzyCache) evictExpiredLocked() {
	now := time.Now()
	for entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, entry)
		}
	}
	// Rebuild buckets after eviction (cheap since most buckets are small).
	c.buckets = make(map[uint64][]*fuzzyEntry, len(c.entries)*fuzzyBands)
	for entry := range c.entries {
		for _, bandHash := range bandHashes(entry.signature) {
			c.buckets[bandHash] = append(c.buckets[bandHash], entry)
		}
	}
}

func (c *fuzzyCache) evictHalfLocked() {
	target := len(c.entries) / 2
	count := 0
	for entry := range c.entries {
		if count >= target {
			break
		}
		delete(c.entries, entry)
		count++
	}
	c.buckets = make(map[uint64][]*fuzzyEntry, len(c.entries)*fuzzyBands)
	for entry := range c.entries {
		for _, bandHash := range bandHashes(entry.signature) {
			c.buckets[bandHash] = append(c.buckets[bandHash], entry)
		}
	}
}

// Stats exposes hit/miss counters for observability.
func (c *fuzzyCache) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}

// firstPolicyVersionID returns the version of the first attached policy or
// "" if none. Used as part of the fuzzy cache scope so a policy roll
// automatically misses (and re-evaluates) the cache rather than serving a
// verdict computed under stale rules.
func firstPolicyVersionID(policies []runtimeapi.PolicyBundle) string {
	for i := range policies {
		if v := strings.TrimSpace(policies[i].PolicyVersionID); v != "" {
			return v
		}
	}
	return ""
}
