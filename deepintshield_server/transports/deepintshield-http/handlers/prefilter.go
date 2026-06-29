package handlers

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// PrefilterMiddleware drops obvious bad traffic before the plugin pipeline
// or any plugin allocation can touch it. Runs at the outermost layer (after
// CORS / decompression, before the router) so a rejected request costs
// only a few microseconds - no plugin bootstrap, no plugin state, no log
// emission.
//
// What it rejects (each toggleable via env):
//
//   1. Oversize bodies (> MaxRequestBodySizeMB * 1.5)        413
//   2. Malformed JSON on /v1/* endpoints                     400
//   3. Banned User-Agent substrings (scanners, abusers)      403
//   4. Burst RPS from a single IP (token bucket per IP)      429
//   5. Path containing obvious injection markers             400
//
// This is the userland version of what eBPF would do at the kernel. The
// eBPF version (see prefilter_ebpf.go behind the `ebpf_prefilter` build
// tag) does the same checks pre-Go and drops malicious packets without
// even allocating a goroutine. Use it on Linux for the highest-RPS
// gateways; the userland version covers macOS/Windows dev + every
// deployment that hasn't enabled the kernel module.

// PrefilterConfig is built once at startup. Env-driven so operators can
// tune without a config-file change.
type PrefilterConfig struct {
	Enabled              bool
	MaxBodyBytes         int      // hard ceiling, after which we 413
	BannedUserAgents     []string // case-insensitive substrings
	BurstRatePerIP       int      // requests per BurstWindow per IP
	BurstWindow          time.Duration
	JSONFastValidatePath string // only validate JSON when path startsWith this; "" disables
}

// LoadPrefilterConfig reads env overrides. All keys are optional; defaults
// are conservative and never block legitimate traffic.
func LoadPrefilterConfig(maxBodyBytesFromHTTPConfig int) PrefilterConfig {
	cfg := PrefilterConfig{
		Enabled:              !envBoolPrefilter("DEEPINTSHIELD_DISABLE_PREFILTER", false),
		MaxBodyBytes:         maxBodyBytesFromHTTPConfig + maxBodyBytesFromHTTPConfig/2, // 1.5x as the absolute cutoff
		BannedUserAgents:     splitCSV(os.Getenv("DEEPINTSHIELD_PREFILTER_BAN_UA")),
		BurstRatePerIP:       envIntPrefilter("DEEPINTSHIELD_PREFILTER_RPS_PER_IP", 0), // 0 = disabled
		BurstWindow:          time.Second,
		JSONFastValidatePath: "/v1/",
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 256 * 1024 * 1024 // 256 MB ceiling when not configured
	}
	return cfg
}

// PrefilterMiddleware returns the fasthttp middleware. Holds a per-process
// rate limiter + counters so observability can report drop rates.
func PrefilterMiddleware(cfg PrefilterConfig) schemas.DeepIntShieldHTTPMiddleware {
	if !cfg.Enabled {
		return func(next fasthttp.RequestHandler) fasthttp.RequestHandler { return next }
	}
	limiter := newIPBurstLimiter(cfg.BurstRatePerIP, cfg.BurstWindow)
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			// Health checks always pass - even at saturation we don't want
			// the orchestrator to mark us unhealthy.
			path := string(ctx.Path())
			if path == "/health" || path == "/healthz" || path == "/ready" {
				next(ctx)
				return
			}

			// 1) Oversize bodies. fasthttp's own MaxRequestBodySize gives a
			// 413, but ours fires earlier (on Content-Length header) so we
			// don't even read the body into memory.
			if cl := ctx.Request.Header.ContentLength(); cl > cfg.MaxBodyBytes {
				prefilterDropped.Add(1)
				ctx.SetStatusCode(fasthttp.StatusRequestEntityTooLarge)
				ctx.SetBodyString(`{"error":"request body exceeds maximum allowed size"}`)
				ctx.SetContentType("application/json")
				return
			}

			// 2) Banned User-Agent. Cheap substring scan over the UA header.
			if len(cfg.BannedUserAgents) > 0 {
				ua := bytes.ToLower(ctx.Request.Header.UserAgent())
				for _, banned := range cfg.BannedUserAgents {
					if bytes.Contains(ua, []byte(banned)) {
						prefilterDropped.Add(1)
						ctx.SetStatusCode(fasthttp.StatusForbidden)
						ctx.SetBodyString(`{"error":"forbidden user agent"}`)
						ctx.SetContentType("application/json")
						return
					}
				}
			}

			// 3) Path-level injection markers - rare but catches scanners
			// probing for /v1/../etc/passwd, /v1/<script>, etc.
			if containsPathInjection(path) {
				prefilterDropped.Add(1)
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				ctx.SetBodyString(`{"error":"malformed path"}`)
				ctx.SetContentType("application/json")
				return
			}

			// 4) Per-IP burst limit. Only enabled when BurstRatePerIP > 0.
			if cfg.BurstRatePerIP > 0 {
				ip := clientIP(ctx)
				if !limiter.allow(ip) {
					prefilterDropped.Add(1)
					ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
					ctx.Response.Header.Set("Retry-After", "1")
					ctx.SetBodyString(`{"error":"rate limit exceeded"}`)
					ctx.SetContentType("application/json")
					return
				}
			}

			// 5) Cheap JSON well-formedness check on /v1/* - catches obvious
			// truncated/garbled requests before any plugin allocates state.
			// We deliberately do NOT do a full parse; we only check that the
			// first non-whitespace byte is `{` or `[` and the last is the
			// matching close. Real parsing still happens downstream.
			if cfg.JSONFastValidatePath != "" && strings.HasPrefix(path, cfg.JSONFastValidatePath) {
				if !looksLikeJSON(ctx.Request.Body()) && len(ctx.Request.Body()) > 0 {
					prefilterDropped.Add(1)
					ctx.SetStatusCode(fasthttp.StatusBadRequest)
					ctx.SetBodyString(`{"error":"request body is not valid JSON"}`)
					ctx.SetContentType("application/json")
					return
				}
			}

			prefilterPassed.Add(1)
			next(ctx)
		}
	}
}

// PrefilterStats exposes drop / pass counters for /metrics. Wire as needed.
var (
	prefilterDropped atomic.Uint64
	prefilterPassed  atomic.Uint64
)

// PrefilterStats returns a snapshot of counters since process start.
func PrefilterStats() (dropped, passed uint64) {
	return prefilterDropped.Load(), prefilterPassed.Load()
}

// ─── helpers ────────────────────────────────────────────────────────────

func looksLikeJSON(b []byte) bool {
	// Skip leading whitespace.
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	if i >= len(b) {
		return false
	}
	first := b[i]
	if first != '{' && first != '[' {
		return false
	}
	// Skip trailing whitespace.
	j := len(b) - 1
	for j > i && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
		j--
	}
	last := b[j]
	if first == '{' && last != '}' {
		return false
	}
	if first == '[' && last != ']' {
		return false
	}
	return true
}

// containsPathInjection flags the obvious "I'm scanning for vulns" path
// shapes. Tight allowlist - false positives here would break legitimate
// API paths.
func containsPathInjection(path string) bool {
	lower := strings.ToLower(path)
	for _, bad := range pathInjectionTokens {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

var pathInjectionTokens = []string{
	"/../",
	"/..%2f",
	"%2e%2e%2f",
	"<script",
	"%3cscript",
	"\x00", // null byte
	"javascript:",
}

func clientIP(ctx *fasthttp.RequestCtx) string {
	// Honor X-Forwarded-For when behind a trusted proxy. The first hop is
	// always the closest client. Falls back to TCP remote when absent.
	if xff := ctx.Request.Header.Peek("X-Forwarded-For"); len(xff) > 0 {
		first := xff
		if comma := bytes.IndexByte(xff, ','); comma >= 0 {
			first = xff[:comma]
		}
		return string(bytes.TrimSpace(first))
	}
	return ctx.RemoteIP().String()
}

// ipBurstLimiter is a sharded token bucket keyed by client IP. Lock
// contention stays low by hashing IPs into 64 shards.
type ipBurstLimiter struct {
	rate   int
	window time.Duration
	shards [64]ipBurstShard
}

type ipBurstShard struct {
	mu      sync.Mutex
	buckets map[string]*ipBurstBucket
}

type ipBurstBucket struct {
	tokens   int
	resetsAt time.Time
}

func newIPBurstLimiter(rate int, window time.Duration) *ipBurstLimiter {
	l := &ipBurstLimiter{rate: rate, window: window}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*ipBurstBucket, 256)
	}
	return l
}

func (l *ipBurstLimiter) allow(ip string) bool {
	if l == nil || l.rate <= 0 || ip == "" {
		return true
	}
	idx := fnvHashByte(ip) & 63
	sh := &l.shards[idx]
	now := time.Now()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b, ok := sh.buckets[ip]
	if !ok {
		b = &ipBurstBucket{tokens: l.rate, resetsAt: now.Add(l.window)}
		sh.buckets[ip] = b
	}
	if now.After(b.resetsAt) {
		b.tokens = l.rate
		b.resetsAt = now.Add(l.window)
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// fnvHashByte is a tiny FNV-1a over the IP string. Good enough to spread
// IPs across 64 shards without a full hash/crc32 call per request.
func fnvHashByte(s string) uint8 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return uint8(h)
}

// ─── env helpers (small, local - avoid pulling in another package) ──────

func envBoolPrefilter(name string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func envIntPrefilter(name string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.ToLower(strings.TrimSpace(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
