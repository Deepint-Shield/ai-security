package handlers

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// Auth rate limiting - per-IP token bucket guarding the credentialed
// session endpoints (login, signup, password resets, OAuth callbacks,
// email verification). Without this, the gateway would accept unbounded
// credential-stuffing or token-replay attempts.
//
// Numbers are intentionally permissive - legitimate operators who fat-
// finger their password or refresh during OAuth dance shouldn't get
// throttled, but a script firing thousands of attempts will. Tune via
// env if you need stricter or looser caps.
//
// Implementation choice: process-local map of buckets. Multi-replica
// deployments will see one bucket per pod, so the effective rate is N×
// the per-pod limit. That's acceptable because credential stuffing also
// scales across attacker IPs; the goal here is to make brute-forcing a
// single account from a single IP unviable, not to perfectly cap
// aggregate auth volume.

const (
	// Refill rate - tokens regenerated per second. 0.5 tokens/s = 30/min
	// sustained, which is plenty for a real human + OAuth retry loop.
	authBucketRefillPerSec = 0.5
	// Burst capacity - initial token count + cap. Allows quick bursts
	// (login → verify-email → re-login) without throttling.
	authBucketBurst = 10
	// Idle eviction - buckets unused for this long are GC'd from the
	// map so a long-lived gateway doesn't grow the map unbounded.
	authBucketIdle = 1 * time.Hour
)

type authBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

// authRateLimiter is the package-level singleton. Goroutine-safe via a
// single mutex - acquired only on the auth path (low QPS), so contention
// is a non-issue.
var (
	authBuckets   = make(map[string]*authBucket)
	authBucketsMu sync.Mutex
	authJanitor   sync.Once
)

// authClientIP extracts the request's effective client IP. Honors
// X-Forwarded-For (set by trusted proxies) but falls back to the
// transport remote addr. Strips brackets/port from IPv6 forms.
func authClientIP(ctx *fasthttp.RequestCtx) string {
	if h := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-For"))); h != "" {
		// Left-most IP is the original client per RFC 7239
		if idx := strings.IndexByte(h, ','); idx > 0 {
			h = strings.TrimSpace(h[:idx])
		}
		if h != "" {
			return h
		}
	}
	if h := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Real-IP"))); h != "" {
		return h
	}
	addr := ctx.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// authAllowRequest performs a leaky-bucket check for the given IP and
// returns true when the request is allowed. False means the caller
// should respond 429.
func authAllowRequest(ip string) bool {
	if ip == "" {
		// Couldn't identify the caller - fail-open so legitimate traffic
		// behind a misconfigured proxy isn't blackholed. The downstream
		// auth check will still enforce credentials.
		return true
	}
	now := time.Now()
	authBucketsMu.Lock()
	defer authBucketsMu.Unlock()

	b, ok := authBuckets[ip]
	if !ok {
		b = &authBucket{tokens: authBucketBurst, updated: now}
		authBuckets[ip] = b
		startAuthBucketJanitor()
	}
	// Refill since last touch.
	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * authBucketRefillPerSec
		if b.tokens > authBucketBurst {
			b.tokens = authBucketBurst
		}
		b.updated = now
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// startAuthBucketJanitor runs once per process to evict idle buckets so
// the map doesn't grow forever as new IPs touch the auth path. Called
// under authBucketsMu so the sync.Once captures the right moment.
func startAuthBucketJanitor() {
	authJanitor.Do(func() {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				cutoff := time.Now().Add(-authBucketIdle)
				authBucketsMu.Lock()
				for ip, b := range authBuckets {
					if b.lastSeen.Before(cutoff) {
						delete(authBuckets, ip)
					}
				}
				authBucketsMu.Unlock()
			}
		}()
	})
}

// authRateLimit wraps a session-route handler with per-IP throttling.
// Drop-in replacement for the handler - when the bucket is empty, the
// caller sees a 429 instead of the underlying handler running.
func authRateLimit(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !authAllowRequest(authClientIP(ctx)) {
			SendError(ctx, fasthttp.StatusTooManyRequests, "Too many auth attempts from this address. Wait a moment and try again.")
			return
		}
		next(ctx)
	}
}
