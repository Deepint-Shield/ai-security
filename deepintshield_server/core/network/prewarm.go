package network

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// Per-(tenant, provider) connection pre-warming.
//
// First-request latency to any external provider has three irreducible
// components: DNS resolve (5-50ms), TCP handshake (~1 RTT), TLS handshake
// (1-2 RTT). On a cold connection to OpenAI/Anthropic that's typically
// 100-300ms - and the user sees ALL of it on their first request because
// the gateway hasn't established a connection yet.
//
// Pre-warming fires a tiny HEAD/GET against each provider's base URL at
// startup. The fasthttp client we share with inference traffic establishes
// the TCP+TLS+HTTP/2 session, the resulting idle connection stays in the
// host pool, and the user's first real request reuses it - saving the
// handshake on every cold-pool fill.
//
// Re-warming runs periodically (default 10 min) to keep pools fresh
// against keepalive eviction at the provider side.

// Default base URLs for the providers we ship adapters for. Override per
// tenant via VK config; this list is the fallback when a tenant's VKs
// don't pin a custom base URL.
var DefaultProviderBaseURLs = map[string]string{
	"openai":     "https://api.openai.com",
	"anthropic":  "https://api.anthropic.com",
	"gemini":     "https://generativelanguage.googleapis.com",
	"mistral":    "https://api.mistral.ai",
	"cohere":     "https://api.cohere.com",
	"groq":       "https://api.groq.com",
	"together":   "https://api.together.xyz",
	"perplexity": "https://api.perplexity.ai",
	"xai":        "https://api.x.ai",
	"openrouter": "https://openrouter.ai",
}

// PrewarmTarget identifies one connection to warm. Tenant is recorded for
// observability only - the connection pool itself is per (Transport,
// Host:Port), not per-tenant. Listing the same Host across many tenants
// just gets dedup'd before the warm.
type PrewarmTarget struct {
	TenantID string
	Provider string // logical name: "openai", "anthropic", ...
	BaseURL  string // overrides DefaultProviderBaseURLs[Provider] when non-empty
}

// PrewarmStats is returned per call so the caller can log + emit metrics.
type PrewarmStats struct {
	Attempted   int
	Succeeded   int
	Failed      int
	TotalTime   time.Duration
	PerHostTime map[string]time.Duration
}

// PrewarmOptions tunes the run. Zero values pick sane defaults.
type PrewarmOptions struct {
	// PerRequestTimeout caps one HEAD attempt. Default: 5s.
	PerRequestTimeout time.Duration
	// Concurrency caps in-flight warm requests. Default: 16.
	Concurrency int
	// RewarmInterval, when > 0, schedules periodic re-warming on the same
	// targets. Recommended: 10 minutes. Zero disables.
	RewarmInterval time.Duration
}

// Prewarm establishes a connection to every unique Host:Port derived from
// the targets, using the inference fasthttp client (so the warmed conn
// lands in the same pool the real provider calls use). Safe to call
// concurrently with traffic.
func (f *HTTPClientFactory) Prewarm(ctx context.Context, targets []PrewarmTarget, opts PrewarmOptions) PrewarmStats {
	if f == nil {
		return PrewarmStats{}
	}
	if opts.PerRequestTimeout <= 0 {
		opts.PerRequestTimeout = 5 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	hosts := resolveUniqueHosts(targets)
	if len(hosts) == 0 {
		return PrewarmStats{}
	}

	client := f.GetFasthttpClient(ClientPurposeInference)
	if client == nil {
		return PrewarmStats{}
	}

	stats := PrewarmStats{
		Attempted:   len(hosts),
		PerHostTime: make(map[string]time.Duration, len(hosts)),
	}
	start := time.Now()

	sem := make(chan struct{}, opts.Concurrency)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for host, baseURL := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host, baseURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			t0 := time.Now()
			err := warmOne(client, baseURL, opts.PerRequestTimeout)
			elapsed := time.Since(t0)
			mu.Lock()
			stats.PerHostTime[host] = elapsed
			if err == nil {
				stats.Succeeded++
			} else {
				stats.Failed++
			}
			mu.Unlock()
		}(host, baseURL)
	}
	wg.Wait()
	stats.TotalTime = time.Since(start)
	return stats
}

// PrewarmAndSchedule fires Prewarm once and, if opts.RewarmInterval > 0,
// schedules periodic re-warming until ctx is canceled. Returns the initial
// stats so the caller can log them.
func (f *HTTPClientFactory) PrewarmAndSchedule(ctx context.Context, targets []PrewarmTarget, opts PrewarmOptions, logger schemas.Logger) PrewarmStats {
	stats := f.Prewarm(ctx, targets, opts)
	if logger != nil {
		logger.Info("[Prewarm] initial run: %d hosts, %d succeeded, %d failed, %v elapsed",
			stats.Attempted, stats.Succeeded, stats.Failed, stats.TotalTime)
	}
	if opts.RewarmInterval > 0 {
		go func() {
			ticker := time.NewTicker(opts.RewarmInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					r := f.Prewarm(ctx, targets, opts)
					if logger != nil {
						logger.Debug("[Prewarm] rewarm: %d hosts, %d succeeded, %d failed, %v elapsed",
							r.Attempted, r.Succeeded, r.Failed, r.TotalTime)
					}
				}
			}
		}()
	}
	return stats
}

// resolveUniqueHosts collapses targets to one entry per Host:Port so we
// don't open redundant connections when many tenants share the same base
// URL (the common case). Returns map[hostKey]baseURL.
func resolveUniqueHosts(targets []PrewarmTarget) map[string]string {
	out := make(map[string]string, len(targets))
	for _, t := range targets {
		baseURL := strings.TrimSpace(t.BaseURL)
		if baseURL == "" {
			baseURL = DefaultProviderBaseURLs[strings.ToLower(strings.TrimSpace(t.Provider))]
		}
		if baseURL == "" {
			continue
		}
		host := hostFromURL(baseURL)
		if host == "" {
			continue
		}
		if _, exists := out[host]; !exists {
			out[host] = baseURL
		}
	}
	return out
}

// hostFromURL extracts the Host:Port portion of a baseURL. Returns ""
// when the URL is malformed.
func hostFromURL(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return ""
	}
	// Strip scheme
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	// Strip path / query
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

// warmOne issues a HEAD against baseURL using the supplied fasthttp client.
// fasthttp pools connections per Host, so this single HEAD establishes the
// TCP+TLS+HTTP/2 session that later inference requests reuse.
//
// We accept any response status as success - even a 404/405 means the
// connection was established. The only failure mode we count is timeout /
// connection refused / DNS failure.
func warmOne(client *fasthttp.Client, baseURL string, timeout time.Duration) error {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(baseURL)
	req.Header.SetMethod(fasthttp.MethodHead)
	req.Header.SetUserAgent("DeepIntShield-Prewarm/1.0")

	return client.DoTimeout(req, resp, timeout)
}
