package server

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/network"
)

// runProviderPrewarm fires HEAD requests against every provider base URL
// we can identify, in parallel, so the first real inference request after
// startup doesn't pay for DNS resolve + TCP handshake + TLS handshake
// (typically 100-300ms on a cold connection to OpenAI/Anthropic/etc.).
//
// Each provider package currently builds its own *fasthttp.Client, so the
// pool we warm here is a separate one - the wins we capture are:
//   - OS-level DNS cache populated for every provider hostname
//   - TLS session ticket / certificate cache populated (TLS 1.3 resumption)
//   - Kernel TCP cache hot for the provider IPs
//
// Net first-request improvement: ~30-100ms. Full sharing of the pool with
// provider packages would unlock the remaining ~100-200ms but requires a
// refactor to pass the shared fasthttp.Client into every provider's New().
//
// Tunables (all env-overridable):
//
//	DEEPINTSHIELD_DISABLE_PREWARM=true        - skip entirely
//	DEEPINTSHIELD_PREWARM_TIMEOUT_MS=5000     - per-host attempt budget
//	DEEPINTSHIELD_PREWARM_REWARM_MIN=10       - periodic re-warm interval
//	DEEPINTSHIELD_PREWARM_PROVIDERS=openai,anthropic,bedrock
//	                                          - override the default set
func (s *DeepIntShieldHTTPServer) runProviderPrewarm() {
	factory := network.NewHTTPClientFactory(nil, logger)
	targets := s.buildPrewarmTargets()
	if len(targets) == 0 {
		return
	}

	opts := network.PrewarmOptions{
		PerRequestTimeout: envDurationMs("DEEPINTSHIELD_PREWARM_TIMEOUT_MS", 5*time.Second),
		Concurrency:       16,
		RewarmInterval:    envDurationMin("DEEPINTSHIELD_PREWARM_REWARM_MIN", 10*time.Minute),
	}

	// Detach from any request-scoped context - prewarm outlives the
	// caller and re-warm goroutines need to live for the process lifetime.
	ctx := context.Background()
	stats := factory.PrewarmAndSchedule(ctx, targets, opts, logger)
	logger.Info("[Prewarm] warmed %d/%d provider endpoints in %v",
		stats.Succeeded, stats.Attempted, stats.TotalTime)
}

// buildPrewarmTargets enumerates which provider hostnames to warm. Order
// of precedence:
//  1. DEEPINTSHIELD_PREWARM_PROVIDERS env var (comma-sep list of provider keys)
//  2. The full DefaultProviderBaseURLs set (currently 10 providers)
//
// Per-tenant base URLs (e.g. Azure custom endpoints, self-hosted Ollama)
// aren't enumerated here because we'd need to walk every VK config + every
// custom provider entry. The override env exists for operators who want
// to add a custom hostname.
func (s *DeepIntShieldHTTPServer) buildPrewarmTargets() []network.PrewarmTarget {
	override := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_PREWARM_PROVIDERS"))
	var providerKeys []string
	if override != "" {
		for _, p := range strings.Split(override, ",") {
			if v := strings.ToLower(strings.TrimSpace(p)); v != "" {
				providerKeys = append(providerKeys, v)
			}
		}
	} else {
		providerKeys = make([]string, 0, len(network.DefaultProviderBaseURLs))
		for k := range network.DefaultProviderBaseURLs {
			providerKeys = append(providerKeys, k)
		}
		sort.Strings(providerKeys) // deterministic ordering for logs
	}

	targets := make([]network.PrewarmTarget, 0, len(providerKeys))
	for _, key := range providerKeys {
		targets = append(targets, network.PrewarmTarget{
			Provider: key, // BaseURL left empty → resolves from DefaultProviderBaseURLs
		})
	}
	return targets
}

// envDurationMs reads an integer env var and returns it as a millisecond
// duration. Falls back to fallback when unset or invalid.
func envDurationMs(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 {
		return fallback
	}
	return time.Duration(n) * time.Millisecond
}

// envDurationMin reads an integer env var and returns it as a minute
// duration. Falls back to fallback when unset, invalid, or zero (zero
// also disables the re-warm scheduler intentionally).
func envDurationMin(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
	}
	if n < 0 {
		return fallback
	}
	return time.Duration(n) * time.Minute
}
