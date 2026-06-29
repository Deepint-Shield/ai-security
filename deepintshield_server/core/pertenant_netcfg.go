package deepintshield

import (
	"context"
	"os"
	"strings"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// perTenantNetworkConfigEnabled reports whether the per-tenant network-config
// feature (PER_TENANT_NETWORK_CONFIG) is on. It is evaluated once at process
// start - the env var is fixed for the lifetime of the process - so the request
// hot path pays no syscall and no per-request branch cost beyond a bool read.
//
// Default OFF. When off, the request worker never stamps per-tenant values on
// the context, every request-path helper falls back to the shared provider
// client's baked settings, and behavior is byte-for-byte identical to before
// this feature. This is the primary guarantee that the feature cannot break
// existing single-tenant / SDK / config.json deployments.
var perTenantNetworkConfigEnabled = os.Getenv("PER_TENANT_NETWORK_CONFIG") == "true"

// InvalidateTenantProviderConfig drops the cached tenant-scoped provider config
// for the caller's context + provider so a UI/API save applies on the very next
// request instead of waiting for the cache TTL. Called by the provider save
// handler. No-op when the feature is off or the account does not support tenant
// resolution; the short cache TTL is the backstop if this is ever missed.
func (deepintshield *DeepIntShield) InvalidateTenantProviderConfig(ctx context.Context, providerKey schemas.ModelProvider) {
	if !perTenantNetworkConfigEnabled {
		return
	}
	type invalidator interface {
		InvalidateResolvedProviderConfig(ctx context.Context, providerKey schemas.ModelProvider)
	}
	if acct, ok := deepintshield.account.(invalidator); ok {
		acct.InvalidateResolvedProviderConfig(ctx, providerKey)
	}
}

// resolvedProviderConfigResolver is implemented by the account (BaseAccount) to
// return a tenant-scoped provider config for the request's context. It is reached
// via a type assertion rather than the Account interface, so accounts that do not
// implement it (tests, alternative backends) transparently disable the feature
// instead of failing to compile or panicking.
type resolvedProviderConfigResolver interface {
	GetResolvedProviderConfig(ctx context.Context, providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error)
}

// clientResolver is implemented by the account to return a per-(tenant,provider)
// HTTP client for transport-bound network config (proxy/TLS/max-conns). Reached
// via type assertion; returns (nil,false) when the tenant has no such override.
type clientResolver interface {
	GetResolvedProviderClient(ctx context.Context, providerKey schemas.ModelProvider) (*fasthttp.Client, bool)
}

// applyTenantNetworkConfig stamps the caller-tenant's resolved provider network
// settings onto the request context so they apply to THIS request without
// rebuilding the shared, per-type provider. It is called once per request by the
// worker (only when the feature flag is on).
//
// Increment 1 covers the per-request-applicable fields - request timeout,
// stream-idle timeout, and base URL - which already fixes per-tenant timeouts for
// chat (non-streaming), responses, and image generation. Transport-bound fields
// (proxy, TLS, max-conns, HTTP/2) are applied by the per-(tenant,provider) client
// cache in Increment 2, which stamps DeepIntShieldContextKeyHTTPClient here.
//
// All stamps are "if empty" so an explicit upstream override (header/transport)
// still wins, and the whole method is a no-op when the account cannot resolve a
// tenant config - preserving prior behavior.
func (deepintshield *DeepIntShield) applyTenantNetworkConfig(ctx *schemas.DeepIntShieldContext, providerKey schemas.ModelProvider) {
	if ctx == nil {
		return
	}
	acct, ok := deepintshield.account.(resolvedProviderConfigResolver)
	if !ok {
		return
	}
	rc, err := acct.GetResolvedProviderConfig(ctx, providerKey)
	if err != nil || rc == nil {
		return
	}
	providerUtils.SetRequestTimeoutIfEmpty(ctx, rc.NetworkConfig.DefaultRequestTimeoutInSeconds)
	providerUtils.SetStreamIdleTimeoutIfEmpty(ctx, rc.NetworkConfig.StreamIdleTimeoutInSeconds)
	// Per-tenant base URL - read by each base-URL-aware provider's buildRequestURL
	// via providerUtils.ResolveBaseURL. Don't clobber a full per-request URL-path
	// override if one is already set.
	if rc.NetworkConfig.BaseURL != "" {
		if _, set := ctx.Value(schemas.DeepIntShieldContextKeyURLPath).(string); !set {
			ctx.SetValue(schemas.DeepIntShieldContextKeyTenantBaseURL, strings.TrimRight(rc.NetworkConfig.BaseURL, "/"))
		}
	}
	// Per-tenant transport client (proxy / TLS / max-conns). Set only when the
	// tenant overrides those fields; otherwise GetResolvedProviderClient returns
	// false and the shared provider client is used. The client is substituted at
	// the request chokepoint + streaming sites via providerUtils.ClientFromContext.
	if cr, ok := deepintshield.account.(clientResolver); ok {
		if client, ok := cr.GetResolvedProviderClient(ctx, providerKey); ok && client != nil {
			ctx.SetValue(schemas.DeepIntShieldContextKeyHTTPClient, client)
		}
	}
}
