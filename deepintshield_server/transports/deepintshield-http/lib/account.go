// Package lib provides core functionality for the DeepIntShield HTTP service,
// including context propagation, header management, and integration with monitoring systems.
package lib

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/valyala/fasthttp"
)

// resolvedProviderConfigTTL bounds how long a tenant-scoped provider config is
// served from the in-memory cache before re-reading the store. Short enough that
// a missed invalidation still self-heals within seconds; long enough that the
// per-request read on the hot path is almost always a cache hit (no DB call).
const resolvedProviderConfigTTL = 5 * time.Second

// resolvedConfigEntry is a cached tenant-scoped provider config.
type resolvedConfigEntry struct {
	cfg  *schemas.ProviderConfig
	hash string
	exp  time.Time
}

// tenantClientEntry is a cached per-(tenant,provider) HTTP client built for
// transport-bound network config overrides.
type tenantClientEntry struct {
	client *fasthttp.Client
	exp    time.Time
}

// BaseAccount implements the Account interface for DeepIntShield.
// It manages provider configurations using a in-memory store for persistent storage.
// All data processing (environment variables, key configs) is done upfront in the store.
type BaseAccount struct {
	store *Config // store for in-memory configuration
	// netCfgCache caches tenant-scoped resolved provider configs for the
	// per-tenant network-config feature (PER_TENANT_NETWORK_CONFIG). Keyed by
	// "tenantID|workspaceID|providerKey". sync.Map suits the read-mostly hot path.
	netCfgCache sync.Map
	// tenantClientCache caches per-(tenant,workspace,provider) *fasthttp.Client
	// instances for transport-bound network config (proxy / TLS / max-conns) that
	// cannot be applied per-request. Only populated for tenants that actually
	// override those fields; the common case uses the shared provider client.
	tenantClientCache sync.Map
}

// NewBaseAccount creates a new BaseAccount with the given store
func NewBaseAccount(store *Config) *BaseAccount {
	return &BaseAccount{
		store: store,
	}
}

// GetConfiguredProviders returns a list of all configured providers.
// Implements the Account interface.
func (baseAccount *BaseAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	if baseAccount.store == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	return baseAccount.store.GetAllProviders()
}

func (baseAccount *BaseAccount) getRawProviderConfig(ctx context.Context, providerKey schemas.ModelProvider) (*configstore.ProviderConfig, error) {
	if baseAccount.store == nil {
		return nil, fmt.Errorf("store not initialized")
	}

	// Authenticated workspace requests carry a tenant-scoped context. Prefer the
	// tenant's provider record so Prompt Repository and other dashboard flows can
	// use keys created in the UI without requiring file-backed bootstrap config.
	if ctx != nil && baseAccount.store.ConfigStore != nil {
		config, err := baseAccount.store.ConfigStore.GetProviderConfig(ctx, providerKey)
		if err == nil && config != nil {
			return config, nil
		}
		if err != nil && !errors.Is(err, configstore.ErrNotFound) {
			return nil, err
		}
	}

	return baseAccount.store.GetProviderConfigRaw(providerKey)
}

// GetKeysForProvider returns the API keys configured for a specific provider.
// Keys are already processed (environment variables resolved) by the store.
// Implements the Account interface.
func (baseAccount *BaseAccount) GetKeysForProvider(ctx context.Context, providerKey schemas.ModelProvider) ([]schemas.Key, error) {
	config, err := baseAccount.getRawProviderConfig(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	keys := config.Keys
	if v := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceIncludeOnlyKeys); v != nil {
		if includeOnlyKeys, ok := v.([]string); ok {
			if len(includeOnlyKeys) == 0 {
				// header present but empty means "no keys allowed"
				keys = nil
			} else {
				set := make(map[string]struct{}, len(includeOnlyKeys))
				for _, id := range includeOnlyKeys {
					set[id] = struct{}{}
				}
				filtered := make([]schemas.Key, 0, len(keys))
				for _, key := range keys {
					if _, ok := set[key.ID]; ok {
						filtered = append(filtered, key)
					}
				}
				keys = filtered
			}
		}
	}
	return keys, nil
}

// GetConfigForProvider returns the complete configuration for a specific provider.
// Configuration is already fully processed (environment variables, key configs) by the store.
// Implements the Account interface.
func (baseAccount *BaseAccount) GetConfigForProvider(providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	if baseAccount.store == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	config, err := baseAccount.store.GetProviderConfigRaw(providerKey)
	if err != nil {
		if !errors.Is(err, ErrNotFound) || !deepintshield.IsStandardProvider(providerKey) {
			return nil, err
		}

		// Standard providers can run with default transport settings. This lets
		// tenant-scoped provider keys added in the UI initialize on demand even
		// when the preset did not predeclare that provider in config.json.
		config = &configstore.ProviderConfig{}
	}
	return toSchemaProviderConfig(config), nil
}

// toSchemaProviderConfig maps a stored provider config to the runtime schema
// config, applying defaults for absent network/concurrency settings. Shared by
// GetConfigForProvider (global) and GetResolvedProviderConfig (tenant-scoped) so
// both produce identical config shapes.
func toSchemaProviderConfig(config *configstore.ProviderConfig) *schemas.ProviderConfig {
	providerConfig := &schemas.ProviderConfig{}
	if config.ProxyConfig != nil {
		providerConfig.ProxyConfig = config.ProxyConfig
	}
	if config.NetworkConfig != nil {
		providerConfig.NetworkConfig = *config.NetworkConfig
	} else {
		providerConfig.NetworkConfig = schemas.DefaultNetworkConfig
	}
	if config.ConcurrencyAndBufferSize != nil {
		providerConfig.ConcurrencyAndBufferSize = *config.ConcurrencyAndBufferSize
	} else {
		providerConfig.ConcurrencyAndBufferSize = schemas.DefaultConcurrencyAndBufferSize
	}
	providerConfig.SendBackRawRequest = config.SendBackRawRequest
	providerConfig.SendBackRawResponse = config.SendBackRawResponse
	if config.CustomProviderConfig != nil {
		providerConfig.CustomProviderConfig = config.CustomProviderConfig
	}
	return providerConfig
}

// resolvedConfigCacheKey scopes a cache entry to the caller's tenant + workspace
// so one tenant's config can never be served to another.
func resolvedConfigCacheKey(ctx context.Context, providerKey schemas.ModelProvider) string {
	return tenantctx.TenantIDFromContext(ctx) + "|" + tenantctx.WorkspaceIDFromContext(ctx) + "|" + string(providerKey)
}

// GetResolvedProviderConfig returns the tenant-scoped provider config (network +
// proxy + concurrency) for the caller's context, falling back to the global
// in-memory config when the tenant has no override row. Used by the request
// worker (PER_TENANT_NETWORK_CONFIG) to apply per-tenant network settings per
// request. Results are cached per (tenant, workspace, provider) with a short TTL
// + ConfigHash so the hot path does not hit the store on every request.
//
// This method is intentionally NOT on the Account interface; callers reach it via
// a type assertion, so adding it cannot break other Account implementations.
func (baseAccount *BaseAccount) GetResolvedProviderConfig(ctx context.Context, providerKey schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	if baseAccount.store == nil {
		return nil, fmt.Errorf("store not initialized")
	}
	key := resolvedConfigCacheKey(ctx, providerKey)
	if v, ok := baseAccount.netCfgCache.Load(key); ok {
		if e, ok := v.(*resolvedConfigEntry); ok && time.Now().Before(e.exp) {
			return e.cfg, nil
		}
	}
	raw, err := baseAccount.getRawProviderConfig(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	cfg := toSchemaProviderConfig(raw)
	baseAccount.netCfgCache.Store(key, &resolvedConfigEntry{cfg: cfg, hash: raw.ConfigHash, exp: time.Now().Add(resolvedProviderConfigTTL)})
	return cfg, nil
}

// InvalidateResolvedProviderConfig drops the cached tenant-scoped config for the
// caller's context + provider, so a UI/API save takes effect on the next request
// without waiting for the TTL. Reached via type assertion from the save handler.
func (baseAccount *BaseAccount) InvalidateResolvedProviderConfig(ctx context.Context, providerKey schemas.ModelProvider) {
	// Clear the exact (tenant, workspace, provider) entry for the caller...
	baseAccount.netCfgCache.Delete(resolvedConfigCacheKey(ctx, providerKey))
	// ...and clear every cached entry for this provider regardless of
	// tenant/workspace. A save's request context may resolve tenant/workspace
	// differently from how the inference path resolves them (e.g. an org-scoped
	// admin session vs a workspace-scoped virtual key), so the exact-key delete
	// alone can miss the entry the inference path actually reads. Saves are rare,
	// so this O(n) scan + the next-request re-read for other tenants is
	// negligible, and it guarantees the change applies on the very next request
	// instead of only after the TTL.
	suffix := "|" + string(providerKey)
	clearBySuffix := func(m *sync.Map) {
		m.Range(func(k, _ any) bool {
			if key, ok := k.(string); ok && strings.HasSuffix(key, suffix) {
				m.Delete(key)
			}
			return true
		})
	}
	clearBySuffix(&baseAccount.netCfgCache)
	clearBySuffix(&baseAccount.tenantClientCache)
}

// needsDedicatedClient reports whether a tenant's network config differs from the
// shared provider client on transport-bound fields (proxy, TLS, max-conns) that
// cannot be applied per request. When false, callers reuse the shared client and
// no per-tenant client is allocated - keeping the common path zero-cost.
func needsDedicatedClient(nc schemas.NetworkConfig, proxy *schemas.ProxyConfig) bool {
	if proxy != nil && proxy.Type != "" && proxy.Type != schemas.NoProxy {
		return true
	}
	if nc.InsecureSkipVerify || strings.TrimSpace(nc.CACertPEM) != "" {
		return true
	}
	if nc.MaxConnsPerHost > 0 && nc.MaxConnsPerHost != schemas.DefaultMaxConnsPerHost {
		return true
	}
	return false
}

// buildTenantClient constructs a *fasthttp.Client from a tenant's resolved
// provider config, mirroring the per-type provider client construction
// (NewOpenAIProvider) so proxy / TLS / connection settings match. The per-request
// timeout still overrides via DoTimeout at the chokepoint; ReadTimeout here is the
// tenant's configured (or default) value so the client is never unbounded.
func buildTenantClient(rc *schemas.ProviderConfig) *fasthttp.Client {
	timeout := time.Second * time.Duration(rc.NetworkConfig.DefaultRequestTimeoutInSeconds)
	if timeout <= 0 {
		timeout = time.Second * time.Duration(schemas.DefaultRequestTimeoutInSeconds)
	}
	maxConns := rc.NetworkConfig.MaxConnsPerHost
	if maxConns <= 0 {
		maxConns = schemas.DefaultMaxConnsPerHost
	}
	client := &fasthttp.Client{
		ReadTimeout:         timeout,
		WriteTimeout:        timeout,
		MaxConnsPerHost:     maxConns,
		MaxIdleConnDuration: 30 * time.Second,
		MaxConnWaitTimeout:  timeout,
		MaxConnDuration:     time.Second * time.Duration(schemas.DefaultMaxConnDurationInSeconds),
		ConnPoolStrategy:    fasthttp.FIFO,
	}
	client = providerUtils.ConfigureProxy(client, rc.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, rc.NetworkConfig, logger)
	return client
}

// GetResolvedProviderClient returns a per-(tenant,provider) *fasthttp.Client when
// the caller-tenant overrides transport-bound network fields (proxy/TLS/max-conns),
// cached per (tenant, workspace, provider) with the same TTL + save-time
// invalidation as the resolved config. Returns (nil, false) for the common case
// (no overrides) so the caller keeps using the shared provider client. Reached via
// type assertion, not the Account interface.
func (baseAccount *BaseAccount) GetResolvedProviderClient(ctx context.Context, providerKey schemas.ModelProvider) (*fasthttp.Client, bool) {
	rc, err := baseAccount.GetResolvedProviderConfig(ctx, providerKey)
	if err != nil || rc == nil || !needsDedicatedClient(rc.NetworkConfig, rc.ProxyConfig) {
		return nil, false
	}
	key := resolvedConfigCacheKey(ctx, providerKey)
	if v, ok := baseAccount.tenantClientCache.Load(key); ok {
		if e, ok := v.(*tenantClientEntry); ok && time.Now().Before(e.exp) {
			return e.client, true
		}
	}
	client := buildTenantClient(rc)
	baseAccount.tenantClientCache.Store(key, &tenantClientEntry{client: client, exp: time.Now().Add(resolvedProviderConfigTTL)})
	return client, true
}
