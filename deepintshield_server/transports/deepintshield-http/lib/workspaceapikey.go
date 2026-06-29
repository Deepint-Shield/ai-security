package lib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore"
)

// WorkspaceAPIKeyPrefix is the leading sentinel on every workspace API key
// plaintext. The middleware uses this to fast-path-skip lookups for tokens
// that obviously aren't workspace keys (e.g. virtual keys, dashboard
// session tokens).
const WorkspaceAPIKeyPrefix = "dis_ws_"

// workspaceCacheTTL bounds how long a cached lookup is trusted before we
// re-hit the DB. Short TTL = a revoked key dies within at most this window
// even without explicit cache invalidation across replicas. The trade-off
// is one DB read per token per ~minute on the hot path; with prepared
// statements + the unique index on key_hash this is sub-millisecond.
const workspaceCacheTTL = 60 * time.Second

// lastUsedThrottle limits the rate at which we write last_used_at back to
// the DB. Without this, every inference request would generate a write -
// catastrophic at high QPS. With this, a key getting 1000 req/s only
// writes the column once per throttle window.
const lastUsedThrottle = 30 * time.Second

// negativeTTL is a separate, longer TTL for "this hash is not a valid
// workspace API key" entries. Stops cheap-cache-bypass attacks where an
// attacker rotates random tokens to force DB hits.
const negativeTTL = 5 * time.Minute

// WorkspaceContext is the bundle of values the inference path needs once a
// workspace API key has been resolved.
type WorkspaceContext struct {
	WorkspaceID string
	OrgID       string
	APIKeyID    string
}

type cachedWorkspaceEntry struct {
	ctx       *WorkspaceContext // nil = negative cache (token not found / revoked)
	expiresAt time.Time
}

// workspaceAPIKeyCache is intentionally a singleton - we want one cache
// per process, not one per handler / per request. sync.Map gives us
// lock-free reads on the hot path; the only writes are the once-per-TTL
// refresh from the resolver and the periodic janitor below.
var workspaceAPIKeyCache sync.Map

// lastUsedTimestamps is keyed by API key ID and tracks when we last wrote
// last_used_at for that key. Used to throttle the async writes.
var lastUsedTimestamps sync.Map

func init() {
	// Janitor: walk the cache every TTL and drop expired entries so we
	// don't grow the map unboundedly when key rotation churns through
	// distinct hashes. The cost is one O(n) walk per minute.
	go func() {
		t := time.NewTicker(workspaceCacheTTL)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			workspaceAPIKeyCache.Range(func(key, value any) bool {
				if entry, ok := value.(*cachedWorkspaceEntry); ok && now.After(entry.expiresAt) {
					workspaceAPIKeyCache.Delete(key)
				}
				return true
			})
		}
	}()
}

// IsWorkspaceAPIKey returns true if the token is shaped like a workspace
// API key. It does NOT validate that the key actually exists - it's a
// fast-path so callers can avoid the SHA-256 + DB roundtrip on the very
// large fraction of traffic that uses virtual keys instead.
func IsWorkspaceAPIKey(token string) bool {
	return strings.HasPrefix(token, WorkspaceAPIKeyPrefix)
}

// ResolveWorkspaceFromBearer takes a plaintext bearer token, returns the
// workspace context if it's a known workspace API key, or nil otherwise.
// Returns nil for non-workspace-key tokens, revoked keys, expired keys,
// and unknown tokens - callers MUST be tolerant of nil.
//
// Hot path:
//   - Cache hit on positive entry: ~100ns (sync.Map read + ptr deref)
//   - Cache hit on negative entry: ~100ns
//   - Cache miss: ~0.5-2ms (one DB query against unique index)
func ResolveWorkspaceFromBearer(ctx context.Context, store configstore.ConfigStore, bearer string) *WorkspaceContext {
	if !IsWorkspaceAPIKey(bearer) {
		return nil
	}
	if store == nil {
		return nil
	}
	hash := hashWorkspaceToken(bearer)

	// Cache check
	if cached, ok := workspaceAPIKeyCache.Load(hash); ok {
		if entry, ok := cached.(*cachedWorkspaceEntry); ok && time.Now().Before(entry.expiresAt) {
			if entry.ctx != nil {
				touchWorkspaceAPIKeyAsync(store, entry.ctx.APIKeyID)
			}
			return entry.ctx
		}
	}

	// Cache miss → DB
	rec, err := store.GetWorkspaceAPIKeyByHash(ctx, hash)
	if err != nil || rec == nil {
		// Negative cache. Expired keys and DB errors fall here too - for a
		// transient DB error this is mildly wrong (we'd cache a "not
		// found" for 5min) but the alternative is an open back door, so
		// fail closed.
		workspaceAPIKeyCache.Store(hash, &cachedWorkspaceEntry{
			ctx:       nil,
			expiresAt: time.Now().Add(negativeTTL),
		})
		return nil
	}
	// Reject expired keys at resolution time (don't trust DB row clock alone).
	if rec.ExpiresAt != nil && rec.ExpiresAt.Before(time.Now()) {
		workspaceAPIKeyCache.Store(hash, &cachedWorkspaceEntry{
			ctx:       nil,
			expiresAt: time.Now().Add(negativeTTL),
		})
		return nil
	}
	// Revoked keys come back from GetWorkspaceAPIKeyByHash already filtered
	// (revoked_at IS NULL in the WHERE clause), but keep an explicit guard
	// so a future store impl that drops the filter doesn't silently
	// grant access.
	if rec.RevokedAt != nil {
		workspaceAPIKeyCache.Store(hash, &cachedWorkspaceEntry{
			ctx:       nil,
			expiresAt: time.Now().Add(negativeTTL),
		})
		return nil
	}

	wsCtx := &WorkspaceContext{
		WorkspaceID: rec.WorkspaceID,
		OrgID:       rec.OrgID,
		APIKeyID:    rec.ID,
	}
	workspaceAPIKeyCache.Store(hash, &cachedWorkspaceEntry{
		ctx:       wsCtx,
		expiresAt: time.Now().Add(workspaceCacheTTL),
	})
	touchWorkspaceAPIKeyAsync(store, rec.ID)
	return wsCtx
}

// touchWorkspaceAPIKeyAsync schedules a last_used_at write off the request
// path. The throttle prevents write amplification on the workspace_api_keys
// table when a single key is used at high QPS.
func touchWorkspaceAPIKeyAsync(store configstore.ConfigStore, apiKeyID string) {
	now := time.Now()
	if last, ok := lastUsedTimestamps.Load(apiKeyID); ok {
		if t, ok := last.(time.Time); ok && now.Sub(t) < lastUsedThrottle {
			return // recently touched, skip
		}
	}
	lastUsedTimestamps.Store(apiKeyID, now)
	go func(id string, at time.Time) {
		// Detached context - we don't want a request cancel to drop the
		// last_used_at write. A short timeout on the call site within
		// store would be a future improvement; for now rely on driver
		// defaults.
		_ = store.TouchWorkspaceAPIKeyLastUsed(context.Background(), id, at)
	}(apiKeyID, now)
}

// InvalidateWorkspaceAPIKeyCache evicts the cached entry for a specific
// token hash. Used by the revoke endpoint so a revoked key stops working
// in the local replica immediately rather than waiting up to TTL.
//
// Multi-replica setups still rely on the TTL because we don't ship a
// pubsub channel - the worst-case window is workspaceCacheTTL, which is
// the documented invalidation guarantee.
func InvalidateWorkspaceAPIKeyCache(tokenHash string) {
	workspaceAPIKeyCache.Delete(tokenHash)
	lastUsedTimestamps.Delete(tokenHash)
}

func hashWorkspaceToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ─── Package-level resolver hook ──────────────────────────────────────────
//
// ConvertToDeepIntShieldContext (in ctx.go) is called from many places and
// has no access to a ConfigStore. Rather than change every call-site
// signature we register a closure at bootstrap that bridges back to the
// store. ctx.go invokes it inline when it sees a `dis_ws_*` bearer.
//
// If the hook is unset (e.g. tests, embedded use) workspace API keys are
// silently ignored - the inference path falls through to virtual-key
// behaviour as if Phase K hadn't shipped. That's the safe default: no
// regression for callers that aren't using the new credential type.

var workspaceResolverHook func(ctx context.Context, bearer string) *WorkspaceContext

// SetWorkspaceKeyResolver registers the package-level resolver. Called
// once at server bootstrap with a closure that captures the live
// ConfigStore. Subsequent calls overwrite the hook (test-friendly).
func SetWorkspaceKeyResolver(fn func(ctx context.Context, bearer string) *WorkspaceContext) {
	workspaceResolverHook = fn
}

// ResolveWorkspaceContextFromHook is the indirection that ctx.go calls
// from inside the header walker. Returns nil if no hook is registered.
func ResolveWorkspaceContextFromHook(ctx context.Context, bearer string) *WorkspaceContext {
	fn := workspaceResolverHook
	if fn == nil {
		return nil
	}
	return fn(ctx, bearer)
}

// HashWorkspaceToken is the public hashing function for callers (e.g. the
// revoke endpoint) that need to invalidate a specific token's cache entry.
func HashWorkspaceToken(token string) string {
	return hashWorkspaceToken(token)
}
