package handlers

import (
	"strings"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

// TestCachedAuthUserFromCtx_synthesisesFromContext verifies that the
// fast-path "user from context" helper builds a usable TableAuthUser
// using only what the auth middleware already stamped on the request
// - no DB load. This is the core perf win that lets every write
// permission check avoid a round trip on the hot path.
func TestCachedAuthUserFromCtx_synthesisesFromContext(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserID, "u-7")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserRole, tables.UserRoleAdmin)
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "org-7")

	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		t.Fatalf("expected non-nil user")
	}
	if user.ID != "u-7" {
		t.Fatalf("expected ID 'u-7', got %q", user.ID)
	}
	if user.Role != tables.UserRoleAdmin {
		t.Fatalf("expected role %q, got %q", tables.UserRoleAdmin, user.Role)
	}
	if user.TenantID != "org-7" {
		t.Fatalf("expected tenant 'org-7', got %q", user.TenantID)
	}
}

// TestCachedAuthUserFromCtx_unauthenticatedNil ensures the helper
// returns nil when the context wasn't populated by the auth middleware
// - callers can use this to short-circuit with a 401.
func TestCachedAuthUserFromCtx_unauthenticatedNil(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if user := cachedAuthUserFromCtx(ctx); user != nil {
		t.Fatalf("expected nil for unauthenticated context, got %+v", user)
	}
}

// TestCachedAuthUserFromCtx_trimsWhitespace covers a small edge case
// - values stamped with stray whitespace should be normalised so
// downstream comparisons (e.g. `user.TenantID == desiredTenant`) hit
// the fast path even when the upstream caller leaks formatting.
func TestCachedAuthUserFromCtx_trimsWhitespace(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserID, "  u-9  ")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserRole, "  "+tables.UserRoleAdmin+"  ")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "  org-9  ")
	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		t.Fatalf("expected non-nil user")
	}
	if strings.ContainsAny(user.ID, " ") || strings.ContainsAny(user.Role, " ") || strings.ContainsAny(user.TenantID, " ") {
		t.Fatalf("expected trimmed values, got %+v", user)
	}
}

// TestAuthCacheMembership covers the per-request membership cache that
// short-circuits the DB lookup in applyActiveScopeOverride when a
// multi-tenant admin is browsing across tenants.
func TestAuthCacheMembership(t *testing.T) {
	cache := newAuthCache(60_000_000_000, 16) // 60s ttl, 16 cap

	// Cache miss before put.
	if _, ok := cache.getMembership("u-1", "org-1"); ok {
		t.Fatalf("expected miss before put")
	}

	// Cache positive entry.
	cache.putMembership("u-1", "org-1", true)
	allowed, ok := cache.getMembership("u-1", "org-1")
	if !ok {
		t.Fatalf("expected hit after put")
	}
	if !allowed {
		t.Fatalf("expected positive answer")
	}

	// Cache negative entry - important so repeated unauthorised attempts
	// don't hammer the DB.
	cache.putMembership("u-1", "org-2", false)
	allowed, ok = cache.getMembership("u-1", "org-2")
	if !ok {
		t.Fatalf("expected hit on negative entry")
	}
	if allowed {
		t.Fatalf("expected negative answer")
	}

	// Empty arguments are silently rejected (defensive).
	if _, ok := cache.getMembership("", "org-1"); ok {
		t.Fatalf("expected miss for empty userID")
	}
	if _, ok := cache.getMembership("u-1", ""); ok {
		t.Fatalf("expected miss for empty tenantID")
	}
}
