package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

// anonymousLocalUser is the implicit single-tenant admin used when dashboard
// auth is disabled (the open-source default). It is never persisted; it just
// lets read-only "/me"-style endpoints return 200 in the no-login OSS build.
func anonymousLocalUser(store configstore.ConfigStore) *tables.TableAuthUser {
	tenantID := ""
	if resolver, ok := store.(interface {
		GetSingleTenantID(context.Context) (string, error)
	}); ok {
		if id, err := resolver.GetSingleTenantID(context.Background()); err == nil {
			tenantID = id
		}
	}
	return &tables.TableAuthUser{
		ID:              "local",
		TenantID:        tenantID,
		Role:            "admin",
		FirstName:       "Local",
		LastName:        "Admin",
		Organization:    "DeepintShield",
		IsEmailVerified: true,
	}
}

// currentAccountUserFromCtx extracts the authenticated user from the request context.
func currentAccountUserFromCtx(ctx *fasthttp.RequestCtx, store configstore.ConfigStore) (*tables.TableAuthUser, *tables.SessionsTable, error) {
	if store == nil {
		return nil, nil, fmt.Errorf("authentication store is not available")
	}

	sessionToken := ""
	if token, ok := ctx.UserValue(schemas.DeepIntShieldContextKeySessionToken).(string); ok {
		sessionToken = strings.TrimSpace(token)
	}
	if sessionToken == "" {
		sessionToken = sessionTokenFromRequest(ctx)
	}
	if sessionToken == "" {
		// OSS no-auth mode: when dashboard authentication is disabled there is no
		// login and no session cookie, so the dashboard's /me-style endpoints
		// (session/me, workspaces/me, organizations, ...) would 401. Return the
		// implicit single-tenant local admin instead so they succeed with 200 -
		// no console errors and no redirect to a login page that does not exist
		// in the open-source build. When auth is enabled, behavior is unchanged.
		if cfg, cfgErr := store.GetAuthConfig(context.Background()); cfgErr == nil && (cfg == nil || !cfg.IsEnabled) {
			return anonymousLocalUser(store), nil, nil
		}
		return nil, nil, errUnauthorizedSession
	}

	// Bypass GORM tenant scoping for these auth re-lookups - same
	// rationale as session_profile.go: token + user UUID are globally
	// unique, and the request ctx may carry a workspace-overridden
	// tenant_id that points at a partition where the session/user row
	// doesn't live (cross-workspace invitee scenario). With ctx the
	// lookups return nil → 401 → UI auto-logout loop.
	authCtx := context.Background()
	session, err := store.GetSession(authCtx, sessionToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load session: %w", err)
	}
	if session == nil {
		return nil, nil, errUnauthorizedSession
	}
	if session.UserID == nil || strings.TrimSpace(*session.UserID) == "" {
		return nil, session, errSessionNotAccount
	}

	user, err := store.GetUserByID(authCtx, strings.TrimSpace(*session.UserID))
	if err != nil {
		return nil, session, fmt.Errorf("failed to load account: %w", err)
	}
	if user == nil {
		return nil, session, errUnauthorizedSession
	}

	return user, session, nil
}

// respondAuthError maps an auth-resolution error to the appropriate HTTP status.
func respondAuthError(ctx *fasthttp.RequestCtx, err error) {
	if errors.Is(err, errUnauthorizedSession) {
		SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
		return
	}
	SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
}

// serializeWorkspace renders a workspace row as a JSON-friendly map.
func serializeWorkspace(ws *tables.TableWorkspace) map[string]any {
	return map[string]any{
		"id":          ws.ID,
		"org_id":      ws.OrgID,
		"name":        ws.Name,
		"slug":        ws.Slug,
		"description": ws.Description,
		"is_default":  ws.IsDefault,
		"created_by":  ws.CreatedBy,
		"created_at":  ws.CreatedAt,
		"updated_at":  ws.UpdatedAt,
	}
}
