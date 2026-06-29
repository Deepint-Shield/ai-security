package tenantctx

import (
	"context"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// TenantIDFromContext returns the active tenant ID from context.
// DeepIntShield now scopes tenant isolation to the normalized user email.
func TenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyTenantID))
}

// UserIDFromContext returns the authenticated dashboard user ID from context.
func UserIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyUserID))
}

// WorkspaceIDFromContext returns the active workspace ID from context.
// The session middleware stamps this from the X-Active-Workspace-Id header
// (the sidebar's workspace switcher); list handlers should use it as a
// default workspace filter when no explicit query/body parameter is given.
func WorkspaceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyWorkspaceID))
}

// ActiveTenantIDFromContext returns the UI-selected org (3-tier "tenant")
// UUID from context - the value of the X-Active-Tenant-Id header after the
// permission check. Distinct from TenantIDFromContext, which is the email-
// keyed GORM partition. Empty / unset = no active-org override.
func ActiveTenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyActiveTenantID))
}

func stringValue(value any) string {
	if raw, ok := value.(string); ok {
		return strings.TrimSpace(raw)
	}
	return ""
}
