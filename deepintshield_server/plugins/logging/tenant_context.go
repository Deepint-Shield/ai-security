package logging

import (
	"context"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
)

func asyncLoggingContext(ctx context.Context) context.Context {
	asyncCtx := context.Background()
	if ctx == nil {
		return asyncCtx
	}

	if tenantID := tenantIDFromContext(ctx); tenantID != "" {
		asyncCtx = context.WithValue(asyncCtx, schemas.DeepIntShieldContextKeyTenantID, tenantID)
	}
	if workspaceID := workspaceIDFromContext(ctx); workspaceID != "" {
		asyncCtx = context.WithValue(asyncCtx, schemas.DeepIntShieldContextKeyWorkspaceID, workspaceID)
	}
	if userID := userIDFromContext(ctx); userID != "" {
		asyncCtx = context.WithValue(asyncCtx, schemas.DeepIntShieldContextKeyUserID, userID)
	}

	return asyncCtx
}

func applyTenantIDToLog(ctx context.Context, entry *logstore.Log) {
	if entry == nil {
		return
	}
	if entry.TenantID == "" {
		entry.TenantID = tenantIDFromContext(ctx)
	}
	// Stamp the workspace at write-time so list/histogram queries can
	// segment by workspace. Inference requests carry the active workspace
	// either via the resolving virtual key (governance plugin sets it on
	// the deepintshield context) or via the workspace API key auth path.
	if entry.WorkspaceID == nil {
		if workspaceID := workspaceIDFromContext(ctx); workspaceID != "" {
			entry.WorkspaceID = &workspaceID
		}
	}
}

func applyTenantIDToMCPLog(ctx context.Context, entry *logstore.MCPToolLog) {
	if entry == nil {
		return
	}
	if entry.TenantID == "" {
		entry.TenantID = tenantIDFromContext(ctx)
	}
	if entry.WorkspaceID == nil {
		if workspaceID := workspaceIDFromContext(ctx); workspaceID != "" {
			entry.WorkspaceID = &workspaceID
		}
	}
}

func tenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyTenantID))
}

func workspaceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyWorkspaceID))
}

func userIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	return stringValue(ctx.Value(schemas.DeepIntShieldContextKeyUserID))
}

func stringValue(value any) string {
	if raw, ok := value.(string); ok {
		return strings.TrimSpace(raw)
	}
	return ""
}
