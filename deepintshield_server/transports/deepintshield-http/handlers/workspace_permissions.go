package handlers

import (
	"context"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

// cachedAuthUserFromCtx returns a minimal TableAuthUser synthesised from
// the values the session middleware already stamped on the request
// context (via the in-process session cache). Saves a fresh DB load for
// every permission check on the hot write path.
//
// TenantID is sourced from the active-scope override if set (the
// switcher's chosen 3-tier tenant), otherwise the session's home
// tenant. The legacy DeepIntShieldContextKeyTenantID itself is the
// email-keyed GORM partition and must NOT be overwritten by the
// override - see applyActiveScopeOverride for the rationale.
//
// Returns nil when the context isn't authenticated. Only ID, Role, and
// TenantID are populated - sufficient for CanManageWorkspace* /
// CanManageTenant which only need those three fields.
func cachedAuthUserFromCtx(ctx *fasthttp.RequestCtx) *tables.TableAuthUser {
	if ctx == nil {
		return nil
	}
	userID, _ := ctx.UserValue(schemas.DeepIntShieldContextKeyUserID).(string)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	role, _ := ctx.UserValue(schemas.DeepIntShieldContextKeyUserRole).(string)
	// Prefer the active-scope key when set; fall back to the session's
	// home tenant.
	tenantID, _ := ctx.UserValue(schemas.DeepIntShieldContextKeyActiveTenantID).(string)
	if strings.TrimSpace(tenantID) == "" {
		tenantID, _ = ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID).(string)
	}
	return &tables.TableAuthUser{
		ID:       userID,
		Role:     strings.TrimSpace(role),
		TenantID: strings.TrimSpace(tenantID),
	}
}

// CanManageWorkspace returns true when the user is allowed to perform a
// destructive write inside the given workspace: create, update, or delete
// resources scoped to it (virtual keys, MCP clients, routing rules,
// guardrail policies, prompts, etc).
//
// The rule is layered:
//  1. System admins (auth_users.role = "admin") pass unconditionally.
//  2. Workspace-level admins on that specific workspace pass.
//  3. Org-level owners/admins on the workspace's tenant pass.
//
// Workspace-level "member" / "viewer" roles return false - those roles
// can read, not write.
//
// Callers should respond with a 403 when this returns false.
func CanManageWorkspace(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, ws *tables.TableWorkspace) bool {
	if user == nil || ws == nil || store == nil {
		return false
	}
	// Only true SUPERADMINS bypass the membership check. UserRoleAdmin is
	// the default role assigned to every fresh signup, so treating it as
	// a system-wide bypass would let any signed-up user read/manage
	// every other tenant - a SaaS isolation breach. Tenant-admin status
	// is conveyed through the org_memberships / workspace_memberships
	// rows the user actually holds, not the global Role column.
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	if m, _ := store.GetWorkspaceMembership(ctx, ws.ID, user.ID); m != nil && m.Role == tables.WorkspaceRoleAdmin {
		return true
	}
	if m, _ := store.GetOrgMembership(ctx, ws.OrgID, user.ID); m != nil {
		return m.Role == tables.OrgRoleOwner || m.Role == tables.OrgRoleAdmin
	}
	return false
}

// CanManageWorkspaceByID is CanManageWorkspace with a workspace-by-id
// lookup. Returns false if the workspace can't be loaded.
//
// Uses globalAuthCache.getWorkspaceParents to skip the DB round-trip
// when the workspace was recently resolved - workspaces change rarely
// and a 60-s TTL eliminates the lookup on the hot write path. We also
// short-circuit for system admins before touching the cache or DB.
func CanManageWorkspaceByID(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, workspaceID string) bool {
	if user == nil || store == nil || workspaceID == "" {
		return false
	}
	// Only true SUPERADMINS bypass the membership check. UserRoleAdmin is
	// the default role assigned to every fresh signup, so treating it as
	// a system-wide bypass would let any signed-up user read/manage
	// every other tenant - a SaaS isolation breach. Tenant-admin status
	// is conveyed through the org_memberships / workspace_memberships
	// rows the user actually holds, not the global Role column.
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	// Cache hit: synthesise a minimal TableWorkspace so the membership
	// helpers can run without the row load.
	if _, tenantID, ok := globalAuthCache.getWorkspaceParents(workspaceID); ok && tenantID != "" {
		stub := &tables.TableWorkspace{ID: workspaceID, OrgID: tenantID}
		return CanManageWorkspace(ctx, store, user, stub)
	}
	ws, err := store.GetWorkspaceByID(ctx, workspaceID)
	if err != nil || ws == nil {
		return false
	}
	// Populate cache for subsequent requests in the next 60 s. The
	// "orgID" key on workspaceCacheEntry stores the governance_org id
	// (top tier); tenantID stores the immediate parent tenant
	// (TableWorkspace.OrgID). Both are useful for permission helpers
	// that walk the 3-tier hierarchy.
	globalAuthCache.putWorkspaceParents(workspaceID, "", ws.OrgID)
	return CanManageWorkspace(ctx, store, user, ws)
}

// CanReadWorkspace returns true when the user is allowed to read resources
// scoped to the given workspace. Membership at any level (workspace
// admin/member/viewer or org owner/admin) suffices; a tenant member
// without a workspace membership does not.
func CanReadWorkspace(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, ws *tables.TableWorkspace) bool {
	if user == nil || ws == nil || store == nil {
		return false
	}
	// Only true SUPERADMINS bypass the membership check. UserRoleAdmin is
	// the default role assigned to every fresh signup, so treating it as
	// a system-wide bypass would let any signed-up user read/manage
	// every other tenant - a SaaS isolation breach. Tenant-admin status
	// is conveyed through the org_memberships / workspace_memberships
	// rows the user actually holds, not the global Role column.
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	if m, _ := store.GetWorkspaceMembership(ctx, ws.ID, user.ID); m != nil {
		return true
	}
	if m, _ := store.GetOrgMembership(ctx, ws.OrgID, user.ID); m != nil {
		return m.Role == tables.OrgRoleOwner || m.Role == tables.OrgRoleAdmin
	}
	return false
}

// CanManageTenant returns true when the user can perform destructive
// writes scoped to the tenant itself (rename, settings, member changes).
// System admins or tenant owners/admins pass.
func CanManageTenant(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, tenantID string) bool {
	if user == nil || store == nil || tenantID == "" {
		return false
	}
	// Only true SUPERADMINS bypass the membership check. UserRoleAdmin is
	// the default role assigned to every fresh signup, so treating it as
	// a system-wide bypass would let any signed-up user read/manage
	// every other tenant - a SaaS isolation breach. Tenant-admin status
	// is conveyed through the org_memberships / workspace_memberships
	// rows the user actually holds, not the global Role column.
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	m, err := store.GetOrgMembership(ctx, tenantID, user.ID)
	if err != nil || m == nil {
		return false
	}
	return m.Role == tables.OrgRoleOwner || m.Role == tables.OrgRoleAdmin
}

// CanManageOrg returns true when the user can perform destructive
// writes at the organization (top-tier) level - creating new tenants
// inside the org, renaming the org, managing org-level members.
// System admins, the org owner (auth_users.organization_id = orgID and
// they're the org's owner_user_id) or anyone holding an
// owner/admin governance_org_membership pass.
//
// This sits ABOVE CanManageTenant: org-admin can manage every tenant
// under the org transitively, but a tenant-admin cannot manage the org.
func CanManageOrg(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, orgID string) bool {
	if user == nil || store == nil || orgID == "" {
		return false
	}
	// Only true SUPERADMINS bypass the membership check. UserRoleAdmin is
	// the default role assigned to every fresh signup, so treating it as
	// a system-wide bypass would let any signed-up user read/manage
	// every other tenant - a SaaS isolation breach. Tenant-admin status
	// is conveyed through the org_memberships / workspace_memberships
	// rows the user actually holds, not the global Role column.
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	m, err := store.GetGovernanceOrgMembership(ctx, orgID, user.ID)
	if err != nil || m == nil {
		return false
	}
	return m.Role == tables.GovernanceOrgRoleOwner || m.Role == tables.GovernanceOrgRoleAdmin
}
