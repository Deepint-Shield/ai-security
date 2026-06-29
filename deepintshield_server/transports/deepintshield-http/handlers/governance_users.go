package handlers

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/valyala/fasthttp"
)

type provisionedUserRow struct {
	ID                string     `json:"id"`
	UserID            *string    `json:"user_id,omitempty"`
	InvitationID      *string    `json:"invitation_id,omitempty"`
	CustomerID        *string    `json:"customer_id,omitempty"`
	EntraConnectionID *string    `json:"entra_connection_id,omitempty"`
	FullName          string     `json:"full_name"`
	Email             string     `json:"email"`
	Role              string     `json:"role"`
	Status            string     `json:"status"`
	IsOwner           bool       `json:"is_owner"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	WorkspaceCount    int        `json:"workspace_count"`
}

func (h *GovernanceHandler) getProvisionedUsers(ctx *fasthttp.RequestCtx) {
	limit, offset := parseUserProvisioningPagination(ctx)
	search := strings.TrimSpace(string(ctx.QueryArgs().Peek("search")))
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	activeWS := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx))

	params := configstore.UsersQueryParams{
		Limit:             500,
		Offset:            0,
		Search:            search,
		CustomerID:        strings.TrimSpace(string(ctx.QueryArgs().Peek("customer_id"))),
		EntraConnectionID: strings.TrimSpace(string(ctx.QueryArgs().Peek("entra_connection_id"))),
	}

	// Background context (no tenant stamp) for cross-tenant user lookups
	// - the workspace_memberships row may point at a user whose
	// auth_users.tenant_id is in a different partition. Membership
	// existence is itself the authorisation; we already vetted the
	// caller can see this workspace via the route-level admin guard.
	lookupCtx := context.Background()
	searchLower := strings.ToLower(search)

	var users []configstoreTables.TableAuthUser
	if activeWS != "" {
		// Workspace-scoped view: list ONLY users who hold a
		// workspace_memberships row on the active workspace. Without
		// this, the tenant-wide GetUsersPaginated returns every user in
		// the legacy email-keyed partition - which produces identical
		// rows across every workspace under the same tenant founder
		// (each sibling workspace shares its creator's tenant_id, so
		// the legacy list can't distinguish them).
		memberships, mErr := h.configStore.ListWorkspaceMembershipsByWorkspace(ctx, activeWS)
		if mErr != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to retrieve workspace members")
			return
		}
		seen := make(map[string]struct{}, len(memberships))
		for _, m := range memberships {
			if _, already := seen[m.UserID]; already {
				continue
			}
			u, getErr := h.configStore.GetUserByID(lookupCtx, m.UserID)
			if getErr != nil || u == nil {
				continue
			}
			// Surface workspace role onto the row's Role column. Admin →
			// Admin, anything else → Viewer (the UI's only two top-level
			// options for per-workspace role).
			switch m.Role {
			case configstoreTables.WorkspaceRoleAdmin:
				u.Role = configstoreTables.UserRoleAdmin
			default:
				u.Role = configstoreTables.UserRoleViewer
			}
			if searchLower != "" {
				hay := strings.ToLower(u.Email + " " + u.FirstName + " " + u.LastName)
				if !strings.Contains(hay, searchLower) {
					continue
				}
			}
			users = append(users, *u)
			seen[m.UserID] = struct{}{}
		}
	} else {
		// No active workspace header (CLI / SDK callers): fall back to
		// the tenant-wide list so existing single-tenant flows keep
		// working unchanged.
		all, _, err := h.configStore.GetUsersPaginated(ctx, params)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to retrieve users")
			return
		}
		users = all
	}
	// Invitations are now stamped with the 3-tier tenant (workspace.OrgID)
	// in inviteUser so applyPendingInvitationForNewUser can use the
	// stored TenantID directly to build a valid org_membership. The
	// GORM tenant-scoping callback filters invitation queries by the
	// request ctx's TenantID though - for self-serve users that's the
	// legacy email-keyed partition, which won't match the new
	// invitation rows. Query with the active 3-tier tenant instead so
	// the list reflects what was just created.
	invitationTenantID := strings.TrimSpace(activeTenantFromCtx(ctx))
	if invitationTenantID == "" {
		invitationTenantID = tenantID
	}
	invitationCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, invitationTenantID)
	invitations, _, err := h.configStore.GetUserInvitations(invitationCtx, params)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to retrieve pending invitations")
		return
	}
	// Filter invitations to the active workspace when one is set, so
	// pending invites for sibling workspaces under the same tenant
	// don't leak into this workspace's list.
	if activeWS != "" {
		filtered := invitations[:0]
		for _, inv := range invitations {
			if inv.WorkspaceID != nil && strings.TrimSpace(*inv.WorkspaceID) == activeWS {
				filtered = append(filtered, inv)
			}
		}
		invitations = filtered
	}

	ownerID := ""
	if activeWS != "" {
		// Surface the workspace's creator as the "owner" so the UI
		// renders the founder/admin badge correctly per-workspace
		// instead of looking at the legacy tenant org row (which has
		// no backing organizations row for self-serve signups).
		if ws, wsErr := h.configStore.GetWorkspaceByID(lookupCtx, activeWS); wsErr == nil && ws != nil {
			ownerID = strings.TrimSpace(ws.CreatedBy)
		}
	} else if tenantID != "" {
		organization, err := h.configStore.GetOrganizationByID(context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID), tenantID)
		if err == nil && organization != nil {
			ownerID = strings.TrimSpace(organization.OwnerID)
		}
	}

	rows := mergeProvisionedUsers(users, invitations, ownerID)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Status != rows[j].Status {
			return rows[i].Status == "active"
		}
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})

	totalCount := len(rows)
	if offset > totalCount {
		offset = totalCount
	}
	end := offset + limit
	if end > totalCount {
		end = totalCount
	}

	SendJSON(ctx, map[string]any{
		"users":       rows[offset:end],
		"count":       end - offset,
		"total_count": totalCount,
		"limit":       limit,
		"offset":      offset,
	})
}

func (h *GovernanceHandler) deleteProvisionedUser(ctx *fasthttp.RequestCtx) {
	currentUser, tenantID, organization, err := h.requireCurrentWorkspaceOwner(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusForbidden, err.Error())
		return
	}

	targetUserID := strings.TrimSpace(stringValue(ctx.UserValue("user_id")))
	if targetUserID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "User id is required")
		return
	}
	if targetUserID == currentUser.ID {
		SendError(ctx, fasthttp.StatusBadRequest, "You cannot delete your own workspace account")
		return
	}

	bg := context.Background()
	targetUser, err := h.configStore.GetUserByID(bg, targetUserID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load user")
		return
	}
	if targetUser == nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}
	if organization != nil && strings.TrimSpace(organization.OwnerID) == targetUser.ID {
		SendError(ctx, fasthttp.StatusBadRequest, "The workspace owner cannot be deleted")
		return
	}

	activeWS := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx))

	// Workspace-scoped delete: when there's an active workspace and the
	// target has a workspace_memberships row on it, remove ONLY that
	// row - don't delete the auth_users record, since the user may
	// retain memberships in sibling workspaces (or have a home tenant
	// of their own).
	if activeWS != "" {
		if m, _ := h.configStore.GetWorkspaceMembership(bg, activeWS, targetUser.ID); m != nil {
			// Block removing the workspace's creator from their own
			// workspace via this endpoint - same intent as the
			// organization-owner guard above.
			if ws, _ := h.configStore.GetWorkspaceByID(bg, activeWS); ws != nil && strings.TrimSpace(ws.CreatedBy) == targetUser.ID {
				SendError(ctx, fasthttp.StatusBadRequest, "The workspace creator cannot be removed from their own workspace")
				return
			}
			if err := h.configStore.DeleteWorkspaceMembership(bg, activeWS, targetUser.ID); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, "Failed to remove workspace membership")
				return
			}
			SendJSON(ctx, map[string]any{
				"message": fmt.Sprintf("%s was removed from this workspace.", targetUser.Email),
			})
			return
		}
	}

	// Same-partition target: fall through to the legacy full-account
	// teardown so single-tenant flows keep working unchanged.
	if targetUser.TenantID != tenantID {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}

	tenantCtx := context.WithValue(bg, schemas.DeepIntShieldContextKeyTenantID, tenantID)
	invitation, err := h.configStore.GetUserInvitationByEmail(tenantCtx, targetUser.Email)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load user invitation")
		return
	}

	if err := h.configStore.DeleteSessionsByUserID(tenantCtx, targetUser.ID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to delete user sessions")
		return
	}
	if err := h.configStore.DeleteEmailVerificationTokensForUser(tenantCtx, targetUser.ID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to delete verification tokens")
		return
	}
	if invitation != nil {
		if err := h.configStore.DeleteUserInvitation(tenantCtx, invitation.ID); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to clear user invitation")
			return
		}
	}
	if err := h.configStore.DeleteUser(tenantCtx, targetUser.ID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to delete user")
		return
	}

	SendJSON(ctx, map[string]any{
		"message": fmt.Sprintf("%s was removed from %s.", targetUser.Email, organizationName(organization)),
	})
}

func (h *GovernanceHandler) requireCurrentWorkspaceAdmin(ctx context.Context) (*configstoreTables.TableAuthUser, string, error) {
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	userID := strings.TrimSpace(tenantctx.UserIDFromContext(ctx))
	if tenantID == "" || userID == "" {
		return nil, "", fmt.Errorf("Only workspace admins can manage user provisioning")
	}

	user, err := h.configStore.GetUserByID(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if user == nil {
		return nil, "", fmt.Errorf("Only workspace admins can manage user provisioning")
	}
	if strings.TrimSpace(user.Role) == configstoreTables.UserRoleViewer {
		return nil, "", fmt.Errorf("Only workspace admins can manage user provisioning")
	}
	return user, tenantID, nil
}

func (h *GovernanceHandler) requireCurrentWorkspaceOwner(ctx *fasthttp.RequestCtx) (*configstoreTables.TableAuthUser, string, *configstoreTables.TableOrganization, error) {
	user, tenantID, err := h.requireCurrentWorkspaceAdmin(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	bg := context.Background()
	activeWS := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx))

	// Resolve the *real* tenant for the action via the active workspace
	// - workspace.OrgID is the 3-tier tenant UUID, which is the row that
	// actually backs an `organizations` record. The legacy email-keyed
	// tenant_id often has no backing organizations row at all (self-serve
	// signups skip creating one), so reading it returns nil and we'd
	// reject every founder. Falls back to the active-tenant header and
	// then to the session tenant for CLI / SDK callers.
	resolvedTenantID := ""
	if activeWS != "" {
		if ws, _ := h.configStore.GetWorkspaceByID(bg, activeWS); ws != nil {
			resolvedTenantID = strings.TrimSpace(ws.OrgID)
		}
	}
	if resolvedTenantID == "" {
		resolvedTenantID = strings.TrimSpace(activeTenantFromCtx(ctx))
	}
	if resolvedTenantID == "" {
		resolvedTenantID = tenantID
	}

	var organization *configstoreTables.TableOrganization
	if resolvedTenantID != "" {
		organization, _ = h.configStore.GetOrganizationByID(bg, resolvedTenantID)
	}

	// Any of these paths authorises the caller for member-management on
	// this workspace. The legacy check (organization.OwnerID == user.ID)
	// is necessary but not sufficient - tenant founders sit on
	// governance_orgs, not organizations, and that's the row the
	// dashboard's `is_tenant_owner` flag actually keys off.
	isSuperadmin := configstoreTables.NormalizeAuthUserRole(user.Role) == configstoreTables.UserRoleSuperadmin
	isTenantOwner := organization != nil && strings.TrimSpace(organization.OwnerID) == user.ID

	isOrgAdmin := false
	if !isSuperadmin && !isTenantOwner && resolvedTenantID != "" {
		if m, _ := h.configStore.GetOrgMembership(bg, resolvedTenantID, user.ID); m != nil {
			isOrgAdmin = m.Role == configstoreTables.OrgRoleOwner || m.Role == configstoreTables.OrgRoleAdmin
		}
	}

	isFounder := false
	if !isSuperadmin && !isTenantOwner && !isOrgAdmin && strings.TrimSpace(user.OrganizationID) != "" {
		if gov, _ := h.configStore.GetGovernanceOrgByID(bg, strings.TrimSpace(user.OrganizationID)); gov != nil {
			isFounder = strings.TrimSpace(gov.OwnerUserID) == user.ID
		}
	}

	isWorkspaceAdmin := false
	if !isSuperadmin && !isTenantOwner && !isOrgAdmin && !isFounder && activeWS != "" {
		if m, _ := h.configStore.GetWorkspaceMembership(bg, activeWS, user.ID); m != nil {
			isWorkspaceAdmin = m.Role == configstoreTables.WorkspaceRoleAdmin
		}
	}

	if !(isSuperadmin || isTenantOwner || isOrgAdmin || isFounder || isWorkspaceAdmin) {
		return nil, "", nil, fmt.Errorf("Only the workspace owner can change member roles or remove access")
	}

	return user, tenantID, organization, nil
}

func parseUserProvisioningPagination(ctx *fasthttp.RequestCtx) (int, int) {
	limit := 25
	offset := 0

	if rawLimit := strings.TrimSpace(string(ctx.QueryArgs().Peek("limit"))); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil {
			limit = parsed
		}
	}
	if rawOffset := strings.TrimSpace(string(ctx.QueryArgs().Peek("offset"))); rawOffset != "" {
		if parsed, err := strconv.Atoi(rawOffset); err == nil {
			offset = parsed
		}
	}
	return ClampPaginationParams(limit, offset)
}

func mergeProvisionedUsers(users []configstoreTables.TableAuthUser, invitations []configstoreTables.TableUserInvitation, ownerID string) []provisionedUserRow {
	rows := make([]provisionedUserRow, 0, len(users)+len(invitations))
	pendingByEmail := make(map[string]*configstoreTables.TableUserInvitation, len(invitations))
	for i := range invitations {
		invitation := invitations[i]
		if invitation.AcceptedAt != nil {
			continue
		}
		pendingByEmail[normalizeEmail(invitation.Email)] = &invitation
	}

	for _, user := range users {
		email := normalizeEmail(user.Email)
		var invitationID *string
		if invitation, ok := pendingByEmail[email]; ok {
			invitationID = stringPtr(invitation.ID)
			delete(pendingByEmail, email)
		}
		rows = append(rows, serializeAuthUserRow(user, invitationID, ownerID))
	}

	for _, invitation := range pendingByEmail {
		rows = append(rows, serializeInvitationRow(invitation))
	}

	return rows
}

func serializeAuthUserRow(user configstoreTables.TableAuthUser, invitationID *string, ownerID string) provisionedUserRow {
	row := provisionedUserRow{
		ID:                user.ID,
		UserID:            stringPtr(user.ID),
		InvitationID:      invitationID,
		CustomerID:        user.CustomerID,
		EntraConnectionID: user.EntraConnectionID,
		FullName:          strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName)),
		Email:             user.Email,
		Role:              configstoreTables.NormalizeAuthUserRole(user.Role),
		Status:            "pending",
		IsOwner:           user.ID != "" && user.ID == ownerID,
		LastLoginAt:       user.LastLoginAt,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
		WorkspaceCount:    1,
	}
	if row.FullName == "" {
		row.FullName = user.Email
	}
	if user.IsEmailVerified {
		row.Status = "active"
	}
	return row
}

func serializeInvitationRow(invitation *configstoreTables.TableUserInvitation) provisionedUserRow {
	role := configstoreTables.NormalizeAuthUserRole(invitation.Role)
	return provisionedUserRow{
		ID:             invitation.ID,
		InvitationID:   stringPtr(invitation.ID),
		FullName:       invitation.Email,
		Email:          invitation.Email,
		Role:           role,
		Status:         "pending",
		CreatedAt:      invitation.CreatedAt,
		UpdatedAt:      invitation.UpdatedAt,
		WorkspaceCount: 1,
	}
}

func stringPtr(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func stringPtrValue(value any) *string {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case *configstoreTables.TableUserInvitation:
		if typed == nil {
			return nil
		}
		return stringPtr(typed.ID)
	case string:
		return stringPtr(typed)
	default:
		return nil
	}
}

func organizationOwnerID(organization *configstoreTables.TableOrganization) string {
	if organization == nil {
		return ""
	}
	return strings.TrimSpace(organization.OwnerID)
}
