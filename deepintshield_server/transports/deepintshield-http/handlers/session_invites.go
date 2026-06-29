package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/encrypt"
	"github.com/valyala/fasthttp"
)

func (h *SessionHandler) getInvitationDetails(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	invitation, err := h.getActiveInvitationByToken(ctx, string(ctx.QueryArgs().Peek("token")))
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	tenant, err := h.configStore.GetOrganizationByID(context.Background(), invitation.TenantID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load invited workspace: %v", err))
		return
	}

	// The invite is to a TENANT (e.g. "dev"); that's what "Invited to …"
	// should show. The Organization field, however, must reflect the parent
	// org (the super-user's governance_org, e.g. "DeepintShield") - the
	// invitee joins that org, not a new org named after the tenant.
	tenantName := organizationName(tenant)
	orgName := ""
	if tenant != nil && strings.TrimSpace(tenant.OrganizationID) != "" {
		if govOrg, gErr := h.configStore.GetGovernanceOrgByID(context.Background(), strings.TrimSpace(tenant.OrganizationID)); gErr == nil && govOrg != nil {
			orgName = strings.TrimSpace(govOrg.Name)
		}
	}
	if orgName == "" {
		orgName = tenantName // legacy invitations with no parent org
	}

	SendJSON(ctx, map[string]any{
		"invitation": map[string]any{
			"email":        invitation.Email,
			"role":         invitation.Role,
			"organization": orgName,    // parent org (super-user's org) - fills the Organization field
			"tenant_name":  tenantName, // the tenant invited to - for "Invited to {tenant}"
			"expires_at":   invitation.ExpiresAt,
		},
	})
}

func (h *SessionHandler) getActiveInvitationByToken(_ context.Context, rawToken string) (*tables.TableUserInvitation, error) {
	if h.configStore == nil {
		return nil, fmt.Errorf("authentication store is not available")
	}

	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("Invitation token is required")
	}

	invitation, err := h.configStore.GetUserInvitationByHash(context.Background(), encrypt.HashSHA256(rawToken))
	if err != nil {
		return nil, err
	}
	if invitation == nil {
		return nil, fmt.Errorf("Invitation link is invalid or has expired")
	}
	if invitation.AcceptedAt != nil {
		return nil, fmt.Errorf("Invitation has already been accepted")
	}
	if time.Now().After(invitation.ExpiresAt) {
		return nil, fmt.Errorf("Invitation link is invalid or has expired")
	}
	return invitation, nil
}

func (h *SessionHandler) acceptInvitationForVerifiedUser(ctx context.Context, user *tables.TableAuthUser, acceptedAt time.Time) error {
	if h == nil || h.configStore == nil || user == nil || strings.TrimSpace(user.Email) == "" || strings.TrimSpace(user.TenantID) == "" {
		return nil
	}

	tenantCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, user.TenantID)
	invitation, err := h.configStore.GetUserInvitationByEmail(tenantCtx, user.Email)
	if err != nil || invitation == nil {
		return err
	}
	if invitation.AcceptedAt != nil {
		return nil
	}
	invitation.AcceptedAt = &acceptedAt
	return h.configStore.UpdateUserInvitation(tenantCtx, invitation)
}

// applyPendingInvitationForNewUser hooks every signup path (email,
// Google, Entra) so that whatever workspace the user was invited to is
// reflected as a real workspace_membership the moment they finish
// authenticating. Without this:
//
//   - The invitation row sits in user_invitations forever.
//   - The new user signs in with their fresh home tenant only, sees
//     nothing about the invited workspace, and the inviter's UI shows
//     them stuck in "Pending invite" status.
//
// Idempotent: skips if the invitation is already marked accepted, or
// if the user already has the membership rows. Uses background context
// throughout so the GORM tenant-scoping callback doesn't filter out
// rows in a tenant the user doesn't yet belong to.
//
// Targeting:
//   - org_membership row in invitation.TenantID, role=member
//   - workspace_membership row in invitation.WorkspaceID (if set), or
//     the tenant's Default workspace as a fallback for legacy
//     invitations that pre-date the workspace_id column
//   - Workspace role mirrors the invite role: admin → WorkspaceRoleAdmin,
//     viewer/member → WorkspaceRoleMember
func (h *SessionHandler) applyPendingInvitationForNewUser(user *tables.TableAuthUser) {
	if h == nil || h.configStore == nil || user == nil {
		return
	}
	email := strings.ToLower(strings.TrimSpace(user.Email))
	if email == "" {
		return
	}
	bg := context.Background()
	invitation, err := h.configStore.GetUserInvitationByEmail(bg, email)
	if err != nil || invitation == nil {
		return
	}
	// IMPORTANT: do NOT bail on already-accepted invitations.
	// verifyEmail calls acceptInvitationForVerifiedUser BEFORE this
	// helper, which stamps AcceptedAt up-front. If we returned here,
	// the membership rows would never get created and the invitee
	// would log in to an empty home tenant ("No tenants available").
	// The CreateOrgMembership / CreateWorkspaceMembership calls below
	// are idempotent (they check GetOrgMembership / GetWorkspaceMembership
	// first), so re-running this on an accepted invitation is safe and
	// repairs any historical gap.
	if time.Now().After(invitation.ExpiresAt) {
		return
	}
	tenantID := strings.TrimSpace(invitation.TenantID)
	if tenantID == "" {
		return
	}

	// Resolve target workspace. Prefer the invitation's explicit
	// workspace_id; fall back to the tenant's Default workspace for
	// legacy invitations that pre-date the workspace_id column.
	var targetWS *tables.TableWorkspace
	if invitation.WorkspaceID != nil && strings.TrimSpace(*invitation.WorkspaceID) != "" {
		ws, _ := h.configStore.GetWorkspaceByID(bg, strings.TrimSpace(*invitation.WorkspaceID))
		targetWS = ws
	}
	if targetWS == nil {
		// Default workspace fallback: scan tenant workspaces for the
		// is_default row. Cheap - typically one row.
		workspaces, _ := h.configStore.ListWorkspacesByOrg(bg, tenantID)
		for i := range workspaces {
			if workspaces[i].IsDefault {
				targetWS = &workspaces[i]
				break
			}
		}
		if targetWS == nil && len(workspaces) > 0 {
			targetWS = &workspaces[0]
		}
	}

	now := time.Now().UTC()

	// Tenant-level membership so the parent tenant shows in the
	// invitee's tenant switcher. Idempotent.
	if existing, _ := h.configStore.GetOrgMembership(bg, tenantID, user.ID); existing == nil {
		_ = h.configStore.CreateOrgMembership(bg, &tables.TableOrgMembership{
			ID:        "om-" + strings.ReplaceAll(invitation.ID, "-", "")[:24],
			OrgID:     tenantID,
			UserID:    user.ID,
			Role:      tables.OrgRoleMember,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	// Workspace-level membership. Map invite role onto workspace role:
	// admin → workspace admin, anything else → workspace member.
	if targetWS != nil {
		wsRole := tables.WorkspaceRoleMember
		if strings.EqualFold(invitation.Role, tables.UserRoleAdmin) {
			wsRole = tables.WorkspaceRoleAdmin
		}
		if existing, _ := h.configStore.GetWorkspaceMembership(bg, targetWS.ID, user.ID); existing == nil {
			_ = h.configStore.CreateWorkspaceMembership(bg, &tables.TableWorkspaceMembership{
				ID:          "wsm-" + strings.ReplaceAll(invitation.ID, "-", "")[:24],
				WorkspaceID: targetWS.ID,
				OrgID:       targetWS.OrgID,
				UserID:      user.ID,
				Role:        wsRole,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
	}

	// Mark invitation as accepted so re-signup attempts (or "Resend
	// invite" flows) don't replay this work.
	invitation.AcceptedAt = &now
	_ = h.configStore.UpdateUserInvitation(bg, invitation)
}

func organizationName(organization *tables.TableOrganization) string {
	if organization == nil || strings.TrimSpace(organization.Name) == "" {
		return "Workspace"
	}
	return strings.TrimSpace(organization.Name)
}
