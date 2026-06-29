package configstore

import (
	"context"
	"errors"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// EnsureWorkspaceBackfill makes the workspace + membership rows consistent
// with the *current* state of organizations and auth_users. It's intended
// to run on every server bootstrap, after BackfillEmailScopedTenancy has
// settled organizations.id values.
//
// Why a separate, post-migration pass: the in-tree workspaces/memberships
// migration runs during triggerMigrations (when the config store opens),
// which happens *before* the email-tenancy backfill renames organizations.
// Memberships seeded by that migration may therefore reference org IDs
// that the rename later orphans, and any user whose rename collided
// ends up with no matching org at all. This function repairs that state
// idempotently - every guard short-circuits on already-good rows so it's
// safe to call on every boot.
//
// Behaviour:
//   - For every organisation row, ensure a Default workspace exists.
//   - For every auth_user with a non-empty tenant_id:
//   - if an org with id = user.tenant_id exists, ensure (org_membership,
//     workspace_membership in default ws). User becomes "owner" if they
//     match orgs.owner_id, "admin" otherwise.
//   - if not, fall back to looking up an org by owner_id = user.ID and
//     correcting the user's tenant_id to point at that org's id, then
//     seating memberships there. This is the collision-skip recovery
//     path: the user's auth_users.tenant_id was renamed to email but
//     their organizations row kept its old UUID.
func (s *RDBConfigStore) EnsureWorkspaceBackfill(ctx context.Context) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. Default workspace per org.
		var orgs []tables.TableOrganization
		if err := tx.Find(&orgs).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, org := range orgs {
			if err := ensureDefaultWorkspace(tx, org, now); err != nil {
				return err
			}
		}

		// 2. Memberships per user.
		var users []tables.TableAuthUser
		if err := tx.
			Where("tenant_id IS NOT NULL AND tenant_id <> ''").
			Find(&users).Error; err != nil {
			return err
		}
		for _, u := range users {
			if err := ensureUserMemberships(tx, u, now); err != nil {
				return err
			}
		}

		return nil
	})
}

func ensureDefaultWorkspace(tx *gorm.DB, org tables.TableOrganization, now time.Time) error {
	// Skip entirely when the org already owns at least one workspace -
	// even if none is flagged is_default. With the post-signup flow
	// users create workspaces by hand (no auto-Default at signup or at
	// tenant creation), and those rows land with is_default = false.
	// Without this guard every restart would mint a fresh "Default"
	// workspace alongside the user's own, and the scope switcher (which
	// prefers is_default = true on hydrate) would auto-land the user on
	// the synthetic Default - making it look like their real workspace
	// disappeared.
	var anyCount int64
	if err := tx.Model(&tables.TableWorkspace{}).
		Where("org_id = ?", org.ID).
		Count(&anyCount).Error; err != nil {
		return err
	}
	if anyCount > 0 {
		return nil
	}
	// Genuinely zero workspaces - leave the org empty. The UI gate
	// (TenantWorkspaceGate) redirects to /workspace/governance/workspaces
	// when there's no active workspace, and the workspaces page
	// auto-opens the create-workspace sheet. So we no longer need to
	// fabricate a Default here.
	_ = now
	return nil
}

func ensureUserMemberships(tx *gorm.DB, u tables.TableAuthUser, now time.Time) error {
	// Resolve the org this user actually belongs to. Preferred path:
	// match by tenant_id. Fallback path: match by owner_id and self-heal
	// the user's tenant_id so future requests resolve correctly.
	var org tables.TableOrganization
	err := tx.Where("id = ?", u.TenantID).First(&org).Error
	switch {
	case err == nil:
		// good
	case errors.Is(err, gorm.ErrRecordNotFound):
		// Fallback: did this user own an org with a different ID?
		if fbErr := tx.Where("owner_id = ?", u.ID).First(&org).Error; fbErr != nil {
			if errors.Is(fbErr, gorm.ErrRecordNotFound) {
				return nil // genuinely no org - leave alone, don't fabricate
			}
			return fbErr
		}
		if u.TenantID != org.ID {
			if uErr := tx.Model(&tables.TableAuthUser{}).
				Where("id = ?", u.ID).
				Update("tenant_id", org.ID).Error; uErr != nil {
				return uErr
			}
			u.TenantID = org.ID
		}
	default:
		return err
	}

	// Ensure org membership.
	var orgMemCount int64
	if err := tx.Model(&tables.TableOrgMembership{}).
		Where("org_id = ? AND user_id = ?", org.ID, u.ID).
		Count(&orgMemCount).Error; err != nil {
		return err
	}
	if orgMemCount == 0 {
		role := tables.OrgRoleAdmin
		if org.OwnerID == u.ID {
			role = tables.OrgRoleOwner
		}
		if err := tx.Create(&tables.TableOrgMembership{
			ID:        "om-" + uuid.New().String(),
			OrgID:     org.ID,
			UserID:    u.ID,
			Role:      role,
			CreatedAt: now,
			UpdatedAt: now,
		}).Error; err != nil {
			return err
		}
	}

	// Ensure workspace membership in the org's default workspace.
	var ws tables.TableWorkspace
	wsErr := tx.Where("org_id = ? AND is_default = ?", org.ID, true).First(&ws).Error
	if wsErr != nil {
		if errors.Is(wsErr, gorm.ErrRecordNotFound) {
			return nil // ensureDefaultWorkspace runs in the same tx earlier; if missing, skip
		}
		return wsErr
	}
	var wsMemCount int64
	if err := tx.Model(&tables.TableWorkspaceMembership{}).
		Where("workspace_id = ? AND user_id = ?", ws.ID, u.ID).
		Count(&wsMemCount).Error; err != nil {
		return err
	}
	if wsMemCount > 0 {
		return nil
	}
	wsRole := tables.WorkspaceRoleAdmin
	if org.OwnerID != u.ID {
		// Org admins get workspace admin too, by current convention.
		wsRole = tables.WorkspaceRoleAdmin
	}
	return tx.Create(&tables.TableWorkspaceMembership{
		ID:          "wm-" + uuid.New().String(),
		WorkspaceID: ws.ID,
		OrgID:       org.ID,
		UserID:      u.ID,
		Role:        wsRole,
		CreatedAt:   now,
		UpdatedAt:   now,
	}).Error
}
