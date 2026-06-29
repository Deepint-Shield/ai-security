package tables

import "time"

// Org-level roles. The owner is the user who created the org (or was
// designated owner during backfill); every org has exactly one owner. Admins
// can create workspaces and manage memberships; members are read-only at the
// org level and may still be granted higher roles inside individual
// workspaces.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// Workspace-level roles. Admins can edit workspace settings (including
// workspace-scoped guardrails) and manage workspace memberships; members can
// use everything inside the workspace; viewers are read-only.
const (
	WorkspaceRoleAdmin  = "admin"
	WorkspaceRoleMember = "member"
	WorkspaceRoleViewer = "viewer"
)

// TableOrgMembership records a user's membership at the TENANT level of
// the 3-tier hierarchy (governance_orgs → organizations/tenants →
// workspaces). The historical name "org_memberships" predates the
// org/tenant split; what's now called an organization at the top tier
// lives in TableGovernanceOrg + TableGovernanceOrgMembership, and what
// this table calls org_id is really the tenant id.
//
// (org_id, user_id) is unique - a user cannot have two roles in the
// same tenant. Org-level (above-tenant) membership lives in
// TableGovernanceOrgMembership. Workspace-level (below-tenant)
// membership lives in TableWorkspaceMembership below.
//
// DO NOT collapse this with TableGovernanceOrgMembership - they
// model different scopes. CanManageTenant in workspace_permissions.go
// reads this table; CanManageOrg reads the governance one.
type TableOrgMembership struct {
	ID        string    `gorm:"type:varchar(64);primaryKey" json:"id"`
	OrgID     string    `gorm:"column:org_id;type:varchar(255);not null;index;index:idx_org_mem_org_user,unique,priority:1" json:"org_id"`
	UserID    string    `gorm:"column:user_id;type:varchar(255);not null;index;index:idx_org_mem_org_user,unique,priority:2" json:"user_id"`
	Role      string    `gorm:"type:varchar(50);not null;default:'member';index" json:"role"`
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableOrgMembership) TableName() string { return "org_memberships" }

// TableWorkspaceMembership records a user's membership in a workspace with a
// role. (workspace_id, user_id) is unique. org_id is denormalized for cheap
// "all workspaces I can access in org X" lookups without a join.
type TableWorkspaceMembership struct {
	ID          string    `gorm:"type:varchar(64);primaryKey" json:"id"`
	WorkspaceID string    `gorm:"column:workspace_id;type:varchar(64);not null;index;index:idx_ws_mem_ws_user,unique,priority:1" json:"workspace_id"`
	OrgID       string    `gorm:"column:org_id;type:varchar(255);not null;index" json:"org_id"`
	UserID      string    `gorm:"column:user_id;type:varchar(255);not null;index;index:idx_ws_mem_ws_user,unique,priority:2" json:"user_id"`
	Role        string    `gorm:"type:varchar(50);not null;default:'member';index" json:"role"`
	CreatedAt   time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableWorkspaceMembership) TableName() string { return "workspace_memberships" }
