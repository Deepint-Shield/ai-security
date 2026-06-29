package tables

import "time"

// TableGovernanceOrg is the top of the 3-tier scope hierarchy:
//
//	governance_orgs (this table)
//	  └─ organizations (tenants - existing TableOrganization)
//	       └─ workspaces (TableWorkspace)
//
// One organization owns many tenants. Each tenant continues to own many
// workspaces (1:N) - that relationship is unchanged.
//
// The org_id is opaque (UUID) and is intentionally never surfaced in the
// UI: callers identify orgs by name in interfaces and by id only on the
// wire. This keeps the dashboard mental model focused on tenants /
// workspaces while billing, top-level RBAC, and tenant lifecycle live
// at the org level.
type TableGovernanceOrg struct {
	ID          string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	Name        string    `gorm:"type:varchar(255);not null" json:"name"`
	Slug        string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"slug"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	OwnerUserID string    `gorm:"column:owner_user_id;type:varchar(255);not null;index" json:"owner_user_id"`
	Plan        string    `gorm:"type:varchar(50);not null;default:'free'" json:"plan"`
	CreatedAt   time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName overrides the default - we keep "governance_orgs" to avoid
// collision with the existing `organizations` table (which now
// semantically represents tenants).
func (TableGovernanceOrg) TableName() string { return "governance_orgs" }

// TableGovernanceOrgMembership records a user's role at the organisation
// level (above tenant-level memberships). Org-owner / org-admin roles can
// create or delete tenants within the org; org-member is implicit
// membership granted automatically when a user is added to any tenant
// in the org.
type TableGovernanceOrgMembership struct {
	ID             string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	OrganizationID string    `gorm:"column:organization_id;type:varchar(255);not null;uniqueIndex:idx_gov_org_member,priority:1" json:"organization_id"`
	UserID         string    `gorm:"column:user_id;type:varchar(255);not null;index;uniqueIndex:idx_gov_org_member,priority:2" json:"user_id"`
	Role           string    `gorm:"type:varchar(32);not null" json:"role"` // "owner" | "admin" | "member"
	CreatedAt      time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt      time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableGovernanceOrgMembership) TableName() string { return "governance_org_memberships" }

// Org-level roles. Mirrors the existing OrgRole* constants on tenants
// but lives at the higher level.
const (
	GovernanceOrgRoleOwner  = "owner"
	GovernanceOrgRoleAdmin  = "admin"
	GovernanceOrgRoleMember = "member"
)
