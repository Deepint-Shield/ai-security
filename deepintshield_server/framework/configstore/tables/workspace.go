package tables

import "time"

// TableWorkspace is a sub-tenant container scoped to an organization. Every
// organization has exactly one default workspace (is_default=true) created
// automatically on backfill / org creation; admins may create additional
// workspaces to isolate environments (e.g. dev/staging/prod) without spinning
// up new tenants.
//
// (org_id, slug) is unique. (org_id, is_default=true) is enforced to be at
// most one row in application code - Postgres partial unique indexes are not
// emitted reliably across the dialects this repo supports.
type TableWorkspace struct {
	ID          string    `gorm:"type:varchar(64);primaryKey" json:"id"`
	OrgID       string    `gorm:"column:org_id;type:varchar(255);not null;index;index:idx_workspaces_org_slug,unique,priority:1" json:"org_id"`
	Name        string    `gorm:"type:varchar(255);not null" json:"name"`
	Slug        string    `gorm:"type:varchar(255);not null;index:idx_workspaces_org_slug,unique,priority:2" json:"slug"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	IsDefault   bool      `gorm:"column:is_default;default:false;index" json:"is_default"`
	CreatedBy   string    `gorm:"column:created_by;type:varchar(255);index" json:"created_by"`
	CreatedAt   time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableWorkspace) TableName() string { return "workspaces" }
