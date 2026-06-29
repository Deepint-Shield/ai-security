package tables

import "time"

// TableOrganization stores user-editable workspace metadata.
// DeepIntShield now uses the normalized account email as the tenant_id key, and
// organization rows are keyed by that same email-scoped tenant identifier.
type TableOrganization struct {
	ID          string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	// OrganizationID points at the parent governance_orgs row in the
	// 3-tier hierarchy (org → tenant → workspace). Backfilled by
	// migrationAdd3TierOrgs. Never NULL after the migration runs.
	OrganizationID string `gorm:"column:organization_id;type:varchar(255);index" json:"-"`
	Name        string    `gorm:"type:varchar(255);not null" json:"name"`
	Slug        string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"slug"`
	Description string    `gorm:"type:text" json:"description"`
	OwnerID     string    `gorm:"type:varchar(255);not null;index" json:"owner_id"`
	Plan        string    `gorm:"type:varchar(50);not null;default:'free'" json:"plan"`
	CreatedAt   time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the table name for each model
func (TableOrganization) TableName() string { return "organizations" }
