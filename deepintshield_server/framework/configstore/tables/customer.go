package tables

import "time"

// TableCustomer represents a customer entity with budget and rate limit
type TableCustomer struct {
	ID       string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index" json:"-"`
	// WorkspaceID narrows the customer to a single workspace within the
	// tenant. NULL = tenant-wide (visible in every workspace under this
	// tenant); non-NULL = scoped to that workspace only. Mirrors the
	// same pattern used by TableProvider / TableTeam / TableVirtualKey.
	WorkspaceID *string `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"`
	Name        string  `gorm:"type:varchar(255);not null" json:"name"`
	BudgetID    *string `gorm:"type:varchar(255);index" json:"budget_id,omitempty"`
	RateLimitID *string `gorm:"type:varchar(255);index" json:"rate_limit_id,omitempty"`

	// Relationships
	Budget      *TableBudget      `gorm:"foreignKey:BudgetID" json:"budget,omitempty"`
	RateLimit   *TableRateLimit   `gorm:"foreignKey:RateLimitID" json:"rate_limit,omitempty"`
	Teams       []TableTeam       `gorm:"foreignKey:CustomerID" json:"teams"`
	VirtualKeys []TableVirtualKey `gorm:"foreignKey:CustomerID" json:"virtual_keys"`

	// AllowedTools was removed in the per-policy targeting consolidation.
	// Member-level entitlements now live as agentic policies with a row in
	// agentic_policy_member_targets. The drop-column migration removes the
	// underlying schema column.

	// Config hash is used to detect the changes synced from config.json file
	// Every time we sync the config.json file, we will update the config hash
	ConfigHash string `gorm:"type:varchar(255);null" json:"config_hash"`

	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the table name for each model
func (TableCustomer) TableName() string { return "governance_customers" }
