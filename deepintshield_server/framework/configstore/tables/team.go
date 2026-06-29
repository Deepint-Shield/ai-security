package tables

import (
	"encoding/json"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"gorm.io/gorm"
)

// TableTeam represents a team entity with budget, rate limit and customer association
type TableTeam struct {
	ID       string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index" json:"-"`
	// WorkspaceID narrows the team to a single workspace within the tenant.
	// NULL = tenant-wide (visible in every workspace under this tenant);
	// non-NULL = scoped to that workspace only. Mirrors the same pattern
	// used by TableProvider / TableVirtualKey / TableGuardrailPolicy.
	WorkspaceID *string `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"`
	Name        string  `gorm:"type:varchar(255);not null" json:"name"`
	CustomerID  *string `gorm:"type:varchar(255);index" json:"customer_id,omitempty"` // A team can belong to a customer
	BudgetID    *string `gorm:"type:varchar(255);index" json:"budget_id,omitempty"`
	RateLimitID *string `gorm:"type:varchar(255);index" json:"rate_limit_id,omitempty"`

	// Relationships
	Customer        *TableCustomer    `gorm:"foreignKey:CustomerID" json:"customer,omitempty"`
	Budget          *TableBudget      `gorm:"foreignKey:BudgetID" json:"budget,omitempty"`
	RateLimit       *TableRateLimit   `gorm:"foreignKey:RateLimitID" json:"rate_limit,omitempty"`
	VirtualKeys     []TableVirtualKey `gorm:"foreignKey:TeamID" json:"virtual_keys"`
	Members         []TableAuthUser   `gorm:"-" json:"members,omitempty"`
	CustomerMembers []TableCustomer   `gorm:"-" json:"member_customers,omitempty"`

	Profile       *string                `gorm:"type:text" json:"-"`
	ParsedProfile map[string]interface{} `gorm:"-" json:"profile"`

	Config       *string                `gorm:"type:text" json:"-"`
	ParsedConfig map[string]interface{} `gorm:"-" json:"config"`

	Claims       *string                `gorm:"type:text" json:"-"`
	ParsedClaims map[string]interface{} `gorm:"-" json:"claims"`

	// AllowedTools was removed in the per-policy targeting consolidation.
	// Team-level entitlements now live as agentic policies with a row in
	// agentic_policy_team_targets - see migrationDeriveVKScopedPolicies.
	// The drop-column migration removes the underlying schema column.

	// Config hash is used to detect the changes synced from config.json file
	// Every time we sync the config.json file, we will update the config hash
	ConfigHash string `gorm:"type:varchar(255);null" json:"config_hash"`

	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the table name for each model
func (TableTeam) TableName() string { return "governance_teams" }

// BeforeSave hook for TableTeam to serialize JSON fields
func (t *TableTeam) BeforeSave(tx *gorm.DB) error {
	if t.ParsedProfile != nil {
		data, err := json.Marshal(t.ParsedProfile)
		if err != nil {
			return err
		}
		t.Profile = deepintshield.Ptr(string(data))
	} else {
		t.Profile = nil
	}
	if t.ParsedConfig != nil {
		data, err := json.Marshal(t.ParsedConfig)
		if err != nil {
			return err
		}
		t.Config = deepintshield.Ptr(string(data))
	} else {
		t.Config = nil
	}
	if t.ParsedClaims != nil {
		data, err := json.Marshal(t.ParsedClaims)
		if err != nil {
			return err
		}
		t.Claims = deepintshield.Ptr(string(data))
	} else {
		t.Claims = nil
	}
	return nil
}

// AfterFind hook for TableTeam to deserialize JSON fields
func (t *TableTeam) AfterFind(tx *gorm.DB) error {
	if t.Profile != nil {
		if err := json.Unmarshal([]byte(*t.Profile), &t.ParsedProfile); err != nil {
			return err
		}
	}
	if t.Config != nil {
		if err := json.Unmarshal([]byte(*t.Config), &t.ParsedConfig); err != nil {
			return err
		}
	}
	if t.Claims != nil {
		if err := json.Unmarshal([]byte(*t.Claims), &t.ParsedClaims); err != nil {
			return err
		}
	}
	return nil
}
