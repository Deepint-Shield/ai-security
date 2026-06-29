package tables

import "time"

// TableTeamCustomerMember stores explicit governance-member membership for a governance team.
type TableTeamCustomerMember struct {
	ID         string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID   string    `gorm:"column:tenant_id;type:varchar(255);index:idx_governance_team_customer_members_tenant_team,priority:1;index:idx_governance_team_customer_members_tenant_customer,priority:1" json:"-"`
	TeamID     string    `gorm:"type:varchar(255);not null;index:idx_governance_team_customer_members_tenant_team,priority:2;index:idx_governance_team_customer_members_team_customer,unique,priority:1" json:"team_id"`
	CustomerID string    `gorm:"type:varchar(255);not null;index:idx_governance_team_customer_members_tenant_customer,priority:2;index:idx_governance_team_customer_members_team_customer,unique,priority:2" json:"customer_id"`
	CreatedAt  time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableTeamCustomerMember) TableName() string { return "governance_team_customer_members" }
