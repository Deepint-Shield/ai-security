package tables

import "time"

// TableTeamMember stores explicit workspace-user membership for a governance team.
type TableTeamMember struct {
	ID        string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID  string    `gorm:"column:tenant_id;type:varchar(255);index:idx_governance_team_members_tenant_team,priority:1;index:idx_governance_team_members_tenant_user,priority:1" json:"-"`
	TeamID    string    `gorm:"type:varchar(255);not null;index:idx_governance_team_members_tenant_team,priority:2;index:idx_governance_team_members_team_user,unique,priority:1" json:"team_id"`
	UserID    string    `gorm:"type:varchar(255);not null;index:idx_governance_team_members_tenant_user,priority:2;index:idx_governance_team_members_team_user,unique,priority:2" json:"user_id"`
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableTeamMember) TableName() string { return "governance_team_members" }
