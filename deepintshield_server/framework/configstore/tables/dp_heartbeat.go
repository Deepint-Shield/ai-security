package tables

import "time"

// TableDPHeartbeat records the last-seen running image version of an
// Enterprise-VPC data plane, keyed by its tunnel scope id (the governance org
// for a one-DP-per-org deployment, or the tenant for a legacy per-tenant DP).
// Upserted on every config poll (the plane-agent sends X-DIS-DP-Version), so the
// admin console can show "org X DP is on 2.0.0 (latest 2.1.0)" and flag
// data planes running an outdated image. Pure visibility - never gates serving.
type TableDPHeartbeat struct {
	TenantID   string    `gorm:"column:tenant_id;type:varchar(255);primaryKey" json:"tenant_id"`
	ScopeKind  string    `gorm:"column:scope_kind;type:varchar(16)" json:"scope_kind"` // "org" | "tenant"
	DPVersion  string    `gorm:"column:dp_version;type:varchar(64)" json:"dp_version"`
	LastSeenAt time.Time `gorm:"column:last_seen_at;index" json:"last_seen_at"`
	CreatedAt  time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"not null" json:"updated_at"`
}

func (TableDPHeartbeat) TableName() string { return "governance_dp_heartbeats" }
