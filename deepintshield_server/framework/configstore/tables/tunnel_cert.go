package tables

import "time"

// TableTunnelCert records each Enterprise-VPC tunnel client certificate issued
// by the control-plane CA (framework/tunnelpki). One row per issuance; the
// tunnel endpoints consult it to reject revoked serials. The private key is
// never stored - only issuance metadata.
type TableTunnelCert struct {
	ID        string     `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID  string     `gorm:"column:tenant_id;type:varchar(255);not null;index" json:"tenant_id"`
	Serial    string     `gorm:"type:varchar(64);not null;uniqueIndex" json:"serial"`
	SHA256    string     `gorm:"column:sha256;type:varchar(128);index" json:"sha256"`
	IssuedBy  string     `gorm:"column:issued_by;type:varchar(255)" json:"issued_by"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `gorm:"index" json:"not_after"`
	RevokedAt *time.Time `gorm:"column:revoked_at;index" json:"revoked_at,omitempty"`
	CreatedAt time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableTunnelCert) TableName() string { return "governance_tunnel_certs" }
