package tables

import "time"

// TableTenantAlias maps a stable lookup key (a normalized account email, or a
// legacy email-keyed tenant id) to the canonical tenant id (a UUID). It is the
// permanent index that lets the platform resolve a person's login email to
// their UUID-keyed tenant without keying the tenant on the email itself -
// decoupling tenant identity from any individual, so offboarding / email reuse
// can't break or hijack a tenant.
//
// Note: this row carries tenant_id so a re-key (MigrateTenantIDs) repoints the
// alias to the new canonical id along with everything else.
type TableTenantAlias struct {
	AliasKey  string    `gorm:"column:alias_key;type:varchar(255);primaryKey" json:"alias_key"`
	TenantID  string    `gorm:"column:tenant_id;type:varchar(255);not null;index" json:"tenant_id"`
	Kind      string    `gorm:"column:kind;type:varchar(32);index" json:"kind"` // "email" | "legacy"
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

func (TableTenantAlias) TableName() string { return "tenant_aliases" }
