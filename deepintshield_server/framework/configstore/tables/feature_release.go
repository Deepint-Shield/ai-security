package tables

import "time"

// TableFeatureRelease is the control-plane registry of opt-in feature releases.
//
// A release advertises a single entitlement `feature_key` that an organization
// can enable for itself ("Update") once a super-admin marks the release
// `available` and in-scope for the org's tier (and, optionally, a specific org
// allowlist for canarying). Applying a release upserts a
// `billing_entitlement_overrides` row (BoolValue=true) for that feature_key -
// which `billing.resolveFeature` reads directly from the database on every
// check. The flip therefore takes effect immediately, is scoped to the single
// tenant, and is fully reversible, with no binary swap, no schema migration, and
// no per-request cache to invalidate.
type TableFeatureRelease struct {
	ID          string `gorm:"type:varchar(255);primaryKey" json:"id"`
	FeatureKey  string `gorm:"type:varchar(120);not null;index" json:"feature_key"`
	Version     string `gorm:"type:varchar(40)" json:"version,omitempty"`
	Title       string `gorm:"type:varchar(200);not null" json:"title"`
	Description string `gorm:"type:text" json:"description,omitempty"`
	// Status governs visibility: "draft" (hidden from orgs), "available" (orgs in
	// scope see an Update button), "deprecated" (no longer offered; already-applied
	// orgs keep the feature).
	Status string `gorm:"type:varchar(20);not null;default:'draft';index" json:"status"`
	// TargetTiers is a comma-separated allowlist of plan ids (e.g. "business,enterprise").
	// Empty means every tier is in scope.
	TargetTiers string `gorm:"type:text" json:"target_tiers,omitempty"`
	// TargetOrgs is a comma-separated allowlist of tenant ids (org.ID). Empty means
	// all orgs (subject to TargetTiers); set it to canary a release to specific orgs.
	TargetOrgs  string     `gorm:"type:text" json:"target_orgs,omitempty"`
	CreatedAt   time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time  `gorm:"index;not null" json:"updated_at"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

func (TableFeatureRelease) TableName() string { return "feature_releases" }
