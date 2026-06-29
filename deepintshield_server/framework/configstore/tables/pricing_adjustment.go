package tables

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// PricingAdjustmentMode selects between the simplified per-token-type
// multiplier form and a free-form JSON expression for advanced
// per-modality / per-additional-unit cost adjustments.
const (
	PricingAdjustmentModeDefault = "default"
	PricingAdjustmentModeCustom  = "custom"
)

// TablePricingAdjustment is a per-integration multiplier applied on top
// of the upstream model-pricing catalogue (see TableModelPricing).
//
// Shape mirrors the industry-standard pricing-adjustment pattern: a
// scalar default multiplier plus optional per-token-type overrides.
// Values are decimals (1.0 = no change, 0.8 = 20% discount, 1.2 = 20%
// markup). When Mode == "custom", CustomJSON carries an extended
// per-modality / per-additional-unit map; the default multipliers are
// ignored in that mode.
//
// Per-tenant scoping via TenantID; optional WorkspaceID narrows further
// to a single workspace within the tenant.
type TablePricingAdjustment struct {
	ID          string  `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID    string  `gorm:"column:tenant_id;type:varchar(255);index;not null" json:"-"`
	WorkspaceID *string `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"`
	Name        string  `gorm:"type:varchar(255);not null" json:"name"`

	// Integration is the provider identifier this adjustment applies
	// to (e.g. "openai", "anthropic", "bedrock"). Required so the
	// runtime knows which traffic to scale.
	Integration string `gorm:"type:varchar(64);not null;index" json:"integration"`

	// Mode: "default" uses the per-token-type multiplier fields below.
	// "custom" defers to CustomJSON.
	Mode string `gorm:"type:varchar(32);not null;default:'default'" json:"mode"`

	// Default multiplier applies to every token type that doesn't have
	// a more specific override below. 1.0 = unchanged.
	DefaultMultiplier float64 `gorm:"not null;default:1.0;column:default_multiplier" json:"default_multiplier"`

	// Per-token-type overrides. NULL means "fall through to
	// DefaultMultiplier". 0 is a valid value (zero out the cost).
	RequestTokenMultiplier  *float64 `gorm:"column:request_token_multiplier" json:"request_token_multiplier,omitempty"`
	ResponseTokenMultiplier *float64 `gorm:"column:response_token_multiplier" json:"response_token_multiplier,omitempty"`
	CacheReadMultiplier     *float64 `gorm:"column:cache_read_multiplier" json:"cache_read_multiplier,omitempty"`
	CacheWriteMultiplier    *float64 `gorm:"column:cache_write_multiplier" json:"cache_write_multiplier,omitempty"`

	// CustomJSON: opaque to the table; the runtime parses it. Only
	// consulted when Mode == "custom".
	CustomJSON string `gorm:"column:custom_json;type:text" json:"custom_json,omitempty"`

	Enabled   bool      `gorm:"default:true;index" json:"enabled"`
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TablePricingAdjustment) TableName() string { return "pricing_adjustments" }

func (p *TablePricingAdjustment) BeforeSave(tx *gorm.DB) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	p.Integration = strings.ToLower(strings.TrimSpace(p.Integration))
	if p.Integration == "" {
		return fmt.Errorf("integration is required")
	}
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode == "" {
		p.Mode = PricingAdjustmentModeDefault
	}
	if p.Mode != PricingAdjustmentModeDefault && p.Mode != PricingAdjustmentModeCustom {
		return fmt.Errorf("mode must be 'default' or 'custom'")
	}
	if p.Mode == PricingAdjustmentModeDefault && p.DefaultMultiplier < 0 {
		return fmt.Errorf("default_multiplier must be non-negative")
	}
	return nil
}
