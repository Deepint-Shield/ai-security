package tables

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// TableModelOverride is a per-tenant absolute-cost override for a
// specific model in the upstream catalogue (see TableModelPricing).
// Used when an org has negotiated provider pricing different from the
// public list - e.g. a discounted enterprise rate for gpt-4-turbo -
// and wants the cost accounting in DeepintShield to reflect that.
//
// Cost values are USD per *1,000,000* tokens - chosen so the admin
// types human-friendly numbers like 5.00, 10.00 rather than 0.000005.
// The request-time runtime converts to per-token before applying.
//
// Per-tenant scoping; optional WorkspaceID narrows to a workspace.
type TableModelOverride struct {
	ID          string  `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID    string  `gorm:"column:tenant_id;type:varchar(255);index;not null" json:"-"`
	WorkspaceID *string `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"`

	// Model + Provider identify the catalogue row this override targets.
	// Provider is optional - empty matches the model across every
	// provider that exposes it. Both are case-insensitive and
	// normalised in BeforeSave.
	Model    string `gorm:"type:varchar(255);not null;index" json:"model"`
	Provider string `gorm:"type:varchar(64);index" json:"provider,omitempty"`

	// Absolute costs per 1M tokens. NULL = "leave the catalogue value
	// alone for this side"; either or both may be overridden.
	InputCostPerMillionTokens  *float64 `gorm:"column:input_cost_per_million" json:"input_cost_per_million_tokens,omitempty"`
	OutputCostPerMillionTokens *float64 `gorm:"column:output_cost_per_million" json:"output_cost_per_million_tokens,omitempty"`

	// Notes is a free-text field the admin uses to record why the
	// override exists (e.g. "Annual contract negotiated 2026-04, see
	// procurement ticket #1234"). Surfaced in the list view so audit
	// reviewers can see the provenance without digging through tickets.
	Notes string `gorm:"type:text" json:"notes,omitempty"`

	Enabled   bool      `gorm:"default:true;index" json:"enabled"`
	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableModelOverride) TableName() string { return "model_overrides" }

func (m *TableModelOverride) BeforeSave(tx *gorm.DB) error {
	m.Model = strings.TrimSpace(m.Model)
	if m.Model == "" {
		return fmt.Errorf("model is required")
	}
	m.Provider = strings.ToLower(strings.TrimSpace(m.Provider))
	if m.InputCostPerMillionTokens == nil && m.OutputCostPerMillionTokens == nil {
		return fmt.Errorf("at least one of input_cost_per_million_tokens or output_cost_per_million_tokens must be set")
	}
	if m.InputCostPerMillionTokens != nil && *m.InputCostPerMillionTokens < 0 {
		return fmt.Errorf("input_cost_per_million_tokens must be non-negative")
	}
	if m.OutputCostPerMillionTokens != nil && *m.OutputCostPerMillionTokens < 0 {
		return fmt.Errorf("output_cost_per_million_tokens must be non-negative")
	}
	return nil
}
