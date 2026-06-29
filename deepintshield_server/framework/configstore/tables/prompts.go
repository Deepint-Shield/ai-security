// Package tables provides tables for the configstore
package tables

import (
	"time"
)

// TablePrompt represents a prompt entity that can have multiple versions and sessions
type TablePrompt struct {
	ID       string `gorm:"type:varchar(36);primaryKey" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index" json:"-"`
	// WorkspaceID narrows the prompt to a single workspace within the
	// tenant. NULL = org-wide / legacy (visible to every workspace in the
	// tenant). PromptVersion + PromptSession inherit scope through
	// PromptID - only the parent row carries the column.
	WorkspaceID *string      `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	Name        string       `gorm:"type:varchar(255);not null" json:"name"`
	FolderID    *string      `gorm:"type:varchar(36);index" json:"folder_id,omitempty"`
	Folder      *TableFolder `gorm:"foreignKey:FolderID;constraint:OnDelete:CASCADE" json:"folder,omitempty"`
	CreatedAt   time.Time    `gorm:"not null" json:"created_at"`
	UpdatedAt   time.Time    `gorm:"not null" json:"updated_at"`
	ConfigHash  string       `gorm:"type:varchar(64)" json:"-"`

	// Relationships
	Versions []TablePromptVersion `gorm:"foreignKey:PromptID;constraint:OnDelete:CASCADE" json:"versions,omitempty"`
	Sessions []TablePromptSession `gorm:"foreignKey:PromptID;constraint:OnDelete:CASCADE" json:"sessions,omitempty"`

	// Virtual fields (not stored in DB)
	LatestVersion *TablePromptVersion `gorm:"-" json:"latest_version,omitempty"`
}

// TableName for TablePrompt
func (TablePrompt) TableName() string { return "prompts" }
