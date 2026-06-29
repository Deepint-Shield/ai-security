package tables

import "time"

// TableWorkspaceLoggingSettings is the per-workspace override of the tenant-
// global Logs Settings. The presence of a row means "this workspace has its
// own logging policy"; absence means "fall back to the tenant default".
//
// Mirrors the four knobs exposed on the Logs Settings page exactly so the
// admin UI's local form state maps 1:1 to columns here:
//   - EnableLogging                - whether requests under this workspace
//     write to the logs table at all.
//   - DisableContentLogging        - when true, only metadata is persisted
//     (latency, cost, tokens); request and
//     response payloads are dropped.
//   - LogRetentionDays             - per-workspace retention; the global
//     retention sweeper honors this for rows
//     that carry workspace_id.
//   - HideDeletedVirtualKeysInFilters - UI-only knob, but persisted server-
//     side so multi-user workspaces share the
//     same filter behavior.
//   - LoggingHeadersJSON           - JSON-encoded []string. Captured in log
//     metadata when a request arrives carrying
//     one of these header names.
//
// (workspace_id) is the primary key - at most one settings row per workspace.
// Tenant scoping lives on the workspace itself (workspaces.org_id), so we
// don't replicate it here; deleting a workspace cascades to its settings via
// application code in DeleteWorkspaceLoggingSettings.
type TableWorkspaceLoggingSettings struct {
	WorkspaceID                     string    `gorm:"column:workspace_id;type:varchar(64);primaryKey" json:"workspace_id"`
	EnableLogging                   bool      `gorm:"column:enable_logging;not null;default:true" json:"enable_logging"`
	DisableContentLogging           bool      `gorm:"column:disable_content_logging;not null;default:false" json:"disable_content_logging"`
	LogRetentionDays                int       `gorm:"column:log_retention_days;not null;default:365" json:"log_retention_days"`
	HideDeletedVirtualKeysInFilters bool      `gorm:"column:hide_deleted_virtual_keys_in_filters;not null;default:false" json:"hide_deleted_virtual_keys_in_filters"`
	LoggingHeadersJSON              string    `gorm:"column:logging_headers_json;type:text" json:"-"`
	CreatedAt                       time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt                       time.Time `gorm:"not null" json:"updated_at"`
}

func (TableWorkspaceLoggingSettings) TableName() string { return "workspace_logging_settings" }
