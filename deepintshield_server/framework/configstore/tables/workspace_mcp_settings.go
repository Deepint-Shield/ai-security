package tables

import "time"

// TableWorkspaceMCPSettings is the per-workspace override of the tenant-
// global MCP Settings. Mirrors the knobs exposed on the MCP Settings page
// 1:1 with the columns here so the UI form maps directly to a row:
//
//   - AgentDepth                 - max recursion depth for an MCP agent step.
//   - ToolExecutionTimeoutSec    - per-tool execution ceiling.
//   - ToolSyncIntervalMinutes    - how often to refresh upstream tool lists
//     (0 = disable polling).
//   - CodeModeBindingLevel       - "server" or "tool"; how VFS types are
//     emitted in code-mode prompts.
//   - CacheEnabled               - direct (hash-match) result cache toggle.
//   - CacheTTLSeconds            - TTL for the result cache when enabled.
//
// (workspace_id) is the primary key - at most one row per workspace.
// Absence means "inherit tenant defaults from CoreConfig".
type TableWorkspaceMCPSettings struct {
	WorkspaceID             string    `gorm:"column:workspace_id;type:varchar(64);primaryKey" json:"workspace_id"`
	AgentDepth              int       `gorm:"column:agent_depth;not null;default:10" json:"agent_depth"`
	ToolExecutionTimeoutSec int       `gorm:"column:tool_execution_timeout_sec;not null;default:30" json:"tool_execution_timeout_sec"`
	ToolSyncIntervalMinutes int       `gorm:"column:tool_sync_interval_minutes;not null;default:10" json:"tool_sync_interval_minutes"`
	CodeModeBindingLevel    string    `gorm:"column:code_mode_binding_level;type:varchar(16);not null;default:'server'" json:"code_mode_binding_level"`
	CacheEnabled            bool      `gorm:"column:cache_enabled;not null;default:true" json:"cache_enabled"`
	CacheTTLSeconds         int       `gorm:"column:cache_ttl_seconds;not null;default:300" json:"cache_ttl_seconds"`
	CreatedAt               time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt               time.Time `gorm:"not null" json:"updated_at"`
}

func (TableWorkspaceMCPSettings) TableName() string { return "workspace_mcp_settings" }
