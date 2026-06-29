package configstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"gorm.io/gorm"
)

// WorkspaceMCPSettings is the in-memory shape returned to handlers. 1:1 with
// the columns on TableWorkspaceMCPSettings - exposing the table struct
// directly would leak the gorm tags into the HTTP layer.
type WorkspaceMCPSettings struct {
	WorkspaceID             string `json:"workspace_id"`
	AgentDepth              int    `json:"agent_depth"`
	ToolExecutionTimeoutSec int    `json:"tool_execution_timeout_sec"`
	ToolSyncIntervalMinutes int    `json:"tool_sync_interval_minutes"`
	CodeModeBindingLevel    string `json:"code_mode_binding_level"`
	CacheEnabled            bool   `json:"cache_enabled"`
	CacheTTLSeconds         int    `json:"cache_ttl_seconds"`
}

// GetWorkspaceMCPSettings loads the per-workspace override row. Returns
// (nil, nil) when no override exists - callers fall back to the tenant-
// global CoreConfig values in that case.
func (s *RDBConfigStore) GetWorkspaceMCPSettings(ctx context.Context, workspaceID string) (*WorkspaceMCPSettings, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, nil
	}
	var row tables.TableWorkspaceMCPSettings
	err := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &WorkspaceMCPSettings{
		WorkspaceID:             row.WorkspaceID,
		AgentDepth:              row.AgentDepth,
		ToolExecutionTimeoutSec: row.ToolExecutionTimeoutSec,
		ToolSyncIntervalMinutes: row.ToolSyncIntervalMinutes,
		CodeModeBindingLevel:    row.CodeModeBindingLevel,
		CacheEnabled:            row.CacheEnabled,
		CacheTTLSeconds:         row.CacheTTLSeconds,
	}, nil
}

// UpsertWorkspaceMCPSettings creates or replaces the override row. Validates
// the binding-level enum + clamps timeout/depth values so a malformed write
// can't take a workspace down.
func (s *RDBConfigStore) UpsertWorkspaceMCPSettings(ctx context.Context, settings *WorkspaceMCPSettings) error {
	if settings == nil {
		return errors.New("settings is required")
	}
	workspaceID := strings.TrimSpace(settings.WorkspaceID)
	if workspaceID == "" {
		return errors.New("workspace_id is required")
	}
	if settings.AgentDepth < 1 {
		settings.AgentDepth = 1
	}
	if settings.ToolExecutionTimeoutSec < 1 {
		settings.ToolExecutionTimeoutSec = 1
	}
	if settings.ToolSyncIntervalMinutes < 0 {
		settings.ToolSyncIntervalMinutes = 0
	}
	if settings.CacheTTLSeconds < 0 {
		settings.CacheTTLSeconds = 0
	}
	bindingLevel := strings.ToLower(strings.TrimSpace(settings.CodeModeBindingLevel))
	if bindingLevel != "server" && bindingLevel != "tool" {
		bindingLevel = "server"
	}
	now := time.Now().UTC()
	row := tables.TableWorkspaceMCPSettings{
		WorkspaceID:             workspaceID,
		AgentDepth:              settings.AgentDepth,
		ToolExecutionTimeoutSec: settings.ToolExecutionTimeoutSec,
		ToolSyncIntervalMinutes: settings.ToolSyncIntervalMinutes,
		CodeModeBindingLevel:    bindingLevel,
		CacheEnabled:            settings.CacheEnabled,
		CacheTTLSeconds:         settings.CacheTTLSeconds,
		UpdatedAt:               now,
	}
	var existing tables.TableWorkspaceMCPSettings
	err := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row.CreatedAt = now
		return s.db.WithContext(ctx).Create(&row).Error
	}
	if err != nil {
		return err
	}
	row.CreatedAt = existing.CreatedAt
	return s.db.WithContext(ctx).Save(&row).Error
}

// DeleteWorkspaceMCPSettings removes the override row so the workspace
// falls back to tenant defaults. Backs the "Reset to defaults" button on
// the MCP Settings page.
func (s *RDBConfigStore) DeleteWorkspaceMCPSettings(ctx context.Context, workspaceID string) error {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil
	}
	return s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).Delete(&tables.TableWorkspaceMCPSettings{}).Error
}
