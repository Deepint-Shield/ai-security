package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"gorm.io/gorm"
)

// WorkspaceLoggingSettings is the in-memory shape returned to handlers. We
// keep the JSON-encoded headers column on the table struct and unwrap it
// here so callers don't need to know about the storage format.
type WorkspaceLoggingSettings struct {
	WorkspaceID                     string   `json:"workspace_id"`
	EnableLogging                   bool     `json:"enable_logging"`
	DisableContentLogging           bool     `json:"disable_content_logging"`
	LogRetentionDays                int      `json:"log_retention_days"`
	HideDeletedVirtualKeysInFilters bool     `json:"hide_deleted_virtual_keys_in_filters"`
	LoggingHeaders                  []string `json:"logging_headers"`
}

// GetWorkspaceLoggingSettings loads the per-workspace override row. Returns
// (nil, nil) when there's no override - caller falls back to the tenant-
// global CoreConfig values in that case.
func (s *RDBConfigStore) GetWorkspaceLoggingSettings(ctx context.Context, workspaceID string) (*WorkspaceLoggingSettings, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, nil
	}
	var row tables.TableWorkspaceLoggingSettings
	err := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	headers := []string{}
	if strings.TrimSpace(row.LoggingHeadersJSON) != "" {
		if err := json.Unmarshal([]byte(row.LoggingHeadersJSON), &headers); err != nil {
			// Corrupt JSON shouldn't take the request down - log via error
			// path and treat as no headers configured.
			headers = []string{}
		}
	}
	return &WorkspaceLoggingSettings{
		WorkspaceID:                     row.WorkspaceID,
		EnableLogging:                   row.EnableLogging,
		DisableContentLogging:           row.DisableContentLogging,
		LogRetentionDays:                row.LogRetentionDays,
		HideDeletedVirtualKeysInFilters: row.HideDeletedVirtualKeysInFilters,
		LoggingHeaders:                  headers,
	}, nil
}

// UpsertWorkspaceLoggingSettings creates or replaces the override row.
// Empty workspaceID is rejected - the caller MUST have resolved the active
// workspace before persisting, otherwise we'd silently write a row that no
// handler can read back.
func (s *RDBConfigStore) UpsertWorkspaceLoggingSettings(ctx context.Context, settings *WorkspaceLoggingSettings) error {
	if settings == nil {
		return errors.New("settings is required")
	}
	workspaceID := strings.TrimSpace(settings.WorkspaceID)
	if workspaceID == "" {
		return errors.New("workspace_id is required")
	}
	if settings.LogRetentionDays < 1 {
		settings.LogRetentionDays = 1
	}
	headers := settings.LoggingHeaders
	if headers == nil {
		headers = []string{}
	}
	headerJSON, err := json.Marshal(headers)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	row := tables.TableWorkspaceLoggingSettings{
		WorkspaceID:                     workspaceID,
		EnableLogging:                   settings.EnableLogging,
		DisableContentLogging:           settings.DisableContentLogging,
		LogRetentionDays:                settings.LogRetentionDays,
		HideDeletedVirtualKeysInFilters: settings.HideDeletedVirtualKeysInFilters,
		LoggingHeadersJSON:              string(headerJSON),
		UpdatedAt:                       now,
	}
	// Upsert via Save when the row exists, Create when it doesn't. GORM's
	// Save on a primary-key-only struct does the right thing because the
	// primary key is set above.
	var existing tables.TableWorkspaceLoggingSettings
	err = s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).First(&existing).Error
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

// DeleteWorkspaceLoggingSettings removes the override row so the workspace
// falls back to tenant defaults. Called from the workspace deletion path
// (when one ships) and from a future "reset to default" button.
func (s *RDBConfigStore) DeleteWorkspaceLoggingSettings(ctx context.Context, workspaceID string) error {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil
	}
	return s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).Delete(&tables.TableWorkspaceLoggingSettings{}).Error
}
