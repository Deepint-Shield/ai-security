package logstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuditLogStore interface {
	CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error
	SearchAuditLogs(ctx context.Context, filters AuditLogFilters, sort *AuditLogSort, limit, offset int) (*AuditLogSearchResult, error)
	ListAllAuditLogs(ctx context.Context, filters AuditLogFilters, sort *AuditLogSort) ([]AuditLogEntry, error)
	VerifyAuditChain(ctx context.Context, opts AuditChainVerifyOptions) (*AuditChainVerificationReport, error)
	CreateAuditExportJob(ctx context.Context, job *AuditExportJob) error
	ListAuditExportJobs(ctx context.Context, limit int) ([]AuditExportJob, error)
	ListDueAuditExportJobs(ctx context.Context, runBefore time.Time, limit int) ([]AuditExportJob, error)
	FindAuditExportJob(ctx context.Context, id string) (*AuditExportJob, error)
	ClaimAuditExportJob(ctx context.Context, id string, expectedNextRunAt, attemptedAt time.Time) (bool, error)
	UpdateAuditExportJobExecution(ctx context.Context, id string, update AuditExportExecutionUpdate) error
}

type AuditExportExecutionUpdate struct {
	Status           string
	RecordCount      int64
	FileName         string
	StorageBackend   string
	ArtifactPath     string
	ArtifactChecksum string
	ArtifactType     string
	ArtifactSize     int64
	DownloadURL      string
	ErrorMessage     string
	NextRunAt        *time.Time
	LastRunAt        *time.Time
	LastAttemptedAt  *time.Time
	CompletedAt      *time.Time
}

func (s *RDBLogStore) CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error {
	if entry == nil {
		return nil
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := entry.SerializeFields(); err != nil {
			return err
		}
		if strings.TrimSpace(entry.TenantID) == "" {
			entry.TenantID = tenantctx.TenantIDFromContext(ctx)
		}
		// Stamp the active workspace from the request context. NULL when
		// the request isn't workspace-scoped (CLI / SDK / system jobs) so
		// history stays consistent.
		if entry.WorkspaceID == nil {
			if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
				entry.WorkspaceID = &ws
			}
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now().UTC()
		}
		// Postgres TIMESTAMP defaults to microsecond precision; SQLite
		// stores RFC3339 strings that lose sub-second precision on round-
		// trip. ComputedHash includes the timestamp formatted as
		// RFC3339Nano, so any precision loss between write and read
		// silently invalidates every row. Truncate to microseconds here -
		// it matches the worst-case DB precision and survives the read
		// path. Done in CreateAuditLog (rather than ComputedHash) so the
		// stored timestamp and the hashed timestamp are guaranteed equal.
		entry.Timestamp = entry.Timestamp.UTC().Truncate(time.Microsecond)
		if strings.TrimSpace(entry.VerificationMethod) == "" {
			entry.VerificationMethod = AuditVerificationMethodCryptographicHash
		}

		var previous AuditLogEntry
		err := tx.Order("sequence DESC").Limit(1).Take(&previous).Error
		switch {
		case err == nil:
			entry.Sequence = previous.Sequence + 1
			entry.PreviousHash = previous.Hash
		case err == gorm.ErrRecordNotFound:
			entry.Sequence = 1
			entry.PreviousHash = ""
		default:
			return err
		}

		entry.Hash = entry.ComputedHash()
		return tx.Clauses(clause.OnConflict{
			DoNothing: true,
		}).Create(entry).Error
	})
}

func (s *RDBLogStore) SearchAuditLogs(ctx context.Context, filters AuditLogFilters, sortConfig *AuditLogSort, limit, offset int) (*AuditLogSearchResult, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > defaultMaxSearchLimit {
		limit = defaultMaxSearchLimit
	}
	if offset < 0 {
		offset = 0
	}

	baseQuery := s.applyAuditFilters(s.db.WithContext(ctx).Model(&AuditLogEntry{}), filters)

	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, err
	}

	logs, err := s.listAuditLogsWithQuery(baseQuery, sortConfig, limit, offset)
	if err != nil {
		return nil, err
	}

	return &AuditLogSearchResult{
		TotalCount: totalCount,
		Logs:       logs,
	}, nil
}

func (s *RDBLogStore) ListAllAuditLogs(ctx context.Context, filters AuditLogFilters, sortConfig *AuditLogSort) ([]AuditLogEntry, error) {
	baseQuery := s.applyAuditFilters(s.db.WithContext(ctx).Model(&AuditLogEntry{}), filters)
	return s.listAuditLogsWithQuery(baseQuery, sortConfig, 0, 0)
}

func (s *RDBLogStore) listAuditLogsWithQuery(query *gorm.DB, sortConfig *AuditLogSort, limit, offset int) ([]AuditLogEntry, error) {
	orderedQuery := applyAuditSort(query, sortConfig)
	if limit > 0 {
		orderedQuery = orderedQuery.Limit(limit).Offset(offset)
	}

	var logs []AuditLogEntry
	if err := orderedQuery.Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *RDBLogStore) CreateAuditExportJob(ctx context.Context, job *AuditExportJob) error {
	if job == nil {
		return nil
	}
	if strings.TrimSpace(job.TenantID) == "" {
		job.TenantID = tenantctx.TenantIDFromContext(ctx)
	}
	return s.db.WithContext(ctx).Create(job).Error
}

func (s *RDBLogStore) ListAuditExportJobs(ctx context.Context, limit int) ([]AuditExportJob, error) {
	if limit < 0 {
		limit = 0
	}
	query := s.db.WithContext(ctx).Model(&AuditExportJob{}).Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	var jobs []AuditExportJob
	if err := query.Find(&jobs).Error; err != nil {
		return nil, err
	}
	sort.SliceStable(jobs, func(i, j int) bool {
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})
	return jobs, nil
}

func (s *RDBLogStore) ListDueAuditExportJobs(ctx context.Context, runBefore time.Time, limit int) ([]AuditExportJob, error) {
	if limit <= 0 {
		limit = 100
	}
	var jobs []AuditExportJob
	if err := s.db.WithContext(ctx).
		Model(&AuditExportJob{}).
		Where("schedule <> ''").
		Where("next_run_at IS NOT NULL").
		Where("next_run_at <= ?", runBefore.UTC()).
		Order("next_run_at ASC").
		Limit(limit).
		Find(&jobs).Error; err != nil {
		return nil, err
	}
	return jobs, nil
}

func (s *RDBLogStore) FindAuditExportJob(ctx context.Context, id string) (*AuditExportJob, error) {
	if strings.TrimSpace(id) == "" {
		return nil, gorm.ErrRecordNotFound
	}
	var job AuditExportJob
	if err := s.db.WithContext(ctx).Model(&AuditExportJob{}).Where("id = ?", strings.TrimSpace(id)).Take(&job).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *RDBLogStore) ClaimAuditExportJob(ctx context.Context, id string, expectedNextRunAt, attemptedAt time.Time) (bool, error) {
	if strings.TrimSpace(id) == "" || expectedNextRunAt.IsZero() {
		return false, nil
	}
	result := s.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&AuditExportJob{}).
		Where("id = ?", strings.TrimSpace(id)).
		Where("next_run_at = ?", expectedNextRunAt.UTC()).
		Updates(map[string]any{
			"status":            "running",
			"last_attempted_at": attemptedAt.UTC(),
			"next_run_at":       nil,
			"error_message":     "",
		})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected == 1, nil
}

func (s *RDBLogStore) UpdateAuditExportJobExecution(ctx context.Context, id string, update AuditExportExecutionUpdate) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	values := map[string]any{
		"status":            strings.TrimSpace(update.Status),
		"record_count":      update.RecordCount,
		"error_message":     strings.TrimSpace(update.ErrorMessage),
		"next_run_at":       update.NextRunAt,
		"last_attempted_at": update.LastAttemptedAt,
	}
	if update.LastRunAt != nil {
		values["last_run_at"] = update.LastRunAt
	}
	if update.CompletedAt != nil {
		values["completed_at"] = update.CompletedAt
	}
	if strings.TrimSpace(update.FileName) != "" {
		values["file_name"] = strings.TrimSpace(update.FileName)
	}
	if strings.TrimSpace(update.StorageBackend) != "" {
		values["storage_backend"] = strings.TrimSpace(update.StorageBackend)
	}
	if strings.TrimSpace(update.ArtifactPath) != "" {
		values["artifact_path"] = strings.TrimSpace(update.ArtifactPath)
	}
	if strings.TrimSpace(update.ArtifactChecksum) != "" {
		values["artifact_checksum"] = strings.TrimSpace(update.ArtifactChecksum)
	}
	if strings.TrimSpace(update.ArtifactType) != "" {
		values["artifact_content_type"] = strings.TrimSpace(update.ArtifactType)
	}
	if update.ArtifactSize > 0 {
		values["artifact_size_bytes"] = update.ArtifactSize
	}
	if strings.TrimSpace(update.DownloadURL) != "" {
		values["download_url"] = strings.TrimSpace(update.DownloadURL)
	}
	return s.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&AuditExportJob{}).
		Where("id = ?", strings.TrimSpace(id)).
		Updates(values).Error
}

func (s *RDBLogStore) applyAuditFilters(baseQuery *gorm.DB, filters AuditLogFilters) *gorm.DB {
	if ws := strings.TrimSpace(filters.WorkspaceID); ws != "" {
		// Narrow to entries scoped to the workspace plus pre-workspace
		// entries (workspace_id IS NULL) so historical audit rows remain
		// visible during the transition.
		baseQuery = baseQuery.Where("workspace_id IS NULL OR workspace_id = ?", ws)
	}
	if len(filters.EventTypes) > 0 {
		baseQuery = baseQuery.Where("event_type IN ?", normalizeAuditStrings(filters.EventTypes))
	}
	if len(filters.Actions) > 0 {
		baseQuery = baseQuery.Where("action IN ?", normalizeAuditStrings(filters.Actions))
	}
	if len(filters.ResourceTypes) > 0 {
		baseQuery = baseQuery.Where("resource_type IN ?", normalizeAuditStrings(filters.ResourceTypes))
	}
	if len(filters.Status) > 0 {
		baseQuery = baseQuery.Where("status IN ?", normalizeAuditStrings(filters.Status))
	}
	if len(filters.Severity) > 0 {
		baseQuery = baseQuery.Where("severity IN ?", normalizeAuditStrings(filters.Severity))
	}
	if filters.DateRange != nil {
		if parsed, ok := parseAuditStoreTime(filters.DateRange.Start); ok {
			baseQuery = baseQuery.Where("timestamp >= ?", parsed)
		}
		if parsed, ok := parseAuditStoreTime(filters.DateRange.End); ok {
			baseQuery = baseQuery.Where("timestamp <= ?", parsed)
		}
	}
	if filters.Actors != nil {
		if len(filters.Actors.UserIDs) > 0 {
			baseQuery = baseQuery.Where("actor_user_id IN ?", normalizeAuditStrings(filters.Actors.UserIDs))
		}
		if len(filters.Actors.Emails) > 0 {
			baseQuery = baseQuery.Where("actor_email IN ?", normalizeAuditStrings(filters.Actors.Emails))
		}
		if len(filters.Actors.IPAddresses) > 0 {
			baseQuery = baseQuery.Where("actor_ip_address IN ?", filters.Actors.IPAddresses)
		}
	}
	if query := strings.ToLower(strings.TrimSpace(filters.Query)); query != "" {
		needle := "%" + query + "%"
		baseQuery = baseQuery.Where(
			`LOWER(event_id) LIKE ? OR LOWER(event_type) LIKE ? OR LOWER(action) LIKE ? OR LOWER(status) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(resource_type) LIKE ? OR LOWER(resource_id) LIKE ? OR LOWER(actor_user_id) LIKE ? OR LOWER(actor_email) LIKE ? OR LOWER(actor_ip_address) LIKE ? OR LOWER(details) LIKE ?`,
			needle, needle, needle, needle, needle, needle, needle, needle, needle, needle, needle,
		)
	}
	return baseQuery
}

func applyAuditSort(query *gorm.DB, sortConfig *AuditLogSort) *gorm.DB {
	field := "timestamp"
	order := "desc"
	if sortConfig != nil {
		if strings.TrimSpace(sortConfig.Field) != "" {
			field = strings.ToLower(strings.TrimSpace(sortConfig.Field))
		}
		if strings.TrimSpace(sortConfig.Order) != "" {
			order = strings.ToLower(strings.TrimSpace(sortConfig.Order))
		}
	}

	column := "timestamp"
	switch field {
	case "event_type":
		column = "event_type"
	case "severity":
		column = "severity"
	case "status":
		column = "status"
	case "resource_type":
		column = "resource_type"
	}

	if order != "asc" {
		order = "desc"
	}
	return query.Order(fmt.Sprintf("%s %s", column, order)).Order("event_id DESC")
}

func parseAuditStoreTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func normalizeAuditStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := normalizeAuditValue(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}
