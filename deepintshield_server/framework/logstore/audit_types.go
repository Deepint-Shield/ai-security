package logstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"gorm.io/gorm"
)

const (
	AuditVerificationMethodCryptographicHash = "cryptographic_hash"
)

var (
	errImmutableAuditLog    = errors.New("audit logs are immutable")
	errImmutableAuditExport = errors.New("audit export jobs are immutable")
)

type AuditLogActor struct {
	UserID    string `json:"user_id,omitempty"`
	Email     string `json:"email,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
}

type AuditLogVerification struct {
	Hash               string `json:"hash"`
	Verified           bool   `json:"verified"`
	VerificationMethod string `json:"verification_method,omitempty"`
}

type AuditLogEntry struct {
	EventID            string    `gorm:"primaryKey;type:varchar(255)" json:"event_id"`
	TenantID           string    `gorm:"column:tenant_id;type:varchar(255);index:idx_audit_logs_tenant_ts,priority:1;uniqueIndex:idx_audit_logs_tenant_sequence,priority:1" json:"-"`
	WorkspaceID        *string   `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"` // Stamped from the request's active workspace; not included in the hash chain so existing entries remain valid.
	Sequence           int64     `gorm:"not null;uniqueIndex:idx_audit_logs_tenant_sequence,priority:2" json:"-"`
	Timestamp          time.Time `gorm:"not null;index:idx_audit_logs_tenant_ts,priority:2;index" json:"timestamp"`
	EventType          string    `gorm:"type:varchar(64);index" json:"event_type"`
	Action             string    `gorm:"type:varchar(128);index" json:"action"`
	Status             string    `gorm:"type:varchar(64);index" json:"status"`
	Severity           string    `gorm:"type:varchar(32);index" json:"severity"`
	ResourceType       string    `gorm:"type:varchar(128);index" json:"resource_type"`
	ResourceID         string    `gorm:"type:varchar(255);index" json:"resource_id,omitempty"`
	ActorUserID        string    `gorm:"column:actor_user_id;type:varchar(255);index" json:"-"`
	ActorEmail         string    `gorm:"column:actor_email;type:varchar(255);index" json:"-"`
	ActorIPAddress     string    `gorm:"column:actor_ip_address;type:varchar(128);index" json:"-"`
	RequestID          string    `gorm:"column:request_id;type:varchar(255);index" json:"-"`
	RequestPath        string    `gorm:"column:request_path;type:text" json:"-"`
	RequestMethod      string    `gorm:"column:request_method;type:varchar(16)" json:"-"`
	DetailsJSON        string    `gorm:"column:details;type:text" json:"-"`
	PreviousHash       string    `gorm:"column:previous_hash;type:varchar(255)" json:"-"`
	Hash               string    `gorm:"column:hash;type:varchar(255);not null" json:"-"`
	VerificationMethod string    `gorm:"column:verification_method;type:varchar(64);not null;default:'cryptographic_hash'" json:"-"`
	CreatedAt          time.Time `gorm:"index;not null" json:"created_at"`

	Actor        AuditLogActor        `gorm:"-" json:"actor"`
	Details      map[string]any       `gorm:"-" json:"details,omitempty"`
	Verification AuditLogVerification `gorm:"-" json:"verification"`
}

func (AuditLogEntry) TableName() string {
	return "audit_logs"
}

func (e *AuditLogEntry) BeforeCreate(tx *gorm.DB) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if strings.TrimSpace(e.VerificationMethod) == "" {
		e.VerificationMethod = AuditVerificationMethodCryptographicHash
	}
	return e.SerializeFields()
}

func (e *AuditLogEntry) AfterFind(tx *gorm.DB) error {
	return e.DeserializeFields()
}

func (e *AuditLogEntry) BeforeUpdate(tx *gorm.DB) error {
	return errImmutableAuditLog
}

func (e *AuditLogEntry) BeforeDelete(tx *gorm.DB) error {
	return errImmutableAuditLog
}

func (e *AuditLogEntry) SerializeFields() error {
	if strings.TrimSpace(e.ActorUserID) == "" {
		e.ActorUserID = strings.TrimSpace(e.Actor.UserID)
	}
	if strings.TrimSpace(e.ActorEmail) == "" {
		e.ActorEmail = strings.TrimSpace(e.Actor.Email)
	}
	if strings.TrimSpace(e.ActorIPAddress) == "" {
		e.ActorIPAddress = strings.TrimSpace(e.Actor.IPAddress)
	}
	// Serialize Details once and only once. Go map iteration order is
	// non-deterministic, so calling sonic.Marshal twice on the same map
	// can produce different JSON - that would break the hash chain
	// because CreateAuditLog computes the hash off the first JSON and
	// BeforeCreate (which fires inside gorm Create) would otherwise
	// overwrite DetailsJSON with the second JSON before the row lands
	// on disk.
	if e.Details != nil && strings.TrimSpace(e.DetailsJSON) == "" {
		raw, err := sonic.Marshal(e.Details)
		if err != nil {
			return err
		}
		e.DetailsJSON = string(raw)
	}
	return nil
}

func (e *AuditLogEntry) DeserializeFields() error {
	e.Actor = AuditLogActor{
		UserID:    strings.TrimSpace(e.ActorUserID),
		Email:     strings.TrimSpace(e.ActorEmail),
		IPAddress: strings.TrimSpace(e.ActorIPAddress),
	}

	if strings.TrimSpace(e.DetailsJSON) != "" {
		var details map[string]any
		if err := sonic.Unmarshal([]byte(e.DetailsJSON), &details); err != nil {
			return err
		}
		e.Details = details
	} else {
		e.Details = nil
	}

	if strings.TrimSpace(e.VerificationMethod) == "" {
		e.VerificationMethod = AuditVerificationMethodCryptographicHash
	}
	e.Verification = AuditLogVerification{
		Hash:               e.Hash,
		Verified:           strings.TrimSpace(e.Hash) != "" && e.Hash == e.ComputedHash(),
		VerificationMethod: e.VerificationMethod,
	}
	return nil
}

func (e *AuditLogEntry) ComputedHash() string {
	payload := fmt.Sprintf(
		"%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		strings.TrimSpace(e.TenantID),
		strings.TrimSpace(e.EventID),
		e.Sequence,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		normalizeAuditValue(e.EventType),
		normalizeAuditValue(e.Action),
		normalizeAuditValue(e.Status),
		normalizeAuditValue(e.Severity),
		normalizeAuditValue(e.ResourceType),
		strings.TrimSpace(e.ResourceID),
		strings.TrimSpace(e.ActorUserID),
		strings.TrimSpace(e.ActorEmail),
		strings.TrimSpace(e.ActorIPAddress),
		strings.TrimSpace(e.RequestID),
		strings.TrimSpace(e.RequestPath),
		strings.TrimSpace(e.RequestMethod),
		strings.TrimSpace(e.PreviousHash)+"|"+strings.TrimSpace(e.DetailsJSON),
	)
	sum := sha256.Sum256([]byte(payload))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type AuditLogDateRange struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type AuditLogActors struct {
	UserIDs     []string `json:"user_ids,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

type AuditLogFilters struct {
	EventTypes    []string           `json:"event_types,omitempty"`
	Actions       []string           `json:"actions,omitempty"`
	ResourceTypes []string           `json:"resource_types,omitempty"`
	DateRange     *AuditLogDateRange `json:"date_range,omitempty"`
	Actors        *AuditLogActors    `json:"actors,omitempty"`
	Status        []string           `json:"status,omitempty"`
	Severity      []string           `json:"severity,omitempty"`
	Query         string             `json:"query,omitempty"`
	IncludeDetail bool               `json:"include_details,omitempty"`
	// WorkspaceID narrows the result to entries scoped to this workspace
	// plus pre-workspace entries (workspace_id IS NULL).
	WorkspaceID string `json:"workspace_id,omitempty"`
}

type AuditLogSort struct {
	Field string `json:"field,omitempty"`
	Order string `json:"order,omitempty"`
}

type AuditLogSearchResult struct {
	TotalCount int64           `json:"total_count"`
	Logs       []AuditLogEntry `json:"audit_logs"`
}

type AuditExportPlan struct {
	Frequency string `json:"frequency,omitempty"`
	StartDate string `json:"start_date,omitempty"`
	Day       string `json:"day,omitempty"`
	Time      string `json:"time,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
}

type AuditExportJob struct {
	ID               string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID         string     `gorm:"column:tenant_id;type:varchar(255);index;default:''" json:"-"`
	Name             string     `gorm:"type:varchar(255);index;not null" json:"name"`
	Status           string     `gorm:"type:varchar(64);index;not null" json:"status"`
	Format           string     `gorm:"type:varchar(64);index;not null" json:"format"`
	Destination      string     `gorm:"type:varchar(128);index;not null" json:"destination"`
	Compression      string     `gorm:"type:varchar(64)" json:"compression,omitempty"`
	IncludeDetails   bool       `gorm:"column:include_details;not null;default:false" json:"include_details"`
	RecordCount      int64      `gorm:"not null;default:0" json:"record_count"`
	EventTypesJSON   string     `gorm:"column:event_types;type:text" json:"-"`
	IncludeTypesJSON string     `gorm:"column:include_types;type:text" json:"-"`
	FiltersJSON      string     `gorm:"column:filters;type:text" json:"-"`
	ScheduleJSON     string     `gorm:"column:schedule;type:text" json:"-"`
	DestinationJSON  string     `gorm:"column:destination_config;type:text" json:"-"`
	FileName         string     `gorm:"type:varchar(512)" json:"file_name"`
	StorageBackend   string     `gorm:"column:storage_backend;type:varchar(64)" json:"storage_backend,omitempty"`
	ArtifactPath     string     `gorm:"column:artifact_path;type:text" json:"artifact_path,omitempty"`
	ArtifactChecksum string     `gorm:"column:artifact_checksum;type:varchar(255)" json:"artifact_checksum,omitempty"`
	ArtifactType     string     `gorm:"column:artifact_content_type;type:varchar(255)" json:"artifact_content_type,omitempty"`
	ArtifactSize     int64      `gorm:"column:artifact_size_bytes;not null;default:0" json:"artifact_size_bytes,omitempty"`
	DownloadURL      string     `gorm:"column:download_url;type:text" json:"download_url,omitempty"`
	ErrorMessage     string     `gorm:"column:error_message;type:text" json:"error_message,omitempty"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	NextRunAt        *time.Time `gorm:"column:next_run_at;index" json:"next_run_at,omitempty"`
	LastRunAt        *time.Time `gorm:"column:last_run_at;index" json:"last_run_at,omitempty"`
	LastAttemptedAt  *time.Time `gorm:"column:last_attempted_at;index" json:"last_attempted_at,omitempty"`
	CompletedAt      *time.Time `gorm:"index" json:"completed_at,omitempty"`

	EventTypes        []string         `gorm:"-" json:"event_types"`
	IncludeTypes      []string         `gorm:"-" json:"include_types,omitempty"`
	Filters           *AuditLogFilters `gorm:"-" json:"filters,omitempty"`
	Schedule          *AuditExportPlan `gorm:"-" json:"schedule,omitempty"`
	DestinationConfig map[string]any   `gorm:"-" json:"-"`
}

func (AuditExportJob) TableName() string {
	return "audit_export_jobs"
}

func (j *AuditExportJob) BeforeCreate(tx *gorm.DB) error {
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	return j.SerializeFields()
}

func (j *AuditExportJob) AfterFind(tx *gorm.DB) error {
	return j.DeserializeFields()
}

func (j *AuditExportJob) BeforeUpdate(tx *gorm.DB) error {
	return errImmutableAuditExport
}

func (j *AuditExportJob) BeforeDelete(tx *gorm.DB) error {
	return errImmutableAuditExport
}

func (j *AuditExportJob) SerializeFields() error {
	if raw, err := sonic.Marshal(j.EventTypes); err != nil {
		return err
	} else {
		j.EventTypesJSON = string(raw)
	}
	if raw, err := sonic.Marshal(j.IncludeTypes); err != nil {
		return err
	} else {
		j.IncludeTypesJSON = string(raw)
	}
	if j.Filters != nil {
		raw, err := sonic.Marshal(j.Filters)
		if err != nil {
			return err
		}
		j.FiltersJSON = string(raw)
	} else {
		j.FiltersJSON = ""
	}
	if j.Schedule != nil {
		raw, err := sonic.Marshal(j.Schedule)
		if err != nil {
			return err
		}
		j.ScheduleJSON = string(raw)
	} else {
		j.ScheduleJSON = ""
	}
	if j.DestinationConfig != nil {
		raw, err := sonic.Marshal(j.DestinationConfig)
		if err != nil {
			return err
		}
		j.DestinationJSON = string(raw)
	} else {
		j.DestinationJSON = ""
	}
	return nil
}

func (j *AuditExportJob) DeserializeFields() error {
	if strings.TrimSpace(j.EventTypesJSON) != "" {
		if err := sonic.Unmarshal([]byte(j.EventTypesJSON), &j.EventTypes); err != nil {
			return err
		}
	} else {
		j.EventTypes = nil
	}
	if strings.TrimSpace(j.IncludeTypesJSON) != "" {
		if err := sonic.Unmarshal([]byte(j.IncludeTypesJSON), &j.IncludeTypes); err != nil {
			return err
		}
	} else {
		j.IncludeTypes = nil
	}
	if strings.TrimSpace(j.FiltersJSON) != "" {
		var filters AuditLogFilters
		if err := sonic.Unmarshal([]byte(j.FiltersJSON), &filters); err != nil {
			return err
		}
		j.Filters = &filters
	} else {
		j.Filters = nil
	}
	if strings.TrimSpace(j.ScheduleJSON) != "" {
		var schedule AuditExportPlan
		if err := sonic.Unmarshal([]byte(j.ScheduleJSON), &schedule); err != nil {
			return err
		}
		j.Schedule = &schedule
	} else {
		j.Schedule = nil
	}
	if strings.TrimSpace(j.DestinationJSON) != "" {
		var config map[string]any
		if err := sonic.Unmarshal([]byte(j.DestinationJSON), &config); err != nil {
			return err
		}
		j.DestinationConfig = config
	} else {
		j.DestinationConfig = nil
	}
	return nil
}

func normalizeAuditValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
