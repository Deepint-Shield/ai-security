package logstore

import (
	"errors"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"gorm.io/gorm"
)

var (
	errImmutableLogExport = errors.New("log export jobs are immutable")
)

type LogExportDateRange struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type LogExportFilters struct {
	DateRange      *LogExportDateRange `json:"date_range,omitempty"`
	Providers      []string            `json:"providers,omitempty"`
	Models         []string            `json:"models,omitempty"`
	Status         []string            `json:"status,omitempty"`
	Objects        []string            `json:"objects,omitempty"`
	StatusCodes    []int               `json:"status_codes,omitempty"`
	Customers      []string            `json:"customers,omitempty"`
	SelectedKeyIDs []string            `json:"selected_key_ids,omitempty"`
	VirtualKeyIDs  []string            `json:"virtual_key_ids,omitempty"`
	RoutingRuleIDs []string            `json:"routing_rule_ids,omitempty"`
	RoutingEngines []string            `json:"routing_engines,omitempty"`
	ToolNames      []string            `json:"tool_names,omitempty"`
	ServerLabels   []string            `json:"server_labels,omitempty"`
	MinLatencyMs   *float64            `json:"min_latency_ms,omitempty"`
	MaxLatencyMs   *float64            `json:"max_latency_ms,omitempty"`
	HasErrors      *bool               `json:"has_errors,omitempty"`
	Query          string              `json:"query,omitempty"`
}

type LogExportSchedule struct {
	Frequency string `json:"frequency,omitempty"`
	Day       string `json:"day,omitempty"`
	Time      string `json:"time,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
}

type LogExportDestination struct {
	Type   string         `json:"type,omitempty"`
	Config map[string]any `json:"config,omitempty"`
}

type LogExportTransformation struct {
	Type      string         `json:"type,omitempty"`
	GroupBy   []string       `json:"group_by,omitempty"`
	Metrics   []string       `json:"metrics,omitempty"`
	Fields    []string       `json:"fields,omitempty"`
	Method    string         `json:"method,omitempty"`
	AddFields map[string]any `json:"add_fields,omitempty"`
}

type LogExportDataConfig struct {
	Format          string                    `json:"format,omitempty"`
	Compression     string                    `json:"compression,omitempty"`
	Include         []string                  `json:"include,omitempty"`
	Filters         *LogExportFilters         `json:"filters,omitempty"`
	Transformations []LogExportTransformation `json:"transformations,omitempty"`
}

type LogExportJob struct {
	ID                    string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID              string     `gorm:"column:tenant_id;type:varchar(255);index;default:''" json:"-"`
	// WorkspaceID narrows the export job to the workspace it was created
	// under. NULL = legacy / pre-workspace job. Used at list time so users
	// don't see exports from other orgs (the tenant_id partition is the
	// email-keyed legacy partition, which is the same across every UI
	// tenant the user owns).
	WorkspaceID           *string    `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"`
	Name                  string     `gorm:"type:varchar(255);index;not null" json:"name"`
	Status                string     `gorm:"type:varchar(64);index;not null" json:"status"`
	Format                string     `gorm:"type:varchar(64);index;not null" json:"format"`
	Destination           string     `gorm:"type:varchar(128);index;not null" json:"destination"`
	Compression           string     `gorm:"type:varchar(64)" json:"compression,omitempty"`
	RecordCount           int64      `gorm:"not null;default:0" json:"record_count"`
	IncludeTypesJSON      string     `gorm:"column:include_types;type:text" json:"-"`
	FiltersJSON           string     `gorm:"column:filters;type:text" json:"-"`
	ScheduleJSON          string     `gorm:"column:schedule;type:text" json:"-"`
	DestinationConfigJSON string     `gorm:"column:destination_config;type:text" json:"-"`
	TransformationsJSON   string     `gorm:"column:transformations;type:text" json:"-"`
	FileName              string     `gorm:"type:varchar(512)" json:"file_name,omitempty"`
	StorageBackend        string     `gorm:"column:storage_backend;type:varchar(64)" json:"storage_backend,omitempty"`
	ArtifactPath          string     `gorm:"column:artifact_path;type:text" json:"artifact_path,omitempty"`
	ArtifactChecksum      string     `gorm:"column:artifact_checksum;type:varchar(255)" json:"artifact_checksum,omitempty"`
	ArtifactType          string     `gorm:"column:artifact_content_type;type:varchar(255)" json:"artifact_content_type,omitempty"`
	ArtifactSize          int64      `gorm:"column:artifact_size_bytes;not null;default:0" json:"artifact_size_bytes,omitempty"`
	DeliveryReference     string     `gorm:"column:delivery_reference;type:text" json:"delivery_reference,omitempty"`
	DeliveryMetadataJSON  string     `gorm:"column:delivery_metadata;type:text" json:"-"`
	DownloadURL           string     `gorm:"column:download_url;type:text" json:"download_url,omitempty"`
	ErrorMessage          string     `gorm:"column:error_message;type:text" json:"error_message,omitempty"`
	CreatedAt             time.Time  `gorm:"index;not null" json:"created_at"`
	NextRunAt             *time.Time `gorm:"column:next_run_at;index" json:"next_run_at,omitempty"`
	LastRunAt             *time.Time `gorm:"column:last_run_at;index" json:"last_run_at,omitempty"`
	LastAttemptedAt       *time.Time `gorm:"column:last_attempted_at;index" json:"last_attempted_at,omitempty"`
	CompletedAt           *time.Time `gorm:"index" json:"completed_at,omitempty"`

	IncludeTypes     []string                  `gorm:"-" json:"include_types,omitempty"`
	Filters          *LogExportFilters         `gorm:"-" json:"filters,omitempty"`
	Schedule         *LogExportSchedule        `gorm:"-" json:"schedule,omitempty"`
	DestinationRef   *LogExportDestination     `gorm:"-" json:"destination_ref,omitempty"`
	Transformations  []LogExportTransformation `gorm:"-" json:"transformations,omitempty"`
	DeliveryMetadata map[string]any            `gorm:"-" json:"delivery_metadata,omitempty"`
}

func (LogExportJob) TableName() string {
	return "log_export_jobs"
}

func (j *LogExportJob) BeforeCreate(tx *gorm.DB) error {
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	return j.SerializeFields()
}

func (j *LogExportJob) AfterFind(tx *gorm.DB) error {
	return j.DeserializeFields()
}

func (j *LogExportJob) BeforeUpdate(tx *gorm.DB) error {
	return errImmutableLogExport
}

func (j *LogExportJob) BeforeDelete(tx *gorm.DB) error {
	return errImmutableLogExport
}

func (j *LogExportJob) SerializeFields() error {
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

	if j.DestinationRef != nil {
		raw, err := sonic.Marshal(j.DestinationRef)
		if err != nil {
			return err
		}
		j.DestinationConfigJSON = string(raw)
	} else {
		j.DestinationConfigJSON = ""
	}

	if len(j.Transformations) > 0 {
		raw, err := sonic.Marshal(j.Transformations)
		if err != nil {
			return err
		}
		j.TransformationsJSON = string(raw)
	} else {
		j.TransformationsJSON = "[]"
	}

	if len(j.DeliveryMetadata) > 0 {
		raw, err := sonic.Marshal(j.DeliveryMetadata)
		if err != nil {
			return err
		}
		j.DeliveryMetadataJSON = string(raw)
	} else {
		j.DeliveryMetadataJSON = ""
	}

	return nil
}

func (j *LogExportJob) DeserializeFields() error {
	if strings.TrimSpace(j.IncludeTypesJSON) != "" {
		if err := sonic.Unmarshal([]byte(j.IncludeTypesJSON), &j.IncludeTypes); err != nil {
			return err
		}
	} else {
		j.IncludeTypes = nil
	}

	if strings.TrimSpace(j.FiltersJSON) != "" {
		var filters LogExportFilters
		if err := sonic.Unmarshal([]byte(j.FiltersJSON), &filters); err != nil {
			return err
		}
		j.Filters = &filters
	} else {
		j.Filters = nil
	}

	if strings.TrimSpace(j.ScheduleJSON) != "" {
		var schedule LogExportSchedule
		if err := sonic.Unmarshal([]byte(j.ScheduleJSON), &schedule); err != nil {
			return err
		}
		j.Schedule = &schedule
	} else {
		j.Schedule = nil
	}

	if strings.TrimSpace(j.DestinationConfigJSON) != "" {
		var destination LogExportDestination
		if err := sonic.Unmarshal([]byte(j.DestinationConfigJSON), &destination); err != nil {
			return err
		}
		j.DestinationRef = &destination
	} else {
		j.DestinationRef = nil
	}

	if strings.TrimSpace(j.TransformationsJSON) != "" {
		if err := sonic.Unmarshal([]byte(j.TransformationsJSON), &j.Transformations); err != nil {
			return err
		}
	} else {
		j.Transformations = nil
	}

	if strings.TrimSpace(j.DeliveryMetadataJSON) != "" {
		var metadata map[string]any
		if err := sonic.Unmarshal([]byte(j.DeliveryMetadataJSON), &metadata); err != nil {
			return err
		}
		j.DeliveryMetadata = metadata
	} else {
		j.DeliveryMetadata = nil
	}

	return nil
}
