package tables

import (
	"encoding/json"
	"strings"
	"time"

	"gorm.io/gorm"
)

type TableGuardrailRAGSettings struct {
	ID                         string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID                   string    `gorm:"column:tenant_id;type:varchar(255);uniqueIndex:idx_guardrail_rag_settings_tenant" json:"-"`
	RuntimeEnforcementEnabled  bool      `gorm:"column:runtime_enforcement_enabled;not null;default:true" json:"runtime_enforcement_enabled"`
	AsyncScanningEnabled       bool      `gorm:"column:async_scanning_enabled;not null;default:true" json:"async_scanning_enabled"`
	PrecomputedScoresEnabled   bool      `gorm:"column:precomputed_scores_enabled;not null;default:true" json:"precomputed_scores_enabled"`
	PolicyCacheEnabled         bool      `gorm:"column:policy_cache_enabled;not null;default:true" json:"policy_cache_enabled"`
	CitationEnforcementEnabled bool      `gorm:"column:citation_enforcement_enabled;not null;default:true" json:"citation_enforcement_enabled"`
	ShadowModeEnabled          bool      `gorm:"column:shadow_mode_enabled;not null;default:false" json:"shadow_mode_enabled"`
	EvidenceExportsEnabled     bool      `gorm:"column:evidence_exports_enabled;not null;default:true" json:"evidence_exports_enabled"`
	DefaultAction              string    `gorm:"column:default_action;type:varchar(64);not null;default:'allow'" json:"default_action"`
	MaxRuntimeLatencyMs        int       `gorm:"column:max_runtime_latency_ms;not null;default:150" json:"max_runtime_latency_ms"`
	LastRulesSyncAt            string    `gorm:"column:last_rules_sync_at;type:varchar(64)" json:"last_rules_sync_at"`
	LastScanAt                 string    `gorm:"column:last_scan_at;type:varchar(64)" json:"last_scan_at"`
	CreatedAt                  time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt                  time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableGuardrailRAGSettings) TableName() string { return "guardrail_rag_settings" }

func (s *TableGuardrailRAGSettings) BeforeSave(tx *gorm.DB) error {
	s.DefaultAction = strings.ToLower(strings.TrimSpace(s.DefaultAction))
	if s.DefaultAction == "" {
		s.DefaultAction = "allow"
	}
	if s.MaxRuntimeLatencyMs <= 0 {
		s.MaxRuntimeLatencyMs = 150
	}
	s.LastRulesSyncAt = strings.TrimSpace(s.LastRulesSyncAt)
	s.LastScanAt = strings.TrimSpace(s.LastScanAt)
	return nil
}

type TableGuardrailRAGSource struct {
	ID               string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID         string    `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_rag_sources_tenant_name,priority:1" json:"-"`
	WorkspaceID      *string   `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"` // NULL = tenant-wide; non-NULL = scoped to that workspace.
	Name             string    `gorm:"type:varchar(255);not null;index:idx_guardrail_rag_sources_tenant_name,priority:2" json:"name"`
	Connector        string    `gorm:"type:varchar(128);index" json:"connector"`
	IndexName        string    `gorm:"column:index_name;type:varchar(255);index" json:"index_name"`
	Owner            string    `gorm:"type:varchar(255);index" json:"owner"`
	Sensitivity      string    `gorm:"type:varchar(64);index" json:"sensitivity"`
	RetentionClass   string    `gorm:"column:retention_class;type:varchar(128)" json:"retention_class"`
	TrustLevel       string    `gorm:"column:trust_level;type:varchar(64);index" json:"trust_level"`
	Tenant           string    `gorm:"type:varchar(255)" json:"tenant"`
	AppName          string    `gorm:"column:app_name;type:varchar(255);index" json:"app_name"`
	ACLTagsJSON      string    `gorm:"column:acl_tags_json;type:text" json:"-"`
	LabelsJSON       string    `gorm:"column:labels_json;type:text" json:"-"`
	DocumentCount    int       `gorm:"column:document_count;not null;default:0" json:"document_count"`
	ChunkCount       int       `gorm:"column:chunk_count;not null;default:0" json:"chunk_count"`
	Health           string    `gorm:"type:varchar(64);index" json:"health"`
	Quarantined      bool      `gorm:"column:quarantined;not null;default:false;index" json:"quarantined"`
	QuarantineReason string    `gorm:"column:quarantine_reason;type:text" json:"quarantine_reason"`
	LastScanAt       string    `gorm:"column:last_scan_at;type:varchar(64)" json:"last_scan_at"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
	ACLTags          []string  `gorm:"-" json:"acl_tags,omitempty"`
	Labels           []string  `gorm:"-" json:"labels,omitempty"`
}

func (TableGuardrailRAGSource) TableName() string { return "guardrail_rag_sources" }

func (s *TableGuardrailRAGSource) BeforeSave(tx *gorm.DB) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		s.Name = "RAG Source"
	}
	s.Connector = strings.TrimSpace(s.Connector)
	s.IndexName = strings.TrimSpace(s.IndexName)
	s.Owner = strings.TrimSpace(s.Owner)
	s.Sensitivity = strings.TrimSpace(s.Sensitivity)
	s.RetentionClass = strings.TrimSpace(s.RetentionClass)
	s.TrustLevel = strings.TrimSpace(s.TrustLevel)
	if s.TrustLevel == "" {
		s.TrustLevel = "trusted"
	}
	s.Tenant = strings.TrimSpace(s.Tenant)
	s.AppName = strings.TrimSpace(s.AppName)
	s.Health = strings.TrimSpace(s.Health)
	if s.Health == "" {
		s.Health = "healthy"
	}
	s.QuarantineReason = strings.TrimSpace(s.QuarantineReason)
	s.LastScanAt = strings.TrimSpace(s.LastScanAt)
	if s.ACLTags != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(s.ACLTags))
		if err != nil {
			return err
		}
		s.ACLTagsJSON = string(data)
	}
	if s.Labels != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(s.Labels))
		if err != nil {
			return err
		}
		s.LabelsJSON = string(data)
	}
	return nil
}

func (s *TableGuardrailRAGSource) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(s.ACLTagsJSON, &s.ACLTags); err != nil {
		return err
	}
	return decodeJSONStringSlice(s.LabelsJSON, &s.Labels)
}
