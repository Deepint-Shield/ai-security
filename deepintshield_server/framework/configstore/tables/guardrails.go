package tables

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/encrypt"
	"gorm.io/gorm"
)

const (
	GuardrailProviderTypeAWSBedrock          = "aws_bedrock"
	GuardrailProviderTypeAzureContentSafe    = "azure_content_safety"
	GuardrailProviderTypeDeepIntShieldModels = "deepintshield_models"
	GuardrailProviderTypeGCPModelArmor       = "gcp_model_armor"
	GuardrailProviderTypeWebhook             = "webhook"
	GuardrailProviderTypeManaged             = "managed"
	GuardrailProviderModeCustomerOwned       = "customer_owned"
	GuardrailProviderModeManaged             = "managed"
	GuardrailPolicyScopeInput                = "input"
	GuardrailPolicyScopeOutput               = "output"
	GuardrailPolicyScopeAction               = "action"
	GuardrailPolicyScopeMCP                  = "mcp"
	GuardrailPolicyScopeRAG                  = "rag"
	GuardrailEnforcementModeMonitor          = "monitor"
	GuardrailEnforcementModeBlock            = "block"
	GuardrailEnforcementModeRedact           = "redact"
	GuardrailEnforcementModeSandbox          = "sandbox"
	GuardrailEnforcementModeApproval         = "approval"
	// Execution mode controls whether guardrail evaluation blocks the
	// request path. Sync (default) is the historical behaviour: the LLM
	// call cannot proceed until the runtime returns a decision, and a
	// "deny" short-circuits with 403. Async runs the runtime evaluation
	// off the request path entirely - useful for log-only observability
	// of *non-enforcement-class* checks during rollout. Shadow keeps the
	// evaluation inline (so latency reflects production), but the
	// decision is downgraded to "allow"; the would-be decision is logged
	// and surfaced via the X-DeepIntShield-Guardrail-Status header so
	// teams can validate a new check's false-positive rate before
	// flipping it to enforcement.
	GuardrailExecutionModeSync            = "sync"
	GuardrailExecutionModeAsync           = "async"
	GuardrailExecutionModeShadow          = "shadow"
	GuardrailPolicyVersionStatusDraft     = "draft"
	GuardrailPolicyVersionStatusPublished = "published"
	GuardrailPolicyVersionStatusArchived  = "archived"
	GuardrailDomainPackStatusActive       = "active"
	GuardrailDomainPackStatusDraft        = "draft"
	GuardrailMCPActionClassRead           = "read"
	GuardrailMCPActionClassWrite          = "write"
	GuardrailMCPActionClassDestructive    = "destructive"
	GuardrailMCPActionClassNetwork        = "network"
	GuardrailMCPActionClassExec           = "exec"
)

type TableGuardrailProvider struct {
	ID       string `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_providers_tenant_name,priority:1" json:"-"`
	// WorkspaceID narrows a provider (Safety Provider or DeepIntShield
	// Models / AI Models entry) to a single workspace. NULL means the row
	// applies to every workspace in the tenant - used only for legacy
	// pre-migration rows; the store stamps the active workspace on every
	// new create so post-fix rows always carry a value.
	WorkspaceID        *string        `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	Name               string         `gorm:"type:varchar(255);not null;index:idx_guardrail_providers_tenant_name,priority:2" json:"name"`
	ProviderType       string         `gorm:"column:provider_type;type:varchar(64);not null;index" json:"provider_type"`
	Mode               string         `gorm:"type:varchar(32);not null;default:'customer_owned'" json:"mode"`
	CustomerID         *string        `gorm:"column:customer_id;type:varchar(255);index" json:"customer_id,omitempty"`
	Enabled            bool           `gorm:"not null;default:true;index" json:"enabled"`
	Region             string         `gorm:"type:varchar(128)" json:"region"`
	Endpoint           string         `gorm:"type:text" json:"endpoint"`
	CredentialsJSON    string         `gorm:"column:credentials_json;type:text" json:"-"`
	ConnectionMetaJSON string         `gorm:"column:connection_meta_json;type:text" json:"-"`
	LastTestedAt       *time.Time     `gorm:"index" json:"last_tested_at,omitempty"`
	LastError          string         `gorm:"type:text" json:"last_error,omitempty"`
	EncryptionStatus   string         `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	CreatedAt          time.Time      `gorm:"index;not null" json:"created_at"`
	UpdatedAt          time.Time      `gorm:"index;not null" json:"updated_at"`
	Credentials        map[string]any `gorm:"-" json:"credentials,omitempty"`
	ConnectionMeta     map[string]any `gorm:"-" json:"connection_meta,omitempty"`
}

func (TableGuardrailProvider) TableName() string {
	return "guardrail_providers"
}

func (p *TableGuardrailProvider) BeforeSave(tx *gorm.DB) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Guardrail Provider"
	}
	p.ProviderType = strings.ToLower(strings.TrimSpace(p.ProviderType))
	if p.ProviderType == "" {
		p.ProviderType = GuardrailProviderTypeManaged
	}
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode == "" {
		p.Mode = GuardrailProviderModeCustomerOwned
	}
	p.Region = strings.TrimSpace(p.Region)
	p.Endpoint = strings.TrimSpace(p.Endpoint)
	p.LastError = strings.TrimSpace(p.LastError)

	if p.Credentials != nil {
		data, err := json.Marshal(p.Credentials)
		if err != nil {
			return err
		}
		p.CredentialsJSON = string(data)
	}
	if p.ConnectionMeta != nil {
		data, err := json.Marshal(p.ConnectionMeta)
		if err != nil {
			return err
		}
		p.ConnectionMetaJSON = string(data)
	}
	if encrypt.IsEnabled() {
		if err := encryptString(&p.CredentialsJSON); err != nil {
			return fmt.Errorf("failed to encrypt guardrail provider credentials: %w", err)
		}
		if strings.TrimSpace(p.CredentialsJSON) != "" {
			p.EncryptionStatus = EncryptionStatusEncrypted
		}
	}
	return nil
}

func (p *TableGuardrailProvider) AfterFind(tx *gorm.DB) error {
	if p.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&p.CredentialsJSON); err != nil {
			return fmt.Errorf("failed to decrypt guardrail provider credentials: %w", err)
		}
	}
	if err := decodeJSONStringMap(p.CredentialsJSON, &p.Credentials); err != nil {
		return err
	}
	if err := decodeJSONStringMap(p.ConnectionMetaJSON, &p.ConnectionMeta); err != nil {
		return err
	}
	return nil
}

type TableGuardrailPolicy struct {
	ID       string `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_policies_tenant_name,priority:1;index:idx_guardrail_policies_tenant_default,priority:1" json:"-"`
	// OrgID is the UI-tenant (org) the policy belongs to - distinct from
	// TenantID, which is the email-keyed partition shared across every UI
	// tenant the same user owns. Without OrgID a "tenant-wide" policy
	// (WorkspaceID IS NULL) leaks across the user's other orgs because the
	// email-keyed TenantID can't tell them apart. NULL is a grandfathered
	// pre-migration row: the store treats those as hidden under active-org
	// scoping. New policies always stamp the active org on create.
	OrgID *string `gorm:"column:org_id;type:varchar(64);index" json:"org_id,omitempty"`
	// WorkspaceID narrows the policy to a single workspace within the org.
	// NULL means org-wide (applies to every workspace in the org).
	WorkspaceID     *string        `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	Name            string         `gorm:"type:varchar(255);not null;index:idx_guardrail_policies_tenant_name,priority:2" json:"name"`
	Description     string         `gorm:"type:text" json:"description"`
	DomainPackID    *string        `gorm:"column:domain_pack_id;type:varchar(255);index" json:"domain_pack_id,omitempty"`
	Scope           string         `gorm:"type:varchar(32);not null;default:'input';index" json:"scope"`
	EnforcementMode string         `gorm:"column:enforcement_mode;type:varchar(32);not null;default:'monitor';index" json:"enforcement_mode"`
	SamplingRate    int            `gorm:"column:sampling_rate;not null;default:100" json:"sampling_rate"`
	TimeoutMs       int            `gorm:"column:timeout_ms;not null;default:150" json:"timeout_ms"`
	Enabled         bool           `gorm:"not null;default:true;index" json:"enabled"`
	IsDefault       bool           `gorm:"column:is_default;not null;default:false;index:idx_guardrail_policies_tenant_default,priority:2" json:"is_default"`
	ActiveVersionID *string        `gorm:"column:active_version_id;type:varchar(255);index" json:"active_version_id,omitempty"`
	ExecutionMode   string         `gorm:"column:execution_mode;type:varchar(16);not null;default:'sync';index" json:"execution_mode"`
	ShadowUntil     *time.Time     `gorm:"column:shadow_until;index" json:"shadow_until,omitempty"`
	MetadataJSON    string         `gorm:"column:metadata_json;type:text" json:"-"`
	CreatedAt       time.Time      `gorm:"index;not null" json:"created_at"`
	UpdatedAt       time.Time      `gorm:"index;not null" json:"updated_at"`
	Metadata        map[string]any `gorm:"-" json:"metadata,omitempty"`
}

func (TableGuardrailPolicy) TableName() string {
	return "guardrail_policies"
}

func (p *TableGuardrailPolicy) BeforeSave(tx *gorm.DB) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Untitled Policy"
	}
	p.Description = strings.TrimSpace(p.Description)
	p.Scope = strings.ToLower(strings.TrimSpace(p.Scope))
	if p.Scope == "" {
		p.Scope = GuardrailPolicyScopeInput
	}
	p.EnforcementMode = strings.ToLower(strings.TrimSpace(p.EnforcementMode))
	if p.EnforcementMode == "" {
		p.EnforcementMode = GuardrailEnforcementModeMonitor
	}
	if p.EnforcementMode == GuardrailEnforcementModeApproval {
		p.EnforcementMode = GuardrailEnforcementModeBlock
	}
	if p.SamplingRate <= 0 {
		p.SamplingRate = 100
	}
	if p.SamplingRate > 100 {
		p.SamplingRate = 100
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 150
	}
	p.ExecutionMode = strings.ToLower(strings.TrimSpace(p.ExecutionMode))
	switch p.ExecutionMode {
	case GuardrailExecutionModeAsync, GuardrailExecutionModeShadow:
		// preserve
	default:
		p.ExecutionMode = GuardrailExecutionModeSync
	}
	// Shadow expiry only makes sense in shadow mode. Clear it in any
	// other mode so a stale value doesn't auto-flip behaviour later.
	if p.ExecutionMode != GuardrailExecutionModeShadow {
		p.ShadowUntil = nil
	}
	if p.Metadata != nil {
		data, err := json.Marshal(p.Metadata)
		if err != nil {
			return err
		}
		p.MetadataJSON = string(data)
	}
	return nil
}

func (p *TableGuardrailPolicy) AfterFind(tx *gorm.DB) error {
	return decodeJSONStringMap(p.MetadataJSON, &p.Metadata)
}

type TableGuardrailPolicyVersion struct {
	ID             string         `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID       string         `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_policy_versions_tenant_policy_version,priority:1" json:"-"`
	PolicyID       string         `gorm:"column:policy_id;type:varchar(255);not null;index:idx_guardrail_policy_versions_tenant_policy_version,priority:2;index" json:"policy_id"`
	Version        int            `gorm:"not null;index:idx_guardrail_policy_versions_tenant_policy_version,priority:3" json:"version"`
	Status         string         `gorm:"type:varchar(32);not null;default:'draft';index" json:"status"`
	DefinitionJSON string         `gorm:"column:definition_json;type:text" json:"-"`
	PublishedBy    string         `gorm:"column:published_by;type:varchar(255)" json:"published_by,omitempty"`
	PublishedAt    *time.Time     `gorm:"index" json:"published_at,omitempty"`
	CreatedAt      time.Time      `gorm:"index;not null" json:"created_at"`
	Definition     map[string]any `gorm:"-" json:"definition,omitempty"`
}

func (TableGuardrailPolicyVersion) TableName() string {
	return "guardrail_policy_versions"
}

func (p *TableGuardrailPolicyVersion) BeforeSave(tx *gorm.DB) error {
	p.PolicyID = strings.TrimSpace(p.PolicyID)
	p.Status = strings.ToLower(strings.TrimSpace(p.Status))
	if p.Status == "" {
		p.Status = GuardrailPolicyVersionStatusDraft
	}
	p.PublishedBy = strings.TrimSpace(p.PublishedBy)
	if p.Definition != nil {
		data, err := json.Marshal(p.Definition)
		if err != nil {
			return err
		}
		p.DefinitionJSON = string(data)
	}
	return nil
}

func (p *TableGuardrailPolicyVersion) AfterFind(tx *gorm.DB) error {
	return decodeJSONStringMap(p.DefinitionJSON, &p.Definition)
}

type TableGuardrailDomainPack struct {
	ID                           string         `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID                     string         `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_domain_packs_tenant_slug,priority:1" json:"-"`
	Name                         string         `gorm:"type:varchar(255);not null" json:"name"`
	Slug                         string         `gorm:"type:varchar(128);not null;index:idx_guardrail_domain_packs_tenant_slug,priority:2" json:"slug"`
	Description                  string         `gorm:"type:text" json:"description"`
	Vertical                     string         `gorm:"type:varchar(128);index" json:"vertical"`
	Status                       string         `gorm:"type:varchar(32);not null;default:'active';index" json:"status"`
	ControlsJSON                 string         `gorm:"column:controls_json;type:text" json:"-"`
	ThreatTemplatesJSON          string         `gorm:"column:threat_templates_json;type:text" json:"-"`
	RecommendedActionsJSON       string         `gorm:"column:recommended_actions_json;type:text" json:"-"`
	TemplatePolicyDefinitionJSON string         `gorm:"column:template_policy_definition_json;type:text" json:"-"`
	CreatedAt                    time.Time      `gorm:"index;not null" json:"created_at"`
	UpdatedAt                    time.Time      `gorm:"index;not null" json:"updated_at"`
	Controls                     []string       `gorm:"-" json:"controls,omitempty"`
	ThreatTemplates              []string       `gorm:"-" json:"threat_templates,omitempty"`
	RecommendedActions           []string       `gorm:"-" json:"recommended_actions,omitempty"`
	TemplatePolicyDefinition     map[string]any `gorm:"-" json:"template_policy_definition,omitempty"`
}

func (TableGuardrailDomainPack) TableName() string {
	return "guardrail_domain_packs"
}

func (p *TableGuardrailDomainPack) BeforeSave(tx *gorm.DB) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Slug = strings.ToLower(strings.TrimSpace(p.Slug))
	p.Description = strings.TrimSpace(p.Description)
	p.Vertical = strings.TrimSpace(p.Vertical)
	p.Status = strings.ToLower(strings.TrimSpace(p.Status))
	if p.Status == "" {
		p.Status = GuardrailDomainPackStatusActive
	}
	if p.Controls != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(p.Controls))
		if err != nil {
			return err
		}
		p.ControlsJSON = string(data)
	}
	if p.ThreatTemplates != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(p.ThreatTemplates))
		if err != nil {
			return err
		}
		p.ThreatTemplatesJSON = string(data)
	}
	if p.RecommendedActions != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(p.RecommendedActions))
		if err != nil {
			return err
		}
		p.RecommendedActionsJSON = string(data)
	}
	if p.TemplatePolicyDefinition != nil {
		data, err := json.Marshal(p.TemplatePolicyDefinition)
		if err != nil {
			return err
		}
		p.TemplatePolicyDefinitionJSON = string(data)
	}
	return nil
}

func (p *TableGuardrailDomainPack) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(p.ControlsJSON, &p.Controls); err != nil {
		return err
	}
	if err := decodeJSONStringSlice(p.ThreatTemplatesJSON, &p.ThreatTemplates); err != nil {
		return err
	}
	if err := decodeJSONStringSlice(p.RecommendedActionsJSON, &p.RecommendedActions); err != nil {
		return err
	}
	return decodeJSONStringMap(p.TemplatePolicyDefinitionJSON, &p.TemplatePolicyDefinition)
}

type TableGuardrailPolicyProviderBinding struct {
	ID         string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID   string    `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_policy_provider_bindings_tenant_policy,priority:1" json:"-"`
	PolicyID   string    `gorm:"column:policy_id;type:varchar(255);not null;index:idx_guardrail_policy_provider_bindings_tenant_policy,priority:2;index" json:"policy_id"`
	ProviderID string    `gorm:"column:provider_id;type:varchar(255);not null;index" json:"provider_id"`
	Stage      string    `gorm:"type:varchar(32);not null;default:'input';index" json:"stage"`
	Priority   int       `gorm:"not null;default:100" json:"priority"`
	Enabled    bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedAt  time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt  time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableGuardrailPolicyProviderBinding) TableName() string {
	return "guardrail_policy_provider_bindings"
}

func (p *TableGuardrailPolicyProviderBinding) BeforeSave(tx *gorm.DB) error {
	p.PolicyID = strings.TrimSpace(p.PolicyID)
	p.ProviderID = strings.TrimSpace(p.ProviderID)
	p.Stage = strings.ToLower(strings.TrimSpace(p.Stage))
	if p.Stage == "" {
		p.Stage = GuardrailPolicyScopeInput
	}
	return nil
}

type TableGuardrailMCPToolPolicy struct {
	ID                    string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID              string    `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_mcp_tool_policies_tenant_policy,priority:1" json:"-"`
	PolicyID              string    `gorm:"column:policy_id;type:varchar(255);not null;index:idx_guardrail_mcp_tool_policies_tenant_policy,priority:2;index" json:"policy_id"`
	ServerLabel           string    `gorm:"column:server_label;type:varchar(255);index" json:"server_label"`
	ToolName              string    `gorm:"column:tool_name;type:varchar(255);index" json:"tool_name"`
	ActionClass           string    `gorm:"column:action_class;type:varchar(32);index" json:"action_class"`
	ApprovalNeeded        bool      `gorm:"column:approval_needed;not null;default:false" json:"approval_needed"`
	AllowedDomainsJSON    string    `gorm:"column:allowed_domains_json;type:text" json:"-"`
	AllowedIdentitiesJSON string    `gorm:"column:allowed_identities_json;type:text" json:"-"`
	CreatedAt             time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt             time.Time `gorm:"index;not null" json:"updated_at"`
	AllowedDomains        []string  `gorm:"-" json:"allowed_domains,omitempty"`
	AllowedIdentities     []string  `gorm:"-" json:"allowed_identities,omitempty"`
}

func (TableGuardrailMCPToolPolicy) TableName() string {
	return "guardrail_mcp_tool_policies"
}

func (p *TableGuardrailMCPToolPolicy) BeforeSave(tx *gorm.DB) error {
	p.PolicyID = strings.TrimSpace(p.PolicyID)
	p.ServerLabel = strings.TrimSpace(p.ServerLabel)
	p.ToolName = strings.TrimSpace(p.ToolName)
	p.ActionClass = strings.ToLower(strings.TrimSpace(p.ActionClass))
	if p.ActionClass == "" {
		p.ActionClass = GuardrailMCPActionClassRead
	}
	if p.AllowedDomains != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(p.AllowedDomains))
		if err != nil {
			return err
		}
		p.AllowedDomainsJSON = string(data)
	}
	if p.AllowedIdentities != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(p.AllowedIdentities))
		if err != nil {
			return err
		}
		p.AllowedIdentitiesJSON = string(data)
	}
	return nil
}

func (p *TableGuardrailMCPToolPolicy) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(p.AllowedDomainsJSON, &p.AllowedDomains); err != nil {
		return err
	}
	return decodeJSONStringSlice(p.AllowedIdentitiesJSON, &p.AllowedIdentities)
}

func decodeJSONStringMap(raw string, target *map[string]any) error {
	if target == nil {
		return nil
	}
	*target = nil
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return err
	}
	*target = decoded
	return nil
}

func decodeJSONStringSlice(raw string, target *[]string) error {
	if target == nil {
		return nil
	}
	*target = nil
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var decoded []string
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return err
	}
	*target = decoded
	return nil
}

func dedupeGuardrailStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}
