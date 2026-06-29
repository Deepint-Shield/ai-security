// Package tables defines GORM models for the Agentic Security control plane.
//
// All tables in this file enforce two non-negotiable invariants from the
// architecture spec (v0.7):
//   - tenant + workspace columns scope every row (4-layer isolation),
//   - zero-data-retention - argument values are digested (sha256) and never
//     stored raw; verdict records carry args_digest only.
//
// The hot-path decision algorithm reads the policy version + virtual_key +
// tenant + workspace from these tables; mutating any of them changes the
// decision cache key (Part II, §2.5 of the spec) so callers do not need to
// trigger an explicit cache flush.
package tables

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/encrypt"
	"gorm.io/gorm"
)

// ============================================================================
// Constants - verdicts, sensitivity tiers, enforcement modes, identity types
// ============================================================================

const (
	// Verdicts returned by decide() - exhaustive per §1.4 of the spec.
	AgenticVerdictAllow           = "ALLOW"
	AgenticVerdictDeny            = "DENY"
	AgenticVerdictRequireApproval = "REQUIRE_APPROVAL"
	AgenticVerdictMask            = "MASK"

	// Tool sensitivity tiers drive fail posture and revocation path.
	AgenticToolSensitivityLow    = "low"
	AgenticToolSensitivityMedium = "medium"
	AgenticToolSensitivityHigh   = "high"

	AgenticFailPostureClosed = "closed" // default for high/medium
	AgenticFailPostureOpen   = "open"   // only for low-risk reads

	AgenticRevocationRealtime = "realtime" // full revocation check
	AgenticRevocationCached   = "cached"   // cached-JWKS local verify

	// Per-tenant enforcement modes - see §4.6 Rollout.
	AgenticEnforcementShadow  = "shadow"
	AgenticEnforcementCanary  = "canary"
	AgenticEnforcementEnforce = "enforce"

	// Identity providers supported by the broker.
	AgenticIdentityProviderEntra  = "entra_agent_id"
	AgenticIdentityProviderZeroID = "zeroid"
	AgenticIdentityProviderOIDC   = "generic_oidc"

	// Entra blueprint credential types (FIC recommended; cert/secret discouraged).
	AgenticEntraCredentialFIC    = "managed_identity_fic"
	AgenticEntraCredentialCert   = "certificate"
	AgenticEntraCredentialSecret = "client_secret"

	// Autonomy budget tiers tied to recovery_cost.
	AgenticAutonomyBudgetLow    = "low"
	AgenticAutonomyBudgetMedium = "medium"
	AgenticAutonomyBudgetHigh   = "high"

	// Token scenarios (Entra) - see Part VII.
	AgenticTokenScenarioAppOnly       = "app_only"
	AgenticTokenScenarioUserOBO       = "user_obo"
	AgenticTokenScenarioImpersonation = "agent_user_impersonation"

	// Policy lifecycle.
	AgenticPolicyStatusDraft     = "draft"
	AgenticPolicyStatusStaged    = "staged"
	AgenticPolicyStatusPublished = "published"
	AgenticPolicyStatusArchived  = "archived"

	// Approval workflow states.
	AgenticApprovalStatePending  = "pending"
	AgenticApprovalStateApproved = "approved"
	AgenticApprovalStateDenied   = "denied"
	AgenticApprovalStateExpired  = "expired"
)

// ============================================================================
// TableAgenticPolicy - RBAC/ABAC/ReBAC policy bundle (compiled to OPA Rego)
// ============================================================================

// TableAgenticPolicy is a versioned, GitOps-managed policy bundle. The visual
// rule builder UI compiles WHEN/IF/THEN into the same Rego that an engineer
// would write by hand (single source of truth, §6.1 of the spec).
//
// DefinitionJSON carries the structured rule (subject role, target tool,
// conditions, verdict, obligations, approvers); GeneratedRego is the
// compiled output that the PDP loads as a WASM module. PolicyVersion is part
// of the L1 cache key, so bumping it via a new published row is an instant
// structural invalidation (§2.5).
type TableAgenticPolicy struct {
	ID             string  `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID       string  `gorm:"column:tenant_id;type:varchar(255);index:idx_agentic_policies_tenant_name,priority:1" json:"-"`
	OrgID          *string `gorm:"column:org_id;type:varchar(64);index" json:"org_id,omitempty"`
	WorkspaceID    *string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	Name           string  `gorm:"type:varchar(255);not null;index:idx_agentic_policies_tenant_name,priority:2" json:"name"`
	Description    string  `gorm:"type:text" json:"description"`
	Status         string  `gorm:"type:varchar(32);not null;default:'draft';index" json:"status"`
	PolicyVersion  int     `gorm:"column:policy_version;not null;default:1;index" json:"policy_version"`
	Enabled        bool    `gorm:"not null;default:true;index" json:"enabled"`
	DefinitionJSON string  `gorm:"column:definition_json;type:text" json:"-"`
	GeneratedRego  string  `gorm:"column:generated_rego;type:text" json:"generated_rego"`
	// AppliesToAllKeys decides whether this policy fires for every VK in
	// the workspace (true) or only for the VKs explicitly listed in the
	// agentic_policy_vk_targets join table (false). Default true so
	// existing policies continue to apply broadly without per-row edits.
	AppliesToAllKeys bool       `gorm:"column:applies_to_all_keys;not null;default:true;index" json:"applies_to_all_keys"`
	TestsPassed      int        `gorm:"column:tests_passed;not null;default:0" json:"tests_passed"`
	TestsTotal       int        `gorm:"column:tests_total;not null;default:0" json:"tests_total"`
	OwasptTags       string     `gorm:"column:owasp_tags;type:varchar(255)" json:"owasp_tags,omitempty"`
	StagedBy         string     `gorm:"column:staged_by;type:varchar(255)" json:"staged_by,omitempty"`
	StagedAt         *time.Time `gorm:"column:staged_at" json:"staged_at,omitempty"`
	ApprovedBy       string     `gorm:"column:approved_by;type:varchar(255)" json:"approved_by,omitempty"`
	ApprovedAt       *time.Time `gorm:"column:approved_at" json:"approved_at,omitempty"`
	PublishedAt      *time.Time `gorm:"column:published_at;index" json:"published_at,omitempty"`
	CreatedBy        string     `gorm:"column:created_by;type:varchar(255)" json:"created_by,omitempty"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"index;not null" json:"updated_at"`

	// Computed / convenience fields (not persisted).
	Definition map[string]any `gorm:"-" json:"definition,omitempty"`
	// Target lists are populated by the store from the three join tables
	// on read and written back as a full replace on update. When
	// AppliesToAllKeys = true the targets are ignored at decide time
	// (broad scope wins); operators may still keep target lists around
	// for documentation purposes.
	TargetVirtualKeyIDs []string `gorm:"-" json:"target_virtual_key_ids,omitempty"`
	TargetTeamIDs       []string `gorm:"-" json:"target_team_ids,omitempty"`
	TargetMemberIDs     []string `gorm:"-" json:"target_member_ids,omitempty"`
}

func (TableAgenticPolicy) TableName() string { return "agentic_policies" }

// ============================================================================
// TableAgenticPolicyVKTarget - join table: policy ↔ virtual key
// ============================================================================
//
// Used when the parent agentic_policies row has applies_to_all_keys = false.
// One row per (policy, vk) assignment. Cascade delete on the parent policy
// and on the referenced VK keeps the table self-cleaning - no orphans, no
// JSON-array surgery, no nightly cleanup job.
//
// tenant_id + workspace_id are denormalized so the PEP's pre-fetch and any
// audit query can use a single composite index without joining back to the
// parent. The DB itself enforces that VK and policy live in the same
// workspace through the validation in agentic_store; the denormalized
// columns are a read-path optimization, not a correctness guarantee.

type TableAgenticPolicyVKTarget struct {
	// PolicyID references agentic_policies.id with ON DELETE CASCADE so
	// deleting a policy automatically cleans up its target assignments.
	PolicyID string `gorm:"column:policy_id;type:varchar(64);not null;primaryKey;index:idx_agentic_policy_vk_targets_workspace,priority:3" json:"policy_id"`
	// VirtualKeyID references governance_virtual_keys.id with ON DELETE
	// CASCADE so deleting a VK auto-removes it from every policy that
	// targeted it (no nightly cleanup, no orphaned references).
	VirtualKeyID string    `gorm:"column:virtual_key_id;type:varchar(64);not null;primaryKey;index:idx_agentic_policy_vk_targets_vk,priority:1" json:"virtual_key_id"`
	TenantID     string    `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_policy_vk_targets_workspace,priority:1" json:"-"`
	WorkspaceID  string    `gorm:"column:workspace_id;type:varchar(64);not null;index:idx_agentic_policy_vk_targets_workspace,priority:2;index:idx_agentic_policy_vk_targets_vk,priority:2" json:"workspace_id"`
	CreatedAt    time.Time `gorm:"not null" json:"created_at"`

	// FK relations - declared so AutoMigrate emits the constraints on
	// engines that honor them (Postgres always; SQLite when foreign_keys
	// pragma is on, which configstore enables at connect time).
	Policy     *TableAgenticPolicy `gorm:"foreignKey:PolicyID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
	VirtualKey *TableVirtualKey    `gorm:"foreignKey:VirtualKeyID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
}

func (TableAgenticPolicyVKTarget) TableName() string { return "agentic_policy_vk_targets" }

// ============================================================================
// TableAgenticPolicyTeamTarget - join table: policy ↔ team
// ============================================================================
//
// Same shape as TableAgenticPolicyVKTarget but for org-level team
// targeting. A policy with a Team target fires for every VK whose
// `team_id` matches one of the targets at decide time. Cascade delete
// on Policy and on the referenced governance_teams row keeps the join
// table self-cleaning.

type TableAgenticPolicyTeamTarget struct {
	PolicyID    string    `gorm:"column:policy_id;type:varchar(64);not null;primaryKey;index:idx_agentic_policy_team_targets_workspace,priority:3" json:"policy_id"`
	TeamID      string    `gorm:"column:team_id;type:varchar(64);not null;primaryKey;index:idx_agentic_policy_team_targets_team,priority:1" json:"team_id"`
	TenantID    string    `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_policy_team_targets_workspace,priority:1" json:"-"`
	WorkspaceID string    `gorm:"column:workspace_id;type:varchar(64);not null;index:idx_agentic_policy_team_targets_workspace,priority:2;index:idx_agentic_policy_team_targets_team,priority:2" json:"workspace_id"`
	CreatedAt   time.Time `gorm:"not null" json:"created_at"`

	Policy *TableAgenticPolicy `gorm:"foreignKey:PolicyID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
	Team   *TableTeam          `gorm:"foreignKey:TeamID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
}

func (TableAgenticPolicyTeamTarget) TableName() string { return "agentic_policy_team_targets" }

// ============================================================================
// TableAgenticPolicyMemberTarget - join table: policy ↔ member (customer)
// ============================================================================
//
// Same shape as the other two target tables. A policy with a Member
// target fires for every VK whose `customer_id` matches one of the
// targets at decide time.

type TableAgenticPolicyMemberTarget struct {
	PolicyID    string    `gorm:"column:policy_id;type:varchar(64);not null;primaryKey;index:idx_agentic_policy_member_targets_workspace,priority:3" json:"policy_id"`
	MemberID    string    `gorm:"column:member_id;type:varchar(64);not null;primaryKey;index:idx_agentic_policy_member_targets_member,priority:1" json:"member_id"`
	TenantID    string    `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_policy_member_targets_workspace,priority:1" json:"-"`
	WorkspaceID string    `gorm:"column:workspace_id;type:varchar(64);not null;index:idx_agentic_policy_member_targets_workspace,priority:2;index:idx_agentic_policy_member_targets_member,priority:2" json:"workspace_id"`
	CreatedAt   time.Time `gorm:"not null" json:"created_at"`

	Policy *TableAgenticPolicy `gorm:"foreignKey:PolicyID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
	Member *TableCustomer      `gorm:"foreignKey:MemberID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
}

func (TableAgenticPolicyMemberTarget) TableName() string { return "agentic_policy_member_targets" }

func (p *TableAgenticPolicy) BeforeSave(tx *gorm.DB) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Untitled Policy"
	}
	p.Status = strings.ToLower(strings.TrimSpace(p.Status))
	if p.Status == "" {
		p.Status = AgenticPolicyStatusDraft
	}
	if p.Definition != nil {
		data, err := json.Marshal(p.Definition)
		if err != nil {
			return fmt.Errorf("marshal policy definition: %w", err)
		}
		p.DefinitionJSON = string(data)
	}
	return nil
}

func (p *TableAgenticPolicy) AfterFind(tx *gorm.DB) error {
	return decodeJSONStringMap(p.DefinitionJSON, &p.Definition)
}

// ============================================================================
// TableAgenticToolTiering - per-tool sensitivity (drives fail posture)
// ============================================================================

type TableAgenticToolTiering struct {
	ID              string  `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID        string  `gorm:"column:tenant_id;type:varchar(255);index:idx_agentic_tools_tenant_name,priority:1" json:"-"`
	WorkspaceID     *string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	ToolName        string  `gorm:"column:tool_name;type:varchar(255);not null;index:idx_agentic_tools_tenant_name,priority:2" json:"tool_name"`
	DisplayName     string  `gorm:"column:display_name;type:varchar(255)" json:"display_name,omitempty"`
	Sensitivity     string  `gorm:"type:varchar(16);not null;default:'medium';index" json:"sensitivity"`
	FailPosture     string  `gorm:"column:fail_posture;type:varchar(16);not null;default:'closed'" json:"fail_posture"`
	RevocationPath  string  `gorm:"column:revocation_path;type:varchar(16);not null;default:'cached'" json:"revocation_path"`
	ObligationsJSON string  `gorm:"column:obligations_json;type:text" json:"-"`
	Enforce         bool    `gorm:"not null;default:true;index" json:"enforce"`
	ArgsSchemaJSON  string  `gorm:"column:args_schema_json;type:text" json:"-"`
	ActionClass     string  `gorm:"column:action_class;type:varchar(32);index" json:"action_class,omitempty"`
	// IntegrityPosture controls what the Tool Integrity Engine does when a
	// call to this tool diverges from its declared action_class / args_schema:
	// flag (record only) | approval (route to human-in-the-loop) | block (deny).
	IntegrityPosture string `gorm:"column:integrity_posture;type:varchar(16);not null;default:'flag'" json:"integrity_posture"`
	RecoveryCost     string `gorm:"column:recovery_cost;type:varchar(16);not null;default:'medium'" json:"recovery_cost"`
	// ASI04 supply-chain: PinnedFingerprint anchors the tool to a known-good
	// behavior fingerprint. When set, a call whose observed ToolFingerprint
	// differs trips fingerprint_drift (tampered / typosquatted / re-described
	// tool). PinnedBy/PinnedAt record the attestation for the AIBOM export.
	PinnedFingerprint string     `gorm:"column:pinned_fingerprint;type:varchar(128);index" json:"pinned_fingerprint,omitempty"`
	PinnedBy          string     `gorm:"column:pinned_by;type:varchar(255)" json:"pinned_by,omitempty"`
	PinnedAt          *time.Time `gorm:"column:pinned_at" json:"pinned_at,omitempty"`
	CreatedAt         time.Time  `gorm:"not null;index" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"not null;index" json:"updated_at"`

	Obligations []string       `gorm:"-" json:"obligations,omitempty"`
	ArgsSchema  map[string]any `gorm:"-" json:"args_schema,omitempty"`
}

func (TableAgenticToolTiering) TableName() string { return "agentic_tool_tiering" }

func (t *TableAgenticToolTiering) BeforeSave(tx *gorm.DB) error {
	t.ToolName = strings.TrimSpace(t.ToolName)
	t.Sensitivity = strings.ToLower(strings.TrimSpace(t.Sensitivity))
	switch t.Sensitivity {
	case AgenticToolSensitivityLow, AgenticToolSensitivityMedium, AgenticToolSensitivityHigh:
	default:
		t.Sensitivity = AgenticToolSensitivityMedium
	}
	t.FailPosture = strings.ToLower(strings.TrimSpace(t.FailPosture))
	if t.FailPosture != AgenticFailPostureOpen {
		t.FailPosture = AgenticFailPostureClosed
	}
	t.RevocationPath = strings.ToLower(strings.TrimSpace(t.RevocationPath))
	if t.RevocationPath != AgenticRevocationRealtime {
		t.RevocationPath = AgenticRevocationCached
	}
	t.IntegrityPosture = strings.ToLower(strings.TrimSpace(t.IntegrityPosture))
	switch t.IntegrityPosture {
	case "block", "approval", "flag":
	default:
		t.IntegrityPosture = "flag"
	}
	if t.Obligations != nil {
		data, err := json.Marshal(dedupeGuardrailStrings(t.Obligations))
		if err != nil {
			return err
		}
		t.ObligationsJSON = string(data)
	}
	if t.ArgsSchema != nil {
		data, err := json.Marshal(t.ArgsSchema)
		if err != nil {
			return err
		}
		t.ArgsSchemaJSON = string(data)
	}
	return nil
}

func (t *TableAgenticToolTiering) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(t.ObligationsJSON, &t.Obligations); err != nil {
		return err
	}
	return decodeJSONStringMap(t.ArgsSchemaJSON, &t.ArgsSchema)
}

// ============================================================================
// TableAgenticIdentityProvider - broker adapter configuration
// ============================================================================

// TableAgenticIdentityProvider holds the configuration for a single broker
// adapter (Entra Agent ID, ZeroID, or generic OIDC). The broker never stores
// upstream wire tokens - verification is signature-based against the
// provider's cached JWKS. Any credential needed for outbound calls
// (e.g. Entra FIC managed-identity object id) is stored encrypted at rest.
type TableAgenticIdentityProvider struct {
	ID           string  `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID     string  `gorm:"column:tenant_id;type:varchar(255);index:idx_agentic_idp_tenant_name,priority:1" json:"-"`
	WorkspaceID  *string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	Name         string  `gorm:"type:varchar(255);not null;index:idx_agentic_idp_tenant_name,priority:2" json:"name"`
	ProviderType string  `gorm:"column:provider_type;type:varchar(32);not null;index" json:"provider_type"`
	Enabled      bool    `gorm:"not null;default:true;index" json:"enabled"`
	Status       string  `gorm:"type:varchar(32);default:'unconfigured';index" json:"status"`

	// Common fields across providers.
	DirectoryTenantID string `gorm:"column:directory_tenant_id;type:varchar(255)" json:"directory_tenant_id,omitempty"`
	Authority         string `gorm:"column:authority;type:varchar(512)" json:"authority,omitempty"`
	Audience          string `gorm:"column:audience;type:varchar(512)" json:"audience,omitempty"`
	JWKSURI           string `gorm:"column:jwks_uri;type:varchar(512)" json:"jwks_uri,omitempty"`
	ScopesJSON        string `gorm:"column:scopes_json;type:text" json:"-"`

	// Entra-specific.
	BlueprintClientID string `gorm:"column:blueprint_client_id;type:varchar(255)" json:"blueprint_client_id,omitempty"`
	CredentialType    string `gorm:"column:credential_type;type:varchar(32);default:'managed_identity_fic'" json:"credential_type,omitempty"`
	MIPrincipalID     string `gorm:"column:mi_principal_id;type:varchar(255)" json:"mi_principal_id,omitempty"`
	FICAudience       string `gorm:"column:fic_audience;type:varchar(255);default:'api://AzureADTokenExchange'" json:"fic_audience,omitempty"`
	AllowCrossTenant  bool   `gorm:"column:allow_cross_tenant;not null;default:false" json:"allow_cross_tenant"`

	// Claim map persisted as JSON; defaults pre-filled for the provider type.
	ClaimMapJSON string `gorm:"column:claim_map_json;type:text" json:"-"`

	// Encrypted blob for any extra secret (cert / client-secret if used in dev).
	SecretBlob       string `gorm:"column:secret_blob;type:text" json:"-"`
	EncryptionStatus string `gorm:"type:varchar(20);default:'plain_text'" json:"-"`

	// Test results from "Test connection" run.
	LastTestedAt       *time.Time `gorm:"column:last_tested_at;index" json:"last_tested_at,omitempty"`
	LastTestOK         bool       `gorm:"column:last_test_ok" json:"last_test_ok"`
	LastError          string     `gorm:"type:text" json:"last_error,omitempty"`
	DetectedClaimsJSON string     `gorm:"column:detected_claims_json;type:text" json:"-"`

	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`

	Scopes         []string          `gorm:"-" json:"scopes,omitempty"`
	ClaimMap       map[string]string `gorm:"-" json:"claim_map,omitempty"`
	DetectedClaims []string          `gorm:"-" json:"detected_claims,omitempty"`
}

func (TableAgenticIdentityProvider) TableName() string { return "agentic_identity_providers" }

// DefaultEntraClaimMap returns the pre-filled Entra → DelegationContext
// claim mapping as specified in §7.5 of the spec.
func DefaultEntraClaimMap() map[string]string {
	return map[string]string{
		"xms_sub_fct": "principal",
		"xms_act_fct": "actor_chain",
		"idtyp":       "identity_type",
		"tid":         "tenant",
		"scp":         "scope",
	}
}

// DefaultZeroIDClaimMap maps RFC 8693 act-chain claims onto the same
// internal DelegationContext shape.
func DefaultZeroIDClaimMap() map[string]string {
	return map[string]string{
		"sub":   "principal",
		"act":   "actor_chain",
		"aud":   "tenant",
		"scope": "scope",
	}
}

func (p *TableAgenticIdentityProvider) BeforeSave(tx *gorm.DB) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Identity Provider"
	}
	p.ProviderType = strings.ToLower(strings.TrimSpace(p.ProviderType))
	if p.ProviderType == "" {
		p.ProviderType = AgenticIdentityProviderEntra
	}
	// Derive authority from directory tenant for Entra if empty.
	if p.ProviderType == AgenticIdentityProviderEntra && p.Authority == "" && p.DirectoryTenantID != "" {
		p.Authority = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", p.DirectoryTenantID)
	}
	if p.CredentialType == "" {
		p.CredentialType = AgenticEntraCredentialFIC
	}
	if p.FICAudience == "" {
		p.FICAudience = "api://AzureADTokenExchange"
	}
	if p.Scopes != nil {
		data, _ := json.Marshal(dedupeGuardrailStrings(p.Scopes))
		p.ScopesJSON = string(data)
	}
	if p.ClaimMap == nil {
		switch p.ProviderType {
		case AgenticIdentityProviderEntra:
			p.ClaimMap = DefaultEntraClaimMap()
		case AgenticIdentityProviderZeroID:
			p.ClaimMap = DefaultZeroIDClaimMap()
		}
	}
	if p.ClaimMap != nil {
		data, _ := json.Marshal(p.ClaimMap)
		p.ClaimMapJSON = string(data)
	}
	if p.DetectedClaims != nil {
		data, _ := json.Marshal(dedupeGuardrailStrings(p.DetectedClaims))
		p.DetectedClaimsJSON = string(data)
	}
	// Encrypt the optional secret blob at rest.
	if encrypt.IsEnabled() && strings.TrimSpace(p.SecretBlob) != "" {
		if err := encryptString(&p.SecretBlob); err != nil {
			return fmt.Errorf("encrypt identity provider secret: %w", err)
		}
		p.EncryptionStatus = EncryptionStatusEncrypted
	}
	return nil
}

func (p *TableAgenticIdentityProvider) AfterFind(tx *gorm.DB) error {
	if p.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&p.SecretBlob); err != nil {
			return fmt.Errorf("decrypt identity provider secret: %w", err)
		}
	}
	if err := decodeJSONStringSlice(p.ScopesJSON, &p.Scopes); err != nil {
		return err
	}
	if err := decodeJSONStringSlice(p.DetectedClaimsJSON, &p.DetectedClaims); err != nil {
		return err
	}
	if strings.TrimSpace(p.ClaimMapJSON) != "" {
		_ = json.Unmarshal([]byte(p.ClaimMapJSON), &p.ClaimMap)
	}
	return nil
}

// ============================================================================
// TableAgenticIdentity - agent identities discovered from a provider
// ============================================================================

type TableAgenticIdentity struct {
	ID                 string  `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID           string  `gorm:"column:tenant_id;type:varchar(255);index:idx_agentic_identity_tenant_name,priority:1" json:"-"`
	WorkspaceID        *string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id,omitempty"`
	ProviderID         string  `gorm:"column:provider_id;type:varchar(64);not null;index" json:"provider_id"`
	AgentName          string  `gorm:"column:agent_name;type:varchar(255);not null;index:idx_agentic_identity_tenant_name,priority:2" json:"agent_name"`
	BlueprintLabel     string  `gorm:"column:blueprint_label;type:varchar(128);index" json:"blueprint_label,omitempty"`
	CredentialKind     string  `gorm:"column:credential_kind;type:varchar(64)" json:"credential_kind,omitempty"`
	TokenScenariosJSON string  `gorm:"column:token_scenarios_json;type:text" json:"-"`
	OAuthScopesJSON    string  `gorm:"column:oauth_scopes_json;type:text" json:"-"`
	UpstreamTenant     string  `gorm:"column:upstream_tenant;type:varchar(255)" json:"upstream_tenant,omitempty"`
	SingleTenant       bool    `gorm:"column:single_tenant;not null;default:true" json:"single_tenant"`
	Status             string  `gorm:"type:varchar(32);not null;default:'active';index" json:"status"`
	Enabled            bool    `gorm:"not null;default:true;index" json:"enabled"`
	// ─── Ownership & lifecycle (accountability registry) ────────────────
	// Pillar 3 (identity & ownership): every agent must answer "who owns it,
	// who registered it, what is it for, what version". OwnerPrincipal is the
	// specific person accountable (not a team alias); OwningTeamID is the
	// owning team; Purpose is the agent's designed function; AgentVersion is
	// the deployed version; RegisteredBy is who created the registry entry.
	OwnerPrincipal string     `gorm:"column:owner_principal;type:varchar(255);index" json:"owner_principal,omitempty"`
	OwningTeamID   string     `gorm:"column:owning_team_id;type:varchar(64);index" json:"owning_team_id,omitempty"`
	Purpose        string     `gorm:"column:purpose;type:text" json:"purpose,omitempty"`
	AgentVersion   string     `gorm:"column:agent_version;type:varchar(64)" json:"agent_version,omitempty"`
	RegisteredBy   string     `gorm:"column:registered_by;type:varchar(255)" json:"registered_by,omitempty"`
	LastSeenAt     *time.Time `gorm:"column:last_seen_at;index" json:"last_seen_at,omitempty"`
	CreatedAt      time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt      time.Time  `gorm:"index;not null" json:"updated_at"`

	TokenScenarios []string `gorm:"-" json:"token_scenarios,omitempty"`
	OAuthScopes    []string `gorm:"-" json:"oauth_scopes,omitempty"`
}

func (TableAgenticIdentity) TableName() string { return "agentic_identities" }

func (a *TableAgenticIdentity) BeforeSave(tx *gorm.DB) error {
	a.AgentName = strings.TrimSpace(a.AgentName)
	if a.TokenScenarios != nil {
		data, _ := json.Marshal(dedupeGuardrailStrings(a.TokenScenarios))
		a.TokenScenariosJSON = string(data)
	}
	if a.OAuthScopes != nil {
		data, _ := json.Marshal(dedupeGuardrailStrings(a.OAuthScopes))
		a.OAuthScopesJSON = string(data)
	}
	return nil
}

func (a *TableAgenticIdentity) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(a.TokenScenariosJSON, &a.TokenScenarios); err != nil {
		return err
	}
	return decodeJSONStringSlice(a.OAuthScopesJSON, &a.OAuthScopes)
}

// ============================================================================
// TableAgenticBlueprint - an agent's DECLARED tool surface (registered by the
// SDK before a run via shield.agentic.govern). Powers full-graph visualization,
// policy pre-validation, and declared-vs-observed drift (ASI04 supply-chain).
// Structure only - names + edges, never arguments, secrets or data (ZDR).
// ============================================================================

type TableAgenticBlueprint struct {
	ID             string `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID       string `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_blueprint_tenant_hash,priority:1" json:"-"`
	WorkspaceID    string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	VirtualKeyID   string `gorm:"column:virtual_key_id;type:varchar(64);index" json:"virtual_key_id,omitempty"`
	Principal      string `gorm:"column:principal;type:varchar(255);index" json:"principal,omitempty"`
	SessionID      string `gorm:"column:session_id;type:varchar(128);index" json:"session_id,omitempty"`
	Framework      string `gorm:"column:framework;type:varchar(64);index" json:"framework"`
	Version        string `gorm:"column:version;type:varchar(64)" json:"version,omitempty"`
	NodesJSON      string `gorm:"column:nodes_json;type:text" json:"-"`
	ToolsJSON      string `gorm:"column:tools_json;type:text" json:"-"`
	EdgesJSON      string `gorm:"column:edges_json;type:text" json:"-"`
	MCPServersJSON string `gorm:"column:mcp_servers_json;type:text" json:"-"`
	// BlueprintHash is sha256 over {framework|sorted tools|edges} - the topology
	// fingerprint. A changed graph yields a new hash (tamper-evident, and the
	// hook for ASI04 topology-drift the same way fingerprint_drift works for tools).
	BlueprintHash string `gorm:"column:blueprint_hash;type:varchar(64);index:idx_agentic_blueprint_tenant_hash,priority:2" json:"blueprint_hash"`
	// ToolFingerprintsJSON: name → "src:<sha256[:16]>" (declared code identity, for
	// drift). ToolThreatsJSON: name → ToolThreatVerdict (the registration-time
	// source-scan result). Source text itself is NEVER persisted (ZDR).
	ToolFingerprintsJSON string    `gorm:"column:tool_fingerprints_json;type:text" json:"-"`
	ToolThreatsJSON      string    `gorm:"column:tool_threats_json;type:text" json:"-"`
	RegisteredAt         time.Time `gorm:"column:registered_at;index;not null" json:"registered_at"`
	CreatedAt            time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt            time.Time `gorm:"index;not null" json:"updated_at"`

	Nodes            []string                     `gorm:"-" json:"nodes,omitempty"`
	Tools            []string                     `gorm:"-" json:"tools"`
	Edges            [][]string                   `gorm:"-" json:"edges,omitempty"`
	MCPServers       []string                     `gorm:"-" json:"mcp_servers,omitempty"`
	ToolFingerprints map[string]string            `gorm:"-" json:"tool_fingerprints,omitempty"`
	ToolThreats      map[string]ToolThreatVerdict `gorm:"-" json:"tool_threats,omitempty"`
}

// ToolThreatVerdict is the result of scanning one tool's source at registration
// (T11 RCE / T17 supply chain). Persisted per blueprint; consulted on the decide
// path via the runtime allow-list (no source, no per-call scan).
type ToolThreatVerdict struct {
	Threat bool    `json:"threat"`
	Score  float64 `json:"score"`
	Reason string  `json:"reason,omitempty"`
	OWASP  string  `json:"owasp,omitempty"`
	// Summary is a short, safe description of the tool (what it does / its risk).
	// The raw source is never stored (ZDR); this is what the UI shows instead.
	Summary string `json:"summary,omitempty"`
}

func (TableAgenticBlueprint) TableName() string { return "agentic_blueprints" }

func (b *TableAgenticBlueprint) BeforeSave(tx *gorm.DB) error {
	if b.Nodes != nil {
		d, _ := json.Marshal(b.Nodes)
		b.NodesJSON = string(d)
	}
	if b.Tools != nil {
		d, _ := json.Marshal(b.Tools)
		b.ToolsJSON = string(d)
	}
	if b.Edges != nil {
		d, _ := json.Marshal(b.Edges)
		b.EdgesJSON = string(d)
	}
	if b.MCPServers != nil {
		d, _ := json.Marshal(b.MCPServers)
		b.MCPServersJSON = string(d)
	}
	if b.ToolFingerprints != nil {
		d, _ := json.Marshal(b.ToolFingerprints)
		b.ToolFingerprintsJSON = string(d)
	}
	if b.ToolThreats != nil {
		d, _ := json.Marshal(b.ToolThreats)
		b.ToolThreatsJSON = string(d)
	}
	return nil
}

func (b *TableAgenticBlueprint) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(b.NodesJSON, &b.Nodes); err != nil {
		return err
	}
	if err := decodeJSONStringSlice(b.ToolsJSON, &b.Tools); err != nil {
		return err
	}
	if err := decodeJSONStringSlice(b.MCPServersJSON, &b.MCPServers); err != nil {
		return err
	}
	if strings.TrimSpace(b.EdgesJSON) != "" {
		_ = json.Unmarshal([]byte(b.EdgesJSON), &b.Edges)
	}
	if strings.TrimSpace(b.ToolFingerprintsJSON) != "" {
		_ = json.Unmarshal([]byte(b.ToolFingerprintsJSON), &b.ToolFingerprints)
	}
	if strings.TrimSpace(b.ToolThreatsJSON) != "" {
		_ = json.Unmarshal([]byte(b.ToolThreatsJSON), &b.ToolThreats)
	}
	return nil
}

// ============================================================================
// TableAgenticDecision - append-only, hash-chained audit
// ============================================================================

// TableAgenticDecision is the unit of compliance evidence. Per §1.5:
//
//   - args_digest is sha256 of the canonicalised arguments - raw values are
//     never stored (zero-data-retention),
//   - prev_hash / hash form a linked list across the chain (tamper-evident),
//   - actor_chain, principal, tenant, virtual_key, verdict, obligations are
//     all preserved to support OWASP-Agentic / DPDP / RBI evidence export.
//
// The chain is per-tenant; a new tenant starts with an all-zero prev_hash.
type TableAgenticDecision struct {
	DecisionID      string  `gorm:"column:decision_id;type:varchar(64);primaryKey" json:"decision_id"`
	Sequence        uint64  `gorm:"column:sequence;not null;autoIncrement" json:"sequence"`
	TenantID        string  `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_decisions_tenant_ts,priority:1" json:"tenant_id"`
	WorkspaceID     string  `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	VirtualKeyID    string  `gorm:"column:virtual_key_id;type:varchar(64);index" json:"virtual_key_id,omitempty"`
	Principal       string  `gorm:"column:principal;type:varchar(255);index" json:"principal"`
	ActorChainJSON  string  `gorm:"column:actor_chain_json;type:text" json:"-"`
	IdentityType    string  `gorm:"column:identity_type;type:varchar(32)" json:"identity_type,omitempty"`
	ProviderID      string  `gorm:"column:provider_id;type:varchar(64);index" json:"provider_id,omitempty"`
	Tool            string  `gorm:"column:tool;type:varchar(255);not null;index" json:"tool"`
	ArgsDigest      string  `gorm:"column:args_digest;type:varchar(128);not null" json:"args_digest"`
	ScopeHash       string  `gorm:"column:scope_hash;type:varchar(128)" json:"scope_hash,omitempty"`
	Verdict         string  `gorm:"column:verdict;type:varchar(32);not null;index:idx_agentic_decisions_tenant_ts,priority:3;index" json:"verdict"`
	Reason          string  `gorm:"column:reason;type:varchar(512)" json:"reason,omitempty"`
	ObligationsJSON string  `gorm:"column:obligations_json;type:text" json:"-"`
	PolicyID        string  `gorm:"column:policy_id;type:varchar(64);index" json:"policy_id,omitempty"`
	PolicyVersion   int     `gorm:"column:policy_version;not null;default:0" json:"policy_version"`
	RecoveryCost    string  `gorm:"column:recovery_cost;type:varchar(16)" json:"recovery_cost,omitempty"`
	RAGProvenance   string  `gorm:"column:rag_provenance;type:varchar(32)" json:"rag_provenance,omitempty"`
	CostUsed        float64 `gorm:"column:cost_used;not null;default:0" json:"cost_used"`
	LatencyUS       int     `gorm:"column:latency_us;not null;default:0" json:"latency_us"`
	CacheHit        bool    `gorm:"column:cache_hit;not null;default:false;index" json:"cache_hit"`
	Mode            string  `gorm:"column:mode;type:varchar(16);not null;default:'enforce'" json:"mode"` // shadow|canary|enforce
	OWASPCategory   string  `gorm:"column:owasp_category;type:varchar(64)" json:"owasp_category,omitempty"`
	CrossTenant     bool    `gorm:"column:cross_tenant;not null;default:false" json:"cross_tenant"`
	// Tool Integrity Engine outputs for this decision. EffectiveActionClass is
	// the action class the call's behavior actually implied; IntegrityRisk is
	// the [0,1] divergence score; IntegrityFlagsJSON holds the matched signals.
	EffectiveActionClass string    `gorm:"column:effective_action_class;type:varchar(32);index" json:"effective_action_class,omitempty"`
	IntegrityRisk        float64   `gorm:"column:integrity_risk;not null;default:0" json:"integrity_risk"`
	IntegrityFlagsJSON   string    `gorm:"column:integrity_flags_json;type:text" json:"-"`
	PrevHash             string    `gorm:"column:prev_hash;type:varchar(128)" json:"prev_hash"`
	Hash                 string    `gorm:"column:hash;type:varchar(128);not null;uniqueIndex" json:"hash"`
	Timestamp            time.Time `gorm:"column:ts;not null;index:idx_agentic_decisions_tenant_ts,priority:2;index" json:"ts"`

	ActorChain     []string `gorm:"-" json:"actor_chain,omitempty"`
	Obligations    []string `gorm:"-" json:"obligations,omitempty"`
	IntegrityFlags []string `gorm:"-" json:"integrity_flags,omitempty"`
}

func (TableAgenticDecision) TableName() string { return "agentic_decisions" }

func (d *TableAgenticDecision) BeforeSave(tx *gorm.DB) error {
	if d.ActorChain != nil {
		data, _ := json.Marshal(d.ActorChain)
		d.ActorChainJSON = string(data)
	}
	if d.Obligations != nil {
		data, _ := json.Marshal(d.Obligations)
		d.ObligationsJSON = string(data)
	}
	if d.IntegrityFlags != nil {
		data, _ := json.Marshal(d.IntegrityFlags)
		d.IntegrityFlagsJSON = string(data)
	}
	return nil
}

func (d *TableAgenticDecision) AfterFind(tx *gorm.DB) error {
	if strings.TrimSpace(d.ActorChainJSON) != "" {
		_ = json.Unmarshal([]byte(d.ActorChainJSON), &d.ActorChain)
	}
	if strings.TrimSpace(d.ObligationsJSON) != "" {
		_ = json.Unmarshal([]byte(d.ObligationsJSON), &d.Obligations)
	}
	if strings.TrimSpace(d.IntegrityFlagsJSON) != "" {
		_ = json.Unmarshal([]byte(d.IntegrityFlagsJSON), &d.IntegrityFlags)
	}
	return nil
}

// ============================================================================
// TableAgenticApproval - human-in-the-loop queue (§Fig 7)
// ============================================================================

type TableAgenticApproval struct {
	ID             string     `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID       string     `gorm:"column:tenant_id;type:varchar(255);not null;index" json:"-"`
	WorkspaceID    string     `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	DecisionID     string     `gorm:"column:decision_id;type:varchar(64);not null;index" json:"decision_id"`
	Principal      string     `gorm:"column:principal;type:varchar(255);index" json:"principal"`
	ActorChainJSON string     `gorm:"column:actor_chain_json;type:text" json:"-"`
	Tool           string     `gorm:"column:tool;type:varchar(255);not null;index" json:"tool"`
	ArgsDigest     string     `gorm:"column:args_digest;type:varchar(128)" json:"args_digest"`
	RecoveryCost   string     `gorm:"column:recovery_cost;type:varchar(16);index" json:"recovery_cost"`
	ApproversJSON  string     `gorm:"column:approvers_json;type:text" json:"-"`
	PolicyID       string     `gorm:"column:policy_id;type:varchar(64)" json:"policy_id,omitempty"`
	Reason         string     `gorm:"column:reason;type:varchar(512)" json:"reason,omitempty"`
	State          string     `gorm:"column:state;type:varchar(32);not null;default:'pending';index" json:"state"`
	DecidedBy      string     `gorm:"column:decided_by;type:varchar(255)" json:"decided_by,omitempty"`
	DecidedAt      *time.Time `gorm:"column:decided_at;index" json:"decided_at,omitempty"`
	ApprovalScope  string     `gorm:"column:approval_scope;type:varchar(32);default:'once'" json:"approval_scope"` // once | session | tenant
	ExpiresAt      *time.Time `gorm:"column:expires_at;index" json:"expires_at,omitempty"`
	// Tool Integrity Engine snapshot - so an approver sees why the call was
	// flagged (effective action class vs declared, divergence risk, signals)
	// without re-deriving it from the decision.
	EffectiveActionClass string  `gorm:"column:effective_action_class;type:varchar(32)" json:"effective_action_class,omitempty"`
	IntegrityRisk        float64 `gorm:"column:integrity_risk;not null;default:0" json:"integrity_risk"`
	IntegrityFlagsJSON   string  `gorm:"column:integrity_flags_json;type:text" json:"-"`
	// VirtualKeyID + ToolFingerprint are carried so an approve→grant can bind
	// the auto-allow to {agent VK, tool, exact behavior fingerprint}.
	VirtualKeyID    string    `gorm:"column:virtual_key_id;type:varchar(64);index" json:"virtual_key_id,omitempty"`
	ToolFingerprint string    `gorm:"column:tool_fingerprint;type:varchar(64);index" json:"tool_fingerprint,omitempty"`
	CreatedAt       time.Time `gorm:"not null;index" json:"created_at"`
	UpdatedAt       time.Time `gorm:"not null;index" json:"updated_at"`

	ActorChain     []string `gorm:"-" json:"actor_chain,omitempty"`
	Approvers      []string `gorm:"-" json:"approvers,omitempty"`
	IntegrityFlags []string `gorm:"-" json:"integrity_flags,omitempty"`
}

func (TableAgenticApproval) TableName() string { return "agentic_approvals" }

func (a *TableAgenticApproval) BeforeSave(tx *gorm.DB) error {
	a.State = strings.ToLower(strings.TrimSpace(a.State))
	if a.State == "" {
		a.State = AgenticApprovalStatePending
	}
	if a.ApprovalScope == "" {
		a.ApprovalScope = "once"
	}
	if a.ActorChain != nil {
		data, _ := json.Marshal(a.ActorChain)
		a.ActorChainJSON = string(data)
	}
	if a.Approvers != nil {
		data, _ := json.Marshal(dedupeGuardrailStrings(a.Approvers))
		a.ApproversJSON = string(data)
	}
	if a.IntegrityFlags != nil {
		data, _ := json.Marshal(a.IntegrityFlags)
		a.IntegrityFlagsJSON = string(data)
	}
	return nil
}

func (a *TableAgenticApproval) AfterFind(tx *gorm.DB) error {
	if strings.TrimSpace(a.ActorChainJSON) != "" {
		_ = json.Unmarshal([]byte(a.ActorChainJSON), &a.ActorChain)
	}
	if strings.TrimSpace(a.IntegrityFlagsJSON) != "" {
		_ = json.Unmarshal([]byte(a.IntegrityFlagsJSON), &a.IntegrityFlags)
	}
	return decodeJSONStringSlice(a.ApproversJSON, &a.Approvers)
}

// ============================================================================
// TableAgenticToolGrant - persisted/JIT auto-allow created by an approval
// ============================================================================
//
// When an approver picks "session" or "always", we record a grant bound to the
// caller's identity + the tool's exact behavior fingerprint (ToolFingerprint:
// tool + action_class + args_schema + source). On the next call the PEP's
// GrantResolver matches {tenant, workspace, subject, tool, fingerprint} and
// short-circuits to ALLOW - but only while the grant is live (not revoked, not
// past expires_at) and only while the tool's logic is unchanged (a new
// fingerprint stops matching, forcing re-approval). This is the narrow,
// revocable, time-bound "remember this approval" layer - distinct from the
// broad, admin-authored policies.
type TableAgenticToolGrant struct {
	ID          string     `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID    string     `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_grants_lookup,priority:1" json:"-"`
	WorkspaceID string     `gorm:"column:workspace_id;type:varchar(64);index:idx_agentic_grants_lookup,priority:2" json:"workspace_id"`
	Subject     string     `gorm:"column:subject;type:varchar(255);index:idx_agentic_grants_lookup,priority:3" json:"subject"` // VK id (preferred) or principal
	ToolName    string     `gorm:"column:tool_name;type:varchar(255);index:idx_agentic_grants_lookup,priority:4" json:"tool_name"`
	Fingerprint string     `gorm:"column:fingerprint;type:varchar(64);index:idx_agentic_grants_lookup,priority:5" json:"fingerprint"`
	Scope       string     `gorm:"column:scope;type:varchar(16);not null;default:'session'" json:"scope"` // session | always
	DecisionID  string     `gorm:"column:decision_id;type:varchar(64)" json:"decision_id,omitempty"`
	Reason      string     `gorm:"column:reason;type:varchar(512)" json:"reason,omitempty"`
	GrantedBy   string     `gorm:"column:granted_by;type:varchar(255)" json:"granted_by,omitempty"`
	CreatedAt   time.Time  `gorm:"not null;index" json:"created_at"`
	ExpiresAt   *time.Time `gorm:"column:expires_at;index" json:"expires_at,omitempty"`
	RevokedAt   *time.Time `gorm:"column:revoked_at;index" json:"revoked_at,omitempty"`
}

func (TableAgenticToolGrant) TableName() string { return "agentic_tool_grants" }

// ============================================================================
// TableAgenticRelationshipAudit - append-only log of ReBAC (OpenFGA) tuple
// changes made through DeepIntShield. The relationship store is the single
// mediated write path; every write/delete lands a row here so relationship
// changes are queryable evidence (who changed which edge, when) - closing the
// "no shadow edits outside DeepIntShield" loop. ZDR-safe: stores only the
// relationship tuple (typed ids), never request bodies.
// ============================================================================
type TableAgenticRelationshipAudit struct {
	ID          string    `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID    string    `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_rel_audit_tenant_ws,priority:1" json:"-"`
	WorkspaceID string    `gorm:"column:workspace_id;type:varchar(64);index:idx_agentic_rel_audit_tenant_ws,priority:2" json:"workspace_id,omitempty"`
	Action      string    `gorm:"column:action;type:varchar(16);not null" json:"action"` // write | delete
	TupleUser   string    `gorm:"column:tuple_user;type:varchar(512);not null" json:"user"`
	Relation    string    `gorm:"column:relation;type:varchar(128);not null" json:"relation"`
	TupleObject string    `gorm:"column:tuple_object;type:varchar(512);not null" json:"object"`
	Actor       string    `gorm:"column:actor;type:varchar(255)" json:"actor,omitempty"` // VK id / principal that made the change
	CreatedAt   time.Time `gorm:"not null;index" json:"created_at"`
}

func (TableAgenticRelationshipAudit) TableName() string { return "agentic_relationship_audit" }

// ============================================================================
// TableAgenticToolSummary - cached "what this tool does" summaries
// ============================================================================
//
// Keyed by a content fingerprint (tool name + action class + args-schema hash +
// source hash) so a given tool definition is summarized once and reused. The
// summary is produced off the hot path by the AgenticToolSummarizer: a
// deterministic schema/source-derived baseline, upgraded to an LLM-written
// explanation when a provider is configured. ZDR-safe: stores prose only, not
// raw arguments.
type TableAgenticToolSummary struct {
	Fingerprint string    `gorm:"column:fingerprint;type:varchar(64);primaryKey" json:"fingerprint"`
	TenantID    string    `gorm:"column:tenant_id;type:varchar(255);index:idx_agentic_tool_summaries_tenant_ws,priority:1" json:"-"`
	WorkspaceID string    `gorm:"column:workspace_id;type:varchar(64);index:idx_agentic_tool_summaries_tenant_ws,priority:2" json:"workspace_id,omitempty"`
	ToolName    string    `gorm:"column:tool_name;type:varchar(255);index" json:"tool_name"`
	ActionClass string    `gorm:"column:action_class;type:varchar(32)" json:"action_class,omitempty"`
	Summary     string    `gorm:"column:summary;type:text" json:"summary"`
	RiskNotes   string    `gorm:"column:risk_notes;type:text" json:"risk_notes,omitempty"`
	Source      string    `gorm:"column:source;type:varchar(16);not null;default:'deterministic'" json:"source"` // deterministic | llm
	CreatedAt   time.Time `gorm:"not null;index" json:"created_at"`
	UpdatedAt   time.Time `gorm:"not null" json:"updated_at"`
}

func (TableAgenticToolSummary) TableName() string { return "agentic_tool_summaries" }

// ============================================================================
// TableAgenticEnforcementState - per-tenant Shadow/Canary/Enforce + kill switch
// ============================================================================

type TableAgenticEnforcementState struct {
	ID                string `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID          string `gorm:"column:tenant_id;type:varchar(255);not null;uniqueIndex:idx_agentic_enforcement_tenant_workspace,priority:1" json:"-"`
	WorkspaceID       string `gorm:"column:workspace_id;type:varchar(64);uniqueIndex:idx_agentic_enforcement_tenant_workspace,priority:2;index" json:"workspace_id"`
	Mode              string `gorm:"column:mode;type:varchar(16);not null;default:'shadow';index" json:"mode"`
	TiersEnforcedJSON string `gorm:"column:tiers_enforced_json;type:text" json:"-"`
	KillSwitch        bool   `gorm:"column:kill_switch;not null;default:false" json:"kill_switch"`
	RevocationSLASec  int    `gorm:"column:revocation_sla_sec;not null;default:30" json:"revocation_sla_sec"`
	L1CacheMaxEntries int    `gorm:"column:l1_cache_max_entries;not null;default:200000" json:"l1_cache_max_entries"`
	DefaultFailClosed bool   `gorm:"column:default_fail_closed;not null;default:true" json:"default_fail_closed"`
	// EnforceBlueprintAllowlist (opt-in, default false): when on, a tool a VK calls
	// that is NOT in its registered blueprint is denied (ASI04 least-privilege) -
	// the declared topology becomes an enforced allow-list. Honours the rollout
	// mode (shadow ⇒ would_block). Off ⇒ no change to current traffic.
	EnforceBlueprintAllowlist bool `gorm:"column:enforce_blueprint_allowlist;not null;default:false" json:"enforce_blueprint_allowlist"`
	// Workspace-level source-code threat scanning (T11 RCE / T17 supply chain).
	// CodeScanMode: off | regex_only | model. CodeScanVKID selects which of the
	// workspace's virtual keys (→ its bound model) runs the model scan; empty ⇒
	// regex + the workspace guardrail model only. EnforceCodeThreat: when on, a
	// tool whose source scanned malicious is DENIED (honours the rollout mode).
	CodeScanMode string `gorm:"column:code_scan_mode;type:varchar(16);not null;default:'off'" json:"code_scan_mode"`
	CodeScanVKID string `gorm:"column:code_scan_vk_id;type:varchar(128)" json:"code_scan_vk_id"`
	// CodeScanModel is the specific model (within the chosen VK's allowed models)
	// that runs the model-mode source scan. Empty ⇒ the scanner uses a default.
	CodeScanModel     string `gorm:"column:code_scan_model;type:varchar(128)" json:"code_scan_model"`
	EnforceCodeThreat bool   `gorm:"column:enforce_code_threat;not null;default:false" json:"enforce_code_threat"`
	// MaxRequestsPerMin caps per-agent (per-VK) decisions/minute - the T4
	// Resource-Overload / DoS guard. 0 (default) = unlimited (feature off, zero
	// hot-path cost). When >0 and exceeded, the call is denied (honours the
	// rollout mode); the verdict is temporal so it is never cached.
	MaxRequestsPerMin int       `gorm:"column:max_requests_per_min;not null;default:0" json:"max_requests_per_min"`
	WouldDenyRate     float64   `gorm:"column:would_deny_rate;not null;default:0" json:"would_deny_rate"`
	WouldEscalateRate float64   `gorm:"column:would_escalate_rate;not null;default:0" json:"would_escalate_rate"`
	WouldAllowRate    float64   `gorm:"column:would_allow_rate;not null;default:0" json:"would_allow_rate"`
	UnexpectedDenies  int       `gorm:"column:unexpected_denies;not null;default:0" json:"unexpected_denies"`
	P99AddedMs        float64   `gorm:"column:p99_added_ms;not null;default:0" json:"p99_added_ms"`
	UpdatedBy         string    `gorm:"column:updated_by;type:varchar(255)" json:"updated_by,omitempty"`
	CreatedAt         time.Time `gorm:"not null;index" json:"created_at"`
	UpdatedAt         time.Time `gorm:"not null;index" json:"updated_at"`

	TiersEnforced []string `gorm:"-" json:"tiers_enforced,omitempty"`
}

func (TableAgenticEnforcementState) TableName() string { return "agentic_enforcement_state" }

func (e *TableAgenticEnforcementState) BeforeSave(tx *gorm.DB) error {
	e.Mode = strings.ToLower(strings.TrimSpace(e.Mode))
	switch e.Mode {
	case AgenticEnforcementShadow, AgenticEnforcementCanary, AgenticEnforcementEnforce:
	default:
		e.Mode = AgenticEnforcementShadow
	}
	if e.TiersEnforced != nil {
		data, _ := json.Marshal(dedupeGuardrailStrings(e.TiersEnforced))
		e.TiersEnforcedJSON = string(data)
	}
	if e.RevocationSLASec <= 0 {
		e.RevocationSLASec = 30
	}
	if e.L1CacheMaxEntries <= 0 {
		e.L1CacheMaxEntries = 200000
	}
	return nil
}

func (e *TableAgenticEnforcementState) AfterFind(tx *gorm.DB) error {
	return decodeJSONStringSlice(e.TiersEnforcedJSON, &e.TiersEnforced)
}
