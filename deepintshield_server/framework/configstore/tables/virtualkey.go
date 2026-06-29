package tables

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/encrypt"
	"gorm.io/gorm"
)

// TableVirtualKeyProviderConfigKey is the join table for the many2many relationship
// between TableVirtualKeyProviderConfig and TableKey
type TableVirtualKeyProviderConfigKey struct {
	TableVirtualKeyProviderConfigID uint `gorm:"primaryKey;uniqueIndex:idx_vk_provider_config_key"`
	TableKeyID                      uint `gorm:"primaryKey;uniqueIndex:idx_vk_provider_config_key"`
}

// TableName sets the table name for the join table
func (TableVirtualKeyProviderConfigKey) TableName() string {
	return "governance_virtual_key_provider_config_keys"
}

// TableVirtualKeyProviderConfig represents a provider configuration for a virtual key
type TableVirtualKeyProviderConfig struct {
	ID                   uint     `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID             string   `gorm:"column:tenant_id;type:varchar(255);index" json:"-"`
	VirtualKeyID         string   `gorm:"type:varchar(255);not null" json:"virtual_key_id"`
	Provider             string   `gorm:"type:varchar(50);not null" json:"provider"`
	Weight               *float64 `json:"weight"`
	AllowedModels        []string `gorm:"type:text;serializer:json" json:"allowed_models"`          // Empty means all models allowed
	KeySelectionStrategy *string  `gorm:"type:varchar(50)" json:"key_selection_strategy,omitempty"` // "weighted_random", "round_robin", "least_load"
	BudgetID             *string  `gorm:"type:varchar(255);index" json:"budget_id,omitempty"`
	RateLimitID          *string  `gorm:"type:varchar(255);index" json:"rate_limit_id,omitempty"`

	// Relationships
	Budget    *TableBudget    `gorm:"foreignKey:BudgetID;onDelete:CASCADE" json:"budget,omitempty"`
	RateLimit *TableRateLimit `gorm:"foreignKey:RateLimitID;onDelete:CASCADE" json:"rate_limit,omitempty"`
	Keys      []TableKey      `gorm:"many2many:governance_virtual_key_provider_config_keys;constraint:OnDelete:CASCADE" json:"keys"` // Empty means all keys allowed for this provider
}

// TableName sets the table name for each model
func (TableVirtualKeyProviderConfig) TableName() string {
	return "governance_virtual_key_provider_configs"
}

// UnmarshalJSON custom unmarshaller to handle both "keys" ([]TableKey) and "allowed_keys" ([]string) formats
func (pc *TableVirtualKeyProviderConfig) UnmarshalJSON(data []byte) error {
	// Temporary struct to capture all fields including allowed_keys
	type Alias TableVirtualKeyProviderConfig
	type TempProviderConfig struct {
		Alias
		AllowedKeys []string `json:"allowed_keys"` // Config file format: array of key names
	}

	var temp TempProviderConfig
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Copy all standard fields
	*pc = TableVirtualKeyProviderConfig(temp.Alias)

	// If allowed_keys is provided (config file format), convert to Keys
	// This takes precedence if Keys is empty but allowed_keys has values
	if len(temp.AllowedKeys) > 0 && len(pc.Keys) == 0 {
		pc.Keys = make([]TableKey, len(temp.AllowedKeys))
		for i, keyName := range temp.AllowedKeys {
			pc.Keys[i] = TableKey{Name: keyName}
		}
	}

	return nil
}

// MarshalJSON custom marshaller to ensure AllowedModels is always an array (never null)
func (pc TableVirtualKeyProviderConfig) MarshalJSON() ([]byte, error) {
	type Alias TableVirtualKeyProviderConfig

	// Ensure AllowedModels is an empty slice instead of nil
	allowedModels := pc.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}

	return json.Marshal(&struct {
		Alias
		AllowedModels []string `json:"allowed_models"`
	}{
		Alias:         Alias(pc),
		AllowedModels: allowedModels,
	})
}

// AfterFind hook for TableVirtualKeyProviderConfig to clear sensitive data from associated keys
func (pc *TableVirtualKeyProviderConfig) AfterFind(tx *gorm.DB) error {
	if pc.Keys != nil {
		// Clear sensitive data from associated keys, keeping only key IDs and non-sensitive metadata
		for i := range pc.Keys {
			key := &pc.Keys[i]

			// Clear the actual API key value
			key.Value = *schemas.NewEnvVar("")

			// Clear all Azure-related sensitive fields
			key.AzureEndpoint = nil
			key.AzureAPIVersion = nil
			key.AzureClientID = nil
			key.AzureClientSecret = nil
			key.AzureTenantID = nil
			key.AzureScopesJSON = nil
			key.AzureDeploymentsJSON = nil
			key.AzureKeyConfig = nil

			// Clear all Vertex-related sensitive fields
			key.VertexProjectID = nil
			key.VertexProjectNumber = nil
			key.VertexRegion = nil
			key.VertexAuthCredentials = nil
			key.VertexKeyConfig = nil

			// Clear all Bedrock-related sensitive fields
			key.BedrockAccessKey = nil
			key.BedrockSecretKey = nil
			key.BedrockSessionToken = nil
			key.BedrockRegion = nil
			key.BedrockARN = nil
			key.BedrockRoleARN = nil
			key.BedrockExternalID = nil
			key.BedrockRoleSessionName = nil
			key.BedrockDeploymentsJSON = nil
			key.BedrockKeyConfig = nil

			// Clear all Replicate-related sensitive fields
			key.ReplicateDeploymentsJSON = nil
			key.ReplicateKeyConfig = nil

			pc.Keys[i] = *key
		}
	}
	return nil
}

type TableVirtualKeyMCPConfig struct {
	ID             uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID       string         `gorm:"column:tenant_id;type:varchar(255);index" json:"-"`
	VirtualKeyID   string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_vk_mcpclient" json:"virtual_key_id"`
	MCPClientID    uint           `gorm:"not null;uniqueIndex:idx_vk_mcpclient" json:"mcp_client_id"`
	MCPClient      TableMCPClient `gorm:"foreignKey:MCPClientID" json:"mcp_client"`
	ToolsToExecute []string       `gorm:"type:text;serializer:json" json:"tools_to_execute"`

	// MCPClientName is used during config file parsing to resolve the MCP client by name.
	// This field is not persisted to the database - it's only used to capture
	// "mcp_client_name" from config.json and then resolve it to MCPClientID.
	MCPClientName string `gorm:"-" json:"-"`
}

// TableName sets the table name for each model
func (TableVirtualKeyMCPConfig) TableName() string {
	return "governance_virtual_key_mcp_configs"
}

// UnmarshalJSON custom unmarshaller to handle both "mcp_client_id" (database format)
// and "mcp_client_name" (config file format) for MCP client references.
func (mc *TableVirtualKeyMCPConfig) UnmarshalJSON(data []byte) error {
	// Temporary struct to capture all fields including mcp_client_name
	type Alias TableVirtualKeyMCPConfig
	type TempMCPConfig struct {
		Alias
		MCPClientName string `json:"mcp_client_name"` // Config file format: MCP client name
	}

	var temp TempMCPConfig
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Copy all standard fields
	*mc = TableVirtualKeyMCPConfig(temp.Alias)

	// Capture mcp_client_name for later resolution to MCPClientID
	if temp.MCPClientName != "" {
		mc.MCPClientName = temp.MCPClientName
	}

	return nil
}

// TableVirtualKey represents a virtual key with budget, rate limits, and team/customer association
type TableVirtualKeyGuardrailPolicy struct {
	VirtualKeyID      string    `gorm:"column:virtual_key_id;type:varchar(255);primaryKey" json:"virtual_key_id"`
	GuardrailPolicyID string    `gorm:"column:guardrail_policy_id;type:varchar(255);primaryKey;index" json:"guardrail_policy_id"`
	CreatedAt         time.Time `gorm:"index;not null" json:"created_at"`
}

func (TableVirtualKeyGuardrailPolicy) TableName() string {
	return "governance_virtual_key_guardrail_policies"
}

// VirtualKeyFallbackEntry is one step in the VK's failover chain.
type VirtualKeyFallbackEntry struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type TableVirtualKey struct {
	ID string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	// NOTE: Keep `index` here even though it's covered by the composite
	// unique indexes below. Stripping it caused AutoMigrate to do
	// a destructive index recreate in Postgres that emptied the table.
	// The minor write-amp cost of the redundant single-col index is
	// strictly preferable to the data-loss risk.
	TenantID                       string   `gorm:"column:tenant_id;type:varchar(255);index;uniqueIndex:idx_virtual_key_tenant_workspace_name;uniqueIndex:idx_virtual_key_tenant_value;uniqueIndex:idx_virtual_key_tenant_value_hash" json:"-"`
	Name                           string   `gorm:"type:varchar(255);not null;uniqueIndex:idx_virtual_key_tenant_workspace_name" json:"name"`
	Description                    string   `gorm:"type:text" json:"description,omitempty"`
	Value                          string   `gorm:"type:text;not null;uniqueIndex:idx_virtual_key_tenant_value" json:"value"` // The virtual key value
	IsActive                       bool     `gorm:"default:true" json:"is_active"`
	CacheKey                       string   `gorm:"type:text" json:"cache_key,omitempty"`
	CacheEnabled                   *bool    `gorm:"default:true" json:"cache_enabled,omitempty"`
	SemanticCacheEnabled           *bool    `gorm:"default:true" json:"semantic_cache_enabled,omitempty"`
	CacheScopeMode                 *string  `gorm:"type:varchar(64)" json:"cache_scope_mode,omitempty"`
	CacheMetadataScopeKeys         []string `gorm:"type:text;serializer:json" json:"cache_metadata_scope_keys,omitempty"`
	CacheAllowSemanticWhenUnscoped *bool    `gorm:"default:false" json:"cache_allow_semantic_when_unscoped,omitempty"`
	// FallbackChain is an ordered list of {provider, model} pairs the
	// gateway tries automatically when the primary call fails (5xx / 429 /
	// timeout). Stored as JSON on the VK row so operators don't have to
	// pass `fallbacks: […]` per-request from the SDK. The runtime path in
	// core/deepintshield.go already cycles through req.*Request.Fallbacks
	// - this field just makes the gateway pre-populate that list from a
	// workspace-level default when the caller didn't specify one.
	FallbackChain     []VirtualKeyFallbackEntry       `gorm:"type:text;serializer:json" json:"fallback_chain,omitempty"`
	ProviderConfigs   []TableVirtualKeyProviderConfig `gorm:"foreignKey:VirtualKeyID;constraint:OnDelete:CASCADE" json:"provider_configs"` // Empty means all providers allowed
	MCPConfigs        []TableVirtualKeyMCPConfig      `gorm:"foreignKey:VirtualKeyID;constraint:OnDelete:CASCADE" json:"mcp_configs"`
	GuardrailPolicies []TableGuardrailPolicy          `gorm:"many2many:governance_virtual_key_guardrail_policies;joinForeignKey:VirtualKeyID;joinReferences:GuardrailPolicyID;constraint:OnDelete:CASCADE" json:"guardrail_policies,omitempty"`

	// Foreign key relationships (mutually exclusive: either TeamID or CustomerID, not both)
	TeamID      *string `gorm:"type:varchar(255);index" json:"team_id,omitempty"`
	CustomerID  *string `gorm:"type:varchar(255);index" json:"customer_id,omitempty"`
	BudgetID    *string `gorm:"type:varchar(255);index" json:"budget_id,omitempty"`
	RateLimitID *string `gorm:"type:varchar(255);index" json:"rate_limit_id,omitempty"`
	// WorkspaceID narrows the virtual key to a single workspace within the
	// tenant. NULL = legacy / org-wide (callable from any workspace in the
	// tenant). Set non-NULL once the workspace API key model lands so the
	// inference path can reject cross-workspace use.
	WorkspaceID *string `gorm:"column:workspace_id;type:varchar(64);index;uniqueIndex:idx_virtual_key_tenant_workspace_name" json:"workspace_id,omitempty"`

	// Relationships
	Team      *TableTeam      `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	Customer  *TableCustomer  `gorm:"foreignKey:CustomerID" json:"customer,omitempty"`
	Budget    *TableBudget    `gorm:"foreignKey:BudgetID;onDelete:CASCADE" json:"budget,omitempty"`
	RateLimit *TableRateLimit `gorm:"foreignKey:RateLimitID;onDelete:CASCADE" json:"rate_limit,omitempty"`

	// Config hash is used to detect the changes synced from config.json file
	// Every time we sync the config.json file, we will update the config hash
	ConfigHash string `gorm:"type:varchar(255);null" json:"config_hash"`

	EncryptionStatus string `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	ValueHash        string `gorm:"type:varchar(64);uniqueIndex:idx_virtual_key_tenant_value_hash" json:"-"`

	// Key rotation. RotationPeriodDays > 0 means the gateway should rotate
	// this key on a schedule (auto-rotation is processed by a follow-up
	// worker; the field is stored today). When a rotation happens - manual
	// or scheduled - the previous Value is parked in PreviousValue and
	// stays accepted by the inference auth path until PreviousValueExpiresAt
	// so consumers have a grace window to roll over their clients.
	RotationPeriodDays      *int `gorm:"column:rotation_period_days" json:"rotation_period_days,omitempty"`
	RotationGracePeriodDays int  `gorm:"column:rotation_grace_period_days;default:7" json:"rotation_grace_period_days,omitempty"`
	// RotationNoticeDays is how many days BEFORE next_rotation_at the worker
	// should email the tenant owner a heads-up that the key is about to
	// rotate. 0 disables the pre-rotation notification. Defaults to 7 so the
	// SOC 2 §3.1 "notification before rotation" control is on out of the box
	// without admins having to opt in per key.
	RotationNoticeDays int        `gorm:"column:rotation_notice_days;default:7" json:"rotation_notice_days,omitempty"`
	LastRotatedAt      *time.Time `gorm:"column:last_rotated_at;index" json:"last_rotated_at,omitempty"`
	NextRotationAt     *time.Time `gorm:"column:next_rotation_at;index" json:"next_rotation_at,omitempty"`
	// RotationNotifiedAt records the moment the worker dispatched the pre-
	// rotation warning email for the current cycle. Reset to NULL whenever
	// next_rotation_at moves forward (after a rotation completes or when an
	// admin reschedules), so the worker only sends one notification per
	// cycle even on tight check intervals.
	RotationNotifiedAt     *time.Time `gorm:"column:rotation_notified_at;index" json:"rotation_notified_at,omitempty"`
	PreviousValue          string     `gorm:"column:previous_value;type:text" json:"-"`
	PreviousValueHash      string     `gorm:"column:previous_value_hash;type:varchar(64);index" json:"-"`
	PreviousValueExpiresAt *time.Time `gorm:"column:previous_value_expires_at;index" json:"previous_value_expires_at,omitempty"`

	// ─── Agentic Security additions (identity-only after policy split) ─
	// The VK row carries authentication context (which IdP issues tokens,
	// which OAuth scopes the token must carry). Authorization (allowed
	// tools, default obligations, rate limit, autonomy budget) has moved
	// to agentic_policies with rows in agentic_policy_vk_targets - see
	// migrationDeriveVKScopedPolicies. The drop-column migration removes
	// the legacy authorization columns from this table.
	BoundIdentityProvider string `gorm:"column:bound_identity_provider;type:varchar(64);index" json:"bound_identity_provider,omitempty"`
	IdentityProviderID    string `gorm:"column:identity_provider_id;type:varchar(64);index" json:"identity_provider_id,omitempty"`
	// Scopes the agent token is expected to request from the IdP. Used
	// by the SDK discovery endpoint to tell agents what to ask for.
	AgentScopes []string `gorm:"column:agent_scopes;type:text;serializer:json" json:"agent_scopes,omitempty"`

	// ─── Agent attribute taxonomy (ABAC operands) ──────────────────────
	// AgentRiskLevel is the calling agent's declared risk tier
	// (low | medium | high). It rides into the PDP via VKScope so policies
	// can express attribute rules like "low-risk agents may call low-risk
	// tools" or "agent_risk_level lte medium" without naming agents. The
	// ordinal compare (low<medium<high) lives in the policy engine.
	AgentRiskLevel string `gorm:"column:agent_risk_level;type:varchar(16);index" json:"agent_risk_level,omitempty"`
	// AgentCapabilities is the set of capability tags this agent declares
	// (e.g. "financial-analysis", "compliance-query"). Policies match with
	// `agent_capability in/not_in` so a new agent with matching tags is
	// governed by existing policies from day one (no allow-list edits).
	AgentCapabilities []string `gorm:"column:agent_capabilities;type:text;serializer:json" json:"agent_capabilities,omitempty"`
	// AgentNamespace is the agent's logical / k8s namespace - the `namespace`
	// ABAC operand ("agents in namespace=production may only call …").
	AgentNamespace string `gorm:"column:agent_namespace;type:varchar(128);index" json:"agent_namespace,omitempty"`

	CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

// TableName sets the table name for each model
func (TableVirtualKey) TableName() string { return "governance_virtual_keys" }

// BeforeSave is a GORM hook that enforces mutual exclusion (team vs customer), computes
// a SHA-256 hash of the plaintext value for indexed lookups, and encrypts the virtual key
// value before writing to the database.
func (vk *TableVirtualKey) BeforeSave(tx *gorm.DB) error {
	// Enforce mutual exclusion: VK can belong to either Team OR Customer, not both
	if vk.TeamID != nil && vk.CustomerID != nil {
		return fmt.Errorf("virtual key cannot belong to both team and customer")
	}

	// Hash must be computed before encryption (from plaintext value)
	if vk.Value != "" {
		vk.ValueHash = encrypt.HashSHA256(vk.Value)
	}
	if encrypt.IsEnabled() && vk.Value != "" {
		if err := encryptString(&vk.Value); err != nil {
			return fmt.Errorf("failed to encrypt virtual key value: %w", err)
		}
		vk.EncryptionStatus = EncryptionStatusEncrypted
	}
	// Same hash + encrypt treatment for the parked previous value (set by
	// the rotate endpoint). Hash is required so the inference auth path can
	// look up the previous key by hash without decrypting every row.
	if vk.PreviousValue != "" {
		vk.PreviousValueHash = encrypt.HashSHA256(vk.PreviousValue)
		if encrypt.IsEnabled() {
			if err := encryptString(&vk.PreviousValue); err != nil {
				return fmt.Errorf("failed to encrypt virtual key previous value: %w", err)
			}
		}
	}
	return nil
}

// AfterFind is a GORM hook that decrypts the virtual key value after reading from the database.
func (vk *TableVirtualKey) AfterFind(tx *gorm.DB) error {
	if vk.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&vk.Value); err != nil {
			return fmt.Errorf("failed to decrypt virtual key value: %w", err)
		}
		if vk.PreviousValue != "" {
			if err := decryptString(&vk.PreviousValue); err != nil {
				return fmt.Errorf("failed to decrypt virtual key previous value: %w", err)
			}
		}
	}
	return nil
}
