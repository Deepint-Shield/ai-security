package tables

import "time"

// API key kinds. Service-Account / User split:
//   - service_account is for automated processes (CI, integrations); not
//     tied to a human user account, lifecycle is workspace-managed.
//   - user is bound to a specific dashboard user and inherits their identity
//     for audit purposes; revoked when the user is removed from the
//     workspace.
const (
	WorkspaceAPIKeyTypeServiceAccount = "service_account"
	WorkspaceAPIKeyTypeUser           = "user"
)

// TableWorkspaceAPIKey is a credential scoped to exactly one workspace. The
// gateway stores only the SHA-256 hash of the secret - the plaintext is
// shown to the caller exactly once at creation and never persisted. KeyPrefix
// is the leading bytes of the plaintext, kept for display so users can
// identify which key is which without revealing the secret.
//
// Workspace API keys are *additive* to the existing virtual-key model:
// virtual keys remain valid for inference; workspace API keys grant access
// to workspace-scoped admin operations and (when the inference middleware
// is updated) inference scoped to a single workspace.
type TableWorkspaceAPIKey struct {
	ID          string `gorm:"type:varchar(64);primaryKey" json:"id"`
	WorkspaceID string `gorm:"column:workspace_id;type:varchar(64);not null;index;index:idx_workspace_api_keys_ws_name,unique,priority:1" json:"workspace_id"`
	OrgID       string `gorm:"column:org_id;type:varchar(255);not null;index" json:"org_id"`
	Type        string `gorm:"type:varchar(32);not null;default:'service_account';index" json:"type"`
	Name        string `gorm:"type:varchar(255);not null;index:idx_workspace_api_keys_ws_name,unique,priority:2" json:"name"`
	// KeyHash stores SHA-256(plaintext). The plaintext is never written to
	// the DB - it is returned to the caller exactly once at creation and
	// must be persisted client-side.
	KeyHash    string     `gorm:"column:key_hash;type:varchar(128);not null;uniqueIndex" json:"-"`
	KeyPrefix  string     `gorm:"column:key_prefix;type:varchar(32);not null" json:"key_prefix"`
	UserID     *string    `gorm:"column:user_id;type:varchar(255);index" json:"user_id,omitempty"`
	CreatedBy  string     `gorm:"column:created_by;type:varchar(255);index;not null" json:"created_by"`
	ExpiresAt  *time.Time `gorm:"column:expires_at;index" json:"expires_at,omitempty"`
	LastUsedAt *time.Time `gorm:"column:last_used_at;index" json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `gorm:"column:revoked_at;index" json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableWorkspaceAPIKey) TableName() string { return "workspace_api_keys" }
