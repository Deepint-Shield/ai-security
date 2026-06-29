package tables

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	AuthProviderPassword = "password"
	AuthProviderGoogle   = "google"
	AuthProviderEntra    = "entra"
	AuthProviderAdmin    = "admin"
	// Auth providers added in the SSO + SCIM 2.0 workstream
	// (SSO_IMPLEMENTATION_PLAN.md Phase C). Routed through the generic
	// session_sso.go handler which uses framework/oauth2 for ID-token
	// verification. Entra keeps its own session_entra.go path for
	// backward compatibility with existing production connections that
	// were configured before the multi-IdP framework landed.
	AuthProviderOkta        = "okta"
	AuthProviderAuth0       = "auth0"
	AuthProviderOIDCGeneric = "oidc-generic"
	AuthProviderSAML        = "saml"

	EmailVerificationPurposeSignup      = "signup"
	EmailVerificationPurposeEmailChange = "email_change"

	UserRoleAdmin      = "admin"
	UserRoleViewer     = "viewer"
	UserRoleSuperadmin = "superadmin"
)

// TableAuthUser stores dashboard user accounts for email/password and Google sign-in.
type TableAuthUser struct {
	ID string `gorm:"type:varchar(255);primaryKey" json:"id"`
	// OrganizationID points at the user's parent governance_orgs row.
	// Backfilled from the user's tenant during migrationAdd3TierOrgs.
	// Never displayed in the UI - internal scope key only.
	OrganizationID    string  `gorm:"column:organization_id;type:varchar(255);index;default:''" json:"-"`
	TenantID          string  `gorm:"column:tenant_id;type:varchar(255);index;default:''" json:"tenant_id"`
	Role              string  `gorm:"type:varchar(50);not null;default:'admin';index" json:"role"`
	FirstName         string  `gorm:"type:varchar(120);not null" json:"first_name"`
	LastName          string  `gorm:"type:varchar(120);not null" json:"last_name"`
	Organization      string  `gorm:"type:varchar(255);not null" json:"organization"`
	Industry          string  `gorm:"type:varchar(120);not null" json:"industry"`
	Email             string  `gorm:"type:varchar(255);not null;uniqueIndex" json:"email"`
	PendingEmail      *string `gorm:"type:varchar(255);uniqueIndex" json:"pending_email,omitempty"`
	PasswordHash      string  `gorm:"type:text" json:"-"`
	GoogleSubject     *string `gorm:"type:varchar(255);uniqueIndex" json:"-"`
	CustomerID        *string `gorm:"column:customer_id;type:varchar(255);index" json:"customer_id,omitempty"`
	EntraSubject      *string `gorm:"column:entra_subject;type:varchar(255);index" json:"-"`
	EntraConnectionID *string `gorm:"column:entra_connection_id;type:varchar(255);index" json:"entra_connection_id,omitempty"`
	EntraIdentityKey  *string `gorm:"column:entra_identity_key;type:varchar(512);uniqueIndex" json:"-"`
	// Generic SSO linking fields (Phase C of SSO_IMPLEMENTATION_PLAN.md).
	// Populated by session_sso.go for Okta / Auth0 / Google-via-SSO /
	// Generic OIDC. Kept separate from EntraSubject so existing Entra
	// production data stays untouched and the column names accurately
	// describe what they hold (any IdP, not just Entra).
	// SSOProvider mirrors TableSCIMProviderConfig.Provider:
	// "okta" | "auth0" | "google" | "oidc-generic" | "saml".
	SSOProvider             *string    `gorm:"column:sso_provider;type:varchar(64);index" json:"sso_provider,omitempty"`
	SSOSubject              *string    `gorm:"column:sso_subject;type:varchar(255);index" json:"-"`
	SSOConnectionID         *string    `gorm:"column:sso_connection_id;type:varchar(255);index" json:"sso_connection_id,omitempty"`
	SSOIdentityKey          *string    `gorm:"column:sso_identity_key;type:varchar(512);uniqueIndex" json:"-"`
	EmailVerifiedAt         *time.Time `gorm:"index" json:"email_verified_at,omitempty"`
	PendingEmailRequestedAt *time.Time `gorm:"index" json:"pending_email_requested_at,omitempty"`
	LastVerificationSentAt  *time.Time `gorm:"index" json:"last_verification_sent_at,omitempty"`
	LastLoginAt             *time.Time `gorm:"index" json:"last_login_at,omitempty"`
	IsEmailVerified         bool       `gorm:"default:false;index" json:"is_email_verified"`
	// ThemePreference persists the user's UI theme choice ("light", "dark",
	// or "system") so it follows them across browsers + devices instead of
	// being trapped in localStorage. Empty = no preference set; clients
	// fall back to the app default ("dark").
	ThemePreference *string `gorm:"column:theme_preference;type:varchar(20)" json:"theme_preference,omitempty"`
	// Native TOTP MFA. MfaSecret is the base32 TOTP secret, AES-256-GCM
	// encrypted at rest and never serialized. MfaEnabled gates the login
	// challenge; a set-up-but-unconfirmed secret sits in MfaSecret with
	// MfaEnabled=false until the user confirms a code.
	MfaEnabled bool   `gorm:"column:mfa_enabled;default:false" json:"-"`
	MfaSecret  string `gorm:"column:mfa_secret;type:text" json:"-"`
	// MfaRecoveryCodes is a JSON array of SHA-256 hashes of single-use backup
	// codes. The plaintext codes are shown to the user exactly once (on
	// enable / regenerate); only the hashes are stored. Consuming a code
	// removes its hash. Lets a user who loses their authenticator still sign
	// in. Never serialized.
	MfaRecoveryCodes string    `gorm:"column:mfa_recovery_codes;type:text" json:"-"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableAuthUser) TableName() string { return "auth_users" }

func (u *TableAuthUser) BeforeSave(tx *gorm.DB) error {
	u.Email = normalizeAuthEmail(u.Email)
	u.Role = NormalizeAuthUserRole(u.Role)
	if u.PendingEmail != nil {
		normalized := normalizeAuthEmail(*u.PendingEmail)
		if normalized == "" {
			u.PendingEmail = nil
		} else {
			u.PendingEmail = &normalized
		}
	}
	return nil
}

// TableUserInvitation stores dashboard workspace invitations that are accepted
// during email/password signup.
//
// WorkspaceID was added so an invitation can target a specific workspace
// (not just a tenant). Pre-existing rows with NULL workspace_id fall
// back to the tenant's Default workspace at acceptance time. This keeps
// the invitation's intent ("I added you to GCP-Prod2-WS-1") encoded so
// that when the invitee finishes signup (via any auth provider) the
// right workspace_membership row gets created.
type TableUserInvitation struct {
	ID              string     `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID        string     `gorm:"column:tenant_id;type:varchar(255);index:idx_user_invitations_tenant_email,priority:1;index;default:''" json:"tenant_id"`
	WorkspaceID     *string    `gorm:"column:workspace_id;type:varchar(255);index" json:"workspace_id,omitempty"`
	Email           string     `gorm:"type:varchar(255);not null;index:idx_user_invitations_tenant_email,priority:2" json:"email"`
	Role            string     `gorm:"type:varchar(50);not null;default:'viewer';index" json:"role"`
	InvitedByUserID string     `gorm:"type:varchar(255);not null;index" json:"invited_by_user_id"`
	TokenHash       string     `gorm:"type:varchar(64);not null;uniqueIndex" json:"-"`
	ExpiresAt       time.Time  `gorm:"index;not null" json:"expires_at"`
	AcceptedAt      *time.Time `gorm:"index" json:"accepted_at,omitempty"`
	LastSentAt      *time.Time `gorm:"index" json:"last_sent_at,omitempty"`
	CreatedAt       time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt       time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableUserInvitation) TableName() string { return "user_invitations" }

func (i *TableUserInvitation) BeforeSave(tx *gorm.DB) error {
	i.Email = normalizeAuthEmail(i.Email)
	i.Role = NormalizeAuthUserRole(i.Role)
	return nil
}

// TableEmailVerificationToken stores one-time email verification tokens.
type TableEmailVerificationToken struct {
	ID          string     `gorm:"type:varchar(255);primaryKey" json:"id"`
	UserID      string     `gorm:"type:varchar(255);not null;index" json:"user_id"`
	Purpose     string     `gorm:"type:varchar(50);not null;index" json:"purpose"`
	TargetEmail *string    `gorm:"type:varchar(255);index" json:"target_email,omitempty"`
	TokenHash   string     `gorm:"type:varchar(64);not null;uniqueIndex" json:"-"`
	ExpiresAt   time.Time  `gorm:"index;not null" json:"expires_at"`
	UsedAt      *time.Time `gorm:"index" json:"used_at,omitempty"`
	CreatedAt   time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt   time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableEmailVerificationToken) TableName() string { return "email_verification_tokens" }

func (t *TableEmailVerificationToken) BeforeSave(tx *gorm.DB) error {
	if t.TargetEmail != nil {
		normalized := normalizeAuthEmail(*t.TargetEmail)
		if normalized == "" {
			t.TargetEmail = nil
		} else {
			t.TargetEmail = &normalized
		}
	}
	return nil
}

func normalizeAuthEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func NormalizeAuthUserRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case UserRoleViewer:
		return UserRoleViewer
	default:
		return UserRoleAdmin
	}
}
