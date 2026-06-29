package tables

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/encrypt"
	"gorm.io/gorm"
)

type SCIMRoleMapping struct {
	Source string `json:"source"`
	Value  string `json:"value"`
	Role   string `json:"role"`
}

type TableSCIMProviderConfig struct {
	ID                     string  `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID               string  `gorm:"column:tenant_id;type:varchar(255);index:idx_scim_provider_tenant_provider,priority:1;index:idx_scim_provider_tenant_customer,priority:1" json:"-"`
	Provider               string  `gorm:"type:varchar(64);not null;index:idx_scim_provider_tenant_provider,priority:2" json:"provider"`
	Name                   string  `gorm:"type:varchar(255);not null;default:'Microsoft Entra'" json:"name"`
	CustomerID             *string `gorm:"column:customer_id;type:varchar(255);index:idx_scim_provider_tenant_customer,priority:2;index" json:"customer_id,omitempty"`
	IsDefault              bool    `gorm:"column:is_default;default:false;index" json:"is_default"`
	Enabled                bool    `gorm:"default:false" json:"enabled"`
	Cloud                  string  `gorm:"type:varchar(64);default:'commercial'" json:"cloud"`
	DirectoryTenantID      string  `gorm:"column:directory_tenant_id;type:varchar(255)" json:"tenant_id"`
	ClientID               string  `gorm:"type:varchar(255)" json:"client_id"`
	ClientSecret           string  `gorm:"type:text" json:"-"`
	Audience               string  `gorm:"type:text" json:"audience"`
	AppIDURI               string  `gorm:"column:app_id_uri;type:text" json:"app_id_uri"`
	UserIDField            string  `gorm:"type:varchar(128);default:'oid'" json:"user_id_field"`
	RolesField             string  `gorm:"type:varchar(128);default:'roles'" json:"roles_field"`
	TeamIDsField           string  `gorm:"column:team_ids_field;type:varchar(128);default:'groups'" json:"team_ids_field"`
	AutoProvisionUsers     bool    `gorm:"default:true" json:"auto_provision_users"`
	SyncGroupsToTeams      bool    `gorm:"default:true" json:"sync_groups_to_teams"`
	DeactivateMissingUsers bool    `gorm:"default:true" json:"deactivate_missing_users"`
	TokenRefreshEnabled    bool    `gorm:"default:true" json:"token_refresh_enabled"`
	// AllowAutoAccountLinking controls whether a first-time SSO sign-in
	// whose verified email matches an existing password-auth user
	// automatically links the SSO identity to that account. Default is
	// false (security-conscious): linking requires an explicit admin
	// approval step. Per SSO_IMPLEMENTATION_PLAN.md §5.4 design decision.
	AllowAutoAccountLinking bool `gorm:"column:allow_auto_account_linking;default:false" json:"allow_auto_account_linking"`

	// SCIM 2.0 inbound bearer-token authentication (RFC 7644).
	// SCIMBearerHash holds the SHA-256 hash of the per-connection bearer
	// the IdP presents in the `Authorization: Bearer <token>` header on
	// every /scim/v2/connections/<id>/... call. The plaintext token is
	// shown to the admin once on enable and never persisted; rotation
	// generates a new token + new hash. SCIMBearerPrefix holds the first
	// 12 chars of the token for human identification in the admin UI
	// (so an admin can recognise "scim_a1b2..." without ever seeing the
	// full secret again).
	SCIMBearerHash   string     `gorm:"column:scim_bearer_hash;type:varchar(64);index" json:"-"`
	SCIMBearerPrefix string     `gorm:"column:scim_bearer_prefix;type:varchar(16)" json:"scim_bearer_prefix,omitempty"`
	EmailDomainsJSON string     `gorm:"column:email_domains_json;type:text" json:"-"`
	RoleMappingsJSON string     `gorm:"type:text" json:"-"`
	LastTestedAt     *time.Time `gorm:"index" json:"last_tested_at,omitempty"`
	LastSyncAt       *time.Time `gorm:"index" json:"last_sync_at,omitempty"`
	LastError        string     `gorm:"type:text" json:"last_error,omitempty"`
	EncryptionStatus string     `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"index;not null" json:"updated_at"`

	RoleMappings []SCIMRoleMapping `gorm:"-" json:"role_mappings"`
	EmailDomains []string          `gorm:"-" json:"email_domains"`
}

func (TableSCIMProviderConfig) TableName() string { return "scim_provider_configs" }

// Supported OIDC provider identifiers. Stored lowercased in the Provider
// column; UI and handler code branch on these constants.
const (
	SCIMProviderEntra       = "entra"
	SCIMProviderOkta        = "okta"
	SCIMProviderAuth0       = "auth0"
	SCIMProviderGoogle      = "google"
	SCIMProviderOIDCGeneric = "oidc-generic"
)

// scimProviderDefaults captures the per-IdP claim-name defaults that get
// applied in BeforeSave when an admin saves a connection without filling
// the optional UserIDField / RolesField / TeamIDsField. The display name
// is also defaulted here so the admin UI shows a recognisable label.
type scimProviderDefaults struct {
	displayName  string
	userIDField  string
	rolesField   string
	teamIDsField string
}

var scimProviderDefaultsByProvider = map[string]scimProviderDefaults{
	SCIMProviderEntra: {
		displayName:  "Microsoft Entra",
		userIDField:  "oid",
		rolesField:   "roles",
		teamIDsField: "groups",
	},
	SCIMProviderOkta: {
		displayName:  "Okta",
		userIDField:  "sub",
		rolesField:   "groups",
		teamIDsField: "groups",
	},
	SCIMProviderAuth0: {
		// Auth0 emits roles + groups under a namespaced claim set up by an
		// onExecutePostLogin Action; the SSO_CONFIGURATION_GUIDE.md walks
		// the admin through that. Default to the namespace this product
		// document recommends.
		displayName:  "Auth0",
		userIDField:  "sub",
		rolesField:   "https://deepintshield.com/roles",
		teamIDsField: "https://deepintshield.com/groups",
	},
	SCIMProviderGoogle: {
		// Google Workspace doesn't emit roles natively - admins map roles
		// manually after first sign-in (or wire Google Groups via the
		// Admin SDK). Default rolesField to empty so we don't pretend a
		// claim exists when it doesn't.
		displayName:  "Google Workspace",
		userIDField:  "sub",
		rolesField:   "",
		teamIDsField: "",
	},
	SCIMProviderOIDCGeneric: {
		// Spec-compliant defaults; admins for Keycloak / Ping / OneLogin
		// override per their issuer.
		displayName:  "Generic OIDC",
		userIDField:  "sub",
		rolesField:   "roles",
		teamIDsField: "groups",
	},
}

func (c *TableSCIMProviderConfig) BeforeSave(tx *gorm.DB) error {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	if c.Provider == "" {
		c.Provider = SCIMProviderEntra
	}
	// Apply per-IdP claim defaults. Admins can still override every field
	// - this only fills in blanks, it never clobbers an explicit value.
	defaults, ok := scimProviderDefaultsByProvider[c.Provider]
	if !ok {
		// Unknown provider - fall back to the generic OIDC defaults so the
		// connection still passes validation. The handler layer is
		// expected to reject unknown providers at the API boundary.
		defaults = scimProviderDefaultsByProvider[SCIMProviderOIDCGeneric]
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		c.Name = defaults.displayName
	}
	c.Cloud = strings.ToLower(strings.TrimSpace(c.Cloud))
	if c.Cloud == "" {
		c.Cloud = "commercial"
	}
	c.DirectoryTenantID = strings.TrimSpace(c.DirectoryTenantID)
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.Audience = strings.TrimSpace(c.Audience)
	c.AppIDURI = strings.TrimSpace(c.AppIDURI)
	c.UserIDField = strings.TrimSpace(c.UserIDField)
	if c.UserIDField == "" {
		c.UserIDField = defaults.userIDField
	}
	c.RolesField = strings.TrimSpace(c.RolesField)
	if c.RolesField == "" {
		c.RolesField = defaults.rolesField
	}
	c.TeamIDsField = strings.TrimSpace(c.TeamIDsField)
	if c.TeamIDsField == "" {
		c.TeamIDsField = defaults.teamIDsField
	}
	if c.RoleMappings != nil {
		data, err := json.Marshal(c.RoleMappings)
		if err != nil {
			return err
		}
		c.RoleMappingsJSON = string(data)
	}
	if c.EmailDomains != nil {
		normalized := make([]string, 0, len(c.EmailDomains))
		seen := make(map[string]struct{}, len(c.EmailDomains))
		for _, domain := range c.EmailDomains {
			trimmed := strings.ToLower(strings.TrimSpace(domain))
			trimmed = strings.TrimPrefix(trimmed, "@")
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			normalized = append(normalized, trimmed)
		}
		data, err := json.Marshal(normalized)
		if err != nil {
			return err
		}
		c.EmailDomainsJSON = string(data)
	}
	if encrypt.IsEnabled() {
		if err := encryptString(&c.ClientSecret); err != nil {
			return fmt.Errorf("failed to encrypt scim client secret: %w", err)
		}
		if c.ClientSecret != "" {
			c.EncryptionStatus = EncryptionStatusEncrypted
		}
	}
	return nil
}

func (c *TableSCIMProviderConfig) AfterFind(tx *gorm.DB) error {
	if c.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&c.ClientSecret); err != nil {
			return fmt.Errorf("failed to decrypt scim client secret: %w", err)
		}
	}
	if strings.TrimSpace(c.RoleMappingsJSON) != "" {
		if err := json.Unmarshal([]byte(c.RoleMappingsJSON), &c.RoleMappings); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.EmailDomainsJSON) != "" {
		if err := json.Unmarshal([]byte(c.EmailDomainsJSON), &c.EmailDomains); err != nil {
			return err
		}
	}
	return nil
}
