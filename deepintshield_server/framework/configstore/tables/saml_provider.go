package tables

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/encrypt"
	"gorm.io/gorm"
)

// SAMLAttributeMapping maps an IdP-emitted SAML assertion attribute onto a
// DeepintShield user field. Source is the IdP attribute name (e.g.
// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" for
// Entra-SAML, "email" for Okta-SAML), Target is the DS field
// (`email`, `first_name`, `last_name`, `roles`, `groups`).
type SAMLAttributeMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// SAMLRoleMapping maps a SAML group/role attribute value to a DeepintShield role.
// Same shape as SCIMRoleMapping but kept as its own type so SAML and OIDC
// connection schemas don't accidentally cross-pollinate.
type SAMLRoleMapping struct {
	Source string `json:"source"`
	Value  string `json:"value"`
	Role   string `json:"role"`
}

// TableSAMLProviderConfig holds the per-tenant SAML 2.0 SSO connection
// record. Parallels TableSCIMProviderConfig (which today covers OIDC +
// SCIM-pull). Splitting them keeps each schema dense - SAML needs
// EntityID/IdPCertPEM/SSOURL/NameIDFormat that have no OIDC analogue, and
// OIDC needs ClientSecret/Audience/AppIDURI that have no SAML analogue.
type TableSAMLProviderConfig struct {
	ID         string  `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID   string  `gorm:"column:tenant_id;type:varchar(255);index:idx_saml_provider_tenant,priority:1" json:"-"`
	Name       string  `gorm:"type:varchar(255);not null;default:'SAML Provider'" json:"name"`
	CustomerID *string `gorm:"column:customer_id;type:varchar(255);index:idx_saml_provider_tenant_customer,priority:2;index" json:"customer_id,omitempty"`
	IsDefault  bool    `gorm:"column:is_default;default:false;index" json:"is_default"`
	Enabled    bool    `gorm:"default:false" json:"enabled"`

	// SP-side identity (advertised to the IdP in our metadata)
	EntityID string `gorm:"column:entity_id;type:text" json:"entity_id"`

	// IdP-side identity + endpoints (consumed from the IdP's metadata)
	IdPEntityID  string `gorm:"column:idp_entity_id;type:text" json:"idp_entity_id"`
	SSOURL       string `gorm:"column:sso_url;type:text" json:"sso_url"`
	SLOURL       string `gorm:"column:slo_url;type:text" json:"slo_url,omitempty"`
	IdPCertPEM   string `gorm:"column:idp_cert_pem;type:text" json:"-"`
	MetadataURL  string `gorm:"column:metadata_url;type:text" json:"metadata_url,omitempty"`
	MetadataXML  string `gorm:"column:metadata_xml;type:text" json:"-"`
	NameIDFormat string `gorm:"column:name_id_format;type:varchar(255);default:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'" json:"name_id_format"`

	// Binding choices
	WantAssertionsSigned bool `gorm:"column:want_assertions_signed;default:true" json:"want_assertions_signed"`
	WantResponseSigned   bool `gorm:"column:want_response_signed;default:true" json:"want_response_signed"`
	SignAuthnRequests    bool `gorm:"column:sign_authn_requests;default:false" json:"sign_authn_requests"`

	// Attribute / claim handling
	AttributeMappingsJSON string `gorm:"column:attribute_mappings_json;type:text" json:"-"`
	RoleMappingsJSON      string `gorm:"column:role_mappings_json;type:text" json:"-"`
	RolesAttribute        string `gorm:"column:roles_attribute;type:varchar(128);default:'roles'" json:"roles_attribute"`
	GroupsAttribute       string `gorm:"column:groups_attribute;type:varchar(128);default:'groups'" json:"groups_attribute"`

	// Provisioning toggles (mirror SCIM connection)
	AutoProvisionUsers     bool `gorm:"column:auto_provision_users;default:true" json:"auto_provision_users"`
	SyncGroupsToTeams      bool `gorm:"column:sync_groups_to_teams;default:true" json:"sync_groups_to_teams"`
	DeactivateMissingUsers bool `gorm:"column:deactivate_missing_users;default:false" json:"deactivate_missing_users"`
	AllowAutoAccountLink   bool `gorm:"column:allow_auto_account_link;default:false" json:"allow_auto_account_link"`

	// Routing (email-domain match)
	EmailDomainsJSON string `gorm:"column:email_domains_json;type:text" json:"-"`

	// Operational state
	LastTestedAt     *time.Time `gorm:"index" json:"last_tested_at,omitempty"`
	LastLoginAt      *time.Time `gorm:"index" json:"last_login_at,omitempty"`
	LastError        string     `gorm:"type:text" json:"last_error,omitempty"`
	EncryptionStatus string     `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"index;not null" json:"updated_at"`

	// Transient hydration - populated from *JSON fields on read, serialised
	// back into them in BeforeSave. Mirrors the SCIM pattern.
	AttributeMappings []SAMLAttributeMapping `gorm:"-" json:"attribute_mappings"`
	RoleMappings      []SAMLRoleMapping      `gorm:"-" json:"role_mappings"`
	EmailDomains      []string               `gorm:"-" json:"email_domains"`
}

func (TableSAMLProviderConfig) TableName() string { return "saml_provider_configs" }

// defaultSAMLAttributeMappings returns the catch-all defaults used when an
// admin creates a connection without specifying attribute mappings. Covers
// the Entra-SAML claim URIs, which are the most painful to type by hand;
// admins for other IdPs override on save.
func defaultSAMLAttributeMappings() []SAMLAttributeMapping {
	return []SAMLAttributeMapping{
		{Source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Target: "email"},
		{Source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", Target: "first_name"},
		{Source: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", Target: "last_name"},
		{Source: "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Target: "roles"},
		{Source: "http://schemas.xmlsoap.org/claims/Group", Target: "groups"},
	}
}

func (c *TableSAMLProviderConfig) BeforeSave(tx *gorm.DB) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		c.Name = "SAML Provider"
	}
	c.EntityID = strings.TrimSpace(c.EntityID)
	c.IdPEntityID = strings.TrimSpace(c.IdPEntityID)
	c.SSOURL = strings.TrimSpace(c.SSOURL)
	c.SLOURL = strings.TrimSpace(c.SLOURL)
	c.MetadataURL = strings.TrimSpace(c.MetadataURL)
	c.NameIDFormat = strings.TrimSpace(c.NameIDFormat)
	if c.NameIDFormat == "" {
		c.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	c.RolesAttribute = strings.TrimSpace(c.RolesAttribute)
	if c.RolesAttribute == "" {
		c.RolesAttribute = "roles"
	}
	c.GroupsAttribute = strings.TrimSpace(c.GroupsAttribute)
	if c.GroupsAttribute == "" {
		c.GroupsAttribute = "groups"
	}

	// First-save: populate attribute mappings with the Entra default set so
	// the connection at least parses an Entra response out of the box.
	if c.AttributeMappings == nil && strings.TrimSpace(c.AttributeMappingsJSON) == "" {
		c.AttributeMappings = defaultSAMLAttributeMappings()
	}
	if c.AttributeMappings != nil {
		data, err := json.Marshal(c.AttributeMappings)
		if err != nil {
			return fmt.Errorf("marshal saml attribute mappings: %w", err)
		}
		c.AttributeMappingsJSON = string(data)
	}

	if c.RoleMappings != nil {
		data, err := json.Marshal(c.RoleMappings)
		if err != nil {
			return fmt.Errorf("marshal saml role mappings: %w", err)
		}
		c.RoleMappingsJSON = string(data)
	}

	if c.EmailDomains != nil {
		normalised := make([]string, 0, len(c.EmailDomains))
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
			normalised = append(normalised, trimmed)
		}
		data, err := json.Marshal(normalised)
		if err != nil {
			return fmt.Errorf("marshal saml email domains: %w", err)
		}
		c.EmailDomainsJSON = string(data)
	}

	// IdP cert + metadata XML are sensitive (the cert is public, but pinning
	// a cert in our DB is the integrity boundary against IdP-impersonation;
	// the XML may contain tenant identifiers). Encrypt at rest when KMS is on.
	if encrypt.IsEnabled() {
		if err := encryptString(&c.IdPCertPEM); err != nil {
			return fmt.Errorf("encrypt saml idp cert: %w", err)
		}
		if err := encryptString(&c.MetadataXML); err != nil {
			return fmt.Errorf("encrypt saml metadata xml: %w", err)
		}
		if c.IdPCertPEM != "" || c.MetadataXML != "" {
			c.EncryptionStatus = EncryptionStatusEncrypted
		}
	}
	return nil
}

func (c *TableSAMLProviderConfig) AfterFind(tx *gorm.DB) error {
	if c.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&c.IdPCertPEM); err != nil {
			return fmt.Errorf("decrypt saml idp cert: %w", err)
		}
		if err := decryptString(&c.MetadataXML); err != nil {
			return fmt.Errorf("decrypt saml metadata xml: %w", err)
		}
	}
	if strings.TrimSpace(c.AttributeMappingsJSON) != "" {
		if err := json.Unmarshal([]byte(c.AttributeMappingsJSON), &c.AttributeMappings); err != nil {
			return fmt.Errorf("unmarshal saml attribute mappings: %w", err)
		}
	}
	if strings.TrimSpace(c.RoleMappingsJSON) != "" {
		if err := json.Unmarshal([]byte(c.RoleMappingsJSON), &c.RoleMappings); err != nil {
			return fmt.Errorf("unmarshal saml role mappings: %w", err)
		}
	}
	if strings.TrimSpace(c.EmailDomainsJSON) != "" {
		if err := json.Unmarshal([]byte(c.EmailDomainsJSON), &c.EmailDomains); err != nil {
			return fmt.Errorf("unmarshal saml email domains: %w", err)
		}
	}
	return nil
}
