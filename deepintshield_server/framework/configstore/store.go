// Package configstore provides a persistent configuration store for DeepIntShield.
package configstore

import (
	"context"
	"fmt"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/migrator"
	"github.com/deepint-shield/ai-security/framework/vectorstore"
	"gorm.io/gorm"
)

// VirtualKeyQueryParams holds pagination, filtering, and search parameters for virtual key queries.
type VirtualKeyQueryParams struct {
	Limit      int
	Offset     int
	Search     string
	CustomerID string
	TeamID     string
	// WorkspaceID, when non-empty, narrows the result set to virtual keys
	// scoped to that workspace plus org-wide virtual keys (workspace_id IS
	// NULL). Empty string returns the legacy unfiltered listing.
	WorkspaceID string
}

// ModelConfigsQueryParams holds pagination, filtering, and search parameters for model configs queries.
type ModelConfigsQueryParams struct {
	Limit  int
	Offset int
	Search string
	// WorkspaceID narrows the result to model configs scoped to this
	// workspace plus tenant-wide rows (workspace_id IS NULL). Empty
	// returns the full tenant view.
	WorkspaceID string
}

// RoutingRulesQueryParams holds pagination, filtering, and search parameters for routing rules queries.
type RoutingRulesQueryParams struct {
	Limit  int
	Offset int
	Search string
	// WorkspaceID narrows the result to rules scoped to this workspace
	// plus tenant-wide rules (workspace_id IS NULL). Empty = full tenant.
	WorkspaceID string
}

// MCPClientsQueryParams holds pagination, filtering, and search parameters for MCP client queries.
type MCPClientsQueryParams struct {
	Limit  int
	Offset int
	Search string
	// WorkspaceID narrows the result to MCP clients scoped to this
	// workspace plus tenant-wide clients (workspace_id IS NULL). Empty
	// string returns the full tenant view.
	WorkspaceID string
}

// TeamsQueryParams holds pagination, filtering, and search parameters for team queries.
type TeamsQueryParams struct {
	Limit      int
	Offset     int
	Search     string
	CustomerID string
	// WorkspaceID narrows the result set to teams scoped to the named
	// workspace plus tenant-wide teams (workspace_id IS NULL). Empty =
	// no workspace narrowing (returns the full tenant view).
	WorkspaceID string
}

// CustomersQueryParams holds pagination, filtering, and search parameters for customer queries.
type CustomersQueryParams struct {
	Limit  int
	Offset int
	Search string
	// WorkspaceID narrows the result set to customers scoped to the named
	// workspace plus tenant-wide customers (workspace_id IS NULL).
	WorkspaceID string
}

// UsersQueryParams holds pagination and search parameters for workspace user queries.
type UsersQueryParams struct {
	Limit             int
	Offset            int
	Search            string
	CustomerID        string
	EntraConnectionID string
}

// LegalConsentQuery filters audit reads of the legal_consents table.
//
// Empty fields mean "no filter on this dimension". Caller can mix freely
// (e.g. UserID + DocumentType + From/To window).
type LegalConsentQuery struct {
	Limit           int
	Offset          int
	UserID          string
	Email           string
	DocumentType    string
	DocumentVersion string
	ConsentMethod   string
	From            *time.Time
	To              *time.Time
}

// ConfigStore is the interface for the config store.
type ConfigStore interface {
	// Health check
	Ping(ctx context.Context) error

	// Encryption
	EncryptPlaintextRows(ctx context.Context) error

	// Client config CRUD
	UpdateClientConfig(ctx context.Context, config *ClientConfig) error
	GetClientConfig(ctx context.Context) (*ClientConfig, error)

	// Framework config CRUD
	UpdateFrameworkConfig(ctx context.Context, config *tables.TableFrameworkConfig) error
	GetFrameworkConfig(ctx context.Context) (*tables.TableFrameworkConfig, error)

	// Provider config CRUD
	UpdateProvidersConfig(ctx context.Context, providers map[schemas.ModelProvider]ProviderConfig, tx ...*gorm.DB) error
	AddProvider(ctx context.Context, provider schemas.ModelProvider, config ProviderConfig, tx ...*gorm.DB) error
	UpdateProvider(ctx context.Context, provider schemas.ModelProvider, config ProviderConfig, tx ...*gorm.DB) error
	DeleteProvider(ctx context.Context, provider schemas.ModelProvider, tx ...*gorm.DB) error
	GetProvidersConfig(ctx context.Context) (map[schemas.ModelProvider]ProviderConfig, error)
	GetProviderConfig(ctx context.Context, provider schemas.ModelProvider) (*ProviderConfig, error)
	GetProviders(ctx context.Context) ([]tables.TableProvider, error)
	GetProvider(ctx context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error)
	UpdateStatus(ctx context.Context, provider schemas.ModelProvider, keyID string, status, errorMsg string) error

	// MCP config CRUD
	GetMCPConfig(ctx context.Context) (*schemas.MCPConfig, error)
	GetMCPClientByID(ctx context.Context, id string) (*tables.TableMCPClient, error)
	GetMCPClientByName(ctx context.Context, name string) (*tables.TableMCPClient, error)
	GetMCPClientsPaginated(ctx context.Context, params MCPClientsQueryParams) ([]tables.TableMCPClient, int64, error)
	CreateMCPClientConfig(ctx context.Context, clientConfig *schemas.MCPClientConfig) error
	UpdateMCPClientConfig(ctx context.Context, id string, clientConfig *tables.TableMCPClient) error
	DeleteMCPClientConfig(ctx context.Context, id string) error

	// Vector store config CRUD
	UpdateVectorStoreConfig(ctx context.Context, config *vectorstore.Config) error
	GetVectorStoreConfig(ctx context.Context) (*vectorstore.Config, error)

	// Logs store config CRUD
	UpdateLogsStoreConfig(ctx context.Context, config *logstore.Config) error
	GetLogsStoreConfig(ctx context.Context) (*logstore.Config, error)

	// Config CRUD
	GetConfig(ctx context.Context, key string) (*tables.TableGovernanceConfig, error)
	UpdateConfig(ctx context.Context, config *tables.TableGovernanceConfig, tx ...*gorm.DB) error
	GetSCIMProviderConfig(ctx context.Context, provider string) (*tables.TableSCIMProviderConfig, error)
	GetSCIMProviderConfigByID(ctx context.Context, id string) (*tables.TableSCIMProviderConfig, error)
	ListSCIMProviderConfigs(ctx context.Context, provider string) ([]tables.TableSCIMProviderConfig, error)
	CreateSCIMProviderConfig(ctx context.Context, config *tables.TableSCIMProviderConfig) error
	UpsertSCIMProviderConfig(ctx context.Context, config *tables.TableSCIMProviderConfig) error
	UpdateSCIMProviderConfig(ctx context.Context, config *tables.TableSCIMProviderConfig) error
	DeleteSCIMProviderConfig(ctx context.Context, id string) error
	ResolveSCIMProviderConfig(ctx context.Context, provider, connectionID, email string) (*tables.TableSCIMProviderConfig, error)
	CreateSCIMLoginState(ctx context.Context, state *tables.TableSCIMLoginState) error
	GetSCIMLoginStateByState(ctx context.Context, state string) (*tables.TableSCIMLoginState, error)
	DeleteSCIMLoginState(ctx context.Context, id string) error

	// GetSCIMConnectionByBearerHash returns the connection whose
	// `scim_bearer_hash` column matches the supplied sha256 hash of the
	// presented bearer. Used by the SCIM 2.0 inbound auth middleware to
	// authenticate IdP-pushed user/group lifecycle events. Returns
	// (nil, nil) when no row matches - the middleware then returns 401.
	GetSCIMConnectionByBearerHash(ctx context.Context, bearerHash string) (*tables.TableSCIMProviderConfig, error)

	// SAML provider config CRUD - parallel to the SCIM (OIDC) provider
	// config methods above. SAML and OIDC connections live in separate
	// tables so the schemas stay dense; the SSO handler layer picks the
	// right one based on what the admin created.
	GetSAMLProviderConfigByID(ctx context.Context, id string) (*tables.TableSAMLProviderConfig, error)
	ListSAMLProviderConfigs(ctx context.Context) ([]tables.TableSAMLProviderConfig, error)
	CreateSAMLProviderConfig(ctx context.Context, config *tables.TableSAMLProviderConfig) error
	UpdateSAMLProviderConfig(ctx context.Context, config *tables.TableSAMLProviderConfig) error
	DeleteSAMLProviderConfig(ctx context.Context, id string) error
	// ResolveSAMLProviderConfig picks the SAML connection that should
	// handle a sign-in attempt. Same routing rules as
	// ResolveSCIMProviderConfig: explicit connectionID wins, then
	// email-domain match, then the IsDefault fallback.
	ResolveSAMLProviderConfig(ctx context.Context, connectionID, email string) (*tables.TableSAMLProviderConfig, error)

	ListGuardrailProviders(ctx context.Context) ([]tables.TableGuardrailProvider, error)
	GetGuardrailProvider(ctx context.Context, id string) (*tables.TableGuardrailProvider, error)
	CreateGuardrailProvider(ctx context.Context, provider *tables.TableGuardrailProvider) error
	UpdateGuardrailProvider(ctx context.Context, provider *tables.TableGuardrailProvider) error
	DeleteGuardrailProvider(ctx context.Context, id string) error
	ListGuardrailPolicies(ctx context.Context) ([]tables.TableGuardrailPolicy, error)
	GetGuardrailPolicy(ctx context.Context, id string) (*tables.TableGuardrailPolicy, error)
	CreateGuardrailPolicy(ctx context.Context, policy *tables.TableGuardrailPolicy) error
	UpdateGuardrailPolicy(ctx context.Context, policy *tables.TableGuardrailPolicy) error
	SetDefaultGuardrailPolicy(ctx context.Context, id string) error
	DeleteGuardrailPolicy(ctx context.Context, id string) error
	ListGuardrailPolicyVersions(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyVersion, error)
	GetGuardrailPolicyVersion(ctx context.Context, id string) (*tables.TableGuardrailPolicyVersion, error)
	CreateGuardrailPolicyVersion(ctx context.Context, version *tables.TableGuardrailPolicyVersion) error
	UpdateGuardrailPolicyVersion(ctx context.Context, version *tables.TableGuardrailPolicyVersion) error
	PublishGuardrailPolicyVersion(ctx context.Context, policyID, versionID, publishedBy string) error
	ListGuardrailDomainPacks(ctx context.Context) ([]tables.TableGuardrailDomainPack, error)
	GetGuardrailDomainPack(ctx context.Context, id string) (*tables.TableGuardrailDomainPack, error)
	CreateGuardrailDomainPack(ctx context.Context, pack *tables.TableGuardrailDomainPack) error
	UpdateGuardrailDomainPack(ctx context.Context, pack *tables.TableGuardrailDomainPack) error
	DeleteGuardrailDomainPack(ctx context.Context, id string) error
	ListGuardrailPolicyProviderBindings(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyProviderBinding, error)
	ReplaceGuardrailPolicyProviderBindings(ctx context.Context, policyID string, bindings []tables.TableGuardrailPolicyProviderBinding) error
	ListGuardrailMCPToolPolicies(ctx context.Context, policyID string) ([]tables.TableGuardrailMCPToolPolicy, error)
	ReplaceGuardrailMCPToolPolicies(ctx context.Context, policyID string, toolPolicies []tables.TableGuardrailMCPToolPolicy) error
	GetGuardrailRAGSettings(ctx context.Context) (*tables.TableGuardrailRAGSettings, error)
	UpsertGuardrailRAGSettings(ctx context.Context, settings *tables.TableGuardrailRAGSettings) error
	ListGuardrailRAGSources(ctx context.Context) ([]tables.TableGuardrailRAGSource, error)
	GetGuardrailRAGSource(ctx context.Context, id string) (*tables.TableGuardrailRAGSource, error)
	CreateGuardrailRAGSource(ctx context.Context, source *tables.TableGuardrailRAGSource) error
	UpdateGuardrailRAGSource(ctx context.Context, source *tables.TableGuardrailRAGSource) error

	// Plugins CRUD
	GetPlugins(ctx context.Context) ([]*tables.TablePlugin, error)
	// GetPluginsForRuntimeBootstrap returns the merged effective plugin
	// config used to instantiate runtime plugin instances at gateway start.
	// Unlike GetPlugins (which honors the request's tenant context and is
	// the right call for UI list endpoints), this method takes every plugin
	// row across all tenants and picks the most-recently-updated row per
	// plugin name. The use case is single-tenant deployments where the UI
	// saves a tenant-scoped row but the runtime needs to pick it up on
	// gateway restart even though the bootstrap context carries no tenant
	// id. Multi-tenant deployments still get correct behaviour at UI-save
	// time via ReloadPlugin; this just makes the startup state survive
	// process restarts.
	GetPluginsForRuntimeBootstrap(ctx context.Context) ([]*tables.TablePlugin, error)
	// GetAllPluginsForRuntimeBootstrap returns one row per (name, workspace_id)
	// for the per-workspace runtime dispatch path - see the RDB impl for the
	// full rationale.
	GetAllPluginsForRuntimeBootstrap(ctx context.Context) ([]*tables.TablePlugin, error)
	GetPlugin(ctx context.Context, name string) (*tables.TablePlugin, error)
	CreatePlugin(ctx context.Context, plugin *tables.TablePlugin, tx ...*gorm.DB) error
	UpsertPlugin(ctx context.Context, plugin *tables.TablePlugin, tx ...*gorm.DB) error
	UpdatePlugin(ctx context.Context, plugin *tables.TablePlugin, tx ...*gorm.DB) error
	DeletePlugin(ctx context.Context, name string, tx ...*gorm.DB) error

	// Governance config CRUD
	GetVirtualKeys(ctx context.Context) ([]tables.TableVirtualKey, error)
	GetVirtualKeysPaginated(ctx context.Context, params VirtualKeyQueryParams) ([]tables.TableVirtualKey, int64, error)
	GetRedactedVirtualKeys(ctx context.Context, ids []string) ([]tables.TableVirtualKey, error) // leave ids empty to get all
	GetVirtualKey(ctx context.Context, id string) (*tables.TableVirtualKey, error)
	GetVirtualKeyByValue(ctx context.Context, value string) (*tables.TableVirtualKey, error)
	CreateVirtualKey(ctx context.Context, virtualKey *tables.TableVirtualKey, tx ...*gorm.DB) error
	UpdateVirtualKey(ctx context.Context, virtualKey *tables.TableVirtualKey, tx ...*gorm.DB) error
	ReplaceVirtualKeyGuardrailPolicies(ctx context.Context, virtualKeyID string, policyIDs []string, tx ...*gorm.DB) error
	DeleteVirtualKey(ctx context.Context, id string) error

	// Virtual key provider config CRUD
	GetVirtualKeyProviderConfigs(ctx context.Context, virtualKeyID string) ([]tables.TableVirtualKeyProviderConfig, error)
	CreateVirtualKeyProviderConfig(ctx context.Context, virtualKeyProviderConfig *tables.TableVirtualKeyProviderConfig, tx ...*gorm.DB) error
	UpdateVirtualKeyProviderConfig(ctx context.Context, virtualKeyProviderConfig *tables.TableVirtualKeyProviderConfig, tx ...*gorm.DB) error
	DeleteVirtualKeyProviderConfig(ctx context.Context, id uint, tx ...*gorm.DB) error

	// Virtual key MCP config CRUD
	GetVirtualKeyMCPConfigs(ctx context.Context, virtualKeyID string) ([]tables.TableVirtualKeyMCPConfig, error)
	CreateVirtualKeyMCPConfig(ctx context.Context, virtualKeyMCPConfig *tables.TableVirtualKeyMCPConfig, tx ...*gorm.DB) error
	UpdateVirtualKeyMCPConfig(ctx context.Context, virtualKeyMCPConfig *tables.TableVirtualKeyMCPConfig, tx ...*gorm.DB) error
	DeleteVirtualKeyMCPConfig(ctx context.Context, id uint, tx ...*gorm.DB) error

	// Team CRUD
	GetTeams(ctx context.Context, customerID string) ([]tables.TableTeam, error)
	GetTeamsPaginated(ctx context.Context, params TeamsQueryParams) ([]tables.TableTeam, int64, error)
	GetTeam(ctx context.Context, id string) (*tables.TableTeam, error)
	CreateTeam(ctx context.Context, team *tables.TableTeam, tx ...*gorm.DB) error
	UpdateTeam(ctx context.Context, team *tables.TableTeam, tx ...*gorm.DB) error
	GetTeamMembers(ctx context.Context, teamID string) ([]tables.TableAuthUser, error)
	ReplaceTeamMembers(ctx context.Context, teamID string, userIDs []string, tx ...*gorm.DB) error
	ReplaceTeamCustomerMembers(ctx context.Context, teamID string, customerIDs []string, tx ...*gorm.DB) error
	DeleteTeamMembersByUserID(ctx context.Context, userID string, tx ...*gorm.DB) error
	DeleteTeam(ctx context.Context, id string) error

	// Customer CRUD
	GetCustomers(ctx context.Context) ([]tables.TableCustomer, error)
	GetCustomersPaginated(ctx context.Context, params CustomersQueryParams) ([]tables.TableCustomer, int64, error)
	GetCustomer(ctx context.Context, id string) (*tables.TableCustomer, error)
	CreateCustomer(ctx context.Context, customer *tables.TableCustomer, tx ...*gorm.DB) error
	UpdateCustomer(ctx context.Context, customer *tables.TableCustomer, tx ...*gorm.DB) error
	DeleteCustomer(ctx context.Context, id string) error

	// Rate limit CRUD
	GetRateLimits(ctx context.Context) ([]tables.TableRateLimit, error)
	GetRateLimit(ctx context.Context, id string, tx ...*gorm.DB) (*tables.TableRateLimit, error)
	CreateRateLimit(ctx context.Context, rateLimit *tables.TableRateLimit, tx ...*gorm.DB) error
	UpdateRateLimit(ctx context.Context, rateLimit *tables.TableRateLimit, tx ...*gorm.DB) error
	UpdateRateLimits(ctx context.Context, rateLimits []*tables.TableRateLimit, tx ...*gorm.DB) error
	DeleteRateLimit(ctx context.Context, id string, tx ...*gorm.DB) error

	// Budget CRUD
	GetBudgets(ctx context.Context) ([]tables.TableBudget, error)
	GetBudget(ctx context.Context, id string, tx ...*gorm.DB) (*tables.TableBudget, error)
	CreateBudget(ctx context.Context, budget *tables.TableBudget, tx ...*gorm.DB) error
	UpdateBudget(ctx context.Context, budget *tables.TableBudget, tx ...*gorm.DB) error
	UpdateBudgets(ctx context.Context, budgets []*tables.TableBudget, tx ...*gorm.DB) error
	DeleteBudget(ctx context.Context, id string, tx ...*gorm.DB) error
	UpdateBudgetUsage(ctx context.Context, id string, currentUsage float64) error
	UpdateRateLimitUsage(ctx context.Context, id string, tokenCurrentUsage int64, requestCurrentUsage int64) error

	// Routing Rules CRUD
	GetRoutingRules(ctx context.Context) ([]tables.TableRoutingRule, error)
	GetRoutingRulesByScope(ctx context.Context, scope string, scopeID string) ([]tables.TableRoutingRule, error)
	GetRoutingRule(ctx context.Context, id string) (*tables.TableRoutingRule, error)
	GetRedactedRoutingRules(ctx context.Context, ids []string) ([]tables.TableRoutingRule, error) // leave ids empty to get all
	GetRoutingRulesPaginated(ctx context.Context, params RoutingRulesQueryParams) ([]tables.TableRoutingRule, int64, error)
	CreateRoutingRule(ctx context.Context, rule *tables.TableRoutingRule, tx ...*gorm.DB) error
	UpdateRoutingRule(ctx context.Context, rule *tables.TableRoutingRule, tx ...*gorm.DB) error
	DeleteRoutingRule(ctx context.Context, id string, tx ...*gorm.DB) error

	// Model config CRUD
	GetModelConfigs(ctx context.Context) ([]tables.TableModelConfig, error)
	GetModelConfigsPaginated(ctx context.Context, params ModelConfigsQueryParams) ([]tables.TableModelConfig, int64, error)
	GetModelConfig(ctx context.Context, modelName string, provider *string) (*tables.TableModelConfig, error)
	GetModelConfigByID(ctx context.Context, id string) (*tables.TableModelConfig, error)
	CreateModelConfig(ctx context.Context, modelConfig *tables.TableModelConfig, tx ...*gorm.DB) error
	UpdateModelConfig(ctx context.Context, modelConfig *tables.TableModelConfig, tx ...*gorm.DB) error
	UpdateModelConfigs(ctx context.Context, modelConfigs []*tables.TableModelConfig, tx ...*gorm.DB) error
	DeleteModelConfig(ctx context.Context, id string) error

	// Governance config CRUD
	GetGovernanceConfig(ctx context.Context) (*GovernanceConfig, error)

	// Tenant-alias resolution (email → canonical UUID tenant id). Decouples
	// tenant identity from a personal email; no-op fallback until aliases exist.
	ResolveCanonicalTenant(ctx context.Context, aliasKey string) (string, error)
	UpsertTenantAlias(ctx context.Context, aliasKey, tenantID, kind string) error
	// MigrateTenantIDs re-keys all tenant-scoped config rows old→new (used by
	// the operator-gated /rekey cutover and verified email changes).
	MigrateTenantIDs(ctx context.Context, mappings map[string]string) error

	// Organization CRUD
	CreateOrganization(ctx context.Context, org *tables.TableOrganization) error
	GetOrganizationByID(ctx context.Context, id string) (*tables.TableOrganization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*tables.TableOrganization, error)
	GetOrganizationsByOwnerID(ctx context.Context, ownerID string) ([]tables.TableOrganization, error)
	ListOrganizations(ctx context.Context) ([]tables.TableOrganization, error)
	UpdateOrganization(ctx context.Context, org *tables.TableOrganization) error
	DeleteOrganization(ctx context.Context, id string) error

	// Governance org (top of the 3-tier org → tenant → workspace
	// hierarchy). The id is internal-only - never surfaced in the UI.
	CreateGovernanceOrg(ctx context.Context, org *tables.TableGovernanceOrg) error
	GetGovernanceOrgByID(ctx context.Context, id string) (*tables.TableGovernanceOrg, error)
	// GetGovernanceOrgBySlug powers the SaaS `/login?org=<slug>` and
	// `/sso/{slug}` discovery routes - the slug is the customer-facing
	// identifier of a single governance_org, so the login screen can
	// show ONLY that customer's SSO buttons without leaking other
	// customers' connection names.
	GetGovernanceOrgBySlug(ctx context.Context, slug string) (*tables.TableGovernanceOrg, error)
	ListGovernanceOrgsByMember(ctx context.Context, userID string) ([]tables.TableGovernanceOrg, error)
	ListTenantsByGovernanceOrg(ctx context.Context, orgID string) ([]tables.TableOrganization, error)
	CreateGovernanceOrgMembership(ctx context.Context, m *tables.TableGovernanceOrgMembership) error
	GetGovernanceOrgMembership(ctx context.Context, orgID, userID string) (*tables.TableGovernanceOrgMembership, error)
	ListGovernanceOrgMemberships(ctx context.Context, orgID string) ([]tables.TableGovernanceOrgMembership, error)
	UpdateGovernanceOrgMembershipRole(ctx context.Context, orgID, userID, role string) error

	// Workspace CRUD
	CreateWorkspace(ctx context.Context, ws *tables.TableWorkspace) error
	GetWorkspaceByID(ctx context.Context, id string) (*tables.TableWorkspace, error)
	GetWorkspaceBySlug(ctx context.Context, orgID, slug string) (*tables.TableWorkspace, error)
	GetDefaultWorkspaceForOrg(ctx context.Context, orgID string) (*tables.TableWorkspace, error)
	ListWorkspacesByOrg(ctx context.Context, orgID string) ([]tables.TableWorkspace, error)
	ListWorkspacesByUser(ctx context.Context, userID string) ([]tables.TableWorkspace, error)
	UpdateWorkspace(ctx context.Context, ws *tables.TableWorkspace) error
	DeleteWorkspace(ctx context.Context, id string) error

	// Org & Workspace memberships
	CreateOrgMembership(ctx context.Context, m *tables.TableOrgMembership) error
	GetOrgMembership(ctx context.Context, orgID, userID string) (*tables.TableOrgMembership, error)
	ListOrgMembershipsByOrg(ctx context.Context, orgID string) ([]tables.TableOrgMembership, error)
	ListOrgMembershipsByUser(ctx context.Context, userID string) ([]tables.TableOrgMembership, error)
	UpdateOrgMembershipRole(ctx context.Context, orgID, userID, role string) error
	DeleteOrgMembership(ctx context.Context, orgID, userID string) error

	CreateWorkspaceMembership(ctx context.Context, m *tables.TableWorkspaceMembership) error
	GetWorkspaceMembership(ctx context.Context, workspaceID, userID string) (*tables.TableWorkspaceMembership, error)
	ListWorkspaceMembershipsByWorkspace(ctx context.Context, workspaceID string) ([]tables.TableWorkspaceMembership, error)
	ListWorkspaceMembershipsByUser(ctx context.Context, userID string) ([]tables.TableWorkspaceMembership, error)
	UpdateWorkspaceMembershipRole(ctx context.Context, workspaceID, userID, role string) error
	DeleteWorkspaceMembership(ctx context.Context, workspaceID, userID string) error

	// EnsureWorkspaceBackfill is the post-migration repair step that makes
	// workspaces + memberships consistent with the live organizations
	// table - see the function docstring in workspace_backfill.go.
	EnsureWorkspaceBackfill(ctx context.Context) error

	// Workspace API keys
	CreateWorkspaceAPIKey(ctx context.Context, key *tables.TableWorkspaceAPIKey) error
	GetWorkspaceAPIKeyByHash(ctx context.Context, keyHash string) (*tables.TableWorkspaceAPIKey, error)
	GetWorkspaceAPIKeyByID(ctx context.Context, id string) (*tables.TableWorkspaceAPIKey, error)
	ListWorkspaceAPIKeys(ctx context.Context, workspaceID string) ([]tables.TableWorkspaceAPIKey, error)
	RevokeWorkspaceAPIKey(ctx context.Context, id string) error
	TouchWorkspaceAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error

	// Auth config CRUD
	GetAuthConfig(ctx context.Context) (*AuthConfig, error)
	UpdateAuthConfig(ctx context.Context, config *AuthConfig) error
	CountUsers(ctx context.Context) (int64, error)
	GetUserByID(ctx context.Context, id string) (*tables.TableAuthUser, error)
	GetUserByEmail(ctx context.Context, email string) (*tables.TableAuthUser, error)
	GetUserByPendingEmail(ctx context.Context, email string) (*tables.TableAuthUser, error)
	GetUserByGoogleSubject(ctx context.Context, subject string) (*tables.TableAuthUser, error)
	GetUserByEntraIdentityKey(ctx context.Context, identityKey string) (*tables.TableAuthUser, error)
	// GetUserBySSOIdentityKey returns the user linked to a generic SSO
	// identity (Okta / Auth0 / Generic OIDC / SAML), looked up by the
	// "{connection_id}:{subject}" identity-key shape that session_sso.go
	// + auth_saml.go construct. Mirrors GetUserByEntraIdentityKey.
	GetUserBySSOIdentityKey(ctx context.Context, identityKey string) (*tables.TableAuthUser, error)
	GetUsersPaginated(ctx context.Context, params UsersQueryParams) ([]tables.TableAuthUser, int64, error)
	CreateUser(ctx context.Context, user *tables.TableAuthUser) error
	UpdateUser(ctx context.Context, user *tables.TableAuthUser) error
	DeleteUser(ctx context.Context, userID string) error
	CreateEmailVerificationToken(ctx context.Context, token *tables.TableEmailVerificationToken) error
	GetEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*tables.TableEmailVerificationToken, error)
	MarkEmailVerificationTokenUsed(ctx context.Context, id string, usedAt time.Time) error
	DeleteEmailVerificationTokensForUser(ctx context.Context, userID string) error
	GetUserInvitationByID(ctx context.Context, id string) (*tables.TableUserInvitation, error)
	GetUserInvitationByEmail(ctx context.Context, email string) (*tables.TableUserInvitation, error)
	GetUserInvitationByHash(ctx context.Context, tokenHash string) (*tables.TableUserInvitation, error)
	GetUserInvitations(ctx context.Context, params UsersQueryParams) ([]tables.TableUserInvitation, int64, error)
	CreateUserInvitation(ctx context.Context, invitation *tables.TableUserInvitation) error
	UpdateUserInvitation(ctx context.Context, invitation *tables.TableUserInvitation) error
	DeleteUserInvitation(ctx context.Context, invitationID string) error

	// Legal consents - append-only audit trail of accepted ToS / Privacy Policy versions.
	CreateLegalConsent(ctx context.Context, consent *tables.TableLegalConsent) error
	GetLegalConsentsForUser(ctx context.Context, userID string) ([]tables.TableLegalConsent, error)
	ListLegalConsents(ctx context.Context, params LegalConsentQuery) ([]tables.TableLegalConsent, int64, error)

	// Proxy config CRUD
	GetProxyConfig(ctx context.Context) (*tables.GlobalProxyConfig, error)
	UpdateProxyConfig(ctx context.Context, config *tables.GlobalProxyConfig) error

	// Restart required config CRUD
	GetRestartRequiredConfig(ctx context.Context) (*tables.RestartRequiredConfig, error)
	SetRestartRequiredConfig(ctx context.Context, config *tables.RestartRequiredConfig) error
	ClearRestartRequiredConfig(ctx context.Context) error

	// Session CRUD
	GetSession(ctx context.Context, token string) (*tables.SessionsTable, error)
	CreateSession(ctx context.Context, session *tables.SessionsTable) error
	UpdateSessionsEmailByUserID(ctx context.Context, userID, email string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	DeleteSession(ctx context.Context, token string) error
	FlushSessions(ctx context.Context) error

	// Model pricing CRUD
	GetModelPrices(ctx context.Context) ([]tables.TableModelPricing, error)
	UpsertModelPrices(ctx context.Context, pricing *tables.TableModelPricing, tx ...*gorm.DB) error
	DeleteModelPrices(ctx context.Context, tx ...*gorm.DB) error

	// Model parameters
	GetModelParameters(ctx context.Context, model string) (*tables.TableModelParameters, error)
	UpsertModelParameters(ctx context.Context, params *tables.TableModelParameters, tx ...*gorm.DB) error

	// Key management
	GetKeysByIDs(ctx context.Context, ids []string) ([]tables.TableKey, error)
	GetKeysByProvider(ctx context.Context, provider string) ([]tables.TableKey, error)
	GetAllRedactedKeys(ctx context.Context, ids []string) ([]schemas.Key, error) // leave ids empty to get all

	// Generic transaction manager
	ExecuteTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error

	// TryAcquireLock attempts to insert a lock row. Returns true if the lock was acquired.
	// If the lock already exists and is not expired, returns false.
	TryAcquireLock(ctx context.Context, lock *tables.TableDistributedLock) (bool, error)

	// GetLock retrieves a lock by its key. Returns nil if the lock doesn't exist.
	GetLock(ctx context.Context, lockKey string) (*tables.TableDistributedLock, error)

	// UpdateLockExpiry updates the expiration time for an existing lock.
	// Only succeeds if the holder ID matches the current lock holder.
	UpdateLockExpiry(ctx context.Context, lockKey, holderID string, expiresAt time.Time) error

	// ReleaseLock deletes a lock if the holder ID matches.
	// Returns true if the lock was released, false if it wasn't held by the given holder.
	ReleaseLock(ctx context.Context, lockKey, holderID string) (bool, error)

	// CleanupExpiredLockByKey atomically deletes a specific lock only if it has expired.
	// Returns true if an expired lock was deleted, false if the lock doesn't exist or hasn't expired.
	CleanupExpiredLockByKey(ctx context.Context, lockKey string) (bool, error)

	// CleanupExpiredLocks removes all locks that have expired.
	// Returns the number of locks cleaned up.
	CleanupExpiredLocks(ctx context.Context) (int64, error)

	// OAuth config CRUD
	GetOauthConfigByID(ctx context.Context, id string) (*tables.TableOauthConfig, error)
	GetOauthConfigByState(ctx context.Context, state string) (*tables.TableOauthConfig, error)
	GetOauthConfigByTokenID(ctx context.Context, tokenID string) (*tables.TableOauthConfig, error)
	CreateOauthConfig(ctx context.Context, config *tables.TableOauthConfig) error
	UpdateOauthConfig(ctx context.Context, config *tables.TableOauthConfig) error

	// OAuth token CRUD
	GetOauthTokenByID(ctx context.Context, id string) (*tables.TableOauthToken, error)
	GetExpiringOauthTokens(ctx context.Context, before time.Time) ([]*tables.TableOauthToken, error)
	CreateOauthToken(ctx context.Context, token *tables.TableOauthToken) error
	UpdateOauthToken(ctx context.Context, token *tables.TableOauthToken) error
	DeleteOauthToken(ctx context.Context, id string) error

	// Not found retry wrapper
	RetryOnNotFound(ctx context.Context, fn func(ctx context.Context) (any, error), maxRetries int, retryDelay time.Duration) (any, error)

	// Prompt Repository - Folders
	GetFolders(ctx context.Context) ([]tables.TableFolder, error)
	GetFolderByID(ctx context.Context, id string) (*tables.TableFolder, error)
	CreateFolder(ctx context.Context, folder *tables.TableFolder) error
	UpdateFolder(ctx context.Context, folder *tables.TableFolder) error
	DeleteFolder(ctx context.Context, id string) error

	// Prompt Repository - Prompts
	GetPrompts(ctx context.Context, folderID *string) ([]tables.TablePrompt, error)
	// GetPromptsScoped returns prompts visible from a specific workspace -
	// org-wide (workspace_id IS NULL) plus rows scoped to the workspace.
	// folderID is optional; pass nil for "all folders". Empty
	// workspaceID falls back to the legacy unscoped GetPrompts behaviour.
	GetPromptsScoped(ctx context.Context, folderID *string, workspaceID string) ([]tables.TablePrompt, error)
	GetPromptByID(ctx context.Context, id string) (*tables.TablePrompt, error)
	CreatePrompt(ctx context.Context, prompt *tables.TablePrompt) error
	UpdatePrompt(ctx context.Context, prompt *tables.TablePrompt) error
	DeletePrompt(ctx context.Context, id string) error

	// Prompt Repository - Versions
	GetPromptVersions(ctx context.Context, promptID string) ([]tables.TablePromptVersion, error)
	GetPromptVersionByID(ctx context.Context, id uint) (*tables.TablePromptVersion, error)
	GetLatestPromptVersion(ctx context.Context, promptID string) (*tables.TablePromptVersion, error)
	CreatePromptVersion(ctx context.Context, version *tables.TablePromptVersion) error
	DeletePromptVersion(ctx context.Context, id uint) error

	// Prompt Repository - Sessions
	GetPromptSessions(ctx context.Context, promptID string) ([]tables.TablePromptSession, error)
	GetPromptSessionByID(ctx context.Context, id uint) (*tables.TablePromptSession, error)
	CreatePromptSession(ctx context.Context, session *tables.TablePromptSession) error
	UpdatePromptSession(ctx context.Context, session *tables.TablePromptSession) error
	RenamePromptSession(ctx context.Context, id uint, name string) error
	DeletePromptSession(ctx context.Context, id uint) error

	// DB returns the underlying database connection.
	DB() *gorm.DB

	// Workspace-scoped logging overrides - per-workspace override of the
	// tenant-global Logs Settings. Absent row means "inherit defaults".
	GetWorkspaceLoggingSettings(ctx context.Context, workspaceID string) (*WorkspaceLoggingSettings, error)
	UpsertWorkspaceLoggingSettings(ctx context.Context, settings *WorkspaceLoggingSettings) error
	DeleteWorkspaceLoggingSettings(ctx context.Context, workspaceID string) error

	// Workspace-scoped MCP overrides - same pattern as logging settings.
	// Tenant-global CoreConfig fields apply unless a workspace writes a row.
	GetWorkspaceMCPSettings(ctx context.Context, workspaceID string) (*WorkspaceMCPSettings, error)
	UpsertWorkspaceMCPSettings(ctx context.Context, settings *WorkspaceMCPSettings) error
	DeleteWorkspaceMCPSettings(ctx context.Context, workspaceID string) error

	// Agentic Security control-plane CRUD. See framework/agentic for the
	// runtime + DelegationContext model these methods feed. All methods
	// enforce tenant + workspace isolation via tenantctx.
	ListAgenticPolicies(ctx context.Context) ([]tables.TableAgenticPolicy, error)
	GetAgenticPolicy(ctx context.Context, id string) (*tables.TableAgenticPolicy, error)
	CreateAgenticPolicy(ctx context.Context, row *tables.TableAgenticPolicy) error
	UpdateAgenticPolicy(ctx context.Context, row *tables.TableAgenticPolicy) error
	DeleteAgenticPolicy(ctx context.Context, id string) error
	// Policy ↔ VK / Team / Member targeting (per-policy scoping, in
	// addition to the AppliesToAllKeys broad-scope flag on the policy
	// row). All three target tables share the same shape; the LoadAll
	// variants are used by the PolicyTargetResolver to warm its
	// in-process maps at startup.
	ListAgenticPolicyTargetsForVK(ctx context.Context, vkID string) ([]string, error)
	ListAllAgenticPolicyTargets(ctx context.Context) ([]tables.TableAgenticPolicyVKTarget, error)
	ListAllAgenticPolicyTeamTargets(ctx context.Context) ([]tables.TableAgenticPolicyTeamTarget, error)
	ListAllAgenticPolicyMemberTargets(ctx context.Context) ([]tables.TableAgenticPolicyMemberTarget, error)
	ListAgenticToolTiering(ctx context.Context) ([]tables.TableAgenticToolTiering, error)
	UpsertAgenticToolTiering(ctx context.Context, row *tables.TableAgenticToolTiering) error
	DeleteAgenticToolTiering(ctx context.Context, id string) error
	AppendAgenticDecision(ctx context.Context, row *tables.TableAgenticDecision) error
	ListAgenticDecisions(ctx context.Context, limit int, verdict, tool string, since, until *time.Time) ([]tables.TableAgenticDecision, error)
	CountAgenticDecisionsByVerdict(ctx context.Context, since, until *time.Time) (map[string]int64, error)
	GetAgenticEnforcementState(ctx context.Context) (*tables.TableAgenticEnforcementState, error)
	// ListAgenticEnforcementStates returns every persisted enforcement row
	// across every tenant/workspace. Used by the boot-time runtime warmup
	// so a cold start respects the operator's last rollout configuration
	// on every workspace, not just the first one the tenant-scoped Get
	// would happen to return. No tenant filter is applied - caller is
	// expected to be the warmup (which iterates all rows by design).
	ListAgenticEnforcementStates(ctx context.Context) ([]tables.TableAgenticEnforcementState, error)
	UpdateAgenticEnforcementState(ctx context.Context, row *tables.TableAgenticEnforcementState) error

	// Agentic Cache - metrics-only event store + per-workspace config (Part X).
	AppendAgenticCacheEvent(ctx context.Context, row *tables.TableAgenticCacheEvent) error
	CountAgenticCacheEventsByKind(ctx context.Context, since, until *time.Time, virtualKeys []string) ([]CacheKindStat, error)
	AggregateAgenticCacheSavings(ctx context.Context, since, until *time.Time, bucket string) ([]CacheSavingsBucket, error)
	DecisionCacheHitRate(ctx context.Context, since, until *time.Time, virtualKeys []string) (hits, total int64, err error)
	GetAgenticCacheSettings(ctx context.Context) (*tables.TableAgenticCacheSettings, error)
	UpdateAgenticCacheSettings(ctx context.Context, row *tables.TableAgenticCacheSettings) error
	ListAllAgenticCacheSettings(ctx context.Context) ([]tables.TableAgenticCacheSettings, error)

	// Migration manager
	RunMigration(ctx context.Context, migration *migrator.Migration) error

	// Cleanup
	Close(ctx context.Context) error
}

// NewConfigStore creates a new config store based on the configuration
func NewConfigStore(ctx context.Context, config *Config, logger schemas.Logger) (ConfigStore, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if !config.Enabled {
		return nil, nil
	}
	switch config.Type {
	case ConfigStoreTypeSQLite:
		if sqliteConfig, ok := config.Config.(*SQLiteConfig); ok {
			return newSqliteConfigStore(ctx, sqliteConfig, logger)
		}
		return nil, fmt.Errorf("invalid sqlite config: %T", config.Config)
	case ConfigStoreTypePostgres:
		if postgresConfig, ok := config.Config.(*PostgresConfig); ok {
			return newPostgresConfigStore(ctx, postgresConfig, logger)
		}
		return nil, fmt.Errorf("invalid postgres config: %T", config.Config)
	}
	return nil, fmt.Errorf("unsupported config store type: %s", config.Type)
}
