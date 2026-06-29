package configstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/migrator"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// migrationAdvisoryLockKey is used for PostgreSQL advisory locks
	// to serialize migrations across cluster nodes
	migrationAdvisoryLockKey = 1000001
)

// migrationLock holds a dedicated connection for the advisory lock.
// This ensures the lock is held on the same connection throughout migrations,
// preventing race conditions caused by GORM's connection pooling.
type migrationLock struct {
	conn *sql.Conn
}

// acquireMigrationLock gets a dedicated connection and acquires an advisory lock.
// For non-PostgreSQL databases, returns a no-op lock.
func acquireMigrationLock(ctx context.Context, db *gorm.DB) (*migrationLock, error) {
	if db.Dialector.Name() != "postgres" {
		return &migrationLock{}, nil
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// Get a dedicated connection (not returned to pool until Close())
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dedicated connection: %w", err)
	}

	// Acquire advisory lock on this dedicated connection.
	// This will BLOCK if another node holds the lock.
	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLockKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to acquire migration advisory lock: %w", err)
	}

	return &migrationLock{conn: conn}, nil
}

// release unlocks and closes the dedicated connection
func (l *migrationLock) release(ctx context.Context) {
	if l.conn == nil {
		return
	}
	// Release lock on the SAME connection that acquired it
	_, _ = l.conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockKey)
	l.conn.Close()
}

// Migrate performs the necessary database migrations.
func triggerMigrations(ctx context.Context, db *gorm.DB) error {
	// Acquire advisory lock to serialize migrations across cluster nodes.
	// This prevents race conditions when multiple nodes start simultaneously
	// and try to create the same tables in parallel.
	lock, err := acquireMigrationLock(ctx, db)
	if err != nil {
		return err
	}
	defer lock.release(ctx)

	if err := migrationInit(ctx, db); err != nil {
		return err
	}
	if err := migrationMany2ManyJoinTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddCustomProviderConfigJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyProviderConfigTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAllowedOriginsJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAllowDirectKeysColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddEnableLiteLLMFallbacksColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationTeamsTableUpdates(ctx, db); err != nil {
		return err
	}
	if err := migrationAddKeyNameColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddFrameworkConfigsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationCleanupMCPClientToolsConfig(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyMCPConfigsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPluginPathColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddProviderConfigBudgetRateLimit(ctx, db); err != nil {
		return err
	}
	if err := migrationAddSessionsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDashboardAuthTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDashboardAuthUserProfileFields(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDashboardAuthUserThemePreference(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDashboardUserInvitationsAndRoles(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGovernanceTeamMembers(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGovernanceTeamCustomerMembers(ctx, db); err != nil {
		return err
	}
	if err := migrationAddHeadersJSONColumnIntoMCPClient(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDisableContentLoggingColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMCPClientIDColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVertexProjectNumberColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVertexDeploymentsJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationMissingProviderColumnInKeyTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddToolsToAutoExecuteJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddIsCodeModeClientColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddLogRetentionDaysColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddEnabledColumnToKeyTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddBatchAndCachePricingColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMCPAgentDepthAndMCPToolExecutionTimeoutColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMCPCodeModeBindingLevelColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationNormalizeMCPClientNames(ctx, db); err != nil {
		return err
	}
	if err := migrationMoveKeysToProviderConfig(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPluginVersionColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddSendBackRawRequestColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddConfigHashColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyConfigHashColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAdditionalConfigHashColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAdd200kTokenPricingColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddImagePricingColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddUseForBatchAPIColumnAndS3BucketsConfig(ctx, db); err != nil {
		return err
	}
	if err := migrationAddUseForCacheColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyCachePolicyColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyCacheKeyColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddHeaderFilterConfigJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAzureClientIDAndClientSecretAndTenantIDColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDistributedLocksTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddModelConfigTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddProviderGovernanceColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAllowedHeadersJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddDisableDBPingsInHealthColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddIsPingAvailableColumnToMCPClientTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddToolPricingJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationRemoveServerPrefixFromMCPTools(ctx, db); err != nil {
		return err
	}
	if err := migrationAddOAuthTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddSCIMProviderConfigsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationExpandSCIMProviderConfigsForMultiConnection(ctx, db); err != nil {
		return err
	}
	if err := RunSSOMigrations(ctx, db); err != nil {
		return err
	}
	if err := RunCatalogMigrations(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailControlPlaneTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailPolicyDefaultsAndVirtualKeyBindings(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailRAGConfigTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddToolSyncIntervalColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMCPClientConfigToOAuthConfig(ctx, db); err != nil {
		return err
	}
	if err := migrationAddRoutingRulesTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddBaseModelPricingColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAzureScopesColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddReplicateDeploymentsJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddKeyStatusColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddProviderStatusColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddRateLimitToTeamsAndCustomers(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAsyncJobResultTTLColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddRequiredHeadersJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddLoggingHeadersJSONColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddHideDeletedVirtualKeysInFiltersColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddEnforceSCIMAuthColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddEnforceAuthOnInferenceColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddProviderPricingOverridesColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddEncryptionColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddOutputCostPerVideoPerSecond(ctx, db); err != nil {

		return err
	}
	if err := migrationDropEnableGovernanceColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVLLMKeyConfigColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationWidenEncryptedVarcharColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddBedrockAssumeRoleColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddStoreRawRequestResponseColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPricingRefactorColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationRenameTruncatedPricingColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddImageQualityPricingColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddRoutingTargetsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPromptRepoTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPluginOrderColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddTenantIsolation(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMultiTenantOrganizations(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeySemanticCacheEnabledColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddKeySelectionStrategyColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailExecutionMode(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMCPCacheColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateLegalConsentsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddWorkspacesAndMemberships(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailPolicyWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailPolicyOrgID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyRotationFields(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyRotationNoticeFields(ctx, db); err != nil {
		return err
	}
	if err := migrationAddLoadBalancerEnabledColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateWorkspaceAPIKeysTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPromptWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddOrganizationDescription(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMCPClientWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddRoutingRuleWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddModelConfigWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddPluginWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddRAGSourceWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationAddGuardrailProviderWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationBackfillGuardrailProviderWrappers(ctx, db); err != nil {
		return err
	}
	if err := migrationDropLegacyNullWorkspaceProviders(ctx, db); err != nil {
		return err
	}
	if err := migrationDropOrphanGuardrailWrappers(ctx, db); err != nil {
		return err
	}
	if err := migrationBumpWrapperPolicyTimeouts(ctx, db); err != nil {
		return err
	}
	if err := migrationFlipWrapperPoliciesAsync(ctx, db); err != nil {
		return err
	}
	if err := migrationFlipWrapperPoliciesSyncCached(ctx, db); err != nil {
		return err
	}
	if err := migrationClearWrapperPolicyDefault(ctx, db); err != nil {
		return err
	}
	// Tracks which specific workspace an invitation grants. Empty/NULL
	// keeps the legacy "tenant-wide" semantics; non-NULL wires the
	// workspace_membership the invitee gets when they accept.
	if err := migrationAddUserInvitationWorkspaceID(ctx, db); err != nil {
		return err
	}
	if err := migrationBackfillNullWorkspaceIDs(ctx, db); err != nil {
		return err
	}
	if err := migrationAddProviderKeyWorkspaceID(ctx, db); err != nil {
		return err
	}
	// Re-run backfill for config_providers specifically. The original
	// migrationBackfillNullWorkspaceIDs (id="backfill_null_workspace_ids")
	// shipped without config_providers in its target list, so any DB
	// that ran it before has already-applied state and won't pick up the
	// added entry on subsequent boots. This separately-IDed migration
	// closes the gap by pinning legacy NULL provider rows to their
	// tenant's Default workspace.
	if err := migrationBackfillNullWorkspaceIDsForProviders(ctx, db); err != nil {
		return err
	}
	// Swap the provider unique index from (tenant_id, name) to
	// (tenant_id, workspace_id, name) so the same provider can be added
	// in different workspaces of the same tenant. Must run BEFORE
	// AutoMigrate so AutoMigrate creates the new index instead of
	// finding the old one and leaving it.
	if err := migrationProviderUniqueIndexAddWorkspace(ctx, db); err != nil {
		return err
	}
	if err := migrationRoutingRuleUniqueIndexAddWorkspace(ctx, db); err != nil {
		return err
	}
	// Backfill keys with their parent provider's workspace_id. Earlier
	// versions of AddProvider/UpdateProvider didn't stamp config_keys
	// with workspace_id, so a tenant's keys ended up with NULL even
	// though their parent provider was workspace-scoped. This migration
	// copies the provider's workspace_id onto every key row that's
	// missing one.
	if err := migrationBackfillKeyWorkspaceFromProvider(ctx, db); err != nil {
		return err
	}
	// Swap the two unique indexes on config_keys to include workspace_id
	// so a tenant admin can use the same key name (or KeyID) in
	// sibling workspaces. Without this, the upsert in UpdateProvider
	// hits a 23505 unique-violation that surfaces as
	// "Failed to update provider: a record with this name already exists".
	if err := migrationKeyUniqueIndexAddWorkspace(ctx, db); err != nil {
		return err
	}
	// Swap the virtual key unique index from (tenant_id, name) to
	// (tenant_id, workspace_id, name) so the same virtual key name can
	// exist in different workspaces of the same tenant. Same shape as
	// migrationProviderUniqueIndexAddWorkspace.
	if err := migrationVirtualKeyUniqueIndexAddWorkspace(ctx, db); err != nil {
		return err
	}
	// Adds the workspace_id column to governance_teams + governance_customers
	// so Members + Teams under the Governance Hub can be scoped per
	// workspace. NULLs (legacy rows) are surfaced as tenant-wide by
	// the OR workspace_id IS NULL filter in the list queries, so no
	// backfill is needed.
	if err := migrationTeamCustomerAddWorkspaceColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationAdd3TierOrgs(ctx, db); err != nil {
		return err
	}
	if err := migrationAddVirtualKeyFallbackChainColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationPluginWorkspaceUniqueIndex(ctx, db); err != nil {
		return err
	}
	if err := migrationMCPWorkspaceUniqueIndex(ctx, db); err != nil {
		return err
	}
	if err := migrationPromptsWorkspaceFreshStart(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateWorkspaceLoggingSettingsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateWorkspaceMCPSettingsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAgenticSecurityTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAgenticObservabilityTables(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAgenticCacheTables(ctx, db); err != nil {
		return err
	}
	if err := migrationUnifyVirtualKeyAgentColumns(ctx, db); err != nil {
		return err
	}
	// Drop the legacy agentic_virtual_keys + agentic_workspace_access
	// tables AFTER the unify migration has copied any remaining rows.
	// Idempotent - no-op on fresh installs that never created them.
	if err := migrationDropLegacyAgenticTables(ctx, db); err != nil {
		return err
	}
	// Per-policy VK scoping: adds applies_to_all_keys + agentic_policy_vk_targets.
	// Must run AFTER the policies table exists.
	if err := migrationAddPolicyVKTargets(ctx, db); err != nil {
		return err
	}
	// Data-copy: materialize per-target scoped policies (draft status) from
	// the legacy allowed_tools / default_obligations / rate-limit / autonomy
	// columns on VK, Team, and Customer. Must run AFTER the target tables
	// exist and AFTER the unify-VK migration has populated the VK agent
	// columns. Idempotent: re-runs skip rows whose policy already exists.
	if err := migrationDeriveVKScopedPoliciesFromVKColumns(ctx, db); err != nil {
		return err
	}
	// Destructive cleanup - drops the now-redundant columns from VK +
	// Team + Customer. Runs AFTER the derive step so no data is lost.
	if err := migrationDropLegacyAllowedToolsColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddTraceSummaryColumns(ctx, db); err != nil {
		return err
	}
	// Tool Integrity Engine columns (integrity_posture + per-decision/approval
	// divergence evidence). Additive; new migration ID so it runs once on
	// databases that predate the feature.
	if err := migrationAddToolIntegrityColumns(ctx, db); err != nil {
		return err
	}
	// Cached tool-behavior summaries ("what this tool does"). Additive.
	if err := migrationAddAgenticToolSummaries(ctx, db); err != nil {
		return err
	}
	// Per-workspace LLM-call config for tool summaries (enable + VK + model).
	if err := migrationAddToolSummaryLLMSettings(ctx, db); err != nil {
		return err
	}
	// Persisted/JIT approval grants + approval fingerprint columns.
	if err := migrationAddAgenticToolGrants(ctx, db); err != nil {
		return err
	}
	// Append-only ReBAC (OpenFGA) tuple-change audit table.
	if err := migrationAddRelationshipAudit(ctx, db); err != nil {
		return err
	}
	// Agent attribute taxonomy: agent_risk_level + agent_capabilities on
	// governance_virtual_keys so policies can match agent risk/capability
	// without naming agents. Additive; new ID so it runs once on databases
	// that predate the feature.
	if err := migrationAddAgentRiskCapabilityColumns(ctx, db); err != nil {
		return err
	}
	// Accountability registry: owner/team/purpose/version/registered_by on
	// agentic_identities (Pillar 3 ownership). Additive; new ID.
	if err := migrationAddAgenticIdentityOwnershipColumns(ctx, db); err != nil {
		return err
	}
	// Fine-grained ABAC: agent_namespace on governance_virtual_keys. Additive; new ID.
	if err := migrationAddAgentNamespaceColumn(ctx, db); err != nil {
		return err
	}
	// ASI04 supply-chain: tool pinning columns on agentic_tool_tiering. Additive; new ID.
	if err := migrationAddToolPinningColumns(ctx, db); err != nil {
		return err
	}
	// Backfill org_id on legacy agentic_policies rows from their workspace's
	// org so the new active-org scoping in ListAgenticPolicies doesn't hide
	// rows that predate org stamping. Must run AFTER the policies + workspaces
	// tables exist. Idempotent.
	if err := migrationBackfillAgenticPolicyOrgID(ctx, db); err != nil {
		return err
	}
	// Drop redundant single-column tenant_id indexes that are already
	// covered by composite (tenant_id, …) indexes. Idempotent.
	if err := migrationDropRedundantTenantIDIndexes(ctx, db); err != nil {
		return err
	}
	if err := migrationAddTunnelCertsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddTenantAliasesTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddMfaColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateDPHeartbeatsTable(ctx, db); err != nil {
		return err
	}
	// Opt-in prompt preview: prompt_preview on agentic_observations + a
	// capture_prompt_preview toggle on agentic_observability_settings. Additive;
	// new ID; default-off so zero-data-retention is preserved until a workspace
	// explicitly enables capture.
	if err := migrationAddPromptPreviewColumns(ctx, db); err != nil {
		return err
	}
	// Agent blueprint registry: the SDK-declared tool surface (nodes/tools/edges)
	// registered before a run. Additive; new ID.
	if err := migrationAddAgenticBlueprintsTable(ctx, db); err != nil {
		return err
	}
	// Opt-in blueprint allow-list enforcement toggle on the enforcement state.
	// Additive; new ID; default false.
	if err := migrationAddBlueprintEnforceColumn(ctx, db); err != nil {
		return err
	}
	// Workspace source-code threat-scan config + per-blueprint scan results.
	// Additive; new ID.
	if err := migrationAddCodeScanColumns(ctx, db); err != nil {
		return err
	}
	// Per-agent rate limit (T4 Resource Overload / DoS guard). Additive; new ID.
	if err := migrationAddRateLimitColumn(ctx, db); err != nil {
		return err
	}
	// Code-scan model selection (within the chosen VK). Additive; new ID.
	if err := migrationAddCodeScanModelColumn(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateFeatureReleasesTable(ctx, db); err != nil {
		return err
	}
	return nil
}

// migrationCreateFeatureReleasesTable creates feature_releases, the control-plane
// registry of opt-in feature releases that orgs apply via the "Update" button.
// AutoMigrate is non-destructive on Postgres + SQLite.
func migrationCreateFeatureReleasesTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_feature_releases_table_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableFeatureRelease{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error creating feature releases table: %s", err.Error())
	}
	return nil
}

// migrationCreateDPHeartbeatsTable creates governance_dp_heartbeats, which holds
// the last-seen running image version of each Enterprise-VPC data plane (keyed by
// tunnel scope id). Pure visibility for the admin console; AutoMigrate is
// non-destructive on Postgres + SQLite.
func migrationCreateDPHeartbeatsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_dp_heartbeats_table_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableDPHeartbeat{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error creating dp heartbeats table: %s", err.Error())
	}
	return nil
}

// migrationAddMfaColumns adds the native-TOTP MFA columns (mfa_enabled,
// mfa_secret, mfa_recovery_codes) to auth_users. AutoMigrate only adds missing
// columns, so it is non-destructive on both Postgres and SQLite. Bumped to v2
// when mfa_recovery_codes was added - a new migration ID is required because
// AutoMigrate inside an already-recorded migration never re-runs.
func migrationAddMfaColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_user_mfa_columns_v2",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAuthUser{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error adding user mfa columns: %s", err.Error())
	}
	return nil
}

// migrationCreateWorkspaceMCPSettingsTable creates the per-workspace MCP
// overrides table. Rows are written by the workspace-scoped MCP Settings
// page; absence means "inherit tenant defaults from CoreConfig". Mirrors
// migrationCreateWorkspaceLoggingSettingsTable in shape so the two
// workspace-override surfaces stay symmetric.
func migrationCreateWorkspaceMCPSettingsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_workspace_mcp_settings_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableWorkspaceMCPSettings{})
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropTable(&tables.TableWorkspaceMCPSettings{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running workspace_mcp_settings migration: %s", err.Error())
	}
	return nil
}

// migrationCreateWorkspaceLoggingSettingsTable creates the per-workspace
// logging overrides table. Rows are written by the workspace-scoped Logs
// Settings page; absence means "this workspace inherits the tenant default
// from CoreConfig". The single-table design keeps the read path tight - a
// single primary-key lookup per request when scoping needs to apply.
func migrationCreateWorkspaceLoggingSettingsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_workspace_logging_settings_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableWorkspaceLoggingSettings{})
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropTable(&tables.TableWorkspaceLoggingSettings{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running workspace_logging_settings migration: %s", err.Error())
	}
	return nil
}

// migrationTeamCustomerAddWorkspaceColumn adds the workspace_id column to
// governance_teams + governance_customers. Idempotent: skips when the
// column already exists. Also creates the matching indexes so list
// queries don't seq-scan the table once it grows.
func migrationTeamCustomerAddWorkspaceColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "team_customer_add_workspace_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			for _, table := range []string{"governance_teams", "governance_customers"} {
				if !tx.Migrator().HasTable(table) {
					continue
				}
				if !tx.Migrator().HasColumn(table, "workspace_id") {
					if err := tx.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN workspace_id varchar(255)`, table)).Error; err != nil {
						return fmt.Errorf("failed to add workspace_id to %s: %w", table, err)
					}
				}
				if err := tx.Exec(fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%s_workspace_id ON %s (workspace_id)`, table, table)).Error; err != nil {
					return fmt.Errorf("failed to create workspace_id index on %s: %w", table, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			for _, table := range []string{"governance_teams", "governance_customers"} {
				if err := tx.Exec(fmt.Sprintf(`DROP INDEX IF EXISTS idx_%s_workspace_id`, table)).Error; err != nil {
					return err
				}
				if tx.Migrator().HasTable(table) && tx.Migrator().HasColumn(table, "workspace_id") {
					if err := tx.Exec(fmt.Sprintf(`ALTER TABLE %s DROP COLUMN workspace_id`, table)).Error; err != nil {
						return err
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error adding workspace_id to teams/customers: %s", err.Error())
	}
	return nil
}

// migrationAdd3TierOrgs introduces the new top-level governance_orgs
// table sitting above the existing organizations (tenants) table.
//
// What it does (idempotent):
//  1. Creates the governance_orgs + governance_org_memberships tables.
//  2. Adds organization_id columns to `organizations` and `auth_users`
//     (the existing migration helpers add NULLable columns, so this is
//     non-destructive).
//  3. For every existing organizations row that doesn't already have an
//     organization_id, creates a parent governance_orgs row with the
//     same name + slug + owner, then sets organizations.organization_id.
//  4. Backfills auth_users.organization_id from each user's tenant.
//  5. Adds an org-owner membership for each parent org's owner so the
//     RBAC helpers find the right role.
//
// The org_id is internal-only - it's a UUID auto-generated here and
// surfaces nowhere in the UI. Existing single-tenant deployments
// transparently gain a wrapping org with the same name as their tenant.
func migrationAdd3TierOrgs(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_3_tier_orgs",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			// 1. Tables.
			if err := tx.AutoMigrate(&tables.TableGovernanceOrg{}, &tables.TableGovernanceOrgMembership{}); err != nil {
				return fmt.Errorf("failed to create governance_orgs tables: %w", err)
			}
			// 2. Columns.
			if !mig.HasColumn(&tables.TableOrganization{}, "organization_id") {
				if err := mig.AddColumn(&tables.TableOrganization{}, "organization_id"); err != nil {
					return fmt.Errorf("failed to add organization_id to organizations: %w", err)
				}
			}
			if !mig.HasColumn(&tables.TableAuthUser{}, "organization_id") {
				if err := mig.AddColumn(&tables.TableAuthUser{}, "organization_id"); err != nil {
					return fmt.Errorf("failed to add organization_id to auth_users: %w", err)
				}
			}
			// 3. Backfill: for every org row missing organization_id,
			// create a parent governance_orgs row using the same name +
			// slug + owner. The slug uniqueness is preserved by suffixing
			// "-org" if a collision is somehow encountered (rare -
			// the organizations.slug column is already unique tenant-wide).
			var orgs []tables.TableOrganization
			if err := tx.Where("organization_id IS NULL OR organization_id = ?", "").Find(&orgs).Error; err != nil {
				return fmt.Errorf("failed to load tenants for backfill: %w", err)
			}
			now := time.Now().UTC()
			for i := range orgs {
				expectedSlug := orgs[i].Slug + "-org"
				// Idempotency: if the migration partially completed on a
				// previous run (parent governance_org created but
				// organizations.organization_id update never landed, or
				// the migrator's tracking row was wiped), reuse the
				// existing parent rather than re-inserting and tripping
				// the idx_governance_orgs_slug unique constraint.
				var parent tables.TableGovernanceOrg
				lookupErr := tx.Where("slug = ?", expectedSlug).First(&parent).Error
				switch {
				case lookupErr == nil:
					// Parent already exists from a prior partial run - keep it.
				case errors.Is(lookupErr, gorm.ErrRecordNotFound):
					parent = tables.TableGovernanceOrg{
						ID:          "go-" + uuid.NewString(),
						Name:        orgs[i].Name,
						Slug:        expectedSlug,
						Description: orgs[i].Description,
						OwnerUserID: orgs[i].OwnerID,
						Plan:        orgs[i].Plan,
						CreatedAt:   orgs[i].CreatedAt,
						UpdatedAt:   now,
					}
					if err := tx.Create(&parent).Error; err != nil {
						return fmt.Errorf("failed to create parent governance_org for tenant %s: %w", orgs[i].ID, err)
					}
				default:
					return fmt.Errorf("failed to look up existing parent governance_org for tenant %s: %w", orgs[i].ID, lookupErr)
				}
				if err := tx.Model(&tables.TableOrganization{}).
					Where("id = ?", orgs[i].ID).
					Update("organization_id", parent.ID).Error; err != nil {
					return fmt.Errorf("failed to set organization_id on tenant %s: %w", orgs[i].ID, err)
				}
				// Org-owner membership for the tenant owner. Same
				// idempotency story: only insert if missing.
				var existingMembers int64
				if err := tx.Model(&tables.TableGovernanceOrgMembership{}).
					Where("organization_id = ? AND user_id = ? AND role = ?", parent.ID, orgs[i].OwnerID, tables.GovernanceOrgRoleOwner).
					Count(&existingMembers).Error; err != nil {
					return fmt.Errorf("failed to check existing org owner membership for tenant %s: %w", orgs[i].ID, err)
				}
				if existingMembers == 0 {
					ownerMem := tables.TableGovernanceOrgMembership{
						ID:             "gom-" + uuid.NewString(),
						OrganizationID: parent.ID,
						UserID:         orgs[i].OwnerID,
						Role:           tables.GovernanceOrgRoleOwner,
						CreatedAt:      now,
						UpdatedAt:      now,
					}
					if err := tx.Create(&ownerMem).Error; err != nil {
						return fmt.Errorf("failed to create org owner membership for tenant %s: %w", orgs[i].ID, err)
					}
				}
				// 4. Backfill every user pinned to this tenant.
				if err := tx.Model(&tables.TableAuthUser{}).
					Where("tenant_id = ? AND (organization_id IS NULL OR organization_id = ?)", orgs[i].ID, "").
					Update("organization_id", parent.ID).Error; err != nil {
					return fmt.Errorf("failed to backfill auth_users.organization_id for tenant %s: %w", orgs[i].ID, err)
				}
			}
			return nil
		},
		Rollback: func(_ *gorm.DB) error {
			// Non-destructive: rolling back would orphan the org_id
			// columns. We leave both tables in place; future migrations
			// can drop them explicitly if needed.
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running 3-tier orgs migration: %s", err.Error())
	}
	return nil
}

// migrationAddProviderKeyWorkspaceID adds nullable workspace_id columns
// to config_providers and config_keys so a tenant can host workspace-
// scoped provider integrations (e.g. Workspace A has its own OpenAI key
// separate from Workspace B). NULL preserves the historical "shared
// across all workspaces" semantics - no migration backfill needed
// because tenant-wide providers are still a valid configuration here.
func migrationAddProviderKeyWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_provider_key_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableProvider{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableProvider{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to config_providers: %w", err)
				}
			}
			if !mig.HasColumn(&tables.TableKey{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableKey{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to config_keys: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if err := mig.DropColumn(&tables.TableKey{}, "workspace_id"); err != nil {
				return err
			}
			return mig.DropColumn(&tables.TableProvider{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running provider/key workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationBackfillNullWorkspaceIDs eliminates NULL workspace_id rows
// across every workspace-aware config table by setting them to their
// tenant's Default workspace. Re-runnable: it's a no-op once every row
// has a workspace_id.
//
// Why: the original design used `workspace_id IS NULL` as "tenant-wide",
// which is non-standard for AI gateway products and creates ambiguity
// between "deliberately tenant-wide" and "legacy / pre-workspace". After
// this migration every resource lives in exactly one workspace.
func migrationBackfillNullWorkspaceIDs(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "backfill_null_workspace_ids",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)

			// Tables with a workspace_id column. Each table is keyed by its
			// tenant_id column so we can derive the Default workspace per
			// tenant.
			type backfillTarget struct {
				table   string
				tenantC string
			}
			targets := []backfillTarget{
				{"governance_virtual_keys", "tenant_id"},
				{"prompts", "tenant_id"},
				{"guardrail_policies", "tenant_id"},
				{"workspace_api_keys", "org_id"},
				{"config_mcp_clients", "tenant_id"},
				{"routing_rules", "tenant_id"},
				{"governance_model_configs", "tenant_id"},
				{"config_plugins", "tenant_id"},
				{"guardrail_rag_sources", "tenant_id"},
				// config_providers was missing from the original list. Once
				// the read filter became strict (no more "workspace_id IS NULL
				// OR workspace_id = ?"), pre-existing providers with NULL
				// workspace_id silently vanished from every workspace view.
				// Pinning them to the parent tenant's Default workspace
				// keeps them visible to the inheriting workspace's admins.
				{"config_providers", "tenant_id"},
			}
			for _, t := range targets {
				// Skip tables that don't exist yet on this DB (older
				// installs that haven't run earlier migrations).
				if !tx.Migrator().HasTable(t.table) {
					continue
				}
				if !tx.Migrator().HasColumn(t.table, "workspace_id") {
					continue
				}
				// Postgres / MySQL UPDATE-FROM syntax.
				stmt := fmt.Sprintf(`
					UPDATE %s AS t
					SET workspace_id = ws.id
					FROM workspaces AS ws
					WHERE t.workspace_id IS NULL
					  AND ws.org_id = t.%s
					  AND ws.is_default = ?
				`, t.table, t.tenantC)
				if err := tx.Exec(stmt, true).Error; err != nil {
					// SQLite portable form
					stmt = fmt.Sprintf(`
						UPDATE %s
						SET workspace_id = (
							SELECT ws.id FROM workspaces AS ws
							WHERE ws.org_id = %s.%s AND ws.is_default = 1 LIMIT 1
						)
						WHERE workspace_id IS NULL
					`, t.table, t.table, t.tenantC)
					if fbErr := tx.Exec(stmt).Error; fbErr != nil {
						return fmt.Errorf("failed to backfill %s.workspace_id: %v / %v", t.table, err, fbErr)
					}
				}
			}
			return nil
		},
		Rollback: func(_ *gorm.DB) error {
			// Backfill is non-destructive - reverting it would NULL out
			// rows that may have been further updated since. We skip.
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while backfilling null workspace ids: %s", err.Error())
	}
	return nil
}

// migrationBackfillNullWorkspaceIDsForProviders pins legacy NULL
// workspace_id rows in config_providers to their tenant's Default
// workspace. The original migrationBackfillNullWorkspaceIDs shipped
// without config_providers in its target list and is idempotent under
// its own ID, so existing DBs need this separate migration to catch up.
//
// Once the read filter on GetProviders went strict (workspace_id = ?
// only - see rdb.go), any provider row with NULL workspace_id became
// invisible to every workspace view in the dashboard. This migration
// makes those rows visible again under the tenant's Default workspace,
// where the inheriting tenant admin can decide whether to keep them
// scoped there or re-assign.
func migrationBackfillNullWorkspaceIDsForProviders(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "backfill_null_workspace_ids_providers",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("config_providers") {
				return nil
			}
			if !tx.Migrator().HasColumn("config_providers", "workspace_id") {
				return nil
			}
			// Postgres / MySQL UPDATE-FROM syntax.
			pgStmt := `
				UPDATE config_providers AS t
				SET workspace_id = ws.id
				FROM workspaces AS ws
				WHERE t.workspace_id IS NULL
				  AND ws.org_id = t.tenant_id
				  AND ws.is_default = ?
			`
			if err := tx.Exec(pgStmt, true).Error; err != nil {
				// SQLite portable form
				sqliteStmt := `
					UPDATE config_providers
					SET workspace_id = (
						SELECT ws.id FROM workspaces AS ws
						WHERE ws.org_id = config_providers.tenant_id AND ws.is_default = 1 LIMIT 1
					)
					WHERE workspace_id IS NULL
				`
				if fbErr := tx.Exec(sqliteStmt).Error; fbErr != nil {
					return fmt.Errorf("failed to backfill config_providers.workspace_id: %v / %v", err, fbErr)
				}
			}
			return nil
		},
		Rollback: func(_ *gorm.DB) error {
			// Non-destructive - leave the backfilled values in place.
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while backfilling null workspace ids for providers: %s", err.Error())
	}
	return nil
}

// migrationProviderUniqueIndexAddWorkspace swaps the unique index on
// config_providers from (tenant_id, name) to
// (tenant_id, workspace_id, name) so the same provider can be added
// in sibling workspaces of the same tenant.
//
// Symptom this fixes: "Failed to add OpenAI provider - 409 Conflict"
// when a tenant admin tried to configure the same provider for
// workspace B after already configuring it for workspace A. The strict
// per-workspace read filter (see GetProvidersConfig) treats them as
// independent rows; the old unique index didn't agree.
//
// AutoMigrate would otherwise see the new uniqueIndex tag on
// TableProvider and try to create idx_provider_tenant_workspace_name,
// but it won't drop the old idx_provider_tenant_name on its own -
// hence this explicit drop. Idempotent: second runs are no-ops because
// the migrator skips already-applied IDs and the DROP IF EXISTS is
// safe even when run directly.
func migrationProviderUniqueIndexAddWorkspace(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "provider_unique_index_add_workspace",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("config_providers") {
				return nil
			}
			// Drop the old (tenant_id, name) unique index. Postgres uses
			// DROP INDEX; SQLite uses the same syntax. Both treat
			// IF EXISTS uniformly.
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_provider_tenant_name`).Error; err != nil {
				return fmt.Errorf("failed to drop old provider unique index: %w", err)
			}
			// AutoMigrate (which runs after this migration) will create
			// idx_provider_tenant_workspace_name from the GORM tag.
			// Belt-and-braces: also create it here so the constraint is
			// in place even if a hypothetical future change skips
			// AutoMigrate for this table. CREATE UNIQUE INDEX IF NOT
			// EXISTS is safe to repeat.
			if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_tenant_workspace_name ON config_providers (tenant_id, workspace_id, name)`).Error; err != nil {
				return fmt.Errorf("failed to create new provider unique index: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// Reverse: drop the new index, recreate the old one.
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_provider_tenant_workspace_name`).Error; err != nil {
				return err
			}
			return tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_tenant_name ON config_providers (tenant_id, name)`).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error swapping provider unique index: %s", err.Error())
	}
	return nil
}

// migrationVirtualKeyUniqueIndexAddWorkspace swaps the unique index on
// governance_virtual_keys from (tenant_id, name) to
// (tenant_id, workspace_id, name) so the same virtual key name can be
// used in different workspaces of the same tenant.
//
// Symptom this fixes: "A record with this name already exists" when a
// tenant admin tried to create a virtual key with a name that already
// existed in a sibling workspace under the same tenant.
//
// Same shape as migrationProviderUniqueIndexAddWorkspace.
func migrationVirtualKeyUniqueIndexAddWorkspace(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "virtual_key_unique_index_add_workspace",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("governance_virtual_keys") {
				return nil
			}
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_virtual_key_tenant_name`).Error; err != nil {
				return fmt.Errorf("failed to drop old virtual key unique index: %w", err)
			}
			if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_virtual_key_tenant_workspace_name ON governance_virtual_keys (tenant_id, workspace_id, name)`).Error; err != nil {
				return fmt.Errorf("failed to create new virtual key unique index: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_virtual_key_tenant_workspace_name`).Error; err != nil {
				return err
			}
			return tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_virtual_key_tenant_name ON governance_virtual_keys (tenant_id, name)`).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error swapping virtual key unique index: %s", err.Error())
	}
	return nil
}

// migrationKeyUniqueIndexAddWorkspace swaps the two unique indexes on
// config_keys from (tenant_id, name) and (tenant_id, key_id) to their
// (tenant_id, workspace_id, ...) equivalents.
//
// Symptom this fixes: trying to add an `openai_key` (or any key name
// that already exists in another workspace under the same tenant)
// returns 500 with "Failed to update provider: a record with this name
// already exists" - even though the read filter already treats the
// two workspaces as independent.
//
// Same shape as migrationProviderUniqueIndexAddWorkspace; AutoMigrate
// won't drop the old indexes on its own, so we DROP IF EXISTS them
// and CREATE the new ones explicitly.
func migrationKeyUniqueIndexAddWorkspace(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "key_unique_index_add_workspace",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("config_keys") {
				return nil
			}
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_key_tenant_name`).Error; err != nil {
				return fmt.Errorf("failed to drop old idx_key_tenant_name: %w", err)
			}
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_key_tenant_key_id`).Error; err != nil {
				return fmt.Errorf("failed to drop old idx_key_tenant_key_id: %w", err)
			}
			if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_key_tenant_workspace_name ON config_keys (tenant_id, workspace_id, name)`).Error; err != nil {
				return fmt.Errorf("failed to create idx_key_tenant_workspace_name: %w", err)
			}
			if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_key_tenant_workspace_key_id ON config_keys (tenant_id, workspace_id, key_id)`).Error; err != nil {
				return fmt.Errorf("failed to create idx_key_tenant_workspace_key_id: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_key_tenant_workspace_name`).Error; err != nil {
				return err
			}
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_key_tenant_workspace_key_id`).Error; err != nil {
				return err
			}
			if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_key_tenant_name ON config_keys (tenant_id, name)`).Error; err != nil {
				return err
			}
			return tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_key_tenant_key_id ON config_keys (tenant_id, key_id)`).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error swapping key unique indexes: %s", err.Error())
	}
	return nil
}

// migrationBackfillKeyWorkspaceFromProvider copies the parent provider's
// workspace_id onto every config_keys row that doesn't already have one.
//
// Symptom this fixes: a key added in workspace B was attached to
// provider id=1 (which lives in workspace A) because GetProvider used
// to do `WHERE name = ?` without a workspace filter. The provider
// itself has been correctly workspace-stamped since creation, so the
// JOIN on provider_id is the right way to recover the intended scope
// for orphan keys without guessing.
//
// Idempotent: only updates rows where workspace_id IS NULL, so re-runs
// are no-ops once the population has settled.
func migrationBackfillKeyWorkspaceFromProvider(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "backfill_key_workspace_from_provider",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("config_keys") {
				return nil
			}
			if !tx.Migrator().HasColumn("config_keys", "workspace_id") {
				return nil
			}
			// Postgres / MySQL UPDATE-FROM syntax.
			pgStmt := `
				UPDATE config_keys AS k
				SET workspace_id = p.workspace_id
				FROM config_providers AS p
				WHERE k.workspace_id IS NULL
				  AND k.provider_id = p.id
				  AND p.workspace_id IS NOT NULL
			`
			if err := tx.Exec(pgStmt).Error; err != nil {
				// SQLite portable form
				sqliteStmt := `
					UPDATE config_keys
					SET workspace_id = (
						SELECT p.workspace_id FROM config_providers p
						WHERE p.id = config_keys.provider_id
						  AND p.workspace_id IS NOT NULL
						LIMIT 1
					)
					WHERE workspace_id IS NULL
				`
				if fbErr := tx.Exec(sqliteStmt).Error; fbErr != nil {
					return fmt.Errorf("failed to backfill config_keys.workspace_id from parent provider: %v / %v", err, fbErr)
				}
			}
			return nil
		},
		Rollback: func(_ *gorm.DB) error {
			// Non-destructive - leave the backfilled values in place.
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error backfilling key workspace_id from parent provider: %s", err.Error())
	}
	return nil
}

// migrationRoutingRuleUniqueIndexAddWorkspace mirrors
// migrationProviderUniqueIndexAddWorkspace for routing_rules: drops the
// old unique index that didn't include workspace_id and creates a new
// one that does. Without this, creating a routing rule with the same
// (scope, name) in workspace B fails with 409 even though the strict
// per-workspace read filter treats them as separate rows.
func migrationRoutingRuleUniqueIndexAddWorkspace(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "routing_rule_unique_index_add_workspace",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("routing_rules") {
				return nil
			}
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_routing_rule_tenant_scope_name`).Error; err != nil {
				return fmt.Errorf("failed to drop old routing_rule unique index: %w", err)
			}
			if err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_routing_rule_tenant_workspace_scope_name ON routing_rules (tenant_id, workspace_id, scope, scope_id, name)`).Error; err != nil {
				return fmt.Errorf("failed to create new routing_rule unique index: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.Exec(`DROP INDEX IF EXISTS idx_routing_rule_tenant_workspace_scope_name`).Error; err != nil {
				return err
			}
			return tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_routing_rule_tenant_scope_name ON routing_rules (tenant_id, scope, scope_id, name)`).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error swapping routing_rule unique index: %s", err.Error())
	}
	return nil
}

// migrationAddGuardrailProviderWorkspaceID adds a nullable workspace_id
// column to guardrail_providers so Safety Providers and DeepIntShield
// Models (AI Models) entries stay scoped to a single workspace within the
// tenant. Pre-existing rows keep workspace_id NULL - the store's read
// filter still surfaces them to every workspace under the tenant so the
// rollout is non-breaking; the create path stamps the active workspace on
// every new row going forward.
func migrationAddGuardrailProviderWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_provider_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableGuardrailProvider{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableGuardrailProvider{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to guardrail_providers: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableGuardrailProvider{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running guardrail provider workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationBackfillGuardrailProviderWrappers walks every existing guardrail
// provider that lacks a wrapper policy and creates one. This is the
// self-heal companion to the auto-wrapper logic in
// handlers/createProvider - that handler covers providers created AFTER
// the feature shipped; this migration covers providers from older
// installs so they also show up in the virtual-key "Guardrail Policies"
// dropdown without operators having to delete + recreate them.
//
// The wrapper is the same shape as the runtime one: a published, enabled,
// workspace-scoped policy with `metadata.auto_wrapper_for_provider_id`
// pointing back at the provider, plus a single
// guardrail_policy_provider_bindings row that fans inference to the
// provider. Idempotent - re-runs are no-ops because we skip providers
// whose wrapper already exists (matched by the metadata marker).
func migrationBackfillGuardrailProviderWrappers(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "backfill_guardrail_provider_wrappers_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)

			// Pull every provider - no tenant filter; the migration runs
			// once at boot before any tenant context exists. Each row's
			// tenant_id / workspace_id is stamped on the wrapper we
			// create so per-tenant isolation continues to hold.
			var providers []tables.TableGuardrailProvider
			if err := tx.Find(&providers).Error; err != nil {
				return fmt.Errorf("load providers for wrapper backfill: %w", err)
			}
			if len(providers) == 0 {
				return nil
			}

			// Look up providers that ALREADY have a wrapper so we skip
			// them. We match by metadata_json substring because that's
			// the marker the create-handler stamps. Cheaper than parsing
			// every policy's metadata_json at the application layer.
			var existing []tables.TableGuardrailPolicy
			if err := tx.Where("metadata_json LIKE ?", "%auto_wrapper_for_provider_id%").Find(&existing).Error; err != nil {
				return fmt.Errorf("load existing wrapper policies: %w", err)
			}
			covered := make(map[string]struct{}, len(existing))
			for i := range existing {
				if marker, ok := existing[i].Metadata["auto_wrapper_for_provider_id"].(string); ok {
					covered[marker] = struct{}{}
				}
			}

			now := time.Now().UTC()
			for i := range providers {
				prov := providers[i]
				if _, ok := covered[prov.ID]; ok {
					continue
				}
				policy := &tables.TableGuardrailPolicy{
					ID:              uuid.NewString(),
					TenantID:        prov.TenantID,
					WorkspaceID:     prov.WorkspaceID,
					Name:            prov.Name,
					Description:     "Auto-created wrapper for " + prov.Name,
					Scope:           "input",
					EnforcementMode: "block",
					ExecutionMode:   tables.GuardrailExecutionModeSync,
					// 10s timeout - see ensureProviderWrapperPolicy for
					// the rationale (150ms column default starves ML
					// provider adapters; this gives them room without
					// loosening regex-class SLAs elsewhere).
					TimeoutMs: 10000,
					Enabled:   true,
					IsDefault: false,
					Metadata:  map[string]any{"auto_wrapper_for_provider_id": prov.ID},
					CreatedAt: now,
					UpdatedAt: now,
				}
				if err := tx.Create(policy).Error; err != nil {
					return fmt.Errorf("create wrapper policy for provider %s: %w", prov.ID, err)
				}
				publishedAt := now
				version := &tables.TableGuardrailPolicyVersion{
					ID:          uuid.NewString(),
					TenantID:    prov.TenantID,
					PolicyID:    policy.ID,
					Version:     1,
					Status:      tables.GuardrailPolicyVersionStatusPublished,
					Definition:  map[string]any{},
					PublishedBy: "wrapper_backfill",
					PublishedAt: &publishedAt,
					CreatedAt:   now,
				}
				if err := tx.Create(version).Error; err != nil {
					return fmt.Errorf("create wrapper policy version for provider %s: %w", prov.ID, err)
				}
				binding := tables.TableGuardrailPolicyProviderBinding{
					ID:         uuid.NewString(),
					TenantID:   prov.TenantID,
					PolicyID:   policy.ID,
					ProviderID: prov.ID,
					Stage:      "input",
					Priority:   100,
					Enabled:    true,
					CreatedAt:  now,
					UpdatedAt:  now,
				}
				if err := tx.Create(&binding).Error; err != nil {
					return fmt.Errorf("create wrapper binding for provider %s: %w", prov.ID, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// Drop only the wrappers we created; operator-authored
			// policies stay untouched because they don't carry the
			// metadata marker.
			return tx.Where("metadata_json LIKE ?", "%auto_wrapper_for_provider_id%").Delete(&tables.TableGuardrailPolicy{}).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running guardrail provider wrapper backfill: %s", err.Error())
	}
	return nil
}

// migrationDropLegacyNullWorkspaceProviders removes pre-workspace-scoping
// guardrail provider rows whose workspace_id is still NULL after the
// scoping fix lands. Those rows are by definition pre-workspace-scoping -
// they were created before the column existed and don't have a sane
// workspace to belong to. Leaving them around was the regression the user
// reported: a provider created without a workspace was visible to every
// workspace in every tenant, which is exactly the leak we're closing.
//
// Cleanup also drops the auto-wrapper policies that
// migrationBackfillGuardrailProviderWrappers minted for these providers
// (matched via metadata_json marker → provider_id), plus the policy
// versions and provider bindings hanging off those wrappers, so the VK
// dropdown stays clean.
//
// Idempotent. Safe to re-run: the second pass finds no NULL providers and
// completes immediately.
func migrationDropLegacyNullWorkspaceProviders(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "drop_legacy_null_workspace_guardrail_providers_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// Pull the IDs first so we can drop their auto-wrapper
			// policies in the same transaction. Without that, the
			// wrappers stick around and the dropdown still surfaces
			// "DeepIntShield Models" as a phantom selectable entry that
			// no longer maps to a provider.
			var legacy []tables.TableGuardrailProvider
			if err := tx.Where("workspace_id IS NULL").Find(&legacy).Error; err != nil {
				return fmt.Errorf("load legacy NULL-workspace providers: %w", err)
			}
			if len(legacy) == 0 {
				return nil
			}
			for i := range legacy {
				providerID := legacy[i].ID
				// Find every auto-wrapper policy pointed at this
				// provider and drop them, their versions, and their
				// bindings. We match by metadata marker so
				// operator-authored policies that happen to be bound
				// to this provider stay untouched.
				var wrappers []tables.TableGuardrailPolicy
				if err := tx.Where("metadata_json LIKE ?", "%"+providerID+"%").Find(&wrappers).Error; err != nil {
					return fmt.Errorf("load wrapper policies for provider %s: %w", providerID, err)
				}
				for j := range wrappers {
					if marker, ok := wrappers[j].Metadata["auto_wrapper_for_provider_id"].(string); !ok || marker != providerID {
						continue
					}
					policyID := wrappers[j].ID
					if err := tx.Where("policy_id = ?", policyID).Delete(&tables.TableGuardrailPolicyProviderBinding{}).Error; err != nil {
						return fmt.Errorf("drop wrapper bindings for policy %s: %w", policyID, err)
					}
					if err := tx.Where("policy_id = ?", policyID).Delete(&tables.TableGuardrailPolicyVersion{}).Error; err != nil {
						return fmt.Errorf("drop wrapper versions for policy %s: %w", policyID, err)
					}
					if err := tx.Delete(&tables.TableGuardrailPolicy{}, "id = ?", policyID).Error; err != nil {
						return fmt.Errorf("drop wrapper policy %s: %w", policyID, err)
					}
				}
				if err := tx.Delete(&tables.TableGuardrailProvider{}, "id = ?", providerID).Error; err != nil {
					return fmt.Errorf("drop legacy provider %s: %w", providerID, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			// Destructive; no rollback path. Operators recreate
			// providers from the UI if they want them back, which now
			// stamps a workspace_id on every new row.
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while dropping legacy NULL-workspace guardrail providers: %s", err.Error())
	}
	return nil
}

// migrationDropOrphanGuardrailWrappers cleans up auto-wrapper policies
// whose target provider has already been deleted. Sibling migration
// migrationDropLegacyNullWorkspaceProviders walks providers and tries to
// delete their wrappers in the same pass, but it relies on GORM's
// AfterFind hook populating the Metadata map at scan time - which doesn't
// fire reliably inside gormigrate transactions for plugin-style hooks.
// This migration sidesteps that by doing the cleanup at the SQL layer:
// any policy whose metadata_json carries the auto-wrapper marker AND
// whose provider_id is no longer present in guardrail_providers is
// dropped along with its versions and bindings.
//
// Idempotent - second run finds no orphans.
func migrationDropOrphanGuardrailWrappers(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "drop_orphan_guardrail_provider_wrappers_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// Postgres-specific cleanup (jsonb + trim(both ...)); skip on other
			// dialects (SQLite in tests) where there are no such orphans. Matches
			// the Dialector.Name() guards used elsewhere in this file.
			if tx.Dialector.Name() != "postgres" {
				return nil
			}
			// SQL: select wrapper policies whose embedded provider_id
			// in metadata_json doesn't match any row in
			// guardrail_providers. We use a subselect of valid IDs and a
			// NOT IN clause so the matching is database-side.
			var orphanIDs []string
			rows := []struct {
				ID         string
				ProviderID string
			}{}
			if err := tx.Raw(`
				SELECT id,
				       trim(both '"' from metadata_json::jsonb->>'auto_wrapper_for_provider_id') AS provider_id
				FROM guardrail_policies
				WHERE metadata_json LIKE '%auto_wrapper_for_provider_id%'
			`).Scan(&rows).Error; err != nil {
				return fmt.Errorf("scan wrapper policies: %w", err)
			}
			if len(rows) == 0 {
				return nil
			}
			for i := range rows {
				if strings.TrimSpace(rows[i].ProviderID) == "" {
					orphanIDs = append(orphanIDs, rows[i].ID)
					continue
				}
				var count int64
				if err := tx.Raw(`SELECT count(*) FROM guardrail_providers WHERE id = ?`, rows[i].ProviderID).Scan(&count).Error; err != nil {
					return fmt.Errorf("check provider %s exists: %w", rows[i].ProviderID, err)
				}
				if count == 0 {
					orphanIDs = append(orphanIDs, rows[i].ID)
				}
			}
			if len(orphanIDs) == 0 {
				return nil
			}
			if err := tx.Where("policy_id IN ?", orphanIDs).Delete(&tables.TableGuardrailPolicyProviderBinding{}).Error; err != nil {
				return fmt.Errorf("delete orphan wrapper bindings: %w", err)
			}
			if err := tx.Where("policy_id IN ?", orphanIDs).Delete(&tables.TableGuardrailPolicyVersion{}).Error; err != nil {
				return fmt.Errorf("delete orphan wrapper versions: %w", err)
			}
			if err := tx.Where("id IN ?", orphanIDs).Delete(&tables.TableGuardrailPolicy{}).Error; err != nil {
				return fmt.Errorf("delete orphan wrapper policies: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error { return nil },
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while dropping orphan guardrail wrappers: %s", err.Error())
	}
	return nil
}

// migrationFlipWrapperPoliciesAsync sets execution_mode = 'async' on every
// auto-wrapper guardrail policy. Async wrappers fire the bound provider
// adapter in a background goroutine and let the response go out at model
// speed; findings still land in guardrail_findings so the AI Models tab
// stays populated. The earlier auto-wrapper code stamped 'sync', which on
// a CPU-bound ML detector batch (300-2000ms per call) showed up as
// "Guardrail (Input): 99.8%" of total wall time in the AI Logs detail
// panel. This restores the zero-hot-path-latency posture for the AI
// Models path while leaving operator-authored sync policies untouched
// (we only target rows whose metadata carries the auto_wrapper marker).
// Idempotent - re-runs find nothing to update.
func migrationFlipWrapperPoliciesAsync(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "flip_wrapper_policies_async_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Exec(`
				UPDATE guardrail_policies
				SET execution_mode = 'async', updated_at = CURRENT_TIMESTAMP
				WHERE metadata_json LIKE '%auto_wrapper_for_provider_id%'
				  AND execution_mode = 'sync'
			`).Error
		},
		Rollback: func(tx *gorm.DB) error { return nil },
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while flipping wrapper policies to async: %s", err.Error())
	}
	return nil
}

// migrationFlipWrapperPoliciesSyncCached reverses migrationFlipWrapperPoliciesAsync:
// sets execution_mode = 'sync' on every auto-wrapper policy so the detector
// verdict actually gates the response. The earlier async flip eliminated the
// 1827ms PostLLMHook wait but also stopped blocking - a deberta "prompt
// injection detected" finding would be persisted async and the model response
// still flowed back. The "zero latency AND blocking" target is met by sync
// mode + the in-process decision/fuzzy caches (decision_cache.go: 60s TTL,
// SHA256 keyed on tenant+stage+policies+content): repeat or template prompts
// hit cache in sub-ms; cache misses run the detector in parallel with the
// model and PostLLMHook waits max(detector, model) - with warm sidecar
// detectors (p50 ~440ms) the wait is bounded by model time. Idempotent -
// only targets rows whose metadata carries the auto_wrapper marker AND are
// currently 'async'; operator-authored async policies (someone deliberately
// downgrading for telemetry-only) are untouched.
func migrationFlipWrapperPoliciesSyncCached(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "flip_wrapper_policies_sync_cached_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Exec(`
				UPDATE guardrail_policies
				SET execution_mode = 'sync', updated_at = CURRENT_TIMESTAMP
				WHERE metadata_json LIKE '%auto_wrapper_for_provider_id%'
				  AND execution_mode = 'async'
			`).Error
		},
		Rollback: func(tx *gorm.DB) error { return nil },
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while flipping wrapper policies to sync (cached): %s", err.Error())
	}
	return nil
}

// migrationClearWrapperPolicyDefault removes the is_default flag from every
// auto-wrapper guardrail policy so operators can attach the wrapper to a
// virtual key explicitly instead of having it fan out to every VK in the
// tenant. is_default = true used to be set on wrapper policies so a fresh
// deepintshield_models provider would gate traffic immediately without any
// VK-side wiring - convenient at onboarding, but it meant every VK paid the
// wrapper's sidecar RTT even when the operator only meant to attach a regex
// card policy. With the runtime's fast-path short-circuit on regex deny,
// the latency cost was already mitigated for blocked requests; clearing
// is_default lets VKs that intentionally skip the wrapper run at pure regex
// (sub-ms) speed end-to-end. Idempotent: only targets rows whose metadata
// carries the auto_wrapper marker AND are currently default=true; operator
// edits via the UI's "mark as default" toggle aren't undone by this.
func migrationClearWrapperPolicyDefault(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "clear_wrapper_policy_default_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Exec(`
				UPDATE guardrail_policies
				SET is_default = false, updated_at = CURRENT_TIMESTAMP
				WHERE metadata_json LIKE '%auto_wrapper_for_provider_id%'
				  AND is_default = true
			`).Error
		},
		Rollback: func(tx *gorm.DB) error { return nil },
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while clearing wrapper policy default: %s", err.Error())
	}
	return nil
}

// migrationBumpWrapperPolicyTimeouts raises timeout_ms on every auto-wrapper
// guardrail policy to 10000 ms. The TableGuardrailPolicy column defaults to
// 150 ms - fine for regex / PII fast-path checks but catastrophic for
// provider adapters that fan out to ML detectors (e.g. deepintshield_models
// cold-start at 600-2000ms per detector). The earlier auto-wrapper code
// path didn't set TimeoutMs explicitly so existing rows inherited the
// 150 ms default, surfacing as "context deadline exceeded" entries on
// every guard trace and silently dropping the finding. Idempotent - runs
// once per install thanks to the gormigrate ID, and only updates rows
// whose current value is still <= 150 ms so manual operator overrides
// (someone tuning for a stricter SLA) aren't clobbered.
func migrationBumpWrapperPolicyTimeouts(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "bump_wrapper_policy_timeouts_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Exec(`
				UPDATE guardrail_policies
				SET timeout_ms = 10000, updated_at = CURRENT_TIMESTAMP
				WHERE metadata_json LIKE '%auto_wrapper_for_provider_id%'
				  AND timeout_ms <= 150
			`).Error
		},
		Rollback: func(tx *gorm.DB) error { return nil },
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while bumping wrapper policy timeouts: %s", err.Error())
	}
	return nil
}

// migrationAddRAGSourceWorkspaceID adds a nullable workspace_id column to
// guardrail_rag_sources so RAG security source registrations can be scoped
// per workspace while still supporting tenant-wide entries.
func migrationAddRAGSourceWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_rag_source_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableGuardrailRAGSource{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableGuardrailRAGSource{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to guardrail_rag_sources: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableGuardrailRAGSource{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running rag source workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddUserInvitationWorkspaceID adds a nullable workspace_id
// column to user_invitations so an invitation can target a specific
// workspace (not just a tenant). On accept, the invitee receives a
// workspace_membership row keyed by this workspace_id when set; legacy
// rows with NULL fall back to the tenant's Default workspace.
func migrationAddUserInvitationWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_user_invitation_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableUserInvitation{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableUserInvitation{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to user_invitations: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableUserInvitation{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running user_invitation workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddPluginWorkspaceID adds a nullable workspace_id column to
// config_plugins so plugin policies can be scoped per workspace while still
// supporting tenant-wide plugins.
func migrationAddPluginWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_plugin_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TablePlugin{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TablePlugin{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to config_plugins: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TablePlugin{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running plugin workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddModelConfigWorkspaceID adds a nullable workspace_id column to
// governance_model_configs so per-model rate limits / budgets can be scoped
// per workspace while still supporting tenant-wide configs.
func migrationAddModelConfigWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_model_config_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableModelConfig{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableModelConfig{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to governance_model_configs: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableModelConfig{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running model config workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddRoutingRuleWorkspaceID adds a nullable workspace_id column to
// routing_rules so load-balancer / routing rules can be scoped per workspace
// while still supporting tenant-wide rules (workspace_id IS NULL).
func migrationAddRoutingRuleWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_routing_rule_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableRoutingRule{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableRoutingRule{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to routing_rules: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableRoutingRule{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running routing rule workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddMCPClientWorkspaceID adds a nullable workspace_id column to
// config_mcp_clients so MCP servers can optionally be scoped to a single
// workspace within their tenant. NULL preserves the existing "visible to
// every workspace in the tenant" behaviour for any rows pre-dating this
// migration; new rows created via the workspace-aware UI will be stamped
// with the active workspace at write time.
func migrationAddMCPClientWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_mcp_client_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableMCPClient{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableMCPClient{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to config_mcp_clients: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableMCPClient{}, "workspace_id")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running mcp client workspace_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddOrganizationDescription adds a free-form description column to
// the organizations table so admins can document what each tenant is for
// (e.g. "GCP production traffic" / "Azure dev sandbox") alongside its name.
func migrationAddOrganizationDescription(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_organization_description",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableOrganization{}, "description") {
				if err := mig.AddColumn(&tables.TableOrganization{}, "description"); err != nil {
					return fmt.Errorf("failed to add description column to organizations: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropColumn(&tables.TableOrganization{}, "description")
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running organization description migration: %s", err.Error())
	}
	return nil
}

// migrationAddPromptWorkspaceID adds the nullable workspace_id column to
// prompts. NULL preserves legacy "visible to every workspace in the
// tenant" behaviour for any rows that pre-date this migration; new rows
// created via the workspace-aware API will be stamped with the active
// workspace at write time.
func migrationAddPromptWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_prompt_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TablePrompt{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TablePrompt{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to prompts: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TablePrompt{}, "workspace_id") {
				if err := mig.DropColumn(&tables.TablePrompt{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to drop workspace_id from prompts: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding workspace_id to prompts: %s", err.Error())
	}
	return nil
}

// migrationCreateWorkspaceAPIKeysTable creates the workspace_api_keys table
// - credentials scoped to a single workspace, distinct from virtual keys
// (which carry tenant-wide admin powers in the legacy model). The table is
// created cold; no backfill, since existing deployments have no workspace
// keys yet.
func migrationCreateWorkspaceAPIKeysTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_workspace_api_keys_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TableWorkspaceAPIKey{}) {
				return nil
			}
			if err := mig.CreateTable(&tables.TableWorkspaceAPIKey{}); err != nil {
				return fmt.Errorf("failed to create workspace_api_keys: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TableWorkspaceAPIKey{}) {
				if err := mig.DropTable(&tables.TableWorkspaceAPIKey{}); err != nil {
					return fmt.Errorf("failed to drop workspace_api_keys: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while creating workspace_api_keys: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyWorkspaceID adds the nullable workspace_id column to
// governance_virtual_keys. NULL preserves legacy "any workspace in this
// tenant" callability; the inference middleware that lands later will treat
// non-NULL as a hard scope and 403 cross-workspace calls.
func migrationAddVirtualKeyWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableVirtualKey{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableVirtualKey{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to governance_virtual_keys: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TableVirtualKey{}, "workspace_id") {
				if err := mig.DropColumn(&tables.TableVirtualKey{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to drop workspace_id from governance_virtual_keys: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding workspace_id to governance_virtual_keys: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyRotationFields adds the rotation-tracking columns
// to governance_virtual_keys: schedule (period + grace), bookkeeping
// (last/next rotation timestamps), and the parked previous value that
// stays accepted during the grace window. All nullable - existing rows
// stay on "never rotate" until an admin opts in.
func migrationAddVirtualKeyRotationFields(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_rotation_fields",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			cols := []string{
				"rotation_period_days",
				"rotation_grace_period_days",
				"last_rotated_at",
				"next_rotation_at",
				"previous_value",
				"previous_value_hash",
				"previous_value_expires_at",
			}
			for _, col := range cols {
				if !mig.HasColumn(&tables.TableVirtualKey{}, col) {
					if err := mig.AddColumn(&tables.TableVirtualKey{}, col); err != nil {
						return fmt.Errorf("failed to add %s to governance_virtual_keys: %w", col, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding rotation fields to governance_virtual_keys: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyRotationNoticeFields tacks on the pre-rotation
// notification bookkeeping columns: rotation_notice_days (how far ahead to
// warn the owner) and rotation_notified_at (timestamp of the warning that
// was sent for the current cycle, NULL once the rotation completes). Both
// nullable / defaulted so existing rows keep working with the SOC 2
// default (7-day warning).
func migrationAddVirtualKeyRotationNoticeFields(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_rotation_notice_fields",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			cols := []string{
				"rotation_notice_days",
				"rotation_notified_at",
			}
			for _, col := range cols {
				if !mig.HasColumn(&tables.TableVirtualKey{}, col) {
					if err := mig.AddColumn(&tables.TableVirtualKey{}, col); err != nil {
						return fmt.Errorf("failed to add %s to governance_virtual_keys: %w", col, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding rotation-notice fields to governance_virtual_keys: %s", err.Error())
	}
	return nil
}

// migrationAddLoadBalancerEnabledColumn adds the load_balancer_enabled flag
// to config_client. Defaults existing rows to true so the strategy-aware key
// selector + health tracker are wired up out-of-the-box; admins can flip it
// off via Client Settings to fall back to the stateless weighted-random path.
func migrationAddLoadBalancerEnabledColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_load_balancer_enabled_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableClientConfig{}, "load_balancer_enabled") {
				if err := mig.AddColumn(&tables.TableClientConfig{}, "load_balancer_enabled"); err != nil {
					return fmt.Errorf("failed to add load_balancer_enabled to config_client: %w", err)
				}
				if err := tx.Exec("UPDATE config_client SET load_balancer_enabled = ? WHERE load_balancer_enabled IS NULL OR load_balancer_enabled = ?", true, false).Error; err != nil {
					return fmt.Errorf("failed to backfill load_balancer_enabled: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TableClientConfig{}, "load_balancer_enabled") {
				if err := mig.DropColumn(&tables.TableClientConfig{}, "load_balancer_enabled"); err != nil {
					return fmt.Errorf("failed to drop load_balancer_enabled from config_client: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding load_balancer_enabled to config_client: %s", err.Error())
	}
	return nil
}

// migrationAddGuardrailPolicyOrgID adds the nullable org_id column to
// guardrail_policies and backfills it from the workspaces table for any row
// that's already workspace-scoped. Without this column, a "tenant-wide"
// policy (workspace_id IS NULL) created in UI tenant DEV would surface in
// STAGE / PROD because the existing tenant_id column is just the email,
// shared across every UI tenant the same user owns.
//
// Backfill scope:
//   - WorkspaceID NOT NULL → JOIN workspaces and copy workspaces.org_id.
//   - WorkspaceID IS NULL  → leave OrgID NULL. We have no reliable way to
//     attribute these to a specific UI tenant; the store treats NULL OrgID
//     rows as hidden under active-org scoping. Operators can either re-create
//     the policy in the desired org or set org_id manually via SQL.
func migrationAddGuardrailPolicyOrgID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_policy_org_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableGuardrailPolicy{}, "org_id") {
				if err := mig.AddColumn(&tables.TableGuardrailPolicy{}, "org_id"); err != nil {
					return fmt.Errorf("failed to add org_id to guardrail_policies: %w", err)
				}
			}
			// Backfill workspace-scoped rows from the workspaces table.
			// Tenant-wide rows (workspace_id IS NULL) remain NULL on purpose.
			if err := tx.Exec(`
				UPDATE guardrail_policies
				SET org_id = (
					SELECT workspaces.org_id
					FROM workspaces
					WHERE workspaces.id = guardrail_policies.workspace_id
				)
				WHERE workspace_id IS NOT NULL AND org_id IS NULL
			`).Error; err != nil {
				return fmt.Errorf("failed to backfill org_id from workspaces: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TableGuardrailPolicy{}, "org_id") {
				if err := mig.DropColumn(&tables.TableGuardrailPolicy{}, "org_id"); err != nil {
					return fmt.Errorf("failed to drop org_id from guardrail_policies: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding org_id to guardrail_policies: %s", err.Error())
	}
	return nil
}

// migrationAddGuardrailPolicyWorkspaceID adds the nullable workspace_id
// column to guardrail_policies. NULL keeps the legacy "applies to every
// workspace in this tenant" behaviour; runtime resolution treats workspace-
// scoped rows as additive overlays once the inference path starts passing
// workspace context.
func migrationAddGuardrailPolicyWorkspaceID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_policy_workspace_id",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasColumn(&tables.TableGuardrailPolicy{}, "workspace_id") {
				if err := mig.AddColumn(&tables.TableGuardrailPolicy{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to add workspace_id to guardrail_policies: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TableGuardrailPolicy{}, "workspace_id") {
				if err := mig.DropColumn(&tables.TableGuardrailPolicy{}, "workspace_id"); err != nil {
					return fmt.Errorf("failed to drop workspace_id from guardrail_policies: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding workspace_id to guardrail_policies: %s", err.Error())
	}
	return nil
}

// migrationAddWorkspacesAndMemberships creates the workspaces, org_memberships,
// and workspace_memberships tables and backfills:
//
//   - one Default workspace per existing organization,
//   - an org_memberships row for every existing user (owner if their user.id
//     matches the org's owner_id, else admin),
//   - a workspace_memberships row in the Default workspace for every existing
//     org_membership (admin role for org owners/admins, member otherwise).
//
// Idempotent: re-running the migration body is safe - every backfill insert
// is guarded by an existence check.
func migrationAddWorkspacesAndMemberships(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_workspaces_and_memberships",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)

			if err := tx.AutoMigrate(
				&tables.TableWorkspace{},
				&tables.TableOrgMembership{},
				&tables.TableWorkspaceMembership{},
			); err != nil {
				return fmt.Errorf("failed to create workspaces/memberships tables: %w", err)
			}

			var orgs []struct {
				ID      string
				OwnerID string
			}
			if err := tx.Raw("SELECT id, owner_id FROM organizations").Scan(&orgs).Error; err != nil {
				return fmt.Errorf("failed to query organizations: %w", err)
			}

			for _, org := range orgs {
				// Default workspace - one per org.
				var existingDefault int64
				if err := tx.Raw(
					"SELECT COUNT(*) FROM workspaces WHERE org_id = ? AND is_default = ?",
					org.ID, true,
				).Scan(&existingDefault).Error; err != nil {
					return fmt.Errorf("failed to check default workspace for org %s: %w", org.ID, err)
				}
				if existingDefault == 0 {
					wsID := "ws-" + uuid.New().String()
					if err := tx.Exec(
						"INSERT INTO workspaces (id, org_id, name, slug, description, is_default, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
						wsID, org.ID, "Default", "default", "", true, org.OwnerID,
					).Error; err != nil {
						return fmt.Errorf("failed to create default workspace for org %s: %w", org.ID, err)
					}
				}
			}

			// Backfill org_memberships from existing users.
			var users []struct {
				ID       string
				TenantID string
			}
			if err := tx.Raw(
				"SELECT id, tenant_id FROM auth_users WHERE tenant_id IS NOT NULL AND tenant_id <> ''",
			).Scan(&users).Error; err != nil {
				return fmt.Errorf("failed to query auth_users: %w", err)
			}

			ownerByOrg := make(map[string]string, len(orgs))
			for _, org := range orgs {
				ownerByOrg[org.ID] = org.OwnerID
			}

			for _, u := range users {
				if _, hasOrg := ownerByOrg[u.TenantID]; !hasOrg {
					continue // user pointing at a non-existent org - skip rather than fail
				}
				var existing int64
				if err := tx.Raw(
					"SELECT COUNT(*) FROM org_memberships WHERE org_id = ? AND user_id = ?",
					u.TenantID, u.ID,
				).Scan(&existing).Error; err != nil {
					return fmt.Errorf("failed to check org membership for user %s: %w", u.ID, err)
				}
				if existing > 0 {
					continue
				}
				role := tables.OrgRoleAdmin
				if ownerByOrg[u.TenantID] == u.ID {
					role = tables.OrgRoleOwner
				}
				if err := tx.Exec(
					"INSERT INTO org_memberships (id, org_id, user_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
					"om-"+uuid.New().String(), u.TenantID, u.ID, role,
				).Error; err != nil {
					return fmt.Errorf("failed to insert org membership for user %s: %w", u.ID, err)
				}
			}

			// Backfill workspace_memberships into each org's default workspace.
			var defaults []struct {
				ID    string
				OrgID string
			}
			if err := tx.Raw(
				"SELECT id, org_id FROM workspaces WHERE is_default = ?", true,
			).Scan(&defaults).Error; err != nil {
				return fmt.Errorf("failed to query default workspaces: %w", err)
			}

			for _, ws := range defaults {
				var members []struct {
					UserID string
					Role   string
				}
				if err := tx.Raw(
					"SELECT user_id, role FROM org_memberships WHERE org_id = ?",
					ws.OrgID,
				).Scan(&members).Error; err != nil {
					return fmt.Errorf("failed to query org members for workspace %s: %w", ws.ID, err)
				}
				for _, mem := range members {
					var existing int64
					if err := tx.Raw(
						"SELECT COUNT(*) FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?",
						ws.ID, mem.UserID,
					).Scan(&existing).Error; err != nil {
						return fmt.Errorf("failed to check workspace membership: %w", err)
					}
					if existing > 0 {
						continue
					}
					wsRole := tables.WorkspaceRoleMember
					if mem.Role == tables.OrgRoleOwner || mem.Role == tables.OrgRoleAdmin {
						wsRole = tables.WorkspaceRoleAdmin
					}
					if err := tx.Exec(
						"INSERT INTO workspace_memberships (id, workspace_id, org_id, user_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
						"wm-"+uuid.New().String(), ws.ID, ws.OrgID, mem.UserID, wsRole,
					).Error; err != nil {
						return fmt.Errorf("failed to insert workspace membership for user %s: %w", mem.UserID, err)
					}
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			for _, t := range []string{"workspace_memberships", "org_memberships", "workspaces"} {
				if mig.HasTable(t) {
					if err := mig.DropTable(t); err != nil {
						return fmt.Errorf("failed to drop %s: %w", t, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while creating workspaces/memberships tables: %s", err.Error())
	}
	return nil
}

// migrationCreateLegalConsentsTable creates the append-only audit table that
// records every Terms-of-Service / Privacy-Policy acceptance.
//
// Uses CreateTable so we get the column definitions, indexes and types
// declared in tables.TableLegalConsent in a single shot. Drops the table on
// rollback - there is no data to preserve in a downgrade scenario.
func migrationCreateLegalConsentsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_legal_consents_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migratorInstance := tx.Migrator()
			if migratorInstance.HasTable(&tables.TableLegalConsent{}) {
				return nil
			}
			if err := migratorInstance.CreateTable(&tables.TableLegalConsent{}); err != nil {
				return fmt.Errorf("failed to create legal_consents table: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migratorInstance := tx.Migrator()
			if err := migratorInstance.DropTable(&tables.TableLegalConsent{}); err != nil {
				return fmt.Errorf("failed to drop legal_consents table: %w", err)
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while creating legal_consents table: %s", err.Error())
	}
	return nil
}

// migrationAddMCPCacheColumns adds the mcp_cache_enabled and mcp_cache_ttl_seconds
// columns to the config_client table. These power the global "Tool Result Cache"
// toggle in MCP Settings (mcpcache plugin). Defaults:
//   - mcp_cache_enabled: true (cache on by default for new + existing rows)
//   - mcp_cache_ttl_seconds: 300 (5 minutes)
func migrationAddMCPCacheColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_mcp_cache_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migratorInstance := tx.Migrator()
			if !migratorInstance.HasColumn(&tables.TableClientConfig{}, "mcp_cache_enabled") {
				if err := migratorInstance.AddColumn(&tables.TableClientConfig{}, "mcp_cache_enabled"); err != nil {
					return fmt.Errorf("failed to add mcp_cache_enabled column: %w", err)
				}
				// AddColumn applies the gorm `default:true` tag for new rows.
				// Backfill existing rows so the toggle reads "on" by default.
				if err := tx.Exec("UPDATE config_client SET mcp_cache_enabled = ? WHERE mcp_cache_enabled IS NULL", true).Error; err != nil {
					return fmt.Errorf("failed to backfill mcp_cache_enabled: %w", err)
				}
			}
			if !migratorInstance.HasColumn(&tables.TableClientConfig{}, "mcp_cache_ttl_seconds") {
				if err := migratorInstance.AddColumn(&tables.TableClientConfig{}, "mcp_cache_ttl_seconds"); err != nil {
					return fmt.Errorf("failed to add mcp_cache_ttl_seconds column: %w", err)
				}
				if err := tx.Exec("UPDATE config_client SET mcp_cache_ttl_seconds = ? WHERE mcp_cache_ttl_seconds IS NULL OR mcp_cache_ttl_seconds = 0", 300).Error; err != nil {
					return fmt.Errorf("failed to backfill mcp_cache_ttl_seconds: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migratorInstance := tx.Migrator()
			if err := migratorInstance.DropColumn(&tables.TableClientConfig{}, "mcp_cache_enabled"); err != nil {
				return fmt.Errorf("failed to drop mcp_cache_enabled column: %w", err)
			}
			if err := migratorInstance.DropColumn(&tables.TableClientConfig{}, "mcp_cache_ttl_seconds"); err != nil {
				return fmt.Errorf("failed to drop mcp_cache_ttl_seconds column: %w", err)
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running mcp cache columns migration: %s", err.Error())
	}
	return nil
}

func migrationAddStoreRawRequestResponseColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_store_raw_request_response_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableProvider{}, "store_raw_request_response") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "store_raw_request_response"); err != nil {
					return err
				}
			}
			// Backfill config_hash for existing providers so they don't appear
			// dirty after upgrade. StoreRawRequestResponse is now part of the
			// hash input; rows written before this migration have stale hashes.
			var providers []tables.TableProvider
			if err := tx.
				Select(
					"id",
					"name",
					"network_config_json",
					"concurrency_buffer_json",
					"proxy_config_json",
					"custom_provider_config_json",
					"pricing_overrides_json",
					"send_back_raw_request",
					"send_back_raw_response",
					"store_raw_request_response",
					"encryption_status",
				).
				Find(&providers).Error; err != nil {
				return fmt.Errorf("failed to fetch providers for hash backfill: %w", err)
			}
			for _, provider := range providers {
				providerConfig := ProviderConfig{
					NetworkConfig:            provider.NetworkConfig,
					ConcurrencyAndBufferSize: provider.ConcurrencyAndBufferSize,
					ProxyConfig:              provider.ProxyConfig,
					SendBackRawRequest:       provider.SendBackRawRequest,
					SendBackRawResponse:      provider.SendBackRawResponse,
					StoreRawRequestResponse:  provider.StoreRawRequestResponse,
					CustomProviderConfig:     provider.CustomProviderConfig,
					PricingOverrides:         provider.PricingOverrides,
				}
				// Here the default value of store_raw_request_response should be based on the default value of SendBackRawRequest and SendBackRawResponse
				if provider.SendBackRawRequest || provider.SendBackRawResponse {
					providerConfig.StoreRawRequestResponse = true
				}
				hash, err := providerConfig.GenerateConfigHash(provider.Name)
				if err != nil {
					return fmt.Errorf("failed to generate hash for provider %s: %w", provider.Name, err)
				}
				if err := tx.Model(&provider).Updates(map[string]interface{}{
					"config_hash":                hash,
					"store_raw_request_response": providerConfig.StoreRawRequestResponse,
				}).Error; err != nil {
					return fmt.Errorf("failed to update hash for provider %s: %w", provider.Name, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableProvider{}, "store_raw_request_response"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add store raw request response column migration: %s", err.Error())
	}
	return nil
}

// migrationInit is the first migration
func migrationInit(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "init",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableConfigHash{}) {
				if err := migrator.CreateTable(&tables.TableConfigHash{}); err != nil {
					return err
				}
			}
			// TableBudget and TableRateLimit must be created before TableProvider
			// because TableProvider has FK references to them
			if !migrator.HasTable(&tables.TableBudget{}) {
				if err := migrator.CreateTable(&tables.TableBudget{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableRateLimit{}) {
				if err := migrator.CreateTable(&tables.TableRateLimit{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableProvider{}) {
				if err := migrator.CreateTable(&tables.TableProvider{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableKey{}) {
				if err := migrator.CreateTable(&tables.TableKey{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableModel{}) {
				if err := migrator.CreateTable(&tables.TableModel{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableOauthConfig{}) {
				if err := migrator.CreateTable(&tables.TableOauthConfig{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableOauthToken{}) {
				if err := migrator.CreateTable(&tables.TableOauthToken{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableMCPClient{}) {
				if err := migrator.CreateTable(&tables.TableMCPClient{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableClientConfig{}) {
				if err := migrator.CreateTable(&tables.TableClientConfig{}); err != nil {
					return err
				}
			} else if !migrator.HasColumn(&tables.TableClientConfig{}, "max_request_body_size_mb") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "max_request_body_size_mb"); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableEnvKey{}) {
				if err := migrator.CreateTable(&tables.TableEnvKey{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableVectorStoreConfig{}) {
				if err := migrator.CreateTable(&tables.TableVectorStoreConfig{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableLogStoreConfig{}) {
				if err := migrator.CreateTable(&tables.TableLogStoreConfig{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableCustomer{}) {
				if err := migrator.CreateTable(&tables.TableCustomer{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableTeam{}) {
				if err := migrator.CreateTable(&tables.TableTeam{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableVirtualKey{}) {
				if err := migrator.CreateTable(&tables.TableVirtualKey{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableGovernanceConfig{}) {
				if err := migrator.CreateTable(&tables.TableGovernanceConfig{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableModelPricing{}) {
				if err := migrator.CreateTable(&tables.TableModelPricing{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TablePlugin{}) {
				if err := migrator.CreateTable(&tables.TablePlugin{}); err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			// Drop children first, then parents (adjust if your actual FKs differ)
			if err := migrator.DropTable(&tables.TableVirtualKey{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableKey{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableTeam{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableProvider{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableCustomer{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableBudget{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableRateLimit{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableModel{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableMCPClient{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableClientConfig{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableEnvKey{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableVectorStoreConfig{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableLogStoreConfig{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableGovernanceConfig{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableModelPricing{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TablePlugin{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableConfigHash{}); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// createMany2ManyJoinTable creates a many-to-many join table for the given tables.
func migrationMany2ManyJoinTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "many2manyjoin",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// create the many-to-many join table for virtual keys and keys
			if !migrator.HasTable("governance_virtual_key_keys") {
				createJoinTableSQL := `
					CREATE TABLE IF NOT EXISTS governance_virtual_key_keys (
						table_virtual_key_id VARCHAR(255) NOT NULL,
						table_key_id INTEGER NOT NULL,
						PRIMARY KEY (table_virtual_key_id, table_key_id),
						FOREIGN KEY (table_virtual_key_id) REFERENCES governance_virtual_keys(id) ON DELETE CASCADE,
						FOREIGN KEY (table_key_id) REFERENCES config_keys(id) ON DELETE CASCADE
					)
				`
				if err := tx.Exec(createJoinTableSQL).Error; err != nil {
					return fmt.Errorf("failed to create governance_virtual_key_keys table: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			if err := tx.Exec("DROP TABLE IF EXISTS governance_virtual_key_keys").Error; err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddCustomProviderConfigJSONColumn adds the custom_provider_config_json column to the provider table
func migrationAddCustomProviderConfigJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "addcustomproviderconfigjsoncolumn",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableProvider{}, "custom_provider_config_json") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "custom_provider_config_json"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyProviderConfigTable adds the virtual_key_provider_config table
func migrationAddVirtualKeyProviderConfigTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "addvirtualkeyproviderconfig",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasTable(&tables.TableVirtualKeyProviderConfig{}) {
				if err := migrator.CreateTable(&tables.TableVirtualKeyProviderConfig{}); err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if err := migrator.DropTable(&tables.TableVirtualKeyProviderConfig{}); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddAllowedOriginsJSONColumn adds the allowed_origins_json column to the client config table
func migrationAddAllowedOriginsJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_allowed_origins_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableClientConfig{}, "allowed_origins_json") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "allowed_origins_json"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddAllowDirectKeysColumn adds the allow_direct_keys column to the client config table
func migrationAddAllowDirectKeysColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_allow_direct_keys_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableClientConfig{}, "allow_direct_keys") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "allow_direct_keys"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddEnableLiteLLMFallbacksColumn adds the enable_litellm_fallbacks column to the client config table
func migrationAddEnableLiteLLMFallbacksColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_enable_litellm_fallbacks_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "enable_litellm_fallbacks") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "enable_litellm_fallbacks"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if err := migrator.DropColumn(&tables.TableClientConfig{}, "enable_litellm_fallbacks"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationTeamsTableUpdates adds profile, config, and claims columns to the team table
func migrationTeamsTableUpdates(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_profile_config_claims_columns_to_team_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableTeam{}, "profile") {
				if err := migrator.AddColumn(&tables.TableTeam{}, "profile"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableTeam{}, "config") {
				if err := migrator.AddColumn(&tables.TableTeam{}, "config"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableTeam{}, "claims") {
				if err := migrator.AddColumn(&tables.TableTeam{}, "claims"); err != nil {
					return err
				}
			}
			return nil
		},
	}, {
		// Agentic PEP per-team / per-member tool entitlements. Stored as
		// a JSON-encoded string of tool names; intersected with the VK's
		// AllowedTools at decide time (see framework/agentic).
		ID: "add_allowed_tools_to_team_and_customer",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			// Use STRING table names + raw ALTER (not struct-field AddColumn) so
			// this migration stays runnable after `allowed_tools` was later
			// removed from the TableTeam / TableCustomer structs. A struct-field
			// AddColumn fails with "failed to look up field with name:
			// allowed_tools" once the field is gone - which crash-loops boot if
			// the migration ledger is ever replayed from before the drop.
			// Idempotent via HasColumn on the string table name.
			for _, tbl := range []string{"governance_teams", "governance_customers"} {
				if !mig.HasTable(tbl) {
					continue
				}
				if !mig.HasColumn(tbl, "allowed_tools") {
					if err := tx.Exec("ALTER TABLE " + tbl + " ADD COLUMN allowed_tools text").Error; err != nil {
						return err
					}
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddFrameworkConfigsTable adds the framework_configs table
func migrationAddFrameworkConfigsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_framework_configs_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableFrameworkConfig{}) {
				if err := migrator.CreateTable(&tables.TableFrameworkConfig{}); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddKeyNameColumn adds the name column to the key table and populates unique names
func migrationAddKeyNameColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_key_name_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "name") {
				// Step 1: Add the column as nullable first
				if err := tx.Exec("ALTER TABLE config_keys ADD COLUMN name VARCHAR(255)").Error; err != nil {
					return fmt.Errorf("failed to add name column: %w", err)
				}

				// Step 2: Populate unique names for all existing keys
				var keys []tables.TableKey
				if err := tx.Find(&keys).Error; err != nil {
					return fmt.Errorf("failed to fetch keys: %w", err)
				}

				for _, key := range keys {
					// Create unique name: provider_name-key-{first8chars_of_key_id}-{key_index}
					keyIDShort := key.KeyID
					if len(keyIDShort) > 8 {
						keyIDShort = keyIDShort[:8]
					}
					keyName := keyIDShort + "-" + strconv.Itoa(int(key.ID))
					uniqueName := fmt.Sprintf("%s-key-%s", key.Provider, keyName)

					// Update the key with the unique name
					if err := tx.Model(&key).Update("name", uniqueName).Error; err != nil {
						return fmt.Errorf("failed to update key %s with name %s: %w", key.KeyID, uniqueName, err)
					}
				}

				// Step 3: Add unique index (SQLite compatible)
				if err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_key_name ON config_keys (name)").Error; err != nil {
					return fmt.Errorf("failed to create unique index on name: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			// Drop the unique index first to avoid orphaned index artifacts
			if err := tx.Exec("DROP INDEX IF EXISTS idx_key_name").Error; err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableKey{}, "name"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationCleanupMCPClientToolsConfig removes ToolsToSkipJSON column and converts empty ToolsToExecuteJSON to wildcard
func migrationCleanupMCPClientToolsConfig(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "cleanup_mcp_client_tools_config",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Step 1: Remove ToolsToSkipJSON column if it exists (cleanup from old versions)
			if migrator.HasColumn(&tables.TableMCPClient{}, "tools_to_skip_json") {
				if err := migrator.DropColumn(&tables.TableMCPClient{}, "tools_to_skip_json"); err != nil {
					return fmt.Errorf("failed to drop tools_to_skip_json column: %w", err)
				}
			}

			// Alternative column name variations that might exist
			if migrator.HasColumn(&tables.TableMCPClient{}, "ToolsToSkipJSON") {
				if err := migrator.DropColumn(&tables.TableMCPClient{}, "ToolsToSkipJSON"); err != nil {
					return fmt.Errorf("failed to drop ToolsToSkipJSON column: %w", err)
				}
			}

			// Step 2: Update empty ToolsToExecuteJSON arrays to wildcard ["*"]
			// Convert "[]" (empty array) to "[\"*\"]" (wildcard array) for backward compatibility
			updateSQL := `
				UPDATE config_mcp_clients 
				SET tools_to_execute_json = '["*"]' 
				WHERE tools_to_execute_json = '[]' OR tools_to_execute_json = '' OR tools_to_execute_json IS NULL
			`
			if err := tx.Exec(updateSQL).Error; err != nil {
				return fmt.Errorf("failed to update empty ToolsToExecuteJSON to wildcard: %w", err)
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			// For rollback, we could add the column back, but since we're moving away from this
			// functionality, we'll just revert the wildcard changes back to empty arrays
			tx = tx.WithContext(ctx)

			revertSQL := `
				UPDATE config_mcp_clients 
				SET tools_to_execute_json = '[]' 
				WHERE tools_to_execute_json = '["*"]'
			`
			if err := tx.Exec(revertSQL).Error; err != nil {
				return fmt.Errorf("failed to revert wildcard ToolsToExecuteJSON to empty arrays: %w", err)
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running MCP client tools cleanup migration: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyMCPConfigsTable adds the virtual_key_mcp_configs table
func migrationAddVirtualKeyMCPConfigsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_vk_mcp_configs_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableVirtualKeyMCPConfig{}) {
				if err := migrator.CreateTable(&tables.TableVirtualKeyMCPConfig{}); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropTable(&tables.TableVirtualKeyMCPConfig{}); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddProviderConfigBudgetRateLimit adds budget_id and rate_limit_id columns with proper foreign key constraints
func migrationAddProviderConfigBudgetRateLimit(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_provider_config_budget_rate_limit",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Add BudgetID column if it doesn't exist
			if migrator.HasTable(&tables.TableVirtualKeyProviderConfig{}) {
				if !migrator.HasColumn(&tables.TableVirtualKeyProviderConfig{}, "budget_id") {
					if err := migrator.AddColumn(&tables.TableVirtualKeyProviderConfig{}, "budget_id"); err != nil {
						return fmt.Errorf("failed to add budget_id column: %w", err)
					}
				}

				// Add RateLimitID column if it doesn't exist
				if !migrator.HasColumn(&tables.TableVirtualKeyProviderConfig{}, "rate_limit_id") {
					if err := migrator.AddColumn(&tables.TableVirtualKeyProviderConfig{}, "rate_limit_id"); err != nil {
						return fmt.Errorf("failed to add rate_limit_id column: %w", err)
					}
				}

				// Create foreign key indexes for better performance
				if !migrator.HasIndex(&tables.TableVirtualKeyProviderConfig{}, "idx_provider_config_budget") {
					if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_provider_config_budget ON governance_virtual_key_provider_configs (budget_id)").Error; err != nil {
						return fmt.Errorf("failed to create budget_id index: %w", err)
					}
				}

				if !migrator.HasIndex(&tables.TableVirtualKeyProviderConfig{}, "idx_provider_config_rate_limit") {
					if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_provider_config_rate_limit ON governance_virtual_key_provider_configs (rate_limit_id)").Error; err != nil {
						return fmt.Errorf("failed to create rate_limit_id index: %w", err)
					}
				}

				// Create FK constraints (dialect‑agnostic)
				if !migrator.HasConstraint(&tables.TableVirtualKeyProviderConfig{}, "Budget") {
					if err := migrator.CreateConstraint(&tables.TableVirtualKeyProviderConfig{}, "Budget"); err != nil {
						return fmt.Errorf("failed to create Budget FK constraint: %w", err)
					}
				}
				if !migrator.HasConstraint(&tables.TableVirtualKeyProviderConfig{}, "RateLimit") {
					if err := migrator.CreateConstraint(&tables.TableVirtualKeyProviderConfig{}, "RateLimit"); err != nil {
						return fmt.Errorf("failed to create RateLimit FK constraint: %w", err)
					}
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Drop indexes first
			if err := tx.Exec("DROP INDEX IF EXISTS idx_provider_config_budget").Error; err != nil {
				return fmt.Errorf("failed to drop budget_id index: %w", err)
			}
			if err := tx.Exec("DROP INDEX IF EXISTS idx_provider_config_rate_limit").Error; err != nil {
				return fmt.Errorf("failed to drop rate_limit_id index: %w", err)
			}

			// Drop FK constraints
			if migrator.HasConstraint(&tables.TableVirtualKeyProviderConfig{}, "Budget") {
				if err := migrator.DropConstraint(&tables.TableVirtualKeyProviderConfig{}, "Budget"); err != nil {
					return fmt.Errorf("failed to drop Budget FK constraint: %w", err)
				}
			}
			if migrator.HasConstraint(&tables.TableVirtualKeyProviderConfig{}, "RateLimit") {
				if err := migrator.DropConstraint(&tables.TableVirtualKeyProviderConfig{}, "RateLimit"); err != nil {
					return fmt.Errorf("failed to drop RateLimit FK constraint: %w", err)
				}
			}

			// Drop columns
			if migrator.HasColumn(&tables.TableVirtualKeyProviderConfig{}, "budget_id") {
				if err := migrator.DropColumn(&tables.TableVirtualKeyProviderConfig{}, "budget_id"); err != nil {
					return fmt.Errorf("failed to drop budget_id column: %w", err)
				}
			}
			if migrator.HasColumn(&tables.TableVirtualKeyProviderConfig{}, "rate_limit_id") {
				if err := migrator.DropColumn(&tables.TableVirtualKeyProviderConfig{}, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to drop rate_limit_id column: %w", err)
				}
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running provider config budget/rate limit migration: %s", err.Error())
	}
	return nil
}

// migrationAddPluginPathColumn adds the path column to the plugin table
func migrationAddPluginPathColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "update_plugins_table_for_custom_plugins",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TablePlugin{}, "path") {
				if err := migrator.AddColumn(&tables.TablePlugin{}, "path"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TablePlugin{}, "is_custom") {
				if err := migrator.AddColumn(&tables.TablePlugin{}, "is_custom"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TablePlugin{}, "path"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TablePlugin{}, "is_custom"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running plugin path migration: %s", err.Error())
	}
	return nil
}

// migrationAddSessionsTable adds the sessions table
func migrationAddSessionsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_sessions_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.SessionsTable{}) {
				if err := migrator.CreateTable(&tables.SessionsTable{}); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropTable(&tables.SessionsTable{}); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

func migrationAddDashboardAuthTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_dashboard_auth_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasTable(&tables.TableAuthUser{}) {
				if err := migrator.CreateTable(&tables.TableAuthUser{}); err != nil {
					return err
				}
			}
			if !migrator.HasTable(&tables.TableEmailVerificationToken{}) {
				if err := migrator.CreateTable(&tables.TableEmailVerificationToken{}); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.SessionsTable{}, "user_id") {
				if err := migrator.AddColumn(&tables.SessionsTable{}, "UserID"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.SessionsTable{}, "user_email") {
				if err := migrator.AddColumn(&tables.SessionsTable{}, "UserEmail"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.SessionsTable{}, "auth_provider") {
				if err := migrator.AddColumn(&tables.SessionsTable{}, "AuthProvider"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropTable(&tables.TableEmailVerificationToken{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableAuthUser{}); err != nil {
				return err
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddDashboardAuthUserThemePreference adds the per-user theme
// preference column ("light" / "dark" / "system") so the workspace and
// admin UIs can persist the user's choice across browsers and devices
// instead of relying solely on localStorage.
func migrationAddDashboardAuthUserThemePreference(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_dashboard_auth_user_theme_preference",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasColumn(&tables.TableAuthUser{}, "theme_preference") {
				if err := mg.AddColumn(&tables.TableAuthUser{}, "ThemePreference"); err != nil {
					return fmt.Errorf("failed to add theme_preference column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasColumn(&tables.TableAuthUser{}, "theme_preference") {
				if err := mg.DropColumn(&tables.TableAuthUser{}, "theme_preference"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running auth-user theme-preference migration: %s", err.Error())
	}
	return nil
}

func migrationAddDashboardAuthUserProfileFields(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_dashboard_auth_user_profile_fields",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableAuthUser{}, "pending_email") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "PendingEmail"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableAuthUser{}, "email_verified_at") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "EmailVerifiedAt"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableAuthUser{}, "pending_email_requested_at") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "PendingEmailRequestedAt"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableEmailVerificationToken{}, "purpose") {
				if err := migrator.AddColumn(&tables.TableEmailVerificationToken{}, "Purpose"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableEmailVerificationToken{}, "target_email") {
				if err := migrator.AddColumn(&tables.TableEmailVerificationToken{}, "TargetEmail"); err != nil {
					return err
				}
			}

			if !migrator.HasIndex(&tables.TableAuthUser{}, "PendingEmail") {
				if err := migrator.CreateIndex(&tables.TableAuthUser{}, "PendingEmail"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableAuthUser{}, "EmailVerifiedAt") {
				if err := migrator.CreateIndex(&tables.TableAuthUser{}, "EmailVerifiedAt"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableAuthUser{}, "PendingEmailRequestedAt") {
				if err := migrator.CreateIndex(&tables.TableAuthUser{}, "PendingEmailRequestedAt"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableEmailVerificationToken{}, "Purpose") {
				if err := migrator.CreateIndex(&tables.TableEmailVerificationToken{}, "Purpose"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableEmailVerificationToken{}, "TargetEmail") {
				if err := migrator.CreateIndex(&tables.TableEmailVerificationToken{}, "TargetEmail"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

func migrationAddDashboardUserInvitationsAndRoles(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_dashboard_user_invitations_and_roles",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableAuthUser{}, "role") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "Role"); err != nil {
					return err
				}
			}
			if err := tx.Exec("UPDATE auth_users SET role = ? WHERE role = '' OR role IS NULL", tables.UserRoleAdmin).Error; err != nil {
				return err
			}
			if !migrator.HasIndex(&tables.TableAuthUser{}, "Role") {
				if err := migrator.CreateIndex(&tables.TableAuthUser{}, "Role"); err != nil {
					return err
				}
			}

			if !migrator.HasTable(&tables.TableUserInvitation{}) {
				if err := migrator.CreateTable(&tables.TableUserInvitation{}); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "idx_user_invitations_tenant_email") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "idx_user_invitations_tenant_email"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "TokenHash") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "TokenHash"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "Role") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "Role"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "InvitedByUserID") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "InvitedByUserID"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "ExpiresAt") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "ExpiresAt"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "AcceptedAt") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "AcceptedAt"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableUserInvitation{}, "LastSentAt") {
				if err := migrator.CreateIndex(&tables.TableUserInvitation{}, "LastSentAt"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropTable(&tables.TableUserInvitation{}); err != nil {
				return err
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

func migrationAddGovernanceTeamMembers(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_governance_team_members",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasTable(&tables.TableTeamMember{}) {
				if err := migrator.CreateTable(&tables.TableTeamMember{}); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableTeamMember{}, "idx_governance_team_members_tenant_team") {
				if err := migrator.CreateIndex(&tables.TableTeamMember{}, "idx_governance_team_members_tenant_team"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableTeamMember{}, "idx_governance_team_members_tenant_user") {
				if err := migrator.CreateIndex(&tables.TableTeamMember{}, "idx_governance_team_members_tenant_user"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableTeamMember{}, "idx_governance_team_members_team_user") {
				if err := migrator.CreateIndex(&tables.TableTeamMember{}, "idx_governance_team_members_team_user"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropTable(&tables.TableTeamMember{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

func migrationAddGovernanceTeamCustomerMembers(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_governance_team_customer_members",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasTable(&tables.TableTeamCustomerMember{}) {
				if err := migrator.CreateTable(&tables.TableTeamCustomerMember{}); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableTeamCustomerMember{}, "idx_governance_team_customer_members_tenant_team") {
				if err := migrator.CreateIndex(&tables.TableTeamCustomerMember{}, "idx_governance_team_customer_members_tenant_team"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableTeamCustomerMember{}, "idx_governance_team_customer_members_tenant_customer") {
				if err := migrator.CreateIndex(&tables.TableTeamCustomerMember{}, "idx_governance_team_customer_members_tenant_customer"); err != nil {
					return err
				}
			}
			if !migrator.HasIndex(&tables.TableTeamCustomerMember{}, "idx_governance_team_customer_members_team_customer") {
				if err := migrator.CreateIndex(&tables.TableTeamCustomerMember{}, "idx_governance_team_customer_members_team_customer"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropTable(&tables.TableTeamCustomerMember{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddHeadersJSONColumnIntoMCPClient adds the headers_json column to the mcp_client table
func migrationAddHeadersJSONColumnIntoMCPClient(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_headers_json_column_into_mcp_client",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableMCPClient{}, "headers_json") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "headers_json"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableMCPClient{}, "headers_json"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddDisableContentLoggingColumn adds the disable_content_logging column to the client config table
func migrationAddDisableContentLoggingColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_disable_content_logging_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "disable_content_logging") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "disable_content_logging"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableClientConfig{}, "disable_content_logging"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddMCPClientIDColumn adds the client_id column to the mcp_clients table and populates unique client IDs
func migrationAddMCPClientIDColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_mcp_client_id_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableMCPClient{}, "client_id") {
				// Add the column as nullable first
				if err := tx.Exec("ALTER TABLE config_mcp_clients ADD COLUMN client_id VARCHAR(255)").Error; err != nil {
					return fmt.Errorf("failed to add client_id column: %w", err)
				}

				// Populate unique client_ids (UUIDs) for all existing MCP clients
				var mcpClients []tables.TableMCPClient
				if err := tx.Find(&mcpClients).Error; err != nil {
					return fmt.Errorf("failed to fetch MCP clients: %w", err)
				}

				for _, client := range mcpClients {
					// Generate a UUID for the client_id
					clientID := uuid.New().String()

					// Update the client with the generated client_id
					if err := tx.Model(&client).Update("client_id", clientID).Error; err != nil {
						return fmt.Errorf("failed to update MCP client %d with client_id %s: %w", client.ID, clientID, err)
					}
				}

				// Create unique index on client_id
				if err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_id ON config_mcp_clients (client_id)").Error; err != nil {
					return fmt.Errorf("failed to create unique index on client_id: %w", err)
				}
				// Enforce NOT NULL in Postgres to guarantee ID presence on new rows
				if tx.Dialector.Name() == "postgres" {
					if err := tx.Exec("ALTER TABLE config_mcp_clients ALTER COLUMN client_id SET NOT NULL").Error; err != nil {
						return fmt.Errorf("failed to set client_id NOT NULL: %w", err)
					}
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Drop the unique index first to avoid orphaned index artifacts
			if err := tx.Exec("DROP INDEX IF EXISTS idx_mcp_client_id").Error; err != nil {
				return fmt.Errorf("failed to drop client_id index: %w", err)
			}

			if err := migrator.DropColumn(&tables.TableMCPClient{}, "client_id"); err != nil {
				return fmt.Errorf("failed to drop client_id column: %w", err)
			}

			return nil
		},
	}})

	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running MCP client_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddVertexProjectNumberColumn adds the vertex_project_number column to the key table
func migrationAddVertexProjectNumberColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_vertex_project_number_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "vertex_project_number") {
				if err := migrator.AddColumn(&tables.TableKey{}, "vertex_project_number"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableKey{}, "vertex_project_number"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running vertex project number migration: %s", err.Error())
	}
	return nil
}

// migrationAddVertexDeploymentsJSONColumn adds the vertex_deployments_json column to the key table
func migrationAddVertexDeploymentsJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_vertex_deployments_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "vertex_deployments_json") {
				if err := migrator.AddColumn(&tables.TableKey{}, "vertex_deployments_json"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableKey{}, "vertex_deployments_json"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running vertex deployments JSON migration: %s", err.Error())
	}
	return nil
}

func migrationMissingProviderColumnInKeyTable(ctx context.Context, db *gorm.DB) error {
	options := &migrator.Options{
		TableName:                 migrator.DefaultOptions.TableName,
		IDColumnName:              migrator.DefaultOptions.IDColumnName,
		IDColumnSize:              migrator.DefaultOptions.IDColumnSize,
		UseTransaction:            true,
		ValidateUnknownMigrations: migrator.DefaultOptions.ValidateUnknownMigrations,
	}
	m := migrator.New(db, options, []*migrator.Migration{{
		ID: "add_and_fill_provider_column_in_key_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Step 1: Add the provider column if it doesn't exist
			if migrator.HasColumn(&tables.TableKey{}, "provider") {
				return nil
			}
			if err := migrator.AddColumn(&tables.TableKey{}, "provider"); err != nil {
				return fmt.Errorf("failed to add provider column: %w", err)
			}

			// Step 2: Find all keys where provider is empty/null but provider_id is set
			var keys []tables.TableKey
			if err := tx.Where("provider IS NULL OR provider = ''").Find(&keys).Error; err != nil {
				return fmt.Errorf("failed to fetch keys with missing provider: %w", err)
			}

			// Step 3: Update each key with the provider name from the provider table
			for _, key := range keys {
				var provider tables.TableProvider
				if err := tx.First(&provider, key.ProviderID).Error; err != nil {
					// Skip keys with invalid provider_id
					if err == gorm.ErrRecordNotFound {
						continue
					}
					return fmt.Errorf("failed to fetch provider %d for key %s: %w", key.ProviderID, key.KeyID, err)
				}

				// Update the key with the provider name
				if err := tx.Model(&key).Update("provider", provider.Name).Error; err != nil {
					return fmt.Errorf("failed to update key %s with provider %s: %w", key.KeyID, provider.Name, err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableKey{}, "provider"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add and fill provider column migration: %s", err.Error())
	}
	return nil
}

// migrationAddToolsToAutoExecuteJSONColumn adds the tools_to_auto_execute_json column to the mcp_client table
func migrationAddToolsToAutoExecuteJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tools_to_auto_execute_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableMCPClient{}, "tools_to_auto_execute_json") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "tools_to_auto_execute_json"); err != nil {
					return err
				}
				// Initialize existing rows with empty array
				if err := tx.Exec("UPDATE config_mcp_clients SET tools_to_auto_execute_json = '[]' WHERE tools_to_auto_execute_json IS NULL OR tools_to_auto_execute_json = ''").Error; err != nil {
					return fmt.Errorf("failed to initialize tools_to_auto_execute_json: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableMCPClient{}, "tools_to_auto_execute_json"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddIsCodeModeClientColumn adds the is_code_mode_client column to the config_mcp_clients table
func migrationAddIsCodeModeClientColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_is_code_mode_client_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableMCPClient{}, "is_code_mode_client") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "is_code_mode_client"); err != nil {
					return err
				}
				// Initialize existing rows with false (default value)
				if err := tx.Exec("UPDATE config_mcp_clients SET is_code_mode_client = false WHERE is_code_mode_client IS NULL").Error; err != nil {
					return fmt.Errorf("failed to initialize is_code_mode_client: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableMCPClient{}, "is_code_mode_client"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddLogRetentionDaysColumn adds the log_retention_days column to the client config table
func migrationAddLogRetentionDaysColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_log_retention_days_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "log_retention_days") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "log_retention_days"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableClientConfig{}, "log_retention_days"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddEnabledColumnToKeyTable adds the enabled column to the config_keys table
func migrationAddEnabledColumnToKeyTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_enabled_column_to_key_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			// Check if column already exists
			if !mg.HasColumn(&tables.TableKey{}, "enabled") {
				// Add the column
				if err := mg.AddColumn(&tables.TableKey{}, "enabled"); err != nil {
					return fmt.Errorf("failed to add enabled column: %w", err)
				}
			}
			// Set default = true for existing rows
			if err := tx.Exec("UPDATE config_keys SET enabled = TRUE WHERE enabled IS NULL").Error; err != nil {
				return fmt.Errorf("failed to backfill enabled column: %w", err)
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if mg.HasColumn(&tables.TableKey{}, "enabled") {
				if err := mg.DropColumn(&tables.TableKey{}, "enabled"); err != nil {
					return fmt.Errorf("failed to drop enabled column: %w", err)
				}
			}

			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running enabled column migration: %s", err.Error())
	}
	return nil
}

// migrationAddBatchAndCachePricingColumns adds the cache_read_input_token_cost, cache_creation_input_token_cost, input_cost_per_token_batches, and output_cost_per_token_batches columns to the model_pricing table
func migrationAddBatchAndCachePricingColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "update_model_pricing_table_to_add_cache_and_batch_pricing",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableModelPricing{}, "cache_read_input_token_cost") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "cache_read_input_token_cost"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableModelPricing{}, "cache_creation_input_token_cost") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "cache_creation_input_token_cost"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableModelPricing{}, "input_cost_per_token_batches") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "input_cost_per_token_batches"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableModelPricing{}, "output_cost_per_token_batches") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "output_cost_per_token_batches"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableModelPricing{}, "cache_read_input_token_cost"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableModelPricing{}, "cache_creation_input_token_cost"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableModelPricing{}, "input_cost_per_token_batches"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableModelPricing{}, "output_cost_per_token_batches"); err != nil {
				return err
			}
			return nil
		},
	}})
	return m.Migrate()
}

func migrationAddMCPAgentDepthAndMCPToolExecutionTimeoutColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_mcp_agent_depth_and_mcp_tool_execution_timeout_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "mcp_agent_depth") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "mcp_agent_depth"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableClientConfig{}, "mcp_tool_execution_timeout") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "mcp_tool_execution_timeout"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableClientConfig{}, "mcp_agent_depth"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableClientConfig{}, "mcp_tool_execution_timeout"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddMCPCodeModeBindingLevelColumn adds the mcp_code_mode_binding_level column to the client config table.
// This column stores the code mode binding level preference (server or tool).
func migrationAddMCPCodeModeBindingLevelColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_mcp_code_mode_binding_level_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migratorInstance := tx.Migrator()
			if !migratorInstance.HasColumn(&tables.TableClientConfig{}, "mcp_code_mode_binding_level") {
				if err := migratorInstance.AddColumn(&tables.TableClientConfig{}, "mcp_code_mode_binding_level"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migratorInstance := tx.Migrator()
			if err := migratorInstance.DropColumn(&tables.TableClientConfig{}, "mcp_code_mode_binding_level"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// normalizeMCPClientName normalizes an MCP client name by:
// 1. Replacing hyphens and spaces with underscores
// 2. Removing leading digits
// 3. Using a default name if the result is empty
func normalizeMCPClientName(name string) string {
	// Replace hyphens and spaces with underscores
	normalized := strings.ReplaceAll(name, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")

	// Remove leading digits
	normalized = strings.TrimLeftFunc(normalized, func(r rune) bool {
		return unicode.IsDigit(r)
	})

	// If name becomes empty after normalization, use a default name
	if normalized == "" {
		normalized = "mcp_client"
	}

	return normalized
}

// migrationNormalizeMCPClientNames normalizes MCP client names by:
// 1. Replacing hyphens and spaces with underscores
// 2. Removing leading digits
// 3. Adding number suffix if name already exists
func migrationNormalizeMCPClientNames(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "normalize_mcp_client_names",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)

			// Fetch all MCP clients
			var mcpClients []tables.TableMCPClient
			if err := tx.Find(&mcpClients).Error; err != nil {
				return fmt.Errorf("failed to fetch MCP clients: %w", err)
			}

			// Track assigned names in memory to avoid transaction visibility issues
			// and ensure we see all updates made during this migration
			assignedNames := make(map[string]bool)

			// Helper function to find a unique name
			findUniqueName := func(baseName string, originalName string, excludeID uint, tx *gorm.DB, assignedNames map[string]bool) (string, error) {
				// First check if base name is already assigned in this migration
				if !assignedNames[baseName] {
					// Also check database for existing names (excluding current client)
					var existing tables.TableMCPClient
					err := tx.Where("name = ? AND id != ?", baseName, excludeID).First(&existing).Error
					if err == gorm.ErrRecordNotFound {
						// Name is available
						assignedNames[baseName] = true
						// Log normalization even when no collision
						if originalName != baseName {
							log.Printf("MCP Client Name Normalized: '%s' -> '%s'", originalName, baseName)
						}
						return baseName, nil
					} else if err != nil {
						return "", fmt.Errorf("failed to check name availability: %w", err)
					}
				}

				// Name exists (either assigned in this migration or in database), try with number suffix starting from 2
				// (base name is conceptually "1", so collisions start from "2")
				suffix := 2
				const maxSuffix = 1000 // Safety limit to prevent infinite loops
				for {
					if suffix > maxSuffix {
						return "", fmt.Errorf("could not find unique name after %d attempts for base name: %s", maxSuffix, baseName)
					}
					candidateName := baseName + strconv.Itoa(suffix)

					// Check both in-memory map and database
					if !assignedNames[candidateName] {
						var existing tables.TableMCPClient
						err := tx.Where("name = ? AND id != ?", candidateName, excludeID).First(&existing).Error
						if err == gorm.ErrRecordNotFound {
							// Found available name - log the transformation
							assignedNames[candidateName] = true
							log.Printf("MCP Client Name Normalized: '%s' -> '%s'", originalName, candidateName)
							return candidateName, nil
						} else if err != nil {
							return "", fmt.Errorf("failed to check name availability: %w", err)
						}
					}
					suffix++
				}
			}

			// Process each client
			for _, client := range mcpClients {
				originalName := client.Name
				needsUpdate := false

				// Check if name needs normalization
				if strings.Contains(originalName, "-") || strings.Contains(originalName, " ") {
					needsUpdate = true
				} else if len(originalName) > 0 && unicode.IsDigit(rune(originalName[0])) {
					needsUpdate = true
				}

				if needsUpdate {
					// Normalize the name
					normalizedName := normalizeMCPClientName(originalName)

					// Find a unique name (pass assignedNames map to track names in this migration)
					uniqueName, err := findUniqueName(normalizedName, originalName, client.ID, tx, assignedNames)
					if err != nil {
						return fmt.Errorf("failed to find unique name for client %d (original: %s): %w", client.ID, originalName, err)
					}

					// Update the client name
					if err := tx.Model(&client).Update("name", uniqueName).Error; err != nil {
						return fmt.Errorf("failed to update MCP client %d name from %s to %s: %w", client.ID, originalName, uniqueName, err)
					}
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			// Rollback is not possible as we don't store the original names
			// This migration is one-way
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running MCP client name normalization migration: %s", err.Error())
	}
	return nil
}

// migrationMoveKeysToProviderConfig migrates keys from virtual key level to provider config level
func migrationMoveKeysToProviderConfig(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "move_keys_to_provider_config",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			gormMigrator := tx.Migrator()

			// Step 1: Create the new join table for provider config -> keys relationship
			// Setup the join table so GORM knows about the custom structure
			if err := tx.SetupJoinTable(&tables.TableVirtualKeyProviderConfig{}, "Keys", &tables.TableVirtualKeyProviderConfigKey{}); err != nil {
				return fmt.Errorf("failed to setup join table for provider config keys: %w", err)
			}

			// Create the join table if it doesn't exist
			if !gormMigrator.HasTable(&tables.TableVirtualKeyProviderConfigKey{}) {
				if err := gormMigrator.CreateTable(&tables.TableVirtualKeyProviderConfigKey{}); err != nil {
					return fmt.Errorf("failed to create join table for provider config keys: %w", err)
				}
			}

			// Step 2: Migrate existing key associations from virtual key to provider config level
			// Check if old join table exists
			hasOldTable := gormMigrator.HasTable("governance_virtual_key_keys")

			if hasOldTable {
				// Get all existing associations from old table using GORM's Table method
				type OldAssociation struct {
					VirtualKeyID string `gorm:"column:table_virtual_key_id"`
					KeyID        uint   `gorm:"column:table_key_id"`
				}
				var oldAssociations []OldAssociation
				if err := tx.Table("governance_virtual_key_keys").Find(&oldAssociations).Error; err == nil {
					// Process each association
					for _, assoc := range oldAssociations {
						// Get only the key ID and provider - using a minimal struct to avoid
						// querying columns that may not exist yet (added by later migrations)
						type KeyMinimal struct {
							ID       uint
							Provider string
						}
						var keyData KeyMinimal
						if err := tx.Table("config_keys").Select("id, provider").Where("id = ?", assoc.KeyID).First(&keyData).Error; err != nil {
							// Key might have been deleted, skip
							continue
						}

						// Find existing provider config for this virtual key and provider
						var providerConfig tables.TableVirtualKeyProviderConfig
						result := tx.Where("virtual_key_id = ? AND provider = ?", assoc.VirtualKeyID, keyData.Provider).First(&providerConfig)

						if result.Error != nil {
							if result.Error == gorm.ErrRecordNotFound {
								// Create a new provider config for this provider
								providerConfig = tables.TableVirtualKeyProviderConfig{
									VirtualKeyID:  assoc.VirtualKeyID,
									Provider:      keyData.Provider,
									Weight:        deepintshield.Ptr(1.0),
									AllowedModels: []string{},
								}
								if err := tx.Create(&providerConfig).Error; err != nil {
									return fmt.Errorf("failed to create provider config for migration: %w", err)
								}
							} else {
								return fmt.Errorf("failed to query provider config: %w", result.Error)
							}
						}

						// Insert directly into the join table using clause.OnConflict for
						// database-agnostic duplicate handling (works for SQLite and PostgreSQL)
						joinEntry := tables.TableVirtualKeyProviderConfigKey{
							TableVirtualKeyProviderConfigID: providerConfig.ID,
							TableKeyID:                      keyData.ID,
						}
						if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&joinEntry).Error; err != nil {
							return fmt.Errorf("failed to associate key %d with provider config %d: %w", keyData.ID, providerConfig.ID, err)
						}
					}
				}

				// Step 3: Drop the old join table
				if err := gormMigrator.DropTable("governance_virtual_key_keys"); err != nil {
					return fmt.Errorf("failed to drop old governance_virtual_key_keys table: %w", err)
				}
			}

			// Note: Empty keys in provider config means all keys are allowed at runtime
			// We don't pre-populate keys here - this is handled at runtime

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			gormMigrator := tx.Migrator()

			// Recreate the old join table structure
			type OldJoinTable struct {
				VirtualKeyID string `gorm:"column:table_virtual_key_id;primaryKey"`
				KeyID        uint   `gorm:"column:table_key_id;primaryKey"`
			}
			if err := gormMigrator.CreateTable(&OldJoinTable{}); err != nil {
				// Table might already exist, ignore error
				_ = err
			}
			// Rename to correct table name if needed
			if gormMigrator.HasTable(&OldJoinTable{}) && !gormMigrator.HasTable("governance_virtual_key_keys") {
				if err := gormMigrator.RenameTable(&OldJoinTable{}, "governance_virtual_key_keys"); err != nil {
					return fmt.Errorf("failed to rename old join table: %w", err)
				}
			}

			// Note: We cannot fully rollback the data migration as it would require
			// reconstructing which keys belonged to which virtual keys

			// Drop the new join table
			if err := gormMigrator.DropTable("governance_virtual_key_provider_config_keys"); err != nil {
				return fmt.Errorf("failed to drop governance_virtual_key_provider_config_keys table: %w", err)
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running move keys to provider config migration: %s", err.Error())
	}
	return nil
}

// migrationAddPluginVersionColumn adds the version column to the plugin table
func migrationAddPluginVersionColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_plugin_version_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TablePlugin{}, "version") {
				if err := migrator.AddColumn(&tables.TablePlugin{}, "version"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TablePlugin{}, "version"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add plugin version column migration: %s", err.Error())
	}
	return nil
}

func migrationAddSendBackRawRequestColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_send_back_raw_request_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableProvider{}, "send_back_raw_request") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "send_back_raw_request"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableProvider{}, "send_back_raw_request"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add send back raw request columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddConfigHashColumn adds the config_hash column to the provider and key tables
func migrationAddConfigHashColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_config_hash_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			// Add config_hash to providers table
			if !migrator.HasColumn(&tables.TableProvider{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing providers
				var providers []tables.TableProvider
				if err := tx.Find(&providers).Error; err != nil {
					return fmt.Errorf("failed to fetch providers for hash migration: %w", err)
				}
				for _, provider := range providers {
					if provider.ConfigHash == "" {
						// Convert to ProviderConfig and generate hash
						providerConfig := ProviderConfig{
							NetworkConfig:            provider.NetworkConfig,
							ConcurrencyAndBufferSize: provider.ConcurrencyAndBufferSize,
							ProxyConfig:              provider.ProxyConfig,
							SendBackRawRequest:       provider.SendBackRawRequest,
							SendBackRawResponse:      provider.SendBackRawResponse,
							CustomProviderConfig:     provider.CustomProviderConfig,
						}
						hash, err := providerConfig.GenerateConfigHash(provider.Name)
						if err != nil {
							return fmt.Errorf("failed to generate hash for provider %s: %w", provider.Name, err)
						}
						if err := tx.Model(&provider).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for provider %s: %w", provider.Name, err)
						}
					}
				}
			}
			// Add config_hash to keys table
			if !migrator.HasColumn(&tables.TableKey{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableKey{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing keys
				var keys []tables.TableKey
				if err := tx.Find(&keys).Error; err != nil {
					return fmt.Errorf("failed to fetch keys for hash migration: %w", err)
				}
				for _, key := range keys {
					if key.ConfigHash == "" {
						// Convert to schemas.Key and generate hash
						schemaKey := schemas.Key{
							Name:               key.Name,
							Value:              key.Value,
							Models:             key.Models,
							Weight:             getWeight(key.Weight),
							AzureKeyConfig:     key.AzureKeyConfig,
							VertexKeyConfig:    key.VertexKeyConfig,
							BedrockKeyConfig:   key.BedrockKeyConfig,
							ReplicateKeyConfig: key.ReplicateKeyConfig,
						}
						hash, err := GenerateKeyHash(schemaKey)
						if err != nil {
							return fmt.Errorf("failed to generate hash for key %s: %w", key.Name, err)
						}
						if err := tx.Model(&key).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for key %s: %w", key.Name, err)
						}
					}
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableProvider{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableKey{}, "config_hash"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add config hash column migration: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyConfigHashColumn adds the config_hash column to the virtual keys table
func migrationAddVirtualKeyConfigHashColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_config_hash_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			// Add config_hash to virtual keys table
			if !migrator.HasColumn(&tables.TableVirtualKey{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableVirtualKey{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing virtual keys
				var virtualKeys []tables.TableVirtualKey
				if err := tx.Preload("ProviderConfigs").Preload("ProviderConfigs.Keys").Preload("MCPConfigs").Find(&virtualKeys).Error; err != nil {
					return fmt.Errorf("failed to fetch virtual keys for hash migration: %w", err)
				}
				for _, vk := range virtualKeys {
					if vk.ConfigHash == "" {
						hash, err := GenerateVirtualKeyHash(vk)
						if err != nil {
							return fmt.Errorf("failed to generate hash for virtual key %s: %w", vk.ID, err)
						}
						if err := tx.Model(&vk).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for virtual key %s: %w", vk.ID, err)
						}
					}
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableVirtualKey{}, "config_hash"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add virtual key config hash column migration: %s", err.Error())
	}
	return nil
}

// migrationAddAdditionalConfigHashColumns adds config_hash columns to client config, budget, rate limit,
// customer, team, MCP client, and plugin tables for reconciliation support
func migrationAddAdditionalConfigHashColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_additional_config_hash_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Add config_hash to client config table
			if !migrator.HasColumn(&tables.TableClientConfig{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing client configs
				var clientConfigs []tables.TableClientConfig
				if err := tx.Find(&clientConfigs).Error; err != nil {
					return fmt.Errorf("failed to fetch client configs for hash migration: %w", err)
				}
				for _, cc := range clientConfigs {
					if cc.ConfigHash == "" {
						clientConfig := ClientConfig{
							DropExcessRequests:      cc.DropExcessRequests,
							InitialPoolSize:         cc.InitialPoolSize,
							PrometheusLabels:        cc.PrometheusLabels,
							EnableLogging:           cc.EnableLogging,
							DisableContentLogging:   cc.DisableContentLogging,
							LogRetentionDays:        cc.LogRetentionDays,
							EnforceGovernanceHeader: cc.EnforceGovernanceHeader,
							AllowDirectKeys:         cc.AllowDirectKeys,
							AllowedOrigins:          cc.AllowedOrigins,
							MaxRequestBodySizeMB:    cc.MaxRequestBodySizeMB,
							EnableLiteLLMFallbacks:  cc.EnableLiteLLMFallbacks,
						}
						hash, err := clientConfig.GenerateClientConfigHash()
						if err != nil {
							return fmt.Errorf("failed to generate hash for client config %d: %w", cc.ID, err)
						}
						if err := tx.Model(&cc).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for client config %d: %w", cc.ID, err)
						}
					}
				}
			}

			// Add config_hash to budgets table
			if !migrator.HasColumn(&tables.TableBudget{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableBudget{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing budgets
				var budgets []tables.TableBudget
				if err := tx.Find(&budgets).Error; err != nil {
					return fmt.Errorf("failed to fetch budgets for hash migration: %w", err)
				}
				for _, budget := range budgets {
					if budget.ConfigHash == "" {
						hash, err := GenerateBudgetHash(budget)
						if err != nil {
							return fmt.Errorf("failed to generate hash for budget %s: %w", budget.ID, err)
						}
						if err := tx.Model(&budget).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for budget %s: %w", budget.ID, err)
						}
					}
				}
			}

			// Add config_hash to rate limits table
			if !migrator.HasColumn(&tables.TableRateLimit{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableRateLimit{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing rate limits
				var rateLimits []tables.TableRateLimit
				if err := tx.Find(&rateLimits).Error; err != nil {
					return fmt.Errorf("failed to fetch rate limits for hash migration: %w", err)
				}
				for _, rl := range rateLimits {
					if rl.ConfigHash == "" {
						hash, err := GenerateRateLimitHash(rl)
						if err != nil {
							return fmt.Errorf("failed to generate hash for rate limit %s: %w", rl.ID, err)
						}
						if err := tx.Model(&rl).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for rate limit %s: %w", rl.ID, err)
						}
					}
				}
			}

			// Add config_hash to customers table
			if !migrator.HasColumn(&tables.TableCustomer{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableCustomer{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing customers
				var customers []tables.TableCustomer
				if err := tx.Find(&customers).Error; err != nil {
					return fmt.Errorf("failed to fetch customers for hash migration: %w", err)
				}
				for _, customer := range customers {
					if customer.ConfigHash == "" {
						hash, err := GenerateCustomerHash(customer)
						if err != nil {
							return fmt.Errorf("failed to generate hash for customer %s: %w", customer.ID, err)
						}
						if err := tx.Model(&customer).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for customer %s: %w", customer.ID, err)
						}
					}
				}
			}

			// Add config_hash to teams table
			if !migrator.HasColumn(&tables.TableTeam{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableTeam{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing teams
				var teams []tables.TableTeam
				if err := tx.Find(&teams).Error; err != nil {
					return fmt.Errorf("failed to fetch teams for hash migration: %w", err)
				}
				for _, team := range teams {
					if team.ConfigHash == "" {
						hash, err := GenerateTeamHash(team)
						if err != nil {
							return fmt.Errorf("failed to generate hash for team %s: %w", team.ID, err)
						}
						if err := tx.Model(&team).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for team %s: %w", team.ID, err)
						}
					}
				}
			}

			// Add config_hash to MCP clients table
			if !migrator.HasColumn(&tables.TableMCPClient{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing MCP clients
				var mcpClients []tables.TableMCPClient
				if err := tx.Find(&mcpClients).Error; err != nil {
					return fmt.Errorf("failed to fetch MCP clients for hash migration: %w", err)
				}
				for _, mcp := range mcpClients {
					if mcp.ConfigHash == "" {
						hash, err := GenerateMCPClientHash(mcp)
						if err != nil {
							return fmt.Errorf("failed to generate hash for MCP client %s: %w", mcp.Name, err)
						}
						if err := tx.Model(&mcp).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for MCP client %s: %w", mcp.Name, err)
						}
					}
				}
			}

			// Add config_hash to plugins table
			if !migrator.HasColumn(&tables.TablePlugin{}, "config_hash") {
				if err := migrator.AddColumn(&tables.TablePlugin{}, "config_hash"); err != nil {
					return err
				}
				// Pre-populate hashes for existing plugins
				var plugins []tables.TablePlugin
				if err := tx.Find(&plugins).Error; err != nil {
					return fmt.Errorf("failed to fetch plugins for hash migration: %w", err)
				}
				for _, plugin := range plugins {
					if plugin.ConfigHash == "" {
						hash, err := GeneratePluginHash(plugin)
						if err != nil {
							return fmt.Errorf("failed to generate hash for plugin %s: %w", plugin.Name, err)
						}
						if err := tx.Model(&plugin).Update("config_hash", hash).Error; err != nil {
							return fmt.Errorf("failed to update hash for plugin %s: %w", plugin.Name, err)
						}
					}
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableClientConfig{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableBudget{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableRateLimit{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableCustomer{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableTeam{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableMCPClient{}, "config_hash"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TablePlugin{}, "config_hash"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add additional config hash columns migration: %s", err.Error())
	}
	return nil
}

// migrationAdd200kTokenPricingColumns adds pricing columns for 200k token tier models
func migrationAdd200kTokenPricingColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_200k_token_pricing_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			columns := []string{
				"input_cost_per_token_above_200k_tokens",
				"output_cost_per_token_above_200k_tokens",
				"cache_creation_input_token_cost_above_200k_tokens",
				"cache_read_input_token_cost_above_200k_tokens",
			}

			for _, field := range columns {
				if !migrator.HasColumn(&tables.TableModelPricing{}, field) {
					if err := migrator.AddColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to add column %s: %w", field, err)
					}
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			columns := []string{
				"input_cost_per_token_above_200k_tokens",
				"output_cost_per_token_above_200k_tokens",
				"cache_creation_input_token_cost_above_200k_tokens",
				"cache_read_input_token_cost_above_200k_tokens",
			}

			for _, field := range columns {
				if migrator.HasColumn(&tables.TableModelPricing{}, field) {
					if err := migrator.DropColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to drop column %s: %w", field, err)
					}
				}
			}
			return nil
		},
	}})
	return m.Migrate()
}

// migrationAddImagePricingColumns adds the image generation pricing columns to the model_pricing table
func migrationAddImagePricingColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_image_pricing_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			columns := []string{
				"input_cost_per_image_token",
				"output_cost_per_image_token",
				"input_cost_per_image",
				"output_cost_per_image",
				"cache_read_input_image_token_cost",
			}

			for _, field := range columns {
				if !migrator.HasColumn(&tables.TableModelPricing{}, field) {
					if err := migrator.AddColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to add column %s: %w", field, err)
					}
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			columns := []string{
				"input_cost_per_image_token",
				"output_cost_per_image_token",
				"input_cost_per_image",
				"output_cost_per_image",
				"cache_read_input_image_token_cost",
			}

			for _, field := range columns {
				if migrator.HasColumn(&tables.TableModelPricing{}, field) {
					if err := migrator.DropColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to drop column %s: %w", field, err)
					}
				}
			}
			return nil
		},
	}})
	return m.Migrate()
}

// migrationAddUseForBatchAPIColumnAndS3BucketsConfig adds the use_for_batch_api and bedrock_batch_s3_config_json columns to the config_keys table
// Existing keys are backfilled with use_for_batch_api = TRUE to preserve current behavior
func migrationAddUseForBatchAPIColumnAndS3BucketsConfig(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_use_for_batch_api_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			// Add use_for_batch_api column
			if !mg.HasColumn(&tables.TableKey{}, "use_for_batch_api") {
				if err := mg.AddColumn(&tables.TableKey{}, "use_for_batch_api"); err != nil {
					return fmt.Errorf("failed to add use_for_batch_api column: %w", err)
				}
			}

			// Add bedrock_batch_s3_config_json column
			if !mg.HasColumn(&tables.TableKey{}, "bedrock_batch_s3_config_json") {
				if err := mg.AddColumn(&tables.TableKey{}, "bedrock_batch_s3_config_json"); err != nil {
					return fmt.Errorf("failed to add bedrock_batch_s3_config_json column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if mg.HasColumn(&tables.TableKey{}, "use_for_batch_api") {
				if err := mg.DropColumn(&tables.TableKey{}, "use_for_batch_api"); err != nil {
					return fmt.Errorf("failed to drop use_for_batch_api column: %w", err)
				}
			}

			if mg.HasColumn(&tables.TableKey{}, "bedrock_batch_s3_config_json") {
				if err := mg.DropColumn(&tables.TableKey{}, "bedrock_batch_s3_config_json"); err != nil {
					return fmt.Errorf("failed to drop bedrock_batch_s3_config_json column: %w", err)
				}
			}

			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running use_for_batch_api migration: %s", err.Error())
	}
	return nil
}

// migrationAddUseForCacheColumn adds the use_for_cache column to the config_keys table.
// Existing keys are backfilled with TRUE so semantic cache remains enabled unless explicitly disabled.
func migrationAddUseForCacheColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_use_for_cache_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if !mg.HasColumn(&tables.TableKey{}, "use_for_cache") {
				if err := mg.AddColumn(&tables.TableKey{}, "use_for_cache"); err != nil {
					return fmt.Errorf("failed to add use_for_cache column: %w", err)
				}
			}

			if err := tx.Model(&tables.TableKey{}).
				Where("use_for_cache IS NULL").
				Update("use_for_cache", true).Error; err != nil {
				return fmt.Errorf("failed to backfill use_for_cache column: %w", err)
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasColumn(&tables.TableKey{}, "use_for_cache") {
				if err := mg.DropColumn(&tables.TableKey{}, "use_for_cache"); err != nil {
					return fmt.Errorf("failed to drop use_for_cache column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running use_for_cache migration: %s", err.Error())
	}
	return nil
}

// migrationMCPWorkspaceUniqueIndex wipes the MCP client table and swaps the
// unique indexes from (tenant_id, client_id) / (tenant_id, name) to the
// (tenant_id, workspace_id, client_id) / (tenant_id, workspace_id, name)
// pairs declared on TableMCPClient. Per the "Clear and start fresh" decision
// for the MCP Hub / Playground per-workspace rollout - every workspace
// re-adds its MCP clients on first use.
func migrationMCPWorkspaceUniqueIndex(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "mcp_workspace_unique_index_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasTable(&tables.TableMCPClient{}) {
				return nil
			}
			// Wipe MCP client rows + the VK ↔ MCP binding rows that point at
			// them; otherwise the bindings would dangle and break per-VK MCP
			// resolution at request time. Gate the binding wipe with
			// HasTable so older installs that predate the binding table
			// don't trip a "relation does not exist" mid-transaction -
			// Postgres aborts the whole tx (SQLSTATE 25P02) the moment any
			// statement errors, no matter what Go does with the err value.
			if tx.Migrator().HasTable("governance_virtual_key_mcp_configs") {
				if err := tx.Exec(`DELETE FROM governance_virtual_key_mcp_configs`).Error; err != nil {
					return fmt.Errorf("failed to wipe governance_virtual_key_mcp_configs: %w", err)
				}
			}
			if err := tx.Exec(`DELETE FROM config_mcp_clients`).Error; err != nil {
				return fmt.Errorf("failed to wipe config_mcp_clients: %w", err)
			}
			// Drop legacy single-axis indexes if present so AutoMigrate
			// creates the new composite versions cleanly.
			for _, idx := range []string{"idx_mcp_tenant_client_id", "idx_mcp_tenant_name"} {
				if mg.HasIndex(&tables.TableMCPClient{}, idx) {
					if err := mg.DropIndex(&tables.TableMCPClient{}, idx); err != nil {
						return fmt.Errorf("failed to drop legacy MCP index %s: %w", idx, err)
					}
				}
			}
			if err := mg.AutoMigrate(&tables.TableMCPClient{}); err != nil {
				return fmt.Errorf("failed to recreate MCP client indexes: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			for _, idx := range []string{"idx_mcp_tenant_workspace_client_id", "idx_mcp_tenant_workspace_name"} {
				if mg.HasIndex(&tables.TableMCPClient{}, idx) {
					if err := mg.DropIndex(&tables.TableMCPClient{}, idx); err != nil {
						return fmt.Errorf("failed to drop new MCP index %s: %w", idx, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running MCP workspace index migration: %s", err.Error())
	}
	return nil
}

// migrationPromptsWorkspaceFreshStart wipes prompt rows (and their cascaded
// versions / sessions / messages) so the new strict per-workspace read path
// starts from a clean slate. Without the wipe, historical NULL-workspace
// prompt rows would simply become invisible (the strict filter drops them)
// - the wipe makes that disappearance explicit rather than silent.
func migrationPromptsWorkspaceFreshStart(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "prompts_workspace_fresh_start_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable(&tables.TablePrompt{}) {
				return nil
			}
			// Order matters: drop child rows before parents so an environment
			// without FK CASCADE (older SQLite, custom Postgres) doesn't trip
			// a constraint. The DELETE statements no-op if the child table
			// doesn't exist on this install.
			// Child-tables-first delete order. HasTable-gate each statement
			// rather than swallow errors after the fact - Postgres aborts
			// the entire transaction on the first failure (SQLSTATE 25P02)
			// regardless of what Go does with the err, so a "relation does
			// not exist" mid-batch poisons every later DELETE in the same
			// migration.
			tables := []string{
				// Grandchildren first - messages live under both version and
				// session rows. Naming matches TablePromptVersionMessage /
				// TablePromptSessionMessage TableName() in tables/promptVersions.go
				// and tables/promptSessions.go (not the singular `prompt_messages`
				// I originally guessed).
				"prompt_version_messages",
				"prompt_session_messages",
				"prompt_versions",
				"prompt_sessions",
				"prompts",
			}
			for _, table := range tables {
				if !tx.Migrator().HasTable(table) {
					continue
				}
				if err := tx.Exec(fmt.Sprintf(`DELETE FROM %s`, table)).Error; err != nil {
					return fmt.Errorf("failed to wipe %s: %w", table, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			// No-op: deleted data isn't recoverable, and the rollback path
			// for a fresh-start migration is to accept the loss.
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running prompts fresh-start migration: %s", err.Error())
	}
	return nil
}

// migrationPluginWorkspaceUniqueIndex wipes existing config_plugins rows and
// swaps the unique index from (tenant_id, name) to
// (tenant_id, workspace_id, name) so each workspace gets its own plugin
// config. Per product decision we start fresh - every workspace re-seeds its
// recommended defaults on next createWorkspace.
func migrationPluginWorkspaceUniqueIndex(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "plugin_workspace_unique_index_v1",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasTable(&tables.TablePlugin{}) {
				return nil
			}
			// Wipe all rows so the new strict (tenant, workspace, name)
			// scoping starts clean - see "Clear and start fresh" product
			// decision in the cost-optimization workspace-scoping rollout.
			if err := tx.Exec(`DELETE FROM config_plugins`).Error; err != nil {
				return fmt.Errorf("failed to wipe config_plugins: %w", err)
			}
			// Drop the legacy (tenant_id, name) unique index if present.
			if mg.HasIndex(&tables.TablePlugin{}, "idx_plugin_tenant_name") {
				if err := mg.DropIndex(&tables.TablePlugin{}, "idx_plugin_tenant_name"); err != nil {
					return fmt.Errorf("failed to drop legacy plugin index: %w", err)
				}
			}
			// AutoMigrate creates the new composite index from the struct tags.
			if err := mg.AutoMigrate(&tables.TablePlugin{}); err != nil {
				return fmt.Errorf("failed to create new plugin index: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasIndex(&tables.TablePlugin{}, "idx_plugin_tenant_workspace_name") {
				if err := mg.DropIndex(&tables.TablePlugin{}, "idx_plugin_tenant_workspace_name"); err != nil {
					return fmt.Errorf("failed to drop new plugin index: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running plugin workspace index migration: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyFallbackChainColumn adds the fallback_chain JSON column to
// governance_virtual_keys. Required because TableVirtualKey gained a FallbackChain
// field but no AutoMigrate runs at startup, so existing PG/SQLite databases would
// reject INSERTs / UPDATEs that reference the new column.
func migrationAddVirtualKeyFallbackChainColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_fallback_chain_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasTable(&tables.TableVirtualKey{}) {
				return nil
			}
			if !mg.HasColumn(&tables.TableVirtualKey{}, "fallback_chain") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "FallbackChain"); err != nil {
					return fmt.Errorf("failed to add fallback_chain column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasTable(&tables.TableVirtualKey{}) && mg.HasColumn(&tables.TableVirtualKey{}, "fallback_chain") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "fallback_chain"); err != nil {
					return fmt.Errorf("failed to drop fallback_chain column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running virtual key fallback chain migration: %s", err.Error())
	}
	return nil
}

// migrationAddVirtualKeyCachePolicyColumns adds automatic cache policy columns to governance_virtual_keys.
func migrationAddVirtualKeyCachePolicyColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_cache_policy_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if !mg.HasColumn(&tables.TableVirtualKey{}, "cache_enabled") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "CacheEnabled"); err != nil {
					return fmt.Errorf("failed to add cache_enabled column: %w", err)
				}
			}
			if !mg.HasColumn(&tables.TableVirtualKey{}, "cache_scope_mode") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "CacheScopeMode"); err != nil {
					return fmt.Errorf("failed to add cache_scope_mode column: %w", err)
				}
			}
			if !mg.HasColumn(&tables.TableVirtualKey{}, "cache_metadata_scope_keys") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "CacheMetadataScopeKeys"); err != nil {
					return fmt.Errorf("failed to add cache_metadata_scope_keys column: %w", err)
				}
			}
			if !mg.HasColumn(&tables.TableVirtualKey{}, "cache_allow_semantic_when_unscoped") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "CacheAllowSemanticWhenUnscoped"); err != nil {
					return fmt.Errorf("failed to add cache_allow_semantic_when_unscoped column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if mg.HasColumn(&tables.TableVirtualKey{}, "cache_allow_semantic_when_unscoped") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "cache_allow_semantic_when_unscoped"); err != nil {
					return fmt.Errorf("failed to drop cache_allow_semantic_when_unscoped column: %w", err)
				}
			}
			if mg.HasColumn(&tables.TableVirtualKey{}, "cache_metadata_scope_keys") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "cache_metadata_scope_keys"); err != nil {
					return fmt.Errorf("failed to drop cache_metadata_scope_keys column: %w", err)
				}
			}
			if mg.HasColumn(&tables.TableVirtualKey{}, "cache_scope_mode") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "cache_scope_mode"); err != nil {
					return fmt.Errorf("failed to drop cache_scope_mode column: %w", err)
				}
			}
			if mg.HasColumn(&tables.TableVirtualKey{}, "cache_enabled") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "cache_enabled"); err != nil {
					return fmt.Errorf("failed to drop cache_enabled column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running virtual key cache policy migration: %s", err.Error())
	}
	return nil
}

func migrationAddVirtualKeyCacheKeyColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_cache_key_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasColumn(&tables.TableVirtualKey{}, "cache_key") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "CacheKey"); err != nil {
					return fmt.Errorf("failed to add cache_key column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasColumn(&tables.TableVirtualKey{}, "cache_key") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "cache_key"); err != nil {
					return fmt.Errorf("failed to drop cache_key column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running virtual key cache key migration: %s", err.Error())
	}
	return nil
}

func migrationAddVirtualKeySemanticCacheEnabledColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_virtual_key_semantic_cache_enabled_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasColumn(&tables.TableVirtualKey{}, "semantic_cache_enabled") {
				if err := mg.AddColumn(&tables.TableVirtualKey{}, "SemanticCacheEnabled"); err != nil {
					return fmt.Errorf("failed to add semantic_cache_enabled column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasColumn(&tables.TableVirtualKey{}, "semantic_cache_enabled") {
				if err := mg.DropColumn(&tables.TableVirtualKey{}, "semantic_cache_enabled"); err != nil {
					return fmt.Errorf("failed to drop semantic_cache_enabled column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running virtual key semantic cache migration: %s", err.Error())
	}
	return nil
}

// migrationAddHeaderFilterConfigJSONColumn adds the header_filter_config_json column to the config_client table
func migrationAddHeaderFilterConfigJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_header_filter_config_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if !mg.HasColumn(&tables.TableClientConfig{}, "header_filter_config_json") {
				if err := mg.AddColumn(&tables.TableClientConfig{}, "header_filter_config_json"); err != nil {
					return fmt.Errorf("failed to add header_filter_config_json column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if mg.HasColumn(&tables.TableClientConfig{}, "header_filter_config_json") {
				if err := mg.DropColumn(&tables.TableClientConfig{}, "header_filter_config_json"); err != nil {
					return fmt.Errorf("failed to drop header_filter_config_json column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running header_filter_config_json migration: %s", err.Error())
	}
	return nil
}

// migrationAddAzureClientIDAndClientSecretAndTenantIDColumns adds the azure_client_id, azure_client_secret, and azure_tenant_id columns to the key table
func migrationAddAzureClientIDAndClientSecretAndTenantIDColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_azure_client_id_and_client_secret_and_tenant_id_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "azure_client_id") {
				if err := migrator.AddColumn(&tables.TableKey{}, "azure_client_id"); err != nil {
					return fmt.Errorf("failed to add azure_client_id column: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableKey{}, "azure_client_secret") {
				if err := migrator.AddColumn(&tables.TableKey{}, "azure_client_secret"); err != nil {
					return fmt.Errorf("failed to add azure_client_secret column: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableKey{}, "azure_tenant_id") {
				if err := migrator.AddColumn(&tables.TableKey{}, "azure_tenant_id"); err != nil {
					return fmt.Errorf("failed to add azure_tenant_id column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableKey{}, "azure_client_id"); err != nil {
				return fmt.Errorf("failed to drop azure_client_id column: %w", err)
			}
			if err := migrator.DropColumn(&tables.TableKey{}, "azure_client_secret"); err != nil {
				return fmt.Errorf("failed to drop azure_client_secret column: %w", err)
			}
			if err := migrator.DropColumn(&tables.TableKey{}, "azure_tenant_id"); err != nil {
				return fmt.Errorf("failed to drop azure_tenant_id column: %w", err)
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running azure_client_id_and_client_secret_and_tenant_id migration: %s", err.Error())
	}
	return nil
}

func migrationAddToolPricingJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tool_pricing_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableMCPClient{}, "tool_pricing_json") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "tool_pricing_json"); err != nil {
					return fmt.Errorf("failed to add tool_pricing_json column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableMCPClient{}, "tool_pricing_json"); err != nil {
				return fmt.Errorf("failed to drop tool_pricing_json column: %w", err)
			}
			return nil
		},
	}})
	return m.Migrate()
}

// migrationRemoveServerPrefixFromMCPTools removes the server name prefix from tool names
// in tools_to_execute_json, tools_to_auto_execute_json, and tool_pricing_json columns
// in both config_mcp_clients and governance_virtual_key_mcp_configs tables.
//
// This migration converts:
//   - tools_to_execute_json: ["calculator_add", "calculator_subtract"] → ["add", "subtract"]
//   - tools_to_auto_execute_json: ["calculator_multiply"] → ["multiply"]
//   - tool_pricing_json: {"calculator_add": 0.001, "calculator_subtract": 0.001} → {"add": 0.001, "subtract": 0.001}
func migrationRemoveServerPrefixFromMCPTools(ctx context.Context, db *gorm.DB) error {
	// Helper function to check if a tool name has a prefix matching the client name
	// Handles both exact matches and legacy normalized forms
	hasClientPrefix := func(toolName, clientName string) (bool, string) {
		prefix := clientName + "_"
		if strings.HasPrefix(toolName, prefix) {
			return true, strings.TrimPrefix(toolName, prefix)
		}
		// Legacy prefix: normalize the substring before first underscore
		if idx := strings.IndexByte(toolName, '_'); idx > 0 {
			toolPrefix := toolName[:idx]
			unprefixed := toolName[idx+1:]
			if normalizeMCPClientName(toolPrefix) == clientName {
				return true, unprefixed
			}
		}
		return false, ""
	}

	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "remove_server_prefix_from_mcp_tools",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)

			// ============================================================
			// Step 1: Migrate config_mcp_clients table
			// ============================================================

			// Fetch all MCP clients
			var mcpClients []tables.TableMCPClient
			if err := tx.Find(&mcpClients).Error; err != nil {
				return fmt.Errorf("failed to fetch MCP clients: %w", err)
			}

			// Process each MCP client
			for i := range mcpClients {
				client := &mcpClients[i]
				clientName := client.Name
				needsUpdate := false

				// Process tools_to_execute_json
				var toolsToExecute []string
				if client.ToolsToExecuteJSON != "" && client.ToolsToExecuteJSON != "null" {
					if err := json.Unmarshal([]byte(client.ToolsToExecuteJSON), &toolsToExecute); err != nil {
						return fmt.Errorf("failed to unmarshal tools_to_execute_json for client %s: %w", clientName, err)
					}

					// Strip prefix from each tool
					updatedTools := make([]string, 0, len(toolsToExecute))
					seenTools := make(map[string]bool)
					for _, tool := range toolsToExecute {
						// Check if tool has client prefix (handles both current and legacy normalized forms)
						if hasPrefix, unprefixedTool := hasClientPrefix(tool, clientName); hasPrefix {
							// Check for collision: if unprefixed tool already exists in the list
							if seenTools[unprefixedTool] {
								log.Printf("Collision detected when stripping prefix from tool '%s' for client '%s': unprefixed name '%s' already exists. Keeping unprefixed value.", tool, clientName, unprefixedTool)
								needsUpdate = true
								continue
							}
							seenTools[unprefixedTool] = true
							updatedTools = append(updatedTools, unprefixedTool)
							needsUpdate = true
						} else {
							// Tool already unprefixed or is wildcard "*"
							if seenTools[tool] {
								log.Printf("Duplicate tool name '%s' found for client '%s'. Keeping first occurrence.", tool, clientName)
								continue
							}
							seenTools[tool] = true
							updatedTools = append(updatedTools, tool)
						}
					}

					// Update the JSON
					if needsUpdate {
						updatedJSON, err := json.Marshal(updatedTools)
						if err != nil {
							return fmt.Errorf("failed to marshal updated tools_to_execute for client %s: %w", clientName, err)
						}
						client.ToolsToExecuteJSON = string(updatedJSON)
					}
				}

				// Process tools_to_auto_execute_json
				var toolsToAutoExecute []string
				if client.ToolsToAutoExecuteJSON != "" && client.ToolsToAutoExecuteJSON != "null" {
					if err := json.Unmarshal([]byte(client.ToolsToAutoExecuteJSON), &toolsToAutoExecute); err != nil {
						return fmt.Errorf("failed to unmarshal tools_to_auto_execute_json for client %s: %w", clientName, err)
					}

					// Strip prefix from each tool
					updatedAutoTools := make([]string, 0, len(toolsToAutoExecute))
					seenAutoTools := make(map[string]bool)
					for _, tool := range toolsToAutoExecute {
						// Check if tool has client prefix (handles both current and legacy normalized forms)
						if hasPrefix, unprefixedTool := hasClientPrefix(tool, clientName); hasPrefix {
							// Check for collision: if unprefixed tool already exists in the list
							if seenAutoTools[unprefixedTool] {
								log.Printf("Collision detected when stripping prefix from auto-execute tool '%s' for client '%s': unprefixed name '%s' already exists. Keeping unprefixed value.", tool, clientName, unprefixedTool)
								needsUpdate = true
								continue
							}
							seenAutoTools[unprefixedTool] = true
							updatedAutoTools = append(updatedAutoTools, unprefixedTool)
							needsUpdate = true
						} else {
							// Tool already unprefixed or is wildcard "*"
							if seenAutoTools[tool] {
								log.Printf("Duplicate auto-execute tool name '%s' found for client '%s'. Keeping first occurrence.", tool, clientName)
								continue
							}
							seenAutoTools[tool] = true
							updatedAutoTools = append(updatedAutoTools, tool)
						}
					}

					// Update the JSON
					if needsUpdate {
						updatedJSON, err := json.Marshal(updatedAutoTools)
						if err != nil {
							return fmt.Errorf("failed to marshal updated tools_to_auto_execute for client %s: %w", clientName, err)
						}
						client.ToolsToAutoExecuteJSON = string(updatedJSON)
					}
				}

				// Process tool_pricing_json
				var toolPricing map[string]float64
				if client.ToolPricingJSON != "" && client.ToolPricingJSON != "null" {
					if err := json.Unmarshal([]byte(client.ToolPricingJSON), &toolPricing); err != nil {
						return fmt.Errorf("failed to unmarshal tool_pricing_json for client %s: %w", clientName, err)
					}

					// Strip prefix from each tool name key
					updatedPricing := make(map[string]float64)
					for toolName, price := range toolPricing {
						// Check if tool has client prefix (handles both current and legacy normalized forms)
						if hasPrefix, unprefixedTool := hasClientPrefix(toolName, clientName); hasPrefix {
							// Check for collision: if unprefixed key already exists
							if existingPrice, exists := updatedPricing[unprefixedTool]; exists {
								log.Printf("Collision detected when stripping prefix from pricing key '%s' for client '%s': unprefixed key '%s' already exists with price %.6f. Keeping existing unprefixed value (%.6f), discarding prefixed value (%.6f).", toolName, clientName, unprefixedTool, existingPrice, existingPrice, price)
								needsUpdate = true
								continue
							}
							updatedPricing[unprefixedTool] = price
							needsUpdate = true
						} else {
							// Check for collision: if unprefixed key already exists (from a previously processed prefixed entry)
							if existingPrice, exists := updatedPricing[toolName]; exists {
								log.Printf("Collision detected for pricing key '%s' for client '%s': key already exists with price %.6f. Keeping first value (%.6f), discarding duplicate (%.6f).", toolName, clientName, existingPrice, existingPrice, price)
								continue
							}
							updatedPricing[toolName] = price
						}
					}

					// Update the JSON
					if needsUpdate {
						updatedJSON, err := json.Marshal(updatedPricing)
						if err != nil {
							return fmt.Errorf("failed to marshal updated tool_pricing for client %s: %w", clientName, err)
						}
						client.ToolPricingJSON = string(updatedJSON)
					}
				}

				// Save the updated client if any changes were made
				if needsUpdate {
					// Use Model + Updates to ensure changes are persisted
					result := tx.Model(&tables.TableMCPClient{}).Where("id = ?", client.ID).Updates(map[string]interface{}{
						"tools_to_execute_json":      client.ToolsToExecuteJSON,
						"tools_to_auto_execute_json": client.ToolsToAutoExecuteJSON,
						"tool_pricing_json":          client.ToolPricingJSON,
					})

					if result.Error != nil {
						return fmt.Errorf("failed to save updated MCP client %s: %w", clientName, result.Error)
					}
				}
			}

			// ============================================================
			// Step 2: Migrate governance_virtual_key_mcp_configs table
			// ============================================================

			// Fetch all virtual key MCP configs with their associated MCP client
			var vkMCPConfigs []tables.TableVirtualKeyMCPConfig
			if err := tx.Preload("MCPClient").Find(&vkMCPConfigs).Error; err != nil {
				return fmt.Errorf("failed to fetch virtual key MCP configs: %w", err)
			}

			// Process each VK MCP config
			for i := range vkMCPConfigs {
				vkConfig := &vkMCPConfigs[i]
				if vkConfig.MCPClient.Name == "" {
					// Skip if MCP client is not loaded
					continue
				}

				clientName := vkConfig.MCPClient.Name
				needsUpdate := false

				// Process tools_to_execute (this is a JSON array stored in GORM's serializer format)
				if len(vkConfig.ToolsToExecute) > 0 {
					updatedTools := make([]string, 0, len(vkConfig.ToolsToExecute))
					seen := make(map[string]bool, len(vkConfig.ToolsToExecute))

					for _, tool := range vkConfig.ToolsToExecute {
						var finalTool string
						// Check if tool has client prefix (handles both current and legacy normalized forms)
						if hasPrefix, unprefixedTool := hasClientPrefix(tool, clientName); hasPrefix {
							finalTool = unprefixedTool
						} else {
							finalTool = tool
						}

						// Skip if we've already added this tool (collision detection)
						if !seen[finalTool] {
							seen[finalTool] = true
							updatedTools = append(updatedTools, finalTool)
						}
					}

					// Only update if the final list differs from the original
					needsUpdate = len(updatedTools) != len(vkConfig.ToolsToExecute)
					if !needsUpdate {
						// Check if any tools actually changed
						for j, tool := range vkConfig.ToolsToExecute {
							if tool != updatedTools[j] {
								needsUpdate = true
								break
							}
						}
					}

					if needsUpdate {
						vkConfig.ToolsToExecute = updatedTools
					}
				}

				// Save the updated VK config if any changes were made
				if needsUpdate {
					if err := tx.Save(vkConfig).Error; err != nil {
						return fmt.Errorf("failed to save updated VK MCP config ID %d: %w", vkConfig.ID, err)
					}
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			// Rollback is complex because we need to re-add the prefix
			// This requires knowing the client name for each tool
			tx = tx.WithContext(ctx)

			// ============================================================
			// Step 1: Rollback config_mcp_clients table
			// ============================================================

			var mcpClients []tables.TableMCPClient
			if err := tx.Find(&mcpClients).Error; err != nil {
				return fmt.Errorf("failed to fetch MCP clients for rollback: %w", err)
			}

			for _, client := range mcpClients {
				clientName := client.Name
				needsUpdate := false

				// Rollback tools_to_execute_json
				var toolsToExecute []string
				if client.ToolsToExecuteJSON != "" && client.ToolsToExecuteJSON != "null" {
					if err := json.Unmarshal([]byte(client.ToolsToExecuteJSON), &toolsToExecute); err != nil {
						return fmt.Errorf("failed to unmarshal tools_to_execute_json for rollback: %w", err)
					}

					prefixedTools := make([]string, 0, len(toolsToExecute))
					for _, tool := range toolsToExecute {
						// Skip wildcard
						if tool == "*" {
							prefixedTools = append(prefixedTools, tool)
							continue
						}
						// Add prefix if not already present
						prefix := clientName + "_"
						if !strings.HasPrefix(tool, prefix) {
							prefixedTools = append(prefixedTools, prefix+tool)
							needsUpdate = true
						} else {
							prefixedTools = append(prefixedTools, tool)
						}
					}

					if needsUpdate {
						updatedJSON, err := json.Marshal(prefixedTools)
						if err != nil {
							return fmt.Errorf("failed to marshal rollback tools_to_execute: %w", err)
						}
						client.ToolsToExecuteJSON = string(updatedJSON)
					}
				}

				// Rollback tools_to_auto_execute_json
				var toolsToAutoExecute []string
				if client.ToolsToAutoExecuteJSON != "" && client.ToolsToAutoExecuteJSON != "null" {
					if err := json.Unmarshal([]byte(client.ToolsToAutoExecuteJSON), &toolsToAutoExecute); err != nil {
						return fmt.Errorf("failed to unmarshal tools_to_auto_execute_json for rollback: %w", err)
					}

					prefixedAutoTools := make([]string, 0, len(toolsToAutoExecute))
					for _, tool := range toolsToAutoExecute {
						if tool == "*" {
							prefixedAutoTools = append(prefixedAutoTools, tool)
							continue
						}
						prefix := clientName + "_"
						if !strings.HasPrefix(tool, prefix) {
							prefixedAutoTools = append(prefixedAutoTools, prefix+tool)
							needsUpdate = true
						} else {
							prefixedAutoTools = append(prefixedAutoTools, tool)
						}
					}

					if needsUpdate {
						updatedJSON, err := json.Marshal(prefixedAutoTools)
						if err != nil {
							return fmt.Errorf("failed to marshal rollback tools_to_auto_execute: %w", err)
						}
						client.ToolsToAutoExecuteJSON = string(updatedJSON)
					}
				}

				// Rollback tool_pricing_json
				var toolPricing map[string]float64
				if client.ToolPricingJSON != "" && client.ToolPricingJSON != "null" {
					if err := json.Unmarshal([]byte(client.ToolPricingJSON), &toolPricing); err != nil {
						return fmt.Errorf("failed to unmarshal tool_pricing_json for rollback: %w", err)
					}

					prefixedPricing := make(map[string]float64)
					for toolName, price := range toolPricing {
						prefix := clientName + "_"
						if !strings.HasPrefix(toolName, prefix) {
							prefixedPricing[prefix+toolName] = price
							needsUpdate = true
						} else {
							prefixedPricing[toolName] = price
						}
					}

					if needsUpdate {
						updatedJSON, err := json.Marshal(prefixedPricing)
						if err != nil {
							return fmt.Errorf("failed to marshal rollback tool_pricing: %w", err)
						}
						client.ToolPricingJSON = string(updatedJSON)
					}
				}

				if needsUpdate {
					if err := tx.Save(&client).Error; err != nil {
						return fmt.Errorf("failed to save rollback MCP client: %w", err)
					}
				}
			}

			// ============================================================
			// Step 2: Rollback governance_virtual_key_mcp_configs table
			// ============================================================

			var vkMCPConfigs []tables.TableVirtualKeyMCPConfig
			if err := tx.Preload("MCPClient").Find(&vkMCPConfigs).Error; err != nil {
				return fmt.Errorf("failed to fetch virtual key MCP configs for rollback: %w", err)
			}

			for _, vkConfig := range vkMCPConfigs {
				if vkConfig.MCPClient.Name == "" {
					continue
				}

				clientName := vkConfig.MCPClient.Name
				needsUpdate := false

				if len(vkConfig.ToolsToExecute) > 0 {
					prefixedTools := make([]string, 0, len(vkConfig.ToolsToExecute))
					for _, tool := range vkConfig.ToolsToExecute {
						if tool == "*" {
							prefixedTools = append(prefixedTools, tool)
							continue
						}
						prefix := clientName + "_"
						if !strings.HasPrefix(tool, prefix) {
							prefixedTools = append(prefixedTools, prefix+tool)
							needsUpdate = true
						} else {
							prefixedTools = append(prefixedTools, tool)
						}
					}

					if needsUpdate {
						vkConfig.ToolsToExecute = prefixedTools
					}
				}

				if needsUpdate {
					if err := tx.Save(&vkConfig).Error; err != nil {
						return fmt.Errorf("failed to save rollback VK MCP config: %w", err)
					}
				}
			}

			return nil
		},
	}})

	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running migration to remove server prefix from MCP tools: %s", err.Error())
	}
	return nil
}

// migrationAddDistributedLocksTable adds the distributed_locks table for distributed locking
func migrationAddDistributedLocksTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_distributed_locks_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// Use raw SQL with IF NOT EXISTS for atomic, race-condition-safe table creation
			createTableSQL := `
				CREATE TABLE IF NOT EXISTS distributed_locks (
					lock_key VARCHAR(255) PRIMARY KEY,
					holder_id VARCHAR(255) NOT NULL,
					expires_at TIMESTAMP NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			`
			if err := tx.Exec(createTableSQL).Error; err != nil {
				return fmt.Errorf("failed to create distributed_locks table: %w", err)
			}
			// Create index on expires_at for efficient cleanup queries
			createIndexSQL := `CREATE INDEX IF NOT EXISTS idx_distributed_locks_expires_at ON distributed_locks (expires_at)`
			if err := tx.Exec(createIndexSQL).Error; err != nil {
				return fmt.Errorf("failed to create expires_at index: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.Exec("DROP TABLE IF EXISTS distributed_locks").Error; err != nil {
				return fmt.Errorf("failed to drop distributed_locks table: %w", err)
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running distributed_locks table migration: %s", err.Error())
	}
	return nil
}

// migrationAddModelConfigTable adds the governance_model_configs table
func migrationAddModelConfigTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_model_config_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableModelConfig{}) {
				if err := migrator.CreateTable(&tables.TableModelConfig{}); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropTable(&tables.TableModelConfig{}); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add model config table migration: %s", err.Error())
	}
	return nil
}

// migrationAddProviderGovernanceColumns adds budget_id and rate_limit_id columns to config_providers table
func migrationAddProviderGovernanceColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_provider_governance_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			provider := &tables.TableProvider{}

			// Add budget_id column if it doesn't exist
			if !migrator.HasColumn(provider, "budget_id") {
				if err := migrator.AddColumn(provider, "budget_id"); err != nil {
					return fmt.Errorf("failed to add budget_id column: %w", err)
				}
			}
			// Create index for budget_id (outside HasColumn to handle reruns where column exists but index doesn't)
			if !migrator.HasIndex(provider, "idx_provider_budget") {
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_provider_budget ON config_providers (budget_id)").Error; err != nil {
					return fmt.Errorf("failed to create budget_id index: %w", err)
				}
			}

			// Add rate_limit_id column if it doesn't exist
			if !migrator.HasColumn(provider, "rate_limit_id") {
				if err := migrator.AddColumn(provider, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to add rate_limit_id column: %w", err)
				}
			}
			// Create index for rate_limit_id (outside HasColumn to handle reruns where column exists but index doesn't)
			if !migrator.HasIndex(provider, "idx_provider_rate_limit") {
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_provider_rate_limit ON config_providers (rate_limit_id)").Error; err != nil {
					return fmt.Errorf("failed to create rate_limit_id index: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			provider := &tables.TableProvider{}

			// Drop indexes first
			if migrator.HasIndex(provider, "idx_provider_rate_limit") {
				if err := tx.Exec("DROP INDEX IF EXISTS idx_provider_rate_limit").Error; err != nil {
					return fmt.Errorf("failed to drop rate_limit_id index: %w", err)
				}
			}

			if migrator.HasIndex(provider, "idx_provider_budget") {
				if err := tx.Exec("DROP INDEX IF EXISTS idx_provider_budget").Error; err != nil {
					return fmt.Errorf("failed to drop budget_id index: %w", err)
				}
			}

			// Drop rate_limit_id column if it exists
			if migrator.HasColumn(provider, "rate_limit_id") {
				if err := migrator.DropColumn(provider, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to drop rate_limit_id column: %w", err)
				}
			}

			// Drop budget_id column if it exists
			if migrator.HasColumn(provider, "budget_id") {
				if err := migrator.DropColumn(provider, "budget_id"); err != nil {
					return fmt.Errorf("failed to drop budget_id column: %w", err)
				}
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running add provider governance columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddAllowedHeadersJSONColumn adds the allowed_headers_json column to the client config table
func migrationAddAllowedHeadersJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_allowed_headers_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "allowed_headers_json") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "allowed_headers_json"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableClientConfig{}, "allowed_headers_json") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "allowed_headers_json"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddDisableDBPingsInHealthColumn adds the disable_db_pings_in_health column to the client config table
func migrationAddDisableDBPingsInHealthColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_disable_db_pings_in_health_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "disable_db_pings_in_health") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "disable_db_pings_in_health"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableClientConfig{}, "disable_db_pings_in_health") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "disable_db_pings_in_health"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running db migration: %s", err.Error())
	}
	return nil
}

// migrationAddIsPingAvailableColumnToMCPClientTable adds the is_ping_available column to the config_mcp_clients table
func migrationAddIsPingAvailableColumnToMCPClientTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_is_ping_available_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableMCPClient{}, "is_ping_available") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "is_ping_available"); err != nil {
					return err
				}
				// Set default value for existing rows
				if err := tx.Model(&tables.TableMCPClient{}).Where("is_ping_available IS NULL").Update("is_ping_available", true).Error; err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableMCPClient{}, "is_ping_available") {
				if err := migrator.DropColumn(&tables.TableMCPClient{}, "is_ping_available"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running is_ping_available migration: %s", err.Error())
	}
	return nil
}

// migrationAddTunnelCertsTable creates governance_tunnel_certs, the issuance
// ledger for Enterprise-VPC tunnel client certificates minted by the
// control-plane CA (framework/tunnelpki).
func migrationAddTunnelCertsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_governance_tunnel_certs_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableTunnelCert{}) {
				if err := migrator.CreateTable(&tables.TableTunnelCert{}); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropTable(&tables.TableTunnelCert{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running governance_tunnel_certs migration: %s", err.Error())
	}
	return nil
}

// migrationAddTenantAliasesTable creates tenant_aliases, the email→canonical
// (UUID) tenant index used to decouple tenant identity from a personal email.
func migrationAddTenantAliasesTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tenant_aliases_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableTenantAlias{}) {
				if err := migrator.CreateTable(&tables.TableTenantAlias{}); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.Migrator().DropTable(&tables.TableTenantAlias{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running tenant_aliases migration: %s", err.Error())
	}
	return nil
}

// migrationAddRoutingRulesTable adds the routing rules table for intelligent request routing
func migrationAddRoutingRulesTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_routing_rules_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasTable(&tables.TableRoutingRule{}) {
				if err := migrator.CreateTable(&tables.TableRoutingRule{}); err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if err := migrator.DropTable(&tables.TableRoutingRule{}); err != nil {
				return err
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running routing_rules_table migration: %s", err.Error())
	}
	return nil
}

// migrationAddOAuthTables creates the oauth_configs and oauth_tokens tables
func migrationAddOAuthTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_oauth_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			// Create oauth_configs table FIRST (before adding FK columns that reference it)
			if !migrator.HasTable(&tables.TableOauthConfig{}) {
				if err := migrator.CreateTable(&tables.TableOauthConfig{}); err != nil {
					return fmt.Errorf("failed to create oauth_configs table: %w", err)
				}
			}
			// Create oauth_tokens table
			if !migrator.HasTable(&tables.TableOauthToken{}) {
				if err := migrator.CreateTable(&tables.TableOauthToken{}); err != nil {
					return fmt.Errorf("failed to create oauth_tokens table: %w", err)
				}
			}
			// IF MCPClient table is not present, create it first
			if !migrator.HasTable(&tables.TableMCPClient{}) {
				if err := migrator.CreateTable(&tables.TableMCPClient{}); err != nil {
					return fmt.Errorf("failed to create mcp_clients table: %w", err)
				}
			}
			// Now update MCPClient table to add auth_type, oauth_config_id columns
			// (oauth_config_id has FK constraint to oauth_configs table created above)
			if !migrator.HasColumn(&tables.TableMCPClient{}, "auth_type") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "auth_type"); err != nil {
					return fmt.Errorf("failed to add auth_type column: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableMCPClient{}, "oauth_config_id") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "oauth_config_id"); err != nil {
					return fmt.Errorf("failed to add oauth_config_id column: %w", err)
				}
			}
			// Set default value for auth_type column
			if err := tx.Model(&tables.TableMCPClient{}).Where("auth_type IS NULL").Update("auth_type", "headers").Error; err != nil {
				return err
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Drop tables in reverse order
			if migrator.HasTable(&tables.TableOauthToken{}) {
				if err := migrator.DropTable(&tables.TableOauthToken{}); err != nil {
					return fmt.Errorf("failed to drop oauth_tokens table: %w", err)
				}
			}

			if migrator.HasTable(&tables.TableOauthConfig{}) {
				if err := migrator.DropTable(&tables.TableOauthConfig{}); err != nil {
					return fmt.Errorf("failed to drop oauth_configs table: %w", err)
				}
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running oauth tables migration: %s", err.Error())
	}
	return nil
}

func migrationAddSCIMProviderConfigsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_scim_provider_configs_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableSCIMProviderConfig{}) {
				if err := migrator.CreateTable(&tables.TableSCIMProviderConfig{}); err != nil {
					return fmt.Errorf("failed to create scim_provider_configs table: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasTable(&tables.TableSCIMProviderConfig{}) {
				if err := migrator.DropTable(&tables.TableSCIMProviderConfig{}); err != nil {
					return fmt.Errorf("failed to drop scim_provider_configs table: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running scim_provider_configs migration: %s", err.Error())
	}
	return nil
}

func migrationExpandSCIMProviderConfigsForMultiConnection(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "expand_scim_provider_configs_for_multi_connection",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableSCIMProviderConfig{}, "name") {
				if err := migrator.AddColumn(&tables.TableSCIMProviderConfig{}, "name"); err != nil {
					return fmt.Errorf("failed to add scim_provider_configs.name: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableSCIMProviderConfig{}, "customer_id") {
				if err := migrator.AddColumn(&tables.TableSCIMProviderConfig{}, "customer_id"); err != nil {
					return fmt.Errorf("failed to add scim_provider_configs.customer_id: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableSCIMProviderConfig{}, "is_default") {
				if err := migrator.AddColumn(&tables.TableSCIMProviderConfig{}, "is_default"); err != nil {
					return fmt.Errorf("failed to add scim_provider_configs.is_default: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableSCIMProviderConfig{}, "email_domains_json") {
				if err := migrator.AddColumn(&tables.TableSCIMProviderConfig{}, "email_domains_json"); err != nil {
					return fmt.Errorf("failed to add scim_provider_configs.email_domains_json: %w", err)
				}
			}

			if migrator.HasIndex(&tables.TableSCIMProviderConfig{}, "idx_scim_provider_tenant_provider") {
				if err := migrator.DropIndex(&tables.TableSCIMProviderConfig{}, "idx_scim_provider_tenant_provider"); err != nil {
					return fmt.Errorf("failed to drop unique SCIM provider tenant/provider index: %w", err)
				}
			}
			if err := tx.Exec("UPDATE scim_provider_configs SET name = COALESCE(NULLIF(name, ''), 'Microsoft Entra')").Error; err != nil {
				return fmt.Errorf("failed to backfill scim provider names: %w", err)
			}
			var configs []tables.TableSCIMProviderConfig
			if err := tx.
				Model(&tables.TableSCIMProviderConfig{}).
				Order("tenant_id ASC, created_at ASC, id ASC").
				Find(&configs).Error; err != nil {
				return fmt.Errorf("failed to load scim provider configs for default backfill: %w", err)
			}

			tenantsWithDefault := make(map[string]struct{}, len(configs))
			firstConfigByTenant := make(map[string]string, len(configs))
			for _, config := range configs {
				if _, ok := firstConfigByTenant[config.TenantID]; !ok {
					firstConfigByTenant[config.TenantID] = config.ID
				}
				if config.IsDefault {
					tenantsWithDefault[config.TenantID] = struct{}{}
				}
			}
			for tenantID, configID := range firstConfigByTenant {
				if _, ok := tenantsWithDefault[tenantID]; ok {
					continue
				}
				if err := tx.
					Model(&tables.TableSCIMProviderConfig{}).
					Where("tenant_id = ? AND id = ?", tenantID, configID).
					Update("is_default", true).Error; err != nil {
					return fmt.Errorf("failed to backfill scim provider defaults: %w", err)
				}
			}
			if !migrator.HasIndex(&tables.TableSCIMProviderConfig{}, "idx_scim_provider_tenant_customer") {
				if err := migrator.CreateIndex(&tables.TableSCIMProviderConfig{}, "idx_scim_provider_tenant_customer"); err != nil {
					return fmt.Errorf("failed to create scim_provider_configs tenant/customer index: %w", err)
				}
			}
			if !migrator.HasTable(&tables.TableSCIMLoginState{}) {
				if err := migrator.CreateTable(&tables.TableSCIMLoginState{}); err != nil {
					return fmt.Errorf("failed to create scim_login_states table: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableAuthUser{}, "customer_id") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "customer_id"); err != nil {
					return fmt.Errorf("failed to add auth_users.customer_id: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableAuthUser{}, "entra_subject") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "entra_subject"); err != nil {
					return fmt.Errorf("failed to add auth_users.entra_subject: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableAuthUser{}, "entra_connection_id") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "entra_connection_id"); err != nil {
					return fmt.Errorf("failed to add auth_users.entra_connection_id: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableAuthUser{}, "entra_identity_key") {
				if err := migrator.AddColumn(&tables.TableAuthUser{}, "entra_identity_key"); err != nil {
					return fmt.Errorf("failed to add auth_users.entra_identity_key: %w", err)
				}
			}
			if !migrator.HasIndex(&tables.TableAuthUser{}, "idx_auth_users_entra_identity_key") {
				if err := migrator.CreateIndex(&tables.TableAuthUser{}, "EntraIdentityKey"); err != nil {
					return fmt.Errorf("failed to create auth_users entra identity index: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while expanding scim provider configs: %s", err.Error())
	}
	return nil
}

// migrationAddToolSyncIntervalColumns adds the tool_sync_interval columns to config_client and config_mcp_clients tables
func migrationAddToolSyncIntervalColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tool_sync_interval_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			// Add mcp_tool_sync_interval column to config_client table (global setting)
			if !migrator.HasColumn(&tables.TableClientConfig{}, "mcp_tool_sync_interval") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "mcp_tool_sync_interval"); err != nil {
					return err
				}
			}
			// Add tool_sync_interval column to config_mcp_clients table (per-client setting)
			if !migrator.HasColumn(&tables.TableMCPClient{}, "tool_sync_interval") {
				if err := migrator.AddColumn(&tables.TableMCPClient{}, "tool_sync_interval"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if err := migrator.DropColumn(&tables.TableClientConfig{}, "mcp_tool_sync_interval"); err != nil {
				return err
			}
			if err := migrator.DropColumn(&tables.TableMCPClient{}, "tool_sync_interval"); err != nil {
				return err
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running tool sync interval migration: %s", err.Error())
	}
	return nil
}

// migrationAddMCPClientConfigToOAuthConfig adds the mcp_client_config_json column to oauth_configs table
// This enables multi-instance support by storing pending MCP client config in the database
// instead of in-memory, so OAuth callbacks can be handled by any server instance
func migrationAddMCPClientConfigToOAuthConfig(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_mcp_client_config_to_oauth_config",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableOauthConfig{}, "mcp_client_config_json") {
				if err := migrator.AddColumn(&tables.TableOauthConfig{}, "mcp_client_config_json"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableOauthConfig{}, "mcp_client_config_json") {
				if err := migrator.DropColumn(&tables.TableOauthConfig{}, "mcp_client_config_json"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running mcp client config oauth migration: %s", err.Error())
	}
	return nil
}

// migrationAddBaseModelPricingColumn adds the base_model column to the model_pricing table
func migrationAddBaseModelPricingColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_base_model_pricing_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableModelPricing{}, "base_model") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "base_model"); err != nil {
					return fmt.Errorf("failed to add column base_model: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableModelPricing{}, "base_model") {
				if err := migrator.DropColumn(&tables.TableModelPricing{}, "base_model"); err != nil {
					return fmt.Errorf("failed to drop column base_model: %w", err)
				}
			}
			return nil
		},
	}})
	return m.Migrate()
}

// migrationAddAzureScopesColumn adds the azure_scopes column to the key table for Entra ID OAuth scopes
func migrationAddAzureScopesColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_azure_scopes_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "azure_scopes") {
				if err := migrator.AddColumn(&tables.TableKey{}, "azure_scopes"); err != nil {
					return fmt.Errorf("failed to add azure_scopes column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableKey{}, "azure_scopes") {
				if err := migrator.DropColumn(&tables.TableKey{}, "azure_scopes"); err != nil {
					return fmt.Errorf("failed to drop azure_scopes column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running azure_scopes migration: %s", err.Error())
	}
	return nil
}

// migrationAddReplicateDeploymentsJSONColumn adds the replicate_deployments_json column to the key table
func migrationAddReplicateDeploymentsJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_replicate_deployments_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "replicate_deployments_json") {
				if err := migrator.AddColumn(&tables.TableKey{}, "replicate_deployments_json"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if err := migrator.DropColumn(&tables.TableKey{}, "replicate_deployments_json"); err != nil {
				return err
			}
			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running replicate deployments JSON migration: %s", err.Error())
	}
	return nil
}

// migrationAddKeyStatusColumns adds status and description columns to config_keys table
// These columns track the status and description of each individual key
func migrationAddKeyStatusColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_key_status_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Add status column
			if !migrator.HasColumn(&tables.TableKey{}, "status") {
				if err := migrator.AddColumn(&tables.TableKey{}, "status"); err != nil {
					return err
				}
			}

			// Add description column
			if !migrator.HasColumn(&tables.TableKey{}, "description") {
				if err := migrator.AddColumn(&tables.TableKey{}, "description"); err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Drop description column
			if migrator.HasColumn(&tables.TableKey{}, "description") {
				if err := migrator.DropColumn(&tables.TableKey{}, "description"); err != nil {
					return err
				}
			}

			// Drop status column
			if migrator.HasColumn(&tables.TableKey{}, "status") {
				if err := migrator.DropColumn(&tables.TableKey{}, "status"); err != nil {
					return err
				}
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running key model discovery status migration: %s", err.Error())
	}
	return nil
}

// migrationAddProviderStatusColumns adds status and description columns to config_providers table
// These columns track the status of model discovery attempts for keyless providers
func migrationAddProviderStatusColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_provider_status_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Add status column
			if !migrator.HasColumn(&tables.TableProvider{}, "status") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "status"); err != nil {
					return err
				}
			}

			// Add description column
			if !migrator.HasColumn(&tables.TableProvider{}, "description") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "description"); err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Drop description column
			if migrator.HasColumn(&tables.TableProvider{}, "description") {
				if err := migrator.DropColumn(&tables.TableProvider{}, "description"); err != nil {
					return err
				}
			}

			// Drop status column
			if migrator.HasColumn(&tables.TableProvider{}, "status") {
				if err := migrator.DropColumn(&tables.TableProvider{}, "status"); err != nil {
					return err
				}
			}

			return nil
		},
	}})
	err := m.Migrate()
	if err != nil {
		return fmt.Errorf("error while running provider model discovery status migration: %s", err.Error())
	}
	return nil
}

// migrationAddAsyncJobResultTTLColumn adds async_job_result_ttl column to config_client table
func migrationAddAsyncJobResultTTLColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_async_job_result_ttl_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableClientConfig{}, "async_job_result_ttl") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "AsyncJobResultTTL"); err != nil {
					return fmt.Errorf("failed to add async_job_result_ttl column: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TableClientConfig{}, "async_job_result_ttl") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "async_job_result_ttl"); err != nil {
					return fmt.Errorf("failed to drop async_job_result_ttl column: %w", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running async_job_result_ttl migration: %s", err.Error())
	}
	return nil
}

// migrationAddRateLimitToTeamsAndCustomers adds rate_limit_id column to governance_teams and governance_customers tables
func migrationAddRateLimitToTeamsAndCustomers(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_rate_limit_to_teams_and_customers",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Add rate_limit_id to governance_teams table
			if !migrator.HasColumn(&tables.TableTeam{}, "rate_limit_id") {
				if err := migrator.AddColumn(&tables.TableTeam{}, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to add rate_limit_id column to teams: %w", err)
				}
			}

			// Add rate_limit_id to governance_customers table
			if !migrator.HasColumn(&tables.TableCustomer{}, "rate_limit_id") {
				if err := migrator.AddColumn(&tables.TableCustomer{}, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to add rate_limit_id column to customers: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TableTeam{}, "rate_limit_id") {
				if err := migrator.DropColumn(&tables.TableTeam{}, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to drop rate_limit_id column from teams: %w", err)
				}
			}

			if migrator.HasColumn(&tables.TableCustomer{}, "rate_limit_id") {
				if err := migrator.DropColumn(&tables.TableCustomer{}, "rate_limit_id"); err != nil {
					return fmt.Errorf("failed to drop rate_limit_id column from customers: %w", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running rate limit migration for teams and customers: %s", err.Error())
	}
	return nil
}

// migrationAddRequiredHeadersJSONColumn adds the required_headers_json column to the config_client table
func migrationAddRequiredHeadersJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_required_headers_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableClientConfig{}, "required_headers_json") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "RequiredHeadersJSON"); err != nil {
					return fmt.Errorf("failed to add required_headers_json column: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TableClientConfig{}, "required_headers_json") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "required_headers_json"); err != nil {
					return fmt.Errorf("failed to drop required_headers_json column: %w", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running required_headers_json migration: %s", err.Error())
	}
	return nil
}

// migrationAddOutputCostPerVideoPerSecond adds output_cost_per_video_per_second column to governance_model_pricing table
func migrationAddOutputCostPerVideoPerSecond(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_output_cost_per_video_per_second_and_output_cost_per_second_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableModelPricing{}, "output_cost_per_video_per_second") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "output_cost_per_video_per_second"); err != nil {
					return fmt.Errorf("failed to add output_cost_per_video_per_second column: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TableModelPricing{}, "output_cost_per_second") {
				if err := migrator.AddColumn(&tables.TableModelPricing{}, "output_cost_per_second"); err != nil {
					return fmt.Errorf("failed to add output_cost_per_second column: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TableModelPricing{}, "output_cost_per_video_per_second") {
				if err := migrator.DropColumn(&tables.TableModelPricing{}, "output_cost_per_video_per_second"); err != nil {
					return fmt.Errorf("failed to drop output_cost_per_video_per_second column: %w", err)
				}
			}

			if migrator.HasColumn(&tables.TableModelPricing{}, "output_cost_per_second") {
				if err := migrator.DropColumn(&tables.TableModelPricing{}, "output_cost_per_second"); err != nil {
					return fmt.Errorf("failed to drop output_cost_per_second column: %w", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running output_cost_per_video_per_second migration: %s", err.Error())
	}
	return nil
}

// migrationAddLoggingHeadersJSONColumn adds the logging_headers_json column to the config_client table
func migrationAddLoggingHeadersJSONColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_logging_headers_json_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableClientConfig{}, "logging_headers_json") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "LoggingHeadersJSON"); err != nil {
					return fmt.Errorf("failed to add logging_headers_json column: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TableClientConfig{}, "logging_headers_json") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "logging_headers_json"); err != nil {
					return fmt.Errorf("failed to drop logging_headers_json column: %w", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running logging_headers_json migration: %s", err.Error())
	}
	return nil
}

// migrationAddHideDeletedVirtualKeysInFiltersColumn adds the hide_deleted_virtual_keys_in_filters column to config_client.
func migrationAddHideDeletedVirtualKeysInFiltersColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_hide_deleted_virtual_keys_in_filters_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TableClientConfig{}, "hide_deleted_virtual_keys_in_filters") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "HideDeletedVirtualKeysInFilters"); err != nil {
					return fmt.Errorf("failed to add hide_deleted_virtual_keys_in_filters column: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TableClientConfig{}, "hide_deleted_virtual_keys_in_filters") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "hide_deleted_virtual_keys_in_filters"); err != nil {
					return fmt.Errorf("failed to drop hide_deleted_virtual_keys_in_filters column: %w", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running hide_deleted_virtual_keys_in_filters migration: %s", err.Error())
	}
	return nil
}

// migrationAddEnforceSCIMAuthColumn adds the enforce_scim_auth column to the client config table
func migrationAddEnforceSCIMAuthColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_enforce_scim_auth_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "enforce_scim_auth") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "enforce_scim_auth"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableClientConfig{}, "enforce_scim_auth") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "enforce_scim_auth"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running enforce SCIM auth column migration: %s", err.Error())
	}
	return nil
}

// migrationAddEnforceAuthOnInferenceColumn adds the enforce_auth_on_inference column to the config_client table
func migrationAddEnforceAuthOnInferenceColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_enforce_auth_on_inference_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableClientConfig{}, "enforce_auth_on_inference") {
				if err := migrator.AddColumn(&tables.TableClientConfig{}, "enforce_auth_on_inference"); err != nil {
					return err
				}
			}
			// Populate from old fields: set to true if either old flag was true
			if err := tx.Exec("UPDATE config_client SET enforce_auth_on_inference = true WHERE enforce_governance_header = true OR enforce_scim_auth = true").Error; err != nil {
				return err
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableClientConfig{}, "enforce_auth_on_inference") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "enforce_auth_on_inference"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running enforce auth on inference column migration: %s", err.Error())
	}
	return nil
}

// migrationAddProviderPricingOverridesColumn adds the pricing_overrides_json column to the config_provider table
func migrationAddProviderPricingOverridesColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_provider_pricing_overrides_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableProvider{}, "pricing_overrides_json") {
				if err := migrator.AddColumn(&tables.TableProvider{}, "PricingOverridesJSON"); err != nil {
					return fmt.Errorf("failed to add pricing_overrides_json column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableProvider{}, "pricing_overrides_json") {
				if err := migrator.DropColumn(&tables.TableProvider{}, "pricing_overrides_json"); err != nil {
					return fmt.Errorf("failed to drop pricing_overrides_json column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running provider pricing overrides column migration: %s", err.Error())
	}
	return nil
}

// migrationAddEncryptionColumns adds the encryption_status column to the config_keys, governance_virtual_keys, sessions, oauth_configs, oauth_tokens, config_mcp_clients, config_providers, config_vector_store, and config_plugins tables
func migrationAddEncryptionColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_encryption_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mgr := tx.Migrator()

			type encryptionTable struct {
				table   interface{}
				columns []string
			}

			targets := []encryptionTable{
				{&tables.TableKey{}, []string{"encryption_status"}},
				{&tables.TableVirtualKey{}, []string{"encryption_status", "value_hash"}},
				{&tables.SessionsTable{}, []string{"encryption_status", "token_hash"}},
				{&tables.TableOauthConfig{}, []string{"encryption_status"}},
				{&tables.TableOauthToken{}, []string{"encryption_status"}},
				{&tables.TableMCPClient{}, []string{"encryption_status"}},
				{&tables.TableProvider{}, []string{"encryption_status"}},
				{&tables.TableVectorStoreConfig{}, []string{"encryption_status"}},
				{&tables.TablePlugin{}, []string{"encryption_status"}},
			}

			for _, t := range targets {
				for _, col := range t.columns {
					if !mgr.HasColumn(t.table, col) {
						if err := mgr.AddColumn(t.table, col); err != nil {
							return fmt.Errorf("failed to add column %s: %w", col, err)
						}
					}
				}
			}

			// Backfill encryption_status for all tables that have the column
			backfillTables := []string{
				"config_keys",
				"governance_virtual_keys",
				"sessions",
				"oauth_configs",
				"oauth_tokens",
				"config_mcp_clients",
				"config_providers",
				"config_vector_store",
				"config_plugins",
			}
			for _, table := range backfillTables {
				if err := tx.Exec(fmt.Sprintf(
					"UPDATE %s SET encryption_status = 'plain_text' WHERE encryption_status IS NULL OR encryption_status = ''",
					table,
				)).Error; err != nil {
					return fmt.Errorf("failed to backfill encryption_status in %s: %w", table, err)
				}
			}

			// Backfill value_hash for existing virtual keys
			// Use NULL instead of '' to avoid unique constraint violations
			// (multiple rows with '' would violate the unique index, but NULLs are excluded)
			if err := tx.Exec(`
				UPDATE governance_virtual_keys
				SET value_hash = NULL
				WHERE value_hash IS NULL OR value_hash = ''
			`).Error; err != nil {
				return fmt.Errorf("failed to initialize value_hash: %w", err)
			}

			// Backfill token_hash for existing sessions
			// Use NULL instead of '' to avoid unique constraint violations
			if err := tx.Exec(`
				UPDATE sessions
				SET token_hash = NULL
				WHERE token_hash IS NULL OR token_hash = ''
			`).Error; err != nil {
				return fmt.Errorf("failed to initialize token_hash: %w", err)
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mgr := tx.Migrator()

			type dropInfo struct {
				table   interface{}
				columns []string
			}

			drops := []dropInfo{
				{&tables.TableKey{}, []string{"encryption_status"}},
				{&tables.TableVirtualKey{}, []string{"encryption_status", "value_hash"}},
				{&tables.SessionsTable{}, []string{"encryption_status", "token_hash"}},
				{&tables.TableOauthConfig{}, []string{"encryption_status"}},
				{&tables.TableOauthToken{}, []string{"encryption_status"}},
				{&tables.TableMCPClient{}, []string{"encryption_status"}},
				{&tables.TableProvider{}, []string{"encryption_status"}},
				{&tables.TableVectorStoreConfig{}, []string{"encryption_status"}},
				{&tables.TablePlugin{}, []string{"encryption_status"}},
			}

			for _, d := range drops {
				for _, col := range d.columns {
					if mgr.HasColumn(d.table, col) {
						if err := mgr.DropColumn(d.table, col); err != nil {
							return err
						}
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running encryption columns migration: %s", err.Error())
	}
	return nil
}

// migrationDropEnableGovernanceColumn drops the enable_governance column from the config_client table
func migrationDropEnableGovernanceColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "drop_enable_governance_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableClientConfig{}, "enable_governance") {
				if err := migrator.DropColumn(&tables.TableClientConfig{}, "enable_governance"); err != nil {
					return fmt.Errorf("failed to drop enable_governance column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running drop enable governance column rollback: %s", err.Error())
	}
	return nil
}

// migrationAddVLLMKeyConfigColumns adds vllm_url and vllm_model_name columns to the key table
func migrationAddVLLMKeyConfigColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_vllm_key_config_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasColumn(&tables.TableKey{}, "vllm_url") {
				if err := migrator.AddColumn(&tables.TableKey{}, "vllm_url"); err != nil {
					return err
				}
			}
			if !migrator.HasColumn(&tables.TableKey{}, "vllm_model_name") {
				if err := migrator.AddColumn(&tables.TableKey{}, "vllm_model_name"); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasColumn(&tables.TableKey{}, "vllm_url") {
				if err := migrator.DropColumn(&tables.TableKey{}, "vllm_url"); err != nil {
					return err
				}
			}
			if migrator.HasColumn(&tables.TableKey{}, "vllm_model_name") {
				if err := migrator.DropColumn(&tables.TableKey{}, "vllm_model_name"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running vllm key config columns migration: %s", err.Error())
	}
	return nil
}

// migrationWidenEncryptedVarcharColumns widens varchar columns that store AES-256-GCM
// encrypted values to TEXT. Encryption adds ~28 bytes of overhead plus base64 expansion (4/3x),
// so a varchar(255) can only hold ~153-char plaintext. Using TEXT removes any size constraints.
// SQLite does not enforce varchar(n) size constraints, so no migration is needed there.
func migrationWidenEncryptedVarcharColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "widen_encrypted_varchar_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if tx.Dialector.Name() != "postgres" {
				return nil
			}
			stmts := []string{
				// config_keys table - all encrypted EnvVar fields
				"ALTER TABLE config_keys ALTER COLUMN azure_api_version TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN azure_client_id TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN azure_tenant_id TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN vertex_project_id TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN vertex_project_number TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN vertex_region TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN bedrock_access_key TYPE TEXT",
				"ALTER TABLE config_keys ALTER COLUMN bedrock_region TYPE TEXT",
				// sessions table
				"ALTER TABLE sessions ALTER COLUMN token TYPE TEXT",
				// governance_virtual_keys table
				"ALTER TABLE governance_virtual_keys ALTER COLUMN value TYPE TEXT",
				// oauth_configs table
				"ALTER TABLE oauth_configs ALTER COLUMN code_verifier TYPE TEXT",
			}
			for _, stmt := range stmts {
				if err := tx.Exec(stmt).Error; err != nil {
					return fmt.Errorf("failed to widen column (%s): %w", stmt, err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running widen encrypted varchar columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddBedrockAssumeRoleColumns adds bedrock_role_arn, bedrock_external_id, and bedrock_role_session_name
// columns to the config_keys table for STS AssumeRole support in Bedrock keys.
func migrationAddBedrockAssumeRoleColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_bedrock_assume_role_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasColumn(&tables.TableKey{}, "bedrock_role_arn") {
				if err := mg.AddColumn(&tables.TableKey{}, "bedrock_role_arn"); err != nil {
					return fmt.Errorf("failed to add bedrock_role_arn column: %w", err)
				}
			}
			if !mg.HasColumn(&tables.TableKey{}, "bedrock_external_id") {
				if err := mg.AddColumn(&tables.TableKey{}, "bedrock_external_id"); err != nil {
					return fmt.Errorf("failed to add bedrock_external_id column: %w", err)
				}
			}
			if !mg.HasColumn(&tables.TableKey{}, "bedrock_role_session_name") {
				if err := mg.AddColumn(&tables.TableKey{}, "bedrock_role_session_name"); err != nil {
					return fmt.Errorf("failed to add bedrock_role_session_name column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasColumn(&tables.TableKey{}, "bedrock_role_arn") {
				if err := mg.DropColumn(&tables.TableKey{}, "bedrock_role_arn"); err != nil {
					return fmt.Errorf("failed to drop bedrock_role_arn column: %w", err)
				}
			}
			if mg.HasColumn(&tables.TableKey{}, "bedrock_external_id") {
				if err := mg.DropColumn(&tables.TableKey{}, "bedrock_external_id"); err != nil {
					return fmt.Errorf("failed to drop bedrock_external_id column: %w", err)
				}
			}
			if mg.HasColumn(&tables.TableKey{}, "bedrock_role_session_name") {
				if err := mg.DropColumn(&tables.TableKey{}, "bedrock_role_session_name"); err != nil {
					return fmt.Errorf("failed to drop bedrock_role_session_name column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running bedrock assume role columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddPricingRefactorColumns adds all new pricing columns introduced in the pricing module refactor
func migrationAddPricingRefactorColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_pricing_refactor_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			columns := []string{
				"input_cost_per_token_priority",
				"output_cost_per_token_priority",
				"cache_creation_input_token_cost_above_1hr",
				"cache_creation_input_token_cost_above_1hr_above_200k_tokens",
				"cache_creation_input_audio_token_cost",
				"cache_read_input_token_cost_priority",
				"input_cost_per_pixel",
				"output_cost_per_pixel",
				"output_cost_per_image_premium_image",
				"output_cost_per_image_above_512_and_512_pixels",
				"output_cost_per_image_above_512x512_pixels_premium",
				"output_cost_per_image_above_1024_and_1024_pixels",
				"output_cost_per_image_above_1024x1024_pixels_premium",
				"input_cost_per_audio_token",
				"input_cost_per_second",
				"input_cost_per_video_per_second",
				"input_cost_per_audio_per_second",
				"output_cost_per_audio_token",
				"search_context_cost_per_query",
				"code_interpreter_cost_per_session",
				"input_cost_per_character",
				"input_cost_per_token_above_128k_tokens",
				"input_cost_per_image_above_128k_tokens",
				"input_cost_per_video_per_second_above_128k_tokens",
				"input_cost_per_audio_per_second_above_128k_tokens",
				"output_cost_per_token_above_128k_tokens",
			}

			for _, field := range columns {
				if !mg.HasColumn(&tables.TableModelPricing{}, field) {
					if err := mg.AddColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to add column %s: %w", field, err)
					}
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			columns := []string{
				"input_cost_per_token_priority",
				"output_cost_per_token_priority",
				"cache_creation_input_token_cost_above_1hr",
				"cache_creation_input_token_cost_above_1hr_above_200k_tokens",
				"cache_creation_input_audio_token_cost",
				"cache_read_input_token_cost_priority",
				"input_cost_per_pixel",
				"output_cost_per_pixel",
				"output_cost_per_image_premium_image",
				"output_cost_per_image_above_512_and_512_pixels",
				"output_cost_per_image_above_512x512_pixels_premium",
				"output_cost_per_image_above_1024_and_1024_pixels",
				"output_cost_per_image_above_1024x1024_pixels_premium",
				"input_cost_per_audio_token",
				"input_cost_per_second",
				"input_cost_per_video_per_second",
				"input_cost_per_audio_per_second",
				"output_cost_per_audio_token",
				"search_context_cost_per_query",
				"code_interpreter_cost_per_session",
				"input_cost_per_character",
				"input_cost_per_token_above_128k_tokens",
				"input_cost_per_image_above_128k_tokens",
				"input_cost_per_video_per_second_above_128k_tokens",
				"input_cost_per_audio_per_second_above_128k_tokens",
				"output_cost_per_token_above_128k_tokens",
			}

			for _, field := range columns {
				if mg.HasColumn(&tables.TableModelPricing{}, field) {
					if err := mg.DropColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to drop column %s: %w", field, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running pricing refactor columns migration: %s", err.Error())
	}
	return nil
}

// migrationRenameTruncatedPricingColumn renames the output_cost_per_image_above_512_and_512_pixels_and_premium_image
// column which at 64 chars exceeds PostgreSQL's 63-character identifier limit. PostgreSQL silently truncated
// it to output_cost_per_image_above_512_and_512_pixels_and_premium_imag (63 chars), while SQLite kept the
// full 64-char name. This migration renames whichever variant exists to the shorter canonical name.
func migrationRenameTruncatedPricingColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "rename_truncated_pricing_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			const newName = "output_cost_per_image_above_512x512_pixels_premium"
			if mg.HasColumn(&tables.TableModelPricing{}, newName) {
				return nil
			}

			// PostgreSQL truncated the 64-char name to 63 chars
			const oldNamePG = "output_cost_per_image_above_512_and_512_pixels_and_premium_imag"
			// SQLite kept the full 64-char name
			const oldNameSQLite = "output_cost_per_image_above_512_and_512_pixels_and_premium_image"

			if mg.HasColumn(&tables.TableModelPricing{}, oldNamePG) {
				if err := tx.Exec("ALTER TABLE governance_model_pricing RENAME COLUMN " + oldNamePG + " TO " + newName).Error; err != nil {
					return fmt.Errorf("failed to rename column %s to %s: %w", oldNamePG, newName, err)
				}
			} else if mg.HasColumn(&tables.TableModelPricing{}, oldNameSQLite) {
				if err := tx.Exec("ALTER TABLE governance_model_pricing RENAME COLUMN " + oldNameSQLite + " TO " + newName).Error; err != nil {
					return fmt.Errorf("failed to rename column %s to %s: %w", oldNameSQLite, newName, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running rename_truncated_pricing_column migration: %s", err.Error())
	}
	return nil
}

// migrationAddImageQualityPricingColumns adds quality-based per-image cost columns (low, medium, high, auto).
func migrationAddImageQualityPricingColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_image_quality_pricing_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			columns := []string{
				"output_cost_per_image_above_2048_and_2048_pixels",
				"output_cost_per_image_above_4096_and_4096_pixels",
				"output_cost_per_image_low_quality",
				"output_cost_per_image_medium_quality",
				"output_cost_per_image_high_quality",
				"output_cost_per_image_auto_quality",
			}
			for _, field := range columns {
				if !mg.HasColumn(&tables.TableModelPricing{}, field) {
					if err := mg.AddColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to add column %s: %w", field, err)
					}
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			columns := []string{
				"output_cost_per_image_above_2048_and_2048_pixels",
				"output_cost_per_image_above_4096_and_4096_pixels",
				"output_cost_per_image_low_quality",
				"output_cost_per_image_medium_quality",
				"output_cost_per_image_high_quality",
				"output_cost_per_image_auto_quality",
			}
			for _, field := range columns {
				if mg.HasColumn(&tables.TableModelPricing{}, field) {
					if err := mg.DropColumn(&tables.TableModelPricing{}, field); err != nil {
						return fmt.Errorf("failed to drop column %s: %w", field, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running image quality pricing columns migration: %s", err.Error())
	}
	return nil
}

// legacyRoutingRuleColumns is a migration-only struct that represents the old routing_rules
// schema before provider/model/key_id were moved to the routing_targets table.
// GORM's SQLite DropColumn/AddColumn need a real struct (not a string table name) to
// reconstruct the table correctly, so we keep this stub around for migration use only.
type legacyRoutingRuleColumns struct {
	Provider string `gorm:"column:provider;type:varchar(255)"`
	Model    string `gorm:"column:model;type:varchar(255)"`
}

func (legacyRoutingRuleColumns) TableName() string { return "routing_rules" }

// migrationAddRoutingTargetsTable creates the routing_targets table and seeds one target row per
// existing routing rule, migrating the legacy provider/model columns.
// After seeding, the legacy columns are dropped from routing_rules.
func migrationAddRoutingTargetsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_routing_targets_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			// 1. Create routing_targets table
			if !mg.HasTable(&tables.TableRoutingTarget{}) {
				if err := mg.CreateTable(&tables.TableRoutingTarget{}); err != nil {
					return fmt.Errorf("failed to create routing_targets table: %w", err)
				}
			}
			if !mg.HasConstraint(&tables.TableRoutingRule{}, "Targets") {
				if err := mg.CreateConstraint(&tables.TableRoutingRule{}, "Targets"); err != nil {
					return fmt.Errorf("failed to create routing_targets foreign key: %w", err)
				}
			}

			// 2. Read legacy data BEFORE dropping columns, then drop columns, then seed.
			// Order matters: DropColumn on SQLite recreates the routing_rules table, which
			// triggers the OnDelete:CASCADE on routing_targets and deletes any rows inserted
			// before the drop. So we read first, drop, then insert.
			type legacyRule struct {
				ID       string
				Provider string
				Model    string
			}
			var legacyRows []legacyRule
			if mg.HasColumn("routing_rules", "provider") {
				if err := tx.Table("routing_rules").Select("id, provider, model").Scan(&legacyRows).Error; err != nil {
					return fmt.Errorf("failed to scan routing_rules for seeding: %w", err)
				}
			}

			// 3. Drop legacy single-target columns from routing_rules.
			// Must use the struct form (not string) so SQLite can reconstruct the table correctly.
			// Do this BEFORE seeding so the CASCADE triggered by table recreation hits an empty
			// routing_targets table (nothing to delete yet).
			legacyModel := &legacyRoutingRuleColumns{}
			for _, col := range []string{"provider", "model"} {
				if mg.HasColumn("routing_rules", col) {
					if err := mg.DropColumn(legacyModel, col); err != nil {
						return fmt.Errorf("failed to drop column %s from routing_rules: %w", col, err)
					}
				}
			}

			// 4. Seed routing_targets from the legacy data read above (idempotent).
			for _, row := range legacyRows {
				var count int64
				if err := tx.Table("routing_targets").Where("rule_id = ?", row.ID).Count(&count).Error; err != nil {
					return fmt.Errorf("failed to count targets for rule %s: %w", row.ID, err)
				}
				if count > 0 {
					continue // already seeded
				}
				target := tables.TableRoutingTarget{
					RuleID: row.ID,
					Weight: 1.0,
				}
				if row.Provider != "" {
					p := row.Provider
					target.Provider = &p
				}
				if row.Model != "" {
					m := row.Model
					target.Model = &m
				}
				if err := tx.Create(&target).Error; err != nil {
					return fmt.Errorf("failed to seed target for rule %s: %w", row.ID, err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()

			if !mg.HasTable(&tables.TableRoutingTarget{}) {
				return nil
			}

			// 1. Add provider and model columns back to routing_rules (before dropping targets)
			legacyModel := &legacyRoutingRuleColumns{}
			for _, col := range []string{"provider", "model"} {
				if !mg.HasColumn("routing_rules", col) {
					if err := mg.AddColumn(legacyModel, col); err != nil {
						return fmt.Errorf("failed to add column %s to routing_rules: %w", col, err)
					}
				}
			}

			// 2. Backfill provider/model from routing_targets into routing_rules (join by rule_id)
			type targetRow struct {
				RuleID   string
				Provider *string
				Model    *string
			}
			var targets []targetRow
			if err := tx.Table("routing_targets").Select("rule_id, provider, model").Order("rule_id").Scan(&targets).Error; err != nil {
				return fmt.Errorf("failed to scan routing_targets for backfill: %w", err)
			}
			ruleData := make(map[string]targetRow)
			for _, t := range targets {
				if _, ok := ruleData[t.RuleID]; !ok {
					ruleData[t.RuleID] = t
				}
			}
			for ruleID, t := range ruleData {
				provider, model := "", ""
				if t.Provider != nil {
					provider = *t.Provider
				}
				if t.Model != nil {
					model = *t.Model
				}
				if err := tx.Table("routing_rules").Where("id = ?", ruleID).Updates(map[string]interface{}{
					"provider": provider,
					"model":    model,
				}).Error; err != nil {
					return fmt.Errorf("failed to backfill routing_rule %s: %w", ruleID, err)
				}
			}

			// 3. Drop routing_targets table
			if mg.HasConstraint(&tables.TableRoutingRule{}, "Targets") {
				if err := mg.DropConstraint(&tables.TableRoutingRule{}, "Targets"); err != nil {
					return fmt.Errorf("failed to drop routing_targets foreign key: %w", err)
				}
			}
			if err := mg.DropTable(&tables.TableRoutingTarget{}); err != nil {
				return fmt.Errorf("failed to drop routing_targets table: %w", err)
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running routing_targets_table migration: %s", err.Error())
	}
	return nil
}

// migrationAddPromptRepoTables adds the prompt repository tables (folders, prompts, versions, sessions)
func migrationAddPromptRepoTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_prompt_repo_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Create folders table
			if !migrator.HasTable(&tables.TableFolder{}) {
				if err := migrator.CreateTable(&tables.TableFolder{}); err != nil {
					return err
				}
			}

			// Create prompts table
			if !migrator.HasTable(&tables.TablePrompt{}) {
				if err := migrator.CreateTable(&tables.TablePrompt{}); err != nil {
					return err
				}
			}

			// Create prompt_versions table
			if !migrator.HasTable(&tables.TablePromptVersion{}) {
				if err := migrator.CreateTable(&tables.TablePromptVersion{}); err != nil {
					return err
				}
			}

			// Create prompt_version_messages table
			if !migrator.HasTable(&tables.TablePromptVersionMessage{}) {
				if err := migrator.CreateTable(&tables.TablePromptVersionMessage{}); err != nil {
					return err
				}
			}

			// Create prompt_sessions table
			if !migrator.HasTable(&tables.TablePromptSession{}) {
				if err := migrator.CreateTable(&tables.TablePromptSession{}); err != nil {
					return err
				}
			}

			// Create prompt_session_messages table
			if !migrator.HasTable(&tables.TablePromptSessionMessage{}) {
				if err := migrator.CreateTable(&tables.TablePromptSessionMessage{}); err != nil {
					return err
				}
			}

			// Apply schema updates (indexes, constraints) to existing tables
			if err := tx.AutoMigrate(
				&tables.TablePromptVersion{},
				&tables.TablePromptSession{},
			); err != nil {
				return err
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			// Drop tables in reverse order (respecting foreign key constraints)
			if err := migrator.DropTable(&tables.TablePromptSessionMessage{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TablePromptSession{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TablePromptVersionMessage{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TablePromptVersion{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TablePrompt{}); err != nil {
				return err
			}
			if err := migrator.DropTable(&tables.TableFolder{}); err != nil {
				return err
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running prompt repo tables migration: %s", err.Error())
	}

	// Add prompt_id column to prompt message tables
	m = migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_prompt_id_to_prompt_message_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TablePromptVersionMessage{}, "prompt_id") {
				if err := migrator.AddColumn(&tables.TablePromptVersionMessage{}, "PromptID"); err != nil {
					return err
				}
			}

			if !migrator.HasColumn(&tables.TablePromptSessionMessage{}, "prompt_id") {
				if err := migrator.AddColumn(&tables.TablePromptSessionMessage{}, "PromptID"); err != nil {
					return err
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TablePromptVersionMessage{}, "prompt_id") {
				if err := migrator.DropColumn(&tables.TablePromptVersionMessage{}, "prompt_id"); err != nil {
					return err
				}
			}
			if migrator.HasColumn(&tables.TablePromptSessionMessage{}, "prompt_id") {
				if err := migrator.DropColumn(&tables.TablePromptSessionMessage{}, "prompt_id"); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running add_prompt_id_to_prompt_message_tables migration: %s", err.Error())
	}

	m = migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_model_parameters_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if !migrator.HasTable(&tables.TableModelParameters{}) {
				if err := migrator.CreateTable(&tables.TableModelParameters{}); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()
			if migrator.HasTable(&tables.TableModelParameters{}) {
				if err := migrator.DropTable(&tables.TableModelParameters{}); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running add_model_parameters_table migration: %s", err.Error())
	}

	return nil
}

func migrationAddTenantIsolation(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tenant_isolation",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.AutoMigrate(
				&tables.TableClientConfig{},
				&tables.TableFrameworkConfig{},
				&tables.TableProvider{},
				&tables.TableKey{},
				&tables.TableMCPClient{},
				&tables.TableVectorStoreConfig{},
				&tables.TableLogStoreConfig{},
				&tables.TableBudget{},
				&tables.TableCustomer{},
				&tables.TableTeam{},
				&tables.TableRateLimit{},
				&tables.TableVirtualKeyProviderConfig{},
				&tables.TableVirtualKeyMCPConfig{},
				&tables.TableVirtualKey{},
				&tables.TablePlugin{},
				&tables.TableModelConfig{},
				&tables.TableRoutingRule{},
				&tables.TableFolder{},
				&tables.TablePrompt{},
				&tables.TablePromptVersion{},
				&tables.TablePromptSession{},
				&tables.TableOauthConfig{},
				&tables.TableOauthToken{},
			); err != nil {
				return err
			}

			dbMigrator := tx.Migrator()
			oldIndexes := []struct {
				model any
				name  string
			}{
				{&tables.TableProvider{}, "idx_config_providers_name"},
				{&tables.TableKey{}, "idx_key_name"},
				{&tables.TableKey{}, "idx_key_id"},
				{&tables.TableMCPClient{}, "idx_config_mcp_clients_client_id"},
				{&tables.TableMCPClient{}, "idx_config_mcp_clients_name"},
				{&tables.TablePlugin{}, "idx_config_plugins_name"},
				{&tables.TableVirtualKey{}, "idx_virtual_key_name"},
				{&tables.TableVirtualKey{}, "idx_virtual_key_value"},
				{&tables.TableVirtualKey{}, "idx_virtual_key_value_hash"},
				{&tables.TableModelConfig{}, "idx_model_provider"},
				{&tables.TableRoutingRule{}, "idx_routing_rule_scope_name"},
			}
			for _, item := range oldIndexes {
				if dbMigrator.HasIndex(item.model, item.name) {
					if err := dbMigrator.DropIndex(item.model, item.name); err != nil {
						return err
					}
				}
			}

			newIndexes := []struct {
				model any
				name  string
			}{
				{&tables.TableClientConfig{}, "idx_config_client_tenant"},
				{&tables.TableFrameworkConfig{}, "idx_framework_config_tenant"},
				// Provider, Key, RoutingRule index names changed when
				// workspace_id was added as a unique-key column. The
				// names below match the current GORM tags on those
				// tables; AutoMigrate (above) creates them, and
				// dbMigrator.CreateIndex is a belt-and-braces that
				// re-looks them up by name.
				{&tables.TableProvider{}, "idx_provider_tenant_workspace_name"},
				{&tables.TableKey{}, "idx_key_tenant_workspace_name"},
				{&tables.TableKey{}, "idx_key_tenant_workspace_key_id"},
				// MCPClient index names also picked up workspace_id when
				// per-workspace MCP scoping landed (see migration around
				// line 4369 which drops the legacy single-axis
				// idx_mcp_tenant_{client_id,name} indexes and re-runs
				// AutoMigrate to create the composite ones below). Using
				// the legacy names here makes HasIndex return false and
				// CreateIndex then fails because there is no GORM tag for
				// those names anymore - observable as
				// `failed to create index with name idx_mcp_tenant_client_id`
				// on any SQLite/Postgres test that exercises the migration.
				{&tables.TableMCPClient{}, "idx_mcp_tenant_workspace_client_id"},
				{&tables.TableMCPClient{}, "idx_mcp_tenant_workspace_name"},
				{&tables.TableVectorStoreConfig{}, "idx_vector_store_tenant"},
				{&tables.TableLogStoreConfig{}, "idx_log_store_tenant"},
				// Plugin index also picked up workspace_id when
				// per-workspace plugin scoping landed in
				// migrationPluginWorkspaceUniqueIndex (around line 4462).
				// Same chicken-and-egg as the MCP entries above: the
				// legacy idx_plugin_tenant_name no longer exists as a
				// GORM tag, so HasIndex returns false and CreateIndex
				// fails. Use the composite name that matches the current
				// tables/plugin.go tag.
				{&tables.TablePlugin{}, "idx_plugin_tenant_workspace_name"},
				{&tables.TableVirtualKey{}, "idx_virtual_key_tenant_workspace_name"},
				{&tables.TableVirtualKey{}, "idx_virtual_key_tenant_value"},
				{&tables.TableVirtualKey{}, "idx_virtual_key_tenant_value_hash"},
				{&tables.TableModelConfig{}, "idx_model_tenant_provider"},
				{&tables.TableRoutingRule{}, "idx_routing_rule_tenant_workspace_scope_name"},
			}
			for _, item := range newIndexes {
				if !dbMigrator.HasIndex(item.model, item.name) {
					if err := dbMigrator.CreateIndex(item.model, item.name); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running tenant isolation migration: %s", err.Error())
	}
	return nil
}

// migrationAddPluginOrderColumns adds placement and exec_order columns to config_plugins table
func migrationAddPluginOrderColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_plugin_order_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if !migrator.HasColumn(&tables.TablePlugin{}, "placement") {
				if err := migrator.AddColumn(&tables.TablePlugin{}, "Placement"); err != nil {
					return fmt.Errorf("failed to add placement column: %w", err)
				}
			}
			if !migrator.HasColumn(&tables.TablePlugin{}, "exec_order") {
				if err := migrator.AddColumn(&tables.TablePlugin{}, "Order"); err != nil {
					return fmt.Errorf("failed to add exec_order column: %w", err)
				}
			}

			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			migrator := tx.Migrator()

			if migrator.HasColumn(&tables.TablePlugin{}, "placement") {
				if err := migrator.DropColumn(&tables.TablePlugin{}, "placement"); err != nil {
					return fmt.Errorf("failed to drop placement column: %w", err)
				}
			}
			if migrator.HasColumn(&tables.TablePlugin{}, "exec_order") {
				if err := migrator.DropColumn(&tables.TablePlugin{}, "exec_order"); err != nil {
					return fmt.Errorf("failed to drop exec_order column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running add_plugin_order_columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddMultiTenantOrganizations creates the organizations table and adds
// tenant_id columns to auth_users and sessions for true multi-tenant SaaS isolation.
// For existing single-tenant data, each user gets their own auto-created organization.
func migrationAddMultiTenantOrganizations(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_multi_tenant_organizations",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)

			// Create the organizations table
			if err := tx.AutoMigrate(&tables.TableOrganization{}); err != nil {
				return fmt.Errorf("failed to create organizations table: %w", err)
			}

			dbMigrator := tx.Migrator()

			// Add tenant_id to auth_users if not present
			if !dbMigrator.HasColumn(&tables.TableAuthUser{}, "tenant_id") {
				if err := tx.Exec("ALTER TABLE auth_users ADD COLUMN tenant_id VARCHAR(255) DEFAULT ''").Error; err != nil {
					return fmt.Errorf("failed to add tenant_id to auth_users: %w", err)
				}
			}

			// Add tenant_id to sessions if not present
			if !dbMigrator.HasColumn(&tables.SessionsTable{}, "tenant_id") {
				if err := tx.Exec("ALTER TABLE sessions ADD COLUMN tenant_id VARCHAR(255) DEFAULT ''").Error; err != nil {
					return fmt.Errorf("failed to add tenant_id to sessions: %w", err)
				}
			}

			// Backfill: create an organization for each existing user and assign tenant_id
			var users []struct {
				ID           string
				Email        string
				FirstName    string
				LastName     string
				Organization string
			}
			if err := tx.Raw("SELECT id, email, first_name, last_name, organization FROM auth_users WHERE tenant_id = '' OR tenant_id IS NULL").Scan(&users).Error; err != nil {
				return fmt.Errorf("failed to query existing users: %w", err)
			}

			for _, u := range users {
				orgID := uuid.New().String()
				orgName := u.Organization
				if orgName == "" {
					orgName = strings.TrimSpace(u.FirstName + " " + u.LastName)
					if orgName == "" {
						orgName = u.Email
					}
				}
				slug := strings.ToLower(strings.ReplaceAll(orgName, " ", "-"))
				slug = orgID[:8] + "-" + slug

				if err := tx.Exec(
					"INSERT INTO organizations (id, name, slug, owner_id, plan, created_at, updated_at) VALUES (?, ?, ?, ?, 'free', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
					orgID, orgName, slug, u.ID,
				).Error; err != nil {
					return fmt.Errorf("failed to create org for user %s: %w", u.ID, err)
				}

				// Set tenant_id on the user
				if err := tx.Exec("UPDATE auth_users SET tenant_id = ? WHERE id = ?", orgID, u.ID).Error; err != nil {
					return fmt.Errorf("failed to set tenant_id on user %s: %w", u.ID, err)
				}

				// Migrate all existing data from user-scoped (tenant_id = user.ID) to org-scoped (tenant_id = orgID)
				tenantScopedTables := []string{
					"governance_customers", "governance_teams", "governance_budgets",
					"governance_rate_limits", "governance_virtual_keys",
					"governance_virtual_key_provider_configs", "governance_virtual_key_mcp_configs",
					"config_keys", "config_providers", "config_plugins", "config_client",
					"config_framework", "config_mcp_clients", "config_vector_store",
					"config_log_store", "config_model", "routing_rules", "routing_targets",
					"folders", "prompts", "prompt_versions", "prompt_sessions",
					"oauth_configs", "oauth_tokens",
				}
				for _, table := range tenantScopedTables {
					if dbMigrator.HasTable(table) {
						tx.Exec("UPDATE "+table+" SET tenant_id = ? WHERE tenant_id = ?", orgID, u.ID)
					}
				}

				// Update sessions for this user
				if err := tx.Exec("UPDATE sessions SET tenant_id = ? WHERE user_id = ?", orgID, u.ID).Error; err != nil {
					return fmt.Errorf("failed to set tenant_id on sessions for user %s: %w", u.ID, err)
				}
			}

			// Add indexes on auth_users.tenant_id and sessions.tenant_id
			if !dbMigrator.HasIndex(&tables.TableAuthUser{}, "idx_auth_users_tenant_id") {
				if err := tx.Exec("CREATE INDEX idx_auth_users_tenant_id ON auth_users (tenant_id)").Error; err != nil {
					log.Printf("WARN: failed to create idx_auth_users_tenant_id (may already exist): %v", err)
				}
			}
			if !dbMigrator.HasIndex(&tables.SessionsTable{}, "idx_sessions_tenant_id") {
				if err := tx.Exec("CREATE INDEX idx_sessions_tenant_id ON sessions (tenant_id)").Error; err != nil {
					log.Printf("WARN: failed to create idx_sessions_tenant_id (may already exist): %v", err)
				}
			}

			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running multi-tenant organizations migration: %s", err.Error())
	}
	return nil
}

func migrationAddKeySelectionStrategyColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_key_selection_strategy_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasColumn(&tables.TableVirtualKeyProviderConfig{}, "key_selection_strategy") {
				if err := mg.AddColumn(&tables.TableVirtualKeyProviderConfig{}, "KeySelectionStrategy"); err != nil {
					return fmt.Errorf("failed to add key_selection_strategy column: %w", err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if mg.HasColumn(&tables.TableVirtualKeyProviderConfig{}, "key_selection_strategy") {
				if err := mg.DropColumn(&tables.TableVirtualKeyProviderConfig{}, "key_selection_strategy"); err != nil {
					return fmt.Errorf("failed to drop key_selection_strategy column: %w", err)
				}
			}
			return nil
		},
	}})

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error running key selection strategy migration: %s", err.Error())
	}
	return nil
}

