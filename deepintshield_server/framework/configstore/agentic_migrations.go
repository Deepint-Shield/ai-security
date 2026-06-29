package configstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/migrator"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// migrationAddAgenticSecurityTables provisions the Agentic Security control
// plane: policies, identity providers + agent identities, tool sensitivity
// tiering, append-only hash-chained decisions, approvals queue and
// per-tenant enforcement state.
//
// Historical note: this migration originally also created agentic_virtual_keys
// and agentic_workspace_access. Both tables were dropped in the unified-VK
// consolidation - agent scope now lives on governance_virtual_keys, and
// per-user/team entitlements moved onto governance_teams.allowed_tools /
// governance_customers.allowed_tools. The drop is performed by
// migrationDropLegacyAgenticTables below; this AutoMigrate list no longer
// references the dead types so the build doesn't depend on them.
func migrationAddAgenticSecurityTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_security_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableAgenticPolicy{},
				&tables.TableAgenticToolTiering{},
				&tables.TableAgenticIdentityProvider{},
				&tables.TableAgenticIdentity{},
				&tables.TableAgenticDecision{},
				&tables.TableAgenticApproval{},
				&tables.TableAgenticEnforcementState{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic security tables migration: %s", err.Error())
	}
	return nil
}

// migrationAddToolIntegrityColumns adds the Tool Integrity Engine columns:
// integrity_posture on the tool tiering table (what a divergence does to the
// verdict) and effective_action_class / integrity_risk / integrity_flags_json
// on the decisions + approvals tables (the per-call divergence evidence). A
// new migration ID is required because the original add_agentic_security_tables
// migration already ran on existing databases, so its AutoMigrate body never
// re-executes. Additive + idempotent - AutoMigrate only adds missing columns.
func migrationAddToolIntegrityColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tool_integrity_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableAgenticToolTiering{},
				&tables.TableAgenticDecision{},
				&tables.TableAgenticApproval{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("tool integrity columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgenticToolSummaries provisions the cached tool-summary table
// (fingerprint → "what this tool does"). Additive + idempotent via AutoMigrate.
func migrationAddAgenticToolSummaries(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_tool_summaries",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticToolSummary{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic tool summaries migration: %s", err.Error())
	}
	return nil
}

// migrationAddToolSummaryLLMSettings adds the per-workspace LLM-call config for
// tool summaries (enable switch + virtual key + provider + model) onto the
// observability settings table. Additive + idempotent via AutoMigrate.
func migrationAddToolSummaryLLMSettings(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tool_summary_llm_settings",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticObservabilitySettings{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("tool summary llm settings migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgenticToolGrants provisions the persisted/JIT auto-allow grants
// table and adds virtual_key_id + tool_fingerprint to the approvals table so an
// approve→grant can bind to {agent VK, tool, exact behavior fingerprint}.
// Additive + idempotent via AutoMigrate (new ID - existing add_agentic_security
// migration is already recorded).
func migrationAddAgenticToolGrants(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_tool_grants",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableAgenticToolGrant{},
				&tables.TableAgenticApproval{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic tool grants migration: %s", err.Error())
	}
	return nil
}

// migrationAddRelationshipAudit provisions the append-only ReBAC (OpenFGA)
// tuple-change audit table. Additive + idempotent via AutoMigrate (NEW ID - the
// earlier agentic migrations are already recorded, so their bodies never
// re-run; a fresh ID is required to create a new table).
func migrationAddRelationshipAudit(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_relationship_audit",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticRelationshipAudit{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic relationship audit migration: %s", err.Error())
	}
	return nil
}

// migrationAddTraceSummaryColumns backfills the trace summary with
// PrimaryTool + PrimaryModel so the Agent Traces list shows what each
// run actually did without joining observations at render time.
// Idempotent - AutoMigrate adds the columns only if missing.
func migrationAddTraceSummaryColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_trace_summary_primary_tool_and_model",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticTrace{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("trace summary primary tool/model migration: %s", err.Error())
	}
	return nil
}

// migrationDropRedundantTenantIDIndexes drops single-column tenant_id
// indexes on tables where a composite index already leads with the
// same column. Postgres uses the composite for any query that filters
// by tenant_id alone (leading-column rule), so the standalone index is
// pure write-amplification + planner overhead.
//
// Identified via:
//
//	SELECT redundant single-col idx WHERE
//	  composite exists on SAME table starting with SAME column
//	  AND NOT (unique OR primary)
//
// Idempotent - DROP INDEX IF EXISTS is a no-op on fresh installs where
// the matching GORM struct tags have already been stripped.
func migrationDropRedundantTenantIDIndexes(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "drop_redundant_tenant_id_indexes",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			drops := []string{
				// Agentic
				"DROP INDEX IF EXISTS idx_agentic_decisions_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_enforcement_state_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_identities_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_identity_providers_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_observability_settings_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_policies_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_tool_tiering_tenant_id",
				"DROP INDEX IF EXISTS idx_agentic_traces_tenant_id",
				// Governance
				"DROP INDEX IF EXISTS idx_governance_model_configs_tenant_id",
				"DROP INDEX IF EXISTS idx_governance_org_memberships_organization_id",
				"DROP INDEX IF EXISTS idx_governance_team_customer_members_tenant_id",
				"DROP INDEX IF EXISTS idx_governance_team_members_tenant_id",
				// NOTE: idx_governance_virtual_keys_tenant_id intentionally
				// kept. The struct tag for TableVirtualKey retains `;index`
				// because stripping it triggered a destructive AutoMigrate
				// path in Postgres in testing. The cost of one redundant
				// single-column index is strictly preferable to the risk.
				// Guardrails
				"DROP INDEX IF EXISTS idx_guardrail_approval_requests_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_decisions_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_domain_packs_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_findings_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_mcp_tool_policies_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_policies_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_policy_provider_bindings_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_policy_versions_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_providers_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_rag_sources_tenant_id",
				"DROP INDEX IF EXISTS idx_guardrail_traces_tenant_id",
				// Audit log - same shape, covered by both
				// (tenant_id, sequence) UNIQUE and (tenant_id, ts).
				"DROP INDEX IF EXISTS idx_audit_logs_tenant_id",
			}
			for _, stmt := range drops {
				if err := tx.Exec(stmt).Error; err != nil {
					return fmt.Errorf("%s: %w", stmt, err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("drop redundant tenant_id indexes: %s", err.Error())
	}
	return nil
}

// migrationDropLegacyAgenticTables removes the two consolidated tables.
// Idempotent - `DROP TABLE IF EXISTS` is a no-op on fresh installs that
// never created them. The migration ID is recorded so it runs once per
// database, then never again.
func migrationDropLegacyAgenticTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "drop_legacy_agentic_virtual_keys_and_workspace_access",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// Indexes drop with the table; explicit DROP INDEX not needed.
			if err := tx.Exec(`DROP TABLE IF EXISTS agentic_workspace_access`).Error; err != nil {
				return fmt.Errorf("drop agentic_workspace_access: %w", err)
			}
			if err := tx.Exec(`DROP TABLE IF EXISTS agentic_virtual_keys`).Error; err != nil {
				return fmt.Errorf("drop agentic_virtual_keys: %w", err)
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("drop legacy agentic tables: %s", err.Error())
	}
	return nil
}

// migrationAddAgenticObservabilityTables provisions the sampled, operational
// observability store that mirrors the Langfuse data model - traces,
// observations, scores, and per-workspace settings. The hash-chained
// security audit (Agentic Decisions) is a *separate* store; this layer is
// sampled and shorter-retention by design.
func migrationAddAgenticObservabilityTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_observability_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableAgenticTrace{},
				&tables.TableAgenticObservation{},
				&tables.TableAgenticScore{},
				&tables.TableAgenticObservabilitySettings{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic observability tables migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgenticCacheTables provisions the agentic-cache analytics +
// config store (Part X). The events table is append-only and metrics-only
// (no cached payloads - ZDR-safe); the settings table is one row per
// tenant/workspace. Additive and idempotent via AutoMigrate.
func migrationAddAgenticCacheTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_cache_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableAgenticCacheEvent{},
				&tables.TableAgenticCacheSettings{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic cache tables migration: %s", err.Error())
	}
	return nil
}

// migrationBackfillAgenticPolicyOrgID stamps org_id on existing
// agentic_policies rows from the org that owns their workspace. The column
// + index were added by AutoMigrate but never populated, so every legacy
// row carries NULL org_id. Once ListAgenticPolicies/GetAgenticPolicy filter
// by the active org (to stop tenant-wide policies leaking across the orgs
// that share an email-keyed tenant_id), those NULL rows would otherwise
// disappear from their own workspace's view.
//
// Rows with no workspace_id (true tenant/email-wide rows) are intentionally
// left NULL - they belong to no single org and stay hidden under the new
// strict-org scoping rather than being arbitrarily assigned to one. The
// correlated-subquery UPDATE form runs on both Postgres and SQLite.
// Idempotent: the WHERE clause skips rows already stamped.
func migrationBackfillAgenticPolicyOrgID(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "backfill_agentic_policy_org_id_from_workspace",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("agentic_policies") || !tx.Migrator().HasTable("workspaces") {
				return nil
			}
			return tx.Exec(`
				UPDATE agentic_policies
				SET org_id = (
					SELECT w.org_id FROM workspaces w
					WHERE w.id = agentic_policies.workspace_id
				)
				WHERE (org_id IS NULL OR org_id = '')
				  AND workspace_id IS NOT NULL
				  AND EXISTS (
					SELECT 1 FROM workspaces w
					WHERE w.id = agentic_policies.workspace_id
				  )
			`).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("backfill agentic policy org_id migration: %s", err.Error())
	}
	return nil
}

// migrationAddPolicyVKTargets adds the per-policy VK-scoping table and
// the applies_to_all_keys boolean. Both are additive - existing policies
// default to applies_to_all_keys = true so behavior is unchanged until
// an operator explicitly narrows the scope. Idempotent via AutoMigrate.
//
// The follow-on migration `migrationDeriveVKScopedPoliciesFromVKColumns`
// reads the legacy per-VK agent columns (allowed_tools / default_obligations
// / tool_rate_limit_per_minute) and materializes them as per-VK scoped
// policies in shadow mode so the PEP can be flipped to read from policy
// rather than from the VK row without losing enforcement.
func migrationAddPolicyVKTargets(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_policy_vk_targets",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// AutoMigrate adds applies_to_all_keys + the three target
			// join tables (vk / team / member). Each table has cascade
			// FKs to its parent so deletes never leave orphans.
			if err := tx.AutoMigrate(
				&tables.TableAgenticPolicy{},
				&tables.TableAgenticPolicyVKTarget{},
				&tables.TableAgenticPolicyTeamTarget{},
				&tables.TableAgenticPolicyMemberTarget{},
			); err != nil {
				return fmt.Errorf("auto-migrate policy target tables: %w", err)
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("policy vk targets migration: %s", err.Error())
	}
	return nil
}

// migrationDeriveVKScopedPoliciesFromVKColumns is the data-copy step that
// reads the now-legacy entitlement columns on VK, Team, and Member rows
// and creates per-target scoped policies in draft mode for any row that
// has non-default values. Operators verify in draft, promote through
// staged → published, then the follow-on migration drops the legacy
// columns from all three tables.
//
// One policy is created per non-default row:
//   - VK row with agent columns → `VK Scope: <key_name>` + vk target
//   - Team row with allowed_tools → `Team Scope: <team_name>` + team target
//   - Customer row with allowed_tools → `Member Scope: <member_name>` + member target
//
// Common shape:
//   - status: 'draft' (operators must stage + publish; nothing fires yet)
//   - applies_to_all_keys: false
//   - definition.tool.any_tool = row.allowed_tools
//   - definition.obligations = row.default_obligations (VK only) + rate-limit
//   - verdict: ALLOW
//
// Safe to re-run because we only insert when no policy with the same
// generated name already exists in the same (tenant, workspace).
func migrationDeriveVKScopedPoliciesFromVKColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "derive_vk_scoped_policies_from_vk_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if !tx.Migrator().HasTable("agentic_policies") {
				return nil
			}
			if tx.Migrator().HasTable("governance_virtual_keys") {
				if err := deriveVKScopedPolicies(ctx, tx); err != nil {
					return err
				}
			}
			if tx.Migrator().HasTable("governance_teams") {
				if err := deriveTeamScopedPolicies(ctx, tx); err != nil {
					return err
				}
			}
			if tx.Migrator().HasTable("governance_customers") {
				if err := deriveMemberScopedPolicies(ctx, tx); err != nil {
					return err
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("derive vk-scoped policies migration: %s", err.Error())
	}
	return nil
}

// deriveVKScopedPolicies is the body of migrationDeriveVKScopedPoliciesFromVKColumns.
// Kept as a free function so the logic can be unit-tested without
// instantiating a migrator.
//
// For each VK that has any non-default agent column value, generate one
// policy:
//   - scoped via agentic_policy_vk_targets to that VK
//   - applies_to_all_keys = false
//   - status = 'draft' (operators must stage + publish; nothing fires yet)
//   - name = "VK Scope: <key_name>"
//
// We refuse to insert if a policy with the same generated name already
// exists in the same (tenant, workspace) - that's the idempotency guard
// for re-runs / partial runs. The migrator's recorded ID gate prevents
// the migration from re-running cleanly on the same DB, but a partial
// run that crashed mid-loop should be safely resumable.
func deriveVKScopedPolicies(_ context.Context, tx *gorm.DB) error {
	// Skip when the legacy entitlement columns are already gone (post-cleanup
	// installs, or any replay after drop_legacy_allowed_tools_columns). Without
	// this guard the raw SELECT of allowed_tools below errors on a schema where
	// the column no longer exists. Mirrors the HasColumn guards in the team /
	// member derive helpers.
	if !tx.Migrator().HasColumn("governance_virtual_keys", "allowed_tools") {
		return nil
	}
	type vkRow struct {
		ID                     string
		TenantID               string
		WorkspaceID            *string
		Name                   string
		BoundIdentityProvider  string
		AllowedToolsRaw        string // SQLite stores serializer:json as text
		DefaultObligationsRaw  string
		AutonomyBudget         string
		ToolRateLimitPerMinute *int
	}

	// Pull only VKs with a bound identity provider; those are agent
	// VKs by construction. LLM-only VKs (NULL binding) are excluded
	// so we don't create noise policies for purely-gateway keys.
	rows := []vkRow{}
	if err := tx.Raw(`
		SELECT id, tenant_id, workspace_id, name,
		       COALESCE(bound_identity_provider, '') AS bound_identity_provider,
		       COALESCE(allowed_tools, '')           AS allowed_tools_raw,
		       COALESCE(default_obligations, '')    AS default_obligations_raw,
		       COALESCE(autonomy_budget, '')         AS autonomy_budget,
		       tool_rate_limit_per_minute
		FROM governance_virtual_keys
		WHERE bound_identity_provider IS NOT NULL
		  AND bound_identity_provider <> ''
	`).Scan(&rows).Error; err != nil {
		return fmt.Errorf("scan vk rows: %w", err)
	}

	for _, r := range rows {
		// Skip rows that contributed nothing meaningful - no point in
		// creating empty policies for VKs that only had a binding.
		allowedTools := parseJSONStringSlice(r.AllowedToolsRaw)
		defaultObligations := parseJSONStringSlice(r.DefaultObligationsRaw)
		hasRateLimit := r.ToolRateLimitPerMinute != nil && *r.ToolRateLimitPerMinute > 0
		hasBudget := strings.TrimSpace(r.AutonomyBudget) != ""
		if len(allowedTools) == 0 && len(defaultObligations) == 0 && !hasRateLimit && !hasBudget {
			continue
		}

		policyName := fmt.Sprintf("VK Scope: %s", strings.TrimSpace(r.Name))

		// Idempotency: skip if a policy with this name already exists in
		// the same (tenant, workspace).
		var existing int64
		if err := tx.Table("agentic_policies").
			Where("tenant_id = ? AND COALESCE(workspace_id, '') = COALESCE(?, '') AND name = ?",
				r.TenantID, r.WorkspaceID, policyName).
			Count(&existing).Error; err != nil {
			return fmt.Errorf("count existing policy %q: %w", policyName, err)
		}
		if existing > 0 {
			continue
		}

		// Build the policy definition. Obligations include the rate-limit
		// signal as `rate-limit:<n>/min` so the runtime obligation handler
		// can pick it up without a separate column.
		obligations := append([]string{}, defaultObligations...)
		if hasRateLimit {
			obligations = append(obligations, fmt.Sprintf("rate-limit:%d/min", *r.ToolRateLimitPerMinute))
		}
		def := map[string]any{
			"verdict":     "ALLOW",
			"obligations": obligations,
			"reason":      fmt.Sprintf("Migrated from VK %q agent-scope columns", r.Name),
		}
		if len(allowedTools) > 0 {
			def["tool"] = map[string]any{"any_tool": allowedTools}
		}
		if hasBudget {
			// Carry autonomy budget through as a context condition; the
			// existing condition handler reads `recovery_cost`.
			def["conditions"] = []map[string]any{
				{"field": "recovery_cost", "operator": "eq", "value": r.AutonomyBudget},
			}
		}
		defJSON, err := json.Marshal(def)
		if err != nil {
			return fmt.Errorf("marshal derived policy definition: %w", err)
		}

		policyID := uuid.NewString()
		now := time.Now().UTC()
		if err := tx.Exec(`
			INSERT INTO agentic_policies
				(id, tenant_id, workspace_id, name, description, status, policy_version,
				 enabled, definition_json, generated_rego, applies_to_all_keys,
				 tests_passed, tests_total, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'draft', 1, true, ?, '', false, 0, 0, ?, ?)
		`, policyID, r.TenantID, r.WorkspaceID, policyName,
			"Auto-migrated from VK agent-scope columns. Review and stage + publish to enforce.",
			string(defJSON), now, now).Error; err != nil {
			return fmt.Errorf("insert derived policy %q: %w", policyName, err)
		}

		// Insert the single (policy, vk) target row.
		workspaceID := ""
		if r.WorkspaceID != nil {
			workspaceID = *r.WorkspaceID
		}
		if err := tx.Exec(`
			INSERT INTO agentic_policy_vk_targets
				(policy_id, virtual_key_id, tenant_id, workspace_id, created_at)
			VALUES (?, ?, ?, ?, ?)
		`, policyID, r.ID, r.TenantID, workspaceID, now).Error; err != nil {
			return fmt.Errorf("insert vk target for policy %q: %w", policyName, err)
		}
	}
	return nil
}

// deriveTeamScopedPolicies materializes per-team policies from
// governance_teams.allowed_tools. Same shape as deriveVKScopedPolicies
// but targets a team_id instead of a virtual_key_id.
func deriveTeamScopedPolicies(_ context.Context, tx *gorm.DB) error {
	if !tx.Migrator().HasColumn("governance_teams", "allowed_tools") {
		return nil
	}
	type teamRow struct {
		ID              string
		TenantID        string
		WorkspaceID     *string
		Name            string
		AllowedToolsRaw string
	}
	rows := []teamRow{}
	if err := tx.Raw(`
		SELECT id, tenant_id, workspace_id, name,
		       COALESCE(allowed_tools, '') AS allowed_tools_raw
		FROM governance_teams
		WHERE allowed_tools IS NOT NULL AND allowed_tools <> '' AND allowed_tools <> 'null'
	`).Scan(&rows).Error; err != nil {
		return fmt.Errorf("scan team rows: %w", err)
	}
	for _, r := range rows {
		allowedTools := parseJSONStringSlice(r.AllowedToolsRaw)
		if len(allowedTools) == 0 {
			continue
		}
		policyName := fmt.Sprintf("Team Scope: %s", strings.TrimSpace(r.Name))
		var existing int64
		if err := tx.Table("agentic_policies").
			Where("tenant_id = ? AND COALESCE(workspace_id, '') = COALESCE(?, '') AND name = ?",
				r.TenantID, r.WorkspaceID, policyName).
			Count(&existing).Error; err != nil {
			return fmt.Errorf("count existing team policy %q: %w", policyName, err)
		}
		if existing > 0 {
			continue
		}
		def := map[string]any{
			"verdict":     "ALLOW",
			"obligations": []string{},
			"reason":      fmt.Sprintf("Migrated from Team %q allowed_tools", r.Name),
			"tool":        map[string]any{"any_tool": allowedTools},
		}
		defJSON, err := json.Marshal(def)
		if err != nil {
			return fmt.Errorf("marshal team policy definition: %w", err)
		}
		policyID := uuid.NewString()
		now := time.Now().UTC()
		if err := tx.Exec(`
			INSERT INTO agentic_policies
				(id, tenant_id, workspace_id, name, description, status, policy_version,
				 enabled, definition_json, generated_rego, applies_to_all_keys,
				 tests_passed, tests_total, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'draft', 1, true, ?, '', false, 0, 0, ?, ?)
		`, policyID, r.TenantID, r.WorkspaceID, policyName,
			"Auto-migrated from Team allowed_tools. Review and stage + publish to enforce.",
			string(defJSON), now, now).Error; err != nil {
			return fmt.Errorf("insert team policy %q: %w", policyName, err)
		}
		workspaceID := ""
		if r.WorkspaceID != nil {
			workspaceID = *r.WorkspaceID
		}
		if err := tx.Exec(`
			INSERT INTO agentic_policy_team_targets
				(policy_id, team_id, tenant_id, workspace_id, created_at)
			VALUES (?, ?, ?, ?, ?)
		`, policyID, r.ID, r.TenantID, workspaceID, now).Error; err != nil {
			return fmt.Errorf("insert team target for policy %q: %w", policyName, err)
		}
	}
	return nil
}

// deriveMemberScopedPolicies materializes per-member policies from
// governance_customers.allowed_tools.
func deriveMemberScopedPolicies(_ context.Context, tx *gorm.DB) error {
	if !tx.Migrator().HasColumn("governance_customers", "allowed_tools") {
		return nil
	}
	type memberRow struct {
		ID              string
		TenantID        string
		WorkspaceID     *string
		Name            string
		AllowedToolsRaw string
	}
	rows := []memberRow{}
	if err := tx.Raw(`
		SELECT id, tenant_id, workspace_id, name,
		       COALESCE(allowed_tools, '') AS allowed_tools_raw
		FROM governance_customers
		WHERE allowed_tools IS NOT NULL AND allowed_tools <> '' AND allowed_tools <> 'null'
	`).Scan(&rows).Error; err != nil {
		return fmt.Errorf("scan member rows: %w", err)
	}
	for _, r := range rows {
		allowedTools := parseJSONStringSlice(r.AllowedToolsRaw)
		if len(allowedTools) == 0 {
			continue
		}
		policyName := fmt.Sprintf("Member Scope: %s", strings.TrimSpace(r.Name))
		var existing int64
		if err := tx.Table("agentic_policies").
			Where("tenant_id = ? AND COALESCE(workspace_id, '') = COALESCE(?, '') AND name = ?",
				r.TenantID, r.WorkspaceID, policyName).
			Count(&existing).Error; err != nil {
			return fmt.Errorf("count existing member policy %q: %w", policyName, err)
		}
		if existing > 0 {
			continue
		}
		def := map[string]any{
			"verdict":     "ALLOW",
			"obligations": []string{},
			"reason":      fmt.Sprintf("Migrated from Member %q allowed_tools", r.Name),
			"tool":        map[string]any{"any_tool": allowedTools},
		}
		defJSON, err := json.Marshal(def)
		if err != nil {
			return fmt.Errorf("marshal member policy definition: %w", err)
		}
		policyID := uuid.NewString()
		now := time.Now().UTC()
		if err := tx.Exec(`
			INSERT INTO agentic_policies
				(id, tenant_id, workspace_id, name, description, status, policy_version,
				 enabled, definition_json, generated_rego, applies_to_all_keys,
				 tests_passed, tests_total, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'draft', 1, true, ?, '', false, 0, 0, ?, ?)
		`, policyID, r.TenantID, r.WorkspaceID, policyName,
			"Auto-migrated from Member allowed_tools. Review and stage + publish to enforce.",
			string(defJSON), now, now).Error; err != nil {
			return fmt.Errorf("insert member policy %q: %w", policyName, err)
		}
		workspaceID := ""
		if r.WorkspaceID != nil {
			workspaceID = *r.WorkspaceID
		}
		if err := tx.Exec(`
			INSERT INTO agentic_policy_member_targets
				(policy_id, member_id, tenant_id, workspace_id, created_at)
			VALUES (?, ?, ?, ?, ?)
		`, policyID, r.ID, r.TenantID, workspaceID, now).Error; err != nil {
			return fmt.Errorf("insert member target for policy %q: %w", policyName, err)
		}
	}
	return nil
}

// migrationDropLegacyAllowedToolsColumns is the destructive cleanup step
// that drops the now-redundant columns from governance_teams,
// governance_customers, and governance_virtual_keys. Runs AFTER the
// derive migrations have copied the data into per-target policies.
// Idempotent: column-drops use IF EXISTS so re-running is a no-op.
func migrationDropLegacyAllowedToolsColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "drop_legacy_allowed_tools_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// gorm's SQLite DropColumn recreates the table and panics on these
			// governance tables. This is a Postgres-deployment cleanup of now-
			// redundant columns; on SQLite (tests / Self-Hosted) leaving them is
			// harmless. Skip - matches the Dialector.Name() guards in this package.
			if tx.Dialector.Name() != "postgres" {
				return nil
			}
			drops := []struct {
				table   string
				columns []string
			}{
				{"governance_virtual_keys", []string{"allowed_tools", "default_obligations", "tool_rate_limit_per_minute", "autonomy_budget"}},
				{"governance_teams", []string{"allowed_tools"}},
				{"governance_customers", []string{"allowed_tools"}},
			}
			for _, d := range drops {
				if !tx.Migrator().HasTable(d.table) {
					continue
				}
				for _, col := range d.columns {
					if !tx.Migrator().HasColumn(d.table, col) {
						continue
					}
					if err := tx.Migrator().DropColumn(d.table, col); err != nil {
						return fmt.Errorf("drop %s.%s: %w", d.table, col, err)
					}
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("drop legacy allowed_tools migration: %s", err.Error())
	}
	return nil
}

func parseJSONStringSlice(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	// Filter empties so policies don't carry junk values.
	clean := make([]string, 0, len(out))
	for _, v := range out {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		clean = append(clean, v)
	}
	return clean
}

// migrationAddToolPinningColumns adds the ASI04 supply-chain columns
// (pinned_fingerprint / pinned_by / pinned_at) to agentic_tool_tiering so a
// tool can be anchored to a known-good behavior fingerprint and drift is
// detectable. Additive + idempotent; new ID.
func migrationAddToolPinningColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_tool_pinning_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticToolTiering{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("tool pinning columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgenticIdentityOwnershipColumns adds the accountability-registry
// columns (owner_principal, owning_team_id, purpose, agent_version,
// registered_by) to agentic_identities so every agent answers Pillar 3's
// "who owns it / who registered it / what is it for / what version". A new
// migration ID is required because add_agentic_security_tables already ran on
// existing databases. Additive + idempotent - AutoMigrate only adds missing
// columns.
func migrationAddAgenticIdentityOwnershipColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_identity_ownership_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticIdentity{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agentic identity ownership columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgentNamespaceColumn adds agent_namespace to
// governance_virtual_keys (the `namespace` ABAC operand). Additive +
// idempotent; new migration ID so it runs once on databases that predate it.
func migrationAddAgentNamespaceColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agent_namespace_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableVirtualKey{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agent namespace column migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgentRiskCapabilityColumns adds the agent attribute taxonomy
// columns (agent_risk_level + agent_capabilities) to governance_virtual_keys
// so the PDP can evaluate attribute-based policies ("low-risk agents call
// low-risk tools", "agent_capability in [...]") without naming agents. A new
// migration ID is required because the unify_virtual_key_agent_columns
// migration already ran on existing databases, so its AutoMigrate body never
// re-executes. Additive + idempotent - AutoMigrate only adds missing columns.
func migrationAddAgentRiskCapabilityColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agent_risk_capability_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableVirtualKey{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("agent risk/capability columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddPromptPreviewColumns adds the opt-in prompt-preview surface:
// prompt_preview on agentic_observations + capture_prompt_preview on
// agentic_observability_settings. Additive + idempotent (AutoMigrate only adds
// the missing columns); a NEW migration ID so it runs once on databases that
// predate the feature. Both default to the zero-data-retention posture
// (preview empty, capture off) until a workspace explicitly opts in.
func migrationAddPromptPreviewColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_prompt_preview_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.AutoMigrate(&tables.TableAgenticObservation{}); err != nil {
				return fmt.Errorf("auto-migrate observation prompt_preview: %w", err)
			}
			return tx.AutoMigrate(&tables.TableAgenticObservabilitySettings{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("add prompt preview columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddAgenticBlueprintsTable provisions agentic_blueprints - the
// declared agent tool-surface registered by the SDK before a run (nodes/tools/
// edges/mcp_servers). Additive; new migration id; AutoMigrate creates the table.
func migrationAddAgenticBlueprintsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_blueprints_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticBlueprint{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("add agentic blueprints table migration: %s", err.Error())
	}
	return nil
}

// migrationAddBlueprintEnforceColumn adds enforce_blueprint_allowlist to
// agentic_enforcement_state (the opt-in least-privilege toggle). Separate, new
// migration id because add_agentic_blueprints_table already ran. Default false.
func migrationAddBlueprintEnforceColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_enforce_blueprint_allowlist_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticEnforcementState{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("add enforce_blueprint_allowlist column migration: %s", err.Error())
	}
	return nil
}

// migrationAddCodeScanColumns adds the workspace source-code threat-scan config
// (code_scan_mode/code_scan_vk_id/enforce_code_threat on agentic_enforcement_state)
// and the per-blueprint scan results (tool_fingerprints_json/tool_threats_json on
// agentic_blueprints). New migration id; both AutoMigrates are additive.
func migrationAddCodeScanColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_code_scan_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.AutoMigrate(&tables.TableAgenticEnforcementState{}); err != nil {
				return err
			}
			return tx.AutoMigrate(&tables.TableAgenticBlueprint{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("add agentic code-scan columns migration: %s", err.Error())
	}
	return nil
}

// migrationAddRateLimitColumn adds max_requests_per_min (T4 Resource Overload /
// DoS guard) to agentic_enforcement_state. New id; additive; default 0 (off).
func migrationAddRateLimitColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_max_requests_per_min",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticEnforcementState{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("add agentic rate-limit column migration: %s", err.Error())
	}
	return nil
}

// migrationAddCodeScanModelColumn adds code_scan_model (the specific model within
// the chosen scan VK) to agentic_enforcement_state. New id; additive.
func migrationAddCodeScanModelColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_agentic_code_scan_model",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&tables.TableAgenticEnforcementState{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("add agentic code-scan-model column migration: %s", err.Error())
	}
	return nil
}

// migrationUnifyVirtualKeyAgentColumns is the unified-VK consolidation
// that added the 7 agent columns to governance_virtual_keys. The
// data-copy step (from the now-dropped agentic_virtual_keys table) is
// retained behind a HasTable check so upgrades from pre-unify schemas
// still backfill, while fresh installs and post-cleanup installs skip
// it cleanly. Idempotent - migrator's recorded ID gate prevents re-runs.
func migrationUnifyVirtualKeyAgentColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "unify_virtual_key_agent_columns",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			// AutoMigrate handles ADD COLUMN for the new agent fields.
			if err := tx.AutoMigrate(&tables.TableVirtualKey{}); err != nil {
				return fmt.Errorf("auto-migrate virtual_key agent columns: %w", err)
			}
			// Data-copy step only runs if the legacy table still exists.
			// Once migrationDropLegacyAgenticTables has run, this is a
			// no-op - but the migration ID being already recorded means
			// this body won't execute again on subsequent boots anyway.
			if !tx.Migrator().HasTable("agentic_virtual_keys") {
				return nil
			}
			return tx.Exec(`
				UPDATE governance_virtual_keys AS vk
				SET
				  bound_identity_provider = avk.bound_identity_provider,
				  identity_provider_id    = avk.identity_provider_id,
				  allowed_tools           = avk.allowed_tools_json,
				  autonomy_budget         = avk.autonomy_budget,
				  default_obligations     = avk.default_obligations_json,
				  tool_rate_limit_per_minute = avk.rate_limit_per_minute
				FROM agentic_virtual_keys AS avk
				WHERE vk.tenant_id = avk.tenant_id
				  AND COALESCE(vk.workspace_id, '') = COALESCE(avk.workspace_id, '')
				  AND vk.name = avk.key_name
				  AND (vk.bound_identity_provider IS NULL OR vk.bound_identity_provider = '')
			`).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("unify virtual key agent columns migration: %s", err.Error())
	}
	return nil
}
