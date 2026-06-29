package configstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// guardrailProviderTenantScope adds the same tenant + workspace boundary
// that ListGuardrailPolicies uses. Providers (Safety Providers AND the
// DeepIntShield Models / AI Models entries) are workspace-scoped: a row
// created in workspace A should never appear in workspace B even when
// both workspaces share the same email-keyed tenant_id partition.
//
// Legacy rows (tenant_id = ” or 'default'; workspace_id IS NULL) stay
// visible to every caller of the same tenant so the catalog of
// previously-created providers doesn't vanish after this fix lands. New
// rows get a real tenant_id AND workspace_id stamped by the handler so
// the leak closes going forward - the OR-NULL clause keeps the migration
// painless without permanently leaking cross-workspace data.
func guardrailProviderTenantScope(q *gorm.DB, ctx context.Context) *gorm.DB {
	tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if tenant != "" {
		q = q.Where("tenant_id = ? OR tenant_id = '' OR tenant_id IS NULL OR tenant_id = ?", tenant, "default")
	}
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		// Strict workspace match - providers (Safety Providers + AI Models)
		// are workspace-scoped. We deliberately do NOT include
		// `workspace_id IS NULL` rows here: those are pre-workspace-scoping
		// legacy rows that used to leak across every workspace under the
		// tenant, which is exactly the bug we're closing. The backfill
		// migration stamps NULLs to a real workspace where it can; rows
		// that remain NULL are intentionally hidden from workspace-scoped
		// views and are visible only to admin tooling that runs without
		// a workspace header.
		q = q.Where("workspace_id = ?", ws)
	}
	return q
}

func (s *RDBConfigStore) ListGuardrailProviders(ctx context.Context) ([]tables.TableGuardrailProvider, error) {
	var providers []tables.TableGuardrailProvider
	q := guardrailProviderTenantScope(s.db.WithContext(ctx), ctx)
	if err := q.Order("enabled DESC, created_at DESC").Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

func (s *RDBConfigStore) GetGuardrailProvider(ctx context.Context, id string) (*tables.TableGuardrailProvider, error) {
	var provider tables.TableGuardrailProvider
	q := guardrailProviderTenantScope(s.db.WithContext(ctx), ctx)
	if err := q.First(&provider, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &provider, nil
}

func (s *RDBConfigStore) CreateGuardrailProvider(ctx context.Context, provider *tables.TableGuardrailProvider) error {
	if provider == nil {
		return nil
	}
	if strings.TrimSpace(provider.ID) == "" {
		provider.ID = uuid.NewString()
	}
	// Stamp the request's tenant_id on every new row so subsequent reads
	// scope correctly. Callers that already set TenantID (e.g. background
	// jobs that know the target tenant explicitly) are left untouched.
	if strings.TrimSpace(provider.TenantID) == "" {
		if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
			provider.TenantID = tenant
		}
	}
	// Same logic for workspace_id - providers (Safety Providers + AI Models)
	// are workspace-scoped now, so a row created in workspace A stays in
	// workspace A. Callers that already set WorkspaceID (background jobs,
	// migrations) are left untouched.
	if provider.WorkspaceID == nil || strings.TrimSpace(*provider.WorkspaceID) == "" {
		if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
			ws := ws
			provider.WorkspaceID = &ws
		}
	}
	return s.db.WithContext(ctx).Create(provider).Error
}

func (s *RDBConfigStore) UpdateGuardrailProvider(ctx context.Context, provider *tables.TableGuardrailProvider) error {
	if provider == nil {
		return nil
	}
	return s.db.WithContext(ctx).Save(provider).Error
}

func (s *RDBConfigStore) DeleteGuardrailProvider(ctx context.Context, id string) error {
	// Delete only within the caller's tenant scope. Without this filter, a
	// tenant could delete another tenant's provider by guessing the ID.
	q := guardrailProviderTenantScope(s.db.WithContext(ctx), ctx)
	return q.Delete(&tables.TableGuardrailProvider{}, "id = ?", strings.TrimSpace(id)).Error
}

func (s *RDBConfigStore) ListGuardrailPolicies(ctx context.Context) ([]tables.TableGuardrailPolicy, error) {
	var policies []tables.TableGuardrailPolicy
	q := s.db.WithContext(ctx)
	// Hard tenant boundary first. tenant_id is the email-keyed partition -
	// shared across every UI tenant the same user owns, so it's necessary
	// but not sufficient for isolation.
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		q = q.Where("tenant_id = ?", tenant)
	}
	// Strict active-org scoping. Without this, a tenant-wide policy
	// (workspace_id IS NULL) created in DEV would surface in STAGE / PROD
	// because the workspace allowlist clause used to OR in `workspace_id
	// IS NULL` and the email tenant_id matched in every UI tenant. Rows
	// with NULL org_id are grandfathered pre-migration entries that we
	// intentionally hide rather than leak.
	if activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); activeOrg != "" {
		q = q.Where("org_id = ?", activeOrg)
	}
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id IS NULL OR workspace_id = ?", ws)
	}
	if err := q.Order("is_default DESC, enabled DESC, updated_at DESC, created_at DESC").Find(&policies).Error; err != nil {
		return nil, err
	}
	return policies, nil
}

// workspaceIDsForOrg returns the workspace IDs that belong to the given org.
// Short, indexed query - invoked on every dashboard read, so kept simple
// (caching can be layered on later if profiling shows it dominates).
func (s *RDBConfigStore) workspaceIDsForOrg(ctx context.Context, orgID string) ([]string, error) {
	var ids []string
	if err := s.db.WithContext(ctx).
		Model(&tables.TableWorkspace{}).
		Where("org_id = ?", orgID).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *RDBConfigStore) GetGuardrailPolicy(ctx context.Context, id string) (*tables.TableGuardrailPolicy, error) {
	var policy tables.TableGuardrailPolicy
	q := s.db.WithContext(ctx)
	// Without this, anyone holding a policy ID (e.g. from a leaked URL) could
	// read a policy that lives in a different tenant. Treat cross-tenant
	// fetches as not-found so we don't even confirm existence.
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		q = q.Where("tenant_id = ?", tenant)
	}
	// Same isolation as the List query: prevent cross-org reads under the
	// same email-keyed tenant_id.
	if activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); activeOrg != "" {
		q = q.Where("org_id = ?", activeOrg)
	}
	if err := q.First(&policy, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &policy, nil
}

func (s *RDBConfigStore) CreateGuardrailPolicy(ctx context.Context, policy *tables.TableGuardrailPolicy) error {
	if policy == nil {
		return nil
	}
	if strings.TrimSpace(policy.ID) == "" {
		policy.ID = uuid.NewString()
	}
	// Stamp the UI-tenant (org) so tenant-wide policies don't leak across
	// the user's other orgs under the shared email-keyed tenant_id.
	if policy.OrgID == nil || strings.TrimSpace(*policy.OrgID) == "" {
		if org := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); org != "" {
			policy.OrgID = &org
		}
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var defaultCount int64
		if err := tx.Model(&tables.TableGuardrailPolicy{}).
			Where("is_default = ?", true).
			Count(&defaultCount).Error; err != nil {
			return err
		}

		shouldDefault := policy.IsDefault || defaultCount == 0
		if shouldDefault {
			policy.IsDefault = true
			policy.Enabled = true
			if err := tx.Model(&tables.TableGuardrailPolicy{}).
				Where("id <> ? AND is_default = ?", policy.ID, true).
				Updates(map[string]any{
					"is_default": false,
					"updated_at": time.Now().UTC(),
				}).Error; err != nil {
				return err
			}
		}
		return tx.Select("*").Create(policy).Error
	})
}

func (s *RDBConfigStore) UpdateGuardrailPolicy(ctx context.Context, policy *tables.TableGuardrailPolicy) error {
	if policy == nil {
		return nil
	}
	tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx))
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Defense-in-depth: refuse to write a policy whose stored tenant
		// doesn't match the caller's active tenant. A handler-level RBAC
		// check that grants write on the active tenant would otherwise let
		// a forged ID overwrite a sibling tenant's policy.
		if tenant != "" {
			var existing tables.TableGuardrailPolicy
			if err := tx.Select("tenant_id", "org_id").First(&existing, "id = ?", policy.ID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					// New row - pin tenant on insert so it can't be created in
					// someone else's tenant.
					policy.TenantID = tenant
				} else {
					return err
				}
			} else {
				if existing.TenantID != tenant {
					return gorm.ErrRecordNotFound
				}
				// Cross-org guard: reject updates that target a policy owned by
				// a different UI tenant under the same email tenant_id. Preserve
				// the existing org_id so callers can't silently re-home a row.
				if activeOrg != "" {
					existingOrg := ""
					if existing.OrgID != nil {
						existingOrg = strings.TrimSpace(*existing.OrgID)
					}
					if existingOrg != "" && existingOrg != activeOrg {
						return gorm.ErrRecordNotFound
					}
				}
				policy.OrgID = existing.OrgID
			}
		}
		// New rows (no existing match): stamp the active org so they're
		// queryable under the same isolation rules as List.
		if policy.OrgID == nil || strings.TrimSpace(*policy.OrgID) == "" {
			if activeOrg != "" {
				policy.OrgID = &activeOrg
			}
		}
		if policy.IsDefault {
			policy.Enabled = true
			// Clearing other defaults must also stay inside the tenant -
			// otherwise promoting in Prod silently demotes DEV's default.
			clear := tx.Model(&tables.TableGuardrailPolicy{}).
				Where("id <> ? AND is_default = ?", policy.ID, true)
			if tenant != "" {
				clear = clear.Where("tenant_id = ?", tenant)
			}
			if err := clear.Updates(map[string]any{
				"is_default": false,
				"updated_at": time.Now().UTC(),
			}).Error; err != nil {
				return err
			}
		}
		return tx.Save(policy).Error
	})
}

func (s *RDBConfigStore) SetDefaultGuardrailPolicy(ctx context.Context, id string) error {
	policyID := strings.TrimSpace(id)
	if policyID == "" {
		return nil
	}
	tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx))
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Look up the policy scoped to the active tenant + org. If the caller
		// passed an ID from a different tenant or a sibling org, fail-closed
		// as not-found.
		lookup := tx
		if tenant != "" {
			lookup = lookup.Where("tenant_id = ?", tenant)
		}
		if activeOrg != "" {
			lookup = lookup.Where("org_id = ?", activeOrg)
		}
		var policy tables.TableGuardrailPolicy
		if err := lookup.First(&policy, "id = ?", policyID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		now := time.Now().UTC()
		// Clear is_default ONLY within this tenant + org. Without these
		// clauses, promoting a Prod policy would silently demote DEV's
		// default under the shared email-keyed tenant_id.
		clear := tx.Model(&tables.TableGuardrailPolicy{}).Where("is_default = ?", true)
		if tenant != "" {
			clear = clear.Where("tenant_id = ?", tenant)
		}
		if activeOrg != "" {
			clear = clear.Where("org_id = ?", activeOrg)
		}
		if err := clear.Updates(map[string]any{
			"is_default": false,
			"updated_at": now,
		}).Error; err != nil {
			return err
		}
		return tx.Model(&tables.TableGuardrailPolicy{}).
			Where("id = ?", policyID).
			Updates(map[string]any{
				"is_default": true,
				"enabled":    true,
				"updated_at": now,
			}).Error
	})
}

func (s *RDBConfigStore) DeleteGuardrailPolicy(ctx context.Context, id string) error {
	policyID := strings.TrimSpace(id)
	if policyID == "" {
		return nil
	}
	tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx))
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Refuse to delete a policy in a different tenant or org. Without
		// this, a tenant-write RBAC check passes against the active tenant
		// but the WHERE id=? still matches another org's row under the same
		// email-keyed tenant_id.
		lookup := tx.Select("id", "is_default", "org_id")
		if tenant != "" {
			lookup = lookup.Where("tenant_id = ?", tenant)
		}
		if activeOrg != "" {
			lookup = lookup.Where("org_id = ?", activeOrg)
		}
		var policy tables.TableGuardrailPolicy
		if err := lookup.First(&policy, "id = ?", policyID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if err := tx.Delete(&tables.TableGuardrailPolicy{}, "id = ?", policyID).Error; err != nil {
			return err
		}
		if !policy.IsDefault {
			return nil
		}
		// Promote a replacement default from the same tenant + org only -
		// don't reach across orgs.
		fallbackQuery := tx.Order("created_at ASC, id ASC")
		if tenant != "" {
			fallbackQuery = fallbackQuery.Where("tenant_id = ?", tenant)
		}
		if activeOrg != "" {
			fallbackQuery = fallbackQuery.Where("org_id = ?", activeOrg)
		}
		var fallback tables.TableGuardrailPolicy
		if err := fallbackQuery.First(&fallback).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		return tx.Model(&tables.TableGuardrailPolicy{}).
			Where("id = ?", fallback.ID).
			Updates(map[string]any{
				"is_default": true,
				"enabled":    true,
				"updated_at": time.Now().UTC(),
			}).Error
	})
}

func (s *RDBConfigStore) ListGuardrailPolicyVersions(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyVersion, error) {
	var versions []tables.TableGuardrailPolicyVersion
	query := s.db.WithContext(ctx).Model(&tables.TableGuardrailPolicyVersion{}).Order("version DESC, created_at DESC")
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		query = query.Where("tenant_id = ?", tenant)
	}
	if trimmedPolicyID := strings.TrimSpace(policyID); trimmedPolicyID != "" {
		query = query.Where("policy_id = ?", trimmedPolicyID)
	}
	if err := query.Find(&versions).Error; err != nil {
		return nil, err
	}
	return versions, nil
}

func (s *RDBConfigStore) GetGuardrailPolicyVersion(ctx context.Context, id string) (*tables.TableGuardrailPolicyVersion, error) {
	var version tables.TableGuardrailPolicyVersion
	q := s.db.WithContext(ctx)
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		q = q.Where("tenant_id = ?", tenant)
	}
	if err := q.First(&version, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &version, nil
}

func (s *RDBConfigStore) CreateGuardrailPolicyVersion(ctx context.Context, version *tables.TableGuardrailPolicyVersion) error {
	if version == nil {
		return nil
	}
	if strings.TrimSpace(version.ID) == "" {
		version.ID = uuid.NewString()
	}
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now().UTC()
	}
	return s.db.WithContext(ctx).Create(version).Error
}

func (s *RDBConfigStore) UpdateGuardrailPolicyVersion(ctx context.Context, version *tables.TableGuardrailPolicyVersion) error {
	if version == nil {
		return nil
	}
	return s.db.WithContext(ctx).Save(version).Error
}

func (s *RDBConfigStore) PublishGuardrailPolicyVersion(ctx context.Context, policyID, versionID, publishedBy string) error {
	policyID = strings.TrimSpace(policyID)
	versionID = strings.TrimSpace(versionID)
	publishedBy = strings.TrimSpace(publishedBy)
	if policyID == "" || versionID == "" {
		return nil
	}
	now := time.Now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var policy tables.TableGuardrailPolicy
		if err := tx.First(&policy, "id = ?", policyID).Error; err != nil {
			return err
		}
		var version tables.TableGuardrailPolicyVersion
		if err := tx.First(&version, "id = ? AND policy_id = ?", versionID, policyID).Error; err != nil {
			return err
		}
		if err := tx.Model(&tables.TableGuardrailPolicyVersion{}).
			Where("policy_id = ? AND status = ?", policyID, tables.GuardrailPolicyVersionStatusPublished).
			Updates(map[string]any{"status": tables.GuardrailPolicyVersionStatusArchived}).Error; err != nil {
			return err
		}
		if err := tx.Model(&tables.TableGuardrailPolicyVersion{}).
			Where("id = ?", versionID).
			Updates(map[string]any{
				"status":       tables.GuardrailPolicyVersionStatusPublished,
				"published_by": publishedBy,
				"published_at": now,
			}).Error; err != nil {
			return err
		}
		return tx.Model(&tables.TableGuardrailPolicy{}).
			Where("id = ?", policyID).
			Updates(map[string]any{
				"active_version_id": versionID,
				"updated_at":        now,
			}).Error
	})
}

func (s *RDBConfigStore) ListGuardrailDomainPacks(ctx context.Context) ([]tables.TableGuardrailDomainPack, error) {
	var packs []tables.TableGuardrailDomainPack
	if err := s.db.WithContext(ctx).Order("name ASC").Find(&packs).Error; err != nil {
		return nil, err
	}
	return packs, nil
}

func (s *RDBConfigStore) GetGuardrailDomainPack(ctx context.Context, id string) (*tables.TableGuardrailDomainPack, error) {
	var pack tables.TableGuardrailDomainPack
	if err := s.db.WithContext(ctx).First(&pack, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &pack, nil
}

func (s *RDBConfigStore) CreateGuardrailDomainPack(ctx context.Context, pack *tables.TableGuardrailDomainPack) error {
	if pack == nil {
		return nil
	}
	if strings.TrimSpace(pack.ID) == "" {
		pack.ID = uuid.NewString()
	}
	return s.db.WithContext(ctx).Create(pack).Error
}

func (s *RDBConfigStore) UpdateGuardrailDomainPack(ctx context.Context, pack *tables.TableGuardrailDomainPack) error {
	if pack == nil {
		return nil
	}
	return s.db.WithContext(ctx).Save(pack).Error
}

func (s *RDBConfigStore) DeleteGuardrailDomainPack(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&tables.TableGuardrailDomainPack{}, "id = ?", strings.TrimSpace(id)).Error
}

func (s *RDBConfigStore) ListGuardrailPolicyProviderBindings(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyProviderBinding, error) {
	var bindings []tables.TableGuardrailPolicyProviderBinding
	query := s.db.WithContext(ctx).Model(&tables.TableGuardrailPolicyProviderBinding{}).Order("priority ASC, created_at ASC")
	if trimmedPolicyID := strings.TrimSpace(policyID); trimmedPolicyID != "" {
		query = query.Where("policy_id = ?", trimmedPolicyID)
	}
	if err := query.Find(&bindings).Error; err != nil {
		return nil, err
	}
	return bindings, nil
}

func (s *RDBConfigStore) ReplaceGuardrailPolicyProviderBindings(ctx context.Context, policyID string, bindings []tables.TableGuardrailPolicyProviderBinding) error {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("policy_id = ?", policyID).Delete(&tables.TableGuardrailPolicyProviderBinding{}).Error; err != nil {
			return err
		}
		for i := range bindings {
			if strings.TrimSpace(bindings[i].ID) == "" {
				bindings[i].ID = uuid.NewString()
			}
			bindings[i].PolicyID = policyID
		}
		if len(bindings) == 0 {
			return nil
		}
		return tx.Create(&bindings).Error
	})
}

func (s *RDBConfigStore) ListGuardrailMCPToolPolicies(ctx context.Context, policyID string) ([]tables.TableGuardrailMCPToolPolicy, error) {
	var policies []tables.TableGuardrailMCPToolPolicy
	query := s.db.WithContext(ctx).Model(&tables.TableGuardrailMCPToolPolicy{}).Order("created_at ASC")
	if trimmedPolicyID := strings.TrimSpace(policyID); trimmedPolicyID != "" {
		query = query.Where("policy_id = ?", trimmedPolicyID)
	}
	if err := query.Find(&policies).Error; err != nil {
		return nil, err
	}
	return policies, nil
}

func (s *RDBConfigStore) ReplaceGuardrailMCPToolPolicies(ctx context.Context, policyID string, policies []tables.TableGuardrailMCPToolPolicy) error {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("policy_id = ?", policyID).Delete(&tables.TableGuardrailMCPToolPolicy{}).Error; err != nil {
			return err
		}
		for i := range policies {
			if strings.TrimSpace(policies[i].ID) == "" {
				policies[i].ID = uuid.NewString()
			}
			policies[i].PolicyID = policyID
		}
		if len(policies) == 0 {
			return nil
		}
		return tx.Create(&policies).Error
	})
}
