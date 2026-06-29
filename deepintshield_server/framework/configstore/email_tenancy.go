package configstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var emailScopedTenantModels = []any{
	&tables.TableAuthUser{},
	&tables.SessionsTable{},
	&tables.TableClientConfig{},
	&tables.TableCustomer{},
	&tables.TableBudget{},
	&tables.TableFolder{},
	&tables.TableFrameworkConfig{},
	&tables.TableModelConfig{},
	&tables.TableOauthConfig{},
	&tables.TableOauthToken{},
	&tables.TablePlugin{},
	&tables.TableMCPClient{},
	&tables.TableLogStoreConfig{},
	&tables.TableKey{},
	&tables.TableGuardrailProvider{},
	&tables.TableGuardrailPolicy{},
	&tables.TableGuardrailPolicyVersion{},
	&tables.TableGuardrailDomainPack{},
	&tables.TableGuardrailPolicyProviderBinding{},
	&tables.TableGuardrailMCPToolPolicy{},
	&tables.TableRoutingRule{},
	&tables.TableTeam{},
	&tables.TableTeamMember{},
	&tables.TableRateLimit{},
	&tables.TableVirtualKey{},
	&tables.TableVirtualKeyProviderConfig{},
	&tables.TableVirtualKeyMCPConfig{},
	&tables.TableProvider{},
	&tables.TableVectorStoreConfig{},
	&tables.TablePrompt{},
	&tables.TablePromptVersion{},
	&tables.TablePromptSession{},
}

type emailTenantUserRecord struct {
	ID           string
	Email        string
	TenantID     string
	FirstName    string
	LastName     string
	Organization string
}

// BackfillEmailScopedTenancy migrates legacy user-scoped and organization-scoped
// tenant IDs to the normalized account email. It returns the old->new mappings so
// sibling stores (such as the log store) can be updated in lockstep.
func (s *RDBConfigStore) BackfillEmailScopedTenancy(ctx context.Context) (map[string]string, error) {
	migrationCtx := tenantMigrationContext(ctx)

	var users []emailTenantUserRecord
	if err := s.db.WithContext(migrationCtx).Model(&tables.TableAuthUser{}).
		Select("id", "email", "tenant_id", "first_name", "last_name", "organization").
		Find(&users).Error; err != nil {
		return nil, err
	}

	// UUID mode (DEEPINTSHIELD_TENANT_UUID_MODE=true): stop forcing org.id to the
	// account email on boot. Instead ensure each org has a stable UUID id (new
	// orgs) + register the email as an alias, and DON'T re-key existing data -
	// the cutover of legacy email-keyed orgs is operator-gated (the /rekey
	// endpoint). Returns nil mappings so the log store isn't re-keyed here.
	if tenantUUIDMode() {
		return s.alignCanonicalTenancy(migrationCtx, users)
	}

	mappings := make(map[string]string)
	for _, user := range users {
		newTenantID := normalizeTenantEmail(user.Email)
		if newTenantID == "" {
			continue
		}
		if oldTenantID := strings.TrimSpace(user.TenantID); oldTenantID != "" && oldTenantID != newTenantID {
			mappings[oldTenantID] = newTenantID
		}
		if user.ID != "" && user.ID != newTenantID {
			mappings[user.ID] = newTenantID
		}
	}
	if len(users) == 1 {
		if soleTenantID := normalizeTenantEmail(users[0].Email); soleTenantID != "" {
			mappings[""] = soleTenantID
		}
	}

	if err := s.db.WithContext(migrationCtx).Transaction(func(tx *gorm.DB) error {
		if err := migrateTenantIDsInConfigStore(tx, mappings); err != nil {
			return err
		}

		for _, user := range users {
			newTenantID := normalizeTenantEmail(user.Email)
			if newTenantID == "" {
				continue
			}

			if err := tx.Model(&tables.TableAuthUser{}).
				Where("id = ?", user.ID).
				Update("tenant_id", newTenantID).Error; err != nil {
				return fmt.Errorf("failed to update auth user tenant for %s: %w", user.ID, err)
			}

			if err := tx.Model(&tables.SessionsTable{}).
				Where("user_id = ?", user.ID).
				Updates(map[string]any{
					"tenant_id":  newTenantID,
					"user_email": newTenantID,
				}).Error; err != nil {
				return fmt.Errorf("failed to update sessions for %s: %w", user.ID, err)
			}

			if err := ensureEmailScopedOrganization(tx, user, newTenantID); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return mappings, nil
}

// MigrateTenantIDs reassigns tenant-scoped rows from one tenant ID to another.
// It is intentionally idempotent so it can be safely reused during verified email changes.
func (s *RDBConfigStore) MigrateTenantIDs(ctx context.Context, mappings map[string]string) error {
	return s.db.WithContext(tenantMigrationContext(ctx)).Transaction(func(tx *gorm.DB) error {
		return migrateTenantIDsInConfigStore(tx, mappings)
	})
}

func migrateTenantIDsInConfigStore(tx *gorm.DB, mappings map[string]string) error {
	if tx == nil {
		return nil
	}

	normalized := normalizeTenantMappings(mappings)
	if len(normalized) == 0 {
		return nil
	}

	if err := reconcilePluginTenantConflicts(tx, normalized); err != nil {
		return err
	}

	if err := reconcileKeyTenantConflicts(tx, normalized); err != nil {
		return err
	}

	if err := reconcileProviderTenantConflicts(tx, normalized); err != nil {
		return err
	}

	for _, model := range emailScopedTenantModels {
		if !tx.Migrator().HasTable(model) {
			continue
		}
		_, isPlugin := model.(*tables.TablePlugin)
		for oldTenantID, newTenantID := range normalized {
			// Plugin rows with tenant_id='' are the global default
			// (bootstrap-loaded from config.json). Reassigning them into
			// the sole user's tenant wipes the global row, so the next
			// boot re-seeds it from config.json and silently undoes every
			// UI-saved plugin setting. Leave the global plugin row alone.
			if isPlugin && oldTenantID == "" {
				continue
			}
			query := tx.Session(&gorm.Session{SkipHooks: true}).Model(model)
			if oldTenantID == "" {
				query = query.Where("(tenant_id = '' OR tenant_id IS NULL)")
			} else {
				query = query.Where("tenant_id = ?", oldTenantID)
			}
			if err := query.UpdateColumn("tenant_id", newTenantID).Error; err != nil {
				return fmt.Errorf("failed to migrate tenant %q -> %q for %T: %w", oldTenantID, newTenantID, model, err)
			}
		}
	}

	if tx.Migrator().HasTable(&tables.TableOrganization{}) {
		for oldTenantID, newTenantID := range normalized {
			if oldTenantID == "" {
				continue
			}
			if err := tx.Session(&gorm.Session{SkipHooks: true}).
				Model(&tables.TableOrganization{}).
				Where("id = ?", oldTenantID).
				UpdateColumn("id", newTenantID).Error; err != nil {
				return fmt.Errorf("failed to migrate organization tenant %q -> %q: %w", oldTenantID, newTenantID, err)
			}
			// Follow the rename onto the FK columns that reference
			// organizations.id. Without these companion updates, every
			// rename leaves workspaces + memberships orphaned: the user
			// stops seeing their workspace under the renamed tenant,
			// and EnsureWorkspaceBackfill mints a fresh "Default"
			// alongside the now-invisible original - exactly the
			// "workspace renamed to Default after restart" symptom this
			// branch fixes.
			fkUpdates := []struct {
				model  any
				column string
			}{
				{&tables.TableWorkspace{}, "org_id"},
				{&tables.TableOrgMembership{}, "org_id"},
				{&tables.TableWorkspaceMembership{}, "org_id"},
			}
			for _, fk := range fkUpdates {
				if !tx.Migrator().HasTable(fk.model) {
					continue
				}
				if err := tx.Session(&gorm.Session{SkipHooks: true}).
					Model(fk.model).
					Where(fk.column+" = ?", oldTenantID).
					UpdateColumn(fk.column, newTenantID).Error; err != nil {
					return fmt.Errorf("failed to migrate %T.%s %q -> %q: %w", fk.model, fk.column, oldTenantID, newTenantID, err)
				}
			}
		}
	}

	// Completeness sweep: rewrite tenant_id on EVERY remaining table that has a
	// tenant_id column but isn't in emailScopedTenantModels above (billing_*,
	// agentic_*, guardrail_rag_*, scim/saml, legal_consents, model_overrides,
	// pricing_adjustments, governance_tunnel_certs, …). Without this a re-key
	// silently orphans those rows. Schema-introspected so new tenant-scoped
	// tables are covered automatically. The model pass + reconcilers above
	// already handled the conflict-prone tables; for a re-key to a fresh UUID
	// there are no unique-constraint collisions here.
	if err := migrateRemainingTenantTables(tx, normalized); err != nil {
		return err
	}

	return nil
}

// modelTableNames is the set of physical table names already handled by the
// emailScopedTenantModels pass, so the completeness sweep can skip them.
func modelTableNames() map[string]bool {
	out := make(map[string]bool, len(emailScopedTenantModels))
	for _, m := range emailScopedTenantModels {
		if t, ok := m.(interface{ TableName() string }); ok {
			out[t.TableName()] = true
		}
	}
	return out
}

// tenantScopedTableNames returns every table that has a tenant_id column,
// dialect-aware (postgres in prod, sqlite in tests/other).
func tenantScopedTableNames(tx *gorm.DB) ([]string, error) {
	var names []string
	switch tx.Dialector.Name() {
	case "sqlite", "sqlite3":
		err := tx.Raw(`SELECT m.name FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type='table' AND p.name='tenant_id'`).Scan(&names).Error
		return names, err
	default: // postgres, mysql, … expose information_schema
		err := tx.Raw(`SELECT table_name FROM information_schema.columns WHERE column_name='tenant_id' AND table_schema = current_schema()`).Scan(&names).Error
		return names, err
	}
}

// migrateRemainingTenantTables sweeps tenant_id old->new on every tenant-scoped
// table not already covered by the model pass. Idempotent.
func migrateRemainingTenantTables(tx *gorm.DB, mappings map[string]string) error {
	handled := modelTableNames()
	tableNames, err := tenantScopedTableNames(tx)
	if err != nil {
		return fmt.Errorf("failed to enumerate tenant-scoped tables: %w", err)
	}
	for _, table := range tableNames {
		if handled[table] {
			continue
		}
		for oldTenantID, newTenantID := range mappings {
			q := tx.Session(&gorm.Session{SkipHooks: true}).Table(table)
			if oldTenantID == "" {
				q = q.Where("tenant_id = '' OR tenant_id IS NULL")
			} else {
				q = q.Where("tenant_id = ?", oldTenantID)
			}
			if err := q.UpdateColumn("tenant_id", newTenantID).Error; err != nil {
				return fmt.Errorf("failed to migrate tenant %q -> %q for table %s: %w", oldTenantID, newTenantID, table, err)
			}
		}
	}
	return nil
}

// UpsertTenantAlias records (or updates) an alias_key → canonical tenant id
// mapping. Used at signup and during re-key to register the account email as a
// stable lookup key for its UUID-keyed tenant. No-op for empty / identity maps.
func (s *RDBConfigStore) UpsertTenantAlias(ctx context.Context, aliasKey, tenantID, kind string) error {
	aliasKey = normalizeTenantEmail(aliasKey)
	tenantID = strings.TrimSpace(tenantID)
	if aliasKey == "" || tenantID == "" || aliasKey == tenantID {
		return nil
	}
	if !s.db.Migrator().HasTable(&tables.TableTenantAlias{}) {
		return nil
	}
	now := time.Now().UTC()
	row := &tables.TableTenantAlias{AliasKey: aliasKey, TenantID: tenantID, Kind: kind, CreatedAt: now, UpdatedAt: now}
	return s.db.WithContext(tenantMigrationContext(ctx)).Session(&gorm.Session{SkipHooks: true}).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "alias_key"}},
			DoUpdates: clause.Assignments(map[string]any{"tenant_id": tenantID, "kind": kind, "updated_at": now}),
		}).Create(row).Error
}

// ResolveCanonicalTenant returns the canonical (UUID) tenant id for an alias
// key (typically a normalized email), or "" when no alias exists - letting the
// caller fall back to legacy email-keyed resolution during the transition.
// Bypasses the tenant-scoping callback (the lookup has no tenant context yet).
func (s *RDBConfigStore) ResolveCanonicalTenant(ctx context.Context, aliasKey string) (string, error) {
	aliasKey = normalizeTenantEmail(aliasKey)
	if aliasKey == "" {
		return "", nil
	}
	if !s.db.Migrator().HasTable(&tables.TableTenantAlias{}) {
		return "", nil
	}
	var alias tables.TableTenantAlias
	err := s.db.WithContext(tenantMigrationContext(ctx)).Session(&gorm.Session{SkipHooks: true}).
		Where("alias_key = ?", aliasKey).First(&alias).Error
	if err == nil {
		return strings.TrimSpace(alias.TenantID), nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	return "", err
}

// tenantUUIDMode reports whether the platform keys new tenants on a stable UUID
// (and registers the email as an alias) instead of using the email as the
// tenant id. Off by default - flip DEEPINTSHIELD_TENANT_UUID_MODE=true to roll
// it out. Existing email-keyed orgs are migrated separately via /rekey.
func tenantUUIDMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("DEEPINTSHIELD_TENANT_UUID_MODE")), "true")
}

// alignCanonicalTenancy is the UUID-mode boot path. It ensures every user has a
// UUID-keyed personal org + an email→canonical alias, WITHOUT re-keying existing
// data to the email. Legacy email-keyed orgs keep their id until the
// operator-gated re-key; their email alias is still registered so login
// resolves. Returns nil mappings (no lockstep log-store migration on boot).
func (s *RDBConfigStore) alignCanonicalTenancy(ctx context.Context, users []emailTenantUserRecord) (map[string]string, error) {
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, user := range users {
			email := normalizeTenantEmail(user.Email)
			if email == "" {
				continue
			}
			canonicalID, err := ensureCanonicalOrganization(tx, user)
			if err != nil {
				return err
			}
			if canonicalID == "" {
				continue // invitee - belongs to someone else's org
			}
			if tx.Migrator().HasTable(&tables.TableTenantAlias{}) {
				now := time.Now().UTC()
				if err := tx.Session(&gorm.Session{SkipHooks: true}).Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "alias_key"}},
					DoUpdates: clause.Assignments(map[string]any{"tenant_id": canonicalID, "kind": "email", "updated_at": now}),
				}).Create(&tables.TableTenantAlias{AliasKey: email, TenantID: canonicalID, Kind: "email", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
					return fmt.Errorf("failed to register tenant alias for %s: %w", user.ID, err)
				}
			}
			if err := tx.Model(&tables.TableAuthUser{}).Where("id = ?", user.ID).
				Update("tenant_id", canonicalID).Error; err != nil {
				return fmt.Errorf("failed to set auth tenant for %s: %w", user.ID, err)
			}
			if err := tx.Model(&tables.SessionsTable{}).Where("user_id = ?", user.ID).
				Update("tenant_id", canonicalID).Error; err != nil {
				return fmt.Errorf("failed to set session tenant for %s: %w", user.ID, err)
			}
		}
		return nil
	})
	return nil, err
}

// ensureCanonicalOrganization (UUID mode) ensures the user has a personal org
// with a STABLE id - a fresh UUID for brand-new orgs - and never renames the id
// to the email. Returns the canonical org id, or "" for invitees (who belong to
// someone else's org). Mirrors ensureEmailScopedOrganization minus the rename.
func ensureCanonicalOrganization(tx *gorm.DB, user emailTenantUserRecord) (string, error) {
	if tx.Migrator().HasTable(&tables.TableOrgMembership{}) {
		var foreignMembershipCount int64
		if err := tx.Model(&tables.TableOrgMembership{}).
			Joins("LEFT JOIN organizations ON organizations.id = org_memberships.org_id").
			Where("org_memberships.user_id = ? AND (organizations.owner_id IS NULL OR organizations.owner_id <> ?)", user.ID, user.ID).
			Count(&foreignMembershipCount).Error; err == nil && foreignMembershipCount > 0 {
			return "", nil
		}
	}

	// STABILITY (one stable identity per user): if the user's tenant_id already
	// points to an existing organization, that IS their canonical tenant - keep
	// it. NEVER switch a user's active tenant on boot. The old code picked
	// First(owned org) with no ORDER BY, so a super-admin who owns several
	// tenants (e.g. dev + prod under one governance_org) would get hopped to a
	// random one on each boot, orphaning all data written under the previously
	// active tenant. Honors the "one org id per super admin" design: the boot
	// path must not invent or swap tenant identity.
	if current := strings.TrimSpace(user.TenantID); current != "" {
		var cur tables.TableOrganization
		if err := tx.Where("id = ?", current).First(&cur).Error; err == nil {
			return cur.ID, nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("failed to load current tenant for %s: %w", user.ID, err)
		}
		// No organizations row for this id yet (a signup partition key). Adopt
		// it under the SAME id so data already written under it stays addressable
		// - never mint a different id and switch.
		adopt := tables.TableOrganization{
			ID:      current,
			Name:    defaultOrganizationName(user),
			Slug:    makeOrganizationSlug(user.ID, defaultOrganizationName(user)),
			OwnerID: user.ID,
			Plan:    "free",
		}
		if err := tx.Create(&adopt).Error; err != nil {
			return "", fmt.Errorf("failed to adopt tenant for %s: %w", user.ID, err)
		}
		return current, nil
	}

	var org tables.TableOrganization
	err := tx.Where("owner_id = ?", user.ID).First(&org).Error
	switch {
	case err == nil:
		updates := map[string]any{}
		if strings.TrimSpace(org.Name) == "" {
			updates["name"] = defaultOrganizationName(user)
		}
		if strings.TrimSpace(org.Slug) == "" {
			updates["slug"] = makeOrganizationSlug(user.ID, defaultOrganizationName(user))
		}
		if strings.TrimSpace(org.Plan) == "" {
			updates["plan"] = "free"
		}
		if len(updates) > 0 {
			if err := tx.Model(&tables.TableOrganization{}).Where("id = ?", org.ID).Updates(updates).Error; err != nil {
				return "", fmt.Errorf("failed to update organization for %s: %w", user.ID, err)
			}
		}
		return org.ID, nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return "", fmt.Errorf("failed to load organization for %s: %w", user.ID, err)
	}

	newID := uuid.NewString()
	org = tables.TableOrganization{
		ID:      newID,
		Name:    defaultOrganizationName(user),
		Slug:    makeOrganizationSlug(user.ID, defaultOrganizationName(user)),
		OwnerID: user.ID,
		Plan:    "free",
	}
	if err := tx.Create(&org).Error; err != nil {
		return "", fmt.Errorf("failed to create organization for %s: %w", user.ID, err)
	}
	return newID, nil
}

func reconcileKeyTenantConflicts(tx *gorm.DB, mappings map[string]string) error {
	if tx == nil || !tx.Migrator().HasTable(&tables.TableKey{}) {
		return nil
	}

	for oldTenantID, newTenantID := range mappings {
		var sourceKeys []tables.TableKey
		query := tx.Session(&gorm.Session{SkipHooks: true}).Model(&tables.TableKey{})
		if oldTenantID == "" {
			query = query.Where("(tenant_id = '' OR tenant_id IS NULL)")
		} else {
			query = query.Where("tenant_id = ?", oldTenantID)
		}
		if err := query.Find(&sourceKeys).Error; err != nil {
			return fmt.Errorf("failed to list keys for tenant %q: %w", oldTenantID, err)
		}

		var targetKeys []tables.TableKey
		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Where("tenant_id = ?", newTenantID).
			Find(&targetKeys).Error; err != nil {
			return fmt.Errorf("failed to list keys for tenant %q: %w", newTenantID, err)
		}

		targetKeysByID := make(map[string]tables.TableKey, len(targetKeys))
		targetKeysByName := make(map[string]tables.TableKey, len(targetKeys))
		for _, targetKey := range targetKeys {
			if keyID := strings.TrimSpace(targetKey.KeyID); keyID != "" {
				targetKeysByID[keyID] = targetKey
			}
			if keyName := strings.TrimSpace(targetKey.Name); keyName != "" {
				targetKeysByName[keyName] = targetKey
			}
		}

		for _, sourceKey := range sourceKeys {
			var duplicate *tables.TableKey
			if keyID := strings.TrimSpace(sourceKey.KeyID); keyID != "" {
				if existing, ok := targetKeysByID[keyID]; ok {
					duplicate = &existing
				}
			}
			if duplicate == nil {
				if keyName := strings.TrimSpace(sourceKey.Name); keyName != "" {
					if existing, ok := targetKeysByName[keyName]; ok {
						duplicate = &existing
					}
				}
			}
			if duplicate == nil || duplicate.ID == sourceKey.ID {
				continue
			}

			if err := mergeKeyTenantConflict(tx, &sourceKey, duplicate, newTenantID); err != nil {
				return err
			}
		}
	}

	return nil
}

func mergeKeyTenantConflict(tx *gorm.DB, sourceKey, targetKey *tables.TableKey, newTenantID string) error {
	if tx == nil || sourceKey == nil || targetKey == nil {
		return nil
	}

	if updates := mergeKeyMetadata(targetKey, sourceKey); len(updates) > 0 {
		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Model(&tables.TableKey{}).
			Where("id = ?", targetKey.ID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to merge key %q into tenant %q: %w", sourceKey.Name, newTenantID, err)
		}
	}

	if err := reassignVirtualKeyProviderConfigKeyRefs(tx, sourceKey.ID, targetKey.ID); err != nil {
		return err
	}

	if err := tx.Session(&gorm.Session{SkipHooks: true}).
		Where("id = ?", sourceKey.ID).
		Delete(&tables.TableKey{}).Error; err != nil {
		return fmt.Errorf("failed to delete duplicate key %q for tenant %q: %w", sourceKey.Name, newTenantID, err)
	}

	return nil
}

func reassignVirtualKeyProviderConfigKeyRefs(tx *gorm.DB, sourceKeyID, targetKeyID uint) error {
	if tx == nil || sourceKeyID == 0 || targetKeyID == 0 || sourceKeyID == targetKeyID {
		return nil
	}
	if !tx.Migrator().HasTable(&tables.TableVirtualKeyProviderConfigKey{}) {
		return nil
	}

	var associations []tables.TableVirtualKeyProviderConfigKey
	if err := tx.Session(&gorm.Session{SkipHooks: true}).
		Where("table_key_id = ?", sourceKeyID).
		Find(&associations).Error; err != nil {
		return fmt.Errorf("failed to list virtual key associations for key %d: %w", sourceKeyID, err)
	}

	for _, association := range associations {
		var count int64
		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Model(&tables.TableVirtualKeyProviderConfigKey{}).
			Where("table_virtual_key_provider_config_id = ? AND table_key_id = ?", association.TableVirtualKeyProviderConfigID, targetKeyID).
			Count(&count).Error; err != nil {
			return fmt.Errorf("failed to check virtual key association for key %d: %w", targetKeyID, err)
		}

		query := tx.Session(&gorm.Session{SkipHooks: true}).
			Where("table_virtual_key_provider_config_id = ? AND table_key_id = ?", association.TableVirtualKeyProviderConfigID, sourceKeyID)
		if count > 0 {
			if err := query.Delete(&tables.TableVirtualKeyProviderConfigKey{}).Error; err != nil {
				return fmt.Errorf("failed to delete duplicate virtual key association for key %d: %w", sourceKeyID, err)
			}
			continue
		}

		if err := query.Model(&tables.TableVirtualKeyProviderConfigKey{}).
			Update("table_key_id", targetKeyID).Error; err != nil {
			return fmt.Errorf("failed to reassign virtual key association from key %d to %d: %w", sourceKeyID, targetKeyID, err)
		}
	}

	return nil
}

func reconcilePluginTenantConflicts(tx *gorm.DB, mappings map[string]string) error {
	if tx == nil || !tx.Migrator().HasTable(&tables.TablePlugin{}) {
		return nil
	}

	for oldTenantID, newTenantID := range mappings {
		// Preserve the global default plugin row (tenant_id=''). It is the
		// bootstrap-loaded source of truth that the gateway reads at
		// startup before any tenant context exists. Migrating it into the
		// sole user's tenant wipes the row, so the next bootstrap re-seeds
		// it from config.json defaults - silently undoing every UI-saved
		// plugin setting on each gateway restart.
		if oldTenantID == "" {
			continue
		}
		var sourcePlugins []tables.TablePlugin
		query := tx.Session(&gorm.Session{SkipHooks: true}).Model(&tables.TablePlugin{}).
			Where("tenant_id = ?", oldTenantID)
		if err := query.Find(&sourcePlugins).Error; err != nil {
			return fmt.Errorf("failed to list plugins for tenant %q: %w", oldTenantID, err)
		}

		for _, sourcePlugin := range sourcePlugins {
			var targetPlugin tables.TablePlugin
			err := tx.Session(&gorm.Session{SkipHooks: true}).
				Where("tenant_id = ? AND name = ?", newTenantID, sourcePlugin.Name).
				First(&targetPlugin).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			if err != nil {
				return fmt.Errorf("failed to load target plugin %q for tenant %q: %w", sourcePlugin.Name, newTenantID, err)
			}
			if sourcePlugin.ID == targetPlugin.ID {
				continue
			}

			if err := mergePluginTenantConflict(tx, &sourcePlugin, &targetPlugin, newTenantID); err != nil {
				return err
			}
		}
	}

	return nil
}

func mergePluginTenantConflict(tx *gorm.DB, sourcePlugin, targetPlugin *tables.TablePlugin, newTenantID string) error {
	if tx == nil || sourcePlugin == nil || targetPlugin == nil {
		return nil
	}

	if updates := mergePluginMetadata(targetPlugin, sourcePlugin); len(updates) > 0 {
		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Model(&tables.TablePlugin{}).
			Where("id = ?", targetPlugin.ID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to merge plugin %q metadata into tenant %q: %w", sourcePlugin.Name, newTenantID, err)
		}
	}

	if err := tx.Session(&gorm.Session{SkipHooks: true}).
		Where("id = ?", sourcePlugin.ID).
		Delete(&tables.TablePlugin{}).Error; err != nil {
		return fmt.Errorf("failed to delete duplicate plugin %q for tenant %q: %w", sourcePlugin.Name, newTenantID, err)
	}

	return nil
}

func mergePluginMetadata(targetPlugin, sourcePlugin *tables.TablePlugin) map[string]any {
	if targetPlugin == nil || sourcePlugin == nil {
		return nil
	}

	updates := map[string]any{}

	if pluginPath := strings.TrimSpace(pluginPathValue(targetPlugin.Path)); pluginPath == "" {
		if sourcePath := strings.TrimSpace(pluginPathValue(sourcePlugin.Path)); sourcePath != "" {
			updates["path"] = sourcePath
			updates["is_custom"] = true
		}
	}

	if isEmptySerializedJSON(targetPlugin.ConfigJSON) && !isEmptySerializedJSON(sourcePlugin.ConfigJSON) {
		updates["config_json"] = sourcePlugin.ConfigJSON
		if strings.TrimSpace(sourcePlugin.EncryptionStatus) != "" {
			updates["encryption_status"] = sourcePlugin.EncryptionStatus
		}
	}

	if targetPlugin.Version < sourcePlugin.Version {
		updates["version"] = sourcePlugin.Version
	}
	if !targetPlugin.IsCustom && sourcePlugin.IsCustom {
		updates["is_custom"] = true
	}
	if targetPlugin.Placement == nil && sourcePlugin.Placement != nil {
		updates["placement"] = *sourcePlugin.Placement
	}
	if targetPlugin.Order == nil && sourcePlugin.Order != nil {
		updates["exec_order"] = *sourcePlugin.Order
	}
	if strings.TrimSpace(targetPlugin.ConfigHash) == "" && strings.TrimSpace(sourcePlugin.ConfigHash) != "" {
		updates["config_hash"] = sourcePlugin.ConfigHash
	}
	if strings.TrimSpace(targetPlugin.EncryptionStatus) == "" && strings.TrimSpace(sourcePlugin.EncryptionStatus) != "" {
		updates["encryption_status"] = sourcePlugin.EncryptionStatus
	}

	return updates
}

func reconcileProviderTenantConflicts(tx *gorm.DB, mappings map[string]string) error {
	if tx == nil || !tx.Migrator().HasTable(&tables.TableProvider{}) {
		return nil
	}

	for oldTenantID, newTenantID := range mappings {
		var sourceProviders []tables.TableProvider
		query := tx.Session(&gorm.Session{SkipHooks: true}).
			Preload("Keys").
			Preload("Models").
			Model(&tables.TableProvider{})
		if oldTenantID == "" {
			query = query.Where("(tenant_id = '' OR tenant_id IS NULL)")
		} else {
			query = query.Where("tenant_id = ?", oldTenantID)
		}
		if err := query.Find(&sourceProviders).Error; err != nil {
			return fmt.Errorf("failed to list providers for tenant %q: %w", oldTenantID, err)
		}

		for _, sourceProvider := range sourceProviders {
			var targetProvider tables.TableProvider
			err := tx.Session(&gorm.Session{SkipHooks: true}).
				Preload("Keys").
				Preload("Models").
				Where("tenant_id = ? AND name = ?", newTenantID, sourceProvider.Name).
				First(&targetProvider).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			if err != nil {
				return fmt.Errorf("failed to load target provider %q for tenant %q: %w", sourceProvider.Name, newTenantID, err)
			}
			if sourceProvider.ID == targetProvider.ID {
				continue
			}

			if err := mergeProviderTenantConflict(tx, &sourceProvider, &targetProvider, newTenantID); err != nil {
				return err
			}
		}
	}

	return nil
}

func mergeProviderTenantConflict(tx *gorm.DB, sourceProvider, targetProvider *tables.TableProvider, newTenantID string) error {
	if tx == nil || sourceProvider == nil || targetProvider == nil {
		return nil
	}

	if mergeProviderMetadata(targetProvider, sourceProvider) {
		if err := tx.Session(&gorm.Session{SkipHooks: true}).Save(targetProvider).Error; err != nil {
			return fmt.Errorf("failed to merge provider %q metadata into tenant %q: %w", sourceProvider.Name, newTenantID, err)
		}
	}

	if err := mergeProviderKeys(tx, sourceProvider, targetProvider, newTenantID); err != nil {
		return err
	}
	if err := mergeProviderModels(tx, sourceProvider, targetProvider); err != nil {
		return err
	}

	if err := tx.Session(&gorm.Session{SkipHooks: true}).
		Where("id = ?", sourceProvider.ID).
		Delete(&tables.TableProvider{}).Error; err != nil {
		return fmt.Errorf("failed to delete duplicate provider %q for tenant %q: %w", sourceProvider.Name, newTenantID, err)
	}

	return nil
}

func mergeProviderMetadata(targetProvider, sourceProvider *tables.TableProvider) bool {
	if targetProvider == nil || sourceProvider == nil {
		return false
	}

	changed := false

	if targetProvider.NetworkConfig == nil && sourceProvider.NetworkConfig != nil {
		cfg := *sourceProvider.NetworkConfig
		targetProvider.NetworkConfig = &cfg
		changed = true
	}
	if targetProvider.ConcurrencyAndBufferSize == nil && sourceProvider.ConcurrencyAndBufferSize != nil {
		cfg := *sourceProvider.ConcurrencyAndBufferSize
		targetProvider.ConcurrencyAndBufferSize = &cfg
		changed = true
	}
	if targetProvider.ProxyConfig == nil && sourceProvider.ProxyConfig != nil {
		cfg := *sourceProvider.ProxyConfig
		targetProvider.ProxyConfig = &cfg
		changed = true
	}
	if targetProvider.CustomProviderConfig == nil && sourceProvider.CustomProviderConfig != nil {
		cfg := *sourceProvider.CustomProviderConfig
		targetProvider.CustomProviderConfig = &cfg
		changed = true
	}
	if len(targetProvider.PricingOverrides) == 0 && len(sourceProvider.PricingOverrides) > 0 {
		targetProvider.PricingOverrides = append([]schemas.ProviderPricingOverride(nil), sourceProvider.PricingOverrides...)
		changed = true
	}
	if !targetProvider.SendBackRawRequest && sourceProvider.SendBackRawRequest {
		targetProvider.SendBackRawRequest = true
		changed = true
	}
	if !targetProvider.SendBackRawResponse && sourceProvider.SendBackRawResponse {
		targetProvider.SendBackRawResponse = true
		changed = true
	}
	if !targetProvider.StoreRawRequestResponse && sourceProvider.StoreRawRequestResponse {
		targetProvider.StoreRawRequestResponse = true
		changed = true
	}
	if targetProvider.BudgetID == nil && sourceProvider.BudgetID != nil {
		budgetID := *sourceProvider.BudgetID
		targetProvider.BudgetID = &budgetID
		changed = true
	}
	if targetProvider.RateLimitID == nil && sourceProvider.RateLimitID != nil {
		rateLimitID := *sourceProvider.RateLimitID
		targetProvider.RateLimitID = &rateLimitID
		changed = true
	}
	if strings.TrimSpace(targetProvider.ConfigHash) == "" && strings.TrimSpace(sourceProvider.ConfigHash) != "" {
		targetProvider.ConfigHash = sourceProvider.ConfigHash
		changed = true
	}
	if (strings.TrimSpace(targetProvider.Status) == "" || targetProvider.Status == "unknown") &&
		strings.TrimSpace(sourceProvider.Status) != "" && sourceProvider.Status != "unknown" {
		targetProvider.Status = sourceProvider.Status
		changed = true
	}
	if strings.TrimSpace(targetProvider.Description) == "" && strings.TrimSpace(sourceProvider.Description) != "" {
		targetProvider.Description = sourceProvider.Description
		changed = true
	}

	return changed
}

func mergeProviderKeys(tx *gorm.DB, sourceProvider, targetProvider *tables.TableProvider, newTenantID string) error {
	if tx == nil || !tx.Migrator().HasTable(&tables.TableKey{}) {
		return nil
	}

	targetKeysByID := make(map[string]tables.TableKey, len(targetProvider.Keys))
	targetKeysByName := make(map[string]tables.TableKey, len(targetProvider.Keys))
	for _, targetKey := range targetProvider.Keys {
		if strings.TrimSpace(targetKey.KeyID) != "" {
			targetKeysByID[targetKey.KeyID] = targetKey
		}
		if strings.TrimSpace(targetKey.Name) != "" {
			targetKeysByName[targetKey.Name] = targetKey
		}
	}

	for _, sourceKey := range sourceProvider.Keys {
		var duplicate *tables.TableKey
		if keyID := strings.TrimSpace(sourceKey.KeyID); keyID != "" {
			if existing, ok := targetKeysByID[keyID]; ok {
				duplicate = &existing
			}
		}
		if duplicate == nil {
			if keyName := strings.TrimSpace(sourceKey.Name); keyName != "" {
				if existing, ok := targetKeysByName[keyName]; ok {
					duplicate = &existing
				}
			}
		}

		if duplicate != nil {
			updates := mergeKeyMetadata(duplicate, &sourceKey)
			if strings.TrimSpace(duplicate.TenantID) != newTenantID {
				updates["tenant_id"] = newTenantID
			}
			if duplicate.ProviderID != targetProvider.ID {
				updates["provider_id"] = targetProvider.ID
			}
			if strings.TrimSpace(duplicate.Provider) != targetProvider.Name {
				updates["provider"] = targetProvider.Name
			}
			if len(updates) > 0 {
				if err := tx.Session(&gorm.Session{SkipHooks: true}).
					Model(&tables.TableKey{}).
					Where("id = ?", duplicate.ID).
					Updates(updates).Error; err != nil {
					return fmt.Errorf("failed to merge duplicate key %q for provider %q: %w", sourceKey.Name, sourceProvider.Name, err)
				}
			}
			if err := tx.Session(&gorm.Session{SkipHooks: true}).
				Where("id = ?", sourceKey.ID).
				Delete(&tables.TableKey{}).Error; err != nil {
				return fmt.Errorf("failed to delete duplicate key %q for provider %q: %w", sourceKey.Name, sourceProvider.Name, err)
			}
			continue
		}

		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Model(&tables.TableKey{}).
			Where("id = ?", sourceKey.ID).
			Updates(map[string]any{
				"tenant_id":   newTenantID,
				"provider_id": targetProvider.ID,
				"provider":    targetProvider.Name,
			}).Error; err != nil {
			return fmt.Errorf("failed to reassign key %q to provider %q: %w", sourceKey.Name, targetProvider.Name, err)
		}
	}

	return nil
}

func mergeKeyMetadata(targetKey, sourceKey *tables.TableKey) map[string]any {
	if targetKey == nil || sourceKey == nil {
		return nil
	}

	updates := map[string]any{}
	if strings.TrimSpace(targetKey.Value.GetValue()) == "" && strings.TrimSpace(sourceKey.Value.GetValue()) != "" {
		updates["value"] = sourceKey.Value
	}
	if isEmptySerializedJSON(targetKey.ModelsJSON) && !isEmptySerializedJSON(sourceKey.ModelsJSON) {
		updates["models_json"] = sourceKey.ModelsJSON
	}
	if targetKey.Weight == nil && sourceKey.Weight != nil {
		updates["weight"] = *sourceKey.Weight
	}
	if targetKey.Enabled == nil && sourceKey.Enabled != nil {
		updates["enabled"] = *sourceKey.Enabled
	}
	if targetKey.UseForBatchAPI == nil && sourceKey.UseForBatchAPI != nil {
		updates["use_for_batch_api"] = *sourceKey.UseForBatchAPI
	}
	if targetKey.UseForCache == nil && sourceKey.UseForCache != nil {
		updates["use_for_cache"] = *sourceKey.UseForCache
	}
	if !envVarPtrHasValue(targetKey.AzureEndpoint) && envVarPtrHasValue(sourceKey.AzureEndpoint) {
		updates["azure_endpoint"] = *sourceKey.AzureEndpoint
	}
	if !envVarPtrHasValue(targetKey.AzureAPIVersion) && envVarPtrHasValue(sourceKey.AzureAPIVersion) {
		updates["azure_api_version"] = *sourceKey.AzureAPIVersion
	}
	if !stringPtrHasValue(targetKey.AzureDeploymentsJSON) && stringPtrHasValue(sourceKey.AzureDeploymentsJSON) {
		updates["azure_deployments_json"] = *sourceKey.AzureDeploymentsJSON
	}
	if !envVarPtrHasValue(targetKey.AzureClientID) && envVarPtrHasValue(sourceKey.AzureClientID) {
		updates["azure_client_id"] = *sourceKey.AzureClientID
	}
	if !envVarPtrHasValue(targetKey.AzureClientSecret) && envVarPtrHasValue(sourceKey.AzureClientSecret) {
		updates["azure_client_secret"] = *sourceKey.AzureClientSecret
	}
	if !envVarPtrHasValue(targetKey.AzureTenantID) && envVarPtrHasValue(sourceKey.AzureTenantID) {
		updates["azure_tenant_id"] = *sourceKey.AzureTenantID
	}
	if !stringPtrHasValue(targetKey.AzureScopesJSON) && stringPtrHasValue(sourceKey.AzureScopesJSON) {
		updates["azure_scopes"] = *sourceKey.AzureScopesJSON
	}
	if !envVarPtrHasValue(targetKey.VertexProjectID) && envVarPtrHasValue(sourceKey.VertexProjectID) {
		updates["vertex_project_id"] = *sourceKey.VertexProjectID
	}
	if !envVarPtrHasValue(targetKey.VertexProjectNumber) && envVarPtrHasValue(sourceKey.VertexProjectNumber) {
		updates["vertex_project_number"] = *sourceKey.VertexProjectNumber
	}
	if !envVarPtrHasValue(targetKey.VertexRegion) && envVarPtrHasValue(sourceKey.VertexRegion) {
		updates["vertex_region"] = *sourceKey.VertexRegion
	}
	if !envVarPtrHasValue(targetKey.VertexAuthCredentials) && envVarPtrHasValue(sourceKey.VertexAuthCredentials) {
		updates["vertex_auth_credentials"] = *sourceKey.VertexAuthCredentials
	}
	if !stringPtrHasValue(targetKey.VertexDeploymentsJSON) && stringPtrHasValue(sourceKey.VertexDeploymentsJSON) {
		updates["vertex_deployments_json"] = *sourceKey.VertexDeploymentsJSON
	}
	if !envVarPtrHasValue(targetKey.BedrockAccessKey) && envVarPtrHasValue(sourceKey.BedrockAccessKey) {
		updates["bedrock_access_key"] = *sourceKey.BedrockAccessKey
	}
	if !envVarPtrHasValue(targetKey.BedrockSecretKey) && envVarPtrHasValue(sourceKey.BedrockSecretKey) {
		updates["bedrock_secret_key"] = *sourceKey.BedrockSecretKey
	}
	if !envVarPtrHasValue(targetKey.BedrockSessionToken) && envVarPtrHasValue(sourceKey.BedrockSessionToken) {
		updates["bedrock_session_token"] = *sourceKey.BedrockSessionToken
	}
	if !envVarPtrHasValue(targetKey.BedrockRegion) && envVarPtrHasValue(sourceKey.BedrockRegion) {
		updates["bedrock_region"] = *sourceKey.BedrockRegion
	}
	if !envVarPtrHasValue(targetKey.BedrockARN) && envVarPtrHasValue(sourceKey.BedrockARN) {
		updates["bedrock_arn"] = *sourceKey.BedrockARN
	}
	if !envVarPtrHasValue(targetKey.BedrockRoleARN) && envVarPtrHasValue(sourceKey.BedrockRoleARN) {
		updates["bedrock_role_arn"] = *sourceKey.BedrockRoleARN
	}
	if !envVarPtrHasValue(targetKey.BedrockExternalID) && envVarPtrHasValue(sourceKey.BedrockExternalID) {
		updates["bedrock_external_id"] = *sourceKey.BedrockExternalID
	}
	if !envVarPtrHasValue(targetKey.BedrockRoleSessionName) && envVarPtrHasValue(sourceKey.BedrockRoleSessionName) {
		updates["bedrock_role_session_name"] = *sourceKey.BedrockRoleSessionName
	}
	if !stringPtrHasValue(targetKey.BedrockDeploymentsJSON) && stringPtrHasValue(sourceKey.BedrockDeploymentsJSON) {
		updates["bedrock_deployments_json"] = *sourceKey.BedrockDeploymentsJSON
	}
	if !stringPtrHasValue(targetKey.BedrockBatchS3ConfigJSON) && stringPtrHasValue(sourceKey.BedrockBatchS3ConfigJSON) {
		updates["bedrock_batch_s3_config_json"] = *sourceKey.BedrockBatchS3ConfigJSON
	}
	if !stringPtrHasValue(targetKey.ReplicateDeploymentsJSON) && stringPtrHasValue(sourceKey.ReplicateDeploymentsJSON) {
		updates["replicate_deployments_json"] = *sourceKey.ReplicateDeploymentsJSON
	}
	if !envVarPtrHasValue(targetKey.VLLMUrl) && envVarPtrHasValue(sourceKey.VLLMUrl) {
		updates["vllm_url"] = *sourceKey.VLLMUrl
	}
	if !stringPtrHasValue(targetKey.VLLMModelName) && stringPtrHasValue(sourceKey.VLLMModelName) {
		updates["vllm_model_name"] = *sourceKey.VLLMModelName
	}
	if strings.TrimSpace(targetKey.ConfigHash) == "" && strings.TrimSpace(sourceKey.ConfigHash) != "" {
		updates["config_hash"] = sourceKey.ConfigHash
	}
	if (strings.TrimSpace(targetKey.Status) == "" || targetKey.Status == "unknown") &&
		strings.TrimSpace(sourceKey.Status) != "" && sourceKey.Status != "unknown" {
		updates["status"] = sourceKey.Status
	}
	if strings.TrimSpace(targetKey.Description) == "" && strings.TrimSpace(sourceKey.Description) != "" {
		updates["description"] = sourceKey.Description
	}
	if strings.TrimSpace(targetKey.EncryptionStatus) == "" && strings.TrimSpace(sourceKey.EncryptionStatus) != "" {
		updates["encryption_status"] = sourceKey.EncryptionStatus
	}

	return updates
}

func mergeProviderModels(tx *gorm.DB, sourceProvider, targetProvider *tables.TableProvider) error {
	if tx == nil || !tx.Migrator().HasTable(&tables.TableModel{}) {
		return nil
	}

	targetModelsByName := make(map[string]tables.TableModel, len(targetProvider.Models))
	for _, targetModel := range targetProvider.Models {
		if strings.TrimSpace(targetModel.Name) != "" {
			targetModelsByName[targetModel.Name] = targetModel
		}
	}

	for _, sourceModel := range sourceProvider.Models {
		if _, exists := targetModelsByName[sourceModel.Name]; exists {
			if err := tx.Session(&gorm.Session{SkipHooks: true}).
				Where("id = ?", sourceModel.ID).
				Delete(&tables.TableModel{}).Error; err != nil {
				return fmt.Errorf("failed to delete duplicate model %q for provider %q: %w", sourceModel.Name, sourceProvider.Name, err)
			}
			continue
		}

		if err := tx.Session(&gorm.Session{SkipHooks: true}).
			Model(&tables.TableModel{}).
			Where("id = ?", sourceModel.ID).
			Update("provider_id", targetProvider.ID).Error; err != nil {
			return fmt.Errorf("failed to reassign model %q to provider %q: %w", sourceModel.Name, targetProvider.Name, err)
		}
	}

	return nil
}

func normalizeTenantMappings(mappings map[string]string) map[string]string {
	normalized := make(map[string]string)
	for oldTenantID, newTenantID := range mappings {
		oldTenantID = strings.TrimSpace(oldTenantID)
		newTenantID = normalizeTenantEmail(newTenantID)
		if newTenantID == "" || (oldTenantID != "" && oldTenantID == newTenantID) {
			continue
		}
		normalized[oldTenantID] = newTenantID
	}
	return normalized
}

func normalizeTenantEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func pluginPathValue(path *string) string {
	if path == nil {
		return ""
	}
	return *path
}

func stringPtrHasValue(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func envVarPtrHasValue(value *schemas.EnvVar) bool {
	return value != nil && strings.TrimSpace(value.GetValue()) != ""
}

func isEmptySerializedJSON(payload string) bool {
	trimmed := strings.TrimSpace(payload)
	return trimmed == "" || trimmed == "{}" || trimmed == "[]" || trimmed == "null"
}

func tenantMigrationContext(context.Context) context.Context {
	return context.Background()
}

func ensureEmailScopedOrganization(tx *gorm.DB, user emailTenantUserRecord, tenantID string) error {
	// Invitees should NOT get an auto-provisioned personal tenant.
	// Signal: if this user already holds an org_membership in a tenant
	// they don't own, they joined an existing workspace via invitation
	// (or SSO JIT against a customer's connection) and shouldn't have
	// a parallel "info@example.com" tenant cluttering their switcher.
	//
	// Founders signing up for the first time have zero memberships at
	// this point - the backfill is the bootstrap that gives them one
	// - so they still get a personal tenant via the create branch below.
	if tx.Migrator().HasTable(&tables.TableOrgMembership{}) {
		var foreignMembershipCount int64
		if err := tx.Model(&tables.TableOrgMembership{}).
			Joins("LEFT JOIN organizations ON organizations.id = org_memberships.org_id").
			Where("org_memberships.user_id = ? AND (organizations.owner_id IS NULL OR organizations.owner_id <> ?)", user.ID, user.ID).
			Count(&foreignMembershipCount).Error; err == nil && foreignMembershipCount > 0 {
			// This user is an invitee - skip personal tenant provisioning.
			return nil
		}
	}

	var org tables.TableOrganization
	err := tx.Where("owner_id = ?", user.ID).First(&org).Error
	switch {
	case err == nil:
		updates := map[string]any{}
		if org.ID != tenantID {
			// Renaming organizations.id is only safe if no other row
			// already occupies the target ID. Otherwise we'd violate the
			// primary key (SQLSTATE 23505) and abort the entire bootstrap
			// transaction. This collision happens whenever:
			//   - the migration has run before and the target row already
			//     exists with the right ID (so we just need to leave it
			//     alone), or
			//   - two users share the same email-derived tenant ID (e.g.
			//     duplicate dev accounts) - both can't own the same row.
			// In either case the conservative move is to skip the id
			// update; other field updates (name/slug/plan) still apply.
			var collision int64
			if cErr := tx.Model(&tables.TableOrganization{}).
				Where("id = ?", tenantID).
				Count(&collision).Error; cErr != nil {
				return fmt.Errorf("failed to check organization collision for %s: %w", user.ID, cErr)
			}
			if collision > 0 {
				delete(updates, "id")
			} else {
				updates["id"] = tenantID
			}
		}
		if strings.TrimSpace(org.Name) == "" {
			updates["name"] = defaultOrganizationName(user)
		}
		if strings.TrimSpace(org.Slug) == "" {
			updates["slug"] = makeOrganizationSlug(user.ID, defaultOrganizationName(user))
		}
		if strings.TrimSpace(org.Plan) == "" {
			updates["plan"] = "free"
		}
		if len(updates) == 0 {
			return nil
		}
		// Capture the old id BEFORE the update so we can follow the
		// rename onto FK columns below. Without this, workspaces +
		// memberships pointing at the old UUID stay dangling, and on
		// the next boot ensureDefaultWorkspace mints a synthetic
		// "Default" alongside the now-invisible original - exactly the
		// "workspaces missing after restart" symptom this branch fixes.
		oldOrgID := org.ID
		// Scope the update to the specific org row we just loaded - not
		// every row owned by this user. With the post–self-serve flow a
		// single user can own multiple tenants (each with its own UUID
		// id), and `Where("owner_id = ?", user.ID).Updates({id: tenantID})`
		// would try to set every owned org to the same id, violating
		// the organizations primary-key uniqueness (SQLSTATE 23505) and
		// crashing the bootstrap.
		if err := tx.Model(&tables.TableOrganization{}).
			Where("id = ?", org.ID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update organization for %s: %w", user.ID, err)
		}
		// Follow the rename onto FK columns that reference
		// organizations.id. Mirrors the same fix applied in
		// migrateTenantIDsInConfigStore - necessary here too because
		// ensureEmailScopedOrganization is a separate code path that
		// bypasses the tenant-mapping rewrite.
		if newID, ok := updates["id"].(string); ok && newID != "" && newID != oldOrgID {
			fkUpdates := []struct {
				model  any
				column string
			}{
				{&tables.TableWorkspace{}, "org_id"},
				{&tables.TableOrgMembership{}, "org_id"},
				{&tables.TableWorkspaceMembership{}, "org_id"},
			}
			for _, fk := range fkUpdates {
				if !tx.Migrator().HasTable(fk.model) {
					continue
				}
				if err := tx.Session(&gorm.Session{SkipHooks: true}).
					Model(fk.model).
					Where(fk.column+" = ?", oldOrgID).
					UpdateColumn(fk.column, newID).Error; err != nil {
					return fmt.Errorf("failed to migrate %T.%s %q -> %q: %w", fk.model, fk.column, oldOrgID, newID, err)
				}
			}
		}
		return nil
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		return fmt.Errorf("failed to load organization for %s: %w", user.ID, err)
	}

	org = tables.TableOrganization{
		ID:      tenantID,
		Name:    defaultOrganizationName(user),
		Slug:    makeOrganizationSlug(user.ID, defaultOrganizationName(user)),
		OwnerID: user.ID,
		Plan:    "free",
	}
	if err := tx.Create(&org).Error; err != nil {
		return fmt.Errorf("failed to create organization for %s: %w", user.ID, err)
	}
	return nil
}

func defaultOrganizationName(user emailTenantUserRecord) string {
	if name := strings.TrimSpace(user.Organization); name != "" && !looksLikeUUID(name) {
		// Skip values that look like a UUID - Entra's `tid` and a few
		// other IdP claims are machine identifiers, and earlier JIT code
		// paths accidentally stored them on auth_users.organization. We
		// don't want those leaking into the tenant switcher as the
		// organization Name. Falls through to the human-friendly defaults.
		return name
	}
	if fullName := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName)); fullName != "" {
		return fullName
	}
	return normalizeTenantEmail(user.Email)
}

// looksLikeUUID matches the canonical 8-4-4-4-12 hex form. Cheap visual
// check - false negatives on non-canonical UUIDs are fine because the
// caller's fallback is also a sane value.
func looksLikeUUID(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

func makeOrganizationSlug(seed, name string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		seed = uuid.NewString()
	}
	if len(seed) > 8 {
		seed = seed[:8]
	}

	slug := strings.ToLower(strings.TrimSpace(name))
	if slug == "" {
		slug = "workspace"
	}
	slug = strings.NewReplacer(" ", "-", "@", "-", ".", "-", "_", "-").Replace(slug)
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "workspace"
	}
	return seed + "-" + slug
}
