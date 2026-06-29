package configstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackfillEmailScopedTenancy_MigratesLegacyTenantData(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{},
		&tables.SessionsTable{},
		&tables.TableOrganization{},
		&tables.TableFolder{},
		&tables.TablePrompt{},
		&tables.TablePromptVersion{},
		&tables.TablePromptSession{},
	))

	userID := "user-1"
	legacyTenantID := "org-tenant-1"
	targetTenantID := "alice@example.com"
	userEmail := "Alice@Example.com"

	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:           userID,
		TenantID:     legacyTenantID,
		FirstName:    "Alice",
		LastName:     "Tester",
		Organization: "Acme",
		Industry:     "Security",
		Email:        userEmail,
	}).Error)

	sessionEmail := targetTenantID
	require.NoError(t, store.db.Create(&tables.SessionsTable{
		TenantID:  legacyTenantID,
		Token:     "session-token",
		UserID:    &userID,
		UserEmail: &sessionEmail,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}).Error)

	require.NoError(t, store.db.Create(&tables.TableOrganization{
		ID:      legacyTenantID,
		Name:    "Acme",
		Slug:    "acme-org",
		OwnerID: userID,
		Plan:    "free",
	}).Error)

	require.NoError(t, store.db.Create(&tables.TableFolder{
		ID:       "folder-1",
		TenantID: legacyTenantID,
		Name:     "Shared Folder",
	}).Error)

	require.NoError(t, store.db.Create(&tables.TablePrompt{
		ID:       "prompt-1",
		TenantID: legacyTenantID,
		Name:     "Shared Prompt",
	}).Error)

	require.NoError(t, store.db.Create(&tables.TablePromptVersion{
		TenantID:      legacyTenantID,
		PromptID:      "prompt-1",
		VersionNumber: 1,
		CommitMessage: "initial",
		IsLatest:      true,
	}).Error)

	require.NoError(t, store.db.Create(&tables.TablePromptSession{
		TenantID: legacyTenantID,
		PromptID: "prompt-1",
		Name:     "Draft Session",
	}).Error)

	require.NoError(t, store.db.Create(&tables.TablePlugin{
		TenantID: userID,
		Name:     "demo-plugin",
		Enabled:  true,
	}).Error)

	mappings, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, targetTenantID, mappings[legacyTenantID])
	assert.Equal(t, targetTenantID, mappings[userID])

	var user tables.TableAuthUser
	require.NoError(t, store.db.First(&user, "id = ?", userID).Error)
	assert.Equal(t, targetTenantID, user.Email)
	assert.Equal(t, targetTenantID, user.TenantID)

	var session tables.SessionsTable
	require.NoError(t, store.db.First(&session, "user_id = ?", userID).Error)
	assert.Equal(t, targetTenantID, session.TenantID)
	require.NotNil(t, session.UserEmail)
	assert.Equal(t, targetTenantID, *session.UserEmail)

	var folder tables.TableFolder
	require.NoError(t, store.db.First(&folder, "id = ?", "folder-1").Error)
	assert.Equal(t, targetTenantID, folder.TenantID)

	var plugin tables.TablePlugin
	require.NoError(t, store.db.First(&plugin, "name = ?", "demo-plugin").Error)
	assert.Equal(t, targetTenantID, plugin.TenantID)

	var prompt tables.TablePrompt
	require.NoError(t, store.db.First(&prompt, "id = ?", "prompt-1").Error)
	assert.Equal(t, targetTenantID, prompt.TenantID)

	var version tables.TablePromptVersion
	require.NoError(t, store.db.First(&version, "prompt_id = ?", "prompt-1").Error)
	assert.Equal(t, targetTenantID, version.TenantID)

	var sessionDraft tables.TablePromptSession
	require.NoError(t, store.db.First(&sessionDraft, "prompt_id = ?", "prompt-1").Error)
	assert.Equal(t, targetTenantID, sessionDraft.TenantID)

	var org tables.TableOrganization
	require.NoError(t, store.db.First(&org, "owner_id = ?", userID).Error)
	assert.Equal(t, targetTenantID, org.ID)
	assert.Equal(t, "Acme", org.Name)
}

func TestBackfillEmailScopedTenancy_ClaimsTenantlessRowsForSoleUser(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{},
		&tables.SessionsTable{},
		&tables.TableOrganization{},
		&tables.TableClientConfig{},
		&tables.TableFolder{},
		&tables.TablePrompt{},
		&tables.TablePromptVersion{},
		&tables.TablePromptSession{},
	))

	targetTenantID := "solo@example.com"
	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:           "user-1",
		TenantID:     targetTenantID,
		FirstName:    "Solo",
		LastName:     "User",
		Organization: "Solo Org",
		Industry:     "Security",
		Email:        targetTenantID,
	}).Error)

	require.NoError(t, store.db.Create(&tables.TableClientConfig{
		DropExcessRequests: true,
		InitialPoolSize:    42,
	}).Error)
	require.NoError(t, store.db.Create(&tables.TableFolder{
		ID:   "folder-tenantless",
		Name: "Tenantless Folder",
	}).Error)
	require.NoError(t, store.db.Create(&tables.TablePrompt{
		ID:   "prompt-tenantless",
		Name: "Tenantless Prompt",
	}).Error)
	require.NoError(t, store.db.Create(&tables.TablePromptVersion{
		PromptID:      "prompt-tenantless",
		VersionNumber: 1,
		CommitMessage: "initial",
		IsLatest:      true,
	}).Error)
	require.NoError(t, store.db.Create(&tables.TablePromptSession{
		PromptID: "prompt-tenantless",
		Name:     "Draft Session",
	}).Error)

	mappings, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, targetTenantID, mappings[""])

	var clientConfig tables.TableClientConfig
	require.NoError(t, store.db.First(&clientConfig).Error)
	assert.Equal(t, targetTenantID, clientConfig.TenantID)

	var folder tables.TableFolder
	require.NoError(t, store.db.First(&folder, "id = ?", "folder-tenantless").Error)
	assert.Equal(t, targetTenantID, folder.TenantID)

	var prompt tables.TablePrompt
	require.NoError(t, store.db.First(&prompt, "id = ?", "prompt-tenantless").Error)
	assert.Equal(t, targetTenantID, prompt.TenantID)

	var version tables.TablePromptVersion
	require.NoError(t, store.db.First(&version, "prompt_id = ?", "prompt-tenantless").Error)
	assert.Equal(t, targetTenantID, version.TenantID)

	var session tables.TablePromptSession
	require.NoError(t, store.db.First(&session, "prompt_id = ?", "prompt-tenantless").Error)
	assert.Equal(t, targetTenantID, session.TenantID)
}

func TestBackfillEmailScopedTenancy_MergesDuplicateProvidersBeforeTenantRewrite(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{},
		&tables.SessionsTable{},
		&tables.TableOrganization{},
		&tables.TableModel{},
	))

	targetTenantID := "tenant-a@example.com"
	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:       "user-1",
		TenantID: targetTenantID,
		Email:    targetTenantID,
	}).Error)

	sourceProvider := tables.TableProvider{
		TenantID: "",
		Name:     string(schemas.OpenAI),
	}
	require.NoError(t, store.db.Create(&sourceProvider).Error)

	targetProvider := tables.TableProvider{
		TenantID: targetTenantID,
		Name:     string(schemas.OpenAI),
	}
	require.NoError(t, store.db.Create(&targetProvider).Error)

	sourceWeight := 1.0
	require.NoError(t, store.db.Create(&tables.TableKey{
		TenantID:   "",
		ProviderID: sourceProvider.ID,
		Provider:   sourceProvider.Name,
		KeyID:      "legacy-openai-key",
		Name:       "OpenAI API Key",
		Value:      *schemas.NewEnvVar("sk-legacy"),
		Weight:     &sourceWeight,
		Models:     []string{"gpt-4o-mini"},
	}).Error)

	targetWeight := 2.0
	require.NoError(t, store.db.Create(&tables.TableKey{
		TenantID:   targetTenantID,
		ProviderID: targetProvider.ID,
		Provider:   targetProvider.Name,
		KeyID:      "tenant-openai-key",
		Name:       "OpenAI API Key",
		Value:      *schemas.NewEnvVar("sk-tenant"),
		Weight:     &targetWeight,
		Models:     []string{"gpt-4o-mini"},
	}).Error)

	require.NoError(t, store.db.Create(&tables.TableModel{
		ID:         "legacy-model",
		ProviderID: sourceProvider.ID,
		Name:       "gpt-4o-mini",
	}).Error)
	require.NoError(t, store.db.Create(&tables.TableModel{
		ID:         "tenant-model",
		ProviderID: targetProvider.ID,
		Name:       "gpt-4o-mini",
	}).Error)

	mappings, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, targetTenantID, mappings[""])

	var providers []tables.TableProvider
	require.NoError(t, store.db.Where("tenant_id = ? AND name = ?", targetTenantID, string(schemas.OpenAI)).Find(&providers).Error)
	require.Len(t, providers, 1, "duplicate providers should be collapsed before tenant rewrite")

	var keys []tables.TableKey
	require.NoError(t, store.db.Where("tenant_id = ? AND provider = ?", targetTenantID, string(schemas.OpenAI)).Find(&keys).Error)
	require.Len(t, keys, 1, "duplicate keys should be deduplicated during provider merge")
	assert.Equal(t, "tenant-openai-key", keys[0].KeyID, "existing tenant-scoped key should win conflicts")
	assert.Equal(t, "sk-tenant", keys[0].Value.GetValue())

	var models []tables.TableModel
	require.NoError(t, store.db.Where("provider_id = ?", providers[0].ID).Find(&models).Error)
	require.Len(t, models, 1, "duplicate models should be deduplicated during provider merge")
	assert.Equal(t, "gpt-4o-mini", models[0].Name)
}

func TestBackfillEmailScopedTenancy_MergesDuplicateKeysBeforeTenantRewrite(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{},
		&tables.SessionsTable{},
		&tables.TableOrganization{},
		&tables.TableModel{},
		&tables.TableProvider{},
		&tables.TableKey{},
	))

	targetTenantID := "tenant-a@example.com"
	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:       "user-1",
		TenantID: targetTenantID,
		Email:    targetTenantID,
	}).Error)

	sourceProvider := tables.TableProvider{
		TenantID: "",
		Name:     string(schemas.OpenAI),
	}
	require.NoError(t, store.db.Create(&sourceProvider).Error)

	targetProvider := tables.TableProvider{
		TenantID: targetTenantID,
		Name:     string(schemas.Anthropic),
	}
	require.NoError(t, store.db.Create(&targetProvider).Error)

	sourceWeight := 1.5
	require.NoError(t, store.db.Create(&tables.TableKey{
		TenantID:   "",
		ProviderID: sourceProvider.ID,
		Provider:   sourceProvider.Name,
		KeyID:      "legacy-openai-key",
		Name:       "Primary API Key",
		Value:      *schemas.NewEnvVar("sk-legacy"),
		Models:     []string{"gpt-4o-mini"},
		Weight:     &sourceWeight,
		ConfigHash: "legacy-key-hash",
	}).Error)

	require.NoError(t, store.db.Create(&tables.TableKey{
		TenantID:   targetTenantID,
		ProviderID: targetProvider.ID,
		Provider:   targetProvider.Name,
		KeyID:      "tenant-anthropic-key",
		Name:       "Primary API Key",
		Value:      *schemas.NewEnvVar(""),
	}).Error)

	mappings, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, targetTenantID, mappings[""])

	var keys []tables.TableKey
	require.NoError(t, store.db.Where("tenant_id = ? AND name = ?", targetTenantID, "Primary API Key").Find(&keys).Error)
	require.Len(t, keys, 1, "duplicate keys should be collapsed before tenant rewrite")
	assert.Equal(t, "tenant-anthropic-key", keys[0].KeyID, "existing tenant-scoped key should win conflicts")
	assert.Equal(t, targetProvider.ID, keys[0].ProviderID, "existing tenant-scoped provider binding should be preserved")
	assert.Equal(t, "sk-legacy", keys[0].Value.GetValue(), "missing key value should be filled from tenantless duplicate")
	assert.Equal(t, []string{"gpt-4o-mini"}, keys[0].Models, "serialized model metadata should be preserved during merge")
	require.NotNil(t, keys[0].Weight)
	assert.Equal(t, sourceWeight, *keys[0].Weight)
	assert.Equal(t, "legacy-key-hash", keys[0].ConfigHash)
}

func TestBackfillEmailScopedTenancy_RepairsDuplicateKeyTenantScope(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{},
		&tables.SessionsTable{},
		&tables.TableOrganization{},
		&tables.TableModel{},
	))

	legacyTenantID := "org-tenant-1"
	targetTenantID := "tenant-a@example.com"
	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:       "user-1",
		TenantID: legacyTenantID,
		Email:    targetTenantID,
	}).Error)

	sourceProvider := tables.TableProvider{
		TenantID: legacyTenantID,
		Name:     string(schemas.OpenAI),
	}
	require.NoError(t, store.db.Create(&sourceProvider).Error)

	targetProvider := tables.TableProvider{
		TenantID: targetTenantID,
		Name:     string(schemas.OpenAI),
	}
	require.NoError(t, store.db.Create(&targetProvider).Error)

	require.NoError(t, store.db.Create(&tables.TableKey{
		TenantID:   legacyTenantID,
		ProviderID: sourceProvider.ID,
		Provider:   sourceProvider.Name,
		KeyID:      "legacy-openai-key",
		Name:       "Primary API Key",
		Value:      *schemas.NewEnvVar("sk-legacy"),
	}).Error)

	require.NoError(t, store.db.Create(&tables.TableKey{
		TenantID:   "",
		ProviderID: targetProvider.ID,
		Provider:   targetProvider.Name,
		KeyID:      "tenant-openai-key",
		Name:       "Primary API Key",
		Value:      *schemas.NewEnvVar(""),
	}).Error)

	mappings, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, targetTenantID, mappings[legacyTenantID])

	var keys []tables.TableKey
	require.NoError(t, store.db.Where("provider_id = ?", targetProvider.ID).Find(&keys).Error)
	require.Len(t, keys, 1)
	assert.Equal(t, targetTenantID, keys[0].TenantID)
	assert.Equal(t, targetProvider.ID, keys[0].ProviderID)
	assert.Equal(t, targetProvider.Name, keys[0].Provider)
	assert.Equal(t, "tenant-openai-key", keys[0].KeyID)
	assert.Equal(t, "sk-legacy", keys[0].Value.GetValue())
}

// TestBackfillEmailScopedTenancy_PreservesGlobalPluginRow asserts the
// post-fix contract: plugin rows with tenant_id=” are the global
// default (loaded by the bootstrap at startup before any tenant context
// exists) and must NOT be migrated into the sole user's tenant.
// Migrating them caused every gateway restart to silently reset
// UI-saved plugin settings back to config.json defaults - see
// reconcilePluginTenantConflicts and migrateTenantIDsInConfigStore for
// the matching "skip empty oldTenantID" guards.
//
// Previously this test was named MergesDuplicatePluginsBeforeTenantRewrite
// and asserted the opposite (that the global row gets merged into the
// tenant row, then deleted). That behaviour is intentionally gone.
func TestBackfillEmailScopedTenancy_PreservesGlobalPluginRow(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{},
		&tables.SessionsTable{},
		&tables.TableOrganization{},
		&tables.TablePlugin{},
	))

	targetTenantID := "tenant-a@example.com"
	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:       "user-1",
		TenantID: targetTenantID,
		Email:    targetTenantID,
	}).Error)

	placement := schemas.PluginPlacementPreBuiltin
	order := 7
	path := "/plugins/semantic-cache"
	globalPlugin := tables.TablePlugin{
		TenantID:   "",
		Name:       "semantic_cache",
		Enabled:    true,
		Path:       &path,
		Version:    2,
		IsCustom:   true,
		Placement:  &placement,
		Order:      &order,
		ConfigHash: "legacy-semantic-cache-hash",
		Config: map[string]any{
			"provider":        "openai",
			"embedding_model": "text-embedding-3-small",
		},
	}
	require.NoError(t, store.db.Create(&globalPlugin).Error)

	tenantPlugin := tables.TablePlugin{
		TenantID: targetTenantID,
		Name:     "semantic_cache",
		Enabled:  false,
		Version:  1,
	}
	require.NoError(t, store.db.Create(&tenantPlugin).Error)

	mappings, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, targetTenantID, mappings[""])

	// Both rows must still exist after the backfill: the global default
	// is preserved, and the tenant row is left untouched.
	var allPlugins []tables.TablePlugin
	require.NoError(t, store.db.Where("name = ?", "semantic_cache").Find(&allPlugins).Error)
	require.Len(t, allPlugins, 2, "global plugin row must NOT be merged into tenant row")

	byTenant := map[string]tables.TablePlugin{}
	for _, p := range allPlugins {
		byTenant[p.TenantID] = p
	}
	global, ok := byTenant[""]
	require.True(t, ok, "global tenant_id='' plugin row should survive backfill")
	assert.True(t, global.Enabled, "global row stays at its original enabled flag")
	require.NotNil(t, global.Path)
	assert.Equal(t, path, *global.Path)
	assert.Equal(t, int16(2), global.Version)
	assert.Equal(t, "legacy-semantic-cache-hash", global.ConfigHash)

	tenant, ok := byTenant[targetTenantID]
	require.True(t, ok, "tenant-scoped plugin row should still be present")
	assert.False(t, tenant.Enabled, "tenant row keeps its original enabled flag")
	assert.Equal(t, int16(1), tenant.Version, "tenant row version is not bumped by the migration")
}

// TestMigrateTenantIDs_SweepsNonModelTenantTables proves the completeness sweep
// re-keys tenant_id on tables NOT in emailScopedTenantModels (billing, legal
// consents, tunnel certs, …) - the rows a re-key used to silently orphan.
func TestMigrateTenantIDs_SweepsNonModelTenantTables(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableOrganization{},
		&tables.TableLegalConsent{},
		&tables.TableTunnelCert{},
	))

	oldID := "legacy-user@example.com" // email-keyed tenant id
	newID := "11111111-2222-3333-4444-555555555555"
	now := time.Now().UTC()

	require.NoError(t, store.db.Create(&tables.TableOrganization{
		ID: oldID, Name: "prod", Slug: "prod", OwnerID: "user-1", Plan: "free",
	}).Error)
	require.NoError(t, store.db.Create(&tables.TableLegalConsent{
		ID: "lc-1", TenantID: oldID, UserID: "user-1", EmailAtConsent: oldID,
		DocumentType: "tos", DocumentVersion: "1", DocumentHash: "h", ConsentMethod: "click",
		AcceptedAt: now, CreatedAt: now,
	}).Error)
	require.NoError(t, store.db.Create(&tables.TableTunnelCert{
		ID: "tc-1", TenantID: oldID, Serial: "abc123", NotAfter: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}).Error)

	require.NoError(t, store.MigrateTenantIDs(context.Background(), map[string]string{oldID: newID}))

	// organizations.id followed the rename (existing behavior).
	var org tables.TableOrganization
	require.NoError(t, store.db.First(&org, "id = ?", newID).Error)

	_ = org // (avoid unused in case asserts below change)
	verifyNonModelSwept(t, store, oldID, newID)
}

func verifyNonModelSwept(t *testing.T, store *RDBConfigStore, oldID, newID string) {
	t.Helper()
	for _, tbl := range []string{"legal_consents", "governance_tunnel_certs"} {
		var oldCount, newCount int64
		require.NoError(t, store.db.Table(tbl).Where("tenant_id = ?", oldID).Count(&oldCount).Error)
		require.NoError(t, store.db.Table(tbl).Where("tenant_id = ?", newID).Count(&newCount).Error)
		assert.Equal(t, int64(0), oldCount, "%s should have NO rows left under the old email tenant", tbl)
		assert.Equal(t, int64(1), newCount, "%s row should have moved to the new UUID tenant", tbl)
	}
}

// TestTenantAlias_ResolveAndUpsert covers the email→canonical(UUID) alias layer.
func TestTenantAlias_ResolveAndUpsert(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(&tables.TableTenantAlias{}))
	ctx := context.Background()

	// No alias yet → "" so callers fall back to legacy resolution.
	got, err := store.ResolveCanonicalTenant(ctx, "Alice@Example.com")
	require.NoError(t, err)
	assert.Equal(t, "", got)

	uuidID := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, store.UpsertTenantAlias(ctx, "Alice@Example.com", uuidID, "email"))

	// Resolves case-insensitively.
	got, err = store.ResolveCanonicalTenant(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, uuidID, got)

	// Idempotent re-point.
	newUUID := "99999999-2222-3333-4444-555555555555"
	require.NoError(t, store.UpsertTenantAlias(ctx, "ALICE@EXAMPLE.COM", newUUID, "email"))
	got, err = store.ResolveCanonicalTenant(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, newUUID, got)
}

// TestBackfill_UUIDMode_MintsUUIDOrgAndAlias proves that with UUID mode on, a
// fresh user gets a UUID-keyed org (not an email id) + an email alias, and the
// boot path never re-keys data to the email.
func TestBackfill_UUIDMode_MintsUUIDOrgAndAlias(t *testing.T) {
	t.Setenv("DEEPINTSHIELD_TENANT_UUID_MODE", "true")
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(
		&tables.TableAuthUser{}, &tables.SessionsTable{}, &tables.TableOrganization{},
		&tables.TableOrgMembership{}, &tables.TableTenantAlias{},
	))
	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID: "user-1", TenantID: "", Email: "Founder@Acme.com", FirstName: "Foo", LastName: "Bar",
	}).Error)

	_, err := store.BackfillEmailScopedTenancy(context.Background())
	require.NoError(t, err)

	// A UUID org was minted - id is NOT the email.
	var org tables.TableOrganization
	require.NoError(t, store.db.Where("owner_id = ?", "user-1").First(&org).Error)
	assert.NotEqual(t, "founder@acme.com", org.ID, "org id must not be the email")
	_, perr := uuid.Parse(org.ID)
	assert.NoError(t, perr, "org id should be a UUID")

	// auth_users.tenant_id points at the UUID, not the email.
	var u tables.TableAuthUser
	require.NoError(t, store.db.First(&u, "id = ?", "user-1").Error)
	assert.Equal(t, org.ID, u.TenantID)

	// email→uuid alias registered + resolves.
	resolved, err := store.ResolveCanonicalTenant(context.Background(), "founder@acme.com")
	require.NoError(t, err)
	assert.Equal(t, org.ID, resolved)
}
