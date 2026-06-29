package configstore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupRDBTestStore creates an in-memory SQLite database and returns an RDBConfigStore for testing
func setupRDBTestStore(t *testing.T) *RDBConfigStore {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err, "Failed to create test database")
	require.NoError(t, registerTenantCallbacks(db), "Failed to register tenant callbacks")

	// Run migrations for all tables
	err = db.AutoMigrate(
		&tables.TableProvider{},
		&tables.TableKey{},
		&tables.TableBudget{},
		&tables.TableRateLimit{},
		&tables.TableVirtualKey{},
		&tables.TableVirtualKeyProviderConfig{},
		&tables.TableVirtualKeyProviderConfigKey{},
		&tables.TableVirtualKeyGuardrailPolicy{},
		&tables.TableCustomer{},
		&tables.TableTeam{},
		&tables.TableTeamMember{},
		&tables.TableTeamCustomerMember{},
		&tables.TableClientConfig{},
		&tables.TableSCIMProviderConfig{},
		&tables.TableSCIMLoginState{},
		&tables.TableGovernanceConfig{},
		&tables.TablePlugin{},
		&tables.TableMCPClient{},
		&tables.TableVirtualKeyMCPConfig{},
		&tables.TableFolder{},
		&tables.TablePrompt{},
		&tables.TablePromptVersion{},
		&tables.TablePromptVersionMessage{},
		&tables.TablePromptSession{},
		&tables.TablePromptSessionMessage{},
		&tables.TableAuthUser{},
		&tables.TableOrganization{},
		&tables.TableGuardrailPolicy{},
		&tables.TableGuardrailPolicyVersion{},
	)
	require.NoError(t, err, "Failed to migrate test database")

	// Setup join table
	err = db.SetupJoinTable(&tables.TableVirtualKeyProviderConfig{}, "Keys", &tables.TableVirtualKeyProviderConfigKey{})
	require.NoError(t, err, "Failed to setup join table")
	err = db.SetupJoinTable(&tables.TableVirtualKey{}, "GuardrailPolicies", &tables.TableVirtualKeyGuardrailPolicy{})
	require.NoError(t, err, "Failed to setup join table for virtual key guardrail policies")

	return &RDBConfigStore{
		db:     db,
		logger: nil,
	}
}

func withTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, schemas.DeepIntShieldContextKeyTenantID, tenantID)
}

func boolPtr(v bool) *bool {
	return &v
}

func TestGetAuthConfig_DefaultDisableAuthOnInferenceWhenUnset(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.db.WithContext(ctx).Create(&tables.TableGovernanceConfig{
		Key:   tables.ConfigAdminUsernameKey,
		Value: "admin",
	}).Error)
	require.NoError(t, store.db.WithContext(ctx).Create(&tables.TableGovernanceConfig{
		Key:   tables.ConfigAdminPasswordKey,
		Value: "hashed-password",
	}).Error)
	require.NoError(t, store.db.WithContext(ctx).Create(&tables.TableGovernanceConfig{
		Key:   tables.ConfigIsAuthEnabledKey,
		Value: "true",
	}).Error)

	authConfig, err := store.GetAuthConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, authConfig)
	assert.True(t, authConfig.DisableAuthOnInference)
}

func TestGetSingleTenantID_ReturnsOnlyTenant(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateUser(ctx, &tables.TableAuthUser{
		ID:           "user-1",
		Email:        "alice@example.com",
		Organization: "Alice Org",
		TenantID:     "alice@example.com",
	}))

	tenantID, err := store.GetSingleTenantID(ctx)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", tenantID)
}

func TestGetSingleTenantID_ReturnsEmptyWhenMultipleTenantsExist(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.CreateUser(ctx, &tables.TableAuthUser{
		ID:           "user-1",
		Email:        "alice@example.com",
		Organization: "Alice Org",
		TenantID:     "alice@example.com",
	}))
	require.NoError(t, store.CreateUser(ctx, &tables.TableAuthUser{
		ID:           "user-2",
		Email:        "bob@example.com",
		Organization: "Bob Org",
		TenantID:     "bob@example.com",
	}))

	tenantID, err := store.GetSingleTenantID(ctx)
	require.NoError(t, err)
	assert.Empty(t, tenantID)
}

func TestUpsertSCIMProviderConfig_IsolatedByTenant(t *testing.T) {
	store := setupRDBTestStore(t)

	tenantA := withTenant(context.Background(), "alice@example.com")
	tenantB := withTenant(context.Background(), "bob@example.com")

	require.NoError(t, store.UpsertSCIMProviderConfig(tenantA, &tables.TableSCIMProviderConfig{
		ID:                "scim-a",
		Provider:          "entra",
		Enabled:           true,
		DirectoryTenantID: "tenant-a",
		ClientID:          "client-a",
		UserIDField:       "oid",
		RolesField:        "roles",
		TeamIDsField:      "groups",
		RoleMappings:      []tables.SCIMRoleMapping{{Source: "app_role", Value: "admin", Role: "admin"}},
	}))
	require.NoError(t, store.UpsertSCIMProviderConfig(tenantB, &tables.TableSCIMProviderConfig{
		ID:                "scim-b",
		Provider:          "entra",
		Enabled:           true,
		DirectoryTenantID: "tenant-b",
		ClientID:          "client-b",
		UserIDField:       "oid",
		RolesField:        "roles",
		TeamIDsField:      "groups",
		RoleMappings:      []tables.SCIMRoleMapping{{Source: "app_role", Value: "viewer", Role: "viewer"}},
	}))

	configA, err := store.GetSCIMProviderConfig(tenantA, "entra")
	require.NoError(t, err)
	require.NotNil(t, configA)
	assert.Equal(t, "tenant-a", configA.DirectoryTenantID)
	assert.Equal(t, "client-a", configA.ClientID)
	require.Len(t, configA.RoleMappings, 1)
	assert.Equal(t, "admin", configA.RoleMappings[0].Role)

	configB, err := store.GetSCIMProviderConfig(tenantB, "entra")
	require.NoError(t, err)
	require.NotNil(t, configB)
	assert.Equal(t, "tenant-b", configB.DirectoryTenantID)
	assert.Equal(t, "client-b", configB.ClientID)
	require.Len(t, configB.RoleMappings, 1)
	assert.Equal(t, "viewer", configB.RoleMappings[0].Role)
}

// =============================================================================
// Provider and Key Tests
// =============================================================================

func TestUpdateProvidersConfig_CreateNew(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	providers := map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{
					ID:     "key-uuid-1",
					Name:   "openai-primary",
					Value:  *schemas.NewEnvVar("sk-test-key"),
					Weight: 1.0,
				},
			},
		},
	}

	err := store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	// Verify provider was created
	result, err := store.GetProvidersConfig(ctx)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Contains(t, result, schemas.ModelProvider("openai"))
	assert.Len(t, result["openai"].Keys, 1)
	assert.Equal(t, "openai-primary", result["openai"].Keys[0].Name)
}

func TestUpdateProvidersConfig_UpdateExistingByKeyID(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create initial provider with key
	providers := map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{
					ID:     "key-uuid-1",
					Name:   "openai-primary",
					Value:  *schemas.NewEnvVar("sk-test-key-v1"),
					Weight: 1.0,
				},
			},
		},
	}
	err := store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	// Update with same KeyID but different value
	providers["openai"] = ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:     "key-uuid-1", // Same KeyID
				Name:   "openai-primary",
				Value:  *schemas.NewEnvVar("sk-test-key-v2"), // Updated value
				Weight: 2.0,
			},
		},
	}
	err = store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	// Verify key was updated, not duplicated
	result, err := store.GetProvidersConfig(ctx)
	require.NoError(t, err)
	assert.Len(t, result["openai"].Keys, 1)
	assert.Equal(t, "sk-test-key-v2", result["openai"].Keys[0].Value.Val)
}

func TestUpdateProvidersConfig_UpdateExistingByName_FallbackFix(t *testing.T) {
	// This test verifies the fix for the unique constraint violation issue
	// when a new UUID is generated for a key that already exists by name
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create initial provider with key
	providers := map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{
					ID:     "original-uuid",
					Name:   "openai-primary",
					Value:  *schemas.NewEnvVar("sk-test-key-v1"),
					Weight: 1.0,
				},
			},
		},
	}
	err := store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	// Simulate config reload with NEW UUID (as happens when loading from config file)
	providers["openai"] = ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:     "new-uuid-from-config-reload", // Different UUID!
				Name:   "openai-primary",              // Same name
				Value:  *schemas.NewEnvVar("sk-test-key-v2"),
				Weight: 1.5,
			},
		},
	}
	err = store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err, "Should not fail with unique constraint violation")

	// Verify key was updated (not duplicated) and original KeyID preserved
	result, err := store.GetProvidersConfig(ctx)
	require.NoError(t, err)
	assert.Len(t, result["openai"].Keys, 1, "Should have exactly one key, not duplicated")
	assert.Equal(t, "sk-test-key-v2", result["openai"].Keys[0].Value.Val, "Value should be updated")
	assert.Equal(t, "original-uuid", result["openai"].Keys[0].ID, "Original KeyID should be preserved")
}

func TestUpdateProvider_UpdateExistingByNameFallback(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	err := store.AddProvider(ctx, "openai", ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:     "original-uuid",
				Name:   "openai-primary",
				Value:  *schemas.NewEnvVar("sk-test-key-v1"),
				Weight: 1.0,
			},
		},
	})
	require.NoError(t, err)

	err = store.UpdateProvider(ctx, "openai", ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:     "new-or-missing-ui-id",
				Name:   "openai-primary",
				Value:  *schemas.NewEnvVar("sk-test-key-v2"),
				Weight: 2.0,
			},
		},
	})
	require.NoError(t, err)

	result, err := store.GetProvidersConfig(ctx)
	require.NoError(t, err)
	require.Len(t, result["openai"].Keys, 1)
	assert.Equal(t, "sk-test-key-v2", result["openai"].Keys[0].Value.Val)
	assert.Equal(t, 2.0, result["openai"].Keys[0].Weight)
	assert.Equal(t, "original-uuid", result["openai"].Keys[0].ID)
}

func TestUpdateProvider_TenantScopedUpdatePreservesKeyVisibility(t *testing.T) {
	store := setupRDBTestStore(t)
	tenantCtx := withTenant(context.Background(), "alice@example.com")

	err := store.AddProvider(tenantCtx, "openai", ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:      "existing-uuid",
				Name:    "openai-primary",
				Value:   *schemas.NewEnvVar("sk-test-key-v1"),
				Weight:  1.0,
				Enabled: boolPtr(true),
			},
		},
	})
	require.NoError(t, err)

	err = store.UpdateProvider(tenantCtx, "openai", ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:      "existing-uuid",
				Name:    "openai-primary",
				Value:   *schemas.NewEnvVar("sk-test-key-v2"),
				Weight:  2.0,
				Enabled: boolPtr(true),
			},
		},
	})
	require.NoError(t, err)

	result, err := store.GetProviderConfig(tenantCtx, "openai")
	require.NoError(t, err)
	require.Len(t, result.Keys, 1)
	assert.Equal(t, "existing-uuid", result.Keys[0].ID)
	assert.Equal(t, "openai-primary", result.Keys[0].Name)
	assert.Equal(t, "sk-test-key-v2", result.Keys[0].Value.Val)

	var dbKey tables.TableKey
	require.NoError(t, store.db.WithContext(tenantCtx).Where("key_id = ?", "existing-uuid").First(&dbKey).Error)
	assert.Equal(t, "alice@example.com", dbKey.TenantID)
}

func TestTenantScopedProviderReads_RepairTenantlessKeyRows(t *testing.T) {
	store := setupRDBTestStore(t)
	tenantCtx := withTenant(context.Background(), "alice@example.com")

	require.NoError(t, store.AddProvider(tenantCtx, "openai", ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:      "existing-uuid",
				Name:    "openai-primary",
				Value:   *schemas.NewEnvVar("sk-test-key-v1"),
				Weight:  1.0,
				Enabled: boolPtr(true),
			},
		},
	}))

	var provider tables.TableProvider
	require.NoError(t, store.db.WithContext(tenantMigrationContext(context.Background())).
		Where("tenant_id = ? AND name = ?", "alice@example.com", "openai").
		First(&provider).Error)

	require.NoError(t, store.db.WithContext(tenantMigrationContext(context.Background())).
		Model(&tables.TableKey{}).
		Where("provider_id = ?", provider.ID).
		Updates(map[string]any{"tenant_id": "", "provider": "openai"}).Error)

	providers, err := store.GetProvidersConfig(tenantCtx)
	require.NoError(t, err)
	require.Len(t, providers["openai"].Keys, 1)
	assert.Equal(t, "openai-primary", providers["openai"].Keys[0].Name)

	require.NoError(t, store.db.WithContext(tenantMigrationContext(context.Background())).
		Model(&tables.TableKey{}).
		Where("provider_id = ?", provider.ID).
		Updates(map[string]any{"tenant_id": "", "provider": "openai"}).Error)

	singleProvider, err := store.GetProviderConfig(tenantCtx, "openai")
	require.NoError(t, err)
	require.Len(t, singleProvider.Keys, 1)
	assert.Equal(t, "openai-primary", singleProvider.Keys[0].Name)

	var repairedKey tables.TableKey
	require.NoError(t, store.db.WithContext(tenantMigrationContext(context.Background())).
		Where("provider_id = ?", provider.ID).
		First(&repairedKey).Error)
	assert.Equal(t, "alice@example.com", repairedKey.TenantID)
	assert.Equal(t, provider.ID, repairedKey.ProviderID)
}

func TestUpdateProvidersConfig_MultipleKeys(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	providers := map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{ID: "key-1", Name: "openai-primary", Value: *schemas.NewEnvVar("sk-key-1"), Weight: 1.0},
				{ID: "key-2", Name: "openai-secondary", Value: *schemas.NewEnvVar("sk-key-2"), Weight: 0.5},
			},
		},
		"anthropic": {
			Keys: []schemas.Key{
				{ID: "key-3", Name: "anthropic-main", Value: *schemas.NewEnvVar("sk-key-3"), Weight: 1.0},
			},
		},
	}

	err := store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	result, err := store.GetProvidersConfig(ctx)
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Len(t, result["openai"].Keys, 2)
	assert.Len(t, result["anthropic"].Keys, 1)
}

func TestUpdateProvidersConfig_IsolatedByTenant(t *testing.T) {
	store := setupRDBTestStore(t)
	tenantA := withTenant(context.Background(), "tenant-a")
	tenantB := withTenant(context.Background(), "tenant-b")

	err := store.UpdateProvidersConfig(tenantA, map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{
					ID:     "shared-key-id",
					Name:   "shared-key-name",
					Value:  *schemas.NewEnvVar("sk-tenant-a"),
					Weight: 1.0,
				},
			},
		},
	})
	require.NoError(t, err)

	err = store.UpdateProvidersConfig(tenantB, map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{
					ID:     "shared-key-id",
					Name:   "shared-key-name",
					Value:  *schemas.NewEnvVar("sk-tenant-b"),
					Weight: 2.0,
				},
			},
		},
	})
	require.NoError(t, err)

	resultA, err := store.GetProvidersConfig(tenantA)
	require.NoError(t, err)
	resultB, err := store.GetProvidersConfig(tenantB)
	require.NoError(t, err)

	require.Len(t, resultA, 1)
	require.Len(t, resultB, 1)
	require.Len(t, resultA["openai"].Keys, 1)
	require.Len(t, resultB["openai"].Keys, 1)
	assert.Equal(t, "sk-tenant-a", resultA["openai"].Keys[0].Value.Val)
	assert.Equal(t, "sk-tenant-b", resultB["openai"].Keys[0].Value.Val)
	assert.Equal(t, 1.0, resultA["openai"].Keys[0].Weight)
	assert.Equal(t, 2.0, resultB["openai"].Keys[0].Weight)
}

func TestUpdateClientConfig_IsolatedByTenant(t *testing.T) {
	store := setupRDBTestStore(t)
	tenantA := withTenant(context.Background(), "tenant-a")
	tenantB := withTenant(context.Background(), "tenant-b")

	err := store.UpdateClientConfig(tenantA, &ClientConfig{
		DropExcessRequests: true,
		AllowedOrigins:     []string{"https://tenant-a.example.com"},
		InitialPoolSize:    111,
	})
	require.NoError(t, err)

	err = store.UpdateClientConfig(tenantB, &ClientConfig{
		DropExcessRequests: false,
		AllowedOrigins:     []string{"https://tenant-b.example.com"},
		InitialPoolSize:    222,
	})
	require.NoError(t, err)

	configA, err := store.GetClientConfig(tenantA)
	require.NoError(t, err)
	configB, err := store.GetClientConfig(tenantB)
	require.NoError(t, err)

	require.NotNil(t, configA)
	require.NotNil(t, configB)
	assert.Equal(t, []string{"https://tenant-a.example.com"}, configA.AllowedOrigins)
	assert.Equal(t, []string{"https://tenant-b.example.com"}, configB.AllowedOrigins)
	assert.Equal(t, 111, configA.InitialPoolSize)
	assert.Equal(t, 222, configB.InitialPoolSize)
}

// =============================================================================
// Budget Tests
// =============================================================================

func TestCreateBudget(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	budget := &tables.TableBudget{
		ID:            "budget-test",
		MaxLimit:      100.0,
		ResetDuration: "1M",
	}

	err := store.CreateBudget(ctx, budget)
	require.NoError(t, err)

	// Verify budget was created
	result, err := store.GetBudget(ctx, "budget-test")
	require.NoError(t, err)
	assert.Equal(t, "budget-test", result.ID)
	assert.Equal(t, 100.0, result.MaxLimit)
	assert.Equal(t, "1M", result.ResetDuration)
}

func TestCreateBudget_InvalidDuration(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	budget := &tables.TableBudget{
		ID:            "budget-invalid",
		MaxLimit:      100.0,
		ResetDuration: "invalid",
	}

	err := store.CreateBudget(ctx, budget)
	assert.Error(t, err, "Should fail with invalid duration")
}

func TestCreateBudget_NegativeLimit(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	budget := &tables.TableBudget{
		ID:            "budget-negative",
		MaxLimit:      -50.0,
		ResetDuration: "1h",
	}

	err := store.CreateBudget(ctx, budget)
	assert.Error(t, err, "Should fail with negative max limit")
}

func TestUpdateBudget(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create budget
	budget := &tables.TableBudget{
		ID:            "budget-update",
		MaxLimit:      100.0,
		ResetDuration: "1h",
	}
	err := store.CreateBudget(ctx, budget)
	require.NoError(t, err)

	// Update budget
	budget.MaxLimit = 200.0
	err = store.UpdateBudget(ctx, budget)
	require.NoError(t, err)

	// Verify update
	result, err := store.GetBudget(ctx, "budget-update")
	require.NoError(t, err)
	assert.Equal(t, 200.0, result.MaxLimit)
}

func TestGetBudgets(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create multiple budgets
	budgets := []*tables.TableBudget{
		{ID: "budget-1", MaxLimit: 100.0, ResetDuration: "1h"},
		{ID: "budget-2", MaxLimit: 200.0, ResetDuration: "1d"},
		{ID: "budget-3", MaxLimit: 300.0, ResetDuration: "1M"},
	}

	for _, b := range budgets {
		err := store.CreateBudget(ctx, b)
		require.NoError(t, err)
	}

	result, err := store.GetBudgets(ctx)
	require.NoError(t, err)
	assert.Len(t, result, 3)
}

// =============================================================================
// Rate Limit Tests
// =============================================================================

func TestCreateRateLimit(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	tokenMax := int64(100000)
	requestMax := int64(1000)
	tokenDuration := "1h"
	requestDuration := "1h"

	rateLimit := &tables.TableRateLimit{
		ID:                   "rate-limit-test",
		TokenMaxLimit:        &tokenMax,
		TokenResetDuration:   &tokenDuration,
		RequestMaxLimit:      &requestMax,
		RequestResetDuration: &requestDuration,
	}

	err := store.CreateRateLimit(ctx, rateLimit)
	require.NoError(t, err)

	result, err := store.GetRateLimit(ctx, "rate-limit-test")
	require.NoError(t, err)
	assert.Equal(t, "rate-limit-test", result.ID)
	assert.Equal(t, int64(100000), *result.TokenMaxLimit)
	assert.Equal(t, int64(1000), *result.RequestMaxLimit)
}

func TestCreateRateLimit_InvalidDuration(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	tokenMax := int64(100000)
	invalidDuration := "invalid"

	rateLimit := &tables.TableRateLimit{
		ID:                 "rate-limit-invalid",
		TokenMaxLimit:      &tokenMax,
		TokenResetDuration: &invalidDuration,
	}

	err := store.CreateRateLimit(ctx, rateLimit)
	assert.Error(t, err, "Should fail with invalid duration")
}

func TestCreateRateLimit_MissingDuration(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	tokenMax := int64(100000)

	rateLimit := &tables.TableRateLimit{
		ID:            "rate-limit-missing",
		TokenMaxLimit: &tokenMax,
		// Missing TokenResetDuration
	}

	err := store.CreateRateLimit(ctx, rateLimit)
	assert.Error(t, err, "Should fail when max limit set without duration")
}

func TestUpdateRateLimit(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	tokenMax := int64(100000)
	tokenDuration := "1h"

	rateLimit := &tables.TableRateLimit{
		ID:                 "rate-limit-update",
		TokenMaxLimit:      &tokenMax,
		TokenResetDuration: &tokenDuration,
	}
	err := store.CreateRateLimit(ctx, rateLimit)
	require.NoError(t, err)

	// Update
	newMax := int64(200000)
	rateLimit.TokenMaxLimit = &newMax
	err = store.UpdateRateLimit(ctx, rateLimit)
	require.NoError(t, err)

	result, err := store.GetRateLimit(ctx, "rate-limit-update")
	require.NoError(t, err)
	assert.Equal(t, int64(200000), *result.TokenMaxLimit)
}

// =============================================================================
// Guardrail Policy Tests
// =============================================================================

func TestCreateGuardrailPolicy_FirstPolicyBecomesDefaultAndPoliciesRemainEnabled(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	policyOne := &tables.TableGuardrailPolicy{
		ID:              "policy-1",
		Name:            "Policy One",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         true,
	}
	policyTwo := &tables.TableGuardrailPolicy{
		ID:              "policy-2",
		Name:            "Policy Two",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         true,
	}
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyOne))
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyTwo))

	savedOne, err := store.GetGuardrailPolicy(ctx, policyOne.ID)
	require.NoError(t, err)
	savedTwo, err := store.GetGuardrailPolicy(ctx, policyTwo.ID)
	require.NoError(t, err)
	require.NotNil(t, savedOne)
	require.NotNil(t, savedTwo)
	assert.True(t, savedOne.Enabled)
	assert.True(t, savedTwo.Enabled)
	assert.True(t, savedOne.IsDefault)
	assert.False(t, savedTwo.IsDefault)
}

func TestSetDefaultGuardrailPolicy_PromotesSelectedPolicyWithoutDisablingOthers(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	policyOne := &tables.TableGuardrailPolicy{
		ID:              "policy-1",
		Name:            "Policy One",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         true,
	}
	policyTwo := &tables.TableGuardrailPolicy{
		ID:              "policy-2",
		Name:            "Policy Two",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         false,
	}
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyOne))
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyTwo))
	require.NoError(t, store.SetDefaultGuardrailPolicy(ctx, policyTwo.ID))

	savedOne, err := store.GetGuardrailPolicy(ctx, policyOne.ID)
	require.NoError(t, err)
	savedTwo, err := store.GetGuardrailPolicy(ctx, policyTwo.ID)
	require.NoError(t, err)
	require.NotNil(t, savedOne)
	require.NotNil(t, savedTwo)
	assert.True(t, savedOne.Enabled)
	assert.True(t, savedTwo.Enabled)
	assert.False(t, savedOne.IsDefault)
	assert.True(t, savedTwo.IsDefault)
}

func TestDeleteGuardrailPolicy_PromotesAnotherPolicyAsDefault(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	policyOne := &tables.TableGuardrailPolicy{
		ID:              "policy-1",
		Name:            "Policy One",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         true,
	}
	policyTwo := &tables.TableGuardrailPolicy{
		ID:              "policy-2",
		Name:            "Policy Two",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         false,
	}
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyOne))
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyTwo))
	require.NoError(t, store.DeleteGuardrailPolicy(ctx, policyOne.ID))

	savedTwo, err := store.GetGuardrailPolicy(ctx, policyTwo.ID)
	require.NoError(t, err)
	require.NotNil(t, savedTwo)
	assert.True(t, savedTwo.Enabled)
	assert.True(t, savedTwo.IsDefault)
}

// =============================================================================
// Virtual Key Tests
// =============================================================================

func TestCreateVirtualKey(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk := &tables.TableVirtualKey{
		ID:       "vk-test",
		Name:     "Test Virtual Key",
		Value:    "vk-test-value-123",
		IsActive: true,
	}

	err := store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	result, err := store.GetVirtualKey(ctx, "vk-test")
	require.NoError(t, err)
	assert.Equal(t, "vk-test", result.ID)
	assert.Equal(t, "Test Virtual Key", result.Name)
	assert.Equal(t, "vk-test-value-123", result.Value)
	assert.True(t, result.IsActive)
}

func TestCreateVirtualKey_WithBudgetAndRateLimit(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create budget first
	budget := &tables.TableBudget{
		ID:            "budget-for-vk",
		MaxLimit:      100.0,
		ResetDuration: "1M",
	}
	err := store.CreateBudget(ctx, budget)
	require.NoError(t, err)

	// Create rate limit
	tokenMax := int64(100000)
	tokenDuration := "1h"
	rateLimit := &tables.TableRateLimit{
		ID:                 "rate-limit-for-vk",
		TokenMaxLimit:      &tokenMax,
		TokenResetDuration: &tokenDuration,
	}
	err = store.CreateRateLimit(ctx, rateLimit)
	require.NoError(t, err)

	// Create virtual key with references
	budgetID := "budget-for-vk"
	rateLimitID := "rate-limit-for-vk"
	vk := &tables.TableVirtualKey{
		ID:          "vk-with-refs",
		Name:        "VK With References",
		Value:       "vk-refs-value",
		IsActive:    true,
		BudgetID:    &budgetID,
		RateLimitID: &rateLimitID,
	}

	err = store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	result, err := store.GetVirtualKey(ctx, "vk-with-refs")
	require.NoError(t, err)
	assert.NotNil(t, result.BudgetID)
	assert.Equal(t, "budget-for-vk", *result.BudgetID)
	assert.NotNil(t, result.RateLimitID)
	assert.Equal(t, "rate-limit-for-vk", *result.RateLimitID)
}

func TestCreateVirtualKey_DuplicateName(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk1 := &tables.TableVirtualKey{
		ID:       "vk-1",
		Name:     "Same Name",
		Value:    "vk-value-1",
		IsActive: true,
	}
	err := store.CreateVirtualKey(ctx, vk1)
	require.NoError(t, err)

	vk2 := &tables.TableVirtualKey{
		ID:       "vk-2",
		Name:     "Same Name", // Duplicate name
		Value:    "vk-value-2",
		IsActive: true,
	}
	err = store.CreateVirtualKey(ctx, vk2)
	assert.Error(t, err, "Should fail with duplicate name")
}

func TestGetVirtualKeyByValue(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk := &tables.TableVirtualKey{
		ID:       "vk-lookup",
		Name:     "Lookup Key",
		Value:    "vk-unique-value-xyz",
		IsActive: true,
	}
	err := store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	result, err := store.GetVirtualKeyByValue(ctx, "vk-unique-value-xyz")
	require.NoError(t, err)
	assert.Equal(t, "vk-lookup", result.ID)
}

func TestGetRedactedVirtualKeys_PreloadsTeam(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	team := &tables.TableTeam{
		ID:   "team-for-redacted-vk",
		Name: "Platform Team",
	}
	require.NoError(t, store.CreateTeam(ctx, team))

	teamID := team.ID
	vk := &tables.TableVirtualKey{
		ID:       "vk-redacted-team",
		Name:     "Redacted Team Key",
		Value:    "vk-redacted-team-value",
		IsActive: true,
		TeamID:   &teamID,
	}
	require.NoError(t, store.CreateVirtualKey(ctx, vk))

	result, err := store.GetRedactedVirtualKeys(ctx, []string{vk.ID})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.NotNil(t, result[0].Team)
	assert.Equal(t, team.ID, result[0].Team.ID)
	assert.Equal(t, team.Name, result[0].Team.Name)
}

func TestUpdateVirtualKey(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk := &tables.TableVirtualKey{
		ID:       "vk-update",
		Name:     "Original Name",
		Value:    "vk-update-value",
		IsActive: true,
	}
	err := store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	// Update
	vk.Name = "Updated Name"
	vk.IsActive = false
	err = store.UpdateVirtualKey(ctx, vk)
	require.NoError(t, err)

	result, err := store.GetVirtualKey(ctx, "vk-update")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", result.Name)
	assert.False(t, result.IsActive)
}

func TestReplaceVirtualKeyGuardrailPolicies_PreloadsPolicies(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	policyOne := &tables.TableGuardrailPolicy{
		ID:              "policy-1",
		Name:            "Policy One",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         true,
	}
	policyTwo := &tables.TableGuardrailPolicy{
		ID:              "policy-2",
		Name:            "Policy Two",
		Scope:           tables.GuardrailPolicyScopeOutput,
		EnforcementMode: tables.GuardrailEnforcementModeMonitor,
		Enabled:         true,
	}
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyOne))
	require.NoError(t, store.CreateGuardrailPolicy(ctx, policyTwo))

	vk := &tables.TableVirtualKey{
		ID:       "vk-with-policies",
		Name:     "VK With Policies",
		Value:    "vk-with-policies-value",
		IsActive: true,
	}
	require.NoError(t, store.CreateVirtualKey(ctx, vk))
	require.NoError(t, store.ReplaceVirtualKeyGuardrailPolicies(ctx, vk.ID, []string{policyOne.ID, policyTwo.ID}))

	savedVK, err := store.GetVirtualKey(ctx, vk.ID)
	require.NoError(t, err)
	require.NotNil(t, savedVK)
	require.Len(t, savedVK.GuardrailPolicies, 2)
	assert.ElementsMatch(t, []string{policyOne.ID, policyTwo.ID}, []string{savedVK.GuardrailPolicies[0].ID, savedVK.GuardrailPolicies[1].ID})
}

func TestDeleteVirtualKey(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk := &tables.TableVirtualKey{
		ID:       "vk-delete",
		Name:     "Delete Me",
		Value:    "vk-delete-value",
		IsActive: true,
	}
	err := store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	err = store.DeleteVirtualKey(ctx, "vk-delete")
	require.NoError(t, err)

	_, err = store.GetVirtualKey(ctx, "vk-delete")
	assert.Error(t, err, "Should not find deleted virtual key")
}

// =============================================================================
// Virtual Key Provider Config Tests
// =============================================================================

func TestCreateVirtualKeyProviderConfig(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create virtual key first
	vk := &tables.TableVirtualKey{
		ID:       "vk-for-pc",
		Name:     "VK For Provider Config",
		Value:    "vk-pc-value",
		IsActive: true,
	}
	err := store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	// Create provider config
	weight := 1.0
	pc := &tables.TableVirtualKeyProviderConfig{
		VirtualKeyID: "vk-for-pc",
		Provider:     "openai",
		Weight:       &weight,
	}

	err = store.CreateVirtualKeyProviderConfig(ctx, pc)
	require.NoError(t, err)

	// Verify
	configs, err := store.GetVirtualKeyProviderConfigs(ctx, "vk-for-pc")
	require.NoError(t, err)
	assert.Len(t, configs, 1)
	assert.Equal(t, "openai", configs[0].Provider)
}

func TestCreateVirtualKeyProviderConfig_WithKeys(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create provider with keys first
	providers := map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{ID: "key-for-pc", Name: "openai-pc-key", Value: *schemas.NewEnvVar("sk-test"), Weight: 1.0},
			},
		},
	}
	err := store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	// Create virtual key
	vk := &tables.TableVirtualKey{
		ID:       "vk-with-keys",
		Name:     "VK With Keys",
		Value:    "vk-keys-value",
		IsActive: true,
	}
	err = store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	// Create provider config with key reference
	weight := 1.0
	pc := &tables.TableVirtualKeyProviderConfig{
		VirtualKeyID: "vk-with-keys",
		Provider:     "openai",
		Weight:       &weight,
		Keys: []tables.TableKey{
			{Name: "openai-pc-key"}, // Reference by name
		},
	}

	err = store.CreateVirtualKeyProviderConfig(ctx, pc)
	require.NoError(t, err)

	// Verify keys are associated
	configs, err := store.GetVirtualKeyProviderConfigs(ctx, "vk-with-keys")
	require.NoError(t, err)
	assert.Len(t, configs, 1)

	// Load with keys
	var configWithKeys tables.TableVirtualKeyProviderConfig
	err = store.db.Preload("Keys").First(&configWithKeys, "id = ?", configs[0].ID).Error
	require.NoError(t, err)
	assert.Len(t, configWithKeys.Keys, 1)
}

func TestCreateVirtualKeyProviderConfig_UnresolvedKeys(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create virtual key
	vk := &tables.TableVirtualKey{
		ID:       "vk-unresolved",
		Name:     "VK Unresolved",
		Value:    "vk-unresolved-value",
		IsActive: true,
	}
	err := store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	// Try to create provider config with non-existent key
	weight := 1.0
	pc := &tables.TableVirtualKeyProviderConfig{
		VirtualKeyID: "vk-unresolved",
		Provider:     "openai",
		Weight:       &weight,
		Keys: []tables.TableKey{
			{Name: "non-existent-key"},
		},
	}

	err = store.CreateVirtualKeyProviderConfig(ctx, pc)
	assert.Error(t, err, "Should fail with unresolved keys")

	var unresolvedErr *ErrUnresolvedKeys
	assert.ErrorAs(t, err, &unresolvedErr, "Should be ErrUnresolvedKeys")
}

// =============================================================================
// Client Config Tests
// =============================================================================

func TestUpdateClientConfig(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	config := &ClientConfig{
		EnableLogging:        true,
		AllowDirectKeys:      true,
		InitialPoolSize:      100,
		LogRetentionDays:     30,
		MaxRequestBodySizeMB: 50,
	}

	err := store.UpdateClientConfig(ctx, config)
	require.NoError(t, err)

	result, err := store.GetClientConfig(ctx)
	require.NoError(t, err)
	assert.True(t, result.EnableLogging)
	assert.Equal(t, 100, result.InitialPoolSize)
}

// =============================================================================
// Transaction Tests
// =============================================================================

func TestExecuteTransaction_Success(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	err := store.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Create budget in transaction
		budget := &tables.TableBudget{
			ID:            "tx-budget",
			MaxLimit:      100.0,
			ResetDuration: "1h",
		}
		return tx.Create(budget).Error
	})
	require.NoError(t, err)

	// Verify budget was created
	result, err := store.GetBudget(ctx, "tx-budget")
	require.NoError(t, err)
	assert.Equal(t, "tx-budget", result.ID)
}

func TestExecuteTransaction_Rollback(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	err := store.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Create budget
		budget := &tables.TableBudget{
			ID:            "tx-rollback-budget",
			MaxLimit:      100.0,
			ResetDuration: "1h",
		}
		if err := tx.Create(budget).Error; err != nil {
			return err
		}

		// Force error to trigger rollback
		return assert.AnError
	})
	assert.Error(t, err)

	// Verify budget was NOT created (rolled back)
	_, err = store.GetBudget(ctx, "tx-rollback-budget")
	assert.Error(t, err, "Budget should not exist after rollback")
}

// =============================================================================
// Customer and Team Tests
// =============================================================================

func TestCreateCustomer(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	customer := &tables.TableCustomer{
		ID:   "customer-test",
		Name: "Test Customer",
	}

	err := store.CreateCustomer(ctx, customer)
	require.NoError(t, err)

	result, err := store.GetCustomer(ctx, "customer-test")
	require.NoError(t, err)
	assert.Equal(t, "Test Customer", result.Name)
}

func TestCreateTeam(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create customer first
	customer := &tables.TableCustomer{
		ID:   "customer-for-team",
		Name: "Customer For Team",
	}
	err := store.CreateCustomer(ctx, customer)
	require.NoError(t, err)

	// Create team
	customerID := "customer-for-team"
	team := &tables.TableTeam{
		ID:         "team-test",
		Name:       "Test Team",
		CustomerID: &customerID,
	}

	err = store.CreateTeam(ctx, team)
	require.NoError(t, err)

	result, err := store.GetTeam(ctx, "team-test")
	require.NoError(t, err)
	assert.Equal(t, "Test Team", result.Name)
	assert.Equal(t, "customer-for-team", *result.CustomerID)
}

func TestReplaceTeamMembers(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "tenant-1")

	team := &tables.TableTeam{
		ID:   "team-with-members",
		Name: "Team With Members",
	}
	require.NoError(t, store.CreateTeam(ctx, team))

	userA := &tables.TableAuthUser{
		ID:              "user-a",
		TenantID:        "tenant-1",
		Role:            tables.UserRoleAdmin,
		FirstName:       "Alice",
		LastName:        "Admin",
		Organization:    "Acme",
		Industry:        "Security",
		Email:           "alice@example.com",
		IsEmailVerified: true,
	}
	userB := &tables.TableAuthUser{
		ID:              "user-b",
		TenantID:        "tenant-1",
		Role:            tables.UserRoleViewer,
		FirstName:       "Bob",
		LastName:        "Viewer",
		Organization:    "Acme",
		Industry:        "Security",
		Email:           "bob@example.com",
		IsEmailVerified: true,
	}
	require.NoError(t, store.CreateUser(ctx, userA))
	require.NoError(t, store.CreateUser(ctx, userB))

	require.NoError(t, store.ReplaceTeamMembers(ctx, team.ID, []string{userA.ID, userB.ID}))

	result, err := store.GetTeam(ctx, team.ID)
	require.NoError(t, err)
	require.Len(t, result.Members, 2)
	assert.Equal(t, []string{"alice@example.com", "bob@example.com"}, []string{result.Members[0].Email, result.Members[1].Email})
}

func TestReplaceTeamCustomerMembers(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "tenant-1")

	team := &tables.TableTeam{
		ID:   "team-with-customer-members",
		Name: "Team With Customer Members",
	}
	require.NoError(t, store.CreateTeam(ctx, team))

	customerA := &tables.TableCustomer{
		ID:       "customer-a",
		TenantID: "tenant-1",
		Name:     "Acme One",
	}
	customerB := &tables.TableCustomer{
		ID:       "customer-b",
		TenantID: "tenant-1",
		Name:     "Acme Two",
	}
	require.NoError(t, store.CreateCustomer(ctx, customerA))
	require.NoError(t, store.CreateCustomer(ctx, customerB))

	require.NoError(t, store.ReplaceTeamCustomerMembers(ctx, team.ID, []string{customerA.ID, customerB.ID}))

	result, err := store.GetTeam(ctx, team.ID)
	require.NoError(t, err)
	require.Len(t, result.CustomerMembers, 2)
	assert.Equal(t, []string{"Acme One", "Acme Two"}, []string{result.CustomerMembers[0].Name, result.CustomerMembers[1].Name})
}

func TestDeleteCustomerRemovesTeamCustomerMemberships(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "tenant-1")

	team := &tables.TableTeam{
		ID:   "team-cleanup",
		Name: "Team Cleanup",
	}
	require.NoError(t, store.CreateTeam(ctx, team))

	customer := &tables.TableCustomer{
		ID:       "customer-cleanup",
		TenantID: "tenant-1",
		Name:     "Cleanup Member",
	}
	require.NoError(t, store.CreateCustomer(ctx, customer))
	require.NoError(t, store.ReplaceTeamCustomerMembers(ctx, team.ID, []string{customer.ID}))

	require.NoError(t, store.DeleteCustomer(ctx, customer.ID))

	result, err := store.GetTeam(ctx, team.ID)
	require.NoError(t, err)
	assert.Empty(t, result.CustomerMembers)
}

// =============================================================================
// Ping and Health Tests
// =============================================================================

func TestPing(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	err := store.Ping(ctx)
	assert.NoError(t, err)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestGetBudget_NotFound(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	_, err := store.GetBudget(ctx, "non-existent-budget")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGetVirtualKey_NotFound(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	_, err := store.GetVirtualKey(ctx, "non-existent-vk")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGetRateLimit_NotFound(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	_, err := store.GetRateLimit(ctx, "non-existent-rate-limit")
	assert.ErrorIs(t, err, ErrNotFound)
}

// =============================================================================
// Plugin Tests
// =============================================================================

func TestCreateAndGetPlugin(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	plugin := &tables.TablePlugin{
		Name:    "test-plugin",
		Enabled: true,
		Version: 1,
	}

	err := store.CreatePlugin(ctx, plugin)
	require.NoError(t, err)

	result, err := store.GetPlugin(ctx, "test-plugin")
	require.NoError(t, err)
	assert.Equal(t, "test-plugin", result.Name)
	assert.True(t, result.Enabled)
}

func TestUpsertPlugin(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create plugin
	plugin := &tables.TablePlugin{
		Name:    "upsert-plugin",
		Enabled: true,
		Version: 1,
	}
	err := store.UpsertPlugin(ctx, plugin)
	require.NoError(t, err)

	// Upsert with update
	plugin.Version = 2
	err = store.UpsertPlugin(ctx, plugin)
	require.NoError(t, err)

	result, err := store.GetPlugin(ctx, "upsert-plugin")
	require.NoError(t, err)
	assert.Equal(t, int16(2), result.Version)
}

// =============================================================================
// Integration Test: Full Virtual Key with Provider Config Flow
// =============================================================================

func TestFullVirtualKeyFlow(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Step 1: Create provider with keys
	providers := map[schemas.ModelProvider]ProviderConfig{
		"openai": {
			Keys: []schemas.Key{
				{ID: "key-1", Name: "openai-main", Value: *schemas.NewEnvVar("sk-main"), Weight: 1.0},
				{ID: "key-2", Name: "openai-backup", Value: *schemas.NewEnvVar("sk-backup"), Weight: 0.5},
			},
		},
	}
	err := store.UpdateProvidersConfig(ctx, providers)
	require.NoError(t, err)

	// Step 2: Create budget
	budget := &tables.TableBudget{
		ID:            "integration-budget",
		MaxLimit:      500.0,
		ResetDuration: "1M",
	}
	err = store.CreateBudget(ctx, budget)
	require.NoError(t, err)

	// Step 3: Create rate limit
	tokenMax := int64(1000000)
	tokenDuration := "1d"
	rateLimit := &tables.TableRateLimit{
		ID:                 "integration-rate-limit",
		TokenMaxLimit:      &tokenMax,
		TokenResetDuration: &tokenDuration,
	}
	err = store.CreateRateLimit(ctx, rateLimit)
	require.NoError(t, err)

	// Step 4: Create virtual key
	budgetID := "integration-budget"
	rateLimitID := "integration-rate-limit"
	vk := &tables.TableVirtualKey{
		ID:          "integration-vk",
		Name:        "Integration Virtual Key",
		Value:       "vk-integration-xyz",
		IsActive:    true,
		BudgetID:    &budgetID,
		RateLimitID: &rateLimitID,
	}
	err = store.CreateVirtualKey(ctx, vk)
	require.NoError(t, err)

	// Step 5: Create provider config with key reference
	weight := 1.0
	pc := &tables.TableVirtualKeyProviderConfig{
		VirtualKeyID: "integration-vk",
		Provider:     "openai",
		Weight:       &weight,
		Keys: []tables.TableKey{
			{Name: "openai-main"},
		},
	}
	err = store.CreateVirtualKeyProviderConfig(ctx, pc)
	require.NoError(t, err)

	// Step 6: Verify complete setup
	result, err := store.GetVirtualKey(ctx, "integration-vk")
	require.NoError(t, err)
	assert.Equal(t, "Integration Virtual Key", result.Name)
	assert.NotNil(t, result.BudgetID)
	assert.NotNil(t, result.RateLimitID)

	configs, err := store.GetVirtualKeyProviderConfigs(ctx, "integration-vk")
	require.NoError(t, err)
	assert.Len(t, configs, 1)
	assert.Equal(t, "openai", configs[0].Provider)
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestGetWeight(t *testing.T) {
	// Test nil weight returns default
	assert.Equal(t, 1.0, getWeight(nil))

	// Test explicit weight
	w := 2.5
	assert.Equal(t, 2.5, getWeight(&w))

	// Test zero weight
	zero := 0.0
	assert.Equal(t, 0.0, getWeight(&zero))
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestMultipleBudgetUpdates(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	// Create initial budget
	budget := &tables.TableBudget{
		ID:            "multi-update-budget",
		MaxLimit:      100.0,
		ResetDuration: "1h",
		CurrentUsage:  0,
	}
	err := store.CreateBudget(ctx, budget)
	require.NoError(t, err)

	// Simulate multiple sequential updates
	for i := 0; i < 10; i++ {
		b := &tables.TableBudget{
			ID:            "multi-update-budget",
			MaxLimit:      100.0 + float64(i),
			ResetDuration: "1h",
		}
		err := store.UpdateBudget(ctx, b)
		require.NoError(t, err)
	}

	// Verify budget exists and has the last value
	result, err := store.GetBudget(ctx, "multi-update-budget")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 109.0, result.MaxLimit) // 100 + 9
}

// =============================================================================
// Duration Validation Tests (for budgets and rate limits)
// =============================================================================

func TestBudgetDurationFormats(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	validDurations := []string{"30s", "5m", "1h", "1d", "1w", "1M", "1Y"}

	for i, duration := range validDurations {
		budget := &tables.TableBudget{
			ID:            "budget-duration-" + string(rune('a'+i)),
			MaxLimit:      100.0,
			ResetDuration: duration,
		}
		err := store.CreateBudget(ctx, budget)
		assert.NoError(t, err, "Duration %s should be valid", duration)
	}
}

func TestRateLimitDurationFormats(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	validDurations := []string{"30s", "5m", "1h", "1d", "1w", "1M", "1Y"}

	for i, duration := range validDurations {
		tokenMax := int64(1000)
		rateLimit := &tables.TableRateLimit{
			ID:                 "rate-limit-duration-" + string(rune('a'+i)),
			TokenMaxLimit:      &tokenMax,
			TokenResetDuration: &duration,
		}
		err := store.CreateRateLimit(ctx, rateLimit)
		assert.NoError(t, err, "Duration %s should be valid", duration)
	}
}

// =============================================================================
// Prompt Deletion Tests
// =============================================================================

// testPromptTree holds IDs of entities created by createTestPromptTree for verification
type testPromptTree struct {
	FolderID   string
	PromptIDs  []string
	VersionIDs []uint
	SessionIDs []uint
}

// createTestPromptTree creates a folder with 2 prompts, each having 2 versions (with messages) and 1 session (with messages).
func createTestPromptTree(t *testing.T, store *RDBConfigStore, ctx context.Context) testPromptTree {
	t.Helper()

	tree := testPromptTree{}

	// Create folder
	folder := &tables.TableFolder{ID: "folder-1", Name: "Test Folder"}
	require.NoError(t, store.CreateFolder(ctx, folder))
	tree.FolderID = folder.ID

	for i, promptID := range []string{"prompt-1", "prompt-2"} {
		_ = i
		prompt := &tables.TablePrompt{ID: promptID, Name: "Prompt " + promptID, FolderID: &tree.FolderID}
		require.NoError(t, store.CreatePrompt(ctx, prompt))
		tree.PromptIDs = append(tree.PromptIDs, promptID)

		// Create 2 versions with messages
		for v := 0; v < 2; v++ {
			version := &tables.TablePromptVersion{
				PromptID:      promptID,
				CommitMessage: "version commit",
				Messages: []tables.TablePromptVersionMessage{
					{PromptID: promptID, Message: json.RawMessage(`{"role":"user","content":"hello"}`)},
				},
			}
			require.NoError(t, store.CreatePromptVersion(ctx, version))
			tree.VersionIDs = append(tree.VersionIDs, version.ID)
		}

		// Create 1 session with messages
		session := &tables.TablePromptSession{
			PromptID: promptID,
			Name:     "Session " + promptID,
			Messages: []tables.TablePromptSessionMessage{
				{PromptID: promptID, Message: json.RawMessage(`{"role":"user","content":"hi"}`)},
			},
		}
		require.NoError(t, store.CreatePromptSession(ctx, session))
		tree.SessionIDs = append(tree.SessionIDs, session.ID)
	}

	return tree
}

// countRows returns the number of rows in a table
func countRows(t *testing.T, store *RDBConfigStore, model interface{}) int64 {
	t.Helper()
	var count int64
	require.NoError(t, store.db.Model(model).Count(&count).Error)
	return count
}

func TestDeleteFolder(t *testing.T) {
	t.Run("NotFound", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		err := store.DeleteFolder(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("Empty", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		folder := &tables.TableFolder{ID: "folder-empty", Name: "Empty"}
		require.NoError(t, store.CreateFolder(ctx, folder))

		require.NoError(t, store.DeleteFolder(ctx, "folder-empty"))

		_, err := store.GetFolderByID(ctx, "folder-empty")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("CascadesAll", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		// Verify entities exist before deletion
		assert.Greater(t, countRows(t, store, &tables.TablePrompt{}), int64(0))
		assert.Greater(t, countRows(t, store, &tables.TablePromptVersion{}), int64(0))
		assert.Greater(t, countRows(t, store, &tables.TablePromptVersionMessage{}), int64(0))
		assert.Greater(t, countRows(t, store, &tables.TablePromptSession{}), int64(0))
		assert.Greater(t, countRows(t, store, &tables.TablePromptSessionMessage{}), int64(0))

		require.NoError(t, store.DeleteFolder(ctx, tree.FolderID))

		// All child entities should be deleted
		assert.Equal(t, int64(0), countRows(t, store, &tables.TableFolder{}))
		assert.Equal(t, int64(0), countRows(t, store, &tables.TablePrompt{}))
		assert.Equal(t, int64(0), countRows(t, store, &tables.TablePromptVersion{}))
		assert.Equal(t, int64(0), countRows(t, store, &tables.TablePromptVersionMessage{}))
		assert.Equal(t, int64(0), countRows(t, store, &tables.TablePromptSession{}))
		assert.Equal(t, int64(0), countRows(t, store, &tables.TablePromptSessionMessage{}))
	})
}

func TestDeletePrompt(t *testing.T) {
	t.Run("NotFound", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		err := store.DeletePrompt(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("CascadesAll", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		require.NoError(t, store.DeletePrompt(ctx, tree.PromptIDs[0]))

		// First prompt and its children should be gone
		_, err := store.GetPromptByID(ctx, tree.PromptIDs[0])
		assert.ErrorIs(t, err, ErrNotFound)

		// Second prompt should still exist
		p2, err := store.GetPromptByID(ctx, tree.PromptIDs[1])
		require.NoError(t, err)
		assert.Equal(t, tree.PromptIDs[1], p2.ID)
	})

	t.Run("LeavesFolder", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		require.NoError(t, store.DeletePrompt(ctx, tree.PromptIDs[0]))

		// Folder should still exist
		folder, err := store.GetFolderByID(ctx, tree.FolderID)
		require.NoError(t, err)
		assert.Equal(t, tree.FolderID, folder.ID)
	})

	t.Run("LeavesSiblings", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		require.NoError(t, store.DeletePrompt(ctx, tree.PromptIDs[0]))

		// Sibling prompt's versions and sessions should be unaffected
		versions, err := store.GetPromptVersions(ctx, tree.PromptIDs[1])
		require.NoError(t, err)
		assert.Len(t, versions, 2)

		sessions, err := store.GetPromptSessions(ctx, tree.PromptIDs[1])
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
	})
}

func TestDeletePromptVersion(t *testing.T) {
	t.Run("NotFound", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		err := store.DeletePromptVersion(ctx, 99999)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("NonLatest", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		// Version at index 0 is v1 (non-latest), index 1 is v2 (latest) for prompt-1
		nonLatestID := tree.VersionIDs[0]
		latestID := tree.VersionIDs[1]

		require.NoError(t, store.DeletePromptVersion(ctx, nonLatestID))

		// Non-latest version should be gone
		_, err := store.GetPromptVersionByID(ctx, nonLatestID)
		assert.ErrorIs(t, err, ErrNotFound)

		// Latest version should still be latest
		latest, err := store.GetPromptVersionByID(ctx, latestID)
		require.NoError(t, err)
		assert.True(t, latest.IsLatest)
	})

	t.Run("LatestPromotesPrevious", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		// Delete the latest version (index 1 = v2 for prompt-1)
		latestID := tree.VersionIDs[1]
		prevID := tree.VersionIDs[0]

		require.NoError(t, store.DeletePromptVersion(ctx, latestID))

		// Previous version should now be latest
		prev, err := store.GetPromptVersionByID(ctx, prevID)
		require.NoError(t, err)
		assert.True(t, prev.IsLatest)
	})

	t.Run("LeavesPrompt", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		require.NoError(t, store.DeletePromptVersion(ctx, tree.VersionIDs[0]))

		// Prompt should still exist
		prompt, err := store.GetPromptByID(ctx, tree.PromptIDs[0])
		require.NoError(t, err)
		assert.Equal(t, tree.PromptIDs[0], prompt.ID)
	})
}

func TestDeletePromptSession(t *testing.T) {
	t.Run("NotFound", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		err := store.DeletePromptSession(ctx, 99999)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("CascadesMessages", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		sessionID := tree.SessionIDs[0]
		require.NoError(t, store.DeletePromptSession(ctx, sessionID))

		// Session should be gone
		_, err := store.GetPromptSessionByID(ctx, sessionID)
		assert.ErrorIs(t, err, ErrNotFound)

		// Session messages for that session should be gone
		var msgCount int64
		require.NoError(t, store.db.Model(&tables.TablePromptSessionMessage{}).Where("session_id = ?", sessionID).Count(&msgCount).Error)
		assert.Equal(t, int64(0), msgCount)
	})

	t.Run("LeavesPrompt", func(t *testing.T) {
		store := setupRDBTestStore(t)
		ctx := context.Background()
		tree := createTestPromptTree(t, store, ctx)

		require.NoError(t, store.DeletePromptSession(ctx, tree.SessionIDs[0]))

		// Prompt and versions should still exist
		prompt, err := store.GetPromptByID(ctx, tree.PromptIDs[0])
		require.NoError(t, err)
		assert.Equal(t, tree.PromptIDs[0], prompt.ID)

		versions, err := store.GetPromptVersions(ctx, tree.PromptIDs[0])
		require.NoError(t, err)
		assert.Len(t, versions, 2)
	})
}
