package configstore

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceProviderModels_ReplacesTenantScopedModelRows(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(&tables.TableModel{}))

	ctx := withTenant(context.Background(), "alice@example.com")
	require.NoError(t, store.AddProvider(ctx, schemas.OpenAI, ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:     "key-1",
				Name:   "openai-key",
				Value:  *schemas.NewEnvVar("sk-test"),
				Weight: 1,
			},
		},
	}))

	require.NoError(t, store.ReplaceProviderModels(ctx, schemas.OpenAI, []string{"gpt-4o-mini", "gpt-4o", "gpt-4o-mini"}))

	provider, err := store.GetProvider(ctx, schemas.OpenAI)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"gpt-4o", "gpt-4o-mini"}, modelNamesFromProvider(provider.Models))

	require.NoError(t, store.ReplaceProviderModels(ctx, schemas.OpenAI, []string{"gpt-4.1"}))

	provider, err = store.GetProvider(ctx, schemas.OpenAI)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"gpt-4.1"}, modelNamesFromProvider(provider.Models))
}

func TestBackfillProviderModelsFromKeys_PopulatesMissingRows(t *testing.T) {
	store := setupRDBTestStore(t)
	require.NoError(t, store.db.AutoMigrate(&tables.TableModel{}))

	tenantCtx := withTenant(context.Background(), "alice@example.com")
	require.NoError(t, store.AddProvider(tenantCtx, schemas.OpenAI, ProviderConfig{
		Keys: []schemas.Key{
			{
				ID:     "key-1",
				Name:   "openai-key",
				Value:  *schemas.NewEnvVar("sk-test"),
				Models: []string{"gpt-4o", "gpt-4o-mini"},
				Weight: 1,
			},
		},
	}))

	providerBefore, err := store.GetProvider(tenantCtx, schemas.OpenAI)
	require.NoError(t, err)
	assert.Empty(t, providerBefore.Models)

	require.NoError(t, store.BackfillProviderModelsFromKeys(context.Background()))

	providerAfter, err := store.GetProvider(tenantCtx, schemas.OpenAI)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"gpt-4o", "gpt-4o-mini"}, modelNamesFromProvider(providerAfter.Models))
}

func modelNamesFromProvider(models []tables.TableModel) []string {
	names := make([]string, 0, len(models))
	for _, model := range models {
		names = append(names, model.Name)
	}
	return names
}
