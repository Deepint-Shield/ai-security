package configstore

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stringPtr(value string) *string {
	return &value
}

func TestGenerateVirtualKeyHash_CachePolicyFields(t *testing.T) {
	base := tables.TableVirtualKey{
		ID:       "vk-cache-policy",
		Name:     "Cache Policy VK",
		Value:    "vk-cache-policy-value",
		IsActive: true,
	}

	baseHash, err := GenerateVirtualKeyHash(base)
	require.NoError(t, err)

	withCacheDisabled := base
	withCacheDisabled.CacheEnabled = boolPtr(false)
	cacheDisabledHash, err := GenerateVirtualKeyHash(withCacheDisabled)
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, cacheDisabledHash)

	withSemanticCacheDisabled := base
	withSemanticCacheDisabled.SemanticCacheEnabled = boolPtr(false)
	semanticCacheDisabledHash, err := GenerateVirtualKeyHash(withSemanticCacheDisabled)
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, semanticCacheDisabledHash)

	withCacheKey := base
	withCacheKey.CacheKey = "shared-sales-cache"
	cacheKeyHash, err := GenerateVirtualKeyHash(withCacheKey)
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, cacheKeyHash)

	withScopeMode := base
	withScopeMode.CacheScopeMode = stringPtr("use_case")
	scopeModeHash, err := GenerateVirtualKeyHash(withScopeMode)
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, scopeModeHash)

	withMetadataKeys := base
	withMetadataKeys.CacheMetadataScopeKeys = []string{"cache_scope", "workflow"}
	metadataKeysHash, err := GenerateVirtualKeyHash(withMetadataKeys)
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, metadataKeysHash)

	withSemanticOverride := base
	withSemanticOverride.CacheAllowSemanticWhenUnscoped = boolPtr(true)
	semanticOverrideHash, err := GenerateVirtualKeyHash(withSemanticOverride)
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, semanticOverrideHash)
}

func TestCreateAndUpdateVirtualKey_CachePolicyFields(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk := &tables.TableVirtualKey{
		ID:                             "vk-cache-roundtrip",
		Name:                           "Cache Policy Roundtrip",
		Value:                          "vk-cache-roundtrip-value",
		IsActive:                       true,
		CacheKey:                       "shared-sales-cache",
		CacheEnabled:                   boolPtr(true),
		SemanticCacheEnabled:           boolPtr(false),
		CacheScopeMode:                 stringPtr("use_case"),
		CacheMetadataScopeKeys:         []string{"cache_scope", "workflow"},
		CacheAllowSemanticWhenUnscoped: boolPtr(true),
	}

	require.NoError(t, store.CreateVirtualKey(ctx, vk))

	created, err := store.GetVirtualKey(ctx, vk.ID)
	require.NoError(t, err)
	assert.Equal(t, "shared-sales-cache", created.CacheKey)
	require.NotNil(t, created.CacheEnabled)
	assert.True(t, *created.CacheEnabled)
	require.NotNil(t, created.SemanticCacheEnabled)
	assert.False(t, *created.SemanticCacheEnabled)
	require.NotNil(t, created.CacheScopeMode)
	assert.Equal(t, "use_case", *created.CacheScopeMode)
	assert.ElementsMatch(t, []string{"cache_scope", "workflow"}, created.CacheMetadataScopeKeys)
	require.NotNil(t, created.CacheAllowSemanticWhenUnscoped)
	assert.True(t, *created.CacheAllowSemanticWhenUnscoped)

	created.CacheKey = "session-sales-cache"
	created.CacheEnabled = boolPtr(false)
	created.SemanticCacheEnabled = boolPtr(true)
	created.CacheScopeMode = stringPtr("session")
	created.CacheMetadataScopeKeys = []string{"session_id"}
	created.CacheAllowSemanticWhenUnscoped = boolPtr(false)

	require.NoError(t, store.UpdateVirtualKey(ctx, created))

	updated, err := store.GetVirtualKey(ctx, vk.ID)
	require.NoError(t, err)
	assert.Equal(t, "session-sales-cache", updated.CacheKey)
	require.NotNil(t, updated.CacheEnabled)
	assert.False(t, *updated.CacheEnabled)
	require.NotNil(t, updated.SemanticCacheEnabled)
	assert.True(t, *updated.SemanticCacheEnabled)
	require.NotNil(t, updated.CacheScopeMode)
	assert.Equal(t, "session", *updated.CacheScopeMode)
	assert.Equal(t, []string{"session_id"}, updated.CacheMetadataScopeKeys)
	require.NotNil(t, updated.CacheAllowSemanticWhenUnscoped)
	assert.False(t, *updated.CacheAllowSemanticWhenUnscoped)
}
