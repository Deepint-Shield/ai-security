package semanticcache

import (
	"context"
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func (plugin *Plugin) shouldUseCacheForLookup(ctx *schemas.DeepIntShieldContext, provider schemas.ModelProvider) bool {
	if plugin.requestKeyProvider == nil {
		return true
	}
	keys, explicitSelection, err := plugin.resolveCacheCandidateKeys(ctx, provider)
	if err != nil {
		plugin.logger.Warn("%s Failed to resolve cache candidate keys: %v", PluginLoggerPrefix, err)
		return false
	}
	if len(keys) == 0 {
		return false
	}

	enabledCount := 0
	for _, key := range keys {
		if keyUsesCache(key) {
			enabledCount++
		}
	}
	if enabledCount == 0 {
		return false
	}
	if explicitSelection {
		return keyUsesCache(keys[0])
	}
	return enabledCount == len(keys)
}

func (plugin *Plugin) shouldStoreCacheForResult(ctx *schemas.DeepIntShieldContext, provider schemas.ModelProvider) bool {
	if plugin.requestKeyProvider == nil {
		return true
	}
	keys, explicitSelection, err := plugin.resolveCacheCandidateKeys(ctx, provider)
	if err != nil {
		plugin.logger.Warn("%s Failed to resolve cache storage key: %v", PluginLoggerPrefix, err)
		return false
	}
	if len(keys) == 0 {
		return false
	}
	if explicitSelection {
		return keyUsesCache(keys[0])
	}
	return false
}

func (plugin *Plugin) resolveCacheCandidateKeys(ctx context.Context, provider schemas.ModelProvider) ([]schemas.Key, bool, error) {
	if ctx == nil {
		return nil, false, nil
	}
	if directKey, ok := ctx.Value(schemas.DeepIntShieldContextKeyDirectKey).(schemas.Key); ok {
		return []schemas.Key{directKey}, true, nil
	}
	if selectedKeyID, ok := ctx.Value(schemas.DeepIntShieldContextKeySelectedKeyID).(string); ok && strings.TrimSpace(selectedKeyID) != "" {
		key, err := plugin.resolveProviderKey(ctx, provider, func(candidate schemas.Key) bool {
			return candidate.ID == selectedKeyID
		})
		if err != nil {
			return nil, false, err
		}
		return []schemas.Key{key}, true, nil
	}
	if keyID, ok := ctx.Value(schemas.DeepIntShieldContextKeyAPIKeyID).(string); ok && strings.TrimSpace(keyID) != "" {
		key, err := plugin.resolveProviderKey(ctx, provider, func(candidate schemas.Key) bool {
			return candidate.ID == keyID
		})
		if err != nil {
			return nil, false, err
		}
		return []schemas.Key{key}, true, nil
	}
	if keyName, ok := ctx.Value(schemas.DeepIntShieldContextKeyAPIKeyName).(string); ok && strings.TrimSpace(keyName) != "" {
		key, err := plugin.resolveProviderKey(ctx, provider, func(candidate schemas.Key) bool {
			return candidate.Name == keyName
		})
		if err != nil {
			return nil, false, err
		}
		return []schemas.Key{key}, true, nil
	}
	if plugin.requestKeyProvider == nil {
		return nil, false, nil
	}
	keys, err := plugin.requestKeyProvider.GetKeysForProvider(ctx, provider)
	if err != nil {
		return nil, false, err
	}
	filtered := make([]schemas.Key, 0, len(keys))
	for _, key := range keys {
		if key.Enabled != nil && !*key.Enabled {
			continue
		}
		filtered = append(filtered, key)
	}
	return filtered, false, nil
}

func (plugin *Plugin) resolveProviderKey(ctx context.Context, provider schemas.ModelProvider, match func(schemas.Key) bool) (schemas.Key, error) {
	if plugin.requestKeyProvider == nil {
		return schemas.Key{}, nil
	}
	keys, err := plugin.requestKeyProvider.GetKeysForProvider(ctx, provider)
	if err != nil {
		return schemas.Key{}, err
	}
	for _, key := range keys {
		if match(key) {
			return key, nil
		}
	}
	return schemas.Key{}, fmt.Errorf("cache key policy could not resolve provider key")
}

func keyUsesCache(key schemas.Key) bool {
	return key.UseForCache == nil || *key.UseForCache
}
