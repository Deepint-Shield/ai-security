package semanticcache

import (
	"context"
	"fmt"
	"strings"

	"github.com/cespare/xxhash/v2"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
)

type AutoScopeMode string

const (
	AutoScopeModeConservative AutoScopeMode = "conservative"
	AutoScopeModeBalanced     AutoScopeMode = "balanced"
	AutoScopeModeAggressive   AutoScopeMode = "aggressive"
)

type SharedVirtualKeyPolicy string

const (
	SharedVirtualKeyPolicyExactOnlyWhenUnscoped     SharedVirtualKeyPolicy = "exact_only_when_unscoped"
	SharedVirtualKeyPolicyAllowSemanticWhenUnscoped SharedVirtualKeyPolicy = "allow_semantic_when_unscoped"
)

type VirtualKeyCacheScopeMode string

const (
	VirtualKeyCacheScopeModeInherit        VirtualKeyCacheScopeMode = "inherit"
	VirtualKeyCacheScopeModeVirtualKey     VirtualKeyCacheScopeMode = "virtual_key"
	VirtualKeyCacheScopeModeUser           VirtualKeyCacheScopeMode = "user"
	VirtualKeyCacheScopeModeUseCase        VirtualKeyCacheScopeMode = "use_case"
	VirtualKeyCacheScopeModeSession        VirtualKeyCacheScopeMode = "session"
	VirtualKeyCacheScopeModeCustomMetadata VirtualKeyCacheScopeMode = "custom_metadata"
	VirtualKeyCacheScopeModeNone           VirtualKeyCacheScopeMode = "none"
)

var DefaultScopeSignalOrder = []string{
	"governance_user_id",
	"request_user",
	"metadata.cache_scope",
	"metadata.use_case",
	"responses_conversation",
	"session_id",
}

var DefaultMetadataScopeKeys = []string{"cache_scope", "use_case"}

const (
	cacheResolutionAppliedKey        schemas.DeepIntShieldContextKey = "semantic_cache_resolution_applied"
	cacheScopeTypeKey                schemas.DeepIntShieldContextKey = "semantic_cache_scope_type"
	cacheScopeSourceKey              schemas.DeepIntShieldContextKey = "semantic_cache_scope_source"
	cacheScopeValueHashKey           schemas.DeepIntShieldContextKey = "semantic_cache_scope_value_hash"
	cacheSemanticAllowedKey          schemas.DeepIntShieldContextKey = "semantic_cache_semantic_allowed"
	cacheSemanticSuppressedReasonKey schemas.DeepIntShieldContextKey = "semantic_cache_semantic_suppressed_reason"
)

type cacheResolution struct {
	Applied                  bool
	CacheKey                 string
	ScopeType                string
	ScopeSource              string
	ScopeValueHash           string
	SemanticAllowed          bool
	SemanticSuppressedReason string
}

type virtualKeyCacheSettings struct {
	HasVirtualKey             bool
	VirtualKeyID              string
	CacheKey                  string
	CacheEnabled              *bool
	SemanticCacheEnabled      *bool
	ScopeMode                 VirtualKeyCacheScopeMode
	MetadataScopeKeys         []string
	AllowSemanticWhenUnscoped *bool
}

func (plugin *Plugin) resolveCachePlan(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) cacheResolution {
	if resolution, ok := plugin.cachePlanFromContext(ctx); ok {
		return resolution
	}

	resolution := cacheResolution{
		Applied:         true,
		SemanticAllowed: true,
	}

	settings := plugin.virtualKeyCacheSettingsFromContext(ctx)

	explicitCacheKey, hasExplicitCacheKey := plugin.explicitCacheKeyFromContext(ctx)
	if hasExplicitCacheKey {
		resolution.CacheKey = explicitCacheKey
		resolution.ScopeType = "explicit"
		resolution.ScopeSource = "explicit_cache_key"
		resolution.ScopeValueHash = hashScopeValue(explicitCacheKey)
		resolution = applySemanticCacheSetting(resolution, settings)
		plugin.storeCachePlanInContext(ctx, resolution)
		return resolution
	}

	if settings.CacheKey != "" {
		resolution.CacheKey = settings.CacheKey
		resolution.ScopeType = "virtual_key_cache_key"
		resolution.ScopeSource = "virtual_key_cache_key"
		resolution.ScopeValueHash = hashScopeValue(settings.CacheKey)
		resolution = applySemanticCacheSetting(resolution, settings)
		plugin.storeCachePlanInContext(ctx, resolution)
		return resolution
	}

	if settings.CacheEnabled != nil && !*settings.CacheEnabled {
		resolution.SemanticAllowed = false
		resolution.SemanticSuppressedReason = "virtual_key_cache_disabled"
		plugin.storeCachePlanInContext(ctx, resolution)
		return resolution
	}

	if settings.ScopeMode == VirtualKeyCacheScopeModeNone {
		resolution.SemanticAllowed = false
		resolution.SemanticSuppressedReason = "virtual_key_scope_mode_none"
		plugin.storeCachePlanInContext(ctx, resolution)
		return resolution
	}

	if plugin.config.AutoScopeEnabled != nil && !*plugin.config.AutoScopeEnabled {
		resolution = plugin.resolveLegacyCachePlan(ctx, req, settings)
		plugin.storeCachePlanInContext(ctx, resolution)
		return resolution
	}

	if settings.HasVirtualKey {
		if derivedScope, ok := plugin.resolveDerivedScope(ctx, req, settings); ok {
			resolution.CacheKey = buildScopedCacheKey(settings.VirtualKeyID, derivedScope.ScopeType, derivedScope.ScopeValueHash)
			resolution.ScopeType = derivedScope.ScopeType
			resolution.ScopeSource = derivedScope.ScopeSource
			resolution.ScopeValueHash = derivedScope.ScopeValueHash
			resolution = applySemanticCacheSetting(resolution, settings)
			plugin.storeCachePlanInContext(ctx, resolution)
			return resolution
		}

		resolution.CacheKey = buildScopedCacheKey(settings.VirtualKeyID, "virtual_key", hashScopeValue(settings.VirtualKeyID))
		resolution.ScopeType = "virtual_key"
		resolution.ScopeSource = "virtual_key"
		resolution.ScopeValueHash = hashScopeValue(settings.VirtualKeyID)
		if semanticCacheEnabled(settings) {
			resolution.SemanticAllowed = plugin.allowSemanticWhenUnscoped(settings)
			if !resolution.SemanticAllowed {
				resolution.SemanticSuppressedReason = "unscoped_shared_virtual_key"
			}
		} else {
			resolution = applySemanticCacheSetting(resolution, settings)
		}
		plugin.storeCachePlanInContext(ctx, resolution)
		return resolution
	}

	// Cache scope is anchored on the virtual key. Without a virtual key on
	// the request, there is nothing to partition on - skip caching rather
	// than fall back to tenant- or workspace-wide scope.
	resolution.SemanticAllowed = false
	resolution.SemanticSuppressedReason = "no_virtual_key"
	plugin.storeCachePlanInContext(ctx, resolution)
	return resolution
}

func (plugin *Plugin) resolveLegacyCachePlan(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, settings virtualKeyCacheSettings) cacheResolution {
	resolution := cacheResolution{
		Applied:         true,
		SemanticAllowed: true,
	}

	if !settings.HasVirtualKey {
		resolution.SemanticAllowed = false
		resolution.SemanticSuppressedReason = "no_virtual_key"
		return resolution
	}

	if req == nil {
		return resolution
	}
	if _, err := plugin.generateRequestHash(req); err != nil {
		plugin.logger.Warn(PluginLoggerPrefix + " Failed to generate legacy fallback cache key for request: " + err.Error())
		return resolution
	}

	resolution.CacheKey = buildScopedCacheKey(settings.VirtualKeyID, "virtual_key", hashScopeValue(settings.VirtualKeyID))
	resolution.ScopeType = "virtual_key"
	resolution.ScopeSource = "virtual_key"
	resolution.ScopeValueHash = hashScopeValue(settings.VirtualKeyID)
	resolution.SemanticAllowed = false
	resolution.SemanticSuppressedReason = "request_hash_fallback"
	return resolution
}

type derivedScope struct {
	ScopeType      string
	ScopeSource    string
	ScopeValueHash string
}

func (plugin *Plugin) resolveDerivedScope(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, settings virtualKeyCacheSettings) (derivedScope, bool) {
	mode := settings.ScopeMode
	if mode == "" {
		mode = VirtualKeyCacheScopeModeInherit
	}

	switch mode {
	case VirtualKeyCacheScopeModeUser:
		if value, ok := plugin.requestUserScopeValue(ctx, req); ok {
			return value, true
		}
	case VirtualKeyCacheScopeModeUseCase:
		if value, ok := plugin.metadataScopeValue(req, settings.MetadataScopeKeys, "use_case"); ok {
			return value, true
		}
		if value, ok := plugin.conversationOrSessionScopeValue(ctx, req); ok {
			return value, true
		}
	case VirtualKeyCacheScopeModeSession:
		if value, ok := plugin.conversationOrSessionScopeValue(ctx, req); ok {
			return value, true
		}
	case VirtualKeyCacheScopeModeCustomMetadata:
		if value, ok := plugin.metadataScopeValue(req, settings.MetadataScopeKeys, "custom_metadata"); ok {
			return value, true
		}
	case VirtualKeyCacheScopeModeVirtualKey:
		if !settings.HasVirtualKey {
			return derivedScope{}, false
		}
		return derivedScope{
			ScopeType:      "virtual_key",
			ScopeSource:    "virtual_key",
			ScopeValueHash: hashScopeValue(settings.VirtualKeyID),
		}, true
	default:
		for _, signal := range plugin.config.ScopeSignalOrder {
			value, ok := plugin.scopeFromSignal(ctx, req, signal, settings.MetadataScopeKeys)
			if ok {
				return value, true
			}
		}
	}

	return derivedScope{}, false
}

func (plugin *Plugin) scopeFromSignal(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, signal string, metadataScopeKeys []string) (derivedScope, bool) {
	switch signal {
	case "governance_user_id":
		if value, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceUserID); ok {
			return derivedScope{
				ScopeType:      "user",
				ScopeSource:    "governance_user_id",
				ScopeValueHash: hashScopeValue(value),
			}, true
		}
		if value, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyUserID); ok {
			return derivedScope{
				ScopeType:      "user",
				ScopeSource:    "authenticated_user_id",
				ScopeValueHash: hashScopeValue(value),
			}, true
		}
	case "request_user":
		if value, ok := requestUserFromRequest(req); ok {
			return derivedScope{
				ScopeType:      "user",
				ScopeSource:    "request_user",
				ScopeValueHash: hashScopeValue(value),
			}, true
		}
	case "responses_conversation":
		if value, ok := responsesConversationFromRequest(req); ok {
			return derivedScope{
				ScopeType:      "session",
				ScopeSource:    "responses_conversation",
				ScopeValueHash: hashScopeValue(value),
			}, true
		}
	case "session_id":
		if value, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeySessionID); ok {
			return derivedScope{
				ScopeType:      "session",
				ScopeSource:    "session_id",
				ScopeValueHash: hashScopeValue(value),
			}, true
		}
	default:
		if strings.HasPrefix(signal, "metadata.") {
			key := strings.TrimPrefix(signal, "metadata.")
			scopeType := "custom_metadata"
			if isDefaultMetadataScopeKey(key, metadataScopeKeys) {
				scopeType = "use_case"
			}
			return plugin.metadataScopeValue(req, []string{key}, scopeType)
		}
	}

	return derivedScope{}, false
}

func (plugin *Plugin) requestUserScopeValue(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (derivedScope, bool) {
	if value, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceUserID); ok {
		return derivedScope{
			ScopeType:      "user",
			ScopeSource:    "governance_user_id",
			ScopeValueHash: hashScopeValue(value),
		}, true
	}
	if value, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyUserID); ok {
		return derivedScope{
			ScopeType:      "user",
			ScopeSource:    "authenticated_user_id",
			ScopeValueHash: hashScopeValue(value),
		}, true
	}
	if value, ok := requestUserFromRequest(req); ok {
		return derivedScope{
			ScopeType:      "user",
			ScopeSource:    "request_user",
			ScopeValueHash: hashScopeValue(value),
		}, true
	}
	return derivedScope{}, false
}

func (plugin *Plugin) conversationOrSessionScopeValue(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (derivedScope, bool) {
	if value, ok := responsesConversationFromRequest(req); ok {
		return derivedScope{
			ScopeType:      "session",
			ScopeSource:    "responses_conversation",
			ScopeValueHash: hashScopeValue(value),
		}, true
	}
	if value, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeySessionID); ok {
		return derivedScope{
			ScopeType:      "session",
			ScopeSource:    "session_id",
			ScopeValueHash: hashScopeValue(value),
		}, true
	}
	return derivedScope{}, false
}

func (plugin *Plugin) metadataScopeValue(req *schemas.DeepIntShieldRequest, keys []string, scopeType string) (derivedScope, bool) {
	metadata := requestMetadataFromRequest(req)
	if len(metadata) == 0 {
		return derivedScope{}, false
	}

	parts := make([]string, 0, len(keys))
	sources := make([]string, 0, len(keys))
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		normalized, ok := stringifyScopeValue(value)
		if !ok {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", key, normalized))
		sources = append(sources, "metadata."+key)
	}
	if len(parts) == 0 {
		return derivedScope{}, false
	}

	source := sources[0]
	if len(sources) > 1 {
		source = strings.Join(sources, "+")
	}

	return derivedScope{
		ScopeType:      scopeType,
		ScopeSource:    source,
		ScopeValueHash: hashScopeValue(strings.Join(parts, "|")),
	}, true
}

func (plugin *Plugin) cachePlanFromContext(ctx context.Context) (cacheResolution, bool) {
	if ctx == nil {
		return cacheResolution{}, false
	}
	applied, ok := ctx.Value(cacheResolutionAppliedKey).(bool)
	if !ok || !applied {
		return cacheResolution{}, false
	}

	resolution := cacheResolution{
		Applied: true,
	}
	if cacheKey, ok := ctx.Value(CacheKey).(string); ok {
		resolution.CacheKey = cacheKey
	}
	if scopeType, ok := ctx.Value(cacheScopeTypeKey).(string); ok {
		resolution.ScopeType = scopeType
	}
	if scopeSource, ok := ctx.Value(cacheScopeSourceKey).(string); ok {
		resolution.ScopeSource = scopeSource
	}
	if scopeValueHash, ok := ctx.Value(cacheScopeValueHashKey).(string); ok {
		resolution.ScopeValueHash = scopeValueHash
	}
	if semanticAllowed, ok := ctx.Value(cacheSemanticAllowedKey).(bool); ok {
		resolution.SemanticAllowed = semanticAllowed
	}
	if reason, ok := ctx.Value(cacheSemanticSuppressedReasonKey).(string); ok {
		resolution.SemanticSuppressedReason = reason
	}
	return resolution, true
}

func (plugin *Plugin) storeCachePlanInContext(ctx *schemas.DeepIntShieldContext, resolution cacheResolution) {
	if ctx == nil {
		return
	}
	ctx.SetValue(cacheResolutionAppliedKey, true)
	ctx.SetValue(cacheSemanticAllowedKey, resolution.SemanticAllowed)
	if resolution.CacheKey != "" {
		ctx.SetValue(CacheKey, resolution.CacheKey)
	}
	if resolution.ScopeType != "" {
		ctx.SetValue(cacheScopeTypeKey, resolution.ScopeType)
	}
	if resolution.ScopeSource != "" {
		ctx.SetValue(cacheScopeSourceKey, resolution.ScopeSource)
	}
	if resolution.ScopeValueHash != "" {
		ctx.SetValue(cacheScopeValueHashKey, resolution.ScopeValueHash)
	}
	if resolution.SemanticSuppressedReason != "" {
		ctx.SetValue(cacheSemanticSuppressedReasonKey, resolution.SemanticSuppressedReason)
	}
}

func (plugin *Plugin) virtualKeyCacheSettingsFromContext(ctx context.Context) virtualKeyCacheSettings {
	settings := virtualKeyCacheSettings{
		ScopeMode:         VirtualKeyCacheScopeModeInherit,
		MetadataScopeKeys: append([]string(nil), plugin.config.MetadataScopeKeys...),
	}

	if virtualKeyID, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID); ok {
		settings.HasVirtualKey = true
		settings.VirtualKeyID = virtualKeyID
	}
	if cacheKey, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyCacheKey); ok {
		settings.CacheKey = cacheKey
	}
	if cacheEnabled, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyCacheEnabled).(bool); ok {
		settings.CacheEnabled = deepintshield.Ptr(cacheEnabled)
	}
	if semanticCacheEnabled, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeySemanticCacheEnabled).(bool); ok {
		settings.SemanticCacheEnabled = deepintshield.Ptr(semanticCacheEnabled)
	}
	if scopeMode, ok := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyCacheScopeMode); ok {
		settings.ScopeMode = VirtualKeyCacheScopeMode(scopeMode)
	}
	if metadataScopeKeys, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyCacheMetadataScopeKeys).([]string); ok && len(metadataScopeKeys) > 0 {
		settings.MetadataScopeKeys = append([]string(nil), metadataScopeKeys...)
	}
	if allowSemanticWhenUnscoped, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyCacheAllowSemanticWhenUnscoped).(bool); ok {
		settings.AllowSemanticWhenUnscoped = deepintshield.Ptr(allowSemanticWhenUnscoped)
	}
	return settings
}

func (plugin *Plugin) allowSemanticWhenUnscoped(settings virtualKeyCacheSettings) bool {
	if settings.AllowSemanticWhenUnscoped != nil {
		return *settings.AllowSemanticWhenUnscoped
	}
	return plugin.config.SharedVKPolicy == SharedVirtualKeyPolicyAllowSemanticWhenUnscoped
}

func semanticCacheEnabled(settings virtualKeyCacheSettings) bool {
	if settings.SemanticCacheEnabled != nil {
		return *settings.SemanticCacheEnabled
	}
	return true
}

func applySemanticCacheSetting(resolution cacheResolution, settings virtualKeyCacheSettings) cacheResolution {
	if settings.HasVirtualKey && !semanticCacheEnabled(settings) {
		resolution.SemanticAllowed = false
		resolution.SemanticSuppressedReason = "virtual_key_semantic_cache_disabled"
	}
	return resolution
}

func (plugin *Plugin) explicitCacheKeyFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	cacheKeyValue := ctx.Value(CacheKey)
	if cacheKeyValue == nil {
		return "", false
	}

	cacheKey, ok := cacheKeyValue.(string)
	if !ok {
		plugin.logger.Warn(PluginLoggerPrefix + " Cache key value is not a string; skipping cache for request")
		return "", false
	}
	cacheKey = strings.TrimSpace(cacheKey)
	return cacheKey, cacheKey != ""
}

// buildScopedCacheKey produces a cache key partitioned by virtual key. Tenant
// isolation is enforced separately via the tenant_id metadata filter on
// vectorstore queries (see appendTenantFilter); the partition unit here is the
// virtual key. Returns "" when no virtual key is available - callers treat an
// empty key as "do not cache".
func buildScopedCacheKey(virtualKeyID string, scopeType string, scopeValueHash string) string {
	vk := strings.TrimSpace(virtualKeyID)
	if vk == "" {
		return ""
	}
	return strings.Join([]string{"vk:" + vk, "scope:" + scopeType + ":" + scopeValueHash}, "|")
}

func hashScopeValue(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("%x", xxhash.Sum64String(trimmed))
}

func stringifyScopeValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		typed = strings.TrimSpace(typed)
		return typed, typed != ""
	default:
		payload, err := schemas.MarshalDeeplySorted(typed)
		if err != nil {
			return "", false
		}
		normalized := strings.TrimSpace(string(payload))
		return normalized, normalized != ""
	}
}

func requestMetadataFromRequest(req *schemas.DeepIntShieldRequest) map[string]any {
	if req == nil {
		return nil
	}
	switch req.RequestType {
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		if req.ChatRequest != nil && req.ChatRequest.Params != nil && req.ChatRequest.Params.Metadata != nil {
			return *req.ChatRequest.Params.Metadata
		}
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		if req.ResponsesRequest != nil && req.ResponsesRequest.Params != nil && req.ResponsesRequest.Params.Metadata != nil {
			return *req.ResponsesRequest.Params.Metadata
		}
	}
	return nil
}

func requestUserFromRequest(req *schemas.DeepIntShieldRequest) (string, bool) {
	if req == nil {
		return "", false
	}
	switch req.RequestType {
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		if req.ChatRequest != nil && req.ChatRequest.Params != nil && req.ChatRequest.Params.User != nil {
			value := strings.TrimSpace(*req.ChatRequest.Params.User)
			return value, value != ""
		}
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		if req.TextCompletionRequest != nil && req.TextCompletionRequest.Params != nil && req.TextCompletionRequest.Params.User != nil {
			value := strings.TrimSpace(*req.TextCompletionRequest.Params.User)
			return value, value != ""
		}
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		if req.ResponsesRequest != nil && req.ResponsesRequest.Params != nil && req.ResponsesRequest.Params.User != nil {
			value := strings.TrimSpace(*req.ResponsesRequest.Params.User)
			return value, value != ""
		}
	}
	return "", false
}

func responsesConversationFromRequest(req *schemas.DeepIntShieldRequest) (string, bool) {
	if req == nil {
		return "", false
	}
	switch req.RequestType {
	case schemas.ResponsesRequest, schemas.ResponsesStreamRequest, schemas.WebSocketResponsesRequest:
		if req.ResponsesRequest != nil && req.ResponsesRequest.Params != nil && req.ResponsesRequest.Params.Conversation != nil {
			value := strings.TrimSpace(*req.ResponsesRequest.Params.Conversation)
			return value, value != ""
		}
	}
	return "", false
}

func stringContextValue(ctx context.Context, key schemas.DeepIntShieldContextKey) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(key).(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func isDefaultMetadataScopeKey(key string, metadataScopeKeys []string) bool {
	if key == "" {
		return false
	}
	for _, metadataScopeKey := range metadataScopeKeys {
		if metadataScopeKey == key {
			return true
		}
	}
	for _, defaultKey := range DefaultMetadataScopeKeys {
		if defaultKey == key {
			return true
		}
	}
	return false
}
