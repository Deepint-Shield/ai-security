package semanticcache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/deepint-shield/ai-security/framework/vectorstore"
	"github.com/deepint-shield/ai-security/plugins/guardrails"
	"github.com/google/uuid"
)

func (plugin *Plugin) preLLMHookDirectGate(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	schemas.EnsureLatencyTracking(ctx, time.Now())
	if _, ok := ctx.Value(requestStartTimeKey).(time.Time); !ok {
		ctx.SetValue(requestStartTimeKey, time.Now())
	}

	provider, model, _ := req.GetRequestFields()

	if !plugin.shouldUseCacheForLookup(ctx, provider) {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping direct cache gate because cache is disabled for the selected or candidate API key(s)")
		return req, nil, nil
	}

	cachePlan := plugin.resolveCachePlan(ctx, req)
	if cachePlan.CacheKey == "" {
		return req, nil, nil
	}
	if plugin.isConversationHistoryThresholdExceeded(req) {
		return req, nil, nil
	}

	if _, ok := ctx.Value(requestIDKey).(string); !ok {
		ctx.SetValue(requestIDKey, uuid.New().String())
	}
	ctx.SetValue(requestModelKey, model)
	ctx.SetValue(requestProviderKey, provider)
	ctx.SetValue(cacheLookupAttemptedKey, true)

	hash, paramsHash, err := plugin.prepareOriginalRequestLookup(ctx, req)
	if err != nil {
		plugin.logger.Warn("%s Failed to prepare original request hash for direct cache gate: %v", PluginLoggerPrefix, err)
		return req, nil, nil
	}

	cacheTypeVal, hasExplicitCacheType := ctx.Value(CacheTypeKey).(CacheType)
	if hasExplicitCacheType && cacheTypeVal == CacheTypeSemantic {
		return req, nil, nil
	}

	guardrailFingerprint, err := plugin.currentGuardrailFingerprint(ctx)
	if err != nil || strings.TrimSpace(guardrailFingerprint) == "" {
		if err != nil {
			plugin.logger.Warn("%s Failed to resolve guardrail fingerprint for direct cache gate: %v", PluginLoggerPrefix, err)
		}
		return req, nil, nil
	}
	ctx.SetValue(guardrailFingerprintKey, guardrailFingerprint)

	stopLookup := schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseCacheLookupDirect)
	shortCircuit, err := plugin.performGuardrailAwareDirectSearch(ctx, req, cachePlan.CacheKey, hash, paramsHash, guardrailFingerprint)
	stopLookup()
	if err != nil {
		plugin.logger.Warn(PluginLoggerPrefix + " Direct search failed: " + err.Error())
		return req, nil, nil
	}
	if shortCircuit != nil {
		return req, shortCircuit, nil
	}
	return req, nil, nil
}

func (plugin *Plugin) preLLMHookSemanticLookup(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	schemas.EnsureLatencyTracking(ctx, time.Now())
	if _, ok := ctx.Value(requestStartTimeKey).(time.Time); !ok {
		ctx.SetValue(requestStartTimeKey, time.Now())
	}

	provider, model, _ := req.GetRequestFields()
	_ = model

	if !plugin.shouldUseCacheForLookup(ctx, provider) {
		plugin.logger.Debug(PluginLoggerPrefix + " Skipping semantic cache lookup because cache is disabled for the selected or candidate API key(s)")
		return req, nil, nil
	}

	cachePlan := plugin.resolveCachePlan(ctx, req)
	if cachePlan.CacheKey == "" {
		return req, nil, nil
	}
	if plugin.isConversationHistoryThresholdExceeded(req) {
		return req, nil, nil
	}

	if _, ok := ctx.Value(requestIDKey).(string); !ok {
		ctx.SetValue(requestIDKey, uuid.New().String())
	}
	ctx.SetValue(requestModelKey, model)
	ctx.SetValue(requestProviderKey, provider)
	ctx.SetValue(cacheLookupAttemptedKey, true)

	cacheTypeVal, hasExplicitCacheType := ctx.Value(CacheTypeKey).(CacheType)
	if err := plugin.prepareCurrentRequestState(ctx, req); err != nil {
		plugin.logger.Warn("%s Failed to prepare current request metadata for semantic cache: %v", PluginLoggerPrefix, err)
		return req, nil, nil
	}

	performSemantic := cachePlan.SemanticAllowed && plugin.client != nil
	if hasExplicitCacheType {
		performSemantic = cacheTypeVal == CacheTypeSemantic
	}

	if performSemantic {
		if req.EmbeddingRequest != nil || req.TranscriptionRequest != nil {
			if plugin.store.RequiresVectors() && plugin.config.Dimension > 0 {
				ctx.SetValue(requestEmbeddingKey, make([]float32, plugin.config.Dimension))
			}
			return req, nil, nil
		}
		stopLookup := schemas.TrackLatencyPhase(ctx, schemas.LatencyPhaseCacheLookupSemantic)
		shortCircuit, err := plugin.performSemanticSearch(ctx, req, cachePlan.CacheKey)
		stopLookup()
		if err != nil {
			return req, nil, nil
		}
		if shortCircuit != nil {
			return req, shortCircuit, nil
		}
		return req, nil, nil
	}

	if plugin.store.RequiresVectors() && plugin.config.Dimension > 0 {
		ctx.SetValue(requestEmbeddingKey, make([]float32, plugin.config.Dimension))
	}
	return req, nil, nil
}

func (plugin *Plugin) postLLMHookDirectGate(ctx *schemas.DeepIntShieldContext, res *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	if deepintshieldErr != nil {
		return res, deepintshieldErr, nil
	}

	if isCacheHit, ok := ctx.Value(isCacheHitKey).(bool); ok && isCacheHit {
		if cacheType, ok := ctx.Value(cacheHitTypeKey).(CacheType); ok && cacheType == CacheTypeDirect {
			plugin.cloneGuardrailEvidenceAsync(ctx)
		}
		return res, nil, nil
	}

	if res == nil {
		return res, nil, nil
	}

	if isLargePayload, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool); ok && isLargePayload {
		return res, nil, nil
	}
	if isLargeResponse, ok := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); ok && isLargeResponse {
		return res, nil, nil
	}

	noStore := ctx.Value(CacheNoStoreKey)
	if noStoreValue, ok := noStore.(bool); ok && noStoreValue {
		return res, nil, nil
	}

	cachePlan := plugin.resolveCachePlan(ctx, nil)
	if cachePlan.CacheKey == "" {
		return res, nil, nil
	}

	extraFields := res.GetExtraFields()
	if attempted, ok := ctx.Value(cacheLookupAttemptedKey).(bool); ok && attempted {
		if extraFields.CacheDebug == nil {
			extraFields.CacheDebug = &schemas.DeepIntShieldCacheDebug{CacheHit: false}
		} else if !extraFields.CacheDebug.CacheHit {
			extraFields.CacheDebug.CacheHit = false
		}
		plugin.populateCacheDebugScope(extraFields.CacheDebug, ctx, cachePlan)
	}

	requestID, ok := ctx.Value(requestIDKey).(string)
	if !ok || strings.TrimSpace(requestID) == "" {
		return res, nil, nil
	}

	provider, ok := ctx.Value(requestProviderKey).(schemas.ModelProvider)
	if !ok {
		return res, nil, nil
	}
	if !plugin.shouldStoreCacheForResult(ctx, provider) {
		return res, nil, nil
	}

	model, ok := ctx.Value(requestModelKey).(string)
	if !ok {
		return res, nil, nil
	}

	currentHash, _ := ctx.Value(currentRequestHashKey).(string)
	if currentHash == "" {
		currentHash, _ = ctx.Value(requestHashKey).(string)
	}
	if currentHash == "" {
		currentHash, _ = ctx.Value(originalRequestHashKey).(string)
	}
	if currentHash == "" {
		plugin.logger.Warn(PluginLoggerPrefix + " Current request hash is not available, continuing without caching")
		return res, nil, nil
	}

	originalHash, _ := ctx.Value(originalRequestHashKey).(string)
	if originalHash == "" {
		originalHash = currentHash
	}

	embedding, _ := ctx.Value(requestEmbeddingKey).([]float32)
	guardrailFingerprint, _ := ctx.Value(guardrailFingerprintKey).(string)
	guardrailSnapshot, _ := ctx.Value(guardrailSnapshotKey).(*guardrails.CacheSnapshot)
	if guardrailSnapshot == nil {
		if snapshot, ok := guardrails.CacheSnapshotFromContext(ctx); ok {
			guardrailSnapshot = snapshot
			ctx.SetValue(guardrailSnapshotKey, snapshot)
		}
	}
	paramsHash, _ := ctx.Value(requestParamsHashKey).(string)

	shouldStoreEmbeddings := cachePlan.SemanticAllowed
	cacheTypeVal, hasExplicitCacheType := ctx.Value(CacheTypeKey).(CacheType)
	if hasExplicitCacheType {
		if cacheTypeVal == CacheTypeDirect && !plugin.store.RequiresVectors() {
			shouldStoreEmbeddings = false
		}
	}
	if !shouldStoreEmbeddings {
		embedding = nil
	}
	if plugin.store.RequiresVectors() && embedding == nil && plugin.config.Dimension > 0 {
		embedding = make([]float32, plugin.config.Dimension)
	}

	inputTokens, ok := ctx.Value(requestEmbeddingTokensKey).(int)
	if ok {
		if extraFields.CacheDebug == nil {
			extraFields.CacheDebug = &schemas.DeepIntShieldCacheDebug{}
		}
		extraFields.CacheDebug.CacheHit = false
		extraFields.CacheDebug.ProviderUsed = deepintshield.Ptr(string(plugin.config.Provider))
		extraFields.CacheDebug.ModelUsed = deepintshield.Ptr(plugin.config.EmbeddingModel)
		extraFields.CacheDebug.InputTokens = &inputTokens
		plugin.populateCacheDebugScope(extraFields.CacheDebug, ctx, cachePlan)
	}

	cacheTTL := plugin.config.TTL
	if ttl, ok := ctx.Value(CacheTTLKey).(time.Duration); ok && ttl > 0 {
		cacheTTL = ttl
	}

	requestType := extraFields.RequestType
	isFinalChunk := deepintshield.IsFinalChunk(ctx)

	plugin.waitGroup.Add(1)
	go func() {
		defer plugin.waitGroup.Done()
		defer safegoroutine.Recover(plugin.logger, "semanticcache.direct-gate-cache-write")

		cacheCtx, cancel := context.WithTimeout(context.Background(), CacheSetTimeout)
		defer cancel()

		unifiedMetadata := plugin.buildUnifiedMetadata(provider, model, paramsHash, currentHash, cachePlan, plugin.tenantIDFromContext(ctx), cacheTTL)
		unifiedMetadata["original_request_hash"] = originalHash
		if strings.TrimSpace(guardrailFingerprint) != "" {
			unifiedMetadata["guardrail_fingerprint"] = guardrailFingerprint
		}
		if guardrailSnapshot != nil {
			rawSnapshot, err := json.Marshal(guardrailSnapshot)
			if err == nil {
				unifiedMetadata["guardrail_snapshot"] = string(rawSnapshot)
			}
		}

		if deepintshield.IsStreamRequestType(requestType) {
			if err := plugin.addStreamingResponse(cacheCtx, requestID, res, deepintshieldErr, embedding, unifiedMetadata, cacheTTL, isFinalChunk); err != nil {
				plugin.logger.Warn("%s Failed to cache streaming response: %v", PluginLoggerPrefix, err)
			}
			return
		}
		if err := plugin.addSingleResponse(cacheCtx, requestID, res, embedding, unifiedMetadata, cacheTTL); err != nil {
			plugin.logger.Warn("%s Failed to cache single response: %v", PluginLoggerPrefix, err)
		}
	}()

	return res, nil, nil
}

func (plugin *Plugin) prepareOriginalRequestLookup(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (string, string, error) {
	hash, err := plugin.generateRequestHash(req)
	if err != nil {
		return "", "", err
	}
	_, paramsHash, err := plugin.extractTextForEmbedding(req)
	if err != nil {
		return "", "", err
	}
	ctx.SetValue(originalRequestHashKey, hash)
	ctx.SetValue(requestParamsHashKey, paramsHash)
	return hash, paramsHash, nil
}

func (plugin *Plugin) prepareCurrentRequestState(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) error {
	hash, err := plugin.generateRequestHash(req)
	if err != nil {
		return err
	}
	ctx.SetValue(currentRequestHashKey, hash)
	ctx.SetValue(requestHashKey, hash)

	_, paramsHash, err := plugin.extractTextForEmbedding(req)
	if err != nil {
		return err
	}
	ctx.SetValue(requestParamsHashKey, paramsHash)
	return nil
}

func (plugin *Plugin) performGuardrailAwareDirectSearch(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, cacheKey, originalHash, paramsHash, fingerprint string) (*schemas.LLMPluginShortCircuit, error) {
	provider, model, _ := req.GetRequestFields()

	filters := []vectorstore.Query{
		{Field: "original_request_hash", Operator: vectorstore.QueryOperatorEqual, Value: originalHash},
		{Field: "cache_key", Operator: vectorstore.QueryOperatorEqual, Value: cacheKey},
		{Field: "params_hash", Operator: vectorstore.QueryOperatorEqual, Value: paramsHash},
		{Field: "guardrail_fingerprint", Operator: vectorstore.QueryOperatorEqual, Value: fingerprint},
		{Field: "from_deepintshield_semantic_cache_plugin", Operator: vectorstore.QueryOperatorEqual, Value: true},
	}
	filters = plugin.appendTenantFilter(ctx, filters)
	if plugin.config.CacheByProvider != nil && *plugin.config.CacheByProvider {
		filters = append(filters, vectorstore.Query{Field: "provider", Operator: vectorstore.QueryOperatorEqual, Value: string(provider)})
	}
	if plugin.config.CacheByModel != nil && *plugin.config.CacheByModel {
		filters = append(filters, vectorstore.Query{Field: "model", Operator: vectorstore.QueryOperatorEqual, Value: model})
	}

	selectFields := append([]string(nil), SelectFields...)
	if deepintshield.IsStreamRequestType(req.RequestType) {
		selectFields = removeField(selectFields, "response")
	} else {
		selectFields = removeField(selectFields, "stream_chunks")
	}

	stream := deepintshield.IsStreamRequestType(req.RequestType)

	// L1 read-through in front of the remote exact-hash lookup. On a hit we
	// skip the ~180 ms vector-store RTT entirely and serve from a ~80 ns map
	// read. The key reproduces the full filter set (incl. tenant + scope +
	// guardrail fingerprint), so the isolation guarantees are identical to the
	// remote query. See direct_l1.go.
	l1Key := directL1Key(plugin.config.VectorStoreNamespace, stream, filters)
	if plugin.directL1 != nil {
		if cached, ok := plugin.directL1.lookup(l1Key); ok {
			return plugin.serveDirectResult(ctx, req, cached)
		}
	}

	var cursor *string
	results, _, err := plugin.store.GetAll(ctx, plugin.config.VectorStoreNamespace, filters, selectFields, cursor, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to search for direct hash match: %w", err)
	}
	if len(results) == 0 {
		return nil, nil
	}

	result := results[0]
	// Populate L1, except for no-store / zero-retention requests (defensive -
	// such requests never get written to the durable store either, so there is
	// normally nothing to read back).
	if plugin.directL1 != nil {
		if noStore, _ := ctx.Value(CacheNoStoreKey).(bool); !noStore {
			plugin.directL1.store(l1Key, result)
		}
	}

	return plugin.serveDirectResult(ctx, req, result)
}

// serveDirectResult turns a direct-gate exact-hash row into a short-circuit
// response, applying the cached guardrail snapshot + evidence-reuse bookkeeping.
// Shared by the L1-hit and remote-store-hit paths so both behave identically
// (guardrail sanitization, snapshot/source-id context values, evidence clone).
func (plugin *Plugin) serveDirectResult(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, result vectorstore.SearchResult) (*schemas.LLMPluginShortCircuit, error) {
	snapshot, ok, err := plugin.extractGuardrailSnapshot(result.Properties)
	if err != nil {
		return nil, err
	}
	if !ok || snapshot == nil {
		return nil, nil
	}

	guardrails.ApplyCachedInputSanitization(req, snapshot)
	ctx.SetValue(guardrailSnapshotKey, snapshot)
	ctx.SetValue(guardrailReuseSourceCacheIDKey, result.ID)
	ctx.SetValue(guardrailReusedKey, true)

	return plugin.buildResponseFromResult(ctx, req, result, CacheTypeDirect, 1.0, 0)
}

func (plugin *Plugin) extractGuardrailSnapshot(properties map[string]interface{}) (*guardrails.CacheSnapshot, bool, error) {
	if properties == nil {
		return nil, false, nil
	}
	raw, ok := properties["guardrail_snapshot"]
	if !ok || raw == nil {
		return nil, false, nil
	}
	rawString, ok := semanticCacheString(raw)
	if !ok || strings.TrimSpace(rawString) == "" {
		return nil, false, nil
	}
	var snapshot guardrails.CacheSnapshot
	if err := json.Unmarshal([]byte(rawString), &snapshot); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal guardrail snapshot: %w", err)
	}
	return &snapshot, true, nil
}

func (plugin *Plugin) currentGuardrailFingerprint(ctx *schemas.DeepIntShieldContext) (string, error) {
	if plugin.guardrailReuse == nil {
		return "", nil
	}
	return plugin.guardrailReuse.CurrentCacheFingerprint(ctx)
}

func (plugin *Plugin) cloneGuardrailEvidenceAsync(ctx *schemas.DeepIntShieldContext) {
	if plugin.guardrailReuse == nil || plugin.evidenceStore == nil {
		return
	}
	snapshot, ok := ctx.Value(guardrailSnapshotKey).(*guardrails.CacheSnapshot)
	if !ok || snapshot == nil {
		return
	}
	sourceCacheID, _ := ctx.Value(guardrailReuseSourceCacheIDKey).(string)

	plugin.waitGroup.Add(1)
	go func(snapshot *guardrails.CacheSnapshot, sourceCacheID string) {
		defer plugin.waitGroup.Done()
		defer safegoroutine.Recover(plugin.logger, "semanticcache.direct-gate-clone-evidence")
		if err := plugin.guardrailReuse.CloneCachedEvidence(ctx, snapshot, sourceCacheID); err != nil {
			plugin.logger.Warn("%s Failed to clone cached guardrail evidence: %v", PluginLoggerPrefix, err)
		}
	}(snapshot, sourceCacheID)
}
