package semanticcache

import "github.com/deepint-shield/ai-security/core/schemas"

type pluginStage string

const (
	pluginStageCombined       pluginStage = "combined"
	pluginStageDirectGate     pluginStage = "direct_gate"
	pluginStageSemanticLookup pluginStage = "semantic_lookup"
)

const (
	DirectGatePluginName string = "semantic_cache_direct_gate"

	originalRequestHashKey         schemas.DeepIntShieldContextKey = "semantic_cache_original_request_hash"
	currentRequestHashKey          schemas.DeepIntShieldContextKey = "semantic_cache_current_request_hash"
	guardrailFingerprintKey        schemas.DeepIntShieldContextKey = "semantic_cache_guardrail_fingerprint"
	guardrailSnapshotKey           schemas.DeepIntShieldContextKey = "semantic_cache_guardrail_snapshot"
	guardrailReuseSourceCacheIDKey schemas.DeepIntShieldContextKey = "semantic_cache_guardrail_source_cache_id"
	guardrailReusedKey             schemas.DeepIntShieldContextKey = "semantic_cache_guardrail_reused"
)
