// TypeScript types for the Agentic Cache control plane (Part X).
//
// Mirror the Go structs in:
//   framework/agentic/agentic_cache.go            (Stats / Kind stats)
//   framework/configstore/agentic_cache_store.go  (CacheSavingsBucket)
//   framework/configstore/tables/agentic_cache.go (settings row)
//   transports/.../handlers/agentic_cache.go       (response envelopes)
// Keep in sync when the backend evolves.

export interface AgenticCacheOverview {
	enabled: boolean;
	decision_cache_hit_rate: number; // security decision/verdict cache
	agentic_cache_hit_rate: number; // response/semantic/tool-result
	semantic_cache_hit_rate: number;
	calls_skipped: number; // == agentic hits
	tokens_saved: number;
	cost_saved_usd_today: number;
	latency_saved_ms: number;
	cross_boundary_serves: number; // 0 by construction
}

export interface CacheTableRow {
	name: string;
	kind: string; // stat kind for /cache-stat ("" = not statable)
	key_scoped: boolean; // supports the per-row VK scope selector
	scope: string; // boundary description (shown as subtitle)
	tier: string;
	ttl: string;
	invalidation: string;
	enabled: boolean;
	hit_rate: number;
	size: number;
	high_risk?: string;
}

export interface CachesResponse {
	security: CacheTableRow[];
	agentic: CacheTableRow[];
}

export interface CacheStat {
	kind: string;
	hit_rate: number;
	size: number;
}

// One time-bucket of savings - the shared shape every additive overlay reads.
export interface CacheSavingsBucket {
	bucket: string; // RFC3339
	hits: number;
	misses: number;
	calls_skipped: number;
	tokens_saved: number;
	cost_saved_usd: number;
	latency_saved_ms: number;
}

export interface CacheSavingsSeries {
	bucket: "hour" | "day";
	series: CacheSavingsBucket[];
}

export interface AgenticCacheSettings {
	id?: string;
	workspace_id?: string;
	enabled: boolean;
	response_enabled: boolean;
	semantic_enabled: boolean;
	tool_result_enabled: boolean;
	embedding_enabled: boolean;
	mcp_discovery_enabled: boolean;
	semantic_threshold: number;
	semantic_read_only: boolean;
	never_cache_high_risk: boolean;
	encrypt_at_rest: boolean;
	honor_obligations: boolean;
	response_ttl_seconds: number;
	semantic_ttl_seconds: number;
	tool_result_ttl_seconds: number;
}
