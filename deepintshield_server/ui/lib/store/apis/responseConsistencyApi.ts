import { baseApi } from "./baseApi";

// JSON shapes mirror response_consistency.Stats / TraceEntry on the Go side.
export interface ConsistencyStats {
	enabled: boolean;
	total_requests: number;
	exact_hits: number;
	semantic_hits: number;
	pinned_hits: number;
	cost_saved_usd: number;
	latency_saved_ms: number;
	tokens_saved: number;
}

export interface ConsistencyStatsResponse {
	instances: number;
	aggregate: ConsistencyStats;
	hit_rate: number;
}

export interface ConsistencyTrace {
	timestamp: string;
	request_id?: string;
	source: "exact" | "semantic" | "pinned" | "miss";
	similarity: number;
	fingerprint: string;
	canonical_query: string;
	incoming_prompt?: string;
	verdict?: string;
	latency_saved_ms: number;
	tokens_saved: number;
	model?: string;
	policy_version?: string;
	pinned_version?: number;
}

export interface ConsistencyTracesResponse {
	traces: ConsistencyTrace[];
}

export const responseConsistencyApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		getConsistencyStats: builder.query<ConsistencyStatsResponse, void>({
			query: () => "/response-consistency/stats",
			// Stats are hot-path counters that move every request; cheap
			// poll-on-mount is fine, no providesTags needed.
		}),
		getConsistencyTraces: builder.query<ConsistencyTracesResponse, number | void>({
			query: (limit) => `/response-consistency/traces${limit ? `?limit=${limit}` : ""}`,
		}),
	}),
});

export const {
	useGetConsistencyStatsQuery,
	useGetConsistencyTracesQuery,
} = responseConsistencyApi;
