// RTK Query slice for the Agentic Cache control plane (Part X).
//
// Backed by /api/agentic-cache/* - live in-process cache stats from the
// runtime plus the persisted, metrics-only event store. The savings-series
// endpoint is the single shared source every additive overlay (Overview /
// Cost / AI Logs / MCP / Agentic Security / Agent Insights) reads, so the
// numbers reconcile across the console.
import type {
	AgenticCacheOverview,
	AgenticCacheSettings,
	CacheSavingsSeries,
	CacheStat,
	CachesResponse,
} from "@/lib/types/agenticCache";
import { baseApi } from "./baseApi";

const TAG_OVERVIEW = "AgenticCacheOverview";
const TAG_CACHES = "AgenticCacheCaches";
const TAG_SETTINGS = "AgenticCacheSettings";
const TAG_SAVINGS = "AgenticCacheSavings";

// windowQS builds the ?since=&until= query string shared by the windowed
// endpoints (overview / caches) from an optional RFC3339 range.
function windowQS(args?: { since?: string; until?: string } | void): string {
	if (!args) return "";
	const params = new URLSearchParams();
	if (args.since) params.set("since", args.since);
	if (args.until) params.set("until", args.until);
	const qs = params.toString();
	return qs ? `?${qs}` : "";
}

const baseWithTags = baseApi.enhanceEndpoints({
	addTagTypes: [TAG_OVERVIEW, TAG_CACHES, TAG_SETTINGS, TAG_SAVINGS],
});

export const agenticCacheApi = baseWithTags.injectEndpoints({
	endpoints: (builder) => ({
		// since/until (RFC3339) honor the same date filter as the Overview screen.
		getAgenticCacheOverview: builder.query<AgenticCacheOverview, { since?: string; until?: string } | void>({
			query: (args) => `/agentic-cache/overview${windowQS(args)}`,
			providesTags: [TAG_OVERVIEW],
		}),

		// Returns the cache table metadata + default hit rates over the window.
		// Each key-scoped row re-fetches its own figure for a selected key set
		// via getAgenticCacheStat (the per-row scope selector).
		getAgenticCaches: builder.query<CachesResponse, { since?: string; until?: string } | void>({
			query: (args) => `/agentic-cache/caches${windowQS(args)}`,
			providesTags: [TAG_CACHES],
		}),

		// Hit rate (+ size) for one cache kind under a chosen virtual-key set.
		// virtualKeys empty ⇒ all keys in the workspace.
		getAgenticCacheStat: builder.query<CacheStat, { kind: string; virtualKeys?: string[] }>({
			query: ({ kind, virtualKeys }) => {
				const params = new URLSearchParams({ kind });
				if (virtualKeys && virtualKeys.length > 0) params.set("virtual_keys", virtualKeys.join(","));
				return `/agentic-cache/cache-stat?${params.toString()}`;
			},
			providesTags: [TAG_CACHES],
		}),

		// Time-bucketed savings. bucket = "hour" | "day"; since/until honor the
		// Overview date filter.
		getAgenticCacheSavingsSeries: builder.query<
			CacheSavingsSeries,
			{ bucket?: "hour" | "day"; since?: string; until?: string } | void
		>({
			query: (args) => {
				const params = new URLSearchParams();
				if (args && args.bucket) params.set("bucket", args.bucket);
				if (args && args.since) params.set("since", args.since);
				if (args && args.until) params.set("until", args.until);
				const qs = params.toString();
				return `/agentic-cache/savings-series${qs ? `?${qs}` : ""}`;
			},
			providesTags: [TAG_SAVINGS],
		}),

		getAgenticCacheSettings: builder.query<AgenticCacheSettings, void>({
			query: () => "/agentic-cache/settings",
			providesTags: [TAG_SETTINGS],
		}),

		updateAgenticCacheSettings: builder.mutation<AgenticCacheSettings, Partial<AgenticCacheSettings>>({
			query: (body) => ({ url: "/agentic-cache/settings", method: "PUT", body }),
			invalidatesTags: [TAG_SETTINGS, TAG_CACHES, TAG_OVERVIEW],
		}),

		flushAgenticCache: builder.mutation<{ ok: boolean }, void>({
			query: () => ({ url: "/agentic-cache/flush", method: "DELETE" }),
			invalidatesTags: [TAG_OVERVIEW, TAG_CACHES, TAG_SAVINGS],
		}),
	}),
});

export const {
	useGetAgenticCacheOverviewQuery,
	useGetAgenticCachesQuery,
	useGetAgenticCacheStatQuery,
	useGetAgenticCacheSavingsSeriesQuery,
	useGetAgenticCacheSettingsQuery,
	useUpdateAgenticCacheSettingsMutation,
	useFlushAgenticCacheMutation,
} = agenticCacheApi;
