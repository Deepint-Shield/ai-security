// RTK Query slice for the Agentic Security control plane (basic PDP).
//
// Maps 1-to-1 to /api/agentic-security/* endpoints. Mutations invalidate
// the relevant tags so the UI re-fetches without manual refresh.
import type {
	AgenticDecision,
	AgenticEnforcementState,
	AgenticPermissionTemplate,
	AgenticPermissionTemplateList,
	AgenticPolicy,
	AgenticToolTemplate,
	AgenticToolTemplateList,
	AgenticToolTier,
} from "@/lib/types/agentic";
import { baseApi } from "./baseApi";

// AgenticBasicStats - the minimal OSS decision-counts payload returned by
// GET /agentic-security/stats. It drives the dashboard's basic Agentic
// analytics tab.
export interface AgenticBasicStatsTimelinePoint {
	bucket: string;
	allow: number;
	deny: number;
	approval: number;
	mask: number;
}
export interface AgenticBasicStats {
	total: number;
	allow: number;
	deny: number;
	approval: number;
	mask: number;
	timeline: AgenticBasicStatsTimelinePoint[];
}

const TAG_POLICIES = "AgenticPolicies";
const TAG_TOOLS = "AgenticTools";
const TAG_DECISIONS = "AgenticDecisions";
const TAG_ROLLOUT = "AgenticRollout";

const baseWithTags = baseApi.enhanceEndpoints({
	addTagTypes: [TAG_POLICIES, TAG_TOOLS, TAG_DECISIONS, TAG_ROLLOUT],
});

export const agenticSecurityApi = baseWithTags.injectEndpoints({
	endpoints: (builder) => ({
		// Basic OSS decision counts (allow/deny/approval/mask + hourly timeline)
		// over the window - backs the dashboard's basic Agentic analytics tab.
		getAgenticBasicStats: builder.query<AgenticBasicStats, { since?: string; until?: string } | void>({
			query: (args) => {
				const p = new URLSearchParams();
				if (args?.since) p.set("since", args.since);
				if (args?.until) p.set("until", args.until);
				const qs = p.toString();
				return `/agentic-security/stats${qs ? `?${qs}` : ""}`;
			},
			providesTags: [TAG_DECISIONS],
		}),

		// Policies
		listAgenticPolicies: builder.query<AgenticPolicy[], void>({
			query: () => "/agentic-security/policies",
			transformResponse: (r: { policies: AgenticPolicy[] }) => r.policies ?? [],
			providesTags: [TAG_POLICIES],
		}),
		getAgenticPolicy: builder.query<AgenticPolicy, string>({
			query: (id) => `/agentic-security/policies/${encodeURIComponent(id)}`,
			providesTags: (_r, _e, id) => [{ type: TAG_POLICIES, id }],
		}),
		createAgenticPolicy: builder.mutation<AgenticPolicy, Partial<AgenticPolicy>>({
			query: (body) => ({ url: "/agentic-security/policies", method: "POST", body }),
			invalidatesTags: [TAG_POLICIES],
		}),
		updateAgenticPolicy: builder.mutation<AgenticPolicy, { id: string; data: Partial<AgenticPolicy> }>({
			query: ({ id, data }) => ({
				url: `/agentic-security/policies/${encodeURIComponent(id)}`,
				method: "PUT",
				body: data,
			}),
			invalidatesTags: [TAG_POLICIES],
		}),
		deleteAgenticPolicy: builder.mutation<{ deleted: string }, string>({
			query: (id) => ({
				url: `/agentic-security/policies/${encodeURIComponent(id)}`,
				method: "DELETE",
			}),
			invalidatesTags: [TAG_POLICIES],
		}),
		stageAgenticPolicy: builder.mutation<AgenticPolicy, string>({
			query: (id) => ({
				url: `/agentic-security/policies/${encodeURIComponent(id)}/stage`,
				method: "POST",
			}),
			invalidatesTags: [TAG_POLICIES],
		}),
		publishAgenticPolicy: builder.mutation<AgenticPolicy, string>({
			query: (id) => ({
				url: `/agentic-security/policies/${encodeURIComponent(id)}/publish`,
				method: "POST",
			}),
			invalidatesTags: [TAG_POLICIES],
		}),
		testAgenticPolicy: builder.mutation<
			{ total: number; passed: number; failed: number; results: Array<Record<string, unknown>> },
			{ definition: Record<string, unknown>; samples?: Array<Record<string, unknown>> }
		>({
			query: (body) => ({
				url: "/agentic-security/policies/test",
				method: "POST",
				body,
			}),
		}),

		// Tools & tiering
		listAgenticTools: builder.query<AgenticToolTier[], void>({
			query: () => "/agentic-security/tools",
			transformResponse: (r: { tools: AgenticToolTier[] }) => r.tools ?? [],
			providesTags: [TAG_TOOLS],
		}),
		upsertAgenticTool: builder.mutation<AgenticToolTier, Partial<AgenticToolTier>>({
			query: (body) => ({ url: "/agentic-security/tools", method: "PUT", body }),
			invalidatesTags: [TAG_TOOLS],
		}),
		deleteAgenticTool: builder.mutation<{ deleted: string }, string>({
			query: (id) => ({
				url: `/agentic-security/tools/${encodeURIComponent(id)}`,
				method: "DELETE",
			}),
			invalidatesTags: [TAG_TOOLS],
		}),
		// ASI04 supply-chain - pin a tool to its current contract fingerprint
		// (drift trips `fingerprint_drift` at decide); unpin clears it.
		pinAgenticTool: builder.mutation<AgenticToolTier, string>({
			query: (id) => ({
				url: `/agentic-security/tools/${encodeURIComponent(id)}/pin`,
				method: "POST",
			}),
			invalidatesTags: [TAG_TOOLS],
		}),
		unpinAgenticTool: builder.mutation<AgenticToolTier, string>({
			query: (id) => ({
				url: `/agentic-security/tools/${encodeURIComponent(id)}/pin`,
				method: "DELETE",
			}),
			invalidatesTags: [TAG_TOOLS],
		}),

		// Decisions audit
		listAgenticDecisions: builder.query<
			AgenticDecision[],
			{ limit?: number; verdict?: string; tool?: string; since?: string; until?: string } | void
		>({
			query: (params) => {
				const q = new URLSearchParams();
				if (params?.limit) q.set("limit", String(params.limit));
				if (params?.verdict) q.set("verdict", params.verdict);
				if (params?.tool) q.set("tool", params.tool);
				if (params?.since) q.set("since", params.since);
				if (params?.until) q.set("until", params.until);
				return `/agentic-security/decisions${q.toString() ? `?${q.toString()}` : ""}`;
			},
			transformResponse: (r: { decisions: AgenticDecision[] }) => r.decisions ?? [],
			providesTags: [TAG_DECISIONS],
		}),

		// Rollout
		getAgenticRollout: builder.query<AgenticEnforcementState, void>({
			query: () => "/agentic-security/rollout",
			providesTags: [TAG_ROLLOUT],
		}),
		updateAgenticRollout: builder.mutation<AgenticEnforcementState, Partial<AgenticEnforcementState>>({
			query: (body) => ({ url: "/agentic-security/rollout", method: "PUT", body }),
			invalidatesTags: [TAG_ROLLOUT],
		}),

		// Permission templates - curated Claude-SDK-adapted starter configs.
		// No mutation: the catalog is read-only and ships with the binary so
		// it doesn't need cache invalidation. Cached forever on the client.
		listAgenticPermissionTemplates: builder.query<AgenticPermissionTemplateList, void>({
			query: () => "/agentic-security/permission-templates",
		}),
		getAgenticPermissionTemplate: builder.query<AgenticPermissionTemplate, string>({
			query: (id) => `/agentic-security/permission-templates/${encodeURIComponent(id)}`,
		}),

		// Tool templates - icon-driven catalog of pre-classified tool tiers.
		listAgenticToolTemplates: builder.query<AgenticToolTemplateList, void>({
			query: () => "/agentic-security/tool-templates",
		}),
		getAgenticToolTemplate: builder.query<AgenticToolTemplate, string>({
			query: (id) => `/agentic-security/tool-templates/${encodeURIComponent(id)}`,
		}),
	}),
});

export const {
	useGetAgenticBasicStatsQuery,
	useListAgenticPoliciesQuery,
	useGetAgenticPolicyQuery,
	useCreateAgenticPolicyMutation,
	useUpdateAgenticPolicyMutation,
	useDeleteAgenticPolicyMutation,
	useStageAgenticPolicyMutation,
	usePublishAgenticPolicyMutation,
	useTestAgenticPolicyMutation,
	useListAgenticToolsQuery,
	useUpsertAgenticToolMutation,
	useDeleteAgenticToolMutation,
	usePinAgenticToolMutation,
	useUnpinAgenticToolMutation,
	useListAgenticDecisionsQuery,
	useGetAgenticRolloutQuery,
	useUpdateAgenticRolloutMutation,
	useListAgenticPermissionTemplatesQuery,
	useGetAgenticPermissionTemplateQuery,
	useListAgenticToolTemplatesQuery,
	useGetAgenticToolTemplateQuery,
} = agenticSecurityApi;
