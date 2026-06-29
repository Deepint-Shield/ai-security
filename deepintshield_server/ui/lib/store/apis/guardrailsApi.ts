import type {
	GuardrailDomainPack,
	GuardrailFinding,
	GuardrailMCPToolPolicy,
	GuardrailMCPToolPolicyPayload,
	GuardrailPolicy,
	GuardrailPolicyPayload,
	GuardrailPolicyVersion,
	GuardrailPolicyVersionPayload,
	GuardrailProvider,
	GuardrailProviderPayload,
	GuardrailProviderTestResult,
	GuardrailSimulationPayload,
	GuardrailSimulationResult,
	GuardrailMetricsStats,
	GuardrailTrace,
} from "@/lib/types/guardrails";
import type { LatencyHistogramResponse } from "@/lib/types/logs";
import { baseApi } from "./baseApi";

export const guardrailsApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		getGuardrailProviders: builder.query<GuardrailProvider[], void>({
			query: () => "/guardrails/providers",
			transformResponse: (response: { providers: GuardrailProvider[] }) => response.providers,
			providesTags: ["GuardrailProviders"],
		}),
		createGuardrailProvider: builder.mutation<GuardrailProvider, GuardrailProviderPayload>({
			query: (body) => ({
				url: "/guardrails/providers",
				method: "POST",
				body,
			}),
			invalidatesTags: ["GuardrailProviders"],
		}),
		updateGuardrailProvider: builder.mutation<GuardrailProvider, { id: string; data: GuardrailProviderPayload }>({
			query: ({ id, data }) => ({
				url: `/guardrails/providers/${encodeURIComponent(id)}`,
				method: "PUT",
				body: data,
			}),
			invalidatesTags: ["GuardrailProviders"],
		}),
		deleteGuardrailProvider: builder.mutation<{ message: string }, string>({
			query: (id) => ({
				url: `/guardrails/providers/${encodeURIComponent(id)}`,
				method: "DELETE",
			}),
			invalidatesTags: ["GuardrailProviders"],
		}),
		testGuardrailProvider: builder.mutation<GuardrailProviderTestResult, string>({
			query: (id) => ({
				url: `/guardrails/providers/${encodeURIComponent(id)}/test`,
				method: "POST",
			}),
			invalidatesTags: ["GuardrailProviders"],
		}),
		getGuardrailPolicies: builder.query<GuardrailPolicy[], void>({
			query: () => "/guardrails/policies",
			transformResponse: (response: { policies: GuardrailPolicy[] }) => response.policies,
			providesTags: ["GuardrailPolicies"],
		}),
		getGuardrailPolicyById: builder.query<GuardrailPolicy, string>({
			query: (id) => `/guardrails/policies/${encodeURIComponent(id)}`,
			providesTags: (result, error, id) => [{ type: "GuardrailPolicies", id }],
		}),
		createGuardrailPolicy: builder.mutation<GuardrailPolicy, GuardrailPolicyPayload>({
			query: (body) => ({
				url: "/guardrails/policies",
				method: "POST",
				body,
			}),
			invalidatesTags: ["GuardrailPolicies", "GuardrailVersions"],
		}),
		updateGuardrailPolicy: builder.mutation<GuardrailPolicy, { id: string; data: GuardrailPolicyPayload }>({
			query: ({ id, data }) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}`,
				method: "PUT",
				body: data,
			}),
			invalidatesTags: (result, error, { id }) => ["GuardrailPolicies", "GuardrailVersions", "GuardrailMCPToolPolicies", { type: "GuardrailPolicies", id }],
		}),
		getGuardrailMCPToolPolicies: builder.query<GuardrailMCPToolPolicy[], string>({
			query: (id) => `/guardrails/policies/${encodeURIComponent(id)}/mcp-tool-policies`,
			transformResponse: (response: { tool_policies: GuardrailMCPToolPolicy[] }) => response.tool_policies,
			providesTags: (result, error, id) => ["GuardrailMCPToolPolicies", { type: "GuardrailPolicies", id }],
		}),
		replaceGuardrailMCPToolPolicies: builder.mutation<GuardrailMCPToolPolicy[], { id: string; tool_policies: GuardrailMCPToolPolicyPayload[] }>({
			query: ({ id, tool_policies }) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}/mcp-tool-policies`,
				method: "PUT",
				body: { tool_policies },
			}),
			transformResponse: (response: { tool_policies: GuardrailMCPToolPolicy[] }) => response.tool_policies,
			invalidatesTags: (result, error, { id }) => ["GuardrailPolicies", "GuardrailMCPToolPolicies", "GuardrailTraces", "GuardrailFindings", { type: "GuardrailPolicies", id }],
		}),
		setGuardrailPolicyAsDefault: builder.mutation<GuardrailPolicy, string>({
			query: (id) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}/default`,
				method: "POST",
			}),
			invalidatesTags: (result, error, id) => ["GuardrailPolicies", { type: "GuardrailPolicies", id }],
		}),
		deleteGuardrailPolicy: builder.mutation<{ message: string }, string>({
			query: (id) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}`,
				method: "DELETE",
			}),
			invalidatesTags: ["GuardrailPolicies", "GuardrailVersions"],
		}),
		getGuardrailPolicyVersions: builder.query<GuardrailPolicyVersion[], string>({
			query: (id) => `/guardrails/policies/${encodeURIComponent(id)}/versions`,
			transformResponse: (response: { versions: GuardrailPolicyVersion[] }) => response.versions,
			providesTags: (result, error, id) => [{ type: "GuardrailVersions", id }],
		}),
		createGuardrailPolicyVersion: builder.mutation<GuardrailPolicyVersion, { id: string; data: GuardrailPolicyVersionPayload }>({
			query: ({ id, data }) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}/versions`,
				method: "POST",
				body: data,
			}),
			invalidatesTags: (result, error, { id }) => ["GuardrailPolicies", "GuardrailVersions", { type: "GuardrailVersions", id }],
		}),
		publishGuardrailPolicyVersion: builder.mutation<GuardrailPolicy, { id: string; version_id: string; published_by?: string }>({
			query: ({ id, ...body }) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}/publish`,
				method: "POST",
				body,
			}),
			invalidatesTags: (result, error, { id }) => ["GuardrailPolicies", "GuardrailVersions", { type: "GuardrailPolicies", id }, { type: "GuardrailVersions", id }],
		}),
		rollbackGuardrailPolicyVersion: builder.mutation<GuardrailPolicy, { id: string; version_id: string; published_by?: string }>({
			query: ({ id, ...body }) => ({
				url: `/guardrails/policies/${encodeURIComponent(id)}/rollback`,
				method: "POST",
				body,
			}),
			invalidatesTags: (result, error, { id }) => ["GuardrailPolicies", "GuardrailVersions", { type: "GuardrailPolicies", id }, { type: "GuardrailVersions", id }],
		}),
		getGuardrailDomainPacks: builder.query<GuardrailDomainPack[], void>({
			query: () => "/guardrails/domain-packs",
			transformResponse: (response: { domain_packs: GuardrailDomainPack[] }) => response.domain_packs,
			providesTags: ["GuardrailDomainPacks"],
		}),
		getGuardrailFindings: builder.query<GuardrailFinding[], Record<string, string | number | undefined> | void>({
			query: (params) => ({
				url: "/guardrails/findings",
				params,
			}),
			transformResponse: (response: { findings: GuardrailFinding[] }) => response.findings,
			providesTags: ["GuardrailFindings"],
		}),
		getGuardrailTraces: builder.query<GuardrailTrace[], Record<string, string | number | undefined> | void>({
			query: (params) => ({
				url: "/guardrails/traces",
				params,
			}),
			transformResponse: (response: { traces: GuardrailTrace[] }) => response.traces,
			providesTags: ["GuardrailTraces"],
		}),
		getGuardrailLatencyHistogram: builder.query<LatencyHistogramResponse, Record<string, string | number | undefined> | void>({
			query: (params) => ({
				url: "/guardrails/latency",
				params,
			}),
			providesTags: ["GuardrailTraces", "GuardrailFindings"],
		}),
		// Server-aggregated headline metrics (true counts + distributions over
		// the full window) - replaces the 5,000-row client window for the KPI
		// tiles + Overview charts so counts aren't capped and the dominant
		// `action` stage isn't truncated out.
		getGuardrailMetricsStats: builder.query<GuardrailMetricsStats, Record<string, string | number | undefined> | void>({
			query: (params) => ({
				url: "/guardrails/metrics-stats",
				params,
			}),
			providesTags: ["GuardrailTraces", "GuardrailFindings"],
		}),
		runGuardrailSimulation: builder.mutation<GuardrailSimulationResult, GuardrailSimulationPayload>({
			query: (body) => ({
				url: "/guardrails/simulations",
				method: "POST",
				body,
			}),
			invalidatesTags: ["GuardrailFindings", "GuardrailTraces"],
		}),
	}),
});

export const {
	useCreateGuardrailPolicyMutation,
	useCreateGuardrailPolicyVersionMutation,
	useCreateGuardrailProviderMutation,
	useDeleteGuardrailPolicyMutation,
	useDeleteGuardrailProviderMutation,
	useGetGuardrailDomainPacksQuery,
	useGetGuardrailFindingsQuery,
	useGetGuardrailLatencyHistogramQuery,
	useGetGuardrailMetricsStatsQuery,
	useGetGuardrailMCPToolPoliciesQuery,
	useGetGuardrailPoliciesQuery,
	useGetGuardrailPolicyByIdQuery,
	useGetGuardrailPolicyVersionsQuery,
	useGetGuardrailProvidersQuery,
	useGetGuardrailTracesQuery,
	useLazyGetGuardrailLatencyHistogramQuery,
	usePublishGuardrailPolicyVersionMutation,
	useReplaceGuardrailMCPToolPoliciesMutation,
	useRollbackGuardrailPolicyVersionMutation,
	useRunGuardrailSimulationMutation,
	useSetGuardrailPolicyAsDefaultMutation,
	useTestGuardrailProviderMutation,
	useUpdateGuardrailPolicyMutation,
	useUpdateGuardrailProviderMutation,
} = guardrailsApi;
