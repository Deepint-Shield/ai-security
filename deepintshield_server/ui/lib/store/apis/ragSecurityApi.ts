import {
	RAGSecurityEvidenceBundle,
	RAGSecurityFinding,
	RAGSecurityPolicy,
	RAGSecuritySettings,
	RAGSecuritySimulationRequest,
	RAGSecuritySimulationResult,
	RAGSecuritySource,
	RAGSecuritySummary,
	RAGSecurityTrace,
} from "@/lib/types/ragSecurity";
import { baseApi } from "./baseApi";

function arrayOrEmpty<T>(value?: T[] | null): T[] {
	return Array.isArray(value) ? value : [];
}

function normalizeRAGSecuritySummary(summary: RAGSecuritySummary): RAGSecuritySummary {
	return {
		...summary,
		control_coverage: arrayOrEmpty(summary.control_coverage),
	};
}

function normalizeRAGSecuritySource(source: RAGSecuritySource): RAGSecuritySource {
	return {
		...source,
		acl_tags: arrayOrEmpty(source.acl_tags),
		labels: arrayOrEmpty(source.labels),
	};
}

function normalizeRAGSecurityFinding(finding: RAGSecurityFinding): RAGSecurityFinding {
	return {
		...finding,
		pii_flags: arrayOrEmpty(finding.pii_flags),
	};
}

function normalizeRAGSecurityTrace(trace: RAGSecurityTrace): RAGSecurityTrace {
	return {
		...trace,
		policy_hits: arrayOrEmpty(trace.policy_hits),
		retrieved_chunks: arrayOrEmpty(trace.retrieved_chunks).map((chunk) => ({
			...chunk,
			pii_flags: arrayOrEmpty(chunk.pii_flags),
		})),
		rejected_chunks: arrayOrEmpty(trace.rejected_chunks).map((chunk) => ({
			...chunk,
			pii_flags: arrayOrEmpty(chunk.pii_flags),
		})),
		citations: arrayOrEmpty(trace.citations),
	};
}

function normalizeRAGSecuritySimulationResult(result: RAGSecuritySimulationResult): RAGSecuritySimulationResult {
	return {
		...result,
		trace: normalizeRAGSecurityTrace(result.trace),
		findings: arrayOrEmpty(result.findings).map(normalizeRAGSecurityFinding),
	};
}

function normalizeRAGSecurityEvidence(bundle: RAGSecurityEvidenceBundle): RAGSecurityEvidenceBundle {
	return {
		...bundle,
		summary: normalizeRAGSecuritySummary(bundle.summary),
		sources: arrayOrEmpty(bundle.sources).map(normalizeRAGSecuritySource),
		policies: arrayOrEmpty(bundle.policies),
		findings: arrayOrEmpty(bundle.findings).map(normalizeRAGSecurityFinding),
		traces: arrayOrEmpty(bundle.traces).map(normalizeRAGSecurityTrace),
	};
}

export const ragSecurityApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		getRAGSecuritySummary: builder.query<RAGSecuritySummary, void>({
			query: () => "/rag-security/summary",
			transformResponse: (response: { summary: RAGSecuritySummary }) => normalizeRAGSecuritySummary(response.summary),
			providesTags: ["RAGSecurity"],
		}),
		getRAGSecuritySettings: builder.query<RAGSecuritySettings, void>({
			query: () => "/rag-security/settings",
			transformResponse: (response: { settings: RAGSecuritySettings }) => response.settings,
			providesTags: ["RAGSecurity"],
		}),
		updateRAGSecuritySettings: builder.mutation<RAGSecuritySettings, RAGSecuritySettings>({
			query: (settings) => ({
				url: "/rag-security/settings",
				method: "PUT",
				body: settings,
			}),
			transformResponse: (response: { settings: RAGSecuritySettings }) => response.settings,
			invalidatesTags: ["RAGSecurity"],
		}),
		getRAGSecuritySources: builder.query<RAGSecuritySource[], void>({
			query: () => "/rag-security/sources",
			transformResponse: (response: { sources: RAGSecuritySource[] | null }) => arrayOrEmpty(response.sources).map(normalizeRAGSecuritySource),
			providesTags: ["RAGSources"],
		}),
		createRAGSecuritySource: builder.mutation<RAGSecuritySource, Partial<RAGSecuritySource>>({
			query: (source) => ({
				url: "/rag-security/sources",
				method: "POST",
				body: source,
			}),
			transformResponse: (response: { source: RAGSecuritySource }) => normalizeRAGSecuritySource(response.source),
			invalidatesTags: ["RAGSources", "RAGSecurity"],
		}),
		updateRAGSecuritySource: builder.mutation<RAGSecuritySource, RAGSecuritySource>({
			query: (source) => ({
				url: `/rag-security/sources/${encodeURIComponent(source.id)}`,
				method: "PUT",
				body: source,
			}),
			transformResponse: (response: { source: RAGSecuritySource }) => normalizeRAGSecuritySource(response.source),
			invalidatesTags: ["RAGSources", "RAGSecurity"],
		}),
		quarantineRAGSecuritySource: builder.mutation<RAGSecuritySource, { id: string; reason?: string }>({
			query: ({ id, reason }) => ({
				url: `/rag-security/sources/${encodeURIComponent(id)}/quarantine`,
				method: "POST",
				body: { reason },
			}),
			transformResponse: (response: { source: RAGSecuritySource }) => normalizeRAGSecuritySource(response.source),
			invalidatesTags: ["RAGSources", "RAGFindings", "RAGSecurity"],
		}),
		releaseRAGSecuritySource: builder.mutation<RAGSecuritySource, { id: string; reason?: string }>({
			query: ({ id, reason }) => ({
				url: `/rag-security/sources/${encodeURIComponent(id)}/release`,
				method: "POST",
				body: { reason },
			}),
			transformResponse: (response: { source: RAGSecuritySource }) => normalizeRAGSecuritySource(response.source),
			invalidatesTags: ["RAGSources", "RAGSecurity"],
		}),
		getRAGSecurityPolicies: builder.query<RAGSecurityPolicy[], void>({
			query: () => "/rag-security/policies",
			transformResponse: (response: { policies: RAGSecurityPolicy[] }) => response.policies,
			providesTags: ["RAGPolicies"],
		}),
		createRAGSecurityPolicy: builder.mutation<RAGSecurityPolicy, Partial<RAGSecurityPolicy>>({
			query: (policy) => ({
				url: "/rag-security/policies",
				method: "POST",
				body: policy,
			}),
			transformResponse: (response: { policy: RAGSecurityPolicy }) => response.policy,
			invalidatesTags: ["RAGPolicies", "RAGSecurity"],
		}),
		updateRAGSecurityPolicy: builder.mutation<RAGSecurityPolicy, RAGSecurityPolicy>({
			query: (policy) => ({
				url: `/rag-security/policies/${encodeURIComponent(policy.id)}`,
				method: "PUT",
				body: policy,
			}),
			transformResponse: (response: { policy: RAGSecurityPolicy }) => response.policy,
			invalidatesTags: ["RAGPolicies", "RAGSecurity"],
		}),
		getRAGSecurityFindings: builder.query<RAGSecurityFinding[], void>({
			query: () => "/rag-security/findings",
			transformResponse: (response: { findings: RAGSecurityFinding[] | null }) => arrayOrEmpty(response.findings).map(normalizeRAGSecurityFinding),
			providesTags: ["RAGFindings"],
		}),
		getRAGSecurityTraces: builder.query<RAGSecurityTrace[], void>({
			query: () => "/rag-security/traces",
			transformResponse: (response: { traces: RAGSecurityTrace[] | null }) => arrayOrEmpty(response.traces).map(normalizeRAGSecurityTrace),
			providesTags: ["RAGTraces"],
		}),
		runRAGSecuritySimulation: builder.mutation<RAGSecuritySimulationResult, RAGSecuritySimulationRequest>({
			query: (request) => ({
				url: "/rag-security/simulations",
				method: "POST",
				body: request,
			}),
			transformResponse: (response: { result: RAGSecuritySimulationResult }) => normalizeRAGSecuritySimulationResult(response.result),
			invalidatesTags: ["RAGFindings", "RAGTraces", "RAGSecurity", "RAGSources"],
		}),
		exportRAGSecurityEvidence: builder.query<RAGSecurityEvidenceBundle, void>({
			query: () => "/rag-security/evidence",
			transformResponse: (response: { bundle: RAGSecurityEvidenceBundle }) => normalizeRAGSecurityEvidence(response.bundle),
			providesTags: ["RAGEvidence"],
		}),
	}),
});

export const {
	useCreateRAGSecurityPolicyMutation,
	useCreateRAGSecuritySourceMutation,
	useExportRAGSecurityEvidenceQuery,
	useGetRAGSecurityFindingsQuery,
	useGetRAGSecurityPoliciesQuery,
	useGetRAGSecuritySettingsQuery,
	useGetRAGSecuritySourcesQuery,
	useGetRAGSecuritySummaryQuery,
	useGetRAGSecurityTracesQuery,
	useLazyExportRAGSecurityEvidenceQuery,
	useQuarantineRAGSecuritySourceMutation,
	useReleaseRAGSecuritySourceMutation,
	useRunRAGSecuritySimulationMutation,
	useUpdateRAGSecurityPolicyMutation,
	useUpdateRAGSecuritySettingsMutation,
	useUpdateRAGSecuritySourceMutation,
} = ragSecurityApi;
