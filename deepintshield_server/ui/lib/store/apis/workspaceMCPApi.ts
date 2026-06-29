import { baseApi } from "./baseApi";

// WorkspaceMCPSettings mirrors the DTO returned by /api/workspace-mcp.
// is_override distinguishes a stored per-workspace row from tenant
// defaults - the UI flips an "Override active" / "Inheriting defaults"
// badge based on this.
export interface WorkspaceMCPSettings {
	workspace_id: string;
	agent_depth: number;
	tool_execution_timeout_sec: number;
	tool_sync_interval_minutes: number;
	code_mode_binding_level: string;
	cache_enabled: boolean;
	cache_ttl_seconds: number;
	is_override: boolean;
}

// Endpoints are workspace-scoped server-side via X-Active-Workspace-Id (set
// by baseApi.prepareHeaders), so the URL doesn't carry the ID.
export const workspaceMCPApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		getWorkspaceMCP: builder.query<WorkspaceMCPSettings, void>({
			query: () => ({ url: "/workspace-mcp", method: "GET" }),
			providesTags: ["Config"],
		}),
		updateWorkspaceMCP: builder.mutation<WorkspaceMCPSettings, WorkspaceMCPSettings>({
			query: (body) => ({ url: "/workspace-mcp", method: "PUT", body }),
			invalidatesTags: ["Config"],
		}),
		resetWorkspaceMCP: builder.mutation<{ status: string; workspace_id: string }, void>({
			query: () => ({ url: "/workspace-mcp", method: "DELETE" }),
			invalidatesTags: ["Config"],
		}),
	}),
});

export const {
	useGetWorkspaceMCPQuery,
	useUpdateWorkspaceMCPMutation,
	useResetWorkspaceMCPMutation,
} = workspaceMCPApi;
