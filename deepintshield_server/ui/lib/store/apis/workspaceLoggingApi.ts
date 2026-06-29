import { baseApi } from "./baseApi";

// WorkspaceLoggingSettings mirrors the DTO returned by /api/workspace-logging.
// is_override distinguishes a stored per-workspace row from the inherited
// tenant defaults - the UI shows a different badge in each case.
export interface WorkspaceLoggingSettings {
	workspace_id: string;
	enable_logging: boolean;
	disable_content_logging: boolean;
	log_retention_days: number;
	hide_deleted_virtual_keys_in_filters: boolean;
	logging_headers: string[];
	is_override: boolean;
}

// The active workspace is injected via the baseApi's X-Active-Workspace-Id
// header - every call below scopes server-side to that workspace, so the
// endpoint URL itself doesn't need to carry the ID.
export const workspaceLoggingApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		getWorkspaceLogging: builder.query<WorkspaceLoggingSettings, void>({
			query: () => ({ url: "/workspace-logging", method: "GET" }),
			providesTags: ["Config"],
		}),
		updateWorkspaceLogging: builder.mutation<WorkspaceLoggingSettings, WorkspaceLoggingSettings>({
			query: (body) => ({ url: "/workspace-logging", method: "PUT", body }),
			invalidatesTags: ["Config"],
		}),
		// Removes the override row so the workspace falls back to tenant
		// defaults. The next GET returns is_override=false with the inherited
		// values pre-filled.
		resetWorkspaceLogging: builder.mutation<{ status: string; workspace_id: string }, void>({
			query: () => ({ url: "/workspace-logging", method: "DELETE" }),
			invalidatesTags: ["Config"],
		}),
	}),
});

export const {
	useGetWorkspaceLoggingQuery,
	useUpdateWorkspaceLoggingMutation,
	useResetWorkspaceLoggingMutation,
} = workspaceLoggingApi;
