import { baseApi } from "./baseApi";

// A feature update an org can opt into. `applied` means the org explicitly
// enabled it (entitlement override); `enabled` means it is currently active for
// the org (via the override or the plan default).
export interface FeatureUpdate {
	id: string;
	feature_key: string;
	version: string;
	title: string;
	description?: string;
	published_at?: string | null;
	applied: boolean;
	enabled: boolean;
}

export interface UpdatesResponse {
	updates: FeatureUpdate[];
	// Platform/SDK build version (e.g. "1.4.13"), shown in the sidebar footer.
	current_version?: string;
	// Number of in-scope releases the org has not yet applied (drives the
	// "Update available" indicator).
	available_count?: number;
}

export interface ApplyUpdateResponse {
	ok: boolean;
	id: string;
	feature_key: string;
	applied: boolean;
}

export const updatesApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		// Releases marked available by a super-admin and in-scope for this org.
		getUpdates: builder.query<UpdatesResponse, void>({
			query: () => ({ url: "/updates", method: "GET" }),
			providesTags: ["Billing"],
		}),
		// Owner-only. Flips the release's feature ON for this org (entitlement
		// override) - takes effect immediately, so we invalidate billing +
		// org-scoped caches to refresh any feature-gated surfaces.
		applyUpdate: builder.mutation<ApplyUpdateResponse, string>({
			query: (id) => ({ url: `/updates/${id}/apply`, method: "POST" }),
			invalidatesTags: ["Billing", "Organization"],
		}),
		// Owner-only. Reverses an applied update (entitlement override OFF).
		rollbackUpdate: builder.mutation<ApplyUpdateResponse, string>({
			query: (id) => ({ url: `/updates/${id}/rollback`, method: "POST" }),
			invalidatesTags: ["Billing", "Organization"],
		}),
	}),
});

export const { useGetUpdatesQuery, useApplyUpdateMutation, useRollbackUpdateMutation } = updatesApi;
