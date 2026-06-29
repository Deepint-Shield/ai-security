import { IS_ENTERPRISE } from "@/lib/constants/config";
import { DeepIntShieldErrorResponse } from "@/lib/types/config";
import { getApiBaseUrl } from "@/lib/utils/port";
import { createBaseQueryWithRefresh } from "@enterprise/lib/store/utils/baseQueryWithRefresh";
import { clearOAuthStorage } from "@enterprise/lib/store/utils/tokenManager";
import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

// Auth tokens are now stored in HTTP-only cookies (set by server)
// No client-side token needed - handled by credentials: "include"
export const getTokenFromStorage = (): Promise<string | null> => {
	return Promise.resolve(null);
};

// Helper function to set auth token
// Non-enterprise: no-op - auth relies on HTTPOnly cookies set by the server
// Enterprise: handled separately via tokenManager
export const setAuthToken = (_token: string | null) => {
	// Non-enterprise auth is cookie-based; no client-side token storage needed.
	// Enterprise token management is handled by the tokenManager module.
};

// Helper function to clear all auth-related storage
//
// On logout this MUST wipe every layer that could re-hydrate the previous
// user's identity into the new login. The layers, in order from outer-most
// to inner-most:
//
//   1. `deepintshield-auth-token`  - legacy localStorage bearer (kept for
//      back-compat; the live auth is HTTPOnly cookie-based and is cleared
//      by the /api/session/logout endpoint itself).
//   2. `dis-rtk-cache-v1`  - the cross-session RTK Query persistence blob
//      I added when shipping the "zero-latency rendering" layer. Without
//      wiping this, a fresh login boots the app from the PREVIOUS user's
//      cached /session/me / workspaces / org responses, the next 401
//      retry kicks in via the baseQuery error path, and the user is
//      bounced back to /login (the "log me out on login" loop the user
//      just reported).
//   3. `sessionStorage` per-session flags (onboarding-shown).
//   4. Enterprise OAuth tokens (Azure / Okta refresh tokens stored
//      separately by the tokenManager).
//   5. Dispatch the `dis:auth-clear` CustomEvent so any listener inside
//      the React tree (the Redux Provider's persistence subscriber)
//      also drops its in-memory state.
//
// `dis_active_scope:<userId>` entries are STILL kept on purpose: each
// user's last tenant + workspace pick is per-user-namespaced and
// validated by `hydrateActiveScope` on next login; a stale entry for
// THIS user is desired UX (it remembers where they were). The pre-fix
// loop wasn't caused by these entries; it was caused by the new RTK
// persistence layer not being wiped.
export const clearAuthStorage = () => {
	if (typeof window === "undefined") {
		return;
	}
	try {
		// (1) Legacy bearer
		localStorage.removeItem("deepintshield-auth-token");

		// (2) RTK Query cross-session persistence (the recent addition).
		// Drop the snapshot blob directly here in case the Provider's
		// event listener isn't mounted yet (e.g. mid-route-transition
		// logout).
		try {
			localStorage.removeItem("dis-rtk-cache-v1");
		} catch {
			// Quota or disabled storage - non-fatal.
		}

		// (3) sessionStorage flags
		try {
			sessionStorage.removeItem("deepintshield-onboarding-shown-session");
		} catch {
			// sessionStorage may be unavailable in private mode; non-fatal.
		}

		// (4) Enterprise OAuth tokens
		if (IS_ENTERPRISE) {
			clearOAuthStorage();
		}

		// (5) Notify the in-React listeners (the Redux provider's
		// auth-clear handler subscribes to this event to drop its
		// debounced-snapshot timer + wipe any in-memory state it holds).
		// CustomEvent isn't available in some test environments; guard.
		try {
			window.dispatchEvent(new CustomEvent("dis:auth-clear"));
		} catch {
			// Best-effort - listeners are an optimisation, not required.
		}
	} catch (error) {
		console.error("Error clearing auth storage:", error);
	}
};

// Define the base query with authentication headers
const baseQuery = fetchBaseQuery({
	baseUrl: getApiBaseUrl(),
	credentials: "include",
	prepareHeaders: async (headers, { getState }) => {
		headers.set("Content-Type", "application/json");
		// Automatically include token from localStorage in Authorization header
		const token = await getTokenFromStorage();
		if (token) {
			headers.set("Authorization", `Bearer ${token}`);
		}
		// Propagate the sidebar's active tenant + workspace selection to
		// every backend call so handlers that opt into workspace-aware
		// filtering can scope their responses without each page wiring it
		// through query params explicitly.
		const state = getState() as { activeScope?: { activeOrgId?: string | null; activeWorkspaceId?: string | null } };
		const scope = state?.activeScope;
		if (scope?.activeOrgId) {
			headers.set("X-Active-Tenant-Id", scope.activeOrgId);
		}
		if (scope?.activeWorkspaceId) {
			headers.set("X-Active-Workspace-Id", scope.activeWorkspaceId);
		}
		return headers;
	},
});

// Wrap base query with enterprise refresh logic (or passthrough for non-enterprise)
const baseQueryWithRefresh = createBaseQueryWithRefresh(baseQuery);

// Enhanced base query with error handling
const baseQueryWithErrorHandling: typeof baseQueryWithRefresh = async (args: any, api: any, extraOptions: any) => {
	// First apply refresh logic (enterprise-specific, handles 401)
	const result = await baseQueryWithRefresh(args, api, extraOptions);

	// Then handle other error types
	if (result.error) {
		const error = result.error as any;

		// OSS build: there is no /login route. A stray 401 is returned to the
		// caller and handled locally instead of redirecting to a nonexistent
		// /login page (which previously caused a dashboard <-> /login loop).

		// Concurrent-deletion safety net: if the active tenant or workspace
		// is referenced in the request URL and we get a 404 / 410, the
		// server-side row was likely deleted by another admin. Trigger a
		// re-hydration of the active scope so the switcher drops the dead
		// ID and we fall back to the user's home tenant + default workspace.
		if (
			(error?.status === 404 || error?.status === 410) &&
			typeof args === "object" &&
			args !== null &&
			typeof args.url === "string"
		) {
			const url: string = args.url;
			if (url.includes("/workspaces/") || url.includes("/organizations/")) {
				try {
					if (typeof window !== "undefined") {
						window.dispatchEvent(new CustomEvent("dis:active-scope-stale"));
					}
				} catch {
					// non-fatal - the next page render will catch the stale
					// scope via the switcher's normal validation.
				}
			}
		}

		// Handle specific error types
		if (error?.status === "FETCH_ERROR") {
			// Network error
			return {
				...result,
				error: {
					...error,
					data: {
						error: {
							message: "Network error: Unable to connect to the server",
						},
					},
				},
			};
		}

		// Handle other errors with proper DeepIntShieldErrorResponse format
		if (error?.data) {
			const errorData = error.data as DeepIntShieldErrorResponse;
			if (errorData.error?.message) {
				return result;
			}
		}

		// Fallback error message
		return {
			...result,
			error: {
				...error,
				data: {
					error: {
						message: "An unexpected error occurred",
					},
				},
			},
		};
	}

	return result;
};

// Create the base API
//
// Cache strategy - "zero latency for graphs / settings / parameters":
//   * keepUnusedDataFor: 600  → cached data survives 10 min after the last
//     subscriber unmounts. Reopening a dashboard tab inside that window
//     renders from cache *synchronously* - no spinner, no waterfall.
//   * refetchOnMountOrArgChange: false  → mounting a hook that already has
//     cached data shows it INSTANTLY. The default behaviour was to
//     re-fetch on mount even with a warm cache, causing a brief loading
//     flash every time the user navigated.
//   * refetchOnFocus + refetchOnReconnect: true  → data stays fresh by
//     refreshing in the BACKGROUND whenever the user tabs back in or
//     the network reconnects. The UI keeps rendering the old data
//     during the refetch (RTK Query exposes `isFetching=true` separately
//     from `isLoading`), so the perceived experience is instant.
//
// Per-endpoint overrides still win: a slow histogram can still bump its
// own keepUnusedDataFor to 30 min; a live polling chart can set
// pollingInterval. The defaults just remove the "every tab change reloads
// from scratch" footgun globally.
export const baseApi = createApi({
	reducerPath: "api",
	baseQuery: baseQueryWithErrorHandling,
	keepUnusedDataFor: 600,
	refetchOnMountOrArgChange: false,
	refetchOnFocus: true,
	refetchOnReconnect: true,
	tagTypes: [
		"Logs",
		"MCPLogs",
		"Providers",
		"MCPClients",
		"Config",
		"CacheConfig",
		"VirtualKeys",
		"Teams",
		"Customers",
		"Budgets",
		"RateLimits",
		"DebugStats",
		"HealthCheck",
		"DBKeys",
		"Models",
		"BaseModels",
		"ModelConfigs",
		"ProviderGovernance",
		"Plugins",
		"SCIMProviders",
		"User",
		"Guardrails",
		"GuardrailProviders",
		"GuardrailPolicies",
		"GuardrailMCPToolPolicies",
		"GuardrailVersions",
		"GuardrailDomainPacks",
		"GuardrailFindings",
		"GuardrailTraces",
		"GuardrailApprovals",
		"ClusterNodes",
		"Users",
		"GuardrailRules",
		"Roles",
		"Resources",
		"Operations",
		"Permissions",
		"APIKeys",
		"OAuth2Config",
		"RoutingRules",
		"MCPToolGroups",
		"AuditLogs",
		"UserGovernance",
		"LargePayloadConfig",
		"Folders",
		"Prompts",
		"Versions",
		"Sessions",
		"RAGSecurity",
		"RAGSources",
		"RAGPolicies",
		"RAGFindings",
		"RAGApprovals",
		"RAGTraces",
		"RAGEvidence",
		"Organization",
		"Organizations",
		"Workspaces",
		"OrgMembers",
		"WorkspaceMembers",
		"WorkspaceAPIKeys",
		"Billing",
	],
	endpoints: () => ({}),
});

// sanitizeErrorMessage strips raw database / driver internals from strings
// before they hit a user-facing toast. The server normally translates these
// via friendlyError (handlers/errors_friendly.go), so this is a last-resort
// safety net for any handler that hasn't been updated yet - we'd rather
// show a generic "couldn't complete this operation" than a SQLSTATE dump
// like `ERROR: duplicate key value violates unique constraint
// "idx_organizations_slug" (SQLSTATE 23505)`.
const sanitizeErrorMessage = (raw: string): string => {
	const lower = raw.toLowerCase();
	if (lower.includes("duplicate key") || lower.includes("unique constraint")) {
		return "This name or value is already in use. Try a different one.";
	}
	if (lower.includes("foreign key constraint")) {
		return "This item is referenced by other records. Remove or reassign them first.";
	}
	if (lower.includes("value too long")) {
		return "One of the values you entered is too long. Shorten it and try again.";
	}
	if (lower.includes("sqlstate") || lower.includes("pg: ") || lower.includes("pgerror")) {
		return "Something went wrong. Please retry; if the issue persists, contact support.";
	}
	return raw;
};

// Helper function to extract error message from RTK Query error
export const getErrorMessage = (error: unknown): string => {
	if (error === undefined || error === null) {
		return "An unexpected error occurred";
	}
	if (error instanceof Error) {
		return sanitizeErrorMessage(error.message);
	}
	if (
		typeof error === "object" &&
		error &&
		"data" in error &&
		error.data &&
		typeof error.data === "object" &&
		"error" in error.data &&
		error.data.error &&
		typeof error.data.error === "object" &&
		"message" in error.data.error &&
		typeof error.data.error.message === "string"
	) {
		const msg = sanitizeErrorMessage(error.data.error.message);
		return msg.charAt(0).toUpperCase() + msg.slice(1);
	}
	if (typeof error === "object" && error && "message" in error && typeof error.message === "string") {
		return sanitizeErrorMessage(error.message);
	}
	return "An unexpected error occurred";
};
