import { baseApi, clearAuthStorage } from "./baseApi";

export interface LegalAcceptanceFields {
	accepted_terms_version?: string;
	accepted_privacy_version?: string;
}

export interface LoginRequest extends LegalAcceptanceFields {
	email?: string;
	username?: string;
	password: string;
	// 6-digit TOTP supplied on the second step of an MFA-enabled login.
	mfa_code?: string;
}

export interface AuthMessageResponse {
	message: string;
	email?: string;
	requires_email_verification?: boolean;
	// true when the credentials were valid but a TOTP code is still required.
	mfa_required?: boolean;
}

export interface SignupRequest extends LegalAcceptanceFields {
	first_name: string;
	last_name: string;
	organization: string;
	industry: string;
	email: string;
	password: string;
	invitation_token?: string;
}

export interface GoogleLoginRequest extends LegalAcceptanceFields {
	credential: string;
	organization?: string;
}

export interface VerifyEmailRequest {
	token: string;
}

export interface ResendVerificationRequest {
	email: string;
}

export interface CurrentUser {
	id: string;
	tenant_id: string;
	customer_id?: string | null;
	role: string;
	first_name: string;
	last_name: string;
	full_name: string;
	organization: string;
	industry: string;
	email: string;
	pending_email: string | null;
	is_email_verified: boolean;
	email_verified_at: string | null;
	pending_email_requested_at: string | null;
	last_verification_sent_at: string | null;
	last_login_at: string | null;
	auth_provider: string;
	has_password: boolean;
	google_linked: boolean;
	// True when this user is the owner_user_id of their governance_org -
	// i.e. the founder who created the tenant. Used to gate SSO/SCIM
	// admin UI: only the founder configures identity federation;
	// regular admins added via User Manager (or JIT-provisioned via
	// SSO itself) do NOT see the SSO settings even if their role is
	// `admin`. Set by the backend in serializeCurrentUser.
	is_tenant_owner?: boolean;
	// Org identity (governance_orgs) - the billing/identity anchor above the
	// tenant. org_id is an opaque UUID (never the user's email); shown
	// read-only in account settings. is_org_owner is the org-level OWNER
	// membership ("super admin"), used to gate the "Make super admin"
	// action in the User Manager.
	org_id?: string;
	org_name?: string;
	is_org_owner?: boolean;
	// Native TOTP MFA status for the signed-in user (drives the account
	// settings toggle + the login challenge).
	mfa_enabled?: boolean;
	theme_preference?: "light" | "dark" | "system" | null;
	created_at: string;
	updated_at: string;
}

export interface CurrentUserResponse {
	user: CurrentUser | null;
}

export interface SignupInvitation {
	email: string;
	role: string;
	// organization = the parent org (super-user's org) name - fills the
	// Organization field. tenant_name = the tenant the invite is TO - shown
	// in the "Invited to {tenant}" banner.
	organization: string;
	tenant_name?: string;
	expires_at: string;
}

export interface SignupInvitationResponse {
	invitation: SignupInvitation;
}

export interface UpdateCurrentUserProfileRequest {
	first_name: string;
	last_name: string;
	organization: string;
	industry: string;
	// Optional. Omit to leave the existing preference untouched; pass
	// "" to clear it.
	theme_preference?: "light" | "dark" | "system" | "" | null;
}

export interface UpdateCurrentUserEmailRequest {
	email: string;
}

export interface Organization {
	id: string;
	name: string;
	slug: string;
	description?: string;
	owner_id: string;
	plan: string;
	created_at: string;
	updated_at: string;
}

export interface OrganizationResponse {
	organization: Organization;
}

export interface UpdateOrganizationRequest {
	name?: string;
	slug?: string;
}

export interface IsAuthEnabledResponse {
	is_auth_enabled: boolean;
	has_valid_token: boolean;
	has_users: boolean;
	requires_email_verification: boolean;
	google_auth_enabled: boolean;
	google_client_id: string;
}

export interface LogoutResponse {
	message: string;
}

export const sessionApi = baseApi.injectEndpoints({
	overrideExisting: false,
	endpoints: (builder) => ({
		// Check if auth is enabled
		isAuthEnabled: builder.query<IsAuthEnabledResponse, void>({
			query: () => ({
				url: "/session/is-auth-enabled",
				method: "GET",
			}),
		}),
		getSignupInvitation: builder.query<SignupInvitationResponse, string>({
			query: (token) => ({
				url: "/session/invitation",
				method: "GET",
				params: { token },
			}),
		}),
		signup: builder.mutation<AuthMessageResponse, SignupRequest>({
			query: (body) => ({
				url: "/session/signup",
				method: "POST",
				body,
			}),
		}),
		// Login endpoint
		login: builder.mutation<AuthMessageResponse, LoginRequest>({
			query: (credentials) => ({
				url: "/session/login",
				method: "POST",
				body: credentials,
			}),
			invalidatesTags: [],
		}),
		googleLogin: builder.mutation<AuthMessageResponse, GoogleLoginRequest>({
			query: (body) => ({
				url: "/session/google",
				method: "POST",
				body,
			}),
		}),
		verifyEmail: builder.mutation<AuthMessageResponse, VerifyEmailRequest>({
			query: (body) => ({
				url: "/session/verify-email",
				method: "POST",
				body,
			}),
		}),
		resendVerification: builder.mutation<AuthMessageResponse, ResendVerificationRequest>({
			query: (body) => ({
				url: "/session/resend-verification",
				method: "POST",
				body,
			}),
		}),
		getCurrentUser: builder.query<CurrentUserResponse, void>({
			query: () => ({
				url: "/session/me",
				method: "GET",
			}),
			providesTags: ["User"],
		}),
		// bootstrap returns user + organizations + tenants + workspaces in
		// a single round-trip - used by the dashboard's first-paint
		// effect to populate the active scope without firing 3-4
		// individual queries on cold load. The shape is intentionally
		// loose so the response can pre-fill the per-resource RTK
		// query caches via `util.upsertQueryData` in the consumer.
		getSessionBootstrap: builder.query<{
			user: CurrentUser;
			organizations: Array<{ id: string; name: string; plan: string; role?: string }>;
			tenants: unknown[];
			workspaces: unknown[];
		}, void>({
			query: () => ({
				url: "/session/bootstrap",
				method: "GET",
			}),
			providesTags: ["User", "Organizations", "Workspaces"],
		}),
		updateCurrentUser: builder.mutation<AuthMessageResponse & CurrentUserResponse, UpdateCurrentUserProfileRequest>({
			query: (body) => ({
				url: "/session/me",
				method: "PUT",
				body,
			}),
			invalidatesTags: ["User"],
		}),
		updateCurrentUserEmail: builder.mutation<AuthMessageResponse & CurrentUserResponse, UpdateCurrentUserEmailRequest>({
			query: (body) => ({
				url: "/session/me/email",
				method: "POST",
				body,
			}),
			invalidatesTags: ["User"],
		}),
		resendCurrentUserVerification: builder.mutation<AuthMessageResponse & CurrentUserResponse, void>({
			query: () => ({
				url: "/session/me/resend-verification",
				method: "POST",
			}),
			invalidatesTags: ["User"],
		}),

		// ── Native TOTP MFA ───────────────────────────────────────────────
		mfaSetup: builder.mutation<{ secret: string; otpauth_uri: string }, void>({
			query: () => ({ url: "/session/mfa/setup", method: "POST" }),
		}),
		mfaEnable: builder.mutation<{ message: string; mfa_enabled: boolean; recovery_codes?: string[] }, { code: string }>({
			query: (body) => ({ url: "/session/mfa/enable", method: "POST", body }),
			invalidatesTags: ["User"],
		}),
		mfaDisable: builder.mutation<{ message: string; mfa_enabled: boolean }, { code: string }>({
			query: (body) => ({ url: "/session/mfa/disable", method: "POST", body }),
			invalidatesTags: ["User"],
		}),
		mfaRegenerateRecoveryCodes: builder.mutation<{ message: string; recovery_codes: string[] }, { code: string }>({
			query: (body) => ({ url: "/session/mfa/recovery-codes", method: "POST", body }),
		}),

		// Organization endpoints
		getCurrentOrganization: builder.query<OrganizationResponse, void>({
			query: () => ({
				url: "/organization",
				method: "GET",
			}),
			providesTags: ["Organization"],
		}),
		updateOrganization: builder.mutation<{ message: string } & OrganizationResponse, UpdateOrganizationRequest>({
			query: (body) => ({
				url: "/organization",
				method: "PUT",
				body,
			}),
			invalidatesTags: ["Organization"],
		}),

		// Logout endpoint
		logout: builder.mutation<LogoutResponse, void>({
			query: () => ({
				url: "/session/logout",
				method: "POST",
			}),
			// After logout: wipe persisted localStorage, dispatch the
			// `dis:auth-clear` notify (clearAuthStorage handles both),
			// then reset RTK Query's in-memory state so re-login can't
			// briefly render with the previous user's bootstrap. Without
			// `resetApiState`, the new user's first /session/me query
			// returns the old user's cached row for ~one render frame
			// before the refetch lands, and the dashboard mounts with
			// the wrong tenant in scope - which then 403s on the next
			// scoped query and bounces back to /login (the loop the
			// user reported).
			async onQueryStarted(arg, { queryFulfilled, dispatch }) {
				try {
					await queryFulfilled;
				} catch (error) {
					// Ignore server-side logout failures - still clear the
					// client so the user can re-auth from a clean slate.
				} finally {
					clearAuthStorage();
					dispatch(baseApi.util.resetApiState());
				}
			},
			invalidatesTags: ["Config", "Providers", "Logs", "VirtualKeys", "Teams", "Customers", "Budgets", "RateLimits", "Organization"],
		}),
	}),
});

export const {
	useGetCurrentUserQuery,
	useGetSessionBootstrapQuery,
	useGetCurrentOrganizationQuery,
	useGoogleLoginMutation,
	useIsAuthEnabledQuery,
	useGetSignupInvitationQuery,
	useLoginMutation,
	useLogoutMutation,
	useResendVerificationMutation,
	useResendCurrentUserVerificationMutation,
	useMfaSetupMutation,
	useMfaEnableMutation,
	useMfaDisableMutation,
	useMfaRegenerateRecoveryCodesMutation,
	useSignupMutation,
	useUpdateCurrentUserEmailMutation,
	useUpdateCurrentUserMutation,
	useUpdateOrganizationMutation,
	useVerifyEmailMutation,
} = sessionApi;
