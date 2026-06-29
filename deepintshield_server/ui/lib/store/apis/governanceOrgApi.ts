import type { Organization } from "./sessionApi";
import { baseApi } from "./baseApi";

export interface Workspace {
	id: string;
	org_id: string;
	name: string;
	slug: string;
	description?: string;
	is_default: boolean;
	created_by?: string;
	created_at: string;
	updated_at: string;
}

export interface OrgMember {
	user_id: string;
	org_id: string;
	role: "owner" | "admin" | "member";
	created_at: string;
	email?: string;
	first_name?: string;
	last_name?: string;
}

export interface WorkspaceMember {
	user_id: string;
	workspace_id: string;
	org_id: string;
	role: "admin" | "member" | "viewer";
	created_at: string;
	email?: string;
	first_name?: string;
	last_name?: string;
}

export type OrganizationWithRole = Organization & { role?: OrgMember["role"] };

export interface CreateOrganizationRequest {
	name: string;
	slug: string;
	description?: string;
	owner_id?: string;
}

export interface UpdateTenantRequest {
	id: string;
	name?: string;
	slug?: string;
	description?: string;
}
export interface CreateWorkspaceRequest {
	orgId: string;
	name: string;
	slug?: string;
	description?: string;
}
export interface UpdateWorkspaceRequest {
	id: string;
	name?: string;
	slug?: string;
	description?: string;
}
export interface AddMemberRequest {
	email?: string;
	user_id?: string;
	role: string;
}

export interface WorkspaceAPIKey {
	id: string;
	workspace_id: string;
	org_id: string;
	type: "service_account" | "user";
	name: string;
	key_prefix: string;
	user_id?: string | null;
	created_by: string;
	expires_at?: string | null;
	last_used_at?: string | null;
	revoked_at?: string | null;
	created_at: string;
}

export interface CreateWorkspaceAPIKeyRequest {
	workspaceId: string;
	name: string;
	type: "service_account" | "user";
	user_id?: string;
	expires_at?: string;
}

export interface CreateWorkspaceAPIKeyResponse {
	api_key: WorkspaceAPIKey;
	plaintext: string;
	warning: string;
}

export const governanceOrgApi = baseApi.injectEndpoints({
	endpoints: (builder) => ({
		// ─── Organisations ────────────────────────────────────────────────
		listOrganizations: builder.query<{ organizations: Organization[] }, void>({
			query: () => ({ url: "/organizations", method: "GET" }),
			providesTags: ["Organizations"],
		}),
		listMyOrganizations: builder.query<{ organizations: OrganizationWithRole[] }, void>({
			query: () => ({ url: "/organizations/me", method: "GET" }),
			providesTags: ["Organizations"],
		}),
		createOrganization: builder.mutation<{ organization: Organization; workspace: Workspace }, CreateOrganizationRequest>({
			query: (body) => ({ url: "/organizations", method: "POST", body }),
			invalidatesTags: ["Organizations", "Organization", "Workspaces"],
		}),

		// ─── Governance org (top tier of org → tenant → workspace) ─────────
		// Lists the governance_orgs the caller has membership in. Used by
		// the Tenants page to know which parent org_id to attach a new
		// tenant to. Distinct from listMyOrganizations: that returns
		// *tenants* (the second tier); this returns *governance_orgs*
		// (the top tier).
		listMyGovernanceOrgs: builder.query<{ organizations: { id: string; name: string; slug?: string; plan?: string; created_at?: string }[] }, void>({
			query: () => ({ url: "/orgs/me", method: "GET" }),
			providesTags: ["Organizations"],
		}),
		// Creates a tenant under a governance_org the caller has owner/admin
		// membership in. Replaces the previous use of POST /organizations
		// (which is now superadmin-only and was the source of the
		// "Only superadmins can create organizations directly" 403 you saw).
		createTenantInOrg: builder.mutation<{ tenant: { id: string; name: string; slug: string; created_at: string } }, { orgId: string; name: string; slug?: string; description?: string }>({
			query: ({ orgId, ...body }) => ({
				url: `/orgs/${orgId}/tenants`,
				method: "POST",
				body,
			}),
			invalidatesTags: ["Organizations", "Workspaces"],
		}),
		// Governance-org (top-tier "super admin") membership - DISTINCT from
		// the tenant-level /organizations/.../members endpoints below. Powers
		// the "Make super admin" action in the User Manager: it grants the
		// org-level OWNER role, keyed on the org + user UUIDs (never email).
		listGovernanceOrgMembers: builder.query<{ members: { user_id: string; role: "owner" | "admin" | "member" }[] }, string>({
			query: (orgId) => ({ url: `/orgs/${orgId}/members`, method: "GET" }),
			providesTags: (_r, _e, orgId) => [{ type: "OrgMembers", id: `gov-${orgId}` }],
		}),
		setGovernanceOrgMemberRole: builder.mutation<{ message: string; user_id: string; role: string }, { orgId: string; userId: string; role: "owner" | "admin" | "member" }>({
			query: ({ orgId, userId, role }) => ({
				url: `/orgs/${orgId}/members/${userId}/role`,
				method: "POST",
				body: { role },
			}),
			invalidatesTags: (_r, _e, { orgId }) => [{ type: "OrgMembers", id: `gov-${orgId}` }],
		}),
		deleteOrganization: builder.mutation<{ deleted: string }, string>({
			query: (id) => ({ url: `/organizations/${id}`, method: "DELETE" }),
			invalidatesTags: ["Organizations", "Workspaces"],
		}),
		updateTenant: builder.mutation<{ organization: Organization }, UpdateTenantRequest>({
			query: ({ id, ...body }) => ({ url: `/organizations/${id}`, method: "PUT", body }),
			invalidatesTags: ["Organizations"],
		}),

		// ─── Workspaces ───────────────────────────────────────────────────
		listMyWorkspaces: builder.query<{ workspaces: Workspace[] }, void>({
			query: () => ({ url: "/workspaces/me", method: "GET" }),
			providesTags: ["Workspaces"],
		}),
		listWorkspacesByOrg: builder.query<{ workspaces: Workspace[] }, string>({
			query: (orgId) => ({ url: `/organizations/${orgId}/workspaces`, method: "GET" }),
			providesTags: (_r, _e, orgId) => [{ type: "Workspaces", id: orgId }, "Workspaces"],
		}),
		getWorkspace: builder.query<{ workspace: Workspace }, string>({
			query: (id) => ({ url: `/workspaces/${id}`, method: "GET" }),
			providesTags: (_r, _e, id) => [{ type: "Workspaces", id }],
		}),
		createWorkspace: builder.mutation<{ workspace: Workspace }, CreateWorkspaceRequest>({
			query: ({ orgId, ...body }) => ({
				url: `/organizations/${orgId}/workspaces`,
				method: "POST",
				body,
			}),
			invalidatesTags: ["Workspaces"],
		}),
		updateWorkspace: builder.mutation<{ workspace: Workspace }, UpdateWorkspaceRequest>({
			query: ({ id, ...body }) => ({ url: `/workspaces/${id}`, method: "PUT", body }),
			invalidatesTags: (_r, _e, { id }) => [{ type: "Workspaces", id }, "Workspaces"],
		}),
		deleteWorkspace: builder.mutation<{ deleted: string }, { id: string; confirmSlug: string }>({
			query: ({ id, confirmSlug }) => ({
				url: `/workspaces/${id}?confirm_slug=${encodeURIComponent(confirmSlug)}`,
				method: "DELETE",
			}),
			invalidatesTags: ["Workspaces"],
		}),

		// ─── Members ──────────────────────────────────────────────────────
		listOrgMembers: builder.query<{ members: OrgMember[] }, string>({
			query: (orgId) => ({ url: `/organizations/${orgId}/members`, method: "GET" }),
			providesTags: (_r, _e, orgId) => [{ type: "OrgMembers", id: orgId }],
		}),
		addOrgMember: builder.mutation<{ membership: OrgMember }, { orgId: string } & AddMemberRequest>({
			query: ({ orgId, ...body }) => ({
				url: `/organizations/${orgId}/members`,
				method: "POST",
				body,
			}),
			invalidatesTags: (_r, _e, { orgId }) => [{ type: "OrgMembers", id: orgId }],
		}),
		updateOrgMemberRole: builder.mutation<{ updated: boolean; role: string }, { orgId: string; userId: string; role: string }>({
			query: ({ orgId, userId, role }) => ({
				url: `/organizations/${orgId}/members/${userId}`,
				method: "PUT",
				body: { role },
			}),
			invalidatesTags: (_r, _e, { orgId }) => [{ type: "OrgMembers", id: orgId }],
		}),
		removeOrgMember: builder.mutation<{ deleted: boolean }, { orgId: string; userId: string }>({
			query: ({ orgId, userId }) => ({
				url: `/organizations/${orgId}/members/${userId}`,
				method: "DELETE",
			}),
			invalidatesTags: (_r, _e, { orgId }) => [{ type: "OrgMembers", id: orgId }],
		}),

		listWorkspaceMembers: builder.query<{ members: WorkspaceMember[] }, string>({
			query: (workspaceId) => ({ url: `/workspaces/${workspaceId}/members`, method: "GET" }),
			providesTags: (_r, _e, workspaceId) => [{ type: "WorkspaceMembers", id: workspaceId }],
		}),
		addWorkspaceMember: builder.mutation<{ membership: WorkspaceMember }, { workspaceId: string } & AddMemberRequest>({
			query: ({ workspaceId, ...body }) => ({
				url: `/workspaces/${workspaceId}/members`,
				method: "POST",
				body,
			}),
			invalidatesTags: (_r, _e, { workspaceId }) => [{ type: "WorkspaceMembers", id: workspaceId }],
		}),
		updateWorkspaceMemberRole: builder.mutation<{ updated: boolean; role: string }, { workspaceId: string; userId: string; role: string }>({
			query: ({ workspaceId, userId, role }) => ({
				url: `/workspaces/${workspaceId}/members/${userId}`,
				method: "PUT",
				body: { role },
			}),
			invalidatesTags: (_r, _e, { workspaceId }) => [{ type: "WorkspaceMembers", id: workspaceId }],
		}),
		removeWorkspaceMember: builder.mutation<{ deleted: boolean }, { workspaceId: string; userId: string }>({
			query: ({ workspaceId, userId }) => ({
				url: `/workspaces/${workspaceId}/members/${userId}`,
				method: "DELETE",
			}),
			invalidatesTags: (_r, _e, { workspaceId }) => [{ type: "WorkspaceMembers", id: workspaceId }],
		}),

		// ─── Workspace API keys ───────────────────────────────────────────
		listWorkspaceAPIKeys: builder.query<{ api_keys: WorkspaceAPIKey[] }, string>({
			query: (workspaceId) => ({ url: `/workspaces/${workspaceId}/api-keys`, method: "GET" }),
			providesTags: (_r, _e, workspaceId) => [{ type: "WorkspaceAPIKeys", id: workspaceId }],
		}),
		createWorkspaceAPIKey: builder.mutation<CreateWorkspaceAPIKeyResponse, CreateWorkspaceAPIKeyRequest>({
			query: ({ workspaceId, ...body }) => ({
				url: `/workspaces/${workspaceId}/api-keys`,
				method: "POST",
				body,
			}),
			invalidatesTags: (_r, _e, { workspaceId }) => [{ type: "WorkspaceAPIKeys", id: workspaceId }],
		}),
		revokeWorkspaceAPIKey: builder.mutation<{ revoked: string }, { workspaceId: string; keyId: string }>({
			query: ({ workspaceId, keyId }) => ({
				url: `/workspaces/${workspaceId}/api-keys/${keyId}`,
				method: "DELETE",
			}),
			invalidatesTags: (_r, _e, { workspaceId }) => [{ type: "WorkspaceAPIKeys", id: workspaceId }],
		}),
	}),
});

export const {
	useListOrganizationsQuery,
	useListMyOrganizationsQuery,
	useListMyGovernanceOrgsQuery,
	useListGovernanceOrgMembersQuery,
	useSetGovernanceOrgMemberRoleMutation,
	useCreateOrganizationMutation,
	useCreateTenantInOrgMutation,
	useDeleteOrganizationMutation,
	useUpdateTenantMutation,
	useListMyWorkspacesQuery,
	useListWorkspacesByOrgQuery,
	useGetWorkspaceQuery,
	useCreateWorkspaceMutation,
	useUpdateWorkspaceMutation,
	useDeleteWorkspaceMutation,
	useListOrgMembersQuery,
	useAddOrgMemberMutation,
	useUpdateOrgMemberRoleMutation,
	useRemoveOrgMemberMutation,
	useListWorkspaceMembersQuery,
	useAddWorkspaceMemberMutation,
	useUpdateWorkspaceMemberRoleMutation,
	useRemoveWorkspaceMemberMutation,
	useListWorkspaceAPIKeysQuery,
	useCreateWorkspaceAPIKeyMutation,
	useRevokeWorkspaceAPIKeyMutation,
} = governanceOrgApi;
