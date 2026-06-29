"use client";

import { useGetCurrentUserQuery, useIsAuthEnabledQuery } from "@/lib/store/apis";
import { createContext, useContext, useMemo } from "react";

// RBAC Resource Names (must match backend definitions)
export enum RbacResource {
	GuardrailsConfig = "GuardrailsConfig",
	GuardrailsProviders = "GuardrailsProviders",
	GuardrailRules = "GuardrailRules",
	UserProvisioning = "UserProvisioning",
	Cluster = "Cluster",
	Settings = "Settings",
	Users = "Users",
	Logs = "Logs",
	Observability = "Observability",
	VirtualKeys = "VirtualKeys",
	ModelProvider = "ModelProvider",
	Plugins = "Plugins",
	MCPGateway = "MCPGateway",
	AdaptiveRouter = "AdaptiveRouter",
	AuditLogs = "AuditLogs",
	Customers = "Customers",
	Teams = "Teams",
	RBAC = "RBAC",
	Governance = "Governance",
	// Organizations management is admin-only at the system level - viewer is
	// denied.
	Organizations = "Organizations",
	// Workspaces is admin-only at the system level (org-membership-level
	// admin/owner is enforced in the backend handlers).
	Workspaces = "Workspaces",
	RoutingRules = "RoutingRules",
	PIIRedactor = "PIIRedactor",
	PromptRepository = "PromptRepository",
	PromptDeploymentStrategy = "PromptDeploymentStrategy",
	// Agentic Security - PEP/PDP control plane (policies, virtual keys,
	// identity providers, approvals, rollout). Mutating endpoints require
	// admin role (system / tenant); viewers see read-only state.
	AgenticSecurity = "AgenticSecurity",
	// Agentic Observability - Langfuse-backed traces, observations, scores,
	// and the per-workspace observability settings.
	AgenticObservability = "AgenticObservability",
}

// RBAC Operation Names (must match backend definitions)
export enum RbacOperation {
	Read = "Read",
	View = "View",
	Create = "Create",
	Update = "Update",
	Delete = "Delete",
	Download = "Download",
}

interface RbacContextType {
	isAllowed: (resource: RbacResource, operation: RbacOperation) => boolean;
	permissions: Record<string, Record<string, boolean>>;
	isLoading: boolean;
	refetch: () => void;
}

const RbacContext = createContext<RbacContextType | null>(null);

const viewerPermissions = new Set<string>([
	`${RbacResource.Logs}:${RbacOperation.View}`,
	`${RbacResource.Logs}:${RbacOperation.Read}`,
	`${RbacResource.Observability}:${RbacOperation.View}`,
	`${RbacResource.Observability}:${RbacOperation.Read}`,
	// Agentic Security + Observability are visible to viewers but the
	// backend handlers still gate writes on admin role.
	`${RbacResource.AgenticSecurity}:${RbacOperation.View}`,
	`${RbacResource.AgenticSecurity}:${RbacOperation.Read}`,
	`${RbacResource.AgenticObservability}:${RbacOperation.View}`,
	`${RbacResource.AgenticObservability}:${RbacOperation.Read}`,
]);

function isRoleAllowed(role: string | undefined, resource: RbacResource, operation: RbacOperation): boolean {
	// System roles in this codebase are normalised to "admin" or "viewer" by
	// NormalizeAuthUserRole on the gateway - anything else collapses to
	// admin. So the only branches that matter here are admin (full access)
	// and viewer (constrained to viewerPermissions for general resources;
	// always denied on Organizations / Workspaces management).
	if (!role || role === "admin") {
		return true;
	}
	if (role === "viewer") {
		// Workspace/org management is never viewer-accessible regardless of
		// the general viewer allowlist.
		if (resource === RbacResource.Organizations || resource === RbacResource.Workspaces) {
			return false;
		}
		return viewerPermissions.has(`${resource}:${operation}`);
	}
	return false;
}

export function RbacProvider({ children }: { children: React.ReactNode }) {
	const { data: authStatus, isLoading: isLoadingAuthStatus } = useIsAuthEnabledQuery();
	const { data, isLoading: isLoadingUser, refetch } = useGetCurrentUserQuery(undefined, {
		skip: !authStatus?.is_auth_enabled,
	});
	const currentUser = data?.user ?? null;
	const isLoading = isLoadingAuthStatus || (authStatus?.is_auth_enabled ? isLoadingUser : false);

	const value = useMemo<RbacContextType>(
		() => ({
			isAllowed: (resource, operation) => {
				if (isLoading || !currentUser) {
					return true;
				}
				return isRoleAllowed(currentUser.role, resource, operation);
			},
			permissions: {},
			isLoading,
			refetch,
		}),
		[currentUser, isLoading, refetch],
	);

	return <RbacContext.Provider value={value}>{children}</RbacContext.Provider>;
}

export function useRbac(resource: RbacResource, operation: RbacOperation): boolean {
	const context = useRbacContext();
	return context.isAllowed(resource, operation);
}

export function useRbacContext() {
	const context = useContext(RbacContext);
	if (!context) {
		return {
			isAllowed: () => true,
			permissions: {},
			isLoading: false,
			refetch: () => {},
		};
	}
	return context;
}
