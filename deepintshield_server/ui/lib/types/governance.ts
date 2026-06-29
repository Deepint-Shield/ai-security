// Governance types that match the Go backend structures

import { ModelProviderName } from "./config";

export interface Budget {
	id: string;
	max_limit: number; // In dollars
	reset_duration: string; // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
	current_usage: number; // In dollars
	last_reset: string; // ISO timestamp
}

export interface RateLimit {
	id: string;
	// Flexible token limits
	token_max_limit?: number; // Maximum tokens allowed
	token_reset_duration?: string; // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
	token_current_usage: number; // Current token usage
	token_last_reset: string; // ISO timestamp
	// Flexible request limits
	request_max_limit?: number; // Maximum requests allowed
	request_reset_duration?: string; // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
	request_current_usage: number; // Current request usage
	request_last_reset: string; // ISO timestamp
}

export interface Team {
	id: string;
	name: string;
	customer_id?: string;
	// workspace_id narrows the team to a single workspace within the
	// tenant. null/undefined = tenant-wide (visible in every workspace).
	workspace_id?: string | null;
	budget_id?: string;
	rate_limit_id?: string;
	members?: GovernanceTeamMember[];
	member_customers?: Customer[];
	// Agent tool entitlements - narrows what any VK owned by this team
	// can invoke via the PEP. Empty = no team-level cap.
	allowed_tools?: string[];
	// Populated relationships
	customer?: Customer;
	budget?: Budget;
	rate_limit?: RateLimit;
}

export interface Customer {
	id: string;
	name: string;
	// workspace_id narrows the customer to a single workspace within
	// the tenant. null/undefined = tenant-wide.
	workspace_id?: string | null;
	budget_id?: string;
	rate_limit_id?: string;
	// Per-member tool entitlements override - narrower than the Team
	// default when set. Empty = inherit from Team or VK.
	allowed_tools?: string[];
	// Populated relationships
	teams?: Team[];
	budget?: Budget;
	rate_limit?: RateLimit;
}

export type GovernanceUserRole = "admin" | "viewer";
export type GovernanceUserStatus = "active" | "pending";

export interface GovernanceTeamMember {
	id: string;
	role: GovernanceUserRole;
	first_name: string;
	last_name: string;
	email: string;
	last_login_at?: string | null;
	is_email_verified: boolean;
	created_at?: string;
	updated_at?: string;
}

export interface GovernanceProvisionedUser {
	id: string;
	user_id?: string | null;
	invitation_id?: string | null;
	customer_id?: string | null;
	full_name: string;
	email: string;
	role: GovernanceUserRole;
	status: GovernanceUserStatus;
	is_owner: boolean;
	last_login_at?: string | null;
	created_at: string;
	updated_at: string;
	workspace_count: number;
}

export interface GetGovernanceUsersParams {
	limit?: number;
	offset?: number;
	search?: string;
	customer_id?: string;
}

export interface GetGovernanceUsersResponse {
	users: GovernanceProvisionedUser[];
	count: number;
	total_count: number;
	limit: number;
	offset: number;
}

export interface InviteGovernanceUserRequest {
	email: string;
	role: GovernanceUserRole;
}

export interface InviteGovernanceUserResponse {
	message: string;
	user: GovernanceProvisionedUser;
}

export interface UpdateGovernanceUserRoleRequest {
	role: GovernanceUserRole;
}

export interface UpdateGovernanceUserRoleResponse {
	message: string;
	user: GovernanceProvisionedUser;
}

export interface GovernanceActionResponse {
	message: string;
}

export interface DBKey {
	key_id: string; // UUID identifier for the key
	name: string; // Name of the key
	provider_id: string; // identifier for the provider
	models: string[]; // List of models this key can access
	provider: ModelProviderName; // Provider name
}

export type VirtualKeyCacheScopeMode = "inherit" | "virtual_key" | "user" | "use_case" | "session" | "custom_metadata" | "none";

export interface RedactedDBKey {
	id: string;
	name: string;
	models: string[];
	weight: number;
}

// VirtualKeyFallbackEntry is one step in the VK's failover chain - the
// gateway tries entries in order when the primary call fails (5xx / 429
// / timeout). Configured workspace-side so callers don't have to send a
// `fallbacks: […]` array on every request.
export interface VirtualKeyFallbackEntry {
	provider: string;
	model: string;
}

export interface VirtualKey {
	id: string;
	name: string;
	value: string; // The actual key value
	description?: string;
	fallback_chain?: VirtualKeyFallbackEntry[];
	provider_configs?: VirtualKeyProviderConfig[];
	mcp_configs?: VirtualKeyMCPConfig[];
	guardrail_policies?: VirtualKeyGuardrailPolicy[];
	cache_key?: string;
	cache_enabled?: boolean;
	semantic_cache_enabled?: boolean;
	cache_scope_mode?: VirtualKeyCacheScopeMode;
	cache_metadata_scope_keys?: string[];
	cache_allow_semantic_when_unscoped?: boolean;
	team_id?: string;
	customer_id?: string;
	workspace_id?: string | null;
	budget_id?: string;
	rate_limit_id?: string;
	is_active: boolean;
	// Key rotation
	rotation_period_days?: number | null;
	rotation_grace_period_days?: number;
	last_rotated_at?: string | null;
	next_rotation_at?: string | null;
	previous_value_expires_at?: string | null;
	// ─── Agentic / unified-VK additions ───────────────────────────────
	// When `bound_identity_provider` is set, this VK is also an agent
	// scope profile - the PEP reads `allowed_tools`, `autonomy_budget`,
	// `default_obligations` directly from the row and the standalone
	// agentic VK table is bypassed. NULL = LLM-only key (no agent
	// behaviour, no PEP firing).
	bound_identity_provider?: string | null;
	identity_provider_id?: string | null;
	allowed_tools?: string[] | null;
	autonomy_budget?: "low" | "medium" | "high" | null;
	default_obligations?: string[] | null;
	tool_rate_limit_per_minute?: number | null;
	agent_scopes?: string[] | null;
	// Agent attribute taxonomy (ABAC operands). Policies match on these so a
	// new agent with matching attributes is governed by existing policies.
	agent_risk_level?: "low" | "medium" | "high" | "critical" | null;
	agent_capabilities?: string[] | null;
	agent_namespace?: string | null;
	created_at: string;
	updated_at: string;
	// Populated relationships
	team?: Team;
	customer?: Customer;
	budget?: Budget;
	rate_limit?: RateLimit;
	config_hash?: string; // Present when config is synced from config.json
}

export interface RotateVirtualKeyRequest {
	rotation_period_days?: number | null;
	rotation_grace_period_days?: number;
}

export interface VirtualKeyGuardrailPolicy {
	id: string;
	name: string;
	is_default?: boolean;
	scope?: string;
}

export type KeySelectionStrategy = "weighted_random" | "round_robin" | "least_load";

export interface VirtualKeyProviderConfig {
	id?: number;
	provider: string;
	weight: number;
	allowed_models: string[];
	key_selection_strategy?: KeySelectionStrategy;
	budget?: Budget;
	rate_limit?: RateLimit;
	keys?: DBKey[]; // Associated database keys for this provider
}

export interface VirtualKeyMCPConfig {
	id?: number;
	virtual_key_id?: string;
	mcp_client_id?: number;
	mcp_client?: {
		id: number;
		name: string;
		connection_type: string;
		connection_string?: string;
		tools_to_execute: string[];
		created_at: string;
		updated_at: string;
	};
	tools_to_execute?: string[];
}

// Request interfaces for create/update operations (still use mcp_client_name)
export interface VirtualKeyMCPConfigRequest {
	id?: number;
	mcp_client_name: string;
	tools_to_execute?: string[];
}

// Request interfaces for provider config operations
export interface VirtualKeyProviderConfigRequest {
	provider: string;
	weight?: number;
	allowed_models?: string[];
	key_selection_strategy?: KeySelectionStrategy;
	budget?: CreateBudgetRequest;
	rate_limit?: CreateRateLimitRequest;
	key_ids?: string[]; // List of DBKey UUIDs to associate with this provider config
}

export interface VirtualKeyProviderConfigUpdateRequest {
	id?: number;
	provider: string;
	weight?: number;
	allowed_models?: string[];
	key_selection_strategy?: KeySelectionStrategy;
	budget?: UpdateBudgetRequest;
	rate_limit?: UpdateRateLimitRequest;
	key_ids?: string[]; // List of DBKey UUIDs to associate with this provider config
}

// Request types for API calls
export interface CreateVirtualKeyRequest {
	name: string;
	description?: string;
	guardrail_policy_ids?: string[];
	cache_key?: string;
	cache_enabled?: boolean;
	semantic_cache_enabled?: boolean;
	cache_scope_mode?: VirtualKeyCacheScopeMode;
	cache_metadata_scope_keys?: string[];
	cache_allow_semantic_when_unscoped?: boolean;
	fallback_chain?: VirtualKeyFallbackEntry[];
	provider_configs?: VirtualKeyProviderConfigRequest[];
	mcp_configs?: VirtualKeyMCPConfigRequest[];
	team_id?: string;
	customer_id?: string;
	// Empty / omitted = org-wide; set to a workspace ID to scope this VK
	// to a specific workspace. The active-workspace state in the UI
	// pre-fills this on create so the most common case ("create a key
	// for the workspace I'm currently looking at") needs no extra click.
	workspace_id?: string;
	budget?: CreateBudgetRequest;
	rate_limit?: CreateRateLimitRequest;
	is_active?: boolean;
	// Rotation schedule. 0 / omitted = manual rotation only. Setting a
	// positive period at create time stamps next_rotation_at so the
	// background worker picks the row up on its scheduled cadence.
	rotation_period_days?: number | null;
	rotation_grace_period_days?: number;
	// ─── Agent Scope (unified-VK) - all optional ─────────────────────
	// Set bound_identity_provider to make the VK PEP-gated. Leaving it
	// empty (the default) keeps the key LLM-only.
	bound_identity_provider?: string;
	identity_provider_id?: string;
	allowed_tools?: string[];
	autonomy_budget?: "low" | "medium" | "high";
	default_obligations?: string[];
	tool_rate_limit_per_minute?: number;
	agent_scopes?: string[];
	// Pass "" to clear a previously-set tier; omit to leave unchanged.
	agent_risk_level?: "low" | "medium" | "high" | "critical" | "";
	agent_capabilities?: string[];
	agent_namespace?: string;
}

export interface UpdateVirtualKeyRequest {
	name?: string;
	description?: string;
	guardrail_policy_ids?: string[];
	cache_key?: string;
	cache_enabled?: boolean;
	semantic_cache_enabled?: boolean;
	cache_scope_mode?: VirtualKeyCacheScopeMode;
	cache_metadata_scope_keys?: string[];
	cache_allow_semantic_when_unscoped?: boolean;
	// `null` clears the chain; `undefined` (field omitted) leaves the
	// stored chain unchanged.
	fallback_chain?: VirtualKeyFallbackEntry[] | null;
	provider_configs?: VirtualKeyProviderConfigUpdateRequest[];
	mcp_configs?: VirtualKeyMCPConfigRequest[];
	team_id?: string;
	customer_id?: string;
	// Pass `""` (empty string) to clear the workspace scope back to org-
	// wide; pass a workspace ID to (re)scope. Omit to leave unchanged.
	workspace_id?: string;
	budget?: UpdateBudgetRequest;
	rate_limit?: UpdateRateLimitRequest;
	is_active?: boolean;
	// Agent Scope (unified-VK) - same shape as the create request. To
	// clear an agent binding pass empty string / empty arrays.
	bound_identity_provider?: string;
	identity_provider_id?: string;
	allowed_tools?: string[];
	autonomy_budget?: "low" | "medium" | "high";
	default_obligations?: string[];
	tool_rate_limit_per_minute?: number;
	agent_scopes?: string[];
	// Pass "" to clear a previously-set tier; omit to leave unchanged.
	agent_risk_level?: "low" | "medium" | "high" | "critical" | "";
	agent_capabilities?: string[];
	agent_namespace?: string;
}

// Bulk agent-attribute apply across a multi-select of VKs or every agent-bound
// VK in the active workspace. Exactly one selection mode must be supplied.
export interface BulkAgentAttributesRequest {
	workspace_id?: string;
	apply_to_all_in_workspace?: boolean;
	virtual_key_ids?: string[];
	only_agent_bound?: boolean;
	agent_risk_level?: "low" | "medium" | "high" | "critical" | "";
	agent_capabilities?: string[];
}

export interface CreateTeamRequest {
	name: string;
	customer_id?: string;
	member_user_ids?: string[];
	member_customer_ids?: string[];
	budget?: CreateBudgetRequest;
	rate_limit?: CreateRateLimitRequest;
	// Agent tool entitlements for VKs owned by this team.
	allowed_tools?: string[];
	// True → server stores workspace_id as NULL (visible in every
	// workspace under the tenant). Omit/false → server stamps the
	// active workspace from X-Active-Workspace-Id, scoping the team
	// to the current workspace only.
	apply_to_all_workspaces?: boolean;
}

export interface UpdateTeamRequest {
	name?: string;
	customer_id?: string;
	member_user_ids?: string[];
	member_customer_ids?: string[];
	budget?: UpdateBudgetRequest;
	rate_limit?: UpdateRateLimitRequest;
	allowed_tools?: string[];
}

export interface CreateCustomerRequest {
	name: string;
	budget?: CreateBudgetRequest;
	rate_limit?: CreateRateLimitRequest;
	// Per-member tool entitlements override.
	allowed_tools?: string[];
	// True → server stores workspace_id as NULL (visible in every
	// workspace under the tenant). Omit/false → server stamps the
	// active workspace from X-Active-Workspace-Id, scoping the
	// member to the current workspace only.
	apply_to_all_workspaces?: boolean;
}

export interface UpdateCustomerRequest {
	name?: string;
	budget?: UpdateBudgetRequest;
	rate_limit?: UpdateRateLimitRequest;
	allowed_tools?: string[];
}

export interface CreateBudgetRequest {
	max_limit: number; // In dollars
	reset_duration: string; // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
}

export interface UpdateBudgetRequest {
	max_limit?: number;
	reset_duration?: string;
}

export interface CreateRateLimitRequest {
	token_max_limit?: number; // Maximum tokens allowed
	token_reset_duration?: string; // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
	request_max_limit?: number; // Maximum requests allowed
	request_reset_duration?: string; // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
}

export interface UpdateRateLimitRequest {
	token_max_limit?: number | null; // Maximum tokens allowed (null to clear)
	token_reset_duration?: string | null; // e.g., "30s", "5m", "1h", "1d", "1w", "1M" (null to clear)
	request_max_limit?: number | null; // Maximum requests allowed (null to clear)
	request_reset_duration?: string | null; // e.g., "30s", "5m", "1h", "1d", "1w", "1M" (null to clear)
}

// Query params
export interface GetVirtualKeysParams {
	limit?: number;
	offset?: number;
	search?: string;
	customer_id?: string;
	team_id?: string;
	// workspace_id, when set, narrows to workspace-scoped + org-wide
	// (workspace_id IS NULL) virtual keys. Empty string returns the legacy
	// unfiltered listing.
	workspace_id?: string;
}

// Response types
export interface GetVirtualKeysResponse {
	virtual_keys: VirtualKey[];
	count: number;
	total_count: number;
	limit: number;
	offset: number;
}

export interface GetTeamsParams {
	limit?: number;
	offset?: number;
	search?: string;
	customer_id?: string;
}

export interface GetTeamsResponse {
	teams: Team[];
	count: number;
	total_count: number;
	limit: number;
	offset: number;
}

export interface GetCustomersParams {
	limit?: number;
	offset?: number;
	search?: string;
}

export interface GetCustomersResponse {
	customers: Customer[];
	count: number;
	total_count: number;
	limit: number;
	offset: number;
}

export interface GetBudgetsResponse {
	budgets: Budget[];
	count: number;
}

export interface GetRateLimitsResponse {
	rate_limits: RateLimit[];
	count: number;
}

export interface DebugStatsResponse {
	plugin_stats: Record<string, any>;
	database_stats: {
		virtual_keys_count: number;
		teams_count: number;
		customers_count: number;
		budgets_count: number;
		rate_limits_count: number;
		usage_tracking_count: number;
		audit_logs_count: number;
	};
	timestamp: string;
}

export interface HealthCheckResponse {
	status: "healthy" | "unhealthy" | "warning";
	timestamp: string;
	checks: Record<
		string,
		{
			status: "healthy" | "unhealthy" | "warning";
			error?: string;
			message?: string;
		}
	>;
}

// Model Config for per-model budgeting and rate limiting
export interface ModelConfig {
	id: string;
	model_name: string;
	provider?: string; // Optional provider - if empty/null, applies to all providers
	budget_id?: string;
	rate_limit_id?: string;
	// Populated relationships
	budget?: Budget;
	rate_limit?: RateLimit;
	created_at: string;
	updated_at: string;
}

// Request types for model config operations
export interface CreateModelConfigRequest {
	model_name: string;
	provider?: string; // Optional provider - if empty/null, applies to all providers
	budget?: CreateBudgetRequest;
	rate_limit?: CreateRateLimitRequest;
}

export interface UpdateModelConfigRequest {
	model_name?: string;
	provider?: string; // Optional provider - if empty/null, applies to all providers
	budget?: UpdateBudgetRequest;
	rate_limit?: UpdateRateLimitRequest;
}

export interface GetModelConfigsParams {
	limit?: number;
	offset?: number;
	search?: string;
}

// Response types for model configs
export interface GetModelConfigsResponse {
	model_configs: ModelConfig[];
	count: number;
	total_count: number;
	limit: number;
	offset: number;
}

// Provider governance - for extending provider with budget/rate limit
export interface ProviderGovernance {
	provider: string;
	budget_id?: string;
	rate_limit_id?: string;
	budget?: Budget;
	rate_limit?: RateLimit;
}

export interface UpdateProviderGovernanceRequest {
	budget?: UpdateBudgetRequest;
	rate_limit?: UpdateRateLimitRequest;
}

export interface GetProviderGovernanceResponse {
	providers: ProviderGovernance[];
	count: number;
}

// Key health status for load balancer monitoring
export interface KeyHealthStatus {
	key_id: string;
	active_requests: number;
	total_requests: number;
	total_tokens: number;
	error_count: number;
	circuit_state: "closed" | "open" | "half_open";
	last_error?: string;
}

export interface KeyHealthResponse {
	keys: KeyHealthStatus[];
}
