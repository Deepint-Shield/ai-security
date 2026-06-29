export type GuardrailProviderType = "aws_bedrock" | "azure_content_safety" | "deepintshield_models" | "gcp_model_armor" | "webhook" | "managed";
export type GuardrailProviderMode = "customer_owned" | "managed";
export type GuardrailScope = "input" | "output" | "action" | "mcp" | "rag";
export type GuardrailEnforcementMode = "monitor" | "block" | "redact" | "sandbox";
// GuardrailExecutionMode controls whether a policy blocks the request:
//   sync   - historical behaviour: the LLM call waits for evaluation and a deny short-circuits with 403.
//   async  - fire-and-forget. Result logged for observability but never affects the response.
//   shadow - runs inline (so latency reflects production) but never blocks; used for rolling out a
//            new check before flipping it to enforcement. Auto-expires at shadow_until.
export type GuardrailExecutionMode = "sync" | "async" | "shadow";
export type GuardrailPolicyVersionStatus = "draft" | "published" | "archived";

export interface GuardrailProvider {
	id: string;
	name: string;
	provider_type: GuardrailProviderType;
	mode: GuardrailProviderMode;
	customer_id?: string | null;
	enabled: boolean;
	region: string;
	endpoint: string;
	connection_meta?: Record<string, unknown>;
	credential_keys: string[];
	credentials_set: boolean;
	last_tested_at?: string | null;
	last_error?: string;
	created_at: string;
	updated_at: string;
}

export interface GuardrailProviderPayload {
	name: string;
	provider_type: GuardrailProviderType;
	mode: GuardrailProviderMode;
	customer_id?: string;
	enabled: boolean;
	region: string;
	endpoint: string;
	credentials?: Record<string, unknown>;
	connection_meta?: Record<string, unknown>;
}

export interface GuardrailProviderTestResult {
	ok: boolean;
	checked_at: string;
	message: string;
	missing_fields?: string[];
	warnings?: string[];
}

export interface GuardrailVersionSummary {
	id: string;
	version: number;
	status: GuardrailPolicyVersionStatus;
	published_by?: string;
	published_at?: string | null;
	created_at: string;
}

export interface GuardrailPolicy {
	id: string;
	name: string;
	description: string;
	domain_pack_id?: string | null;
	// workspace_id narrows the policy to a single workspace within the
	// tenant. null/undefined = org-wide (legacy default - applies to every
	// workspace in this tenant).
	workspace_id?: string | null;
	scope: GuardrailScope;
	scopes?: GuardrailScope[];
	enforcement_mode: GuardrailEnforcementMode;
	execution_mode: GuardrailExecutionMode;
	shadow_until?: string | null;
	sampling_rate: number;
	timeout_ms: number;
	enabled: boolean;
	is_default: boolean;
	active_version_id?: string | null;
	metadata?: Record<string, unknown>;
	active_version?: GuardrailVersionSummary | null;
	latest_version?: GuardrailVersionSummary | null;
	created_at: string;
	updated_at: string;
}

export interface GuardrailPolicyPayload {
	name: string;
	description: string;
	domain_pack_id?: string;
	workspace_id?: string | null;
	// apply_to_all_workspaces toggles the policy's scope on the server.
	// True → workspace_id stored as NULL (tenant-wide; visible in every
	// workspace under the tenant). False → workspace_id stamped from the
	// active workspace header, so the policy is only visible in that
	// workspace.
	apply_to_all_workspaces?: boolean;
	scope: GuardrailScope;
	scopes?: GuardrailScope[];
	enforcement_mode: GuardrailEnforcementMode;
	execution_mode?: GuardrailExecutionMode;
	shadow_until?: string | null;
	sampling_rate: number;
	timeout_ms: number;
	enabled: boolean;
	metadata?: Record<string, unknown>;
	initial_definition?: Record<string, unknown>;
}

export interface GuardrailMCPToolPolicy {
	id: string;
	policy_id: string;
	server_label: string;
	tool_name: string;
	action_class: string;
	restricted_action: boolean;
	allowed_domains: string[];
	allowed_identities: string[];
	created_at: string;
	updated_at: string;
}

export interface GuardrailMCPToolPolicyPayload {
	id?: string;
	server_label?: string;
	tool_name?: string;
	action_class?: string;
	restricted_action?: boolean;
	allowed_domains?: string[];
	allowed_identities?: string[];
}

export interface GuardrailPolicyVersion {
	id: string;
	policy_id: string;
	version: number;
	status: GuardrailPolicyVersionStatus;
	published_by?: string;
	published_at?: string | null;
	created_at: string;
	definition?: Record<string, unknown>;
}

export interface GuardrailPolicyVersionPayload {
	definition: Record<string, unknown>;
}

export interface GuardrailDomainPack {
	id: string;
	name: string;
	slug: string;
	description: string;
	vertical: string;
	status: string;
	controls: string[];
	threat_templates: string[];
	recommended_actions: string[];
	template_policy_definition?: Record<string, unknown>;
	created_at: string;
	updated_at: string;
}

export interface GuardrailFinding {
	id: string;
	request_id: string;
	trace_id: string;
	stage: string;
	policy_id: string;
	policy_version_id: string;
	provider_id?: string;
	category: string;
	severity: string;
	confidence: number;
	outcome: string;
	summary: string;
	actor_type?: string;
	actor_id?: string;
	resource_type?: string;
	resource_id?: string;
	details?: Record<string, unknown>;
	created_at: string;
}

export interface GuardrailTrace {
	id: string;
	request_id: string;
	stage?: string;
	actor_type: string;
	actor_id: string;
	model: string;
	provider: string;
	input_summary: string;
	output_summary?: string;
	decision: string;
	decision_chain?: string[];
	metadata?: Record<string, unknown>;
	created_at: string;
}

// GuardrailMetricsStats - server-aggregated headline figures for the Guardrail
// Metrics page (true counts + distributions over the full window).
export interface GuardrailMetricsStats {
	traces_total: number;
	traces_agent_tool: number;
	traces_rag: number;
	findings_total: number;
	findings_blocking: number;
	findings_agent_tool: number;
	traces_by_stage: { name: string; value: number }[];
	findings_by_severity: { name: string; value: number }[];
	findings_by_policy: { name: string; value: number }[];
	decision_timeline: { bucket: string; decision: string; count: number }[];
}

export interface GuardrailSimulationPayload {
	policy_ids?: string[];
	stage: GuardrailScope;
	actor_type: string;
	actor_id: string;
	actor_role?: string;
	model?: string;
	provider?: string;
	input?: string;
	output?: string;
	tool_input?: string;
	server_label?: string;
	tool_name?: string;
	action_class?: string;
	domains?: string[];
	metadata?: Record<string, unknown>;
	inline_mode?: "merge" | "replace";
	input_guardrails?: Array<Record<string, unknown>>;
	output_guardrails?: Array<Record<string, unknown>>;
}

export interface GuardrailRuntimeFinding {
	policy_id?: string;
	policy_version_id?: string;
	category: string;
	severity: string;
	confidence: number;
	outcome: string;
	summary: string;
	details?: Record<string, unknown>;
}

export interface GuardrailRuntimeResult {
	decision: string;
	reason: string;
	redactions?: string[];
	sanitized_input?: string;
	sanitized_output?: string;
	findings: GuardrailRuntimeFinding[];
	decision_chain?: string[];
	latency_ms: number;
}

export interface GuardrailSimulationResult {
	trace: GuardrailTrace;
	decision: {
		id: string;
		request_id: string;
		trace_id: string;
		stage: string;
		policy_id?: string;
		policy_version_id?: string;
		decision: string;
		reason: string;
		latency_ms: number;
		redactions?: string[];
		decision_chain?: string[];
		created_at: string;
	};
	findings: GuardrailFinding[];
	result: GuardrailRuntimeResult;
}
