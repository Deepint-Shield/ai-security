// TypeScript types for the Agentic Security control plane (basic PDP).
//
// These mirror the Go structs in framework/configstore/tables/agentic_*.go
// 1-to-1 - keep them in sync when the backend evolves. The build-spec
// invariants apply at the type level too: args_digest only, hash-chained
// audit, workspace+tenant scoping.

export type AgenticVerdict = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "MASK";

export type AgenticSensitivity = "low" | "medium" | "high";

export type AgenticFailPosture = "closed" | "open";

export type AgenticRevocationPath = "realtime" | "cached";

export type AgenticEnforcementMode = "shadow" | "canary" | "enforce";

export type AgenticAutonomyBudget = "low" | "medium" | "high";

export type AgenticPolicyStatus = "draft" | "staged" | "published" | "archived";

export interface AgenticPolicyCondition {
	field: string;
	operator: string;
	value: string;
	values?: string[];
}

export interface AgenticPolicyDefinition {
	subject?: { any_role?: string[]; any_agent?: string[]; any_subject?: string[] };
	tool?: { any_tool?: string[]; prefix_tool?: string[] };
	conditions?: AgenticPolicyCondition[];
	verdict?: AgenticVerdict;
	approvers?: string[];
	obligations?: string[];
	reason?: string;
}

export interface AgenticPolicy {
	id: string;
	org_id?: string;
	workspace_id?: string;
	name: string;
	description?: string;
	status: AgenticPolicyStatus;
	policy_version: number;
	enabled: boolean;
	generated_rego?: string;
	tests_passed?: number;
	tests_total?: number;
	owasp_tags?: string;
	staged_by?: string;
	staged_at?: string;
	approved_by?: string;
	approved_at?: string;
	published_at?: string;
	created_by?: string;
	created_at: string;
	updated_at: string;
	definition?: AgenticPolicyDefinition;
	// Per-policy targeting. When applies_to_all_keys is true the policy
	// fires for every authenticated caller in the workspace. Otherwise
	// it fires only when the caller's VK, Team, or Member id appears
	// in one of the three target_* arrays. Default true on creation.
	applies_to_all_keys?: boolean;
	target_virtual_key_ids?: string[];
	target_team_ids?: string[];
	target_member_ids?: string[];
}

export interface AgenticToolTier {
	id: string;
	workspace_id?: string;
	tool_name: string;
	display_name?: string;
	sensitivity: AgenticSensitivity;
	fail_posture: AgenticFailPosture;
	revocation_path: AgenticRevocationPath;
	obligations?: string[];
	enforce: boolean;
	action_class?: string;
	// integrity_posture controls what the Tool Integrity Engine does when a
	// call to this tool diverges from its declared action_class / args_schema.
	integrity_posture?: "flag" | "approval" | "block";
	recovery_cost: AgenticAutonomyBudget;
	created_at: string;
	updated_at: string;
	args_schema?: Record<string, unknown>;
	// ASI04 supply-chain pin. When pinned_fingerprint is set and the tool's
	// live contract fingerprint differs, decide sets context.fingerprint_drift.
	pinned_fingerprint?: string;
	pinned_by?: string;
	pinned_at?: string | null;
}

export interface AgenticDecision {
	decision_id: string;
	sequence: number;
	tenant_id: string;
	workspace_id: string;
	virtual_key_id?: string;
	principal: string;
	actor_chain?: string[];
	identity_type?: string;
	provider_id?: string;
	tool: string;
	args_digest: string;
	scope_hash?: string;
	verdict: AgenticVerdict;
	reason?: string;
	obligations?: string[];
	policy_id?: string;
	policy_version: number;
	recovery_cost?: string;
	rag_provenance?: string;
	cost_used: number;
	latency_us: number;
	cache_hit: boolean;
	mode: AgenticEnforcementMode;
	owasp_category?: string;
	cross_tenant: boolean;
	prev_hash: string;
	hash: string;
	ts: string;
	// Tool Integrity Engine outputs - the action class the call's behavior
	// actually implied, the [0,1] divergence risk, and the matched signals.
	effective_action_class?: string;
	integrity_risk?: number;
	integrity_flags?: string[];
	// OWASP → formal-framework cross-walk, enriched by the listDecisions handler
	// via ComplianceFor(owasp_category). Lets Findings show the compliance
	// mapping without recomputing it client-side.
	compliance?: ComplianceMapping | null;
}

export interface AgenticEnforcementState {
	id: string;
	workspace_id: string;
	mode: AgenticEnforcementMode;
	tiers_enforced?: string[];
	kill_switch: boolean;
	revocation_sla_sec: number;
	l1_cache_max_entries: number;
	default_fail_closed: boolean;
	// Opt-in (default false): enforce each agent's registered blueprint as an
	// allow-list - a tool called but never declared is denied (ASI04).
	enforce_blueprint_allowlist?: boolean;
	// Workspace source-code threat scanning (T11 RCE / T17 supply chain).
	// code_scan_mode: off | regex_only | model. code_scan_vk_id selects which VK's
	// model runs the model scan. enforce_code_threat: deny tools that scan malicious.
	code_scan_mode?: "off" | "regex_only" | "model";
	code_scan_vk_id?: string;
	code_scan_model?: string;
	enforce_code_threat?: boolean;
	// Per-agent decisions/minute cap (T4 Resource Overload / DoS). 0 = unlimited.
	max_requests_per_min?: number;
	would_deny_rate: number;
	would_escalate_rate: number;
	would_allow_rate: number;
	unexpected_denies: number;
	p99_added_ms: number;
	updated_by?: string;
	created_at: string;
	updated_at: string;
}

// ComplianceMapping mirrors the Go `agentic.ComplianceMapping` cross-walk -
// the formal-framework controls (NIST AI RMF / ISO 42001 / EU AI Act /
// MITRE ATLAS) an OWASP Agentic category corresponds to. Surfaced in the
// decision detail panel so denial/escalation rows carry their audit
// references inline.
export interface ComplianceMapping {
	owasp: string;
	nist_ai_rmf: string;
	iso_42001: string;
	eu_ai_act: string;
	mitre_atlas: string;
}

// ----------------------------------------------------------------------------
// Permission Templates (Claude-SDK-adapted starter configs)
// ----------------------------------------------------------------------------

export interface AgenticPermissionRule {
	tool: string;
	specifier?: string;
	negate?: boolean;
}

export interface AgenticPermissionRules {
	allow?: AgenticPermissionRule[];
	ask?: AgenticPermissionRule[];
	deny?: AgenticPermissionRule[];
}

export interface AgenticSandboxProfile {
	mode?: "none" | "wasm" | "container" | "";
	allow_egress?: string[];
	allow_fs_read?: string[];
	allow_fs_write?: string[];
	deny_fs_read?: string[];
	deny_fs_write?: string[];
	max_subprocesses?: number;
}

export interface AgenticPermissionTemplate {
	id: string;
	name: string;
	category: string;
	description: string;
	tags?: string[];
	soc2_controls?: string[];
	owasp_categories?: string[];
	source: string;
	permissions: AgenticPermissionRules;
	recommended_mode: string;
	sandbox: AgenticSandboxProfile;
	policy_definition?: Record<string, unknown>;
	tool_defaults?: Array<Record<string, unknown>>;
}

export interface AgenticPermissionTemplateList {
	templates: AgenticPermissionTemplate[];
	categories: string[];
}

// Tool Templates - icon-driven, pre-classified tool tiers.
export interface AgenticToolTemplate {
	id: string;
	name: string;
	category: string;
	icon: string; // lucide-react component name
	accent?: string; // tailwind hue: emerald | amber | rose | cyan | indigo | slate
	description: string;
	tags?: string[];
	soc2_controls?: string[];
	owasp_categories?: string[];
	source: string;
	tool_defaults: Record<string, unknown>;
}

export interface AgenticToolTemplateList {
	templates: AgenticToolTemplate[];
	categories: string[];
}
