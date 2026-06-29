export interface RAGSecuritySettings {
	runtime_enforcement_enabled: boolean;
	async_scanning_enabled: boolean;
	precomputed_scores_enabled: boolean;
	policy_cache_enabled: boolean;
	citation_enforcement_enabled: boolean;
	shadow_mode_enabled: boolean;
	evidence_exports_enabled: boolean;
	default_action: string;
	max_runtime_latency_ms: number;
	last_rules_sync_at: string;
	last_scan_at: string;
}

export interface RAGSecurityControlCoverage {
	framework: string;
	covered_controls: number;
	total_controls: number;
	status: string;
}

export interface RAGSecuritySummary {
	source_count: number;
	quarantined_source_count: number;
	protected_chunk_count: number;
	active_policy_count: number;
	open_findings_count: number;
	critical_findings_count: number;
	trace_count: number;
	shadow_decision_count: number;
	runtime_latency_p95_ms: number;
	control_coverage: RAGSecurityControlCoverage[];
}

export interface RAGSecuritySource {
	id: string;
	name: string;
	connector: string;
	index_name: string;
	owner: string;
	sensitivity: string;
	retention_class: string;
	trust_level: string;
	tenant: string;
	app_name: string;
	acl_tags: string[];
	labels: string[];
	document_count: number;
	chunk_count: number;
	health: string;
	quarantined: boolean;
	quarantine_reason: string;
	last_scan_at: string;
	created_at: string;
	updated_at: string;
}

export interface RAGSecurityPolicy {
	id: string;
	name: string;
	description: string;
	enabled: boolean;
	scope: string;
	action: string;
	severity: string;
	min_trust_score: number;
	max_injection_score: number;
	block_on_pii: boolean;
	citation_required: boolean;
	shadow_mode: boolean;
	allowed_roles: string[];
	allowed_apps: string[];
	trusted_source_ids: string[];
	blocked_patterns: string[];
	destination_restrictions: string[];
	session_action_budget: number;
	rate_limit_per_session: number;
	control_mappings: string[];
	updated_at: string;
}

export interface RAGSecurityFinding {
	id: string;
	source_id: string;
	source_name: string;
	severity: string;
	category: string;
	subcategory: string;
	status: string;
	summary: string;
	recommendation: string;
	detection_method: string;
	policy_id: string;
	policy_name: string;
	chunk_id: string;
	document_id: string;
	document_version: string;
	trust_score: number;
	injection_score: number;
	pii_flags: string[];
	created_at: string;
	updated_at: string;
}

export interface RAGSecurityCitation {
	source_id: string;
	source_name: string;
	document_id: string;
	document_version: string;
	chunk_id: string;
	offset_start: number;
	offset_end: number;
}

export interface RAGSecurityTraceChunk {
	chunk_id: string;
	document_id: string;
	document_version: string;
	content_preview: string;
	offset_start: number;
	offset_end: number;
	trust_score: number;
	injection_score: number;
	pii_flags: string[];
	decision: string;
	reason: string;
}

export interface RAGSecurityTrace {
	id: string;
	query: string;
	requester: string;
	requester_role: string;
	app_name: string;
	agent_name: string;
	source_id: string;
	source_name: string;
	decision: string;
	mode: string;
	policy_hits: string[];
	retrieved_chunks: RAGSecurityTraceChunk[];
	rejected_chunks: RAGSecurityTraceChunk[];
	final_answer_preview: string;
	citations: RAGSecurityCitation[];
	created_at: string;
}

export interface RAGSecuritySimulationChunkInput {
	chunk_id?: string;
	document_id: string;
	document_version: string;
	content: string;
	offset_start: number;
	offset_end: number;
	acl_tags?: string[];
}

export interface RAGSecuritySimulationRequest {
	query: string;
	source_id: string;
	requester: string;
	requester_role: string;
	app_name: string;
	agent_name: string;
	use_shadow_mode: boolean;
	retrieved_chunks: RAGSecuritySimulationChunkInput[];
}

export interface RAGSecuritySimulationResult {
	trace: RAGSecurityTrace;
	findings: RAGSecurityFinding[];
	final_action: string;
	allowed_count: number;
	blocked_count: number;
	sanitized_answer_preview: string;
}

export interface RAGSecurityEvidenceBundle {
	generated_at: string;
	summary: RAGSecuritySummary;
	settings: RAGSecuritySettings;
	sources: RAGSecuritySource[];
	policies: RAGSecurityPolicy[];
	findings: RAGSecurityFinding[];
	traces: RAGSecurityTrace[];
}
