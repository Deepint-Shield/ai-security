package entitlements

// Plan capability / quota / meter KEYS. These are plain string identifiers — no
// IP. They live in the open-core seam so OSS-retained handlers can reference a
// gate key (e.g. EnforceFeature(..., FeatureGuardrailsInTreeML)) without
// importing the commercial framework/billing package. The plan -> key MAPPING
// (which plan grants which key, and the numeric limits) stays closed in
// framework/billing/catalog.go. billing re-exports each of these as an alias so
// existing billing.* references keep compiling and never drift.
const (
	FeatureGatewayCore             = "gateway_core"
	FeatureProviderRouting         = "provider_routing"
	FeatureModelCatalog            = "model_catalog"
	FeatureSemanticCache           = "semantic_cache"
	FeatureVirtualKeys             = "virtual_keys"
	FeaturePromptRepository        = "prompt_repository"
	FeatureAdvancedObservability   = "advanced_observability"
	FeatureRoutingRules            = "routing_rules"
	FeatureBudgetsAndLimits        = "budgets_and_limits"
	FeatureProxyEgress             = "proxy_egress"
	FeatureRAGSecurity             = "rag_security"
	FeatureGuardrails              = "guardrails"
	FeatureSCIM                    = "scim"
	FeatureAuditLogs               = "audit_logs"
	FeatureAdaptiveRouting         = "adaptive_routing"
	FeatureCluster                 = "cluster"
	FeatureManagedDashboardAuth    = "managed_dashboard_auth"
	FeatureAdvancedAuthOnInference = "advanced_auth_on_inference"

	// Guardrails capability flags (per-surface gates).
	FeatureGuardrailsCustomCard       = "guardrails.custom_card"
	FeatureGuardrailsInTreeML         = "guardrails.in_tree_ml"
	FeatureGuardrailsPartnerProviders = "guardrails.partner_providers"
	FeatureGuardrailsMCPSecurity      = "guardrails.mcp_security"
	FeatureGuardrailsRAGSecurity      = "guardrails.rag_security"

	// Agentic + accuracy capability flags (Business+).
	FeatureAgenticIntegrity          = "agentic.integrity"
	FeatureAgenticGrants             = "agentic.grants"
	FeatureAgenticIdentity           = "agentic.identity"
	FeatureAgenticRollout            = "agentic.rollout"
	FeatureAgenticObservability      = "agentic.observability"
	FeatureAgenticCache              = "agentic.cache"
	FeatureAccuracyConsistency       = "accuracy.consistency"
	FeatureGuardrailsOWASPAgentic    = "guardrails.owasp_agentic"
	FeatureGuardrailsDomainPacks     = "guardrails.domain_packs"
	FeatureObservabilityIntegrations = "observability.integrations"

	// Team+ cost-optimization plugin flags.
	FeatureMCPResultCache = "cache.mcp_result"
	FeatureRequestMocker  = "ops.request_mocker"
)

// Metering keys.
const (
	MeterGovernedRequests = "governed_requests"
	MeterLoggedRequests   = "logged_requests"
	MeterProviderSpend    = "provider_spend"
	MeterGuardrailEvals   = "guardrail_evals"
)

// Quota / limit keys.
const (
	LimitConditionalRules   = "gateway.conditional_rules"
	LimitRateLimitedModels  = "gateway.rate_limited_models"
	LimitCostBudgetedModels = "gateway.cost_budgeted_models"
	LimitVirtualKeys        = "gateway.virtual_keys"
	LimitWorkspaces         = "governance.workspaces"
	LimitMCPServers         = "mcp.servers"
	LimitLogRetentionDays   = "log_retention_days"
)
