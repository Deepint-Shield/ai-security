package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/entitlements"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeengine"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

type guardrailControlStore interface {
	ListGuardrailProviders(ctx context.Context) ([]tables.TableGuardrailProvider, error)
	GetGuardrailProvider(ctx context.Context, id string) (*tables.TableGuardrailProvider, error)
	CreateGuardrailProvider(ctx context.Context, provider *tables.TableGuardrailProvider) error
	UpdateGuardrailProvider(ctx context.Context, provider *tables.TableGuardrailProvider) error
	DeleteGuardrailProvider(ctx context.Context, id string) error
	ListGuardrailPolicies(ctx context.Context) ([]tables.TableGuardrailPolicy, error)
	GetGuardrailPolicy(ctx context.Context, id string) (*tables.TableGuardrailPolicy, error)
	CreateGuardrailPolicy(ctx context.Context, policy *tables.TableGuardrailPolicy) error
	UpdateGuardrailPolicy(ctx context.Context, policy *tables.TableGuardrailPolicy) error
	SetDefaultGuardrailPolicy(ctx context.Context, id string) error
	DeleteGuardrailPolicy(ctx context.Context, id string) error
	ListGuardrailPolicyVersions(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyVersion, error)
	GetGuardrailPolicyVersion(ctx context.Context, id string) (*tables.TableGuardrailPolicyVersion, error)
	CreateGuardrailPolicyVersion(ctx context.Context, version *tables.TableGuardrailPolicyVersion) error
	UpdateGuardrailPolicyVersion(ctx context.Context, version *tables.TableGuardrailPolicyVersion) error
	PublishGuardrailPolicyVersion(ctx context.Context, policyID, versionID, publishedBy string) error
	ListGuardrailDomainPacks(ctx context.Context) ([]tables.TableGuardrailDomainPack, error)
	GetGuardrailDomainPack(ctx context.Context, id string) (*tables.TableGuardrailDomainPack, error)
	CreateGuardrailDomainPack(ctx context.Context, pack *tables.TableGuardrailDomainPack) error
	ListGuardrailPolicyProviderBindings(ctx context.Context, policyID string) ([]tables.TableGuardrailPolicyProviderBinding, error)
	ReplaceGuardrailPolicyProviderBindings(ctx context.Context, policyID string, bindings []tables.TableGuardrailPolicyProviderBinding) error
	ListGuardrailMCPToolPolicies(ctx context.Context, policyID string) ([]tables.TableGuardrailMCPToolPolicy, error)
	ReplaceGuardrailMCPToolPolicies(ctx context.Context, policyID string, toolPolicies []tables.TableGuardrailMCPToolPolicy) error
	GetGuardrailRAGSettings(ctx context.Context) (*tables.TableGuardrailRAGSettings, error)
	ListGuardrailRAGSources(ctx context.Context) ([]tables.TableGuardrailRAGSource, error)

	// DB and GetOrganizationByID are required by the billing-tier
	// enforcement layer to resolve the calling tenant's plan and apply
	// FeatureLockedError responses on guardrails create endpoints.
	DB() *gorm.DB
	GetOrganizationByID(ctx context.Context, id string) (*tables.TableOrganization, error)
}

// requireGuardrailWrite gates destructive guardrail writes against the
// caller's workspace permission. If the configStore implementation isn't
// the full ConfigStore (e.g. tests with a fake), the check is skipped.
// Mirrors the pattern in GovernanceHandler / PluginsHandler.
func (h *GuardrailsHandler) requireGuardrailWrite(ctx *fasthttp.RequestCtx) bool {
	if tenantctx.TenantIDFromContext(ctx) == "" {
		return true
	}
	if currentSessionUserRole(ctx) == tables.UserRoleAdmin {
		return true
	}
	full, ok := h.configStore.(configstore.ConfigStore)
	if !ok {
		// Test / restricted store - skip rather than block.
		return true
	}
	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		respondAuthError(ctx, errUnauthorizedSession)
		return false
	}
	allowed := false
	if ws := tenantctx.WorkspaceIDFromContext(ctx); ws != "" {
		allowed = CanManageWorkspaceByID(ctx, full, user, ws)
	} else {
		allowed = CanManageTenant(ctx, full, user, user.TenantID)
	}
	if !allowed {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins, tenant owners/admins, or system admins can modify guardrails")
		return false
	}
	return true
}

// resolveOrgForGating returns the calling tenant's organization for use
// by the billing-tier enforcement layer. Falls back to the single-tenant
// resolver when no session user is present (matches CurrentOrgFromCtx
// behaviour without pulling in the whole ConfigStore surface).
func (h *GuardrailsHandler) resolveOrgForGating(ctx *fasthttp.RequestCtx) *tables.TableOrganization {
	// Use the ACTIVE tenant (scope switcher / workspace), NOT the raw home
	// tenant key - otherwise a multi-org user operating in a Team org gets
	// gated against their (possibly free) home org and 402s on Team features.
	// activeTenantFromCtx already falls back to the home tenant for single-org
	// users. (This mirrors CurrentOrgFromCtx; see middlewares.go.)
	tenantID := strings.TrimSpace(activeTenantFromCtx(ctx))
	if tenantID == "" {
		if resolver, ok := h.configStore.(interface {
			GetSingleTenantID(context.Context) (string, error)
		}); ok {
			if id, err := resolver.GetSingleTenantID(context.Background()); err == nil {
				tenantID = strings.TrimSpace(id)
			}
		}
	}
	if tenantID == "" {
		return nil
	}
	// Dual-resolve email→canonical UUID (no-op until tenant aliases exist).
	if r, ok := h.configStore.(interface {
		ResolveCanonicalTenant(context.Context, string) (string, error)
	}); ok {
		if canonical, err := r.ResolveCanonicalTenant(ctx, tenantID); err == nil && canonical != "" && canonical != tenantID {
			tenantID = canonical
		}
	}
	org, err := h.configStore.GetOrganizationByID(ctx, tenantID)
	if err != nil || org == nil {
		return nil
	}
	return org
}

// usesCustomCard reports whether a policy create payload contains a
// hand-built card definition (the "Custom card" flow in the Add-card
// sheet) versus a card chosen entirely from the canned catalog. The UI
// stores the marker under metadata.has_custom_card so the runtime can
// audit it; we treat any truthy value as "yes, gate this".
func usesCustomCard(payload guardrailPolicyPayload) bool {
	if payload.Metadata == nil {
		return false
	}
	v, ok := payload.Metadata["has_custom_card"]
	if !ok {
		return false
	}
	switch typed := v.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

// usesInTreeMLDetector reports whether a policy create payload requests
// one of the in-tree ML detectors (DeBERTa / RoBERTa / BERT). The UI
// stores the chosen model under metadata.detector_model; the runtime
// resolves it back from there. We treat any non-empty value as "uses
// in-tree ML" so future detector additions don't silently bypass the gate.
func usesInTreeMLDetector(payload guardrailPolicyPayload) bool {
	if payload.Metadata == nil {
		return false
	}
	v, ok := payload.Metadata["detector_model"]
	if !ok {
		return false
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	return strings.TrimSpace(s) != ""
}

// usesDomainPack reports whether a policy create payload adopts one of the
// 7 vertical domain packs (it carries a non-empty domain_pack_id). Domain
// packs are a Business+ capability.
func usesDomainPack(payload guardrailPolicyPayload) bool {
	return payload.DomainPackID != nil && strings.TrimSpace(*payload.DomainPackID) != ""
}

// sendFeatureLocked emits the canonical 402 body the UI consumes when a
// feature is gated to a higher tier. Mirrors the QUOTA_EXCEEDED shape
// from the routing-rules / model-configs gates so a single client-side
// helper can render either.
func sendFeatureLocked(ctx *fasthttp.RequestCtx, err *entitlements.FeatureLockedError) {
	SendJSONWithStatus(ctx, map[string]any{
		"error":      err.Error(),
		"code":       "FEATURE_LOCKED",
		"feature":    err.FeatureKey,
		"plan":       err.Plan,
		"upgrade_to": err.UpgradeTo,
	}, fasthttp.StatusPaymentRequired)
}

type GuardrailsHandler struct {
	configStore     guardrailControlStore
	evidenceStore   logstore.GuardrailEvidenceStore
	runtimeClient   *guardRuntimeClient
	embeddedRuntime *runtimeengine.Engine
}

type guardrailProviderPayload struct {
	Name           string         `json:"name"`
	ProviderType   string         `json:"provider_type"`
	Mode           string         `json:"mode"`
	CustomerID     *string        `json:"customer_id,omitempty"`
	Enabled        bool           `json:"enabled"`
	Region         string         `json:"region"`
	Endpoint       string         `json:"endpoint"`
	Credentials    map[string]any `json:"credentials,omitempty"`
	ConnectionMeta map[string]any `json:"connection_meta,omitempty"`
}

type guardrailProviderResponse struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	ProviderType   string         `json:"provider_type"`
	Mode           string         `json:"mode"`
	CustomerID     *string        `json:"customer_id,omitempty"`
	Enabled        bool           `json:"enabled"`
	Region         string         `json:"region"`
	Endpoint       string         `json:"endpoint"`
	ConnectionMeta map[string]any `json:"connection_meta,omitempty"`
	CredentialKeys []string       `json:"credential_keys,omitempty"`
	CredentialsSet bool           `json:"credentials_set"`
	LastTestedAt   *time.Time     `json:"last_tested_at,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type guardrailPolicyPayload struct {
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	DomainPackID      *string        `json:"domain_pack_id,omitempty"`
	Scope             string         `json:"scope"`
	Scopes            []string       `json:"scopes,omitempty"`
	EnforcementMode   string         `json:"enforcement_mode"`
	ExecutionMode     string         `json:"execution_mode,omitempty"`
	ShadowUntil       *time.Time     `json:"shadow_until,omitempty"`
	SamplingRate      int            `json:"sampling_rate"`
	TimeoutMs         int            `json:"timeout_ms"`
	Enabled           bool           `json:"enabled"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	InitialDefinition map[string]any `json:"initial_definition,omitempty"`
	// ApplyToAllWorkspaces toggles the policy's scope. When true, the
	// policy is stored with workspace_id = NULL and shows up in every
	// workspace under the tenant ("tenant-wide"). When false (default),
	// the policy is stamped with the active workspace from
	// X-Active-Workspace-Id and is only visible there. The list query
	// returns BOTH tenant-wide and the active workspace's policies.
	ApplyToAllWorkspaces bool `json:"apply_to_all_workspaces,omitempty"`
}

type guardrailPolicyVersionPayload struct {
	Definition map[string]any `json:"definition"`
}

type guardrailMCPToolPolicyPayload struct {
	ID                string   `json:"id,omitempty"`
	ServerLabel       string   `json:"server_label,omitempty"`
	ToolName          string   `json:"tool_name,omitempty"`
	ActionClass       string   `json:"action_class,omitempty"`
	RestrictedAction  bool     `json:"restricted_action"`
	AllowedDomains    []string `json:"allowed_domains,omitempty"`
	AllowedIdentities []string `json:"allowed_identities,omitempty"`
}

type guardrailMCPToolPoliciesPayload struct {
	ToolPolicies []guardrailMCPToolPolicyPayload `json:"tool_policies"`
}

type guardrailPublishPayload struct {
	VersionID   string `json:"version_id"`
	PublishedBy string `json:"published_by"`
}

type guardrailSimulationPayload struct {
	PolicyIDs        []string         `json:"policy_ids,omitempty"`
	Stage            string           `json:"stage"`
	ActorType        string           `json:"actor_type"`
	ActorID          string           `json:"actor_id"`
	ActorRole        string           `json:"actor_role,omitempty"`
	Model            string           `json:"model,omitempty"`
	Provider         string           `json:"provider,omitempty"`
	Input            string           `json:"input,omitempty"`
	Output           string           `json:"output,omitempty"`
	ToolInput        string           `json:"tool_input,omitempty"`
	ServerLabel      string           `json:"server_label,omitempty"`
	ToolName         string           `json:"tool_name,omitempty"`
	ActionClass      string           `json:"action_class,omitempty"`
	Domains          []string         `json:"domains,omitempty"`
	Metadata         map[string]any   `json:"metadata,omitempty"`
	InlineMode       string           `json:"inline_mode,omitempty"`
	InputGuardrails  []map[string]any `json:"input_guardrails,omitempty"`
	OutputGuardrails []map[string]any `json:"output_guardrails,omitempty"`
}

type guardrailEvaluatePayload struct {
	Stage           string         `json:"stage"`
	ActorType       string         `json:"actor_type"`
	ActorID         string         `json:"actor_id"`
	ActorRole       string         `json:"actor_role,omitempty"`
	ActorCustomerID string         `json:"actor_customer_id,omitempty"`
	ActorTeamID     string         `json:"actor_team_id,omitempty"`
	Model           string         `json:"model,omitempty"`
	Provider        string         `json:"provider,omitempty"`
	Input           string         `json:"input,omitempty"`
	Output          string         `json:"output,omitempty"`
	ToolInput       string         `json:"tool_input,omitempty"`
	ServerLabel     string         `json:"server_label,omitempty"`
	ToolName        string         `json:"tool_name,omitempty"`
	ActionClass     string         `json:"action_class,omitempty"`
	Domains         []string       `json:"domains,omitempty"`
	AppName         string         `json:"app_name,omitempty"`
	AgentName       string         `json:"agent_name,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	Persist         *bool          `json:"persist,omitempty"`
}

type guardrailVersionSummary struct {
	ID          string     `json:"id"`
	Version     int        `json:"version"`
	Status      string     `json:"status"`
	PublishedBy string     `json:"published_by,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type guardrailPolicyResponse struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	DomainPackID *string `json:"domain_pack_id,omitempty"`
	// WorkspaceID is the workspace this policy is scoped to. nil/omitted
	// means tenant-wide (visible to every workspace in the org). The UI
	// derives the "Apply to all workspaces" checkbox from this field, so
	// it MUST round-trip on every read - otherwise the checkbox silently
	// re-ticks itself after save.
	WorkspaceID     *string                  `json:"workspace_id,omitempty"`
	Scope           string                   `json:"scope"`
	Scopes          []string                 `json:"scopes,omitempty"`
	EnforcementMode string                   `json:"enforcement_mode"`
	ExecutionMode   string                   `json:"execution_mode"`
	ShadowUntil     *time.Time               `json:"shadow_until,omitempty"`
	SamplingRate    int                      `json:"sampling_rate"`
	TimeoutMs       int                      `json:"timeout_ms"`
	Enabled         bool                     `json:"enabled"`
	IsDefault       bool                     `json:"is_default"`
	ActiveVersionID *string                  `json:"active_version_id,omitempty"`
	Metadata        map[string]any           `json:"metadata,omitempty"`
	ActiveVersion   *guardrailVersionSummary `json:"active_version,omitempty"`
	LatestVersion   *guardrailVersionSummary `json:"latest_version,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

type guardrailSimulationResponse struct {
	Trace    logstore.GuardrailTrace       `json:"trace"`
	Decision logstore.GuardrailDecision    `json:"decision"`
	Findings []logstore.GuardrailFinding   `json:"findings"`
	Result   *guardRuntimeEvaluateResponse `json:"result"`
}

type guardrailMCPToolPolicyResponse struct {
	ID               string `json:"id"`
	PolicyID         string `json:"policy_id"`
	ServerLabel      string `json:"server_label,omitempty"`
	ToolName         string `json:"tool_name,omitempty"`
	ActionClass      string `json:"action_class,omitempty"`
	RestrictedAction bool   `json:"restricted_action"`
	// Slices must serialize as `[]` (not be omitted) - the MCP Security
	// tab on the dashboard does `policy.allowed_domains.join(', ')`
	// directly, so an absent field becomes `undefined.join()` and the
	// page crashes with "Cannot read properties of undefined (reading
	// 'join')". Keep `omitempty` off and ensure the builder seeds an
	// empty slice instead of nil.
	AllowedDomains    []string  `json:"allowed_domains"`
	AllowedIdentities []string  `json:"allowed_identities"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

const defaultGuardrailTenantID = "default"

func NewGuardrailsHandler(configStore guardrailControlStore, evidenceStore logstore.GuardrailEvidenceStore, runtimeURL, grpcTarget, sharedSecret string, preferGRPC bool, timeout time.Duration) *GuardrailsHandler {
	if configStore == nil || evidenceStore == nil {
		return nil
	}
	handler := &GuardrailsHandler{
		configStore:   configStore,
		evidenceStore: evidenceStore,
		runtimeClient: newGuardRuntimeClient(runtimeURL, grpcTarget, sharedSecret, preferGRPC, timeout),
	}
	// Embedded fallback. When no HTTP/gRPC guard URL is configured the
	// handler used to drop into evaluateGuardRuntimeLocally, which compiles
	// rules from the policy version's stored input_guardrails as-is -
	// never running the preset expansion that the inference plugin path
	// goes through. That left dashboards / SDK agent surfaces / standalone
	// `/api/guardrails/evaluate` blind to anything not in the customPattern.
	// Wiring the same embedded engine here makes the local-only deployment
	// behave identically to the inference path on every guardrail decision.
	if handler.runtimeClient == nil {
		handler.embeddedRuntime = runtimeengine.New()
	}
	return handler
}

func (h *GuardrailsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/guardrails/providers", lib.ChainMiddlewares(h.listProviders, middlewares...))
	r.POST("/api/guardrails/providers", lib.ChainMiddlewares(h.createProvider, middlewares...))
	r.GET("/api/guardrails/providers/{id}", lib.ChainMiddlewares(h.getProviderByID, middlewares...))
	r.PUT("/api/guardrails/providers/{id}", lib.ChainMiddlewares(h.updateProviderByID, middlewares...))
	r.DELETE("/api/guardrails/providers/{id}", lib.ChainMiddlewares(h.deleteProviderByID, middlewares...))
	r.POST("/api/guardrails/providers/{id}/test", lib.ChainMiddlewares(h.testProviderByID, middlewares...))
	r.GET("/api/guardrails/policies", lib.ChainMiddlewares(h.listPolicies, middlewares...))
	r.POST("/api/guardrails/policies", lib.ChainMiddlewares(h.createPolicy, middlewares...))
	r.GET("/api/guardrails/policies/{id}", lib.ChainMiddlewares(h.getPolicyByID, middlewares...))
	r.PUT("/api/guardrails/policies/{id}", lib.ChainMiddlewares(h.updatePolicyByID, middlewares...))
	r.POST("/api/guardrails/policies/{id}/default", lib.ChainMiddlewares(h.setDefaultPolicyByID, middlewares...))
	r.DELETE("/api/guardrails/policies/{id}", lib.ChainMiddlewares(h.deletePolicyByID, middlewares...))
	r.GET("/api/guardrails/policies/{id}/mcp-tool-policies", lib.ChainMiddlewares(h.listMCPToolPoliciesByPolicyID, middlewares...))
	r.PUT("/api/guardrails/policies/{id}/mcp-tool-policies", lib.ChainMiddlewares(h.replaceMCPToolPoliciesByPolicyID, middlewares...))
	r.GET("/api/guardrails/policies/{id}/versions", lib.ChainMiddlewares(h.listPolicyVersions, middlewares...))
	r.POST("/api/guardrails/policies/{id}/versions", lib.ChainMiddlewares(h.createPolicyVersion, middlewares...))
	r.POST("/api/guardrails/policies/{id}/publish", lib.ChainMiddlewares(h.publishPolicyVersion, middlewares...))
	r.POST("/api/guardrails/policies/{id}/rollback", lib.ChainMiddlewares(h.rollbackPolicyVersion, middlewares...))
	// NOTE: GET /api/guardrails/domain-packs is intentionally NOT registered in
	// the OSS build. The vertical domain packs are a Cloud/Enterprise feature
	// (gated by FeatureGuardrailsDomainPacks); OSS ships none and never seeds
	// builtinGuardrailDomainPacks. The listDomainPacks handler + seeding helpers
	// are retained but unreachable so a commercial build can re-register them.
	r.GET("/api/guardrails/findings", lib.ChainMiddlewares(h.listFindings, middlewares...))
	r.GET("/api/guardrails/traces", lib.ChainMiddlewares(h.listTraces, middlewares...))
	r.GET("/api/guardrails/metrics-stats", lib.ChainMiddlewares(h.getMetricsStats, middlewares...))
	r.GET("/api/guardrails/latency", lib.ChainMiddlewares(h.getLatencyHistogram, middlewares...))
	r.POST("/api/guardrails/evaluate", lib.ChainMiddlewares(h.evaluatePolicyRuntime, middlewares...))
	r.POST("/api/guardrails/simulations", lib.ChainMiddlewares(h.runSimulation, middlewares...))
	r.POST("/api/guardrails/finetune/extract-regex", lib.ChainMiddlewares(h.extractRegexFromCSV, middlewares...))
	r.POST("/api/guardrails/finetune/lora", lib.ChainMiddlewares(h.enqueueLoRAJob, middlewares...))
	r.GET("/api/guardrails/finetune/jobs", lib.ChainMiddlewares(h.listFinetuneJobsHandler, middlewares...))
	r.POST("/api/guardrails/finetune/deploy", lib.ChainMiddlewares(h.deployLoRAJob, middlewares...))
	r.GET("/api/guardrails/finetune/csv", lib.ChainMiddlewares(h.downloadFinetuneCSV, middlewares...))
	r.DELETE("/api/guardrails/finetune/job", lib.ChainMiddlewares(h.deleteLoRAJob, middlewares...))
}

func (h *GuardrailsHandler) listProviders(ctx *fasthttp.RequestCtx) {
	providers, err := h.configStore.ListGuardrailProviders(auditStoreContext(ctx))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail providers: %v", err))
		return
	}
	responses := make([]guardrailProviderResponse, 0, len(providers))
	for i := range providers {
		responses = append(responses, buildGuardrailProviderResponse(&providers[i]))
	}
	SendJSON(ctx, map[string]any{"providers": responses})
}

func (h *GuardrailsHandler) getLatencyHistogram(ctx *fasthttp.RequestCtx) {
	filters := logstore.GuardrailLatencyFilters{}
	if startTime := strings.TrimSpace(string(ctx.QueryArgs().Peek("start_time"))); startTime != "" {
		if parsed, err := time.Parse(time.RFC3339, startTime); err == nil {
			filters.StartTime = &parsed
		}
	}
	if endTime := strings.TrimSpace(string(ctx.QueryArgs().Peek("end_time"))); endTime != "" {
		if parsed, err := time.Parse(time.RFC3339, endTime); err == nil {
			filters.EndTime = &parsed
		}
	}

	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)
	result, err := h.evidenceStore.GetGuardrailLatencyHistogram(auditStoreContext(ctx), filters, bucketSizeSeconds)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail latency: %v", err))
		return
	}
	SendJSON(ctx, result)
}

func (h *GuardrailsHandler) createProvider(ctx *fasthttp.RequestCtx) {
	if !h.requireGuardrailWrite(ctx) {
		return
	}
	// Plan-tier gate: partner guardrail providers (AWS Bedrock, Azure
	// Content Safety, GCP Model Armor, etc.) are Cloud/Enterprise only.
	// Enforced unconditionally - the OSS Enforcer denies this key even when
	// org resolution returns nil, so a hand-crafted curl can't register a
	// partner adapter by dodging tenant resolution. (Commercial builds always
	// resolve an org, so this only strengthens OSS.)
	if err := entitlements.EnforceFeature(ctx, h.configStore.DB(), h.resolveOrgForGating(ctx), entitlements.FeatureGuardrailsPartnerProviders); err != nil {
		if fe, ok := err.(*entitlements.FeatureLockedError); ok {
			sendFeatureLocked(ctx, fe)
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	var payload guardrailProviderPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail provider payload")
		return
	}
	provider := providerFromPayload(&payload, nil)
	if strings.TrimSpace(provider.ID) == "" {
		provider.ID = uuid.NewString()
	}
	provider.CreatedAt = time.Now().UTC()
	provider.UpdatedAt = provider.CreatedAt
	provider.LastError = ""
	missing, warnings := validateGuardrailProvider(provider)
	if len(missing) > 0 {
		SendJSONWithStatus(ctx, map[string]any{
			"ok":             false,
			"missing_fields": missing,
			"warnings":       warnings,
			"message":        "Missing required guardrail provider fields",
		}, fasthttp.StatusBadRequest)
		return
	}
	if err := h.configStore.CreateGuardrailProvider(auditStoreContext(ctx), provider); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create guardrail provider: %v", err))
		return
	}
	saved, err := h.configStore.GetGuardrailProvider(auditStoreContext(ctx), provider.ID)
	if err != nil || saved == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail provider")
		return
	}
	// Auto-create a thin wrapper policy bound to this provider so the
	// provider shows up as a selectable entry in the VK "Guardrail Policies"
	// dropdown without forcing the operator to hand-author a policy.
	// Existing policies (operator-authored, multi-check) are unaffected.
	// Errors are logged but not returned - the provider create itself
	// already succeeded; the wrapper is a UX nicety.
	if err := h.ensureProviderWrapperPolicy(auditStoreContext(ctx), saved); err != nil {
		// Best-effort. Operator can still bind manually via the Policies tab.
		_ = err
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSONWithStatus(ctx, buildGuardrailProviderResponse(saved), fasthttp.StatusCreated)
}

// ensureProviderWrapperPolicy creates a published, enabled, workspace-scoped
// policy whose only job is to fan a single inference request out to the
// supplied provider. The policy's name mirrors the provider's so the VK
// "Guardrail Policies" multi-select renders "Safety Provider X" and
// "AI Models Y" as ordinary, selectable entries.
//
// Why this design rather than a separate VK→provider join: the runtime
// already understands policy→provider bindings (see
// guardrail_policy_provider_bindings + PolicyBundle.ProviderBindings).
// Reusing that mechanism means the runtime evaluator, decision cache,
// fingerprinting, and analytics all keep working untouched - the wrapper
// is invisible to every layer below the UI.
func (h *GuardrailsHandler) ensureProviderWrapperPolicy(ctx context.Context, provider *tables.TableGuardrailProvider) error {
	if provider == nil {
		return nil
	}
	policy := &tables.TableGuardrailPolicy{
		ID:              uuid.NewString(),
		WorkspaceID:     provider.WorkspaceID,
		Name:            provider.Name,
		Description:     "Auto-created wrapper for " + provider.Name,
		Scope:           "input",
		EnforcementMode: "block",
		// Sync execution - the wrapper actually blocks on detector findings.
		// Hot-path latency is absorbed by two layers:
		//   1. globalDecisionCache (60s TTL, SHA256 keyed on tenant+stage+
		//      policies+content) - repeat / template prompts hit in sub-ms.
		//   2. Speculative dispatch - on a cache miss PreLLMHook fires the
		//      detector goroutine and returns immediately, the model call
		//      runs in parallel, PostLLMHook waits at max(detector, model).
		//      With warm sidecar detectors (~440ms p50) and model time
		//      dominating (~600-1500ms), the wait is bounded by model time.
		// Net: cache-hit = zero hot-path latency, cache-miss = ~model time,
		// detector findings DO gate the response. This is the "zero-latency
		// AND blocking" path. Operators who want pure observation (no
		// gating) can edit the policy to "async" from the Policies tab.
		ExecutionMode: tables.GuardrailExecutionModeSync,
		// 10s ceiling - the cold-path PostLLMHook wait is bounded by this
		// when both the detector and the model stall. Below this the wait
		// is naturally bounded by whichever finishes first.
		TimeoutMs: 10000,
		Enabled:   true,
		IsDefault: false,
		Metadata:  map[string]any{"auto_wrapper_for_provider_id": provider.ID},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := h.configStore.CreateGuardrailPolicy(ctx, policy); err != nil {
		return fmt.Errorf("create wrapper policy: %w", err)
	}
	publishedAt := time.Now().UTC()
	version := &tables.TableGuardrailPolicyVersion{
		ID:          uuid.NewString(),
		PolicyID:    policy.ID,
		Version:     1,
		Status:      tables.GuardrailPolicyVersionStatusPublished,
		Definition:  map[string]any{}, // empty - the provider binding does the work
		PublishedBy: "auto_wrapper",
		PublishedAt: &publishedAt,
		CreatedAt:   time.Now().UTC(),
	}
	if err := h.configStore.CreateGuardrailPolicyVersion(ctx, version); err != nil {
		return fmt.Errorf("create wrapper policy version: %w", err)
	}
	binding := tables.TableGuardrailPolicyProviderBinding{
		ID:         uuid.NewString(),
		PolicyID:   policy.ID,
		ProviderID: provider.ID,
		Stage:      "input",
		Priority:   100,
		Enabled:    true,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := h.configStore.ReplaceGuardrailPolicyProviderBindings(ctx, policy.ID, []tables.TableGuardrailPolicyProviderBinding{binding}); err != nil {
		return fmt.Errorf("bind provider to wrapper policy: %w", err)
	}
	return nil
}

func (h *GuardrailsHandler) getProviderByID(ctx *fasthttp.RequestCtx) {
	provider, err := h.configStore.GetGuardrailProvider(auditStoreContext(ctx), stringValue(ctx.UserValue("id")))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail provider: %v", err))
		return
	}
	if provider == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail provider not found")
		return
	}
	SendJSON(ctx, buildGuardrailProviderResponse(provider))
}

func (h *GuardrailsHandler) updateProviderByID(ctx *fasthttp.RequestCtx) {
	if !h.requireGuardrailWrite(ctx) {
		return
	}
	var payload guardrailProviderPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail provider payload")
		return
	}
	existing, err := h.configStore.GetGuardrailProvider(auditStoreContext(ctx), stringValue(ctx.UserValue("id")))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail provider: %v", err))
		return
	}
	if existing == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail provider not found")
		return
	}
	provider := providerFromPayload(&payload, existing)
	provider.ID = existing.ID
	provider.CreatedAt = existing.CreatedAt
	provider.LastTestedAt = existing.LastTestedAt
	provider.LastError = existing.LastError
	missing, warnings := validateGuardrailProvider(provider)
	if len(missing) > 0 {
		SendJSONWithStatus(ctx, map[string]any{
			"ok":             false,
			"missing_fields": missing,
			"warnings":       warnings,
			"message":        "Missing required guardrail provider fields",
		}, fasthttp.StatusBadRequest)
		return
	}
	if err := h.configStore.UpdateGuardrailProvider(auditStoreContext(ctx), provider); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update guardrail provider: %v", err))
		return
	}
	saved, err := h.configStore.GetGuardrailProvider(auditStoreContext(ctx), provider.ID)
	if err != nil || saved == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail provider")
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSON(ctx, buildGuardrailProviderResponse(saved))
}

func (h *GuardrailsHandler) deleteProviderByID(ctx *fasthttp.RequestCtx) {
	if !h.requireGuardrailWrite(ctx) {
		return
	}
	providerID := stringValue(ctx.UserValue("id"))
	if err := h.configStore.DeleteGuardrailProvider(auditStoreContext(ctx), providerID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete guardrail provider: %v", err))
		return
	}
	// Best-effort cleanup of the auto-wrapper policy that createProvider
	// stamped so a delete on Safety Providers also removes the matching
	// entry from the VK dropdown. Operator-authored policies are unaffected
	// because we only target rows that carry our own metadata marker.
	if policies, err := h.configStore.ListGuardrailPolicies(auditStoreContext(ctx)); err == nil {
		for i := range policies {
			pol := policies[i]
			if pol.Metadata == nil {
				continue
			}
			if marker, ok := pol.Metadata["auto_wrapper_for_provider_id"].(string); ok && marker == providerID {
				_ = h.configStore.DeleteGuardrailPolicy(auditStoreContext(ctx), pol.ID)
			}
		}
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSON(ctx, map[string]string{"message": "Guardrail provider deleted"})
}

func (h *GuardrailsHandler) testProviderByID(ctx *fasthttp.RequestCtx) {
	provider, err := h.configStore.GetGuardrailProvider(auditStoreContext(ctx), stringValue(ctx.UserValue("id")))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail provider: %v", err))
		return
	}
	if provider == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail provider not found")
		return
	}
	missing, warnings := validateGuardrailProvider(provider)
	now := time.Now().UTC()
	provider.LastTestedAt = &now
	if len(missing) > 0 {
		provider.LastError = "Missing required fields: " + strings.Join(missing, ", ")
		_ = h.configStore.UpdateGuardrailProvider(auditStoreContext(ctx), provider)
		SendJSONWithStatus(ctx, map[string]any{
			"ok":             false,
			"checked_at":     now,
			"message":        provider.LastError,
			"missing_fields": missing,
			"warnings":       warnings,
		}, fasthttp.StatusBadRequest)
		return
	}
	provider.LastError = ""
	_ = h.configStore.UpdateGuardrailProvider(auditStoreContext(ctx), provider)
	SendJSON(ctx, map[string]any{
		"ok":         true,
		"checked_at": now,
		"message":    "Provider configuration is valid for runtime orchestration",
		"warnings":   warnings,
	})
}

// ensureDefaultPolicyMu serializes default-policy seeding across the
// concurrent callers (server startup + every GET /api/guardrails/policies).
// Without it, two requests landing on a fresh tenant simultaneously each pass
// the "no real policy exists" check and create a duplicate "Default Protection"
// row, which is exactly the config-page refresh race we're closing. The mutex
// is keyed by tenant so unrelated tenants never block each other.
var (
	ensureDefaultPolicyMu    sync.Mutex
	ensureDefaultPolicyLocks sync.Map // tenantID -> *sync.Mutex
)

func ensureDefaultPolicyLockFor(tenantID string) *sync.Mutex {
	if existing, ok := ensureDefaultPolicyLocks.Load(tenantID); ok {
		return existing.(*sync.Mutex)
	}
	actual, _ := ensureDefaultPolicyLocks.LoadOrStore(tenantID, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// ensureDefaultPolicy seeds the out-of-the-box deterministic guardrail policy
// (PII + regex on input/output) the first time a tenant has none, so the
// Policies page is populated on first visit rather than after the first inference
// request. Idempotent, best-effort, and concurrency-safe: a per-tenant lock
// guards the check-then-create so concurrent dashboard loads (and the startup
// seed) never produce duplicate "Default Protection" rows, and the page never
// needs multiple refreshes. Scoped to the caller's tenant via the request
// context (empty tenant in the single-tenant OSS build).
func (h *GuardrailsHandler) ensureDefaultPolicy(ctx context.Context) {
	if h == nil {
		return
	}
	lock := ensureDefaultPolicyLockFor(tenantIDFromStoreContext(ctx))
	lock.Lock()
	defer lock.Unlock()
	h.seedDefaultPolicyLocked(ctx)
}

// seedDefaultPolicyLocked performs the check-then-create under the caller's
// already-held per-tenant lock. Callers that don't already hold the lock must
// use ensureDefaultPolicy.
func (h *GuardrailsHandler) seedDefaultPolicyLocked(ctx context.Context) {
	existing, err := h.configStore.ListGuardrailPolicies(ctx)
	if err != nil {
		return
	}
	for i := range existing {
		if !strings.EqualFold(strings.TrimSpace(existing[i].Scope), tables.GuardrailPolicyScopeRAG) {
			return // a real policy already exists
		}
	}
	now := time.Now().UTC()
	policy := &tables.TableGuardrailPolicy{
		ID:              uuid.NewString(),
		Name:            "Default Protection",
		Description:     "Deterministic PII / regex / content-policy checks on prompts, responses, and tool I/O.",
		Scope:           tables.GuardrailPolicyScopeInput,
		EnforcementMode: "block",
		ExecutionMode:   tables.GuardrailExecutionModeSync,
		TimeoutMs:       3000,
		Enabled:         true,
		IsDefault:       true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := h.configStore.CreateGuardrailPolicy(ctx, policy); err != nil {
		return
	}
	published := now
	version := &tables.TableGuardrailPolicyVersion{
		ID:          uuid.NewString(),
		PolicyID:    policy.ID,
		Version:     1,
		Status:      tables.GuardrailPolicyVersionStatusPublished,
		Definition:  defaultGuardRuntimeDefinition("input"),
		PublishedBy: "system",
		PublishedAt: &published,
		CreatedAt:   now,
	}
	_ = h.configStore.CreateGuardrailPolicyVersion(ctx, version)
	// Push the freshly-seeded policy into the runtime engine's tenant bundle
	// so an inference request that arrives immediately after startup (before
	// the plugin's own lazy hydration TTL kicks in) sees it.
	_ = h.hydrateRuntimeTenant(ctx)
}

// EnsureDefaultPolicyAtStartup seeds the deterministic default guardrail policy
// for the inference tenant at server bootstrap so the guardrails plugin's
// tenantHasEnabledPolicies check is satisfied from the very first request - PII
// is redacted/blocked and analytics populate without anyone opening the config
// page first. Uses an empty (single-tenant) store context, which is the exact
// partition the OSS inference path resolves (the VK carries no tenant_id and
// GetSingleTenantID returns empty when there's no dashboard user), so one
// default policy serves both the inference path and the config page. Idempotent
// and concurrency-safe via the same per-tenant lock the config page uses.
func (h *GuardrailsHandler) EnsureDefaultPolicyAtStartup(ctx context.Context) {
	if h == nil {
		return
	}
	storeCtx := h.defaultSeedContext(ctx)
	lock := ensureDefaultPolicyLockFor(tenantIDFromStoreContext(storeCtx))
	lock.Lock()
	defer lock.Unlock()
	h.seedDefaultPolicyLocked(storeCtx)
}

// defaultSeedContext resolves the store context the startup seed should write
// under. In the single-tenant OSS build GetSingleTenantID returns "" (no
// dashboard user), so we seed under the empty-tenant partition that the
// inference path reads. If a single canonical tenant DOES exist (commercial
// single-tenant deploys), stamp it so the seeded policy lands in that tenant's
// partition and the inference path - which resolves the same tenant - finds it.
func (h *GuardrailsHandler) defaultSeedContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if resolver, ok := h.configStore.(interface {
		GetSingleTenantID(context.Context) (string, error)
	}); ok {
		if id, err := resolver.GetSingleTenantID(ctx); err == nil {
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				return context.WithValue(ctx, schemas.DeepIntShieldContextKeyTenantID, trimmed)
			}
		}
	}
	return ctx
}

func (h *GuardrailsHandler) listPolicies(ctx *fasthttp.RequestCtx) {
	// Pre-populate the default policy on first visit so the page is never empty.
	h.ensureDefaultPolicy(auditStoreContext(ctx))
	policies, err := h.configStore.ListGuardrailPolicies(auditStoreContext(ctx))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policies: %v", err))
		return
	}
	// Filter out scope="rag" entries. RAG policies share the same
	// guardrail_policies table as a persistence convenience but they
	// don't carry the regular policy shape (`_deepintshield_builder.
	// selected_cards`, `domain_pack_id`, etc.) the Policies page expects.
	// Without this filter the dashboard's policies route crashes with
	// "Something went wrong" the moment a RAG policy is created. The
	// RAG Security console lists those rows via /api/rag-security/policies.
	filtered := policies[:0]
	for i := range policies {
		if strings.EqualFold(strings.TrimSpace(policies[i].Scope), tables.GuardrailPolicyScopeRAG) {
			continue
		}
		filtered = append(filtered, policies[i])
	}
	policies = filtered
	versionIndex, err := h.guardrailVersionIndex(auditStoreContext(ctx), policies)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load policy versions: %v", err))
		return
	}
	responses := make([]guardrailPolicyResponse, 0, len(policies))
	for i := range policies {
		responses = append(responses, buildGuardrailPolicyResponse(&policies[i], versionIndex[policies[i].ID]))
	}
	SendJSON(ctx, map[string]any{"policies": responses})
}

func (h *GuardrailsHandler) createPolicy(ctx *fasthttp.RequestCtx) {
	if !h.requireGuardrailWrite(ctx) {
		return
	}
	var payload guardrailPolicyPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail policy payload")
		return
	}

	// Plan-tier gates on policy *content*. Creating a deterministic policy
	// (regex_match / detect_pii / content checks) is open to every tier; what
	// is gated are the premium content surfaces:
	//   - in-tree ML detectors (DeBERTa / RoBERTa / BERT)  -> InTreeML
	//   - hand-authored custom guardrail cards             -> CustomCard
	//   - the vertical domain packs (BFSI / Healthcare ...)-> DomainPacks
	// These are enforced UNCONDITIONALLY (org may be nil): the OSS Enforcer
	// denies these keys with a FeatureLockedError so a hand-crafted curl can't
	// smuggle a premium card past the UI by dropping tenant context. Commercial
	// builds always resolve an org, so plan-aware behaviour is unchanged.
	gateOrg := h.resolveOrgForGating(ctx)
	enforcePolicyFeature := func(featureKey string) bool {
		if err := entitlements.EnforceFeature(ctx, h.configStore.DB(), gateOrg, featureKey); err != nil {
			if fe, ok := err.(*entitlements.FeatureLockedError); ok {
				sendFeatureLocked(ctx, fe)
				return false
			}
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return false
		}
		return true
	}
	if usesInTreeMLDetector(payload) {
		if !enforcePolicyFeature(entitlements.FeatureGuardrailsInTreeML) {
			return
		}
	}
	if usesCustomCard(payload) {
		if !enforcePolicyFeature(entitlements.FeatureGuardrailsCustomCard) {
			return
		}
	}
	if usesDomainPack(payload) {
		if !enforcePolicyFeature(entitlements.FeatureGuardrailsDomainPacks) {
			return
		}
	}
	metadata := normalizeGuardrailPolicyMetadata(payload.Metadata, payload.Scope, payload.Scopes)
	executionMode := normalizeGuardrailExecutionMode(payload.ExecutionMode)
	if executionMode == tables.GuardrailExecutionModeAsync && policyDefinitionContainsEnforcementClass(payload.InitialDefinition) {
		SendError(ctx, fasthttp.StatusBadRequest,
			"Async execution mode is not allowed for policies that include enforcement-class checks (prompt injection, PII/secrets, poisoning, output handling, system prompt leakage). Use sync or shadow instead.")
		return
	}
	shadowUntil := normalizeGuardrailShadowUntil(executionMode, payload.ShadowUntil)
	// Policy scope: tenant-wide (workspace_id = NULL) when the caller
	// flips ApplyToAllWorkspaces; otherwise stamp the active workspace
	// from the dashboard's scope switcher (X-Active-Workspace-Id header)
	// so the policy is only visible to that workspace. If the caller
	// asked for workspace-scoped but didn't supply a workspace context,
	// fail loudly - the previous silent fallback to tenant-wide caused
	// the UI's "Apply to all workspaces" toggle to re-tick after save.
	var policyWorkspaceID *string
	if !payload.ApplyToAllWorkspaces {
		ws := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx))
		if ws == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "Workspace context required to create a workspace-scoped policy. Switch to a workspace or enable \"Apply to all workspaces\".")
			return
		}
		policyWorkspaceID = &ws
	}
	policy := &tables.TableGuardrailPolicy{
		ID:              uuid.NewString(),
		WorkspaceID:     policyWorkspaceID,
		Name:            payload.Name,
		Description:     payload.Description,
		DomainPackID:    payload.DomainPackID,
		Scope:           guardrailPrimaryScope(payload.Scope, metadata),
		EnforcementMode: normalizeGuardrailEnforcementMode(payload.EnforcementMode),
		ExecutionMode:   executionMode,
		ShadowUntil:     shadowUntil,
		SamplingRate:    payload.SamplingRate,
		TimeoutMs:       payload.TimeoutMs,
		Enabled:         payload.Enabled,
		IsDefault:       false,
		Metadata:        metadata,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	if err := h.configStore.CreateGuardrailPolicy(auditStoreContext(ctx), policy); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create guardrail policy: %v", err))
		return
	}
	initialDefinition := payload.InitialDefinition
	if len(initialDefinition) == 0 {
		initialDefinition = h.resolveInitialPolicyDefinition(auditStoreContext(ctx), payload.DomainPackID, policy.Scope)
	}
	version := &tables.TableGuardrailPolicyVersion{
		ID:         uuid.NewString(),
		PolicyID:   policy.ID,
		Version:    1,
		Status:     tables.GuardrailPolicyVersionStatusDraft,
		Definition: initialDefinition,
		CreatedAt:  time.Now().UTC(),
	}
	if err := h.configStore.CreateGuardrailPolicyVersion(auditStoreContext(ctx), version); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create initial guardrail policy version: %v", err))
		return
	}
	saved, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), policy.ID)
	if err != nil || saved == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail policy")
		return
	}
	responses, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), policy.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail policy versions")
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSONWithStatus(ctx, buildGuardrailPolicyResponse(saved, responses), fasthttp.StatusCreated)
}

func (h *GuardrailsHandler) getPolicyByID(ctx *fasthttp.RequestCtx) {
	policy, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), stringValue(ctx.UserValue("id")))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy: %v", err))
		return
	}
	if policy == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail policy not found")
		return
	}
	versions, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), policy.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy versions: %v", err))
		return
	}
	SendJSON(ctx, buildGuardrailPolicyResponse(policy, versions))
}

func (h *GuardrailsHandler) updatePolicyByID(ctx *fasthttp.RequestCtx) {
	if !h.requireGuardrailWrite(ctx) {
		return
	}
	var payload guardrailPolicyPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail policy payload")
		return
	}
	existing, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), stringValue(ctx.UserValue("id")))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy: %v", err))
		return
	}
	if existing == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail policy not found")
		return
	}
	executionMode := normalizeGuardrailExecutionMode(payload.ExecutionMode)
	if executionMode == tables.GuardrailExecutionModeAsync {
		// Update path: the user might be flipping mode without
		// touching the definition. Fetch the active version's
		// definition (if any) and validate against it. If the
		// policy has no version yet, fall back to the explicit
		// initial_definition the caller may have passed.
		var defToCheck map[string]any = payload.InitialDefinition
		if existing.ActiveVersionID != nil && strings.TrimSpace(*existing.ActiveVersionID) != "" {
			if version, vErr := h.configStore.GetGuardrailPolicyVersion(auditStoreContext(ctx), *existing.ActiveVersionID); vErr == nil && version != nil && len(version.Definition) > 0 {
				defToCheck = version.Definition
			}
		}
		if policyDefinitionContainsEnforcementClass(defToCheck) {
			SendError(ctx, fasthttp.StatusBadRequest,
				"Async execution mode is not allowed for policies that include enforcement-class checks (prompt injection, PII/secrets, poisoning, output handling, system prompt leakage). Use sync or shadow instead.")
			return
		}
	}
	existing.Name = payload.Name
	existing.Description = payload.Description
	existing.DomainPackID = payload.DomainPackID
	existing.Metadata = normalizeGuardrailPolicyMetadata(payload.Metadata, payload.Scope, payload.Scopes)
	existing.Scope = guardrailPrimaryScope(payload.Scope, existing.Metadata)
	existing.EnforcementMode = normalizeGuardrailEnforcementMode(payload.EnforcementMode)
	existing.ExecutionMode = executionMode
	existing.ShadowUntil = normalizeGuardrailShadowUntil(executionMode, payload.ShadowUntil)
	existing.SamplingRate = payload.SamplingRate
	existing.TimeoutMs = payload.TimeoutMs
	existing.Enabled = payload.Enabled
	// Toggle the policy's scope. ApplyToAllWorkspaces=true → workspace_id
	// NULL. False → pin to the request's active workspace. If the caller
	// asked for workspace-scoped but supplied no workspace header AND the
	// row is currently tenant-wide, fail loudly - silently leaving the
	// row as tenant-wide caused the UI's "Apply to all workspaces" toggle
	// to re-tick after save. When the row is already workspace-scoped and
	// no header is present (SDK / config caller), preserve the existing
	// workspace_id so we don't accidentally widen the scope.
	if payload.ApplyToAllWorkspaces {
		existing.WorkspaceID = nil
	} else {
		ws := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx))
		if ws != "" {
			existing.WorkspaceID = &ws
		} else if existing.WorkspaceID == nil {
			SendError(ctx, fasthttp.StatusBadRequest, "Workspace context required to update this policy as workspace-scoped. Switch to a workspace or enable \"Apply to all workspaces\".")
			return
		}
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := h.configStore.UpdateGuardrailPolicy(auditStoreContext(ctx), existing); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update guardrail policy: %v", err))
		return
	}
	versions, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), existing.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail policy versions")
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSON(ctx, buildGuardrailPolicyResponse(existing, versions))
}

func (h *GuardrailsHandler) setDefaultPolicyByID(ctx *fasthttp.RequestCtx) {
	policyID := strings.TrimSpace(stringValue(ctx.UserValue("id")))
	if policyID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Guardrail policy id is required")
		return
	}
	if err := h.configStore.SetDefaultGuardrailPolicy(auditStoreContext(ctx), policyID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to set default guardrail policy: %v", err))
		return
	}
	policy, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to reload guardrail policy: %v", err))
		return
	}
	if policy == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail policy not found")
		return
	}
	versions, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), policy.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail policy versions")
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSON(ctx, buildGuardrailPolicyResponse(policy, versions))
}

func (h *GuardrailsHandler) deletePolicyByID(ctx *fasthttp.RequestCtx) {
	if !h.requireGuardrailWrite(ctx) {
		return
	}
	if err := h.configStore.DeleteGuardrailPolicy(auditStoreContext(ctx), stringValue(ctx.UserValue("id"))); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete guardrail policy: %v", err))
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSON(ctx, map[string]string{"message": "Guardrail policy deleted"})
}

func (h *GuardrailsHandler) listMCPToolPoliciesByPolicyID(ctx *fasthttp.RequestCtx) {
	policyID := stringValue(ctx.UserValue("id"))
	policy, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy: %v", err))
		return
	}
	if policy == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail policy not found")
		return
	}
	policies, err := h.configStore.ListGuardrailMCPToolPolicies(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load MCP tool policies: %v", err))
		return
	}
	responses := make([]guardrailMCPToolPolicyResponse, 0, len(policies))
	for i := range policies {
		responses = append(responses, buildGuardrailMCPToolPolicyResponse(&policies[i]))
	}
	SendJSON(ctx, map[string]any{"tool_policies": responses})
}

func (h *GuardrailsHandler) replaceMCPToolPoliciesByPolicyID(ctx *fasthttp.RequestCtx) {
	// Plan-tier gate: MCP Security tool-policy editing is Team+ only.
	if org := h.resolveOrgForGating(ctx); org != nil {
		if err := entitlements.EnforceFeature(ctx, h.configStore.DB(), org, entitlements.FeatureGuardrailsMCPSecurity); err != nil {
			if fe, ok := err.(*entitlements.FeatureLockedError); ok {
				sendFeatureLocked(ctx, fe)
				return
			}
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
	}

	policyID := stringValue(ctx.UserValue("id"))
	policy, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy: %v", err))
		return
	}
	if policy == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail policy not found")
		return
	}

	var payload guardrailMCPToolPoliciesPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid MCP tool policy payload")
		return
	}

	now := time.Now().UTC()
	nextPolicies := make([]tables.TableGuardrailMCPToolPolicy, 0, len(payload.ToolPolicies))
	for _, rawPolicy := range payload.ToolPolicies {
		serverLabel := strings.TrimSpace(rawPolicy.ServerLabel)
		toolName := strings.TrimSpace(rawPolicy.ToolName)
		actionClass := strings.TrimSpace(rawPolicy.ActionClass)
		if serverLabel == "" && toolName == "" && actionClass == "" {
			continue
		}
		nextPolicies = append(nextPolicies, tables.TableGuardrailMCPToolPolicy{
			ID:                strings.TrimSpace(rawPolicy.ID),
			PolicyID:          policyID,
			ServerLabel:       serverLabel,
			ToolName:          toolName,
			ActionClass:       actionClass,
			ApprovalNeeded:    rawPolicy.RestrictedAction,
			AllowedDomains:    rawPolicy.AllowedDomains,
			AllowedIdentities: rawPolicy.AllowedIdentities,
			CreatedAt:         now,
			UpdatedAt:         now,
		})
	}

	if err := h.configStore.ReplaceGuardrailMCPToolPolicies(auditStoreContext(ctx), policyID, nextPolicies); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update MCP tool policies: %v", err))
		return
	}

	updatedPolicies, err := h.configStore.ListGuardrailMCPToolPolicies(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to reload MCP tool policies: %v", err))
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))

	responses := make([]guardrailMCPToolPolicyResponse, 0, len(updatedPolicies))
	for i := range updatedPolicies {
		responses = append(responses, buildGuardrailMCPToolPolicyResponse(&updatedPolicies[i]))
	}
	SendJSON(ctx, map[string]any{"tool_policies": responses})
}

func (h *GuardrailsHandler) listPolicyVersions(ctx *fasthttp.RequestCtx) {
	versions, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), stringValue(ctx.UserValue("id")))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy versions: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{"versions": versions})
}

func (h *GuardrailsHandler) createPolicyVersion(ctx *fasthttp.RequestCtx) {
	var payload guardrailPolicyVersionPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail policy version payload")
		return
	}
	policyID := strings.TrimSpace(stringValue(ctx.UserValue("id")))
	policy, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load guardrail policy: %v", err))
		return
	}
	if policy == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Guardrail policy not found")
		return
	}
	versions, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), policyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load existing policy versions: %v", err))
		return
	}
	nextVersion := 1
	for _, version := range versions {
		if version.Version >= nextVersion {
			nextVersion = version.Version + 1
		}
	}
	version := &tables.TableGuardrailPolicyVersion{
		ID:         uuid.NewString(),
		PolicyID:   policyID,
		Version:    nextVersion,
		Status:     tables.GuardrailPolicyVersionStatusDraft,
		Definition: payload.Definition,
		CreatedAt:  time.Now().UTC(),
	}
	if err := h.configStore.CreateGuardrailPolicyVersion(auditStoreContext(ctx), version); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create guardrail policy version: %v", err))
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSONWithStatus(ctx, version, fasthttp.StatusCreated)
}

func (h *GuardrailsHandler) publishPolicyVersion(ctx *fasthttp.RequestCtx) {
	h.changePolicyVersionState(ctx, false)
}

func (h *GuardrailsHandler) rollbackPolicyVersion(ctx *fasthttp.RequestCtx) {
	h.changePolicyVersionState(ctx, true)
}

func (h *GuardrailsHandler) changePolicyVersionState(ctx *fasthttp.RequestCtx, rollback bool) {
	var payload guardrailPublishPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail publish payload")
		return
	}
	policyID := strings.TrimSpace(stringValue(ctx.UserValue("id")))
	if strings.TrimSpace(payload.VersionID) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "version_id is required")
		return
	}
	if rollback {
		payload.PublishedBy = strings.TrimSpace(payload.PublishedBy)
		if payload.PublishedBy == "" {
			payload.PublishedBy = "rollback"
		}
	}
	if err := h.configStore.PublishGuardrailPolicyVersion(auditStoreContext(ctx), policyID, payload.VersionID, payload.PublishedBy); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to publish guardrail policy version: %v", err))
		return
	}
	policy, err := h.configStore.GetGuardrailPolicy(auditStoreContext(ctx), policyID)
	if err != nil || policy == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail policy")
		return
	}
	versions, err := h.configStore.ListGuardrailPolicyVersions(auditStoreContext(ctx), policy.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to reload guardrail policy versions")
		return
	}
	_ = h.hydrateRuntimeTenant(auditStoreContext(ctx))
	SendJSON(ctx, buildGuardrailPolicyResponse(policy, versions))
}

// NOTE: listDomainPacks (GET /api/guardrails/domain-packs) and its
// ensureBuiltinDomainPacks seeding helper are removed from the OSS build. The
// vertical domain packs are a Cloud/Enterprise capability gated behind
// FeatureGuardrailsDomainPacks; OSS neither serves them nor seeds them into the
// config store. builtinGuardrailDomainPacks / ensureBuiltinDomainPacks are kept
// (unreferenced) so a commercial build can re-wire the surface without porting
// the pack catalog back.

// parseGuardrailWindow reads an optional RFC3339 time window from the query.
// Accepts since/until (used by the analytics screens) or start_time/end_time
// (used by the latency endpoint) - either form works. Nil ⇒ no bound.
func parseGuardrailWindow(ctx *fasthttp.RequestCtx) (*time.Time, *time.Time) {
	parse := func(keys ...string) *time.Time {
		for _, k := range keys {
			if raw := strings.TrimSpace(string(ctx.QueryArgs().Peek(k))); raw != "" {
				if t, err := time.Parse(time.RFC3339, raw); err == nil {
					return &t
				}
			}
		}
		return nil
	}
	return parse("since", "start_time"), parse("until", "end_time")
}

func (h *GuardrailsHandler) listFindings(ctx *fasthttp.RequestCtx) {
	filters := logstore.GuardrailFindingFilters{
		RequestID: string(ctx.QueryArgs().Peek("request_id")),
		PolicyID:  string(ctx.QueryArgs().Peek("policy_id")),
		Stage:     string(ctx.QueryArgs().Peek("stage")),
		Severity:  string(ctx.QueryArgs().Peek("severity")),
		Outcome:   string(ctx.QueryArgs().Peek("outcome")),
		Query:     string(ctx.QueryArgs().Peek("query")),
		Source:    string(ctx.QueryArgs().Peek("source")),
	}
	filters.StartTime, filters.EndTime = parseGuardrailWindow(ctx)
	limit := parseIntOrDefault(string(ctx.QueryArgs().Peek("limit")), 100)
	offset := parseIntOrDefault(string(ctx.QueryArgs().Peek("offset")), 0)
	findings, total, err := h.evidenceStore.ListGuardrailFindings(auditStoreContext(ctx), filters, limit, offset)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load runtime findings: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{"findings": findings, "total_count": total})
}

// getMetricsStats serves the server-aggregated Guardrail Metrics headline
// figures (true counts + stage/severity/policy/timeline distributions over the
// FULL window). The page used to derive these from a 5,000-row client window,
// which capped the counts and dropped older rows (the dominant action stage).
func (h *GuardrailsHandler) getMetricsStats(ctx *fasthttp.RequestCtx) {
	since, until := parseGuardrailWindow(ctx)
	bucket := int64(parseIntOrDefault(string(ctx.QueryArgs().Peek("bucket")), 3600))
	stats, err := h.evidenceStore.AggregateGuardrailMetrics(auditStoreContext(ctx), since, until, bucket)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to aggregate guardrail metrics: %v", err))
		return
	}
	SendJSON(ctx, stats)
}

func (h *GuardrailsHandler) listTraces(ctx *fasthttp.RequestCtx) {
	filters := logstore.GuardrailTraceFilters{
		RequestID: string(ctx.QueryArgs().Peek("request_id")),
		Stage:     string(ctx.QueryArgs().Peek("stage")),
		Decision:  string(ctx.QueryArgs().Peek("decision")),
		ActorType: string(ctx.QueryArgs().Peek("actor_type")),
		Query:     string(ctx.QueryArgs().Peek("query")),
	}
	filters.StartTime, filters.EndTime = parseGuardrailWindow(ctx)
	limit := parseIntOrDefault(string(ctx.QueryArgs().Peek("limit")), 100)
	offset := parseIntOrDefault(string(ctx.QueryArgs().Peek("offset")), 0)
	traces, total, err := h.evidenceStore.ListGuardrailTraces(auditStoreContext(ctx), filters, limit, offset)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load traces: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{"traces": traces, "total_count": total})
}

func (h *GuardrailsHandler) runSimulation(ctx *fasthttp.RequestCtx) {
	var payload guardrailSimulationPayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid simulation payload")
		return
	}
	storeCtx := auditStoreContext(ctx)
	if err := h.hydrateRuntimeTenant(storeCtx); err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Failed to hydrate runtime tenant bundle: %v", err))
		return
	}
	policies, err := h.resolveSimulationPolicies(storeCtx, payload.PolicyIDs, payload.Stage)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to resolve policies: %v", err))
		return
	}
	if inlinePolicies := buildSimulationInlinePolicies(&payload); len(inlinePolicies) > 0 {
		if strings.EqualFold(strings.TrimSpace(payload.InlineMode), "replace") {
			policies = inlinePolicies
		} else {
			policies = append(inlinePolicies, policies...)
		}
	}
	requestID := uuid.NewString()
	runtimeRequest := &guardRuntimeEvaluateRequest{
		TenantID:  tenantIDFromStoreContext(storeCtx),
		RequestID: requestID,
		Stage:     strings.TrimSpace(payload.Stage),
		Model:     payload.Model,
		Provider:  payload.Provider,
		Actor: guardRuntimeActor{
			Type: payload.ActorType,
			ID:   payload.ActorID,
			Role: payload.ActorRole,
		},
		Content: guardRuntimeContent{
			Input:     payload.Input,
			Output:    payload.Output,
			ToolInput: payload.ToolInput,
		},
		Policies: policies,
		Metadata: payload.Metadata,
	}
	if strings.TrimSpace(payload.ToolName) != "" || strings.TrimSpace(payload.ServerLabel) != "" || strings.TrimSpace(payload.ActionClass) != "" || len(payload.Domains) > 0 {
		runtimeRequest.MCP = &guardRuntimeMCPContext{
			ServerLabel: payload.ServerLabel,
			ToolName:    payload.ToolName,
			ActionClass: payload.ActionClass,
			Domains:     payload.Domains,
		}
	}

	result, err := h.evaluateGuardRuntime(storeCtx, runtimeRequest)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to run runtime simulation: %v", err))
		return
	}

	trace := logstore.GuardrailTrace{
		ID:            uuid.NewString(),
		RequestID:     requestID,
		Stage:         payload.Stage,
		ActorType:     payload.ActorType,
		ActorID:       payload.ActorID,
		Model:         payload.Model,
		Provider:      payload.Provider,
		InputSummary:  strings.TrimSpace(payload.Input),
		OutputSummary: strings.TrimSpace(payload.Output),
		Decision:      result.Decision,
		DecisionChain: result.DecisionChain,
		Metadata: map[string]any{
			"stage":        payload.Stage,
			"tool_name":    payload.ToolName,
			"server_label": payload.ServerLabel,
			"action_class": payload.ActionClass,
			"domains":      payload.Domains,
		},
	}
	if err := h.evidenceStore.CreateGuardrailTrace(storeCtx, &trace); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist guardrail trace: %v", err))
		return
	}
	decision := logstore.GuardrailDecision{
		ID:               uuid.NewString(),
		RequestID:        requestID,
		TraceID:          trace.ID,
		Stage:            payload.Stage,
		Decision:         result.Decision,
		Reason:           result.Reason,
		ApprovalRequired: result.ApprovalRequired,
		LatencyMs:        result.LatencyMs,
		Redactions:       result.Redactions,
		DecisionChain:    result.DecisionChain,
	}
	if len(policies) > 0 {
		decision.PolicyID = policies[0].PolicyID
		decision.PolicyVersionID = policies[0].PolicyVersionID
	}
	if err := h.evidenceStore.CreateGuardrailDecision(storeCtx, &decision); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist guardrail decision: %v", err))
		return
	}

	findings := make([]logstore.GuardrailFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		persisted := logstore.GuardrailFinding{
			ID:              uuid.NewString(),
			RequestID:       requestID,
			TraceID:         trace.ID,
			Stage:           payload.Stage,
			PolicyID:        finding.PolicyID,
			PolicyVersionID: finding.PolicyVersionID,
			Category:        finding.Category,
			Severity:        finding.Severity,
			Confidence:      finding.Confidence,
			Outcome:         finding.Outcome,
			Summary:         finding.Summary,
			ActorType:       payload.ActorType,
			ActorID:         payload.ActorID,
			ResourceType:    payload.ActionClass,
			ResourceID:      payload.ToolName,
			Details:         finding.Details,
		}
		if err := h.evidenceStore.CreateGuardrailFinding(storeCtx, &persisted); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist runtime finding: %v", err))
			return
		}
		findings = append(findings, persisted)
	}

	SendJSONWithStatus(ctx, guardrailSimulationResponse{
		Trace:    trace,
		Decision: decision,
		Findings: findings,
		Result:   result,
	}, fasthttp.StatusCreated)
}

func (h *GuardrailsHandler) evaluatePolicyRuntime(ctx *fasthttp.RequestCtx) {
	var payload guardrailEvaluatePayload
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid guardrail evaluate payload")
		return
	}

	stage := strings.ToLower(strings.TrimSpace(payload.Stage))
	switch stage {
	case tables.GuardrailPolicyScopeOutput, tables.GuardrailPolicyScopeAction, tables.GuardrailPolicyScopeMCP, tables.GuardrailPolicyScopeRAG:
	default:
		stage = tables.GuardrailPolicyScopeInput
	}

	storeCtx := auditStoreContext(ctx)
	if err := h.hydrateRuntimeTenant(storeCtx); err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Failed to hydrate runtime tenant bundle: %v", err))
		return
	}
	policies, err := h.resolveSimulationPolicies(storeCtx, nil, stage)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to resolve policies: %v", err))
		return
	}

	metadata := cloneRuntimeMetadata(payload.Metadata)
	if metadata == nil {
		metadata = make(map[string]any, 8)
	}
	if appName := strings.TrimSpace(payload.AppName); appName != "" {
		metadata["app_name"] = appName
	}
	if agentName := strings.TrimSpace(payload.AgentName); agentName != "" {
		metadata["agent_name"] = agentName
	}

	requestID := uuid.NewString()
	runtimeRequest := &guardRuntimeEvaluateRequest{
		TenantID:  tenantIDFromStoreContext(storeCtx),
		RequestID: requestID,
		Stage:     stage,
		Model:     strings.TrimSpace(payload.Model),
		Provider:  strings.TrimSpace(payload.Provider),
		Actor: guardRuntimeActor{
			Type:       defaultString(strings.TrimSpace(payload.ActorType), "sdk_user"),
			ID:         defaultString(strings.TrimSpace(payload.ActorID), "sdk-user"),
			Role:       strings.TrimSpace(payload.ActorRole),
			CustomerID: strings.TrimSpace(payload.ActorCustomerID),
			TeamID:     strings.TrimSpace(payload.ActorTeamID),
		},
		Content: guardRuntimeContent{
			Input:     payload.Input,
			Output:    payload.Output,
			ToolInput: payload.ToolInput,
		},
		Policies: policies,
		Metadata: metadata,
	}
	if strings.TrimSpace(payload.ToolName) != "" || strings.TrimSpace(payload.ServerLabel) != "" || strings.TrimSpace(payload.ActionClass) != "" || len(payload.Domains) > 0 {
		runtimeRequest.MCP = &guardRuntimeMCPContext{
			ServerLabel: payload.ServerLabel,
			ToolName:    payload.ToolName,
			ActionClass: payload.ActionClass,
			Domains:     payload.Domains,
		}
	}

	result, err := h.evaluateGuardRuntime(storeCtx, runtimeRequest)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to evaluate guardrail runtime: %v", err))
		return
	}

	traceMetadata := mergeAnyMaps(metadata, map[string]any{
		"stage":             stage,
		"actor_role":        runtimeRequest.Actor.Role,
		"actor_customer_id": runtimeRequest.Actor.CustomerID,
		"actor_team_id":     runtimeRequest.Actor.TeamID,
		"tool_name":         strings.TrimSpace(payload.ToolName),
		"server_label":      strings.TrimSpace(payload.ServerLabel),
		"action_class":      strings.TrimSpace(payload.ActionClass),
		"domains":           append([]string(nil), payload.Domains...),
	})

	contentSummary := strings.TrimSpace(payload.Input)
	if contentSummary == "" {
		contentSummary = strings.TrimSpace(payload.ToolInput)
	}
	trace := logstore.GuardrailTrace{
		ID:            uuid.NewString(),
		RequestID:     requestID,
		Stage:         stage,
		ActorType:     runtimeRequest.Actor.Type,
		ActorID:       runtimeRequest.Actor.ID,
		Model:         runtimeRequest.Model,
		Provider:      runtimeRequest.Provider,
		InputSummary:  truncateGuardrailText(contentSummary, 2000),
		OutputSummary: truncateGuardrailText(strings.TrimSpace(payload.Output), 2000),
		Decision:      result.Decision,
		DecisionChain: append([]string(nil), result.DecisionChain...),
		Metadata:      traceMetadata,
	}
	decision := logstore.GuardrailDecision{
		ID:               uuid.NewString(),
		RequestID:        requestID,
		TraceID:          trace.ID,
		Stage:            stage,
		Decision:         result.Decision,
		Reason:           truncateGuardrailText(result.Reason, 2000),
		ApprovalRequired: result.ApprovalRequired,
		LatencyMs:        result.LatencyMs,
		Redactions:       append([]string(nil), result.Redactions...),
		DecisionChain:    append([]string(nil), result.DecisionChain...),
	}
	if len(result.Findings) > 0 {
		decision.PolicyID = result.Findings[0].PolicyID
		decision.PolicyVersionID = result.Findings[0].PolicyVersionID
	} else if len(policies) > 0 {
		decision.PolicyID = policies[0].PolicyID
		decision.PolicyVersionID = policies[0].PolicyVersionID
	}

	findings := make([]logstore.GuardrailFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		findings = append(findings, logstore.GuardrailFinding{
			ID:              uuid.NewString(),
			RequestID:       requestID,
			TraceID:         trace.ID,
			Stage:           stage,
			PolicyID:        finding.PolicyID,
			PolicyVersionID: finding.PolicyVersionID,
			ProviderID:      finding.ProviderID,
			Category:        finding.Category,
			Severity:        finding.Severity,
			Confidence:      finding.Confidence,
			Outcome:         finding.Outcome,
			Summary:         truncateGuardrailText(finding.Summary, 2000),
			ActorType:       runtimeRequest.Actor.Type,
			ActorID:         runtimeRequest.Actor.ID,
			ResourceType:    defaultString(strings.TrimSpace(payload.ActionClass), stage),
			ResourceID:      defaultString(strings.TrimSpace(payload.ToolName), strings.TrimSpace(payload.ServerLabel)),
			Details:         cloneRuntimeMetadata(finding.Details),
		})
	}

	persist := payload.Persist == nil || *payload.Persist
	if persist {
		if err := h.evidenceStore.CreateGuardrailTrace(storeCtx, &trace); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist guardrail trace: %v", err))
			return
		}
		if err := h.evidenceStore.CreateGuardrailDecision(storeCtx, &decision); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist guardrail decision: %v", err))
			return
		}
		for i := range findings {
			if err := h.evidenceStore.CreateGuardrailFinding(storeCtx, &findings[i]); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist guardrail finding: %v", err))
				return
			}
		}
	}

	SendJSON(ctx, guardrailSimulationResponse{
		Trace:    trace,
		Decision: decision,
		Findings: findings,
		Result:   result,
	})
}

func (h *GuardrailsHandler) evaluateGuardRuntime(ctx context.Context, request *guardRuntimeEvaluateRequest) (*guardRuntimeEvaluateResponse, error) {
	if h.runtimeClient != nil {
		response, err := h.runtimeClient.Evaluate(ctx, request)
		if err == nil && response != nil {
			return response, nil
		}
	}
	if h.embeddedRuntime != nil {
		response, err := h.embeddedRuntime.Evaluate(ctx, request)
		if err == nil && response != nil {
			return response, nil
		}
	}
	return evaluateGuardRuntimeLocally(request), nil
}

func buildGuardrailProviderResponse(provider *tables.TableGuardrailProvider) guardrailProviderResponse {
	response := guardrailProviderResponse{
		ID:             provider.ID,
		Name:           provider.Name,
		ProviderType:   provider.ProviderType,
		Mode:           provider.Mode,
		CustomerID:     provider.CustomerID,
		Enabled:        provider.Enabled,
		Region:         provider.Region,
		Endpoint:       provider.Endpoint,
		ConnectionMeta: provider.ConnectionMeta,
		CredentialsSet: len(provider.Credentials) > 0 || strings.TrimSpace(provider.CredentialsJSON) != "",
		LastTestedAt:   provider.LastTestedAt,
		LastError:      provider.LastError,
		CreatedAt:      provider.CreatedAt,
		UpdatedAt:      provider.UpdatedAt,
	}
	keys := make([]string, 0, len(provider.Credentials))
	for key := range provider.Credentials {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	response.CredentialKeys = keys
	return response
}

func providerFromPayload(payload *guardrailProviderPayload, existing *tables.TableGuardrailProvider) *tables.TableGuardrailProvider {
	provider := &tables.TableGuardrailProvider{}
	if existing != nil {
		*provider = *existing
	}
	provider.Name = payload.Name
	provider.ProviderType = payload.ProviderType
	provider.Mode = payload.Mode
	provider.CustomerID = payload.CustomerID
	provider.Enabled = payload.Enabled
	provider.Region = payload.Region
	provider.Endpoint = payload.Endpoint
	if payload.ConnectionMeta != nil {
		provider.ConnectionMeta = payload.ConnectionMeta
	}
	if payload.Credentials != nil {
		provider.Credentials = payload.Credentials
	}
	provider.UpdatedAt = time.Now().UTC()
	return provider
}

func validateGuardrailProvider(provider *tables.TableGuardrailProvider) ([]string, []string) {
	missing := make([]string, 0, 4)
	warnings := make([]string, 0, 2)
	if strings.TrimSpace(provider.Name) == "" {
		missing = append(missing, "name")
	}
	if strings.TrimSpace(provider.ProviderType) == "" {
		missing = append(missing, "provider_type")
	}
	if strings.TrimSpace(provider.Mode) == "" {
		missing = append(missing, "mode")
	}
	switch provider.ProviderType {
	case tables.GuardrailProviderTypeAWSBedrock:
		if strings.TrimSpace(provider.Region) == "" {
			missing = append(missing, "region")
		}
		if provider.Mode == tables.GuardrailProviderModeCustomerOwned && len(provider.Credentials) == 0 {
			warnings = append(warnings, "AWS Bedrock customer-owned mode normally expects IAM or STS credential material")
		}
	case tables.GuardrailProviderTypeAzureContentSafe:
		if strings.TrimSpace(provider.Endpoint) == "" {
			missing = append(missing, "endpoint")
		}
	case tables.GuardrailProviderTypeDeepIntShieldModels:
		// Endpoint is no longer collected from the UI - the gateway adapter
		// (internal/providers/deepintshieldmodels) resolves it from
		// ProviderConfig.Endpoint → credentials.service_url → the
		// DEEPINTSHIELD_MODELS_ENDPOINT env → the compose default. So an
		// empty endpoint on the row is the expected configuration; we
		// don't fail the create on it. detectors live on the dedicated
		// Models tab now, so the missing-detectors warning is also gone.
	case tables.GuardrailProviderTypeGCPModelArmor:
		if strings.TrimSpace(provider.Region) == "" {
			warnings = append(warnings, "GCP Model Armor usually needs a regional deployment target")
		}
	case tables.GuardrailProviderTypeWebhook:
		if strings.TrimSpace(provider.Endpoint) == "" && strings.TrimSpace(stringValueFromMap(provider.Credentials, "webhook_url", "url")) == "" {
			missing = append(missing, "endpoint")
		}
	}
	return missing, warnings
}

func stringValueFromMap(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if values == nil {
			return ""
		}
		raw, ok := values[key]
		if !ok || raw == nil {
			continue
		}
		if rendered := strings.TrimSpace(fmt.Sprintf("%v", raw)); rendered != "" && rendered != "<nil>" {
			return rendered
		}
	}
	return ""
}

func (h *GuardrailsHandler) guardrailVersionIndex(ctx context.Context, policies []tables.TableGuardrailPolicy) (map[string][]tables.TableGuardrailPolicyVersion, error) {
	index := make(map[string][]tables.TableGuardrailPolicyVersion, len(policies))
	for _, policy := range policies {
		versions, err := h.configStore.ListGuardrailPolicyVersions(ctx, policy.ID)
		if err != nil {
			return nil, err
		}
		index[policy.ID] = versions
	}
	return index, nil
}

func buildGuardrailPolicyResponse(policy *tables.TableGuardrailPolicy, versions []tables.TableGuardrailPolicyVersion) guardrailPolicyResponse {
	response := guardrailPolicyResponse{
		ID:              policy.ID,
		Name:            policy.Name,
		Description:     policy.Description,
		DomainPackID:    policy.DomainPackID,
		WorkspaceID:     policy.WorkspaceID,
		Scope:           policy.Scope,
		Scopes:          guardrailPolicyScopes(policy.Scope, policy.Metadata),
		EnforcementMode: normalizeGuardrailEnforcementMode(policy.EnforcementMode),
		ExecutionMode:   normalizeGuardrailExecutionMode(policy.ExecutionMode),
		ShadowUntil:     policy.ShadowUntil,
		SamplingRate:    policy.SamplingRate,
		TimeoutMs:       policy.TimeoutMs,
		Enabled:         policy.Enabled,
		IsDefault:       policy.IsDefault,
		ActiveVersionID: policy.ActiveVersionID,
		Metadata:        policy.Metadata,
		CreatedAt:       policy.CreatedAt,
		UpdatedAt:       policy.UpdatedAt,
	}
	if len(versions) == 0 {
		return response
	}
	sort.SliceStable(versions, func(i, j int) bool {
		if versions[i].Version == versions[j].Version {
			return versions[i].CreatedAt.After(versions[j].CreatedAt)
		}
		return versions[i].Version > versions[j].Version
	})
	response.LatestVersion = &guardrailVersionSummary{
		ID:          versions[0].ID,
		Version:     versions[0].Version,
		Status:      versions[0].Status,
		PublishedBy: versions[0].PublishedBy,
		PublishedAt: versions[0].PublishedAt,
		CreatedAt:   versions[0].CreatedAt,
	}
	for _, version := range versions {
		if policy.ActiveVersionID != nil && version.ID == *policy.ActiveVersionID {
			response.ActiveVersion = &guardrailVersionSummary{
				ID:          version.ID,
				Version:     version.Version,
				Status:      version.Status,
				PublishedBy: version.PublishedBy,
				PublishedAt: version.PublishedAt,
				CreatedAt:   version.CreatedAt,
			}
			break
		}
	}
	return response
}

func buildGuardrailMCPToolPolicyResponse(policy *tables.TableGuardrailMCPToolPolicy) guardrailMCPToolPolicyResponse {
	if policy == nil {
		return guardrailMCPToolPolicyResponse{
			AllowedDomains:    []string{},
			AllowedIdentities: []string{},
		}
	}
	// Always materialize empty slices instead of nil so JSON marshals
	// them as `[]`. The dashboard's MCP Security tab calls
	// `policy.allowed_domains.join(', ')` directly.
	allowedDomains := append([]string{}, policy.AllowedDomains...)
	allowedIdentities := append([]string{}, policy.AllowedIdentities...)
	return guardrailMCPToolPolicyResponse{
		ID:                policy.ID,
		PolicyID:          policy.PolicyID,
		ServerLabel:       policy.ServerLabel,
		ToolName:          policy.ToolName,
		ActionClass:       policy.ActionClass,
		RestrictedAction:  policy.ApprovalNeeded,
		AllowedDomains:    allowedDomains,
		AllowedIdentities: allowedIdentities,
		CreatedAt:         policy.CreatedAt,
		UpdatedAt:         policy.UpdatedAt,
	}
}

func (h *GuardrailsHandler) ensureBuiltinDomainPacks(ctx context.Context) error {
	packs, err := h.configStore.ListGuardrailDomainPacks(ctx)
	if err != nil {
		return err
	}
	if len(packs) > 0 {
		return nil
	}
	for _, pack := range builtinGuardrailDomainPacks() {
		copy := pack
		if copy.ID == "" {
			copy.ID = uuid.NewString()
		}
		if err := h.configStore.CreateGuardrailDomainPack(ctx, &copy); err != nil {
			return err
		}
	}
	return nil
}

func builtinGuardrailDomainPacks() []tables.TableGuardrailDomainPack {
	return []tables.TableGuardrailDomainPack{
		{
			Name:               "BFSI Runtime Protection",
			Slug:               "bfsi",
			Description:        "Controls for financial prompt injection, fraud workflows, and sensitive account actions.",
			Vertical:           "BFSI",
			Status:             tables.GuardrailDomainPackStatusActive,
			Controls:           []string{"OWASP-LLM01", "OWASP-LLM06", "MITRE-ATLAS:AML.T0051", "NIST-AI-RMF:MAP-2"},
			ThreatTemplates:    []string{"Prompt injection into account workflows", "Approval bypass during fund transfer", "Sensitive payment data exfiltration"},
			RecommendedActions: []string{"block", "redact"},
			TemplatePolicyDefinition: map[string]any{
				"input_guardrails": []map[string]any{
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 10,
						"config": map[string]any{
							"category": "finance_prompt_injection",
							"rule":     `(?i)(override approval|disable reviewer|ignore account policy)`,
							"severity": "critical",
							"summary":  "Finance workflow override attempt",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
					{
						"name":     "detect_pii",
						"enabled":  true,
						"priority": 20,
						"config": map[string]any{
							"categories": []string{"credit_card"},
							"severity":   "high",
							"summary":    "Payment or card data detected",
						},
						"action": map[string]any{"on_fail": "redact"},
					},
				},
				"blocked_domains":       []string{"pastebin.com", "ngrok.io"},
				"denied_action_classes": []string{"destructive", "network"},
			},
		},
		{
			Name:               "Healthcare Safety",
			Slug:               "healthcare",
			Description:        "Controls for PHI, unsupported medical claims, and high-risk clinical instructions.",
			Vertical:           "Healthcare",
			Status:             tables.GuardrailDomainPackStatusActive,
			Controls:           []string{"OWASP-LLM02", "OWASP-LLM06", "HIPAA", "MITRE-ATLAS:AML.T0049"},
			ThreatTemplates:    []string{"Unsafe dosage recommendation", "PHI disclosure", "Unsupported diagnostic claim"},
			RecommendedActions: []string{"redact", "block"},
			TemplatePolicyDefinition: map[string]any{
				"input_guardrails": []map[string]any{
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 10,
						"config": map[string]any{
							"category": "phi",
							"rule":     `(?i)(patient id|medical record number|\b\d{3}-\d{2}-\d{4}\b)`,
							"severity": "high",
							"summary":  "Protected health data detected",
						},
						"action": map[string]any{"on_fail": "redact"},
					},
				},
				"output_guardrails": []map[string]any{
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 10,
						"config": map[string]any{
							"category": "clinical_risk",
							"rule":     `(?i)(guaranteed cure|stop prescribed medication|double your dose)`,
							"severity": "critical",
							"summary":  "High-risk clinical instruction detected",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
				},
				"denied_action_classes": []string{"destructive", "exec"},
			},
		},
		{
			Name:                     "Insurance Claims Controls",
			Slug:                     "insurance",
			Description:              "Controls for policy manipulation, claimant PII, and fraud scoring escalation.",
			Vertical:                 "Insurance",
			Status:                   tables.GuardrailDomainPackStatusActive,
			Controls:                 []string{"OWASP-LLM01", "OWASP-LLM06", "SOC2-CC7"},
			ThreatTemplates:          []string{"Claims escalation override", "Claimant PII disclosure"},
			RecommendedActions:       []string{"redact", "block"},
			TemplatePolicyDefinition: defaultGuardRuntimeDefinition("input"),
		},
		{
			Name:                     "Enterprise Copilot Baseline",
			Slug:                     "enterprise-copilot",
			Description:              "Baseline runtime protection for enterprise copilots and assistants.",
			Vertical:                 "Enterprise",
			Status:                   tables.GuardrailDomainPackStatusActive,
			Controls:                 []string{"OWASP-LLM01", "OWASP-LLM07", "MITRE-ATLAS:AML.T0058"},
			ThreatTemplates:          []string{"System prompt leakage", "Tool hijacking", "Unsafe internal data exfiltration"},
			RecommendedActions:       []string{"block", "redact"},
			TemplatePolicyDefinition: defaultGuardRuntimeDefinition("input"),
		},
		{
			Name:                     "Customer Support Assistant",
			Slug:                     "customer-support",
			Description:              "Baseline runtime protection for customer support and agent-assist flows.",
			Vertical:                 "Support",
			Status:                   tables.GuardrailDomainPackStatusActive,
			Controls:                 []string{"OWASP-LLM02", "OWASP-LLM06"},
			ThreatTemplates:          []string{"Refund abuse instruction", "Sensitive customer data leak"},
			RecommendedActions:       []string{"redact", "block"},
			TemplatePolicyDefinition: defaultGuardRuntimeDefinition("output"),
		},
		{
			Name:               "Development Assistant",
			Slug:               "development-assistant",
			Description:        "Runtime protection for coding copilots, MCP tooling, and repository actions.",
			Vertical:           "Engineering",
			Status:             tables.GuardrailDomainPackStatusActive,
			Controls:           []string{"OWASP-LLM01", "OWASP-LLM08", "MITRE-ATLAS:AML.T0016"},
			ThreatTemplates:    []string{"Destructive shell execution", "Credential exfiltration in code", "Tool scope bypass"},
			RecommendedActions: []string{"sandbox", "block"},
			TemplatePolicyDefinition: map[string]any{
				"input_guardrails": []map[string]any{
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 10,
						"config": map[string]any{
							"category": "destructive_exec",
							"rule":     `(?i)(rm -rf|drop table|chmod 777|curl .*\\|\\s*sh)`,
							"severity": "critical",
							"summary":  "Destructive or remote shell execution detected",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 20,
						"config": map[string]any{
							"category": "code_secret",
							"rule":     `(?i)(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|sk-[a-zA-Z0-9]{20,})`,
							"severity": "critical",
							"summary":  "Code or shell content contains credential material",
						},
						"action": map[string]any{"on_fail": "redact"},
					},
				},
				"allowed_action_classes": []string{"read", "write"},
				"denied_action_classes":  []string{"destructive", "exec", "network"},
			},
		},
		{
			Name:               "Agentic Runtime Protection",
			Slug:               "agentic",
			Description:        "OWASP Top 10 for Agentic Applications 2026 - comprehensive controls for agent goal hijack, tool misuse, privilege abuse, supply chain, RCE, memory poisoning, inter-agent comms, cascading failures, trust exploitation, and rogue agents.",
			Vertical:           "Agentic",
			Status:             tables.GuardrailDomainPackStatusActive,
			Controls:           []string{"OWASP-ASI01", "OWASP-ASI02", "OWASP-ASI03", "OWASP-ASI04", "OWASP-ASI05", "OWASP-ASI06", "OWASP-ASI07", "OWASP-ASI08", "OWASP-ASI09", "OWASP-ASI10"},
			ThreatTemplates:    []string{"Agent goal hijack via prompt injection", "Tool misuse and exploit chaining", "Privilege escalation in agent context", "Untrusted plugin or supply chain attack", "Unexpected code execution or sandbox escape", "Memory and context poisoning", "Inter-agent message injection", "Cascading failure and retry storm", "Social engineering via agent output", "Rogue agent policy bypass"},
			RecommendedActions: []string{"block", "sandbox"},
			TemplatePolicyDefinition: map[string]any{
				"input_guardrails": []map[string]any{
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 10,
						"config": map[string]any{
							"category": "agent_goal_hijack",
							"rule":     `(?i)(change your goal|new objective|forget your task|your real goal is|ignore your purpose|override assigned task|switch to this goal)`,
							"severity": "critical",
							"summary":  "Agent goal hijack or objective manipulation detected",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 20,
						"config": map[string]any{
							"category": "agent_tool_misuse",
							"rule":     `(?i)(bypass tool restriction|escalate tool permission|pipe output to exec|tool chain bypass|use tool A to unlock tool B)`,
							"severity": "critical",
							"summary":  "Agent tool misuse or exploitation attempt detected",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 30,
						"config": map[string]any{
							"category": "agent_identity_privilege",
							"rule":     `(?i)(escalate privilege|grant admin|elevate permission|impersonate user|act as admin|spoof identity|assume role|become superuser)`,
							"severity": "critical",
							"summary":  "Agent privilege abuse or identity spoofing detected",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 40,
						"config": map[string]any{
							"category": "agent_unexpected_rce",
							"rule":     `(?i)(escape sandbox|break out of container|bypass isolation|generate and run|compile and run|os\.system|subprocess\.call|eval\()`,
							"severity": "critical",
							"summary":  "Unexpected code execution attempt by agent",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
					{
						"name":     "regex_match",
						"enabled":  true,
						"priority": 50,
						"config": map[string]any{
							"category": "rogue_agent",
							"rule":     `(?i)(ignore policy|bypass constraint|override restriction|disable guardrail|act autonomously|self-authorize|proceed without permission)`,
							"severity": "critical",
							"summary":  "Rogue agent behavior - operating outside policy boundaries",
						},
						"action": map[string]any{"on_fail": "deny"},
					},
				},
				"blocked_domains":       []string{"pastebin.com", "ngrok.io"},
				"denied_action_classes": []string{"destructive", "exec"},
			},
		},
	}
}

func (h *GuardrailsHandler) resolveInitialPolicyDefinition(ctx context.Context, domainPackID *string, scope string) map[string]any {
	if domainPackID != nil && strings.TrimSpace(*domainPackID) != "" {
		if pack, err := h.configStore.GetGuardrailDomainPack(ctx, strings.TrimSpace(*domainPackID)); err == nil && pack != nil && len(pack.TemplatePolicyDefinition) > 0 {
			return pack.TemplatePolicyDefinition
		}
	}
	return defaultGuardRuntimeDefinition(scope)
}

func (h *GuardrailsHandler) resolveSimulationPolicies(ctx context.Context, selectedPolicyIDs []string, stage string) ([]guardRuntimePolicyBundle, error) {
	policies, err := h.configStore.ListGuardrailPolicies(ctx)
	if err != nil {
		return nil, err
	}
	enabledProviders, err := h.listEnabledRuntimeProviders(ctx)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]struct{}, len(selectedPolicyIDs))
	for _, policyID := range selectedPolicyIDs {
		policyID = strings.TrimSpace(policyID)
		if policyID != "" {
			selected[policyID] = struct{}{}
		}
	}
	normalizedStage := strings.ToLower(strings.TrimSpace(stage))
	if normalizedStage == "" {
		normalizedStage = tables.GuardrailPolicyScopeInput
	}
	if normalizedStage != tables.GuardrailPolicyScopeOutput &&
		normalizedStage != tables.GuardrailPolicyScopeAction &&
		normalizedStage != tables.GuardrailPolicyScopeMCP &&
		normalizedStage != tables.GuardrailPolicyScopeRAG {
		normalizedStage = tables.GuardrailPolicyScopeInput
	}

	bundles := make([]guardRuntimePolicyBundle, 0, len(policies))
	for _, policy := range policies {
		if len(selected) > 0 {
			if _, ok := selected[policy.ID]; !ok {
				continue
			}
		} else if !policy.Enabled || !guardrailPolicyAppliesToStage(policy, normalizedStage) {
			continue
		}

		version, err := h.resolvePolicyVersionForExecution(ctx, &policy)
		if err != nil {
			return nil, err
		}
		if version == nil {
			continue
		}
		bundle, _, err := h.buildRuntimePolicyBundle(ctx, &policy, version, enabledProviders)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

func (h *GuardrailsHandler) resolvePolicyVersionForExecution(ctx context.Context, policy *tables.TableGuardrailPolicy) (*tables.TableGuardrailPolicyVersion, error) {
	if policy == nil {
		return nil, nil
	}
	if policy.ActiveVersionID != nil && strings.TrimSpace(*policy.ActiveVersionID) != "" {
		version, err := h.configStore.GetGuardrailPolicyVersion(ctx, *policy.ActiveVersionID)
		if err != nil || version != nil {
			return version, err
		}
	}
	versions, err := h.configStore.ListGuardrailPolicyVersions(ctx, policy.ID)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, nil
	}
	sort.SliceStable(versions, func(i, j int) bool {
		if versions[i].Version == versions[j].Version {
			return versions[i].CreatedAt.After(versions[j].CreatedAt)
		}
		return versions[i].Version > versions[j].Version
	})
	return &versions[0], nil
}

func tenantIDFromStoreContext(ctx context.Context) string {
	if ctx == nil {
		return defaultGuardrailTenantID
	}
	if tenantID, ok := ctx.Value(schemas.DeepIntShieldContextKeyTenantID).(string); ok {
		if trimmed := strings.TrimSpace(tenantID); trimmed != "" {
			return trimmed
		}
	}
	return defaultGuardrailTenantID
}

func (h *GuardrailsHandler) hydrateRuntimeTenant(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.runtimeClient == nil && h.embeddedRuntime == nil {
		return nil
	}
	bundle, err := h.buildRuntimeTenantBundle(ctx)
	if err != nil {
		return err
	}
	refreshCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	refreshReq := &guardRuntimeRefreshTenantRequest{
		TenantID: bundle.TenantID,
		Bundle:   bundle,
	}
	if h.runtimeClient != nil {
		if _, err := h.runtimeClient.RefreshTenant(refreshCtx, refreshReq); err != nil {
			return err
		}
	}
	if h.embeddedRuntime != nil {
		if _, err := h.embeddedRuntime.RefreshTenant(refreshCtx, refreshReq); err != nil {
			return err
		}
	}
	return nil
}

func (h *GuardrailsHandler) buildRuntimeTenantBundle(ctx context.Context) (guardRuntimeTenantBundle, error) {
	enabledProviders, err := h.listEnabledRuntimeProviders(ctx)
	if err != nil {
		return guardRuntimeTenantBundle{}, err
	}
	policies, err := h.configStore.ListGuardrailPolicies(ctx)
	if err != nil {
		return guardRuntimeTenantBundle{}, err
	}
	bundle := guardRuntimeTenantBundle{
		TenantID:    tenantIDFromStoreContext(ctx),
		RefreshedAt: time.Now().UTC(),
		Providers:   make([]guardRuntimeProviderConfig, 0, len(enabledProviders)),
		Policies:    make([]guardRuntimePolicyBundle, 0, len(policies)),
		Metadata: map[string]any{
			"source": "deepintshield_server",
		},
	}
	for _, provider := range enabledProviders {
		customerID := ""
		if provider.CustomerID != nil {
			customerID = strings.TrimSpace(*provider.CustomerID)
		}
		bundle.Providers = append(bundle.Providers, guardRuntimeProviderConfig{
			ID:             provider.ID,
			Name:           provider.Name,
			ProviderType:   provider.ProviderType,
			Mode:           provider.Mode,
			CustomerID:     customerID,
			Enabled:        provider.Enabled,
			Region:         provider.Region,
			Endpoint:       provider.Endpoint,
			Credentials:    provider.Credentials,
			ConnectionMeta: provider.ConnectionMeta,
		})
	}

	mcpPolicies := make([]guardRuntimeMCPToolPolicy, 0)
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		version, err := h.resolvePolicyVersionForExecution(ctx, &policy)
		if err != nil {
			return guardRuntimeTenantBundle{}, err
		}
		if version == nil {
			continue
		}
		policyBundle, toolPolicies, err := h.buildRuntimePolicyBundle(ctx, &policy, version, enabledProviders)
		if err != nil {
			return guardRuntimeTenantBundle{}, err
		}
		bundle.Policies = append(bundle.Policies, policyBundle)
		mcpPolicies = append(mcpPolicies, toolPolicies...)
	}
	bundle.MCPToolPolicies = mcpPolicies
	bundle.Metadata["provider_count"] = len(bundle.Providers)
	bundle.Metadata["policy_count"] = len(bundle.Policies)
	bundle.Metadata["mcp_policy_count"] = len(bundle.MCPToolPolicies)
	if settings, err := h.configStore.GetGuardrailRAGSettings(ctx); err == nil && settings != nil {
		bundle.Metadata["rag_settings"] = runtimeRAGSettingsMetadata(settings)
	}
	if sources, err := h.configStore.ListGuardrailRAGSources(ctx); err == nil && len(sources) > 0 {
		bundle.Metadata["rag_sources"] = runtimeRAGSourcesMetadata(sources)
	}

	revision, err := runtimeTenantBundleRevision(bundle)
	if err != nil {
		return guardRuntimeTenantBundle{}, err
	}
	bundle.Revision = revision
	return bundle, nil
}

func (h *GuardrailsHandler) listEnabledRuntimeProviders(ctx context.Context) ([]tables.TableGuardrailProvider, error) {
	providers, err := h.configStore.ListGuardrailProviders(ctx)
	if err != nil {
		return nil, err
	}
	enabled := make([]tables.TableGuardrailProvider, 0, len(providers))
	for _, provider := range providers {
		if provider.Enabled {
			enabled = append(enabled, provider)
		}
	}
	return enabled, nil
}

func (h *GuardrailsHandler) buildRuntimePolicyBundle(ctx context.Context, policy *tables.TableGuardrailPolicy, version *tables.TableGuardrailPolicyVersion, enabledProviders []tables.TableGuardrailProvider) (guardRuntimePolicyBundle, []guardRuntimeMCPToolPolicy, error) {
	bindings, err := h.resolveRuntimePolicyBindings(ctx, policy, enabledProviders)
	if err != nil {
		return guardRuntimePolicyBundle{}, nil, err
	}
	mcpPolicies, err := h.resolveRuntimeMCPToolPolicies(ctx, policy.ID)
	if err != nil {
		return guardRuntimePolicyBundle{}, nil, err
	}
	return guardRuntimePolicyBundle{
		PolicyID:         policy.ID,
		PolicyVersionID:  version.ID,
		Name:             policy.Name,
		DomainPackID:     optionalString(policy.DomainPackID),
		Scope:            policy.Scope,
		EnforcementMode:  normalizeGuardrailEnforcementMode(policy.EnforcementMode),
		Enabled:          policy.Enabled,
		IsDefault:        policy.IsDefault,
		TimeoutMs:        policy.TimeoutMs,
		Metadata:         normalizeGuardrailPolicyMetadata(policy.Metadata, policy.Scope, nil),
		Definition:       version.Definition,
		ProviderBindings: bindings,
	}, mcpPolicies, nil
}

func buildSimulationInlinePolicies(payload *guardrailSimulationPayload) []guardRuntimePolicyBundle {
	if payload == nil {
		return nil
	}
	definition := make(map[string]any, 2)
	if len(payload.InputGuardrails) > 0 {
		definition["input_guardrails"] = guardrailMapsToSlice(payload.InputGuardrails)
	}
	if len(payload.OutputGuardrails) > 0 {
		definition["output_guardrails"] = guardrailMapsToSlice(payload.OutputGuardrails)
	}
	if len(definition) == 0 {
		return nil
	}
	sum, _ := json.Marshal(definition)
	digest := sha256.Sum256(sum)
	policyID := "test-lab-inline-" + hex.EncodeToString(digest[:8])
	return []guardRuntimePolicyBundle{{
		PolicyID:        policyID,
		PolicyVersionID: policyID + "-v1",
		Name:            "Test Lab Inline Guardrails",
		Scope:           strings.ToLower(strings.TrimSpace(payload.Stage)),
		EnforcementMode: tables.GuardrailEnforcementModeBlock,
		Enabled:         true,
		Definition:      definition,
		Metadata: map[string]any{
			"source": "test_lab_inline",
		},
	}}
}

func guardrailMapsToSlice(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func cloneRuntimeMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	copy := make(map[string]any, len(metadata))
	for key, value := range metadata {
		copy[key] = value
	}
	return copy
}

// mergeAnyMaps returns base with extras overlaid. base is cloned so the
// inputs are never mutated.
func mergeAnyMaps(base map[string]any, extras map[string]any) map[string]any {
	if len(base) == 0 && len(extras) == 0 {
		return map[string]any{}
	}
	merged := cloneRuntimeMetadata(base)
	if merged == nil {
		merged = make(map[string]any, len(extras))
	}
	for key, value := range extras {
		merged[key] = value
	}
	return merged
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func truncateGuardrailText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func normalizeGuardrailPolicyMetadata(metadata map[string]any, fallbackScope string, requestedScopes []string) map[string]any {
	copy := cloneRuntimeMetadata(metadata)
	if copy == nil {
		copy = make(map[string]any, 1)
	}
	scopes := guardrailPolicyScopesWithRequested(fallbackScope, copy, requestedScopes)
	copy["scopes"] = scopes
	return copy
}

func guardrailPolicyScopes(scope string, metadata map[string]any) []string {
	return guardrailPolicyScopesWithRequested(scope, metadata, nil)
}

func guardrailPolicyScopesWithRequested(scope string, metadata map[string]any, requestedScopes []string) []string {
	candidates := requestedScopes
	if len(candidates) == 0 && metadata != nil {
		candidates = toStringSlice(metadata["scopes"])
	}
	normalized := make([]string, 0, len(candidates)+1)
	for _, candidate := range append(candidates, scope) {
		stage := normalizeGuardrailStage(candidate)
		if stage == "" || containsNormalizedGuardrailValue(normalized, stage) {
			continue
		}
		normalized = append(normalized, stage)
	}
	if len(normalized) == 0 {
		return []string{tables.GuardrailPolicyScopeInput}
	}
	return normalized
}

func guardrailPrimaryScope(scope string, metadata map[string]any) string {
	scopes := guardrailPolicyScopes(scope, metadata)
	if len(scopes) == 0 {
		return tables.GuardrailPolicyScopeInput
	}
	return scopes[0]
}

func guardrailPolicyAppliesToStage(policy tables.TableGuardrailPolicy, stage string) bool {
	target := normalizeGuardrailStage(stage)
	for _, scope := range guardrailPolicyScopes(policy.Scope, policy.Metadata) {
		if strings.EqualFold(scope, target) {
			return true
		}
	}
	return false
}

func normalizeGuardrailStage(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case tables.GuardrailPolicyScopeOutput:
		return tables.GuardrailPolicyScopeOutput
	case tables.GuardrailPolicyScopeAction:
		return tables.GuardrailPolicyScopeAction
	case tables.GuardrailPolicyScopeMCP:
		return tables.GuardrailPolicyScopeMCP
	case tables.GuardrailPolicyScopeRAG:
		return tables.GuardrailPolicyScopeRAG
	case tables.GuardrailPolicyScopeInput:
		return tables.GuardrailPolicyScopeInput
	default:
		return tables.GuardrailPolicyScopeInput
	}
}

func normalizeGuardrailEnforcementMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case tables.GuardrailEnforcementModeMonitor:
		return tables.GuardrailEnforcementModeMonitor
	case tables.GuardrailEnforcementModeRedact:
		return tables.GuardrailEnforcementModeRedact
	case tables.GuardrailEnforcementModeSandbox:
		return tables.GuardrailEnforcementModeSandbox
	case tables.GuardrailEnforcementModeApproval:
		return tables.GuardrailEnforcementModeBlock
	default:
		return tables.GuardrailEnforcementModeBlock
	}
}

func normalizeGuardrailExecutionMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case tables.GuardrailExecutionModeAsync:
		return tables.GuardrailExecutionModeAsync
	case tables.GuardrailExecutionModeShadow:
		return tables.GuardrailExecutionModeShadow
	default:
		return tables.GuardrailExecutionModeSync
	}
}

// normalizeGuardrailShadowUntil clamps the shadow expiry to nil unless
// the policy is actually in shadow mode, and drops past timestamps so
// a policy can't be created already-expired (which would silently snap
// to sync - surprising behavior at create time).
func normalizeGuardrailShadowUntil(mode string, shadowUntil *time.Time) *time.Time {
	if mode != tables.GuardrailExecutionModeShadow || shadowUntil == nil {
		return nil
	}
	t := shadowUntil.UTC()
	if !t.After(time.Now().UTC()) {
		return nil
	}
	return &t
}

// enforcementClassCardIDs are guardrail card IDs that we refuse to run
// in async mode. These represent the "must enforce or attack succeeds"
// class - prompt injection attempts that have already passed through to
// the LLM cannot be retroactively blocked, and a leaked SSN cannot be
// un-leaked. Shadow mode is still allowed for these (so customers can
// validate false-positive rates during rollout) - only async (no inline
// evaluation) is forbidden.
var enforcementClassCardIDs = map[string]struct{}{
	"owasp-llm01-prompt-injection":                 {},
	"owasp-llm02-sensitive-information-disclosure": {},
	"owasp-llm04-data-model-poisoning":             {},
	"owasp-llm05-improper-output-handling":         {},
	"owasp-llm07-system-prompt-leakage":            {},
}

// policyDefinitionContainsEnforcementClass walks a policy's builder
// metadata and returns true if any enabled card belongs to the
// enforcement-class set. We read the builder metadata rather than the
// emitted runtime checks because the metadata is the source of truth
// for "what did the user click on?" - a compiled regex check could
// have come from any source and isn't reliably classifiable.
func policyDefinitionContainsEnforcementClass(definition map[string]any) bool {
	if len(definition) == 0 {
		return false
	}
	builder, ok := definition["_deepintshield_builder"].(map[string]any)
	if !ok {
		return false
	}
	cards, ok := builder["selected_cards"].([]any)
	if !ok {
		return false
	}
	for _, raw := range cards {
		card, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		enabled, _ := card["enabled"].(bool)
		if !enabled {
			continue
		}
		id, _ := card["id"].(string)
		if _, hit := enforcementClassCardIDs[id]; hit {
			return true
		}
	}
	return false
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func (h *GuardrailsHandler) resolveRuntimePolicyBindings(ctx context.Context, policy *tables.TableGuardrailPolicy, enabledProviders []tables.TableGuardrailProvider) ([]guardRuntimePolicyProviderBinding, error) {
	rawBindings, err := h.configStore.ListGuardrailPolicyProviderBindings(ctx, policy.ID)
	if err != nil {
		return nil, err
	}
	providerTypeByID := make(map[string]string, len(enabledProviders))
	for _, provider := range enabledProviders {
		providerTypeByID[provider.ID] = provider.ProviderType
	}
	bindings := make([]guardRuntimePolicyProviderBinding, 0, len(rawBindings))
	for _, binding := range rawBindings {
		if !binding.Enabled {
			continue
		}
		providerType, ok := providerTypeByID[binding.ProviderID]
		if !ok {
			continue
		}
		bindings = append(bindings, guardRuntimePolicyProviderBinding{
			ProviderID:   binding.ProviderID,
			ProviderType: providerType,
			Stage:        binding.Stage,
			Priority:     binding.Priority,
			Enabled:      binding.Enabled,
		})
	}
	if len(bindings) == 0 {
		for _, provider := range enabledProviders {
			bindings = append(bindings, guardRuntimePolicyProviderBinding{
				ProviderID:   provider.ID,
				ProviderType: provider.ProviderType,
				Stage:        policy.Scope,
				Priority:     100,
				Enabled:      true,
			})
		}
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		return bindings[i].Priority < bindings[j].Priority
	})
	return bindings, nil
}

func (h *GuardrailsHandler) resolveRuntimeMCPToolPolicies(ctx context.Context, policyID string) ([]guardRuntimeMCPToolPolicy, error) {
	rawPolicies, err := h.configStore.ListGuardrailMCPToolPolicies(ctx, policyID)
	if err != nil {
		return nil, err
	}
	policies := make([]guardRuntimeMCPToolPolicy, 0, len(rawPolicies))
	for _, toolPolicy := range rawPolicies {
		policies = append(policies, guardRuntimeMCPToolPolicy{
			PolicyID:          toolPolicy.PolicyID,
			ServerLabel:       toolPolicy.ServerLabel,
			ToolName:          toolPolicy.ToolName,
			ActionClass:       toolPolicy.ActionClass,
			ApprovalNeeded:    toolPolicy.ApprovalNeeded,
			AllowedDomains:    append([]string(nil), toolPolicy.AllowedDomains...),
			AllowedIdentities: append([]string(nil), toolPolicy.AllowedIdentities...),
		})
	}
	return policies, nil
}

func runtimeTenantBundleRevision(bundle guardRuntimeTenantBundle) (string, error) {
	copy := bundle
	copy.Revision = ""
	raw, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func runtimeRAGSettingsMetadata(settings *tables.TableGuardrailRAGSettings) map[string]any {
	if settings == nil {
		return nil
	}
	return map[string]any{
		"runtime_enforcement_enabled":  settings.RuntimeEnforcementEnabled,
		"async_scanning_enabled":       settings.AsyncScanningEnabled,
		"precomputed_scores_enabled":   settings.PrecomputedScoresEnabled,
		"policy_cache_enabled":         settings.PolicyCacheEnabled,
		"citation_enforcement_enabled": settings.CitationEnforcementEnabled,
		"shadow_mode_enabled":          settings.ShadowModeEnabled,
		"evidence_exports_enabled":     settings.EvidenceExportsEnabled,
		"default_action":               settings.DefaultAction,
		"max_runtime_latency_ms":       settings.MaxRuntimeLatencyMs,
		"last_rules_sync_at":           settings.LastRulesSyncAt,
		"last_scan_at":                 settings.LastScanAt,
	}
}

func runtimeRAGSourcesMetadata(sources []tables.TableGuardrailRAGSource) map[string]any {
	result := make(map[string]any, len(sources))
	for _, source := range sources {
		result[source.ID] = map[string]any{
			"id":                source.ID,
			"name":              source.Name,
			"source_name":       source.Name,
			"connector":         source.Connector,
			"index_name":        source.IndexName,
			"owner":             source.Owner,
			"sensitivity":       source.Sensitivity,
			"retention_class":   source.RetentionClass,
			"trust_level":       source.TrustLevel,
			"trust_score":       runtimeRAGTrustScore(source.TrustLevel),
			"tenant":            source.Tenant,
			"app_name":          source.AppName,
			"acl_tags":          append([]string(nil), source.ACLTags...),
			"labels":            append([]string(nil), source.Labels...),
			"document_count":    source.DocumentCount,
			"chunk_count":       source.ChunkCount,
			"health":            source.Health,
			"source_health":     source.Health,
			"quarantined":       source.Quarantined,
			"quarantine_reason": source.QuarantineReason,
			"last_scan_at":      source.LastScanAt,
		}
	}
	return result
}

func runtimeRAGTrustScore(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "trusted":
		return 90
	case "medium", "monitored":
		return 70
	case "low", "untrusted":
		return 45
	default:
		return 80
	}
}
