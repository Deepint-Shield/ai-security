// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains all governance management functionality including CRUD operations for VKs, Rules, and configs.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/entitlements"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/plugins/governance"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// GovernanceManager is the interface for the governance manager
type GovernanceManager interface {
	GetGovernanceData(ctx context.Context) *governance.GovernanceData
	ReloadVirtualKey(ctx context.Context, id string) (*configstoreTables.TableVirtualKey, error)
	RemoveVirtualKey(ctx context.Context, id string) error
	ReloadTeam(ctx context.Context, id string) (*configstoreTables.TableTeam, error)
	RemoveTeam(ctx context.Context, id string) error
	ReloadCustomer(ctx context.Context, id string) (*configstoreTables.TableCustomer, error)
	RemoveCustomer(ctx context.Context, id string) error
	ReloadModelConfig(ctx context.Context, id string) (*configstoreTables.TableModelConfig, error)
	RemoveModelConfig(ctx context.Context, id string) error
	ReloadProvider(ctx context.Context, provider schemas.ModelProvider) (*configstoreTables.TableProvider, error)
	RemoveProvider(ctx context.Context, provider schemas.ModelProvider) error
	ReloadRoutingRule(ctx context.Context, id string) error
	RemoveRoutingRule(ctx context.Context, id string) error
}

// GovernanceHandler manages HTTP requests for governance operations
// KeyHealthInfo contains health information about a single API key for the load balancer status API.
type KeyHealthInfo struct {
	KeyID          string `json:"key_id"`
	ActiveRequests int64  `json:"active_requests"`
	TotalRequests  int64  `json:"total_requests"`
	TotalTokens    int64  `json:"total_tokens"`
	ErrorCount     int64  `json:"error_count"`
	CircuitState   string `json:"circuit_state"`
	LastError      string `json:"last_error,omitempty"`
}

// KeyHealthProvider is a function that returns health data for all tracked keys.
// Set by the transport layer when the load balancer feature is enabled.
type KeyHealthProvider func() []KeyHealthInfo

type GovernanceHandler struct {
	configStore       configstore.ConfigStore
	governanceManager GovernanceManager
	keyHealthProvider KeyHealthProvider // nil when load balancer is disabled
}

// syncVKToAgenticResolver is a no-op in the open-source build: there is no
// in-process agentic runtime to push live VK-scope updates to. Retained so
// the VK create/update call sites compile unchanged.
func (h *GovernanceHandler) syncVKToAgenticResolver(_ *configstoreTables.TableVirtualKey) {}

// agentRiskLevels is the closed vocabulary for the agent risk tier. Kept in
// sync with riskRank() in the agentic policy engine (low<medium<high<critical).
var agentRiskLevels = map[string]struct{}{
	"low": {}, "medium": {}, "high": {}, "critical": {},
}

// normaliseAgentRiskLevel lower-cases + trims the requested risk tier and
// validates it against the closed vocabulary. An unknown / empty value
// returns "" (cleared) so a malformed input can never persist a tier the
// policy engine doesn't understand.
func normaliseAgentRiskLevel(level string) string {
	level = strings.ToLower(strings.TrimSpace(level))
	if _, ok := agentRiskLevels[level]; ok {
		return level
	}
	return ""
}

// normaliseAgentCapabilities lower-cases, trims, de-duplicates, and drops
// empties so capability tags persist in the same canonical form the policy
// engine matches against (case-insensitive set membership).
func normaliseAgentCapabilities(caps []string) []string {
	seen := make(map[string]struct{}, len(caps))
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// removeVKFromAgenticResolver is a no-op in the open-source build (no
// in-process agentic runtime). Retained so the VK delete call site compiles.
func (h *GovernanceHandler) removeVKFromAgenticResolver(_ string) {}

// syncTeamAllowedTools / removeTeamAllowedTools /
// syncCustomerAllowedTools / removeCustomerAllowedTools used to keep
// the in-memory entitlements maps on VKResolver in sync with the now-
// removed `allowed_tools` columns on governance_teams and
// governance_customers. Team / Member entitlements moved to per-policy
// targeting (agentic_policy_team_targets / agentic_policy_member_targets)
// where they are kept in sync by the PolicyTargetResolver instead.
//
// These stubs are kept (as no-ops) so the existing call sites continue
// to compile; remove in a follow-up sweep once every caller is updated.
func (h *GovernanceHandler) syncTeamAllowedTools(_ *configstoreTables.TableTeam)         {}
func (h *GovernanceHandler) removeTeamAllowedTools(_ string)                             {}
func (h *GovernanceHandler) syncCustomerAllowedTools(_ *configstoreTables.TableCustomer) {}
func (h *GovernanceHandler) removeCustomerAllowedTools(_ string)                         {}

// NewGovernanceHandler creates a new governance handler instance
func NewGovernanceHandler(manager GovernanceManager, configStore configstore.ConfigStore) (*GovernanceHandler, error) {
	if manager == nil {
		return nil, fmt.Errorf("governance manager is required")
	}
	if configStore == nil {
		return nil, fmt.Errorf("config store is required")
	}
	return &GovernanceHandler{
		governanceManager: manager,
		configStore:       configStore,
	}, nil
}

// SetKeyHealthProvider sets the function that provides key health data for the load balancer status API.
func (h *GovernanceHandler) SetKeyHealthProvider(provider KeyHealthProvider) {
	h.keyHealthProvider = provider
}

func (h *GovernanceHandler) shouldServeFromMemory(ctx *fasthttp.RequestCtx) bool {
	if string(ctx.QueryArgs().Peek("from_memory")) != "true" {
		return false
	}
	return tenantctx.TenantIDFromContext(ctx) == ""
}

// requireWorkspaceWrite gates destructive governance writes (create /
// update / delete) against the user's permission for the target
// workspace. Empty workspaceID falls back to a tenant-level admin check.
// Returns false (and writes an HTTP 403) when denied; callers should
// bail out immediately. In legacy single-tenant deployments where no
// tenant_id is on the request context, the check is skipped to preserve
// backwards compatibility with pre-multi-tenant clients.
//
// Fast path: when the caller is a system admin (role recorded on the
// session and stamped on the request context by the auth middleware),
// we skip the membership / workspace lookup entirely - admins always
// pass, and the most common dashboard caller is a tenant admin.
func (h *GovernanceHandler) requireWorkspaceWrite(ctx *fasthttp.RequestCtx, workspaceID string) bool {
	if h.configStore == nil {
		return true
	}
	if tenantctx.TenantIDFromContext(ctx) == "" {
		return true
	}
	// Fast path: skip the user load + permission lookup when the
	// session role on the context is already "admin" (system admin).
	if currentSessionUserRole(ctx) == configstoreTables.UserRoleAdmin {
		return true
	}
	// Synthesise the user from the request context (no DB round-trip)
	// - the auth middleware already stamped userID / role / tenantID
	// from the session cache. CanManageWorkspaceByID / CanManageTenant
	// only need those three fields.
	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		respondAuthError(ctx, errUnauthorizedSession)
		return false
	}
	allowed := false
	if strings.TrimSpace(workspaceID) != "" {
		allowed = CanManageWorkspaceByID(ctx, h.configStore, user, workspaceID)
	} else {
		allowed = CanManageTenant(ctx, h.configStore, user, strings.TrimSpace(user.TenantID))
	}
	if !allowed {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins, tenant owners/admins, or system admins can perform this action")
		return false
	}
	return true
}

// resolveTargetWorkspace picks the effective workspace for a write: the
// explicit request value (if non-empty), falling back to the sidebar's
// active workspace from the request context. Empty means tenant-wide.
func (h *GovernanceHandler) resolveTargetWorkspace(ctx *fasthttp.RequestCtx, requestWS *string) string {
	if requestWS != nil {
		if ws := strings.TrimSpace(*requestWS); ws != "" {
			return ws
		}
	}
	return tenantctx.WorkspaceIDFromContext(ctx)
}

// moveWorkspaceRequest is the body shape for every cross-workspace move
// endpoint. We standardise on `workspace_id` so the same shape works for
// VKs, routing rules, model configs, etc.
type moveWorkspaceRequest struct {
	WorkspaceID string `json:"workspace_id"`
}

// authoriseWorkspaceMove validates the move target + caller permissions.
// Returns false (and writes the HTTP error) on any failure; callers
// should bail. Returns the parsed target workspace ID on success.
//
// Rules:
//  1. The target workspace must exist and live in the same tenant the
//     resource is currently in (cross-tenant moves are deliberately not
//     allowed - that's a different operation).
//  2. The caller must be able to manage BOTH the source and target
//     workspaces (system admin / tenant admin / per-workspace admin).
//
// Empty target → tenant-level admin check (move to "no workspace" is
// disallowed under the new design; the caller would need to explicitly
// pass a target ID).
func (h *GovernanceHandler) authoriseWorkspaceMove(ctx *fasthttp.RequestCtx, sourceWorkspaceID, sourceTenantID string) (string, bool) {
	var req moveWorkspaceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid JSON")
		return "", false
	}
	target := strings.TrimSpace(req.WorkspaceID)
	if target == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "workspace_id is required")
		return "", false
	}
	targetWS, err := h.configStore.GetWorkspaceByID(ctx, target)
	if err != nil || targetWS == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Target workspace not found")
		return "", false
	}
	if targetWS.OrgID != sourceTenantID {
		SendError(ctx, fasthttp.StatusBadRequest, "Cannot move resource across tenants")
		return "", false
	}
	// Permission gating: source + target.
	if currentSessionUserRole(ctx) != configstoreTables.UserRoleAdmin {
		user := cachedAuthUserFromCtx(ctx)
		if user == nil {
			respondAuthError(ctx, errUnauthorizedSession)
			return "", false
		}
		// Source: if the resource is currently pinned to a workspace,
		// require write rights on it. Otherwise tenant-level admin.
		if sourceWorkspaceID != "" {
			if !CanManageWorkspaceByID(ctx, h.configStore, user, sourceWorkspaceID) {
				SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the source workspace")
				return "", false
			}
		} else if !CanManageTenant(ctx, h.configStore, user, sourceTenantID) {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the source tenant")
			return "", false
		}
		// Target: write rights on the destination.
		if !CanManageWorkspace(ctx, h.configStore, user, targetWS) {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the target workspace")
			return "", false
		}
	}
	return target, true
}

// moveVirtualKeyWorkspace handles PATCH /api/governance/virtual-keys/{vk_id}/workspace
func (h *GovernanceHandler) moveVirtualKeyWorkspace(ctx *fasthttp.RequestCtx) {
	vkID := ctx.UserValue("vk_id").(string)
	vk, err := h.configStore.GetVirtualKey(ctx, vkID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Virtual key not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve virtual key")
		return
	}
	currentWS := ""
	if vk.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*vk.WorkspaceID)
	}
	target, ok := h.authoriseWorkspaceMove(ctx, currentWS, vk.TenantID)
	if !ok {
		return
	}
	vk.WorkspaceID = &target
	if err := h.configStore.UpdateVirtualKey(ctx, vk); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to move virtual key: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"message":     "Virtual key moved",
		"virtual_key": vk,
		"from":        currentWS,
		"to":          target,
	})
}

// moveRoutingRuleWorkspace handles PATCH /api/governance/routing-rules/{rule_id}/workspace
func (h *GovernanceHandler) moveRoutingRuleWorkspace(ctx *fasthttp.RequestCtx) {
	ruleID := ctx.UserValue("rule_id").(string)
	rule, err := h.configStore.GetRoutingRule(ctx, ruleID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Routing rule not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve routing rule")
		return
	}
	currentWS := ""
	if rule.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*rule.WorkspaceID)
	}
	target, ok := h.authoriseWorkspaceMove(ctx, currentWS, rule.TenantID)
	if !ok {
		return
	}
	rule.WorkspaceID = &target
	if err := h.configStore.UpdateRoutingRule(ctx, rule); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to move routing rule: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"message": "Routing rule moved",
		"rule":    rule,
		"from":    currentWS,
		"to":      target,
	})
}

// moveModelConfigWorkspace handles PATCH /api/governance/model-configs/{mc_id}/workspace
func (h *GovernanceHandler) moveModelConfigWorkspace(ctx *fasthttp.RequestCtx) {
	mcID := ctx.UserValue("mc_id").(string)
	mc, err := h.configStore.GetModelConfigByID(ctx, mcID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Model config not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve model config")
		return
	}
	currentWS := ""
	if mc != nil && mc.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*mc.WorkspaceID)
	}
	target, ok := h.authoriseWorkspaceMove(ctx, currentWS, mc.TenantID)
	if !ok {
		return
	}
	mc.WorkspaceID = &target
	if err := h.configStore.UpdateModelConfig(ctx, mc); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to move model config: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"message":      "Model config moved",
		"model_config": mc,
		"from":         currentWS,
		"to":           target,
	})
}

// CreateVirtualKeyRequest represents the request body for creating a virtual key
type CreateVirtualKeyRequest struct {
	Name                           string   `json:"name" validate:"required"`
	Description                    string   `json:"description,omitempty"`
	GuardrailPolicyIDs             []string `json:"guardrail_policy_ids,omitempty"`
	CacheKey                       string   `json:"cache_key,omitempty"`
	CacheEnabled                   *bool    `json:"cache_enabled,omitempty"`
	SemanticCacheEnabled           *bool    `json:"semantic_cache_enabled,omitempty"`
	CacheScopeMode                 *string  `json:"cache_scope_mode,omitempty"`
	CacheMetadataScopeKeys         []string `json:"cache_metadata_scope_keys,omitempty"`
	CacheAllowSemanticWhenUnscoped *bool    `json:"cache_allow_semantic_when_unscoped,omitempty"`
	ProviderConfigs                []struct {
		Provider             string                  `json:"provider" validate:"required"`
		Weight               float64                 `json:"weight,omitempty"`
		AllowedModels        []string                `json:"allowed_models,omitempty"`         // Empty means all models allowed
		KeySelectionStrategy *string                 `json:"key_selection_strategy,omitempty"` // "weighted_random", "round_robin", "least_load"
		Budget               *CreateBudgetRequest    `json:"budget,omitempty"`                 // Provider-level budget
		RateLimit            *CreateRateLimitRequest `json:"rate_limit,omitempty"`             // Provider-level rate limit
		KeyIDs               []string                `json:"key_ids,omitempty"`                // List of DBKey UUIDs to associate with this provider config
	} `json:"provider_configs,omitempty"` // Empty means all providers allowed
	// FallbackChain is an ordered list the gateway tries automatically
	// when the primary provider call fails (5xx / 429 / timeout). Empty
	// means no automatic failover; the caller can still supply request-
	// level fallbacks per-call.
	FallbackChain []configstoreTables.VirtualKeyFallbackEntry `json:"fallback_chain,omitempty"`
	MCPConfigs    []struct {
		MCPClientName  string   `json:"mcp_client_name" validate:"required"`
		ToolsToExecute []string `json:"tools_to_execute,omitempty"`
	} `json:"mcp_configs,omitempty"` // Empty means all MCP clients allowed
	TeamID      *string                 `json:"team_id,omitempty"`      // Mutually exclusive with CustomerID
	CustomerID  *string                 `json:"customer_id,omitempty"`  // Mutually exclusive with TeamID
	WorkspaceID *string                 `json:"workspace_id,omitempty"` // Empty / omitted = org-wide
	Budget      *CreateBudgetRequest    `json:"budget,omitempty"`
	RateLimit   *CreateRateLimitRequest `json:"rate_limit,omitempty"`
	IsActive    *bool                   `json:"is_active,omitempty"`
	// Rotation schedule (optional). When RotationPeriodDays > 0 the
	// background rotation worker will rotate this key on the configured
	// cadence; the prior value stays accepted for RotationGracePeriodDays
	// so consumers have a roll-over window. Omit / set to 0 to mean
	// "manual rotation only" - admins can still rotate any time via the
	// rotate endpoint or "Rotate now" button.
	RotationPeriodDays      *int `json:"rotation_period_days,omitempty"`
	RotationGracePeriodDays *int `json:"rotation_grace_period_days,omitempty"`

	// ─── Agent Scope (unified-VK) - optional ─────────────────────────
	// When BoundIdentityProvider is set, the VK acts as both a platform
	// bearer (sk-bf-…) AND an agent scope profile: the PEP reads
	// AllowedTools / AutonomyBudget / DefaultObligations directly from
	// this row. Omit all fields to leave the VK LLM-only (no agent
	// behaviour, the PEP doesn't fire on this VK's traffic).
	BoundIdentityProvider  *string   `json:"bound_identity_provider,omitempty"`
	IdentityProviderID     *string   `json:"identity_provider_id,omitempty"`
	AllowedTools           *[]string `json:"allowed_tools,omitempty"`
	AutonomyBudget         *string   `json:"autonomy_budget,omitempty"` // low | medium | high
	DefaultObligations     *[]string `json:"default_obligations,omitempty"`
	ToolRateLimitPerMinute *int      `json:"tool_rate_limit_per_minute,omitempty"`
	AgentScopes            *[]string `json:"agent_scopes,omitempty"`
	// AgentRiskLevel + AgentCapabilities are the agent attribute taxonomy
	// (ABAC operands). Policies match on them so a new agent with matching
	// attributes is governed by existing policies without allow-list edits.
	AgentRiskLevel    *string   `json:"agent_risk_level,omitempty"` // low | medium | high | critical
	AgentCapabilities *[]string `json:"agent_capabilities,omitempty"`
	AgentNamespace    *string   `json:"agent_namespace,omitempty"` // logical / k8s namespace (ABAC operand)
}

// UpdateVirtualKeyRequest represents the request body for updating a virtual key
type UpdateVirtualKeyRequest struct {
	Name                           *string   `json:"name,omitempty"`
	Description                    *string   `json:"description,omitempty"`
	GuardrailPolicyIDs             []string  `json:"guardrail_policy_ids,omitempty"`
	CacheKey                       *string   `json:"cache_key,omitempty"`
	CacheEnabled                   *bool     `json:"cache_enabled,omitempty"`
	SemanticCacheEnabled           *bool     `json:"semantic_cache_enabled,omitempty"`
	CacheScopeMode                 *string   `json:"cache_scope_mode,omitempty"`
	CacheMetadataScopeKeys         *[]string `json:"cache_metadata_scope_keys,omitempty"`
	CacheAllowSemanticWhenUnscoped *bool     `json:"cache_allow_semantic_when_unscoped,omitempty"`
	ProviderConfigs                []struct {
		ID                   *uint                   `json:"id,omitempty"` // null for new entries
		Provider             string                  `json:"provider" validate:"required"`
		Weight               float64                 `json:"weight,omitempty"`
		AllowedModels        []string                `json:"allowed_models,omitempty"`         // Empty means all models allowed
		KeySelectionStrategy *string                 `json:"key_selection_strategy,omitempty"` // "weighted_random", "round_robin", "least_load"
		Budget               *UpdateBudgetRequest    `json:"budget,omitempty"`                 // Provider-level budget
		RateLimit            *UpdateRateLimitRequest `json:"rate_limit,omitempty"`             // Provider-level rate limit
		KeyIDs               []string                `json:"key_ids,omitempty"`                // List of DBKey UUIDs to associate with this provider config
	} `json:"provider_configs,omitempty"`
	// FallbackChain replaces the stored chain wholesale when present.
	// Pass `[]` to clear it; omit the field to leave it unchanged.
	FallbackChain *[]configstoreTables.VirtualKeyFallbackEntry `json:"fallback_chain,omitempty"`
	MCPConfigs    []struct {
		ID             *uint    `json:"id,omitempty"` // null for new entries
		MCPClientName  string   `json:"mcp_client_name" validate:"required"`
		ToolsToExecute []string `json:"tools_to_execute,omitempty"`
	} `json:"mcp_configs,omitempty"`
	TeamID     *string `json:"team_id,omitempty"`
	CustomerID *string `json:"customer_id,omitempty"`
	// WorkspaceID: pass empty string ("") to clear back to org-wide; pass
	// a workspace ID to (re)scope; omit (nil) to leave unchanged.
	WorkspaceID *string                 `json:"workspace_id,omitempty"`
	Budget      *UpdateBudgetRequest    `json:"budget,omitempty"`
	RateLimit   *UpdateRateLimitRequest `json:"rate_limit,omitempty"`
	IsActive    *bool                   `json:"is_active,omitempty"`

	// ─── Agent Scope (unified-VK) - optional ─────────────────────────
	// Same semantics as CreateVirtualKeyRequest. To clear an existing
	// agent binding, pass empty string for BoundIdentityProvider or an
	// empty slice for the list fields. Omit (nil) to leave unchanged.
	BoundIdentityProvider  *string   `json:"bound_identity_provider,omitempty"`
	IdentityProviderID     *string   `json:"identity_provider_id,omitempty"`
	AllowedTools           *[]string `json:"allowed_tools,omitempty"`
	AutonomyBudget         *string   `json:"autonomy_budget,omitempty"`
	DefaultObligations     *[]string `json:"default_obligations,omitempty"`
	ToolRateLimitPerMinute *int      `json:"tool_rate_limit_per_minute,omitempty"`
	AgentScopes            *[]string `json:"agent_scopes,omitempty"`
	// Agent attribute taxonomy (ABAC operands). Pass empty string / empty
	// slice to clear; omit (nil) to leave unchanged.
	AgentRiskLevel    *string   `json:"agent_risk_level,omitempty"`
	AgentCapabilities *[]string `json:"agent_capabilities,omitempty"`
	AgentNamespace    *string   `json:"agent_namespace,omitempty"`
}

// CreateBudgetRequest represents the request body for creating a budget
type CreateBudgetRequest struct {
	MaxLimit      float64 `json:"max_limit" validate:"required"`      // Maximum budget in dollars
	ResetDuration string  `json:"reset_duration" validate:"required"` // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
}

// UpdateBudgetRequest represents the request body for updating a budget
type UpdateBudgetRequest struct {
	MaxLimit      *float64 `json:"max_limit,omitempty"`
	ResetDuration *string  `json:"reset_duration,omitempty"`
}

// RoutingTarget represents a single weighted routing target within a rule.
// All fields except Weight are optional; nil means "use the incoming request's value".
// Weights across all targets in a rule must sum to 1 (e.g. 0.7 + 0.3 = 1.0).
type RoutingTarget struct {
	Provider *string `json:"provider,omitempty"` // nil = use incoming provider
	Model    *string `json:"model,omitempty"`    // nil = use incoming model
	KeyID    *string `json:"key_id,omitempty"`   // nil = no key pin
	Weight   float64 `json:"weight"`             // must be > 0; all weights must sum to 1
}

// CreateRoutingRuleRequest represents the request body for creating a routing rule
type CreateRoutingRuleRequest struct {
	Name          string          `json:"name" validate:"required"`
	Description   string          `json:"description,omitempty"`
	Enabled       *bool           `json:"enabled,omitempty"` // nil = use DB default (true)
	CelExpression string          `json:"cel_expression"`
	Targets       []RoutingTarget `json:"targets"` // Required; weights must sum to 1
	Fallbacks     []string        `json:"fallbacks,omitempty"`
	Scope         string          `json:"scope,omitempty"` // Defaults to "global" if not provided
	ScopeID       *string         `json:"scope_id,omitempty"`
	Query         map[string]any  `json:"query,omitempty"`
	Priority      int             `json:"priority,omitempty"` // Defaults to 0 if not provided
}

// UpdateRoutingRuleRequest represents the request body for updating a routing rule
type UpdateRoutingRuleRequest struct {
	Name          *string         `json:"name,omitempty"`
	Description   *string         `json:"description,omitempty"`
	Enabled       *bool           `json:"enabled,omitempty"`
	CelExpression *string         `json:"cel_expression,omitempty"`
	Targets       []RoutingTarget `json:"targets,omitempty"` // If provided, replaces all existing targets; weights must sum to 1
	Fallbacks     []string        `json:"fallbacks,omitempty"`
	Query         map[string]any  `json:"query,omitempty"`
	Priority      *int            `json:"priority,omitempty"`
	Scope         *string         `json:"scope,omitempty"`
	ScopeID       *string         `json:"scope_id,omitempty"`
}

// CreateRateLimitRequest represents the request body for creating a rate limit using flexible approach
type CreateRateLimitRequest struct {
	TokenMaxLimit        *int64  `json:"token_max_limit,omitempty"`        // Maximum tokens allowed
	TokenResetDuration   *string `json:"token_reset_duration,omitempty"`   // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
	RequestMaxLimit      *int64  `json:"request_max_limit,omitempty"`      // Maximum requests allowed
	RequestResetDuration *string `json:"request_reset_duration,omitempty"` // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
}

// UpdateRateLimitRequest represents the request body for updating a rate limit using flexible approach
type UpdateRateLimitRequest struct {
	TokenMaxLimit        *int64  `json:"token_max_limit,omitempty"`        // Maximum tokens allowed
	TokenResetDuration   *string `json:"token_reset_duration,omitempty"`   // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
	RequestMaxLimit      *int64  `json:"request_max_limit,omitempty"`      // Maximum requests allowed
	RequestResetDuration *string `json:"request_reset_duration,omitempty"` // e.g., "30s", "5m", "1h", "1d", "1w", "1M"
}

func isBudgetRemovalRequest(req *UpdateBudgetRequest) bool {
	return req != nil && req.MaxLimit == nil && req.ResetDuration == nil
}

// normaliseWorkspaceIDPtr translates the request-side WorkspaceID convention
// (nil = unset, "" = explicitly clear, non-empty = scope to workspace) into
// the storage-side convention (TableVirtualKey.WorkspaceID is *string with
// nil meaning org-wide). Callers should only invoke this when they have
// decided to apply the field - i.e. when req.WorkspaceID itself is non-nil.
func normaliseWorkspaceIDPtr(reqWS *string) *string {
	if reqWS == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*reqWS)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func isRateLimitRemovalRequest(req *UpdateRateLimitRequest) bool {
	return req != nil && req.TokenMaxLimit == nil && req.RequestMaxLimit == nil &&
		req.TokenResetDuration == nil && req.RequestResetDuration == nil
}

const modelConfigUsageControlsRequiredError = "at least one budget or rate limit is required"

func createRateLimitHasValues(rateLimit *CreateRateLimitRequest) bool {
	return rateLimit != nil && (rateLimit.TokenMaxLimit != nil || rateLimit.RequestMaxLimit != nil)
}

func updateRateLimitHasValues(rateLimit *UpdateRateLimitRequest) bool {
	return rateLimit != nil && (rateLimit.TokenMaxLimit != nil || rateLimit.RequestMaxLimit != nil)
}

func createModelConfigHasUsageControls(req CreateModelConfigRequest) bool {
	return req.Budget != nil || createRateLimitHasValues(req.RateLimit)
}

func updatedModelConfigHasUsageControls(existing *configstoreTables.TableModelConfig, req UpdateModelConfigRequest) bool {
	budgetPresent := existing != nil && existing.BudgetID != nil
	if req.Budget != nil {
		budgetPresent = req.Budget.MaxLimit != nil
	}

	rateLimitPresent := existing != nil && existing.RateLimitID != nil
	if req.RateLimit != nil {
		rateLimitPresent = updateRateLimitHasValues(req.RateLimit)
	}

	return budgetPresent || rateLimitPresent
}

func validateModelConfigBudgetUpdate(existing *configstoreTables.TableModelConfig, req *UpdateBudgetRequest) error {
	if req == nil || req.MaxLimit == nil {
		return nil
	}
	if req.ResetDuration == nil {
		if existing != nil && existing.BudgetID != nil {
			return fmt.Errorf("both max_limit and reset_duration are required when updating a budget")
		}
		return fmt.Errorf("both max_limit and reset_duration are required when creating a new budget")
	}
	return validateBudget(&configstoreTables.TableBudget{
		MaxLimit:      *req.MaxLimit,
		ResetDuration: *req.ResetDuration,
	})
}

func validateModelConfigRateLimitUpdate(req *UpdateRateLimitRequest) error {
	if req == nil || !updateRateLimitHasValues(req) {
		return nil
	}
	return validateRateLimit(&configstoreTables.TableRateLimit{
		TokenMaxLimit:        req.TokenMaxLimit,
		TokenResetDuration:   req.TokenResetDuration,
		RequestMaxLimit:      req.RequestMaxLimit,
		RequestResetDuration: req.RequestResetDuration,
	})
}

func modelConfigConflictMessage(modelName string, provider *string) string {
	if provider != nil {
		return fmt.Sprintf("Model config for model '%s' with provider '%s' already exists", modelName, *provider)
	}
	return fmt.Sprintf("Model config for model '%s' (global) already exists", modelName)
}

func collectProviderConfigDeleteIDs(
	config configstoreTables.TableVirtualKeyProviderConfig,
	budgetIDs []string,
	rateLimitIDs []string,
) ([]string, []string) {
	if config.BudgetID != nil {
		budgetIDs = append(budgetIDs, *config.BudgetID)
	}
	if config.RateLimitID != nil {
		rateLimitIDs = append(rateLimitIDs, *config.RateLimitID)
	}
	return budgetIDs, rateLimitIDs
}

func normalizeGuardrailPolicyIDs(policyIDs []string) []string {
	if len(policyIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(policyIDs))
	normalized := make([]string, 0, len(policyIDs))
	for _, policyID := range policyIDs {
		trimmed := strings.TrimSpace(policyID)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func (h *GovernanceHandler) validateGuardrailPolicyIDs(ctx context.Context, policyIDs []string) ([]string, error) {
	normalized := normalizeGuardrailPolicyIDs(policyIDs)
	for _, policyID := range normalized {
		policy, err := h.configStore.GetGuardrailPolicy(ctx, policyID)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			return nil, fmt.Errorf("guardrail policy %s not found", policyID)
		}
	}
	return normalized, nil
}

// CreateTeamRequest represents the request body for creating a team
type CreateTeamRequest struct {
	Name              string                  `json:"name" validate:"required"`
	CustomerID        *string                 `json:"customer_id,omitempty"`         // Team can belong to a customer
	MemberUserIDs     []string                `json:"member_user_ids,omitempty"`     // Active workspace users assigned to the team
	MemberCustomerIDs []string                `json:"member_customer_ids,omitempty"` // Governance members assigned to the team
	Budget            *CreateBudgetRequest    `json:"budget,omitempty"`              // Team can have its own budget
	RateLimit         *CreateRateLimitRequest `json:"rate_limit,omitempty"`          // Team can have its own rate limit
	// AllowedTools narrows what tools any VK owned by this team can
	// invoke via the agentic PEP. Empty = no team-level cap.
	AllowedTools []string `json:"allowed_tools,omitempty"`
	// ApplyToAllWorkspaces toggles team scope. true → workspace_id is
	// stored as NULL (visible in every workspace under the tenant);
	// false (default) → stamped from X-Active-Workspace-Id and visible
	// only in that workspace.
	ApplyToAllWorkspaces bool `json:"apply_to_all_workspaces,omitempty"`
}

// UpdateTeamRequest represents the request body for updating a team
type UpdateTeamRequest struct {
	Name              *string                 `json:"name,omitempty"`
	CustomerID        *string                 `json:"customer_id,omitempty"`
	MemberUserIDs     *[]string               `json:"member_user_ids,omitempty"`
	MemberCustomerIDs *[]string               `json:"member_customer_ids,omitempty"`
	Budget            *UpdateBudgetRequest    `json:"budget,omitempty"`
	RateLimit         *UpdateRateLimitRequest `json:"rate_limit,omitempty"`
	// AllowedTools - pointer-to-slice so callers can distinguish
	// "leave alone" (nil) from "clear" (empty slice).
	AllowedTools *[]string `json:"allowed_tools,omitempty"`
}

// CreateCustomerRequest represents the request body for creating a customer
type CreateCustomerRequest struct {
	Name      string                  `json:"name" validate:"required"`
	Budget    *CreateBudgetRequest    `json:"budget,omitempty"`
	RateLimit *CreateRateLimitRequest `json:"rate_limit,omitempty"` // Customer can have its own rate limit
	// AllowedTools is a per-member override for the agentic PEP.
	// Empty = inherit from the Team or fall through to the VK.
	AllowedTools []string `json:"allowed_tools,omitempty"`
	// ApplyToAllWorkspaces toggles customer scope. true → workspace_id
	// is stored as NULL (visible in every workspace under the tenant);
	// false (default) → stamped from X-Active-Workspace-Id and visible
	// only in that workspace.
	ApplyToAllWorkspaces bool `json:"apply_to_all_workspaces,omitempty"`
}

// UpdateCustomerRequest represents the request body for updating a customer
type UpdateCustomerRequest struct {
	Name      *string                 `json:"name,omitempty"`
	Budget    *UpdateBudgetRequest    `json:"budget,omitempty"`
	RateLimit *UpdateRateLimitRequest `json:"rate_limit,omitempty"`
	// AllowedTools override - pointer-to-slice for nil vs empty.
	AllowedTools *[]string `json:"allowed_tools,omitempty"`
}

// CreateModelConfigRequest represents the request body for creating a model config
type CreateModelConfigRequest struct {
	ModelName string                  `json:"model_name" validate:"required"`
	Provider  *string                 `json:"provider,omitempty"` // Optional provider, nil means all providers
	Budget    *CreateBudgetRequest    `json:"budget,omitempty"`
	RateLimit *CreateRateLimitRequest `json:"rate_limit,omitempty"`
}

// UpdateModelConfigRequest represents the request body for updating a model config
type UpdateModelConfigRequest struct {
	ModelName *string                 `json:"model_name,omitempty"`
	Provider  *string                 `json:"provider,omitempty"` // Optional provider, nil means no change
	Budget    *UpdateBudgetRequest    `json:"budget,omitempty"`
	RateLimit *UpdateRateLimitRequest `json:"rate_limit,omitempty"`
}

// UpdateProviderGovernanceRequest represents the request body for updating provider governance
type UpdateProviderGovernanceRequest struct {
	Budget    *UpdateBudgetRequest    `json:"budget,omitempty"`
	RateLimit *UpdateRateLimitRequest `json:"rate_limit,omitempty"`
}

// RegisterRoutes registers all governance-related routes for the new hierarchical system
func (h *GovernanceHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// Virtual Key CRUD operations
	r.GET("/api/governance/virtual-keys", lib.ChainMiddlewares(h.getVirtualKeys, middlewares...))
	r.POST("/api/governance/virtual-keys", lib.ChainMiddlewares(h.createVirtualKey, middlewares...))
	r.PATCH("/api/governance/virtual-keys/{vk_id}/workspace", lib.ChainMiddlewares(h.moveVirtualKeyWorkspace, middlewares...))
	r.PATCH("/api/governance/routing-rules/{rule_id}/workspace", lib.ChainMiddlewares(h.moveRoutingRuleWorkspace, middlewares...))
	r.PATCH("/api/governance/model-configs/{mc_id}/workspace", lib.ChainMiddlewares(h.moveModelConfigWorkspace, middlewares...))
	r.GET("/api/governance/virtual-keys/{vk_id}", lib.ChainMiddlewares(h.getVirtualKey, middlewares...))
	r.PUT("/api/governance/virtual-keys/{vk_id}", lib.ChainMiddlewares(h.updateVirtualKey, middlewares...))
	r.DELETE("/api/governance/virtual-keys/{vk_id}", lib.ChainMiddlewares(h.deleteVirtualKey, middlewares...))
	r.POST("/api/governance/virtual-keys/{vk_id}/rotate", lib.ChainMiddlewares(h.rotateVirtualKey, middlewares...))
	// Bulk agent-attribute apply - set agent_risk_level / agent_capabilities
	// across an explicit multi-select of VKs OR every agent-bound VK in the
	// active workspace. Workspace-scoped: only VKs in the caller's workspace
	// are touched (strict isolation).
	r.POST("/api/governance/virtual-keys/bulk-agent-attributes", lib.ChainMiddlewares(h.bulkUpdateVirtualKeyAgentAttributes, middlewares...))

	// Team CRUD operations
	r.GET("/api/governance/teams", lib.ChainMiddlewares(h.getTeams, middlewares...))
	r.POST("/api/governance/teams", lib.ChainMiddlewares(h.createTeam, middlewares...))
	r.GET("/api/governance/teams/{team_id}", lib.ChainMiddlewares(h.getTeam, middlewares...))
	r.PUT("/api/governance/teams/{team_id}", lib.ChainMiddlewares(h.updateTeam, middlewares...))
	r.DELETE("/api/governance/teams/{team_id}", lib.ChainMiddlewares(h.deleteTeam, middlewares...))

	// Customer CRUD operations
	r.GET("/api/governance/customers", lib.ChainMiddlewares(h.getCustomers, middlewares...))
	r.POST("/api/governance/customers", lib.ChainMiddlewares(h.createCustomer, middlewares...))
	r.GET("/api/governance/customers/{customer_id}", lib.ChainMiddlewares(h.getCustomer, middlewares...))
	r.PUT("/api/governance/customers/{customer_id}", lib.ChainMiddlewares(h.updateCustomer, middlewares...))
	r.DELETE("/api/governance/customers/{customer_id}", lib.ChainMiddlewares(h.deleteCustomer, middlewares...))

	// Workspace user provisioning (read-only listing + removal). The
	// invite / role-mutation provisioning surface is an enterprise
	// multi-tenant feature and is not part of the OSS build.
	r.GET("/api/governance/users", lib.ChainMiddlewares(h.getProvisionedUsers, middlewares...))
	r.DELETE("/api/governance/users/{user_id}", lib.ChainMiddlewares(h.deleteProvisionedUser, middlewares...))

	// Budget and Rate Limit GET operations
	r.GET("/api/governance/budgets", lib.ChainMiddlewares(h.getBudgets, middlewares...))
	r.GET("/api/governance/rate-limits", lib.ChainMiddlewares(h.getRateLimits, middlewares...))

	// Routing Rules CRUD operations
	r.GET("/api/governance/routing-rules", lib.ChainMiddlewares(h.getRoutingRules, middlewares...))
	r.POST("/api/governance/routing-rules", lib.ChainMiddlewares(h.createRoutingRule, middlewares...))
	r.GET("/api/governance/routing-rules/{rule_id}", lib.ChainMiddlewares(h.getRoutingRule, middlewares...))
	r.PUT("/api/governance/routing-rules/{rule_id}", lib.ChainMiddlewares(h.updateRoutingRule, middlewares...))
	r.DELETE("/api/governance/routing-rules/{rule_id}", lib.ChainMiddlewares(h.deleteRoutingRule, middlewares...))

	// Model Config CRUD operations
	r.GET("/api/governance/model-configs", lib.ChainMiddlewares(h.getModelConfigs, middlewares...))
	r.POST("/api/governance/model-configs", lib.ChainMiddlewares(h.createModelConfig, middlewares...))
	r.GET("/api/governance/model-configs/{mc_id}", lib.ChainMiddlewares(h.getModelConfig, middlewares...))
	r.PUT("/api/governance/model-configs/{mc_id}", lib.ChainMiddlewares(h.updateModelConfig, middlewares...))
	r.DELETE("/api/governance/model-configs/{mc_id}", lib.ChainMiddlewares(h.deleteModelConfig, middlewares...))

	// Provider Governance operations
	r.GET("/api/governance/providers", lib.ChainMiddlewares(h.getProviderGovernance, middlewares...))
	r.PUT("/api/governance/providers/{provider_name}", lib.ChainMiddlewares(h.updateProviderGovernance, middlewares...))
	r.DELETE("/api/governance/providers/{provider_name}", lib.ChainMiddlewares(h.deleteProviderGovernance, middlewares...))

	// Load Balancer key health status
	r.GET("/api/governance/key-health", lib.ChainMiddlewares(h.getKeyHealth, middlewares...))
}

// Virtual Key CRUD Operations

// getVirtualKeys handles GET /api/governance/virtual-keys - Get all virtual keys with relationships
func (h *GovernanceHandler) getVirtualKeys(ctx *fasthttp.RequestCtx) {
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		// Convert map to slice to match the non-memory response format (array)
		virtualKeys := make([]*configstoreTables.TableVirtualKey, 0, len(data.VirtualKeys))
		for _, vk := range data.VirtualKeys {
			virtualKeys = append(virtualKeys, vk)
		}
		sort.Slice(virtualKeys, func(i, j int) bool {
			return virtualKeys[i].CreatedAt.Before(virtualKeys[j].CreatedAt)
		})
		SendJSON(ctx, map[string]interface{}{
			"virtual_keys": virtualKeys,
			"count":        len(virtualKeys),
			"total_count":  len(virtualKeys),
			"limit":        len(virtualKeys),
			"offset":       0,
		})
		return
	}
	// Check for pagination/filter parameters
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	offsetStr := string(ctx.QueryArgs().Peek("offset"))
	search := string(ctx.QueryArgs().Peek("search"))
	customerID := string(ctx.QueryArgs().Peek("customer_id"))
	teamID := string(ctx.QueryArgs().Peek("team_id"))
	workspaceID := string(ctx.QueryArgs().Peek("workspace_id"))
	// Fall back to the sidebar's active workspace (X-Active-Workspace-Id)
	// when the caller didn't pass an explicit query param. The frontend
	// already does for this endpoint, but other callers (CLI/SDK) may not.
	if strings.TrimSpace(workspaceID) == "" {
		if ws := tenantctx.WorkspaceIDFromContext(ctx); ws != "" {
			workspaceID = ws
		}
	}

	if limitStr != "" || offsetStr != "" || search != "" || customerID != "" || teamID != "" || workspaceID != "" {
		// Paginated/filtered path
		params := configstore.VirtualKeyQueryParams{
			Search:      search,
			CustomerID:  customerID,
			TeamID:      teamID,
			WorkspaceID: workspaceID,
		}
		if limitStr != "" {
			n, err := strconv.Atoi(limitStr)
			if err != nil {
				SendError(ctx, 400, "Invalid limit parameter: must be a number")
				return
			}
			if n < 0 {
				SendError(ctx, 400, "Invalid limit parameter: must be non-negative")
				return
			}
			params.Limit = n
		}
		if offsetStr != "" {
			n, err := strconv.Atoi(offsetStr)
			if err != nil {
				SendError(ctx, 400, "Invalid offset parameter: must be a number")
				return
			}
			if n < 0 {
				SendError(ctx, 400, "Invalid offset parameter: must be non-negative")
				return
			}
			params.Offset = n
		}

		params.Limit, params.Offset = ClampPaginationParams(params.Limit, params.Offset)
		virtualKeys, totalCount, err := h.configStore.GetVirtualKeysPaginated(ctx, params)
		if err != nil {
			logger.Error("failed to retrieve virtual keys: %v", err)
			SendError(ctx, 500, "Failed to retrieve virtual keys")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"virtual_keys": virtualKeys,
			"count":        len(virtualKeys),
			"total_count":  totalCount,
			"limit":        params.Limit,
			"offset":       params.Offset,
		})
		return
	}

	// Non-paginated path: return all virtual keys
	virtualKeys, err := h.configStore.GetVirtualKeys(ctx)
	if err != nil {
		logger.Error("failed to retrieve virtual keys: %v", err)
		SendError(ctx, 500, "Failed to retrieve virtual keys")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"virtual_keys": virtualKeys,
		"count":        len(virtualKeys),
		"total_count":  len(virtualKeys),
		"limit":        len(virtualKeys),
		"offset":       0,
	})
}

// createVirtualKey handles POST /api/governance/virtual-keys - Create a new virtual key
func (h *GovernanceHandler) createVirtualKey(ctx *fasthttp.RequestCtx) {
	var req CreateVirtualKeyRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Validate required fields
	if req.Name == "" {
		SendError(ctx, 400, "Virtual key name is required")
		return
	}
	// Open-source edition is capped at a single virtual key. DeepintShield Cloud /
	// Enterprise lifts this limit and adds tenant / workspace / team scoping.
	const openSourceMaxVirtualKeys = 1
	if existing, err := h.configStore.GetVirtualKeys(ctx); err == nil && len(existing) >= openSourceMaxVirtualKeys {
		SendError(ctx, 403, "Open-source edition is limited to a single virtual key. Upgrade to DeepintShield Cloud / Enterprise for unlimited virtual keys with team / workspace scoping.")
		return
	}
	if !h.requireWorkspaceWrite(ctx, h.resolveTargetWorkspace(ctx, req.WorkspaceID)) {
		return
	}
	// Validate mutually exclusive TeamID and CustomerID
	if req.TeamID != nil && req.CustomerID != nil {
		SendError(ctx, 400, "VirtualKey cannot be attached to both Team and Customer")
		return
	}
	// Validate budget if provided
	if req.Budget != nil {
		if req.Budget.MaxLimit < 0 {
			SendError(ctx, 400, fmt.Sprintf("Budget max_limit cannot be negative: %.2f", req.Budget.MaxLimit))
			return
		}
		// Validate reset duration format
		if _, err := configstoreTables.ParseDuration(req.Budget.ResetDuration); err != nil {
			SendError(ctx, 400, fmt.Sprintf("Invalid reset duration format: %s", req.Budget.ResetDuration))
			return
		}
	}
	guardrailPolicyIDs, err := h.validateGuardrailPolicyIDs(ctx, req.GuardrailPolicyIDs)
	if err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	// Set defaults
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	var vk configstoreTables.TableVirtualKey
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		vk = configstoreTables.TableVirtualKey{
			ID:                             uuid.NewString(),
			Name:                           req.Name,
			Value:                          governance.GenerateVirtualKey(),
			Description:                    req.Description,
			CacheKey:                       strings.TrimSpace(req.CacheKey),
			CacheEnabled:                   req.CacheEnabled,
			SemanticCacheEnabled:           req.SemanticCacheEnabled,
			CacheScopeMode:                 req.CacheScopeMode,
			CacheMetadataScopeKeys:         req.CacheMetadataScopeKeys,
			CacheAllowSemanticWhenUnscoped: req.CacheAllowSemanticWhenUnscoped,
			FallbackChain:                  req.FallbackChain,
			TeamID:                         req.TeamID,
			CustomerID:                     req.CustomerID,
			WorkspaceID:                    normaliseWorkspaceIDPtr(req.WorkspaceID),
			IsActive:                       isActive,
		}
		// Agent Scope (unified-VK). Non-nil pointers opt this VK into
		// agent semantics - the PEP will fire on calls authenticated by
		// this bearer. Leaving everything nil keeps the VK LLM-only.
		if req.BoundIdentityProvider != nil {
			vk.BoundIdentityProvider = strings.TrimSpace(*req.BoundIdentityProvider)
		}
		if req.IdentityProviderID != nil {
			vk.IdentityProviderID = strings.TrimSpace(*req.IdentityProviderID)
		}
		// AllowedTools / AutonomyBudget / DefaultObligations /
		// ToolRateLimitPerMinute on the VK request are accepted for
		// backward compatibility but no longer persisted on the VK
		// row - they live on per-VK policies (agentic_policy_vk_targets).
		if req.AgentScopes != nil {
			vk.AgentScopes = append([]string(nil), (*req.AgentScopes)...)
		}
		if req.AgentRiskLevel != nil {
			vk.AgentRiskLevel = normaliseAgentRiskLevel(*req.AgentRiskLevel)
		}
		if req.AgentCapabilities != nil {
			vk.AgentCapabilities = normaliseAgentCapabilities(*req.AgentCapabilities)
		}
		if req.AgentNamespace != nil {
			vk.AgentNamespace = strings.ToLower(strings.TrimSpace(*req.AgentNamespace))
		}
		// Apply rotation schedule at create time. When RotationPeriodDays
		// is positive we also stamp NextRotationAt so the worker can pick
		// the row up without waiting for an admin to hit the rotate
		// endpoint. Negative values get clamped to zero to mirror the
		// rotateVirtualKey handler's tolerance.
		if req.RotationPeriodDays != nil {
			period := *req.RotationPeriodDays
			if period <= 0 {
				vk.RotationPeriodDays = nil
				vk.NextRotationAt = nil
			} else {
				vk.RotationPeriodDays = &period
				nxt := time.Now().UTC().Add(time.Duration(period) * 24 * time.Hour)
				vk.NextRotationAt = &nxt
			}
		}
		if req.RotationGracePeriodDays != nil {
			grace := *req.RotationGracePeriodDays
			if grace < 0 {
				grace = 0
			}
			vk.RotationGracePeriodDays = grace
		}
		if req.Budget != nil {
			budget := configstoreTables.TableBudget{
				ID:            uuid.NewString(),
				MaxLimit:      req.Budget.MaxLimit,
				ResetDuration: req.Budget.ResetDuration,
				LastReset:     time.Now(),
				CurrentUsage:  0,
			}
			if err := validateBudget(&budget); err != nil {
				return err
			}
			if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
				return err
			}
			vk.BudgetID = &budget.ID
		}
		if req.RateLimit != nil {
			rateLimit := configstoreTables.TableRateLimit{
				ID:                   uuid.NewString(),
				TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
				TokenResetDuration:   req.RateLimit.TokenResetDuration,
				RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
				RequestResetDuration: req.RateLimit.RequestResetDuration,
				TokenLastReset:       time.Now(),
				RequestLastReset:     time.Now(),
			}
			if err := validateRateLimit(&rateLimit); err != nil {
				return err
			}
			if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
				return err
			}
			vk.RateLimitID = &rateLimit.ID
		}
		if err := h.configStore.CreateVirtualKey(ctx, &vk, tx); err != nil {
			return err
		}
		if err := h.configStore.ReplaceVirtualKeyGuardrailPolicies(ctx, vk.ID, guardrailPolicyIDs, tx); err != nil {
			return err
		}
		if req.ProviderConfigs != nil {
			for _, pc := range req.ProviderConfigs {
				// Validate budget if provided
				if pc.Budget != nil {
					if pc.Budget.MaxLimit < 0 {
						return fmt.Errorf("provider config budget max_limit cannot be negative: %.2f", pc.Budget.MaxLimit)
					}
					// Validate reset duration format
					if _, err := configstoreTables.ParseDuration(pc.Budget.ResetDuration); err != nil {
						return fmt.Errorf("invalid provider config budget reset duration format: %s", pc.Budget.ResetDuration)
					}
				}

				// Get keys for this provider config if specified
				var keys []configstoreTables.TableKey
				if len(pc.KeyIDs) > 0 {
					var err error
					keys, err = h.configStore.GetKeysByIDs(ctx, pc.KeyIDs)
					if err != nil {
						return fmt.Errorf("failed to get keys by IDs for provider %s: %w", pc.Provider, err)
					}
					if len(keys) != len(pc.KeyIDs) {
						return fmt.Errorf("some keys not found for provider %s: expected %d, found %d", pc.Provider, len(pc.KeyIDs), len(keys))
					}
				}

				providerConfig := &configstoreTables.TableVirtualKeyProviderConfig{
					VirtualKeyID:         vk.ID,
					Provider:             pc.Provider,
					Weight:               &pc.Weight,
					AllowedModels:        pc.AllowedModels,
					KeySelectionStrategy: pc.KeySelectionStrategy,
					Keys:                 keys,
				}

				// Create budget for provider config if provided
				if pc.Budget != nil {
					budget := configstoreTables.TableBudget{
						ID:            uuid.NewString(),
						MaxLimit:      pc.Budget.MaxLimit,
						ResetDuration: pc.Budget.ResetDuration,
						LastReset:     time.Now(),
						CurrentUsage:  0,
					}
					if err := validateBudget(&budget); err != nil {
						return err
					}
					if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
						return err
					}
					providerConfig.BudgetID = &budget.ID
				}
				// Create rate limit for provider config if provided
				if pc.RateLimit != nil {
					rateLimit := configstoreTables.TableRateLimit{
						ID:                   uuid.NewString(),
						TokenMaxLimit:        pc.RateLimit.TokenMaxLimit,
						TokenResetDuration:   pc.RateLimit.TokenResetDuration,
						RequestMaxLimit:      pc.RateLimit.RequestMaxLimit,
						RequestResetDuration: pc.RateLimit.RequestResetDuration,
						TokenLastReset:       time.Now(),
						RequestLastReset:     time.Now(),
					}
					if err := validateRateLimit(&rateLimit); err != nil {
						return err
					}
					if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
						return err
					}
					providerConfig.RateLimitID = &rateLimit.ID
				}

				if err := h.configStore.CreateVirtualKeyProviderConfig(ctx, providerConfig, tx); err != nil {
					return err
				}
			}
		}
		if req.MCPConfigs != nil {
			// Check for duplicate MCPClientName values before processing
			seenMCPClientNames := make(map[string]bool)
			for _, mc := range req.MCPConfigs {
				if seenMCPClientNames[mc.MCPClientName] {
					return fmt.Errorf("duplicate mcp_client_name: %s", mc.MCPClientName)
				}
				seenMCPClientNames[mc.MCPClientName] = true
			}

			for _, mc := range req.MCPConfigs {
				mcpClient, err := h.configStore.GetMCPClientByName(ctx, mc.MCPClientName)
				if err != nil {
					return fmt.Errorf("failed to get MCP client: %w", err)
				}
				if err := h.configStore.CreateVirtualKeyMCPConfig(ctx, &configstoreTables.TableVirtualKeyMCPConfig{
					VirtualKeyID:   vk.ID,
					MCPClientID:    mcpClient.ID,
					ToolsToExecute: mc.ToolsToExecute,
				}, tx); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		// Check if this is a duplicate MCPClientName error and return 400 instead of 500
		if strings.Contains(err.Error(), "duplicate mcp_client_name:") {
			SendError(ctx, 400, err.Error())
			return
		}
		SendError(ctx, 500, err.Error())
		return
	}
	preloadedVk, err := h.governanceManager.ReloadVirtualKey(ctx, vk.ID)
	if err != nil {
		logger.Error("failed to reload virtual key: %v", err)
		preloadedVk = &vk
	}
	// Push the new VK's agent scope into the runtime's in-memory map
	// so the PEP sees it on the very next call - no restart needed.
	h.syncVKToAgenticResolver(preloadedVk)

	SendJSON(ctx, map[string]any{
		"message":     "Virtual key created successfully",
		"virtual_key": preloadedVk,
	})
}

// getVirtualKey handles GET /api/governance/virtual-keys/{vk_id} - Get a specific virtual key
func (h *GovernanceHandler) getVirtualKey(ctx *fasthttp.RequestCtx) {
	vkID := ctx.UserValue("vk_id").(string)
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		for _, vk := range data.VirtualKeys {
			if vk.ID == vkID {
				SendJSON(ctx, map[string]interface{}{
					"virtual_key": vk,
				})
				return
			}
		}
		SendError(ctx, 404, "Virtual key not found")
		return
	}
	vk, err := h.configStore.GetVirtualKey(ctx, vkID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Virtual key not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve virtual key")
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"virtual_key": vk,
	})
}

// updateVirtualKey handles PUT /api/governance/virtual-keys/{vk_id} - Update a virtual key
func (h *GovernanceHandler) updateVirtualKey(ctx *fasthttp.RequestCtx) {
	vkID := ctx.UserValue("vk_id").(string)
	var req UpdateVirtualKeyRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Validate mutually exclusive TeamID and CustomerID
	if req.TeamID != nil && req.CustomerID != nil {
		SendError(ctx, 400, "VirtualKey cannot be attached to both Team and Customer")
		return
	}
	vk, err := h.configStore.GetVirtualKey(ctx, vkID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Virtual key not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve virtual key")
		return
	}
	// Workspace-write check against the VK's current workspace pinning.
	currentWS := ""
	if vk.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*vk.WorkspaceID)
	}
	if !h.requireWorkspaceWrite(ctx, currentWS) {
		return
	}
	var guardrailPolicyIDs []string
	if req.GuardrailPolicyIDs != nil {
		guardrailPolicyIDs, err = h.validateGuardrailPolicyIDs(ctx, req.GuardrailPolicyIDs)
		if err != nil {
			SendError(ctx, 400, err.Error())
			return
		}
	}
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		var budgetIDToDelete, rateLimitIDToDelete string
		var providerBudgetIDsToDelete, providerRateLimitIDsToDelete []string

		// Update fields if provided
		if req.Name != nil {
			vk.Name = *req.Name
		}
		if req.Description != nil {
			vk.Description = *req.Description
		}
		if req.CacheKey != nil {
			vk.CacheKey = strings.TrimSpace(*req.CacheKey)
		}
		if req.CacheEnabled != nil {
			vk.CacheEnabled = req.CacheEnabled
		}
		if req.SemanticCacheEnabled != nil {
			vk.SemanticCacheEnabled = req.SemanticCacheEnabled
		}
		if req.CacheScopeMode != nil {
			vk.CacheScopeMode = req.CacheScopeMode
		}
		if req.CacheMetadataScopeKeys != nil {
			vk.CacheMetadataScopeKeys = *req.CacheMetadataScopeKeys
		}
		if req.CacheAllowSemanticWhenUnscoped != nil {
			vk.CacheAllowSemanticWhenUnscoped = req.CacheAllowSemanticWhenUnscoped
		}
		// FallbackChain uses a pointer-to-slice so callers can distinguish
		// "leave alone" (nil) from "clear" (empty slice).
		if req.FallbackChain != nil {
			vk.FallbackChain = *req.FallbackChain
		}
		if req.TeamID != nil {
			vk.TeamID = req.TeamID
			vk.CustomerID = nil // Clear CustomerID if setting TeamID
		}
		if req.CustomerID != nil {
			vk.CustomerID = req.CustomerID
			vk.TeamID = nil // Clear TeamID if setting CustomerID
		}
		// When both TeamID and CustomerID are nil
		if req.TeamID == nil && req.CustomerID == nil {
			vk.TeamID = nil
			vk.CustomerID = nil
		}
		// WorkspaceID semantics: nil = leave unchanged; "" = clear; any
		// other value = (re)scope. We can't use a plain pointer-vs-empty
		// check on the struct field because GORM serialises both as NULL.
		if req.WorkspaceID != nil {
			vk.WorkspaceID = normaliseWorkspaceIDPtr(req.WorkspaceID)
		}
		if req.IsActive != nil {
			vk.IsActive = *req.IsActive
		}
		// Agent Scope (unified-VK) updates. Pointer-vs-nil distinguishes
		// "leave alone" (nil) from "explicit empty" (empty string / empty
		// slice); the latter is how callers clear an agent binding.
		if req.BoundIdentityProvider != nil {
			vk.BoundIdentityProvider = strings.TrimSpace(*req.BoundIdentityProvider)
		}
		if req.IdentityProviderID != nil {
			vk.IdentityProviderID = strings.TrimSpace(*req.IdentityProviderID)
		}
		// AllowedTools / AutonomyBudget / DefaultObligations /
		// ToolRateLimitPerMinute on the VK request are accepted for
		// backward compatibility but no longer persisted on the VK
		// row - they live on per-VK policies (agentic_policy_vk_targets).
		if req.AgentScopes != nil {
			vk.AgentScopes = append([]string(nil), (*req.AgentScopes)...)
		}
		if req.AgentRiskLevel != nil {
			vk.AgentRiskLevel = normaliseAgentRiskLevel(*req.AgentRiskLevel)
		}
		if req.AgentCapabilities != nil {
			vk.AgentCapabilities = normaliseAgentCapabilities(*req.AgentCapabilities)
		}
		if req.AgentNamespace != nil {
			vk.AgentNamespace = strings.ToLower(strings.TrimSpace(*req.AgentNamespace))
		}
		// Handle budget updates
		if req.Budget != nil {
			if isBudgetRemovalRequest(req.Budget) {
				if vk.BudgetID != nil {
					budgetIDToDelete = *vk.BudgetID
					vk.BudgetID = nil
					vk.Budget = nil
				}
			} else if vk.BudgetID != nil {
				// Update existing budget
				budget := configstoreTables.TableBudget{}
				if err := tx.First(&budget, "id = ?", *vk.BudgetID).Error; err != nil {
					return err
				}

				if req.Budget.MaxLimit != nil {
					budget.MaxLimit = *req.Budget.MaxLimit
				}
				if req.Budget.ResetDuration != nil {
					budget.ResetDuration = *req.Budget.ResetDuration
				}
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.UpdateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				vk.Budget = &budget
			} else {
				// Create new budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when creating a new budget")
				}
				if *req.Budget.MaxLimit < 0 {
					return fmt.Errorf("budget max_limit cannot be negative: %.2f", *req.Budget.MaxLimit)
				}
				if _, err := configstoreTables.ParseDuration(*req.Budget.ResetDuration); err != nil {
					return fmt.Errorf("invalid reset duration format: %s", *req.Budget.ResetDuration)
				}
				// Storing now
				budget := configstoreTables.TableBudget{
					ID:            uuid.NewString(),
					MaxLimit:      *req.Budget.MaxLimit,
					ResetDuration: *req.Budget.ResetDuration,
					LastReset:     time.Now(),
					CurrentUsage:  0,
				}
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				vk.BudgetID = &budget.ID
				vk.Budget = &budget
			}
		}
		// Handle rate limit updates
		if req.RateLimit != nil {
			if isRateLimitRemovalRequest(req.RateLimit) {
				if vk.RateLimitID != nil {
					rateLimitIDToDelete = *vk.RateLimitID
					vk.RateLimitID = nil
					vk.RateLimit = nil
				}
			} else if vk.RateLimitID != nil {
				// Update existing rate limit
				rateLimit := configstoreTables.TableRateLimit{}
				if err := tx.First(&rateLimit, "id = ?", *vk.RateLimitID).Error; err != nil {
					return err
				}

				if req.RateLimit.TokenMaxLimit != nil {
					rateLimit.TokenMaxLimit = req.RateLimit.TokenMaxLimit
				}
				if req.RateLimit.TokenResetDuration != nil {
					rateLimit.TokenResetDuration = req.RateLimit.TokenResetDuration
				}
				if req.RateLimit.RequestMaxLimit != nil {
					rateLimit.RequestMaxLimit = req.RateLimit.RequestMaxLimit
				}
				if req.RateLimit.RequestResetDuration != nil {
					rateLimit.RequestResetDuration = req.RateLimit.RequestResetDuration
				}

				if err := h.configStore.UpdateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
			} else {
				// Create new rate limit
				rateLimit := configstoreTables.TableRateLimit{
					ID:                   uuid.NewString(),
					TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
					TokenResetDuration:   req.RateLimit.TokenResetDuration,
					RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
					RequestResetDuration: req.RateLimit.RequestResetDuration,
					TokenLastReset:       time.Now(),
					RequestLastReset:     time.Now(),
				}
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				vk.RateLimitID = &rateLimit.ID
			}
		}

		if err := h.configStore.UpdateVirtualKey(ctx, vk, tx); err != nil {
			return err
		}
		if req.GuardrailPolicyIDs != nil {
			if err := h.configStore.ReplaceVirtualKeyGuardrailPolicies(ctx, vk.ID, guardrailPolicyIDs, tx); err != nil {
				return err
			}
		}
		if req.ProviderConfigs != nil {
			// Get existing provider configs for comparison
			var existingConfigs []configstoreTables.TableVirtualKeyProviderConfig
			if err := tx.Where("virtual_key_id = ?", vk.ID).Find(&existingConfigs).Error; err != nil {
				return err
			}
			// Create maps for easier lookup
			existingConfigsMap := make(map[uint]configstoreTables.TableVirtualKeyProviderConfig)
			for _, config := range existingConfigs {
				existingConfigsMap[config.ID] = config
			}
			requestConfigsMap := make(map[uint]bool)
			// Process new configs: create new ones and update existing ones
			for _, pc := range req.ProviderConfigs {
				if pc.ID == nil {
					// Validate budget if provided for new provider config
					if pc.Budget != nil {
						if pc.Budget.MaxLimit != nil && *pc.Budget.MaxLimit < 0 {
							return fmt.Errorf("provider config budget max_limit cannot be negative: %.2f", *pc.Budget.MaxLimit)
						}
						if pc.Budget.ResetDuration != nil {
							if _, err := configstoreTables.ParseDuration(*pc.Budget.ResetDuration); err != nil {
								return fmt.Errorf("invalid provider config budget reset duration format: %s", *pc.Budget.ResetDuration)
							}
						}
						// Both fields are required when creating new budget
						if pc.Budget.MaxLimit == nil || pc.Budget.ResetDuration == nil {
							return fmt.Errorf("both max_limit and reset_duration are required when creating a new provider budget")
						}
					}
					// Get keys for this provider config if specified
					var keys []configstoreTables.TableKey
					if len(pc.KeyIDs) > 0 {
						var err error
						keys, err = h.configStore.GetKeysByIDs(ctx, pc.KeyIDs)
						if err != nil {
							return fmt.Errorf("failed to get keys by IDs for provider %s: %w", pc.Provider, err)
						}
						if len(keys) != len(pc.KeyIDs) {
							return fmt.Errorf("some keys not found for provider %s: expected %d, found %d", pc.Provider, len(pc.KeyIDs), len(keys))
						}
					}

					// Create new provider config
					providerConfig := &configstoreTables.TableVirtualKeyProviderConfig{
						VirtualKeyID:         vk.ID,
						Provider:             pc.Provider,
						Weight:               &pc.Weight,
						AllowedModels:        pc.AllowedModels,
						KeySelectionStrategy: pc.KeySelectionStrategy,
						Keys:                 keys,
					}
					// Create budget for provider config if provided
					if pc.Budget != nil {
						budget := configstoreTables.TableBudget{
							ID:            uuid.NewString(),
							MaxLimit:      *pc.Budget.MaxLimit,
							ResetDuration: *pc.Budget.ResetDuration,
							LastReset:     time.Now(),
							CurrentUsage:  0,
						}
						if err := validateBudget(&budget); err != nil {
							return err
						}
						if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
							return err
						}
						providerConfig.BudgetID = &budget.ID
					}
					// Create rate limit for provider config if provided
					if pc.RateLimit != nil {
						rateLimit := configstoreTables.TableRateLimit{
							ID:                   uuid.NewString(),
							TokenMaxLimit:        pc.RateLimit.TokenMaxLimit,
							TokenResetDuration:   pc.RateLimit.TokenResetDuration,
							RequestMaxLimit:      pc.RateLimit.RequestMaxLimit,
							RequestResetDuration: pc.RateLimit.RequestResetDuration,
							TokenLastReset:       time.Now(),
							RequestLastReset:     time.Now(),
						}
						if err := validateRateLimit(&rateLimit); err != nil {
							return err
						}
						if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
							return err
						}
						providerConfig.RateLimitID = &rateLimit.ID
					}
					if err := h.configStore.CreateVirtualKeyProviderConfig(ctx, providerConfig, tx); err != nil {
						return err
					}
				} else {
					// Update existing provider config
					existing, ok := existingConfigsMap[*pc.ID]
					if !ok {
						return fmt.Errorf("provider config %d does not belong to this virtual key", *pc.ID)
					}
					requestConfigsMap[*pc.ID] = true
					existing.Provider = pc.Provider
					existing.Weight = &pc.Weight
					existing.AllowedModels = pc.AllowedModels
					existing.KeySelectionStrategy = pc.KeySelectionStrategy

					// Get keys for this provider config if specified
					var keys []configstoreTables.TableKey
					if len(pc.KeyIDs) > 0 {
						var err error
						keys, err = h.configStore.GetKeysByIDs(ctx, pc.KeyIDs)
						if err != nil {
							return fmt.Errorf("failed to get keys by IDs for provider %s: %w", pc.Provider, err)
						}
						if len(keys) != len(pc.KeyIDs) {
							return fmt.Errorf("some keys not found for provider %s: expected %d, found %d", pc.Provider, len(pc.KeyIDs), len(keys))
						}
					}
					existing.Keys = keys

					// Handle budget updates for provider config
					if pc.Budget != nil {
						if isBudgetRemovalRequest(pc.Budget) {
							if existing.BudgetID != nil {
								providerBudgetIDsToDelete = append(providerBudgetIDsToDelete, *existing.BudgetID)
								existing.BudgetID = nil
								existing.Budget = nil
							}
						} else if existing.BudgetID != nil {
							// Update existing budget
							budget := configstoreTables.TableBudget{}
							if err := tx.First(&budget, "id = ?", *existing.BudgetID).Error; err != nil {
								return err
							}
							if pc.Budget.MaxLimit != nil {
								budget.MaxLimit = *pc.Budget.MaxLimit
							}
							if pc.Budget.ResetDuration != nil {
								budget.ResetDuration = *pc.Budget.ResetDuration
							}
							if err := validateBudget(&budget); err != nil {
								return err
							}
							if err := h.configStore.UpdateBudget(ctx, &budget, tx); err != nil {
								return err
							}
						} else {
							// Create new budget for existing provider config
							if pc.Budget.MaxLimit == nil || pc.Budget.ResetDuration == nil {
								return fmt.Errorf("both max_limit and reset_duration are required when creating a new provider budget")
							}
							if *pc.Budget.MaxLimit < 0 {
								return fmt.Errorf("provider config budget max_limit cannot be negative: %.2f", *pc.Budget.MaxLimit)
							}
							if _, err := configstoreTables.ParseDuration(*pc.Budget.ResetDuration); err != nil {
								return fmt.Errorf("invalid provider config budget reset duration format: %s", *pc.Budget.ResetDuration)
							}
							budget := configstoreTables.TableBudget{
								ID:            uuid.NewString(),
								MaxLimit:      *pc.Budget.MaxLimit,
								ResetDuration: *pc.Budget.ResetDuration,
								LastReset:     time.Now(),
								CurrentUsage:  0,
							}
							if err := validateBudget(&budget); err != nil {
								return err
							}
							if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
								return err
							}
							existing.BudgetID = &budget.ID
						}
					}
					// Handle rate limit updates for provider config
					if pc.RateLimit != nil {
						if isRateLimitRemovalRequest(pc.RateLimit) {
							if existing.RateLimitID != nil {
								providerRateLimitIDsToDelete = append(providerRateLimitIDsToDelete, *existing.RateLimitID)
								existing.RateLimitID = nil
								existing.RateLimit = nil
							}
						} else if existing.RateLimitID != nil {
							// Update existing rate limit
							rateLimit := configstoreTables.TableRateLimit{}
							if err := tx.First(&rateLimit, "id = ?", *existing.RateLimitID).Error; err != nil {
								return err
							}
							if pc.RateLimit.TokenMaxLimit != nil {
								rateLimit.TokenMaxLimit = pc.RateLimit.TokenMaxLimit
							}
							if pc.RateLimit.TokenResetDuration != nil {
								rateLimit.TokenResetDuration = pc.RateLimit.TokenResetDuration
							}
							if pc.RateLimit.RequestMaxLimit != nil {
								rateLimit.RequestMaxLimit = pc.RateLimit.RequestMaxLimit
							}
							if pc.RateLimit.RequestResetDuration != nil {
								rateLimit.RequestResetDuration = pc.RateLimit.RequestResetDuration
							}
							if err := h.configStore.UpdateRateLimit(ctx, &rateLimit, tx); err != nil {
								return err
							}
						} else {
							// Create new rate limit for existing provider config
							rateLimit := configstoreTables.TableRateLimit{
								ID:                   uuid.NewString(),
								TokenMaxLimit:        pc.RateLimit.TokenMaxLimit,
								TokenResetDuration:   pc.RateLimit.TokenResetDuration,
								RequestMaxLimit:      pc.RateLimit.RequestMaxLimit,
								RequestResetDuration: pc.RateLimit.RequestResetDuration,
								TokenLastReset:       time.Now(),
								RequestLastReset:     time.Now(),
							}
							if err := validateRateLimit(&rateLimit); err != nil {
								return err
							}
							if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
								return err
							}
							existing.RateLimitID = &rateLimit.ID
						}
					}
					if err := h.configStore.UpdateVirtualKeyProviderConfig(ctx, &existing, tx); err != nil {
						return err
					}
				}
			}
			// Delete provider configs that are not in the request
			for id := range existingConfigsMap {
				if !requestConfigsMap[id] {
					providerBudgetIDsToDelete, providerRateLimitIDsToDelete = collectProviderConfigDeleteIDs(
						existingConfigsMap[id],
						providerBudgetIDsToDelete,
						providerRateLimitIDsToDelete,
					)
					if err := h.configStore.DeleteVirtualKeyProviderConfig(ctx, id, tx); err != nil {
						return err
					}
				}
			}
		}
		if req.MCPConfigs != nil {
			// Check for duplicate MCPClientName values among all configs before processing
			seenMCPClientNames := make(map[string]bool)
			for _, mc := range req.MCPConfigs {
				if seenMCPClientNames[mc.MCPClientName] {
					return fmt.Errorf("duplicate mcp_client_name: %s", mc.MCPClientName)
				}
				seenMCPClientNames[mc.MCPClientName] = true
			}
			// Get existing MCP configs for comparison
			var existingMCPConfigs []configstoreTables.TableVirtualKeyMCPConfig
			if err := tx.Where("virtual_key_id = ?", vk.ID).Find(&existingMCPConfigs).Error; err != nil {
				return err
			}
			// Create maps for easier lookup
			existingMCPConfigsMap := make(map[uint]configstoreTables.TableVirtualKeyMCPConfig)
			for _, config := range existingMCPConfigs {
				existingMCPConfigsMap[config.ID] = config
			}
			requestMCPConfigsMap := make(map[uint]bool)
			// Process new configs: create new ones and update existing ones
			for _, mc := range req.MCPConfigs {
				if mc.ID == nil {
					mcpClient, err := h.configStore.GetMCPClientByName(ctx, mc.MCPClientName)
					if err != nil {
						return fmt.Errorf("failed to get MCP client: %w", err)
					}
					// Create new MCP config
					if err := h.configStore.CreateVirtualKeyMCPConfig(ctx, &configstoreTables.TableVirtualKeyMCPConfig{
						VirtualKeyID:   vk.ID,
						MCPClientID:    mcpClient.ID,
						ToolsToExecute: mc.ToolsToExecute,
					}, tx); err != nil {
						return err
					}
				} else {
					// Update existing MCP config
					existing, ok := existingMCPConfigsMap[*mc.ID]
					if !ok {
						return fmt.Errorf("MCP config %d does not belong to this virtual key", *mc.ID)
					}
					requestMCPConfigsMap[*mc.ID] = true
					existing.ToolsToExecute = mc.ToolsToExecute
					if err := h.configStore.UpdateVirtualKeyMCPConfig(ctx, &existing, tx); err != nil {
						return err
					}
				}
			}
			// Delete MCP configs that are not in the request
			for id := range existingMCPConfigsMap {
				if !requestMCPConfigsMap[id] {
					if err := h.configStore.DeleteVirtualKeyMCPConfig(ctx, id, tx); err != nil {
						return err
					}
				}
			}
		}

		if budgetIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", budgetIDToDelete).Error; err != nil {
				return err
			}
		}
		if rateLimitIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", rateLimitIDToDelete).Error; err != nil {
				return err
			}
		}
		for _, id := range providerBudgetIDsToDelete {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", id).Error; err != nil {
				return err
			}
		}
		for _, id := range providerRateLimitIDsToDelete {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", id).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		errMsg := err.Error()
		// Check if this is a duplicate MCPClientName error and return 400 instead of 500
		if strings.Contains(errMsg, "duplicate mcp_client_name:") ||
			strings.Contains(errMsg, "already exists'") ||
			strings.Contains(errMsg, "duplicate key") {
			SendError(ctx, 400, fmt.Sprintf("Failed to update virtual key: %v", err))
			return
		}
		SendError(ctx, 500, fmt.Sprintf("Failed to update virtual key: %v", err))
		return
	}
	// Load relationships for response
	preloadedVk, err := h.configStore.GetVirtualKey(ctx, vk.ID)
	if err != nil {
		logger.Error("failed to load relationships for updated VK: %v", err)
		preloadedVk = vk
	}
	h.governanceManager.ReloadVirtualKey(ctx, vk.ID)
	// Refresh the agentic runtime's in-memory map so any change to the
	// VK's agent scope (allowed_tools, autonomy_budget, etc.) is live
	// on the very next decision - no restart needed.
	h.syncVKToAgenticResolver(preloadedVk)
	SendJSON(ctx, map[string]interface{}{
		"message":     "Virtual key updated successfully",
		"virtual_key": preloadedVk,
	})
}

// RotateVirtualKeyRequest carries the optional schedule + grace overrides for
// a manual rotation. Period 0 / nil leaves the existing schedule untouched.
type RotateVirtualKeyRequest struct {
	RotationPeriodDays      *int `json:"rotation_period_days,omitempty"`
	RotationGracePeriodDays *int `json:"rotation_grace_period_days,omitempty"`
}

// BulkAgentAttributesRequest is the body for the bulk agent-attribute apply.
// Exactly one selection mode must be supplied: an explicit VirtualKeyIDs
// multi-select, or ApplyToAllInWorkspace. At least one attribute (risk level
// or capabilities) must be present or the call is a no-op (400).
type BulkAgentAttributesRequest struct {
	// WorkspaceID scopes the operation. Falls back to the active workspace
	// from context (X-Active-Workspace-Id) when omitted.
	WorkspaceID *string `json:"workspace_id,omitempty"`
	// ApplyToAllInWorkspace targets every VK explicitly pinned to the
	// resolved workspace. Mutually exclusive with VirtualKeyIDs.
	ApplyToAllInWorkspace bool `json:"apply_to_all_in_workspace,omitempty"`
	// VirtualKeyIDs is an explicit multi-select. VKs outside the resolved
	// workspace are skipped (strict isolation).
	VirtualKeyIDs []string `json:"virtual_key_ids,omitempty"`
	// OnlyAgentBound limits "apply to all" to VKs that already have an
	// identity-provider binding (the only VKs the PEP fires on). Defaults
	// to true; pass false to also stamp attributes on not-yet-bound VKs.
	OnlyAgentBound *bool `json:"only_agent_bound,omitempty"`
	// Attributes to set. Omit (nil) to leave that attribute unchanged.
	AgentRiskLevel    *string   `json:"agent_risk_level,omitempty"`
	AgentCapabilities *[]string `json:"agent_capabilities,omitempty"`
}

// bulkUpdateVirtualKeyAgentAttributes handles
// POST /api/governance/virtual-keys/bulk-agent-attributes. It sets the agent
// attribute taxonomy (risk level / capabilities) across a multi-select of VKs
// or every agent-bound VK in the active workspace, then re-syncs the in-memory
// VKResolver for each touched key so PEP decisions reflect the change without a
// restart. Workspace-scoped: only VKs in the caller's workspace are mutated.
func (h *GovernanceHandler) bulkUpdateVirtualKeyAgentAttributes(ctx *fasthttp.RequestCtx) {
	var req BulkAgentAttributesRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	if req.AgentRiskLevel == nil && req.AgentCapabilities == nil {
		SendError(ctx, 400, "Nothing to apply: provide agent_risk_level and/or agent_capabilities")
		return
	}
	if !req.ApplyToAllInWorkspace && len(req.VirtualKeyIDs) == 0 {
		SendError(ctx, 400, "Provide virtual_key_ids or set apply_to_all_in_workspace")
		return
	}

	// Resolve the target workspace and enforce write access once.
	workspaceID := ""
	if req.WorkspaceID != nil {
		workspaceID = strings.TrimSpace(*req.WorkspaceID)
	}
	if workspaceID == "" {
		workspaceID = tenantctx.WorkspaceIDFromContext(ctx)
	}
	if !h.requireWorkspaceWrite(ctx, workspaceID) {
		return
	}
	onlyAgentBound := true
	if req.OnlyAgentBound != nil {
		onlyAgentBound = *req.OnlyAgentBound
	}

	// inWorkspace enforces strict isolation: when a workspace is resolved,
	// only VKs pinned to it match; org-wide (NULL) keys are touched only in
	// an org-wide context (empty workspace).
	inWorkspace := func(vk *configstoreTables.TableVirtualKey) bool {
		if workspaceID == "" {
			return vk.WorkspaceID == nil || strings.TrimSpace(*vk.WorkspaceID) == ""
		}
		return vk.WorkspaceID != nil && strings.TrimSpace(*vk.WorkspaceID) == workspaceID
	}

	// Build the target set.
	var targets []*configstoreTables.TableVirtualKey
	if len(req.VirtualKeyIDs) > 0 {
		for _, id := range req.VirtualKeyIDs {
			vk, err := h.configStore.GetVirtualKey(ctx, strings.TrimSpace(id))
			if err != nil || vk == nil {
				continue // skip unknown / cross-tenant ids rather than failing the batch
			}
			if !inWorkspace(vk) {
				continue
			}
			if onlyAgentBound && vk.BoundIdentityProvider == "" {
				continue
			}
			targets = append(targets, vk)
		}
	} else {
		all, err := h.configStore.GetVirtualKeys(ctx)
		if err != nil {
			SendError(ctx, 500, "Failed to list virtual keys")
			return
		}
		for i := range all {
			vk := &all[i]
			if !inWorkspace(vk) {
				continue
			}
			if onlyAgentBound && vk.BoundIdentityProvider == "" {
				continue
			}
			targets = append(targets, vk)
		}
	}

	// Apply + persist + re-sync the resolver for each target.
	updated := 0
	for _, vk := range targets {
		if req.AgentRiskLevel != nil {
			vk.AgentRiskLevel = normaliseAgentRiskLevel(*req.AgentRiskLevel)
		}
		if req.AgentCapabilities != nil {
			vk.AgentCapabilities = normaliseAgentCapabilities(*req.AgentCapabilities)
		}
		if err := h.configStore.UpdateVirtualKey(ctx, vk); err != nil {
			continue // best-effort across the batch; report the count that stuck
		}
		h.syncVKToAgenticResolver(vk)
		updated++
	}

	SendJSON(ctx, map[string]any{
		"updated":      updated,
		"matched":      len(targets),
		"workspace_id": workspaceID,
	})
}

// rotateVirtualKey handles POST /api/governance/virtual-keys/{vk_id}/rotate.
// Generates a fresh key value, parks the prior one in PreviousValue for the
// grace window (so existing clients keep working until they roll over), and
// stamps the new last/next-rotation timestamps. Optional body fields update
// the schedule + grace at the same time.
func (h *GovernanceHandler) rotateVirtualKey(ctx *fasthttp.RequestCtx) {
	vkID := ctx.UserValue("vk_id").(string)
	var req RotateVirtualKeyRequest
	if body := ctx.PostBody(); len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			SendError(ctx, 400, "Invalid JSON")
			return
		}
	}
	vk, err := h.configStore.GetVirtualKey(ctx, vkID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Virtual key not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve virtual key")
		return
	}
	currentWS := ""
	if vk.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*vk.WorkspaceID)
	}
	if !h.requireWorkspaceWrite(ctx, currentWS) {
		return
	}
	if req.RotationPeriodDays != nil {
		periodCopy := *req.RotationPeriodDays
		if periodCopy < 0 {
			periodCopy = 0
		}
		if periodCopy == 0 {
			vk.RotationPeriodDays = nil
		} else {
			vk.RotationPeriodDays = &periodCopy
		}
	}
	if req.RotationGracePeriodDays != nil {
		if *req.RotationGracePeriodDays < 0 {
			vk.RotationGracePeriodDays = 0
		} else {
			vk.RotationGracePeriodDays = *req.RotationGracePeriodDays
		}
	}
	now := time.Now().UTC()
	// Park the current value as the previous one with a grace expiry.
	// Inference auth will accept either the new or previous value until
	// expiry, then drop the parked value on the next save.
	vk.PreviousValue = vk.Value
	if vk.RotationGracePeriodDays > 0 {
		exp := now.Add(time.Duration(vk.RotationGracePeriodDays) * 24 * time.Hour)
		vk.PreviousValueExpiresAt = &exp
	} else {
		vk.PreviousValueExpiresAt = &now
	}
	vk.Value = governance.GenerateVirtualKey()
	vk.LastRotatedAt = &now
	if vk.RotationPeriodDays != nil && *vk.RotationPeriodDays > 0 {
		nxt := now.Add(time.Duration(*vk.RotationPeriodDays) * 24 * time.Hour)
		vk.NextRotationAt = &nxt
	} else {
		vk.NextRotationAt = nil
	}
	if err := h.configStore.UpdateVirtualKey(ctx, vk); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to rotate virtual key: %v", err))
		return
	}
	h.governanceManager.ReloadVirtualKey(ctx, vk.ID)
	SendJSON(ctx, map[string]interface{}{
		"message":     "Virtual key rotated successfully",
		"virtual_key": vk,
	})
}

// deleteVirtualKey handles DELETE /api/governance/virtual-keys/{vk_id} - Delete a virtual key
func (h *GovernanceHandler) deleteVirtualKey(ctx *fasthttp.RequestCtx) {
	vkID := ctx.UserValue("vk_id").(string)
	// Fetch the virtual key from the database to get the budget and rate limit
	vk, err := h.configStore.GetVirtualKey(ctx, vkID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Virtual key not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve virtual key")
		return
	}
	currentWS := ""
	if vk.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*vk.WorkspaceID)
	}
	if !h.requireWorkspaceWrite(ctx, currentWS) {
		return
	}
	// Removing key from in-memory store
	err = h.governanceManager.RemoveVirtualKey(ctx, vk.ID)
	if err != nil {
		// But we ignore this error because its not
		logger.Error("failed to remove virtual key: %v", err)
	}
	// Deleting key from database
	if err := h.configStore.DeleteVirtualKey(ctx, vkID); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Virtual key not found")
			return
		}
		logger.Error("failed to delete virtual key: %v", err)
		SendError(ctx, 500, "Failed to delete virtual key")
		return
	}
	// Drop the agentic runtime's cached scope so subsequent decisions
	// for this VK id miss the resolver (and therefore the L1 cache
	// re-keys cleanly when the same id is recycled).
	h.removeVKFromAgenticResolver(vkID)
	SendJSON(ctx, map[string]interface{}{
		"message": "Virtual key deleted successfully",
	})
}

// Team CRUD Operations

// getTeams handles GET /api/governance/teams - Get all teams
func (h *GovernanceHandler) getTeams(ctx *fasthttp.RequestCtx) {
	customerID := string(ctx.QueryArgs().Peek("customer_id"))
	// Workspace narrowing: prefer the explicit query param, fall back
	// to X-Active-Workspace-Id from the dashboard's scope switcher.
	// The store-side filter then returns teams scoped to this workspace
	// plus tenant-wide teams (workspace_id IS NULL).
	workspaceID := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id")))
	if workspaceID == "" {
		workspaceID = tenantctx.WorkspaceIDFromContext(ctx)
	}
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		if customerID != "" {
			teams := make(map[string]*configstoreTables.TableTeam)
			for _, team := range data.Teams {
				if team.CustomerID != nil && *team.CustomerID == customerID {
					teams[team.ID] = team
				}
			}
			SendJSON(ctx, map[string]interface{}{
				"teams":       teams,
				"count":       len(teams),
				"total_count": len(teams),
				"limit":       len(teams),
				"offset":      0,
			})
		} else {
			SendJSON(ctx, map[string]interface{}{
				"teams":       data.Teams,
				"count":       len(data.Teams),
				"total_count": len(data.Teams),
				"limit":       len(data.Teams),
				"offset":      0,
			})
		}
		return
	}

	// Check for pagination parameters
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	offsetStr := string(ctx.QueryArgs().Peek("offset"))
	search := string(ctx.QueryArgs().Peek("search"))

	if limitStr != "" || offsetStr != "" || search != "" || workspaceID != "" {
		limit, _ := strconv.Atoi(limitStr)
		offset, _ := strconv.Atoi(offsetStr)
		limit, offset = ClampPaginationParams(limit, offset)
		teams, totalCount, err := h.configStore.GetTeamsPaginated(ctx, configstore.TeamsQueryParams{
			Limit:       limit,
			Offset:      offset,
			Search:      search,
			CustomerID:  customerID,
			WorkspaceID: workspaceID,
		})
		if err != nil {
			logger.Error("failed to retrieve teams: %v", err)
			SendError(ctx, 500, fmt.Sprintf("Failed to retrieve teams: %v", err))
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"teams":       teams,
			"count":       len(teams),
			"total_count": totalCount,
			"limit":       limit,
			"offset":      offset,
		})
		return
	}

	// Non-paginated path: return all teams
	teams, err := h.configStore.GetTeams(ctx, customerID)
	if err != nil {
		logger.Error("failed to retrieve teams: %v", err)
		SendError(ctx, 500, fmt.Sprintf("Failed to retrieve teams: %v", err))
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"teams":       teams,
		"count":       len(teams),
		"total_count": len(teams),
		"limit":       len(teams),
		"offset":      0,
	})
}

// createTeam handles POST /api/governance/teams - Create a new team
func (h *GovernanceHandler) createTeam(ctx *fasthttp.RequestCtx) {
	var req CreateTeamRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Validate required fields
	if req.Name == "" {
		SendError(ctx, 400, "Team name is required")
		return
	}
	if !h.requireWorkspaceWrite(ctx, "") {
		return
	}
	// Validate budget if provided
	if req.Budget != nil {
		if req.Budget.MaxLimit < 0 {
			SendError(ctx, 400, fmt.Sprintf("Budget max_limit cannot be negative: %.2f", req.Budget.MaxLimit))
			return
		}
		// Validate reset duration format
		if _, err := configstoreTables.ParseDuration(req.Budget.ResetDuration); err != nil {
			SendError(ctx, 400, fmt.Sprintf("Invalid reset duration format: %s", req.Budget.ResetDuration))
			return
		}
	}
	// Validate rate limit if provided
	if req.RateLimit != nil {
		rateLimit := configstoreTables.TableRateLimit{
			TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
			TokenResetDuration:   req.RateLimit.TokenResetDuration,
			RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
			RequestResetDuration: req.RateLimit.RequestResetDuration,
		}
		if err := validateRateLimit(&rateLimit); err != nil {
			SendError(ctx, 400, fmt.Sprintf("Invalid rate limit: %s", err.Error()))
			return
		}
	}
	memberUserIDs, err := h.normalizeTeamMemberUserIDs(ctx, req.MemberUserIDs)
	if err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	memberCustomerIDs, err := h.normalizeTeamMemberCustomerIDs(ctx, req.MemberCustomerIDs)
	if err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	// Resolve the policy's workspace scope: tenant-wide (NULL) when the
	// caller flips ApplyToAllWorkspaces; otherwise stamp the active
	// workspace from the dashboard's scope switcher
	// (X-Active-Workspace-Id) so the team is only visible there.
	var teamWorkspaceID *string
	if !req.ApplyToAllWorkspaces {
		if ws := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx)); ws != "" {
			teamWorkspaceID = &ws
		}
	}
	// Creating team in database
	var team configstoreTables.TableTeam
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		team = configstoreTables.TableTeam{
			ID:          uuid.NewString(),
			Name:        req.Name,
			CustomerID:  req.CustomerID,
			WorkspaceID: teamWorkspaceID,
			// AllowedTools moved to per-policy targeting; req.AllowedTools
			// is silently dropped here. Operators set team-scoped
			// entitlements via agentic_policy_team_targets now.
		}
		if req.Budget != nil {
			budget := configstoreTables.TableBudget{
				ID:            uuid.NewString(),
				MaxLimit:      req.Budget.MaxLimit,
				ResetDuration: req.Budget.ResetDuration,
				LastReset:     time.Now(),
				CurrentUsage:  0,
			}
			if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
				return err
			}
			team.BudgetID = &budget.ID
		}
		if req.RateLimit != nil {
			rateLimit := configstoreTables.TableRateLimit{
				ID:                   uuid.NewString(),
				TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
				TokenResetDuration:   req.RateLimit.TokenResetDuration,
				RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
				RequestResetDuration: req.RateLimit.RequestResetDuration,
				TokenLastReset:       time.Now(),
				RequestLastReset:     time.Now(),
			}
			if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
				return err
			}
			team.RateLimitID = &rateLimit.ID
		}
		if err := h.configStore.CreateTeam(ctx, &team, tx); err != nil {
			return err
		}
		if err := h.configStore.ReplaceTeamMembers(ctx, team.ID, memberUserIDs, tx); err != nil {
			return err
		}
		if err := h.configStore.ReplaceTeamCustomerMembers(ctx, team.ID, memberCustomerIDs, tx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		logger.Error("failed to create team: %v", err)
		SendError(ctx, 500, "failed to create team")
		return
	}
	// Reloading team from in-memory store
	preloadedTeam, err := h.governanceManager.ReloadTeam(ctx, team.ID)
	if err != nil {
		logger.Error("failed to reload team: %v", err)
		preloadedTeam = &team
	}
	h.syncTeamAllowedTools(preloadedTeam)
	SendJSON(ctx, map[string]interface{}{
		"message": "Team created successfully",
		"team":    preloadedTeam,
	})
}

// getTeam handles GET /api/governance/teams/{team_id} - Get a specific team
func (h *GovernanceHandler) getTeam(ctx *fasthttp.RequestCtx) {
	teamID := ctx.UserValue("team_id").(string)
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		team, ok := data.Teams[teamID]
		if !ok {
			SendError(ctx, 404, "Team not found")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"team": team,
		})
		return
	}
	team, err := h.configStore.GetTeam(ctx, teamID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Team not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve team")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"team": team,
	})
}

// updateTeam handles PUT /api/governance/teams/{team_id} - Update a team
func (h *GovernanceHandler) updateTeam(ctx *fasthttp.RequestCtx) {
	teamID := ctx.UserValue("team_id").(string)

	if !h.requireWorkspaceWrite(ctx, "") {
		return
	}

	var req UpdateTeamRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	memberUserIDs := []string(nil)
	shouldReplaceMembers := false
	if req.MemberUserIDs != nil {
		normalizedMemberUserIDs, normalizeErr := h.normalizeTeamMemberUserIDs(ctx, *req.MemberUserIDs)
		if normalizeErr != nil {
			SendError(ctx, 400, normalizeErr.Error())
			return
		}
		memberUserIDs = normalizedMemberUserIDs
		shouldReplaceMembers = true
	}
	memberCustomerIDs := []string(nil)
	shouldReplaceCustomerMembers := false
	if req.MemberCustomerIDs != nil {
		normalizedMemberCustomerIDs, normalizeErr := h.normalizeTeamMemberCustomerIDs(ctx, *req.MemberCustomerIDs)
		if normalizeErr != nil {
			SendError(ctx, 400, normalizeErr.Error())
			return
		}
		memberCustomerIDs = normalizedMemberCustomerIDs
		shouldReplaceCustomerMembers = true
	}
	// Fetching team from database
	team, err := h.configStore.GetTeam(ctx, teamID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Team not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve team")
		return
	}
	// Updating team in database
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Track IDs to delete after updating the team (to avoid FK constraint)
		var budgetIDToDelete, rateLimitIDToDelete string

		// Update fields if provided
		if req.Name != nil {
			team.Name = *req.Name
		}
		if req.CustomerID != nil {
			if *req.CustomerID == "" {
				team.CustomerID = nil
			} else {
				team.CustomerID = req.CustomerID
			}
		}
		// Agentic PEP tool entitlements moved to per-policy targeting
		// (agentic_policy_team_targets). req.AllowedTools is accepted
		// on the API for backward compatibility but no longer written
		// to the Team row.
		// Handle budget updates
		if req.Budget != nil {
			// Check if budget limit is empty - means remove budget (reset duration doesn't matter)
			budgetIsEmpty := req.Budget.MaxLimit == nil
			if budgetIsEmpty {
				// Mark budget for deletion after FK is removed
				if team.BudgetID != nil {
					budgetIDToDelete = *team.BudgetID
					team.BudgetID = nil
					team.Budget = nil
				}
			} else if team.BudgetID != nil {
				// Update existing budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when updating a budget")
				}
				budget := configstoreTables.TableBudget{}
				if err := tx.First(&budget, "id = ?", *team.BudgetID).Error; err != nil {
					return err
				}
				budget.MaxLimit = *req.Budget.MaxLimit
				budget.ResetDuration = *req.Budget.ResetDuration
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.UpdateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				team.Budget = &budget
			} else {
				// Create new budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when creating a new budget")
				}
				if *req.Budget.MaxLimit < 0 {
					return fmt.Errorf("budget max_limit cannot be negative: %.2f", *req.Budget.MaxLimit)
				}
				if _, err := configstoreTables.ParseDuration(*req.Budget.ResetDuration); err != nil {
					return fmt.Errorf("invalid reset duration format: %s", *req.Budget.ResetDuration)
				}
				budget := configstoreTables.TableBudget{
					ID:            uuid.NewString(),
					MaxLimit:      *req.Budget.MaxLimit,
					ResetDuration: *req.Budget.ResetDuration,
					LastReset:     time.Now(),
					CurrentUsage:  0,
				}
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				team.BudgetID = &budget.ID
				team.Budget = &budget
			}
		}
		// Handle rate limit updates
		if req.RateLimit != nil {
			// Check if rate limit values are empty - means remove rate limit (reset durations don't matter)
			rateLimitIsEmpty := req.RateLimit.TokenMaxLimit == nil && req.RateLimit.RequestMaxLimit == nil
			if rateLimitIsEmpty {
				// Mark rate limit for deletion after FK is removed
				if team.RateLimitID != nil {
					rateLimitIDToDelete = *team.RateLimitID
					team.RateLimitID = nil
					team.RateLimit = nil
				}
			} else if team.RateLimitID != nil {
				// Update existing rate limit
				rateLimit := configstoreTables.TableRateLimit{}
				if err := tx.First(&rateLimit, "id = ?", *team.RateLimitID).Error; err != nil {
					return err
				}
				rateLimit.TokenMaxLimit = req.RateLimit.TokenMaxLimit
				rateLimit.TokenResetDuration = req.RateLimit.TokenResetDuration
				rateLimit.RequestMaxLimit = req.RateLimit.RequestMaxLimit
				rateLimit.RequestResetDuration = req.RateLimit.RequestResetDuration
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.UpdateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				team.RateLimit = &rateLimit
			} else {
				// Create new rate limit
				rateLimit := configstoreTables.TableRateLimit{
					ID:                   uuid.NewString(),
					TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
					TokenResetDuration:   req.RateLimit.TokenResetDuration,
					RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
					RequestResetDuration: req.RateLimit.RequestResetDuration,
					TokenLastReset:       time.Now(),
					RequestLastReset:     time.Now(),
				}
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				team.RateLimitID = &rateLimit.ID
				team.RateLimit = &rateLimit
			}
		}
		if err := h.configStore.UpdateTeam(ctx, team, tx); err != nil {
			return err
		}
		if shouldReplaceMembers {
			if err := h.configStore.ReplaceTeamMembers(ctx, team.ID, memberUserIDs, tx); err != nil {
				return err
			}
		}
		if shouldReplaceCustomerMembers {
			if err := h.configStore.ReplaceTeamCustomerMembers(ctx, team.ID, memberCustomerIDs, tx); err != nil {
				return err
			}
		}

		// Now that FK references are removed, delete the orphaned budget/rate limit
		if budgetIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", budgetIDToDelete).Error; err != nil {
				return err
			}
		}
		if rateLimitIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", rateLimitIDToDelete).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		SendError(ctx, 500, "Failed to update team")
		return
	}
	// Reloading team from in-memory store
	preloadedTeam, err := h.governanceManager.ReloadTeam(ctx, team.ID)
	if err != nil {
		logger.Error("failed to reload team: %v", err)
		preloadedTeam = team
	}
	h.syncTeamAllowedTools(preloadedTeam)
	SendJSON(ctx, map[string]interface{}{
		"message": "Team updated successfully",
		"team":    preloadedTeam,
	})
}

func (h *GovernanceHandler) normalizeTeamMemberUserIDs(ctx context.Context, userIDs []string) ([]string, error) {
	if len(userIDs) == 0 {
		return []string{}, nil
	}

	normalized := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		trimmed := strings.TrimSpace(userID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}

		user, err := h.configStore.GetUserByID(ctx, trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to validate team member")
		}
		if user == nil || !user.IsEmailVerified {
			return nil, fmt.Errorf("team members must be active workspace users")
		}

		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	return normalized, nil
}

func (h *GovernanceHandler) normalizeTeamMemberCustomerIDs(ctx context.Context, customerIDs []string) ([]string, error) {
	if len(customerIDs) == 0 {
		return []string{}, nil
	}

	normalized := make([]string, 0, len(customerIDs))
	seen := make(map[string]struct{}, len(customerIDs))
	for _, customerID := range customerIDs {
		trimmed := strings.TrimSpace(customerID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}

		customer, err := h.configStore.GetCustomer(ctx, trimmed)
		if err != nil {
			if errors.Is(err, configstore.ErrNotFound) {
				return nil, fmt.Errorf("team members must be governance members from the Members tab")
			}
			return nil, fmt.Errorf("failed to validate team member")
		}
		if customer == nil {
			return nil, fmt.Errorf("team members must be governance members from the Members tab")
		}

		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	return normalized, nil
}

// deleteTeam handles DELETE /api/governance/teams/{team_id} - Delete a team
func (h *GovernanceHandler) deleteTeam(ctx *fasthttp.RequestCtx) {
	teamID := ctx.UserValue("team_id").(string)
	if !h.requireWorkspaceWrite(ctx, "") {
		return
	}
	team, err := h.configStore.GetTeam(ctx, teamID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Team not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve team")
		return
	}
	// Removing team from in-memory store
	err = h.governanceManager.RemoveTeam(ctx, team.ID)
	if err != nil {
		// But we ignore this error because its not
		logger.Error("failed to remove team: %v", err)
	}
	if err := h.configStore.DeleteTeam(ctx, teamID); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Team not found")
			return
		}
		SendError(ctx, 500, "Failed to delete team")
		return
	}
	h.removeTeamAllowedTools(teamID)
	SendJSON(ctx, map[string]interface{}{
		"message": "Team deleted successfully",
	})
}

// Customer CRUD Operations

// getCustomers handles GET /api/governance/customers - Get all customers
func (h *GovernanceHandler) getCustomers(ctx *fasthttp.RequestCtx) {
	// Workspace narrowing - same shape as getTeams. Returns customers
	// scoped to this workspace plus tenant-wide ones (workspace_id IS NULL).
	workspaceID := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id")))
	if workspaceID == "" {
		workspaceID = tenantctx.WorkspaceIDFromContext(ctx)
	}
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"customers":   data.Customers,
			"count":       len(data.Customers),
			"total_count": len(data.Customers),
			"limit":       len(data.Customers),
			"offset":      0,
		})
		return
	}
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	offsetStr := string(ctx.QueryArgs().Peek("offset"))
	search := string(ctx.QueryArgs().Peek("search"))

	if limitStr != "" || offsetStr != "" || search != "" || workspaceID != "" {
		limit, _ := strconv.Atoi(limitStr)
		offset, _ := strconv.Atoi(offsetStr)
		limit, offset = ClampPaginationParams(limit, offset)
		customers, totalCount, err := h.configStore.GetCustomersPaginated(ctx, configstore.CustomersQueryParams{
			Limit:       limit,
			Offset:      offset,
			Search:      search,
			WorkspaceID: workspaceID,
		})
		if err != nil {
			logger.Error("failed to retrieve customers: %v", err)
			SendError(ctx, 500, "failed to retrieve customers")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"customers":   customers,
			"count":       len(customers),
			"total_count": totalCount,
			"limit":       limit,
			"offset":      offset,
		})
		return
	}

	customers, err := h.configStore.GetCustomers(ctx)
	if err != nil {
		logger.Error("failed to retrieve customers: %v", err)
		SendError(ctx, 500, "failed to retrieve customers")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"customers":   customers,
		"count":       len(customers),
		"total_count": len(customers),
		"limit":       len(customers),
		"offset":      0,
	})
}

// createCustomer handles POST /api/governance/customers - Create a new customer
func (h *GovernanceHandler) createCustomer(ctx *fasthttp.RequestCtx) {
	// Customers (end-user attribution) are a Team+ feature.
	if !gateAdvancedObservability(ctx, h.configStore) {
		return
	}
	var req CreateCustomerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Validate required fields
	if req.Name == "" {
		SendError(ctx, 400, "Customer name is required")
		return
	}
	if !h.requireWorkspaceWrite(ctx, "") {
		return
	}
	// Validate budget if provided
	if req.Budget != nil {
		if req.Budget.MaxLimit < 0 {
			SendError(ctx, 400, fmt.Sprintf("Budget max_limit cannot be negative: %.2f", req.Budget.MaxLimit))
			return
		}
		// Validate reset duration format
		if _, err := configstoreTables.ParseDuration(req.Budget.ResetDuration); err != nil {
			SendError(ctx, 400, fmt.Sprintf("Invalid reset duration format: %s", req.Budget.ResetDuration))
			return
		}
	}
	// Validate rate limit if provided
	if req.RateLimit != nil {
		rateLimit := configstoreTables.TableRateLimit{
			TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
			TokenResetDuration:   req.RateLimit.TokenResetDuration,
			RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
			RequestResetDuration: req.RateLimit.RequestResetDuration,
		}
		if err := validateRateLimit(&rateLimit); err != nil {
			SendError(ctx, 400, fmt.Sprintf("Invalid rate limit: %s", err.Error()))
			return
		}
	}
	// Resolve customer scope: tenant-wide (NULL) when ApplyToAllWorkspaces
	// is true; otherwise stamp the active workspace from the dashboard's
	// scope switcher (X-Active-Workspace-Id) so the customer is only
	// visible there.
	var customerWorkspaceID *string
	if !req.ApplyToAllWorkspaces {
		if ws := strings.TrimSpace(lib.ActiveWorkspaceHeader(ctx)); ws != "" {
			customerWorkspaceID = &ws
		}
	}
	var customer configstoreTables.TableCustomer
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		customer = configstoreTables.TableCustomer{
			ID:          uuid.NewString(),
			Name:        req.Name,
			WorkspaceID: customerWorkspaceID,
			// AllowedTools moved to per-policy targeting
			// (agentic_policy_member_targets). req.AllowedTools is no
			// longer persisted on the Customer row.
		}

		if req.Budget != nil {
			budget := configstoreTables.TableBudget{
				ID:            uuid.NewString(),
				MaxLimit:      req.Budget.MaxLimit,
				ResetDuration: req.Budget.ResetDuration,
				LastReset:     time.Now(),
				CurrentUsage:  0,
			}
			if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
				return err
			}
			customer.BudgetID = &budget.ID
		}
		if req.RateLimit != nil {
			rateLimit := configstoreTables.TableRateLimit{
				ID:                   uuid.NewString(),
				TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
				TokenResetDuration:   req.RateLimit.TokenResetDuration,
				RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
				RequestResetDuration: req.RateLimit.RequestResetDuration,
				TokenLastReset:       time.Now(),
				RequestLastReset:     time.Now(),
			}
			if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
				return err
			}
			customer.RateLimitID = &rateLimit.ID
		}
		if err := h.configStore.CreateCustomer(ctx, &customer, tx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		SendError(ctx, 500, "failed to create customer")
		return
	}
	preloadedCustomer, err := h.governanceManager.ReloadCustomer(ctx, customer.ID)
	if err != nil {
		logger.Error("failed to reload customer: %v", err)
		preloadedCustomer = &customer
	}
	h.syncCustomerAllowedTools(preloadedCustomer)
	SendJSON(ctx, map[string]interface{}{
		"message":  "Customer created successfully",
		"customer": preloadedCustomer,
	})
}

// getCustomer handles GET /api/governance/customers/{customer_id} - Get a specific customer
func (h *GovernanceHandler) getCustomer(ctx *fasthttp.RequestCtx) {
	customerID := ctx.UserValue("customer_id").(string)
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		customer, ok := data.Customers[customerID]
		if !ok {
			SendError(ctx, 404, "Customer not found")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"customer": customer,
		})
		return
	}
	customer, err := h.configStore.GetCustomer(ctx, customerID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Customer not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve customer")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"customer": customer,
	})
}

// updateCustomer handles PUT /api/governance/customers/{customer_id} - Update a customer
func (h *GovernanceHandler) updateCustomer(ctx *fasthttp.RequestCtx) {
	customerID := ctx.UserValue("customer_id").(string)
	if !h.requireWorkspaceWrite(ctx, "") {
		return
	}
	var req UpdateCustomerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Fetching customer from database
	customer, err := h.configStore.GetCustomer(ctx, customerID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Customer not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve customer")
		return
	}
	// Updating customer in database
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Track IDs to delete after updating the customer (to avoid FK constraint)
		var budgetIDToDelete, rateLimitIDToDelete string

		// Update fields if provided
		if req.Name != nil {
			customer.Name = *req.Name
		}
		// Per-member tool entitlements moved to per-policy targeting
		// (agentic_policy_member_targets). req.AllowedTools is no
		// longer applied to the Customer row.
		// Handle budget updates
		if req.Budget != nil {
			// Check if budget limit is empty - means remove budget (reset duration doesn't matter)
			budgetIsEmpty := req.Budget.MaxLimit == nil
			if budgetIsEmpty {
				// Mark budget for deletion after FK is removed
				if customer.BudgetID != nil {
					budgetIDToDelete = *customer.BudgetID
					customer.BudgetID = nil
					customer.Budget = nil
				}
			} else if customer.BudgetID != nil {
				// Update existing budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when updating a budget")
				}
				budget := configstoreTables.TableBudget{}
				if err := tx.First(&budget, "id = ?", *customer.BudgetID).Error; err != nil {
					return err
				}
				budget.MaxLimit = *req.Budget.MaxLimit
				budget.ResetDuration = *req.Budget.ResetDuration
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.UpdateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				customer.Budget = &budget
			} else {
				// Create new budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when creating a new budget")
				}
				if *req.Budget.MaxLimit < 0 {
					return fmt.Errorf("budget max_limit cannot be negative: %.2f", *req.Budget.MaxLimit)
				}
				if _, err := configstoreTables.ParseDuration(*req.Budget.ResetDuration); err != nil {
					return fmt.Errorf("invalid reset duration format: %s", *req.Budget.ResetDuration)
				}
				budget := configstoreTables.TableBudget{
					ID:            uuid.NewString(),
					MaxLimit:      *req.Budget.MaxLimit,
					ResetDuration: *req.Budget.ResetDuration,
					LastReset:     time.Now(),
					CurrentUsage:  0,
				}
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				customer.BudgetID = &budget.ID
				customer.Budget = &budget
			}
		}
		// Handle rate limit updates
		if req.RateLimit != nil {
			// Check if rate limit values are empty - means remove rate limit (reset durations don't matter)
			rateLimitIsEmpty := req.RateLimit.TokenMaxLimit == nil && req.RateLimit.RequestMaxLimit == nil
			if rateLimitIsEmpty {
				// Mark rate limit for deletion after FK is removed
				if customer.RateLimitID != nil {
					rateLimitIDToDelete = *customer.RateLimitID
					customer.RateLimitID = nil
					customer.RateLimit = nil
				}
			} else if customer.RateLimitID != nil {
				// Update existing rate limit
				rateLimit := configstoreTables.TableRateLimit{}
				if err := tx.First(&rateLimit, "id = ?", *customer.RateLimitID).Error; err != nil {
					return err
				}
				rateLimit.TokenMaxLimit = req.RateLimit.TokenMaxLimit
				rateLimit.TokenResetDuration = req.RateLimit.TokenResetDuration
				rateLimit.RequestMaxLimit = req.RateLimit.RequestMaxLimit
				rateLimit.RequestResetDuration = req.RateLimit.RequestResetDuration
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.UpdateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				customer.RateLimit = &rateLimit
			} else {
				// Create new rate limit
				rateLimit := configstoreTables.TableRateLimit{
					ID:                   uuid.NewString(),
					TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
					TokenResetDuration:   req.RateLimit.TokenResetDuration,
					RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
					RequestResetDuration: req.RateLimit.RequestResetDuration,
					TokenLastReset:       time.Now(),
					RequestLastReset:     time.Now(),
				}
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				customer.RateLimitID = &rateLimit.ID
				customer.RateLimit = &rateLimit
			}
		}
		if err := h.configStore.UpdateCustomer(ctx, customer, tx); err != nil {
			return err
		}

		// Now that FK references are removed, delete the orphaned budget/rate limit
		if budgetIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", budgetIDToDelete).Error; err != nil {
				return err
			}
		}
		if rateLimitIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", rateLimitIDToDelete).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		SendError(ctx, 500, "Failed to update customer")
		return
	}

	preloadedCustomer, err := h.governanceManager.ReloadCustomer(ctx, customer.ID)
	if err != nil {
		logger.Error("failed to reload customer: %v", err)
		preloadedCustomer = customer
	}
	h.syncCustomerAllowedTools(preloadedCustomer)

	SendJSON(ctx, map[string]interface{}{
		"message":  "Customer updated successfully",
		"customer": preloadedCustomer,
	})
}

// deleteCustomer handles DELETE /api/governance/customers/{customer_id} - Delete a customer
func (h *GovernanceHandler) deleteCustomer(ctx *fasthttp.RequestCtx) {
	customerID := ctx.UserValue("customer_id").(string)
	if !h.requireWorkspaceWrite(ctx, "") {
		return
	}

	customer, err := h.configStore.GetCustomer(ctx, customerID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Customer not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve customer")
		return
	}
	err = h.governanceManager.RemoveCustomer(ctx, customer.ID)
	if err != nil {
		// But we ignore this error because its not
		logger.Error("failed to remove customer: %v", err)
	}
	if err := h.configStore.DeleteCustomer(ctx, customerID); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Customer not found")
			return
		}
		SendError(ctx, 500, "Failed to delete customer")
		return
	}
	h.removeCustomerAllowedTools(customerID)
	SendJSON(ctx, map[string]interface{}{
		"message": "Customer deleted successfully",
	})
}

// Budget and Rate Limit GET operations

// getBudgets handles GET /api/governance/budgets - Get all budgets
func (h *GovernanceHandler) getBudgets(ctx *fasthttp.RequestCtx) {
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"budgets": data.Budgets,
			"count":   len(data.Budgets),
		})
		return
	}
	budgets, err := h.configStore.GetBudgets(ctx)
	if err != nil {
		logger.Error("failed to retrieve budgets: %v", err)
		SendError(ctx, 500, "failed to retrieve budgets")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"budgets": budgets,
		"count":   len(budgets),
	})
}

// getRateLimits handles GET /api/governance/rate-limits - Get all rate limits
func (h *GovernanceHandler) getRateLimits(ctx *fasthttp.RequestCtx) {
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"rate_limits": data.RateLimits,
			"count":       len(data.RateLimits),
		})
		return
	}
	rateLimits, err := h.configStore.GetRateLimits(ctx)
	if err != nil {
		logger.Error("failed to retrieve rate limits: %v", err)
		SendError(ctx, 500, "failed to retrieve rate limits")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"rate_limits": rateLimits,
		"count":       len(rateLimits),
	})
}

// validateRateLimit validates the rate limit
func validateRateLimit(rateLimit *configstoreTables.TableRateLimit) error {
	if rateLimit.TokenMaxLimit != nil && (*rateLimit.TokenMaxLimit < 0 || *rateLimit.TokenMaxLimit == 0) {
		return fmt.Errorf("rate limit token max limit cannot be negative or zero: %d", *rateLimit.TokenMaxLimit)
	}
	// Only require token reset duration if token limit is set
	if rateLimit.TokenMaxLimit != nil {
		if rateLimit.TokenResetDuration == nil {
			return fmt.Errorf("rate limit token reset duration is required")
		}
		if _, err := configstoreTables.ParseDuration(*rateLimit.TokenResetDuration); err != nil {
			return fmt.Errorf("invalid rate limit token reset duration format: %s", *rateLimit.TokenResetDuration)
		}
	}
	if rateLimit.RequestMaxLimit != nil && (*rateLimit.RequestMaxLimit < 0 || *rateLimit.RequestMaxLimit == 0) {
		return fmt.Errorf("rate limit request max limit cannot be negative or zero: %d", *rateLimit.RequestMaxLimit)
	}
	// Only require request reset duration if request limit is set
	if rateLimit.RequestMaxLimit != nil {
		if rateLimit.RequestResetDuration == nil {
			return fmt.Errorf("rate limit request reset duration is required")
		}
		if _, err := configstoreTables.ParseDuration(*rateLimit.RequestResetDuration); err != nil {
			return fmt.Errorf("invalid rate limit request reset duration format: %s", *rateLimit.RequestResetDuration)
		}
	}
	return nil
}

// validateBudget validates the budget
func validateBudget(budget *configstoreTables.TableBudget) error {
	if budget.MaxLimit < 0 || budget.MaxLimit == 0 {
		return fmt.Errorf("budget max limit cannot be negative or zero: %.2f", budget.MaxLimit)
	}
	if budget.ResetDuration == "" {
		return fmt.Errorf("budget reset duration is required")
	}
	if _, err := configstoreTables.ParseDuration(budget.ResetDuration); err != nil {
		return fmt.Errorf("invalid budget reset duration format: %s", budget.ResetDuration)
	}
	return nil
}

// Model Config CRUD Operations

// getModelConfigs handles GET /api/governance/model-configs - Get all model configs
func (h *GovernanceHandler) getModelConfigs(ctx *fasthttp.RequestCtx) {
	fromMemory := h.shouldServeFromMemory(ctx)
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	offsetStr := string(ctx.QueryArgs().Peek("offset"))
	search := string(ctx.QueryArgs().Peek("search"))
	workspaceID := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id")))
	if workspaceID == "" {
		workspaceID = tenantctx.WorkspaceIDFromContext(ctx)
	}

	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		modelConfigs := data.ModelConfigs
		if search != "" {
			filtered := make([]*configstoreTables.TableModelConfig, 0, len(modelConfigs))
			query := strings.ToLower(search)
			for _, modelConfig := range modelConfigs {
				if modelConfig == nil {
					continue
				}
				if strings.Contains(strings.ToLower(modelConfig.ModelName), query) {
					filtered = append(filtered, modelConfig)
				}
			}
			modelConfigs = filtered
		}

		totalCount := len(modelConfigs)
		limit, offset := totalCount, 0
		if limitStr != "" || offsetStr != "" || search != "" {
			var err error
			if limitStr != "" {
				limit, err = strconv.Atoi(limitStr)
				if err != nil {
					SendError(ctx, 400, "Invalid limit parameter: must be a number")
					return
				}
				if limit < 0 {
					SendError(ctx, 400, "Invalid limit parameter: must be non-negative")
					return
				}
			}
			if offsetStr != "" {
				offset, err = strconv.Atoi(offsetStr)
				if err != nil {
					SendError(ctx, 400, "Invalid offset parameter: must be a number")
					return
				}
				if offset < 0 {
					SendError(ctx, 400, "Invalid offset parameter: must be non-negative")
					return
				}
			}
			limit, offset = ClampPaginationParams(limit, offset)
			if offset > totalCount {
				offset = totalCount
			}
			end := offset + limit
			if end > totalCount {
				end = totalCount
			}
			modelConfigs = modelConfigs[offset:end]
		}
		SendJSON(ctx, map[string]any{
			"model_configs": modelConfigs,
			"count":         len(modelConfigs),
			"total_count":   totalCount,
			"limit":         limit,
			"offset":        offset,
		})
		return
	}

	// Check for pagination parameters
	if limitStr != "" || offsetStr != "" || search != "" || workspaceID != "" {
		// Paginated path
		params := configstore.ModelConfigsQueryParams{
			Search:      search,
			WorkspaceID: workspaceID,
		}
		if limitStr != "" {
			n, err := strconv.Atoi(limitStr)
			if err != nil {
				SendError(ctx, 400, "Invalid limit parameter: must be a number")
				return
			}
			if n < 0 {
				SendError(ctx, 400, "Invalid limit parameter: must be non-negative")
				return
			}
			params.Limit = n
		}
		if offsetStr != "" {
			n, err := strconv.Atoi(offsetStr)
			if err != nil {
				SendError(ctx, 400, "Invalid offset parameter: must be a number")
				return
			}
			if n < 0 {
				SendError(ctx, 400, "Invalid offset parameter: must be non-negative")
				return
			}
			params.Offset = n
		}

		params.Limit, params.Offset = ClampPaginationParams(params.Limit, params.Offset)
		modelConfigs, totalCount, err := h.configStore.GetModelConfigsPaginated(ctx, params)
		if err != nil {
			logger.Error("failed to retrieve model configs: %v", err)
			SendError(ctx, 500, "Failed to retrieve model configs")
			return
		}
		SendJSON(ctx, map[string]any{
			"model_configs": modelConfigs,
			"count":         len(modelConfigs),
			"total_count":   totalCount,
			"limit":         params.Limit,
			"offset":        params.Offset,
		})
		return
	}

	// Non-paginated path: return all model configs
	modelConfigs, err := h.configStore.GetModelConfigs(ctx)
	if err != nil {
		logger.Error("failed to retrieve model configs: %v", err)
		SendError(ctx, 500, "Failed to retrieve model configs")
		return
	}
	SendJSON(ctx, map[string]any{
		"model_configs": modelConfigs,
		"count":         len(modelConfigs),
		"total_count":   len(modelConfigs),
		"limit":         len(modelConfigs),
		"offset":        0,
	})
}

// getModelConfig handles GET /api/governance/model-configs/{mc_id} - Get a specific model config
func (h *GovernanceHandler) getModelConfig(ctx *fasthttp.RequestCtx) {
	mcID := ctx.UserValue("mc_id").(string)
	mc, err := h.configStore.GetModelConfigByID(ctx, mcID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Model config not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve model config")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"model_config": mc,
	})
}

// createModelConfig handles POST /api/governance/model-configs - Create a new model config
func (h *GovernanceHandler) createModelConfig(ctx *fasthttp.RequestCtx) {
	var req CreateModelConfigRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Validate required fields
	if req.ModelName == "" {
		SendError(ctx, 400, "Model name is required")
		return
	}
	if !createModelConfigHasUsageControls(req) {
		SendError(ctx, 400, modelConfigUsageControlsRequiredError)
		return
	}
	if !h.requireWorkspaceWrite(ctx, h.resolveTargetWorkspace(ctx, nil)) {
		return
	}

	// Plan-tier quota: Dev allows 2 per-model usage-control configs, Team
	// allows 25, Enterprise unlimited. The pricing matrix lists rate-limit /
	// concurrency / cost-budget as a single row, so we gate against the
	// total per-model config count regardless of which control they use.
	if org, _, orgErr := CurrentOrgFromCtx(ctx, h.configStore); orgErr == nil && org != nil {
		var modelCount int64
		if db := h.configStore.DB(); db != nil {
			_ = db.WithContext(ctx).
				Model(&configstoreTables.TableModelConfig{}).
				Where("tenant_id = ?", org.ID).
				Count(&modelCount).Error
		}
		if err := entitlements.EnforceQuota(ctx, h.configStore.DB(), org, entitlements.LimitRateLimitedModels, modelCount); err != nil {
			if qe, ok := err.(*entitlements.QuotaError); ok {
				SendJSONWithStatus(ctx, map[string]any{
					"error":     err.Error(),
					"code":      "QUOTA_EXCEEDED",
					"limit_key": qe.LimitKey,
					"limit":     qe.Limit,
					"current":   qe.Current,
					"plan":      qe.Plan,
					"feature":   qe.Feature,
				}, fasthttp.StatusPaymentRequired)
				return
			}
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
	}
	// Check if model config with same (model_name, provider) already exists
	existing, err := h.configStore.GetModelConfig(ctx, req.ModelName, req.Provider)
	if err != nil && err != configstore.ErrNotFound {
		logger.Error("failed to check existing model config: %v", err)
		SendError(ctx, 500, fmt.Sprintf("Failed to check existing model config: %v", err))
		return
	}
	if existing != nil {
		SendError(ctx, 409, modelConfigConflictMessage(req.ModelName, req.Provider))
		return
	}
	// Validate budget if provided
	if req.Budget != nil {
		if req.Budget.MaxLimit < 0 {
			SendError(ctx, 400, fmt.Sprintf("Budget max_limit cannot be negative: %.2f", req.Budget.MaxLimit))
			return
		}
		if _, err := configstoreTables.ParseDuration(req.Budget.ResetDuration); err != nil {
			SendError(ctx, 400, fmt.Sprintf("Invalid reset duration format: %s", req.Budget.ResetDuration))
			return
		}
	}
	if req.RateLimit != nil {
		rateLimit := configstoreTables.TableRateLimit{
			TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
			TokenResetDuration:   req.RateLimit.TokenResetDuration,
			RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
			RequestResetDuration: req.RateLimit.RequestResetDuration,
		}
		if err := validateRateLimit(&rateLimit); err != nil {
			SendError(ctx, 400, err.Error())
			return
		}
	}
	var mc configstoreTables.TableModelConfig
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		mc = configstoreTables.TableModelConfig{
			ID:        uuid.NewString(),
			ModelName: req.ModelName,
			Provider:  req.Provider,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		// Create budget if provided
		if req.Budget != nil {
			budget := configstoreTables.TableBudget{
				ID:            uuid.NewString(),
				MaxLimit:      req.Budget.MaxLimit,
				ResetDuration: req.Budget.ResetDuration,
				LastReset:     time.Now(),
				CurrentUsage:  0,
			}
			if err := validateBudget(&budget); err != nil {
				return err
			}
			if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
				return err
			}
			mc.BudgetID = &budget.ID
			mc.Budget = &budget
		}
		// Create rate limit if provided
		if req.RateLimit != nil {
			rateLimit := configstoreTables.TableRateLimit{
				ID:                   uuid.NewString(),
				TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
				TokenResetDuration:   req.RateLimit.TokenResetDuration,
				RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
				RequestResetDuration: req.RateLimit.RequestResetDuration,
				TokenLastReset:       time.Now(),
				RequestLastReset:     time.Now(),
			}
			if err := validateRateLimit(&rateLimit); err != nil {
				return err
			}
			if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
				return err
			}
			mc.RateLimitID = &rateLimit.ID
			mc.RateLimit = &rateLimit
		}
		if err := h.configStore.CreateModelConfig(ctx, &mc, tx); err != nil {
			return err
		}
		return nil
	}); err != nil {
		logger.Error("failed to create model config: %v", err)
		SendError(ctx, 500, fmt.Sprintf("Failed to create model config: %v", err))
		return
	}
	// Reload model config in memory
	preloadedMC, err := h.governanceManager.ReloadModelConfig(ctx, mc.ID)
	if err != nil {
		logger.Error("failed to reload model config in memory: %v", err)
		preloadedMC = &mc
	}
	SendJSON(ctx, map[string]interface{}{
		"message":      "Model config created successfully",
		"model_config": preloadedMC,
	})
}

// updateModelConfig handles PUT /api/governance/model-configs/{mc_id} - Update a model config
func (h *GovernanceHandler) updateModelConfig(ctx *fasthttp.RequestCtx) {
	mcID := ctx.UserValue("mc_id").(string)
	var req UpdateModelConfigRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	mc, err := h.configStore.GetModelConfigByID(ctx, mcID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Model config not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve model config")
		return
	}
	currentWS := ""
	if mc.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*mc.WorkspaceID)
	}
	if !h.requireWorkspaceWrite(ctx, currentWS) {
		return
	}
	targetModelName := mc.ModelName
	if req.ModelName != nil {
		targetModelName = *req.ModelName
	}
	targetProvider := mc.Provider
	if req.Provider != nil {
		targetProvider = req.Provider
	}
	existing, err := h.configStore.GetModelConfig(ctx, targetModelName, targetProvider)
	if err != nil && err != configstore.ErrNotFound {
		logger.Error("failed to check existing model config: %v", err)
		SendError(ctx, 500, fmt.Sprintf("Failed to check existing model config: %v", err))
		return
	}
	if existing != nil && existing.ID != mc.ID {
		SendError(ctx, 409, modelConfigConflictMessage(targetModelName, targetProvider))
		return
	}
	if !updatedModelConfigHasUsageControls(mc, req) {
		SendError(ctx, 400, modelConfigUsageControlsRequiredError)
		return
	}
	if err := validateModelConfigBudgetUpdate(mc, req.Budget); err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	if err := validateModelConfigRateLimitUpdate(req.RateLimit); err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Track IDs to delete after updating the model config (to avoid FK constraint)
		var budgetIDToDelete, rateLimitIDToDelete string

		// Update fields if provided
		if req.ModelName != nil {
			mc.ModelName = *req.ModelName
		}
		// Update provider if provided in request
		if req.Provider != nil {
			mc.Provider = req.Provider
		}
		// Handle budget updates
		if req.Budget != nil {
			// Check if budget limit is empty - means remove budget (reset duration doesn't matter)
			budgetIsEmpty := req.Budget.MaxLimit == nil
			if budgetIsEmpty {
				// Mark budget for deletion after FK is removed
				if mc.BudgetID != nil {
					budgetIDToDelete = *mc.BudgetID
					mc.BudgetID = nil
					mc.Budget = nil
				}
			} else if mc.BudgetID != nil {
				// Update existing budget
				// Validate that both fields are present before dereferencing
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when updating a budget")
				}
				budget := configstoreTables.TableBudget{}
				if err := tx.First(&budget, "id = ?", *mc.BudgetID).Error; err != nil {
					return err
				}
				// Set all fields from request
				budget.MaxLimit = *req.Budget.MaxLimit
				budget.ResetDuration = *req.Budget.ResetDuration
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.UpdateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				mc.Budget = &budget
			} else {
				// Create new budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when creating a new budget")
				}
				if *req.Budget.MaxLimit < 0 {
					return fmt.Errorf("budget max_limit cannot be negative: %.2f", *req.Budget.MaxLimit)
				}
				if _, err := configstoreTables.ParseDuration(*req.Budget.ResetDuration); err != nil {
					return fmt.Errorf("invalid reset duration format: %s", *req.Budget.ResetDuration)
				}
				budget := configstoreTables.TableBudget{
					ID:            uuid.NewString(),
					MaxLimit:      *req.Budget.MaxLimit,
					ResetDuration: *req.Budget.ResetDuration,
					LastReset:     time.Now(),
					CurrentUsage:  0,
				}
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				mc.BudgetID = &budget.ID
				mc.Budget = &budget
			}
		}
		// Handle rate limit updates
		if req.RateLimit != nil {
			// Check if rate limit values are empty - means remove rate limit (reset durations don't matter)
			rateLimitIsEmpty := req.RateLimit.TokenMaxLimit == nil && req.RateLimit.RequestMaxLimit == nil
			if rateLimitIsEmpty {
				// Mark rate limit for deletion after FK is removed
				if mc.RateLimitID != nil {
					rateLimitIDToDelete = *mc.RateLimitID
					mc.RateLimitID = nil
					mc.RateLimit = nil
				}
			} else if mc.RateLimitID != nil {
				// Update existing rate limit - set ALL fields from request (nil means clear)
				rateLimit := configstoreTables.TableRateLimit{}
				if err := tx.First(&rateLimit, "id = ?", *mc.RateLimitID).Error; err != nil {
					return err
				}
				// Set all fields from request - nil values will clear the field
				rateLimit.TokenMaxLimit = req.RateLimit.TokenMaxLimit
				rateLimit.TokenResetDuration = req.RateLimit.TokenResetDuration
				rateLimit.RequestMaxLimit = req.RateLimit.RequestMaxLimit
				rateLimit.RequestResetDuration = req.RateLimit.RequestResetDuration
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.UpdateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				mc.RateLimit = &rateLimit
			} else {
				// Create new rate limit
				rateLimit := configstoreTables.TableRateLimit{
					ID:                   uuid.NewString(),
					TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
					TokenResetDuration:   req.RateLimit.TokenResetDuration,
					RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
					RequestResetDuration: req.RateLimit.RequestResetDuration,
					TokenLastReset:       time.Now(),
					RequestLastReset:     time.Now(),
				}
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				mc.RateLimitID = &rateLimit.ID
				mc.RateLimit = &rateLimit
			}
		}
		mc.UpdatedAt = time.Now()
		if err := h.configStore.UpdateModelConfig(ctx, mc, tx); err != nil {
			return err
		}

		// Now that FK references are removed, delete the orphaned budget/rate limit
		if budgetIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", budgetIDToDelete).Error; err != nil {
				return err
			}
		}
		if rateLimitIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", rateLimitIDToDelete).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		logger.Error("failed to update model config: %v", err)
		SendError(ctx, 500, fmt.Sprintf("Failed to update model config: %v", err))
		return
	}
	// Reload model config in memory (also reloads from DB to get full relationships)
	updatedMC, err := h.governanceManager.ReloadModelConfig(ctx, mc.ID)
	if err != nil {
		logger.Error("failed to reload model config in memory: %v", err)
		updatedMC = mc
	}
	SendJSON(ctx, map[string]interface{}{
		"message":      "Model config updated successfully",
		"model_config": updatedMC,
	})
}

// deleteModelConfig handles DELETE /api/governance/model-configs/{mc_id} - Delete a model config
func (h *GovernanceHandler) deleteModelConfig(ctx *fasthttp.RequestCtx) {
	mcID := ctx.UserValue("mc_id").(string)
	// Check if model config exists
	mc, err := h.configStore.GetModelConfigByID(ctx, mcID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Model config not found")
			return
		}
		SendError(ctx, 500, "Failed to retrieve model config")
		return
	}
	currentWS := ""
	if mc != nil && mc.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*mc.WorkspaceID)
	}
	if !h.requireWorkspaceWrite(ctx, currentWS) {
		return
	}
	// Delete the model config
	if err := h.configStore.DeleteModelConfig(ctx, mcID); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Model config not found")
			return
		}
		logger.Error("failed to delete model config: %v", err)
		SendError(ctx, 500, "Failed to delete model config")
		return
	}
	// Remove model config from in-memory store
	if err := h.governanceManager.RemoveModelConfig(ctx, mcID); err != nil {
		logger.Error("failed to remove model config from memory: %v", err)
		// Continue anyway, the config is deleted from DB
	}
	SendJSON(ctx, map[string]interface{}{
		"message": "Model config deleted successfully",
	})
}

// Provider Governance Operations

// ProviderGovernanceResponse represents a provider with its governance settings
type ProviderGovernanceResponse struct {
	Provider  string                            `json:"provider"`
	Budget    *configstoreTables.TableBudget    `json:"budget,omitempty"`
	RateLimit *configstoreTables.TableRateLimit `json:"rate_limit,omitempty"`
}

// getProviderGovernance handles GET /api/governance/providers - Get all providers with governance settings
func (h *GovernanceHandler) getProviderGovernance(ctx *fasthttp.RequestCtx) {
	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		data := h.governanceManager.GetGovernanceData(ctx)
		if data == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		var result []ProviderGovernanceResponse
		for _, p := range data.Providers {
			if p.Budget != nil || p.RateLimit != nil {
				result = append(result, ProviderGovernanceResponse{
					Provider:  p.Name,
					Budget:    p.Budget,
					RateLimit: p.RateLimit,
				})
			}
		}
		SendJSON(ctx, map[string]interface{}{
			"providers": result,
			"count":     len(result),
		})
		return
	}
	providers, err := h.configStore.GetProviders(ctx)
	if err != nil {
		logger.Error("failed to retrieve providers: %v", err)
		SendError(ctx, 500, "Failed to retrieve providers")
		return
	}
	// Transform to governance response format
	var result []ProviderGovernanceResponse
	for _, p := range providers {
		if p.Budget != nil || p.RateLimit != nil {
			result = append(result, ProviderGovernanceResponse{
				Provider:  p.Name,
				Budget:    p.Budget,
				RateLimit: p.RateLimit,
			})
		}
	}
	SendJSON(ctx, map[string]interface{}{
		"providers": result,
		"count":     len(result),
	})
}

// updateProviderGovernance handles PUT /api/governance/providers/{provider_name} - Update provider governance
func (h *GovernanceHandler) updateProviderGovernance(ctx *fasthttp.RequestCtx) {
	providerName := ctx.UserValue("provider_name").(string)
	var req UpdateProviderGovernanceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}
	// Get all providers and find the one we need
	providers, err := h.configStore.GetProviders(ctx)
	if err != nil {
		SendError(ctx, 500, "Failed to retrieve providers")
		return
	}
	var provider *configstoreTables.TableProvider
	for i := range providers {
		if providers[i].Name == providerName {
			provider = &providers[i]
			break
		}
	}
	if provider == nil {
		SendError(ctx, 404, "Provider not found")
		return
	}
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Track IDs to delete after updating the provider (to avoid FK constraint)
		var budgetIDToDelete, rateLimitIDToDelete string

		// Handle budget updates
		if req.Budget != nil {
			// Check if budget limit is empty - means remove budget (reset duration doesn't matter)
			budgetIsEmpty := req.Budget.MaxLimit == nil
			if budgetIsEmpty {
				// Mark budget for deletion after FK is removed
				if provider.BudgetID != nil {
					budgetIDToDelete = *provider.BudgetID
					provider.BudgetID = nil
					provider.Budget = nil
				}
			} else if provider.BudgetID != nil {
				// Update existing budget
				// Validate that both fields are present before dereferencing
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when updating a budget")
				}
				budget := configstoreTables.TableBudget{}
				if err := tx.First(&budget, "id = ?", *provider.BudgetID).Error; err != nil {
					return err
				}
				// Set all fields from request
				budget.MaxLimit = *req.Budget.MaxLimit
				budget.ResetDuration = *req.Budget.ResetDuration
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.UpdateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				provider.Budget = &budget
			} else {
				// Create new budget
				if req.Budget.MaxLimit == nil || req.Budget.ResetDuration == nil {
					return fmt.Errorf("both max_limit and reset_duration are required when creating a new budget")
				}
				budget := configstoreTables.TableBudget{
					ID:            uuid.NewString(),
					MaxLimit:      *req.Budget.MaxLimit,
					ResetDuration: *req.Budget.ResetDuration,
					LastReset:     time.Now(),
					CurrentUsage:  0,
				}
				if err := validateBudget(&budget); err != nil {
					return err
				}
				if err := h.configStore.CreateBudget(ctx, &budget, tx); err != nil {
					return err
				}
				provider.BudgetID = &budget.ID
				provider.Budget = &budget
			}
		}
		// Handle rate limit updates
		if req.RateLimit != nil {
			// Check if rate limit values are empty - means remove rate limit (reset durations don't matter)
			rateLimitIsEmpty := req.RateLimit.TokenMaxLimit == nil && req.RateLimit.RequestMaxLimit == nil
			if rateLimitIsEmpty {
				// Mark rate limit for deletion after FK is removed
				if provider.RateLimitID != nil {
					rateLimitIDToDelete = *provider.RateLimitID
					provider.RateLimitID = nil
					provider.RateLimit = nil
				}
			} else if provider.RateLimitID != nil {
				// Update existing rate limit - set ALL fields from request (nil means clear)
				rateLimit := configstoreTables.TableRateLimit{}
				if err := tx.First(&rateLimit, "id = ?", *provider.RateLimitID).Error; err != nil {
					return err
				}
				// Set all fields from request - nil values will clear the field
				rateLimit.TokenMaxLimit = req.RateLimit.TokenMaxLimit
				rateLimit.TokenResetDuration = req.RateLimit.TokenResetDuration
				rateLimit.RequestMaxLimit = req.RateLimit.RequestMaxLimit
				rateLimit.RequestResetDuration = req.RateLimit.RequestResetDuration
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.UpdateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				provider.RateLimit = &rateLimit
			} else {
				// Create new rate limit
				rateLimit := configstoreTables.TableRateLimit{
					ID:                   uuid.NewString(),
					TokenMaxLimit:        req.RateLimit.TokenMaxLimit,
					TokenResetDuration:   req.RateLimit.TokenResetDuration,
					RequestMaxLimit:      req.RateLimit.RequestMaxLimit,
					RequestResetDuration: req.RateLimit.RequestResetDuration,
					TokenLastReset:       time.Now(),
					RequestLastReset:     time.Now(),
				}
				if err := validateRateLimit(&rateLimit); err != nil {
					return err
				}
				if err := h.configStore.CreateRateLimit(ctx, &rateLimit, tx); err != nil {
					return err
				}
				provider.RateLimitID = &rateLimit.ID
				provider.RateLimit = &rateLimit
			}
		}
		// Update only budget/rate limit FK references (avoid overwriting encrypted fields)
		if err := tx.Model(provider).Select("budget_id", "rate_limit_id").Updates(provider).Error; err != nil {
			return err
		}

		// Now that FK references are removed, delete the orphaned budget/rate limit
		if budgetIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", budgetIDToDelete).Error; err != nil {
				return err
			}
		}
		if rateLimitIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", rateLimitIDToDelete).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		logger.Error("failed to update provider governance: %v", err)
		SendError(ctx, 500, fmt.Sprintf("Failed to update provider governance: %v", err))
		return
	}
	// Reload provider in memory
	updatedProvider, err := h.governanceManager.ReloadProvider(ctx, schemas.ModelProvider(providerName))
	if err != nil {
		logger.Error("failed to reload provider in memory: %v", err)
		// Use the local provider object if reload fails
	} else {
		provider = updatedProvider
	}
	SendJSON(ctx, map[string]interface{}{
		"message": "Provider governance updated successfully",
		"provider": ProviderGovernanceResponse{
			Provider:  provider.Name,
			Budget:    provider.Budget,
			RateLimit: provider.RateLimit,
		},
	})
}

// deleteProviderGovernance handles DELETE /api/governance/providers/{provider_name} - Remove governance from provider
func (h *GovernanceHandler) deleteProviderGovernance(ctx *fasthttp.RequestCtx) {
	providerName := ctx.UserValue("provider_name").(string)
	// Get all providers and find the one we need
	providers, err := h.configStore.GetProviders(ctx)
	if err != nil {
		SendError(ctx, 500, "Failed to retrieve providers")
		return
	}
	var provider *configstoreTables.TableProvider
	for i := range providers {
		if providers[i].Name == providerName {
			provider = &providers[i]
			break
		}
	}
	if provider == nil {
		SendError(ctx, 404, "Provider not found")
		return
	}
	if err := h.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Store IDs to delete after removing FK references
		var budgetIDToDelete, rateLimitIDToDelete string

		if provider.BudgetID != nil {
			budgetIDToDelete = *provider.BudgetID
			provider.BudgetID = nil
			provider.Budget = nil
		}
		if provider.RateLimitID != nil {
			rateLimitIDToDelete = *provider.RateLimitID
			provider.RateLimitID = nil
			provider.RateLimit = nil
		}

		// Update only budget/rate limit FK references (avoid overwriting encrypted fields)
		if err := tx.Model(provider).Select("budget_id", "rate_limit_id").Updates(provider).Error; err != nil {
			return err
		}

		// Now delete the orphaned budget/rate limit
		if budgetIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableBudget{}, "id = ?", budgetIDToDelete).Error; err != nil {
				return err
			}
		}
		if rateLimitIDToDelete != "" {
			if err := tx.Delete(&configstoreTables.TableRateLimit{}, "id = ?", rateLimitIDToDelete).Error; err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		logger.Error("failed to delete provider governance: %v", err)
		SendError(ctx, 500, "Failed to delete provider governance")
		return
	}
	// Reload provider in memory (to clear the budget/rate limit)
	if _, err := h.governanceManager.ReloadProvider(ctx, schemas.ModelProvider(providerName)); err != nil {
		logger.Error("failed to reload provider in memory: %v", err)
		// Continue anyway, the governance is deleted from DB
	}
	SendJSON(ctx, map[string]interface{}{
		"message": "Provider governance deleted successfully",
	})
}

// Routing Rules CRUD Operations

// getRoutingRules retrieves all routing rules with optional filtering from database
func (h *GovernanceHandler) getRoutingRules(ctx *fasthttp.RequestCtx) {
	// Get query parameters for filtering
	scope := string(ctx.QueryArgs().Peek("scope"))
	scopeID := string(ctx.QueryArgs().Peek("scope_id"))

	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		gd := h.governanceManager.GetGovernanceData(ctx)
		if gd == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		inMemoryRules := gd.RoutingRules

		// Filter rules by scope and scopeID
		var rules []configstoreTables.TableRoutingRule
		for _, rule := range inMemoryRules {
			if scope != "" && rule.Scope != scope {
				continue
			}
			if scopeID != "" {
				ruleScope := ""
				if rule.ScopeID != nil {
					ruleScope = *rule.ScopeID
				}
				if ruleScope != scopeID {
					continue
				}
			}
			rules = append(rules, *rule)
		}

		SendJSON(ctx, map[string]interface{}{
			"rules":       rules,
			"count":       len(rules),
			"total_count": len(rules),
			"limit":       len(rules),
			"offset":      0,
		})
		return
	}

	// If scope/scopeID filters are specified, use the existing non-paginated path
	if scope != "" || scopeID != "" {
		rules, err := h.configStore.GetRoutingRulesByScope(ctx, scope, scopeID)
		if err != nil {
			SendError(ctx, 500, "Failed to get routing rules")
			return
		}
		response := make([]configstoreTables.TableRoutingRule, 0, len(rules))
		for _, rule := range rules {
			response = append(response, rule)
		}
		SendJSON(ctx, map[string]interface{}{
			"rules":       response,
			"count":       len(response),
			"total_count": len(response),
			"limit":       len(response),
			"offset":      0,
		})
		return
	}

	// Check for pagination parameters
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	offsetStr := string(ctx.QueryArgs().Peek("offset"))
	search := string(ctx.QueryArgs().Peek("search"))
	workspaceID := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id")))
	if workspaceID == "" {
		workspaceID = tenantctx.WorkspaceIDFromContext(ctx)
	}

	if limitStr != "" || offsetStr != "" || search != "" || workspaceID != "" {
		// Paginated path
		params := configstore.RoutingRulesQueryParams{
			Search:      search,
			WorkspaceID: workspaceID,
		}
		if limitStr != "" {
			n, err := strconv.Atoi(limitStr)
			if err != nil {
				SendError(ctx, 400, "Invalid limit parameter: must be a number")
				return
			}
			if n < 0 {
				SendError(ctx, 400, "Invalid limit parameter: must be non-negative")
				return
			}
			params.Limit = n
		}
		if offsetStr != "" {
			n, err := strconv.Atoi(offsetStr)
			if err != nil {
				SendError(ctx, 400, "Invalid offset parameter: must be a number")
				return
			}
			if n < 0 {
				SendError(ctx, 400, "Invalid offset parameter: must be non-negative")
				return
			}
			params.Offset = n
		}

		params.Limit, params.Offset = ClampPaginationParams(params.Limit, params.Offset)
		rules, totalCount, err := h.configStore.GetRoutingRulesPaginated(ctx, params)
		if err != nil {
			logger.Error("failed to retrieve routing rules: %v", err)
			SendError(ctx, 500, "Failed to retrieve routing rules")
			return
		}
		SendJSON(ctx, map[string]interface{}{
			"rules":       rules,
			"count":       len(rules),
			"total_count": totalCount,
			"limit":       params.Limit,
			"offset":      params.Offset,
		})
		return
	}

	// Non-paginated path: return all routing rules
	rules, err := h.configStore.GetRoutingRules(ctx)
	if err != nil {
		logger.Error("failed to retrieve routing rules: %v", err)
		SendError(ctx, 500, "Failed to retrieve routing rules")
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"rules":       rules,
		"count":       len(rules),
		"total_count": len(rules),
		"limit":       len(rules),
		"offset":      0,
	})
}

// getRoutingRule retrieves a single routing rule by ID from database
func (h *GovernanceHandler) getRoutingRule(ctx *fasthttp.RequestCtx) {
	ruleID := ctx.UserValue("rule_id").(string)

	var rule *configstoreTables.TableRoutingRule
	var err error

	fromMemory := h.shouldServeFromMemory(ctx)
	if fromMemory {
		gd := h.governanceManager.GetGovernanceData(ctx)
		if gd == nil {
			SendError(ctx, 500, "Governance data is not available")
			return
		}
		inMemoryRules := gd.RoutingRules

		// Find rule by ID in memory
		for _, r := range inMemoryRules {
			if r.ID == ruleID {
				rule = r
				break
			}
		}
		if rule == nil {
			SendError(ctx, 404, "Routing rule not found")
			return
		}
	} else {
		rule, err = h.configStore.GetRoutingRule(ctx, ruleID)
		if err != nil {
			if errors.Is(err, configstore.ErrNotFound) {
				SendError(ctx, 404, "Routing rule not found")
				return
			}
			logger.Error("failed to get routing rule: %v", err)
			SendError(ctx, 500, "Failed to retrieve routing rule")
			return
		}
	}

	SendJSON(ctx, map[string]interface{}{
		"rule": rule,
	})
}

// createRoutingRule creates a new routing rule
func (h *GovernanceHandler) createRoutingRule(ctx *fasthttp.RequestCtx) {
	// Parse request body
	var req CreateRoutingRuleRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}

	// Validate required fields
	if req.Name == "" {
		SendError(ctx, 400, "name field is required")
		return
	}

	// Validate targets
	if len(req.Targets) == 0 {
		SendError(ctx, 400, "at least one target is required")
		return
	}
	if err := validateRoutingTargets(req.Targets); err != nil {
		SendError(ctx, 400, err.Error())
		return
	}

	if !h.requireWorkspaceWrite(ctx, h.resolveTargetWorkspace(ctx, nil)) {
		return
	}

	// Set defaults and normalize scope/scope_id
	scope := req.Scope
	if scope == "" {
		scope = "global"
	}

	// Validate scope value before normalization
	if err := validateRoutingScope(scope); err != nil {
		SendError(ctx, 400, err.Error())
		return
	}

	// Validate: scope_id required for non-global scopes; must be nil/empty for global
	if scope == "global" {
		req.ScopeID = nil // normalize: global rules must not have scope_id
	} else if req.ScopeID == nil || *req.ScopeID == "" {
		SendError(ctx, 400, "scope_id field is required when scope is not global")
		return
	}

	// Build targets
	ruleID := uuid.NewString()
	targets := make([]configstoreTables.TableRoutingTarget, 0, len(req.Targets))
	for _, t := range req.Targets {
		targets = append(targets, configstoreTables.TableRoutingTarget{
			Provider: t.Provider,
			Model:    t.Model,
			KeyID:    t.KeyID,
			Weight:   t.Weight,
		})
	}

	// Create routing rule
	// Handle Enabled: nil means use DB default (true), otherwise use provided value
	enabled := true // DB default
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	rule := &configstoreTables.TableRoutingRule{
		ID:              ruleID,
		Name:            req.Name,
		Description:     req.Description,
		Enabled:         enabled,
		CelExpression:   req.CelExpression,
		Targets:         targets,
		Scope:           scope,
		ScopeID:         req.ScopeID,
		Priority:        req.Priority,
		ParsedFallbacks: req.Fallbacks,
		ParsedQuery:     req.Query,
	}

	// Plan-tier quota: block creates over the cap. Count is taken from the
	// routing_rules table itself so it stays consistent with on-disk truth
	// across retries; -1 = unlimited (Enterprise) short-circuits cleanly
	// inside EnforceQuota.
	if org, _, orgErr := CurrentOrgFromCtx(ctx, h.configStore); orgErr == nil && org != nil {
		var ruleCount int64
		if db := h.configStore.DB(); db != nil {
			_ = db.WithContext(ctx).
				Model(&configstoreTables.TableRoutingRule{}).
				Where("tenant_id = ?", org.ID).
				Count(&ruleCount).Error
		}
		if err := entitlements.EnforceQuota(ctx, h.configStore.DB(), org, entitlements.LimitConditionalRules, ruleCount); err != nil {
			if qe, ok := err.(*entitlements.QuotaError); ok {
				SendJSONWithStatus(ctx, map[string]any{
					"error":     err.Error(),
					"code":      "QUOTA_EXCEEDED",
					"limit_key": qe.LimitKey,
					"limit":     qe.Limit,
					"current":   qe.Current,
					"plan":      qe.Plan,
					"feature":   qe.Feature,
				}, fasthttp.StatusPaymentRequired)
				return
			}
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
	}

	// Create in database
	if err := h.configStore.CreateRoutingRule(ctx, rule); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to create routing rule: %v", err))
		return
	}

	// Update in-memory store via manager callback
	if err := h.governanceManager.ReloadRoutingRule(ctx, rule.ID); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to reload routing rule in memory: %v, please restart deepintshield to sync with the database", err))
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"message": "Routing rule created successfully",
		"rule":    rule,
	})
}

// updateRoutingRule updates an existing routing rule
func (h *GovernanceHandler) updateRoutingRule(ctx *fasthttp.RequestCtx) {
	ruleID := ctx.UserValue("rule_id").(string)

	// Parse request body
	var req UpdateRoutingRuleRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, 400, "Invalid JSON")
		return
	}

	rule, err := h.configStore.GetRoutingRule(ctx, ruleID)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Routing rule not found")
			return
		}
		logger.Error("failed to get routing rule: %v", err)
		SendError(ctx, 500, "Failed to retrieve routing rule")
		return
	}
	currentWS := ""
	if rule.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*rule.WorkspaceID)
	}
	if !h.requireWorkspaceWrite(ctx, currentWS) {
		return
	}

	// Update fields if provided
	if req.Name != nil && *req.Name != "" {
		rule.Name = *req.Name
	}
	if req.Description != nil {
		rule.Description = *req.Description
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.CelExpression != nil {
		rule.CelExpression = *req.CelExpression
	}
	if req.Targets != nil {
		if len(req.Targets) == 0 {
			SendError(ctx, 400, "at least one routing target is required")
			return
		}
		if err := validateRoutingTargets(req.Targets); err != nil {
			SendError(ctx, 400, err.Error())
			return
		}
		newTargets := make([]configstoreTables.TableRoutingTarget, 0, len(req.Targets))
		for _, t := range req.Targets {
			newTargets = append(newTargets, configstoreTables.TableRoutingTarget{
				Provider: t.Provider,
				Model:    t.Model,
				KeyID:    t.KeyID,
				Weight:   t.Weight,
			})
		}
		rule.Targets = newTargets
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.Query != nil {
		rule.ParsedQuery = req.Query
	}
	if req.Fallbacks != nil {
		rule.ParsedFallbacks = req.Fallbacks
	}
	if req.Scope != nil && *req.Scope != "" {
		// Validate scope value before updating
		if err := validateRoutingScope(*req.Scope); err != nil {
			SendError(ctx, 400, err.Error())
			return
		}
		rule.Scope = *req.Scope
	}
	if req.ScopeID != nil {
		rule.ScopeID = req.ScopeID
	}

	// If scope is global, ensure scope_id is nil
	if rule.Scope == "global" {
		rule.ScopeID = nil
	} else if rule.ScopeID == nil || *rule.ScopeID == "" {
		SendError(ctx, 400, "scope_id field is required when scope is not global")
		return
	}

	// Update in database
	if err := h.configStore.UpdateRoutingRule(ctx, rule); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to update routing rule in database: %v", err))
		return
	}

	// Update in-memory store via manager callback
	if err := h.governanceManager.ReloadRoutingRule(ctx, rule.ID); err != nil {
		SendError(ctx, 500, fmt.Sprintf("Failed to reload routing rule in memory: %v, please restart deepintshield to sync with the database", err))
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"message": "Routing rule updated successfully",
		"rule":    rule,
	})
}

// deleteRoutingRule deletes a routing rule
func (h *GovernanceHandler) deleteRoutingRule(ctx *fasthttp.RequestCtx) {
	ruleID := ctx.UserValue("rule_id").(string)

	// Workspace-write check against the rule's current workspace pinning.
	if rule, err := h.configStore.GetRoutingRule(ctx, ruleID); err == nil && rule != nil {
		currentWS := ""
		if rule.WorkspaceID != nil {
			currentWS = strings.TrimSpace(*rule.WorkspaceID)
		}
		if !h.requireWorkspaceWrite(ctx, currentWS) {
			return
		}
	}

	// Delete from database
	if err := h.configStore.DeleteRoutingRule(ctx, ruleID); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, 404, "Routing rule not found")
			return
		}
		SendError(ctx, 500, fmt.Sprintf("Failed to delete routing rule from database: %v", err))
		return
	}

	// Remove from in-memory store via manager callback (non-fatal: DB already updated)
	if err := h.governanceManager.RemoveRoutingRule(ctx, ruleID); err != nil {
		logger.Error("failed to remove routing rule from memory: %v", err)
	}

	SendJSON(ctx, map[string]interface{}{
		"message": "Routing rule deleted successfully",
	})
}

// validRoutingScopes contains the allowed scope values for routing rules
var validRoutingScopes = map[string]bool{
	"global":      true,
	"team":        true,
	"customer":    true,
	"virtual_key": true,
}

// validateRoutingScope validates that the scope value is one of the allowed values
func validateRoutingScope(scope string) error {
	if scope == "" {
		return nil // Empty scope will default to "global" later
	}
	if !validRoutingScopes[scope] {
		return fmt.Errorf("invalid scope %q: must be one of: global, team, customer, virtual_key", scope)
	}
	return nil
}

// validateRoutingTargets checks that all weights are positive, that no two
// targets share the same (provider, model, key_id) identity, and that all
// weights sum to 1.
func validateRoutingTargets(targets []RoutingTarget) error {
	seen := make(map[string]struct{}, len(targets))
	total := 0.0
	for _, t := range targets {
		if t.Weight < 0 {
			return fmt.Errorf("each target weight must be positive")
		}
		if t.KeyID != nil && *t.KeyID != "" && (t.Provider == nil || *t.Provider == "") {
			return fmt.Errorf("key_id requires provider to be set")
		}

		// Canonicalise identity: lowercase provider/model, treat nil == "".
		provider := ""
		if t.Provider != nil {
			provider = strings.ToLower(*t.Provider)
		}
		model := ""
		if t.Model != nil {
			model = strings.ToLower(*t.Model)
		}
		keyID := ""
		if t.KeyID != nil {
			keyID = *t.KeyID
		}
		key := provider + "|" + model + "|" + keyID
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate target entry: provider=%q model=%q key_id=%q", provider, model, keyID)
		}
		seen[key] = struct{}{}

		total += t.Weight
	}
	if math.Abs(total-1.0) > 0.001 {
		return fmt.Errorf("target weights must sum to 1, got %.4f", total)
	}
	return nil
}

// getKeyHealth handles GET /api/governance/key-health - Returns health status for all tracked keys
func (h *GovernanceHandler) getKeyHealth(ctx *fasthttp.RequestCtx) {
	if h.keyHealthProvider == nil {
		SendJSON(ctx, map[string]interface{}{"keys": []KeyHealthInfo{}})
		return
	}
	keys := h.keyHealthProvider()
	if keys == nil {
		keys = []KeyHealthInfo{}
	}
	SendJSON(ctx, map[string]interface{}{"keys": keys})
}
