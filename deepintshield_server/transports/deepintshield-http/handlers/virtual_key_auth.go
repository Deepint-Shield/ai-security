package handlers

import (
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/plugins/governance"
	"github.com/valyala/fasthttp"
)

const promptRepositoryFrontendSourceHeader = "X-BF-Frontend-Source"
const promptRepositoryFrontendSourceValue = "prompt-repo"

func supportsVirtualKeyAPIAuth(ctx *fasthttp.RequestCtx) bool {
	if ctx == nil {
		return false
	}

	path := string(ctx.Path())
	// ReBAC Authorization surface (config / relationships CRUD / check /
	// list-objects / graph). Every endpoint derives its tenant from the VK
	// lookup and confines reads + writes to that tenant's OpenFGA store, so
	// SDKs and automation can manage relationships with the same bearer the
	// agent already uses for /decide. Covers GET, POST and DELETE.
	if strings.HasPrefix(path, "/api/agentic-security/authorization/") {
		return true
	}
	if ctx.IsPost() {
		switch path {
		case "/api/rag-security/evaluate", "/api/guardrails/rag/evaluate", "/api/guardrails/evaluate":
			return true
		case "/api/agentic-security/decide":
			// Agent SDKs call /decide on every tool invocation with
			// only the VK bearer. Tenant + workspace are derived from
			// the VK lookup; the X-Agent-Token (when present) is a
			// further strengthening signal verified by the runtime.
			return true
		case "/api/agentic-security/blueprints":
			// shield.agentic.govern() registers the declared tool surface
			// before a run with the same VK bearer it uses for /decide.
			// Tenant + workspace are derived from the VK lookup; the body
			// carries structure only (names/edges), never args or data.
			return true
		}
		// Approval decisions - the agent SDK polls GET /approvals/{id}
		// and the operator (oncall, runbook, etc.) can flip approve/deny
		// via POST /approvals/{id}/decide using the same VK bearer.
		// Tenant scoping comes from the VK row; the handler additionally
		// validates the approval row belongs to that tenant before
		// mutating, so a leaked VK can only act on its own approvals.
		if strings.HasPrefix(path, "/api/agentic-security/approvals/") && strings.HasSuffix(path, "/decide") {
			return true
		}
		// Grant revocation - operator automation (oncall / runbook) and the
		// agent SDK can revoke a behavior-bound auto-allow grant with the
		// same VK bearer. The handler re-validates the grant's tenant via the
		// resolver/store, so a leaked VK can only revoke its own tenant's
		// grants. (The GET /grants listing stays session-gated.)
		if strings.HasPrefix(path, "/api/agentic-security/grants/") && strings.HasSuffix(path, "/revoke") {
			return true
		}
	}
	// SDK-facing discovery routes the d.mcp surface hits with just a
	// VK header - the SDK has no session cookie. Tenant + workspace
	// context are derived from the VK lookup, so the handlers stay
	// tenant-scoped without needing a session.
	if ctx.IsGet() {
		switch path {
		case "/api/mcp/clients":
			return true
		case "/api/agentic-security/vk-credential-info":
			// SDK construction-time discovery - returns OIDC info
			// (tenant / blueprint / authority / scopes) for the VK.
			// No secrets in the response.
			return true
		}
		// Agent SDK polls /approvals/{id} when a verdict was
		// REQUIRE_APPROVAL. Prefix match because the id is a path
		// variable.
		if strings.HasPrefix(path, "/api/agentic-security/approvals/") {
			return true
		}
	}
	return false
}

func tryAttachValidVirtualKey(ctx *fasthttp.RequestCtx, store configstore.ConfigStore) (bool, bool) {
	if ctx == nil || store == nil {
		return false, false
	}

	virtualKeyValue := governance.ParseVirtualKeyFromFastHTTPRequest(ctx)
	if virtualKeyValue == nil || strings.TrimSpace(*virtualKeyValue) == "" {
		return false, false
	}
	trimmedKey := strings.TrimSpace(*virtualKeyValue)

	// Fast path: check in-process cache. Beyond the VK identity itself,
	// the entry also carries pre-computed early-exit hints
	// (has_guards, has_mcp_config) so the inference plugin chain can
	// skip its own per-request lookups when neither feature is bound.
	if cached, ok := globalAuthCache.getVirtualKey(trimmedKey); ok {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyVirtualKey, cached.vkValue)
		if cached.tenantID != "" && ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID) == nil {
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, cached.tenantID)
		}
		if cached.workspaceID != "" && ctx.UserValue(schemas.DeepIntShieldContextKeyWorkspaceID) == nil {
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyWorkspaceID, cached.workspaceID)
		}
		// Pre-stamped early-exit hints - readable by the guardrails
		// + MCP plugins via context to skip per-request DB roundtrips.
		ctx.SetUserValue("__bf_vk_has_guards", cached.hasGuards)
		ctx.SetUserValue("__bf_vk_has_mcp", cached.hasMCPConfig)
		return true, true
	}

	vk, err := store.GetVirtualKeyByValue(ctx, trimmedKey)
	if err != nil {
		if err == configstore.ErrNotFound {
			SendError(ctx, fasthttp.StatusForbidden, "Virtual key not found.")
			return false, true
		}
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to validate virtual key")
		return false, true
	}

	ctx.SetUserValue(schemas.DeepIntShieldContextKeyVirtualKey, vk.Value)
	tenantID := strings.TrimSpace(vk.TenantID)
	if tenantID != "" && ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID) == nil {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, tenantID)
	}
	workspaceID := ""
	if vk.WorkspaceID != nil {
		workspaceID = strings.TrimSpace(*vk.WorkspaceID)
	}
	if workspaceID != "" && ctx.UserValue(schemas.DeepIntShieldContextKeyWorkspaceID) == nil {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyWorkspaceID, workspaceID)
	}
	// Pre-compute hot-path early-exit hints. The bound slices are
	// populated by GORM's many2many preloads when the VK is fetched
	// for governance use; on the inference path we may have a thin
	// VK without preloads and the hints stay false (safe default -
	// the plugins fall through to their normal lookup).
	hasGuards := len(vk.GuardrailPolicies) > 0
	hasMCPConfig := len(vk.MCPConfigs) > 0
	ctx.SetUserValue("__bf_vk_has_guards", hasGuards)
	ctx.SetUserValue("__bf_vk_has_mcp", hasMCPConfig)
	globalAuthCache.putVirtualKey(trimmedKey, vkCacheEntry{
		vkValue:      vk.Value,
		tenantID:     tenantID,
		workspaceID:  workspaceID,
		hasGuards:    hasGuards,
		hasMCPConfig: hasMCPConfig,
	})
	return true, true
}

func shouldBypassVirtualKeyValidation(ctx *fasthttp.RequestCtx) bool {
	if ctx == nil {
		return false
	}

	if !strings.EqualFold(strings.TrimSpace(string(ctx.Request.Header.Peek(promptRepositoryFrontendSourceHeader))), promptRepositoryFrontendSourceValue) {
		return false
	}

	if string(ctx.Path()) != "/v1/chat/completions" {
		return false
	}

	if sessionToken := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeySessionToken))); sessionToken != "" {
		return true
	}

	if tenantID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID))); tenantID != "" {
		return true
	}

	return false
}

// RequireValidVirtualKeyMiddleware enforces that inference-style routes are accessed
// only with a real, persisted virtual key.
func RequireValidVirtualKeyMiddleware(store configstore.ConfigStore) schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			if shouldBypassVirtualKeyValidation(ctx) {
				next(ctx)
				return
			}

			if store == nil {
				SendError(ctx, fasthttp.StatusInternalServerError, "Virtual key validation is unavailable")
				return
			}

			authorized, handled := tryAttachValidVirtualKey(ctx, store)
			if !handled {
				SendError(ctx, fasthttp.StatusUnauthorized, "Virtual key is required. Provide a virtual key via the x-bf-vk header.")
				return
			}
			if !authorized {
				return
			}
			next(ctx)
		}
	}
}
