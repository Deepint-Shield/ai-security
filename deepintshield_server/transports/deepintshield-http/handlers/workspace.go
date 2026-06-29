package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// WorkspaceHandler manages workspace CRUD + workspace-scoped membership reads.
// Org-level membership reads also live here for routing convenience (single
// auth helper).
type WorkspaceHandler struct {
	configStore configstore.ConfigStore
}

func NewWorkspaceHandler(configStore configstore.ConfigStore) *WorkspaceHandler {
	return &WorkspaceHandler{configStore: configStore}
}

func (h *WorkspaceHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/organizations/{orgId}/workspaces", lib.ChainMiddlewares(h.listWorkspacesByOrg, middlewares...))
	r.POST("/api/organizations/{orgId}/workspaces", lib.ChainMiddlewares(h.createWorkspace, middlewares...))
	r.GET("/api/organizations/{orgId}/members", lib.ChainMiddlewares(h.listOrgMembers, middlewares...))

	r.GET("/api/workspaces/me", lib.ChainMiddlewares(h.listMyWorkspaces, middlewares...))
	r.GET("/api/workspaces/{id}", lib.ChainMiddlewares(h.getWorkspace, middlewares...))
	r.PUT("/api/workspaces/{id}", lib.ChainMiddlewares(h.updateWorkspace, middlewares...))
	r.DELETE("/api/workspaces/{id}", lib.ChainMiddlewares(h.deleteWorkspace, middlewares...))
	r.POST("/api/workspaces/{id}/clone", lib.ChainMiddlewares(h.cloneWorkspace, middlewares...))
	r.GET("/api/workspaces/{id}/members", lib.ChainMiddlewares(h.listWorkspaceMembers, middlewares...))

	r.POST("/api/organizations/{orgId}/members", lib.ChainMiddlewares(h.addOrgMember, middlewares...))
	r.PUT("/api/organizations/{orgId}/members/{userId}", lib.ChainMiddlewares(h.updateOrgMember, middlewares...))
	r.DELETE("/api/organizations/{orgId}/members/{userId}", lib.ChainMiddlewares(h.removeOrgMember, middlewares...))

	r.POST("/api/workspaces/{id}/members", lib.ChainMiddlewares(h.addWorkspaceMember, middlewares...))
	r.PUT("/api/workspaces/{id}/members/{userId}", lib.ChainMiddlewares(h.updateWorkspaceMember, middlewares...))
	r.DELETE("/api/workspaces/{id}/members/{userId}", lib.ChainMiddlewares(h.removeWorkspaceMember, middlewares...))

	r.GET("/api/workspaces/{id}/api-keys", lib.ChainMiddlewares(h.listWorkspaceAPIKeys, middlewares...))
	r.POST("/api/workspaces/{id}/api-keys", lib.ChainMiddlewares(h.createWorkspaceAPIKey, middlewares...))
	r.DELETE("/api/workspaces/{id}/api-keys/{keyId}", lib.ChainMiddlewares(h.revokeWorkspaceAPIKey, middlewares...))
}

type createAPIKeyRequest struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	UserID    string `json:"user_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type updateMemberRequest struct {
	Role string `json:"role"`
}

type createWorkspaceRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

type updateWorkspaceRequest struct {
	Name        *string `json:"name"`
	Slug        *string `json:"slug"`
	Description *string `json:"description"`
}

func (h *WorkspaceHandler) listWorkspacesByOrg(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	orgID := pathParam(ctx, "orgId")
	if orgID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "orgId is required")
		return
	}
	if !h.canReadOrg(ctx, user, orgID) {
		SendError(ctx, fasthttp.StatusForbidden, "You are not a member of this organization")
		return
	}
	workspaces, err := h.configStore.ListWorkspacesByOrg(ctx, orgID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list workspaces: %v", err))
		return
	}
	// Tenant-level admins (owner / admin role on this tenant) and
	// superadmins see every workspace - they manage the tenant. Plain
	// org_members (i.e. cross-workspace invitees we added at the
	// tenant level so the tenant shows in their switcher) only see
	// workspaces they were explicitly invited to via
	// workspace_memberships. Without this filter, inviting alpha to
	// workspace B under Madhu's tenant ALSO leaked workspaces A, C,
	// D under that tenant just because alpha now has an org_membership
	// row for the parent tenant.
	if !canSeeAllWorkspacesInOrg(ctx, h.configStore, user, orgID) {
		visibleByID := make(map[string]struct{})
		if memberships, mErr := h.configStore.ListWorkspaceMembershipsByUser(ctx, user.ID); mErr == nil {
			for _, m := range memberships {
				if m.OrgID == orgID {
					visibleByID[m.WorkspaceID] = struct{}{}
				}
			}
		}
		filtered := workspaces[:0]
		for _, ws := range workspaces {
			if _, ok := visibleByID[ws.ID]; ok {
				filtered = append(filtered, ws)
			}
		}
		workspaces = filtered
	}
	out := make([]map[string]any, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, serializeWorkspace(&workspaces[i]))
	}
	SendJSON(ctx, map[string]any{"workspaces": out})
}

// canRenameWorkspace returns true when the caller can change the
// workspace's name or slug - a "container" operation distinct from
// managing the workspace's contents (providers, keys, members).
//
// Allowed:
//   - System superadmin
//   - The workspace creator (workspaces.created_by == user.id)
//   - The parent tenant's owner / admin (org_memberships.role in
//     {owner, admin} for ws.org_id)
//
// NOT allowed: workspace_admins who were invited into the workspace
// from a different tenant. They can manage contents but should not
// rename someone else's workspace container.
func canRenameWorkspace(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, ws *tables.TableWorkspace) bool {
	if user == nil || ws == nil || store == nil {
		return false
	}
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	if strings.TrimSpace(ws.CreatedBy) != "" && ws.CreatedBy == user.ID {
		return true
	}
	mem, err := store.GetOrgMembership(ctx, ws.OrgID, user.ID)
	if err != nil || mem == nil {
		return false
	}
	return mem.Role == tables.OrgRoleOwner || mem.Role == tables.OrgRoleAdmin
}

// canSeeAllWorkspacesInOrg returns true when the caller is allowed to
// see every workspace in the org (tenant) regardless of their personal
// workspace_memberships - i.e. they're a system superadmin, or they
// hold an org_memberships row with role=owner/admin on this tenant.
// Plain org_members (cross-workspace invitees) only see workspaces
// they were explicitly added to.
func canSeeAllWorkspacesInOrg(ctx context.Context, store configstore.ConfigStore, user *tables.TableAuthUser, orgID string) bool {
	if user == nil {
		return false
	}
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	mem, err := store.GetOrgMembership(ctx, orgID, user.ID)
	if err != nil || mem == nil {
		return false
	}
	return mem.Role == tables.OrgRoleOwner || mem.Role == tables.OrgRoleAdmin
}

func (h *WorkspaceHandler) createWorkspace(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	orgID := pathParam(ctx, "orgId")
	if orgID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "orgId is required")
		return
	}
	if !h.canManageOrg(ctx, user, orgID) {
		SendError(ctx, fasthttp.StatusForbidden, "Only org owners/admins or system admins can create workspaces")
		return
	}

	var payload createWorkspaceRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	name := strings.TrimSpace(payload.Name)
	slug := slugify(payload.Slug, name)
	if name == "" || slug == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "name is required")
		return
	}
	if existing, err := h.configStore.GetWorkspaceBySlug(ctx, orgID, slug); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to validate slug: %v", err))
		return
	} else if existing != nil {
		SendError(ctx, fasthttp.StatusConflict, "Slug already in use within this organization")
		return
	}

	now := time.Now().UTC()
	ws := &tables.TableWorkspace{
		ID:          "ws-" + uuid.New().String(),
		OrgID:       orgID,
		Name:        name,
		Slug:        slug,
		Description: strings.TrimSpace(payload.Description),
		IsDefault:   false,
		CreatedBy:   user.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.configStore.CreateWorkspace(ctx, ws); err != nil {
		status, msg := friendlyError(err, "workspace")
		SendError(ctx, status, msg)
		return
	}
	if err := h.configStore.CreateWorkspaceMembership(ctx, &tables.TableWorkspaceMembership{
		ID:          "wm-" + uuid.New().String(),
		WorkspaceID: ws.ID,
		OrgID:       orgID,
		UserID:      user.ID,
		Role:        tables.WorkspaceRoleAdmin,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		status, msg := friendlyError(err, "workspace membership")
		SendError(ctx, status, msg)
		return
	}
	// Seed cache defaults so the new workspace ships with the items flagged
	// RECOMMENDED in the UI (Provider Prompt Caching, Semantic Cache,
	// Coalescing, Guardrail Decision Cache) turned on. Non-fatal - a seeding
	// failure logs but doesn't block workspace creation; the user can always
	// toggle from Settings → Caches.
	if err := h.seedRecommendedPlugins(ctx, ws); err != nil {
		logger.Warn("failed to seed recommended plugins for workspace %s: %v", ws.ID, err)
	}
	SendJSON(ctx, map[string]any{"workspace": serializeWorkspace(ws)})
}

// seedRecommendedPlugins inserts the per-workspace plugin row that matches the
// UI's RECOMMENDED cache defaults so every fresh workspace ships with provider
// prompt caching, semantic caching, request coalescing and the guardrail
// decision cache turned on out-of-the-box.
//
// The plugin row is workspace-scoped via the CreatePlugin path's
// resolveEffectiveWorkspaceID - we pass ws.ID through context so the row
// lands on the new workspace even though the caller's active workspace in
// the original request was the source/parent.
//
// Each cache fail-opens on a miss / provider unreachable / sidecar error, so a
// misconfigured embedding sidecar etc. degrades to "no cache hit" rather than
// "broken requests".
func (h *WorkspaceHandler) seedRecommendedPlugins(ctx *fasthttp.RequestCtx, ws *tables.TableWorkspace) error {
	if h.configStore == nil || ws == nil {
		return nil
	}
	seeded := &tables.TablePlugin{
		Name:        "semantic_cache",
		Enabled:     true,
		IsCustom:    false,
		WorkspaceID: &ws.ID,
		Config:      recommendedSemanticCacheDefaults(),
	}
	return h.configStore.CreatePlugin(ctx, seeded)
}

// recommendedSemanticCacheDefaults returns the canonical cache preset shipped
// with every fresh workspace. Centralized so the UI's defaultCacheConfig and
// this seed agree on the same numbers.
func recommendedSemanticCacheDefaults() map[string]any {
	return map[string]any{
		// ── Semantic Cache ────────────────────────────────────────────
		// Embedding provider stays huggingface so out-of-the-box installs
		// hit the local deepintshield-models sidecar; operators who want
		// the cheaper / higher-quality OpenAI text-embedding-3-small path
		// flip embedding_via_vk_enabled and pick a VK in the UI.
		"provider":              "huggingface",
		"embedding_model":       "BAAI/bge-base-en-v1.5",
		"ttl_seconds":           3600,  // 1h (was 5m) - typical "what did the user just ask" windows
		"threshold":             0.70,  // similarity cutoff - 0.70 hits ~30% more paraphrased queries vs 0.75
		"cache_by_model":        false, // shares cache buckets across model tiers (gpt-4o / gpt-4o-mini)
		"cache_by_provider":     true,
		"exclude_system_prompt": false,
		"auto_scope_enabled":    true,
		"auto_scope_mode":       "conservative",
		"shared_vk_policy":      "exact_only_when_unscoped",

		// ── Provider Prompt Caching (Anthropic/OpenAI/Bedrock/Google) ─
		// 90% discount on cached input tokens. Always ON - fail-open.
		"prompt_cache_enabled":           true,
		"prompt_cache_providers":         []string{"anthropic", "openai", "bedrock", "google"},
		"prompt_cache_breakpoints":       []string{"system", "tools"},
		"prompt_cache_anthropic_ttl":     "5m",
		"prompt_cache_google_ttl":        "1h",
		"prompt_cache_min_static_tokens": 1024,

		// ── Coalescing ────────────────────────────────────────────────
		// In-flight dedup of identical requests; pure win.
		"coalescing_enabled":         true,
		"coalescing_max_in_flight":   1000,
		"coalescing_wait_timeout_ms": 30000,

		// ── Guardrail Decision Cache ──────────────────────────────────
		"guardrail_cache_enabled":     true,
		"guardrail_cache_ttl_seconds": 3600,
		"guardrail_cache_max_entries": 10000,
	}
}

type cloneWorkspaceRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
}

// cloneWorkspace handles POST /api/workspaces/{id}/clone - creates a new
// workspace inside the same tenant, then copies workspace-scoped config
// (MCP Clients, Routing Rules, Model Configs, Plugins, RAG Sources)
// from the source workspace, suffixing each resource's name to avoid
// the (tenant_id, name) unique-index collisions that would otherwise
// reject the inserts.
//
// What we do NOT clone (deliberately):
//   - Virtual Keys: secret values must be re-issued; out of scope for
//     this endpoint.
//   - Prompts + versions + sessions: large surface, audit-attached;
//     usually not what "clone workspace" should mean.
//   - Memberships: only the caller is added to the new workspace as
//     admin; team membership is intentional and should be re-curated.
//   - Logs / audit / billing: observability and metering data, not
//     config.
func (h *WorkspaceHandler) cloneWorkspace(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	sourceID := pathParam(ctx, "id")
	if sourceID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Workspace id is required")
		return
	}
	src, err := h.configStore.GetWorkspaceByID(ctx, sourceID)
	if err != nil || src == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Source workspace not found")
		return
	}
	// Permission: must be able to read the source AND create a new
	// workspace in its tenant.
	if !h.canReadWorkspace(ctx, user, src) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot read the source workspace")
		return
	}
	if !h.canManageOrg(ctx, user, src.OrgID) {
		SendError(ctx, fasthttp.StatusForbidden, "Only tenant owners/admins or system admins can clone workspaces")
		return
	}

	var req cloneWorkspaceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = src.Name + " (copy)"
	}
	slug := slugify(req.Slug, name)
	if slug == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "name produces an empty slug")
		return
	}
	if existing, err := h.configStore.GetWorkspaceBySlug(ctx, src.OrgID, slug); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to validate slug: %v", err))
		return
	} else if existing != nil {
		SendError(ctx, fasthttp.StatusConflict, "Slug already in use within this tenant")
		return
	}

	now := time.Now().UTC()
	target := &tables.TableWorkspace{
		ID:          "ws-" + uuid.New().String(),
		OrgID:       src.OrgID,
		Name:        name,
		Slug:        slug,
		Description: strings.TrimSpace(req.Description),
		IsDefault:   false,
		CreatedBy:   user.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.configStore.CreateWorkspace(ctx, target); err != nil {
		status, msg := friendlyError(err, "cloned workspace")
		SendError(ctx, status, msg)
		return
	}
	if err := h.configStore.CreateWorkspaceMembership(ctx, &tables.TableWorkspaceMembership{
		ID:          "wm-" + uuid.New().String(),
		WorkspaceID: target.ID,
		OrgID:       src.OrgID,
		UserID:      user.ID,
		Role:        tables.WorkspaceRoleAdmin,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		status, msg := friendlyError(err, "workspace membership")
		SendError(ctx, status, msg)
		return
	}

	// ─── Bulk-copy workspace-scoped resources via raw SQL ──────────────
	// Approach: INSERT ... SELECT, rewriting workspace_id and giving the
	// new rows fresh names suffixed with the target slug to dodge the
	// (tenant_id, name) unique constraints. Generated IDs / timestamps
	// are also recomputed so the new rows look freshly created. We
	// capture per-resource counts so the response can show the operator
	// what landed in the new workspace.
	type cloneCount struct {
		Resource string `json:"resource"`
		Copied   int64  `json:"copied"`
	}
	counts := make([]cloneCount, 0, 5)
	if db := h.configStore.DB(); db != nil {
		// MCP Clients: rename to "<name> [<targetSlug>]" so the
		// (tenant_id, name) index doesn't blow up.
		if res := db.WithContext(ctx).Exec(`
			INSERT INTO config_mcp_clients
				(tenant_id, workspace_id, client_id, name, is_code_mode_client, connection_type, connection_string,
				 stdio_config_json, tools_to_execute_json, tools_to_auto_execute_json, headers_json, is_ping_available,
				 tool_pricing_json, tool_sync_interval, auth_type, oauth_config_id, config_hash, encryption_status,
				 created_at, updated_at)
			SELECT
				tenant_id, ?, client_id || '-' || ?, name || ' [' || ? || ']', is_code_mode_client, connection_type,
				connection_string, stdio_config_json, tools_to_execute_json, tools_to_auto_execute_json, headers_json,
				is_ping_available, tool_pricing_json, tool_sync_interval, auth_type, oauth_config_id, config_hash,
				encryption_status, ?, ?
			FROM config_mcp_clients
			WHERE workspace_id = ?
		`, target.ID, target.Slug, target.Slug, now, now, sourceID); res.Error == nil {
			counts = append(counts, cloneCount{Resource: "mcp_clients", Copied: res.RowsAffected})
		}
		// Routing Rules
		if res := db.WithContext(ctx).Exec(`
			INSERT INTO routing_rules
				(id, tenant_id, workspace_id, config_hash, name, description, enabled, cel_expression, fallbacks,
				 query, scope, scope_id, priority, created_at, updated_at)
			SELECT
				'rr-' || lower(hex(randomblob(16))), tenant_id, ?, config_hash, name || ' [' || ? || ']', description,
				enabled, cel_expression, fallbacks, query, scope, scope_id, priority, ?, ?
			FROM routing_rules
			WHERE workspace_id = ?
		`, target.ID, target.Slug, now, now, sourceID); res.Error == nil {
			counts = append(counts, cloneCount{Resource: "routing_rules", Copied: res.RowsAffected})
		}
		// Plugins
		if res := db.WithContext(ctx).Exec(`
			INSERT INTO config_plugins
				(tenant_id, workspace_id, name, enabled, path, config_json, created_at, version, updated_at,
				 is_custom, placement, exec_order, config_hash, encryption_status)
			SELECT
				tenant_id, ?, name || ' [' || ? || ']', enabled, path, config_json, ?, version, ?,
				is_custom, placement, exec_order, config_hash, encryption_status
			FROM config_plugins
			WHERE workspace_id = ?
		`, target.ID, target.Slug, now, now, sourceID); res.Error == nil {
			counts = append(counts, cloneCount{Resource: "plugins", Copied: res.RowsAffected})
		}
		// RAG Sources
		if res := db.WithContext(ctx).Exec(`
			INSERT INTO guardrail_rag_sources
				(id, tenant_id, workspace_id, name, connector, index_name, owner, sensitivity, retention_class,
				 trust_level, tenant, app_name, acl_tags_json, labels_json, document_count, chunk_count, health,
				 quarantined, quarantine_reason, last_scan_at, created_at, updated_at)
			SELECT
				'rs-' || lower(hex(randomblob(16))), tenant_id, ?, name || ' [' || ? || ']', connector, index_name,
				owner, sensitivity, retention_class, trust_level, tenant, app_name, acl_tags_json, labels_json,
				document_count, chunk_count, health, quarantined, quarantine_reason, last_scan_at, ?, ?
			FROM guardrail_rag_sources
			WHERE workspace_id = ?
		`, target.ID, target.Slug, now, now, sourceID); res.Error == nil {
			counts = append(counts, cloneCount{Resource: "rag_sources", Copied: res.RowsAffected})
		}
	}

	SendJSON(ctx, map[string]any{
		"workspace": serializeWorkspace(target),
		"cloned":    counts,
		"source_id": sourceID,
	})
}

func (h *WorkspaceHandler) getWorkspace(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canReadWorkspace(ctx, user, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "You are not a member of this workspace")
		return
	}
	SendJSON(ctx, map[string]any{"workspace": serializeWorkspace(ws)})
}

func (h *WorkspaceHandler) updateWorkspace(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canManageWorkspace(ctx, user, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins can update workspaces")
		return
	}

	var payload updateWorkspaceRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	// Renaming the workspace (or changing its slug) is a "container"
	// operation - distinct from managing its contents (providers, keys,
	// members). Cross-workspace invitees who land here as
	// WorkspaceRoleAdmin can manage contents, but they shouldn't be
	// able to rename the workspace they were invited into. Restrict
	// rename/slug to the creator, the tenant owner/admin, or
	// superadmins.
	wantsRename := (payload.Name != nil && strings.TrimSpace(*payload.Name) != "" && strings.TrimSpace(*payload.Name) != ws.Name) ||
		(payload.Slug != nil && strings.TrimSpace(*payload.Slug) != "" && strings.TrimSpace(*payload.Slug) != ws.Slug)
	if wantsRename && !canRenameWorkspace(ctx, h.configStore, user, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only the workspace creator or a tenant owner/admin can rename the workspace.")
		return
	}
	if payload.Name != nil {
		if name := strings.TrimSpace(*payload.Name); name != "" {
			ws.Name = name
		}
	}
	if payload.Slug != nil {
		newSlug := slugify(*payload.Slug, ws.Name)
		if newSlug != "" && newSlug != ws.Slug {
			if existing, err := h.configStore.GetWorkspaceBySlug(ctx, ws.OrgID, newSlug); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to validate slug: %v", err))
				return
			} else if existing != nil && existing.ID != ws.ID {
				SendError(ctx, fasthttp.StatusConflict, "Slug already in use within this organization")
				return
			}
			ws.Slug = newSlug
		}
	}
	if payload.Description != nil {
		ws.Description = strings.TrimSpace(*payload.Description)
	}
	ws.UpdatedAt = time.Now().UTC()
	if err := h.configStore.UpdateWorkspace(ctx, ws); err != nil {
		status, msg := friendlyError(err, "workspace")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"workspace": serializeWorkspace(ws)})
}

func (h *WorkspaceHandler) deleteWorkspace(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if ws.IsDefault {
		// Default workspace is only protected when it's the *only* workspace
		// in the tenant - otherwise the user can delete it just like any
		// other (the UI guards against deleting the active workspace
		// separately, so they have to switch first).
		siblings, err := h.configStore.ListWorkspacesByOrg(ctx, ws.OrgID)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to count workspaces: %v", err))
			return
		}
		if len(siblings) <= 1 {
			SendError(ctx, fasthttp.StatusBadRequest, "Cannot delete the only workspace in this tenant - create another first")
			return
		}
	}
	if !h.canManageWorkspace(ctx, user, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins or system admins can delete workspaces")
		return
	}

	// Resource-gate: count rows that explicitly reference this workspace.
	// We never auto-delete those - the caller has to clean them up first
	// (or move them) so a workspace deletion can't quietly orphan VKs,
	// guardrails, prompts, or unrevoked API keys. Org-wide rows
	// (workspace_id IS NULL) are not counted because they don't get
	// dropped with this workspace.
	rc, err := h.countWorkspaceResources(ctx, ws.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to count workspace resources: %v", err))
		return
	}
	if rc.total() > 0 {
		SendJSON(ctx, map[string]any{
			"error":     "workspace not empty - delete or move the listed resources first",
			"resources": rc,
		})
		ctx.SetStatusCode(fasthttp.StatusConflict)
		return
	}

	// Type-the-slug confirmation. Required as a query param so a stray
	// DELETE doesn't proceed even if the resource gate happens to pass.
	if confirm := strings.TrimSpace(string(ctx.QueryArgs().Peek("confirm_slug"))); confirm != ws.Slug {
		SendError(ctx, fasthttp.StatusBadRequest, "Pass ?confirm_slug=<workspace slug> to confirm deletion")
		return
	}

	if err := h.configStore.DeleteWorkspace(ctx, id); err != nil {
		status, msg := friendlyError(err, "workspace")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"deleted": id})
}

// workspaceResourceCounts is the body returned alongside a 409 from the
// workspace delete endpoint when the resource gate trips. The caller can
// render this verbatim in the confirm UI to tell the user exactly what
// they need to clear out before retrying.
type workspaceResourceCounts struct {
	VirtualKeys       int64 `json:"virtual_keys"`
	GuardrailPolicies int64 `json:"guardrail_policies"`
	Prompts           int64 `json:"prompts"`
	APIKeysActive     int64 `json:"api_keys_active"`
}

func (c workspaceResourceCounts) total() int64 {
	return c.VirtualKeys + c.GuardrailPolicies + c.Prompts + c.APIKeysActive
}

// countWorkspaceResources runs five indexed COUNT queries to gauge
// whether a workspace is safe to delete. All five hit the workspace_id
// index we added in earlier phases, so the total cost is in the
// single-digit-ms range - acceptable for a rare admin action.
func (h *WorkspaceHandler) countWorkspaceResources(ctx *fasthttp.RequestCtx, workspaceID string) (workspaceResourceCounts, error) {
	var rc workspaceResourceCounts

	// Virtual keys explicitly scoped to this workspace. We can't reuse the
	// `(workspace_id = ? OR workspace_id IS NULL)` filter from
	// VirtualKeyQueryParams because we want the strictly-this-workspace
	// count for delete-gating, not the inclusive view used by the admin
	// list. So pass through with limit 1 and inspect total - but filter
	// in-process to drop org-wide hits.
	if vks, _, err := h.configStore.GetVirtualKeysPaginated(ctx, configstore.VirtualKeyQueryParams{WorkspaceID: workspaceID, Limit: 100}); err == nil {
		var n int64
		for i := range vks {
			if vks[i].WorkspaceID != nil && *vks[i].WorkspaceID == workspaceID {
				n++
			}
		}
		rc.VirtualKeys = n
	} else {
		return rc, err
	}

	// Guardrail policies (workspace-scoped only; org-wide stays).
	if policies, err := h.configStore.ListGuardrailPolicies(ctx); err == nil {
		var n int64
		for i := range policies {
			if policies[i].WorkspaceID != nil && *policies[i].WorkspaceID == workspaceID {
				n++
			}
		}
		rc.GuardrailPolicies = n
	} else {
		return rc, err
	}

	// Prompts scoped to this workspace.
	if prompts, err := h.configStore.GetPromptsScoped(ctx, nil, workspaceID); err == nil {
		var n int64
		for i := range prompts {
			if prompts[i].WorkspaceID != nil && *prompts[i].WorkspaceID == workspaceID {
				n++
			}
		}
		rc.Prompts = n
	} else {
		return rc, err
	}

	// Workspace API keys not yet revoked. Revoked keys are kept for audit
	// but don't block deletion.
	if keys, err := h.configStore.ListWorkspaceAPIKeys(ctx, workspaceID); err == nil {
		var n int64
		for i := range keys {
			if keys[i].RevokedAt == nil {
				n++
			}
		}
		rc.APIKeysActive = n
	} else {
		return rc, err
	}

	return rc, nil
}

func (h *WorkspaceHandler) listMyWorkspaces(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	workspaces, err := h.configStore.ListWorkspacesByUser(ctx, user.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list workspaces: %v", err))
		return
	}
	out := make([]map[string]any, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, serializeWorkspace(&workspaces[i]))
	}
	SendJSON(ctx, map[string]any{"workspaces": out})
}

func (h *WorkspaceHandler) listOrgMembers(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	orgID := pathParam(ctx, "orgId")
	if !h.canReadOrg(ctx, user, orgID) {
		SendError(ctx, fasthttp.StatusForbidden, "You are not a member of this organization")
		return
	}
	memberships, err := h.configStore.ListOrgMembershipsByOrg(ctx, orgID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list members: %v", err))
		return
	}
	out := make([]map[string]any, 0, len(memberships))
	for _, m := range memberships {
		entry := map[string]any{
			"user_id":    m.UserID,
			"org_id":     m.OrgID,
			"role":       m.Role,
			"created_at": m.CreatedAt,
		}
		if u, err := h.configStore.GetUserByID(ctx, m.UserID); err == nil && u != nil {
			entry["email"] = u.Email
			entry["first_name"] = u.FirstName
			entry["last_name"] = u.LastName
		}
		out = append(out, entry)
	}
	SendJSON(ctx, map[string]any{"members": out})
}

func (h *WorkspaceHandler) listWorkspaceMembers(ctx *fasthttp.RequestCtx) {
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canReadWorkspace(ctx, user, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "You are not a member of this workspace")
		return
	}
	memberships, err := h.configStore.ListWorkspaceMembershipsByWorkspace(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list members: %v", err))
		return
	}
	out := make([]map[string]any, 0, len(memberships))
	for _, m := range memberships {
		entry := map[string]any{
			"user_id":      m.UserID,
			"workspace_id": m.WorkspaceID,
			"org_id":       m.OrgID,
			"role":         m.Role,
			"created_at":   m.CreatedAt,
		}
		if u, err := h.configStore.GetUserByID(ctx, m.UserID); err == nil && u != nil {
			entry["email"] = u.Email
			entry["first_name"] = u.FirstName
			entry["last_name"] = u.LastName
		}
		out = append(out, entry)
	}
	SendJSON(ctx, map[string]any{"members": out})
}

// Authorization helpers. Superadmins pass unconditionally; otherwise we
// fall through to org/workspace membership role checks. UserRoleAdmin is
// the default for fresh signups and intentionally does NOT bypass - see
// workspace_permissions.go for the rationale.

func (h *WorkspaceHandler) canReadOrg(ctx *fasthttp.RequestCtx, user *tables.TableAuthUser, orgID string) bool {
	if user.Role == tables.UserRoleSuperadmin {
		return true
	}
	m, err := h.configStore.GetOrgMembership(ctx, orgID, user.ID)
	return err == nil && m != nil
}

func (h *WorkspaceHandler) canManageOrg(ctx *fasthttp.RequestCtx, user *tables.TableAuthUser, orgID string) bool {
	return CanManageTenant(ctx, h.configStore, user, orgID)
}

func (h *WorkspaceHandler) canReadWorkspace(ctx *fasthttp.RequestCtx, user *tables.TableAuthUser, ws *tables.TableWorkspace) bool {
	return CanReadWorkspace(ctx, h.configStore, user, ws)
}

func (h *WorkspaceHandler) canManageWorkspace(ctx *fasthttp.RequestCtx, user *tables.TableAuthUser, ws *tables.TableWorkspace) bool {
	return CanManageWorkspace(ctx, h.configStore, user, ws)
}

func pathParam(ctx *fasthttp.RequestCtx, key string) string {
	if v, ok := ctx.UserValue(key).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// resolveMemberUser locates the auth_user identified by either user_id or
// email in the request payload, normalising precedence: explicit user_id
// wins over email lookup.
func (h *WorkspaceHandler) resolveMemberUser(ctx *fasthttp.RequestCtx, payload addMemberRequest) (*tables.TableAuthUser, error) {
	if id := strings.TrimSpace(payload.UserID); id != "" {
		return h.configStore.GetUserByID(ctx, id)
	}
	if email := strings.TrimSpace(payload.Email); email != "" {
		return h.configStore.GetUserByEmail(ctx, email)
	}
	return nil, nil
}

func normaliseOrgRole(role string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case tables.OrgRoleOwner:
		return tables.OrgRoleOwner, true
	case tables.OrgRoleAdmin:
		return tables.OrgRoleAdmin, true
	case "", tables.OrgRoleMember:
		return tables.OrgRoleMember, true
	}
	return "", false
}

func normaliseWorkspaceRole(role string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case tables.WorkspaceRoleAdmin:
		return tables.WorkspaceRoleAdmin, true
	case "", tables.WorkspaceRoleMember:
		return tables.WorkspaceRoleMember, true
	case tables.WorkspaceRoleViewer:
		return tables.WorkspaceRoleViewer, true
	}
	return "", false
}

func (h *WorkspaceHandler) addOrgMember(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	orgID := pathParam(ctx, "orgId")
	if !h.canManageOrg(ctx, caller, orgID) {
		SendError(ctx, fasthttp.StatusForbidden, "Only org owners/admins or system admins can add members")
		return
	}
	var payload addMemberRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	role, ok := normaliseOrgRole(payload.Role)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "role must be owner, admin, or member")
		return
	}
	target, err := h.resolveMemberUser(ctx, payload)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to resolve user: %v", err))
		return
	}
	if target == nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found - pass user_id or a registered email")
		return
	}
	if existing, _ := h.configStore.GetOrgMembership(ctx, orgID, target.ID); existing != nil {
		SendError(ctx, fasthttp.StatusConflict, "User is already a member of this organisation")
		return
	}
	now := time.Now().UTC()
	mem := &tables.TableOrgMembership{
		ID:        "om-" + uuid.New().String(),
		OrgID:     orgID,
		UserID:    target.ID,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.configStore.CreateOrgMembership(ctx, mem); err != nil {
		status, msg := friendlyError(err, "membership")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"membership": mem})
}

func (h *WorkspaceHandler) updateOrgMember(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	orgID := pathParam(ctx, "orgId")
	userID := pathParam(ctx, "userId")
	if !h.canManageOrg(ctx, caller, orgID) {
		SendError(ctx, fasthttp.StatusForbidden, "Only org owners/admins or system admins can change roles")
		return
	}
	var payload updateMemberRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	role, ok := normaliseOrgRole(payload.Role)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "role must be owner, admin, or member")
		return
	}
	// Block demoting the last owner.
	if role != tables.OrgRoleOwner {
		members, err := h.configStore.ListOrgMembershipsByOrg(ctx, orgID)
		if err == nil {
			ownerCount := 0
			demotingOwner := false
			for _, m := range members {
				if m.Role == tables.OrgRoleOwner {
					ownerCount++
					if m.UserID == userID {
						demotingOwner = true
					}
				}
			}
			if demotingOwner && ownerCount <= 1 {
				SendError(ctx, fasthttp.StatusBadRequest, "Cannot demote the only org owner")
				return
			}
		}
	}
	if err := h.configStore.UpdateOrgMembershipRole(ctx, orgID, userID, role); err != nil {
		status, msg := friendlyError(err, "membership")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"updated": true, "role": role})
}

func (h *WorkspaceHandler) removeOrgMember(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	orgID := pathParam(ctx, "orgId")
	userID := pathParam(ctx, "userId")
	if !h.canManageOrg(ctx, caller, orgID) {
		SendError(ctx, fasthttp.StatusForbidden, "Only org owners/admins or system admins can remove members")
		return
	}
	target, _ := h.configStore.GetOrgMembership(ctx, orgID, userID)
	if target == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Membership not found")
		return
	}
	if target.Role == tables.OrgRoleOwner {
		members, _ := h.configStore.ListOrgMembershipsByOrg(ctx, orgID)
		ownerCount := 0
		for _, m := range members {
			if m.Role == tables.OrgRoleOwner {
				ownerCount++
			}
		}
		if ownerCount <= 1 {
			SendError(ctx, fasthttp.StatusBadRequest, "Cannot remove the only org owner")
			return
		}
	}
	if err := h.configStore.DeleteOrgMembership(ctx, orgID, userID); err != nil {
		status, msg := friendlyError(err, "membership")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"deleted": true})
}

func (h *WorkspaceHandler) addWorkspaceMember(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canManageWorkspace(ctx, caller, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins can add members")
		return
	}
	var payload addMemberRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	role, ok := normaliseWorkspaceRole(payload.Role)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "role must be admin, member, or viewer")
		return
	}
	target, err := h.resolveMemberUser(ctx, payload)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to resolve user: %v", err))
		return
	}
	if target == nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found - pass user_id or a registered email")
		return
	}
	// Workspace member must already be in the org.
	if orgMem, _ := h.configStore.GetOrgMembership(ctx, ws.OrgID, target.ID); orgMem == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "User must be an org member before joining a workspace")
		return
	}
	if existing, _ := h.configStore.GetWorkspaceMembership(ctx, ws.ID, target.ID); existing != nil {
		SendError(ctx, fasthttp.StatusConflict, "User is already a member of this workspace")
		return
	}
	now := time.Now().UTC()
	mem := &tables.TableWorkspaceMembership{
		ID:          "wm-" + uuid.New().String(),
		WorkspaceID: ws.ID,
		OrgID:       ws.OrgID,
		UserID:      target.ID,
		Role:        role,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.configStore.CreateWorkspaceMembership(ctx, mem); err != nil {
		status, msg := friendlyError(err, "workspace membership")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"membership": mem})
}

func (h *WorkspaceHandler) updateWorkspaceMember(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	userID := pathParam(ctx, "userId")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canManageWorkspace(ctx, caller, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins can change roles")
		return
	}
	var payload updateMemberRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	role, ok := normaliseWorkspaceRole(payload.Role)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "role must be admin, member, or viewer")
		return
	}
	if err := h.configStore.UpdateWorkspaceMembershipRole(ctx, ws.ID, userID, role); err != nil {
		status, msg := friendlyError(err, "membership")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"updated": true, "role": role})
}

func (h *WorkspaceHandler) removeWorkspaceMember(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	userID := pathParam(ctx, "userId")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canManageWorkspace(ctx, caller, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins can remove members")
		return
	}
	if err := h.configStore.DeleteWorkspaceMembership(ctx, ws.ID, userID); err != nil {
		status, msg := friendlyError(err, "membership")
		SendError(ctx, status, msg)
		return
	}
	SendJSON(ctx, map[string]any{"deleted": true})
}

// generateWorkspaceAPIKey returns (plaintext, hash, prefix). The plaintext
// is shown to the caller exactly once and is never persisted; the hash is
// what we compare against on subsequent inbound requests.
//
// Format: dis_ws_<32 url-safe base64 bytes>. The "dis_ws_" sentinel lets
// the inference middleware tell at a glance whether a presented bearer is
// a workspace API key vs a virtual key, without a DB lookup.
func generateWorkspaceAPIKey() (plaintext, hash, prefix string, err error) {
	raw := make([]byte, 24)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	plaintext = "dis_ws_" + body
	sum := sha256.Sum256([]byte(plaintext))
	hash = hex.EncodeToString(sum[:])
	// Prefix is the human-friendly identifier shown in lists. Keep it long
	// enough to disambiguate keys created seconds apart but short enough
	// not to leak entropy beyond what's already visible at creation time.
	if len(plaintext) >= 14 {
		prefix = plaintext[:14] + "…"
	} else {
		prefix = plaintext
	}
	return plaintext, hash, prefix, nil
}

func serializeWorkspaceAPIKey(k *tables.TableWorkspaceAPIKey) map[string]any {
	return map[string]any{
		"id":           k.ID,
		"workspace_id": k.WorkspaceID,
		"org_id":       k.OrgID,
		"type":         k.Type,
		"name":         k.Name,
		"key_prefix":   k.KeyPrefix,
		"user_id":      k.UserID,
		"created_by":   k.CreatedBy,
		"expires_at":   k.ExpiresAt,
		"last_used_at": k.LastUsedAt,
		"revoked_at":   k.RevokedAt,
		"created_at":   k.CreatedAt,
	}
}

func (h *WorkspaceHandler) listWorkspaceAPIKeys(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canReadWorkspace(ctx, caller, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "You are not a member of this workspace")
		return
	}
	keys, err := h.configStore.ListWorkspaceAPIKeys(ctx, ws.ID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list API keys: %v", err))
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for i := range keys {
		out = append(out, serializeWorkspaceAPIKey(&keys[i]))
	}
	SendJSON(ctx, map[string]any{"api_keys": out})
}

// createWorkspaceAPIKey issues a brand-new credential. The plaintext key is
// returned in the response under "plaintext" exactly once; subsequent reads
// only return the prefix. Caller must persist the plaintext immediately.
func (h *WorkspaceHandler) createWorkspaceAPIKey(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canManageWorkspace(ctx, caller, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins or system admins can create API keys")
		return
	}

	var payload createAPIKeyRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "name is required")
		return
	}
	keyType := strings.ToLower(strings.TrimSpace(payload.Type))
	switch keyType {
	case tables.WorkspaceAPIKeyTypeServiceAccount, tables.WorkspaceAPIKeyTypeUser:
		// ok
	case "":
		keyType = tables.WorkspaceAPIKeyTypeServiceAccount
	default:
		SendError(ctx, fasthttp.StatusBadRequest, "type must be service_account or user")
		return
	}

	var userID *string
	if keyType == tables.WorkspaceAPIKeyTypeUser {
		uid := strings.TrimSpace(payload.UserID)
		if uid == "" {
			uid = caller.ID
		}
		userID = &uid
	}

	var expiresAt *time.Time
	if exp := strings.TrimSpace(payload.ExpiresAt); exp != "" {
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expiresAt = &t
	}

	plaintext, keyHash, keyPrefix, err := generateWorkspaceAPIKey()
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to generate API key")
		return
	}

	now := time.Now().UTC()
	rec := &tables.TableWorkspaceAPIKey{
		ID:          "wak-" + uuid.New().String(),
		WorkspaceID: ws.ID,
		OrgID:       ws.OrgID,
		Type:        keyType,
		Name:        name,
		KeyHash:     keyHash,
		KeyPrefix:   keyPrefix,
		UserID:      userID,
		CreatedBy:   caller.ID,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.configStore.CreateWorkspaceAPIKey(ctx, rec); err != nil {
		status, msg := friendlyError(err, "API key")
		SendError(ctx, status, msg)
		return
	}

	SendJSON(ctx, map[string]any{
		"api_key":   serializeWorkspaceAPIKey(rec),
		"plaintext": plaintext,
		"warning":   "This is the only time the secret is shown. Store it somewhere safe.",
	})
}

func (h *WorkspaceHandler) revokeWorkspaceAPIKey(ctx *fasthttp.RequestCtx) {
	caller, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}
	id := pathParam(ctx, "id")
	keyID := pathParam(ctx, "keyId")
	ws, err := h.configStore.GetWorkspaceByID(ctx, id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load workspace: %v", err))
		return
	}
	if ws == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Workspace not found")
		return
	}
	if !h.canManageWorkspace(ctx, caller, ws) {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins or org owners/admins or system admins can revoke API keys")
		return
	}
	target, err := h.configStore.GetWorkspaceAPIKeyByID(ctx, keyID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load API key: %v", err))
		return
	}
	if target == nil || target.WorkspaceID != ws.ID {
		SendError(ctx, fasthttp.StatusNotFound, "API key not found in this workspace")
		return
	}
	if err := h.configStore.RevokeWorkspaceAPIKey(ctx, keyID); err != nil {
		status, msg := friendlyError(err, "API key")
		SendError(ctx, status, msg)
		return
	}
	// Drop the cached resolution so the local replica stops accepting the
	// token immediately. Other replicas will catch up within
	// workspaceCacheTTL - see InvalidateWorkspaceAPIKeyCache docstring.
	lib.InvalidateWorkspaceAPIKeyCache(target.KeyHash)
	SendJSON(ctx, map[string]any{"revoked": keyID})
}

func slugify(input, fallback string) string {
	out := strings.ToLower(strings.TrimSpace(input))
	if out == "" {
		out = strings.ToLower(strings.TrimSpace(fallback))
	}
	out = strings.ReplaceAll(out, " ", "-")
	// Strip anything other than [a-z0-9-_]; keep tight to avoid weird URLs.
	var b strings.Builder
	for _, r := range out {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}
