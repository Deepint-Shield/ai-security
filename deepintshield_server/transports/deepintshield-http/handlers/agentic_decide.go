// Package handlers - basic open-source Agentic Security Policy Decision Point.
//
// This is the OSS slice of the agentic control plane: a standalone /decide
// endpoint backed by ABAC rules (a Rego / typed-AST policy evaluator), an
// in-process decision cache + async audit, plus the simple policy / tool CRUD
// needed to author and load the rules. The premium agentic surfaces (tool
// integrity, AIBOM / code-scan, grants, ReBAC / OpenFGA identity, observability
// exporters, the post-decision cache, OWASP analytics) are intentionally absent.
//
// Endpoints mounted under /api/agentic-security:
//
//	POST /decide           - direct PDP call (VK-bearer auth; used by SDKs/tests)
//	GET  /health           - runtime cache hit ratio + audit drop counters
//	GET  /policies         - list ABAC policies
//	POST /policies         - create (validates Rego compiles, loads into runtime)
//	GET  /policies/{id}    - read one
//	PUT  /policies/{id}    - update (bumps version → cache invalidation)
//	DELETE /policies/{id}  - delete
//	GET  /tools            - list tool tiering rows
//	PUT  /tools            - upsert a tool tier (loads into runtime)
//	DELETE /tools/{id}     - delete a tool tier
//	GET  /rollout          - per-tenant Shadow/Canary/Enforce state
//	PUT  /rollout          - set rollout state
//	GET  /decisions        - append-only decision audit query
//	GET  /permission-templates[/{id}] - curated starter policy catalog
//	GET  /tool-templates[/{id}]        - curated starter tool catalog
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/agentic"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
)

// agenticDecideStore is the minimal configstore contract the basic PDP needs:
// policy + tool-tiering CRUD, decision append/query, and the policy-target
// reads that warm the in-memory resolver.
type agenticDecideStore interface {
	// Policies
	ListAgenticPolicies(ctx context.Context) ([]tables.TableAgenticPolicy, error)
	GetAgenticPolicy(ctx context.Context, id string) (*tables.TableAgenticPolicy, error)
	CreateAgenticPolicy(ctx context.Context, row *tables.TableAgenticPolicy) error
	UpdateAgenticPolicy(ctx context.Context, row *tables.TableAgenticPolicy) error
	DeleteAgenticPolicy(ctx context.Context, id string) error
	// Tool tiering
	ListAgenticToolTiering(ctx context.Context) ([]tables.TableAgenticToolTiering, error)
	UpsertAgenticToolTiering(ctx context.Context, row *tables.TableAgenticToolTiering) error
	DeleteAgenticToolTiering(ctx context.Context, id string) error
	// Decisions
	ListAgenticDecisions(ctx context.Context, limit int, verdict, tool string, since, until *time.Time) ([]tables.TableAgenticDecision, error)
	AppendAgenticDecision(ctx context.Context, row *tables.TableAgenticDecision) error
	// Enforcement (rollout) state
	GetAgenticEnforcementState(ctx context.Context) (*tables.TableAgenticEnforcementState, error)
	ListAgenticEnforcementStates(ctx context.Context) ([]tables.TableAgenticEnforcementState, error)
	UpdateAgenticEnforcementState(ctx context.Context, row *tables.TableAgenticEnforcementState) error
}

// AgenticSecurityHandler exposes the basic PDP HTTP API and bridges persisted
// config to the runtime decision engine.
type AgenticSecurityHandler struct {
	store   agenticDecideStore
	runtime *agentic.Runtime
}

// NewAgenticSecurityHandler wires the persistence layer with the PDP runtime so
// policy edits made through the API take effect on the next decision (a
// policy_version bump invalidates the cache).
func NewAgenticSecurityHandler(store agenticDecideStore, runtime *agentic.Runtime) *AgenticSecurityHandler {
	return &AgenticSecurityHandler{store: store, runtime: runtime}
}

// RegisterRoutes mounts the basic Agentic Security surface under
// /api/agentic-security.
func (h *AgenticSecurityHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	base := "/api/agentic-security"
	// Runtime health.
	r.GET(base+"/health", lib.ChainMiddlewares(h.getHealth, middlewares...))
	// Policies (ABAC rule authoring).
	r.GET(base+"/policies", lib.ChainMiddlewares(h.listPolicies, middlewares...))
	r.POST(base+"/policies", lib.ChainMiddlewares(h.createPolicy, middlewares...))
	r.GET(base+"/policies/{id}", lib.ChainMiddlewares(h.getPolicy, middlewares...))
	r.PUT(base+"/policies/{id}", lib.ChainMiddlewares(h.updatePolicy, middlewares...))
	r.DELETE(base+"/policies/{id}", lib.ChainMiddlewares(h.deletePolicy, middlewares...))
	// Tool tiering.
	r.GET(base+"/tools", lib.ChainMiddlewares(h.listTools, middlewares...))
	r.PUT(base+"/tools", lib.ChainMiddlewares(h.upsertTool, middlewares...))
	r.DELETE(base+"/tools/{id}", lib.ChainMiddlewares(h.deleteTool, middlewares...))
	// Rollout (Shadow / Canary / Enforce).
	r.GET(base+"/rollout", lib.ChainMiddlewares(h.getRollout, middlewares...))
	r.PUT(base+"/rollout", lib.ChainMiddlewares(h.updateRollout, middlewares...))
	// Decisions audit query.
	r.GET(base+"/decisions", lib.ChainMiddlewares(h.listDecisions, middlewares...))
	// Basic OSS decision stats (allow/deny/approval/mask counts + timeline) for
	// the dashboard Agentic analytics tab. The premium /stats surface (verdict/
	// latency/cost series, OWASP rollups, etc.) is enterprise-only; this is the
	// minimal counts-only slice computed from the decision audit store.
	r.GET(base+"/stats", lib.ChainMiddlewares(h.getStats, middlewares...))
	// Curated, in-memory starter catalogs (read-only, constant-time).
	r.GET(base+"/permission-templates", lib.ChainMiddlewares(h.listPermissionTemplates, middlewares...))
	r.GET(base+"/permission-templates/{id}", lib.ChainMiddlewares(h.getPermissionTemplate, middlewares...))
	r.GET(base+"/tool-templates", lib.ChainMiddlewares(h.listToolTemplates, middlewares...))
	r.GET(base+"/tool-templates/{id}", lib.ChainMiddlewares(h.getToolTemplate, middlewares...))
	// PDP direct invoke (VK-bearer auth via supportsVirtualKeyAPIAuth).
	r.POST(base+"/decide", lib.ChainMiddlewares(h.decide, middlewares...))
}

// requireAgenticWrite gates mutating endpoints to admins.
func (h *AgenticSecurityHandler) requireAgenticWrite(ctx *fasthttp.RequestCtx) bool {
	if currentSessionUserRole(ctx) == tables.UserRoleAdmin {
		return true
	}
	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		// OSS no-login build: dashboard auth is disabled, so there is no
		// session user - the caller is the local admin. (When auth IS enabled,
		// the auth middleware rejects session-less requests to these non-
		// whitelisted routes before they ever reach this handler, so a nil user
		// here can only mean the open-source single-admin mode.)
		return true
	}
	if user.Role != tables.UserRoleAdmin {
		SendError(ctx, fasthttp.StatusForbidden,
			"Only system admins or tenant admins can modify Agentic Security configuration")
		return false
	}
	return true
}

// ----------------------------------------------------------------------------
// /decide
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) decide(ctx *fasthttp.RequestCtx) {
	if h.runtime == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "agentic runtime unavailable")
		return
	}
	var dc agentic.DelegationContext
	if err := json.Unmarshal(ctx.PostBody(), &dc); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	// Hard-stop: arguments must already be a digest. We refuse raw args so the
	// zero-data-retention invariant cannot be violated through this endpoint.
	if dc.ArgsDigest == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "args_digest is required (zero-data-retention)")
		return
	}
	// Stamp tenant + workspace + VK from the middleware-attached context. The SDK
	// only ships the bearer; the middleware has already validated it and pinned
	// tenant/workspace to the request. Doing this server-side keeps the audit row
	// tenant-scoped without trusting SDK-supplied values.
	if v, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyVirtualKey).(string); ok && v != "" {
		dc.VirtualKey = v
	}
	if t, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID).(string); ok && t != "" {
		dc.Tenant = t
	}
	if w, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyWorkspaceID).(string); ok && w != "" {
		dc.Workspace = w
	}
	dec := h.runtime.Decide(auditStoreContext(ctx), dc)
	SendJSON(ctx, dec)
}

// ----------------------------------------------------------------------------
// Health
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) getHealth(ctx *fasthttp.RequestCtx) {
	if h.runtime == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "agentic runtime unavailable")
		return
	}
	snap := h.runtime.Health()
	type out struct {
		agentic.HealthSnapshot
		CacheHitRate float64 `json:"cache_hit_rate"`
	}
	total := snap.Cache.Hits + snap.Cache.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(snap.Cache.Hits) / float64(total) * 100.0
	}
	SendJSON(ctx, out{HealthSnapshot: snap, CacheHitRate: hitRate})
}

// ----------------------------------------------------------------------------
// Policies
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) listPolicies(ctx *fasthttp.RequestCtx) {
	rows, err := h.store.ListAgenticPolicies(auditStoreContext(ctx))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSON(ctx, map[string]any{"policies": rows})
}

func (h *AgenticSecurityHandler) getPolicy(ctx *fasthttp.RequestCtx) {
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	row, err := h.store.GetAgenticPolicy(auditStoreContext(ctx), id)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	if row == nil {
		SendError(ctx, fasthttp.StatusNotFound, "policy not found")
		return
	}
	SendJSON(ctx, row)
}

func (h *AgenticSecurityHandler) createPolicy(ctx *fasthttp.RequestCtx) {
	if !h.requireAgenticWrite(ctx) {
		return
	}
	var row tables.TableAgenticPolicy
	if err := json.Unmarshal(ctx.PostBody(), &row); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	// Power-user-supplied Rego wins (Advanced editor); else compile the visual
	// rule into Rego. Either way validate it compiles via OPA before accepting.
	if strings.TrimSpace(row.GeneratedRego) == "" {
		if compiled, ok := compilePolicyDefinitionToRego(row.Definition); ok {
			row.GeneratedRego = compiled
		}
	}
	if rg := strings.TrimSpace(row.GeneratedRego); rg != "" {
		ev := agentic.CompileRegoModules([]string{rg})
		if err := ev.LastCompileError(); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Rego compile error: %v", err))
			return
		}
	}
	if err := h.store.CreateAgenticPolicy(auditStoreContext(ctx), &row); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	h.reloadRuntimePolicies(ctx)
	SendJSON(ctx, row)
}

func (h *AgenticSecurityHandler) updatePolicy(ctx *fasthttp.RequestCtx) {
	if !h.requireAgenticWrite(ctx) {
		return
	}
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	existing, err := h.store.GetAgenticPolicy(auditStoreContext(ctx), id)
	if err != nil || existing == nil {
		SendError(ctx, fasthttp.StatusNotFound, "policy not found")
		return
	}
	var body tables.TableAgenticPolicy
	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	// Merge - preserve immutable id/tenant/created_at.
	body.ID = existing.ID
	body.TenantID = existing.TenantID
	body.CreatedAt = existing.CreatedAt
	// Bump policy_version on every body update so cached decisions for this
	// policy become structurally stale.
	body.PolicyVersion = existing.PolicyVersion + 1
	if strings.TrimSpace(body.GeneratedRego) == "" {
		if compiled, ok := compilePolicyDefinitionToRego(body.Definition); ok {
			body.GeneratedRego = compiled
		}
	}
	if rg := strings.TrimSpace(body.GeneratedRego); rg != "" {
		ev := agentic.CompileRegoModules([]string{rg})
		if err := ev.LastCompileError(); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Rego compile error: %v", err))
			return
		}
	}
	if err := h.store.UpdateAgenticPolicy(auditStoreContext(ctx), &body); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	h.reloadRuntimePolicies(ctx)
	SendJSON(ctx, body)
}

func (h *AgenticSecurityHandler) deletePolicy(ctx *fasthttp.RequestCtx) {
	if !h.requireAgenticWrite(ctx) {
		return
	}
	id, _ := getIDFromCtx(ctx)
	if err := h.store.DeleteAgenticPolicy(auditStoreContext(ctx), id); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	if h.runtime != nil {
		if resolver := h.runtime.PolicyTargetResolver(); resolver != nil {
			resolver.DeletePolicy(id)
		}
	}
	h.reloadRuntimePolicies(ctx)
	SendJSON(ctx, map[string]any{"deleted": id})
}

// ----------------------------------------------------------------------------
// Tool tiering
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) listTools(ctx *fasthttp.RequestCtx) {
	rows, err := h.store.ListAgenticToolTiering(auditStoreContext(ctx))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSON(ctx, map[string]any{"tools": rows})
}

func (h *AgenticSecurityHandler) upsertTool(ctx *fasthttp.RequestCtx) {
	if !h.requireAgenticWrite(ctx) {
		return
	}
	var row tables.TableAgenticToolTiering
	if err := json.Unmarshal(ctx.PostBody(), &row); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.UpsertAgenticToolTiering(auditStoreContext(ctx), &row); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	h.reloadRuntimeTiering(ctx)
	SendJSON(ctx, row)
}

func (h *AgenticSecurityHandler) deleteTool(ctx *fasthttp.RequestCtx) {
	if !h.requireAgenticWrite(ctx) {
		return
	}
	id, _ := getIDFromCtx(ctx)
	if err := h.store.DeleteAgenticToolTiering(auditStoreContext(ctx), id); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	h.reloadRuntimeTiering(ctx)
	SendJSON(ctx, map[string]any{"deleted": id})
}

// ----------------------------------------------------------------------------
// Rollout (Shadow / Canary / Enforce)
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) getRollout(ctx *fasthttp.RequestCtx) {
	// The Agentic Policy config page consumes a SINGLE enforcement state for the
	// current scope, not the full list. Returning {"states":[...]} left the page
	// reading kill_switch/mode off an array (always undefined), so the Enforce
	// toggle never reflected or persisted the saved value. Return the scoped state
	// (auto-provisioned in shadow mode if it doesn't exist yet).
	state, err := h.store.GetAgenticEnforcementState(auditStoreContext(ctx))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSON(ctx, state)
}

func (h *AgenticSecurityHandler) updateRollout(ctx *fasthttp.RequestCtx) {
	if !h.requireAgenticWrite(ctx) {
		return
	}
	var row tables.TableAgenticEnforcementState
	if err := json.Unmarshal(ctx.PostBody(), &row); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.UpdateAgenticEnforcementState(auditStoreContext(ctx), &row); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	if h.runtime != nil {
		mode := agentic.EnforcementMode(strings.ToLower(strings.TrimSpace(row.Mode)))
		switch mode {
		case agentic.EnforcementCanary, agentic.EnforcementEnforce, agentic.EnforcementShadow:
			h.runtime.SetEnforcementMode(row.TenantID, row.WorkspaceID, mode)
		}
	}
	SendJSON(ctx, row)
}

// ----------------------------------------------------------------------------
// Decisions audit
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) listDecisions(ctx *fasthttp.RequestCtx) {
	limit := 100
	if v := strings.TrimSpace(string(ctx.QueryArgs().Peek("limit"))); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	verdict := strings.TrimSpace(string(ctx.QueryArgs().Peek("verdict")))
	tool := strings.TrimSpace(string(ctx.QueryArgs().Peek("tool")))
	rows, err := h.store.ListAgenticDecisions(auditStoreContext(ctx), limit, verdict, tool, nil, nil)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSON(ctx, map[string]any{"decisions": rows})
}

// ----------------------------------------------------------------------------
// Basic decision stats (OSS)
// ----------------------------------------------------------------------------

// agenticBasicStats is the minimal shape the dashboard Agentic analytics tab
// consumes: total + per-verdict counts plus a coarse hourly timeline. It is
// deliberately tiny - the full premium analytics endpoint (latency/cost/OWASP
// series) is enterprise-only.
type agenticBasicStats struct {
	Total    int64                       `json:"total"`
	Allow    int64                       `json:"allow"`
	Deny     int64                       `json:"deny"`
	Approval int64                       `json:"approval"`
	Mask     int64                       `json:"mask"`
	Timeline []agenticBasicTimelinePoint `json:"timeline"`
}

type agenticBasicTimelinePoint struct {
	Bucket   string `json:"bucket"`
	Allow    int64  `json:"allow"`
	Deny     int64  `json:"deny"`
	Approval int64  `json:"approval"`
	Mask     int64  `json:"mask"`
}

// getStats aggregates allow/deny/approval/mask counts and a coarse hourly
// timeline over the [since, until] window from the decision audit store. Counts
// are computed from a bounded scan of the audit rows (no extra SQL surface), so
// this stays consistent with the existing OSS handlers and small.
func (h *AgenticSecurityHandler) getStats(ctx *fasthttp.RequestCtx) {
	var since, until *time.Time
	if v := strings.TrimSpace(string(ctx.QueryArgs().Peek("since"))); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			since = &parsed
		}
	}
	if v := strings.TrimSpace(string(ctx.QueryArgs().Peek("until"))); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			until = &parsed
		}
	}
	// Bounded scan: enough to cover typical dashboard windows without an
	// unbounded query. The audit reader returns rows newest-first within the
	// window, tenant/workspace scoped by the store.
	rows, err := h.store.ListAgenticDecisions(auditStoreContext(ctx), 10000, "", "", since, until)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	out := agenticBasicStats{Timeline: []agenticBasicTimelinePoint{}}
	buckets := map[string]*agenticBasicTimelinePoint{}
	order := []string{}
	classify := func(verdict string) string {
		switch strings.ToUpper(strings.TrimSpace(verdict)) {
		case tables.AgenticVerdictAllow:
			return "allow"
		case tables.AgenticVerdictDeny:
			return "deny"
		case tables.AgenticVerdictRequireApproval:
			return "approval"
		case tables.AgenticVerdictMask:
			return "mask"
		default:
			return ""
		}
	}
	for i := range rows {
		row := &rows[i]
		out.Total++
		key := classify(row.Verdict)
		switch key {
		case "allow":
			out.Allow++
		case "deny":
			out.Deny++
		case "approval":
			out.Approval++
		case "mask":
			out.Mask++
		}
		bucketKey := row.Timestamp.UTC().Truncate(time.Hour).Format(time.RFC3339)
		point, ok := buckets[bucketKey]
		if !ok {
			point = &agenticBasicTimelinePoint{Bucket: bucketKey}
			buckets[bucketKey] = point
			order = append(order, bucketKey)
		}
		switch key {
		case "allow":
			point.Allow++
		case "deny":
			point.Deny++
		case "approval":
			point.Approval++
		case "mask":
			point.Mask++
		}
	}
	sort.Strings(order)
	for _, k := range order {
		out.Timeline = append(out.Timeline, *buckets[k])
	}
	SendJSON(ctx, out)
}

// ----------------------------------------------------------------------------
// Curated catalogs (in-memory, read-only)
// ----------------------------------------------------------------------------

func (h *AgenticSecurityHandler) listPermissionTemplates(ctx *fasthttp.RequestCtx) {
	SendJSON(ctx, map[string]any{
		"templates":  agentic.PermissionTemplatesCatalog,
		"categories": agentic.PermissionTemplateCategories(),
	})
}

func (h *AgenticSecurityHandler) getPermissionTemplate(ctx *fasthttp.RequestCtx) {
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	t := agentic.FindPermissionTemplate(id)
	if t == nil {
		SendError(ctx, fasthttp.StatusNotFound, "permission template not found")
		return
	}
	SendJSON(ctx, t)
}

func (h *AgenticSecurityHandler) listToolTemplates(ctx *fasthttp.RequestCtx) {
	SendJSON(ctx, map[string]any{
		"templates":  agentic.ToolTemplatesCatalog,
		"categories": agentic.ToolTemplateCategories(),
	})
}

func (h *AgenticSecurityHandler) getToolTemplate(ctx *fasthttp.RequestCtx) {
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	t := agentic.FindToolTemplate(id)
	if t == nil {
		SendError(ctx, fasthttp.StatusNotFound, "tool template not found")
		return
	}
	SendJSON(ctx, t)
}

// ----------------------------------------------------------------------------
// Runtime reload helpers (fold the prewarm loading logic inline so the OSS
// build needs no separate prewarm file)
// ----------------------------------------------------------------------------

// reloadRuntimePolicies recompiles every published policy into the runtime and
// refreshes the in-memory target resolver, so an edit takes effect on the next
// decision without a DB roundtrip on the hot path.
func (h *AgenticSecurityHandler) reloadRuntimePolicies(ctx *fasthttp.RequestCtx) {
	if h.runtime == nil {
		return
	}
	rows, err := h.store.ListAgenticPolicies(auditStoreContext(ctx))
	if err != nil || len(rows) == 0 {
		return
	}
	set := agentic.PolicySet{}
	var regoSnippets []string
	for i := range rows {
		row := &rows[i]
		if !row.Enabled || row.Status != tables.AgenticPolicyStatusPublished {
			continue
		}
		c, ok := compilePolicyDefinitionToCompiled(row.Definition)
		if !ok {
			continue
		}
		c.ID = row.ID
		c.Tenant = row.TenantID
		c.Version = row.PolicyVersion
		c.Enabled = row.Enabled
		set.Policies = append(set.Policies, c)
		if row.PolicyVersion > set.Version {
			set.Version = row.PolicyVersion
		}
		if rg := strings.TrimSpace(row.GeneratedRego); rg != "" {
			regoSnippets = append(regoSnippets, rg)
		} else {
			regoSnippets = append(regoSnippets, c.CompileRego())
		}
	}
	if len(regoSnippets) > 0 {
		set.Rego = agentic.CompileRegoModules(regoSnippets)
	}
	h.runtime.LoadPolicySet(rows[0].TenantID, set)

	if resolver := h.runtime.PolicyTargetResolver(); resolver != nil {
		for i := range rows {
			row := &rows[i]
			if !row.Enabled || row.Status != tables.AgenticPolicyStatusPublished {
				resolver.DeletePolicy(row.ID)
				continue
			}
			resolver.UpsertPolicy(
				row.ID,
				row.AppliesToAllKeys,
				row.TargetVirtualKeyIDs,
				row.TargetTeamIDs,
				row.TargetMemberIDs,
			)
		}
	}
}

// reloadRuntimeTiering reloads the tool tier map into the runtime and drops the
// active tenant's decision-cache entries (a tier edit can change verdicts for
// already-cached (tool,args) pairs; other tenants self-heal within the TTL).
func (h *AgenticSecurityHandler) reloadRuntimeTiering(ctx *fasthttp.RequestCtx) {
	if h.runtime == nil {
		return
	}
	rows, err := h.store.ListAgenticToolTiering(auditStoreContext(ctx))
	if err != nil {
		return
	}
	tiers := make(map[string]agentic.ToolTier, len(rows))
	for _, r := range rows {
		tiers[r.ToolName] = agentic.ToolTier{
			Sensitivity:      r.Sensitivity,
			FailPosture:      r.FailPosture,
			RevocationPath:   r.RevocationPath,
			Obligations:      r.Obligations,
			Enforce:          r.Enforce,
			RecoveryCost:     r.RecoveryCost,
			ActionClass:      r.ActionClass,
			ArgsSchema:       r.ArgsSchema,
			IntegrityPosture: agentic.NormalizePosture(r.IntegrityPosture),
		}
	}
	h.runtime.LoadToolTiering(tiers)
	if t := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Active-Tenant-Id"))); t != "" {
		h.runtime.InvalidateTenant(t)
	}
}

// ----------------------------------------------------------------------------
// Policy compilation helpers (visual definition → CompiledPolicy / Rego)
// ----------------------------------------------------------------------------

// CompileAgenticPolicyRow turns a persisted policy row into a runtime
// CompiledPolicy plus the Rego source the OPA evaluator should use. Exported so
// the server-side pre-warmer can pre-compile every tenant's published bundles
// before the listener accepts traffic. Returns ok=false if the row's definition
// cannot be compiled.
func CompileAgenticPolicyRow(row *tables.TableAgenticPolicy) (agentic.CompiledPolicy, string, bool) {
	if row == nil {
		return agentic.CompiledPolicy{}, "", false
	}
	c, ok := compilePolicyDefinitionToCompiled(row.Definition)
	if !ok {
		return agentic.CompiledPolicy{}, "", false
	}
	c.ID = row.ID
	rego := strings.TrimSpace(row.GeneratedRego)
	if rego == "" {
		rego = c.CompileRego()
	}
	return c, rego, true
}

func compilePolicyDefinitionToCompiled(def map[string]any) (agentic.CompiledPolicy, bool) {
	c := agentic.CompiledPolicy{
		Verdict: agentic.VerdictDeny,
		Enabled: true,
	}
	if def == nil {
		return c, false
	}
	if subj, ok := def["subject"].(map[string]any); ok {
		c.Subject.AnyRole = asStringSlice(subj["any_role"])
		c.Subject.AnyAgent = asStringSlice(subj["any_agent"])
		c.Subject.AnySubject = asStringSlice(subj["any_subject"])
	}
	if tool, ok := def["tool"].(map[string]any); ok {
		c.Tool.AnyTool = asStringSlice(tool["any_tool"])
		c.Tool.PrefixTool = asStringSlice(tool["prefix_tool"])
	}
	if conds, ok := def["conditions"].([]any); ok {
		for _, raw := range conds {
			m, _ := raw.(map[string]any)
			if m == nil {
				continue
			}
			c.Conditions = append(c.Conditions, agentic.Condition{
				Field:    asString(m["field"]),
				Operator: asString(m["operator"]),
				Value:    asString(m["value"]),
				Values:   asStringSlice(m["values"]),
			})
		}
	}
	if v, ok := def["verdict"].(string); ok && v != "" {
		c.Verdict = agentic.Verdict(strings.ToUpper(strings.TrimSpace(v)))
	}
	c.Approvers = asStringSlice(def["approvers"])
	c.Obligations = asStringSlice(def["obligations"])
	c.Reason = asString(def["reason"])
	return c, true
}

func compilePolicyDefinitionToRego(def map[string]any) (string, bool) {
	c, ok := compilePolicyDefinitionToCompiled(def)
	if !ok {
		return "", false
	}
	return c.CompileRego(), true
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asStringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, i := range x {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	}
	return nil
}
