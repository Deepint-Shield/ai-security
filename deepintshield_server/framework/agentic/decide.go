package agentic

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// timeNow is a package-level injection point so tests can freeze time.
var timeNow = time.Now

// Runtime is the top-level entry point a transport calls. It bundles the L1
// decision cache, the active policy set (loaded from configstore and refreshed
// on bundle bump), and the async audit pipeline.
//
// Runtime is safe for concurrent use. Hot-path callers should reuse a single
// instance per process - the in-process cache is what makes the p99 budget
// achievable (a cache hit is O(1) with no lock on r.mu and no network).
type Runtime struct {
	mu              sync.RWMutex
	policySets      map[string]PolicySet       // keyed by tenant_id
	toolTiering     map[string]ToolTier        // tool name → tier
	enforcementMode map[string]EnforcementMode // tenant_workspace → mode
	// timeSensitive[tenant] is true when that tenant's active policy set has any
	// rule conditioned on time_of_day. Only those tenants fold the hour bucket
	// into the decision cache key. A sync.Map so the cache-hit fast path reads it
	// without taking r.mu.
	timeSensitive sync.Map // tenant_id → bool
	cache         *DecisionCache
	auditSink     AuditSink
	// auditMode governs audit-sink backpressure behaviour. Empty/best_effort
	// keeps the original drop-on-full; fail_closed makes an unguaranteed audit
	// override a non-deny verdict to DENY.
	auditMode     AuditMode
	revocationSLA time.Duration
	// vkResolver gives the PDP O(1) access to the identity-relevant slice of a
	// platform VK (bound IdP, team/customer membership, agent attributes).
	vkResolver *VKResolver
	// policyTargets answers "which policy IDs apply to this caller?" in O(1)
	// using the caller's VK + team + member identifiers from vkResolver.
	policyTargets *PolicyTargetResolver
}

// ToolTier mirrors the persisted tool tiering row but in a hot-path friendly
// form (no JSON / no decoding).
type ToolTier struct {
	Sensitivity    string
	FailPosture    string
	RevocationPath string
	Obligations    []string
	Enforce        bool
	RecoveryCost   string
	// Declared contract carried from the tiering row. ActionClass + ArgsSchema +
	// IntegrityPosture are kept for the supply-chain fingerprint comparison and
	// for policy operands; the OSS PDP never runs the integrity engine.
	ActionClass      string
	ArgsSchema       map[string]any
	IntegrityPosture IntegrityPosture
	// PinnedFingerprint is the ASI04 supply-chain anchor: the contract
	// fingerprint this tool was pinned to. When non-empty and the call's
	// recomputed contract fingerprint differs, Decide sets Context.FingerprintDrift.
	PinnedFingerprint string
}

// AuditSink is implemented by the async audit pipeline (see audit.go).
type AuditSink interface {
	Enqueue(record AuditRecord)
}

// AuditRecord is the off-hot-path record the runtime emits per decision.
// The persistence layer computes prev_hash/hash and writes append-only.
type AuditRecord struct {
	DecisionID    string
	Tenant        string
	Workspace     string
	VirtualKey    string
	SessionID     string
	Principal     string
	ActorChain    []string
	IdentityType  string
	ProviderID    string
	Tool          string
	ArgsDigest    string
	ScopeHash     string
	Verdict       Verdict
	Reason        string
	Obligations   []string
	PolicyID      string
	PolicyVersion int
	RecoveryCost  string
	RAGProvenance string
	CostUsed      float64
	LatencyUS     int
	CacheHit      bool
	Mode          EnforcementMode
	CrossTenant   bool
	Timestamp     time.Time
}

// NewRuntime builds a Runtime backed by the configured decision cache and audit
// sink. This is the entire OSS PDP wiring: decision logic + decision cache +
// audit sink. No broker, no observability/Langfuse/OTLP, no agentic cache, no
// grants, no relationships.
func NewRuntime(cacheSize int, sink AuditSink, revocationSLA time.Duration) *Runtime {
	if revocationSLA <= 0 {
		revocationSLA = 30 * time.Second
	}
	return &Runtime{
		policySets:      make(map[string]PolicySet),
		toolTiering:     make(map[string]ToolTier),
		enforcementMode: make(map[string]EnforcementMode),
		cache:           NewDecisionCache(cacheSize),
		auditSink:       sink,
		revocationSLA:   revocationSLA,
	}
}

// SetAuditMode sets the audit backpressure mode. best_effort (default) and
// durable never affect a verdict; fail_closed denies a non-deny verdict whose
// audit record could not be guaranteed.
func (r *Runtime) SetAuditMode(mode AuditMode) {
	if r != nil {
		r.auditMode = mode
	}
}

// SetVKResolver attaches the unified-VK metadata resolver. The PDP consults it
// on every Decide() call to fill agent scope (tenant/workspace/provider + agent
// attributes) from the platform VK row. Lookup is O(1) sync.Map.
func (r *Runtime) SetVKResolver(resolver *VKResolver) {
	if r != nil {
		r.vkResolver = resolver
	}
}

// VKResolver exposes the resolver for handlers that need to upsert scopes after
// a VK edit (so the runtime view stays fresh without a pre-warm replay).
func (r *Runtime) VKResolver() *VKResolver {
	if r == nil {
		return nil
	}
	return r.vkResolver
}

// SetPolicyTargetResolver wires the in-memory target index. Handlers call
// UpsertPolicy / DeletePolicy on this resolver after every policy CRUD so the
// PDP filter sees the new scope without a DB roundtrip.
func (r *Runtime) SetPolicyTargetResolver(resolver *PolicyTargetResolver) {
	if r != nil {
		r.policyTargets = resolver
	}
}

// PolicyTargetResolver exposes the resolver for handler hooks.
func (r *Runtime) PolicyTargetResolver() *PolicyTargetResolver {
	if r == nil {
		return nil
	}
	return r.policyTargets
}

// LoadPolicySet swaps in a freshly compiled bundle for a tenant. Because
// policy_version is part of every cache key, callers do NOT need to flush the
// cache - old entries become structurally unreachable.
func (r *Runtime) LoadPolicySet(tenant string, set PolicySet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policySets[tenant] = set
	// Record whether any rule in the bundle depends on the wall clock, so the hot
	// path knows to fold the hour bucket into the cache key for this tenant.
	uses := false
	for _, p := range set.Policies {
		for _, c := range p.Conditions {
			if strings.EqualFold(strings.TrimSpace(c.Field), "time_of_day") {
				uses = true
			}
		}
	}
	r.timeSensitive.Store(tenant, uses)
}

// isTimeSensitive reports whether the tenant's policy set uses time_of_day.
// Lock-free (sync.Map.Load) so it is safe to call on the cache-hit fast path.
func (r *Runtime) isTimeSensitive(tenant string) bool {
	if r == nil {
		return false
	}
	if v, ok := r.timeSensitive.Load(tenant); ok {
		b, _ := v.(bool)
		return b
	}
	return false
}

// LoadToolTiering replaces the runtime tool tier map.
func (r *Runtime) LoadToolTiering(tiers map[string]ToolTier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.toolTiering = make(map[string]ToolTier, len(tiers))
	for k, v := range tiers {
		r.toolTiering[k] = v
	}
}

// SetEnforcementMode sets the rollout state for a tenant/workspace.
func (r *Runtime) SetEnforcementMode(tenant, workspace string, mode EnforcementMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enforcementMode[tenant+"|"+workspace] = mode
}

// GetEnforcementMode returns the rollout state or Shadow as the default.
func (r *Runtime) GetEnforcementMode(tenant, workspace string) EnforcementMode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mode, ok := r.enforcementMode[tenant+"|"+workspace]; ok {
		return mode
	}
	return EnforcementShadow
}

// CacheStats exposes the L1 hit/miss counters.
func (r *Runtime) CacheStats() CacheStats {
	return r.cache.Stats()
}

// HealthSnapshot returns a flat operational snapshot of the runtime.
type HealthSnapshot struct {
	Cache               CacheStats        `json:"cache"`
	AuditDrops          uint64            `json:"audit_drops"`
	LoadedPolicySets    int               `json:"loaded_policy_sets"`
	PolicyVersions      map[string]int    `json:"policy_versions"`
	EnforcementByTenant map[string]string `json:"enforcement_by_tenant"`
	ToolTiering         int               `json:"tool_tiering_entries"`
	RevocationSLA       string            `json:"revocation_sla"`
	VKResolverSize      int               `json:"vk_resolver_size"`
}

// Health returns a snapshot for the /agentic-security/health endpoint.
func (r *Runtime) Health() HealthSnapshot {
	if r == nil {
		return HealthSnapshot{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap := HealthSnapshot{
		Cache:               r.cache.Stats(),
		LoadedPolicySets:    len(r.policySets),
		PolicyVersions:      make(map[string]int, len(r.policySets)),
		EnforcementByTenant: make(map[string]string, len(r.enforcementMode)),
		ToolTiering:         len(r.toolTiering),
		RevocationSLA:       r.revocationSLA.String(),
	}
	for tenant, set := range r.policySets {
		snap.PolicyVersions[tenant] = set.Version
	}
	for k, v := range r.enforcementMode {
		snap.EnforcementByTenant[k] = string(v)
	}
	if d, ok := r.auditSink.(interface{ Drops() uint64 }); ok {
		snap.AuditDrops = d.Drops()
	}
	if r.vkResolver != nil {
		snap.VKResolverSize = r.vkResolver.Size()
	}
	return snap
}

// InvalidateTenant clears cached entries for a tenant - wired to VK / policy
// publishes.
func (r *Runtime) InvalidateTenant(tenant string) {
	r.cache.InvalidateTenant(tenant)
}

// Decide is the PDP entry point. The hot-path algorithm:
//
//  1. cache lookup keyed on semantic inputs (O(1), no lock, no network),
//  2. on miss: identity enrichment + cheapest-deny-first short-circuit,
//  3. policy evaluation (compiled AST + Rego, in-process),
//  4. combine policy verdict with the autonomy budget,
//  5. cache under the revocation SLA,
//  6. enqueue audit asynchronously.
func (r *Runtime) Decide(ctx context.Context, dc DelegationContext) Decision {
	start := timeNow()

	// Hot-path enrichment: if the caller passed a VK id/bearer and we have a
	// resolver, fill in the agent scope (tenant/workspace/provider + agent
	// attributes) directly from the platform VK row's cached scope. O(1).
	if r.vkResolver != nil && dc.VirtualKey != "" {
		scope, ok := r.vkResolver.Lookup(dc.VirtualKey)
		if !ok {
			scope, ok = r.vkResolver.LookupByValue(dc.VirtualKey)
		}
		if ok && scope != nil && scope.AgentConfigured {
			if dc.Tenant == "" {
				dc.Tenant = scope.Tenant
			}
			if dc.Workspace == "" {
				dc.Workspace = scope.Workspace
			}
			if dc.ProviderID == "" && scope.IdentityProviderID != "" {
				dc.ProviderID = scope.IdentityProviderID
			}
			// The SDK's convenience decide(tool=...) shortcut leaves principal +
			// actor_chain empty; derive a deterministic role-prefixed handle from
			// the VK id so subject matchers authored against {any_role: ["agent"]}
			// match the SDK path.
			handle := dc.VirtualKey
			if len(handle) > 8 {
				handle = handle[len(handle)-8:]
			}
			if dc.Principal == "" {
				dc.Principal = "agent:" + handle
			}
			if len(dc.ActorChain) == 0 {
				dc.ActorChain = []string{dc.Principal}
			}
			if dc.IdentityType == "" {
				dc.IdentityType = "application"
			}
			// Agent attribute taxonomy → ABAC inputs. Only fill when the caller
			// didn't already supply them (explicit SDK input wins).
			if dc.Context.AgentRiskLevel == "" && scope.AgentRiskLevel != "" {
				dc.Context.AgentRiskLevel = scope.AgentRiskLevel
			}
			if len(dc.Context.AgentCapabilities) == 0 && len(scope.AgentCapabilities) > 0 {
				dc.Context.AgentCapabilities = scope.AgentCapabilities
			}
			if dc.Context.Namespace == "" && scope.AgentNamespace != "" {
				dc.Context.Namespace = scope.AgentNamespace
			}
		}
	}

	// time_of_day ABAC input - the wall-clock hour. For time-sensitive tenants
	// only (lock-free sync.Map read), fold the hour into the cache bucket so a
	// clock-dependent verdict isn't served stale across the hour boundary.
	dc.Context.HourOfDay = timeNow().Hour()
	if dc.CacheBucket == "" && r.isTimeSensitive(dc.Tenant) {
		dc.CacheBucket = "h" + strconv.Itoa(dc.Context.HourOfDay)
	}
	// delegation_depth = how deep the delegation chain is. Server-derived from
	// the actor chain (already in the cache key).
	if dc.Context.DelegationDepth == 0 {
		dc.Context.DelegationDepth = len(dc.ActorChain)
	}

	key := dc.CacheKey()
	if cached, ok := r.cache.Get(key); ok {
		cached.LatencyUS = int(timeNow().Sub(start).Microseconds())
		// Do NOT re-emit to the audit sink on a cache hit. The first miss already
		// wrote an immutable record. Cache reuse is tracked via CacheStats().Hits.
		return cached
	}

	r.mu.RLock()
	set := r.policySets[dc.Tenant]
	tier := r.toolTiering[dc.Tool]
	mode := r.enforcementMode[dc.Tenant+"|"+dc.Workspace]
	r.mu.RUnlock()

	// data_class ABAC operand = the called tool's sensitivity, taken from the
	// tier we just read. Set only when the caller didn't supply it. Miss-path
	// only, so the cache-hit fast path pays nothing.
	if dc.Context.DataClass == "" && tier.Sensitivity != "" {
		dc.Context.DataClass = tier.Sensitivity
	}
	// ASI04 supply-chain drift: if the tool is pinned, recompute its CONTRACT
	// fingerprint from the current tier and flag drift when it differs from the
	// pinned value.
	if tier.PinnedFingerprint != "" {
		currentFP := ToolFingerprint(dc.Tool, tier.ActionClass, tier.ArgsSchema, "")
		if tier.PinnedFingerprint != currentFP {
			dc.Context.FingerprintDrift = true
		}
	}

	if mode == "" {
		mode = EnforcementShadow
	}

	// 1. Cheapest-deny-first: tool ∈ virtual_key.allowed_tools.
	if len(dc.AllowedTools) > 0 && !containsCI(dc.AllowedTools, dc.Tool) {
		dec := Decision{
			Verdict:    VerdictDeny,
			Reason:     "tool not in virtual key allow-list",
			DecisionID: "d-" + shortID(),
			Mode:       mode,
			Timestamp:  start,
		}
		dec.LatencyUS = int(timeNow().Sub(start).Microseconds())
		return r.finalize(dc, dec, key, tier.RecoveryCost)
	}

	// 2. Cross-tenant guard.
	if dc.CrossTenant {
		dec := Decision{
			Verdict:    VerdictDeny,
			Reason:     "cross-tenant delegation not allowed",
			DecisionID: "d-" + shortID(),
			Mode:       mode,
			Timestamp:  start,
		}
		dec.LatencyUS = int(timeNow().Sub(start).Microseconds())
		return r.finalize(dc, dec, key, tier.RecoveryCost)
	}

	// 3. Policy evaluation (compiled AST + Rego, in-process).
	//    Step 3a: filter the candidate set by the caller's identity through the
	//    PolicyTargetResolver, so OPA only evaluates rules that could match.
	policySetForCaller := set
	if r.policyTargets != nil {
		teamID, memberID := "", ""
		if r.vkResolver != nil && dc.VirtualKey != "" {
			scope, ok := r.vkResolver.Lookup(dc.VirtualKey)
			if !ok {
				scope, _ = r.vkResolver.LookupByValue(dc.VirtualKey)
			}
			if scope != nil {
				teamID = scope.TeamID
				memberID = scope.CustomerID
			}
		}
		applicable := r.policyTargets.Resolve(dc.VirtualKey, teamID, memberID)
		policySetForCaller = filterPolicySetByIDs(set, applicable)
	}

	policyDec := policySetForCaller.Evaluate(dc)
	policyDec.DecisionID = "d-" + shortID()
	policyDec.Mode = mode
	policyDec.Timestamp = start

	// 4. Tool-tier obligations are unioned with policy obligations.
	if len(tier.Obligations) > 0 {
		policyDec.Obligations = uniqueAppend(policyDec.Obligations, tier.Obligations)
	}

	// 5. Shadow mode never blocks - annotate would_block so the divergence
	//    report can compute false-positive rates without affecting traffic.
	if mode == EnforcementShadow && policyDec.Verdict != VerdictAllow {
		policyDec.WouldBlock = true
		policyDec.Verdict = VerdictAllow
	}

	// 6. Fail-closed for high-sensitivity tools on policy load failure.
	if len(set.Policies) == 0 && tier.Sensitivity == "high" {
		policyDec.Verdict = VerdictDeny
		policyDec.Reason = "fail-closed: no policy set for high-sensitivity tool"
	}

	policyDec.LatencyUS = int(timeNow().Sub(start).Microseconds())
	return r.finalize(dc, policyDec, key, tier.RecoveryCost)
}

// maybeAudit enqueues the record off the hot path. Fire-and-forget - the
// decision returns before the write completes.
func (r *Runtime) maybeAudit(dc DelegationContext, dec Decision, tierRecoveryCost string) bool {
	if r.auditSink == nil {
		return true
	}
	rec := AuditRecord{
		DecisionID:    dec.DecisionID,
		Tenant:        dc.Tenant,
		Workspace:     dc.Workspace,
		VirtualKey:    dc.VirtualKey,
		SessionID:     dc.SessionID,
		Principal:     dc.Principal,
		ActorChain:    dc.ActorChain,
		IdentityType:  dc.IdentityType,
		ProviderID:    dc.ProviderID,
		Tool:          dc.Tool,
		ArgsDigest:    dc.ArgsDigest,
		Verdict:       dec.Verdict,
		Reason:        dec.Reason,
		Obligations:   dec.Obligations,
		PolicyID:      dec.PolicyID,
		PolicyVersion: dc.PolicyVersion,
		RecoveryCost:  dc.Context.RecoveryCost,
		RAGProvenance: dc.Context.RAGProvenance,
		CostUsed:      dc.Context.CostUsed,
		LatencyUS:     dec.LatencyUS,
		CacheHit:      dec.CacheHit,
		Mode:          dec.Mode,
		CrossTenant:   dc.CrossTenant,
		Timestamp:     dec.Timestamp,
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = timeNow()
	}
	// When the caller didn't supply a recovery cost, fall back to the tool tier's
	// value so the audit row carries the effective recovery cost.
	if rec.RecoveryCost == "" {
		rec.RecoveryCost = tierRecoveryCost
	}
	// Prefer the richer EnqueueChecked (durable / fail_closed pipelines) so we
	// learn whether the record was guaranteed; fall back to fire-and-forget.
	if checked, ok := r.auditSink.(interface{ EnqueueChecked(AuditRecord) bool }); ok {
		return checked.EnqueueChecked(rec)
	}
	r.auditSink.Enqueue(rec)
	return true
}

// finalize runs the audit fan-out for a decision, then caches and returns it -
// unless fail_closed mode is active and the audit could not be guaranteed for a
// non-deny verdict, in which case the verdict is overridden to DENY and the
// decision is NOT cached.
func (r *Runtime) finalize(dc DelegationContext, dec Decision, key string, tierRecoveryCost string) Decision {
	accepted := r.maybeAudit(dc, dec, tierRecoveryCost)
	if r.auditMode == AuditFailClosed && !accepted && dec.Verdict != VerdictDeny {
		dec.Verdict = VerdictDeny
		dec.Reason = "audit unavailable - denied (fail-closed audit mode)"
		dec.Obligations = nil
		return dec
	}
	r.cache.Put(key, dec, r.revocationSLA)
	return dec
}

// Timestamp returns a non-nil time (helper for callers that don't want to
// import time.Time directly when building a DelegationContext).
func (dc DelegationContext) Timestamp() time.Time { return timeNow() }

func uniqueAppend(dst, src []string) []string {
	seen := make(map[string]struct{}, len(dst)+len(src))
	out := make([]string, 0, len(dst)+len(src))
	for _, v := range append(append([]string(nil), dst...), src...) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func shortID() string {
	// 8-byte random hex from the local PRNG seeded at package init in audit.go.
	return prng(8)
}
