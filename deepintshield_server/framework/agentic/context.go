// Package agentic implements the open-source agentic Policy Decision Point
// (PDP): the in-process decision hot path, an L1 decision cache keyed on the
// semantic inputs of a call, and an async audit pipeline.
//
// Design goals:
//   - in-process decision, no network hop in Decide ⇒ sub-millisecond p99,
//   - cache decisions on their semantic inputs (W-TinyLFU L1) ⇒ O(1) cache hit,
//   - cheapest-deny-first short-circuit (allow-list / cross-tenant before policy),
//   - async audit (off the hot path),
//   - zero-data-retention by construction: arguments are digested, not stored.
//
// The package is deliberately framework-only (no fasthttp / handler types)
// so it can be reused by other transports (gRPC, SDKs).
package agentic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Verdict is the closed set of outcomes the PDP returns.
type Verdict string

const (
	VerdictAllow           Verdict = "ALLOW"
	VerdictDeny            Verdict = "DENY"
	VerdictRequireApproval Verdict = "REQUIRE_APPROVAL"
	VerdictMask            Verdict = "MASK"
)

// EnforcementMode is the per-tenant rollout state.
type EnforcementMode string

const (
	EnforcementShadow  EnforcementMode = "shadow"
	EnforcementCanary  EnforcementMode = "canary"
	EnforcementEnforce EnforcementMode = "enforce"
)

// DelegationContext is the normalised input the PDP evaluates. It is
// provider-agnostic so the PDP never sees a wire token.
type DelegationContext struct {
	Principal    string   `json:"principal"`
	ActorChain   []string `json:"actor_chain"`
	IdentityType string   `json:"identity_type"` // user | application
	Scope        []string `json:"scope"`
	Tenant       string   `json:"tenant"`
	Workspace    string   `json:"workspace"`
	VirtualKey   string   `json:"virtual_key"`
	// SessionID - optional client-supplied run/session id. Never part of the
	// cache key.
	SessionID     string   `json:"session_id,omitempty"`
	AllowedTools  []string `json:"allowed_tools"`
	CrossTenant   bool     `json:"cross_tenant"`
	Tool          string   `json:"tool"`
	ArgsDigest    string   `json:"args_digest"`
	ProviderID    string   `json:"provider_id"`
	PolicyVersion int      `json:"policy_version"`

	Context Context `json:"context"`

	// CacheBucket is an internal cache-correctness discriminator (never
	// serialized to the PDP input). Decide() sets it to a time bucket (e.g.
	// "h14") ONLY when the active policy set references time_of_day, so a
	// verdict that depends on the wall clock is not served stale across an
	// hour boundary. Empty for time-insensitive tenants.
	CacheBucket string `json:"-"`
}

// Context carries the runtime ABAC inputs.
type Context struct {
	RAGProvenance string  `json:"rag_provenance"`
	CostUsed      float64 `json:"cost_used"`
	RecoveryCost  string  `json:"recovery_cost"` // low | medium | high
	// AgentRiskLevel + AgentCapabilities are the calling agent's attribute
	// taxonomy, filled at Decide() time from the resolved VKScope. Policies
	// match on `agent_risk_level` (ordinal) and `agent_capability` (in/not_in).
	AgentRiskLevel    string   `json:"agent_risk_level,omitempty"`
	AgentCapabilities []string `json:"agent_capabilities,omitempty"`
	// Fine-grained ABAC operands. DataClass is the sensitivity of the tool being
	// called (from its tiering row); Namespace is the agent's logical namespace
	// (from its VK); HourOfDay is the server-clock hour [0,23] for time windows.
	DataClass string `json:"data_class,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	HourOfDay int    `json:"time_of_day"`
	// FingerprintDrift is the ASI04 (supply-chain) signal: true when the tool has
	// a pinned behavior fingerprint and the call's observed contract differs from
	// it. Set at Decide() from the tool's tiering row. Policies match
	// `fingerprint_drift`.
	FingerprintDrift bool `json:"fingerprint_drift,omitempty"`
	// Integrity is the Tool Integrity Engine signal. In the OSS PDP nothing
	// populates it, so it is always the zero value; the integrity policy operands
	// (effective_action_class / behavior_divergence / integrity_risk) therefore
	// evaluate against the default un-diverged signal. The TYPE is kept so policy
	// authoring and audit columns stay stable.
	Integrity IntegritySignal `json:"integrity,omitempty"`
	// ToolFingerprint is the tool's behavior identity, computed at interception.
	// Folded into CacheKey so a changed implementation gets a distinct key.
	ToolFingerprint string `json:"tool_fingerprint,omitempty"`
	// DelegationDepth (server-computed from the actor chain) caps runaway
	// multi-agent delegation chains. Policies match `delegation_depth`.
	DelegationDepth int `json:"delegation_depth,omitempty"`
}

// Decision is the PDP output. It carries enough metadata for both
// enforcement (verdict, obligations, approvers) and audit (policy_id,
// decision_id, reason).
type Decision struct {
	Verdict     Verdict         `json:"verdict"`
	Reason      string          `json:"reason"`
	Approvers   []string        `json:"approvers,omitempty"`
	Obligations []string        `json:"obligations,omitempty"`
	PolicyID    string          `json:"policy_id,omitempty"`
	DecisionID  string          `json:"decision_id"`
	Mode        EnforcementMode `json:"mode"`
	CacheHit    bool            `json:"cache_hit"`
	LatencyUS   int             `json:"latency_us"`
	WouldBlock  bool            `json:"would_block,omitempty"` // shadow-mode signal
	Timestamp   time.Time       `json:"ts"`
}

// CacheKey derives a deterministic key from the semantic inputs of the
// decision:
//
//	hash(agent, tool, shape(args), scope_hash, policy_version, tenant, virtual_key)
//
// scope_hash is the sha256 of the sorted, unique scope list - this is what
// makes scope attenuation an instant invalidation.
func (d DelegationContext) CacheKey() string {
	scopes := append([]string(nil), d.Scope...)
	sort.Strings(scopes)
	scopeHash := sha256.Sum256([]byte(strings.Join(scopes, "|")))

	parts := []string{
		strings.Join(d.ActorChain, ">"),
		d.Tool,
		d.ArgsDigest,
		hex.EncodeToString(scopeHash[:]),
		toolPolicyVersion(d.PolicyVersion),
		d.Tenant,
		d.VirtualKey,
		IntegrityRulesetVersion,
		d.CacheBucket,
		// Code-bound caching: the tool's source fingerprint. Empty for callers
		// that don't supply it (today's traffic ⇒ unchanged key).
		d.Context.ToolFingerprint,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

func toolPolicyVersion(v int) string {
	if v <= 0 {
		return "0"
	}
	// allocation-free itoa for the common version
	return string(rune('0'+v%10)) + string(rune('a'+byte(v/10)%26))
}

// ComputeArgsDigest reduces structured arguments to a canonical sha256
// digest - used by every caller that builds a DelegationContext.
func ComputeArgsDigest(args any) string {
	if args == nil {
		return "sha256:" + strings.Repeat("0", 64)
	}
	data, err := json.Marshal(args)
	if err != nil {
		return "sha256:" + strings.Repeat("0", 64)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// AutonomyBudget caps how much authority a single call can spend. A "high"
// recovery_cost downgrades ALLOW → REQUIRE_APPROVAL.
func AutonomyBudget(recoveryCost string) Verdict {
	switch strings.ToLower(strings.TrimSpace(recoveryCost)) {
	case "high":
		return VerdictRequireApproval
	default:
		return VerdictAllow
	}
}
