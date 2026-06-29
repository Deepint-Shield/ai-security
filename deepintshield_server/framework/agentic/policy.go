package agentic

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// regoCtx returns a context for synchronous Rego evaluation.
func regoCtx() context.Context { return context.Background() }

func stringsEqualFoldLocal(a, b string) bool { return strings.EqualFold(a, b) }

// CompiledPolicy is the in-memory representation of a single rule the PDP
// evaluates against the DelegationContext. The visual rule builder UI
// compiles to this structure; the same structure also drives the
// generated Rego that ships with each policy version.
//
// We deliberately implement a typed AST rather than an interpreter loop -
// every condition is a closed-set discriminated union so policy
// evaluation is allocation-free on the hot path.
type CompiledPolicy struct {
	ID          string
	Tenant      string
	Workspace   string
	Version     int
	Enabled     bool
	Priority    int // lower = evaluated first
	Subject     SubjectMatcher
	Tool        ToolMatcher
	Conditions  []Condition
	Verdict     Verdict
	Approvers   []string
	Obligations []string
	Reason      string
}

// SubjectMatcher narrows the actor_chain / principal that triggers a rule.
type SubjectMatcher struct {
	AnyRole    []string // any of these roles in the actor_chain
	AnyAgent   []string // any of these agent ids
	AnySubject []string // principal allow-list
}

// ToolMatcher restricts a rule by tool name (exact or prefix).
type ToolMatcher struct {
	AnyTool    []string
	PrefixTool []string
}

// Condition is a single ABAC condition. The discriminated union keeps
// evaluation fast and the rule body human-readable.
type Condition struct {
	Field    string // rag_provenance | recovery_cost | cross_tenant | scope | cost_used
	Operator string // eq | ne | gt | lt | in | not_in
	Value    string
	Values   []string
}

// MatchesContext returns true iff the policy applies to the call.
func (p CompiledPolicy) MatchesContext(dc DelegationContext) bool {
	if !p.Enabled {
		return false
	}
	if !p.Subject.matches(dc) {
		return false
	}
	if !p.Tool.matches(dc.Tool) {
		return false
	}
	for _, c := range p.Conditions {
		if !c.matches(dc) {
			return false
		}
	}
	return true
}

func (s SubjectMatcher) matches(dc DelegationContext) bool {
	// Empty matcher = applies to everyone.
	if len(s.AnyRole) == 0 && len(s.AnyAgent) == 0 && len(s.AnySubject) == 0 {
		return true
	}
	if len(s.AnyAgent) > 0 {
		for _, a := range dc.ActorChain {
			if containsCI(s.AnyAgent, a) {
				return true
			}
		}
	}
	if len(s.AnySubject) > 0 {
		if containsCI(s.AnySubject, dc.Principal) {
			return true
		}
	}
	if len(s.AnyRole) > 0 {
		for _, a := range dc.ActorChain {
			// A role is encoded as "agent:role" or just the role suffix.
			role := agentRole(a)
			if containsCI(s.AnyRole, role) {
				return true
			}
		}
	}
	return false
}

func (t ToolMatcher) matches(tool string) bool {
	tool = strings.TrimSpace(tool)
	if len(t.AnyTool) == 0 && len(t.PrefixTool) == 0 {
		return true
	}
	if containsCI(t.AnyTool, tool) {
		return true
	}
	for _, p := range t.PrefixTool {
		if strings.HasPrefix(strings.ToLower(tool), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func (c Condition) matches(dc DelegationContext) bool {
	field := strings.ToLower(c.Field)
	op := strings.ToLower(c.Operator)
	val := c.Value
	switch field {
	case "rag_provenance":
		return compareString(dc.Context.RAGProvenance, op, val)
	case "recovery_cost":
		return compareString(dc.Context.RecoveryCost, op, val)
	case "cross_tenant":
		want := strings.EqualFold(val, "true")
		return dc.CrossTenant == want
	case "identity_type":
		return compareString(dc.IdentityType, op, val)
	case "tool":
		return compareString(dc.Tool, op, val)
	case "scope":
		if op == "in" {
			return containsCI(dc.Scope, val)
		}
		if op == "not_in" {
			return !containsCI(dc.Scope, val)
		}
	case "tenant":
		return compareString(dc.Tenant, op, val)
	case "workspace":
		return compareString(dc.Workspace, op, val)
	case "effective_action_class":
		// The action class the call's behavior actually implied (Tool Integrity
		// Engine signal). In the OSS PDP the signal is never populated, so this
		// evaluates against the empty default.
		return compareString(dc.Context.Integrity.EffectiveClass, op, val)
	case "behavior_divergence":
		// Boolean: did the call diverge from its declared contract? Always the
		// un-diverged default in the OSS PDP.
		want := strings.EqualFold(val, "true")
		return dc.Context.Integrity.Diverged == want
	case "integrity_risk":
		// Numeric [0,1] divergence risk - supports gt/lt/gte/lte/eq. Always 0 in
		// the OSS PDP.
		return compareFloat(dc.Context.Integrity.Risk, op, val)
	case "delegation_depth":
		// Numeric (server-computed from len(actor_chain)). Cap runaway delegation:
		// "delegation_depth gt 4 → DENY".
		return compareFloat(float64(dc.Context.DelegationDepth), op, val)
	case "agent_risk_level":
		// Ordinal compare on the calling agent's risk tier (low<medium<high).
		return compareRisk(dc.Context.AgentRiskLevel, op, val)
	case "agent_capability":
		// Set membership over the agent's declared capability tags.
		if op == "not_in" {
			return !containsCI(dc.Context.AgentCapabilities, val)
		}
		return containsCI(dc.Context.AgentCapabilities, val)
	case "data_class":
		// Sensitivity class of the tool being called (from its tiering row).
		return compareString(dc.Context.DataClass, op, val)
	case "namespace":
		// The agent's logical / k8s namespace (from its VK).
		return compareString(dc.Context.Namespace, op, val)
	case "time_of_day":
		// Server-clock hour [0,23]. Numeric compare for business-hours windows.
		return compareFloat(float64(dc.Context.HourOfDay), op, val)
	case "fingerprint_drift":
		// Boolean (ASI04): did the tool's contract fingerprint drift from its
		// pinned value? Supply-chain tamper / typosquat detector.
		want := strings.EqualFold(val, "true")
		return dc.Context.FingerprintDrift == want
	}
	return false
}

// riskRank maps the ordinal risk tier to an integer so low<medium<high
// comparisons are well-defined. Unknown / empty tiers rank -1.
func riskRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "low":
		return 0
	case "medium", "med":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return -1
	}
}

// compareRisk evaluates an ordinal comparison between an agent's risk tier and
// a policy threshold. Unparseable thresholds never match (fail-safe).
func compareRisk(got, op, want string) bool {
	w := riskRank(want)
	if w < 0 {
		return false
	}
	g := riskRank(got)
	if g < 0 {
		return false
	}
	switch op {
	case "eq", "==", "":
		return g == w
	case "ne", "!=":
		return g != w
	case "gt", ">":
		return g > w
	case "gte", ">=":
		return g >= w
	case "lt", "<":
		return g < w
	case "lte", "<=":
		return g <= w
	default:
		return false
	}
}

func compareString(got, op, want string) bool {
	switch op {
	case "eq", "==":
		return strings.EqualFold(got, want)
	case "ne", "!=":
		return !strings.EqualFold(got, want)
	default:
		return strings.EqualFold(got, want)
	}
}

// compareFloat compares a numeric context value against a policy threshold.
// Unparseable thresholds never match (fail-safe).
func compareFloat(got float64, op, want string) bool {
	w, err := strconv.ParseFloat(strings.TrimSpace(want), 64)
	if err != nil {
		return false
	}
	switch op {
	case "eq", "==":
		return got == w
	case "ne", "!=":
		return got != w
	case "gt", ">":
		return got > w
	case "gte", ">=":
		return got >= w
	case "lt", "<":
		return got < w
	case "lte", "<=":
		return got <= w
	default:
		return false
	}
}

func containsCI(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func agentRole(actor string) string {
	idx := strings.Index(actor, ":")
	if idx < 0 {
		return actor
	}
	return actor[:idx]
}

// CompileRego renders a compact Rego snippet that mirrors the AST. The
// generated Rego is shown in the read-only panel beside the visual rule
// builder so power users can verify what the UI is about to publish.
//
// policy_id is embedded directly in the decision body so the audit row
// can carry it back.
func (p CompiledPolicy) CompileRego() string {
	var b strings.Builder
	b.WriteString("# auto-generated from policy ")
	b.WriteString(p.ID)
	b.WriteString("\n\n")
	b.WriteString("package deepintshield.authz\n\n")
	b.WriteString("import rego.v1\n\n")
	b.WriteString("decision := {\n")
	b.WriteString("  \"verdict\": \"")
	b.WriteString(string(p.Verdict))
	b.WriteString("\",\n")
	if p.ID != "" {
		b.WriteString("  \"policy_id\": \"")
		b.WriteString(p.ID)
		b.WriteString("\",\n")
	}
	if len(p.Approvers) > 0 {
		b.WriteString("  \"approvers\": [\"")
		b.WriteString(strings.Join(p.Approvers, "\",\""))
		b.WriteString("\"],\n")
	}
	if len(p.Obligations) > 0 {
		b.WriteString("  \"obligations\": [\"")
		b.WriteString(strings.Join(p.Obligations, "\",\""))
		b.WriteString("\"],\n")
	}
	if p.Reason != "" {
		b.WriteString("  \"reason\": \"")
		b.WriteString(p.Reason)
		b.WriteString("\",\n")
	}
	b.WriteString("} if {\n")
	if len(p.Subject.AnyRole) > 0 {
		b.WriteString("  some role in roles_of(input.actor_chain)\n")
		b.WriteString("  role in {\"")
		b.WriteString(strings.Join(p.Subject.AnyRole, "\",\""))
		b.WriteString("\"}\n")
	}
	if len(p.Tool.AnyTool) > 0 {
		b.WriteString("  input.tool in {\"")
		b.WriteString(strings.Join(p.Tool.AnyTool, "\",\""))
		b.WriteString("\"}\n")
	}
	for _, c := range p.Conditions {
		switch strings.ToLower(c.Field) {
		case "rag_provenance":
			b.WriteString("  input.context.rag_provenance == \"")
			b.WriteString(c.Value)
			b.WriteString("\"\n")
		case "recovery_cost":
			b.WriteString("  input.context.recovery_cost == \"")
			b.WriteString(c.Value)
			b.WriteString("\"\n")
		case "cross_tenant":
			if strings.EqualFold(c.Value, "true") {
				b.WriteString("  input.context.cross_tenant\n")
			} else {
				b.WriteString("  not input.context.cross_tenant\n")
			}
		case "tool":
			b.WriteString("  input.tool == \"")
			b.WriteString(c.Value)
			b.WriteString("\"\n")
		case "effective_action_class":
			b.WriteString("  input.context.integrity.effective_class == \"")
			b.WriteString(c.Value)
			b.WriteString("\"\n")
		case "behavior_divergence":
			if strings.EqualFold(c.Value, "true") {
				b.WriteString("  input.context.integrity.diverged\n")
			} else {
				b.WriteString("  not input.context.integrity.diverged\n")
			}
		case "integrity_risk":
			b.WriteString("  input.context.integrity.risk ")
			b.WriteString(regoComparator(c.Operator))
			b.WriteString(" ")
			b.WriteString(regoNumber(c.Value))
			b.WriteString("\n")
		case "delegation_depth":
			b.WriteString("  input.context.delegation_depth ")
			b.WriteString(regoComparator(c.Operator))
			b.WriteString(" ")
			b.WriteString(regoNumber(c.Value))
			b.WriteString("\n")
		case "agent_risk_level":
			// Ordinal compare via the risk_rank object defined in the merged
			// module preamble (low<medium<high<critical).
			b.WriteString("  risk_rank[input.context.agent_risk_level] ")
			b.WriteString(regoComparator(c.Operator))
			b.WriteString(" risk_rank[\"")
			b.WriteString(strings.ToLower(strings.TrimSpace(c.Value)))
			b.WriteString("\"]\n")
		case "agent_capability":
			if strings.EqualFold(strings.TrimSpace(c.Operator), "not_in") {
				b.WriteString("  not \"")
				b.WriteString(strings.ToLower(strings.TrimSpace(c.Value)))
				b.WriteString("\" in input.context.agent_capabilities\n")
			} else {
				b.WriteString("  \"")
				b.WriteString(strings.ToLower(strings.TrimSpace(c.Value)))
				b.WriteString("\" in input.context.agent_capabilities\n")
			}
		case "data_class":
			b.WriteString("  input.context.data_class == \"")
			b.WriteString(strings.ToLower(strings.TrimSpace(c.Value)))
			b.WriteString("\"\n")
		case "namespace":
			b.WriteString("  input.context.namespace == \"")
			b.WriteString(strings.ToLower(strings.TrimSpace(c.Value)))
			b.WriteString("\"\n")
		case "time_of_day":
			b.WriteString("  input.context.time_of_day ")
			b.WriteString(regoComparator(c.Operator))
			b.WriteString(" ")
			b.WriteString(regoNumber(c.Value))
			b.WriteString("\n")
		case "fingerprint_drift":
			if strings.EqualFold(c.Value, "true") {
				b.WriteString("  input.context.fingerprint_drift\n")
			} else {
				b.WriteString("  not input.context.fingerprint_drift\n")
			}
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// PolicySet is the in-memory bundle of compiled policies for a tenant.
// The Rego evaluator (when CompileRego succeeded for the bundle) is the
// authoritative path; the typed-AST evaluator is the safety net that
// kicks in if any module fails to compile or eval at runtime.
type PolicySet struct {
	Policies []CompiledPolicy
	Version  int
	Rego     *RegoEvaluator // nil = AST-only mode
}

// Evaluate walks the policies in priority order, returning the first
// match. If no rule matches, the default verdict is DENY (closed-by-default).
// The autonomy budget is applied to ALLOW verdicts only - a high recovery_cost
// downgrades ALLOW to REQUIRE_APPROVAL.
func (s PolicySet) Evaluate(dc DelegationContext) Decision {
	// Real Rego first when available - it's the authoritative path.
	if s.Rego != nil && s.Rego.LastCompileError() == nil {
		if dec, ok := s.Rego.Evaluate(regoCtx(), dc); ok {
			if dec.Verdict == VerdictAllow && stringsEqualFoldLocal(dc.Context.RecoveryCost, "high") {
				dec.Verdict = VerdictRequireApproval
				if len(dec.Approvers) == 0 {
					dec.Approvers = []string{"security-team"}
				}
				if dec.Reason == "" {
					dec.Reason = "high recovery_cost outside autonomy budget"
				}
			}
			if dec.Timestamp.IsZero() {
				dec.Timestamp = now()
			}
			return dec
		}
		// Fall through to AST on Rego eval error.
	}
	dec := Decision{
		Verdict:   VerdictDeny,
		Reason:    "no matching allow",
		Timestamp: now(),
	}
	for _, p := range s.Policies {
		if !p.MatchesContext(dc) {
			continue
		}
		dec.Verdict = p.Verdict
		dec.Reason = p.Reason
		dec.Approvers = p.Approvers
		dec.Obligations = append([]string(nil), p.Obligations...)
		dec.PolicyID = p.ID
		break
	}
	// Autonomy budget: high recovery_cost on a write-class tool escalates.
	if dec.Verdict == VerdictAllow && strings.EqualFold(dc.Context.RecoveryCost, "high") {
		dec.Verdict = VerdictRequireApproval
		if len(dec.Approvers) == 0 {
			dec.Approvers = []string{"security-team"}
		}
		if dec.Reason == "" {
			dec.Reason = "high recovery_cost outside autonomy budget"
		}
	}
	return dec
}

func now() time.Time { return timeNow() }

// regoComparator maps a policy operator to its Rego infix form. Defaults to
// equality for anything unrecognized.
func regoComparator(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "gt", ">":
		return ">"
	case "gte", ">=":
		return ">="
	case "lt", "<":
		return "<"
	case "lte", "<=":
		return "<="
	case "ne", "!=":
		return "!="
	default:
		return "=="
	}
}

// regoNumber sanitizes a numeric literal for inlining into generated Rego.
// Non-numeric input collapses to 0 so the snippet always compiles.
func regoNumber(v string) string {
	if _, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err != nil {
		return "0"
	}
	return strings.TrimSpace(v)
}

// filterPolicySetByIDs returns a PolicySet whose Policies slice is
// restricted to the supplied ID set - the result of a
// PolicyTargetResolver.Resolve(vk, team, member) lookup.
//
// nil allowedIDs == "no resolver wired" → return src unchanged. A non-nil but
// empty allowedIDs == "no policy applies to this caller" → return a set with
// zero policies (clean default-deny).
func filterPolicySetByIDs(src PolicySet, allowedIDs []string) PolicySet {
	if allowedIDs == nil {
		return src
	}
	allow := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allow[id] = struct{}{}
	}
	out := PolicySet{
		Policies: make([]CompiledPolicy, 0, len(src.Policies)),
		Version:  src.Version,
		Rego:     src.Rego,
	}
	for _, p := range src.Policies {
		if _, ok := allow[p.ID]; ok {
			out.Policies = append(out.Policies, p)
		}
	}
	return out
}
