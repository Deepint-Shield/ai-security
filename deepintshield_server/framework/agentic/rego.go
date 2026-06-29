// Real Rego compilation + evaluation backed by github.com/open-policy-agent/opa.
//
// Lifecycle:
//  1. CompiledPolicy.CompileRego() (policy.go) emits a Rego source snippet from
//     the typed AST. The same snippet is shown in the "Generated (read-only)"
//     panel next to the visual rule builder.
//  2. CompileRegoModules combines every published policy module for a tenant
//     into a single package, prepares an opa rego.PreparedEvalQuery once at
//     policy load, and stores it on the PolicySet.
//  3. PolicySet.Evaluate calls PreparedEvalQuery.Eval(input=DelegationContext)
//     on every miss path. The typed-AST evaluator is kept as a fallback so a
//     policy with a broken Rego module doesn't take the whole tenant offline.
package agentic

import (
	"context"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

// RegoEvaluator wraps an OPA PreparedEvalQuery. Safe for concurrent use.
type RegoEvaluator struct {
	mu       sync.RWMutex
	prepared *rego.PreparedEvalQuery
	source   string
	err      error
}

// CompileRegoModules merges the per-policy Rego snippets into a single
// module under package deepintshield.authz, prepares the query, and
// returns a ready-to-call RegoEvaluator. If compilation fails the
// evaluator's err is set; callers should fall back to the typed-AST
// evaluator in that case.
func CompileRegoModules(snippets []string) *RegoEvaluator {
	merged := buildMergedModule(snippets)
	ctx := context.Background()
	q, err := rego.New(
		rego.Query("data.deepintshield.authz.decision"),
		rego.Module("deepintshield_authz.rego", merged),
	).PrepareForEval(ctx)
	if err != nil {
		return &RegoEvaluator{source: merged, err: err}
	}
	return &RegoEvaluator{prepared: &q, source: merged}
}

func buildMergedModule(snippets []string) string {
	var b strings.Builder
	b.WriteString("package deepintshield.authz\n\n")
	b.WriteString("import rego.v1\n\n")
	// A safe default - every rule body is OR'd via Rego's multiple-rule
	// semantics, but at least one ALLOW must match for a non-DENY verdict.
	b.WriteString("default decision := {\"verdict\": \"DENY\", \"reason\": \"no matching allow\"}\n\n")
	// roles_of(chain) - extract role tokens from each actor_chain entry.
	b.WriteString("roles_of(chain) := { role_of(a) | some a in chain }\n\n")
	b.WriteString("role_of(actor) := substring(actor, 0, indexof(actor, \":\")) if indexof(actor, \":\") > 0\n")
	b.WriteString("role_of(actor) := actor if indexof(actor, \":\") <= 0\n\n")
	// risk_rank - ordinal mapping for the agent_risk_level condition.
	b.WriteString("risk_rank := {\"low\": 0, \"medium\": 1, \"med\": 1, \"high\": 2, \"critical\": 3}\n\n")
	for _, s := range snippets {
		body := stripPackageAndImports(s)
		if strings.TrimSpace(body) == "" {
			continue
		}
		b.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func stripPackageAndImports(src string) string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") || strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// Evaluate runs the prepared Rego query against the DelegationContext.
// Returns ok=false on any evaluation error so the caller can fall back
// to the typed-AST path without surfacing the error to the hot path.
func (e *RegoEvaluator) Evaluate(ctx context.Context, dc DelegationContext) (Decision, bool) {
	if e == nil {
		return Decision{}, false
	}
	e.mu.RLock()
	prepared := e.prepared
	e.mu.RUnlock()
	if prepared == nil {
		return Decision{}, false
	}
	input := map[string]any{
		"principal":     dc.Principal,
		"actor_chain":   dc.ActorChain,
		"identity_type": dc.IdentityType,
		"scope":         dc.Scope,
		"tenant":        dc.Tenant,
		"workspace":     dc.Workspace,
		"virtual_key":   dc.VirtualKey,
		"allowed_tools": dc.AllowedTools,
		"cross_tenant":  dc.CrossTenant,
		"tool":          dc.Tool,
		"args_digest":   dc.ArgsDigest,
		"context": map[string]any{
			"rag_provenance": dc.Context.RAGProvenance,
			"cost_used":      dc.Context.CostUsed,
			"recovery_cost":  dc.Context.RecoveryCost,
			"cross_tenant":   dc.CrossTenant,
			// Tool Integrity Engine signal (always the zero value in the OSS PDP),
			// so integrity-based policies evaluate against the un-diverged default.
			"integrity": map[string]any{
				"effective_class": dc.Context.Integrity.EffectiveClass,
				"risk":            dc.Context.Integrity.Risk,
				"diverged":        dc.Context.Integrity.Diverged,
			},
			// Agent attribute taxonomy. Lower-cased so the Rego `in` / risk_rank
			// lookups are effectively case-insensitive.
			"agent_risk_level":   strings.ToLower(strings.TrimSpace(dc.Context.AgentRiskLevel)),
			"agent_capabilities": lowerStrings(dc.Context.AgentCapabilities),
			// Fine-grained ABAC operands.
			"data_class":  strings.ToLower(strings.TrimSpace(dc.Context.DataClass)),
			"namespace":   strings.ToLower(strings.TrimSpace(dc.Context.Namespace)),
			"time_of_day": dc.Context.HourOfDay,
			// ASI04 supply-chain drift signal.
			"fingerprint_drift": dc.Context.FingerprintDrift,
			// Server-computed delegation chain depth.
			"delegation_depth": dc.Context.DelegationDepth,
		},
	}
	res, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil || len(res) == 0 || len(res[0].Expressions) == 0 {
		return Decision{}, false
	}
	dec, ok := decodeRegoResult(res[0].Expressions[0].Value)
	if !ok {
		return Decision{}, false
	}
	return dec, true
}

// lowerStrings returns a lower-cased, trimmed copy of the input slice so the
// Rego `in` membership test on agent_capabilities is case-insensitive.
func lowerStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Source returns the merged module - used by the /policies endpoint to
// expose the authoritative Rego that ships through GitOps.
func (e *RegoEvaluator) Source() string {
	if e == nil {
		return ""
	}
	return e.source
}

// LastCompileError surfaces a compilation error so the UI can flag a
// broken policy instead of silently using the AST fallback.
func (e *RegoEvaluator) LastCompileError() error {
	if e == nil {
		return nil
	}
	return e.err
}

// decodeRegoResult parses the Rego evaluation result back into a Decision.
// The Rego rule shape is `{"verdict": "...", "approvers": [...], "obligations": [...], "reason": "..."}`.
func decodeRegoResult(raw any) (Decision, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return Decision{}, false
	}
	dec := Decision{Verdict: VerdictDeny}
	if v, ok := m["verdict"].(string); ok && v != "" {
		dec.Verdict = Verdict(strings.ToUpper(strings.TrimSpace(v)))
	}
	if r, ok := m["reason"].(string); ok {
		dec.Reason = r
	}
	if apps, ok := m["approvers"].([]any); ok {
		for _, a := range apps {
			if s, ok := a.(string); ok {
				dec.Approvers = append(dec.Approvers, s)
			}
		}
	}
	if obs, ok := m["obligations"].([]any); ok {
		for _, a := range obs {
			if s, ok := a.(string); ok {
				dec.Obligations = append(dec.Obligations, s)
			}
		}
	}
	if p, ok := m["policy_id"].(string); ok {
		dec.PolicyID = p
	}
	return dec, true
}
