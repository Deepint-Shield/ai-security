package guardrails

import (
	"context"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
	"github.com/google/uuid"
)

// ScanText runs the workspace's input-stage guardrail policies against
// the supplied raw text and returns (allowed, reason). It exists for
// admin surfaces that need to gate non-LLM inputs - CSV uploads into the
// Response Consistency Golden Registry, prompt-repo edits, RAG ground-
// truth ingest - through the same policy set the runtime enforces on
// live inference traffic. The contract:
//
//   - Workspace + tenant context drives policy selection: the function
//     stamps both onto a fresh DeepIntShieldContext so attachRuntimePolicies
//     pulls the right per-workspace bundle. Cross-tenant policy leakage is
//     structurally impossible.
//
//   - Fail-OPEN on infrastructure failure: a guard runtime outage or
//     timeout returns (true, "scan unavailable: ...") so a degraded
//     guardrails service doesn't block legitimate admin work. Operators
//     see the reason in the upload response and can retry.
//
//   - Single round-trip per call: no speculative dispatch (admin scans
//     are off the hot path), no decision-cache lookup (the cache is keyed
//     on full EvaluateRequest inputs the admin scan doesn't carry).
//     Hard timeout via the plugin's runtimeTimeout - same SLO the
//     PreLLMHook path honors.
//
// Returns:
//   - allowed=true,  reason="" → text passed every active policy
//   - allowed=true,  reason="..." → scan unavailable, admit fail-OPEN
//   - allowed=false, reason="..." → text blocked by a policy; reason is
//     the first finding's message
func (p *Plugin) ScanText(ctx context.Context, workspaceID, tenantID, text string) (bool, string) {
	if p == nil || strings.TrimSpace(text) == "" {
		return true, ""
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = defaultTenantID
	}

	// Build a synthetic plugin context with the right tenant/workspace
	// so attachRuntimePolicies + hydrateTenantIfNeeded pick the right
	// policy set. The deadline matches the runtime timeout so a stalled
	// guard sidecar surfaces as (allowed, "scan unavailable") instead of
	// hanging the upload request.
	deadline := time.Now().Add(p.runtimeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	bctx := schemas.NewDeepIntShieldContext(ctx, deadline)
	bctx.SetValue(schemas.DeepIntShieldContextKeyTenantID, tenantID)
	if workspaceID != "" {
		bctx.SetValue(schemas.DeepIntShieldContextKeyWorkspaceID, workspaceID)
	}

	if err := p.hydrateTenantIfNeeded(bctx, tenantID, false); err != nil {
		// Fail-OPEN - degraded tenant cache shouldn't block admin uploads.
		return true, "scan unavailable: " + err.Error()
	}

	evalRequest := &runtimeapi.EvaluateRequest{
		TenantID:  tenantID,
		RequestID: "admin-scan-" + uuid.NewString(),
		Stage:     runtimeapi.StageInput,
		// Actor.Type "admin" signals this came from an admin surface (not
		// inference traffic) so the runtime can apply policy-level mode
		// filters that target operator actions specifically. ID is the
		// scan request id so the audit row is greppable.
		Actor:   runtimeapi.Actor{Type: "admin", ID: "admin-scan", Role: "admin"},
		Content: runtimeapi.Content{Input: text},
		Metadata: map[string]any{
			"source":       "admin_scan",
			"workspace_id": workspaceID,
			"tenant_id":    tenantID,
		},
	}
	evalRequest.Policies, evalRequest.Metadata = p.attachRuntimePolicies(bctx, runtimeapi.StageInput, evalRequest.Metadata)

	// Early exit: no policies attached and the tenant doesn't have any
	// either → no scan to run, admit unconditionally. Saves the runtime
	// RPC entirely for unguarded workspaces.
	if len(evalRequest.Policies) == 0 && !p.tenantHasEnabledPolicies(tenantID) {
		return true, ""
	}

	result, err := p.evaluateRuntime(bctx, evalRequest)
	if err != nil || result == nil {
		// Fail-OPEN - keep the upload path resilient to a guard outage.
		reason := "scan unavailable"
		if err != nil {
			reason = "scan unavailable: " + err.Error()
		}
		return true, reason
	}
	if strings.EqualFold(result.Decision, "deny") || strings.EqualFold(result.Decision, "block") {
		// First non-empty finding message gives the operator something
		// actionable in the admin UI (e.g. "matched 'us-ssn' regex").
		for _, f := range result.Findings {
			if strings.TrimSpace(f.Summary) != "" {
				return false, f.Summary
			}
		}
		return false, "blocked by guardrail policy"
	}
	return true, ""
}
