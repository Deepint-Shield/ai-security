package guardrails

import (
	"context"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// tenantHasSyncPoliciesForStage reports whether any cached policy for the
// tenant is in sync mode at the given stage. Used by PostLLMHook to decide
// whether the output evaluation can run detached: if every applicable policy
// is shadow/async, the runtime call is observation-only and the response can
// be released immediately.
//
// Returns true when the cache hasn't populated yet (defensive - never assume
// "no sync policies" before the first hydration completes).
func (p *Plugin) tenantHasSyncPoliciesForStage(tenantID, stage string) bool {
	if p == nil {
		return true
	}
	if tenantID == "" {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	state, ok := p.tenantCache[tenantID]
	if !ok {
		return true
	}
	modes := p.policyModes[tenantID]
	normalizedStage := runtimeapi.NormalizeStage(stage)
	for _, policy := range state.Bundle.Policies {
		if !policy.Enabled {
			continue
		}
		if runtimeapi.NormalizeStage(policy.Scope) != normalizedStage {
			continue
		}
		entry, ok := modes[policy.PolicyID]
		if !ok {
			return true
		}
		switch entry.mode {
		case "shadow", "async":
			continue
		default:
			return true
		}
	}
	return false
}

// tenantHasProviderBoundPolicies reports whether any cached policy for the
// tenant has a provider binding active for the given stage - i.e. would the
// slow eval path (AI Models wrapper / Bedrock / Azure Content Safety adapter
// calls) have anything to do? Used by PreLLMHook's fast-only pre-flight to
// decide whether the spec dispatch can be skipped after a fast-eval allow.
//
// Returns true defensively when the tenant bundle hasn't hydrated yet so
// the pre-flight never silently drops a slow-eval finding that hasn't
// loaded into the cache.
func (p *Plugin) tenantHasProviderBoundPolicies(tenantID, stage string) bool {
	if p == nil {
		return true
	}
	if tenantID == "" {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	state, ok := p.tenantCache[tenantID]
	if !ok {
		return true
	}
	normalizedStage := runtimeapi.NormalizeStage(stage)
	for _, policy := range state.Bundle.Policies {
		if !policy.Enabled {
			continue
		}
		if runtimeapi.NormalizeStage(policy.Scope) != normalizedStage {
			continue
		}
		if len(policy.ProviderBindings) > 0 {
			return true
		}
	}
	return false
}

// requestHasProviderBoundPolicies mirrors the tenant-cache check above for
// request-attached policies (the ones set by the gateway's inline header
// path). Together they cover both sources of provider bindings.
func requestHasProviderBoundPolicies(policies []runtimeapi.PolicyBundle) bool {
	for _, policy := range policies {
		if len(policy.ProviderBindings) > 0 {
			return true
		}
	}
	return false
}

// hasRequestSyncPolicies returns true when any policy attached via the
// request (governance/VK overrides) is sync-mode. Async detachment is only
// safe when *both* tenant-resident and request-resident policies are
// non-enforcing for this stage.
func (p *Plugin) hasRequestSyncPolicies(policies []runtimeapi.PolicyBundle) bool {
	for _, policy := range policies {
		mode, ok := policy.Metadata["execution_mode"].(string)
		if !ok || mode == "" {
			return true
		}
		switch mode {
		case "shadow", "async":
			continue
		default:
			return true
		}
	}
	return false
}

// spawnAsyncOutputEval detaches the post-LLM evaluation onto the persistence
// worker pool's coroutine and returns immediately. Findings still go to the
// evidence store via persistEvaluation; the only thing dropped is the wait.
//
// Uses a detached context so a client disconnect after we returned the
// response doesn't tear down the audit write.
func (p *Plugin) spawnAsyncOutputEval(ctx *schemas.DeepIntShieldContext, evalRequest *runtimeapi.EvaluateRequest, requestID string, provider, model, output string) {
	detached := detachContext(ctx)
	go func() {
		defer safegoroutine.Recover(p.logger, "guardrails.async-post-eval")
		result, err := p.evaluateRuntime(detached, evalRequest)
		if err != nil || result == nil {
			if err != nil {
				p.logger.Warn("[Guardrails] async post-guard runtime error: %v", err)
			}
			return
		}
		p.persistEvaluation(detached, runtimeapi.StageOutput, requestID, evalRequest.Actor, provider, model, "", output, "", nil, evalRequest.Policies, result)
	}()
}

// detachContext returns a context that preserves the tenant scope, the
// resolved actor, and the request's latency-breakdown tracker, but outlives
// a client cancel. The eval and the audit write must complete even if the
// caller disconnects after we return the response.
//
// Carrying the LatencyBreakdown tracker is what makes the async post-guard
// eval show up as `guardrail_output` in the AI Logs detail drawer. Without
// it, the phase is recorded into a tracker-less context and silently
// dropped (rolled into "Platform Overhead" by the logging plugin).
func detachContext(ctx *schemas.DeepIntShieldContext) context.Context {
	tenantID := guardrailTenantIDContext(ctx)
	out := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
	if vk, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID).(string); ok && vk != "" {
		out = context.WithValue(out, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID, vk)
	}
	// Preserve the latency-breakdown tracker so async post-eval is visible
	// alongside the sync phases in AI Logs.
	if tracker, ok := ctx.Value(schemas.DeepIntShieldContextKeyLatencyBreakdown).(*schemas.LatencyBreakdown); ok && tracker != nil {
		out = context.WithValue(out, schemas.DeepIntShieldContextKeyLatencyBreakdown, tracker)
	}
	// Preserve the resolved-actor struct so the async path's audit writes
	// carry the same VK / customer / team identity the original request did.
	if actor, ok := ctx.Value(resolvedActorKey).(*resolvedActor); ok && actor != nil {
		out = context.WithValue(out, resolvedActorKey, actor)
	}
	// Preserve the VK's guardrail policy IDs so the async path's
	// resolveEvaluatedPolicies can stamp engine_source on the persisted
	// output decision. Without it, the wrapper-bound VK persisted
	// engine_source='' on output rows and AI Logs rolled the request up as
	// "Mixed" - the input row carried ai_model, the empty output row fell
	// into the legacy join's NULL-provider "policy" branch.
	if ids, ok := ctx.Value(schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs).([]string); ok && len(ids) > 0 {
		out = context.WithValue(out, schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs, ids)
	}
	return out
}
