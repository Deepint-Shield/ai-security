package guardrails

import (
	"sync"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// speculativeInputResultKey carries the in-flight input-guard evaluation
// future from PreLLMHook to PostLLMHook. The value is *speculativeInputFuture;
// PostLLMHook blocks on its Done channel before releasing the model response.
const speculativeInputResultKey schemas.DeepIntShieldContextKey = "deepintshield-guardrail-spec-input"

// speculativeInputFuture is a one-shot async slot for the input-guard verdict
// computed in parallel with the provider call. Close(Done) signals readiness;
// the slot is read-once by PostLLMHook.
type speculativeInputFuture struct {
	Done       chan struct{}
	Response   *runtimeapi.EvaluateResponse
	Err        error
	StartedAt  time.Time
	FinishedAt time.Time

	// Captured at submission so the persistence write inside the goroutine
	// has everything it needs without re-reading the (possibly recycled)
	// request after PreLLMHook returns.
	requestID string
	provider  string
	model     string
	input     string
	actor     runtimeapi.Actor
	stage     string

	// Policies the request was submitted with - used by the speculative
	// collector to fast-path async-only requests without re-resolving
	// tenant state. Tenant-wide sync policies that do not apply to this
	// request must not force the wait.
	policies []runtimeapi.PolicyBundle

	once sync.Once
}

// finish signals completion exactly once. Safe to call from the eval goroutine
// and from a cancellation path.
func (f *speculativeInputFuture) finish(resp *runtimeapi.EvaluateResponse, err error) {
	if f == nil {
		return
	}
	f.once.Do(func() {
		f.Response = resp
		f.Err = err
		f.FinishedAt = time.Now()
		close(f.Done)
	})
}

// isStreamingRequest reports whether the request type would deliver chunks
// rather than a single response. Speculative dispatch is disabled for
// streaming because there is no clean "discard model output" path once the
// first chunk reaches the wire - the gate must run sync ahead of the call.
func isStreamingRequest(rt schemas.RequestType) bool {
	switch rt {
	case schemas.TextCompletionStreamRequest,
		schemas.ChatCompletionStreamRequest,
		schemas.ResponsesStreamRequest,
		schemas.PassthroughStreamRequest:
		return true
	default:
		return false
	}
}

// collectSpeculativeInputVerdict blocks until the input guard future settles
// (bounded by runtimeTimeout already enforced inside evaluateRuntime), then
// converts the verdict into the same shape PostLLMHook expects.
//
// Returns a non-nil error when the response must be discarded:
//   - deny / sandbox decisions → guardrail_blocked
//   - allow_with_redaction → guardrail_blocked (the model already saw the
//     unredacted input; serving the response would defeat the redactor)
//   - runtime failure → respects failOpen (nil → allow, non-nil → block)
//
// Allow paths return nil and the response flows through unchanged.
func (p *Plugin) collectSpeculativeInputVerdict(ctx *schemas.DeepIntShieldContext, future *speculativeInputFuture) *schemas.DeepIntShieldError {
	if future == nil {
		return nil
	}
	tenantID := guardrailTenantID(ctx)
	// Fast path: every policy that could gate this request is async/shadow,
	// so the wait adds latency to no gating outcome - applyExecutionModes
	// would downgrade every finding anyway. Fire-and-forget: spawn a
	// goroutine that awaits the future and persists findings async, then
	// return nil (allow) to the caller IMMEDIATELY.
	//
	// Checking BOTH predicates is necessary:
	//   - hasRequestSyncPolicies() covers inline header-attached policies
	//     (X-DeepIntShield-Guardrails-Config, etc.). When the request has
	//     no inline policies this returns false even though tenant-side
	//     policies may still gate.
	//   - tenantHasSyncPoliciesForStage() covers VK-bound and is_default
	//     policies loaded into the tenant bundle. This is the path the
	//     auto-wrapper takes - bound to the VK via vkgp, not pushed via
	//     request header.
	// Skipping the tenant check made a sync wrapper silently downgrade to
	// async (header mode=async on a sync policy) because future.policies
	// was empty for VK-routed traffic.
	if !p.hasRequestSyncPolicies(future.policies) && !p.tenantHasSyncPoliciesForStage(tenantID, runtimeapi.StageInput) {
		go func() {
			<-future.Done
			if future.Err != nil || future.Response == nil {
				return
			}
			p.persistEvaluation(ctx, runtimeapi.StageInput, future.requestID, future.actor, future.provider, future.model, future.input, "", "", nil, future.policies, future.Response)
		}()
		setGuardrailResponseHeaders(ctx, "pass", tables.GuardrailExecutionModeAsync)
		return nil
	}
	<-future.Done
	if future.Err != nil {
		return p.runtimeFailureDeepIntShieldError(future.Err)
	}
	if future.Response == nil {
		return nil
	}
	p.persistEvaluation(ctx, runtimeapi.StageInput, future.requestID, future.actor, future.provider, future.model, future.input, "", "", nil, future.policies, future.Response)
	outcome := p.applyExecutionModes(tenantID, future.Response)
	setGuardrailResponseHeaders(ctx, outcome.headerStatus, outcome.headerMode)
	effective := outcome.effective
	// In speculative mode the model has already produced output. A redact
	// verdict on the *input* can no longer rewrite what the model saw, so
	// promote it to a block: discard the response rather than serve content
	// derived from text the policy wanted scrubbed.
	if effective.Decision == "allow_with_redaction" {
		return p.errorForDecision(&runtimeapi.EvaluateResponse{Decision: "deny", Reason: "Speculative dispatch: input would have been redacted; discarding model response"}, runtimeapi.StageInput)
	}
	return p.errorForDecision(effective, runtimeapi.StageInput)
}
