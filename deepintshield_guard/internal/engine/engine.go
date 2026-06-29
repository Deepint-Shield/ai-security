package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	regexp "github.com/grafana/regexp"

	"github.com/deepint-shield/ai-security-guard/internal/cards"
	providerspkg "github.com/deepint-shield/ai-security-guard/internal/providers"
	awsbedrock "github.com/deepint-shield/ai-security-guard/internal/providers/awsbedrock"
	azurecontentsafety "github.com/deepint-shield/ai-security-guard/internal/providers/azurecontentsafety"
	deepintshieldmodels "github.com/deepint-shield/ai-security-guard/internal/providers/deepintshieldmodels"
	gcpmodelarmor "github.com/deepint-shield/ai-security-guard/internal/providers/gcpmodelarmor"
	webhookprovider "github.com/deepint-shield/ai-security-guard/internal/providers/webhook"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

type compiledRule struct {
	Category string
	Pattern  *regexp.Regexp
	Severity string
	Outcome  string
	Summary  string
}

// RuntimeConfig holds tunable parameters for the guard runtime engine.
type RuntimeConfig struct {
	// AdapterTimeoutMs is the global default time in milliseconds for provider
	// adapter calls (e.g. AWS Bedrock, deepintshield_models). Default: 1500ms.
	// PerCategoryTimeoutsMs takes precedence per-call when a policy advertises
	// a category, and an explicit policy.TimeoutMs takes precedence over both.
	AdapterTimeoutMs int
	// RAGChunkParallelism is the maximum number of RAG chunks evaluated
	// concurrently. Default: 8.
	RAGChunkParallelism int
	// PerCategoryTimeoutsMs is a category → milliseconds map letting operators
	// tighten budgets for fast-class checks (regex/PII <200ms) without
	// loosening them for slow-class checks (jailbreak classifiers ~1200ms).
	// Tail-latency optimization: the global 1500ms ceiling is pessimistic for
	// most categories and causes p99 spikes when a single slow adapter ties up
	// the wait. Keys are matched against the policy's metadata "category"
	// field (case-insensitive). Unmatched categories fall back to
	// AdapterTimeoutMs.
	PerCategoryTimeoutsMs map[string]int
}

type Runtime struct {
	mu               sync.RWMutex
	tenantBundles    map[string]runtimeapi.TenantBundle
	refreshedTenants map[string]time.Time
	compiledDefs     map[string]map[string]any
	compiledRules    map[string][]compiledRule
	// compiledRuleUnions caches a single alternation regex per rule set
	// used by evaluateLocalPolicies as a no-match fast path.
	compiledRuleUnions map[string]*regexp.Regexp
	// compiledRuleACs caches an Aho-Corasick automaton built from the
	// REQUIRED literal anchors of every pattern in a rule set. Acts as
	// an even cheaper pre-filter than the union regex - linear-time
	// single-pass scan over the input. Nil when any pattern in the set
	// lacks a literal anchor (e.g. `\d{16}`), in which case the union
	// regex remains the pre-filter.
	compiledRuleACs     map[string]*ahoCorasickAutomaton
	adapters            map[string]providerspkg.Adapter
	adapterTimeout      time.Duration
	ragChunkParallelism int
	perCategoryTimeouts map[string]time.Duration
}

const (
	// Default per-policy adapter call ceiling. 10 s is generous for
	// "fast" partner providers (AWS Bedrock guardrails ~120ms, Azure
	// Content Safety ~150ms) but mandatory for the deepintshield_models
	// sidecar, which on CPU can take 600-2000ms on the first call when
	// PyTorch JITs the kernels for a detector that wasn't preloaded -
	// reliably tripping the previous 1.5s ceiling and dropping the
	// finding with a "context deadline exceeded" entry on the decision
	// chain. Operators who want a tighter SLA on partner providers can
	// override per-category via PerCategoryTimeoutsMs.
	defaultAdapterTimeoutMs = 10000
	defaultRAGChunkParallel = 8
)

func New(opts ...RuntimeConfig) *Runtime {
	adapterTimeout := time.Duration(defaultAdapterTimeoutMs) * time.Millisecond
	ragParallelism := defaultRAGChunkParallel
	var perCategory map[string]int
	if len(opts) > 0 {
		cfg := opts[0]
		if cfg.AdapterTimeoutMs > 0 {
			adapterTimeout = time.Duration(cfg.AdapterTimeoutMs) * time.Millisecond
		}
		if cfg.RAGChunkParallelism > 0 {
			ragParallelism = cfg.RAGChunkParallelism
		}
		if len(cfg.PerCategoryTimeoutsMs) > 0 {
			perCategory = cfg.PerCategoryTimeoutsMs
		}
	}
	// Allow environment overrides for deployment-level tuning.
	if v := envInt("DEEPINTSHIELD_GUARD_ADAPTER_TIMEOUT_MS", 0); v > 0 {
		adapterTimeout = time.Duration(v) * time.Millisecond
	}
	if v := envInt("DEEPINTSHIELD_GUARD_RAG_CHUNK_PARALLELISM", 0); v > 0 {
		ragParallelism = v
	}
	// JSON-encoded {"pii":150,"toxicity":600,"jailbreak":1200} via env.
	// Operator-driven; an absent or invalid value is treated as "no per-class
	// override" (the global adapterTimeout applies).
	if raw := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_GUARD_TIMEOUTS_BY_CATEGORY")); raw != "" {
		parsed := map[string]int{}
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			if perCategory == nil {
				perCategory = parsed
			} else {
				for k, v := range parsed {
					perCategory[k] = v
				}
			}
		}
	}
	perCategoryDur := make(map[string]time.Duration, len(perCategory))
	for k, v := range perCategory {
		if v > 0 {
			perCategoryDur[strings.ToLower(strings.TrimSpace(k))] = time.Duration(v) * time.Millisecond
		}
	}
	return &Runtime{
		tenantBundles:       make(map[string]runtimeapi.TenantBundle),
		refreshedTenants:    make(map[string]time.Time),
		compiledDefs:        make(map[string]map[string]any),
		compiledRules:       make(map[string][]compiledRule),
		compiledRuleUnions:  make(map[string]*regexp.Regexp),
		compiledRuleACs:     make(map[string]*ahoCorasickAutomaton),
		adapterTimeout:      adapterTimeout,
		ragChunkParallelism: ragParallelism,
		perCategoryTimeouts: perCategoryDur,
		adapters: map[string]providerspkg.Adapter{
			"aws_bedrock":          awsbedrock.New(),
			"azure_content_safety": azurecontentsafety.New(),
			"deepintshield_models": deepintshieldmodels.New(),
			"gcp_model_armor":      gcpmodelarmor.New(),
			"webhook":              webhookprovider.New(),
		},
	}
}

// resolveTimeout picks the budget for one adapter call.
// Precedence: explicit policy.TimeoutMs > per-category override > global default.
// Per-category lookup uses policy.Metadata["category"] (case-insensitive),
// falling back to policy.Metadata["check_class"]. Unmatched falls back to
// adapterTimeout.
func (r *Runtime) resolveTimeout(policy runtimeapi.PolicyBundle) time.Duration {
	if policy.TimeoutMs > 0 {
		return time.Duration(policy.TimeoutMs) * time.Millisecond
	}
	if len(r.perCategoryTimeouts) == 0 {
		return r.adapterTimeout
	}
	category := ""
	if v, ok := policy.Metadata["category"].(string); ok {
		category = strings.ToLower(strings.TrimSpace(v))
	}
	if category == "" {
		if v, ok := policy.Metadata["check_class"].(string); ok {
			category = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if category != "" {
		if d, ok := r.perCategoryTimeouts[category]; ok && d > 0 {
			return d
		}
	}
	return r.adapterTimeout
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func (r *Runtime) RefreshTenant(bundle runtimeapi.TenantBundle) {
	tenantID := strings.TrimSpace(bundle.TenantID)
	if tenantID == "" {
		return
	}
	bundle.TenantID = tenantID
	if bundle.RefreshedAt.IsZero() {
		bundle.RefreshedAt = time.Now().UTC()
	}
	r.prewarmTenantBundle(bundle)
	r.mu.Lock()
	r.tenantBundles[tenantID] = bundle
	r.refreshedTenants[tenantID] = bundle.RefreshedAt
	r.mu.Unlock()
}

// EvaluateFastOnly runs ONLY the portkey + local check evaluation paths,
// skipping provider bindings (sidecar calls) + MCP entirely. Returns the
// resulting findings + decision exactly as Evaluate would, but in
// sub-millisecond time for the common case where regex/card checks cover
// the request.
//
// The gateway uses this for a pre-flight sync check before launching the
// full speculative dispatch: if fast policies already say "deny", we
// short-circuit immediately and never make the upstream model call. The
// previous speculative path always fired the model call in parallel,
// then waited for the full eval - meaning even regex-blocked requests
// paid the model RTT, surfacing as `latency_block_fast` > 500ms.
//
// Callers MUST still run full Evaluate (or speculative dispatch) when
// this returns "allow", since provider-binding policies (the AI Models
// wrapper) may still gate the request.
func (r *Runtime) EvaluateFastOnly(ctx context.Context, request runtimeapi.EvaluateRequest) runtimeapi.EvaluateResponse {
	// Mirror the full path: extracted attachment text must be visible to the
	// fast pre-flight checks too, otherwise a deny that the full path would
	// raise could be missed by the speculative short-circuit.
	request = r.applyModalityExtraction(ctx, request)
	response := runtimeapi.EvaluateResponse{
		Decision:      "allow",
		Reason:        "No guardrail violations detected",
		Findings:      []runtimeapi.Finding{},
		Redactions:    []string{},
		DecisionChain: []string{"deepintshield_guard fast-only evaluation"},
	}
	bundle, hasBundle := r.lookupTenantBundle(request.TenantID)
	policies := append([]runtimeapi.PolicyBundle(nil), request.Policies...)
	if hasBundle {
		hydratedPolicies := selectPolicies(bundle.Policies, request)
		requestedPolicies := selectPoliciesByID(bundle.Policies, requestMetadataValues(request.Metadata, "requested_policy_ids"), request.Stage)
		skipTenantGuardrails := boolValue(request.Metadata, "skip_tenant_guardrails", false)
		if len(requestedPolicies) > 0 {
			policies = mergeRuntimePolicies(requestedPolicies, policies)
		} else if len(policies) == 0 && !skipTenantGuardrails {
			policies = mergeRuntimePolicies(selectDefaultPolicies(bundle.Policies, request.Stage), hydratedPolicies)
		}
	}
	if len(policies) == 0 {
		return response
	}
	compiledPolicies := r.compileRuntimePolicies(policies, request.Stage)
	portkeyFindings, portkeyRedactions, portkeySanitizedInput, portkeySanitizedOutput, portkeyChain := evaluateRuntimeChecksWithRuntime(ctx, r, r.adapterTimeout, compiledPolicies, request)
	localFindings, localRedactions, localSanitizedInput, localSanitizedOutput, localChain := r.evaluateLocalPolicies(compiledPolicies, request)
	response.Findings = append(response.Findings, portkeyFindings...)
	response.Findings = append(response.Findings, localFindings...)
	response.Redactions = append(response.Redactions, portkeyRedactions...)
	response.Redactions = append(response.Redactions, localRedactions...)
	response.DecisionChain = append(response.DecisionChain, portkeyChain...)
	response.DecisionChain = append(response.DecisionChain, localChain...)
	if strings.TrimSpace(portkeySanitizedInput) != "" && portkeySanitizedInput != request.Content.Input {
		response.SanitizedInput = portkeySanitizedInput
	} else if localSanitizedInput != request.Content.Input {
		response.SanitizedInput = localSanitizedInput
	}
	if strings.TrimSpace(portkeySanitizedOutput) != "" && portkeySanitizedOutput != request.Content.Output {
		response.SanitizedOutput = portkeySanitizedOutput
	} else if localSanitizedOutput != request.Content.Output {
		response.SanitizedOutput = localSanitizedOutput
	}
	response.Decision, response.ApprovalRequired, response.Reason = resolveDecision(response.Findings, response.Redactions)
	return response
}

func (r *Runtime) Evaluate(ctx context.Context, request runtimeapi.EvaluateRequest) runtimeapi.EvaluateResponse {
	start := time.Now()
	// Modality-extraction stage: fold image/audio/video/document attachments
	// into Content.Input/Output as text before any detector runs. No-op (and
	// zero cost) when the stage is disabled or no attachments are present.
	request = r.applyModalityExtraction(ctx, request)
	response := runtimeapi.EvaluateResponse{
		Decision:      "allow",
		Reason:        "No guardrail violations detected",
		Findings:      []runtimeapi.Finding{},
		DecisionChain: []string{"deepintshield_guard runtime evaluation"},
	}

	bundle, hasBundle := r.lookupTenantBundle(request.TenantID)
	policies := append([]runtimeapi.PolicyBundle(nil), request.Policies...)
	if hasBundle {
		defaultPolicies := selectDefaultPolicies(bundle.Policies, request.Stage)
		hydratedPolicies := selectPolicies(bundle.Policies, request)
		requestedPolicies := selectPoliciesByID(bundle.Policies, requestMetadataValues(request.Metadata, "requested_policy_ids"), request.Stage)
		skipTenantGuardrails := boolValue(request.Metadata, "skip_tenant_guardrails", false)
		if len(hydratedPolicies) > 0 {
			response.DecisionChain = append(response.DecisionChain, fmt.Sprintf("using hydrated tenant bundle revision %s", strings.TrimSpace(bundle.Revision)))
		}
		if len(requestedPolicies) > 0 {
			policies = mergeRuntimePolicies(requestedPolicies, policies)
			response.DecisionChain = append(response.DecisionChain, "attached virtual-key guardrails from hydrated tenant bundle")
			if boolValue(request.Metadata, "merge_tenant_policies", false) {
				policies = mergeRuntimePolicies(policies, defaultPolicies)
				policies = mergeRuntimePolicies(policies, hydratedPolicies)
				response.DecisionChain = append(response.DecisionChain, "merged attached virtual-key guardrails with default and matched tenant policies")
			}
		} else if len(policies) == 0 {
			if skipTenantGuardrails {
				response.DecisionChain = append(response.DecisionChain, "virtual key has no attached guardrails; skipped tenant default policy hydration")
			} else {
				policies = mergeRuntimePolicies(defaultPolicies, hydratedPolicies)
				if len(defaultPolicies) > 0 {
					response.DecisionChain = append(response.DecisionChain, "applied tenant default guardrail policy")
				}
			}
		}
	}
	if len(policies) == 0 && !hasBundle && len(request.Policies) == 0 {
		policies = []runtimeapi.PolicyBundle{{
			PolicyID:        "builtin-runtime-default",
			PolicyVersionID: "builtin-runtime-default-v1",
			Name:            "Default Runtime Protection",
			Scope:           runtimeapi.NormalizeStage(request.Stage),
			EnforcementMode: "block",
			Enabled:         true,
			Definition:      defaultDefinition(request.Stage),
		}}
		response.DecisionChain = append(response.DecisionChain, "no hydrated tenant policies available, using built-in defaults")
	} else if len(policies) == 0 {
		response.DecisionChain = append(response.DecisionChain, "no enabled tenant policies matched the request")
	}
	compiledPolicies := r.compileRuntimePolicies(policies, request.Stage)
	if runtimeapi.NormalizeStage(request.Stage) == runtimeapi.StageRAG {
		return r.evaluateRAG(ctx, start, bundle, hasBundle, policies, request, response)
	}

	// Run all four evaluation paths concurrently: portkey checks, local rule evaluation,
	// MCP tool policies, and external provider bindings. Each path is independent -
	// findings are merged at the end. This eliminates the previous serial bottleneck
	// where portkey evaluation (especially webhook checks) blocked all other paths.
	type evalResult struct {
		findings        []runtimeapi.Finding
		redactions      []string
		sanitizedInput  string
		sanitizedOutput string
		chain           []string
	}
	var (
		runtimeEval      evalResult
		localEval        evalResult
		mcpFindings      []runtimeapi.Finding
		mcpChain         []string
		provFindings     []runtimeapi.Finding
		provChain        []string
		modalityFindings []runtimeapi.Finding
		modalityChain    []string
	)

	// Two-phase evaluation:
	//   1. Fast paths (portkey + local) - in-process regex / card / preset
	//      checks that finish in sub-ms. Run in parallel, wait for both.
	//   2. Slow paths (provider bindings + MCP) - sidecar HTTP calls to
	//      deepintshield_models / AWS Bedrock / Azure Content Safety etc.,
	//      typically 100-500 ms warm. Started in parallel with phase 1 if
	//      none of the fast paths produced a deny, OR cancelled when a
	//      deny is already determined from a fast path.
	//
	// The previous single-WaitGroup design waited for ALL four paths to
	// complete, so a request denied by a sub-ms regex still paid the
	// 250 ms wrapper sidecar cost on the critical path - the canonical
	// "why is guard ms 287ms when Policy decided?" pattern in AI Logs.
	// With the two-phase split, a regex-denied request returns in ~1 ms
	// and the wrapper call is cancelled mid-flight (best-effort - the
	// HTTP RTT may already be in-flight, but no further wait is taken).
	//
	// Trade-off: when a fast path denies, we no longer wait for the
	// wrapper's verdict on that same request. Wrapper findings for
	// already-denied requests don't land in guardrail_findings - they're
	// already redundant for gating, but they would have added to the AI
	// Models analytics. Acceptable: operators chose this trade when
	// flipping the wrapper to sync (see [[feedback-guardrail-zero-latency]]).
	slowCtx, cancelSlow := context.WithCancel(ctx)
	defer cancelSlow()
	var slowWg sync.WaitGroup
	if hasBundle && request.MCP != nil {
		slowWg.Add(1)
		go func() {
			defer slowWg.Done()
			mcpFindings, mcpChain = evaluateMCPToolPolicies(bundle.MCPToolPolicies, request)
		}()
	}
	if hasBundle {
		slowWg.Add(1)
		go func() {
			defer slowWg.Done()
			provFindings, provChain = r.evaluateProviderBindings(slowCtx, bundle, compiledPolicies, request)
		}()
	}
	// Modality-native safety detectors (vision/audio) run alongside the other
	// slow paths over the request attachments. No-op unless the modality stage
	// is enabled AND an operator has registered a detector. Cancelled with the
	// rest of the slow group when a fast path already produced a deny.
	if modalityDetectorsActive() && len(request.Content.Attachments) > 0 {
		slowWg.Add(1)
		go func() {
			defer slowWg.Done()
			modalityFindings, modalityChain = runModalityDetectors(slowCtx, request)
		}()
	}

	var fastWg sync.WaitGroup
	fastWg.Add(2)
	go func() {
		defer fastWg.Done()
		findings, redactions, si, so, chain := evaluateRuntimeChecksWithRuntime(ctx, r, r.adapterTimeout, compiledPolicies, request)
		runtimeEval = evalResult{findings: findings, redactions: redactions, sanitizedInput: si, sanitizedOutput: so, chain: chain}
	}()
	go func() {
		defer fastWg.Done()
		findings, redactions, si, so, chain := r.evaluateLocalPolicies(compiledPolicies, request)
		localEval = evalResult{findings: findings, redactions: redactions, sanitizedInput: si, sanitizedOutput: so, chain: chain}
	}()
	fastWg.Wait()

	// Determine if a fast-path deny / sandbox has already settled the
	// outcome. If so, cancel the slow paths - their result can't change
	// the verdict at gating time.
	fastDecided := hasGatingDeny(runtimeEval.findings) || hasGatingDeny(localEval.findings)
	if fastDecided {
		// A fast path already settled the verdict; cancel the in-flight slow
		// paths (sidecar bindings, MCP, modality detectors) so they abort early.
		cancelSlow()
	}
	// Always join the slow group before reading its results. cancelSlow() above
	// makes the wait short on the deny path (ctx-aware work returns promptly),
	// while the Wait establishes the happens-before edge so provFindings,
	// mcpFindings and modalityFindings are read without a data race in the merge.
	slowWg.Wait()

	// Merge results: portkey first, then local, MCP, providers (preserves decision precedence).
	response.Findings = append(response.Findings, runtimeEval.findings...)
	response.Redactions = append(response.Redactions, runtimeEval.redactions...)
	response.DecisionChain = append(response.DecisionChain, runtimeEval.chain...)
	response.Findings = append(response.Findings, localEval.findings...)
	response.Redactions = append(response.Redactions, localEval.redactions...)
	response.DecisionChain = append(response.DecisionChain, localEval.chain...)
	response.Findings = append(response.Findings, mcpFindings...)
	response.DecisionChain = append(response.DecisionChain, mcpChain...)
	response.Findings = append(response.Findings, provFindings...)
	response.DecisionChain = append(response.DecisionChain, provChain...)
	response.Findings = append(response.Findings, modalityFindings...)
	response.DecisionChain = append(response.DecisionChain, modalityChain...)

	response.Decision, response.ApprovalRequired, response.Reason = resolveDecision(response.Findings, response.Redactions)

	// Apply sanitized content from whichever path modified it.
	portkeySanitizedInput := runtimeEval.sanitizedInput
	portkeySanitizedOutput := runtimeEval.sanitizedOutput
	if strings.TrimSpace(portkeySanitizedInput) != "" && portkeySanitizedInput != request.Content.Input {
		response.SanitizedInput = portkeySanitizedInput
	}
	if strings.TrimSpace(portkeySanitizedOutput) != "" && portkeySanitizedOutput != request.Content.Output {
		response.SanitizedOutput = portkeySanitizedOutput
	}
	if localEval.sanitizedInput != request.Content.Input {
		response.SanitizedInput = localEval.sanitizedInput
	}
	if localEval.sanitizedOutput != request.Content.Output {
		response.SanitizedOutput = localEval.sanitizedOutput
	}
	response.LatencyMs = int(time.Since(start).Milliseconds())
	return response
}

func (r *Runtime) lookupTenantBundle(tenantID string) (runtimeapi.TenantBundle, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return runtimeapi.TenantBundle{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	bundle, ok := r.tenantBundles[tenantID]
	return bundle, ok
}

func selectPolicies(policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest) []runtimeapi.PolicyBundle {
	normalizedStage := runtimeapi.NormalizeStage(request.Stage)
	type candidate struct {
		policy      runtimeapi.PolicyBundle
		priority    int
		specificity int
	}
	selected := make([]candidate, 0, len(policies))
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if policy.IsDefault {
			continue
		}
		if !policyAppliesToStage(policy, normalizedStage) {
			continue
		}
		if !policyMatchesRequest(policy, request) {
			continue
		}
		selected = append(selected, candidate{
			policy:      policy,
			priority:    selectorPriority(policy.Metadata),
			specificity: selectorSpecificity(policy),
		})
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].priority != selected[j].priority {
			return selected[i].priority < selected[j].priority
		}
		if selected[i].specificity != selected[j].specificity {
			return selected[i].specificity > selected[j].specificity
		}
		if !strings.EqualFold(selected[i].policy.Name, selected[j].policy.Name) {
			return strings.ToLower(selected[i].policy.Name) < strings.ToLower(selected[j].policy.Name)
		}
		return strings.ToLower(selected[i].policy.PolicyID) < strings.ToLower(selected[j].policy.PolicyID)
	})
	bundles := make([]runtimeapi.PolicyBundle, 0, len(selected))
	for _, item := range selected {
		bundles = append(bundles, item.policy)
	}
	return bundles
}

func selectDefaultPolicies(policies []runtimeapi.PolicyBundle, stage string) []runtimeapi.PolicyBundle {
	normalizedStage := runtimeapi.NormalizeStage(stage)
	selected := make([]runtimeapi.PolicyBundle, 0, 1)
	for _, policy := range policies {
		if !policy.Enabled || !policy.IsDefault {
			continue
		}
		if !policyAppliesToStage(policy, normalizedStage) {
			continue
		}
		selected = append(selected, policy)
	}
	return selected
}

func selectPoliciesByID(policies []runtimeapi.PolicyBundle, policyIDs []string, stage string) []runtimeapi.PolicyBundle {
	if len(policyIDs) == 0 {
		return nil
	}
	normalizedStage := runtimeapi.NormalizeStage(stage)
	index := make(map[string]runtimeapi.PolicyBundle, len(policies))
	for _, policy := range policies {
		if !policy.Enabled || !policyAppliesToStage(policy, normalizedStage) {
			continue
		}
		index[strings.TrimSpace(policy.PolicyID)] = policy
	}
	selected := make([]runtimeapi.PolicyBundle, 0, len(policyIDs))
	seen := make(map[string]struct{}, len(policyIDs))
	for _, policyID := range policyIDs {
		trimmedPolicyID := strings.TrimSpace(policyID)
		if trimmedPolicyID == "" {
			continue
		}
		if _, ok := seen[trimmedPolicyID]; ok {
			continue
		}
		policy, ok := index[trimmedPolicyID]
		if !ok {
			continue
		}
		seen[trimmedPolicyID] = struct{}{}
		selected = append(selected, policy)
	}
	return selected
}

func policyMatchesRequest(policy runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest) bool {
	if boolValue(policy.Metadata, "assignment_only", false) {
		return false
	}
	selectors := policySelectors(policy.Metadata)
	if len(selectors) == 0 && strings.TrimSpace(policy.DomainPackID) == "" {
		return true
	}
	if !matchSelectorValues(selectorValues(selectors, "tenant_ids"), []string{request.TenantID}) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "workspace_ids", "workspace_id"), requestWorkspaceValues(request)) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "apps", "app_ids", "app"), requestMetadataValues(request.Metadata, "app", "app_id", "application", "application_id")) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "models", "model_patterns"), requestValues(request.Model, requestMetadataValues(request.Metadata, "model")...)) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "routes", "route_patterns"), requestMetadataValues(request.Metadata, "route", "url_path")) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "providers"), requestValues(request.Provider, requestMetadataValues(request.Metadata, "provider")...)) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "request_types"), requestMetadataValues(request.Metadata, "request_type")) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "customer_ids"), requestValues(request.Actor.CustomerID, requestMetadataValues(request.Metadata, "customer_id")...)) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "team_ids"), requestValues(request.Actor.TeamID, requestMetadataValues(request.Metadata, "team_id")...)) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "actor_types"), []string{request.Actor.Type}) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "actor_roles"), requestValues(request.Actor.Role, requestMetadataValues(request.Metadata, "actor_role")...)) {
		return false
	}
	requestDomainPacks := requestMetadataValues(request.Metadata, "domain_pack_id", "domain_pack_ids")
	if strings.TrimSpace(policy.DomainPackID) != "" && len(requestDomainPacks) > 0 && !containsNormalizedValue(requestDomainPacks, policy.DomainPackID) {
		return false
	}
	if !matchSelectorValues(selectorValues(selectors, "domain_pack_ids"), append(requestDomainPacks, policy.DomainPackID)) {
		return false
	}
	return true
}

func policySelectors(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	raw, ok := metadata["selectors"]
	if !ok || raw == nil {
		return metadata
	}
	typed, ok := raw.(map[string]any)
	if !ok {
		return metadata
	}
	return typed
}

func selectorPriority(metadata map[string]any) int {
	selectors := policySelectors(metadata)
	if priority, ok := numericValue(selectors["priority"]); ok {
		return priority
	}
	if priority, ok := numericValue(metadata["priority"]); ok {
		return priority
	}
	return 100
}

func selectorSpecificity(policy runtimeapi.PolicyBundle) int {
	selectors := policySelectors(policy.Metadata)
	count := 0
	for _, key := range []string{
		"tenant_ids",
		"workspace_ids",
		"workspace_id",
		"apps",
		"app_ids",
		"app",
		"models",
		"model_patterns",
		"routes",
		"route_patterns",
		"providers",
		"request_types",
		"customer_ids",
		"team_ids",
		"actor_types",
		"actor_roles",
		"domain_pack_ids",
	} {
		if len(selectorValues(selectors, key)) > 0 {
			count++
		}
	}
	if strings.TrimSpace(policy.DomainPackID) != "" {
		count++
	}
	return count
}

func selectorValues(selectors map[string]any, keys ...string) []string {
	if len(selectors) == 0 {
		return nil
	}
	for _, key := range keys {
		if raw, ok := selectors[key]; ok {
			values := toStringSlice(raw)
			if len(values) > 0 {
				return values
			}
		}
	}
	return nil
}

func requestWorkspaceValues(request runtimeapi.EvaluateRequest) []string {
	values := []string{request.TenantID}
	values = append(values, requestMetadataValues(request.Metadata, "workspace_id", "workspace", "tenant_id")...)
	return dedupeNonEmptyStrings(values...)
}

func requestMetadataValues(metadata map[string]any, keys ...string) []string {
	if len(metadata) == 0 {
		return nil
	}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		raw, ok := metadata[key]
		if !ok {
			continue
		}
		values = append(values, toStringSlice(raw)...)
	}
	return dedupeNonEmptyStrings(values...)
}

func requestValues(primary string, extras ...string) []string {
	values := make([]string, 0, 1+len(extras))
	if strings.TrimSpace(primary) != "" {
		values = append(values, primary)
	}
	values = append(values, extras...)
	return dedupeNonEmptyStrings(values...)
}

func matchSelectorValues(selectors, candidates []string) bool {
	if len(selectors) == 0 {
		return true
	}
	if len(candidates) == 0 {
		return false
	}
	for _, selector := range selectors {
		for _, candidate := range candidates {
			if selectorMatches(selector, candidate) {
				return true
			}
		}
	}
	return false
}

func selectorMatches(pattern, candidate string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if pattern == "" || candidate == "" {
		return false
	}
	if pattern == "*" || strings.EqualFold(pattern, candidate) {
		return true
	}
	if strings.Contains(pattern, "*") {
		ok, err := path.Match(pattern, candidate)
		return err == nil && ok
	}
	return false
}

func mergeRuntimePolicies(basePolicies, requestPolicies []runtimeapi.PolicyBundle) []runtimeapi.PolicyBundle {
	merged := make([]runtimeapi.PolicyBundle, 0, len(basePolicies)+len(requestPolicies))
	seen := make(map[string]struct{}, len(basePolicies)+len(requestPolicies))
	for _, collection := range [][]runtimeapi.PolicyBundle{basePolicies, requestPolicies} {
		for _, policy := range collection {
			key := strings.TrimSpace(policy.PolicyID) + "::" + strings.TrimSpace(policy.PolicyVersionID) + "::" + strings.TrimSpace(policy.Name)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, policy)
		}
	}
	return merged
}

func (r *Runtime) compileRuntimePolicies(policies []runtimeapi.PolicyBundle, stage string) []runtimeapi.PolicyBundle {
	if len(policies) == 0 {
		return nil
	}
	compiledStage := runtimeapi.NormalizeStage(stage)
	compiled := make([]runtimeapi.PolicyBundle, 0, len(policies))
	for _, policy := range policies {
		clone := policy
		clone.Definition = r.compiledDefinitionForPolicy(policy, compiledStage)
		compiled = append(compiled, clone)
	}
	return compiled
}

func (r *Runtime) evaluateLocalPolicies(policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest) ([]runtimeapi.Finding, []string, string, string, []string) {
	target := pickContent(request)
	sanitizedInput := request.Content.Input
	sanitizedOutput := request.Content.Output
	findings := make([]runtimeapi.Finding, 0, 8)
	redactions := make([]string, 0, 4)
	decisionChain := make([]string, 0, len(policies))

	for _, policy := range policies {
		rules := r.compiledRulesForDefinition(policy.Definition)
		if len(rules) == 0 {
			rules = r.compiledRulesForDefinition(r.compiledDefinitionForPolicy(runtimeapi.PolicyBundle{
				PolicyID:        "builtin-runtime-default",
				PolicyVersionID: "builtin-runtime-default-v1",
				Scope:           policy.Scope,
				Definition:      defaultDefinition(policy.Scope),
			}, runtimeapi.NormalizeStage(policy.Scope)))
		}
		// No-match fast path: try one combined alternation regex against
		// the input before iterating per-rule. RE2 treats `(p1)|(p2)|...`
		// as logical-OR, so a non-match here proves no individual rule can
		// match - we can skip the loop entirely. For clean traffic (the
		// 95%+ case on real workloads) this cuts the local-policy phase
		// from ~150ms (one FindAllString per rule) to ~3-5ms (a single
		// scan). Behaviour-preserving: when the union DOES match we fall
		// through to the per-rule loop so finding attribution, redactions,
		// and per-rule outcomes are identical to the un-optimized path.
		// Skipped when fast scanners are involved (those don't show up
		// in the union) or when a policy has none of `policy.Definition`
		// → rules came from the built-in defaults instead.
		if union := r.unionRegexForRules(policy.Definition, rules); union != nil {
			if !union.MatchString(target) {
				// Also need to skip if any rule uses a fast scanner - those
				// patterns may not match what the rule actually flags
				// (e.g. credit_card uses Luhn validation in addition to
				// regex). Defensive: only take the fast no-match path
				// when every rule routes through the regex path.
				anyFastScanner := false
				for _, rule := range rules {
					if fastScannerForCategory(rule.Category) != nil {
						anyFastScanner = true
						break
					}
				}
				if !anyFastScanner {
					decisionChain = append(decisionChain, fmt.Sprintf("%s evaluated via union fast-path (no match)", policy.Name))
					continue
				}
			}
		}
		for _, rule := range rules {
			// Fast-path: if a hand-tuned scanner exists for this rule's
			// category, run it instead of the regex DFA. The scanner walks
			// raw bytes and (for credit cards) applies Luhn validation, so
			// it's both faster and more precise than the regex alternative.
			// On any miss-config (e.g. unknown category), fall back to
			// regex so custom rules keep working unchanged.
			var matches []string
			if scanner := fastScannerForCategory(rule.Category); scanner != nil {
				if hits := scanner([]byte(target), nil); len(hits) > 0 {
					matches = make([]string, 0, len(hits))
					for _, h := range hits {
						matches = append(matches, target[h.Start:h.End])
					}
				}
			} else {
				matches = rule.Pattern.FindAllString(target, -1)
			}
			if len(matches) == 0 {
				continue
			}
			// Compose a match-aware summary so operators see *what*
			// triggered the block instead of the card's generic blurb.
			// Without this, a BFSI card that includes the destructive_shell
			// preset reports every match as "Finance workflow override or
			// payment data detected" - even on `rm -rf`. With this fix the
			// summary becomes e.g. "Finance workflow override … (matched
			// rm -rf in shell_exec)" so the operator immediately sees the
			// real cause.
			findings = append(findings, runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        rule.Category,
				Severity:        rule.Severity,
				Confidence:      0.84,
				Outcome:         normalizeOutcomeForPolicy(policy, normalizeOutcome(rule.Outcome)),
				Summary:         composeFindingSummary(rule.Summary, rule.Category, matches),
				Details: map[string]any{
					"matches": matches,
				},
			})
			decisionChain = append(decisionChain, fmt.Sprintf("%s matched %s", policy.Name, rule.Category))

			if normalizeOutcome(rule.Outcome) == "redact" {
				redactions = append(redactions, fmt.Sprintf("%s:%s", rule.Category, matches[0]))
				if request.Content.Input != "" {
					sanitizedInput = rule.Pattern.ReplaceAllString(sanitizedInput, "[REDACTED]")
				}
				if request.Content.Output != "" {
					sanitizedOutput = rule.Pattern.ReplaceAllString(sanitizedOutput, "[REDACTED]")
				}
			}
		}

		blockedDomains := toStringSlice(policy.Definition["blocked_domains"])
		if request.MCP != nil && len(blockedDomains) > 0 && len(request.MCP.Domains) > 0 {
			for _, blockedDomain := range blockedDomains {
				for _, domain := range request.MCP.Domains {
					if strings.EqualFold(strings.TrimSpace(domain), strings.TrimSpace(blockedDomain)) {
						findings = append(findings, runtimeapi.Finding{
							PolicyID:        policy.PolicyID,
							PolicyVersionID: policy.PolicyVersionID,
							Category:        "blocked_domain",
							Severity:        "high",
							Confidence:      0.95,
							Outcome:         normalizeOutcomeForPolicy(policy, "deny"),
							Summary:         fmt.Sprintf("Request domain %s is blocked by policy", domain),
							Details: map[string]any{
								"domain": domain,
							},
						})
						decisionChain = append(decisionChain, "blocked MCP destination domain")
					}
				}
			}
		}

		allowedActionClasses := toStringSlice(policy.Definition["allowed_action_classes"])
		if request.MCP != nil && len(allowedActionClasses) > 0 && !containsNormalizedValue(allowedActionClasses, request.MCP.ActionClass) {
			findings = append(findings, runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "action_scope",
				Severity:        "critical",
				Confidence:      0.96,
				Outcome:         normalizeOutcomeForPolicy(policy, "deny"),
				Summary:         fmt.Sprintf("Action class %s is outside the allowed MCP scope", request.MCP.ActionClass),
				Details: map[string]any{
					"allowed_action_classes": allowedActionClasses,
				},
			})
			decisionChain = append(decisionChain, "blocked MCP action class outside scope")
		}

		deniedActionClasses := toStringSlice(policy.Definition["denied_action_classes"])
		if request.MCP != nil && len(deniedActionClasses) > 0 && containsNormalizedValue(deniedActionClasses, request.MCP.ActionClass) {
			findings = append(findings, runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "denied_action_class",
				Severity:        "high",
				Confidence:      0.90,
				Outcome:         normalizeOutcomeForPolicy(policy, "deny"),
				Summary:         fmt.Sprintf("Action class %s is denied by policy", request.MCP.ActionClass),
				Details: map[string]any{
					"denied_action_classes": deniedActionClasses,
				},
			})
			decisionChain = append(decisionChain, "blocked MCP action class requiring manual review")
		}
	}
	return findings, redactions, sanitizedInput, sanitizedOutput, decisionChain
}

func (r *Runtime) prewarmTenantBundle(bundle runtimeapi.TenantBundle) {
	for _, policy := range bundle.Policies {
		stage := runtimeapi.NormalizeStage(policy.Scope)
		compiled := r.compiledDefinitionForPolicy(policy, stage)
		// Pre-compute and store the definition hash so that per-evaluation
		// compiledDefinitionRulesCacheKey avoids a full json.Marshal+SHA256.
		if _, ok := compiled[definitionHashKey]; !ok {
			if h := computeDefinitionHash(compiled); h != "" {
				compiled[definitionHashKey] = h
			}
		}
		_ = r.compiledRulesForDefinition(compiled)
	}
}

func (r *Runtime) compiledDefinitionForPolicy(policy runtimeapi.PolicyBundle, stage string) map[string]any {
	cacheKey := compiledPolicyCacheKey(policy, stage)
	if cacheKey != "" {
		r.mu.RLock()
		if compiled, ok := r.compiledDefs[cacheKey]; ok {
			r.mu.RUnlock()
			return compiled
		}
		r.mu.RUnlock()
	}

	compiled := cards.CompileDefinition(policy.Definition, runtimeapi.NormalizeStage(stage))
	if cacheKey == "" {
		return compiled
	}

	r.mu.Lock()
	if existing, ok := r.compiledDefs[cacheKey]; ok {
		r.mu.Unlock()
		return existing
	}
	r.compiledDefs[cacheKey] = compiled
	r.mu.Unlock()
	return compiled
}

func (r *Runtime) compiledRulesForDefinition(definition map[string]any) []compiledRule {
	cacheKey := compiledDefinitionRulesCacheKey(definition)
	if cacheKey != "" {
		r.mu.RLock()
		if rules, ok := r.compiledRules[cacheKey]; ok {
			r.mu.RUnlock()
			return rules
		}
		r.mu.RUnlock()
	}

	rules := compileRules(definition)
	if cacheKey == "" {
		return rules
	}

	r.mu.Lock()
	if existing, ok := r.compiledRules[cacheKey]; ok {
		r.mu.Unlock()
		return existing
	}
	r.compiledRules[cacheKey] = rules
	r.mu.Unlock()
	return rules
}

// ahoCorasickForRegexMatchChecks returns a cached Aho-Corasick automaton
// built from the required literal anchors of every regex_match check's
// pattern. Returns nil when ANY pattern in the set lacks a literal anchor
// - in that case the AC pre-filter is unsound and the caller must fall
// back to the union regex (which is always safe but ~3-10× slower than AC).
//
// Cached keyed identically to the union regex so the two share a
// life-cycle (rebuild on policy version roll).
func (r *Runtime) ahoCorasickForRegexMatchChecks(policy runtimeapi.PolicyBundle, checks []runtimeCheck) *ahoCorasickAutomaton {
	if len(checks) == 0 {
		return nil
	}
	cacheKey := compiledPolicyCacheKey(policy, runtimeapi.NormalizeStage(policy.Scope)) + ":ac"
	r.mu.RLock()
	if ac, ok := r.compiledRuleACs[cacheKey]; ok {
		r.mu.RUnlock()
		return ac
	}
	r.mu.RUnlock()
	literals := make([]string, 0, len(checks))
	for _, check := range checks {
		if check.Name != "regex_match" {
			continue
		}
		pattern := stringValue(check.Config, "rule", "pattern")
		if pattern == "" {
			continue
		}
		// A pattern can itself be an alternation (`a|b|c`) - pull every
		// branch's literal anchor. Empty result from a branch means the
		// pre-filter is unsound for this whole rule set; bail out and
		// cache nil so we don't pay the parse cost again.
		anchors := extractAllAlternativeLiterals(pattern)
		if len(anchors) == 0 {
			r.mu.Lock()
			r.compiledRuleACs[cacheKey] = nil
			r.mu.Unlock()
			return nil
		}
		literals = append(literals, anchors...)
	}
	if len(literals) == 0 {
		return nil
	}
	ac := buildAhoCorasick(literals)
	r.mu.Lock()
	if existing, ok := r.compiledRuleACs[cacheKey]; ok {
		r.mu.Unlock()
		return existing
	}
	r.compiledRuleACs[cacheKey] = ac
	r.mu.Unlock()
	return ac
}

// unionRegexForRegexMatchChecks returns a cached alternation of every
// regex_match check's pattern in a portkey-style policy definition. Used by
// evaluateRuntimeChecksWithRuntime to skip the per-check regex loop when
// the input couldn't possibly match any pattern. Cached by policy version
// + stage so the union is compiled once per policy roll, not per request.
func (r *Runtime) unionRegexForRegexMatchChecks(policy runtimeapi.PolicyBundle, checks []runtimeCheck) *regexp.Regexp {
	if len(checks) == 0 {
		return nil
	}
	cacheKey := compiledPolicyCacheKey(policy, runtimeapi.NormalizeStage(policy.Scope)) + ":portkey-union"
	r.mu.RLock()
	if union, ok := r.compiledRuleUnions[cacheKey]; ok {
		r.mu.RUnlock()
		return union
	}
	r.mu.RUnlock()
	parts := make([]string, 0, len(checks))
	for _, check := range checks {
		if check.Name != "regex_match" {
			continue
		}
		pattern := stringValue(check.Config, "rule", "pattern")
		if pattern == "" {
			continue
		}
		if _, err := cachedRegexpCompile(pattern); err != nil {
			// One bad pattern disables the fast path; the per-check loop
			// will surface the compile error in the decision chain.
			return nil
		}
		parts = append(parts, "(?:"+pattern+")")
	}
	if len(parts) == 0 {
		return nil
	}
	union, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil
	}
	r.mu.Lock()
	if existing, ok := r.compiledRuleUnions[cacheKey]; ok {
		r.mu.Unlock()
		return existing
	}
	r.compiledRuleUnions[cacheKey] = union
	r.mu.Unlock()
	return union
}

// unionRegexForRules returns a compiled alternation of every rule's pattern,
// used as a safe no-match fast-path in evaluateLocalPolicies: if this union
// doesn't match the input at all, no individual rule can match either, so
// we can return zero findings without paying the per-rule iteration cost.
//
// Behaviour is identical to running each rule individually - Go's regexp
// (RE2) treats `(p1)|(p2)|...` as logical-OR with no quirks around capture
// groups, greediness, or anchoring as long as every original pattern is
// wrapped in a non-capturing group. We do that wrapping below so a rule
// that uses backreferences or alternation internally can't bleed into a
// sibling rule.
//
// Cached alongside the per-rule list, keyed by the same definition hash,
// so a clean-traffic request only pays one MatchString call.
//
// Returns nil when there are 0 rules or any rule pattern fails to wrap
// (defensive: a nil pattern here just disables the fast path; full
// per-rule evaluation still runs).
func (r *Runtime) unionRegexForRules(definition map[string]any, rules []compiledRule) *regexp.Regexp {
	if len(rules) == 0 {
		return nil
	}
	cacheKey := compiledDefinitionRulesCacheKey(definition)
	if cacheKey != "" {
		r.mu.RLock()
		if union, ok := r.compiledRuleUnions[cacheKey]; ok {
			r.mu.RUnlock()
			return union
		}
		r.mu.RUnlock()
	}
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Pattern == nil {
			continue
		}
		// Wrap each in a non-capturing group so internal alternation stays
		// scoped. Don't reuse the cached compiled object - we need the source
		// string. regexp.Regexp.String() is the canonical form.
		parts = append(parts, "(?:"+rule.Pattern.String()+")")
	}
	if len(parts) == 0 {
		return nil
	}
	union, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		// Shouldn't happen if each rule compiled, but be safe.
		return nil
	}
	if cacheKey == "" {
		return union
	}
	r.mu.Lock()
	if existing, ok := r.compiledRuleUnions[cacheKey]; ok {
		r.mu.Unlock()
		return existing
	}
	r.compiledRuleUnions[cacheKey] = union
	r.mu.Unlock()
	return union
}

func compiledPolicyCacheKey(policy runtimeapi.PolicyBundle, stage string) string {
	stage = runtimeapi.NormalizeStage(stage)
	if strings.TrimSpace(policy.PolicyVersionID) != "" {
		return strings.TrimSpace(policy.PolicyVersionID) + ":" + stage
	}
	if strings.TrimSpace(policy.PolicyID) == "builtin-runtime-default" {
		return "builtin-runtime-default-v1:" + stage
	}
	return ""
}

// definitionHashKey is the well-known key used to store a pre-computed hash
// inside a compiled definition map, avoiding repeated json.Marshal+SHA256 on
// every evaluation.  The key is set during prewarmTenantBundle and consumed by
// compiledDefinitionRulesCacheKey.
const definitionHashKey = "__definition_hash__"

func computeDefinitionHash(definition map[string]any) string {
	if len(definition) == 0 {
		return ""
	}
	raw, err := json.Marshal(definition)
	if err != nil || len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func compiledDefinitionRulesCacheKey(definition map[string]any) string {
	if len(definition) == 0 {
		return ""
	}
	// Fast path: use pre-computed hash set during prewarm.
	if h, ok := definition[definitionHashKey].(string); ok && h != "" {
		return h
	}
	return computeDefinitionHash(definition)
}

func evaluateMCPToolPolicies(policies []runtimeapi.MCPToolPolicy, request runtimeapi.EvaluateRequest) ([]runtimeapi.Finding, []string) {
	if request.MCP == nil || len(policies) == 0 {
		return nil, nil
	}
	findings := make([]runtimeapi.Finding, 0, 4)
	chain := make([]string, 0, 4)
	for _, policy := range policies {
		if !matchesToolPolicy(policy, request) {
			continue
		}
		if len(policy.AllowedIdentities) > 0 && !containsNormalizedValue(policy.AllowedIdentities, request.Actor.ID) {
			findings = append(findings, runtimeapi.Finding{
				PolicyID:   policy.PolicyID,
				Category:   "identity_scope",
				Severity:   "critical",
				Confidence: 0.97,
				Outcome:    normalizeOutcomeForPolicy(runtimeapi.PolicyBundle{EnforcementMode: "block"}, "deny"),
				Summary:    fmt.Sprintf("Actor %s is not allowed to execute tool %s", request.Actor.ID, request.MCP.ToolName),
				Details: map[string]any{
					"allowed_identities": policy.AllowedIdentities,
				},
			})
			chain = append(chain, "blocked MCP tool execution by identity scope")
		}
		if len(policy.AllowedDomains) > 0 && len(request.MCP.Domains) > 0 {
			for _, domain := range request.MCP.Domains {
				if !containsNormalizedValue(policy.AllowedDomains, domain) {
					findings = append(findings, runtimeapi.Finding{
						PolicyID:   policy.PolicyID,
						Category:   "domain_scope",
						Severity:   "high",
						Confidence: 0.94,
						Outcome:    normalizeOutcomeForPolicy(runtimeapi.PolicyBundle{EnforcementMode: "block"}, "deny"),
						Summary:    fmt.Sprintf("Domain %s is outside the allowed MCP domain scope", domain),
						Details: map[string]any{
							"allowed_domains": policy.AllowedDomains,
						},
					})
					chain = append(chain, "blocked MCP destination outside allowed domains")
				}
			}
		}
		if policy.ApprovalNeeded {
			findings = append(findings, runtimeapi.Finding{
				PolicyID:   policy.PolicyID,
				Category:   "restricted_action_class",
				Severity:   "high",
				Confidence: 0.91,
				Outcome:    normalizeOutcomeForPolicy(runtimeapi.PolicyBundle{EnforcementMode: "block"}, "deny"),
				Summary:    fmt.Sprintf("Tool %s is blocked for restricted action class %s", request.MCP.ToolName, request.MCP.ActionClass),
				Details: map[string]any{
					"server_label": policy.ServerLabel,
					"tool_name":    policy.ToolName,
					"action_class": policy.ActionClass,
				},
			})
			chain = append(chain, "MCP tool policy blocked a restricted action class")
		}
	}
	return findings, chain
}

func matchesToolPolicy(policy runtimeapi.MCPToolPolicy, request runtimeapi.EvaluateRequest) bool {
	if request.MCP == nil {
		return false
	}
	if strings.TrimSpace(policy.ServerLabel) != "" && !strings.EqualFold(strings.TrimSpace(policy.ServerLabel), strings.TrimSpace(request.MCP.ServerLabel)) {
		return false
	}
	if strings.TrimSpace(policy.ToolName) != "" && !strings.EqualFold(strings.TrimSpace(policy.ToolName), strings.TrimSpace(request.MCP.ToolName)) {
		return false
	}
	if strings.TrimSpace(policy.ActionClass) != "" && !strings.EqualFold(strings.TrimSpace(policy.ActionClass), strings.TrimSpace(request.MCP.ActionClass)) {
		return false
	}
	return true
}

func (r *Runtime) evaluateProviderBindings(ctx context.Context, bundle runtimeapi.TenantBundle, policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest) ([]runtimeapi.Finding, []string) {
	providersByID := make(map[string]runtimeapi.ProviderConfig, len(bundle.Providers))
	for _, provider := range bundle.Providers {
		if provider.Enabled {
			providersByID[provider.ID] = provider
		}
	}
	type task struct {
		policy   runtimeapi.PolicyBundle
		binding  runtimeapi.PolicyProviderBinding
		provider runtimeapi.ProviderConfig
	}
	tasks := make([]task, 0, len(policies))
	for _, policy := range policies {
		for _, binding := range policy.ProviderBindings {
			if !binding.Enabled {
				continue
			}
			if binding.Stage != "" && runtimeapi.NormalizeStage(binding.Stage) != runtimeapi.NormalizeStage(request.Stage) {
				continue
			}
			provider, ok := providersByID[binding.ProviderID]
			if !ok {
				continue
			}
			tasks = append(tasks, task{policy: policy, binding: binding, provider: provider})
		}
	}
	if len(tasks) == 0 {
		return nil, nil
	}
	sort.SliceStable(tasks, func(i, j int) bool {
		return tasks[i].binding.Priority < tasks[j].binding.Priority
	})

	type result struct {
		findings []runtimeapi.Finding
		chain    []string
	}
	results := make(chan result, len(tasks))
	var wg sync.WaitGroup
	for _, task := range tasks {
		task := task
		adapter, ok := r.adapters[strings.TrimSpace(task.provider.ProviderType)]
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			timeout := r.resolveTimeout(task.policy)
			evalCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			adapterFindings, err := adapter.Evaluate(evalCtx, providerspkg.Request{
				TenantID:       request.TenantID,
				Stage:          request.Stage,
				Model:          request.Model,
				Provider:       request.Provider,
				Content:        pickContent(request),
				Actor:          request.Actor,
				MCP:            request.MCP,
				ProviderConfig: task.provider,
				Policy:         task.policy,
				Metadata:       request.Metadata,
			})
			if err != nil {
				results <- result{chain: []string{fmt.Sprintf("provider %s evaluation failed: %v", task.provider.Name, err)}}
				return
			}
			findings := make([]runtimeapi.Finding, 0, len(adapterFindings))
			for _, finding := range adapterFindings {
				findings = append(findings, runtimeapi.Finding{
					PolicyID:        task.policy.PolicyID,
					PolicyVersionID: task.policy.PolicyVersionID,
					ProviderID:      task.provider.ID,
					ProviderType:    task.provider.ProviderType,
					Category:        finding.Category,
					Severity:        normalizeSeverity(finding.Severity),
					Confidence:      finding.Confidence,
					Outcome:         normalizeOutcomeForPolicy(task.policy, finding.Outcome),
					Summary:         finding.Summary,
					Details:         finding.Details,
				})
			}
			results <- result{
				findings: findings,
				chain:    []string{fmt.Sprintf("provider %s evaluated %d finding(s)", task.provider.Name, len(findings))},
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	allFindings := make([]runtimeapi.Finding, 0, len(tasks))
	decisionChain := make([]string, 0, len(tasks))
	for result := range results {
		allFindings = append(allFindings, result.findings...)
		decisionChain = append(decisionChain, result.chain...)
	}
	return allFindings, decisionChain
}

func defaultDefinition(_ string) map[string]any {
	inputChecks := []map[string]any{
		{
			"name":     "regex_match",
			"enabled":  true,
			"priority": 10,
			"config": map[string]any{
				"rule":     `(?i)(ignore previous instructions|reveal system prompt|developer mode|jailbreak|bypass safety|override policy)`,
				"severity": "high",
				"summary":  "Prompt injection or jailbreak attempt detected",
			},
			"action": map[string]any{"on_fail": "deny"},
		},
		{
			"name":     "detect_pii",
			"enabled":  true,
			"priority": 20,
			"config": map[string]any{
				"categories": []string{"email", "phone", "ssn", "credit_card"},
				"severity":   "high",
			},
			"action": map[string]any{"on_fail": "deny"},
		},
		{
			"name":     "detect_gibberish",
			"enabled":  true,
			"priority": 30,
			"config":   map[string]any{"severity": "medium"},
			"action":   map[string]any{"on_fail": "deny"},
		},
	}
	outputChecks := []map[string]any{
		{
			"name":     "detect_pii",
			"enabled":  true,
			"priority": 10,
			"config": map[string]any{
				"categories": []string{"email", "phone", "ssn", "credit_card"},
				"severity":   "high",
			},
			"action": map[string]any{"on_fail": "deny"},
		},
		{
			"name":     "regex_match",
			"enabled":  true,
			"priority": 20,
			"config": map[string]any{
				"rule":     `(?i)(guaranteed cure|certain outcome|no evidence needed)`,
				"severity": "medium",
				"summary":  "Potentially unsafe unsupported claim detected",
			},
			"action": map[string]any{"on_fail": "redact"},
		},
	}

	definition := map[string]any{
		"input_guardrails":       inputChecks,
		"output_guardrails":      outputChecks,
		"blocked_domains":        []string{"pastebin.com", "ngrok.io", "example-malware.test"},
		"allowed_action_classes": []string{"read", "write", "network", "destructive", "exec"},
		"denied_action_classes":  []string{"destructive", "exec"},
	}
	return definition
}

func compileRules(definition map[string]any) []compiledRule {
	rawRules, ok := definition["rules"]
	if !ok {
		return nil
	}
	rawSlice, ok := rawRules.([]any)
	if !ok {
		return nil
	}

	rules := make([]compiledRule, 0, len(rawSlice))
	for _, item := range rawSlice {
		ruleMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pattern := strings.TrimSpace(fmt.Sprintf("%v", ruleMap["pattern"]))
		if pattern == "" {
			continue
		}
		compiled, err := cachedRegexpCompile(pattern)
		if err != nil {
			continue
		}
		rules = append(rules, compiledRule{
			Category: strings.TrimSpace(fmt.Sprintf("%v", ruleMap["category"])),
			Pattern:  compiled,
			Severity: normalizeSeverity(fmt.Sprintf("%v", ruleMap["severity"])),
			Outcome:  normalizeOutcome(fmt.Sprintf("%v", ruleMap["outcome"])),
			Summary:  strings.TrimSpace(fmt.Sprintf("%v", ruleMap["summary"])),
		})
	}
	return rules
}

func pickContent(request runtimeapi.EvaluateRequest) string {
	switch runtimeapi.NormalizeStage(request.Stage) {
	case runtimeapi.StageOutput:
		if strings.TrimSpace(request.Content.Output) != "" {
			return request.Content.Output
		}
	case runtimeapi.StageAction, runtimeapi.StageMCP:
		if strings.TrimSpace(request.Content.ToolInput) != "" {
			return request.Content.ToolInput
		}
	}
	if strings.TrimSpace(request.Content.Input) != "" {
		return request.Content.Input
	}
	if strings.TrimSpace(request.Content.Output) != "" {
		return request.Content.Output
	}
	return request.Content.ToolInput
}

// hasGatingDeny reports whether any of the given findings carries a
// terminal block outcome (deny / sandbox). Used by Runtime.Evaluate to
// short-circuit the slow provider-binding paths when a fast in-process
// regex / card / preset check has already determined the response will
// be blocked - paying the wrapper sidecar RTT past that point only
// inflates guard ms for no gating benefit.
func hasGatingDeny(findings []runtimeapi.Finding) bool {
	for _, finding := range findings {
		switch normalizeOutcome(finding.Outcome) {
		case "deny", "sandbox":
			return true
		}
	}
	return false
}

func resolveDecision(findings []runtimeapi.Finding, redactions []string) (string, bool, string) {
	decision := "allow"
	reason := "No guardrail violations detected"
	approvalRequired := false
	severityRank := map[string]int{
		"allow":   0,
		"redact":  1,
		"sandbox": 2,
		"deny":    3,
	}
	bestRank := 0
	bestSummary := ""

	for _, finding := range findings {
		outcome := normalizeOutcome(finding.Outcome)
		rank := severityRank[outcome]
		if rank > bestRank {
			bestRank = rank
			bestSummary = finding.Summary
		}
	}

	switch bestRank {
	case severityRank["deny"]:
		decision = "deny"
		reason = bestSummary
	case severityRank["sandbox"]:
		decision = "sandbox"
		reason = bestSummary
	case severityRank["redact"]:
		decision = "allow_with_redaction"
		reason = bestSummary
	default:
		if len(redactions) > 0 {
			decision = "allow_with_redaction"
			reason = "Content was sanitized by runtime redaction rules"
		}
	}
	return decision, approvalRequired, reason
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func normalizeOutcome(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "block", "deny":
		return "deny"
	case "approval", "human_approval", "review":
		return "deny"
	case "sandbox":
		return "sandbox"
	case "redact", "allow_with_redaction":
		return "redact"
	default:
		return "allow"
	}
}

func normalizeOutcomeForPolicy(policy runtimeapi.PolicyBundle, outcome string) string {
	outcome = normalizeOutcome(outcome)
	if strings.EqualFold(strings.TrimSpace(policy.EnforcementMode), "approval") {
		policy.EnforcementMode = "block"
	}
	if strings.EqualFold(strings.TrimSpace(policy.EnforcementMode), "monitor") {
		return "allow"
	}
	return outcome
}

func policyAppliesToStage(policy runtimeapi.PolicyBundle, stage string) bool {
	normalizedStage := runtimeapi.NormalizeStage(stage)
	for _, scope := range policyScopes(policy) {
		if scope == normalizedStage {
			return true
		}
	}
	return false
}

func policyScopes(policy runtimeapi.PolicyBundle) []string {
	if len(policy.Metadata) > 0 {
		if rawScopes, ok := policy.Metadata["scopes"]; ok {
			scopes := make([]string, 0, 4)
			for _, scope := range toStringSlice(rawScopes) {
				normalized := runtimeapi.NormalizeStage(scope)
				if !containsNormalizedValue(scopes, normalized) {
					scopes = append(scopes, normalized)
				}
			}
			if len(scopes) > 0 {
				return scopes
			}
		}
	}
	return []string{runtimeapi.NormalizeStage(policy.Scope)}
}

func toStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return dedupeNonEmptyStrings(typed...)
	case string:
		return dedupeNonEmptyStrings(typed)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			trimmed := strings.TrimSpace(fmt.Sprintf("%v", item))
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return dedupeNonEmptyStrings(result...)
	default:
		return nil
	}
}

func containsNormalizedValue(values []string, candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func dedupeNonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func numericValue(raw any) (int, bool) {
	switch typed := raw.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float32:
		return int(typed), true
	case float64:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
