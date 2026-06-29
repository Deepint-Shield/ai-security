package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	regexp "github.com/grafana/regexp"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type runtimeCheck struct {
	Name        string
	Enabled     bool
	Priority    int
	Config      map[string]any
	Action      map[string]any
	fingerprint string // pre-computed during extraction to avoid per-evaluation json.Marshal
}

type runtimeCheckResult struct {
	Triggered        bool
	Summary          string
	Details          map[string]any
	SanitizedInput   string
	SanitizedOutput  string
	OverrideOutcome  string
	OverrideSeverity string
	Confidence       float64
}

// sharedRuntimeChecksHTTPClient is reused across all portkey webhook evaluations to
// benefit from connection pooling and keep-alive. Per-request timeouts are
// applied via context.WithTimeout instead of a client-level timeout.
var sharedRuntimeChecksHTTPClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// newRuntimeChecksHTTPClient is a test seam. In production it returns the shared
// pooled client. Tests can swap it to inject a mock transport.
var newRuntimeChecksHTTPClient = func(_ time.Duration) *http.Client {
	return sharedRuntimeChecksHTTPClient
}

// maxConcurrentWebhooks limits the number of webhook checks that run in parallel.
const maxConcurrentWebhooks = 8

// webhookCheckResult captures the output of a single concurrent webhook check
// along with its originating policy and check metadata.
type webhookCheckResult struct {
	policy runtimeapi.PolicyBundle
	check  runtimeCheck
	result *runtimeCheckResult
	err    error
}

func evaluateRuntimeCheckPolicies(ctx context.Context, timeout time.Duration, policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest) ([]runtimeapi.Finding, []string, string, string, []string) {
	return evaluateRuntimeChecksWithRuntime(ctx, nil, timeout, policies, request)
}

// evaluateRuntimeChecksWithRuntime is the runtime-aware variant that uses
// per-policy union-regex caching to avoid re-running every regex_match check
// when the combined input couldn't possibly match any of them. The non-runtime
// shim above is kept for tests that build policies inline.
func evaluateRuntimeChecksWithRuntime(ctx context.Context, r *Runtime, timeout time.Duration, policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest) ([]runtimeapi.Finding, []string, string, string, []string) {
	sanitizedInput := request.Content.Input
	sanitizedOutput := request.Content.Output
	findings := make([]runtimeapi.Finding, 0, 8)
	redactions := make([]string, 0, 4)
	chain := make([]string, 0, len(policies))
	seenChecks := make(map[string]struct{}, 16)
	// regexMatchCache memoises the FindAllString result for each unique
	// regex pattern within this request, so a pattern shared by multiple
	// checks (e.g. one card emits regex_match→deny and another emits
	// regex_match→redact for the SAME pattern) only runs the DFA scan
	// once. Cache keyed by the raw pattern string - compile already
	// runs through cachedRegexpCompile, so this layers on top to skip
	// the scan itself. Cleared per request (no cross-request sharing -
	// the input content differs).
	regexMatchCache := make(map[string][]string, 8)

	// Separate checks into local (CPU-bound, microseconds) and webhook (network-bound).
	type taggedCheck struct {
		policy runtimeapi.PolicyBundle
		check  runtimeCheck
	}
	var webhookChecks []taggedCheck

	for _, policy := range policies {
		checks := extractRuntimeChecks(policy.Definition, request.Stage)
		if len(checks) == 0 {
			continue
		}
		// No-match fast path for regex_match checks. dev_policy and similar
		// card-based policies emit one regex_match check per OWASP card -
		// historically that meant N FindAllString calls for clean traffic,
		// ~150ms total. Build a single alternation regex of every pattern
		// once per policy version (cached in Runtime), and skip the
		// regex_match subloop when it doesn't match. Behaviour-preserving:
		// non-regex checks (PII, word count, etc.) still run individually.
		var skipRegexMatch bool
		if r != nil {
			// Two-stage no-match fast path:
			//   1. Aho-Corasick over required literal anchors (~1-3 µs,
			//      linear in input length) - fires only when every pattern
			//      has an extractable literal.
			//   2. RE2 union alternation regex (~5-20 µs, fallback when AC
			//      is unsound for the rule set or to confirm a literal hit
			//      is also a regex hit).
			// Each layer is behaviour-preserving: a no-match here means no
			// individual regex_match check can match either.
			target := pickContent(request)
			if ac := r.ahoCorasickForRegexMatchChecks(policy, checks); ac != nil {
				if !ac.matches(strings.ToLower(target)) {
					skipRegexMatch = true
				}
			}
			if !skipRegexMatch {
				if union := r.unionRegexForRegexMatchChecks(policy, checks); union != nil {
					if !union.MatchString(target) {
						skipRegexMatch = true
					}
				}
			}
		}
		for _, check := range checks {
			fingerprint := runtimeCheckFingerprint(policy.EnforcementMode, check)
			if _, seen := seenChecks[fingerprint]; seen {
				continue
			}
			seenChecks[fingerprint] = struct{}{}

			// Defer webhook checks for concurrent execution.
			if check.Name == "webhook" {
				webhookChecks = append(webhookChecks, taggedCheck{policy: policy, check: check})
				continue
			}
			// Skip regex_match checks when the union pre-screen proved
			// no individual pattern can match - saves up to ~150ms on
			// clean allow traffic without changing any verdict.
			if skipRegexMatch && check.Name == "regex_match" {
				continue
			}

			// Local checks run serially - they're fast (regex, contains, PII, etc.).
			// regex_match checks route through the per-request cache so a
			// pattern shared by multiple checks runs its DFA scan once.
			var (
				result *runtimeCheckResult
				err    error
			)
			if check.Name == "regex_match" {
				result, err = evaluateRegexCheckCached(check, request, regexMatchCache)
			} else {
				result, err = executeRuntimeCheck(ctx, nil, check, request)
			}
			if err != nil {
				chain = append(chain, fmt.Sprintf("guardrail check %s failed: %v", check.Name, err))
				continue
			}
			applyRuntimeCheckResult(policy, check, result, request.Stage,
				&findings, &redactions, &chain, &sanitizedInput, &sanitizedOutput)
		}
	}

	// Run all webhook checks concurrently with a bounded semaphore.
	if len(webhookChecks) > 0 {
		httpClient := newRuntimeChecksHTTPClient(timeout)
		results := make([]webhookCheckResult, len(webhookChecks))
		sem := make(chan struct{}, maxConcurrentWebhooks)
		var wg sync.WaitGroup
		for i, tc := range webhookChecks {
			wg.Add(1)
			go func(idx int, tc taggedCheck) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				webhookCtx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				result, err := evaluateWebhookCheck(webhookCtx, httpClient, tc.check, request)
				results[idx] = webhookCheckResult{policy: tc.policy, check: tc.check, result: result, err: err}
			}(i, tc)
		}
		wg.Wait()

		// Merge webhook results in original priority order (deterministic).
		for _, wr := range results {
			if wr.err != nil {
				chain = append(chain, fmt.Sprintf("guardrail check %s failed: %v", wr.check.Name, wr.err))
				continue
			}
			applyRuntimeCheckResult(wr.policy, wr.check, wr.result, request.Stage,
				&findings, &redactions, &chain, &sanitizedInput, &sanitizedOutput)
		}
	}

	return findings, redactions, sanitizedInput, sanitizedOutput, chain
}

// applyRuntimeCheckResult processes a single check result into the shared findings/redactions/chain slices.
func applyRuntimeCheckResult(
	policy runtimeapi.PolicyBundle, check runtimeCheck, result *runtimeCheckResult, stage string,
	findings *[]runtimeapi.Finding, redactions *[]string, chain *[]string,
	sanitizedInput, sanitizedOutput *string,
) {
	if !result.Triggered {
		if successFeedback := extractActionFeedback(check.Action, "on_success_message", "success_message"); successFeedback != "" {
			*sanitizedInput, *sanitizedOutput = applyPortkeyFeedback(stage, *sanitizedInput, *sanitizedOutput, successFeedback)
		}
		return
	}

	outcome, asyncMode, passThrough := resolvePortkeyAction(policy, check, result.OverrideOutcome)
	if asyncMode || passThrough || strings.EqualFold(policy.EnforcementMode, "monitor") {
		outcome = "allow"
	}
	severity := normalizeSeverity(result.OverrideSeverity)
	if severity == "" {
		severity = normalizeSeverity(stringValue(check.Config, "severity"))
	}
	if severity == "" {
		severity = "medium"
	}
	confidence := result.Confidence
	if confidence <= 0 {
		confidence = 0.9
	}
	summary := strings.TrimSpace(result.Summary)
	if summary == "" {
		summary = fmt.Sprintf("Guardrail check %s failed", check.Name)
	}
	details := cloneMap(result.Details)
	if details == nil {
		details = map[string]any{}
	}
	details["check_name"] = check.Name
	if asyncMode {
		details["async"] = true
	}
	if passThrough {
		details["pass_through"] = true
	}

	feedback := extractActionFeedback(check.Action, "feedback", "on_fail_message", "failure_message")
	nextInput := *sanitizedInput
	nextOutput := *sanitizedOutput
	if strings.TrimSpace(result.SanitizedInput) != "" {
		nextInput = result.SanitizedInput
		details["sanitized_input"] = result.SanitizedInput
	}
	if strings.TrimSpace(result.SanitizedOutput) != "" {
		nextOutput = result.SanitizedOutput
		details["sanitized_output"] = result.SanitizedOutput
	}
	if feedback != "" {
		nextInput, nextOutput = applyPortkeyFeedback(stage, nextInput, nextOutput, feedback)
		details["feedback"] = feedback
	}

	*findings = append(*findings, runtimeapi.Finding{
		PolicyID:        policy.PolicyID,
		PolicyVersionID: policy.PolicyVersionID,
		Category:        normalizeCheckCategory(check.Name),
		Severity:        severity,
		Confidence:      confidence,
		Outcome:         outcome,
		Summary:         summary,
		Details:         details,
	})
	*chain = append(*chain, fmt.Sprintf("%s:%s failed", policy.Name, check.Name))
	if outcome == "redact" {
		*redactions = append(*redactions, fmt.Sprintf("%s:%s", check.Name, summary))
	}
	*sanitizedInput = nextInput
	*sanitizedOutput = nextOutput
}

// runtimeCheckFingerprint returns a deduplication key for the given check within
// a policy enforcement mode. Uses the pre-computed fingerprint on the check
// struct (set during extractRuntimeChecks) to avoid repeated json.Marshal calls.
func runtimeCheckFingerprint(enforcementMode string, check runtimeCheck) string {
	if check.fingerprint != "" {
		return strings.ToLower(strings.TrimSpace(enforcementMode)) + "::" + check.fingerprint
	}
	configJSON, _ := json.Marshal(check.Config)
	actionJSON, _ := json.Marshal(check.Action)
	return strings.ToLower(strings.TrimSpace(check.Name)) + "::" +
		strings.ToLower(strings.TrimSpace(enforcementMode)) + "::" +
		string(configJSON) + "::" +
		string(actionJSON)
}

func extractRuntimeChecks(definition map[string]any, stage string) []runtimeCheck {
	stage = runtimeapi.NormalizeStage(stage)
	keys := []string{"input_guardrails"}
	switch stage {
	case runtimeapi.StageOutput:
		keys = []string{"output_guardrails", "after_request_hooks"}
	default:
		keys = []string{"input_guardrails", "before_request_hooks"}
	}
	checks := make([]runtimeCheck, 0, 8)
	for _, key := range keys {
		raw := definition[key]
		items, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, item := range items {
			checkMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(stringValue(checkMap, "name", "check", "type")))
			if name == "" {
				continue
			}
			config := mapValue(checkMap, "config")
			action := mapValue(checkMap, "action")
			configJSON, _ := json.Marshal(config)
			actionJSON, _ := json.Marshal(action)
			check := runtimeCheck{
				Name:        name,
				Enabled:     boolValue(checkMap, "enabled", true),
				Priority:    intValue(checkMap, "priority", 100),
				Config:      config,
				Action:      action,
				fingerprint: name + "::" + string(configJSON) + "::" + string(actionJSON),
			}
			if !check.Enabled {
				continue
			}
			checks = append(checks, check)
		}
	}
	sort.SliceStable(checks, func(i, j int) bool {
		return checks[i].Priority < checks[j].Priority
	})
	return checks
}

func executeRuntimeCheck(ctx context.Context, httpClient *http.Client, check runtimeCheck, request runtimeapi.EvaluateRequest) (*runtimeCheckResult, error) {
	switch check.Name {
	case "regex_match":
		return evaluateRegexCheck(check, request)
	case "sentence_count":
		return evaluateSentenceCountCheck(check, request), nil
	case "word_count":
		return evaluateWordCountCheck(check, request), nil
	case "character_count":
		return evaluateCharacterCountCheck(check, request), nil
	case "json_schema":
		return evaluateJSONSchemaCheck(check, request)
	case "json_keys":
		return evaluateJSONKeysCheck(check, request)
	case "contains":
		return evaluateContainsCheck(check, request), nil
	case "valid_urls":
		return evaluateValidURLsCheck(check, request), nil
	case "contains_code":
		return evaluateContainsCodeCheck(check, request), nil
	case "lowercase_detection":
		return evaluateLowercaseCheck(check, request), nil
	case "ends_with":
		return evaluateEndsWithCheck(check, request), nil
	case "model_whitelist":
		return evaluateModelWhitelistCheck(check, request), nil
	case "detect_pii":
		return evaluatePIICheck(check, request), nil
	case "detect_gibberish":
		return evaluateGibberishCheck(check, request), nil
	case "webhook":
		return evaluateWebhookCheck(ctx, httpClient, check, request)
	default:
		return &runtimeCheckResult{Triggered: false}, nil
	}
}

func evaluateRegexCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) (*runtimeCheckResult, error) {
	return evaluateRegexCheckCached(check, request, nil)
}

// evaluateRegexCheckCached is the per-pattern memoising variant. When matchCache
// is non-nil, the FindAllString result for the rule string is looked up + stored
// there so checks that share the same pattern across different cards/policies
// don't re-scan the input. The redaction step still runs per-check (it depends
// on check.Action, which differs between e.g. deny / redact configurations
// over the same pattern), but the dominant DFA scan cost runs exactly once
// per unique pattern per request.
func evaluateRegexCheckCached(check runtimeCheck, request runtimeapi.EvaluateRequest, matchCache map[string][]string) (*runtimeCheckResult, error) {
	rule := stringValue(check.Config, "rule", "pattern")
	if rule == "" {
		return &runtimeCheckResult{}, nil
	}
	compiled, err := cachedRegexpCompile(rule)
	if err != nil {
		return nil, err
	}
	target := pickContent(request)
	var matches []string
	if matchCache != nil {
		if cached, ok := matchCache[rule]; ok {
			matches = cached
		} else {
			matches = compiled.FindAllString(target, -1)
			matchCache[rule] = matches
		}
	} else {
		matches = compiled.FindAllString(target, -1)
	}
	if len(matches) == 0 {
		return &runtimeCheckResult{}, nil
	}
	redacted := compiled.ReplaceAllString(target, redactWith(check.Action))
	return &runtimeCheckResult{
		Triggered:       true,
		Summary:         stringValue(check.Config, "summary", "message"),
		Confidence:      0.95,
		SanitizedInput:  chooseSanitizedInput(request, redacted),
		SanitizedOutput: chooseSanitizedOutput(request, redacted),
		Details: map[string]any{
			"matches": matches,
			"rule":    rule,
		},
	}, nil
}

func evaluateSentenceCountCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	count := sentenceCount(target)
	min := intValue(check.Config, "minSentences", -1)
	max := intValue(check.Config, "maxSentences", -1)
	if !outsideRange(count, min, max) {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    fmt.Sprintf("Sentence count %d violated the configured range", count),
		Details: map[string]any{
			"sentence_count": count,
			"min":            min,
			"max":            max,
		},
	}
}

func evaluateWordCountCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	count := len(strings.Fields(target))
	min := intValue(check.Config, "minWords", -1)
	max := intValue(check.Config, "maxWords", -1)
	if !outsideRange(count, min, max) {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    fmt.Sprintf("Word count %d violated the configured range", count),
		Details: map[string]any{
			"word_count": count,
			"min":        min,
			"max":        max,
		},
	}
}

func evaluateCharacterCountCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	count := len([]rune(target))
	min := intValue(check.Config, "minCharacters", -1)
	max := intValue(check.Config, "maxCharacters", -1)
	if !outsideRange(count, min, max) {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    fmt.Sprintf("Character count %d violated the configured range", count),
		Details: map[string]any{
			"character_count": count,
			"min":             min,
			"max":             max,
		},
	}
}

func evaluateJSONSchemaCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) (*runtimeCheckResult, error) {
	target := strings.TrimSpace(pickContent(request))
	if target == "" {
		return &runtimeCheckResult{}, nil
	}
	schemaValue, ok := check.Config["schema"]
	if !ok || schemaValue == nil {
		return &runtimeCheckResult{}, nil
	}
	schemaRaw, err := json.Marshal(schemaValue)
	if err != nil {
		return nil, err
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("inline.json", schemaDoc); err != nil {
		return nil, err
	}
	compiled, err := compiler.Compile("inline.json")
	if err != nil {
		return nil, err
	}
	var payload any
	if err := json.Unmarshal([]byte(target), &payload); err != nil {
		return &runtimeCheckResult{
			Triggered:  true,
			Confidence: 0.95,
			Summary:    "Response is not valid JSON",
			Details: map[string]any{
				"error": err.Error(),
			},
		}, nil
	}
	if err := compiled.Validate(payload); err != nil {
		return &runtimeCheckResult{
			Triggered:  true,
			Confidence: 0.95,
			Summary:    "Response JSON does not match the configured schema",
			Details: map[string]any{
				"error": err.Error(),
			},
		}, nil
	}
	return &runtimeCheckResult{}, nil
}

func evaluateJSONKeysCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) (*runtimeCheckResult, error) {
	target := strings.TrimSpace(pickContent(request))
	if target == "" {
		return &runtimeCheckResult{}, nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(target), &payload); err != nil {
		return &runtimeCheckResult{
			Triggered:  true,
			Confidence: 0.95,
			Summary:    "Response is not valid JSON",
			Details: map[string]any{
				"error": err.Error(),
			},
		}, nil
	}
	keys := stringSlice(check.Config["keys"])
	if len(keys) == 0 {
		return &runtimeCheckResult{}, nil
	}
	operator := strings.ToLower(strings.TrimSpace(stringValue(check.Config, "operator")))
	matched := 0
	for _, key := range keys {
		if _, ok := payload[key]; ok {
			matched++
		}
	}
	triggered := false
	switch operator {
	case "all":
		triggered = matched != len(keys)
	case "none":
		triggered = matched > 0
	default:
		triggered = matched == 0
	}
	if !triggered {
		return &runtimeCheckResult{}, nil
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    fmt.Sprintf("JSON keys check failed with operator %s", defaultString(operator, "any")),
		Details: map[string]any{
			"keys":     keys,
			"matched":  matched,
			"operator": defaultString(operator, "any"),
		},
	}, nil
}

func evaluateContainsCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	words := stringSlice(check.Config["words"])
	if len(words) == 0 {
		return &runtimeCheckResult{}
	}
	operator := strings.ToLower(strings.TrimSpace(stringValue(check.Config, "operator")))
	normalizedTarget := strings.ToLower(target)
	matched := make([]string, 0, len(words))
	for _, word := range words {
		if strings.Contains(normalizedTarget, strings.ToLower(word)) {
			matched = append(matched, word)
		}
	}
	triggered := false
	switch operator {
	case "all":
		triggered = len(matched) != len(words)
	case "none":
		triggered = len(matched) > 0
	default:
		triggered = len(matched) == 0
	}
	if !triggered {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.88,
		Summary:    "Contains check failed",
		Details: map[string]any{
			"words":    words,
			"matched":  matched,
			"operator": defaultString(operator, "any"),
		},
	}
}

func evaluateValidURLsCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	urls := urlPattern.FindAllString(target, -1)
	if len(urls) == 0 {
		return &runtimeCheckResult{}
	}
	invalid := make([]string, 0, len(urls))
	for _, candidate := range urls {
		parsed, err := neturl.ParseRequestURI(candidate)
		if err != nil || parsed == nil || strings.TrimSpace(parsed.Host) == "" {
			invalid = append(invalid, candidate)
			continue
		}
		if boolValue(check.Config, "onlyDNS", false) && !strings.Contains(parsed.Host, ".") {
			invalid = append(invalid, candidate)
		}
	}
	if len(invalid) == 0 {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    "One or more URLs are invalid",
		Details: map[string]any{
			"invalid_urls": invalid,
		},
	}
}

func evaluateContainsCodeCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	format := strings.ToLower(strings.TrimSpace(stringValue(check.Config, "format")))
	if !containsCode(target, format) {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.82,
		Summary:    "Content contains code",
		Details: map[string]any{
			"format": format,
		},
	}
}

func evaluateLowercaseCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	expectedLowercase := boolValue(check.Config, "expected", true)
	isLower := target == strings.ToLower(target)
	if isLower == expectedLowercase {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    "Lowercase check failed",
		Details: map[string]any{
			"expected": expectedLowercase,
		},
	}
}

func evaluateEndsWithCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := strings.TrimSpace(pickContent(request))
	suffix := stringValue(check.Config, "suffix", "Suffix")
	if suffix == "" || strings.HasSuffix(target, suffix) {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.9,
		Summary:    fmt.Sprintf("Content does not end with %q", suffix),
		Details: map[string]any{
			"suffix": suffix,
		},
	}
}

func evaluateModelWhitelistCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	models := stringSlice(check.Config["models"])
	if len(models) == 0 {
		models = stringSlice(check.Config["Models"])
	}
	if len(models) == 0 {
		return &runtimeCheckResult{}
	}
	inverse := boolValue(check.Config, "inverse", false) || boolValue(check.Config, "Inverse", false)
	matched := containsFold(models, request.Model)
	triggered := (!inverse && !matched) || (inverse && matched)
	if !triggered {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.97,
		Summary:    fmt.Sprintf("Model %s violated the configured whitelist policy", request.Model),
		Details: map[string]any{
			"models":  models,
			"inverse": inverse,
		},
	}
}

func evaluatePIICheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	categories := normalizedStringSlice(check.Config["categories"])
	if len(categories) == 0 {
		categories = []string{"email", "phone", "ssn", "credit_card"}
	}
	matches := make(map[string][]string)
	redacted := target
	for _, category := range categories {
		pattern := piiPattern(category)
		if pattern == nil {
			continue
		}
		found := pattern.FindAllString(target, -1)
		if len(found) == 0 {
			continue
		}
		matches[category] = found
		redacted = pattern.ReplaceAllString(redacted, redactWith(check.Action))
	}
	if len(matches) == 0 {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:       true,
		Confidence:      0.94,
		Summary:         "Potential PII detected",
		SanitizedInput:  chooseSanitizedInput(request, redacted),
		SanitizedOutput: chooseSanitizedOutput(request, redacted),
		Details: map[string]any{
			"categories": categories,
			"matches":    matches,
		},
	}
}

func evaluateGibberishCheck(check runtimeCheck, request runtimeapi.EvaluateRequest) *runtimeCheckResult {
	target := pickContent(request)
	if !looksGibberish(target) {
		return &runtimeCheckResult{}
	}
	return &runtimeCheckResult{
		Triggered:  true,
		Confidence: 0.78,
		Summary:    "Content appears to be gibberish",
	}
}

func evaluateWebhookCheck(ctx context.Context, httpClient *http.Client, check runtimeCheck, request runtimeapi.EvaluateRequest) (*runtimeCheckResult, error) {
	webhookURL := stringValue(check.Config, "webhookURL", "webhook_url", "url")
	if webhookURL == "" {
		return &runtimeCheckResult{}, nil
	}
	headers := map[string]string{}
	switch typed := check.Config["headers"].(type) {
	case map[string]any:
		for key, value := range typed {
			if rendered := strings.TrimSpace(fmt.Sprintf("%v", value)); rendered != "" {
				headers[key] = rendered
			}
		}
	case map[string]string:
		for key, value := range typed {
			if strings.TrimSpace(value) != "" {
				headers[key] = strings.TrimSpace(value)
			}
		}
	}

	payload := map[string]any{
		"request": map[string]any{
			"text":               request.Content.Input,
			"isStreamingRequest": boolValue(request.Metadata, "stream", false),
		},
		"response": map[string]any{
			"text":       request.Content.Output,
			"statusCode": nil,
		},
		"provider":    request.Provider,
		"requestType": requestTypeForCheck(request),
		"metadata":    request.Metadata,
		"eventType":   eventTypeForCheck(request.Stage),
	}
	if request.Content.Output == "" {
		payload["response"] = map[string]any{"text": "", "statusCode": nil}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		httpReq.Header.Set(key, value)
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded struct {
		Verdict         *bool          `json:"verdict"`
		Outcome         string         `json:"outcome"`
		Severity        string         `json:"severity"`
		Summary         string         `json:"summary"`
		Confidence      float64        `json:"confidence"`
		Details         map[string]any `json:"details"`
		TransformedData struct {
			Request struct {
				Text string `json:"text"`
			} `json:"request"`
			Response struct {
				Text string `json:"text"`
			} `json:"response"`
		} `json:"transformedData"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	verdict := true
	if decoded.Verdict != nil {
		verdict = *decoded.Verdict
	}
	triggered := !verdict || strings.TrimSpace(decoded.Outcome) != ""
	if !triggered && strings.TrimSpace(decoded.TransformedData.Request.Text) == "" && strings.TrimSpace(decoded.TransformedData.Response.Text) == "" {
		return &runtimeCheckResult{}, nil
	}
	result := &runtimeCheckResult{
		Triggered:        triggered || strings.TrimSpace(decoded.TransformedData.Request.Text) != "" || strings.TrimSpace(decoded.TransformedData.Response.Text) != "",
		Summary:          strings.TrimSpace(decoded.Summary),
		Details:          cloneMap(decoded.Details),
		OverrideOutcome:  decoded.Outcome,
		OverrideSeverity: decoded.Severity,
		Confidence:       normalizedConfidence(decoded.Confidence),
	}
	if strings.TrimSpace(decoded.TransformedData.Request.Text) != "" {
		result.SanitizedInput = decoded.TransformedData.Request.Text
	}
	if strings.TrimSpace(decoded.TransformedData.Response.Text) != "" {
		result.SanitizedOutput = decoded.TransformedData.Response.Text
	}
	if verdict && strings.TrimSpace(result.OverrideOutcome) == "" && (strings.TrimSpace(result.SanitizedInput) != "" || strings.TrimSpace(result.SanitizedOutput) != "") {
		result.OverrideOutcome = "redact"
	}
	if result.Summary == "" && !verdict {
		result.Summary = "Webhook guardrail rejected the request"
	}
	return result, nil
}

func resolvePortkeyAction(policy runtimeapi.PolicyBundle, check runtimeCheck, override string) (string, bool, bool) {
	action := check.Action
	outcome := normalizeOutcome(defaultString(override, stringValue(action, "on_fail", "outcome", "action")))
	if outcome == "allow" {
		if boolValue(action, "deny", false) {
			outcome = "deny"
		} else {
			switch strings.ToLower(strings.TrimSpace(policy.EnforcementMode)) {
			case "redact":
				outcome = "redact"
			case "approval":
				outcome = "deny"
			case "sandbox":
				outcome = "sandbox"
			case "block":
				outcome = "deny"
			default:
				outcome = "deny"
			}
		}
	}
	return outcome, boolValue(action, "async", false), boolValue(action, "pass_through", false) || boolValue(action, "direct_to_provider", false)
}

func extractActionFeedback(action map[string]any, keys ...string) string {
	for _, key := range keys {
		if rendered := stringValue(action, key); rendered != "" {
			return rendered
		}
	}
	return ""
}

func applyPortkeyFeedback(stage, input, output, feedback string) (string, string) {
	feedback = strings.TrimSpace(feedback)
	if feedback == "" {
		return input, output
	}
	if runtimeapi.NormalizeStage(stage) == runtimeapi.StageOutput {
		return input, strings.TrimSpace(strings.TrimSpace(output) + "\n\n" + feedback)
	}
	return strings.TrimSpace(strings.TrimSpace(input) + "\n\n" + feedback), output
}

func chooseSanitizedInput(request runtimeapi.EvaluateRequest, value string) string {
	if strings.TrimSpace(request.Content.Input) == "" {
		return ""
	}
	return value
}

func chooseSanitizedOutput(request runtimeapi.EvaluateRequest, value string) string {
	if strings.TrimSpace(request.Content.Output) == "" {
		return ""
	}
	return value
}

func normalizeCheckCategory(name string) string {
	return "check_" + strings.TrimSpace(strings.ToLower(name))
}

func requestTypeForCheck(request runtimeapi.EvaluateRequest) string {
	if request.MCP != nil {
		return "tool"
	}
	return "chatComplete"
}

func eventTypeForCheck(stage string) string {
	if runtimeapi.NormalizeStage(stage) == runtimeapi.StageOutput {
		return "afterRequestHook"
	}
	return "beforeRequestHook"
}

func outsideRange(value, min, max int) bool {
	if min >= 0 && value < min {
		return true
	}
	if max >= 0 && value > max {
		return true
	}
	return false
}

func sentenceCount(text string) int {
	count := 0
	for _, part := range regexp.MustCompile(`[.!?]+`).Split(text, -1) {
		if strings.TrimSpace(part) != "" {
			count++
		}
	}
	return count
}

func containsCode(text, format string) bool {
	if strings.Contains(text, "```") {
		return true
	}
	switch format {
	case "sql":
		return regexp.MustCompile(`(?is)\b(select|insert|update|delete|from|where|join)\b`).MatchString(text)
	case "python":
		return regexp.MustCompile(`(?m)\b(def |class |import |from .+ import |print\()`).MatchString(text)
	case "typescript", "javascript", "ts", "js":
		return regexp.MustCompile(`(?m)\b(const |let |function |interface |type |=>)`).MatchString(text)
	default:
		return regexp.MustCompile(`(?m)(\{|\}|;|<\w+>|SELECT\s+.+\s+FROM|def\s+\w+\()`).MatchString(text)
	}
}

func looksGibberish(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < 24 {
		return false
	}
	letters := 0
	vowels := 0
	spaces := 0
	repeats := 0
	last := rune(0)
	runLength := 0
	for _, r := range strings.ToLower(trimmed) {
		if unicode.IsSpace(r) {
			spaces++
		}
		if unicode.IsLetter(r) {
			letters++
			if strings.ContainsRune("aeiou", r) {
				vowels++
			}
		}
		if r == last {
			runLength++
		} else {
			runLength = 1
			last = r
		}
		if runLength >= 5 {
			repeats++
		}
	}
	if letters == 0 {
		return false
	}
	vowelRatio := float64(vowels) / float64(letters)
	spaceRatio := float64(spaces) / float64(len([]rune(trimmed)))
	return vowelRatio < 0.18 || (spaceRatio < 0.05 && repeats > 0)
}

func piiPattern(category string) *regexp.Regexp {
	return compiledPIIPattern(category)
}

func normalizedConfidence(value float64) float64 {
	if value <= 0 {
		return 0.9
	}
	return math.Min(value, 1.0)
}

func redactWith(action map[string]any) string {
	if value := stringValue(action, "redact_with", "mask_with"); value != "" {
		return value
	}
	return "[REDACTED]"
}

func mapValue(source map[string]any, key string) map[string]any {
	switch typed := source[key].(type) {
	case map[string]any:
		return cloneMap(typed)
	case map[string]string:
		result := make(map[string]any, len(typed))
		for k, v := range typed {
			result[k] = v
		}
		return result
	default:
		return map[string]any{}
	}
}

func cloneMap(source map[string]any) map[string]any {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func stringValue(source map[string]any, keys ...string) string {
	for _, key := range keys {
		if source == nil {
			return ""
		}
		raw, ok := source[key]
		if !ok || raw == nil {
			continue
		}
		rendered := strings.TrimSpace(fmt.Sprintf("%v", raw))
		if rendered != "" && rendered != "<nil>" {
			return rendered
		}
	}
	return ""
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			rendered := strings.TrimSpace(fmt.Sprintf("%v", item))
			if rendered != "" && rendered != "<nil>" {
				result = append(result, rendered)
			}
		}
		return result
	default:
		return nil
	}
}

func normalizedStringSlice(value any) []string {
	values := stringSlice(value)
	for index := range values {
		values[index] = strings.ToLower(strings.TrimSpace(values[index]))
	}
	return values
}

func intValue(source map[string]any, key string, fallback int) int {
	if source == nil {
		return fallback
	}
	raw, ok := source[key]
	if !ok || raw == nil {
		return fallback
	}
	switch typed := raw.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		var parsed int
		if _, err := fmt.Sscanf(strings.TrimSpace(fmt.Sprintf("%v", raw)), "%d", &parsed); err == nil {
			return parsed
		}
	}
	return fallback
}

func boolValue(source map[string]any, key string, fallback bool) bool {
	if source == nil {
		return fallback
	}
	raw, ok := source[key]
	if !ok || raw == nil {
		return fallback
	}
	switch typed := raw.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		}
	}
	return fallback
}

func containsFold(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)
