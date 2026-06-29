package handlers

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// guardRegexCache is a process-wide concurrent cache for compiled regexp patterns
// used by the guardrail runtime fast-path evaluator. Patterns are write-once-read-many
// so sync.Map is ideal - avoids lock contention on the hot evaluation path.
var guardRegexCache sync.Map

func cachedGuardRegexpCompile(pattern string) (*regexp.Regexp, error) {
	if cached, ok := guardRegexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	actual, _ := guardRegexCache.LoadOrStore(pattern, compiled)
	return actual.(*regexp.Regexp), nil
}

type guardRuntimeClient struct {
	client *runtimeapi.Client
}

type guardRuntimeActor = runtimeapi.Actor
type guardRuntimeMCPContext = runtimeapi.MCPContext
type guardRuntimeContent = runtimeapi.Content
type guardRuntimePolicyProviderBinding = runtimeapi.PolicyProviderBinding
type guardRuntimePolicyBundle = runtimeapi.PolicyBundle
type guardRuntimeProviderConfig = runtimeapi.ProviderConfig
type guardRuntimeMCPToolPolicy = runtimeapi.MCPToolPolicy
type guardRuntimeTenantBundle = runtimeapi.TenantBundle
type guardRuntimeEvaluateRequest = runtimeapi.EvaluateRequest
type guardRuntimeFinding = runtimeapi.Finding
type guardRuntimeEvaluateResponse = runtimeapi.EvaluateResponse
type guardRuntimeRefreshTenantRequest = runtimeapi.RefreshTenantRequest
type guardRuntimeRefreshTenantResponse = runtimeapi.RefreshTenantResponse

func newGuardRuntimeClient(httpURL, grpcTarget, sharedSecret string, preferGRPC bool, timeout time.Duration) *guardRuntimeClient {
	client, err := runtimeapi.NewClient(runtimeapi.ClientConfig{
		HTTPURL:      strings.TrimSpace(httpURL),
		GRPCTarget:   strings.TrimSpace(grpcTarget),
		SharedSecret: strings.TrimSpace(sharedSecret),
		Timeout:      timeout,
		PreferGRPC:   preferGRPC,
	})
	if err != nil || client == nil {
		return nil
	}
	return &guardRuntimeClient{client: client}
}

func (c *guardRuntimeClient) Evaluate(ctx context.Context, request *guardRuntimeEvaluateRequest) (*guardRuntimeEvaluateResponse, error) {
	if c == nil || c.client == nil || request == nil {
		return nil, fmt.Errorf("runtime client is not configured")
	}
	return c.client.Evaluate(ctx, request)
}

func (c *guardRuntimeClient) RefreshTenant(ctx context.Context, request *guardRuntimeRefreshTenantRequest) (*guardRuntimeRefreshTenantResponse, error) {
	if c == nil || c.client == nil || request == nil {
		return nil, fmt.Errorf("runtime client is not configured")
	}
	return c.client.RefreshTenant(ctx, request)
}

type compiledGuardRule struct {
	Category string
	Pattern  *regexp.Regexp
	Severity string
	Outcome  string
	Summary  string
}

func evaluateGuardRuntimeLocally(request *guardRuntimeEvaluateRequest) *guardRuntimeEvaluateResponse {
	start := time.Now()
	content := pickGuardRuntimeContent(request)
	response := &guardRuntimeEvaluateResponse{
		Decision:      "allow",
		Reason:        "No guardrail violations detected",
		Findings:      []guardRuntimeFinding{},
		DecisionChain: []string{"fast-path local evaluation"},
	}

	policies := request.Policies
	if len(policies) == 0 {
		policies = []guardRuntimePolicyBundle{{
			PolicyID:        "builtin-runtime-default",
			PolicyVersionID: "builtin-runtime-default-v1",
			Name:            "Default Runtime Protection",
			Scope:           request.Stage,
			EnforcementMode: "block",
			Enabled:         true,
			Definition:      defaultGuardRuntimeDefinition(request.Stage),
		}}
		response.DecisionChain = append(response.DecisionChain, "using built-in runtime heuristics")
	}

	sanitizedInput := request.Content.Input
	sanitizedOutput := request.Content.Output

	for _, policy := range policies {
		rules := compileGuardRuntimeRules(policy.Definition)
		if len(rules) == 0 {
			rules = compileGuardRuntimeRules(defaultGuardRuntimeDefinition(request.Stage))
		}
		target := content
		for _, rule := range rules {
			matches := rule.Pattern.FindAllString(target, -1)
			if len(matches) == 0 {
				continue
			}
			finding := guardRuntimeFinding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        rule.Category,
				Severity:        rule.Severity,
				Confidence:      0.84,
				Outcome:         normalizeGuardRuleOutcome(rule.Outcome),
				Summary:         rule.Summary,
				Details: map[string]any{
					"matches": matches,
				},
			}
			response.Findings = append(response.Findings, finding)
			response.DecisionChain = append(response.DecisionChain, fmt.Sprintf("%s matched %s", policy.Name, rule.Category))
			if finding.Outcome == "redact" {
				response.Redactions = append(response.Redactions, fmt.Sprintf("%s:%s", rule.Category, matches[0]))
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
				for _, requestDomain := range request.MCP.Domains {
					if strings.EqualFold(strings.TrimSpace(requestDomain), strings.TrimSpace(blockedDomain)) {
						response.Findings = append(response.Findings, guardRuntimeFinding{
							PolicyID:        policy.PolicyID,
							PolicyVersionID: policy.PolicyVersionID,
							Category:        "blocked_domain",
							Severity:        "high",
							Confidence:      0.95,
							Outcome:         "deny",
							Summary:         fmt.Sprintf("Request domain %s is blocked by policy", requestDomain),
							Details: map[string]any{
								"domain": requestDomain,
							},
						})
						response.DecisionChain = append(response.DecisionChain, "blocked MCP destination domain")
					}
				}
			}
		}

		allowedActionClasses := toStringSlice(policy.Definition["allowed_action_classes"])
		if request.MCP != nil && len(allowedActionClasses) > 0 {
			if !containsNormalizedGuardrailValue(allowedActionClasses, request.MCP.ActionClass) {
				response.Findings = append(response.Findings, guardRuntimeFinding{
					PolicyID:        policy.PolicyID,
					PolicyVersionID: policy.PolicyVersionID,
					Category:        "action_scope",
					Severity:        "critical",
					Confidence:      0.96,
					Outcome:         "deny",
					Summary:         fmt.Sprintf("Action class %s is outside the allowed MCP scope", request.MCP.ActionClass),
					Details: map[string]any{
						"allowed_action_classes": allowedActionClasses,
					},
				})
				response.DecisionChain = append(response.DecisionChain, "blocked MCP action class outside scope")
			}
		}

		deniedActionClasses := toStringSlice(policy.Definition["denied_action_classes"])
		if len(deniedActionClasses) == 0 {
			deniedActionClasses = toStringSlice(policy.Definition["approval_action_classes"])
		}
		if request.MCP != nil && len(deniedActionClasses) > 0 && containsNormalizedGuardrailValue(deniedActionClasses, request.MCP.ActionClass) {
			response.Findings = append(response.Findings, guardRuntimeFinding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "denied_action_class",
				Severity:        "high",
				Confidence:      0.9,
				Outcome:         "deny",
				Summary:         fmt.Sprintf("Action class %s is denied by policy", request.MCP.ActionClass),
				Details: map[string]any{
					"denied_action_classes": deniedActionClasses,
				},
			})
			response.DecisionChain = append(response.DecisionChain, "blocked MCP action class requiring manual review")
		}
	}

	response.Decision, response.ApprovalRequired, response.Reason = resolveGuardRuntimeDecision(response.Findings, response.Redactions)
	if sanitizedInput != request.Content.Input {
		response.SanitizedInput = sanitizedInput
	}
	if sanitizedOutput != request.Content.Output {
		response.SanitizedOutput = sanitizedOutput
	}
	response.LatencyMs = int(time.Since(start).Milliseconds())
	return response
}

func defaultGuardRuntimeDefinition(stage string) map[string]any {
	inputChecks := make([]map[string]any, 0, len(defaultInputRegexRules)+1)
	for _, r := range defaultInputRegexRules {
		action := map[string]any{"on_fail": r.OnFail}
		if r.OnFail == "redact" {
			action["redact_with"] = "[REDACTED]"
		}
		inputChecks = append(inputChecks, map[string]any{
			"name":     "regex_match",
			"enabled":  true,
			"priority": r.Priority,
			"config":   map[string]any{"rule": r.Rule, "severity": r.Severity, "summary": r.Summary},
			"action":   action,
		})
	}
	inputChecks = append(inputChecks, map[string]any{
		"name":     "detect_pii",
		"enabled":  true,
		"priority": 30,
		"config":   map[string]any{"categories": defaultInputPIICategories, "severity": "high", "summary": "Sensitive personal or payment data detected"},
		"action":   map[string]any{"on_fail": "redact", "redact_with": "[REDACTED]"},
	})

	outputChecks := []map[string]any{
		{
			"name":     "detect_pii",
			"enabled":  true,
			"priority": 10,
			"config":   map[string]any{"categories": defaultOutputPIICategories, "severity": "high", "summary": "Sensitive personal or payment data detected"},
			"action":   map[string]any{"on_fail": "redact", "redact_with": "[REDACTED]"},
		},
	}
	for _, r := range defaultOutputRegexRules {
		action := map[string]any{"on_fail": r.OnFail}
		if r.OnFail == "redact" {
			action["redact_with"] = "[REDACTED]"
		}
		outputChecks = append(outputChecks, map[string]any{
			"name":     "regex_match",
			"enabled":  true,
			"priority": r.Priority,
			"config":   map[string]any{"rule": r.Rule, "severity": r.Severity, "summary": r.Summary},
			"action":   action,
		})
	}

	legacyRules := make([]map[string]any, 0, len(defaultLegacyRules)+1)
	for _, r := range defaultLegacyRules {
		legacyRules = append(legacyRules, map[string]any{
			"category": r.Category, "pattern": r.Pattern, "severity": r.Severity, "outcome": r.Outcome, "summary": r.Summary,
		})
	}

	definition := map[string]any{
		"rules":                  legacyRules,
		"input_guardrails":       inputChecks,
		"output_guardrails":      outputChecks,
		"blocked_domains":        defaultBlockedDomains,
		"allowed_action_classes": defaultAllowedActionClasses,
		"denied_action_classes":  defaultDeniedActionClasses,
	}
	if strings.EqualFold(stage, "output") {
		definition["rules"] = append(legacyRules, map[string]any{
			"category": outputStageLegacyRule.Category,
			"pattern":  outputStageLegacyRule.Pattern,
			"severity": outputStageLegacyRule.Severity,
			"outcome":  outputStageLegacyRule.Outcome,
			"summary":  outputStageLegacyRule.Summary,
		})
	}
	return definition
}

func compileGuardRuntimeRules(definition map[string]any) []compiledGuardRule {
	rules := make([]compiledGuardRule, 0, 8)
	appendRule := func(category, pattern, severity, outcome, summary string) {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return
		}
		compiled, err := cachedGuardRegexpCompile(pattern)
		if err != nil {
			return
		}
		rules = append(rules, compiledGuardRule{
			Category: strings.TrimSpace(category),
			Pattern:  compiled,
			Severity: normalizeGuardRuleSeverity(severity),
			Outcome:  normalizeGuardRuleOutcome(outcome),
			Summary:  strings.TrimSpace(summary),
		})
	}

	for _, item := range toAnySlice(definition["rules"]) {
		ruleMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		appendRule(
			fmt.Sprintf("%v", ruleMap["category"]),
			fmt.Sprintf("%v", ruleMap["pattern"]),
			fmt.Sprintf("%v", ruleMap["severity"]),
			fmt.Sprintf("%v", ruleMap["outcome"]),
			fmt.Sprintf("%v", ruleMap["summary"]),
		)
	}

	for _, key := range []string{"input_guardrails", "before_request_hooks", "output_guardrails", "after_request_hooks"} {
		for _, item := range toAnySlice(definition[key]) {
			checkMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", checkMap["name"])))
			config, _ := checkMap["config"].(map[string]any)
			action, _ := checkMap["action"].(map[string]any)
			switch name {
			case "regex_match":
				appendRule(
					defaultGuardrailString(config, "category", "check_regex_match"),
					defaultGuardrailString(config, "rule", ""),
					defaultGuardrailString(config, "severity", "medium"),
					resolveGuardRuntimeCheckOutcome(action),
					defaultGuardrailString(config, "summary", "Guardrail regex check failed"),
				)
			case "detect_pii":
				for _, category := range toStringSlice(config["categories"]) {
					if pattern := guardRuntimePIIPattern(category); pattern != "" {
						appendRule(
							"pii_"+strings.ToLower(strings.TrimSpace(category)),
							pattern,
							defaultGuardrailString(config, "severity", "high"),
							resolveGuardRuntimeCheckOutcome(action),
							defaultGuardrailString(config, "summary", "Sensitive data detected"),
						)
					}
				}
			}
		}
	}

	return rules
}

func pickGuardRuntimeContent(request *guardRuntimeEvaluateRequest) string {
	switch strings.ToLower(strings.TrimSpace(request.Stage)) {
	case "output":
		if strings.TrimSpace(request.Content.Output) != "" {
			return request.Content.Output
		}
	case "action", "mcp":
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

func resolveGuardRuntimeDecision(findings []guardRuntimeFinding, redactions []string) (string, bool, string) {
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
		outcome := normalizeGuardRuleOutcome(finding.Outcome)
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

func normalizeGuardRuleSeverity(value string) string {
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

func normalizeGuardRuleOutcome(value string) string {
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

func toStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			trimmed := strings.TrimSpace(fmt.Sprintf("%v", item))
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	default:
		return nil
	}
}

func containsNormalizedGuardrailValue(values []string, candidate string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func toAnySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []map[string]any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, item)
		}
		return result
	default:
		return nil
	}
}

func defaultGuardrailString(source map[string]any, key, fallback string) string {
	if source == nil {
		return fallback
	}
	value := strings.TrimSpace(fmt.Sprintf("%v", source[key]))
	if value == "" || value == "<nil>" {
		return fallback
	}
	return value
}

func resolveGuardRuntimeCheckOutcome(action map[string]any) string {
	if action == nil {
		return "deny"
	}
	if deny, ok := action["deny"].(bool); ok && deny {
		return "deny"
	}
	for _, key := range []string{"on_fail", "outcome", "action"} {
		value := strings.TrimSpace(fmt.Sprintf("%v", action[key]))
		if value != "" && value != "<nil>" {
			return value
		}
	}
	return "deny"
}

func guardRuntimePIIPattern(category string) string {
	return guardPIIPatterns[strings.ToLower(strings.TrimSpace(category))]
}
