package guardrails

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

const (
	headerGuardrailsConfig       = "x-bf-guardrails-config"
	headerInputGuardrails        = "x-bf-input-guardrails"
	headerOutputGuardrails       = "x-bf-output-guardrails"
	headerBeforeRequestHooks     = "x-bf-before-request-hooks"
	headerAfterRequestHooks      = "x-bf-after-request-hooks"
	headerGuardrailsMode         = "x-bf-guardrails-mode"
	requestGuardrailsModeMerge   = "merge"
	requestGuardrailsModeReplace = "replace"
)

func requestHeaders(ctx *schemas.DeepIntShieldContext) map[string]string {
	if ctx == nil {
		return nil
	}
	raw, ok := ctx.Value(schemas.DeepIntShieldContextKeyRequestHeaders).(map[string]string)
	if !ok || len(raw) == 0 {
		return nil
	}
	copy := make(map[string]string, len(raw))
	for key, value := range raw {
		copy[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return copy
}

func hasInlineGuardrailHeaders(ctx *schemas.DeepIntShieldContext) bool {
	headers := requestHeaders(ctx)
	if len(headers) == 0 {
		return false
	}
	for _, header := range []string{
		headerGuardrailsConfig,
		headerInputGuardrails,
		headerOutputGuardrails,
		headerBeforeRequestHooks,
		headerAfterRequestHooks,
		headerGuardrailsMode,
	} {
		if strings.TrimSpace(headers[header]) != "" {
			return true
		}
	}
	return false
}

func validateLiveRequestGuardrails(ctx *schemas.DeepIntShieldContext) error {
	if !hasInlineGuardrailHeaders(ctx) {
		return nil
	}
	return fmt.Errorf("raw input_guardrails/output_guardrails are restricted to the test lab simulation flow")
}

func requestAttachedPolicies(ctx *schemas.DeepIntShieldContext, stage string) ([]runtimeapi.PolicyBundle, string, error) {
	headers := requestHeaders(ctx)
	if len(headers) == 0 {
		return nil, requestGuardrailsModeMerge, nil
	}

	stageKey, aliasKey := guardrailStageHeaderKeys(stage)
	mergedChecks := make([]any, 0, 8)
	mode := strings.ToLower(strings.TrimSpace(headers[headerGuardrailsMode]))
	if mode == "" {
		mode = requestGuardrailsModeMerge
	}

	if raw := strings.TrimSpace(headers[headerGuardrailsConfig]); raw != "" {
		var config map[string]any
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			return nil, mode, fmt.Errorf("invalid %s header: %w", headerGuardrailsConfig, err)
		}
		mergedChecks = append(mergedChecks, extractGuardrailChecksArray(config[stageKey])...)
		mergedChecks = append(mergedChecks, extractGuardrailChecksArray(config[aliasKey])...)
		if configuredMode := strings.ToLower(strings.TrimSpace(renderedGuardrailValue(config["mode"]))); configuredMode != "" {
			mode = configuredMode
		}
	}

	for _, header := range []string{stageHeader(stage), aliasHeader(stage)} {
		if raw := strings.TrimSpace(headers[header]); raw != "" {
			var checks []any
			if err := json.Unmarshal([]byte(raw), &checks); err != nil {
				return nil, mode, fmt.Errorf("invalid %s header: %w", header, err)
			}
			mergedChecks = append(mergedChecks, checks...)
		}
	}

	if len(mergedChecks) == 0 {
		return nil, mode, nil
	}
	definition := map[string]any{
		stageKey: mergedChecks,
	}
	raw, _ := json.Marshal(definition)
	sum := sha256.Sum256(raw)
	policyID := "request-inline-" + runtimeapi.NormalizeStage(stage) + "-" + hex.EncodeToString(sum[:8])
	return []runtimeapi.PolicyBundle{{
		PolicyID:        policyID,
		PolicyVersionID: policyID + "-v1",
		Name:            "Request Attached Guardrails",
		Scope:           runtimeapi.NormalizeStage(stage),
		EnforcementMode: "block",
		Enabled:         true,
		Definition:      definition,
	}}, mode, nil
}

func guardrailStageHeaderKeys(stage string) (string, string) {
	if runtimeapi.NormalizeStage(stage) == runtimeapi.StageOutput {
		return "output_guardrails", "after_request_hooks"
	}
	return "input_guardrails", "before_request_hooks"
}

func stageHeader(stage string) string {
	if runtimeapi.NormalizeStage(stage) == runtimeapi.StageOutput {
		return headerOutputGuardrails
	}
	return headerInputGuardrails
}

func aliasHeader(stage string) string {
	if runtimeapi.NormalizeStage(stage) == runtimeapi.StageOutput {
		return headerAfterRequestHooks
	}
	return headerBeforeRequestHooks
}

func extractGuardrailChecksArray(raw any) []any {
	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	return values
}

func renderedGuardrailValue(raw any) string {
	if raw == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}
