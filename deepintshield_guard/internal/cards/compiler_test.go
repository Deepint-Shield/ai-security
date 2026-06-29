package cards

import "testing"

func TestCompileDefinitionCompilesBuilderCardsIntoRuntimeChecks(t *testing.T) {
	definition := map[string]any{
		builderMetadataKey: map[string]any{
			"selected_cards": []any{
				map[string]any{
					"id":              "owasp-llm01-prompt-injection",
					"enabled":         true,
					"action":          "deny",
					"severity":        "high",
					"summary":         "Prompt injection detected",
					"selectedPresets": []any{"direct_override", "obfuscated_prompt"},
				},
				map[string]any{
					"id":                    "owasp-llm06-excessive-agency",
					"enabled":               true,
					"allowedActionClasses":  []any{"read", "write"},
					"approvalActionClasses": []any{"network"},
					"blockedDomains":        []any{"example.com"},
				},
			},
		},
		"input_guardrails": []any{
			map[string]any{
				"name":    "regex_match",
				"enabled": true,
				"config": map[string]any{
					"card_id": "owasp-llm01-prompt-injection",
					"rule":    "(?i)(old pattern)",
				},
				"action": map[string]any{"on_fail": "deny"},
			},
		},
	}

	compiled := CompileDefinition(definition, "action")
	checks, ok := compiled["input_guardrails"].([]any)
	if !ok || len(checks) != 2 {
		t.Fatalf("expected 2 compiled checks, got %#v", compiled["input_guardrails"])
	}
	checkMap := checks[0].(map[string]any)
	config := checkMap["config"].(map[string]any)
	rule := config["rule"].(string)
	if rule == "(?i)(old pattern)" {
		t.Fatalf("expected runtime compiler to replace builder-managed check with compiled pattern")
	}
	if _, ok := compiled["blocked_domains"]; !ok {
		t.Fatalf("expected blocked_domains to be compiled from agency card")
	}
	if _, ok := compiled["denied_action_classes"]; !ok {
		t.Fatalf("expected denied_action_classes to be compiled from agency card")
	}
}
