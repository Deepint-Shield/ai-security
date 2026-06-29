package cards

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const builderMetadataKey = "_deepintshield_builder"

//go:embed patterns/presets.json
var presetCatalogJSON []byte

type presetCatalog struct {
	Presets map[string]presetDefinition `json:"presets"`
}

type presetDefinition struct {
	Literals []string `json:"literals"`
	Regex    []string `json:"regex"`
}

type builderCardState struct {
	ID                   string
	Enabled              bool
	Action               string
	Severity             string
	Summary              string
	SelectedPresets      []string
	SelectedCategories   []string
	ModelAllowlist       []string
	InverseMatch         bool
	BlockedDomains       []string
	AllowedActionClasses []string
	DeniedActionClasses  []string
	MaxCharacters        string
	MaxWords             string
	MaxSentences         string
	CustomPattern        string
	CustomTerms          string
	RequireValidURLs     bool
}

type cardEmission struct {
	Checks               []map[string]any
	BlockedDomains       []string
	AllowedActionClasses []string
	DeniedActionClasses  []string
}

var presets = loadPresetCatalog()

// msPresetDefaults maps each OWASP card ID to the MS-derived preset names
// (loaded from presets.json) that should always be unioned in when the card
// is enabled. This is what makes the 111 patterns from the MS Agent
// Governance Toolkit fire out of the box rather than requiring explicit
// per-policy opt-in. Operators can still tighten or relax via
// selectedPresets in the card config.
var msPresetDefaults = map[string][]string{
	"owasp-llm01-prompt-injection": {
		"ms_prompt_injection_direct_override",
		"ms_prompt_injection_delimiter_attack",
		"ms_prompt_injection_roleplay_jailbreak",
		"ms_prompt_injection_encoding_obfuscation",
		"ms_prompt_injection_context_manipulation",
		"ms_prompt_injection_multi_turn_escalation",
		"ms_evasion_unicode",
		// These three are technically "excessive agency" risks (LLM06),
		// but they are almost always *delivered as* prompt injections
		// - "fetch this metadata URL", "execute this code",
		// "set role=admin". Most workspaces enable LLM01 by default
		// without separately enabling LLM06, which left a real
		// protection gap for SSRF, dangerous-command, and privilege-
		// escalation attempts. Wiring them here closes that gap with
		// zero workspace-config change.
		"ms_exec_dangerous_commands",
		"ms_exfiltration_network",
		"ms_privilege_escalation",
	},
	"owasp-llm02-sensitive-information-disclosure": {
		"ms_pii_detection",
		"ms_secrets_credentials",
	},
	"owasp-llm04-data-model-poisoning": {
		"ms_rag_memory_poisoning",
		"ms_evasion_unicode",
	},
	"owasp-llm05-improper-output-handling": {
		"ms_output_guardrails",
		"ms_injection_sql_nosql",
	},
	"owasp-llm06-excessive-agency": {
		"ms_mcp_tool_threats",
		"ms_exec_dangerous_commands",
		"ms_exfiltration_network",
		"ms_privilege_escalation",
	},
	"owasp-llm07-system-prompt-leakage": {
		"ms_prompt_injection_canary_leak",
		"ms_output_guardrails",
	},
	"owasp-llm08-vector-embedding-weaknesses": {
		"ms_rag_memory_poisoning",
		"ms_evasion_unicode",
	},
	// LLM09 / Misinformation - historically had no msPresetDefaults entry,
	// which meant the card depended entirely on the workspace's explicit
	// selectedPresets. Standardisation: every misinformation policy now
	// carries the canonical certainty/no-evidence preset pair out of the box.
	"owasp-llm09-misinformation": {
		"no_evidence_claims",
		"unsupported_certainty",
	},
	// Domain packs - each pack now declares the canonical preset bundle
	// that defines it, so the workspace gets the pack's intended baseline
	// even when an operator clears the SelectedPresets list. Anything the
	// operator adds via SelectedPresets / CustomPattern / CustomTerms is
	// still unioned in on top.
	"domain-bfsi-runtime-protection": {
		"payment_card_data",
		"finance_override",
		"wire_transfer_escalation",
	},
	"domain-healthcare-clinical-safety": {
		"phi_markers",
		"unsafe_clinical_instructions",
		"unsupported_diagnosis",
		"high_stakes_guidance",
	},
	"domain-insurance-claims-controls": {
		"claimant_pii",
		"claims_override",
		"fraud_score_manipulation",
		"verification_bypass",
	},
	"domain-enterprise-copilot-baseline": {
		"prompt_injection",
		"prompt_leakage",
		"credential_exposure",
		"hidden_instructions",
		"role_discovery",
	},
	"domain-customer-support-assistant": {
		"refund_override",
		"ms_pii_detection",
		"cross_context_leak",
	},
	"domain-development-assistant": {
		"shell_exec",
		"script_payload",
		"dependency_exfiltration",
		"ms_exec_dangerous_commands",
		"embedded_secrets",
	},
}

// mergeMSDefaults returns the union of state.SelectedPresets and the
// MS-derived defaults for the card, deduped. Defaults are appended so
// operator-supplied selections still drive the regex order.
func mergeMSDefaults(state builderCardState) []string {
	defaults := msPresetDefaults[state.ID]
	if len(defaults) == 0 {
		return state.SelectedPresets
	}
	combined := make([]string, 0, len(state.SelectedPresets)+len(defaults))
	combined = append(combined, state.SelectedPresets...)
	combined = append(combined, defaults...)
	return dedupeStrings(combined...)
}

// emitStandardRegexRule is the canonical regex-composer used by every
// regex-emitting card. It unions four sources, deduped:
//
//  1. msPresetDefaults[card_id]      - the canonical baseline that fires
//     out of the box for the card
//  2. state.SelectedPresets          - operator-chosen additions from the
//     guardrail policy builder
//  3. state.CustomPattern            - operator-authored raw regex (passed
//     through unescaped)
//  4. state.CustomTerms              - operator-authored comma-separated
//     literal strings (regex-quoted into the rule)
//
// Returns "" only when all four sources are empty. Previously, several
// emit*Card functions only consulted some of these (e.g. emitVectorCard
// dropped CustomPattern; emitMisinformationCard skipped the MS defaults
// entirely; the domain-pack emitters bypassed mergeMSDefaults). Routing
// every card through this helper standardises behaviour so a workspace's
// operator-supplied regex always reaches the runtime, regardless of which
// card hosts it.
func emitStandardRegexRule(state builderCardState) string {
	presetIDs := mergeMSDefaults(state)
	literals := make([]string, 0, 16)
	regexes := make([]string, 0, 16)
	for _, presetID := range normalizeStringSlice(presetIDs) {
		definition, ok := presets.Presets[presetID]
		if !ok {
			continue
		}
		literals = append(literals, definition.Literals...)
		regexes = append(regexes, definition.Regex...)
	}
	literals = append(literals, parseList(state.CustomTerms)...)
	return buildAlternationRegex(literals, regexes, state.CustomPattern)
}

var cardScopes = map[string][]string{
	"owasp-llm01-prompt-injection":                 {"input", "action", "mcp", "rag"},
	"owasp-llm02-sensitive-information-disclosure": {"input", "output", "action", "mcp", "rag"},
	"owasp-llm03-supply-chain":                     {"input", "action", "mcp", "rag"},
	"owasp-llm04-data-model-poisoning":             {"input", "rag", "mcp"},
	"owasp-llm05-improper-output-handling":         {"output", "action", "mcp"},
	"owasp-llm06-excessive-agency":                 {"action", "mcp"},
	"owasp-llm07-system-prompt-leakage":            {"input", "output"},
	"owasp-llm08-vector-embedding-weaknesses":      {"input", "rag", "mcp"},
	"owasp-llm09-misinformation":                   {"input", "output"},
	"owasp-llm10-unbounded-consumption":            {"input", "action", "mcp", "rag"},
	"domain-bfsi-runtime-protection":               {"input", "action", "mcp"},
	"domain-healthcare-clinical-safety":            {"input", "output"},
	"domain-insurance-claims-controls":             {"input", "action", "mcp"},
	"domain-enterprise-copilot-baseline":           {"input", "output", "action", "mcp"},
	"domain-customer-support-assistant":            {"input", "output"},
	"domain-development-assistant":                 {"input", "action", "mcp"},
}

func CompileDefinition(definition map[string]any, scope string) map[string]any {
	compiled := cloneDefinition(definition)
	if len(compiled) == 0 {
		return compiled
	}
	selectedCards := parseSelectedCards(compiled)
	if len(selectedCards) == 0 {
		return compiled
	}

	stageKey := stageCheckKey(scope)
	existingChecks := asObjectArray(compiled[stageKey])
	nextChecks := make([]map[string]any, 0, len(existingChecks))
	seen := make(map[string]struct{}, len(existingChecks))
	for _, check := range existingChecks {
		config := mapValue(check["config"])
		if strings.TrimSpace(stringValue(config["card_id"])) != "" {
			continue
		}
		fingerprint := guardrailCheckFingerprint(check)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		nextChecks = append(nextChecks, check)
	}

	blockedDomains := make(stringSet)
	allowedActionClasses := make(stringSet)
	deniedActionClasses := make(stringSet)
	delete(compiled, "blocked_domains")
	delete(compiled, "allowed_action_classes")
	delete(compiled, "approval_action_classes")
	delete(compiled, "denied_action_classes")

	for _, state := range selectedCards {
		if !state.Enabled || !supportsScope(state.ID, scope) {
			continue
		}
		emitted := emitCardState(state, scope)
		for _, check := range emitted.Checks {
			fingerprint := guardrailCheckFingerprint(check)
			if _, ok := seen[fingerprint]; ok {
				continue
			}
			seen[fingerprint] = struct{}{}
			nextChecks = append(nextChecks, check)
		}
		blockedDomains.addAll(emitted.BlockedDomains...)
		allowedActionClasses.addAll(emitted.AllowedActionClasses...)
		deniedActionClasses.addAll(emitted.DeniedActionClasses...)
	}

	if len(nextChecks) > 0 {
		compiled[stageKey] = objectArray(nextChecks)
	} else {
		delete(compiled, stageKey)
	}
	if values := blockedDomains.values(); len(values) > 0 {
		compiled["blocked_domains"] = stringArray(values)
	}
	if values := allowedActionClasses.values(); len(values) > 0 {
		compiled["allowed_action_classes"] = stringArray(values)
	}
	if values := deniedActionClasses.values(); len(values) > 0 {
		compiled["denied_action_classes"] = stringArray(values)
	}
	return compiled
}

func loadPresetCatalog() presetCatalog {
	var catalog presetCatalog
	if err := json.Unmarshal(presetCatalogJSON, &catalog); err != nil {
		panic(fmt.Sprintf("failed to load guardrail preset catalog: %v", err))
	}
	if catalog.Presets == nil {
		catalog.Presets = map[string]presetDefinition{}
	}
	return catalog
}

func parseSelectedCards(definition map[string]any) []builderCardState {
	metadata := mapValue(definition[builderMetadataKey])
	rawCards, ok := metadata["selected_cards"].([]any)
	if !ok {
		return nil
	}
	cards := make([]builderCardState, 0, len(rawCards))
	for _, rawCard := range rawCards {
		record, ok := rawCard.(map[string]any)
		if !ok {
			continue
		}
		id := strings.TrimSpace(stringValue(record["id"]))
		if id == "" {
			continue
		}
		cards = append(cards, builderCardState{
			ID:                   id,
			Enabled:              boolValue(record["enabled"], true),
			Action:               normalizeAction(stringValue(record["action"])),
			Severity:             normalizeSeverity(stringValue(record["severity"])),
			Summary:              strings.TrimSpace(stringValue(record["summary"])),
			SelectedPresets:      normalizeStringSlice(record["selectedPresets"]),
			SelectedCategories:   normalizeStringSlice(record["selectedCategories"]),
			ModelAllowlist:       stringSlice(record["modelAllowlist"]),
			InverseMatch:         boolValue(record["inverseMatch"], false),
			BlockedDomains:       stringSlice(record["blockedDomains"]),
			AllowedActionClasses: stringSlice(record["allowedActionClasses"]),
			DeniedActionClasses:  stringSlice(firstNonNil(record["deniedActionClasses"], record["approvalActionClasses"])),
			MaxCharacters:        strings.TrimSpace(stringValue(record["maxCharacters"])),
			MaxWords:             strings.TrimSpace(stringValue(record["maxWords"])),
			MaxSentences:         strings.TrimSpace(stringValue(record["maxSentences"])),
			CustomPattern:        strings.TrimSpace(stringValue(record["customPattern"])),
			CustomTerms:          strings.TrimSpace(stringValue(record["customTerms"])),
			RequireValidURLs:     boolValue(record["requireValidUrls"], false),
		})
	}
	return cards
}

func emitCardState(state builderCardState, scope string) cardEmission {
	switch state.ID {
	case "owasp-llm01-prompt-injection":
		return emitPromptInjectionCard(state)
	case "owasp-llm02-sensitive-information-disclosure":
		return emitSensitiveInfoCard(state)
	case "owasp-llm03-supply-chain":
		return emitSupplyChainCard(state, scope)
	case "owasp-llm04-data-model-poisoning":
		return emitPoisoningCard(state)
	case "owasp-llm05-improper-output-handling":
		return emitImproperOutputCard(state)
	case "owasp-llm06-excessive-agency":
		return emitAgencyCard(state)
	case "owasp-llm07-system-prompt-leakage":
		return emitSystemPromptLeakageCard(state)
	case "owasp-llm08-vector-embedding-weaknesses":
		return emitVectorCard(state, scope)
	case "owasp-llm09-misinformation":
		return emitMisinformationCard(state)
	case "owasp-llm10-unbounded-consumption":
		return emitUnboundedConsumptionCard(state)
	case "domain-bfsi-runtime-protection":
		return emitBFSICard(state)
	case "domain-healthcare-clinical-safety":
		return emitHealthcareCard(state, scope)
	case "domain-insurance-claims-controls":
		return emitInsuranceCard(state)
	case "domain-enterprise-copilot-baseline":
		return emitEnterpriseCopilotCard(state)
	case "domain-customer-support-assistant":
		return emitCustomerSupportCard(state)
	case "domain-development-assistant":
		return emitDevelopmentCard(state)
	default:
		return cardEmission{}
	}
}

func emitPromptInjectionCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 2)
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 10, regexRule, "prompt_injection"))
	}
	if containsPreset(state.SelectedPresets, "obfuscated_prompt") {
		checks = append(checks, buildCheck(state, 20, "detect_gibberish", map[string]any{
			"card_id":  state.ID,
			"severity": stateSeverity(state, "high"),
			"summary":  stateSummary(state, "Obfuscated prompt content detected"),
		}))
	}
	return cardEmission{Checks: checks}
}

func emitSensitiveInfoCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 2)
	if len(state.SelectedCategories) > 0 {
		checks = append(checks, buildCheck(state, 10, "detect_pii", map[string]any{
			"card_id":    state.ID,
			"categories": stringArray(state.SelectedCategories),
			"severity":   stateSeverity(state, "high"),
			"summary":    stateSummary(state, "Sensitive information detected"),
		}))
	}
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 20, regexRule, "sensitive_information"))
	}
	return cardEmission{Checks: checks}
}

func emitSupplyChainCard(state builderCardState, scope string) cardEmission {
	checks := make([]map[string]any, 0, 1)
	if len(state.ModelAllowlist) > 0 {
		checks = append(checks, buildCheck(state, 10, "model_whitelist", map[string]any{
			"card_id":  state.ID,
			"models":   stringArray(state.ModelAllowlist),
			"inverse":  state.InverseMatch,
			"severity": stateSeverity(state, "high"),
			"summary":  stateSummary(state, "Model or supplier inventory policy violated"),
		}))
	}
	emission := cardEmission{Checks: checks}
	if scope == "action" || scope == "mcp" || scope == "rag" {
		emission.BlockedDomains = dedupeStrings(state.BlockedDomains...)
	}
	return emission
}

func emitPoisoningCard(state builderCardState) cardEmission {
	regexRule := emitStandardRegexRule(state)
	if regexRule == "" {
		return cardEmission{}
	}
	return cardEmission{
		Checks: []map[string]any{
			buildRegexCheck(state, 10, regexRule, "data_model_poisoning"),
		},
	}
}

func emitImproperOutputCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, len(state.SelectedCategories)+2)
	for index, format := range dedupeStrings(state.SelectedCategories...) {
		checks = append(checks, buildCheck(state, 10+index, "contains_code", map[string]any{
			"card_id":  state.ID,
			"format":   format,
			"severity": stateSeverity(state, "high"),
			"summary":  stateSummary(state, "Generated content contains code"),
		}))
	}
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 40, regexRule, "improper_output_handling"))
	}
	if state.RequireValidURLs {
		checks = append(checks, buildCheck(state, 50, "valid_urls", map[string]any{
			"card_id":  state.ID,
			"severity": stateSeverity(state, "high"),
			"summary":  stateSummary(state, "Generated output contains malformed URLs"),
		}))
	}
	return cardEmission{Checks: checks}
}

func emitAgencyCard(state builderCardState) cardEmission {
	return cardEmission{
		BlockedDomains:       dedupeStrings(state.BlockedDomains...),
		AllowedActionClasses: dedupeStrings(state.AllowedActionClasses...),
		DeniedActionClasses:  dedupeStrings(state.DeniedActionClasses...),
	}
}

func emitSystemPromptLeakageCard(state builderCardState) cardEmission {
	regexRule := emitStandardRegexRule(state)
	if regexRule == "" {
		return cardEmission{}
	}
	return cardEmission{
		Checks: []map[string]any{
			buildRegexCheck(state, 10, regexRule, "system_prompt_leakage"),
		},
	}
}

func emitVectorCard(state builderCardState, scope string) cardEmission {
	checks := make([]map[string]any, 0, 2)
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 10, regexRule, "vector_embedding_weakness"))
	}
	if state.RequireValidURLs {
		checks = append(checks, buildCheck(state, 20, "valid_urls", map[string]any{
			"card_id":  state.ID,
			"severity": stateSeverity(state, "high"),
			"summary":  stateSummary(state, "Retrieved content contains malformed URLs"),
		}))
	}
	emission := cardEmission{Checks: checks}
	if scope == "action" || scope == "mcp" {
		emission.BlockedDomains = dedupeStrings(state.BlockedDomains...)
	}
	return emission
}

func emitMisinformationCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 2)
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 10, regexRule, "misinformation"))
	}
	if state.RequireValidURLs {
		checks = append(checks, buildCheck(state, 20, "valid_urls", map[string]any{
			"card_id":  state.ID,
			"severity": stateSeverity(state, "medium"),
			"summary":  stateSummary(state, "Generated citations or URLs are malformed"),
		}))
	}
	return cardEmission{Checks: checks}
}

func emitUnboundedConsumptionCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 3)
	if maxCharacters := parsePositiveInt(state.MaxCharacters); maxCharacters > 0 {
		checks = append(checks, buildCheck(state, 10, "character_count", map[string]any{
			"card_id":       state.ID,
			"maxCharacters": maxCharacters,
			"severity":      stateSeverity(state, "medium"),
			"summary":       stateSummary(state, "Request exceeded the configured character limit"),
		}))
	}
	if maxWords := parsePositiveInt(state.MaxWords); maxWords > 0 {
		checks = append(checks, buildCheck(state, 20, "word_count", map[string]any{
			"card_id":  state.ID,
			"maxWords": maxWords,
			"severity": stateSeverity(state, "medium"),
			"summary":  stateSummary(state, "Request exceeded the configured word limit"),
		}))
	}
	if maxSentences := parsePositiveInt(state.MaxSentences); maxSentences > 0 {
		checks = append(checks, buildCheck(state, 30, "sentence_count", map[string]any{
			"card_id":      state.ID,
			"maxSentences": maxSentences,
			"severity":     stateSeverity(state, "medium"),
			"summary":      stateSummary(state, "Request exceeded the configured sentence limit"),
		}))
	}
	return cardEmission{Checks: checks}
}

func emitBFSICard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 2)
	bfsiState := state
	bfsiState.SelectedPresets = append([]string(nil), state.SelectedPresets...)
	if containsNormalizedValue(state.SelectedCategories, "credit_card") && !containsPreset(bfsiState.SelectedPresets, "payment_card_data") {
		bfsiState.SelectedPresets = append(bfsiState.SelectedPresets, "payment_card_data")
	}
	if regexRule := emitStandardRegexRule(bfsiState); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 10, regexRule, "bfsi_runtime_protection"))
	}
	if containsPreset(bfsiState.SelectedPresets, "payment_card_data") || containsNormalizedValue(state.SelectedCategories, "credit_card") {
		checks = append(checks, buildCheck(state, 20, "detect_pii", map[string]any{
			"card_id":    state.ID,
			"categories": stringArray([]string{"credit_card"}),
			"severity":   stateSeverity(state, "critical"),
			"summary":    stateSummary(state, "Payment or card data detected"),
		}))
	}
	return cardEmission{
		Checks:              checks,
		BlockedDomains:      dedupeStrings(state.BlockedDomains...),
		DeniedActionClasses: dedupeStrings(state.DeniedActionClasses...),
	}
}

// emitHealthcareCard keeps a per-scope check split: PHI redaction fires on
// every scope; the unsafe-instruction and unsupported-diagnosis presets only
// fire on the output stage. Standardisation here merges PHI-related MS
// defaults (phi_markers, high_stakes_guidance) PLUS the workspace's
// CustomPattern / CustomTerms into the input-stage check, and unions the
// output-clinical presets with any operator-selected ones.
func emitHealthcareCard(state builderCardState, scope string) cardEmission {
	checks := make([]map[string]any, 0, 3)
	phiSelected := containsPreset(state.SelectedPresets, "phi_markers") ||
		containsPreset(msPresetDefaults[state.ID], "phi_markers")
	if phiSelected {
		phiState := state
		// PHI redaction always behaves as redact even when the broader card
		// is `deny`, so the gateway scrubs rather than blocking the entire
		// clinical conversation on a single label match.
		if phiState.Action == "deny" {
			phiState.Action = "redact"
		}
		// Narrow the preset set to PHI-relevant items so we don't pull in
		// output-stage clinical regexes on input.
		phiState.SelectedPresets = []string{"phi_markers", "high_stakes_guidance"}
		if regexRule := emitStandardRegexRule(phiState); regexRule != "" {
			checks = append(checks, buildRegexCheck(phiState, 10, regexRule, "phi"))
		}
	}
	if scope == "output" {
		clinicalPresets := dedupeStrings(append(
			[]string{"unsafe_clinical_instructions"},
			intersectPresets(state.SelectedPresets, []string{"unsafe_clinical_instructions"})...,
		)...)
		if regexRule := buildPatternRule(clinicalPresets, ""); regexRule != "" {
			checks = append(checks, buildRegexCheck(state, 20, regexRule, "clinical_risk"))
		}
		diagnosisPresets := dedupeStrings(append(
			[]string{"unsupported_diagnosis"},
			intersectPresets(state.SelectedPresets, []string{"unsupported_diagnosis"})...,
		)...)
		if regexRule := buildPatternRule(diagnosisPresets, ""); regexRule != "" {
			checks = append(checks, buildRegexCheck(state, 30, regexRule, "clinical_risk"))
		}
	}
	return cardEmission{
		Checks:              checks,
		DeniedActionClasses: dedupeStrings(state.DeniedActionClasses...),
	}
}

// intersectPresets is a tiny helper kept here (rather than alongside the
// other set helpers) because it is only used by emitHealthcareCard. It
// returns elements in `selected` that are also in `allowed`, preserving
// order from `selected`.
func intersectPresets(selected, allowed []string) []string {
	if len(selected) == 0 || len(allowed) == 0 {
		return nil
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allow[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	out := make([]string, 0, len(selected))
	for _, name := range selected {
		if _, ok := allow[strings.ToLower(strings.TrimSpace(name))]; ok {
			out = append(out, name)
		}
	}
	return out
}

func emitInsuranceCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 2)
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 10, regexRule, "insurance_claims"))
	}
	if containsPreset(state.SelectedPresets, "claimant_pii") || len(state.SelectedCategories) > 0 {
		categories := state.SelectedCategories
		if len(categories) == 0 {
			categories = []string{"email", "phone"}
		}
		checks = append(checks, buildCheck(state, 20, "detect_pii", map[string]any{
			"card_id":    state.ID,
			"categories": stringArray(categories),
			"severity":   stateSeverity(state, "high"),
			"summary":    stateSummary(state, "Claimant PII detected"),
		}))
	}
	return cardEmission{
		Checks:              checks,
		DeniedActionClasses: dedupeStrings(state.DeniedActionClasses...),
	}
}

func emitEnterpriseCopilotCard(state builderCardState) cardEmission {
	regexRule := emitStandardRegexRule(state)
	if regexRule == "" {
		return cardEmission{}
	}
	return cardEmission{
		Checks: []map[string]any{
			buildRegexCheck(state, 10, regexRule, "enterprise_copilot"),
		},
	}
}

func emitCustomerSupportCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 3)
	if len(state.SelectedCategories) > 0 {
		checks = append(checks, buildCheck(state, 10, "detect_pii", map[string]any{
			"card_id":    state.ID,
			"categories": stringArray(state.SelectedCategories),
			"severity":   stateSeverity(state, "high"),
			"summary":    stateSummary(state, "Customer data detected"),
		}))
	}
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 20, regexRule, "customer_support"))
	}
	if state.RequireValidURLs {
		checks = append(checks, buildCheck(state, 30, "valid_urls", map[string]any{
			"card_id":  state.ID,
			"severity": stateSeverity(state, "high"),
			"summary":  stateSummary(state, "Support response contains malformed URLs"),
		}))
	}
	return cardEmission{Checks: checks}
}

func emitDevelopmentCard(state builderCardState) cardEmission {
	checks := make([]map[string]any, 0, 1)
	if regexRule := emitStandardRegexRule(state); regexRule != "" {
		checks = append(checks, buildRegexCheck(state, 10, regexRule, "development_assistant"))
	}
	return cardEmission{
		Checks:               checks,
		AllowedActionClasses: dedupeStrings(state.AllowedActionClasses...),
		DeniedActionClasses:  dedupeStrings(state.DeniedActionClasses...),
	}
}

func buildPatternRule(selectedPresets []string, customPattern string) string {
	literals := make([]string, 0, 8)
	regexes := make([]string, 0, 8)
	for _, preset := range normalizeStringSlice(selectedPresets) {
		definition, ok := presets.Presets[preset]
		if !ok {
			continue
		}
		literals = append(literals, definition.Literals...)
		regexes = append(regexes, definition.Regex...)
	}
	return buildAlternationRegex(literals, regexes, customPattern)
}

func buildAlternationRegex(literals, regexes []string, customPattern string) string {
	parts := make([]string, 0, len(literals)+len(regexes)+1)
	for _, literal := range dedupeStrings(literals...) {
		if strings.TrimSpace(literal) == "" {
			continue
		}
		parts = append(parts, regexp.QuoteMeta(strings.TrimSpace(literal)))
	}
	for _, regexPattern := range dedupeStrings(regexes...) {
		trimmed := strings.TrimSpace(regexPattern)
		if trimmed == "" {
			continue
		}
		parts = append(parts, trimmed)
	}
	if strings.TrimSpace(customPattern) != "" {
		parts = append(parts, strings.TrimSpace(customPattern))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

func literalRegex(values ...string) string {
	literals := dedupeStrings(values...)
	if len(literals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(literals))
	for _, literal := range literals {
		if strings.TrimSpace(literal) == "" {
			continue
		}
		parts = append(parts, regexp.QuoteMeta(strings.TrimSpace(literal)))
	}
	return strings.Join(parts, "|")
}

func buildRegexCheck(state builderCardState, priority int, patternBody string, category string) map[string]any {
	return buildCheck(state, priority, "regex_match", map[string]any{
		"card_id":  state.ID,
		"category": category,
		"rule":     fmt.Sprintf("(?i)(%s)", patternBody),
		"severity": stateSeverity(state, "medium"),
		"summary":  stateSummary(state, "Guardrail policy triggered"),
	})
}

func buildCheck(state builderCardState, priority int, name string, config map[string]any) map[string]any {
	action := normalizeAction(state.Action)
	if action == "" {
		action = "deny"
	}
	return map[string]any{
		"name":     name,
		"enabled":  state.Enabled,
		"priority": priority,
		"config":   config,
		"action": map[string]any{
			"on_fail":     action,
			"redact_with": "[REDACTED]",
		},
	}
}

func supportsScope(cardID, scope string) bool {
	scopes, ok := cardScopes[cardID]
	if !ok {
		return false
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	for _, candidate := range scopes {
		if candidate == scope {
			return true
		}
	}
	return false
}

func stageCheckKey(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "output":
		return "output_guardrails"
	default:
		return "input_guardrails"
	}
}

func guardrailCheckFingerprint(check map[string]any) string {
	config, _ := json.Marshal(check["config"])
	action, _ := json.Marshal(check["action"])
	return strings.ToLower(strings.TrimSpace(stringValue(check["name"]))) + "::" + string(config) + "::" + string(action)
}

func cloneDefinition(definition map[string]any) map[string]any {
	if len(definition) == 0 {
		return map[string]any{}
	}
	payload, err := json.Marshal(definition)
	if err != nil {
		return shallowCloneMap(definition)
	}
	var cloned map[string]any
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return shallowCloneMap(definition)
	}
	return cloned
}

func shallowCloneMap(source map[string]any) map[string]any {
	if source == nil {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func mapValue(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func asObjectArray(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		typed, ok := item.(map[string]any)
		if ok {
			result = append(result, typed)
		}
	}
	return result
}

func objectArray(values []map[string]any) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func stringArray(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return dedupeStrings(typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			rendered := strings.TrimSpace(stringValue(item))
			if rendered != "" && rendered != "<nil>" {
				values = append(values, rendered)
			}
		}
		return dedupeStrings(values...)
	default:
		return nil
	}
}

func normalizeStringSlice(value any) []string {
	values := stringSlice(value)
	for index := range values {
		values[index] = strings.ToLower(strings.TrimSpace(values[index]))
	}
	return dedupeStrings(values...)
}

func boolValue(value any, fallback bool) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func normalizeAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow":
		return "allow"
	case "redact":
		return "redact"
	case "sandbox":
		return "sandbox"
	default:
		return "deny"
	}
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
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

func stateSummary(state builderCardState, fallback string) string {
	if strings.TrimSpace(state.Summary) != "" {
		return strings.TrimSpace(state.Summary)
	}
	return fallback
}

func stateSeverity(state builderCardState, fallback string) string {
	severity := normalizeSeverity(state.Severity)
	if severity == "low" && strings.ToLower(strings.TrimSpace(fallback)) != "low" && strings.TrimSpace(state.Severity) == "" {
		return fallback
	}
	if strings.TrimSpace(severity) == "" {
		return fallback
	}
	return severity
}

func parseList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	segments := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';'
	})
	values := make([]string, 0, len(segments))
	for _, segment := range segments {
		trimmed := strings.TrimSpace(segment)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return dedupeStrings(values...)
}

func dedupeStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
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
	sort.Strings(result)
	return result
}

func containsPreset(values []string, target string) bool {
	return containsNormalizedValue(values, target)
}

func containsNormalizedValue(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}

func parsePositiveInt(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

type stringSet map[string]struct{}

func (s stringSet) addAll(values ...string) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		s[trimmed] = struct{}{}
	}
}

func (s stringSet) values() []string {
	if len(s) == 0 {
		return nil
	}
	values := make([]string, 0, len(s))
	for value := range s {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
