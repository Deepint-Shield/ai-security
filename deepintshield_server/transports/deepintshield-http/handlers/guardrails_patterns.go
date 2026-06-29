package handlers

// Centralised guardrail detection patterns for the runtime fast-path evaluator.
// Keeping patterns separate from evaluation logic makes them easy to audit,
// extend, and keep in sync with the frontend guardrailPatterns.ts catalog.

// ── Input stage regex rules ─────────────────────────────────────────────────

var defaultInputRegexRules = []struct {
	Priority int
	Rule     string
	Severity string
	OnFail   string
	Summary  string
}{
	{
		Priority: 10,
		Rule:     `(?i)(ignore previous instructions|reveal system prompt|developer mode|jailbreak|bypass safety|override policy)`,
		Severity: "high",
		OnFail:   "deny",
		Summary:  "Prompt injection or jailbreak attempt detected",
	},
	{
		Priority: 20,
		Rule:     `(?i)(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|sk-[a-zA-Z0-9]{20,}|api[_-]?key)`,
		Severity: "critical",
		OnFail:   "redact",
		Summary:  "Sensitive credential material detected",
	},
	{
		Priority: 40,
		Rule:     `(?i)(disable approval|override reviewer|rm -rf|drop table|wire transfer|exfiltrate data|delete bucket)`,
		Severity: "critical",
		OnFail:   "deny",
		Summary:  "High-risk action chain blocked",
	},
}

// ── Output stage regex rules ────────────────────────────────────────────────

var defaultOutputRegexRules = []struct {
	Priority int
	Rule     string
	Severity string
	OnFail   string
	Summary  string
}{
	{
		Priority: 20,
		Rule:     `(?i)(guaranteed cure|certain outcome|no evidence needed)`,
		Severity: "medium",
		OnFail:   "redact",
		Summary:  "Potentially unsafe unsupported claim detected",
	},
}

// ── PII detection categories ────────────────────────────────────────────────

var defaultInputPIICategories = []string{"ssn", "credit_card"}
var defaultOutputPIICategories = []string{"email", "phone", "ssn", "credit_card"}

// ── Legacy rule definitions (flat category/pattern pairs) ───────────────────

var defaultLegacyRules = []struct {
	Category string
	Pattern  string
	Severity string
	Outcome  string
	Summary  string
}{
	{
		Category: "prompt_injection",
		Pattern:  `(?i)(ignore previous instructions|reveal system prompt|developer mode|jailbreak|bypass safety|override policy)`,
		Severity: "high",
		Outcome:  "deny",
		Summary:  "Prompt injection or jailbreak attempt detected",
	},
	{
		Category: "secrets",
		Pattern:  `(?i)(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+PRIVATE KEY-----|sk-[a-zA-Z0-9]{20,}|api[_-]?key)`,
		Severity: "critical",
		Outcome:  "redact",
		Summary:  "Sensitive credential material detected",
	},
	{
		Category: "pii",
		Pattern:  `\b(?:\d{3}-\d{2}-\d{4}|(?:\d[ -]*?){13,16})\b`,
		Severity: "high",
		Outcome:  "redact",
		Summary:  "Sensitive personal or payment data detected",
	},
	{
		Category: "unsafe_action_chain",
		Pattern:  `(?i)(disable approval|override reviewer|rm -rf|drop table|wire transfer|exfiltrate data|delete bucket)`,
		Severity: "critical",
		Outcome:  "deny",
		Summary:  "High-risk action chain blocked",
	},
}

var outputStageLegacyRule = struct {
	Category string
	Pattern  string
	Severity string
	Outcome  string
	Summary  string
}{
	Category: "grounding_gap",
	Pattern:  `(?i)(guaranteed cure|certain outcome|no evidence needed)`,
	Severity: "medium",
	Outcome:  "redact",
	Summary:  "Potentially unsafe unsupported claim detected",
}

// ── Domain blocklists and action class defaults ─────────────────────────────

var defaultBlockedDomains = []string{"pastebin.com", "ngrok.io", "example-malware.test"}
var defaultAllowedActionClasses = []string{"read", "write", "network", "destructive", "exec"}
var defaultDeniedActionClasses = []string{"destructive", "exec"}

// ── PII pattern registry ────────────────────────────────────────────────────

// guardPIIPatterns maps normalised PII category names to their detection regex.
// Add new categories here - guardRuntimePIIPattern and the guard engine's
// piiPattern (runtime_checks.go) both reference this registry.
var guardPIIPatterns = map[string]string{
	"email":       `(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`,
	"phone":       `\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)\d{3}[ -]?\d{4}\b`,
	"ssn":         `\b\d{3}-\d{2}-\d{4}\b`,
	"credit_card": `\b(?:\d[ -]*?){13,16}\b`,
}
