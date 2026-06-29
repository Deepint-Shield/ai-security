package engine

import "strings"

// composeFindingSummary appends a short, redaction-aware excerpt of the
// matched substring to the rule's static summary so operators see *what*
// fired instead of just the card's generic blurb.
//
// Why this matters: the local-policy evaluator builds one big alternation
// regex per card from all selected presets, then stamps the card's static
// Summary on every match. So a BFSI card that includes the
// `destructive_shell` preset reports `rm -rf` matches as "Finance workflow
// override or payment data detected" - technically correct attribution
// (the BFSI card fired) but useless triage signal.
//
// The augmentation keeps the operator-supplied summary first (so existing
// audit consumers don't break) and appends "(matched <excerpt> in <cat>)".
// For sensitive categories (pii, secrets, credit card) we redact the
// excerpt to a length-only hint so audit logs don't replicate the original
// secret.
//
// Excerpts are length-capped at 64 chars to keep summaries scannable in
// table UIs.
func composeFindingSummary(baseSummary, category string, matches []string) string {
	base := strings.TrimSpace(baseSummary)
	if len(matches) == 0 {
		return base
	}
	excerpt := redactExcerptForCategory(category, matches[0])
	switch {
	case base == "" && category == "":
		return "matched: " + excerpt
	case base == "":
		return "matched " + category + ": " + excerpt
	case category == "":
		return base + " (matched: " + excerpt + ")"
	default:
		return base + " (matched " + category + ": " + excerpt + ")"
	}
}

// redactExcerptForCategory returns either the raw match (for innocuous
// categories like prompt_injection where the match IS the attack we want
// the operator to see) or a length-only summary (for categories carrying
// real secrets/PII we don't want re-logged in cleartext).
func redactExcerptForCategory(category, match string) string {
	const maxExcerpt = 64
	trimmed := strings.TrimSpace(match)
	if trimmed == "" {
		return "<empty>"
	}
	if isSensitiveCategory(category) {
		// Show the first 4 chars + length so operators can still cross-
		// reference with raw matches in Details without the audit log
		// re-storing the full secret in plaintext.
		head := trimmed
		if len(head) > 4 {
			head = head[:4]
		}
		return head + "…[" + intToASCII(len(trimmed)) + " chars redacted]"
	}
	if len(trimmed) > maxExcerpt {
		return trimmed[:maxExcerpt] + "…"
	}
	return trimmed
}

// isSensitiveCategory flags categories whose match content shouldn't be
// re-emitted into log/summary text.
func isSensitiveCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "pii", "ssn", "ssn_us", "credit_card", "email", "phone", "iban",
		"passport", "india_pan", "india_aadhaar",
		"bearer_token", "api_key_kv", "aws_access_key", "aws_secret",
		"github_pat", "slack_token", "jwt", "private_key_block",
		"generic_secret_kv", "google_api_key",
		"secrets", "credentials", "secret":
		return true
	}
	return false
}

// intToASCII avoids strconv.Itoa to keep the function tiny + inlineable.
func intToASCII(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
