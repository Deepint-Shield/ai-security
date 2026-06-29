package engine

import (
	"strings"

	regexp "github.com/grafana/regexp"
)

// piiPatternRegistry maps normalised PII category names to their detection regex.
// Add new categories here - both the portkey check evaluator and the runtime
// fast-path evaluator reference this registry.
var piiPatternRegistry = map[string]string{
	"email":       `(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`,
	"phone":       `\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)\d{3}[ -]?\d{4}\b`,
	"ssn":         `\b\d{3}-\d{2}-\d{4}\b`,
	"credit_card": `\b(?:\d[ -]*?){13,16}\b`,
}

// compiledPIIPattern returns a cached *regexp.Regexp for the given PII category.
func compiledPIIPattern(category string) *regexp.Regexp {
	pattern, ok := piiPatternRegistry[strings.ToLower(strings.TrimSpace(category))]
	if !ok || pattern == "" {
		return nil
	}
	compiled, err := cachedRegexpCompile(pattern)
	if err != nil {
		return nil
	}
	return compiled
}
