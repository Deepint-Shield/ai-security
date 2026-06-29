package engine

import (
	"sync"

	regexp "github.com/grafana/regexp"
)

// regexCache is a process-wide concurrent cache for compiled regexp patterns.
// Keys are the raw pattern strings; values are *regexp.Regexp.
// Using sync.Map because patterns are write-once-read-many and the key set
// stabilises quickly (guardrail definitions change infrequently).
//
// The underlying package is grafana/regexp - a fork of the Go stdlib regexp
// that's typically 2-3x faster on common patterns (literal prefix scanning,
// alternation, char classes). API-compatible drop-in. The compiled
// *regexp.Regexp is shared across all eval goroutines safely.
var regexCache sync.Map

// cachedRegexpCompile returns a compiled *regexp.Regexp for the given pattern,
// using a global cache to avoid recompilation on repeated evaluations.
func cachedRegexpCompile(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Store-or-load: if another goroutine stored first, use its value.
	actual, _ := regexCache.LoadOrStore(pattern, compiled)
	return actual.(*regexp.Regexp), nil
}
