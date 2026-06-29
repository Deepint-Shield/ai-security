package engine

import (
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// Aho-Corasick literal pre-filter for the runtime-check regex evaluator.
//
// Motivation: the union-alternation pre-screen we ship in
// unionRegexForRegexMatchChecks runs a combined RE2 DFA over the input - fast
// (~5-20 µs per request on typical OWASP card sets) but still bounded by the
// DFA size. Aho-Corasick on the REQUIRED literal anchors of every pattern is
// strictly faster because:
//
//   1. Linear-time scan over the input regardless of pattern count (RE2 DFA
//      cost scales sub-linearly with input but its constant grows with
//      union arity).
//   2. Early exit at the first match - for the dominant clean-traffic case
//      (no anchor present anywhere), we scan once and return.
//
// This is the technique Snort / Suricata call "Multi-Pattern Matching" (MPM)
// and what Cloudflare's WAF uses to gate ~600 patterns per request at <10 µs.
//
// Safety: we only build the AC over LITERAL anchors EVERY pattern in the
// union has. If any pattern lacks a literal anchor (e.g. `\d{16}` with no
// fixed substring), the AC pre-filter is unsound for that union and we
// skip it - the union regex still runs as the fast path. The behaviour
// you observe is identical to evaluating each rule individually; only the
// hot-path cost changes.

// ahoCorasickAutomaton is a minimal AC implementation:
//   - goto:  state × byte → next state (sparse via per-state map)
//   - fail:  state → suffix-link state
//   - emit:  state → bool (true = at least one pattern ends here)
//
// Built once at policy compile time, stored in Runtime.compiledRuleUnions's
// sibling cache.
type ahoCorasickAutomaton struct {
	gotoFn []map[byte]int // gotoFn[state][b] = next state, or 0 if absent
	fail   []int          // failure links
	emit   []bool         // true at terminal states
}

// build constructs the automaton from a set of patterns. Patterns are
// lower-cased to match the case-insensitive regex flag used by the OWASP
// cards; callers are responsible for matching against a lower-cased input.
func buildAhoCorasick(patterns []string) *ahoCorasickAutomaton {
	if len(patterns) == 0 {
		return nil
	}
	ac := &ahoCorasickAutomaton{
		gotoFn: []map[byte]int{{}}, // state 0 is the root
		fail:   []int{0},
		emit:   []bool{false},
	}
	for _, p := range patterns {
		p = strings.ToLower(p)
		if p == "" {
			continue
		}
		state := 0
		for i := 0; i < len(p); i++ {
			next, ok := ac.gotoFn[state][p[i]]
			if !ok {
				next = len(ac.gotoFn)
				ac.gotoFn = append(ac.gotoFn, map[byte]int{})
				ac.fail = append(ac.fail, 0)
				ac.emit = append(ac.emit, false)
				ac.gotoFn[state][p[i]] = next
			}
			state = next
		}
		ac.emit[state] = true
	}
	// Build failure links via BFS over the goto trie. The root and its
	// direct children have fail = root; everything else uses the standard
	// AC failure-link computation.
	type bfsNode struct {
		state, depth int
	}
	queue := make([]bfsNode, 0, len(ac.gotoFn))
	for b, next := range ac.gotoFn[0] {
		_ = b
		ac.fail[next] = 0
		queue = append(queue, bfsNode{state: next, depth: 1})
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for b, next := range ac.gotoFn[node.state] {
			// Follow fail links until we either find a state with a goto
			// on b, or hit the root.
			f := ac.fail[node.state]
			for {
				if _, ok := ac.gotoFn[f][b]; ok || f == 0 {
					break
				}
				f = ac.fail[f]
			}
			if fg, ok := ac.gotoFn[f][b]; ok && fg != next {
				ac.fail[next] = fg
			} else {
				ac.fail[next] = 0
			}
			// emit-propagation: a state is terminal if any state along
			// its failure chain is terminal.
			if ac.emit[ac.fail[next]] {
				ac.emit[next] = true
			}
			queue = append(queue, bfsNode{state: next, depth: node.depth + 1})
		}
	}
	return ac
}

// matches reports whether ANY pattern from the build set occurs in input.
// Returns at the first hit - the runtime engine only cares whether at least
// one pattern could match; per-pattern attribution happens downstream in
// the regex DFA scan. Input is assumed already lower-cased by the caller.
func (ac *ahoCorasickAutomaton) matches(input string) bool {
	if ac == nil || len(input) == 0 {
		return false
	}
	state := 0
	for i := 0; i < len(input); i++ {
		b := input[i]
		// Failure-link traversal until goto exists or we hit root.
		for state != 0 {
			if _, ok := ac.gotoFn[state][b]; ok {
				break
			}
			state = ac.fail[state]
		}
		if next, ok := ac.gotoFn[state][b]; ok {
			state = next
		}
		if ac.emit[state] {
			return true
		}
	}
	return false
}

// extractRequiredLiteral pulls out a single literal substring that MUST be
// present in any string the pattern matches. Returns ("", false) when the
// pattern has no useful literal anchor (e.g. `\d{16}`, `^.*$`) - in that
// case the caller MUST NOT use the AC pre-filter for the union containing
// this pattern, because absence of the literal doesn't prove non-match.
//
// Strategy: parse the pattern into a syntax tree, then walk it picking the
// longest contiguous run of literal characters. For alternations we collect
// one literal per branch; if any branch produces no literal, we return
// ("", false) - the union can still pre-screen via regex, just not via AC.
//
// Case-insensitive flag (?i) is preserved by lowercasing the literal here
// and lowercasing the input at match time.
func extractRequiredLiteral(pattern string) (string, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", false
	}
	lit := longestLiteralInTree(re)
	if utf8.RuneCountInString(lit) < 3 {
		// Single-character literals (e.g. punctuation) match nearly every
		// input. Skip them - they'd defeat the pre-filter's selectivity.
		return "", false
	}
	return strings.ToLower(lit), true
}

// extractAllAlternativeLiterals returns one required literal per top-level
// alternative branch. Used when the pattern is itself an alternation: each
// branch's literal must be in the AC, and the AC pre-filter is sound only
// when EVERY branch contributes a literal anchor.
func extractAllAlternativeLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	// Skip leading capturing groups / non-capturing wrappers so an
	// alternation written as `(?:a|b|c)` parses as OpAlternate at the root.
	root := re
	for root.Op == syntax.OpCapture && len(root.Sub) == 1 {
		root = root.Sub[0]
	}
	if root.Op != syntax.OpAlternate {
		// Single-branch pattern - fall back to the longest literal anchor.
		if lit, ok := extractRequiredLiteral(pattern); ok {
			return []string{lit}
		}
		return nil
	}
	out := make([]string, 0, len(root.Sub))
	for _, branch := range root.Sub {
		lit := longestLiteralInTree(branch)
		if utf8.RuneCountInString(lit) < 3 {
			// Branch with no usable literal - the AC pre-filter is unsound
			// for this alternation.
			return nil
		}
		out = append(out, strings.ToLower(lit))
	}
	return out
}

// longestLiteralInTree returns the longest contiguous literal sequence
// reachable from any concatenation in the tree. For non-literal nodes
// (capture, plus, star, alternate, etc.) it recurses into the children
// and returns the longest literal found across them.
func longestLiteralInTree(re *syntax.Regexp) string {
	if re == nil {
		return ""
	}
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpConcat:
		// For concat, scan adjacent OpLiteral runs; the longest such run
		// is the best anchor for this concatenation. Non-literal nodes
		// (e.g. `\d`) break the run.
		var best, current strings.Builder
		flush := func() {
			if current.Len() > best.Len() {
				best.Reset()
				best.WriteString(current.String())
			}
			current.Reset()
		}
		for _, child := range re.Sub {
			if child.Op == syntax.OpLiteral {
				current.WriteString(string(child.Rune))
			} else {
				flush()
				// Even a non-literal child can hide a deeper literal
				// inside it (e.g. capturing group around a literal).
				deeper := longestLiteralInTree(child)
				if len(deeper) > best.Len() {
					best.Reset()
					best.WriteString(deeper)
				}
			}
		}
		flush()
		return best.String()
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return longestLiteralInTree(re.Sub[0])
		}
	case syntax.OpAlternate:
		// For an alternation embedded inside a larger pattern, return the
		// SHORTEST branch literal - any match must satisfy ONE branch, so
		// the shortest is the "guaranteed" common factor. Empty branch
		// (no literal) means we can't produce a common factor at all.
		var shortest string
		first := true
		for _, branch := range re.Sub {
			lit := longestLiteralInTree(branch)
			if lit == "" {
				return ""
			}
			if first || len(lit) < len(shortest) {
				shortest = lit
				first = false
			}
		}
		return shortest
	}
	return ""
}
