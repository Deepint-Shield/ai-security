package agentic

// integrity_types.go - the plain value types + constants the Tool Integrity
// Engine USED to populate. The engine itself (the regex/scoring analysis in the
// premium build) is intentionally NOT part of the open-source PDP: these types
// stay as a stable, zero-valued surface so policies that reference integrity
// operands compile and evaluate against the default (un-diverged) signal, and
// audit rows carry the columns without ever being populated.
//
// Nothing here computes a signal; AnalyzeToolCall / ResolveIntegrityVerdict and
// the behaviour/injection pattern engine live in the premium package only.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// IntegrityRulesetVersion is folded into the decision cache key (see
// DelegationContext.CacheKey) so that, were the integrity ruleset ever to
// change, previously cached verdicts become structurally unreachable. The OSS
// build never populates a signal, so this is effectively a constant key segment.
const IntegrityRulesetVersion = "1"

// Action classes - the integrity lattice, ordered by blast radius. Kept so the
// tool-tier contract surface (ToolContract / ToolTier.ActionClass) and the
// effective_action_class policy operand have a stable vocabulary.
const (
	ActionClassRead        = "read"
	ActionClassWrite       = "write"
	ActionClassNetwork     = "network"
	ActionClassExec        = "exec"
	ActionClassDestructive = "destructive"
)

// IntegrityPosture controls what a divergence does to the verdict. Stored per
// tool. In the OSS PDP nothing diverges, so the posture is carried but inert.
type IntegrityPosture string

const (
	IntegrityPostureFlag     IntegrityPosture = "flag"     // record only, never changes the verdict
	IntegrityPostureApproval IntegrityPosture = "approval" // route to human-in-the-loop
	IntegrityPostureBlock    IntegrityPosture = "block"    // hard deny
)

// NormalizePosture coerces free-form input to a known posture (default flag).
func NormalizePosture(s string) IntegrityPosture {
	switch IntegrityPosture(strings.ToLower(strings.TrimSpace(s))) {
	case IntegrityPostureBlock:
		return IntegrityPostureBlock
	case IntegrityPostureApproval:
		return IntegrityPostureApproval
	default:
		return IntegrityPostureFlag
	}
}

// ToolContract is the declared side of a tool's integrity contract, sourced
// from the approved-tool tiering row. Carried for cache-key / fingerprint use.
type ToolContract struct {
	ActionClass   string
	ArgsSchema    map[string]any
	Posture       IntegrityPosture
	RiskThreshold float64
}

// IntegritySignal is the (never-populated in OSS) deterministic analysis result.
// It stays a plain JSON-stable value type so the Context.Integrity field, the
// integrity policy operands, and the audit columns keep their shape. In the OSS
// PDP this is always the zero value (Diverged=false, Risk=0, empty class).
type IntegritySignal struct {
	DeclaredClass  string   `json:"declared_class,omitempty"`
	EffectiveClass string   `json:"effective_class,omitempty"`
	Risk           float64  `json:"risk"`
	Flags          []string `json:"flags,omitempty"`
	Diverged       bool     `json:"diverged"`
}

// ToolFingerprint is a content hash of a tool's declared contract + observed
// source - its behaviour identity. Used to detect supply-chain contract drift
// (ASI04) via the pinned-fingerprint comparison in Decide.
func ToolFingerprint(tool, actionClass string, argsSchema map[string]any, source string) string {
	schemaJSON := ""
	if len(argsSchema) > 0 {
		if b, err := json.Marshal(argsSchema); err == nil {
			schemaJSON = string(b)
		}
	}
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(tool)),
		strings.ToLower(strings.TrimSpace(actionClass)),
		schemaJSON,
		source,
	}, "|")))
	return hex.EncodeToString(h[:16])
}
