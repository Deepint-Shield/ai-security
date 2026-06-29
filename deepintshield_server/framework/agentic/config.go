package agentic

import (
	"os"
	"path/filepath"
	"strings"
)

// AuditModeFromEnv returns the configured audit backpressure mode
// (DEEPINTSHIELD_AUDIT_MODE = best_effort | durable | fail_closed), defaulting
// to best_effort so unconfigured deployments behave exactly as before.
func AuditModeFromEnv() AuditMode {
	return ParseAuditMode(os.Getenv("DEEPINTSHIELD_AUDIT_MODE"))
}

// AuditSpillPath returns the on-disk overflow path for durable / fail_closed
// audit modes (DEEPINTSHIELD_AUDIT_SPILL_PATH), defaulting to a file in the
// OS temp dir. Unused in best_effort mode.
func AuditSpillPath() string {
	if p := strings.TrimSpace(os.Getenv("DEEPINTSHIELD_AUDIT_SPILL_PATH")); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "deepintshield-audit-spill.ndjson")
}
