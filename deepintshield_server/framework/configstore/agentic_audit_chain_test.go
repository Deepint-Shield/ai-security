package configstore

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
)

// Default (no key): bare sha256 hex, identical to the original scheme, and
// deterministically recomputable.
func TestChainHash_DefaultSha256_NoKey(t *testing.T) {
	os.Unsetenv("DEEPINTSHIELD_AUDIT_HMAC_KEY")
	h := chainHash("payload-1")
	if len(h) != 64 || strings.Contains(h, ":") {
		t.Fatalf("expected bare 64-char sha256 hex, got %q", h)
	}
	if recomputeChainHash(h, "payload-1") != h {
		t.Fatal("sha256 recompute must round-trip")
	}
}

// Keyed mode: hmac-sha256 prefix, recomputes under the same key, and the
// digest depends on the key (forgery resistance).
func TestChainHash_HMAC_WhenKeySet(t *testing.T) {
	t.Setenv("DEEPINTSHIELD_AUDIT_HMAC_KEY", "secret-key")
	h := chainHash("payload-1")
	if !strings.HasPrefix(h, "hmac-sha256:") {
		t.Fatalf("expected hmac-sha256 prefix, got %q", h)
	}
	if recomputeChainHash(h, "payload-1") != h {
		t.Fatal("hmac recompute must round-trip under the same key")
	}
	t.Setenv("DEEPINTSHIELD_AUDIT_HMAC_KEY", "different-key")
	if recomputeChainHash(h, "payload-1") == h {
		t.Fatal("hmac digest must depend on the key")
	}
}

// The canonical pre-image must be byte-identical at write time and on
// read-back (different tz, microsecond precision) - the property that makes
// the chain verifiable after the DB round-trip.
func TestAuditPayload_StableAcrossReadback(t *testing.T) {
	ts := time.Date(2026, 6, 3, 8, 35, 26, 419764000, time.UTC).Truncate(time.Microsecond)
	row := &tables.TableAgenticDecision{
		DecisionID: "d1", Timestamp: ts, Tool: "finance.report",
		Verdict: "ALLOW", ArgsDigest: "sha256:abc", PrevHash: strings.Repeat("0", 64),
	}
	atWrite := auditPayload(row)

	// Simulate a DB driver returning the same instant in a non-UTC location.
	row.Timestamp = row.Timestamp.In(time.FixedZone("UTC+5", 5*3600))
	onReadback := auditPayload(row)

	if atWrite != onReadback {
		t.Fatalf("payload not stable across read-back:\n write=%q\n read =%q", atWrite, onReadback)
	}
}
