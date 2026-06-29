package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardrailDecision_AppendsHashChainedAuditEntry(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "alice@example.com")

	require.NoError(t, store.CreateGuardrailDecision(ctx, &GuardrailDecision{
		ID:               "dec-deny-1",
		RequestID:        "req-1",
		Stage:            "output",
		PolicyID:         "policy-pii",
		PolicyVersionID:  "v2",
		Decision:         "deny",
		Reason:           "phi detected in completion",
		ApprovalRequired: false,
		LatencyMs:        12,
		EngineSource:     "policy",
		CreatedAt:        time.Date(2026, 5, 30, 10, 0, 0, 0, time.UTC),
	}))
	require.NoError(t, store.CreateGuardrailDecision(ctx, &GuardrailDecision{
		ID:        "dec-allow-2",
		RequestID: "req-2",
		Stage:     "input",
		Decision:  "allow",
		LatencyMs: 4,
		CreatedAt: time.Date(2026, 5, 30, 10, 1, 0, 0, time.UTC),
	}))

	result, err := store.SearchAuditLogs(ctx, AuditLogFilters{
		EventTypes: []string{"guardrail_decision"},
	}, &AuditLogSort{Field: "timestamp", Order: "asc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, result.Logs, 2)

	first := result.Logs[0]
	second := result.Logs[1]

	assert.Equal(t, "guardrail_deny", first.Action)
	assert.Equal(t, "blocked", first.Status)
	assert.Equal(t, "high", first.Severity)
	assert.Equal(t, "guardrail_decision", first.ResourceType)
	assert.Equal(t, "dec-deny-1", first.ResourceID)
	assert.Equal(t, "req-1", first.RequestID)
	assert.Equal(t, "policy", first.Details["engine_source"])
	assert.Equal(t, "phi detected in completion", first.Details["reason"])
	assert.True(t, first.Verification.Verified)

	assert.Equal(t, "guardrail_allow", second.Action)
	assert.Equal(t, "success", second.Status)
	assert.Equal(t, "low", second.Severity)
	// Chain linkage: the second audit entry should reference the first
	// entry's hash as previous_hash, proving the verdicts joined the
	// shared per-tenant chain rather than splitting into a side ledger.
	assert.Equal(t, first.Hash, second.PreviousHash)

	report, err := store.VerifyAuditChain(ctx, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, AuditChainStatusIntact, report.Chain)
	assert.EqualValues(t, 2, report.TotalEntries)
}
