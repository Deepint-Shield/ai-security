package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestVerifyAuditChain_IntactChainReportsClean(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "alice@example.com")

	for i := 1; i <= 3; i++ {
		require.NoError(t, store.CreateAuditLog(ctx, &AuditLogEntry{
			EventID:      "evt-" + time.Unix(int64(i), 0).Format("150405"),
			Timestamp:    time.Date(2026, 4, i, 10, 0, 0, 0, time.UTC),
			EventType:    "authentication",
			Action:       "user_login",
			Status:       "success",
			Severity:     "low",
			ResourceType: "session",
			Actor: AuditLogActor{
				UserID: "user-a",
				Email:  "alice@example.com",
			},
		}))
	}

	report, err := store.VerifyAuditChain(ctx, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, AuditChainStatusIntact, report.Chain)
	assert.EqualValues(t, 3, report.TotalEntries)
	assert.EqualValues(t, 3, report.VerifiedCount)
	assert.EqualValues(t, 0, report.BrokenCount)
	assert.EqualValues(t, 1, report.FirstSequence)
	assert.EqualValues(t, 3, report.LastSequence)
	assert.Empty(t, report.Breaks)
	assert.NotEmpty(t, report.HeadHash)
}

func TestVerifyAuditChain_EmptyChain(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "alice@example.com")

	report, err := store.VerifyAuditChain(ctx, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, AuditChainStatusEmpty, report.Chain)
	assert.EqualValues(t, 0, report.TotalEntries)
	assert.Empty(t, report.Breaks)
}

func TestVerifyAuditChain_DetectsTamperedRowHash(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "alice@example.com")

	for i := 1; i <= 3; i++ {
		require.NoError(t, store.CreateAuditLog(ctx, &AuditLogEntry{
			EventID:      "evt-tamper-" + time.Unix(int64(i), 0).Format("150405"),
			Timestamp:    time.Date(2026, 4, i, 10, 0, 0, 0, time.UTC),
			EventType:    "configuration_change",
			Action:       "policy_updated",
			Status:       "success",
			Severity:     "medium",
			ResourceType: "policy",
		}))
	}

	// Backdoor the action field on the middle row to simulate tampering
	// after the chain was sealed. Skip hooks so the immutable guard
	// doesn't reject our test mutation.
	require.NoError(t, store.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&AuditLogEntry{}).
		Where("sequence = ?", 2).
		UpdateColumn("action", "policy_silently_modified").Error)

	report, err := store.VerifyAuditChain(ctx, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, AuditChainStatusBroken, report.Chain)
	require.NotEmpty(t, report.Breaks)

	// Tampering one row's content invalidates that row's hash *and*
	// breaks the link from the following row (which still carries the
	// pre-tamper previous_hash). Both signals should be reported.
	kinds := map[string]int{}
	for _, b := range report.Breaks {
		kinds[b.Kind]++
	}
	assert.GreaterOrEqual(t, kinds[AuditChainBreakHashMismatch], 1, "expected hash mismatch report")
}

func TestVerifyAuditChain_DetectsBrokenLinkage(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "alice@example.com")

	for i := 1; i <= 3; i++ {
		require.NoError(t, store.CreateAuditLog(ctx, &AuditLogEntry{
			EventID:      "evt-link-" + time.Unix(int64(i), 0).Format("150405"),
			Timestamp:    time.Date(2026, 4, i, 10, 0, 0, 0, time.UTC),
			EventType:    "data_access",
			Action:       "resource_accessed",
			Status:       "success",
			Severity:     "low",
			ResourceType: "audit_logs",
		}))
	}

	// Overwrite the middle row's previous_hash with a random sentinel.
	// The row's own hash still passes its computed-payload check
	// (because it includes the now-incorrect previous_hash), but the
	// chain link to the prior row is broken.
	require.NoError(t, store.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&AuditLogEntry{}).
		Where("sequence = ?", 2).
		UpdateColumn("previous_hash", "sha256:0000000000000000000000000000000000000000000000000000000000000000").Error)

	report, err := store.VerifyAuditChain(ctx, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, AuditChainStatusBroken, report.Chain)

	saw := false
	for _, b := range report.Breaks {
		if b.Kind == AuditChainBreakPreviousMismatch {
			saw = true
			break
		}
	}
	assert.True(t, saw, "expected previous_hash mismatch report")
}

func TestVerifyAuditChain_DetectsSequenceGap(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := withLogTenant(context.Background(), "alice@example.com")

	for i := 1; i <= 3; i++ {
		require.NoError(t, store.CreateAuditLog(ctx, &AuditLogEntry{
			EventID:      "evt-gap-" + time.Unix(int64(i), 0).Format("150405"),
			Timestamp:    time.Date(2026, 4, i, 10, 0, 0, 0, time.UTC),
			EventType:    "authorization",
			Action:       "permission_denied",
			Status:       "denied",
			Severity:     "high",
			ResourceType: "settings",
		}))
	}

	// Wipe the middle row outright to simulate the chain being thinned.
	require.NoError(t, store.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Where("sequence = ?", 2).
		Delete(&AuditLogEntry{}).Error)

	report, err := store.VerifyAuditChain(ctx, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, AuditChainStatusBroken, report.Chain)
	assert.EqualValues(t, 2, report.TotalEntries)

	saw := false
	for _, b := range report.Breaks {
		if b.Kind == AuditChainBreakSequenceGap {
			saw = true
			break
		}
	}
	assert.True(t, saw, "expected sequence-gap report when a row is missing")
}

func TestVerifyAuditChain_IsolatedPerTenant(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	alice := withLogTenant(context.Background(), "alice@example.com")
	bob := withLogTenant(context.Background(), "bob@example.com")

	require.NoError(t, store.CreateAuditLog(alice, &AuditLogEntry{
		EventID:      "evt-alice-1",
		Timestamp:    time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
		EventType:    "authentication",
		Action:       "user_login",
		Status:       "success",
		Severity:     "low",
		ResourceType: "session",
	}))
	require.NoError(t, store.CreateAuditLog(bob, &AuditLogEntry{
		EventID:      "evt-bob-1",
		Timestamp:    time.Date(2026, 4, 1, 11, 0, 0, 0, time.UTC),
		EventType:    "authentication",
		Action:       "user_login",
		Status:       "success",
		Severity:     "low",
		ResourceType: "session",
	}))

	reportA, err := store.VerifyAuditChain(alice, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, reportA.TotalEntries)
	assert.Equal(t, "alice@example.com", reportA.TenantID)
	assert.Equal(t, AuditChainStatusIntact, reportA.Chain)

	reportB, err := store.VerifyAuditChain(bob, AuditChainVerifyOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, 1, reportB.TotalEntries)
	assert.Equal(t, "bob@example.com", reportB.TenantID)
	assert.Equal(t, AuditChainStatusIntact, reportB.Chain)
}
