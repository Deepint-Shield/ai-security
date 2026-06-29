package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditLogStore_IsolatedByTenantAndHashChained(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	tenantA := withLogTenant(context.Background(), "alice@example.com")
	tenantB := withLogTenant(context.Background(), "bob@example.com")

	require.NoError(t, store.CreateAuditLog(tenantA, &AuditLogEntry{
		EventID:      "evt-a-1",
		Timestamp:    time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
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
	require.NoError(t, store.CreateAuditLog(tenantA, &AuditLogEntry{
		EventID:      "evt-a-2",
		Timestamp:    time.Date(2026, 4, 2, 10, 0, 0, 0, time.UTC),
		EventType:    "configuration_change",
		Action:       "team_updated",
		Status:       "success",
		Severity:     "medium",
		ResourceType: "team",
		ResourceID:   "team-a",
		Actor: AuditLogActor{
			UserID: "user-a",
			Email:  "alice@example.com",
		},
		Details: map[string]any{"changed_fields": []string{"name"}},
	}))
	require.NoError(t, store.CreateAuditLog(tenantB, &AuditLogEntry{
		EventID:      "evt-b-1",
		Timestamp:    time.Date(2026, 4, 3, 10, 0, 0, 0, time.UTC),
		EventType:    "security_event",
		Action:       "rate_limit_violation",
		Status:       "blocked",
		Severity:     "high",
		ResourceType: "inference",
		Actor: AuditLogActor{
			UserID: "user-b",
			Email:  "bob@example.com",
		},
	}))

	resultA, err := store.SearchAuditLogs(tenantA, AuditLogFilters{}, &AuditLogSort{Field: "timestamp", Order: "asc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, resultA.Logs, 2)
	assert.EqualValues(t, 2, resultA.TotalCount)
	assert.Equal(t, "evt-a-1", resultA.Logs[0].EventID)
	assert.Equal(t, "evt-a-2", resultA.Logs[1].EventID)
	assert.True(t, resultA.Logs[0].Verification.Verified)
	assert.True(t, resultA.Logs[1].Verification.Verified)
	assert.Equal(t, resultA.Logs[0].Hash, resultA.Logs[1].PreviousHash)

	resultB, err := store.SearchAuditLogs(tenantB, AuditLogFilters{}, &AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, resultB.Logs, 1)
	assert.Equal(t, "evt-b-1", resultB.Logs[0].EventID)
}

func TestAuditLogStore_ListsExportsPerTenant(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	tenantA := withLogTenant(context.Background(), "alice@example.com")
	tenantB := withLogTenant(context.Background(), "bob@example.com")

	require.NoError(t, store.CreateAuditExportJob(tenantA, &AuditExportJob{
		ID:          "exp-a-1",
		Name:        "alice-export",
		Status:      "ready",
		Format:      "csv",
		Destination: "s3",
		CreatedAt:   time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
	}))
	require.NoError(t, store.CreateAuditExportJob(tenantB, &AuditExportJob{
		ID:          "exp-b-1",
		Name:        "bob-export",
		Status:      "ready",
		Format:      "json",
		Destination: "bigquery",
		CreatedAt:   time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC),
	}))

	exportsA, err := store.ListAuditExportJobs(tenantA, 10)
	require.NoError(t, err)
	require.Len(t, exportsA, 1)
	assert.Equal(t, "alice-export", exportsA[0].Name)

	exportsB, err := store.ListAuditExportJobs(tenantB, 10)
	require.NoError(t, err)
	require.Len(t, exportsB, 1)
	assert.Equal(t, "bob-export", exportsB[0].Name)
}

func TestAuditLogStore_AssignsTenantFromContext(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	ctx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	require.NoError(t, store.CreateAuditLog(ctx, &AuditLogEntry{
		EventID:      "evt-tenant",
		EventType:    "data_access",
		Action:       "log_query_executed",
		Status:       "success",
		Severity:     "low",
		ResourceType: "audit_logs",
	}))

	logs, err := store.ListAllAuditLogs(ctx, AuditLogFilters{}, &AuditLogSort{Field: "timestamp", Order: "desc"})
	require.NoError(t, err)
	require.Len(t, logs, 1)
	assert.Equal(t, "alice@example.com", logs[0].TenantID)
}

func TestAuditLogStore_ClaimsDueScheduledExportsPerTenant(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	tenantA := withLogTenant(context.Background(), "alice@example.com")
	tenantB := withLogTenant(context.Background(), "bob@example.com")
	now := time.Now().UTC()
	dueAt := now.Add(-time.Minute)

	require.NoError(t, store.CreateAuditExportJob(tenantA, &AuditExportJob{
		ID:          "exp-scheduled-a",
		Name:        "alice-scheduled-export",
		Status:      "scheduled",
		Format:      "json",
		Destination: "s3",
		Schedule: &AuditExportPlan{
			Frequency: "daily",
			StartDate: "2026-04-08",
			Time:      "02:00",
			Timezone:  "UTC",
		},
		NextRunAt: &dueAt,
		CreatedAt: now,
	}))
	require.NoError(t, store.CreateAuditExportJob(tenantB, &AuditExportJob{
		ID:          "exp-scheduled-b",
		Name:        "bob-scheduled-export",
		Status:      "scheduled",
		Format:      "json",
		Destination: "s3",
		Schedule: &AuditExportPlan{
			Frequency: "daily",
			StartDate: "2026-04-08",
			Time:      "02:00",
			Timezone:  "UTC",
		},
		NextRunAt: &dueAt,
		CreatedAt: now,
	}))

	dueJobsA, err := store.ListDueAuditExportJobs(tenantA, now, 10)
	require.NoError(t, err)
	require.Len(t, dueJobsA, 1)
	assert.Equal(t, "exp-scheduled-a", dueJobsA[0].ID)

	claimed, err := store.ClaimAuditExportJob(tenantA, "exp-scheduled-a", dueAt, now)
	require.NoError(t, err)
	assert.True(t, claimed)

	claimedAgain, err := store.ClaimAuditExportJob(tenantA, "exp-scheduled-a", dueAt, now)
	require.NoError(t, err)
	assert.False(t, claimedAgain)

	job, err := store.FindAuditExportJob(tenantA, "exp-scheduled-a")
	require.NoError(t, err)
	assert.Equal(t, "running", job.Status)
	assert.Nil(t, job.NextRunAt)
	require.NotNil(t, job.LastAttemptedAt)
}
