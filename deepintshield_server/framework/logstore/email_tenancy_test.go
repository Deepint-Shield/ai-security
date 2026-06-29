package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateTenantIDs_ReassignsLogsMCPLogsAndAsyncJobs(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	now := time.Now().UTC()

	legacyOrgCtx := withLogTenant(context.Background(), "org-tenant-1")
	legacyUserCtx := withLogTenant(context.Background(), "user-1")
	targetCtx := withLogTenant(context.Background(), "alice@example.com")

	require.NoError(t, store.Create(legacyOrgCtx, &Log{
		ID:        "log-org",
		Timestamp: now,
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "success",
	}))
	require.NoError(t, store.Create(legacyUserCtx, &Log{
		ID:        "log-user",
		Timestamp: now.Add(time.Second),
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "success",
	}))

	require.NoError(t, store.CreateMCPToolLog(legacyOrgCtx, &MCPToolLog{
		ID:        "mcp-org",
		Timestamp: now,
		ToolName:  "lookup",
		Status:    "success",
	}))

	require.NoError(t, store.CreateAsyncJob(legacyUserCtx, &AsyncJob{
		ID:          "job-user",
		Status:      schemas.AsyncJobStatusCompleted,
		RequestType: schemas.ChatCompletionRequest,
		ResultTTL:   3600,
		CreatedAt:   now,
	}))

	require.NoError(t, store.MigrateTenantIDs(context.Background(), map[string]string{
		"org-tenant-1":      "alice@example.com",
		"user-1":            "alice@example.com",
		"alice@example.com": "alice@example.com",
	}))

	result, err := store.SearchLogs(targetCtx, SearchFilters{}, PaginationOptions{
		Limit:  10,
		Offset: 0,
		SortBy: string(SortByTimestamp),
		Order:  string(SortDesc),
	})
	require.NoError(t, err)
	require.Len(t, result.Logs, 2)
	assert.ElementsMatch(t, []string{"log-org", "log-user"}, []string{result.Logs[0].ID, result.Logs[1].ID})

	mcpLog, err := store.FindMCPToolLog(targetCtx, "mcp-org")
	require.NoError(t, err)
	assert.Equal(t, "mcp-org", mcpLog.ID)

	job, err := store.FindAsyncJobByID(targetCtx, "job-user")
	require.NoError(t, err)
	assert.Equal(t, "job-user", job.ID)
}

func TestMigrateTenantIDs_ClaimsTenantlessRows(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	now := time.Now().UTC()
	targetCtx := withLogTenant(context.Background(), "solo@example.com")

	require.NoError(t, store.db.Create(&Log{
		ID:        "tenantless-log",
		TenantID:  "",
		Timestamp: now,
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "success",
	}).Error)

	require.NoError(t, store.MigrateTenantIDs(context.Background(), map[string]string{
		"": "solo@example.com",
	}))

	found, err := store.FindByID(targetCtx, "tenantless-log")
	require.NoError(t, err)
	assert.Equal(t, "tenantless-log", found.ID)
	assert.Equal(t, "solo@example.com", found.TenantID)
}
