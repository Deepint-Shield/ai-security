package logstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTenantAwareLogStore(t *testing.T) *RDBLogStore {
	dbPath := filepath.Join(t.TempDir(), "logstore-test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, registerTenantCallbacks(db))
	require.NoError(t, db.AutoMigrate(&Log{}, &MCPToolLog{}, &AsyncJob{}, &AuditLogEntry{}, &AuditExportJob{}, &LogExportJob{}, &GuardrailDecision{}))
	return &RDBLogStore{db: db}
}

func withLogTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, schemas.DeepIntShieldContextKeyTenantID, tenantID)
}

func TestLogStore_IsolatedByTenant(t *testing.T) {
	store := setupTenantAwareLogStore(t)
	tenantA := withLogTenant(context.Background(), "tenant-a")
	tenantB := withLogTenant(context.Background(), "tenant-b")
	now := time.Now().UTC()

	require.NoError(t, store.Create(tenantA, &Log{
		ID:        "log-a",
		Timestamp: now,
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "success",
	}))
	require.NoError(t, store.Create(tenantB, &Log{
		ID:        "log-b",
		Timestamp: now.Add(time.Second),
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "success",
	}))

	foundA, err := store.FindByID(tenantA, "log-a")
	require.NoError(t, err)
	assert.Equal(t, "log-a", foundA.ID)

	_, err = store.FindByID(tenantA, "log-b")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))

	resultA, err := store.SearchLogs(tenantA, SearchFilters{}, PaginationOptions{
		Limit:  10,
		Offset: 0,
		SortBy: string(SortByTimestamp),
		Order:  string(SortDesc),
	})
	require.NoError(t, err)
	require.Len(t, resultA.Logs, 1)
	assert.Equal(t, "log-a", resultA.Logs[0].ID)

	resultB, err := store.SearchLogs(tenantB, SearchFilters{}, PaginationOptions{
		Limit:  10,
		Offset: 0,
		SortBy: string(SortByTimestamp),
		Order:  string(SortDesc),
	})
	require.NoError(t, err)
	require.Len(t, resultB.Logs, 1)
	assert.Equal(t, "log-b", resultB.Logs[0].ID)
}
