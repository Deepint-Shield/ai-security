package logstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newDryRunMatViewDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DryRun: true,
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	return db
}

func TestApplyMatViewFilters_TenantScopedContextIncludesTenantFilter(t *testing.T) {
	db := newDryRunMatViewDB(t)
	start := time.Unix(1710000000, 0).UTC()
	end := start.Add(2 * time.Hour)
	var rows []struct{}

	query := applyMatViewFilters(
		withLogTenant(context.Background(), "alice@example.com"),
		db.Table("mv_logs_hourly"),
		SearchFilters{
			StartTime: &start,
			EndTime:   &end,
			Providers: []string{"openai"},
		},
	).Find(&rows)

	assert.Contains(t, query.Statement.SQL.String(), "tenant_id = ?")
	require.Contains(t, query.Statement.Vars, "alice@example.com")
}

func TestApplyMatViewTenantFilter_FilterDataQueryIncludesTenantFilter(t *testing.T) {
	db := newDryRunMatViewDB(t)
	var models []string

	query := applyMatViewTenantFilter(
		withLogTenant(context.Background(), "alice@example.com"),
		db.Table("mv_logs_filterdata"),
	).Distinct("model").Pluck("model", &models)

	assert.Contains(t, query.Statement.SQL.String(), "tenant_id = ?")
	require.Contains(t, query.Statement.Vars, "alice@example.com")
}
