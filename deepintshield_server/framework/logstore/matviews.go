package logstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Materialized view definitions
// ---------------------------------------------------------------------------

// mvLogsHourlyDDL creates a materialized view that pre-aggregates logs into
// hourly buckets grouped by provider, model, status, object_type, and key IDs.
// Includes exact percentiles (p90/p95/p99) computed per hour so they can be
// re-aggregated via weighted averages across wider time ranges.
const mvLogsHourlyDDL = `
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_logs_hourly AS
SELECT
    date_trunc('hour', timestamp) AS hour,
    COALESCE(tenant_id, '') AS tenant_id,
    provider,
    model,
    status,
    object_type,
    selected_key_id,
    COALESCE(virtual_key_id, '') AS virtual_key_id,
    COALESCE(routing_rule_id, '') AS routing_rule_id,
    COUNT(*) AS count,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_count,
    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_count,
    COALESCE(AVG(latency), 0) AS avg_latency,
    COALESCE(percentile_cont(0.90) WITHIN GROUP (ORDER BY latency), 0) AS p90_latency,
    COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency), 0) AS p95_latency,
    COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY latency), 0) AS p99_latency,
    COALESCE(SUM(CASE WHEN cache_debug IS NOT NULL AND cache_debug != '' AND COALESCE((cache_debug::jsonb->>'cache_hit')::boolean, false) THEN 0 ELSE prompt_tokens END), 0) AS total_prompt_tokens,
    COALESCE(SUM(CASE WHEN cache_debug IS NOT NULL AND cache_debug != '' AND COALESCE((cache_debug::jsonb->>'cache_hit')::boolean, false) THEN 0 ELSE completion_tokens END), 0) AS total_completion_tokens,
    COALESCE(SUM(CASE WHEN cache_debug IS NOT NULL AND cache_debug != '' AND COALESCE((cache_debug::jsonb->>'cache_hit')::boolean, false) THEN 0 ELSE total_tokens END), 0) AS total_tokens,
    COALESCE(SUM(cached_read_tokens), 0) AS total_cached_read_tokens,
    COALESCE(SUM(CASE WHEN cache_debug IS NOT NULL AND cache_debug != '' AND COALESCE((cache_debug::jsonb->>'cache_hit')::boolean, false) THEN COALESCE(NULLIF(cached_read_tokens, 0), prompt_tokens) ELSE cached_read_tokens END), 0) AS total_effective_cached_prompt_tokens,
    COALESCE(SUM(cost), 0) AS total_cost,
    COALESCE(SUM(cache_savings), 0) AS total_cache_savings
FROM logs
WHERE status IN ('success', 'error')
  AND object_type NOT LIKE 'agentic.%'
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9
`

// mvLogsHourlyUniqueIdx is required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
const mvLogsHourlyUniqueIdx = `
CREATE UNIQUE INDEX IF NOT EXISTS mv_logs_hourly_uniq
ON mv_logs_hourly (hour, tenant_id, provider, model, status, object_type, selected_key_id, virtual_key_id, routing_rule_id)
`

// mvLogsFilterdataDDL creates a materialized view of distinct filter values
// (models, providers, keys, routing rules, engines) from logs in the last 60
// days. Used to populate filter dropdowns without scanning the raw table.
const mvLogsFilterdataDDL = `
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_logs_filterdata AS
SELECT DISTINCT
    COALESCE(tenant_id, '') AS tenant_id,
    model,
    provider,
    selected_key_id,
    selected_key_name,
    COALESCE(virtual_key_id, '') AS virtual_key_id,
    COALESCE(virtual_key_name, '') AS virtual_key_name,
    COALESCE(routing_rule_id, '') AS routing_rule_id,
    COALESCE(routing_rule_name, '') AS routing_rule_name,
    COALESCE(routing_engines_used, '') AS routing_engines_used
FROM logs
WHERE timestamp >= NOW() - INTERVAL '60 days'
  AND model IS NOT NULL AND model != ''
  AND object_type NOT LIKE 'agentic.%'
`

// mvLogsFilterdataUniqueIdx is required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
// Includes both ID and name columns so renamed keys don't cause duplicate violations.
const mvLogsFilterdataUniqueIdx = `
CREATE UNIQUE INDEX IF NOT EXISTS mv_logs_filterdata_uniq
ON mv_logs_filterdata (tenant_id, model, provider, selected_key_id, selected_key_name, virtual_key_id, virtual_key_name, routing_rule_id, routing_rule_name, routing_engines_used)
`

// ---------------------------------------------------------------------------
// View lifecycle
// ---------------------------------------------------------------------------

// ensureMatViews creates materialized views and their unique indexes if they
// don't already exist. Called once on startup.
func ensureMatViews(ctx context.Context, db *gorm.DB) error {
	if err := recreateLegacyMatViewsIfNeeded(ctx, db); err != nil {
		return err
	}
	for _, ddl := range []string{
		mvLogsHourlyDDL,
		mvLogsHourlyUniqueIdx,
		mvLogsFilterdataDDL,
		mvLogsFilterdataUniqueIdx,
	} {
		if err := db.WithContext(ctx).Exec(ddl).Error; err != nil {
			return fmt.Errorf("failed to create materialized view: %w", err)
		}
	}
	return nil
}

func recreateLegacyMatViewsIfNeeded(ctx context.Context, db *gorm.DB) error {
	requiredColumns := map[string][]string{
		"mv_logs_hourly":     {"tenant_id", "total_cache_savings", "total_effective_cached_prompt_tokens"},
		"mv_logs_filterdata": {"tenant_id"},
	}

	requiredDefinitionFragments := map[string][]string{
		"mv_logs_hourly": {
			"then 0 else prompt_tokens end",
			"then 0 else completion_tokens end",
			"then 0 else total_tokens end",
			"coalesce(nullif(cached_read_tokens, 0), prompt_tokens)",
			// Forces a one-time recreate so the view picks up the
			// "object_type NOT LIKE 'agentic.%'" exclusion (keeps dashboard
			// aggregates LLM-only now that agentic activity rows live in logs).
			"agentic.%",
		},
		"mv_logs_filterdata": {
			// Same: keep the model/provider/key filter dropdowns LLM-only.
			"agentic.%",
		},
	}

	for viewName, columns := range requiredColumns {
		hasAllColumns, err := matViewHasColumns(ctx, db, viewName, columns)
		if err != nil {
			return err
		}
		hasCompatibleDefinition := true
		if fragments := requiredDefinitionFragments[viewName]; len(fragments) > 0 {
			hasCompatibleDefinition, err = matViewDefinitionContains(ctx, db, viewName, fragments)
			if err != nil {
				return err
			}
		}
		if hasAllColumns && hasCompatibleDefinition {
			continue
		}
		if err := db.WithContext(ctx).Exec("DROP MATERIALIZED VIEW IF EXISTS " + viewName + " CASCADE").Error; err != nil {
			return fmt.Errorf("failed to recreate legacy materialized view %s: %w", viewName, err)
		}
	}

	return nil
}

func matViewHasColumns(ctx context.Context, db *gorm.DB, viewName string, requiredColumns []string) (bool, error) {
	if len(requiredColumns) == 0 {
		return true, nil
	}

	var count int64
	if err := db.WithContext(ctx).Raw(`
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = ?
		  AND column_name IN ?
	`, viewName, requiredColumns).Scan(&count).Error; err != nil {
		return false, fmt.Errorf("failed to inspect materialized view %s: %w", viewName, err)
	}

	return count == int64(len(requiredColumns)), nil
}

func matViewDefinitionContains(ctx context.Context, db *gorm.DB, viewName string, requiredFragments []string) (bool, error) {
	if len(requiredFragments) == 0 {
		return true, nil
	}

	var definition string
	tx := db.WithContext(ctx).Raw(`
		SELECT definition
		FROM pg_matviews
		WHERE schemaname = current_schema()
		  AND matviewname = ?
	`, viewName).Scan(&definition)
	if tx.Error != nil {
		return false, fmt.Errorf("failed to inspect materialized view definition %s: %w", viewName, tx.Error)
	}
	if tx.RowsAffected == 0 {
		return false, nil
	}

	definition = strings.ToLower(definition)
	for _, fragment := range requiredFragments {
		if !strings.Contains(definition, strings.ToLower(fragment)) {
			return false, nil
		}
	}

	return true, nil
}

// refreshMatViews refreshes all materialized views concurrently (non-blocking
// for readers). Uses a PostgreSQL advisory try-lock so that in multi-replica
// deployments only one instance refreshes at a time - others skip silently.
func refreshMatViews(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB for matview refresh: %w", err)
	}

	// Use a dedicated connection so lock/unlock/refresh all run on the same session.
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to get dedicated connection for matview refresh: %w", err)
	}
	defer conn.Close()

	// Try to acquire advisory lock; skip refresh if another replica holds it.
	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", matviewRefreshAdvisoryLockKey).Scan(&acquired); err != nil {
		return fmt.Errorf("failed to try advisory lock for matview refresh: %w", err)
	}
	if !acquired {
		return nil // another replica is refreshing
	}
	defer func() {
		// Release lock explicitly; connection close would also release session-scoped locks.
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", matviewRefreshAdvisoryLockKey)
	}()

	for _, view := range []string{"mv_logs_hourly", "mv_logs_filterdata"} {
		if _, err := conn.ExecContext(ctx, "REFRESH MATERIALIZED VIEW CONCURRENTLY "+view); err != nil {
			return fmt.Errorf("failed to refresh %s: %w", view, err)
		}
	}
	return nil
}

// startMatViewRefresher launches a background goroutine that periodically
// refreshes materialized views. Returns a stop function for graceful shutdown.
func startMatViewRefresher(ctx context.Context, db *gorm.DB, interval time.Duration, logger schemas.Logger) func() {
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := refreshMatViews(ctx, db); err != nil {
					logger.Warn(fmt.Sprintf("logstore: matview refresh failed: %s", err))
				}
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			}
		}
	}()
	return func() { close(stopCh) }
}

// canUseMatView returns true if the given filters can be served from
// mv_logs_hourly. Per-row filters (content search, metadata, numeric ranges)
// require the raw logs table.
//
// Workspace narrowing also forces the raw-table path: mv_logs_hourly's
// GROUP BY includes (tenant_id, provider, model, status, ...) but NOT
// workspace_id, so aggregates roll up across every workspace under the
// same tenant. Without this guard the dashboard "GCP-Prod / GCP-Prod
// Workspace" view leaked rows from sibling workspaces (e.g.
// "GCP-Prod-2 / GCP-Prod2_Workspace") because they share a tenant_id
// in the matview. The follow-up perf fix is to add workspace_id as a
// grouping column on the matview + index, then drop this guard.
func canUseMatView(f SearchFilters) bool {
	return f.ContentSearch == "" &&
		len(f.MetadataFilters) == 0 &&
		len(f.RoutingEngineUsed) == 0 &&
		f.MinLatency == nil && f.MaxLatency == nil &&
		f.MinTokens == nil && f.MaxTokens == nil &&
		f.MinCost == nil && f.MaxCost == nil &&
		!f.MissingCostOnly &&
		// Agentic activity rows are excluded from mv_logs_hourly (it's the
		// LLM-only AI Logs aggregate), so an agentic-scoped query (the Agentic
		// Logs view) must use the raw logs table or its KPIs/histograms would
		// count zero.
		!objectsIncludeAgentic(f.Objects) &&
		strings.TrimSpace(f.WorkspaceID) == "" &&
		// mv_logs_hourly is keyed on tenant_id only - it doesn't carry a
		// workspace_id column. When the active-org allowlist is in use we
		// must fall through to the slow path so the workspace filter
		// actually applies; otherwise switching tenants in the sidebar
		// leaves the dashboard showing another org's traffic.
		f.AllowedWorkspaceIDs == nil
}

// ---------------------------------------------------------------------------
// Mat-view filter helpers
// ---------------------------------------------------------------------------

// applyMatViewFilters builds WHERE clauses for queries against mv_logs_hourly.
func applyMatViewFilters(ctx context.Context, q *gorm.DB, f SearchFilters) *gorm.DB {
	q = applyMatViewTenantFilter(ctx, q)
	if f.StartTime != nil {
		q = q.Where("hour >= date_trunc('hour', ?::timestamptz)", *f.StartTime)
	}
	if f.EndTime != nil {
		q = q.Where("hour <= ?", *f.EndTime)
	}
	if len(f.Providers) > 0 {
		q = q.Where("provider IN ?", f.Providers)
	}
	if len(f.Models) > 0 {
		q = q.Where("model IN ?", f.Models)
	}
	if len(f.Status) > 0 {
		q = q.Where("status IN ?", f.Status)
	}
	if len(f.Objects) > 0 {
		q = q.Where("object_type IN ?", f.Objects)
	}
	if len(f.SelectedKeyIDs) > 0 {
		q = q.Where("selected_key_id IN ?", f.SelectedKeyIDs)
	}
	if len(f.VirtualKeyIDs) > 0 {
		q = q.Where("virtual_key_id IN ?", f.VirtualKeyIDs)
	}
	if len(f.RoutingRuleIDs) > 0 {
		q = q.Where("routing_rule_id IN ?", f.RoutingRuleIDs)
	}
	return q
}

func applyMatViewTenantFilter(ctx context.Context, q *gorm.DB) *gorm.DB {
	if tenantID := tenantctx.TenantIDFromContext(ctx); tenantID != "" {
		return q.Where("tenant_id = ?", tenantID)
	}
	return q
}

// ---------------------------------------------------------------------------
// Mat-view query methods (called from rdb.go when dialect == "postgres")
// ---------------------------------------------------------------------------

// getCountFromMatView returns the total number of logs matching the filters
// by summing pre-aggregated counts from mv_logs_hourly.
func (s *RDBLogStore) getCountFromMatView(ctx context.Context, filters SearchFilters) (int64, error) {
	var total int64
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select("COALESCE(SUM(count), 0)").Row().Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// getStatsFromMatView computes dashboard statistics (total requests, success
// rate, average latency, total tokens, total cost) from mv_logs_hourly.
// Latency is a weighted average across hourly buckets.
func (s *RDBLogStore) getStatsFromMatView(ctx context.Context, filters SearchFilters) (*SearchStats, error) {
	var result struct {
		TotalCount   int64   `gorm:"column:total_count"`
		SuccessCount int64   `gorm:"column:success_count"`
		AvgLatency   float64 `gorm:"column:avg_latency"`
		TotalTokens  int64   `gorm:"column:total_tokens"`
		TotalCost    float64 `gorm:"column:total_cost"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(`
		COALESCE(SUM(count), 0) AS total_count,
		COALESCE(SUM(success_count), 0) AS success_count,
		CASE WHEN SUM(count) > 0 THEN SUM(avg_latency * count) / SUM(count) ELSE 0 END AS avg_latency,
		COALESCE(SUM(total_tokens), 0) AS total_tokens,
		COALESCE(SUM(total_cost), 0) AS total_cost
	`).Scan(&result).Error; err != nil {
		return nil, err
	}

	var successRate float64
	if result.TotalCount > 0 {
		successRate = float64(result.SuccessCount) / float64(result.TotalCount) * 100
	}
	return &SearchStats{
		TotalRequests:  result.TotalCount,
		SuccessRate:    successRate,
		AverageLatency: result.AvgLatency,
		TotalTokens:    result.TotalTokens,
		TotalCost:      result.TotalCost,
	}, nil
}

// getHistogramFromMatView returns time-bucketed request counts (total,
// success, error) by re-aggregating hourly buckets from mv_logs_hourly.
func (s *RDBLogStore) getHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*HistogramResult, error) {
	var results []struct {
		BucketTimestamp int64 `gorm:"column:bucket_timestamp"`
		Total           int64 `gorm:"column:total"`
		Success         int64 `gorm:"column:success"`
		ErrorCount      int64 `gorm:"column:error_count"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		SUM(count) AS total,
		SUM(success_count) AS success,
		SUM(error_count) AS error_count
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	resultMap := make(map[int64]*struct{ total, success, errCount int64 }, len(results))
	for _, r := range results {
		resultMap[r.BucketTimestamp] = &struct{ total, success, errCount int64 }{r.Total, r.Success, r.ErrorCount}
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]HistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := HistogramBucket{Timestamp: time.Unix(ts, 0).UTC()}
		if a, ok := resultMap[ts]; ok {
			b.Count = a.total
			b.Success = a.success
			b.Error = a.errCount
		}
		buckets = append(buckets, b)
	}
	return &HistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds}, nil
}

// getTokenHistogramFromMatView returns time-bucketed token usage (prompt,
// completion, total, cached) from mv_logs_hourly.
func (s *RDBLogStore) getTokenHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*TokenHistogramResult, error) {
	var results []struct {
		BucketTimestamp             int64 `gorm:"column:bucket_timestamp"`
		PromptTokens                int64 `gorm:"column:prompt_tokens"`
		CompletionTokens            int64 `gorm:"column:completion_tokens"`
		TotalTokens                 int64 `gorm:"column:total_tkns"`
		CachedReadTokens            int64 `gorm:"column:cached_read_tokens"`
		EffectiveCachedPromptTokens int64 `gorm:"column:effective_cached_prompt_tokens"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		SUM(total_prompt_tokens) AS prompt_tokens,
		SUM(total_completion_tokens) AS completion_tokens,
		SUM(total_tokens) AS total_tkns,
		SUM(total_cached_read_tokens) AS cached_read_tokens,
		SUM(total_effective_cached_prompt_tokens) AS effective_cached_prompt_tokens
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	resultMap := make(map[int64]int, len(results))
	for i, r := range results {
		resultMap[r.BucketTimestamp] = i
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]TokenHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := TokenHistogramBucket{Timestamp: time.Unix(ts, 0).UTC()}
		if idx, ok := resultMap[ts]; ok {
			r := results[idx]
			b.PromptTokens = r.PromptTokens
			b.CompletionTokens = r.CompletionTokens
			b.TotalTokens = r.TotalTokens
			b.CachedReadTokens = r.CachedReadTokens
			b.EffectiveCachedPromptTokens = r.EffectiveCachedPromptTokens
		}
		buckets = append(buckets, b)
	}
	return &TokenHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds}, nil
}

// getCostHistogramFromMatView returns time-bucketed cost data with per-model
// breakdown from mv_logs_hourly.
func (s *RDBLogStore) getCostHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*CostHistogramResult, error) {
	var results []struct {
		BucketTimestamp int64   `gorm:"column:bucket_timestamp"`
		Model           string  `gorm:"column:model"`
		Cost            float64 `gorm:"column:cost"`
		CacheSavings    float64 `gorm:"column:cache_savings"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		model,
		SUM(total_cost) AS cost,
		SUM(total_cache_savings) AS cache_savings
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp, model").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	type bucketAgg struct {
		totalCost    float64
		cacheSavings float64
		byModel      map[string]float64
		byModelCache map[string]float64
	}
	grouped := make(map[int64]*bucketAgg)
	modelsSet := make(map[string]struct{})
	for _, r := range results {
		a, ok := grouped[r.BucketTimestamp]
		if !ok {
			a = &bucketAgg{
				byModel:      make(map[string]float64),
				byModelCache: make(map[string]float64),
			}
			grouped[r.BucketTimestamp] = a
		}
		a.totalCost += r.Cost
		a.cacheSavings += r.CacheSavings
		a.byModel[r.Model] += r.Cost
		a.byModelCache[r.Model] += r.CacheSavings
		modelsSet[r.Model] = struct{}{}
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]CostHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := CostHistogramBucket{
			Timestamp:           time.Unix(ts, 0).UTC(),
			ByModel:             make(map[string]float64),
			ByModelCacheSavings: make(map[string]float64),
		}
		if a, ok := grouped[ts]; ok {
			b.TotalCost = a.totalCost
			b.CacheSavings = a.cacheSavings
			b.ByModel = a.byModel
			b.ByModelCacheSavings = a.byModelCache
		}
		buckets = append(buckets, b)
	}

	models := sortedStringKeys(modelsSet)
	return &CostHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds, Models: models}, nil
}

// getModelHistogramFromMatView returns time-bucketed model usage with
// success/error breakdown per model from mv_logs_hourly.
func (s *RDBLogStore) getModelHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ModelHistogramResult, error) {
	var results []struct {
		BucketTimestamp int64  `gorm:"column:bucket_timestamp"`
		Model           string `gorm:"column:model"`
		Total           int64  `gorm:"column:total"`
		Success         int64  `gorm:"column:success"`
		ErrorCount      int64  `gorm:"column:error_count"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		model,
		SUM(count) AS total,
		SUM(success_count) AS success,
		SUM(error_count) AS error_count
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp, model").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	type bucketAgg struct {
		byModel map[string]ModelUsageStats
	}
	grouped := make(map[int64]*bucketAgg)
	modelsSet := make(map[string]struct{})
	for _, r := range results {
		a, ok := grouped[r.BucketTimestamp]
		if !ok {
			a = &bucketAgg{byModel: make(map[string]ModelUsageStats)}
			grouped[r.BucketTimestamp] = a
		}
		existing := a.byModel[r.Model]
		existing.Total += r.Total
		existing.Success += r.Success
		existing.Error += r.ErrorCount
		a.byModel[r.Model] = existing
		modelsSet[r.Model] = struct{}{}
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]ModelHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := ModelHistogramBucket{Timestamp: time.Unix(ts, 0).UTC(), ByModel: make(map[string]ModelUsageStats)}
		if a, ok := grouped[ts]; ok {
			b.ByModel = a.byModel
		}
		buckets = append(buckets, b)
	}

	models := sortedStringKeys(modelsSet)
	return &ModelHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds, Models: models}, nil
}

// getLatencyHistogramFromMatView returns time-bucketed latency percentiles
// (avg, p90, p95, p99) from mv_logs_hourly. Percentiles are re-aggregated
// across hourly buckets using weighted averages (weighted by request count).
func (s *RDBLogStore) getLatencyHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*LatencyHistogramResult, error) {
	var results []struct {
		BucketTimestamp int64   `gorm:"column:bucket_timestamp"`
		AvgLatency      float64 `gorm:"column:avg_lat"`
		P90Latency      float64 `gorm:"column:p90_lat"`
		P95Latency      float64 `gorm:"column:p95_lat"`
		P99Latency      float64 `gorm:"column:p99_lat"`
		TotalRequests   int64   `gorm:"column:total_requests"`
	}
	// Weighted average of percentiles across hourly buckets
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		CASE WHEN SUM(count) > 0 THEN SUM(avg_latency * count) / SUM(count) ELSE 0 END AS avg_lat,
		CASE WHEN SUM(count) > 0 THEN SUM(p90_latency * count) / SUM(count) ELSE 0 END AS p90_lat,
		CASE WHEN SUM(count) > 0 THEN SUM(p95_latency * count) / SUM(count) ELSE 0 END AS p95_lat,
		CASE WHEN SUM(count) > 0 THEN SUM(p99_latency * count) / SUM(count) ELSE 0 END AS p99_lat,
		SUM(count) AS total_requests
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	resultMap := make(map[int64]int, len(results))
	for i, r := range results {
		resultMap[r.BucketTimestamp] = i
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]LatencyHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := LatencyHistogramBucket{Timestamp: time.Unix(ts, 0).UTC()}
		if idx, ok := resultMap[ts]; ok {
			r := results[idx]
			b.AvgLatency = r.AvgLatency
			b.P90Latency = r.P90Latency
			b.P95Latency = r.P95Latency
			b.P99Latency = r.P99Latency
			b.TotalRequests = r.TotalRequests
		}
		buckets = append(buckets, b)
	}
	return &LatencyHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds}, nil
}

// getProviderCostHistogramFromMatView returns time-bucketed cost data with
// per-provider breakdown from mv_logs_hourly.
func (s *RDBLogStore) getProviderCostHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ProviderCostHistogramResult, error) {
	var results []struct {
		BucketTimestamp int64   `gorm:"column:bucket_timestamp"`
		Provider        string  `gorm:"column:provider"`
		Cost            float64 `gorm:"column:cost"`
		CacheSavings    float64 `gorm:"column:cache_savings"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		provider,
		SUM(total_cost) AS cost,
		SUM(total_cache_savings) AS cache_savings
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp, provider").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	type bucketAgg struct {
		totalCost              float64
		cacheSavings           float64
		byProvider             map[string]float64
		byProviderCacheSavings map[string]float64
	}
	grouped := make(map[int64]*bucketAgg)
	providersSet := make(map[string]struct{})
	for _, r := range results {
		a, ok := grouped[r.BucketTimestamp]
		if !ok {
			a = &bucketAgg{
				byProvider:             make(map[string]float64),
				byProviderCacheSavings: make(map[string]float64),
			}
			grouped[r.BucketTimestamp] = a
		}
		a.totalCost += r.Cost
		a.cacheSavings += r.CacheSavings
		a.byProvider[r.Provider] += r.Cost
		a.byProviderCacheSavings[r.Provider] += r.CacheSavings
		providersSet[r.Provider] = struct{}{}
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]ProviderCostHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := ProviderCostHistogramBucket{
			Timestamp:              time.Unix(ts, 0).UTC(),
			ByProvider:             make(map[string]float64),
			ByProviderCacheSavings: make(map[string]float64),
		}
		if a, ok := grouped[ts]; ok {
			b.TotalCost = a.totalCost
			b.CacheSavings = a.cacheSavings
			b.ByProvider = a.byProvider
			b.ByProviderCacheSavings = a.byProviderCacheSavings
		}
		buckets = append(buckets, b)
	}

	providers := sortedStringKeys(providersSet)
	return &ProviderCostHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds, Providers: providers}, nil
}

// getProviderTokenHistogramFromMatView returns time-bucketed token usage with
// per-provider breakdown from mv_logs_hourly.
func (s *RDBLogStore) getProviderTokenHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ProviderTokenHistogramResult, error) {
	var results []struct {
		BucketTimestamp  int64  `gorm:"column:bucket_timestamp"`
		Provider         string `gorm:"column:provider"`
		PromptTokens     int64  `gorm:"column:prompt_tokens"`
		CompletionTokens int64  `gorm:"column:completion_tokens"`
		TotalTokens      int64  `gorm:"column:total_tkns"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		provider,
		SUM(total_prompt_tokens) AS prompt_tokens,
		SUM(total_completion_tokens) AS completion_tokens,
		SUM(total_tokens) AS total_tkns,
		SUM(total_cached_read_tokens) AS cached_read_tokens
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp, provider").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	type provAgg struct {
		prompt, completion, total int64
	}
	type bucketAgg struct {
		byProvider map[string]*provAgg
	}
	grouped := make(map[int64]*bucketAgg)
	providersSet := make(map[string]struct{})
	for _, r := range results {
		a, ok := grouped[r.BucketTimestamp]
		if !ok {
			a = &bucketAgg{byProvider: make(map[string]*provAgg)}
			grouped[r.BucketTimestamp] = a
		}
		pa, ok := a.byProvider[r.Provider]
		if !ok {
			pa = &provAgg{}
			a.byProvider[r.Provider] = pa
		}
		pa.prompt += r.PromptTokens
		pa.completion += r.CompletionTokens
		pa.total += r.TotalTokens
		providersSet[r.Provider] = struct{}{}
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]ProviderTokenHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := ProviderTokenHistogramBucket{Timestamp: time.Unix(ts, 0).UTC(), ByProvider: make(map[string]ProviderTokenStats)}
		if a, ok := grouped[ts]; ok {
			for prov, pa := range a.byProvider {
				b.ByProvider[prov] = ProviderTokenStats{
					PromptTokens:     pa.prompt,
					CompletionTokens: pa.completion,
					TotalTokens:      pa.total,
				}
			}
		}
		buckets = append(buckets, b)
	}

	providers := sortedStringKeys(providersSet)
	return &ProviderTokenHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds, Providers: providers}, nil
}

// getProviderLatencyHistogramFromMatView returns time-bucketed latency
// percentiles with per-provider breakdown from mv_logs_hourly. Percentiles
// are re-aggregated using weighted averages.
func (s *RDBLogStore) getProviderLatencyHistogramFromMatView(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ProviderLatencyHistogramResult, error) {
	var results []struct {
		BucketTimestamp int64   `gorm:"column:bucket_timestamp"`
		Provider        string  `gorm:"column:provider"`
		AvgLatency      float64 `gorm:"column:avg_lat"`
		P90Latency      float64 `gorm:"column:p90_lat"`
		P95Latency      float64 `gorm:"column:p95_lat"`
		P99Latency      float64 `gorm:"column:p99_lat"`
		TotalRequests   int64   `gorm:"column:total_requests"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(fmt.Sprintf(`
		CAST(FLOOR(EXTRACT(EPOCH FROM hour) / %d) * %d AS BIGINT) AS bucket_timestamp,
		provider,
		CASE WHEN SUM(count) > 0 THEN SUM(avg_latency * count) / SUM(count) ELSE 0 END AS avg_lat,
		CASE WHEN SUM(count) > 0 THEN SUM(p90_latency * count) / SUM(count) ELSE 0 END AS p90_lat,
		CASE WHEN SUM(count) > 0 THEN SUM(p95_latency * count) / SUM(count) ELSE 0 END AS p95_lat,
		CASE WHEN SUM(count) > 0 THEN SUM(p99_latency * count) / SUM(count) ELSE 0 END AS p99_lat,
		SUM(count) AS total_requests
	`, bucketSizeSeconds, bucketSizeSeconds)).
		Group("bucket_timestamp, provider").
		Order("bucket_timestamp ASC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	type bucketAgg struct {
		byProvider map[string]ProviderLatencyStats
	}
	grouped := make(map[int64]*bucketAgg)
	providersSet := make(map[string]struct{})
	for _, r := range results {
		a, ok := grouped[r.BucketTimestamp]
		if !ok {
			a = &bucketAgg{byProvider: make(map[string]ProviderLatencyStats)}
			grouped[r.BucketTimestamp] = a
		}
		a.byProvider[r.Provider] = ProviderLatencyStats{
			AvgLatency:    r.AvgLatency,
			P90Latency:    r.P90Latency,
			P95Latency:    r.P95Latency,
			P99Latency:    r.P99Latency,
			TotalRequests: r.TotalRequests,
		}
		providersSet[r.Provider] = struct{}{}
	}

	allTimestamps := generateBucketTimestamps(filters.StartTime, filters.EndTime, bucketSizeSeconds)
	buckets := make([]ProviderLatencyHistogramBucket, 0, len(allTimestamps))
	for _, ts := range allTimestamps {
		b := ProviderLatencyHistogramBucket{Timestamp: time.Unix(ts, 0).UTC(), ByProvider: make(map[string]ProviderLatencyStats)}
		if a, ok := grouped[ts]; ok {
			b.ByProvider = a.byProvider
		}
		buckets = append(buckets, b)
	}

	providers := sortedStringKeys(providersSet)
	return &ProviderLatencyHistogramResult{Buckets: buckets, BucketSizeSeconds: bucketSizeSeconds, Providers: providers}, nil
}

// getModelRankingsFromMatView returns models ranked by usage with trend
// comparison to the previous period of equal duration from mv_logs_hourly.
func (s *RDBLogStore) getModelRankingsFromMatView(ctx context.Context, filters SearchFilters) (*ModelRankingResult, error) {
	var results []struct {
		Model        string  `gorm:"column:model"`
		Provider     string  `gorm:"column:provider"`
		Total        int64   `gorm:"column:total"`
		SuccessCount int64   `gorm:"column:success_count"`
		AvgLatency   float64 `gorm:"column:avg_lat"`
		TotalTokens  int64   `gorm:"column:total_tkns"`
		TotalCost    float64 `gorm:"column:total_cost"`
	}
	q := s.db.WithContext(ctx).Table("mv_logs_hourly")
	q = applyMatViewFilters(ctx, q, filters)
	if err := q.Select(`
		model, provider,
		SUM(count) AS total,
		SUM(success_count) AS success_count,
		CASE WHEN SUM(count) > 0 THEN SUM(avg_latency * count) / SUM(count) ELSE 0 END AS avg_lat,
		SUM(total_tokens) AS total_tkns,
		SUM(total_cost) AS total_cost
	`).Group("model, provider").
		Order("total DESC").
		Find(&results).Error; err != nil {
		return nil, err
	}

	// Previous period for trend (same duration, ending just before current start)
	type prevRow struct {
		Model       string  `gorm:"column:model"`
		Provider    string  `gorm:"column:provider"`
		Total       int64   `gorm:"column:total"`
		AvgLatency  float64 `gorm:"column:avg_lat"`
		TotalTokens int64   `gorm:"column:total_tkns"`
		TotalCost   float64 `gorm:"column:total_cost"`
	}
	var prevResults []prevRow
	if filters.StartTime != nil && filters.EndTime != nil {
		duration := filters.EndTime.Sub(*filters.StartTime)
		prevStart := filters.StartTime.Add(-duration)
		prevEnd := filters.StartTime.Add(-time.Nanosecond)
		prevFilters := filters
		prevFilters.StartTime = &prevStart
		prevFilters.EndTime = &prevEnd
		pq := s.db.WithContext(ctx).Table("mv_logs_hourly")
		pq = applyMatViewFilters(ctx, pq, prevFilters)
		if err := pq.Select(`
			model, provider,
			SUM(count) AS total,
			CASE WHEN SUM(count) > 0 THEN SUM(avg_latency * count) / SUM(count) ELSE 0 END AS avg_lat,
			SUM(total_tokens) AS total_tkns,
			SUM(total_cost) AS total_cost
		`).Group("model, provider").Find(&prevResults).Error; err != nil {
			return nil, fmt.Errorf("failed to get previous period rankings: %w", err)
		}
	}
	// Key by model+provider to match current period granularity
	type rankingKey struct{ model, provider string }
	prevMap := make(map[rankingKey]int, len(prevResults))
	for i, r := range prevResults {
		prevMap[rankingKey{r.Model, r.Provider}] = i
	}

	rankings := make([]ModelRankingWithTrend, 0, len(results))
	for _, r := range results {
		var successRate float64
		if r.Total > 0 {
			successRate = float64(r.SuccessCount) / float64(r.Total) * 100
		}
		entry := ModelRankingEntry{
			Model:         r.Model,
			Provider:      r.Provider,
			TotalRequests: r.Total,
			SuccessCount:  r.SuccessCount,
			SuccessRate:   successRate,
			TotalTokens:   r.TotalTokens,
			TotalCost:     r.TotalCost,
			AvgLatency:    r.AvgLatency,
		}
		mrt := ModelRankingWithTrend{ModelRankingEntry: entry}
		if idx, ok := prevMap[rankingKey{r.Model, r.Provider}]; ok {
			prev := prevResults[idx]
			mrt.Trend = ModelRankingTrend{
				HasPreviousPeriod: true,
				RequestsTrend:     trendPct(float64(r.Total), float64(prev.Total)),
				TokensTrend:       trendPct(float64(r.TotalTokens), float64(prev.TotalTokens)),
				CostTrend:         trendPct(r.TotalCost, prev.TotalCost),
				LatencyTrend:      trendPct(r.AvgLatency, prev.AvgLatency),
			}
		}
		rankings = append(rankings, mrt)
	}
	return &ModelRankingResult{Rankings: rankings}, nil
}

// ---------------------------------------------------------------------------
// Filterdata from mat view
// ---------------------------------------------------------------------------

// getDistinctModelsFromMatView returns unique model names from mv_logs_filterdata.
func (s *RDBLogStore) getDistinctModelsFromMatView(ctx context.Context) ([]string, error) {
	var models []string
	if err := applyMatViewTenantFilter(ctx, s.db.WithContext(ctx).Table("mv_logs_filterdata")).
		Distinct("model").
		Pluck("model", &models).Error; err != nil {
		return nil, err
	}
	return models, nil
}

// getDistinctKeyPairsFromMatView returns unique ID-Name pairs for the given
// columns (e.g. selected_key_id/name, virtual_key_id/name) from mv_logs_filterdata.
func (s *RDBLogStore) getDistinctKeyPairsFromMatView(ctx context.Context, idCol, nameCol string) ([]KeyPairResult, error) {
	var results []KeyPairResult
	if err := applyMatViewTenantFilter(ctx, s.db.WithContext(ctx).Table("mv_logs_filterdata")).
		Select(fmt.Sprintf("DISTINCT %s AS id, %s AS name", idCol, nameCol)).
		Where(fmt.Sprintf("%s IS NOT NULL AND %s != ''", idCol, idCol)).
		Find(&results).Error; err != nil {
		return nil, err
	}
	return results, nil
}

// getDistinctRoutingEnginesFromMatView returns unique routing engine names by
// parsing the comma-separated routing_engines_used values from mv_logs_filterdata.
func (s *RDBLogStore) getDistinctRoutingEnginesFromMatView(ctx context.Context) ([]string, error) {
	var rawValues []string
	if err := applyMatViewTenantFilter(ctx, s.db.WithContext(ctx).Table("mv_logs_filterdata")).
		Distinct("routing_engines_used").
		Where("routing_engines_used != ''").
		Pluck("routing_engines_used", &rawValues).Error; err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, raw := range rawValues {
		for _, eng := range strings.Split(raw, ",") {
			eng = strings.TrimSpace(eng)
			if eng != "" {
				seen[eng] = struct{}{}
			}
		}
	}
	return sortedStringKeys(seen), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sortedStringKeys returns the keys of a set map in sorted order.
func sortedStringKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// trendPct computes the percentage change from previous to current.
// Returns 0 when the previous value is zero (no basis for comparison).
func trendPct(current, previous float64) float64 {
	if previous == 0 {
		return 0
	}
	return ((current - previous) / previous) * 100
}
