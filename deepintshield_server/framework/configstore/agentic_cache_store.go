// Package configstore: Agentic Cache analytics + config CRUD.
//
// Follows the same workspace-isolation pattern as agentic_store.go. The event
// table is append-only and metrics-only (no cached payloads); the settings
// table is one row per tenant/workspace.
package configstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
)

// nonEmptyStrings returns the input with blank entries trimmed out.
func nonEmptyStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// AppendAgenticCacheEvent persists one cache event. Called off the hot path by
// the async sink, so a slow DB never blocks a cache hit.
func (s *RDBConfigStore) AppendAgenticCacheEvent(ctx context.Context, row *tables.TableAgenticCacheEvent) error {
	if row == nil {
		return nil
	}
	stampAgenticOwnership(ctx, &row.TenantID, &row.WorkspaceID)
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	return s.db.WithContext(ctx).Create(row).Error
}

// CacheKindStat is a per-(kind,event) rollup for the active boundary.
type CacheKindStat struct {
	CacheKind      string  `json:"cache_kind"`
	Event          string  `json:"event"`
	Count          int64   `json:"count"`
	TokensSaved    int64   `json:"tokens_saved"`
	CostSavedUSD   float64 `json:"cost_saved_usd"`
	LatencySavedMs int64   `json:"latency_saved_ms"`
}

// CountAgenticCacheEventsByKind rolls cache events up by (cache_kind, event)
// for the caller's tenant/workspace over the window. Powers the per-cache
// table on the console. virtualKey (optional) narrows the rollup to a single
// virtual key so the console's "scope" selector can show per-VK hit rates.
func (s *RDBConfigStore) CountAgenticCacheEventsByKind(ctx context.Context, since, until *time.Time, virtualKeys []string) ([]CacheKindStat, error) {
	q := agenticTenantScope(s.db.WithContext(ctx).Model(&tables.TableAgenticCacheEvent{}), ctx, true)
	if vks := nonEmptyStrings(virtualKeys); len(vks) > 0 {
		q = q.Where("virtual_key_id IN ?", vks)
	}
	if since != nil {
		q = q.Where("created_at >= ?", *since)
	}
	if until != nil {
		q = q.Where("created_at <= ?", *until)
	}
	var out []CacheKindStat
	err := q.
		Select("cache_kind, event, COUNT(*) AS count, COALESCE(SUM(tokens_saved),0) AS tokens_saved, COALESCE(SUM(cost_saved_usd),0) AS cost_saved_usd, COALESCE(SUM(latency_saved_ms),0) AS latency_saved_ms").
		Group("cache_kind, event").
		Scan(&out).Error
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CacheSavingsBucket is one time-bucket of savings. This is the single shared
// shape every additive overlay (Overview / Cost / AI Logs / MCP / Agentic
// Security) reads, so the numbers reconcile across the console.
type CacheSavingsBucket struct {
	Bucket         time.Time `json:"bucket"`
	Hits           int64     `json:"hits"`
	Misses         int64     `json:"misses"`
	CallsSkipped   int64     `json:"calls_skipped"` // == hits
	TokensSaved    int64     `json:"tokens_saved"`
	CostSavedUSD   float64   `json:"cost_saved_usd"`
	LatencySavedMs int64     `json:"latency_saved_ms"`
}

// AggregateAgenticCacheSavings returns time-bucketed savings for the caller's
// tenant/workspace. bucket is "hour" or "day" (default "hour"). Uses
// date_trunc so it works on Postgres; SQLite test DBs fall back to a
// per-row scan handled by the caller when needed.
func (s *RDBConfigStore) AggregateAgenticCacheSavings(ctx context.Context, since, until *time.Time, bucket string) ([]CacheSavingsBucket, error) {
	trunc := "hour"
	if strings.EqualFold(bucket, "day") {
		trunc = "day"
	}
	type rawRow struct {
		Bucket         time.Time
		Event          string
		Cnt            int64
		TokensSaved    int64
		CostSavedUSD   float64
		LatencySavedMs int64
	}
	q := agenticTenantScope(s.db.WithContext(ctx).Model(&tables.TableAgenticCacheEvent{}), ctx, true)
	if since != nil {
		q = q.Where("created_at >= ?", *since)
	}
	if until != nil {
		q = q.Where("created_at <= ?", *until)
	}
	var rows []rawRow
	err := q.
		Select("date_trunc('" + trunc + "', created_at) AS bucket, event, COUNT(*) AS cnt, COALESCE(SUM(tokens_saved),0) AS tokens_saved, COALESCE(SUM(cost_saved_usd),0) AS cost_saved_usd, COALESCE(SUM(latency_saved_ms),0) AS latency_saved_ms").
		Group("bucket, event").
		Order("bucket ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	// Fold the per-event rows into one bucket each.
	byBucket := make(map[time.Time]*CacheSavingsBucket)
	var order []time.Time
	for _, r := range rows {
		b, ok := byBucket[r.Bucket]
		if !ok {
			b = &CacheSavingsBucket{Bucket: r.Bucket}
			byBucket[r.Bucket] = b
			order = append(order, r.Bucket)
		}
		switch r.Event {
		case tables.AgenticCacheEventHit:
			b.Hits += r.Cnt
			b.CallsSkipped += r.Cnt
			b.TokensSaved += r.TokensSaved
			b.CostSavedUSD += r.CostSavedUSD
			b.LatencySavedMs += r.LatencySavedMs
		case tables.AgenticCacheEventMiss:
			b.Misses += r.Cnt
		}
	}
	out := make([]CacheSavingsBucket, 0, len(order))
	for _, t := range order {
		out = append(out, *byBucket[t])
	}
	return out, nil
}

// GetAgenticCacheSettings returns the per-workspace settings row, auto-
// provisioning one with §10.5 defaults on first access.
func (s *RDBConfigStore) GetAgenticCacheSettings(ctx context.Context) (*tables.TableAgenticCacheSettings, error) {
	var row tables.TableAgenticCacheSettings
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, true)
	err := q.First(&row).Error
	if err == nil {
		return &row, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	row = tables.TableAgenticCacheSettings{
		ID:                   "cache-set-" + uuid.NewString()[:10],
		TenantID:             strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)),
		WorkspaceID:          strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)),
		Enabled:              true,
		ResponseEnabled:      true,
		SemanticEnabled:      true,
		ToolResultEnabled:    true,
		EmbeddingEnabled:     true,
		MCPDiscoveryEnabled:  true,
		SemanticThreshold:    0.92,
		SemanticReadOnly:     true,
		NeverCacheHighRisk:   true,
		EncryptAtRest:        true,
		HonorObligations:     true,
		ResponseTTLSeconds:   3600,
		SemanticTTLSeconds:   1800,
		ToolResultTTLSeconds: 600,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// ListAllAgenticCacheSettings returns every workspace's settings row across all
// tenants - used ONLY by the server's startup prewarm to seed the in-process
// per-workspace cache config. Not tenant-scoped by design (it loads config into
// memory, it does not serve tenant data).
func (s *RDBConfigStore) ListAllAgenticCacheSettings(ctx context.Context) ([]tables.TableAgenticCacheSettings, error) {
	var rows []tables.TableAgenticCacheSettings
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// DecisionCacheHitRate returns (hits, total) for the security decision/verdict
// cache from the hash-chained agentic_decisions log, scoped to the caller's
// tenant/workspace and optionally a single virtual key + time window. Powers
// the per-VK hit rate on the Security Caches console.
func (s *RDBConfigStore) DecisionCacheHitRate(ctx context.Context, since, until *time.Time, virtualKeys []string) (hits, total int64, err error) {
	// Build a fresh query per finalizer so GORM never accumulates clauses
	// across the two Count calls.
	scope := func() *gorm.DB {
		q := agenticTenantScope(s.db.WithContext(ctx).Model(&tables.TableAgenticDecision{}), ctx, true)
		if vks := nonEmptyStrings(virtualKeys); len(vks) > 0 {
			q = q.Where("virtual_key_id IN ?", vks)
		}
		if since != nil {
			q = q.Where("ts >= ?", *since)
		}
		if until != nil {
			q = q.Where("ts <= ?", *until)
		}
		return q
	}
	if err = scope().Count(&total).Error; err != nil {
		return 0, 0, err
	}
	if err = scope().Where("cache_hit = ?", true).Count(&hits).Error; err != nil {
		return 0, 0, err
	}
	return hits, total, nil
}

// UpdateAgenticCacheSettings persists the settings row for the active boundary.
func (s *RDBConfigStore) UpdateAgenticCacheSettings(ctx context.Context, row *tables.TableAgenticCacheSettings) error {
	if row == nil {
		return nil
	}
	stampAgenticOwnership(ctx, &row.TenantID, nil)
	if strings.TrimSpace(row.WorkspaceID) == "" {
		row.WorkspaceID = strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	}
	if strings.TrimSpace(row.ID) == "" {
		row.ID = "cache-set-" + uuid.NewString()[:10]
	}
	row.UpdatedAt = time.Now().UTC()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = row.UpdatedAt
	}
	return s.db.WithContext(ctx).Save(row).Error
}
