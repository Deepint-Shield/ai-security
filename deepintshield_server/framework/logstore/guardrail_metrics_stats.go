package logstore

// Server-side aggregation for the Guardrail Metrics analytics page.
//
// The page used to fetch the latest 5,000 traces + findings and aggregate them
// in the browser. Past 5,000 rows in the window the count tiles showed the cap
// (e.g. 5,000 instead of the true 9,549) and the recency-ordered slice dropped
// older rows entirely - which made the dominant `action` stage vanish from the
// Trace Stages chart. These GROUP BY queries compute the headline counts and
// distributions over the FULL window, scoped to the active tenant + workspace,
// so the numbers are correct at any volume (mirrors the agentic /stats pattern).

import (
	"context"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"gorm.io/gorm"
)

type GuardrailNameVal struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

type GuardrailTimelinePoint struct {
	// Bucket is a string, not time.Time: the SQLite epoch-floor expression yields
	// a TEXT value (datetime(...)) that cannot scan into time.Time, which 500s the
	// whole query whenever the timeline has rows (i.e. exactly when there IS
	// guardrail activity). Postgres' to_timestamp(...) scans into a string fine,
	// and the UI already treats bucket as an opaque label, so string works for
	// both dialects.
	Bucket   string `json:"bucket"`
	Decision string `json:"decision"`
	Count    int64  `json:"count"`
}

// GuardrailMetricsStats backs the KPI tiles + Overview charts on the Guardrail
// Metrics page.
type GuardrailMetricsStats struct {
	TracesTotal       int64 `json:"traces_total"`
	TracesAgentTool   int64 `json:"traces_agent_tool"`
	TracesRAG         int64 `json:"traces_rag"`
	FindingsTotal     int64 `json:"findings_total"`
	FindingsBlocking  int64 `json:"findings_blocking"`
	FindingsAgentTool int64 `json:"findings_agent_tool"`

	TracesByStage      []GuardrailNameVal       `json:"traces_by_stage"`
	FindingsBySeverity []GuardrailNameVal       `json:"findings_by_severity"`
	FindingsByPolicy   []GuardrailNameVal       `json:"findings_by_policy"` // Name = policy_id (UI resolves the display name)
	DecisionTimeline   []GuardrailTimelinePoint `json:"decision_timeline"`
}

// AggregateGuardrailMetrics computes the Guardrail Metrics headline figures
// server-side over the [since, until] window. Each finalizer builds a fresh
// scoped query so GORM never accumulates clauses across calls (same pattern as
// the ListGuardrail* readers, whose scoping is reproduced here verbatim).
func (s *RDBLogStore) AggregateGuardrailMetrics(ctx context.Context, since, until *time.Time, bucketSeconds int64) (*GuardrailMetricsStats, error) {
	out := &GuardrailMetricsStats{
		TracesByStage:      []GuardrailNameVal{},
		FindingsBySeverity: []GuardrailNameVal{},
		FindingsByPolicy:   []GuardrailNameVal{},
		DecisionTimeline:   []GuardrailTimelinePoint{},
	}

	withWindow := func(q *gorm.DB) *gorm.DB {
		if since != nil {
			q = q.Where("created_at >= ?", since.UTC())
		}
		if until != nil {
			q = q.Where("created_at <= ?", until.UTC())
		}
		return q
	}
	scopedTraces := func() *gorm.DB {
		q := s.db.WithContext(ctx).Model(&GuardrailTrace{})
		if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
			q = q.Where("tenant_id = ?", tenant)
		}
		q = applyActiveOrgRequestIDScope(ctx, q, s.db)
		q = applyActiveWorkspaceRequestIDScope(ctx, q, s.db)
		return withWindow(q)
	}
	scopedFindings := func() *gorm.DB {
		q := s.db.WithContext(ctx).Model(&GuardrailFinding{})
		if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
			q = q.Where("tenant_id = ?", tenant)
		}
		q = applyActiveOrgRequestIDScope(ctx, q, s.db)
		q = applyActiveWorkspaceRequestIDScope(ctx, q, s.db)
		return withWindow(q)
	}

	// --- Counts ----------------------------------------------------------
	if err := scopedTraces().Count(&out.TracesTotal).Error; err != nil {
		return nil, err
	}
	// agent/tool = action/mcp stage OR an agent actor (mirrors the UI's
	// isAgenticTrace heuristic, column-only approximation).
	if err := scopedTraces().Where("stage IN ? OR LOWER(actor_type) LIKE ?", []string{"action", "mcp"}, "%agent%").
		Count(&out.TracesAgentTool).Error; err != nil {
		return nil, err
	}
	if err := scopedTraces().Where("stage = ?", "rag").Count(&out.TracesRAG).Error; err != nil {
		return nil, err
	}
	if err := scopedFindings().Count(&out.FindingsTotal).Error; err != nil {
		return nil, err
	}
	if err := scopedFindings().Where("outcome = ?", "block").Count(&out.FindingsBlocking).Error; err != nil {
		return nil, err
	}
	if err := scopedFindings().Where("stage IN ?", []string{"action", "mcp"}).Count(&out.FindingsAgentTool).Error; err != nil {
		return nil, err
	}

	// --- Distributions ---------------------------------------------------
	if err := scopedTraces().
		Select("COALESCE(NULLIF(stage,''),'input') AS name, COUNT(*) AS value").
		Group("name").Order("value DESC").Scan(&out.TracesByStage).Error; err != nil {
		return nil, err
	}
	if err := scopedFindings().
		Select("COALESCE(NULLIF(severity,''),'unknown') AS name, COUNT(*) AS value").
		Group("name").Order("value DESC").Scan(&out.FindingsBySeverity).Error; err != nil {
		return nil, err
	}
	if err := scopedFindings().
		Select("COALESCE(NULLIF(policy_id,''),'') AS name, COUNT(*) AS value").
		Group("name").Order("value DESC").Limit(8).Scan(&out.FindingsByPolicy).Error; err != nil {
		return nil, err
	}

	// --- Decision timeline (epoch-floor buckets, matches the UI buildTimeline) -
	if bucketSeconds <= 0 {
		bucketSeconds = 3600
	}
	// Floor created_at into bucketSeconds-wide buckets. Postgres and SQLite have
	// no shared epoch-floor expression, so pick per dialect (Postgres lacks
	// strftime; SQLite lacks to_timestamp/extract - the latter is the "near from"
	// syntax error on SQLite-backed logs).
	bucketExpr := "to_timestamp(floor(extract(epoch from created_at)/?)*?) AS bucket"
	if s.db.Dialector.Name() == "sqlite" {
		bucketExpr = "datetime((CAST(strftime('%s', created_at) AS INTEGER) / ?) * ?, 'unixepoch') AS bucket"
	}
	if err := scopedTraces().
		Select(bucketExpr+", COALESCE(NULLIF(decision,''),'allow') AS decision, COUNT(*) AS count", bucketSeconds, bucketSeconds).
		Group("bucket, decision").Order("bucket ASC").Scan(&out.DecisionTimeline).Error; err != nil {
		return nil, err
	}

	return out, nil
}
