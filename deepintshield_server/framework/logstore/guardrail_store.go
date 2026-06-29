package logstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// applyActiveOrgWorkspaceScope narrows the query to rows whose workspace_id
// belongs to the UI-selected org (X-Active-Tenant-Id). The dashboard's
// tenant_id column is the email-keyed partition (same value across every
// org the user owns), so the explicit org allowlist is required for true
// per-tenant isolation on the Guardrail Metrics page. Empty allowlist =
// org has no workspaces, return zero rows. No-op when no active org is
// set (SDK / config-file calls, or a session-home tenant view).
//
// Use this for tables that have a workspace_id column (logs, mcp_logs).
// For guardrail_* tables that only carry request_id, use
// applyActiveOrgRequestIDScope instead.
func applyActiveOrgWorkspaceScope(ctx context.Context, query *gorm.DB, db *gorm.DB) *gorm.DB {
	activeOrg := tenantctx.ActiveTenantIDFromContext(ctx)
	if activeOrg == "" {
		return query
	}
	var ids []string
	if err := db.WithContext(ctx).
		Table("workspaces").
		Where("org_id = ?", activeOrg).
		Pluck("id", &ids).Error; err != nil {
		// Fail closed - return nothing rather than silently widen the
		// scope back to the legacy partition.
		return query.Where("1 = 0")
	}
	if len(ids) == 0 {
		return query.Where("1 = 0")
	}
	return query.Where("workspace_id IN ?", ids)
}

// applyActiveOrgRequestIDScope is the workspace-aware filter for tables
// that don't carry a workspace_id of their own (guardrail_traces,
// guardrail_decisions, guardrail_findings). It scopes the query to rows
// whose request_id matches a log entry in the active org's workspaces.
//
// Implemented as a subquery rather than a JOIN so the caller's existing
// SELECT / GROUP BY clauses don't need to be rewritten.
func applyActiveOrgRequestIDScope(ctx context.Context, query *gorm.DB, db *gorm.DB) *gorm.DB {
	activeOrg := tenantctx.ActiveTenantIDFromContext(ctx)
	if activeOrg == "" {
		return query
	}
	var ids []string
	if err := db.WithContext(ctx).
		Table("workspaces").
		Where("org_id = ?", activeOrg).
		Pluck("id", &ids).Error; err != nil {
		return query.Where("1 = 0")
	}
	if len(ids) == 0 {
		return query.Where("1 = 0")
	}
	// Direct column path: rows written after the workspace_id migration
	// carry their own workspace_id, so we can drop the UNION subqueries
	// entirely for those. Legacy rows (workspace_id IS NULL) fall back to
	// the same logs.id / agentic_decisions.decision_id matching the union
	// path has always used - that keeps historical traces visible during
	// the transition window. The OR with `1=0` is a no-op shape so we
	// don't accidentally widen the result set; only the OR with the
	// legacy union widens for NULL rows.
	logIDs := db.WithContext(ctx).
		Table("logs").
		Select("id").
		Where("workspace_id IN ?", ids)
	agenticIDs := db.WithContext(ctx).
		Table("agentic_decisions").
		Select("decision_id").
		Where("workspace_id IN ?", ids)
	return query.Where(
		"workspace_id IN (?) OR (workspace_id IS NULL AND (request_id IN (?) OR request_id IN (?)))",
		ids, logIDs, agenticIDs)
}

// applyActiveWorkspaceRequestIDScope is the workspace-narrow companion to
// applyActiveOrgRequestIDScope. When the request carries an
// X-Active-Workspace-Id (set by the sidebar scope switcher), guardrail
// reads should surface only the rows whose request_id matches a log in
// THAT one workspace - not the wider org's workspaces. This is what makes
// the Guardrail Metrics / AI Models analytics pages obey the workspace
// dropdown the way Logs and Cost Optimization already do.
//
// Falls through (no-op) when no workspace header is present, which keeps
// admin / cross-workspace tooling working unchanged.
func applyActiveWorkspaceRequestIDScope(ctx context.Context, query *gorm.DB, db *gorm.DB) *gorm.DB {
	ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	if ws == "" {
		return query
	}
	// Same direct-column + legacy-fallback shape as
	// applyActiveOrgRequestIDScope - see that function for the rationale.
	logIDs := db.WithContext(ctx).
		Table("logs").
		Select("id").
		Where("workspace_id = ?", ws)
	agenticIDs := db.WithContext(ctx).
		Table("agentic_decisions").
		Select("decision_id").
		Where("workspace_id = ?", ws)
	return query.Where(
		"workspace_id = ? OR (workspace_id IS NULL AND (request_id IN (?) OR request_id IN (?)))",
		ws, logIDs, agenticIDs)
}

// --- request_id-only scopes for tables WITHOUT a workspace_id column ---------
//
// guardrail_decisions and guardrail_approval_requests never gained the
// workspace_id column that guardrail_findings / guardrail_traces got in the
// workspace-isolation migration. Running the workspace_id-column helpers above
// against those two tables makes Postgres reject the whole query with
// `column "workspace_id" does not exist` - which is exactly what blanked the
// dashboard "Guardrail Latency" chart (and would 500 the approvals list). These
// companions scope purely by matching request_id against the active scope's
// logs.id + agentic_decisions.decision_id (the latter per the PDP-bridge
// memory - decision_id is a valid request_id source). Use these for any
// guardrail table that has request_id but no workspace_id.
func applyActiveOrgRequestIDScopeByRequestID(ctx context.Context, query *gorm.DB, db *gorm.DB) *gorm.DB {
	activeOrg := tenantctx.ActiveTenantIDFromContext(ctx)
	if activeOrg == "" {
		return query
	}
	var ids []string
	if err := db.WithContext(ctx).
		Table("workspaces").
		Where("org_id = ?", activeOrg).
		Pluck("id", &ids).Error; err != nil {
		return query.Where("1 = 0")
	}
	if len(ids) == 0 {
		return query.Where("1 = 0")
	}
	logIDs := db.WithContext(ctx).
		Table("logs").
		Select("id").
		Where("workspace_id IN ?", ids)
	agenticIDs := db.WithContext(ctx).
		Table("agentic_decisions").
		Select("decision_id").
		Where("workspace_id IN ?", ids)
	return query.Where("request_id IN (?) OR request_id IN (?)", logIDs, agenticIDs)
}

func applyActiveWorkspaceRequestIDScopeByRequestID(ctx context.Context, query *gorm.DB, db *gorm.DB) *gorm.DB {
	ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	if ws == "" {
		return query
	}
	logIDs := db.WithContext(ctx).
		Table("logs").
		Select("id").
		Where("workspace_id = ?", ws)
	agenticIDs := db.WithContext(ctx).
		Table("agentic_decisions").
		Select("decision_id").
		Where("workspace_id = ?", ws)
	return query.Where("request_id IN (?) OR request_id IN (?)", logIDs, agenticIDs)
}

type guardrailDecisionRow struct {
	RequestID string    `gorm:"column:request_id"`
	Decision  string    `gorm:"column:decision"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

type GuardrailFindingFilters struct {
	RequestID string
	PolicyID  string
	Stage     string
	Severity  string
	Outcome   string
	Query     string
	// Source partitions findings by where they came from:
	//   "ai_model" - categories ending in "_model" (e.g. prompt_injection_model,
	//                pii_model, toxicity_model) - i.e. the deepintshield_models
	//                wrapper / any ML detector.
	//   "policy"   - every other category (regex cards, builtin defaults, etc.)
	//   ""         - no partitioning, all findings.
	// Lets the Findings page render two side-by-side tables ("Policy Findings"
	// and "AI Model Findings") without a follow-up join on guardrail_providers.
	Source string
	// StartTime / EndTime window findings by created_at. Set from the dashboard
	// date filter so the analytics page aggregates the correct window
	// server-side instead of fetching the latest N and filtering in the browser
	// (which blanked older buckets on wide windows).
	StartTime *time.Time
	EndTime   *time.Time
}

type GuardrailTraceFilters struct {
	RequestID string
	Stage     string
	Decision  string
	ActorType string
	Query     string
	// StartTime / EndTime window traces by created_at - see GuardrailFindingFilters.
	StartTime *time.Time
	EndTime   *time.Time
}

type GuardrailApprovalFilters struct {
	Status string
	Stage  string
	Query  string
}

type GuardrailLatencyFilters struct {
	Stage     string
	StartTime *time.Time
	EndTime   *time.Time
}

type GuardrailEvidenceStore interface {
	CreateGuardrailFinding(ctx context.Context, finding *GuardrailFinding) error
	CreateGuardrailDecision(ctx context.Context, decision *GuardrailDecision) error
	CreateGuardrailTrace(ctx context.Context, trace *GuardrailTrace) error
	ListGuardrailFindings(ctx context.Context, filters GuardrailFindingFilters, limit, offset int) ([]GuardrailFinding, int64, error)
	ListGuardrailTraces(ctx context.Context, filters GuardrailTraceFilters, limit, offset int) ([]GuardrailTrace, int64, error)
	CreateGuardrailApprovalRequest(ctx context.Context, approval *GuardrailApprovalRequest) error
	ListGuardrailApprovalRequests(ctx context.Context, filters GuardrailApprovalFilters, limit, offset int) ([]GuardrailApprovalRequest, int64, error)
	GetGuardrailLatencyHistogram(ctx context.Context, filters GuardrailLatencyFilters, bucketSizeSeconds int64) (*LatencyHistogramResult, error)
	AggregateGuardrailMetrics(ctx context.Context, since, until *time.Time, bucketSeconds int64) (*GuardrailMetricsStats, error)
	GetGuardrailApprovalRequest(ctx context.Context, id string) (*GuardrailApprovalRequest, error)
	UpdateGuardrailApprovalRequestDecision(ctx context.Context, id, status, approver, notes string, reviewedAt time.Time) error
}

func (s *RDBLogStore) CreateGuardrailFinding(ctx context.Context, finding *GuardrailFinding) error {
	if finding == nil {
		return nil
	}
	if strings.TrimSpace(finding.ID) == "" {
		finding.ID = uuid.NewString()
	}
	if strings.TrimSpace(finding.TenantID) == "" {
		finding.TenantID = tenantctx.TenantIDFromContext(ctx)
	}
	return s.db.WithContext(ctx).Create(finding).Error
}

func (s *RDBLogStore) CreateGuardrailDecision(ctx context.Context, decision *GuardrailDecision) error {
	if decision == nil {
		return nil
	}
	if strings.TrimSpace(decision.ID) == "" {
		decision.ID = uuid.NewString()
	}
	if strings.TrimSpace(decision.TenantID) == "" {
		decision.TenantID = tenantctx.TenantIDFromContext(ctx)
	}
	if err := s.db.WithContext(ctx).Create(decision).Error; err != nil {
		return err
	}
	// Mirror the decision summary into the hash-chained audit log so
	// every allow / deny / redact / sandbox / human_approval verdict has
	// a tamper-evident receipt. Errors are downgraded to a warning - a
	// failed audit append must not roll back the decision the caller
	// just persisted, and the verify endpoint will surface any drift.
	if err := persistAuditLogForGuardrailDecision(ctx, s, decision); err != nil && s.logger != nil {
		s.logger.Warn(fmt.Sprintf("audit chain append failed for guardrail decision %s: %v", decision.ID, err))
	}
	return nil
}

func (s *RDBLogStore) CreateGuardrailTrace(ctx context.Context, trace *GuardrailTrace) error {
	if trace == nil {
		return nil
	}
	if strings.TrimSpace(trace.ID) == "" {
		trace.ID = uuid.NewString()
	}
	if strings.TrimSpace(trace.TenantID) == "" {
		trace.TenantID = tenantctx.TenantIDFromContext(ctx)
	}
	return s.db.WithContext(ctx).Create(trace).Error
}

func (s *RDBLogStore) ListGuardrailFindings(ctx context.Context, filters GuardrailFindingFilters, limit, offset int) ([]GuardrailFinding, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	query := s.db.WithContext(ctx).Model(&GuardrailFinding{})
	// Tenant boundary - otherwise the Findings counter on the Guardrail
	// Metrics page sums rows from every tenant in the database.
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		query = query.Where("tenant_id = ?", tenant)
	}
	query = applyActiveOrgRequestIDScope(ctx, query, s.db)
	query = applyActiveWorkspaceRequestIDScope(ctx, query, s.db)
	if trimmed := strings.TrimSpace(filters.RequestID); trimmed != "" {
		query = query.Where("request_id = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.PolicyID); trimmed != "" {
		query = query.Where("policy_id = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Stage); trimmed != "" {
		query = query.Where("stage = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Severity); trimmed != "" {
		query = query.Where("severity = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Outcome); trimmed != "" {
		query = query.Where("outcome = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Query); trimmed != "" {
		like := "%" + trimmed + "%"
		query = query.Where("summary LIKE ? OR category LIKE ? OR actor_id LIKE ?", like, like, like)
	}
	switch strings.ToLower(strings.TrimSpace(filters.Source)) {
	case "ai_model":
		query = query.Where("category LIKE ?", "%_model")
	case "policy":
		query = query.Where("category NOT LIKE ?", "%_model")
	}
	if filters.StartTime != nil {
		query = query.Where("created_at >= ?", filters.StartTime.UTC())
	}
	if filters.EndTime != nil {
		query = query.Where("created_at <= ?", filters.EndTime.UTC())
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var findings []GuardrailFinding
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&findings).Error; err != nil {
		return nil, 0, err
	}
	return findings, total, nil
}

func (s *RDBLogStore) ListGuardrailTraces(ctx context.Context, filters GuardrailTraceFilters, limit, offset int) ([]GuardrailTrace, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	query := s.db.WithContext(ctx).Model(&GuardrailTrace{})
	// Tenant boundary - drives the "POLICY TRACES" counter on the Guardrail
	// Metrics page. Without it that number sums every tenant's traces.
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		query = query.Where("tenant_id = ?", tenant)
	}
	query = applyActiveOrgRequestIDScope(ctx, query, s.db)
	query = applyActiveWorkspaceRequestIDScope(ctx, query, s.db)
	if trimmed := strings.TrimSpace(filters.RequestID); trimmed != "" {
		query = query.Where("request_id = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Stage); trimmed != "" {
		query = query.Where("stage = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Decision); trimmed != "" {
		query = query.Where("decision = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.ActorType); trimmed != "" {
		query = query.Where("actor_type = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Query); trimmed != "" {
		like := "%" + trimmed + "%"
		query = query.Where("input_summary LIKE ? OR output_summary LIKE ? OR actor_id LIKE ?", like, like, like)
	}
	if filters.StartTime != nil {
		query = query.Where("created_at >= ?", filters.StartTime.UTC())
	}
	if filters.EndTime != nil {
		query = query.Where("created_at <= ?", filters.EndTime.UTC())
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var traces []GuardrailTrace
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&traces).Error; err != nil {
		return nil, 0, err
	}
	return traces, total, nil
}

func (s *RDBLogStore) CreateGuardrailApprovalRequest(ctx context.Context, approval *GuardrailApprovalRequest) error {
	if approval == nil {
		return nil
	}
	if strings.TrimSpace(approval.ID) == "" {
		approval.ID = uuid.NewString()
	}
	if strings.TrimSpace(approval.TenantID) == "" {
		approval.TenantID = tenantctx.TenantIDFromContext(ctx)
	}
	return s.db.WithContext(ctx).Create(approval).Error
}

func (s *RDBLogStore) ListGuardrailApprovalRequests(ctx context.Context, filters GuardrailApprovalFilters, limit, offset int) ([]GuardrailApprovalRequest, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	query := s.db.WithContext(ctx).Model(&GuardrailApprovalRequest{})
	// Tenant boundary - approval queues are per-tenant.
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		query = query.Where("tenant_id = ?", tenant)
	}
	// guardrail_approval_requests has no workspace_id column - scope by
	// request_id only (see applyActive*RequestIDScopeByRequestID).
	query = applyActiveOrgRequestIDScopeByRequestID(ctx, query, s.db)
	query = applyActiveWorkspaceRequestIDScopeByRequestID(ctx, query, s.db)
	if trimmed := strings.TrimSpace(filters.Status); trimmed != "" {
		query = query.Where("status = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Stage); trimmed != "" {
		query = query.Where("stage = ?", trimmed)
	}
	if trimmed := strings.TrimSpace(filters.Query); trimmed != "" {
		like := "%" + trimmed + "%"
		query = query.Where("title LIKE ? OR risk_summary LIKE ? OR approver LIKE ?", like, like, like)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var approvals []GuardrailApprovalRequest
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&approvals).Error; err != nil {
		return nil, 0, err
	}
	sort.SliceStable(approvals, func(i, j int) bool {
		return approvals[i].CreatedAt.After(approvals[j].CreatedAt)
	})
	return approvals, total, nil
}

func (s *RDBLogStore) GetGuardrailLatencyHistogram(ctx context.Context, filters GuardrailLatencyFilters, bucketSizeSeconds int64) (*LatencyHistogramResult, error) {
	if bucketSizeSeconds <= 0 {
		bucketSizeSeconds = 3600
	}

	type latencyRow struct {
		CreatedAt time.Time `gorm:"column:created_at"`
		LatencyMs int       `gorm:"column:latency_ms"`
	}

	query := s.db.WithContext(ctx).Model(&GuardrailDecision{}).Select("created_at, latency_ms")
	// Tenant + active-org workspace boundary. Without these, the Guardrail
	// Latency chart sums every tenant's decisions and surfaces a spike
	// under any workspace the user opens.
	if tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenant != "" {
		query = query.Where("tenant_id = ?", tenant)
	}
	// guardrail_decisions has no workspace_id column - scope by request_id
	// only (see applyActive*RequestIDScopeByRequestID). Using the
	// workspace_id-column helpers here errors with `column "workspace_id"
	// does not exist`, which blanked this chart with "No data available".
	query = applyActiveOrgRequestIDScopeByRequestID(ctx, query, s.db)
	query = applyActiveWorkspaceRequestIDScopeByRequestID(ctx, query, s.db)
	if trimmed := strings.TrimSpace(filters.Stage); trimmed != "" {
		query = query.Where("stage = ?", trimmed)
	}
	if filters.StartTime != nil {
		query = query.Where("created_at >= ?", filters.StartTime.UTC())
	}
	if filters.EndTime != nil {
		query = query.Where("created_at <= ?", filters.EndTime.UTC())
	}

	var rows []latencyRow
	if err := query.Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}

	type bucketData struct {
		latencies []float64
		total     float64
	}

	bucketMap := make(map[int64]*bucketData)
	for _, row := range rows {
		bucketTimestamp := row.CreatedAt.UTC().Unix() / bucketSizeSeconds * bucketSizeSeconds
		bucket := bucketMap[bucketTimestamp]
		if bucket == nil {
			bucket = &bucketData{}
			bucketMap[bucketTimestamp] = bucket
		}
		latency := float64(row.LatencyMs)
		bucket.latencies = append(bucket.latencies, latency)
		bucket.total += latency
	}

	computedBuckets := make(map[int64]LatencyHistogramBucket, len(bucketMap))
	orderedKeys := make([]int64, 0, len(bucketMap))
	for bucketTimestamp, bucket := range bucketMap {
		sort.Float64s(bucket.latencies)
		orderedKeys = append(orderedKeys, bucketTimestamp)
		computedBuckets[bucketTimestamp] = LatencyHistogramBucket{
			Timestamp:     time.Unix(bucketTimestamp, 0).UTC(),
			AvgLatency:    bucket.total / float64(len(bucket.latencies)),
			P90Latency:    computePercentile(bucket.latencies, 0.90),
			P95Latency:    computePercentile(bucket.latencies, 0.95),
			P99Latency:    computePercentile(bucket.latencies, 0.99),
			TotalRequests: int64(len(bucket.latencies)),
		}
	}
	sort.Slice(orderedKeys, func(i, j int) bool {
		return orderedKeys[i] < orderedKeys[j]
	})

	if filters.StartTime == nil || filters.EndTime == nil {
		buckets := make([]LatencyHistogramBucket, 0, len(orderedKeys))
		for _, bucketTimestamp := range orderedKeys {
			buckets = append(buckets, computedBuckets[bucketTimestamp])
		}
		return &LatencyHistogramResult{
			Buckets:           buckets,
			BucketSizeSeconds: bucketSizeSeconds,
		}, nil
	}

	startTimestamp := filters.StartTime.UTC().Unix() / bucketSizeSeconds * bucketSizeSeconds
	endTimestamp := filters.EndTime.UTC().Unix() / bucketSizeSeconds * bucketSizeSeconds
	if endTimestamp < startTimestamp {
		endTimestamp = startTimestamp
	}

	buckets := make([]LatencyHistogramBucket, 0, ((endTimestamp-startTimestamp)/bucketSizeSeconds)+1)
	for ts := startTimestamp; ts <= endTimestamp; ts += bucketSizeSeconds {
		if bucket, ok := computedBuckets[ts]; ok {
			buckets = append(buckets, bucket)
			continue
		}
		buckets = append(buckets, LatencyHistogramBucket{
			Timestamp:     time.Unix(ts, 0).UTC(),
			AvgLatency:    0,
			P90Latency:    0,
			P95Latency:    0,
			P99Latency:    0,
			TotalRequests: 0,
		})
	}

	return &LatencyHistogramResult{
		Buckets:           buckets,
		BucketSizeSeconds: bucketSizeSeconds,
	}, nil
}

func (s *RDBLogStore) GetLatestGuardrailDecisionMap(ctx context.Context, requestIDs []string) (map[string]string, error) {
	result := make(map[string]string)
	if len(requestIDs) == 0 {
		return result, nil
	}

	deduped := make([]string, 0, len(requestIDs))
	seen := make(map[string]struct{}, len(requestIDs))
	for _, requestID := range requestIDs {
		trimmed := strings.TrimSpace(requestID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		deduped = append(deduped, trimmed)
	}
	if len(deduped) == 0 {
		return result, nil
	}

	rows := make([]guardrailDecisionRow, 0, len(deduped))
	if err := s.db.WithContext(ctx).
		Model(&GuardrailDecision{}).
		Select("request_id, decision, created_at").
		Where("request_id IN ?", deduped).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	for _, row := range rows {
		if _, exists := result[row.RequestID]; exists {
			continue
		}
		result[row.RequestID] = strings.TrimSpace(row.Decision)
	}

	return result, nil
}

// GetGuardrailSourceByRequestIDs classifies each request_id by which kind of
// guardrail EVALUATED it (not just which detected). Reads from
// guardrail_decisions joined to guardrail_policy_provider_bindings /
// guardrail_providers so requests that allowed cleanly still get tagged.
// Returns:
//
//	"ai_model" - only the deepintshield_models wrapper policy evaluated
//	"policy"   - only regex / card / builtin policies evaluated
//	"mixed"    - both wrapper and policy evaluated (typical: every workspace
//	             with both an AI Models provider AND a regex card policy)
//	""         - no decisions recorded for this request (cache short-circuit
//	             upstream, no policies attached, or pre-guardrail error)
//
// Single GROUP BY round trip per page load, joined into the log row at
// read time the same way GetLatestGuardrailDecisionMap stamps guardrail_status.
// The earlier version queried guardrail_findings, which only records
// detections - pure-Allow requests came back empty and the dashboard
// Engine column showed "-". Decisions are written for every evaluation
// outcome (allow / deny / redact), so Allow rows now carry the engine tag.
func (s *RDBLogStore) GetGuardrailSourceByRequestIDs(ctx context.Context, requestIDs []string) (map[string]string, error) {
	result := make(map[string]string)
	if len(requestIDs) == 0 {
		return result, nil
	}
	deduped := make([]string, 0, len(requestIDs))
	seen := make(map[string]struct{}, len(requestIDs))
	for _, requestID := range requestIDs {
		trimmed := strings.TrimSpace(requestID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		deduped = append(deduped, trimmed)
	}
	if len(deduped) == 0 {
		return result, nil
	}
	type sourceRow struct {
		RequestID string `gorm:"column:request_id"`
		HasAI     bool   `gorm:"column:has_ai"`
		HasPolicy bool   `gorm:"column:has_policy"`
	}
	var rows []sourceRow
	// Prefer the write-time engine_source tag on guardrail_decisions (set from the evaluated
	// policies' provider bindings). Fall back to the legacy join through
	// guardrail_policy_provider_bindings / guardrail_providers for decision rows written before
	// the column existed (policy_id is only populated on findings, so allow-no-finding rows
	// joined to nothing and silently classified as "policy"). NULL-provider_type rows in the
	// fallback path count as "policy" - they're the regex cards.
	// Skip decision rows that recorded "nothing to evaluate" - those are
	// written when a request enters a stage with no applicable policies
	// (e.g. an AI Models wrapper VK only attaches an input-scope policy,
	// so the output stage row carries engine_source='' AND policy_id=''
	// AND no findings). Without the filter, the LEFT JOIN against the
	// no-binding row falls into the legacy "policy" branch and a clean
	// Allow under an AI Models wrapper VK rolls up as "Mixed" instead of
	// "AI Models" on the AI Logs Engine column. The filter keeps "true"
	// policy rows (decision wrote engine_source explicitly) and "true"
	// finding-bearing rows (policy_id set) classifiable as before.
	if err := s.db.WithContext(ctx).
		Raw(`
			SELECT
				gd.request_id,
				BOOL_OR(
					gd.engine_source IN ('ai_model','mixed')
					OR (COALESCE(gd.engine_source,'') = '' AND gp.provider_type = ?)
				) AS has_ai,
				BOOL_OR(
					gd.engine_source IN ('policy','mixed')
					OR (COALESCE(gd.engine_source,'') = '' AND COALESCE(gd.policy_id,'') <> '' AND (gp.provider_type IS DISTINCT FROM ? OR gp.provider_type IS NULL))
				) AS has_policy
			FROM guardrail_decisions gd
			LEFT JOIN guardrail_policy_provider_bindings gpb ON gd.policy_id = gpb.policy_id
			LEFT JOIN guardrail_providers gp ON gpb.provider_id = gp.id
			WHERE gd.request_id IN ?
			  AND (COALESCE(gd.engine_source,'') <> '' OR COALESCE(gd.policy_id,'') <> '')
			GROUP BY gd.request_id
		`, "deepintshield_models", "deepintshield_models", deduped).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		switch {
		case row.HasAI && row.HasPolicy:
			result[row.RequestID] = "mixed"
		case row.HasAI:
			result[row.RequestID] = "ai_model"
		case row.HasPolicy:
			result[row.RequestID] = "policy"
		}
	}
	return result, nil
}

func (s *RDBLogStore) GetGuardrailApprovalRequest(ctx context.Context, id string) (*GuardrailApprovalRequest, error) {
	var approval GuardrailApprovalRequest
	if err := s.db.WithContext(ctx).First(&approval, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &approval, nil
}

func (s *RDBLogStore) UpdateGuardrailApprovalRequestDecision(ctx context.Context, id, status, approver, notes string, reviewedAt time.Time) error {
	return s.db.WithContext(ctx).
		Model(&GuardrailApprovalRequest{}).
		Where("id = ?", strings.TrimSpace(id)).
		Updates(map[string]any{
			"status":         strings.ToLower(strings.TrimSpace(status)),
			"approver":       strings.TrimSpace(approver),
			"decision_notes": strings.TrimSpace(notes),
			"reviewed_at":    reviewedAt.UTC(),
			"updated_at":     time.Now().UTC(),
		}).Error
}
