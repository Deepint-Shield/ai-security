package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

type AuditLogsHandler struct {
	logStore   logstore.LogStore
	auditStore logstore.AuditLogStore
}

type AuditLogEntry = logstore.AuditLogEntry
type AuditLogActor = logstore.AuditLogActor
type AuditLogVerification = logstore.AuditLogVerification
type AuditLogFilters = logstore.AuditLogFilters
type AuditLogDateRange = logstore.AuditLogDateRange
type AuditLogActors = logstore.AuditLogActors
type AuditLogSort = logstore.AuditLogSort

type AuditLogQueryRequest struct {
	Filters        AuditLogFilters `json:"filters"`
	Sort           *AuditLogSort   `json:"sort,omitempty"`
	Limit          int             `json:"limit,omitempty"`
	Page           int             `json:"page,omitempty"`
	IncludeDetails bool            `json:"include_details,omitempty"`
}

type AuditLogsResponse struct {
	TotalCount    int             `json:"total_count"`
	ReturnedCount int             `json:"returned_count"`
	Page          int             `json:"page"`
	Limit         int             `json:"limit"`
	AuditLogs     []AuditLogEntry `json:"audit_logs"`
	NextPage      string          `json:"next_page,omitempty"`
}

type AuditSummaryResponse struct {
	Overview              AuditSummaryOverview  `json:"overview"`
	VolumeTimeline        []AuditTimelineBucket `json:"volume_timeline"`
	EventTypeBreakdown    []AuditSummaryMetric  `json:"event_type_breakdown"`
	SeverityBreakdown     []AuditSummaryMetric  `json:"severity_breakdown"`
	StatusBreakdown       []AuditSummaryMetric  `json:"status_breakdown"`
	ResourceTypeBreakdown []AuditSummaryMetric  `json:"resource_type_breakdown"`
}

type AuditSummaryOverview struct {
	TotalEvents    int `json:"total_events"`
	FailedEvents   int `json:"failed_events"`
	CriticalEvents int `json:"critical_events"`
	UniqueActors   int `json:"unique_actors"`
	VerifiedEvents int `json:"verified_events"`
}

type AuditTimelineBucket struct {
	Label               string `json:"label"`
	Timestamp           string `json:"timestamp"`
	Authentication      int    `json:"authentication"`
	Authorization       int    `json:"authorization"`
	ConfigurationChange int    `json:"configuration_change"`
	DataAccess          int    `json:"data_access"`
	SecurityEvent       int    `json:"security_event"`
	Total               int    `json:"total"`
}

type AuditSummaryMetric struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func NewAuditLogsHandler(logStore logstore.LogStore) *AuditLogsHandler {
	if logStore == nil {
		return &AuditLogsHandler{}
	}
	auditStore, _ := logStore.(logstore.AuditLogStore)
	return &AuditLogsHandler{
		logStore:   logStore,
		auditStore: auditStore,
	}
}

func (h *AuditLogsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/audit-logs", lib.ChainMiddlewares(h.getAuditLogs, middlewares...))
	r.GET("/api/audit-logs/summary", lib.ChainMiddlewares(h.getAuditSummary, middlewares...))
	r.POST("/api/audit-logs/query", lib.ChainMiddlewares(h.queryAuditLogs, middlewares...))
	r.GET("/api/audit-logs/verify", lib.ChainMiddlewares(h.verifyAuditChain, middlewares...))
}

// verifyAuditChain walks the audit log hash chain for the requesting
// tenant end-to-end and returns a verification report. SOC 2 auditors
// and on-call admins use this to prove (or disprove) tamper-evidence;
// the response also feeds the verification banner on the Audit UI.
func (h *AuditLogsHandler) verifyAuditChain(ctx *fasthttp.RequestCtx) {
	if h.auditStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Audit log store is not configured")
		return
	}
	storeCtx := auditStoreContext(ctx)
	// Sync any runtime / MCP / guardrail events into the audit chain
	// before we verify so a "verify just-after-traffic" request doesn't
	// race a not-yet-mirrored row.
	if err := h.backfillRuntimeAuditLogs(storeCtx, AuditLogFilters{}); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to sync runtime audit logs: %v", err))
		return
	}
	opts := logstore.AuditChainVerifyOptions{
		WorkspaceID: strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))),
	}
	report, err := h.auditStore.VerifyAuditChain(storeCtx, opts)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to verify audit chain: %v", err))
		return
	}
	SendJSON(ctx, report)
}

func (h *AuditLogsHandler) getAuditLogs(ctx *fasthttp.RequestCtx) {
	filters := auditFiltersFromQuery(ctx)
	limit, offset := ClampPaginationParams(parseIntOrDefault(string(ctx.QueryArgs().Peek("limit")), 25), parseIntOrDefault(string(ctx.QueryArgs().Peek("offset")), 0))
	page := parseIntOrDefault(string(ctx.QueryArgs().Peek("page")), 1)
	if page < 1 {
		page = 1
	}
	if offset == 0 && page > 1 {
		offset = (page - 1) * limit
	}
	if h.auditStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Audit log store is not configured")
		return
	}
	if err := h.backfillRuntimeAuditLogs(auditStoreContext(ctx), filters); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to sync runtime audit logs: %v", err))
		return
	}

	result, err := h.auditStore.SearchAuditLogs(auditStoreContext(ctx), filters, &AuditLogSort{Field: "timestamp", Order: "desc"}, limit, offset)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to query audit logs: %v", err))
		return
	}

	SendJSON(ctx, paginateAuditLogs(ctx, result.Logs, int(result.TotalCount), page, limit, offset))
}

func (h *AuditLogsHandler) queryAuditLogs(ctx *fasthttp.RequestCtx) {
	var req AuditLogQueryRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid audit log query payload")
		return
	}

	limit := req.Limit
	if limit == 0 {
		limit = 100
	}
	page := req.Page
	if page == 0 {
		page = 1
	}
	if page < 1 {
		page = 1
	}
	limit, _ = ClampPaginationParams(limit, 0)
	offset := (page - 1) * limit
	if h.auditStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Audit log store is not configured")
		return
	}
	if err := h.backfillRuntimeAuditLogs(auditStoreContext(ctx), req.Filters); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to sync runtime audit logs: %v", err))
		return
	}

	result, err := h.auditStore.SearchAuditLogs(auditStoreContext(ctx), req.Filters, req.Sort, limit, offset)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to query audit logs: %v", err))
		return
	}

	SendJSON(ctx, paginateAuditLogs(ctx, result.Logs, int(result.TotalCount), page, limit, offset))
}

func (h *AuditLogsHandler) getAuditSummary(ctx *fasthttp.RequestCtx) {
	filters := auditFiltersFromQuery(ctx)
	if h.auditStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Audit log store is not configured")
		return
	}

	storeCtx := auditStoreContext(ctx)
	if err := h.backfillRuntimeAuditLogs(storeCtx, filters); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to sync runtime audit logs: %v", err))
		return
	}
	filtered, err := h.auditStore.ListAllAuditLogs(storeCtx, filters, &AuditLogSort{Field: "timestamp", Order: "desc"})
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load audit summary: %v", err))
		return
	}
	response := AuditSummaryResponse{
		Overview:              buildAuditSummaryOverview(filtered),
		VolumeTimeline:        buildAuditTimeline(filtered),
		EventTypeBreakdown:    countAuditField(filtered, func(log AuditLogEntry) string { return log.EventType }),
		SeverityBreakdown:     countAuditField(filtered, func(log AuditLogEntry) string { return log.Severity }),
		StatusBreakdown:       countAuditField(filtered, func(log AuditLogEntry) string { return log.Status }),
		ResourceTypeBreakdown: countAuditField(filtered, func(log AuditLogEntry) string { return log.ResourceType }),
	}

	SendJSON(ctx, response)
}

func auditFiltersFromQuery(ctx *fasthttp.RequestCtx) AuditLogFilters {
	filters := AuditLogFilters{
		EventTypes:    parseCSVParam(string(ctx.QueryArgs().Peek("event_type"))),
		Actions:       parseCSVParam(string(ctx.QueryArgs().Peek("action"))),
		ResourceTypes: parseCSVParam(string(ctx.QueryArgs().Peek("resource_type"))),
		Status:        parseCSVParam(string(ctx.QueryArgs().Peek("status"))),
		Severity:      parseCSVParam(string(ctx.QueryArgs().Peek("severity"))),
		Query:         strings.TrimSpace(string(ctx.QueryArgs().Peek("search"))),
	}

	startDate := strings.TrimSpace(string(ctx.QueryArgs().Peek("start_date")))
	endDate := strings.TrimSpace(string(ctx.QueryArgs().Peek("end_date")))
	if startDate != "" || endDate != "" {
		filters.DateRange = &AuditLogDateRange{
			Start: startDate,
			End:   endDate,
		}
	}

	userIDs := parseCSVParam(string(ctx.QueryArgs().Peek("user_id")))
	emails := parseCSVParam(string(ctx.QueryArgs().Peek("email")))
	ips := parseCSVParam(string(ctx.QueryArgs().Peek("ip_address")))
	if len(userIDs) > 0 || len(emails) > 0 || len(ips) > 0 {
		filters.Actors = &AuditLogActors{
			UserIDs:     userIDs,
			Emails:      emails,
			IPAddresses: ips,
		}
	}

	// Workspace narrowing: explicit ?workspace_id= wins, otherwise fall
	// back to the sidebar's active workspace from the request context.
	if ws := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); ws != "" {
		filters.WorkspaceID = ws
	} else if ws := tenantctx.WorkspaceIDFromContext(ctx); ws != "" {
		filters.WorkspaceID = ws
	}

	return filters
}

func paginateAuditLogs(ctx *fasthttp.RequestCtx, logs []AuditLogEntry, totalCount, page, limit, offset int) AuditLogsResponse {
	result := AuditLogsResponse{
		TotalCount:    totalCount,
		ReturnedCount: len(logs),
		Page:          page,
		Limit:         limit,
		AuditLogs:     logs,
	}
	if offset+len(logs) < totalCount {
		args := fasthttp.AcquireArgs()
		defer fasthttp.ReleaseArgs(args)
		ctx.QueryArgs().CopyTo(args)
		args.Set("page", strconv.Itoa(page+1))
		args.Set("limit", strconv.Itoa(limit))
		result.NextPage = fmt.Sprintf("%s?%s", string(ctx.Path()), args.String())
	}
	return result
}

func buildAuditSummaryOverview(logs []AuditLogEntry) AuditSummaryOverview {
	actors := map[string]struct{}{}
	overview := AuditSummaryOverview{}
	for _, log := range logs {
		overview.TotalEvents++
		if log.Status == "failed" || log.Status == "error" || log.Status == "denied" || log.Status == "blocked" {
			overview.FailedEvents++
		}
		if log.Severity == "critical" {
			overview.CriticalEvents++
		}
		if log.Verification.Verified {
			overview.VerifiedEvents++
		}
		if log.Actor.UserID != "" {
			actors[log.Actor.UserID] = struct{}{}
		}
	}
	overview.UniqueActors = len(actors)
	return overview
}

func buildAuditTimeline(logs []AuditLogEntry) []AuditTimelineBucket {
	type bucketCounts struct {
		Start               time.Time
		Authentication      int
		Authorization       int
		ConfigurationChange int
		DataAccess          int
		SecurityEvent       int
		Total               int
	}

	buckets := map[string]*bucketCounts{}
	for _, log := range logs {
		start := log.Timestamp.UTC().Truncate(24 * time.Hour)
		key := start.Format("2006-01-02")
		bucket := buckets[key]
		if bucket == nil {
			bucket = &bucketCounts{Start: start}
			buckets[key] = bucket
		}
		switch log.EventType {
		case "authentication":
			bucket.Authentication++
		case "authorization":
			bucket.Authorization++
		case "configuration_change":
			bucket.ConfigurationChange++
		case "data_access":
			bucket.DataAccess++
		case "security_event":
			bucket.SecurityEvent++
		}
		bucket.Total++
	}

	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]AuditTimelineBucket, 0, len(keys))
	for _, key := range keys {
		bucket := buckets[key]
		result = append(result, AuditTimelineBucket{
			Label:               bucket.Start.Format("Jan 02"),
			Timestamp:           bucket.Start.Format(time.RFC3339),
			Authentication:      bucket.Authentication,
			Authorization:       bucket.Authorization,
			ConfigurationChange: bucket.ConfigurationChange,
			DataAccess:          bucket.DataAccess,
			SecurityEvent:       bucket.SecurityEvent,
			Total:               bucket.Total,
		})
	}
	return result
}

func countAuditField(logs []AuditLogEntry, selector func(AuditLogEntry) string) []AuditSummaryMetric {
	counts := map[string]int{}
	for _, log := range logs {
		value := selector(log)
		if value == "" {
			continue
		}
		counts[value]++
	}

	result := make([]AuditSummaryMetric, 0, len(counts))
	for name, count := range counts {
		result = append(result, AuditSummaryMetric{Name: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return result[i].Name < result[j].Name
		}
		return result[i].Count > result[j].Count
	})
	return result
}

func parseCSVParam(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	return uniqueNonEmptyStrings(parts)
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(strings.ToLower(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func parseIntOrDefault(value string, fallback int) int {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func auditStoreContext(ctx *fasthttp.RequestCtx) context.Context {
	storeCtx := context.Background()
	if ctx == nil {
		return storeCtx
	}
	if tenantID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID))); tenantID != "" {
		storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyTenantID, tenantID)
	}
	if userID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyUserID))); userID != "" {
		storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyUserID, userID)
	}
	// Carry the UI-selected org and workspace through so store-layer queries
	// (policies, guardrail metrics) can scope to the active org. Without
	// these, the policy list query falls back to the email-keyed tenant
	// partition and leaks DEV-owned policies into the Prod tenant view.
	if activeTenant := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyActiveTenantID))); activeTenant != "" {
		storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyActiveTenantID, activeTenant)
	}
	if workspaceID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyWorkspaceID))); workspaceID != "" {
		storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyWorkspaceID, workspaceID)
	}
	return storeCtx
}

const auditBackfillBatchSize = 250

func (h *AuditLogsHandler) backfillRuntimeAuditLogs(ctx context.Context, filters AuditLogFilters) error {
	if h.auditStore == nil || h.logStore == nil {
		return nil
	}
	if err := h.backfillRequestAuditLogs(ctx, filters); err != nil {
		return err
	}
	if err := h.backfillMCPAuditLogs(ctx, filters); err != nil {
		return err
	}
	return nil
}

func (h *AuditLogsHandler) backfillRequestAuditLogs(ctx context.Context, filters AuditLogFilters) error {
	if !shouldBackfillRequestLogs(filters) {
		return nil
	}

	searchFilters := logstore.SearchFilters{}
	if filters.DateRange != nil {
		searchFilters.StartTime = parseAuditLogFilterTime(filters.DateRange.Start)
		searchFilters.EndTime = parseAuditLogFilterTime(filters.DateRange.End)
	}
	if len(filters.Status) > 0 {
		searchFilters.Status = mapAuditStatusesToRuntimeStatuses(filters.Status)
	}

	offset := 0
	for {
		result, err := h.logStore.SearchLogs(ctx, searchFilters, logstore.PaginationOptions{
			Limit:  auditBackfillBatchSize,
			Offset: offset,
			SortBy: string(logstore.SortByTimestamp),
			Order:  string(logstore.SortAsc),
		})
		if err != nil {
			return err
		}
		if result == nil || len(result.Logs) == 0 {
			return nil
		}
		for i := range result.Logs {
			logEntry := result.Logs[i]
			if err := PersistAuditLogForRequestLog(ctx, h.auditStore, &logEntry); err != nil {
				return err
			}
		}
		if len(result.Logs) < auditBackfillBatchSize {
			return nil
		}
		offset += auditBackfillBatchSize
	}
}

func (h *AuditLogsHandler) backfillMCPAuditLogs(ctx context.Context, filters AuditLogFilters) error {
	if !shouldBackfillMCPLogs(filters) {
		return nil
	}

	searchFilters := logstore.MCPToolLogSearchFilters{}
	if filters.DateRange != nil {
		searchFilters.StartTime = parseAuditLogFilterTime(filters.DateRange.Start)
		searchFilters.EndTime = parseAuditLogFilterTime(filters.DateRange.End)
	}
	if len(filters.Status) > 0 {
		searchFilters.Status = mapAuditStatusesToRuntimeStatuses(filters.Status)
	}

	offset := 0
	for {
		result, err := h.logStore.SearchMCPToolLogs(ctx, searchFilters, logstore.PaginationOptions{
			Limit:  auditBackfillBatchSize,
			Offset: offset,
			SortBy: string(logstore.SortByTimestamp),
			Order:  string(logstore.SortAsc),
		})
		if err != nil {
			return err
		}
		if result == nil || len(result.Logs) == 0 {
			return nil
		}
		for i := range result.Logs {
			logEntry := result.Logs[i]
			if err := PersistAuditLogForMCPToolLog(ctx, h.auditStore, &logEntry); err != nil {
				return err
			}
		}
		if len(result.Logs) < auditBackfillBatchSize {
			return nil
		}
		offset += auditBackfillBatchSize
	}
}

func shouldBackfillRequestLogs(filters AuditLogFilters) bool {
	if len(filters.EventTypes) == 0 && len(filters.ResourceTypes) == 0 {
		return true
	}
	for _, eventType := range filters.EventTypes {
		switch strings.TrimSpace(strings.ToLower(eventType)) {
		case "", "authorization", "security_event":
			return true
		}
	}
	for _, resourceType := range filters.ResourceTypes {
		switch strings.TrimSpace(strings.ToLower(resourceType)) {
		case "virtual_key", "model_provider", "inference":
			return true
		}
	}
	return false
}

func shouldBackfillMCPLogs(filters AuditLogFilters) bool {
	if len(filters.EventTypes) == 0 && len(filters.ResourceTypes) == 0 {
		return true
	}
	for _, eventType := range filters.EventTypes {
		switch strings.TrimSpace(strings.ToLower(eventType)) {
		case "", "data_access":
			return true
		}
	}
	for _, resourceType := range filters.ResourceTypes {
		switch strings.TrimSpace(strings.ToLower(resourceType)) {
		case "mcp_gateway":
			return true
		}
	}
	return false
}

func parseAuditLogFilterTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			utc := parsed.UTC()
			return &utc
		}
	}
	return nil
}

func mapAuditStatusesToRuntimeStatuses(statuses []string) []string {
	if len(statuses) == 0 {
		return nil
	}
	runtimeStatuses := make([]string, 0, len(statuses))
	for _, status := range statuses {
		switch strings.TrimSpace(strings.ToLower(status)) {
		case "success":
			runtimeStatuses = append(runtimeStatuses, "success")
		case "failed", "error", "denied", "blocked", "warning":
			runtimeStatuses = append(runtimeStatuses, "error")
		}
	}
	return uniqueNonEmptyStrings(runtimeStatuses)
}
