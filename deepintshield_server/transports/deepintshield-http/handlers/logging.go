// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains logging-related handlers for log search, stats, and management.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/plugins/logging"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
	"golang.org/x/sync/errgroup"
)

// applyActiveWorkspaceToLogFilters seeds filters.WorkspaceID and TenantID
// from the request context (X-Tenant-Id / X-Active-Workspace-Id headers)
// when the caller didn't pass them explicitly. Tenant scoping is always
// applied when present in context - without it, dashboard histograms leak
// rows from sibling tenants whose logs share the same NULL workspace_id.
func applyActiveWorkspaceToLogFilters(ctx *fasthttp.RequestCtx, filters *logstore.SearchFilters) {
	if filters == nil {
		return
	}
	if strings.TrimSpace(filters.TenantID) == "" {
		if t := tenantctx.TenantIDFromContext(ctx); t != "" {
			filters.TenantID = t
		}
	}
	if strings.TrimSpace(filters.WorkspaceID) == "" {
		if ws := tenantctx.WorkspaceIDFromContext(ctx); ws != "" {
			filters.WorkspaceID = ws
		}
	}
}

func applyActiveWorkspaceToMCPLogFilters(ctx *fasthttp.RequestCtx, filters *logstore.MCPToolLogSearchFilters) {
	if filters == nil {
		return
	}
	if strings.TrimSpace(filters.TenantID) == "" {
		if t := tenantctx.TenantIDFromContext(ctx); t != "" {
			filters.TenantID = t
		}
	}
	if strings.TrimSpace(filters.WorkspaceID) == "" {
		if ws := tenantctx.WorkspaceIDFromContext(ctx); ws != "" {
			filters.WorkspaceID = ws
		}
	}
}

// applyActiveOrgWorkspaceAllowlist scopes the dashboard query to the
// workspaces that belong to the UI-selected org. The legacy tenant_id is
// the email-keyed partition (one value per user account), so without this
// allowlist switching between Prod / DEV / TEST in the sidebar leaves the
// data unchanged. When the active org has zero workspaces (e.g., a freshly-
// created TEST tenant), the allowlist is set to an empty slice so the data
// layer returns zero rows - the correct empty state.
//
// Safe to call even when filters or h.workspaceLister are nil; both make
// this a no-op (legacy behaviour).
func (h *LoggingHandler) applyActiveOrgWorkspaceAllowlist(ctx *fasthttp.RequestCtx, filters *logstore.SearchFilters) {
	if h == nil || h.workspaceLister == nil || filters == nil || filters.AllowedWorkspaceIDs != nil {
		return
	}
	activeOrg := tenantctx.ActiveTenantIDFromContext(ctx)
	if activeOrg == "" {
		// No UI override; legacy partition scoping (filters.TenantID) is
		// sufficient when the user is in their home org.
		return
	}
	workspaces, err := h.workspaceLister.ListWorkspacesByOrg(ctx, activeOrg)
	if err != nil {
		// Be safe: if we can't enumerate the org's workspaces, return
		// nothing rather than fall back to the leaky tenant filter.
		empty := []string{}
		filters.AllowedWorkspaceIDs = &empty
		return
	}
	ids := make([]string, 0, len(workspaces))
	for _, ws := range workspaces {
		ids = append(ids, ws.ID)
	}
	filters.AllowedWorkspaceIDs = &ids
}

func (h *LoggingHandler) applyActiveOrgWorkspaceAllowlistMCP(ctx *fasthttp.RequestCtx, filters *logstore.MCPToolLogSearchFilters) {
	if h == nil || h.workspaceLister == nil || filters == nil || filters.AllowedWorkspaceIDs != nil {
		return
	}
	activeOrg := tenantctx.ActiveTenantIDFromContext(ctx)
	if activeOrg == "" {
		return
	}
	workspaces, err := h.workspaceLister.ListWorkspacesByOrg(ctx, activeOrg)
	if err != nil {
		empty := []string{}
		filters.AllowedWorkspaceIDs = &empty
		return
	}
	ids := make([]string, 0, len(workspaces))
	for _, ws := range workspaces {
		ids = append(ids, ws.ID)
	}
	filters.AllowedWorkspaceIDs = &ids
}

// LoggingHandler manages HTTP requests for logging operations
type LoggingHandler struct {
	logManager          logging.LogManager
	redactedKeysManager RedactedKeysManager
	config              *lib.Config
	// workspaceLister resolves the workspace IDs that belong to the active
	// org so dashboard reads can be scoped to the UI tenant the user
	// picked, not just the email-keyed partition. May be nil in tests /
	// non-dashboard configurations - when nil, active-org workspace
	// scoping is skipped (legacy behaviour).
	workspaceLister WorkspaceLister
}

// WorkspaceLister is the minimal slice of the configstore that the logging
// handler needs to enforce per-org isolation across the dashboard. Kept as a
// narrow interface so unit tests can swap in a fake without dragging the full
// configstore in.
type WorkspaceLister interface {
	ListWorkspacesByOrg(ctx context.Context, orgID string) ([]tables.TableWorkspace, error)
}

type guardrailStatusProvider interface {
	GetGuardrailStatusByRequestIDs(ctx context.Context, requestIDs []string) (map[string]string, error)
}

type guardrailSourceProvider interface {
	GetGuardrailSourceByRequestIDs(ctx context.Context, requestIDs []string) (map[string]string, error)
}

type RedactedKeysManager interface {
	GetAllRedactedKeys(ctx context.Context, ids []string) []schemas.Key
	GetAllRedactedVirtualKeys(ctx context.Context, ids []string) []tables.TableVirtualKey
	GetAllRedactedRoutingRules(ctx context.Context, ids []string) []tables.TableRoutingRule
}

// NewLoggingHandler creates a new logging handler instance
func NewLoggingHandler(logManager logging.LogManager, redactedKeysManager RedactedKeysManager, config *lib.Config, workspaceLister WorkspaceLister) *LoggingHandler {
	return &LoggingHandler{
		logManager:          logManager,
		redactedKeysManager: redactedKeysManager,
		config:              config,
		workspaceLister:     workspaceLister,
	}
}

func (h *LoggingHandler) shouldHideDeletedVirtualKeysInFilters() bool {
	if h == nil || h.config == nil {
		return false
	}
	return h.config.ClientConfig.HideDeletedVirtualKeysInFilters
}

// RegisterRoutes registers all logging-related routes
func (h *LoggingHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// LLM Log retrieval with filtering, search, and pagination
	r.GET("/api/logs", lib.ChainMiddlewares(h.getLogs, middlewares...))
	r.GET("/api/logs/{id}", lib.ChainMiddlewares(h.getLogByID, middlewares...))
	r.GET("/api/logs/stats", lib.ChainMiddlewares(h.getLogsStats, middlewares...))
	r.GET("/api/logs/histogram", lib.ChainMiddlewares(h.getLogsHistogram, middlewares...))
	r.GET("/api/logs/histogram/tokens", lib.ChainMiddlewares(h.getLogsTokenHistogram, middlewares...))
	r.GET("/api/logs/histogram/cache", lib.ChainMiddlewares(h.getLogsCacheHistogram, middlewares...))
	r.GET("/api/logs/histogram/cost", lib.ChainMiddlewares(h.getLogsCostHistogram, middlewares...))
	r.GET("/api/logs/histogram/optimization", lib.ChainMiddlewares(h.getLogsOptimizationHistogram, middlewares...))
	r.GET("/api/logs/histogram/models", lib.ChainMiddlewares(h.getLogsModelHistogram, middlewares...))
	r.GET("/api/logs/histogram/latency", lib.ChainMiddlewares(h.getLogsLatencyHistogram, middlewares...))
	r.GET("/api/logs/histogram/cost/by-provider", lib.ChainMiddlewares(h.getLogsProviderCostHistogram, middlewares...))
	r.GET("/api/logs/histogram/tokens/by-provider", lib.ChainMiddlewares(h.getLogsProviderTokenHistogram, middlewares...))
	r.GET("/api/logs/histogram/latency/by-provider", lib.ChainMiddlewares(h.getLogsProviderLatencyHistogram, middlewares...))
	r.GET("/api/logs/dropped", lib.ChainMiddlewares(h.getDroppedRequests, middlewares...))
	r.GET("/api/logs/filterdata", lib.ChainMiddlewares(h.getAvailableFilterData, middlewares...))
	r.GET("/api/logs/rankings", lib.ChainMiddlewares(h.getModelRankings, middlewares...))
	r.DELETE("/api/logs", lib.ChainMiddlewares(h.deleteLogs, middlewares...))
	r.POST("/api/logs/recalculate-cost", lib.ChainMiddlewares(h.recalculateLogCosts, middlewares...))
	r.POST("/api/logs/refresh-dashboard", lib.ChainMiddlewares(h.refreshDashboardAggregates, middlewares...))

	// MCP Tool Log retrieval with filtering, search, and pagination
	r.GET("/api/mcp-logs", lib.ChainMiddlewares(h.getMCPLogs, middlewares...))
	r.GET("/api/mcp-logs/stats", lib.ChainMiddlewares(h.getMCPLogsStats, middlewares...))
	r.GET("/api/mcp-logs/filterdata", lib.ChainMiddlewares(h.getMCPLogsFilterData, middlewares...))
	r.GET("/api/mcp-logs/histogram", lib.ChainMiddlewares(h.getMCPHistogram, middlewares...))
	r.GET("/api/mcp-logs/histogram/cost", lib.ChainMiddlewares(h.getMCPCostHistogram, middlewares...))
	r.GET("/api/mcp-logs/histogram/top-tools", lib.ChainMiddlewares(h.getMCPTopTools, middlewares...))
	r.DELETE("/api/mcp-logs", lib.ChainMiddlewares(h.deleteMCPLogs, middlewares...))
}

// getLogs handles GET /api/logs - Get logs with filtering, search, and pagination via query parameters
func (h *LoggingHandler) getLogs(ctx *fasthttp.RequestCtx) {
	// Parse query parameters into filters
	filters := &logstore.SearchFilters{}
	pagination := &logstore.PaginationOptions{}

	// Extract filters from query parameters
	if providers := string(ctx.QueryArgs().Peek("providers")); providers != "" {
		filters.Providers = parseCommaSeparated(providers)
	}
	if models := string(ctx.QueryArgs().Peek("models")); models != "" {
		filters.Models = parseCommaSeparated(models)
	}
	if statuses := string(ctx.QueryArgs().Peek("status")); statuses != "" {
		filters.Status = parseCommaSeparated(statuses)
	}
	if objects := string(ctx.QueryArgs().Peek("objects")); objects != "" {
		filters.Objects = parseCommaSeparated(objects)
	}
	if selectedKeyIDs := string(ctx.QueryArgs().Peek("selected_key_ids")); selectedKeyIDs != "" {
		filters.SelectedKeyIDs = parseCommaSeparated(selectedKeyIDs)
	}
	if virtualKeyIDs := string(ctx.QueryArgs().Peek("virtual_key_ids")); virtualKeyIDs != "" {
		filters.VirtualKeyIDs = parseCommaSeparated(virtualKeyIDs)
	}
	if routingRuleIDs := string(ctx.QueryArgs().Peek("routing_rule_ids")); routingRuleIDs != "" {
		filters.RoutingRuleIDs = parseCommaSeparated(routingRuleIDs)
	}
	if routingEngines := string(ctx.QueryArgs().Peek("routing_engine_used")); routingEngines != "" {
		filters.RoutingEngineUsed = parseCommaSeparated(routingEngines)
	}
	if guardrailStatuses := string(ctx.QueryArgs().Peek("guardrail_statuses")); guardrailStatuses != "" {
		filters.GuardrailStatuses = parseCommaSeparated(guardrailStatuses)
	}
	if guardrailSources := string(ctx.QueryArgs().Peek("guardrail_sources")); guardrailSources != "" {
		filters.GuardrailSources = parseCommaSeparated(guardrailSources)
	}
	if startTime := string(ctx.QueryArgs().Peek("start_time")); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filters.StartTime = &t
		}
	}
	if endTime := string(ctx.QueryArgs().Peek("end_time")); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filters.EndTime = &t
		}
	}
	if minLatency := string(ctx.QueryArgs().Peek("min_latency")); minLatency != "" {
		if f, err := strconv.ParseFloat(minLatency, 64); err == nil {
			filters.MinLatency = &f
		}
	}
	if maxLatency := string(ctx.QueryArgs().Peek("max_latency")); maxLatency != "" {
		if val, err := strconv.ParseFloat(maxLatency, 64); err == nil {
			filters.MaxLatency = &val
		}
	}
	if minTokens := string(ctx.QueryArgs().Peek("min_tokens")); minTokens != "" {
		if val, err := strconv.Atoi(minTokens); err == nil {
			filters.MinTokens = &val
		}
	}
	if maxTokens := string(ctx.QueryArgs().Peek("max_tokens")); maxTokens != "" {
		if val, err := strconv.Atoi(maxTokens); err == nil {
			filters.MaxTokens = &val
		}
	}
	if cost := string(ctx.QueryArgs().Peek("min_cost")); cost != "" {
		if val, err := strconv.ParseFloat(cost, 64); err == nil {
			filters.MinCost = &val
		}
	}
	if maxCost := string(ctx.QueryArgs().Peek("max_cost")); maxCost != "" {
		if val, err := strconv.ParseFloat(maxCost, 64); err == nil {
			filters.MaxCost = &val
		}
	}
	if missingCost := string(ctx.QueryArgs().Peek("missing_cost_only")); missingCost != "" {
		if val, err := strconv.ParseBool(missingCost); err == nil {
			filters.MissingCostOnly = val
		}
	}
	if contentSearch := string(ctx.QueryArgs().Peek("content_search")); contentSearch != "" {
		filters.ContentSearch = contentSearch
	}
	parseMetadataFilters(ctx, filters)

	// Extract pagination parameters
	pagination.Limit = 50 // Default limit
	if limit := string(ctx.QueryArgs().Peek("limit")); limit != "" {
		if i, err := strconv.Atoi(limit); err == nil {
			if i <= 0 {
				SendError(ctx, fasthttp.StatusBadRequest, "limit must be greater than 0")
				return
			}
			if i > 1000 {
				SendError(ctx, fasthttp.StatusBadRequest, "limit cannot exceed 1000")
				return
			}
			pagination.Limit = i
		}
	}

	pagination.Offset = 0 // Default offset
	if offset := string(ctx.QueryArgs().Peek("offset")); offset != "" {
		if i, err := strconv.Atoi(offset); err == nil {
			if i < 0 {
				SendError(ctx, fasthttp.StatusBadRequest, "offset cannot be negative")
				return
			}
			pagination.Offset = i
		}
	}

	// Sort parameters
	pagination.SortBy = "timestamp" // Default sort field
	if sortBy := string(ctx.QueryArgs().Peek("sort_by")); sortBy != "" {
		if sortBy == "timestamp" || sortBy == "latency" || sortBy == "tokens" || sortBy == "cost" {
			pagination.SortBy = sortBy
		}
	}

	pagination.Order = "desc" // Default sort order
	if order := string(ctx.QueryArgs().Peek("order")); order != "" {
		if order == "asc" || order == "desc" {
			pagination.Order = order
		}
	}

	if ws := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); ws != "" {
		filters.WorkspaceID = ws
	}
	applyActiveWorkspaceToLogFilters(ctx, filters)
	h.applyActiveOrgWorkspaceAllowlist(ctx, filters)

	result, err := h.logManager.Search(ctx, filters, pagination)
	if err != nil {
		logger.Error("failed to search logs: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Search failed: %v", err))
		return
	}

	selectedKeyIDs := make(map[string]struct{})
	virtualKeyIDs := make(map[string]struct{})
	routingRuleIDs := make(map[string]struct{})
	for _, log := range result.Logs {
		if log.SelectedKeyID != "" {
			selectedKeyIDs[log.SelectedKeyID] = struct{}{}
		}
		if log.VirtualKeyID != nil && *log.VirtualKeyID != "" {
			virtualKeyIDs[*log.VirtualKeyID] = struct{}{}
		}
		if log.RoutingRuleID != nil && *log.RoutingRuleID != "" {
			routingRuleIDs[*log.RoutingRuleID] = struct{}{}
		}
	}

	toSlice := func(m map[string]struct{}) []string {
		if len(m) == 0 {
			return nil
		}
		out := make([]string, 0, len(m))
		for id := range m {
			out = append(out, id)
		}
		return out
	}

	redactedKeys := h.redactedKeysManager.GetAllRedactedKeys(ctx, toSlice(selectedKeyIDs))
	redactedVirtualKeys := h.redactedKeysManager.GetAllRedactedVirtualKeys(ctx, toSlice(virtualKeyIDs))
	redactedRoutingRules := h.redactedKeysManager.GetAllRedactedRoutingRules(ctx, toSlice(routingRuleIDs))

	guardrailStatuses := map[string]string{}
	if provider, ok := h.logManager.(guardrailStatusProvider); ok {
		requestIDs := make([]string, 0, len(result.Logs))
		for _, log := range result.Logs {
			if strings.TrimSpace(log.ID) == "" {
				continue
			}
			requestIDs = append(requestIDs, log.ID)
		}
		statuses, statusErr := provider.GetGuardrailStatusByRequestIDs(ctx, requestIDs)
		if statusErr != nil {
			logger.Warn("failed to load guardrail statuses for logs: %v", statusErr)
		} else {
			guardrailStatuses = statuses
		}
	}
	guardrailSources := map[string]string{}
	if provider, ok := h.logManager.(guardrailSourceProvider); ok {
		requestIDs := make([]string, 0, len(result.Logs))
		for _, log := range result.Logs {
			if strings.TrimSpace(log.ID) == "" {
				continue
			}
			requestIDs = append(requestIDs, log.ID)
		}
		sources, sourceErr := provider.GetGuardrailSourceByRequestIDs(ctx, requestIDs)
		if sourceErr != nil {
			logger.Warn("failed to load guardrail sources for logs: %v", sourceErr)
		} else {
			guardrailSources = sources
		}
	}

	// Add selected key, virtual key, and routing rule to the result
	for i, log := range result.Logs {
		if log.SelectedKeyID != "" && log.SelectedKeyName != "" {
			result.Logs[i].SelectedKey = findRedactedKey(redactedKeys, log.SelectedKeyID, log.SelectedKeyName)
		}
		if log.VirtualKeyID != nil && log.VirtualKeyName != nil && *log.VirtualKeyID != "" && *log.VirtualKeyName != "" {
			result.Logs[i].VirtualKey = findRedactedVirtualKey(redactedVirtualKeys, *log.VirtualKeyID, *log.VirtualKeyName)
		}
		if log.RoutingRuleID != nil && log.RoutingRuleName != nil && *log.RoutingRuleID != "" && *log.RoutingRuleName != "" {
			result.Logs[i].RoutingRule = findRedactedRoutingRule(redactedRoutingRules, *log.RoutingRuleID, *log.RoutingRuleName)
		}
		if status := strings.TrimSpace(guardrailStatuses[log.ID]); status != "" {
			result.Logs[i].GuardrailStatus = status
		}
		if source := strings.TrimSpace(guardrailSources[log.ID]); source != "" {
			result.Logs[i].GuardrailSource = source
		}
	}

	SendJSON(ctx, result)
}

// getLogByID handles GET /api/logs/{id} - Get a single log entry by ID including raw_request and raw_response
func (h *LoggingHandler) getLogByID(ctx *fasthttp.RequestCtx) {
	id, ok := ctx.UserValue("id").(string)
	if !ok || id == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "log id is required")
		return
	}

	log, err := h.logManager.GetLog(ctx, id)
	if err != nil {
		if errors.Is(err, logstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, "log not found")
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get log: %v", err))
		return
	}

	SendJSON(ctx, log)
}

// getLogsStats handles GET /api/logs/stats - Get statistics for logs with filtering
func (h *LoggingHandler) getLogsStats(ctx *fasthttp.RequestCtx) {
	// Parse query parameters into filters (same as getLogs)
	filters := &logstore.SearchFilters{}

	// Extract filters from query parameters
	if providers := string(ctx.QueryArgs().Peek("providers")); providers != "" {
		filters.Providers = parseCommaSeparated(providers)
	}
	if models := string(ctx.QueryArgs().Peek("models")); models != "" {
		filters.Models = parseCommaSeparated(models)
	}
	if statuses := string(ctx.QueryArgs().Peek("status")); statuses != "" {
		filters.Status = parseCommaSeparated(statuses)
	}
	if objects := string(ctx.QueryArgs().Peek("objects")); objects != "" {
		filters.Objects = parseCommaSeparated(objects)
	}
	if selectedKeyIDs := string(ctx.QueryArgs().Peek("selected_key_ids")); selectedKeyIDs != "" {
		filters.SelectedKeyIDs = parseCommaSeparated(selectedKeyIDs)
	}
	if virtualKeyIDs := string(ctx.QueryArgs().Peek("virtual_key_ids")); virtualKeyIDs != "" {
		filters.VirtualKeyIDs = parseCommaSeparated(virtualKeyIDs)
	}
	if routingRuleIDs := string(ctx.QueryArgs().Peek("routing_rule_ids")); routingRuleIDs != "" {
		filters.RoutingRuleIDs = parseCommaSeparated(routingRuleIDs)
	}
	if routingEngines := string(ctx.QueryArgs().Peek("routing_engine_used")); routingEngines != "" {
		filters.RoutingEngineUsed = parseCommaSeparated(routingEngines)
	}
	if guardrailStatuses := string(ctx.QueryArgs().Peek("guardrail_statuses")); guardrailStatuses != "" {
		filters.GuardrailStatuses = parseCommaSeparated(guardrailStatuses)
	}
	if guardrailSources := string(ctx.QueryArgs().Peek("guardrail_sources")); guardrailSources != "" {
		filters.GuardrailSources = parseCommaSeparated(guardrailSources)
	}
	if startTime := string(ctx.QueryArgs().Peek("start_time")); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filters.StartTime = &t
		}
	}
	if endTime := string(ctx.QueryArgs().Peek("end_time")); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filters.EndTime = &t
		}
	}
	if minLatency := string(ctx.QueryArgs().Peek("min_latency")); minLatency != "" {
		if f, err := strconv.ParseFloat(minLatency, 64); err == nil {
			filters.MinLatency = &f
		}
	}
	if maxLatency := string(ctx.QueryArgs().Peek("max_latency")); maxLatency != "" {
		if val, err := strconv.ParseFloat(maxLatency, 64); err == nil {
			filters.MaxLatency = &val
		}
	}
	if minTokens := string(ctx.QueryArgs().Peek("min_tokens")); minTokens != "" {
		if val, err := strconv.Atoi(minTokens); err == nil {
			filters.MinTokens = &val
		}
	}
	if maxTokens := string(ctx.QueryArgs().Peek("max_tokens")); maxTokens != "" {
		if val, err := strconv.Atoi(maxTokens); err == nil {
			filters.MaxTokens = &val
		}
	}
	if cost := string(ctx.QueryArgs().Peek("min_cost")); cost != "" {
		if val, err := strconv.ParseFloat(cost, 64); err == nil {
			filters.MinCost = &val
		}
	}
	if maxCost := string(ctx.QueryArgs().Peek("max_cost")); maxCost != "" {
		if val, err := strconv.ParseFloat(maxCost, 64); err == nil {
			filters.MaxCost = &val
		}
	}
	if missingCost := string(ctx.QueryArgs().Peek("missing_cost_only")); missingCost != "" {
		if val, err := strconv.ParseBool(missingCost); err == nil {
			filters.MissingCostOnly = val
		}
	}
	if contentSearch := string(ctx.QueryArgs().Peek("content_search")); contentSearch != "" {
		filters.ContentSearch = contentSearch
	}
	if ws := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); ws != "" {
		filters.WorkspaceID = ws
	}
	parseMetadataFilters(ctx, filters)
	applyActiveWorkspaceToLogFilters(ctx, filters)
	h.applyActiveOrgWorkspaceAllowlist(ctx, filters)

	stats, err := h.logManager.GetStats(ctx, filters)
	if err != nil {
		logger.Error("failed to get log stats: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Stats calculation failed: %v", err))
		return
	}

	SendJSON(ctx, stats)
}

// getLogsHistogram handles GET /api/logs/histogram - Get time-bucketed request counts
func (h *LoggingHandler) getLogsHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get log histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Histogram calculation failed: %v", err))
		return
	}

	SendJSON(ctx, result)
}

// calculateBucketSize determines appropriate bucket size based on time range
func calculateBucketSize(start, end *time.Time) int64 {
	if start == nil || end == nil {
		return 3600 // Default 1 hour
	}
	duration := end.Sub(*start)
	switch {
	case duration >= 365*24*time.Hour: // >= 12 months
		return 30 * 24 * 3600 // Monthly (30 days)
	case duration >= 90*24*time.Hour: // >= 3 months
		return 7 * 24 * 3600 // Weekly (7 days)
	case duration >= 30*24*time.Hour: // >= 1 month
		return 3 * 24 * 3600 // 3 days
	case duration >= 7*24*time.Hour: // >= 7 days
		return 24 * 3600 // Daily
	case duration >= 3*24*time.Hour: // >= 3 days
		return 8 * 3600 // 8 hours
	case duration >= 24*time.Hour: // >= 24 hours
		return 3600 // Hourly
	case duration >= 2*time.Hour: // >= 2 hours
		return 600 // 10 minutes
	default:
		return 60 // 1 minute buckets for < 2 hours
	}
}

// parseHistogramFilters extracts common filter parameters from query args.
// Method on LoggingHandler so the active-org workspace allowlist can be
// resolved against the workspace store the handler owns.
func (h *LoggingHandler) parseHistogramFilters(ctx *fasthttp.RequestCtx) *logstore.SearchFilters {
	filters := &logstore.SearchFilters{}

	if providers := string(ctx.QueryArgs().Peek("providers")); providers != "" {
		filters.Providers = parseCommaSeparated(providers)
	}
	if models := string(ctx.QueryArgs().Peek("models")); models != "" {
		filters.Models = parseCommaSeparated(models)
	}
	if statuses := string(ctx.QueryArgs().Peek("status")); statuses != "" {
		filters.Status = parseCommaSeparated(statuses)
	}
	if objects := string(ctx.QueryArgs().Peek("objects")); objects != "" {
		filters.Objects = parseCommaSeparated(objects)
	}
	if selectedKeyIDs := string(ctx.QueryArgs().Peek("selected_key_ids")); selectedKeyIDs != "" {
		filters.SelectedKeyIDs = parseCommaSeparated(selectedKeyIDs)
	}
	if virtualKeyIDs := string(ctx.QueryArgs().Peek("virtual_key_ids")); virtualKeyIDs != "" {
		filters.VirtualKeyIDs = parseCommaSeparated(virtualKeyIDs)
	}
	if routingRuleIDs := string(ctx.QueryArgs().Peek("routing_rule_ids")); routingRuleIDs != "" {
		filters.RoutingRuleIDs = parseCommaSeparated(routingRuleIDs)
	}
	if routingEngines := string(ctx.QueryArgs().Peek("routing_engine_used")); routingEngines != "" {
		filters.RoutingEngineUsed = parseCommaSeparated(routingEngines)
	}
	if guardrailStatuses := string(ctx.QueryArgs().Peek("guardrail_statuses")); guardrailStatuses != "" {
		filters.GuardrailStatuses = parseCommaSeparated(guardrailStatuses)
	}
	if guardrailSources := string(ctx.QueryArgs().Peek("guardrail_sources")); guardrailSources != "" {
		filters.GuardrailSources = parseCommaSeparated(guardrailSources)
	}
	if startTime := string(ctx.QueryArgs().Peek("start_time")); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filters.StartTime = &t
		}
	}
	if endTime := string(ctx.QueryArgs().Peek("end_time")); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filters.EndTime = &t
		}
	}
	if minLatency := string(ctx.QueryArgs().Peek("min_latency")); minLatency != "" {
		if f, err := strconv.ParseFloat(minLatency, 64); err == nil {
			filters.MinLatency = &f
		}
	}
	if maxLatency := string(ctx.QueryArgs().Peek("max_latency")); maxLatency != "" {
		if val, err := strconv.ParseFloat(maxLatency, 64); err == nil {
			filters.MaxLatency = &val
		}
	}
	if minTokens := string(ctx.QueryArgs().Peek("min_tokens")); minTokens != "" {
		if val, err := strconv.Atoi(minTokens); err == nil {
			filters.MinTokens = &val
		}
	}
	if maxTokens := string(ctx.QueryArgs().Peek("max_tokens")); maxTokens != "" {
		if val, err := strconv.Atoi(maxTokens); err == nil {
			filters.MaxTokens = &val
		}
	}
	if cost := string(ctx.QueryArgs().Peek("min_cost")); cost != "" {
		if val, err := strconv.ParseFloat(cost, 64); err == nil {
			filters.MinCost = &val
		}
	}
	if maxCost := string(ctx.QueryArgs().Peek("max_cost")); maxCost != "" {
		if val, err := strconv.ParseFloat(maxCost, 64); err == nil {
			filters.MaxCost = &val
		}
	}
	if missingCost := string(ctx.QueryArgs().Peek("missing_cost_only")); missingCost != "" {
		if val, err := strconv.ParseBool(missingCost); err == nil {
			filters.MissingCostOnly = val
		}
	}
	if contentSearch := string(ctx.QueryArgs().Peek("content_search")); contentSearch != "" {
		filters.ContentSearch = contentSearch
	}
	if ws := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); ws != "" {
		filters.WorkspaceID = ws
	}
	parseMetadataFilters(ctx, filters)
	applyActiveWorkspaceToLogFilters(ctx, filters)
	h.applyActiveOrgWorkspaceAllowlist(ctx, filters)

	return filters
}

// getLogsTokenHistogram handles GET /api/logs/histogram/tokens - Get time-bucketed token usage
func (h *LoggingHandler) getLogsTokenHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetTokenHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get token histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Token histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsCacheHistogram handles GET /api/logs/histogram/cache - Get time-bucketed semantic cache outcomes
func (h *LoggingHandler) getLogsCacheHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetCacheHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get cache histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Cache histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsCostHistogram handles GET /api/logs/histogram/cost - Get time-bucketed cost data with model breakdown
func (h *LoggingHandler) getLogsCostHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetCostHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get cost histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Cost histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsOptimizationHistogram handles GET /api/logs/histogram/optimization -
// per-source savings + categorical aggregates for the Cost Optimization
// analytics tab. Same filter / bucket-size semantics as the cost histogram,
// so the UI can reuse parseHistogramFilters + calculateBucketSize verbatim.
func (h *LoggingHandler) getLogsOptimizationHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetOptimizationHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get optimization histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Optimization histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsModelHistogram handles GET /api/logs/histogram/models - Get time-bucketed model usage with success/error breakdown
func (h *LoggingHandler) getLogsModelHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetModelHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get model histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Model histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsLatencyHistogram handles GET /api/logs/histogram/latency - Get time-bucketed latency percentiles
func (h *LoggingHandler) getLogsLatencyHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetLatencyHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get latency histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Latency histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsProviderCostHistogram handles GET /api/logs/histogram/cost/by-provider - Get time-bucketed cost data with provider breakdown
func (h *LoggingHandler) getLogsProviderCostHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetProviderCostHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get provider cost histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Provider cost histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsProviderTokenHistogram handles GET /api/logs/histogram/tokens/by-provider - Get time-bucketed token usage with provider breakdown
func (h *LoggingHandler) getLogsProviderTokenHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetProviderTokenHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get provider token histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Provider token histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getLogsProviderLatencyHistogram handles GET /api/logs/histogram/latency/by-provider - Get time-bucketed latency percentiles with provider breakdown
func (h *LoggingHandler) getLogsProviderLatencyHistogram(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetProviderLatencyHistogram(ctx, filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get provider latency histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Provider latency histogram calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getDroppedRequests handles GET /api/logs/dropped - Get the number of dropped requests
func (h *LoggingHandler) getDroppedRequests(ctx *fasthttp.RequestCtx) {
	droppedRequests := h.logManager.GetDroppedRequests(ctx)
	SendJSON(ctx, map[string]int64{"dropped_requests": droppedRequests})
}

// getModelRankings handles GET /api/logs/rankings - Get models ranked by usage with trends
func (h *LoggingHandler) getModelRankings(ctx *fasthttp.RequestCtx) {
	filters := h.parseHistogramFilters(ctx)

	result, err := h.logManager.GetModelRankings(ctx, filters)
	if err != nil {
		logger.Error("failed to get model rankings: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Model rankings calculation failed: %v", err))
		return
	}

	SendJSONCached(ctx, result, 30)
}

// getAvailableFilterData handles GET /api/logs/filterdata - Get all unique filter data from logs
func (h *LoggingHandler) getAvailableFilterData(ctx *fasthttp.RequestCtx) {
	hideDeletedVirtualKeys := h.shouldHideDeletedVirtualKeysInFilters()

	var (
		models            []string
		selectedKeys      []logging.KeyPair
		virtualKeys       []logging.KeyPair
		routingRules      []logging.KeyPair
		routingEngines    []string
		guardrailStatuses []string
		metadataKeys      map[string][]string
		mu                sync.Mutex
	)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		result := h.logManager.GetAvailableModels(gCtx)
		mu.Lock()
		models = result
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		result := h.logManager.GetAvailableSelectedKeys(gCtx)
		mu.Lock()
		selectedKeys = result
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		result := h.logManager.GetAvailableVirtualKeys(gCtx)
		mu.Lock()
		virtualKeys = result
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		result := h.logManager.GetAvailableRoutingRules(gCtx)
		mu.Lock()
		routingRules = result
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		result := h.logManager.GetAvailableRoutingEngines(gCtx)
		mu.Lock()
		routingEngines = result
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		result := h.logManager.GetAvailableGuardrailStatuses(gCtx)
		mu.Lock()
		guardrailStatuses = result
		mu.Unlock()
		return nil
	})
	g.Go(func() error {
		// scope=llm  (AI Logs / default)   → object_type NOT LIKE 'agentic.%'
		// scope=agentic (Agentic Logs)     → object_type LIKE 'agentic.%'
		// scope=all  (legacy / exports)    → no object_type filter
		// AI Logs was rendering decision_id / identity_type / verdict / etc.
		// as permanently-empty dynamic columns because the previous
		// aggregator returned the union across both audiences; this
		// param keeps each list's metadata column set disjoint.
		scope := logstore.MetadataScopeLLM
		switch strings.ToLower(string(ctx.QueryArgs().Peek("scope"))) {
		case "agentic":
			scope = logstore.MetadataScopeAgentic
		case "all":
			scope = logstore.MetadataScopeAll
		}
		result, err := h.logManager.GetAvailableMetadataKeysScoped(gCtx, scope)
		if err != nil {
			return err
		}
		mu.Lock()
		metadataKeys = result
		mu.Unlock()
		return nil
	})

	if err := g.Wait(); err != nil {
		logger.Error("failed to get filter data: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get filter data: %v", err))
		return
	}

	// Extract IDs for redaction lookup
	selectedKeyIDs := make([]string, len(selectedKeys))
	for i, key := range selectedKeys {
		selectedKeyIDs[i] = key.ID
	}
	virtualKeyIDs := make([]string, len(virtualKeys))
	for i, key := range virtualKeys {
		virtualKeyIDs[i] = key.ID
	}
	routingRuleIDs := make([]string, len(routingRules))
	for i, rule := range routingRules {
		routingRuleIDs[i] = rule.ID
	}

	redactedSelectedKeys := make(map[string]schemas.Key)
	for _, selectedKey := range h.redactedKeysManager.GetAllRedactedKeys(ctx, selectedKeyIDs) {
		redactedSelectedKeys[selectedKey.ID] = selectedKey
	}
	redactedVirtualKeys := make(map[string]tables.TableVirtualKey)
	for _, virtualKey := range h.redactedKeysManager.GetAllRedactedVirtualKeys(ctx, virtualKeyIDs) {
		redactedVirtualKeys[virtualKey.ID] = virtualKey
	}
	redactedRoutingRules := make(map[string]tables.TableRoutingRule)
	for _, routingRule := range h.redactedKeysManager.GetAllRedactedRoutingRules(ctx, routingRuleIDs) {
		redactedRoutingRules[routingRule.ID] = routingRule
	}

	// Check if all selected key ids are present in the redacted selected keys (will not be present in case a key is deleted, but we still need to show its filter)
	for _, selectedKey := range selectedKeys {
		if _, ok := redactedSelectedKeys[selectedKey.ID]; !ok {
			// Create a new key struct directly since we know it doesn't exist
			redactedSelectedKeys[selectedKey.ID] = schemas.Key{
				ID:   selectedKey.ID,
				Name: selectedKey.Name + " (deleted)",
			}
		}
	}

	// Check if all virtual key ids are present in the redacted virtual keys (will not be present in case a virtual key is deleted, but we still need to show its filter)
	for _, virtualKey := range virtualKeys {
		if _, ok := redactedVirtualKeys[virtualKey.ID]; !ok {
			if hideDeletedVirtualKeys {
				continue
			}
			// Create a new virtual key struct directly since we know it doesn't exist
			redactedVirtualKeys[virtualKey.ID] = tables.TableVirtualKey{
				ID:   virtualKey.ID,
				Name: virtualKey.Name + " (deleted)",
			}
		}
	}

	// Check if all routing rule ids are present in the redacted routing rules (will not be present in case a routing rule is deleted, but we still need to show its filter)
	for _, routingRule := range routingRules {
		if _, ok := redactedRoutingRules[routingRule.ID]; !ok {
			// Create a new routing rule struct directly since we know it doesn't exist
			redactedRoutingRules[routingRule.ID] = tables.TableRoutingRule{
				ID:   routingRule.ID,
				Name: routingRule.Name + " (deleted)",
			}
		}
	}

	// Convert maps to arrays for frontend consumption
	selectedKeysArray := make([]schemas.Key, 0, len(redactedSelectedKeys))
	for _, key := range redactedSelectedKeys {
		selectedKeysArray = append(selectedKeysArray, key)
	}

	virtualKeysArray := make([]tables.TableVirtualKey, 0, len(redactedVirtualKeys))
	for _, key := range redactedVirtualKeys {
		virtualKeysArray = append(virtualKeysArray, key)
	}

	routingRulesArray := make([]tables.TableRoutingRule, 0, len(redactedRoutingRules))
	for _, rule := range redactedRoutingRules {
		routingRulesArray = append(routingRulesArray, rule)
	}

	if metadataKeys == nil {
		metadataKeys = make(map[string][]string)
	}
	if guardrailStatuses == nil {
		guardrailStatuses = []string{}
	}
	SendJSON(ctx, map[string]interface{}{"models": models, "selected_keys": selectedKeysArray, "virtual_keys": virtualKeysArray, "routing_rules": routingRulesArray, "routing_engines": routingEngines, "guardrail_statuses": guardrailStatuses, "metadata_keys": metadataKeys})
}

// deleteLogs handles DELETE /api/logs - Delete logs by their IDs
func (h *LoggingHandler) deleteLogs(ctx *fasthttp.RequestCtx) {
	// AI Logs are an immutable audit trail - they now also surface the
	// hash-chained agentic PDP decisions - so deletion is disabled. Refusing
	// here (not just hiding the UI button) makes immutability hold for the API
	// and any bulk path too. Retention should be a time-based policy, never an
	// interactive delete.
	SendError(ctx, fasthttp.StatusForbidden, "AI Logs are immutable; deletion is disabled")
}

// recalculateLogCosts handles POST /api/logs/recalculate-cost - recompute missing costs in batches
func (h *LoggingHandler) recalculateLogCosts(ctx *fasthttp.RequestCtx) {
	var payload recalculateCostRequest
	body := ctx.PostBody()
	if len(body) > 0 {
		if err := sonic.Unmarshal(body, &payload); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, "Invalid JSON")
			return
		}
	}

	limit := 200
	if payload.Limit != nil {
		limit = *payload.Limit
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	filters := payload.Filters
	filters.MissingCostOnly = true

	result, err := h.logManager.RecalculateCosts(ctx, &filters, limit)
	if err != nil {
		logger.Error("failed to recalculate log costs: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to recalculate costs: %v", err))
		return
	}

	SendJSON(ctx, result)
}

// refreshDashboardAggregates handles POST /api/logs/refresh-dashboard - refresh dashboard aggregates before refetching charts.
func (h *LoggingHandler) refreshDashboardAggregates(ctx *fasthttp.RequestCtx) {
	if err := h.logManager.RefreshDashboardAggregates(ctx); err != nil {
		logger.Error("failed to refresh dashboard aggregates: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Dashboard refresh failed: %v", err))
		return
	}

	SendJSON(ctx, map[string]bool{"refreshed": true})
}

// Helper functions

func findRedactedKey(redactedKeys []schemas.Key, id string, name string) *schemas.Key {
	if len(redactedKeys) == 0 {
		return &schemas.Key{
			ID: id,
			Name: func() string {
				if name != "" {
					return name + " (deleted)"
				} else {
					return ""
				}
			}(),
		}
	}
	for _, key := range redactedKeys {
		if key.ID == id {
			return &key
		}
	}
	return &schemas.Key{
		ID: id,
		Name: func() string {
			if name != "" {
				return name + " (deleted)"
			} else {
				return ""
			}
		}(),
	}
}

func findRedactedVirtualKey(redactedVirtualKeys []tables.TableVirtualKey, id string, name string) *tables.TableVirtualKey {
	if len(redactedVirtualKeys) == 0 {
		return &tables.TableVirtualKey{
			ID: id,
			Name: func() string {
				if name != "" {
					return name + " (deleted)"
				} else {
					return ""
				}
			}(),
		}
	}
	for _, virtualKey := range redactedVirtualKeys {
		if virtualKey.ID == id {
			return &virtualKey
		}
	}
	return &tables.TableVirtualKey{
		ID: id,
		Name: func() string {
			if name != "" {
				return name + " (deleted)"
			} else {
				return ""
			}
		}(),
	}
}

func findRedactedRoutingRule(redactedRoutingRules []tables.TableRoutingRule, id string, name string) *tables.TableRoutingRule {
	if len(redactedRoutingRules) == 0 {
		return &tables.TableRoutingRule{
			ID: id,
			Name: func() string {
				if name != "" {
					return name + " (deleted)"
				} else {
					return ""
				}
			}(),
		}
	}
	for _, routingRule := range redactedRoutingRules {
		if routingRule.ID == id {
			return &routingRule
		}
	}
	return &tables.TableRoutingRule{
		ID: id,
		Name: func() string {
			if name != "" {
				return name + " (deleted)"
			} else {
				return ""
			}
		}(),
	}
}

// parseCommaSeparated splits a comma-separated string into a slice
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}

	var result []string
	for _, item := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// parseMetadataFilters extracts metadata_* query params and sets them on the filters.
func parseMetadataFilters(ctx *fasthttp.RequestCtx, filters *logstore.SearchFilters) {
	var metadataFilters map[string]string
	ctx.QueryArgs().VisitAll(func(key, value []byte) { //nolint:staticcheck
		keyStr := string(key)
		if strings.HasPrefix(keyStr, "metadata_") {
			metadataKey := strings.TrimPrefix(keyStr, "metadata_")
			if metadataKey != "" {
				if metadataFilters == nil {
					metadataFilters = make(map[string]string)
				}
				metadataFilters[metadataKey] = string(value)
			}
		}
	})
	if len(metadataFilters) > 0 {
		filters.MetadataFilters = metadataFilters
	}
}

type recalculateCostRequest struct {
	Filters logstore.SearchFilters `json:"filters"`
	Limit   *int                   `json:"limit,omitempty"`
}

// parseMCPFiltersAndPagination parses MCP tool log filters and pagination from query parameters.
// Returns an error if any required parsing fails (e.g., invalid time format, invalid number format).
// Method on LoggingHandler so we can resolve the active-org workspace
// allowlist against the workspace store the handler owns.
func (h *LoggingHandler) parseMCPFiltersAndPagination(ctx *fasthttp.RequestCtx) (*logstore.MCPToolLogSearchFilters, *logstore.PaginationOptions, error) {
	filters := &logstore.MCPToolLogSearchFilters{}
	pagination := &logstore.PaginationOptions{}

	// Extract filters from query parameters
	if toolNames := string(ctx.QueryArgs().Peek("tool_names")); toolNames != "" {
		filters.ToolNames = parseCommaSeparated(toolNames)
	}
	if serverLabels := string(ctx.QueryArgs().Peek("server_labels")); serverLabels != "" {
		filters.ServerLabels = parseCommaSeparated(serverLabels)
	}
	if statuses := string(ctx.QueryArgs().Peek("status")); statuses != "" {
		filters.Status = parseCommaSeparated(statuses)
	}
	if virtualKeyIDs := string(ctx.QueryArgs().Peek("virtual_key_ids")); virtualKeyIDs != "" {
		filters.VirtualKeyIDs = parseCommaSeparated(virtualKeyIDs)
	}
	if llmRequestIDs := string(ctx.QueryArgs().Peek("llm_request_ids")); llmRequestIDs != "" {
		filters.LLMRequestIDs = parseCommaSeparated(llmRequestIDs)
	}
	if startTime := string(ctx.QueryArgs().Peek("start_time")); startTime != "" {
		t, err := time.Parse(time.RFC3339, startTime)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid start_time format: %w", err)
		}
		filters.StartTime = &t
	}
	if endTime := string(ctx.QueryArgs().Peek("end_time")); endTime != "" {
		t, err := time.Parse(time.RFC3339, endTime)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid end_time format: %w", err)
		}
		filters.EndTime = &t
	}
	if minLatency := string(ctx.QueryArgs().Peek("min_latency")); minLatency != "" {
		f, err := strconv.ParseFloat(minLatency, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid min_latency format: %w", err)
		}
		filters.MinLatency = &f
	}
	if maxLatency := string(ctx.QueryArgs().Peek("max_latency")); maxLatency != "" {
		val, err := strconv.ParseFloat(maxLatency, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid max_latency format: %w", err)
		}
		filters.MaxLatency = &val
	}
	if contentSearch := string(ctx.QueryArgs().Peek("content_search")); contentSearch != "" {
		filters.ContentSearch = contentSearch
	}

	// Extract pagination parameters
	pagination.Limit = 50 // Default limit
	if limit := string(ctx.QueryArgs().Peek("limit")); limit != "" {
		i, err := strconv.Atoi(limit)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid limit format: %w", err)
		}
		if i <= 0 {
			return nil, nil, fmt.Errorf("limit must be greater than 0")
		}
		if i > 1000 {
			return nil, nil, fmt.Errorf("limit cannot exceed 1000")
		}
		pagination.Limit = i
	}

	pagination.Offset = 0 // Default offset
	if offset := string(ctx.QueryArgs().Peek("offset")); offset != "" {
		i, err := strconv.Atoi(offset)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid offset format: %w", err)
		}
		if i < 0 {
			return nil, nil, fmt.Errorf("offset cannot be negative")
		}
		pagination.Offset = i
	}

	// Sort parameters
	pagination.SortBy = "timestamp" // Default sort field
	if sortBy := string(ctx.QueryArgs().Peek("sort_by")); sortBy != "" {
		if sortBy == "timestamp" || sortBy == "latency" || sortBy == "cost" {
			pagination.SortBy = sortBy
		} else {
			return nil, nil, fmt.Errorf("invalid sort_by: must be 'timestamp', 'latency' or 'cost'")
		}
	}

	pagination.Order = "desc" // Default sort order
	if order := string(ctx.QueryArgs().Peek("order")); order != "" {
		if order == "asc" || order == "desc" {
			pagination.Order = order
		} else {
			return nil, nil, fmt.Errorf("invalid order: must be 'asc' or 'desc'")
		}
	}

	if ws := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); ws != "" {
		filters.WorkspaceID = ws
	}
	applyActiveWorkspaceToMCPLogFilters(ctx, filters)
	h.applyActiveOrgWorkspaceAllowlistMCP(ctx, filters)

	return filters, pagination, nil
}

// parseMCPFilters parses MCP tool log filters from query parameters (without pagination).
// Returns an error if any required parsing fails.
func (h *LoggingHandler) parseMCPFilters(ctx *fasthttp.RequestCtx) (*logstore.MCPToolLogSearchFilters, error) {
	filters := &logstore.MCPToolLogSearchFilters{}

	// Extract filters from query parameters
	if toolNames := string(ctx.QueryArgs().Peek("tool_names")); toolNames != "" {
		filters.ToolNames = parseCommaSeparated(toolNames)
	}
	if serverLabels := string(ctx.QueryArgs().Peek("server_labels")); serverLabels != "" {
		filters.ServerLabels = parseCommaSeparated(serverLabels)
	}
	if statuses := string(ctx.QueryArgs().Peek("status")); statuses != "" {
		filters.Status = parseCommaSeparated(statuses)
	}
	if virtualKeyIDs := string(ctx.QueryArgs().Peek("virtual_key_ids")); virtualKeyIDs != "" {
		filters.VirtualKeyIDs = parseCommaSeparated(virtualKeyIDs)
	}
	if llmRequestIDs := string(ctx.QueryArgs().Peek("llm_request_ids")); llmRequestIDs != "" {
		filters.LLMRequestIDs = parseCommaSeparated(llmRequestIDs)
	}
	if startTime := string(ctx.QueryArgs().Peek("start_time")); startTime != "" {
		t, err := time.Parse(time.RFC3339, startTime)
		if err != nil {
			return nil, fmt.Errorf("invalid start_time format: %w", err)
		}
		filters.StartTime = &t
	}
	if endTime := string(ctx.QueryArgs().Peek("end_time")); endTime != "" {
		t, err := time.Parse(time.RFC3339, endTime)
		if err != nil {
			return nil, fmt.Errorf("invalid end_time format: %w", err)
		}
		filters.EndTime = &t
	}
	if minLatency := string(ctx.QueryArgs().Peek("min_latency")); minLatency != "" {
		f, err := strconv.ParseFloat(minLatency, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid min_latency format: %w", err)
		}
		filters.MinLatency = &f
	}
	if maxLatency := string(ctx.QueryArgs().Peek("max_latency")); maxLatency != "" {
		val, err := strconv.ParseFloat(maxLatency, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid max_latency format: %w", err)
		}
		filters.MaxLatency = &val
	}
	if contentSearch := string(ctx.QueryArgs().Peek("content_search")); contentSearch != "" {
		filters.ContentSearch = contentSearch
	}
	if ws := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id"))); ws != "" {
		filters.WorkspaceID = ws
	}
	applyActiveWorkspaceToMCPLogFilters(ctx, filters)
	h.applyActiveOrgWorkspaceAllowlistMCP(ctx, filters)

	return filters, nil
}

// ==================== MCP TOOL LOGGING HANDLERS ====================

// getMCPLogs handles GET /api/mcp-logs - Get MCP tool logs with filtering, search, and pagination via query parameters
func (h *LoggingHandler) getMCPLogs(ctx *fasthttp.RequestCtx) {
	filters, pagination, err := h.parseMCPFiltersAndPagination(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	result, err := h.logManager.SearchMCPToolLogs(ctx, filters, pagination)
	if err != nil {
		logger.Error("failed to search MCP tool logs: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Search failed: %v", err))
		return
	}

	// Collect unique virtual key IDs from the logs
	virtualKeyIDs := make(map[string]struct{})
	for _, log := range result.Logs {
		if log.VirtualKeyID != nil && *log.VirtualKeyID != "" {
			virtualKeyIDs[*log.VirtualKeyID] = struct{}{}
		}
	}

	toSlice := func(m map[string]struct{}) []string {
		if len(m) == 0 {
			return nil
		}
		out := make([]string, 0, len(m))
		for id := range m {
			out = append(out, id)
		}
		return out
	}

	redactedVirtualKeys := h.redactedKeysManager.GetAllRedactedVirtualKeys(ctx, toSlice(virtualKeyIDs))

	// Resolve the latest guardrail decision per MCP log (mirrors the AI Logs list endpoint).
	// MCP guardrail traces are persisted under the gateway request ID, which is also the MCP log ID.
	guardrailStatuses := map[string]string{}
	if provider, ok := h.logManager.(guardrailStatusProvider); ok {
		requestIDs := make([]string, 0, len(result.Logs))
		for _, log := range result.Logs {
			if strings.TrimSpace(log.ID) == "" {
				continue
			}
			requestIDs = append(requestIDs, log.ID)
		}
		statuses, statusErr := provider.GetGuardrailStatusByRequestIDs(ctx, requestIDs)
		if statusErr != nil {
			logger.Warn("failed to load guardrail statuses for MCP logs: %v", statusErr)
		} else {
			guardrailStatuses = statuses
		}
	}
	guardrailSources := map[string]string{}
	if provider, ok := h.logManager.(guardrailSourceProvider); ok {
		requestIDs := make([]string, 0, len(result.Logs))
		for _, log := range result.Logs {
			if strings.TrimSpace(log.ID) == "" {
				continue
			}
			requestIDs = append(requestIDs, log.ID)
		}
		sources, sourceErr := provider.GetGuardrailSourceByRequestIDs(ctx, requestIDs)
		if sourceErr != nil {
			logger.Warn("failed to load guardrail sources for MCP logs: %v", sourceErr)
		} else {
			guardrailSources = sources
		}
	}

	// Add virtual key + guardrail status + source to the result
	for i, log := range result.Logs {
		if log.VirtualKeyID != nil && log.VirtualKeyName != nil && *log.VirtualKeyID != "" && *log.VirtualKeyName != "" {
			result.Logs[i].VirtualKey = findRedactedVirtualKey(redactedVirtualKeys, *log.VirtualKeyID, *log.VirtualKeyName)
		}
		if status := strings.TrimSpace(guardrailStatuses[log.ID]); status != "" {
			result.Logs[i].GuardrailStatus = status
		}
		if source := strings.TrimSpace(guardrailSources[log.ID]); source != "" {
			result.Logs[i].GuardrailSource = source
		}
	}

	SendJSON(ctx, result)
}

// getMCPLogsStats handles GET /api/mcp-logs/stats - Get statistics for MCP tool logs with filtering
func (h *LoggingHandler) getMCPLogsStats(ctx *fasthttp.RequestCtx) {
	filters, err := h.parseMCPFilters(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	stats, err := h.logManager.GetMCPToolLogStats(ctx, filters)
	if err != nil {
		logger.Error("failed to get MCP tool log stats: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Stats calculation failed: %v", err))
		return
	}

	SendJSON(ctx, stats)
}

// getMCPLogsFilterData handles GET /api/mcp-logs/filterdata - Get all unique filter data from MCP tool logs
func (h *LoggingHandler) getMCPLogsFilterData(ctx *fasthttp.RequestCtx) {
	hideDeletedVirtualKeys := h.shouldHideDeletedVirtualKeysInFilters()

	toolNames, err := h.logManager.GetAvailableToolNames(ctx)
	if err != nil {
		logger.Error("failed to get available tool names: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get available tool names: %v", err))
		return
	}

	serverLabels, err := h.logManager.GetAvailableServerLabels(ctx)
	if err != nil {
		logger.Error("failed to get available server labels: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get available server labels: %v", err))
		return
	}

	virtualKeys := h.logManager.GetAvailableMCPVirtualKeys(ctx)

	// Extract IDs for redaction lookup
	virtualKeyIDs := make([]string, len(virtualKeys))
	for i, key := range virtualKeys {
		virtualKeyIDs[i] = key.ID
	}

	redactedVirtualKeys := make(map[string]tables.TableVirtualKey)
	for _, virtualKey := range h.redactedKeysManager.GetAllRedactedVirtualKeys(ctx, virtualKeyIDs) {
		redactedVirtualKeys[virtualKey.ID] = virtualKey
	}

	// Check if all virtual key ids are present in the redacted virtual keys (will not be present in case a virtual key is deleted, but we still need to show its filter)
	for _, virtualKey := range virtualKeys {
		if _, ok := redactedVirtualKeys[virtualKey.ID]; !ok {
			if hideDeletedVirtualKeys {
				continue
			}
			// Create a new virtual key struct directly since we know it doesn't exist
			redactedVirtualKeys[virtualKey.ID] = tables.TableVirtualKey{
				ID:   virtualKey.ID,
				Name: virtualKey.Name + " (deleted)",
			}
		}
	}

	// Convert maps to arrays for frontend consumption
	virtualKeysArray := make([]tables.TableVirtualKey, 0, len(redactedVirtualKeys))
	for _, key := range redactedVirtualKeys {
		virtualKeysArray = append(virtualKeysArray, key)
	}

	SendJSON(ctx, map[string]interface{}{
		"tool_names":    toolNames,
		"server_labels": serverLabels,
		"virtual_keys":  virtualKeysArray,
	})
}

// deleteMCPLogs handles DELETE /api/mcp-logs - Delete MCP tool logs by their IDs
func (h *LoggingHandler) deleteMCPLogs(ctx *fasthttp.RequestCtx) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid JSON")
		return
	}

	if len(req.IDs) == 0 {
		SendError(ctx, fasthttp.StatusBadRequest, "No log IDs provided")
		return
	}

	if err := h.logManager.DeleteMCPToolLogs(ctx, req.IDs); err != nil {
		logger.Error("failed to delete MCP tool logs: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to delete MCP tool logs")
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"message": "MCP tool logs deleted successfully",
	})
}

// parseMCPHistogramFilters extracts time range and MCP-specific filters for histogram queries.
func (h *LoggingHandler) parseMCPHistogramFilters(ctx *fasthttp.RequestCtx) (*logstore.MCPToolLogSearchFilters, error) {
	return h.parseMCPFilters(ctx)
}

// getMCPHistogram handles GET /api/mcp-logs/histogram - Get time-bucketed MCP tool call volume
func (h *LoggingHandler) getMCPHistogram(ctx *fasthttp.RequestCtx) {
	filters, err := h.parseMCPHistogramFilters(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetMCPHistogram(ctx, *filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get MCP histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("MCP histogram calculation failed: %v", err))
		return
	}

	SendJSON(ctx, result)
}

// getMCPCostHistogram handles GET /api/mcp-logs/histogram/cost - Get time-bucketed MCP cost data
func (h *LoggingHandler) getMCPCostHistogram(ctx *fasthttp.RequestCtx) {
	filters, err := h.parseMCPHistogramFilters(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	bucketSizeSeconds := calculateBucketSize(filters.StartTime, filters.EndTime)

	result, err := h.logManager.GetMCPCostHistogram(ctx, *filters, bucketSizeSeconds)
	if err != nil {
		logger.Error("failed to get MCP cost histogram: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("MCP cost histogram calculation failed: %v", err))
		return
	}

	SendJSON(ctx, result)
}

// getMCPTopTools handles GET /api/mcp-logs/histogram/top-tools - Get top 10 MCP tools by call count
func (h *LoggingHandler) getMCPTopTools(ctx *fasthttp.RequestCtx) {
	filters, err := h.parseMCPHistogramFilters(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	result, err := h.logManager.GetMCPTopTools(ctx, *filters, 10)
	if err != nil {
		logger.Error("failed to get MCP top tools: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("MCP top tools calculation failed: %v", err))
		return
	}

	SendJSON(ctx, result)
}
