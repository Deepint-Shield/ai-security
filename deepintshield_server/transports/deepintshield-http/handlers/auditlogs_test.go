package handlers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func newTestAuditRuntimeStore(t *testing.T) logstore.LogStore {
	t.Helper()

	store, err := logstore.NewLogStore(context.Background(), &logstore.Config{
		Type: logstore.LogStoreTypeSQLite,
		Config: &logstore.SQLiteConfig{
			Path: filepath.Join(t.TempDir(), "audit-handler-test.db"),
		},
	}, &mockLogger{})
	require.NoError(t, err)
	return store
}

func newTestAuditStore(t *testing.T) logstore.AuditLogStore {
	t.Helper()

	store := newTestAuditRuntimeStore(t)
	auditStore, ok := store.(logstore.AuditLogStore)
	require.True(t, ok)
	return auditStore
}

func seedTenantAuditFixtures(t *testing.T, store logstore.AuditLogStore, tenantID string) {
	t.Helper()

	tenantCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
	prefix := strings.ReplaceAll(strings.Split(tenantID, "@")[0], ".", "_")
	require.NoError(t, store.CreateAuditLog(tenantCtx, &logstore.AuditLogEntry{
		EventID:      "evt_auth_" + prefix,
		Timestamp:    time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
		EventType:    "authentication",
		Action:       "user_login",
		Status:       "failed",
		Severity:     "medium",
		ResourceType: "session",
		Actor: logstore.AuditLogActor{
			UserID:    "user-alice-001",
			Email:     tenantID,
			IPAddress: "203.0.113.42",
		},
		Details: map[string]any{
			"auth_method":    "password",
			"attempts_count": 3,
		},
	}))
	require.NoError(t, store.CreateAuditLog(tenantCtx, &logstore.AuditLogEntry{
		EventID:      "evt_cfg_" + prefix,
		Timestamp:    time.Date(2026, 4, 2, 10, 0, 0, 0, time.UTC),
		EventType:    "configuration_change",
		Action:       "oidc_settings_updated",
		Status:       "success",
		Severity:     "high",
		ResourceType: "oidc",
		ResourceID:   "entra",
		Actor: logstore.AuditLogActor{
			UserID:    "user-admin-001",
			Email:     tenantID,
			IPAddress: "198.51.100.10",
		},
		Details: map[string]any{
			"changed_fields": []string{"client_id", "roles_field"},
		},
	}))
	require.NoError(t, store.CreateAuditLog(tenantCtx, &logstore.AuditLogEntry{
		EventID:      "evt_sec_" + prefix,
		Timestamp:    time.Date(2026, 4, 3, 10, 0, 0, 0, time.UTC),
		EventType:    "security_event",
		Action:       "suspicious_ip_detected",
		Status:       "warning",
		Severity:     "critical",
		ResourceType: "session",
		Actor: logstore.AuditLogActor{
			UserID:    "user-security-001",
			Email:     tenantID,
			IPAddress: "192.0.2.77",
		},
		Details: map[string]any{
			"ip_reputation": "high_risk",
		},
	}))
}

func newTestAuditLogsHandler(t *testing.T, store logstore.LogStore) *AuditLogsHandler {
	t.Helper()
	return NewAuditLogsHandler(store)
}

func TestAuditLogsHandler_GetAuditLogs_FiltersByQueryParams(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditRuntimeStore(t)
	auditStore, ok := store.(logstore.AuditLogStore)
	require.True(t, ok)
	seedTenantAuditFixtures(t, auditStore, "alice@example.com")
	seedTenantAuditFixtures(t, auditStore, "bob@example.com")

	handler := newTestAuditLogsHandler(t, store)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/audit-logs?event_type=configuration_change&resource_type=oidc&severity=high")

	handler.getAuditLogs(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	var response AuditLogsResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))
	require.Len(t, response.AuditLogs, 1)
	assert.Equal(t, 1, response.TotalCount)
	assert.Equal(t, "configuration_change", response.AuditLogs[0].EventType)
	assert.Equal(t, "oidc", response.AuditLogs[0].ResourceType)
	assert.Equal(t, "high", response.AuditLogs[0].Severity)
	assert.True(t, response.AuditLogs[0].Verification.Verified)
}

func TestAuditLogsHandler_GetAuditSummary_ReturnsFilteredOverview(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditRuntimeStore(t)
	auditStore, ok := store.(logstore.AuditLogStore)
	require.True(t, ok)
	seedTenantAuditFixtures(t, auditStore, "alice@example.com")
	seedTenantAuditFixtures(t, auditStore, "bob@example.com")

	handler := newTestAuditLogsHandler(t, store)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/audit-logs/summary?event_type=security_event&severity=critical")

	handler.getAuditSummary(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	var response AuditSummaryResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))

	assert.Equal(t, 1, response.Overview.TotalEvents)
	assert.Equal(t, 1, response.Overview.CriticalEvents)
	assert.Equal(t, 0, response.Overview.FailedEvents)
	assert.Len(t, response.VolumeTimeline, 1)
	require.Len(t, response.EventTypeBreakdown, 1)
	assert.Equal(t, "security_event", response.EventTypeBreakdown[0].Name)
	assert.Equal(t, 1, response.EventTypeBreakdown[0].Count)
}

func TestAuditLogsHandler_BackfillsFromRuntimeLogs(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditRuntimeStore(t)
	tenantCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	require.NoError(t, store.Create(tenantCtx, &logstore.Log{
		ID:        "req_backfill_runtime",
		TenantID:  "alice@example.com",
		Timestamp: time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "success",
	}))
	require.NoError(t, store.CreateMCPToolLog(tenantCtx, &logstore.MCPToolLog{
		ID:          "mcp_backfill_runtime",
		TenantID:    "alice@example.com",
		Timestamp:   time.Date(2026, 4, 4, 10, 1, 0, 0, time.UTC),
		ToolName:    "search_docs",
		ServerLabel: "knowledge",
		Status:      "success",
	}))

	handler := newTestAuditLogsHandler(t, store)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI("/api/audit-logs/summary?start_date=2026-04-01&end_date=2026-04-08")

	handler.getAuditSummary(ctx)

	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	var response AuditSummaryResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))
	assert.Equal(t, 2, response.Overview.TotalEvents)
	assert.NotEmpty(t, response.EventTypeBreakdown)

	auditStore, ok := store.(logstore.AuditLogStore)
	require.True(t, ok)
	searchResult, err := auditStore.SearchAuditLogs(tenantCtx, logstore.AuditLogFilters{}, &logstore.AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, searchResult.Logs, 2)
}
