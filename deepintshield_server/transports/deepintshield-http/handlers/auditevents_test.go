package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersistAuditLogForRequestLog_PersistsRuntimeInferenceEvent(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditStore(t)
	ctx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	ctx = context.WithValue(ctx, schemas.DeepIntShieldContextKeyUserID, "user-runtime-001")

	logEntry := &logstore.Log{
		ID:               "req_runtime_success",
		TenantID:         "alice@example.com",
		Timestamp:        time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC),
		Object:           "chat.completion",
		Provider:         "openai",
		Model:            "gpt-4o-mini",
		Status:           "success",
		SelectedKeyID:    "key_1",
		SelectedKeyName:  "Primary OpenAI Key",
		PromptTokens:     123,
		CompletionTokens: 45,
		TotalTokens:      168,
		MetadataParsed: map[string]interface{}{
			"ip_address": "203.0.113.42",
		},
	}

	require.NoError(t, PersistAuditLogForRequestLog(ctx, store, logEntry))

	result, err := store.SearchAuditLogs(ctx, logstore.AuditLogFilters{
		EventTypes:    []string{"authorization"},
		Actions:       []string{"model_access_allowed"},
		ResourceTypes: []string{"model_provider"},
	}, &logstore.AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, result.Logs, 1)

	entry := result.Logs[0]
	assert.Equal(t, "success", entry.Status)
	assert.Equal(t, "user-runtime-001", entry.Actor.UserID)
	assert.Equal(t, "alice@example.com", entry.Actor.Email)
	assert.Equal(t, "203.0.113.42", entry.Actor.IPAddress)
	assert.Equal(t, "openai", entry.ResourceID)
	assert.EqualValues(t, 168, entry.Details["total_tokens"])
	assert.Equal(t, "gpt-4o-mini", entry.Details["model"])
}

func TestPersistAuditLogForRequestLog_TransformsSecurityFailures(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditStore(t)
	ctx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	statusCode := 429
	logEntry := &logstore.Log{
		ID:        "req_runtime_blocked",
		TenantID:  "alice@example.com",
		Timestamp: time.Date(2026, 4, 8, 11, 0, 0, 0, time.UTC),
		Object:    "chat.completion",
		Provider:  "openai",
		Model:     "gpt-4o-mini",
		Status:    "error",
		ErrorDetailsParsed: &schemas.DeepIntShieldError{
			StatusCode: &statusCode,
			Error: &schemas.ErrorField{
				Message: "rate limit exceeded for virtual key",
			},
		},
	}

	require.NoError(t, PersistAuditLogForRequestLog(ctx, store, logEntry))

	result, err := store.SearchAuditLogs(ctx, logstore.AuditLogFilters{
		EventTypes: []string{"security_event"},
		Actions:    []string{"rate_limit_violation"},
		Status:     []string{"blocked"},
	}, &logstore.AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, result.Logs, 1)
	assert.Equal(t, "high", result.Logs[0].Severity)
}

func TestPersistAuditLogForMCPToolLog_IgnoresProcessingAndPersistsFinalEvent(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditStore(t)
	ctx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
	ctx = context.WithValue(ctx, schemas.DeepIntShieldContextKeyUserID, "user-runtime-001")

	processing := &logstore.MCPToolLog{
		ID:          "mcp_processing",
		TenantID:    "alice@example.com",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
		ToolName:    "search_docs",
		ServerLabel: "knowledge",
		Status:      "processing",
	}
	require.NoError(t, PersistAuditLogForMCPToolLog(ctx, store, processing))

	final := &logstore.MCPToolLog{
		ID:          "mcp_processing",
		TenantID:    "alice@example.com",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 1, 0, time.UTC),
		ToolName:    "search_docs",
		ServerLabel: "knowledge",
		Status:      "success",
		MetadataParsed: map[string]interface{}{
			"client_ip": "198.51.100.20",
		},
	}
	require.NoError(t, PersistAuditLogForMCPToolLog(ctx, store, final))

	result, err := store.SearchAuditLogs(ctx, logstore.AuditLogFilters{
		EventTypes:    []string{"data_access"},
		ResourceTypes: []string{"mcp_gateway"},
	}, &logstore.AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, result.Logs, 1)

	entry := result.Logs[0]
	assert.Equal(t, "mcp_tool_executed", entry.Action)
	assert.Equal(t, "knowledge:search_docs", entry.ResourceID)
	assert.Equal(t, "198.51.100.20", entry.Actor.IPAddress)
}
