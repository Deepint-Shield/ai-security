package handlers

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestAuditLogsMiddleware_PersistsConfigurationChangesPerTenant(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditStore(t)
	middleware := AuditLogsMiddleware(store, nil)
	handler := middleware(func(ctx *fasthttp.RequestCtx) {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserID, "user-admin-001")
		ctx.SetStatusCode(fasthttp.StatusOK)
	})

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPut)
	ctx.Request.SetRequestURI("/api/governance/teams/team-platform")
	ctx.Request.SetBodyString(`{"name":"Platform","member_customer_ids":["cust_1","cust_2"]}`)
	handler(ctx)

	result, err := store.SearchAuditLogs(context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com"), logstore.AuditLogFilters{
		EventTypes:    []string{"configuration_change"},
		ResourceTypes: []string{"team"},
	}, &logstore.AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, result.Logs, 1)

	entry := result.Logs[0]
	assert.Equal(t, "team_updated", entry.Action)
	assert.Equal(t, "success", entry.Status)
	assert.Equal(t, "user-admin-001", entry.Actor.UserID)
	assert.Equal(t, "team-platform", entry.ResourceID)
	assert.ElementsMatch(t, []string{"member_customer_ids", "name"}, entry.Details["changed_fields"])
}

func TestAuditLogsMiddleware_ResolvesTenantFromLoginEmail(t *testing.T) {
	SetLogger(&mockLogger{})

	store := newTestAuditStore(t)
	middleware := AuditLogsMiddleware(store, nil)
	handler := middleware(func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	})

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/api/session/login")
	ctx.Request.SetBodyString(`{"email":"alice@example.com","password":"bad-password"}`)
	handler(ctx)

	result, err := store.SearchAuditLogs(context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, "alice@example.com"), logstore.AuditLogFilters{
		EventTypes: []string{"authentication"},
		Actions:    []string{"user_login"},
	}, &logstore.AuditLogSort{Field: "timestamp", Order: "desc"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, result.Logs, 1)

	entry := result.Logs[0]
	assert.Equal(t, "denied", entry.Status)
	assert.Equal(t, "alice@example.com", entry.Actor.Email)
	assert.Equal(t, "session", entry.ResourceType)
	assert.Equal(t, "password", entry.Details["auth_method"])
}
