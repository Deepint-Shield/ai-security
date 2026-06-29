package handlers

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

type mockVirtualKeyValidationStore struct {
	configstore.ConfigStore
	virtualKeys map[string]*tables.TableVirtualKey
}

func (m *mockVirtualKeyValidationStore) GetVirtualKeyByValue(_ context.Context, value string) (*tables.TableVirtualKey, error) {
	if m == nil {
		return nil, configstore.ErrNotFound
	}
	vk, ok := m.virtualKeys[value]
	if !ok || vk == nil {
		return nil, configstore.ErrNotFound
	}
	copyVK := *vk
	return &copyVK, nil
}

func TestRequireValidVirtualKeyMiddleware_RejectsMissingAndInvalidAcrossRouteFamilies(t *testing.T) {
	store := &mockVirtualKeyValidationStore{
		virtualKeys: map[string]*tables.TableVirtualKey{
			"sk-bf-valid": {
				ID:       "vk-1",
				Value:    "sk-bf-valid",
				TenantID: "tenant-a",
			},
		},
	}

	families := []struct {
		name        string
		method      string
		uri         string
		isWebSocket bool
	}{
		{name: "inference", method: fasthttp.MethodPost, uri: "/v1/chat/completions"},
		{name: "integration", method: fasthttp.MethodPost, uri: "/openai/v1/chat/completions"},
		{name: "async", method: fasthttp.MethodPost, uri: "/v1/async/chat/completions"},
		{name: "mcp_inference", method: fasthttp.MethodPost, uri: "/v1/mcp/tool/execute"},
		{name: "mcp_server", method: fasthttp.MethodPost, uri: "/mcp"},
		{name: "guardrails_api", method: fasthttp.MethodPost, uri: "/api/guardrails/evaluate"},
		{name: "rag_api", method: fasthttp.MethodPost, uri: "/api/rag-security/evaluate"},
		{name: "ws_responses", method: fasthttp.MethodGet, uri: "/v1/responses", isWebSocket: true},
	}

	tests := []struct {
		name        string
		headerName  string
		headerValue string
		wantStatus  int
		wantNext    bool
	}{
		{
			name:       "missing virtual key",
			wantStatus: fasthttp.StatusUnauthorized,
		},
		{
			name:        "invalid virtual key",
			headerName:  "x-bf-vk",
			headerValue: "sk-bf-missing",
			wantStatus:  fasthttp.StatusForbidden,
		},
	}

	middleware := RequireValidVirtualKeyMiddleware(store)

	for _, family := range families {
		for _, tt := range tests {
			t.Run(family.name+"_"+tt.name, func(t *testing.T) {
				ctx := &fasthttp.RequestCtx{}
				ctx.Request.Header.SetMethod(family.method)
				ctx.Request.SetRequestURI(family.uri)
				if family.isWebSocket {
					ctx.Request.Header.Set("Upgrade", "websocket")
					ctx.Request.Header.Set("Connection", "Upgrade")
				}
				if tt.headerName != "" {
					ctx.Request.Header.Set(tt.headerName, tt.headerValue)
				}

				nextCalled := false
				handler := middleware(func(ctx *fasthttp.RequestCtx) {
					nextCalled = true
					ctx.SetStatusCode(fasthttp.StatusNoContent)
				})
				handler(ctx)

				if nextCalled != tt.wantNext {
					t.Fatalf("nextCalled = %v, want %v", nextCalled, tt.wantNext)
				}
				if got := ctx.Response.StatusCode(); got != tt.wantStatus {
					t.Fatalf("status = %d, want %d, body=%s", got, tt.wantStatus, string(ctx.Response.Body()))
				}
			})
		}
	}
}

func TestRequireValidVirtualKeyMiddleware_AllowsValidVirtualKeyCarriersAcrossRouteFamilies(t *testing.T) {
	store := &mockVirtualKeyValidationStore{
		virtualKeys: map[string]*tables.TableVirtualKey{
			"sk-bf-valid": {
				ID:       "vk-1",
				Value:    "sk-bf-valid",
				TenantID: "tenant-a",
			},
		},
	}

	tests := []struct {
		name        string
		method      string
		uri         string
		headerName  string
		headerValue string
		isWebSocket bool
	}{
		{
			name:        "inference_x_bf_vk",
			method:      fasthttp.MethodPost,
			uri:         "/v1/chat/completions",
			headerName:  "x-bf-vk",
			headerValue: "sk-bf-valid",
		},
		{
			name:        "integration_authorization",
			method:      fasthttp.MethodPost,
			uri:         "/openai/v1/chat/completions",
			headerName:  "Authorization",
			headerValue: "Bearer sk-bf-valid",
		},
		{
			name:        "async_x_api_key",
			method:      fasthttp.MethodPost,
			uri:         "/v1/async/chat/completions",
			headerName:  "x-api-key",
			headerValue: "sk-bf-valid",
		},
		{
			name:        "mcp_inference_x_goog_api_key",
			method:      fasthttp.MethodPost,
			uri:         "/v1/mcp/tool/execute",
			headerName:  "x-goog-api-key",
			headerValue: "sk-bf-valid",
		},
		{
			name:        "mcp_server_x_bf_vk",
			method:      fasthttp.MethodPost,
			uri:         "/mcp",
			headerName:  "x-bf-vk",
			headerValue: "sk-bf-valid",
		},
		{
			name:        "guardrails_api_x_bf_vk",
			method:      fasthttp.MethodPost,
			uri:         "/api/guardrails/evaluate",
			headerName:  "x-bf-vk",
			headerValue: "sk-bf-valid",
		},
		{
			name:        "rag_api_authorization",
			method:      fasthttp.MethodPost,
			uri:         "/api/rag-security/evaluate",
			headerName:  "Authorization",
			headerValue: "Bearer sk-bf-valid",
		},
		{
			name:        "ws_responses_authorization",
			method:      fasthttp.MethodGet,
			uri:         "/v1/responses",
			headerName:  "Authorization",
			headerValue: "Bearer sk-bf-valid",
			isWebSocket: true,
		},
	}

	middleware := RequireValidVirtualKeyMiddleware(store)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod(tt.method)
			ctx.Request.SetRequestURI(tt.uri)
			ctx.Request.Header.Set(tt.headerName, tt.headerValue)
			if tt.isWebSocket {
				ctx.Request.Header.Set("Upgrade", "websocket")
				ctx.Request.Header.Set("Connection", "Upgrade")
			}

			nextCalled := false
			handler := middleware(func(ctx *fasthttp.RequestCtx) {
				nextCalled = true
				ctx.SetStatusCode(fasthttp.StatusNoContent)
			})
			handler(ctx)

			if !nextCalled {
				t.Fatalf("expected middleware to allow valid virtual key for %s", tt.uri)
			}
			if got := ctx.Response.StatusCode(); got != fasthttp.StatusNoContent {
				t.Fatalf("status = %d, want %d, body=%s", got, fasthttp.StatusNoContent, string(ctx.Response.Body()))
			}
			if got := ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID); got != "tenant-a" {
				t.Fatalf("tenant_id = %v, want tenant-a", got)
			}
			if got := ctx.UserValue(schemas.DeepIntShieldContextKeyVirtualKey); got != "sk-bf-valid" {
				t.Fatalf("virtual_key = %v, want sk-bf-valid", got)
			}
		})
	}
}

func TestRequireValidVirtualKeyMiddleware_AllowsPromptRepositoryFrontendBypassWithAuthenticatedContext(t *testing.T) {
	middleware := RequireValidVirtualKeyMiddleware(&mockVirtualKeyValidationStore{})

	tests := []struct {
		name         string
		path         string
		sessionToken string
		tenantID     string
		wantNext     bool
		wantStatus   int
	}{
		{
			name:         "validated session token bypasses prompt repo frontend request",
			path:         "/v1/chat/completions",
			sessionToken: "session-token",
			wantNext:     true,
			wantStatus:   fasthttp.StatusNoContent,
		},
		{
			name:       "tenant scoped request bypasses prompt repo frontend request",
			path:       "/v1/chat/completions",
			tenantID:   "tenant-a",
			wantNext:   true,
			wantStatus: fasthttp.StatusNoContent,
		},
		{
			name:       "missing frontend context still requires virtual key",
			path:       "/v1/chat/completions",
			wantNext:   false,
			wantStatus: fasthttp.StatusUnauthorized,
		},
		{
			name:         "bypass is limited to prompt repo chat completions route",
			path:         "/v1/responses",
			sessionToken: "session-token",
			wantNext:     false,
			wantStatus:   fasthttp.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod(fasthttp.MethodPost)
			ctx.Request.SetRequestURI(tt.path)
			ctx.Request.Header.Set(promptRepositoryFrontendSourceHeader, promptRepositoryFrontendSourceValue)
			if tt.sessionToken != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, tt.sessionToken)
			}
			if tt.tenantID != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, tt.tenantID)
			}

			nextCalled := false
			handler := middleware(func(ctx *fasthttp.RequestCtx) {
				nextCalled = true
				ctx.SetStatusCode(fasthttp.StatusNoContent)
			})
			handler(ctx)

			if nextCalled != tt.wantNext {
				t.Fatalf("nextCalled = %v, want %v", nextCalled, tt.wantNext)
			}
			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", got, tt.wantStatus, string(ctx.Response.Body()))
			}
		})
	}
}
