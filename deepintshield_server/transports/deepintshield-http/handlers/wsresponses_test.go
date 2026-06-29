package handlers

import (
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func TestWSResponsesCreateDeepIntShieldContext_UsesFullVirtualKeyCarriersAndRejectsDirectKeys(t *testing.T) {
	handler := &WSResponsesHandler{}

	tests := []struct {
		name   string
		auth   *authHeaders
		wantVK string
	}{
		{
			name:   "x_bf_vk_header",
			auth:   &authHeaders{virtualKey: "sk-bf-valid"},
			wantVK: "sk-bf-valid",
		},
		{
			name:   "authorization_bearer",
			auth:   &authHeaders{authorization: "Bearer sk-bf-valid"},
			wantVK: "sk-bf-valid",
		},
		{
			name:   "x_api_key",
			auth:   &authHeaders{apiKey: "sk-bf-valid"},
			wantVK: "sk-bf-valid",
		},
		{
			name:   "x_goog_api_key",
			auth:   &authHeaders{googAPIKey: "sk-bf-valid"},
			wantVK: "sk-bf-valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deepintshieldCtx, cancel := handler.createDeepIntShieldContext(tt.auth)
			defer cancel()

			if got, _ := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyVirtualKey).(string); got != tt.wantVK {
				t.Fatalf("virtual key = %q, want %q", got, tt.wantVK)
			}
			if got := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyDirectKey); got != nil {
				t.Fatalf("expected no direct key in websocket context, got %#v", got)
			}
		})
	}

	deepintshieldCtx, cancel := handler.createDeepIntShieldContext(&authHeaders{
		authorization: "Bearer provider-secret",
		apiKey:        "provider-secret",
		googAPIKey:    "provider-secret",
	})
	defer cancel()

	if got := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyVirtualKey); got != nil {
		t.Fatalf("expected no virtual key from direct provider credentials, got %#v", got)
	}
	if got := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyDirectKey); got != nil {
		t.Fatalf("expected no direct key from websocket credentials, got %#v", got)
	}
}
