package guardrails

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func TestValidateLiveRequestGuardrailsRejectsInlineHeaders(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyRequestHeaders, map[string]string{
		headerInputGuardrails: `[{"name":"regex_match"}]`,
	})

	if err := validateLiveRequestGuardrails(ctx); err == nil {
		t.Fatalf("expected inline request guardrails to be rejected")
	}
}

func TestValidateLiveRequestGuardrailsAllowsPlainRequests(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)

	if err := validateLiveRequestGuardrails(ctx); err != nil {
		t.Fatalf("expected plain request to pass, got %v", err)
	}
}
