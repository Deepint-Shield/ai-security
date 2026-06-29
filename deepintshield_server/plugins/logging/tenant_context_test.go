package logging

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func TestAsyncLoggingContextCopiesTenantAndUser(t *testing.T) {
	baseCtx := context.Background()
	baseCtx = context.WithValue(baseCtx, schemas.DeepIntShieldContextKeyTenantID, "tenant-123")
	baseCtx = context.WithValue(baseCtx, schemas.DeepIntShieldContextKeyUserID, "user-456")

	asyncCtx := asyncLoggingContext(baseCtx)

	if got := asyncCtx.Value(schemas.DeepIntShieldContextKeyTenantID); got != "tenant-123" {
		t.Fatalf("expected tenant id to be preserved, got %v", got)
	}
	if got := asyncCtx.Value(schemas.DeepIntShieldContextKeyUserID); got != "user-456" {
		t.Fatalf("expected user id to be preserved, got %v", got)
	}
}

func TestBuildInitialLogEntryPreservesTenantID(t *testing.T) {
	pending := &PendingLogData{
		RequestID: "req-1",
		TenantID:  "tenant-abc",
		Timestamp: time.Now().UTC(),
		InitialData: &InitialLogData{
			Object:   "chat.completion",
			Provider: "openai",
			Model:    "gpt-4o-mini",
		},
	}

	entry := buildInitialLogEntry(pending)

	if entry.TenantID != "tenant-abc" {
		t.Fatalf("expected tenant id on initial log entry, got %q", entry.TenantID)
	}
}
