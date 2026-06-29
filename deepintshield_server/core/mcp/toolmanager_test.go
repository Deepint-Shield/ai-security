package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func TestIsToolPermittedForExecution(t *testing.T) {
	makeClient := func() *schemas.MCPClientState {
		return &schemas.MCPClientState{
			ExecutionConfig: &schemas.MCPClientConfig{
				Name:           "weather",
				ToolsToExecute: []string{"*"},
			},
			ToolMap: map[string]schemas.ChatTool{
				"weather-forecast": {
					Type: schemas.ChatToolTypeFunction,
					Function: &schemas.ChatToolFunction{
						Name: "weather-forecast",
					},
				},
			},
		}
	}

	t.Run("allows available tool with matching config", func(t *testing.T) {
		ctx := schemas.NewDeepIntShieldContext(context.Background(), time.Time{})
		if !isToolPermittedForExecution(ctx, makeClient(), "weather-forecast", &MockLogger{}) {
			t.Fatal("expected tool to be permitted")
		}
	})

	t.Run("blocks missing tool", func(t *testing.T) {
		ctx := schemas.NewDeepIntShieldContext(context.Background(), time.Time{})
		if isToolPermittedForExecution(ctx, makeClient(), "weather-radar", &MockLogger{}) {
			t.Fatal("expected missing tool to be blocked")
		}
	})

	t.Run("blocks client filtered out by request", func(t *testing.T) {
		ctx := schemas.NewDeepIntShieldContext(context.Background(), time.Time{})
		ctx.SetValue(MCPContextKeyIncludeClients, []string{"search"})
		if isToolPermittedForExecution(ctx, makeClient(), "weather-forecast", &MockLogger{}) {
			t.Fatal("expected tool to be blocked by include-clients filter")
		}
	})

	t.Run("blocks tool filtered out by request", func(t *testing.T) {
		ctx := schemas.NewDeepIntShieldContext(context.Background(), time.Time{})
		ctx.SetValue(MCPContextKeyIncludeTools, []string{"weather-current"})
		if isToolPermittedForExecution(ctx, makeClient(), "weather-forecast", &MockLogger{}) {
			t.Fatal("expected tool to be blocked by include-tools filter")
		}
	})

	t.Run("blocks tool not in client allow list", func(t *testing.T) {
		ctx := schemas.NewDeepIntShieldContext(context.Background(), time.Time{})
		client := makeClient()
		client.ExecutionConfig.ToolsToExecute = []string{"current"}
		if isToolPermittedForExecution(ctx, client, "weather-forecast", &MockLogger{}) {
			t.Fatal("expected tool to be blocked by client config allow list")
		}
	})
}
