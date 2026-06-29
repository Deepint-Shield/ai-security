package mcp

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/cli/internal/apis"
	"github.com/deepint-shield/ai-security/cli/internal/harness"
)

// AttachBestEffort attempts to register the DeepIntShield MCP server with the harness.
// For Claude Code it auto-attaches via the CLI; for other harnesses it prints manual instructions.
func AttachBestEffort(ctx context.Context, stdout, stderr io.Writer, h harness.Harness, baseURL, vk string) {
	mcpURL, err := apis.BuildEndpoint(baseURL, "/mcp")
	if err != nil {
		fmt.Fprintf(stderr, "warning: invalid MCP URL: %v\n", err)
		return
	}

	if !h.SupportsMCP {
		fmt.Fprintf(stdout, "MCP: %s has no native auto-attach yet. Use server URL: %s\n", h.Label, mcpURL)
		return
	}

	if h.ID != "claude" {
		fmt.Fprintf(stdout, "MCP: manual setup for %s with URL %s\n", h.Label, mcpURL)
		if strings.TrimSpace(vk) != "" {
			fmt.Fprintf(stdout, "MCP: include header \"Authorization: Bearer <your-virtual-key>\" when connecting\n")
		}
		return
	}

	if strings.TrimSpace(vk) == "" {
		tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(tCtx, "claude", "mcp", "add", "--transport", "http", "deepintshield", mcpURL)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(stderr, "warning: auto MCP add failed. Run: claude mcp add --transport http deepintshield %s\n", mcpURL)
			return
		}
		fmt.Fprintln(stdout, "MCP: attached Claude MCP server 'deepintshield'.")
		return
	}

	payloadBytes, err := sonic.Marshal(map[string]any{
		"type": "http",
		"url":  mcpURL,
		"headers": map[string]string{
			"Authorization": "Bearer " + strings.TrimSpace(vk),
		},
	})
	if err != nil {
		fmt.Fprintln(stderr, "warning: build MCP payload:", err)
		return
	}

	payload := string(payloadBytes)
	tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tCtx, "claude", "mcp", "add-json", "deepintshield", payload)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(stderr, "warning: auto MCP add failed. Run: claude mcp add-json deepintshield '<payload>' (with your Authorization header)\n")
		return
	}
	fmt.Fprintln(stdout, "MCP: attached Claude MCP server 'deepintshield' with virtual key.")
}
