package providers

import (
	"context"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

type Finding struct {
	Category   string
	Severity   string
	Outcome    string
	Summary    string
	Confidence float64
	Details    map[string]any
}

type Request struct {
	TenantID       string
	Stage          string
	Model          string
	Provider       string
	Content        string
	Actor          runtimeapi.Actor
	MCP            *runtimeapi.MCPContext
	ProviderConfig runtimeapi.ProviderConfig
	Policy         runtimeapi.PolicyBundle
	Metadata       map[string]any
}

type Adapter interface {
	Name() string
	Evaluate(context.Context, Request) ([]Finding, error)
}
