package runtimeengine

import (
	"context"
	"fmt"

	"github.com/deepint-shield/ai-security-guard/internal/engine"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// Engine exposes the in-process guard runtime so the server can bypass RPC hops
// when low-latency synchronous enforcement is required.
type Engine struct {
	runtime *engine.Runtime
}

// Config mirrors engine.RuntimeConfig so the gateway can tune embedded-mode
// behavior (adapter timeouts, per-category budgets, fan-out parallelism)
// without importing internal/engine directly.
type Config struct {
	AdapterTimeoutMs       int
	RAGChunkParallelism    int
	PerCategoryTimeoutsMs  map[string]int
}

func New() *Engine {
	return &Engine{runtime: engine.New()}
}

// NewWith constructs an embedded engine with operator-supplied tuning.
// Falls back to engine defaults / env overrides for fields left zero/nil.
func NewWith(cfg Config) *Engine {
	return &Engine{runtime: engine.New(engine.RuntimeConfig{
		AdapterTimeoutMs:      cfg.AdapterTimeoutMs,
		RAGChunkParallelism:   cfg.RAGChunkParallelism,
		PerCategoryTimeoutsMs: cfg.PerCategoryTimeoutsMs,
	})}
}

func (e *Engine) RefreshTenant(_ context.Context, request *runtimeapi.RefreshTenantRequest) (*runtimeapi.RefreshTenantResponse, error) {
	if e == nil || e.runtime == nil || request == nil {
		return nil, fmt.Errorf("embedded runtime is not configured")
	}
	e.runtime.RefreshTenant(request.Bundle)
	return &runtimeapi.RefreshTenantResponse{
		OK:         true,
		TenantID:   request.Bundle.TenantID,
		Revision:   request.Bundle.Revision,
		HydratedAt: request.Bundle.RefreshedAt,
		Message:    "tenant refreshed in embedded runtime",
	}, nil
}

func (e *Engine) Evaluate(ctx context.Context, request *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	if e == nil || e.runtime == nil || request == nil {
		return nil, fmt.Errorf("embedded runtime is not configured")
	}
	response := e.runtime.Evaluate(ctx, *request)
	return &response, nil
}

// EvaluateFastOnly runs only the in-process portkey + local check evaluation
// paths, skipping provider-binding (sidecar) and MCP evaluation entirely.
// Used by the gateway's PreLLMHook as a sub-millisecond pre-flight check:
// if fast policies already produce a "deny" verdict, the model call can be
// skipped entirely instead of fired-then-discarded via speculative dispatch.
func (e *Engine) EvaluateFastOnly(ctx context.Context, request *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	if e == nil || e.runtime == nil || request == nil {
		return nil, fmt.Errorf("embedded runtime is not configured")
	}
	response := e.runtime.EvaluateFastOnly(ctx, *request)
	return &response, nil
}

func (e *Engine) Close() error {
	return nil
}
