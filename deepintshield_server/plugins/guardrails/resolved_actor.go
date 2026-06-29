package guardrails

import (
	"context"
	"strings"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// resolvedActorKey holds a memoised view of every actor / governance field
// the guardrails hot path reads. The original code re-read each value via
// ctx.Value(k) on every plugin invocation - N mutex-protected map walks
// per request. Cache the typed struct on the context once per request, then
// every guardrails callsite reads via a single pointer.
const resolvedActorKey schemas.DeepIntShieldContextKey = "deepintshield-guardrail-resolved-actor"

// resolvedActor mirrors every field the guardrails plugin needs from the
// request context. Construct via resolveActorFromContext; reuse via
// fetchResolvedActor on subsequent calls within the same request.
type resolvedActor struct {
	TenantID       string
	VirtualKeyID   string
	VirtualKeyName string
	CustomerID     string
	TeamID         string
	UserID         string
	UserRole       string
	URLPath        string
	HasGuards      bool
}

// resolveActorFromContext walks the context once, snapshots every field
// into a resolvedActor, and stashes the pointer back on the context for
// subsequent plugin reads.
func resolveActorFromContext(ctx *schemas.DeepIntShieldContext) *resolvedActor {
	if ctx == nil {
		return &resolvedActor{}
	}
	if existing, ok := ctx.Value(resolvedActorKey).(*resolvedActor); ok && existing != nil {
		return existing
	}
	r := &resolvedActor{
		TenantID:       strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyTenantID)),
		VirtualKeyID:   strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)),
		VirtualKeyName: strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyName)),
		CustomerID:     strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceCustomerID)),
		TeamID:         strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceTeamID)),
		UserID:         strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserID)),
		UserRole:       strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserRole)),
		URLPath:        strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyURLPath)),
		HasGuards:      deepintshield.GetBoolFromContext(ctx, schemas.DeepIntShieldContextKey("__bf_vk_has_guards")),
	}
	ctx.SetValue(resolvedActorKey, r)
	return r
}

// fetchResolvedActor reads the cached actor without resolving (used in
// detached contexts after the request returns). Returns an empty actor if
// the context never had one stashed (e.g. background workers).
func fetchResolvedActor(ctx context.Context) *resolvedActor {
	if ctx == nil {
		return &resolvedActor{}
	}
	if existing, ok := ctx.Value(resolvedActorKey).(*resolvedActor); ok && existing != nil {
		return existing
	}
	return &resolvedActor{}
}
