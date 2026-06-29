package agentic

import (
	"context"
	"strings"
	"sync"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
)

// VKScope is the identity-relevant slice of a platform Virtual Key. The
// runtime keeps a per-process map of these (keyed by VK id) so the PEP
// never has to read from the DB on the hot path. Updates happen at
// startup (pre-warm) and whenever a handler edits a VK row (call
// UpsertVKScope from the handler post-save).
//
// Authorization-relevant fields (AllowedTools, AutonomyBudget,
// DefaultObligations, ToolRateLimit) have moved to per-policy targeting
// (agentic_policies + agentic_policy_vk_targets / team_targets /
// member_targets). VKScope is now strictly identity: which IdP issues
// tokens, which Team / Customer this credential belongs to. The
// PolicyTargetResolver handles the entitlement side.
//
// SCALABILITY: lookups go through a sync.Map - lock-free reads on the
// hot path, single-writer mutex behind the scenes.
type VKScope struct {
	ID                 string
	Value              string // raw bearer "sk-bf-…"; used by the value→id index
	Tenant             string
	Workspace          string
	BoundProvider      string
	IdentityProviderID string
	// TeamID / CustomerID are the org-membership pointers used by the
	// PolicyTargetResolver to evaluate Team-scoped and Member-scoped
	// policies. They are NOT entitlement narrowing - that role moved to
	// the policy targets table.
	TeamID          string
	CustomerID      string
	AgentConfigured bool
	// AgentRiskLevel + AgentCapabilities are the agent attribute taxonomy
	// the PDP evaluates (filled into dc.Context at Decide time). Denormalized
	// here from the VK row so the hot path stays a single sync.Map read.
	AgentRiskLevel    string
	AgentCapabilities []string
	// AgentNamespace is the agent's logical / k8s namespace (the `namespace`
	// ABAC operand). Denormalized from the VK row for the hot path.
	AgentNamespace string
}

// VKResolver is a lock-free read map of VK scopes. Primary index is the
// VK id; a secondary index maps the raw bearer value to its id so the
// /decide handler can resolve "sk-bf-…" → scope without a DB roundtrip
// (the bearer is what the SDK ships; the id is what the resolver keys).
type VKResolver struct {
	scopes    sync.Map // key: vk_id (string)    → value: *VKScope
	valueToID sync.Map // key: vk_value (string) → value: vk_id (string)
}

// NewVKResolver constructs an empty resolver. Use UpsertVKScope to
// populate; queries via Lookup are safe before the first upsert (they
// just return ok=false).
func NewVKResolver() *VKResolver { return &VKResolver{} }

// Lookup returns the cached scope for a VK id. Hot-path; allocation-
// free; safe for concurrent readers.
func (r *VKResolver) Lookup(vkID string) (*VKScope, bool) {
	if r == nil || vkID == "" {
		return nil, false
	}
	v, ok := r.scopes.Load(vkID)
	if !ok {
		return nil, false
	}
	scope, ok := v.(*VKScope)
	return scope, ok
}

// LookupByValue resolves the raw bearer (sk-bf-…) directly to a scope
// via the secondary index. Two sync.Map reads (value → id → scope) -
// still allocation-free, still lock-free, ~100ns total.
func (r *VKResolver) LookupByValue(vkValue string) (*VKScope, bool) {
	if r == nil || vkValue == "" {
		return nil, false
	}
	idAny, ok := r.valueToID.Load(vkValue)
	if !ok {
		return nil, false
	}
	id, ok := idAny.(string)
	if !ok || id == "" {
		return nil, false
	}
	return r.Lookup(id)
}

// UpsertVKScope is called by the handler on every VK create/update so
// the runtime's view stays in sync without a DB roundtrip on the hot
// path. Idempotent and safe for concurrent callers.
func (r *VKResolver) UpsertVKScope(scope *VKScope) {
	if r == nil || scope == nil || scope.ID == "" {
		return
	}
	r.scopes.Store(scope.ID, scope)
	if scope.Value != "" {
		r.valueToID.Store(scope.Value, scope.ID)
	}
}

// DeleteVKScope removes a VK from the resolver. Called when a VK is
// deleted or has its agent binding removed.
func (r *VKResolver) DeleteVKScope(vkID string) {
	if r == nil || vkID == "" {
		return
	}
	if existing, ok := r.Lookup(vkID); ok && existing.Value != "" {
		r.valueToID.Delete(existing.Value)
	}
	r.scopes.Delete(vkID)
}

// LoadAll replaces the entire resolver content from a snapshot. Used by
// the pre-warmer at startup. Cheap: under 10ms for a thousand VKs.
func (r *VKResolver) LoadAll(scopes []*VKScope) {
	if r == nil {
		return
	}
	for _, s := range scopes {
		r.UpsertVKScope(s)
	}
}

// Size returns the count of cached scopes - for the health endpoint to
// surface "X agent VKs loaded".
func (r *VKResolver) Size() int {
	if r == nil {
		return 0
	}
	n := 0
	r.scopes.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// VKScopeFromRow translates a TableVirtualKey into the runtime's scope
// shape. Returns AgentConfigured=false when the VK is LLM-only (no
// BoundIdentityProvider) - the PEP simply skips agent checks for such
// VKs.
func VKScopeFromRow(row *tables.TableVirtualKey) *VKScope {
	if row == nil {
		return nil
	}
	workspace := ""
	if row.WorkspaceID != nil {
		workspace = strings.TrimSpace(*row.WorkspaceID)
	}
	teamID := ""
	if row.TeamID != nil {
		teamID = strings.TrimSpace(*row.TeamID)
	}
	customerID := ""
	if row.CustomerID != nil {
		customerID = strings.TrimSpace(*row.CustomerID)
	}
	// Defensive copy of the capability slice so the resolver never shares
	// backing storage with the GORM row (which may be reused/mutated).
	var capabilities []string
	if len(row.AgentCapabilities) > 0 {
		capabilities = append(capabilities, row.AgentCapabilities...)
	}
	return &VKScope{
		ID:                 row.ID,
		Value:              row.Value,
		Tenant:             row.TenantID,
		Workspace:          workspace,
		BoundProvider:      row.BoundIdentityProvider,
		IdentityProviderID: row.IdentityProviderID,
		TeamID:             teamID,
		CustomerID:         customerID,
		AgentConfigured:    row.BoundIdentityProvider != "",
		AgentRiskLevel:     strings.TrimSpace(row.AgentRiskLevel),
		AgentCapabilities:  capabilities,
		AgentNamespace:     strings.TrimSpace(row.AgentNamespace),
	}
}

// VKReader is the subset of configstore methods the pre-warmer needs.
// Subset-interface kept narrow so we don't import the whole ConfigStore
// type and create a cycle.
type VKReader interface {
	GetVirtualKeys(ctx context.Context) ([]tables.TableVirtualKey, error)
}

// PreWarmVKResolver populates the in-process map with every VK that has
// agent semantics. Called once at server startup before the listener
// accepts traffic so the first request lands warm.
func (r *VKResolver) PreWarm(ctx context.Context, reader VKReader) error {
	if r == nil || reader == nil {
		return nil
	}
	rows, err := reader.GetVirtualKeys(ctx)
	if err != nil {
		return err
	}
	scopes := make([]*VKScope, 0, len(rows))
	for i := range rows {
		if rows[i].BoundIdentityProvider == "" {
			continue
		}
		if s := VKScopeFromRow(&rows[i]); s != nil {
			scopes = append(scopes, s)
		}
	}
	r.LoadAll(scopes)
	return nil
}
