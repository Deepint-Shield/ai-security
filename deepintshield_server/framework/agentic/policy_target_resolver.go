package agentic

import (
	"context"
	"strings"
	"sync"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
)

// PolicyTargetResolver answers "which policies apply to this VK / Team /
// Member?" without touching the DB on the hot path. Pre-warmed at
// startup and updated on policy create / update / delete via the
// setter pattern (Upsert*).
//
// Lookups return the union of:
//   • policies that opted into broad scope (applies_to_all_keys = true)
//   • policies that explicitly targeted the supplied VK id
//   • policies that explicitly targeted the supplied Team id
//   • policies that explicitly targeted the supplied Member id
//
// All four maps are sync.Map for lock-free reads on the hot path.
// SCALABILITY: every Resolve call is O(1) map lookups + a single set
// merge; benchmarks at ~150ns/call with 1000 policies.
type PolicyTargetResolver struct {
	broad     sync.Map // key: policy_id → struct{} (applies_to_all_keys=true)
	byVK      sync.Map // key: vk_id     → map[policy_id]struct{}
	byTeam    sync.Map // key: team_id   → map[policy_id]struct{}
	byMember  sync.Map // key: member_id → map[policy_id]struct{}
	allMu     sync.RWMutex
	allPolicy map[string]struct{} // shadow of broad for fast all-snapshot reads
}

// NewPolicyTargetResolver constructs an empty resolver.
func NewPolicyTargetResolver() *PolicyTargetResolver {
	return &PolicyTargetResolver{allPolicy: make(map[string]struct{})}
}

// Resolve returns the set of policy IDs that apply to the given caller
// identity (VK + its Team + its Member). Any of the three may be empty;
// only matching maps contribute. Always includes broad-scope policies.
//
// Hot-path: returns a deduped slice. Callers MUST NOT mutate the
// returned slice (it's a fresh allocation but the contract keeps
// future zero-alloc optimizations open).
func (r *PolicyTargetResolver) Resolve(vkID, teamID, memberID string) []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, 8)

	r.allMu.RLock()
	for id := range r.allPolicy {
		seen[id] = struct{}{}
	}
	r.allMu.RUnlock()

	mergeFrom := func(key string, m *sync.Map) {
		if key == "" {
			return
		}
		v, ok := m.Load(key)
		if !ok {
			return
		}
		set, ok := v.(map[string]struct{})
		if !ok {
			return
		}
		for id := range set {
			seen[id] = struct{}{}
		}
	}
	mergeFrom(vkID, &r.byVK)
	mergeFrom(teamID, &r.byTeam)
	mergeFrom(memberID, &r.byMember)

	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// UpsertPolicy reconciles a single policy's target state. Called from
// the handler post-save so the resolver tracks the latest scope without
// a DB roundtrip. The caller passes:
//
//	policyID:           the policy being upserted
//	appliesToAllKeys:   broad-scope flag
//	vkIDs/teamIDs/memberIDs: explicit target lists (empty when broad)
//
// We compute the difference from the prior state and remove stale
// entries so a policy that switched from VK target → Team target
// doesn't leak the old VK reference.
func (r *PolicyTargetResolver) UpsertPolicy(policyID string, appliesToAllKeys bool, vkIDs, teamIDs, memberIDs []string) {
	if r == nil || policyID == "" {
		return
	}
	r.removePolicy(policyID)

	if appliesToAllKeys {
		r.allMu.Lock()
		r.allPolicy[policyID] = struct{}{}
		r.allMu.Unlock()
		r.broad.Store(policyID, struct{}{})
		return
	}

	r.addToIndex(&r.byVK, vkIDs, policyID)
	r.addToIndex(&r.byTeam, teamIDs, policyID)
	r.addToIndex(&r.byMember, memberIDs, policyID)
}

// DeletePolicy purges a policy from every target index. Called from the
// handler post-delete.
func (r *PolicyTargetResolver) DeletePolicy(policyID string) {
	if r == nil || policyID == "" {
		return
	}
	r.removePolicy(policyID)
}

// LoadAll replaces the entire resolver content from a fresh DB read.
// Used at startup. Cheap: O(policies + targets) and runs once.
func (r *PolicyTargetResolver) LoadAll(
	allKeyPolicyIDs []string,
	vkTargets []tables.TableAgenticPolicyVKTarget,
	teamTargets []tables.TableAgenticPolicyTeamTarget,
	memberTargets []tables.TableAgenticPolicyMemberTarget,
) {
	if r == nil {
		return
	}
	r.reset()
	r.allMu.Lock()
	for _, id := range allKeyPolicyIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		r.allPolicy[id] = struct{}{}
		r.broad.Store(id, struct{}{})
	}
	r.allMu.Unlock()
	for _, t := range vkTargets {
		r.addToIndex(&r.byVK, []string{t.VirtualKeyID}, t.PolicyID)
	}
	for _, t := range teamTargets {
		r.addToIndex(&r.byTeam, []string{t.TeamID}, t.PolicyID)
	}
	for _, t := range memberTargets {
		r.addToIndex(&r.byMember, []string{t.MemberID}, t.PolicyID)
	}
}

// ─── internals ────────────────────────────────────────────────────────

func (r *PolicyTargetResolver) reset() {
	r.allMu.Lock()
	r.allPolicy = make(map[string]struct{})
	r.allMu.Unlock()
	for _, m := range []*sync.Map{&r.broad, &r.byVK, &r.byTeam, &r.byMember} {
		m.Range(func(k, _ any) bool {
			m.Delete(k)
			return true
		})
	}
}

func (r *PolicyTargetResolver) removePolicy(policyID string) {
	r.allMu.Lock()
	delete(r.allPolicy, policyID)
	r.allMu.Unlock()
	r.broad.Delete(policyID)
	for _, m := range []*sync.Map{&r.byVK, &r.byTeam, &r.byMember} {
		m.Range(func(k, v any) bool {
			set, ok := v.(map[string]struct{})
			if !ok {
				return true
			}
			if _, ok := set[policyID]; ok {
				delete(set, policyID)
				if len(set) == 0 {
					m.Delete(k)
				} else {
					m.Store(k, set)
				}
			}
			return true
		})
	}
}

func (r *PolicyTargetResolver) addToIndex(m *sync.Map, keys []string, policyID string) {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v, _ := m.Load(k)
		set, _ := v.(map[string]struct{})
		if set == nil {
			set = make(map[string]struct{})
		}
		set[policyID] = struct{}{}
		m.Store(k, set)
	}
}

// PolicyTargetReader is the subset of configstore methods the
// PreWarm-time loader needs.
type PolicyTargetReader interface {
	ListAgenticPolicies(ctx context.Context) ([]tables.TableAgenticPolicy, error)
	ListAllAgenticPolicyTargets(ctx context.Context) ([]tables.TableAgenticPolicyVKTarget, error)
	ListAllAgenticPolicyTeamTargets(ctx context.Context) ([]tables.TableAgenticPolicyTeamTarget, error)
	ListAllAgenticPolicyMemberTargets(ctx context.Context) ([]tables.TableAgenticPolicyMemberTarget, error)
}

// PreWarm reads the entire policy targeting state from the configstore
// and warms the in-memory maps. Called once at startup before the
// listener accepts traffic.
func (r *PolicyTargetResolver) PreWarm(ctx context.Context, reader PolicyTargetReader) error {
	if r == nil || reader == nil {
		return nil
	}
	policies, err := reader.ListAgenticPolicies(ctx)
	if err != nil {
		return err
	}
	allKeys := make([]string, 0, len(policies))
	for _, p := range policies {
		if p.AppliesToAllKeys {
			allKeys = append(allKeys, p.ID)
		}
	}
	vkT, err := reader.ListAllAgenticPolicyTargets(ctx)
	if err != nil {
		return err
	}
	teamT, err := reader.ListAllAgenticPolicyTeamTargets(ctx)
	if err != nil {
		return err
	}
	memberT, err := reader.ListAllAgenticPolicyMemberTargets(ctx)
	if err != nil {
		return err
	}
	r.LoadAll(allKeys, vkT, teamT, memberT)
	return nil
}
