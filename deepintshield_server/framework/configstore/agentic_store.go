// Package configstore: Agentic Security (basic PDP) CRUD.
//
// All methods follow the established workspace-isolation pattern (§4-layer
// isolation memory): tenant_id is the email-keyed partition; workspace_id
// is the strict isolation boundary. NULL workspace rows are grandfathered
// for migrations only - new rows always stamp both columns from the
// request context (tenantctx).
package configstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
)

// ----------------------------------------------------------------------------
// scoping helpers - tenant + (optionally) workspace
// ----------------------------------------------------------------------------

func agenticTenantScope(q *gorm.DB, ctx context.Context, strictWorkspace bool) *gorm.DB {
	tenant := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if tenant != "" {
		q = q.Where("tenant_id = ?", tenant)
	}
	if strictWorkspace {
		if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
			q = q.Where("workspace_id = ?", ws)
		}
	}
	return q
}

func stampAgenticOwnership(ctx context.Context, tenantID *string, workspaceID *string) {
	if tenantID != nil && strings.TrimSpace(*tenantID) == "" {
		if t := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); t != "" {
			*tenantID = t
		}
	}
	if workspaceID != nil && strings.TrimSpace(*workspaceID) == "" {
		if w := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); w != "" {
			*workspaceID = w
		}
	}
}

func ptrWorkspace(ctx context.Context, existing *string) *string {
	if existing != nil && strings.TrimSpace(*existing) != "" {
		return existing
	}
	if w := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); w != "" {
		copy := w
		return &copy
	}
	return existing
}

// ----------------------------------------------------------------------------
// Policies (RBAC/ABAC/ReBAC + autonomy budget)
// ----------------------------------------------------------------------------

func (s *RDBConfigStore) ListAgenticPolicies(ctx context.Context) ([]tables.TableAgenticPolicy, error) {
	var rows []tables.TableAgenticPolicy
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	// Strict active-org scoping (mirrors ListGuardrailPolicies). tenant_id is
	// the email-keyed partition shared across every UI org the same user owns,
	// so without this clause a tenant-wide policy (NULL workspace_id) created
	// in one org leaks into every other org's workspace via the IS NULL
	// allowlist below. Rows with NULL org_id are grandfathered pre-backfill
	// entries that we intentionally hide rather than leak across orgs.
	if activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); activeOrg != "" {
		q = q.Where("org_id = ?", activeOrg)
	}
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		// Tenant-wide policies (NULL workspace_id) apply to every workspace
		// *within the active org* - the org_id clause above bounds the spread.
		q = q.Where("workspace_id = ? OR workspace_id IS NULL", ws)
	}
	if err := q.Order("enabled DESC, created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	if err := s.hydratePolicyTargets(ctx, rows); err != nil {
		return nil, fmt.Errorf("hydrate vk targets: %w", err)
	}
	return rows, nil
}

func (s *RDBConfigStore) GetAgenticPolicy(ctx context.Context, id string) (*tables.TableAgenticPolicy, error) {
	var row tables.TableAgenticPolicy
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	// Same isolation as the List query: a leaked policy ID must not resolve a
	// row that belongs to a different org under the shared email tenant_id.
	if activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); activeOrg != "" {
		q = q.Where("org_id = ?", activeOrg)
	}
	if err := q.First(&row, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if err := s.hydratePolicyTargets(ctx, []tables.TableAgenticPolicy{row}); err != nil {
		return nil, fmt.Errorf("hydrate vk targets: %w", err)
	}
	// hydratePolicyTargets mutates by index - re-read from a slice copy.
	target, err := s.listPolicyTargets(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	row.TargetVirtualKeyIDs = target
	return &row, nil
}

func (s *RDBConfigStore) CreateAgenticPolicy(ctx context.Context, row *tables.TableAgenticPolicy) error {
	if row == nil {
		return nil
	}
	if strings.TrimSpace(row.ID) == "" {
		row.ID = uuid.NewString()
	}
	stampAgenticOwnership(ctx, &row.TenantID, nil)
	row.WorkspaceID = ptrWorkspace(ctx, row.WorkspaceID)
	// Stamp the UI-selected org so tenant-wide policies don't leak across the
	// user's other orgs under the shared email-keyed tenant_id (mirrors
	// CreateGuardrailPolicy).
	if row.OrgID == nil || strings.TrimSpace(*row.OrgID) == "" {
		if org := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); org != "" {
			row.OrgID = &org
		}
	}
	if row.PolicyVersion == 0 {
		row.PolicyVersion = 1
	}
	// Default to broad scope so existing flows (Catalog adoption,
	// New rule) get a sensible default without requiring the caller to
	// stamp the column.
	if !row.AppliesToAllKeys && len(row.TargetVirtualKeyIDs) == 0 && len(row.TargetTeamIDs) == 0 && len(row.TargetMemberIDs) == 0 {
		row.AppliesToAllKeys = true
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		return s.replacePolicyTargetsTx(tx, ctx, row, row.TargetVirtualKeyIDs, row.TargetTeamIDs, row.TargetMemberIDs)
	})
}

func (s *RDBConfigStore) UpdateAgenticPolicy(ctx context.Context, row *tables.TableAgenticPolicy) error {
	if row == nil {
		return nil
	}
	// Bumping policy_version is what invalidates cached decisions (§2.5).
	// Bump on every update that changes the rule body, status transition
	// 'staged'→'published', enabled flip, OR any of the three target
	// lists - the last one is critical because the cache key includes
	// policy_version and a target change without a bump would let stale
	// decisions fire against the new scope.
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing tables.TableAgenticPolicy
		if err := tx.First(&existing, "id = ?", row.ID).Error; err != nil {
			return err
		}
		// Preserve the original org so an update can't silently re-home a
		// policy into a different org; backfill from the active org only when
		// the row predates org stamping (grandfathered NULL).
		if existing.OrgID != nil && strings.TrimSpace(*existing.OrgID) != "" {
			row.OrgID = existing.OrgID
		} else if org := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); org != "" {
			row.OrgID = &org
		}
		oldVK, err := s.listPolicyTargets(ctx, row.ID)
		if err != nil {
			return err
		}
		oldTeam, err := s.listPolicyTeamTargets(ctx, row.ID)
		if err != nil {
			return err
		}
		oldMember, err := s.listPolicyMemberTargets(ctx, row.ID)
		if err != nil {
			return err
		}
		if targetsDiffer(
			existing.AppliesToAllKeys, oldVK, oldTeam, oldMember,
			row.AppliesToAllKeys, row.TargetVirtualKeyIDs, row.TargetTeamIDs, row.TargetMemberIDs,
		) {
			row.PolicyVersion = existing.PolicyVersion + 1
		}
		if err := tx.Save(row).Error; err != nil {
			return err
		}
		return s.replacePolicyTargetsTx(tx, ctx, row, row.TargetVirtualKeyIDs, row.TargetTeamIDs, row.TargetMemberIDs)
	})
}

// targetsDiffer returns true if any of the (applies_to_all_keys + 3
// target lists) changed in a way that would alter which callers the
// policy fires for. Set-equality on each list - order doesn't matter.
func targetsDiffer(oldAll bool, oldVK, oldTeam, oldMember []string, newAll bool, newVK, newTeam, newMember []string) bool {
	if oldAll != newAll {
		return true
	}
	if oldAll {
		// Both broad-scope; target lists are irrelevant for the
		// effective set of callers.
		return false
	}
	return setNotEqual(oldVK, newVK) || setNotEqual(oldTeam, newTeam) || setNotEqual(oldMember, newMember)
}

func setNotEqual(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	seen := make(map[string]struct{}, len(a))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			return true
		}
	}
	return false
}

func (s *RDBConfigStore) DeleteAgenticPolicy(ctx context.Context, id string) error {
	// ON DELETE CASCADE on the three target tables makes the parent
	// delete drop their rows. We explicitly delete the targets first so
	// the cascade is deterministic even on engines where AutoMigrate
	// did not emit the FK (SQLite without the foreign_keys pragma).
	cleanID := strings.TrimSpace(id)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, mdl := range []any{
			&tables.TableAgenticPolicyVKTarget{},
			&tables.TableAgenticPolicyTeamTarget{},
			&tables.TableAgenticPolicyMemberTarget{},
		} {
			if err := tx.Where("policy_id = ?", cleanID).Delete(mdl).Error; err != nil {
				return err
			}
		}
		q := agenticTenantScope(tx, ctx, false)
		return q.Delete(&tables.TableAgenticPolicy{}, "id = ?", cleanID).Error
	})
}

// hydratePolicyTargets fills TargetVirtualKeyIDs + TargetTeamIDs +
// TargetMemberIDs on every row that has applies_to_all_keys = false.
// Done in three batched queries keyed by the policy IDs we already
// have in memory, so callers pay O(1) per policy regardless of how
// many target rows the workspace carries.
func (s *RDBConfigStore) hydratePolicyTargets(ctx context.Context, rows []tables.TableAgenticPolicy) error {
	if len(rows) == 0 {
		return nil
	}
	scopedIDs := make([]string, 0, len(rows))
	for _, r := range rows {
		if !r.AppliesToAllKeys {
			scopedIDs = append(scopedIDs, r.ID)
		}
	}
	if len(scopedIDs) == 0 {
		return nil
	}

	var vkTargets []tables.TableAgenticPolicyVKTarget
	if err := s.db.WithContext(ctx).
		Where("policy_id IN ?", scopedIDs).
		Find(&vkTargets).Error; err != nil {
		return err
	}
	var teamTargets []tables.TableAgenticPolicyTeamTarget
	if err := s.db.WithContext(ctx).
		Where("policy_id IN ?", scopedIDs).
		Find(&teamTargets).Error; err != nil {
		return err
	}
	var memberTargets []tables.TableAgenticPolicyMemberTarget
	if err := s.db.WithContext(ctx).
		Where("policy_id IN ?", scopedIDs).
		Find(&memberTargets).Error; err != nil {
		return err
	}

	byPolicyVK := make(map[string][]string, len(scopedIDs))
	for _, t := range vkTargets {
		byPolicyVK[t.PolicyID] = append(byPolicyVK[t.PolicyID], t.VirtualKeyID)
	}
	byPolicyTeam := make(map[string][]string, len(scopedIDs))
	for _, t := range teamTargets {
		byPolicyTeam[t.PolicyID] = append(byPolicyTeam[t.PolicyID], t.TeamID)
	}
	byPolicyMember := make(map[string][]string, len(scopedIDs))
	for _, t := range memberTargets {
		byPolicyMember[t.PolicyID] = append(byPolicyMember[t.PolicyID], t.MemberID)
	}
	for i := range rows {
		if !rows[i].AppliesToAllKeys {
			rows[i].TargetVirtualKeyIDs = byPolicyVK[rows[i].ID]
			rows[i].TargetTeamIDs = byPolicyTeam[rows[i].ID]
			rows[i].TargetMemberIDs = byPolicyMember[rows[i].ID]
		}
	}
	return nil
}

func (s *RDBConfigStore) listPolicyTargets(ctx context.Context, policyID string) ([]string, error) {
	var rows []tables.TableAgenticPolicyVKTarget
	if err := s.db.WithContext(ctx).
		Where("policy_id = ?", strings.TrimSpace(policyID)).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.VirtualKeyID)
	}
	return out, nil
}

func (s *RDBConfigStore) listPolicyTeamTargets(ctx context.Context, policyID string) ([]string, error) {
	var rows []tables.TableAgenticPolicyTeamTarget
	if err := s.db.WithContext(ctx).
		Where("policy_id = ?", strings.TrimSpace(policyID)).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.TeamID)
	}
	return out, nil
}

func (s *RDBConfigStore) listPolicyMemberTargets(ctx context.Context, policyID string) ([]string, error) {
	var rows []tables.TableAgenticPolicyMemberTarget
	if err := s.db.WithContext(ctx).
		Where("policy_id = ?", strings.TrimSpace(policyID)).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.MemberID)
	}
	return out, nil
}

// replacePolicyTargetsTx is the full-replace write path for a policy's
// VK / Team / Member targets. Delete-then-insert across all three join
// tables inside the caller-provided transaction so create + update
// share the exact same semantics: the targets list is whatever the
// caller passed in, no merge, no diff.
//
// Tenant safety: every inserted target row carries the parent policy's
// tenant_id + workspace_id so the join table can be scoped by workspace
// without joining back to the parent. Validation that each
// vk_id/team_id/member_id belongs to the same workspace lives in the
// HTTP handler so a 400 surfaces with a useful message.
func (s *RDBConfigStore) replacePolicyTargetsTx(tx *gorm.DB, _ context.Context, policy *tables.TableAgenticPolicy, vkIDs, teamIDs, memberIDs []string) error {
	for _, mdl := range []any{
		&tables.TableAgenticPolicyVKTarget{},
		&tables.TableAgenticPolicyTeamTarget{},
		&tables.TableAgenticPolicyMemberTarget{},
	} {
		if err := tx.Where("policy_id = ?", policy.ID).Delete(mdl).Error; err != nil {
			return err
		}
	}
	if policy.AppliesToAllKeys {
		return nil
	}
	workspaceID := ""
	if policy.WorkspaceID != nil {
		workspaceID = *policy.WorkspaceID
	}
	now := time.Now().UTC()

	// VK targets
	if vkRows := dedupeStrings(vkIDs); len(vkRows) > 0 {
		rows := make([]tables.TableAgenticPolicyVKTarget, 0, len(vkRows))
		for _, vk := range vkRows {
			rows = append(rows, tables.TableAgenticPolicyVKTarget{
				PolicyID:     policy.ID,
				VirtualKeyID: vk,
				TenantID:     policy.TenantID,
				WorkspaceID:  workspaceID,
				CreatedAt:    now,
			})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return err
		}
	}
	// Team targets
	if tRows := dedupeStrings(teamIDs); len(tRows) > 0 {
		rows := make([]tables.TableAgenticPolicyTeamTarget, 0, len(tRows))
		for _, t := range tRows {
			rows = append(rows, tables.TableAgenticPolicyTeamTarget{
				PolicyID:    policy.ID,
				TeamID:      t,
				TenantID:    policy.TenantID,
				WorkspaceID: workspaceID,
				CreatedAt:   now,
			})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return err
		}
	}
	// Member targets
	if mRows := dedupeStrings(memberIDs); len(mRows) > 0 {
		rows := make([]tables.TableAgenticPolicyMemberTarget, 0, len(mRows))
		for _, m := range mRows {
			rows = append(rows, tables.TableAgenticPolicyMemberTarget{
				PolicyID:    policy.ID,
				MemberID:    m,
				TenantID:    policy.TenantID,
				WorkspaceID: workspaceID,
				CreatedAt:   now,
			})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return err
		}
	}
	return nil
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ListAgenticPolicyTargetsForVK returns the set of policy IDs that
// explicitly target the given VK. Used by the PEP's target resolver to
// avoid scanning the join table on every decide call.
func (s *RDBConfigStore) ListAgenticPolicyTargetsForVK(ctx context.Context, vkID string) ([]string, error) {
	var rows []tables.TableAgenticPolicyVKTarget
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	if err := q.Where("virtual_key_id = ?", strings.TrimSpace(vkID)).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.PolicyID)
	}
	return out, nil
}

// ListAllAgenticPolicyTargets dumps the entire VK join table (scoped to
// the caller's tenant). Used at startup to warm the PEP's in-memory
// resolver. Returns rows sorted by workspace+policy for stable warm.
func (s *RDBConfigStore) ListAllAgenticPolicyTargets(ctx context.Context) ([]tables.TableAgenticPolicyVKTarget, error) {
	var rows []tables.TableAgenticPolicyVKTarget
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	if err := q.Order("workspace_id ASC, policy_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ListAllAgenticPolicyTeamTargets - team-target equivalent of the
// VK lister above. Used at startup to warm the resolver.
func (s *RDBConfigStore) ListAllAgenticPolicyTeamTargets(ctx context.Context) ([]tables.TableAgenticPolicyTeamTarget, error) {
	var rows []tables.TableAgenticPolicyTeamTarget
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	if err := q.Order("workspace_id ASC, policy_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ListAllAgenticPolicyMemberTargets - member-target equivalent.
func (s *RDBConfigStore) ListAllAgenticPolicyMemberTargets(ctx context.Context) ([]tables.TableAgenticPolicyMemberTarget, error) {
	var rows []tables.TableAgenticPolicyMemberTarget
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	if err := q.Order("workspace_id ASC, policy_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ----------------------------------------------------------------------------
// Tool tiering
// ----------------------------------------------------------------------------

func (s *RDBConfigStore) ListAgenticToolTiering(ctx context.Context) ([]tables.TableAgenticToolTiering, error) {
	var rows []tables.TableAgenticToolTiering
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ? OR workspace_id IS NULL", ws)
	}
	if err := q.Order("CASE sensitivity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, tool_name ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *RDBConfigStore) UpsertAgenticToolTiering(ctx context.Context, row *tables.TableAgenticToolTiering) error {
	if row == nil {
		return nil
	}
	if strings.TrimSpace(row.ID) == "" {
		row.ID = uuid.NewString()
	}
	stampAgenticOwnership(ctx, &row.TenantID, nil)
	row.WorkspaceID = ptrWorkspace(ctx, row.WorkspaceID)
	return s.db.WithContext(ctx).Save(row).Error
}

func (s *RDBConfigStore) DeleteAgenticToolTiering(ctx context.Context, id string) error {
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	return q.Delete(&tables.TableAgenticToolTiering{}, "id = ?", strings.TrimSpace(id)).Error
}

// NOTE: The advanced agentic control-plane store methods (tool summaries, tool
// grants / JIT, ReBAC relationship audit, identity providers + identities, and
// agent blueprints / AIBOM) have been removed from the OSS build. They had no
// registered HTTP routes. Their backing table structs remain as inert schema in
// the tables package (referenced by the migration chain) but are no longer
// written or read by any code path.

// ----------------------------------------------------------------------------
// Decisions (append-only, hash-chained)
// ----------------------------------------------------------------------------

// AppendAgenticDecision is the only write path into the audit chain. The
// caller fills decision fields except prev_hash/hash; this method reads the
// most recent decision for the tenant, computes hash(record || prev_hash)
// and persists atomically. A serializable transaction would be ideal; for
// throughput we rely on the unique index on (hash) + the sequence column
// to detect chain forks during evidence verification.
func (s *RDBConfigStore) AppendAgenticDecision(ctx context.Context, row *tables.TableAgenticDecision) error {
	if row == nil {
		return nil
	}
	if strings.TrimSpace(row.DecisionID) == "" {
		row.DecisionID = "d-" + uuid.NewString()
	}
	stampAgenticOwnership(ctx, &row.TenantID, nil)
	if strings.TrimSpace(row.WorkspaceID) == "" {
		row.WorkspaceID = strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	}
	if row.Timestamp.IsZero() {
		row.Timestamp = time.Now()
	}
	// Truncate to microseconds so the stored value round-trips identically
	// through the database (Postgres timestamptz is microsecond-precision).
	// This is what makes a row's canonical pre-image - and therefore its
	// chain hash - recomputable, and so verifiable, after read-back.
	row.Timestamp = row.Timestamp.UTC().Truncate(time.Microsecond)
	// Read the most recent prev_hash for the chain (per-tenant chain).
	var prev tables.TableAgenticDecision
	err := s.db.WithContext(ctx).
		Where("tenant_id = ?", row.TenantID).
		Order("sequence DESC").
		Limit(1).
		Take(&prev).Error
	prevHash := strings.Repeat("0", 64)
	if err == nil {
		prevHash = prev.Hash
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	row.PrevHash = prevHash

	// Tamper-evidence hash over the canonical pre-image. Keyed (HMAC-SHA256)
	// when DEEPINTSHIELD_AUDIT_HMAC_KEY is set - forgery-resistant even to a
	// DB writer without the key - and bare SHA-256 otherwise (default,
	// behaviour-identical to inception). Computed here in the async drain
	// worker, never on the decision hot path.
	row.Hash = chainHash(auditPayload(row))
	return s.db.WithContext(ctx).Create(row).Error
}

// auditPayload is the canonical, deterministic pre-image hashed into the audit
// chain. The timestamp is already microsecond-truncated by the writer so this
// string is byte-identical whether built at write time or recomputed from a
// row read back from the database - the property the verifier relies on.
func auditPayload(row *tables.TableAgenticDecision) string {
	return strings.Join([]string{
		row.DecisionID,
		row.Timestamp.UTC().Format(time.RFC3339Nano),
		row.Tool,
		row.Verdict,
		row.ArgsDigest,
		row.PrevHash,
	}, "|")
}

// auditHMACKey returns the configured audit-chain HMAC key, or "" if integrity
// keying is disabled (the default). Read per-write - cheap, off the hot path -
// so operators can enable it without a restart. It MUST stay stable for a
// tenant's chain to remain verifiable.
func auditHMACKey() string {
	return strings.TrimSpace(os.Getenv("DEEPINTSHIELD_AUDIT_HMAC_KEY"))
}

// chainHash computes the tamper-evidence hash for an audit row. When an HMAC
// key is configured it returns a keyed "hmac-sha256:<hex>" digest; otherwise a
// bare sha256 hex (the original, default scheme). The algorithm is encoded in
// the value's prefix so VerifyAgenticChain can recompute every row under the
// algorithm that produced it - making enabling the key seamless and
// migration-free (no schema change, no rewrite of existing rows).
func chainHash(payload string) string {
	if key := auditHMACKey(); key != "" {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(payload))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	}
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// recomputeChainHash recomputes a row's hash under the algorithm recorded in
// its stored hash prefix. Verifier-only - never the hot path.
func recomputeChainHash(storedHash, payload string) string {
	if strings.HasPrefix(storedHash, "hmac-sha256:") {
		mac := hmac.New(sha256.New, []byte(auditHMACKey()))
		mac.Write([]byte(payload))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	}
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// ChainVerifyResult is the outcome of VerifyAgenticChain.
type ChainVerifyResult struct {
	OK       bool   `json:"ok"`
	Verified int    `json:"verified"`            // rows checked before stopping
	BrokenAt string `json:"broken_at,omitempty"` // decision_id of the first bad row
	Sequence uint64 `json:"sequence,omitempty"`  // its sequence number
	Reason   string `json:"reason,omitempty"`
}

// VerifyAgenticChain walks a tenant's append-only decision chain in sequence
// order and confirms (a) each row's prev_hash links to the prior row's hash
// and (b) each row's hash recomputes from its canonical pre-image under the
// algorithm recorded in its hash prefix. Read-only; intended for the evidence
// export and a scheduled integrity check - never called on the decision hot
// path.
//
// Rows written before audit-chain integrity shipped used nanosecond-precision
// timestamps and are not byte-recomputable; for a chain that predates the
// upgrade the verifier reports the first mismatch, which marks the boundary
// from which the chain is cryptographically verifiable.
func (s *RDBConfigStore) VerifyAgenticChain(ctx context.Context, tenantID string) (ChainVerifyResult, error) {
	var rows []tables.TableAgenticDecision
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("sequence ASC").
		Find(&rows).Error; err != nil {
		return ChainVerifyResult{}, err
	}
	expectedPrev := strings.Repeat("0", 64)
	for i := range rows {
		row := &rows[i]
		if row.PrevHash != expectedPrev {
			return ChainVerifyResult{
				OK: false, Verified: i, BrokenAt: row.DecisionID, Sequence: row.Sequence,
				Reason: "prev_hash does not link to the previous row's hash",
			}, nil
		}
		if recomputeChainHash(row.Hash, auditPayload(row)) != row.Hash {
			return ChainVerifyResult{
				OK: false, Verified: i, BrokenAt: row.DecisionID, Sequence: row.Sequence,
				Reason: "row hash does not match its recomputed canonical hash",
			}, nil
		}
		expectedPrev = row.Hash
	}
	return ChainVerifyResult{OK: true, Verified: len(rows)}, nil
}

func (s *RDBConfigStore) ListAgenticDecisions(ctx context.Context, limit int, verdict, tool string, since, until *time.Time) ([]tables.TableAgenticDecision, error) {
	var rows []tables.TableAgenticDecision
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, false)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if v := strings.TrimSpace(verdict); v != "" {
		q = q.Where("verdict = ?", strings.ToUpper(v))
	}
	if t := strings.TrimSpace(tool); t != "" {
		q = q.Where("tool = ?", t)
	}
	if since != nil {
		q = q.Where("ts >= ?", *since)
	}
	if until != nil {
		q = q.Where("ts <= ?", *until)
	}
	if err := q.Order("ts DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// CountAgenticDecisionsByVerdict returns counts per verdict for the
// caller's tenant/workspace, optionally filtered by time. Used by the
// Overview KPIs and analytics screens.
func (s *RDBConfigStore) CountAgenticDecisionsByVerdict(ctx context.Context, since, until *time.Time) (map[string]int64, error) {
	type row struct {
		Verdict string
		Cnt     int64
	}
	q := agenticTenantScope(s.db.WithContext(ctx).Model(&tables.TableAgenticDecision{}), ctx, false)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if since != nil {
		q = q.Where("ts >= ?", *since)
	}
	if until != nil {
		q = q.Where("ts <= ?", *until)
	}
	var out []row
	if err := q.Select("verdict, COUNT(*) AS cnt").Group("verdict").Scan(&out).Error; err != nil {
		return nil, err
	}
	m := make(map[string]int64, len(out))
	for _, r := range out {
		m[r.Verdict] = r.Cnt
	}
	return m, nil
}

// ----------------------------------------------------------------------------
// Enforcement state
// ----------------------------------------------------------------------------

func (s *RDBConfigStore) GetAgenticEnforcementState(ctx context.Context) (*tables.TableAgenticEnforcementState, error) {
	var row tables.TableAgenticEnforcementState
	q := agenticTenantScope(s.db.WithContext(ctx), ctx, true)
	err := q.First(&row).Error
	if err == nil {
		return &row, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	// Auto-provision a shadow-mode row so the UI is never empty.
	row = tables.TableAgenticEnforcementState{
		ID:                "es-" + uuid.NewString(),
		TenantID:          strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)),
		WorkspaceID:       strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)),
		Mode:              tables.AgenticEnforcementShadow,
		TiersEnforced:     []string{tables.AgenticToolSensitivityLow},
		RevocationSLASec:  30,
		L1CacheMaxEntries: 200000,
		DefaultFailClosed: true,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// ListAgenticEnforcementStates returns every persisted row. Tenant scoping
// is intentionally skipped because the only caller is the boot-time
// runtime warmup, which iterates all rows so every (tenant, workspace)
// pair gets its mode loaded into the runtime.
func (s *RDBConfigStore) ListAgenticEnforcementStates(ctx context.Context) ([]tables.TableAgenticEnforcementState, error) {
	var rows []tables.TableAgenticEnforcementState
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *RDBConfigStore) UpdateAgenticEnforcementState(ctx context.Context, row *tables.TableAgenticEnforcementState) error {
	if row == nil {
		return nil
	}
	stampAgenticOwnership(ctx, &row.TenantID, nil)
	if strings.TrimSpace(row.WorkspaceID) == "" {
		row.WorkspaceID = strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	}
	// There is exactly one enforcement row per (tenant, workspace), enforced by
	// idx_agentic_enforcement_tenant_workspace. The settings page PUTs a body
	// without the row id, so reuse the existing row's identity and update it in
	// place; inserting a fresh id here would collide with the unique index and
	// 500 on every save after the first. Fall back to an insert only when no row
	// exists for this scope yet.
	var existing tables.TableAgenticEnforcementState
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND workspace_id = ?", row.TenantID, row.WorkspaceID).
		First(&existing).Error
	switch {
	case err == nil:
		row.ID = existing.ID
		row.CreatedAt = existing.CreatedAt
		return s.db.WithContext(ctx).Save(row).Error
	case errors.Is(err, gorm.ErrRecordNotFound):
		if strings.TrimSpace(row.ID) == "" {
			row.ID = "es-" + uuid.NewString()
		}
		return s.db.WithContext(ctx).Create(row).Error
	default:
		return err
	}
}

// ComputeArgsDigest is a helper so callers (handlers, runtime) never
// store raw arguments by accident. Always reduce structured args to a
// canonical JSON string first.
func ComputeArgsDigest(canonical string) string {
	h := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(h[:])
}

// _ keep import alive for callers that may need fmt.
var _ = fmt.Sprintf
