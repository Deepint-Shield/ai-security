package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/google/uuid"
)

const (
	guardrailCacheSnapshotKey schemas.DeepIntShieldContextKey = "deepintshield-guardrail-cache-snapshot"
)

type CacheReuseProvider interface {
	CurrentCacheFingerprint(ctx *schemas.DeepIntShieldContext) (string, error)
	CloneCachedEvidence(ctx *schemas.DeepIntShieldContext, snapshot *CacheSnapshot, sourceCacheEntryID string) error
}

type CacheStageSnapshot struct {
	Trace           logstore.GuardrailTrace     `json:"trace"`
	Decision        logstore.GuardrailDecision  `json:"decision"`
	Findings        []logstore.GuardrailFinding `json:"findings,omitempty"`
	SanitizedInput  string                      `json:"sanitized_input,omitempty"`
	SanitizedOutput string                      `json:"sanitized_output,omitempty"`
}

type CacheSnapshot struct {
	Input  *CacheStageSnapshot `json:"input,omitempty"`
	Output *CacheStageSnapshot `json:"output,omitempty"`
}

type cacheFingerprintInput struct {
	TenantRevision    string   `json:"tenant_revision"`
	VirtualKeyID      string   `json:"virtual_key_id,omitempty"`
	UserID            string   `json:"user_id,omitempty"`
	UserRole          string   `json:"user_role,omitempty"`
	TeamID            string   `json:"team_id,omitempty"`
	CustomerID        string   `json:"customer_id,omitempty"`
	RequestedPolicyID []string `json:"requested_policy_ids,omitempty"`
}

func CacheSnapshotFromContext(ctx context.Context) (*CacheSnapshot, bool) {
	if ctx == nil {
		return nil, false
	}
	snapshot, ok := ctx.Value(guardrailCacheSnapshotKey).(*CacheSnapshot)
	if !ok || snapshot == nil {
		return nil, false
	}
	return snapshot, true
}

func ApplyCachedInputSanitization(req *schemas.DeepIntShieldRequest, snapshot *CacheSnapshot) bool {
	if snapshot == nil || snapshot.Input == nil || strings.TrimSpace(snapshot.Input.SanitizedInput) == "" {
		return false
	}
	return rewriteRequestInput(req, snapshot.Input.SanitizedInput)
}

func (p *Plugin) CurrentCacheFingerprint(ctx *schemas.DeepIntShieldContext) (string, error) {
	if p == nil {
		return "", fmt.Errorf("guardrails plugin is not configured")
	}
	tenantID := guardrailTenantID(ctx)
	revision, err := p.currentTenantRevision(ctx, tenantID)
	if err != nil {
		return "", err
	}

	policyIDs := guardrailPolicyIDsFromContext(ctx)
	sort.Strings(policyIDs)
	raw, err := json.Marshal(cacheFingerprintInput{
		TenantRevision:    revision,
		VirtualKeyID:      strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)),
		UserID:            strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserID)),
		UserRole:          strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyUserRole)),
		TeamID:            strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceTeamID)),
		CustomerID:        strings.TrimSpace(deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyGovernanceCustomerID)),
		RequestedPolicyID: policyIDs,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (p *Plugin) CloneCachedEvidence(ctx *schemas.DeepIntShieldContext, snapshot *CacheSnapshot, sourceCacheEntryID string) error {
	if p == nil || p.evidenceStore == nil || snapshot == nil {
		return nil
	}
	requestID := guardrailRequestID(ctx)
	tenantID := guardrailTenantID(ctx)
	persistCtx := guardrailPersistenceContext(tenantID)

	for _, stageSnapshot := range []*CacheStageSnapshot{snapshot.Input, snapshot.Output} {
		if stageSnapshot == nil {
			continue
		}
		if err := p.cloneCachedStageEvidence(persistCtx, requestID, stageSnapshot, sourceCacheEntryID); err != nil {
			return err
		}
	}

	return nil
}

func (p *Plugin) currentTenantRevision(ctx context.Context, tenantID string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("guardrails plugin is not configured")
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = defaultTenantID
	}
	p.mu.RLock()
	state, ok := p.tenantCache[tenantID]
	p.mu.RUnlock()
	if ok && strings.TrimSpace(state.Revision) != "" && time.Now().UTC().Before(state.ExpiresAt) {
		return state.Revision, nil
	}

	// Route through hydrateTenantIfNeeded so the runtime's tenant bundle gets
	// populated in lock-step with the plugin's tenantCache. The previous
	// implementation built+stored the bundle into tenantCache directly,
	// bypassing runtimeClient.RefreshTenant. That left the runtime's
	// tenantBundles map empty - every subsequent inference request lost the
	// fast-path cache hit, the fallback skipped tenant policy hydration, and
	// the runtime evaluated requests against its builtin default policy
	// instead of the workspace's configured cards. Symptom: workspace
	// guardrails silently stopped firing after the first cache-fingerprint
	// lookup ran (typically the semantic_cache plugin's pre-eval). Now
	// hydrateTenantIfNeeded handles buildBundle + RefreshTenant + cache
	// population in one atomic step, so both maps stay in sync.
	if err := p.hydrateTenantIfNeeded(ctx, tenantID, false); err != nil {
		return "", err
	}

	p.mu.RLock()
	state, ok = p.tenantCache[tenantID]
	p.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("tenant %s not hydrated after refresh", tenantID)
	}
	return state.Revision, nil
}

func (p *Plugin) cloneCachedStageEvidence(ctx context.Context, requestID string, stageSnapshot *CacheStageSnapshot, sourceCacheEntryID string) error {
	trace := stageSnapshot.Trace
	traceID := uuid.NewString()
	trace.ID = traceID
	trace.RequestID = requestID
	trace.CreatedAt = time.Time{}
	trace.Metadata = cloneGuardrailMetadata(trace.Metadata)
	if trace.Metadata == nil {
		trace.Metadata = make(map[string]any, 4)
	}
	trace.Metadata["reused_from_cache"] = true
	trace.Metadata["cache_hit_type"] = "direct"
	trace.Metadata["source_cache_entry_id"] = sourceCacheEntryID
	trace.Metadata["guardrail_runtime_skipped"] = true
	if err := p.evidenceStore.CreateGuardrailTrace(ctx, &trace); err != nil {
		return err
	}

	decision := stageSnapshot.Decision
	decision.ID = uuid.NewString()
	decision.RequestID = requestID
	decision.TraceID = traceID
	decision.LatencyMs = 0
	decision.CreatedAt = time.Time{}
	if err := p.evidenceStore.CreateGuardrailDecision(ctx, &decision); err != nil {
		return err
	}

	for i := range stageSnapshot.Findings {
		finding := stageSnapshot.Findings[i]
		finding.ID = uuid.NewString()
		finding.RequestID = requestID
		finding.TraceID = traceID
		finding.CreatedAt = time.Time{}
		if err := p.evidenceStore.CreateGuardrailFinding(ctx, &finding); err != nil {
			return err
		}
	}

	return nil
}
