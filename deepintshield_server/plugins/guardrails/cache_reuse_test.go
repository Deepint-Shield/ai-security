package guardrails

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	runtimeapi "github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

type mockGuardrailEvidenceStore struct {
	traces    []*logstore.GuardrailTrace
	decisions []*logstore.GuardrailDecision
	findings  []*logstore.GuardrailFinding
}

func (m *mockGuardrailEvidenceStore) CreateGuardrailFinding(ctx context.Context, finding *logstore.GuardrailFinding) error {
	copyFinding := *finding
	m.findings = append(m.findings, &copyFinding)
	return nil
}

func (m *mockGuardrailEvidenceStore) CreateGuardrailDecision(ctx context.Context, decision *logstore.GuardrailDecision) error {
	copyDecision := *decision
	m.decisions = append(m.decisions, &copyDecision)
	return nil
}

func (m *mockGuardrailEvidenceStore) CreateGuardrailTrace(ctx context.Context, trace *logstore.GuardrailTrace) error {
	copyTrace := *trace
	copyTrace.Metadata = cloneGuardrailMetadata(trace.Metadata)
	m.traces = append(m.traces, &copyTrace)
	return nil
}

func (m *mockGuardrailEvidenceStore) ListGuardrailFindings(ctx context.Context, filters logstore.GuardrailFindingFilters, limit, offset int) ([]logstore.GuardrailFinding, int64, error) {
	return nil, 0, nil
}
func (m *mockGuardrailEvidenceStore) ListGuardrailTraces(ctx context.Context, filters logstore.GuardrailTraceFilters, limit, offset int) ([]logstore.GuardrailTrace, int64, error) {
	return nil, 0, nil
}
func (m *mockGuardrailEvidenceStore) CreateGuardrailApprovalRequest(ctx context.Context, approval *logstore.GuardrailApprovalRequest) error {
	return nil
}
func (m *mockGuardrailEvidenceStore) ListGuardrailApprovalRequests(ctx context.Context, filters logstore.GuardrailApprovalFilters, limit, offset int) ([]logstore.GuardrailApprovalRequest, int64, error) {
	return nil, 0, nil
}
func (m *mockGuardrailEvidenceStore) GetGuardrailLatencyHistogram(ctx context.Context, filters logstore.GuardrailLatencyFilters, bucketSizeSeconds int64) (*logstore.LatencyHistogramResult, error) {
	return nil, nil
}
func (m *mockGuardrailEvidenceStore) GetGuardrailApprovalRequest(ctx context.Context, id string) (*logstore.GuardrailApprovalRequest, error) {
	return nil, nil
}
func (m *mockGuardrailEvidenceStore) UpdateGuardrailApprovalRequestDecision(ctx context.Context, id, status, approver, notes string, reviewedAt time.Time) error {
	return nil
}
func (m *mockGuardrailEvidenceStore) AggregateGuardrailMetrics(ctx context.Context, since, until *time.Time, bucketSeconds int64) (*logstore.GuardrailMetricsStats, error) {
	return nil, nil
}

func TestCurrentCacheFingerprint_UsesCachedTenantRevisionAndContext(t *testing.T) {
	plugin := &Plugin{
		tenantCache: map[string]tenantHydrationState{
			"default": {
				Revision:  "tenant-rev-1",
				ExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}

	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID, "vk-1")
	ctx.SetValue(schemas.DeepIntShieldContextKeyUserID, "user-1")
	ctx.SetValue(schemas.DeepIntShieldContextKeyUserRole, "analyst")
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceTeamID, "team-1")
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceCustomerID, "customer-1")
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs, []string{"policy-b", "policy-a"})

	first, err := plugin.CurrentCacheFingerprint(ctx)
	if err != nil {
		t.Fatalf("CurrentCacheFingerprint failed: %v", err)
	}

	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceTeamID, "team-2")
	second, err := plugin.CurrentCacheFingerprint(ctx)
	if err != nil {
		t.Fatalf("CurrentCacheFingerprint failed: %v", err)
	}

	if first == "" || second == "" {
		t.Fatal("expected non-empty fingerprints")
	}
	if first == second {
		t.Fatal("expected fingerprint to change when guardrail context changes")
	}
}

func TestCloneCachedEvidence_ZeroesLatencyAndAddsReuseMetadata(t *testing.T) {
	evidenceStore := &mockGuardrailEvidenceStore{}
	plugin := &Plugin{evidenceStore: evidenceStore}

	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyRequestID, "req-123")
	ctx.SetValue(schemas.DeepIntShieldContextKeyTenantID, "tenant-123")

	snapshot := &CacheSnapshot{
		Input: &CacheStageSnapshot{
			Trace: logstore.GuardrailTrace{
				ID:        "trace-old",
				RequestID: "old-request",
				Stage:     "input",
				Decision:  "allow",
				Metadata:  map[string]any{"actor_role": "analyst"},
			},
			Decision: logstore.GuardrailDecision{
				ID:        "decision-old",
				RequestID: "old-request",
				TraceID:   "trace-old",
				Stage:     "input",
				Decision:  "allow",
				LatencyMs: 41,
			},
			Findings: []logstore.GuardrailFinding{
				{
					ID:        "finding-old",
					RequestID: "old-request",
					TraceID:   "trace-old",
					Stage:     "input",
					PolicyID:  "policy-1",
				},
			},
		},
	}

	if err := plugin.CloneCachedEvidence(ctx, snapshot, "cache-entry-1"); err != nil {
		t.Fatalf("CloneCachedEvidence failed: %v", err)
	}

	if len(evidenceStore.traces) != 1 || len(evidenceStore.decisions) != 1 || len(evidenceStore.findings) != 1 {
		t.Fatalf("expected 1 cloned trace/decision/finding, got %d/%d/%d", len(evidenceStore.traces), len(evidenceStore.decisions), len(evidenceStore.findings))
	}
	if evidenceStore.decisions[0].LatencyMs != 0 {
		t.Fatalf("expected cloned decision latency to be 0, got %d", evidenceStore.decisions[0].LatencyMs)
	}
	if evidenceStore.traces[0].Metadata["reused_from_cache"] != true {
		t.Fatalf("expected reused_from_cache metadata, got %#v", evidenceStore.traces[0].Metadata)
	}
	if evidenceStore.traces[0].Metadata["source_cache_entry_id"] != "cache-entry-1" {
		t.Fatalf("expected source_cache_entry_id metadata, got %#v", evidenceStore.traces[0].Metadata)
	}
	if evidenceStore.traces[0].RequestID != "req-123" {
		t.Fatalf("expected cloned trace request id to be updated, got %s", evidenceStore.traces[0].RequestID)
	}
}

func TestTenantBundleRevision_IgnoresRefreshedAt(t *testing.T) {
	base := runtimeapi.TenantBundle{
		TenantID: "tenant-1",
		Providers: []runtimeapi.ProviderConfig{
			{ID: "provider-1", ProviderType: "mock", Enabled: true},
		},
		Policies: []runtimeapi.PolicyBundle{
			{PolicyID: "policy-1", PolicyVersionID: "version-1", Enabled: true},
		},
	}

	first := base
	first.RefreshedAt = time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	firstRevision, err := tenantBundleRevision(first)
	if err != nil {
		t.Fatalf("tenantBundleRevision(first) failed: %v", err)
	}

	second := base
	second.RefreshedAt = time.Date(2026, 4, 15, 12, 5, 0, 0, time.UTC)
	secondRevision, err := tenantBundleRevision(second)
	if err != nil {
		t.Fatalf("tenantBundleRevision(second) failed: %v", err)
	}

	if firstRevision == "" || secondRevision == "" {
		t.Fatal("expected non-empty tenant bundle revisions")
	}
	if firstRevision != secondRevision {
		t.Fatalf("expected identical revisions when only RefreshedAt differs, got %s vs %s", firstRevision, secondRevision)
	}
}
