package logstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
)

// persistAuditLogForGuardrailDecision mirrors a guardrail verdict
// (allow / allow_with_redaction / human_approval / sandbox / deny / etc.)
// into the hash-chained audit log so every decision summary is covered
// by the tamper-evident chain. Lives next to the chain code (not in
// transports) so non-HTTP entry points (SDK, MCP gateway, async eval
// workers) inherit the same coverage without each call site re-implementing
// the mapping.
func persistAuditLogForGuardrailDecision(ctx context.Context, store *RDBLogStore, decision *GuardrailDecision) error {
	if store == nil || decision == nil {
		return nil
	}
	tenantID := strings.TrimSpace(decision.TenantID)
	if tenantID == "" {
		tenantID = tenantctx.TenantIDFromContext(ctx)
	}
	if tenantID == "" {
		return nil
	}

	verdict := strings.TrimSpace(strings.ToLower(decision.Decision))
	if verdict == "" {
		verdict = "unspecified"
	}

	eventType := "guardrail_decision"
	severity := guardrailDecisionSeverity(verdict)
	status := guardrailDecisionStatus(verdict)
	action := "guardrail_" + verdict

	details := map[string]any{
		"decision":          verdict,
		"stage":             decision.Stage,
		"approval_required": decision.ApprovalRequired,
		"latency_ms":        decision.LatencyMs,
	}
	if strings.TrimSpace(decision.PolicyID) != "" {
		details["policy_id"] = decision.PolicyID
	}
	if strings.TrimSpace(decision.PolicyVersionID) != "" {
		details["policy_version_id"] = decision.PolicyVersionID
	}
	if strings.TrimSpace(decision.EngineSource) != "" {
		details["engine_source"] = decision.EngineSource
	}
	if strings.TrimSpace(decision.Reason) != "" {
		details["reason"] = decision.Reason
	}
	if len(decision.Redactions) > 0 {
		details["redaction_count"] = len(decision.Redactions)
	}
	if len(decision.DecisionChain) > 0 {
		details["decision_chain"] = decision.DecisionChain
	}

	timestamp := decision.CreatedAt
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	entry := &AuditLogEntry{
		EventID:       guardrailDecisionAuditEventID(decision.TenantID, decision.ID),
		Timestamp:     timestamp.UTC(),
		EventType:     eventType,
		Action:        action,
		Status:        status,
		Severity:      severity,
		ResourceType:  "guardrail_decision",
		ResourceID:    decision.ID,
		RequestID:     decision.RequestID,
		RequestPath:   decision.Stage,
		RequestMethod: "POLICY",
		Details:       details,
	}

	storeCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
	return store.CreateAuditLog(storeCtx, entry)
}

// guardrailDecisionSeverity maps a verdict to the same severity scale
// the existing audit middleware uses, so admin filters and SOC 2 reports
// can treat policy decisions and request-path security events uniformly.
func guardrailDecisionSeverity(verdict string) string {
	switch verdict {
	case "deny", "block", "blocked":
		return "high"
	case "human_approval", "sandbox", "redact", "allow_with_redaction":
		return "medium"
	default:
		return "low"
	}
}

func guardrailDecisionStatus(verdict string) string {
	switch verdict {
	case "deny", "block", "blocked":
		return "blocked"
	case "human_approval":
		return "pending_review"
	case "sandbox":
		return "sandboxed"
	default:
		return "success"
	}
}

func guardrailDecisionAuditEventID(tenantID, decisionID string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"guardrail_decision", tenantID, decisionID}, "|")))
	return "evt_guardrail_decision_" + hex.EncodeToString(sum[:16])
}
