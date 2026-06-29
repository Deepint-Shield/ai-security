package agentic

import (
	"context"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
)

// ConfigStoreWriter is the minimal contract the agentic runtime needs
// from the configstore. We do NOT import configstore directly here to
// avoid an import cycle (configstore imports tables; agentic imports
// tables); we work against this small interface instead and let the
// caller pass an adapter.
type ConfigStoreWriter interface {
	AppendAgenticDecision(ctx context.Context, row *tables.TableAgenticDecision) error
}

// StoreAuditWriter is a thin adapter from the runtime's AuditRecord to
// the configstore's TableAgenticDecision. It is the AuditWriter that
// AsyncAudit uses. Only the basic decision fields are mapped; the
// premium integrity / OWASP columns on the table are left at their zero
// values (the OSS PDP never populates them).
type StoreAuditWriter struct {
	Store ConfigStoreWriter
}

// WriteDecision converts and persists the audit record.
func (s StoreAuditWriter) WriteDecision(ctx context.Context, rec AuditRecord) error {
	if s.Store == nil {
		return nil
	}
	row := &tables.TableAgenticDecision{
		DecisionID:    rec.DecisionID,
		TenantID:      rec.Tenant,
		WorkspaceID:   rec.Workspace,
		VirtualKeyID:  rec.VirtualKey,
		Principal:     rec.Principal,
		ActorChain:    rec.ActorChain,
		IdentityType:  rec.IdentityType,
		ProviderID:    rec.ProviderID,
		Tool:          rec.Tool,
		ArgsDigest:    rec.ArgsDigest,
		Verdict:       string(rec.Verdict),
		Reason:        rec.Reason,
		Obligations:   rec.Obligations,
		PolicyID:      rec.PolicyID,
		PolicyVersion: rec.PolicyVersion,
		RecoveryCost:  rec.RecoveryCost,
		RAGProvenance: rec.RAGProvenance,
		CostUsed:      rec.CostUsed,
		LatencyUS:     rec.LatencyUS,
		CacheHit:      rec.CacheHit,
		Mode:          string(rec.Mode),
		CrossTenant:   rec.CrossTenant,
		Timestamp:     orNow(rec.Timestamp),
	}
	return s.Store.AppendAgenticDecision(ctx, row)
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}
