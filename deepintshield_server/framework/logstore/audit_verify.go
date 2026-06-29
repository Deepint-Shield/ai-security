package logstore

import (
	"context"
	"strings"
	"time"
)

// AuditChainBreak describes a single integrity failure encountered while
// walking the audit log hash chain. Surfaced verbatim to admin UIs and
// SOC 2 auditors, so field names favour clarity over brevity.
type AuditChainBreak struct {
	Kind         string    `json:"kind"`
	Sequence     int64     `json:"sequence"`
	EventID      string    `json:"event_id,omitempty"`
	Timestamp    time.Time `json:"timestamp,omitempty"`
	ExpectedHash string    `json:"expected_hash,omitempty"`
	ActualHash   string    `json:"actual_hash,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

const (
	AuditChainBreakHashMismatch      = "hash_mismatch"
	AuditChainBreakPreviousMismatch  = "previous_hash_mismatch"
	AuditChainBreakSequenceGap       = "sequence_gap"
	AuditChainBreakSequenceDuplicate = "sequence_duplicate"
	AuditChainBreakUnexpectedStart   = "unexpected_chain_start"
)

// AuditChainVerificationReport is the result of walking the audit log hash
// chain end-to-end for a tenant. Intended to be embedded in the admin UI
// and exported as evidence for compliance reviews.
type AuditChainVerificationReport struct {
	TenantID       string            `json:"tenant_id"`
	WorkspaceID    string            `json:"workspace_id,omitempty"`
	TotalEntries   int64             `json:"total_entries"`
	VerifiedCount  int64             `json:"verified_count"`
	BrokenCount    int64             `json:"broken_count"`
	FirstSequence  int64             `json:"first_sequence,omitempty"`
	LastSequence   int64             `json:"last_sequence,omitempty"`
	FirstTimestamp *time.Time        `json:"first_timestamp,omitempty"`
	LastTimestamp  *time.Time        `json:"last_timestamp,omitempty"`
	HeadHash       string            `json:"head_hash,omitempty"`
	Chain          string            `json:"chain_status"`
	VerifiedAt     time.Time         `json:"verified_at"`
	Breaks         []AuditChainBreak `json:"breaks,omitempty"`
}

// AuditChainVerifyOptions controls the verification window. A zero-value
// options struct walks the entire tenant chain.
type AuditChainVerifyOptions struct {
	WorkspaceID string
	MaxBreaks   int
}

const (
	AuditChainStatusIntact = "intact"
	AuditChainStatusEmpty  = "empty"
	AuditChainStatusBroken = "broken"
)

const defaultAuditChainMaxBreaks = 100

// VerifyAuditChain walks every audit log row for the active tenant in
// sequence order and confirms (a) each row's stored hash matches its
// recomputed hash, (b) each row's PreviousHash matches the prior row's
// Hash, and (c) sequences are contiguous starting at 1. Returns a report
// the admin UI can render and an auditor can archive.
//
// The tenant is read from the gorm callback context (RDB log store
// installs `scopeTenantStatement`), so callers must supply a context that
// carries the tenant ID via tenantctx - the same convention as every
// other store method.
func (s *RDBLogStore) VerifyAuditChain(ctx context.Context, opts AuditChainVerifyOptions) (*AuditChainVerificationReport, error) {
	report := &AuditChainVerificationReport{
		VerifiedAt: time.Now().UTC(),
		Chain:      AuditChainStatusEmpty,
	}

	maxBreaks := opts.MaxBreaks
	if maxBreaks <= 0 {
		maxBreaks = defaultAuditChainMaxBreaks
	}

	query := s.db.WithContext(ctx).Model(&AuditLogEntry{})
	if ws := strings.TrimSpace(opts.WorkspaceID); ws != "" {
		// Match the read-path semantics in audit_store.applyAuditFilters:
		// pre-workspace entries (workspace_id IS NULL) stay in the chain
		// so historical rows remain verifiable after the workspace column
		// was added.
		query = query.Where("workspace_id IS NULL OR workspace_id = ?", ws)
		report.WorkspaceID = ws
	}

	var (
		previousHash     string
		previousSequence int64
		seenAny          bool
	)

	// Load the chain in sequence order; the gorm tenant-scope callback
	// installed in tenant_scoping.go appends the per-tenant WHERE clause.
	// For multi-million-row tenants this will eventually need a cursor;
	// that is tracked alongside the federated query-engine work.
	var entries []AuditLogEntry
	if err := query.Order("sequence ASC").Find(&entries).Error; err != nil {
		return nil, err
	}

	for i := range entries {
		entry := &entries[i]
		if report.TenantID == "" {
			report.TenantID = entry.TenantID
		}

		report.TotalEntries++
		if !seenAny {
			report.FirstSequence = entry.Sequence
			ts := entry.Timestamp.UTC()
			report.FirstTimestamp = &ts
		}
		seenAny = true
		report.LastSequence = entry.Sequence
		lastTs := entry.Timestamp.UTC()
		report.LastTimestamp = &lastTs
		report.HeadHash = entry.Hash

		expectedHash := entry.ComputedHash()
		if expectedHash != entry.Hash {
			report.BrokenCount++
			if len(report.Breaks) < maxBreaks {
				report.Breaks = append(report.Breaks, AuditChainBreak{
					Kind:         AuditChainBreakHashMismatch,
					Sequence:     entry.Sequence,
					EventID:      entry.EventID,
					Timestamp:    entry.Timestamp.UTC(),
					ExpectedHash: expectedHash,
					ActualHash:   entry.Hash,
					Detail:       "row hash does not match recomputed payload",
				})
			}
		} else {
			report.VerifiedCount++
		}

		if previousSequence == 0 {
			if entry.Sequence != 1 {
				report.BrokenCount++
				if len(report.Breaks) < maxBreaks {
					report.Breaks = append(report.Breaks, AuditChainBreak{
						Kind:     AuditChainBreakUnexpectedStart,
						Sequence: entry.Sequence,
						EventID:  entry.EventID,
						Detail:   "first row sequence is not 1",
					})
				}
			}
			if strings.TrimSpace(entry.PreviousHash) != "" {
				report.BrokenCount++
				if len(report.Breaks) < maxBreaks {
					report.Breaks = append(report.Breaks, AuditChainBreak{
						Kind:       AuditChainBreakPreviousMismatch,
						Sequence:   entry.Sequence,
						EventID:    entry.EventID,
						ActualHash: entry.PreviousHash,
						Detail:     "first row carries a non-empty previous_hash",
					})
				}
			}
		} else {
			if entry.Sequence == previousSequence {
				report.BrokenCount++
				if len(report.Breaks) < maxBreaks {
					report.Breaks = append(report.Breaks, AuditChainBreak{
						Kind:     AuditChainBreakSequenceDuplicate,
						Sequence: entry.Sequence,
						EventID:  entry.EventID,
						Detail:   "duplicate sequence number",
					})
				}
			} else if entry.Sequence != previousSequence+1 {
				report.BrokenCount++
				if len(report.Breaks) < maxBreaks {
					report.Breaks = append(report.Breaks, AuditChainBreak{
						Kind:     AuditChainBreakSequenceGap,
						Sequence: entry.Sequence,
						EventID:  entry.EventID,
						Detail:   "sequence number jumped - chain has a missing row",
					})
				}
			}
			if entry.PreviousHash != previousHash {
				report.BrokenCount++
				if len(report.Breaks) < maxBreaks {
					report.Breaks = append(report.Breaks, AuditChainBreak{
						Kind:         AuditChainBreakPreviousMismatch,
						Sequence:     entry.Sequence,
						EventID:      entry.EventID,
						ExpectedHash: previousHash,
						ActualHash:   entry.PreviousHash,
						Detail:       "previous_hash does not match prior row's hash",
					})
				}
			}
		}

		previousHash = entry.Hash
		previousSequence = entry.Sequence
	}

	if !seenAny {
		report.Chain = AuditChainStatusEmpty
		return report, nil
	}

	if report.BrokenCount == 0 {
		report.Chain = AuditChainStatusIntact
	} else {
		report.Chain = AuditChainStatusBroken
	}
	return report, nil
}

// Compile-time check the chain verifier hangs off the same store as the
// rest of the audit log surface.
var _ interface {
	VerifyAuditChain(context.Context, AuditChainVerifyOptions) (*AuditChainVerificationReport, error)
} = (*RDBLogStore)(nil)
