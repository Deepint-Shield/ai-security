package engine

import (
	"context"
	"strings"
	"sync"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// ModalityDetector inspects a non-text attachment directly and returns safety
// findings that text extraction cannot surface - NSFW / violent imagery, audio
// whose acoustic content is disallowed, video frames, etc. It is the Phase 3
// counterpart to Extractor: extractors turn an asset into text for the existing
// text detectors, whereas a ModalityDetector is itself a modality-native model
// that emits Findings.
//
// The default registry is empty, so even with the modality stage enabled this
// is a no-op until an operator wires a vision/audio model - keeping the core
// guard binary free of heavy model dependencies. Implementations MUST be
// side-effect free and honor ctx cancellation/deadline.
type ModalityDetector interface {
	// Kinds returns the attachment kinds this detector scores. Empty = any.
	Kinds() []string
	// Detect returns zero or more findings for the attachment. A non-nil error
	// is treated as a soft failure (no findings) so one detector's outage never
	// fails the whole evaluation.
	Detect(ctx context.Context, att runtimeapi.Attachment) ([]runtimeapi.Finding, error)
}

var (
	detectorMu sync.RWMutex
	detectors  []ModalityDetector
)

// RegisterModalityDetector adds a detector to the global chain. Intended to be
// called from init() or operator wiring before requests are served.
func RegisterModalityDetector(d ModalityDetector) {
	if d == nil {
		return
	}
	detectorMu.Lock()
	detectors = append(detectors, d)
	detectorMu.Unlock()
}

// modalityDetectorsActive reports whether any modality detector should run: the
// modality stage must be enabled and at least one detector registered.
func modalityDetectorsActive() bool {
	if !modalityExtractionEnabled {
		return false
	}
	detectorMu.RLock()
	n := len(detectors)
	detectorMu.RUnlock()
	return n > 0
}

// runModalityDetectors runs every registered detector over the request's
// attachments and returns the merged findings plus a decision-chain note. Each
// finding is tagged with the source attachment (kind + content hash) for
// traceability. Bounded by the same per-request attachment cap as extraction.
func runModalityDetectors(ctx context.Context, request runtimeapi.EvaluateRequest) ([]runtimeapi.Finding, []string) {
	attachments := request.Content.Attachments
	if len(attachments) == 0 {
		return nil, nil
	}
	detectorMu.RLock()
	chain := detectors
	detectorMu.RUnlock()
	if len(chain) == 0 {
		return nil, nil
	}

	var findings []runtimeapi.Finding
	scored := 0
	for i, att := range attachments {
		if i >= maxAttachmentsPerRequest {
			break
		}
		if ctx.Err() != nil {
			break
		}
		for _, d := range chain {
			if !detectorHandlesKind(d, att.Kind) {
				continue
			}
			fs, err := d.Detect(ctx, att)
			if err != nil {
				continue
			}
			for j := range fs {
				tagFindingWithAttachment(&fs[j], att)
			}
			findings = append(findings, fs...)
			scored++
		}
	}

	if scored == 0 {
		return findings, nil
	}
	return findings, []string{"evaluated modality detectors over request attachments"}
}

func detectorHandlesKind(d ModalityDetector, kind string) bool {
	kinds := d.Kinds()
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

// tagFindingWithAttachment records which attachment produced a finding so the
// verdict is traceable back to the asset in guardrail analytics.
func tagFindingWithAttachment(f *runtimeapi.Finding, att runtimeapi.Attachment) {
	if f.Details == nil {
		f.Details = map[string]any{}
	}
	if att.Kind != "" {
		f.Details["attachment_kind"] = att.Kind
	}
	if att.Hash != "" {
		f.Details["attachment_hash"] = att.Hash
	}
	if att.MIME != "" {
		f.Details["attachment_mime"] = att.MIME
	}
}
