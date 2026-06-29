package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

// modalityExtractionEnabled gates the entire modality-extraction stage
// (DEEPINTSHIELD_GUARD_MODALITY_EXTRACT). Evaluated once at process start.
// Default OFF: applyModalityExtraction returns the request untouched, so a
// build with no attachments and the flag off behaves byte-for-byte like the
// pre-feature runtime - zero added latency on the hot path.
var modalityExtractionEnabled = os.Getenv("DEEPINTSHIELD_GUARD_MODALITY_EXTRACT") == "true"

// Bounds that keep extraction work predictable under load (scalability). A
// single oversized asset must never tie up a worker, so attachments are capped
// in count, per-asset byte size, and per-asset extracted-text length.
const (
	maxAttachmentsPerRequest = 16
	maxExtractBytes          = 8 << 20  // 8 MiB: assets larger than this are skipped, not extracted
	maxExtractedTextPerAsset = 32 << 10 // 32 KiB of extracted text folded in per asset
	maxExtractCacheEntries   = 4096     // bounded dedup cache; cleared wholesale on overflow
)

// Extractor turns a single non-text attachment into text (OCR for images, STT
// for audio, keyframe-caption + track-transcript for video, layout text for
// documents). Implementations MUST be side-effect free and honor ctx
// cancellation/deadline. The default registry ships only a dependency-free text
// extractor; heavyweight vision/audio extractors are registered by the operator
// or a provider integration, keeping the core binary lean.
type Extractor interface {
	// Kinds returns the attachment kinds this extractor handles, e.g.
	// runtimeapi.AttachmentKindImage. An empty slice means "any kind".
	Kinds() []string
	// Extract resolves the attachment to text. ok=false signals "not handled by
	// this extractor" so the chain falls through to the next candidate; a
	// non-nil err is treated as a soft failure (no text, chain continues).
	Extract(ctx context.Context, att runtimeapi.Attachment) (text string, ok bool, err error)
}

var (
	extractorMu sync.RWMutex
	extractors  []Extractor
)

// RegisterExtractor adds an extractor to the global chain. Intended to be called
// from init() or operator wiring before requests are served. Registration order
// is preserved; the first extractor whose Kinds match and that returns ok wins.
func RegisterExtractor(e Extractor) {
	if e == nil {
		return
	}
	extractorMu.Lock()
	extractors = append(extractors, e)
	extractorMu.Unlock()
}

func init() {
	// The only default extractor is dependency-free: it surfaces already-text
	// documents (UTF-8 bytes / text MIME). It never decodes images or audio, so
	// enabling the stage cannot introduce a heavy codec dependency by accident.
	RegisterExtractor(textAttachmentExtractor{})
}

// applyModalityExtraction resolves every attachment to text and folds it into
// Content.Input / Content.Output (by Role) so the existing detector engine
// scores it with no detector-side changes - the key to consistency across
// modalities. Returns the request unchanged when the stage is disabled or no
// attachments are present (the overwhelmingly common case → zero overhead).
func (r *Runtime) applyModalityExtraction(ctx context.Context, request runtimeapi.EvaluateRequest) runtimeapi.EvaluateRequest {
	if !modalityExtractionEnabled || len(request.Content.Attachments) == 0 {
		return request
	}

	var inputParts, outputParts []string
	for i, att := range request.Content.Attachments {
		if i >= maxAttachmentsPerRequest {
			break
		}
		text := resolveAttachmentText(ctx, att)
		if text == "" {
			continue
		}
		if strings.EqualFold(att.Role, runtimeapi.AttachmentRoleOutput) {
			outputParts = append(outputParts, text)
		} else {
			inputParts = append(inputParts, text)
		}
	}

	if len(inputParts) > 0 {
		request.Content.Input = appendExtractedText(request.Content.Input, inputParts)
	}
	if len(outputParts) > 0 {
		request.Content.Output = appendExtractedText(request.Content.Output, outputParts)
	}
	return request
}

// appendExtractedText joins the extracted attachment texts onto the existing
// content with newlines, skipping a leading separator when the base is empty.
func appendExtractedText(base string, parts []string) string {
	joined := strings.Join(parts, "\n")
	if strings.TrimSpace(base) == "" {
		return joined
	}
	return base + "\n" + joined
}

// resolveAttachmentText returns the safety-relevant text for an attachment,
// using (in precedence order) pre-extracted Text, the dedup cache, then the
// extractor chain. Results are bounded by maxExtractedTextPerAsset.
func resolveAttachmentText(ctx context.Context, att runtimeapi.Attachment) string {
	// 1. Pre-extracted text supplied by the gateway wins outright - no work.
	if t := strings.TrimSpace(att.Text); t != "" {
		return capExtractedText(t)
	}
	// Nothing extractable inline and no extractor input.
	if len(att.Data) == 0 && strings.TrimSpace(att.Ref) == "" {
		return ""
	}
	// Bound per-asset work: skip extraction of oversized inlined payloads.
	if len(att.Data) > maxExtractBytes {
		return ""
	}

	// 2. Dedup cache: identical assets are never extracted twice. When the guard
	// holds the bytes, key on sha256(Data) it actually has - authoritative and
	// consistent with the extracted content - rather than trusting the
	// caller-supplied Hash. Fall back to the supplied Hash only for Ref-only
	// assets where the guard cannot recompute the fingerprint.
	var key string
	if len(att.Data) > 0 {
		key = hashBytes(att.Data)
	} else {
		key = strings.TrimSpace(att.Hash)
	}
	if key != "" {
		if cached, ok := loadExtractCache(key); ok {
			return cached
		}
	}

	// 3. Extractor chain.
	text := capExtractedText(strings.TrimSpace(runExtractors(ctx, att)))
	if key != "" {
		storeExtractCache(key, text)
	}
	return text
}

// runExtractors walks the registered chain, returning the first successful
// extraction for an attachment of a matching kind.
func runExtractors(ctx context.Context, att runtimeapi.Attachment) string {
	extractorMu.RLock()
	chain := extractors
	extractorMu.RUnlock()

	for _, e := range chain {
		if !extractorHandlesKind(e, att.Kind) {
			continue
		}
		if ctx.Err() != nil {
			return ""
		}
		text, ok, err := e.Extract(ctx, att)
		if err != nil || !ok {
			continue
		}
		if text = strings.TrimSpace(text); text != "" {
			return text
		}
	}
	return ""
}

func extractorHandlesKind(e Extractor, kind string) bool {
	kinds := e.Kinds()
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

func capExtractedText(s string) string {
	if len(s) <= maxExtractedTextPerAsset {
		return s
	}
	// Trim on a rune boundary to avoid splitting a multi-byte sequence.
	cut := maxExtractedTextPerAsset
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- bounded dedup cache -----------------------------------------------------

var (
	extractCacheMu sync.Mutex
	extractCache   = make(map[string]string, 256)
)

func loadExtractCache(key string) (string, bool) {
	extractCacheMu.Lock()
	v, ok := extractCache[key]
	extractCacheMu.Unlock()
	return v, ok
}

func storeExtractCache(key, val string) {
	extractCacheMu.Lock()
	// Simple bounded cache: a dedup optimization, so dropping everything on
	// overflow is correctness-neutral and avoids per-entry LRU bookkeeping on
	// the hot path.
	if len(extractCache) >= maxExtractCacheEntries {
		extractCache = make(map[string]string, 256)
	}
	extractCache[key] = val
	extractCacheMu.Unlock()
}

// --- default extractor -------------------------------------------------------

// textAttachmentExtractor surfaces attachments that already are text: documents
// whose bytes are valid UTF-8, or any attachment with a text/* MIME type. It
// performs no binary decoding, so the default build carries no OCR/STT/codec
// dependency. Image/audio/video attachments fall through (ok=false) until a
// real modality extractor is registered.
type textAttachmentExtractor struct{}

func (textAttachmentExtractor) Kinds() []string {
	return []string{runtimeapi.AttachmentKindDocument}
}

func (textAttachmentExtractor) Extract(_ context.Context, att runtimeapi.Attachment) (string, bool, error) {
	// Only surface bytes that are genuinely text. Valid UTF-8 is the gate
	// (covering text/* documents and UTF-8 payloads); binary assets are left
	// for a real modality extractor.
	if len(att.Data) == 0 || !utf8.Valid(att.Data) {
		return "", false, nil
	}
	return string(att.Data), true, nil
}
