package guardrails

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Bounded extraction budget - chosen to keep p99 added latency under ~150ms
// even on adversarial inputs.
const (
	attachmentMaxDecodedBytes = 8 * 1024 * 1024 // hard ceiling on decoded payload
	attachmentMaxExtractBytes = 1 * 1024 * 1024 // hard ceiling on emitted text
	attachmentMaxStreams      = 256             // PDF flate streams to decode per file
	attachmentTimeBudget      = 100 * time.Millisecond
	attachmentCacheCapacity   = 256
	attachmentImageMinRun     = 4 // min printable-ASCII run length in image strings scan
)

type attachmentCacheEntry struct {
	text string
}

var (
	attachmentCache   sync.Map // key: [32]byte sha256, value: attachmentCacheEntry
	attachmentCacheMu sync.Mutex
	attachmentCacheN  int
)

func cacheGet(key [32]byte) (string, bool) {
	v, ok := attachmentCache.Load(key)
	if !ok {
		return "", false
	}
	return v.(attachmentCacheEntry).text, true
}

func cachePut(key [32]byte, text string) {
	if _, loaded := attachmentCache.LoadOrStore(key, attachmentCacheEntry{text: text}); loaded {
		return
	}
	attachmentCacheMu.Lock()
	attachmentCacheN++
	if attachmentCacheN > attachmentCacheCapacity {
		// Naive eviction: drop everything when over cap. The cache is a
		// best-effort fast path, not a correctness requirement.
		attachmentCache.Range(func(k, _ any) bool {
			attachmentCache.Delete(k)
			return true
		})
		attachmentCacheN = 0
	}
	attachmentCacheMu.Unlock()
}

// extractAttachmentText returns guardrail-scannable text from a (possibly
// base64-encoded data URI or raw base64) attachment payload. The function is
// zero-dep, bounded by attachmentTimeBudget, and caches by SHA-256 so repeated
// turns in a chat skip extraction entirely.
func extractAttachmentText(rawData string) string {
	trimmed := strings.TrimSpace(rawData)
	if trimmed == "" {
		return ""
	}

	// Strip data URI prefix if present.
	if idx := strings.Index(trimmed, ","); idx != -1 && strings.HasPrefix(trimmed, "data:") {
		trimmed = trimmed[idx+1:]
	}

	// Try base64 first; fall back to raw bytes when the payload is already
	// a plain text string (some clients send file_data uncoded).
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		if utf8.ValidString(trimmed) {
			return capText(trimmed)
		}
		return ""
	}
	return extractAttachmentBytesText(decoded)
}

// extractAttachmentBytesText runs the bounded, cached extraction pipeline over
// already-decoded attachment bytes. It is the shared core behind
// extractAttachmentText (which decodes base64/data-URIs first) and is also
// called directly for request types that carry raw bytes (e.g. image-edit
// source images, []byte audio). Same SHA-256 dedup cache and time/size caps.
func extractAttachmentBytesText(decoded []byte) string {
	if len(decoded) == 0 {
		return ""
	}
	if len(decoded) > attachmentMaxDecodedBytes {
		decoded = decoded[:attachmentMaxDecodedBytes]
	}

	key := sha256.Sum256(decoded)
	if cached, ok := cacheGet(key); ok {
		return cached
	}

	deadline := time.Now().Add(attachmentTimeBudget)
	var text string
	switch sniffAttachmentKind(decoded) {
	case attachmentKindPDF:
		text = extractPDFText(decoded, deadline)
	case attachmentKindImage:
		text = extractImageText(decoded, deadline)
	case attachmentKindUTF8:
		text = string(decoded)
	default:
		// Last-ditch: if the bytes happen to be UTF-8 (CSV, JSON, MD with
		// unusual prefix), pass them through.
		if utf8.Valid(decoded) {
			text = string(decoded)
		}
	}

	text = capText(strings.TrimSpace(text))
	cachePut(key, text)
	return text
}

func capText(text string) string {
	if len(text) > attachmentMaxExtractBytes {
		return text[:attachmentMaxExtractBytes]
	}
	return text
}

type attachmentKind int

const (
	attachmentKindUnknown attachmentKind = iota
	attachmentKindPDF
	attachmentKindImage
	attachmentKindUTF8
)

func sniffAttachmentKind(b []byte) attachmentKind {
	if len(b) >= 5 && bytes.Equal(b[:5], []byte("%PDF-")) {
		return attachmentKindPDF
	}
	if isImageMagic(b) {
		return attachmentKindImage
	}
	if utf8.Valid(b) {
		return attachmentKindUTF8
	}
	return attachmentKindUnknown
}

func isImageMagic(b []byte) bool {
	switch {
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
		return true // PNG
	case len(b) >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff:
		return true // JPEG / JFIF / EXIF
	case len(b) >= 6 && (bytes.Equal(b[:6], []byte("GIF87a")) || bytes.Equal(b[:6], []byte("GIF89a"))):
		return true // GIF
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return true // WEBP
	case len(b) >= 2 && b[0] == 'B' && b[1] == 'M':
		return true // BMP
	case len(b) >= 4 && (bytes.Equal(b[:4], []byte("II*\x00")) || bytes.Equal(b[:4], []byte("MM\x00*"))):
		return true // TIFF (also EXIF container)
	}
	return false
}

// extractImageText pulls scannable text out of an image without OCR. Three
// fast passes, all bounded:
//   - PNG tEXt/iTXt chunks (microseconds, exact text)
//   - JPEG APP1/COM segments (EXIF, XMP, comments - usually has UserComment,
//     ImageDescription, Artist, GPS strings)
//   - Generic strings(1)-style scan for printable ASCII runs ≥4 chars
//
// The strings scan catches text in any container we don't explicitly parse,
// including watermarks, embedded metadata, and renderer banners. Total cost
// for a 1MB image is sub-millisecond on modern hardware.
func extractImageText(data []byte, deadline time.Time) string {
	var out strings.Builder
	out.Grow(min(len(data)/8, attachmentMaxExtractBytes))

	switch {
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
		extractPNGTextChunks(data[8:], &out, deadline)
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		extractJPEGTextSegments(data, &out, deadline)
	}

	if out.Len() < attachmentMaxExtractBytes && !time.Now().After(deadline) {
		extractPrintableRuns(data, &out, attachmentImageMinRun, deadline)
	}

	return out.String()
}

// extractPNGTextChunks walks PNG chunks looking for tEXt, iTXt, zTXt.
// Layout per chunk: 4-byte big-endian length, 4-byte type, length bytes of
// data, 4-byte CRC.
func extractPNGTextChunks(body []byte, out *strings.Builder, deadline time.Time) {
	i := 0
	for i+12 <= len(body) {
		if time.Now().After(deadline) || out.Len() >= attachmentMaxExtractBytes {
			return
		}
		length := int(uint32(body[i])<<24 | uint32(body[i+1])<<16 | uint32(body[i+2])<<8 | uint32(body[i+3]))
		if length < 0 || i+8+length+4 > len(body) {
			return
		}
		chunkType := string(body[i+4 : i+8])
		payload := body[i+8 : i+8+length]
		switch chunkType {
		case "tEXt":
			// keyword\0text - both Latin-1; treat as ASCII passthrough.
			if nul := bytes.IndexByte(payload, 0); nul >= 0 && nul+1 < len(payload) {
				writeBounded(out, payload[nul+1:])
				out.WriteByte('\n')
			}
		case "iTXt":
			// keyword\0 compFlag compMethod lang\0 transKey\0 text
			if nul := bytes.IndexByte(payload, 0); nul >= 0 && nul+3 < len(payload) {
				rest := payload[nul+3:]
				if l := bytes.IndexByte(rest, 0); l >= 0 && l+1 < len(rest) {
					tk := rest[l+1:]
					if t := bytes.IndexByte(tk, 0); t >= 0 && t+1 < len(tk) {
						writeBounded(out, tk[t+1:])
						out.WriteByte('\n')
					}
				}
			}
		case "IEND":
			return
		}
		i += 8 + length + 4
	}
}

// extractJPEGTextSegments walks JPEG markers (0xFF xx) and emits payload
// of APP-segments and COM. EXIF strings are passed through the printable-run
// scan, which catches them without needing a full TIFF parser.
func extractJPEGTextSegments(data []byte, out *strings.Builder, deadline time.Time) {
	i := 2 // skip SOI 0xFFD8
	for i+4 <= len(data) {
		if time.Now().After(deadline) || out.Len() >= attachmentMaxExtractBytes {
			return
		}
		if data[i] != 0xff {
			return
		}
		marker := data[i+1]
		// SOS (0xDA) - entropy-coded segment follows; bail.
		if marker == 0xda || marker == 0xd9 {
			return
		}
		// Standalone markers (no length): RSTn, SOI, EOI, TEM.
		if marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7) {
			i += 2
			continue
		}
		segLen := int(uint16(data[i+2])<<8 | uint16(data[i+3]))
		if segLen < 2 || i+2+segLen > len(data) {
			return
		}
		payload := data[i+4 : i+2+segLen]
		// APP0..APP15 (0xE0..0xEF) and COM (0xFE) are the text-bearing ones.
		if (marker >= 0xe0 && marker <= 0xef) || marker == 0xfe {
			extractPrintableRuns(payload, out, attachmentImageMinRun, deadline)
		}
		i += 2 + segLen
	}
}

// extractPrintableRuns is a strings(1)-style scan: emit any run of printable
// ASCII (and tab/newline) of length ≥ minRun. O(n), no allocations beyond
// the output builder.
func extractPrintableRuns(data []byte, out *strings.Builder, minRun int, deadline time.Time) {
	const checkEvery = 65536
	runStart := -1
	for i := 0; i < len(data); i++ {
		if i&(checkEvery-1) == 0 && (out.Len() >= attachmentMaxExtractBytes || time.Now().After(deadline)) {
			return
		}
		c := data[i]
		printable := (c >= 0x20 && c < 0x7f) || c == '\t'
		if printable {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		if runStart >= 0 && i-runStart >= minRun {
			writeBounded(out, data[runStart:i])
			out.WriteByte('\n')
		}
		runStart = -1
	}
	if runStart >= 0 && len(data)-runStart >= minRun {
		writeBounded(out, data[runStart:])
		out.WriteByte('\n')
	}
}

func writeBounded(out *strings.Builder, b []byte) {
	if out.Len() >= attachmentMaxExtractBytes {
		return
	}
	remaining := attachmentMaxExtractBytes - out.Len()
	if len(b) > remaining {
		b = b[:remaining]
	}
	out.Write(b)
}

// extractPDFText is a deliberately small, allocation-conscious PDF text
// extractor. It scans for compressed content streams (FlateDecode) and for
// inline `(text) Tj` / `[(text) ...] TJ` operators in BT…ET blocks.
//
// It does NOT decode CMaps, ToUnicode tables, or font encodings - but for the
// guardrail use case (regex / detect_pii over the visible characters) the
// resulting string is good enough to flag PII embedded in the document.
func extractPDFText(data []byte, deadline time.Time) string {
	var out strings.Builder
	out.Grow(min(len(data)/2, attachmentMaxExtractBytes))

	streams := 0
	i := 0
	for i < len(data) {
		if streams >= attachmentMaxStreams || time.Now().After(deadline) {
			break
		}
		if out.Len() >= attachmentMaxExtractBytes {
			break
		}

		// Find the next `stream` ... `endstream` block.
		streamStart := bytes.Index(data[i:], []byte("stream"))
		if streamStart < 0 {
			break
		}
		streamStart += i + len("stream")
		// PDF spec requires a newline immediately after `stream`.
		if streamStart < len(data) && (data[streamStart] == '\r' || data[streamStart] == '\n') {
			streamStart++
			if streamStart < len(data) && data[streamStart] == '\n' {
				streamStart++
			}
		}
		streamEnd := bytes.Index(data[streamStart:], []byte("endstream"))
		if streamEnd < 0 {
			break
		}
		streamBody := bytes.TrimRight(data[streamStart:streamStart+streamEnd], "\r\n ")
		i = streamStart + streamEnd + len("endstream")
		streams++

		// Heuristic: try zlib decode; if it fails, treat as plain (some PDFs
		// have uncompressed content streams).
		body := streamBody
		if zr, err := zlib.NewReader(bytes.NewReader(streamBody)); err == nil {
			lim := io.LimitReader(zr, attachmentMaxExtractBytes)
			decoded, derr := io.ReadAll(lim)
			_ = zr.Close()
			if derr == nil && len(decoded) > 0 {
				body = decoded
			}
		}

		extractPDFOperators(body, &out)
	}

	return out.String()
}

// extractPDFOperators walks a content stream looking for text-showing
// operators. Allocations are minimised: the builder is reused across streams
// and parens/strings are decoded in place.
func extractPDFOperators(body []byte, out *strings.Builder) {
	i := 0
	for i < len(body) {
		switch body[i] {
		case '(':
			s, end := readPDFString(body, i)
			if end < 0 {
				return
			}
			// Tj / TJ / ' / " operators consume preceding strings; we emit
			// indiscriminately because guardrails only care about content.
			if s != "" {
				out.WriteString(s)
				out.WriteByte(' ')
				if out.Len() >= attachmentMaxExtractBytes {
					return
				}
			}
			i = end
		case '<':
			// Hex string `<...>` - skip; rarely contains scannable text.
			end := bytes.IndexByte(body[i:], '>')
			if end < 0 {
				return
			}
			i += end + 1
		case '\n':
			out.WriteByte('\n')
			i++
		default:
			i++
		}
	}
}

// readPDFString reads a balanced `(...)` literal starting at i and returns
// the unescaped contents and the index immediately after the closing paren.
func readPDFString(body []byte, i int) (string, int) {
	if i >= len(body) || body[i] != '(' {
		return "", -1
	}
	i++
	depth := 1
	var sb strings.Builder
	for i < len(body) {
		c := body[i]
		switch c {
		case '\\':
			if i+1 >= len(body) {
				return sb.String(), i + 1
			}
			esc := body[i+1]
			switch esc {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'b', 'f':
				sb.WriteByte(' ')
			case '(', ')', '\\':
				sb.WriteByte(esc)
			default:
				sb.WriteByte(esc)
			}
			i += 2
		case '(':
			depth++
			sb.WriteByte('(')
			i++
		case ')':
			depth--
			if depth == 0 {
				return sb.String(), i + 1
			}
			sb.WriteByte(')')
			i++
		default:
			sb.WriteByte(c)
			i++
		}
		if sb.Len() >= attachmentMaxExtractBytes {
			return sb.String(), i
		}
	}
	return sb.String(), i
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
