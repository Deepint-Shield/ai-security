// Package jsonfast re-exports goccy/go-json under a project-local name so
// the hot path can swap codecs in one place. goccy/go-json is API-compatible
// with encoding/json and benchmarks ~2-3x faster on the EvaluateRequest /
// EvaluateResponse payloads - most of the win is on Unmarshal of nested
// content + metadata maps.
//
// Only use this on the request hot path (runtimeapi client/server, eval
// cache key construction). Slow-path code (config loaders, audit writers)
// should keep encoding/json so the stdlib path stays exercised.
package jsonfast

import gojson "github.com/goccy/go-json"

// Marshal is a drop-in for encoding/json.Marshal.
func Marshal(v any) ([]byte, error) { return gojson.Marshal(v) }

// Unmarshal is a drop-in for encoding/json.Unmarshal.
func Unmarshal(data []byte, v any) error { return gojson.Unmarshal(data, v) }

// NewEncoder / NewDecoder kept for symmetry with encoding/json call sites.
var (
	NewEncoder = gojson.NewEncoder
	NewDecoder = gojson.NewDecoder
)
