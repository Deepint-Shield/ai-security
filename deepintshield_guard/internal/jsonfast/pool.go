package jsonfast

import (
	"github.com/valyala/bytebufferpool"
)

// MarshalPooled marshals v into a pooled []byte. Returns the bytes and a
// release func - call release() once the bytes are no longer needed (e.g.
// after http.Do returns, or after the gRPC frame is sent).
//
// The returned []byte aliases pool memory: do NOT retain it past release().
// Use this for request bodies that are sent + discarded; do NOT use it for
// values that escape into long-lived structures (responses, audit records).
func MarshalPooled(v any) ([]byte, func(), error) {
	buf := bytebufferpool.Get()
	if err := NewEncoder(buf).Encode(v); err != nil {
		bytebufferpool.Put(buf)
		return nil, noop, err
	}
	// goccy's Encoder appends a trailing newline - trim it so HMAC + content
	// length match what callers expect from json.Marshal.
	b := buf.B
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return b, func() { bytebufferpool.Put(buf) }, nil
}

func noop() {}
