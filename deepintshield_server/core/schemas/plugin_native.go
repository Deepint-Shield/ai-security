//go:build !tinygo && !wasm

package schemas

import (
	"github.com/valyala/fasthttp"
)

// DeepIntShieldHTTPMiddleware is a middleware function for the DeepIntShield HTTP transport.
// It follows the standard pattern: receives the next handler and returns a new handler.
// Used internally for CORS, Auth, Tracing middleware. Plugins use HTTPTransportIntercept instead.
type DeepIntShieldHTTPMiddleware func(next fasthttp.RequestHandler) fasthttp.RequestHandler

// EventBroadcaster is a generic callback for broadcasting typed events to connected clients (e.g., via WebSocket).
// Any plugin or subsystem can use this to push real-time updates to the frontend.
// eventType identifies the message (e.g., "governance_update"), data is the JSON-serializable payload.
type EventBroadcaster func(eventType string, data interface{})

// LLMPluginShortCircuit represents a plugin's decision to short-circuit the normal flow.
// It can contain either a response (success short-circuit), a stream (streaming short-circuit), or an error (error short-circuit).
type LLMPluginShortCircuit struct {
	Response *DeepIntShieldResponse    // If set, short-circuit with this response (skips provider call)
	Stream   chan *DeepIntShieldStreamChunk // If set, short-circuit with this stream (skips provider call)
	Error    *DeepIntShieldError       // If set, short-circuit with this error (can set AllowFallbacks field)
}

// MCPPluginShortCircuit represents a plugin's decision to short-circuit the normal flow.
// It can contain either a response (success short-circuit), or an error (error short-circuit).
type MCPPluginShortCircuit struct {
	Response *DeepIntShieldMCPResponse // If set, short-circuit with this response (skips MCP call)
	Error    *DeepIntShieldError       // If set, short-circuit with this error (can set AllowFallbacks field)
}

// PluginShortCircuit is the legacy name for LLMPluginShortCircuit (v1.3.x compatibility).
// Deprecated: Use LLMPluginShortCircuit instead.
type PluginShortCircuit = LLMPluginShortCircuit
