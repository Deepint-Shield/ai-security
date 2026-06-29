// Package lib provides core functionality for the DeepIntShield HTTP service,
// including context propagation, header management, and integration with monitoring systems.
//
// This package handles the conversion of FastHTTP request contexts to DeepIntShield contexts,
// ensuring that important metadata and tracking information is preserved across the system.
// It supports propagation of Prometheus metrics through HTTP headers.
package lib

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/plugins/governance"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// Context-key constants for the semantic-cache plugin, which is not part of the
// open-source build. The header-parsing shims below still stash these hints on
// the request context so the wire protocol is unchanged; in the OSS build no
// plugin consumes them. Kept in sync with the commercial plugin's exported keys.
type cacheType = string

const (
	semanticCacheKey          schemas.DeepIntShieldContextKey = "semantic_cache_key"
	semanticCacheTTLKey       schemas.DeepIntShieldContextKey = "semantic_cache_ttl"
	semanticCacheThresholdKey schemas.DeepIntShieldContextKey = "semantic_cache_threshold"
	semanticCacheTypeKey      schemas.DeepIntShieldContextKey = "semantic_cache_cache_type"
	semanticCacheNoStoreKey   schemas.DeepIntShieldContextKey = "semantic_cache_no_store"
)

const (
	// FastHTTPUserValueDeepIntShieldContext stores the active *schemas.DeepIntShieldContext on fasthttp.RequestCtx.
	// This allows transport middleware and request handlers to share the same context instance.
	FastHTTPUserValueDeepIntShieldContext = "__deepintshield_context"
	// FastHTTPUserValueDeepIntShieldCancel stores the cancel func for the active shared DeepIntShield context.
	FastHTTPUserValueDeepIntShieldCancel = "__deepintshield_context_cancel"
	// FastHTTPUserValueLargeResponseMode marks requests that streamed a large response body.
	// It is used by transport middleware to avoid re-buffering response bodies for post-hooks.
	FastHTTPUserValueLargeResponseMode = "__deepintshield_large_response_mode"
)

// ConvertToDeepIntShieldContext converts a FastHTTP RequestCtx to a DeepIntShield context,
// preserving important header values for monitoring and tracing purposes.
//
// The function processes several types of special headers:
// 1. Prometheus Headers (x-bf-prom-*):
//   - All headers prefixed with 'x-bf-prom-' are copied to the context
//   - The prefix is stripped and the remainder becomes the context key
//   - Example: 'x-bf-prom-latency' becomes 'latency' in the context
//
// 2. MCP Headers (x-bf-mcp-*):
//   - Specifically handles 'x-bf-mcp-include-clients' and 'x-bf-mcp-include-tools' (include-only filtering)
//   - These headers enable MCP client and tool filtering
//   - Values are stored using MCP context keys for consistency
//
// 3. Governance Headers:
//   - x-bf-vk: Virtual key for governance (required for governance to work)
//
// 4. API Key Headers:
//   - Authorization: Bearer token format only when carrying a virtual key (e.g., "Bearer sk-bf-...")
//   - x-api-key: Virtual key value - Anthropic-style carrier
//   - x-goog-api-key: Virtual key value - Google Gemini-style carrier
// 	 - x-bf-api-key references a stored API key name rather than the raw secret.
//   - Keys are extracted and stored in the context using schemas.DeepIntShieldContextKey
//   - Raw provider API keys are not accepted on HTTP inference paths
//
// 5. Cancellable Context:
//   - Creates a cancellable context that can be used to cancel upstream requests when clients disconnect
//   - This is critical for streaming requests where write errors indicate client disconnects
//   - Also useful for non-streaming requests to allow provider-level cancellation
//
// 6. Extra Headers (x-bf-eh-*):
//   - Any header starting with 'x-bf-eh-' is collected and added to the map stored under schemas.DeepIntShieldContextKeyExtraHeaders
//   - The prefix is stripped, the remainder is lower-cased, and duplicate names append values
//   - This allows callers to send arbitrary context metadata without needing to extend the public schema
//
// 7. Session Stickiness Headers:
//   - x-bf-session-id: Session identifier for key binding (reuse same key across requests)
//   - x-bf-session-ttl: Per-request TTL override (duration string e.g. "30m" or seconds integer)

// Parameters:
//   - ctx: The FastHTTP request context containing the original headers
//   - allowDirectKeys: Retained for backward compatibility; direct provider keys are ignored
//
// Returns:
//   - *context.Context: A new cancellable context.Context containing the propagated values
//   - context.CancelFunc: Function to cancel the context (should be called when request completes)
//
// Example Usage:
//
//	fastCtx := &fasthttp.RequestCtx{...}
//	deepintshieldCtx, cancel := ConvertToDeepIntShieldContext(fastCtx, false, nil)
//	defer cancel() // Ensure cleanup
//	// deepintshieldCtx now contains propagated header values including Prometheus metrics,
//	// MCP filters, governance keys, API keys, cache settings,
//	// session stickiness, and extra headers

func ConvertToDeepIntShieldContext(ctx *fasthttp.RequestCtx, allowDirectKeys bool, matcher *HeaderMatcher) (*schemas.DeepIntShieldContext, context.CancelFunc) {
	_ = allowDirectKeys

	// Reuse a shared request-scoped context when available.
	var deepintshieldCtx *schemas.DeepIntShieldContext
	var cancel context.CancelFunc
	if existing, ok := ctx.UserValue(FastHTTPUserValueDeepIntShieldContext).(*schemas.DeepIntShieldContext); ok && existing != nil {
		if existingCancel, ok := ctx.UserValue(FastHTTPUserValueDeepIntShieldCancel).(context.CancelFunc); ok && existingCancel != nil {
			deepintshieldCtx = existing
			cancel = existingCancel
		} else {
			// Create one cancellable child context and promote it as the shared context.
			deepintshieldCtx, cancel = schemas.NewDeepIntShieldContextWithCancel(existing)
			ctx.SetUserValue(FastHTTPUserValueDeepIntShieldContext, deepintshieldCtx)
			ctx.SetUserValue(FastHTTPUserValueDeepIntShieldCancel, cancel)
		}
	}
	if deepintshieldCtx == nil {
		// Create cancellable context for requests that don't have a shared context yet.
		parent := context.Context(ctx)
		func() {
			// Zero-value fasthttp.RequestCtx can panic on Done(); fall back safely.
			defer func() {
				if recover() != nil {
					parent = context.Background()
				}
			}()
			_ = ctx.Done()
		}()
		deepintshieldCtx, cancel = schemas.NewDeepIntShieldContextWithCancel(parent)
		ctx.SetUserValue(FastHTTPUserValueDeepIntShieldContext, deepintshieldCtx)
		ctx.SetUserValue(FastHTTPUserValueDeepIntShieldCancel, cancel)
	}
	schemas.EnsureLatencyTracking(deepintshieldCtx, time.Now())

	// Preserve existing request-id if already present on the shared context.
	if existingRequestID, ok := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyRequestID).(string); !ok || existingRequestID == "" {
		// First, check if x-request-id header exists
		requestID := string(ctx.Request.Header.Peek("x-request-id"))
		if requestID == "" {
			requestID = uuid.New().String()
		}
		deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyRequestID, requestID)
	}
	// Populating all user values from the request context
	ctx.VisitUserValuesAll(func(key, value any) {
		deepintshieldCtx.SetValue(key, value)
	})
	// Initialize extra headers map for headers prefixed with x-bf-eh-
	extraHeaders := make(map[string][]string)
	// Collect all request headers in a single pass (used downstream for governance checks)
	allHeaders := make(map[string]string)
	// Security denylist of header names that should never be accepted (case-insensitive)
	// This denylist is always enforced regardless of user configuration
	securityDenylist := map[string]bool{
		"proxy-authorization": true,
		"cookie":              true,
		"host":                true,
		"content-length":      true,
		"connection":          true,
		"transfer-encoding":   true,

		// prevent auth/key overrides via x-bf-eh-*
		"x-api-key":       true,
		"x-goog-api-key":  true,
		"x-bf-api-key":    true,
		"x-bf-api-key-id": true,
		"x-bf-vk":         true,
	}

	// Debug: Log header matcher state
	if logger != nil {
		if matcher != nil {
			logger.Debug("headerMatcher hasAllowlist=%v, hasDenylist=%v", matcher.HasAllowlist(), matcher.hasDenylist)
		} else {
			logger.Debug("headerMatcher is nil (allow all)")
		}
	}

	// Then process other headers
	ctx.Request.Header.All()(func(key, value []byte) bool {
		keyStr := strings.ToLower(string(key))
		// Collect every header for downstream governance checks (single-pass)
		allHeaders[keyStr] = string(value)
		if labelName, ok := strings.CutPrefix(keyStr, "x-bf-prom-"); ok {
			deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKey(labelName), string(value))
			return true
		}
		// MCP control headers (include-only filtering)
		if labelName, ok := strings.CutPrefix(keyStr, "x-bf-mcp-"); ok {
			switch labelName {
			case "include-clients":
				fallthrough
			case "include-tools":
				// Parse comma-separated values into []string
				valueStr := string(value)
				var parsedValues []string
				if valueStr != "" {
					// Split by comma and trim whitespace
					for _, v := range strings.Split(valueStr, ",") {
						if trimmed := strings.TrimSpace(v); trimmed != "" {
							parsedValues = append(parsedValues, trimmed)
						}
					}
				} else {
					parsedValues = []string{""}
				}
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKey("mcp-"+labelName), parsedValues)
				return true
			}
		}
		// Handle virtual key header (x-bf-vk, authorization, x-api-key, x-goog-api-key headers)
		if keyStr == string(schemas.DeepIntShieldContextKeyVirtualKey) {
			deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyVirtualKey, string(value))
			return true
		}
		if keyStr == "authorization" {
			valueStr := string(value)
			// Only accept Bearer token format: "Bearer ..."
			if strings.HasPrefix(strings.ToLower(valueStr), "bearer ") {
				authHeaderValue := strings.TrimSpace(valueStr[7:]) // Remove "Bearer " prefix
				if authHeaderValue != "" && strings.HasPrefix(strings.ToLower(authHeaderValue), governance.VirtualKeyPrefix) {
					deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyVirtualKey, authHeaderValue)
					return true
				}
				// Workspace API key path: dis_ws_* bearer. Resolution is
				// best-effort - if the resolver hook isn't registered or
				// the token isn't recognised, we leave the context untouched
				// (the request falls through to whatever auth the rest of
				// the stack normally enforces, typically a 401).
				if authHeaderValue != "" && IsWorkspaceAPIKey(authHeaderValue) {
					if wsCtx := ResolveWorkspaceContextFromHook(deepintshieldCtx, authHeaderValue); wsCtx != nil {
						deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyWorkspaceID, wsCtx.WorkspaceID)
						deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyTenantID, wsCtx.OrgID)
						deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyWorkspaceAPIKeyID, wsCtx.APIKeyID)
					}
					return true
				}
			}
		}
		if keyStr == "x-api-key" && strings.HasPrefix(strings.ToLower(string(value)), governance.VirtualKeyPrefix) {
			deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyVirtualKey, string(value))
			return true
		}
		if keyStr == "x-goog-api-key" && strings.HasPrefix(strings.ToLower(string(value)), governance.VirtualKeyPrefix) {
			deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyVirtualKey, string(value))
			return true
		}
		if keyStr == "x-bf-api-key" {
			if keyName := strings.TrimSpace(string(value)); keyName != "" {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyAPIKeyName, keyName)
			}
			return true
		}
		if keyStr == "x-bf-api-key-id" {
			if keyID := strings.TrimSpace(string(value)); keyID != "" {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyAPIKeyID, keyID)
			}
			return true
		}
		// Handle cache key header (x-bf-cache-key)
		if keyStr == "x-bf-cache-key" {
			deepintshieldCtx.SetValue(semanticCacheKey, string(value))
			return true
		}
		// Handle cache TTL header (x-bf-cache-ttl)
		if keyStr == "x-bf-cache-ttl" {
			valueStr := string(value)
			var ttlDuration time.Duration
			var err error

			// First try to parse as duration (e.g., "30s", "5m", "1h")
			if ttlDuration, err = time.ParseDuration(valueStr); err != nil {
				// If that fails, try to parse as plain number and treat as seconds
				if seconds, parseErr := strconv.Atoi(valueStr); parseErr == nil && seconds > 0 {
					ttlDuration = time.Duration(seconds) * time.Second
					err = nil // Reset error since we successfully parsed as seconds
				}
			}

			if err == nil {
				deepintshieldCtx.SetValue(semanticCacheTTLKey, ttlDuration)
			}
			// If both parsing attempts fail, we silently ignore the header and use default TTL
			return true
		}
		// Cache threshold header
		if keyStr == "x-bf-cache-threshold" {
			threshold, err := strconv.ParseFloat(string(value), 64)
			if err == nil {
				// Clamp threshold to the inclusive range [0.0, 1.0]
				if threshold < 0.0 {
					threshold = 0.0
				} else if threshold > 1.0 {
					threshold = 1.0
				}
				deepintshieldCtx.SetValue(semanticCacheThresholdKey, threshold)
			}
			// If parsing fails, silently ignore the header (no context value set)
			return true
		}
		// Cache type header
		if keyStr == "x-bf-cache-type" {
			deepintshieldCtx.SetValue(semanticCacheTypeKey, cacheType(string(value)))
			return true
		}
		// Cache no store header
		if keyStr == "x-bf-cache-no-store" {
			if valueStr := string(value); valueStr == "true" {
				deepintshieldCtx.SetValue(semanticCacheNoStoreKey, true)
			}
			return true
		}
		// Session stickiness: session ID for key binding
		if keyStr == "x-bf-session-id" {
			if valueStr := strings.TrimSpace(string(value)); valueStr != "" {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeySessionID, valueStr)
			}
			return true
		}
		// Session stickiness: per-request TTL override (duration string or seconds integer)
		if keyStr == "x-bf-session-ttl" {
			valueStr := strings.TrimSpace(string(value))
			var ttlDuration time.Duration
			var err error
			if ttlDuration, err = time.ParseDuration(valueStr); err != nil {
				if seconds, parseErr := strconv.Atoi(valueStr); parseErr == nil && seconds > 0 {
					ttlDuration = time.Duration(seconds) * time.Second
					err = nil
				}
			}
			if err == nil && ttlDuration > 0 {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeySessionTTL, ttlDuration)
			}
			return true
		}
		if labelName, ok := strings.CutPrefix(keyStr, "x-bf-eh-"); ok {
			// Skip empty header names after prefix removal
			if labelName == "" {
				return true
			}
			// Normalize header name to lowercase
			labelName = strings.ToLower(labelName)
			// Validate against security denylist (always enforced)
			if securityDenylist[labelName] {
				return true
			}
			// Apply configurable header filter
			if !matcher.ShouldAllow(labelName) {
				return true
			}
			// Append header value (allow multiple values for the same header)
			extraHeaders[labelName] = append(extraHeaders[labelName], string(value))
			return true
		}
		// Direct header forwarding: when allowlist is configured, any header explicitly
		// in the allowlist can be forwarded directly without the x-bf-eh- prefix.
		// This enables forwarding arbitrary headers like "anthropic-beta" directly.
		// Only applies when allowlist is non-empty (backward compatible).
		if matcher.HasAllowlist() {
			if matcher.MatchesAllow(keyStr) {
				// Skip reserved x-bf-* headers (handled separately)
				if strings.HasPrefix(keyStr, "x-bf-") {
					return true
				}
				// Validate against security denylist (always enforced)
				if securityDenylist[keyStr] {
					return true
				}
				// Check denylist
				if matcher.MatchesDeny(keyStr) {
					return true
				}
				// Forward the header directly with its original name
				if logger != nil {
					logger.Debug("forwarding header via allowlist: %s", keyStr)
				}
				extraHeaders[keyStr] = append(extraHeaders[keyStr], string(value))
				return true
			}
		}
		// Send back raw response header
		if keyStr == "x-bf-send-back-raw-response" {
			if valueStr := string(value); valueStr == "true" {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeySendBackRawResponse, true)
			}
			return true
		}
		// Parent request ID header (for linking MCP tool calls to parent LLM requests)
		if keyStr == "x-bf-parent-request-id" {
			if valueStr := strings.TrimSpace(string(value)); valueStr != "" {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldMCPAgentOriginalRequestID, valueStr)
			}
			return true
		}
		// Add passthrough extra params header support
		if keyStr == "x-bf-passthrough-extra-params" {
			if valueStr := string(value); valueStr == "true" {
				deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyPassthroughExtraParams, true)
			}
			return true
		}
		return true
	})

	// Store collected extra headers in the context if any were found
	if len(extraHeaders) > 0 {
		deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyExtraHeaders, extraHeaders)
	}

	deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyRequestHeaders, allHeaders)

	return deepintshieldCtx, cancel
}

// BuildHTTPRequestFromFastHTTP creates an HTTPRequest from fasthttp context for streaming handlers.
// The returned request should be released with schemas.ReleaseHTTPRequest when done.
// Note: Body is not copied for streaming (body was already consumed for the request).
func BuildHTTPRequestFromFastHTTP(ctx *fasthttp.RequestCtx) *schemas.HTTPRequest {
	req := schemas.AcquireHTTPRequest()
	req.Method = string(ctx.Method())
	req.Path = string(ctx.Path())

	// Copy headers
	for key, value := range ctx.Request.Header.All() {
		req.Headers[string(key)] = string(value)
	}

	// Copy query params
	for key, value := range ctx.Request.URI().QueryArgs().All() {
		req.Query[string(key)] = string(value)
	}

	// Copy path parameters from user values
	ctx.VisitUserValuesAll(func(key, value any) {
		keyStr, keyIsString := key.(string)
		valueStr, valueIsString := value.(string)
		if !keyIsString || !valueIsString {
			return
		}
		if strings.HasPrefix(keyStr, "deepintshield-") ||
			keyStr == "DeepIntShieldContextKeyRequestID" ||
			keyStr == "trace_id" ||
			keyStr == "span_id" {
			return
		}
		req.PathParams[keyStr] = valueStr
	})

	// Note: Body not copied - for streaming, body was already consumed
	return req
}
