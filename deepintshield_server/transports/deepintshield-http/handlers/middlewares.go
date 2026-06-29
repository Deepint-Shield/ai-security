package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/encrypt"
	"github.com/deepint-shield/ai-security/framework/tracing"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/valyala/fasthttp"
)

var loggingSkipPaths = []string{"/health", "/_next", "/api/dev"}

// SecurityHeadersMiddleware sets security-related HTTP headers on every response.
// This should wrap the outermost handler so all responses (API, UI, errors) include these headers.
func SecurityHeadersMiddleware() schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			ctx.Response.Header.Set("X-Frame-Options", "DENY")
			ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
			ctx.Response.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			ctx.Response.Header.Set("Content-Security-Policy", "frame-ancestors 'none'")
			ctx.Response.Header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			// Only set HSTS when serving over HTTPS (detected via reverse proxy header or direct TLS)
			if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" || ctx.IsTLS() {
				ctx.Response.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next(ctx)
		}
	}
}

// CorsMiddleware handles CORS headers for localhost and configured allowed origins
func CorsMiddleware(config *lib.Config) schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			startTime := time.Now()
			// skip logging if it's a /health check request
			if slices.IndexFunc(loggingSkipPaths, func(path string) bool {
				return strings.HasPrefix(string(ctx.RequestURI()), path)
			}) != -1 {
				goto corsFlow
			}
			defer func() {
				statusCode := ctx.Response.Header.StatusCode()
				level := schemas.LogLevelInfo
				if statusCode >= 500 {
					level = schemas.LogLevelError
				} else if statusCode >= 400 {
					level = schemas.LogLevelWarn
				}
				logBuilder := logger.LogHTTPRequest(level, "request completed").
					Str("http.method", string(ctx.Method())).
					Str("http.target", string(ctx.RequestURI())).
					Int("http.status_code", statusCode).
					Int64("http.request_duration_ms", time.Since(startTime).Milliseconds()).
					Str("http.remote_addr", ctx.RemoteAddr().String()).
					Str("http.user_agent", string(ctx.Request.Header.UserAgent()))
				if traceID, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyTraceID).(string); ok && traceID != "" {
					logBuilder = logBuilder.Str("trace_id", traceID)
				}
				logBuilder.Send()
			}()
		corsFlow:
			origin := string(ctx.Request.Header.Peek("Origin"))
			allowed := IsOriginAllowed(origin, config.ClientConfig.AllowedOrigins)
			allowedHeaders := []string{"Content-Type", "Authorization", "X-Requested-With", "X-Stainless-Timeout"}
			if len(config.ClientConfig.AllowedHeaders) > 0 {
				// append allowed headers from config to the default headers
				for _, header := range config.ClientConfig.AllowedHeaders {
					if !slices.Contains(allowedHeaders, header) {
						allowedHeaders = append(allowedHeaders, header)
					}
				}
			}
			// Check if origin is allowed (localhost always allowed + configured origins)
			if allowed {
				ctx.Response.Header.Set("Access-Control-Allow-Origin", origin)
				ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD")
				ctx.Response.Header.Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
				// Set Allow-Credentials for credentialed requests. Only skip when wildcard
				// is configured AND the origin was matched by the wildcard (not by localhost rule
				// or explicit listing). Localhost origins and explicitly listed origins always
				// get credentials support since we return the specific origin.
				if !slices.Contains(config.ClientConfig.AllowedOrigins, "*") ||
					isLocalhostOrigin(origin) ||
					slices.Contains(config.ClientConfig.AllowedOrigins, origin) {
					ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
				}
				ctx.Response.Header.Set("Access-Control-Max-Age", "86400")
				// Vary: Origin tells caches that the response varies based on the Origin
				// request header, preventing incorrect CORS headers from being served.
				ctx.Response.Header.Set("Vary", "Origin")
			}
			// Handle preflight OPTIONS requests
			if string(ctx.Method()) == "OPTIONS" {
				if allowed {
					ctx.SetStatusCode(fasthttp.StatusOK)
				} else {
					ctx.SetStatusCode(fasthttp.StatusForbidden)
				}
				return
			}
			next(ctx)
		}
	}
}

// RequestDecompressionMiddleware transparently decompresses compressed request bodies.
// Two paths based on compressed Content-Length:
//   - Large or chunked (CL > threshold or CL unknown): streaming decompression via
//     SetBodyStream, avoiding full body materialization. Uses pooled gzip readers
//     matching the response-side pattern in core/providers/utils.
//   - Small (CL ≤ threshold): buffered decompression via io.ReadAll + SetBodyRaw,
//     with decompression bomb protection via MaxRequestBodySizeMB.
func RequestDecompressionMiddleware(config *lib.Config) schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			if len(ctx.Request.Header.ContentEncoding()) == 0 {
				next(ctx)
				return
			}

			if shouldStreamDecompress(config, ctx) {
				cleanup, applied, err := streamingDecompress(ctx)
				if err != nil {
					SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid compressed request body: %v", err))
					return
				}
				if applied {
					next(ctx)
					cleanup()
					return
				}
				// No body stream available (StreamRequestBody not enabled) - fall
				// through to the buffered decompression path below.
			}

			// Buffered path: small compressed request - materialize fully.
			maxRequestBodyBytes := 100 * 1024 * 1024 // default 100 MB (matches decodeRequestBodyWithLimit fallback)
			if config != nil && config.ClientConfig.MaxRequestBodySizeMB > 0 {
				maxRequestBodyBytes = config.ClientConfig.MaxRequestBodySizeMB * 1024 * 1024
			}

			body, err := decodeRequestBodyWithLimit(&ctx.Request, maxRequestBodyBytes)
			if errors.Is(err, errRequestBodyTooLarge) {
				SendError(ctx, fasthttp.StatusRequestEntityTooLarge, fmt.Sprintf("decompressed request body exceeds max allowed size of %d bytes", maxRequestBodyBytes))
				return
			}
			if err != nil {
				SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid compressed request body: %v", err))
				return
			}

			ctx.Request.SetBodyRaw(body)
			ctx.Request.Header.Del(fasthttp.HeaderContentEncoding)
			ctx.Request.Header.Del(fasthttp.HeaderContentLength)
			next(ctx)
		}
	}
}

// shouldStreamDecompress returns true when the compressed request body should
// use streaming decompression rather than full materialization. Uses the
// config threshold (set by enterprise from LargePayloadConfig.RequestThresholdBytes)
// or falls back to DefaultLargePayloadRequestThresholdBytes.
// Chunked requests (unknown size) always stream to be safe.
func shouldStreamDecompress(config *lib.Config, ctx *fasthttp.RequestCtx) bool {
	contentLength := ctx.Request.Header.ContentLength()
	// Chunked transfer encoding: fasthttp reports -1. Size unknown, stream to be safe.
	if contentLength < 0 {
		return true
	}
	var threshold int64 = schemas.DefaultLargePayloadRequestThresholdBytes
	if config != nil && config.StreamingDecompressThreshold > 0 {
		threshold = config.StreamingDecompressThreshold
	}
	return int64(contentLength) > threshold
}

// streamingDecompress wraps the request body stream with a streaming decompression
// reader, avoiding full body materialization for large compressed requests.
// Returns (cleanup, applied, err):
//   - applied=true: body stream was wrapped; caller must invoke cleanup after the
//     handler chain completes and the body is fully consumed.
//   - applied=false: no body stream available (StreamRequestBody not enabled on the
//     server). Caller should fall back to the buffered decompression path.
func streamingDecompress(ctx *fasthttp.RequestCtx) (cleanup func(), applied bool, err error) {
	bodyStream := ctx.RequestBodyStream()
	if bodyStream == nil {
		return func() {}, false, nil
	}

	encoding := strings.ToLower(strings.TrimSpace(
		string(ctx.Request.Header.ContentEncoding()),
	))

	decompReader, cleanup, err := newDecompressReader(bodyStream, encoding)
	if err != nil {
		return nil, false, err
	}

	ctx.Request.SetBodyStream(decompReader, -1)
	ctx.Request.Header.Del(fasthttp.HeaderContentEncoding)
	ctx.Request.Header.Del(fasthttp.HeaderContentLength)

	return cleanup, true, nil
}

var errRequestBodyTooLarge = errors.New("decompressed request body exceeds max allowed size")

// decodeRequestBodyWithLimit decodes the request body with a limit on the size of the body.
func decodeRequestBodyWithLimit(req *fasthttp.Request, maxRequestBodyBytes int) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(string(req.Header.ContentEncoding())))
	bodyReader := bytes.NewReader(req.Body())

	var reader io.Reader = bodyReader
	cleanup := func() {}
	if encoding != "" {
		var err error
		reader, cleanup, err = newDecompressReader(bodyReader, encoding)
		if err != nil {
			return nil, err
		}
	}
	defer cleanup()

	if maxRequestBodyBytes <= 0 {
		maxRequestBodyBytes = 100 * 1024 * 1024 // 100 MB hard cap
	}

	limitedReader := &io.LimitedReader{R: reader, N: int64(maxRequestBodyBytes + 1)}
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if len(body) > maxRequestBodyBytes {
		return nil, errRequestBodyTooLarge
	}
	return body, nil
}

// newDecompressReader wraps r with a decompression reader for the given encoding.
// All encodings use pooled readers from core/providers/utils. The returned cleanup
// function must be called when the reader is no longer needed.
func newDecompressReader(r io.Reader, encoding string) (io.Reader, func(), error) {
	switch encoding {
	case "gzip":
		gz, err := providerUtils.AcquireGzipReader(r)
		if err != nil {
			return nil, nil, err
		}
		return gz, func() { providerUtils.ReleaseGzipReader(gz) }, nil
	case "deflate":
		fr, err := providerUtils.AcquireFlateReader(r)
		if err != nil {
			return nil, nil, err
		}
		return fr, func() { providerUtils.ReleaseFlateReader(fr) }, nil
	case "br":
		br := providerUtils.AcquireBrotliReader(r)
		return br, func() { providerUtils.ReleaseBrotliReader(br) }, nil
	case "zstd":
		dec, err := providerUtils.AcquireZstdDecoder(r)
		if err != nil {
			return nil, nil, err
		}
		return dec, func() { providerUtils.ReleaseZstdDecoder(dec) }, nil
	default:
		return nil, nil, fmt.Errorf("%w: %q", fasthttp.ErrContentEncodingUnsupported, encoding)
	}
}

// TransportInterceptorMiddleware runs all plugin HTTP transport interceptors.
// It converts the fasthttp request to a serializable HTTPRequest, runs all plugin interceptors,
// and applies any modifications back to the fasthttp context.
func TransportInterceptorMiddleware(config *lib.Config) schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			plugins := config.GetLoadedHTTPTransportPlugins()
			if len(plugins) == 0 {
				next(ctx)
				return
			}
			// Get or create DeepIntShieldContext from fasthttp context
			deepintshieldCtx := getDeepIntShieldContextFromFastHTTP(ctx)
			// Acquire pooled request
			req := schemas.AcquireHTTPRequest()
			defer schemas.ReleaseHTTPRequest(req)
			fasthttpToHTTPRequest(ctx, req)
			// Run plugin interceptors
			for _, plugin := range plugins {
				resp, err := plugin.HTTPTransportPreHook(deepintshieldCtx, req)
				if err != nil {
					// Short-circuit with error
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					ctx.SetBodyString(err.Error())
					return
				}
				if resp != nil {
					// Short-circuit with response
					applyHTTPResponseToCtx(ctx, resp)
					return
				}
				// If we got here, the plugin may have modified req in-place
			}
			// Apply modifications back to fasthttp context
			applyHTTPRequestToCtx(ctx, req)
			// Adding user values
			for key, value := range deepintshieldCtx.GetUserValues() {
				ctx.SetUserValue(key, value)
			}
			next(ctx)

			// Skip HTTPTransportPostHook for streaming responses
			// Streaming handlers set DeferTraceCompletion and use StreamChunkInterceptor for per-chunk hooks
			if deferred, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyDeferTraceCompletion).(bool); ok && deferred {
				return
			}

			// Acquire pooled response for post-hooks (non-streaming only)
			httpResp := schemas.AcquireHTTPResponse()
			defer schemas.ReleaseHTTPResponse(httpResp)
			fasthttpResponseToHTTPResponse(ctx, httpResp)
			// Run http post-hooks in reverse order
			for i := len(plugins) - 1; i >= 0; i-- {
				plugin := plugins[i]
				err := plugin.HTTPTransportPostHook(deepintshieldCtx, req, httpResp)
				if err != nil {
					logger.Warn("error in HTTPTransportPostHook for plugin %s: %s", plugin.GetName(), err.Error())
					// Short-circuit with response
					applyHTTPResponseToCtx(ctx, httpResp)
					return
				}
			}
			// Apply modifications back to fasthttp context
			applyHTTPResponseToCtx(ctx, httpResp)
		}
	}
}

// getDeepIntShieldContextFromFastHTTP gets or creates a DeepIntShieldContext from fasthttp context.
func getDeepIntShieldContextFromFastHTTP(ctx *fasthttp.RequestCtx) *schemas.DeepIntShieldContext {
	return schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
}

// fasthttpToHTTPRequest populates a pooled HTTPRequest from fasthttp context.
func fasthttpToHTTPRequest(ctx *fasthttp.RequestCtx, req *schemas.HTTPRequest) {
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
	// The fasthttp router stores path variables (like {file_id}, {model}) as user values
	// We extract all string user values that are likely path parameters
	ctx.VisitUserValuesAll(func(key, value any) {
		// Only process string keys and string values
		keyStr, keyIsString := key.(string)
		valueStr, valueIsString := value.(string)
		if !keyIsString || !valueIsString {
			return
		}
		// Skip internal DeepIntShield system keys and tracing keys
		if strings.HasPrefix(keyStr, "deepintshield-") ||
			keyStr == "DeepIntShieldContextKeyRequestID" ||
			keyStr == "trace_id" ||
			keyStr == "span_id" {
			return
		}
		// Store as path parameter
		req.PathParams[keyStr] = valueStr
	})

	// Skip body copy for large payloads.
	// Check threshold first (set by RequestThresholdMiddleware before this middleware runs)
	// because the large-payload-mode flag is only set later inside the handler hook.
	if threshold, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyLargePayloadRequestThreshold).(int64); ok && threshold > 0 {
		cl := int64(ctx.Request.Header.ContentLength())
		// Skip body copy when CL exceeds threshold OR CL is unknown (streaming/
		// chunked, e.g. after streaming decompression deletes the header).
		if cl > threshold || cl < 0 {
			return
		}
	}
	if isLargePayload, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool); ok && isLargePayload {
		return
	}
	body := ctx.Request.Body()
	if len(body) > 0 {
		req.Body = make([]byte, len(body))
		copy(req.Body, body)
	}
}

// applyHTTPRequestToCtx applies modifications from HTTPRequest back to fasthttp context.
func applyHTTPRequestToCtx(ctx *fasthttp.RequestCtx, req *schemas.HTTPRequest) {
	// If path/method is different, throw error
	if req.Method != string(ctx.Method()) || req.Path != string(ctx.Path()) {
		logger.Error("request method/path mismatch: %s %s != %s %s", req.Method, req.Path, string(ctx.Method()), string(ctx.Path()))
		SendError(ctx, fasthttp.StatusConflict, "request method/path was modified by a plugin, this is not allowed")
		return
	}
	// Apply headers
	for key, value := range req.Headers {
		ctx.Request.Header.Set(key, value)
	}
	// Apply query params
	for key, value := range req.Query {
		ctx.Request.URI().QueryArgs().Set(key, value)
	}
	// Apply body if set
	if req.Body != nil {
		ctx.Request.SetBody(req.Body)
	}
}

// applyHTTPResponseToCtx writes a short-circuit response to fasthttp context.
func applyHTTPResponseToCtx(ctx *fasthttp.RequestCtx, resp *schemas.HTTPResponse) {
	ctx.SetStatusCode(resp.StatusCode)
	for key, value := range resp.Headers {
		ctx.Response.Header.Set(key, value)
	}
	if resp.Body != nil {
		ctx.SetBody(resp.Body)
	}
}

// fasthttpResponseToHTTPResponse populates a pooled HTTPResponse from fasthttp context.
func fasthttpResponseToHTTPResponse(ctx *fasthttp.RequestCtx, resp *schemas.HTTPResponse) {
	resp.StatusCode = ctx.Response.StatusCode()
	for key, value := range ctx.Response.Header.All() {
		resp.Headers[string(key)] = string(value)
	}
	// Skip response body copy when large payload/response mode is active - the response is
	// streamed directly to the client and materializing it here would spike memory.
	if isLargePayload, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool); ok && isLargePayload {
		return
	}
	if isLargeResponse, ok := ctx.UserValue(lib.FastHTTPUserValueLargeResponseMode).(bool); ok && isLargeResponse {
		return
	}
	// Also skip if response Content-Length exceeds the configured response threshold.
	if threshold, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyLargeResponseThreshold).(int64); ok && threshold > 0 {
		if int64(ctx.Response.Header.ContentLength()) > threshold {
			return
		}
	}
	body := ctx.Response.Body()
	if len(body) > 0 {
		resp.Body = make([]byte, len(body))
		copy(resp.Body, body)
	}
}

// validateSession checks if a session token is valid and, when it belongs to a
// dashboard account, attaches the user/tenant identity to the request context.
// The tenant_id is set from the session's email-scoped tenant_id so all downstream
// queries stay isolated to the authenticated account - unless the request
// carries an X-Active-Tenant-Id / X-Active-Workspace-Id header (the sidebar's
// scope switcher), in which case we apply that override after a permission
// check so multi-tenant admins can browse across tenants without re-login.
//
// An in-process TTL cache (globalAuthCache) eliminates the DB round-trips for
// repeated requests with the same token within the cache window (~60s).
func validateSession(ctx *fasthttp.RequestCtx, store configstore.ConfigStore, token string) bool {
	// Fast path: check in-process cache.
	if cached, ok := globalAuthCache.getSession(token); ok {
		if ctx != nil {
			if cached.userID != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserID, cached.userID)
			}
			if cached.userRole != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserRole, cached.userRole)
			}
			if cached.tenantID != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, cached.tenantID)
			}
			applyActiveScopeOverride(ctx, store, cached.userID, cached.userRole)
		}
		return true
	}

	session, err := store.GetSession(context.Background(), token)
	if err != nil || session == nil {
		return false
	}
	if session.ExpiresAt.Before(time.Now()) {
		return false
	}

	entry := sessionCacheEntry{}
	if ctx != nil {
		if session.UserID != nil {
			userID := strings.TrimSpace(*session.UserID)
			if userID != "" {
				entry.userID = userID
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserID, userID)
				if userRole, ok := lookupSessionUserRole(store, userID); ok {
					entry.userRole = userRole
					ctx.SetUserValue(schemas.DeepIntShieldContextKeyUserRole, userRole)
				}
			}
		}
		// Set tenant_id from the session's email-scoped tenant_id.
		tenantID := strings.TrimSpace(session.TenantID)
		if tenantID != "" {
			entry.tenantID = tenantID
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, tenantID)
		}
		applyActiveScopeOverride(ctx, store, entry.userID, entry.userRole)
	}
	globalAuthCache.putSession(token, entry)
	return true
}

// applyActiveScopeOverride consults the X-Active-Tenant-Id and
// X-Active-Workspace-Id headers (set by the admin UI's scope switcher) and
// stamps the chosen tenant + workspace on a SEPARATE context key
// (DeepIntShieldContextKeyActiveTenantID), leaving the legacy session
// tenant_id (the email-keyed GORM partition) untouched.
//
// Why two keys: the legacy DeepIntShieldContextKeyTenantID is the
// partitioning key for the GORM tenant-scoping callback. It carries the
// user's email-scoped partition (e.g. "user@example.com") and every read
// goes through `WHERE tenant_id = ?`. If we rewrote it to the 3-tier
// tenant UUID, the next session reload would filter by UUID, find no
// rows in the email-scoped partition, and return 401 - which is exactly
// the bug we're fixing here.
//
// Permission helpers (CanManage*/CanRead*) read the active key when set,
// falling back to the session tenant when not. The override is
// permission-gated: applied only when the caller is a system admin or
// holds an org-membership on the target tenant. A bogus or unauthorised
// header is silently ignored - handlers continue to operate on the
// session's home tenant. Workspace override is unconditional because it
// can only narrow within whatever tenant is already active.
func applyActiveScopeOverride(ctx *fasthttp.RequestCtx, store configstore.ConfigStore, userID, userRole string) {
	if ctx == nil || store == nil {
		return
	}
	desiredTenant := lib.ActiveTenantHeader(ctx)
	desiredWorkspace := lib.ActiveWorkspaceHeader(ctx)
	if desiredTenant == "" && desiredWorkspace == "" {
		return
	}

	// Workspace stamp is cheap (no DB) - do it first.
	if desiredWorkspace != "" {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyWorkspaceID, desiredWorkspace)

		// Cross-workspace access: when the invitee is browsing a
		// workspace whose parent tenant differs from their session's
		// home tenant, the legacy email-keyed GORM tenant filter would
		// hit the WRONG partition (the invitee's email, not the
		// workspace owner's email) and return zero rows for logs,
		// providers, models, etc. - even though they have a valid
		// workspace_membership. Override the legacy tenant_id key with
		// the workspace's email-keyed partition so the GORM tenant
		// callback reads from the right partition.
		//
		// Permission gate: only override if the user has a
		// workspace_membership in this workspace, OR is a superadmin.
		// Otherwise we'd be granting cross-tenant data access via a
		// header alone.
		isSuperadmin := configstoreTables.NormalizeAuthUserRole(userRole) == configstoreTables.UserRoleSuperadmin
		if isSuperadmin || (strings.TrimSpace(userID) != "" && hasWorkspaceMembershipCached(store, desiredWorkspace, userID)) {
			if legacyTenant := resolveWorkspaceLegacyTenant(store, desiredWorkspace); legacyTenant != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, legacyTenant)
			}
		}
	}

	if desiredTenant == "" {
		return
	}

	// Dual-resolve: a browser may still send the pre-re-key email in
	// X-Active-Tenant-Id. Canonicalize it to the UUID via the alias so the
	// membership check below hits the migrated org_membership (which now
	// references the UUID). No-op until aliases exist, so behavior is
	// unchanged pre-migration.
	if canonical, err := store.ResolveCanonicalTenant(context.Background(), desiredTenant); err == nil && canonical != "" && canonical != desiredTenant {
		desiredTenant = canonical
	}

	// Only superadmins bypass the membership check - see workspace_permissions.go.
	// A plain UserRoleAdmin (every fresh signup) must still hold an org_membership
	// on the target tenant to switch to it; otherwise tenant isolation is gone.
	isSuperadmin := configstoreTables.NormalizeAuthUserRole(userRole) == configstoreTables.UserRoleSuperadmin
	permitted := isSuperadmin
	if !permitted && strings.TrimSpace(userID) != "" {
		// Cached membership lookup avoids re-querying on every request
		// when a multi-tenant admin is browsing across tenants.
		permitted = checkOrgMembershipCached(store, desiredTenant, userID)
	}
	if permitted {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeyActiveTenantID, desiredTenant)
	}
}

// hasWorkspaceMembershipCached returns true when the user holds a
// workspace_membership row for the given workspace. Re-uses the
// (userID, tenantID)-keyed membership cache by passing the workspaceID
// as the second key so we don't need a parallel cache structure;
// collisions with the org_membership cache are impossible because UUIDs
// don't match between workspaces.id and organizations.id.
func hasWorkspaceMembershipCached(store configstore.ConfigStore, workspaceID, userID string) bool {
	if cached, ok := globalAuthCache.getMembership(userID, workspaceID); ok {
		return cached
	}
	mem, err := store.GetWorkspaceMembership(context.Background(), workspaceID, userID)
	allowed := err == nil && mem != nil
	globalAuthCache.putMembership(userID, workspaceID, allowed)
	return allowed
}

// resolveWorkspaceLegacyTenant returns the email-keyed tenant_id used by
// the GORM tenant-scoping callback for any row scoped to the given
// workspace. The chain is:
//
//	workspaces.id  →  workspaces.created_by  →  auth_users.tenant_id
//
// The created_by user is the workspace's first admin; their email-keyed
// tenant_id is the partition all the workspace's rows (providers, keys,
// logs, routing rules, virtual keys) were stamped with at creation
// time. So returning that value lets a cross-tenant invitee read those
// rows when an active workspace is in scope. Cached via
// globalAuthCache.workspaces - the same cache that already memoises
// (workspace_id → org_id, tenant_id) for permission helpers.
func resolveWorkspaceLegacyTenant(store configstore.ConfigStore, workspaceID string) string {
	// We extend the existing workspaceCacheEntry hit path: the cached
	// "tenantID" there is the workspaces.org_id (UUID-based parent
	// tenant), NOT the legacy email partition. So a hit on that cache
	// doesn't give us what we want; instead, do a direct lookup and
	// memoise via a small in-process map keyed by workspaceID.
	//
	// Trade-off: one extra DB lookup the FIRST time a user hits a
	// non-home workspace, then cache-hits for subsequent requests.
	if v, ok := workspaceLegacyTenantCache.Load(workspaceID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	ws, err := store.GetWorkspaceByID(context.Background(), workspaceID)
	if err != nil || ws == nil {
		return ""
	}
	createdBy := strings.TrimSpace(ws.CreatedBy)
	if createdBy == "" {
		return ""
	}
	owner, err := store.GetUserByID(context.Background(), createdBy)
	if err != nil || owner == nil {
		return ""
	}
	tenantID := strings.TrimSpace(owner.TenantID)
	if tenantID != "" {
		workspaceLegacyTenantCache.Store(workspaceID, tenantID)
	}
	return tenantID
}

// workspaceLegacyTenantCache memoises (workspaceID → email-keyed
// tenant_id) lookups. sync.Map for lock-free reads on the hot path;
// no expiry needed since the relationship is immutable.
var workspaceLegacyTenantCache sync.Map

// activeTenantFromCtx returns the active 3-tier tenant chosen by the
// scope switcher, falling back to the session's home tenant when no
// override is in effect. Permission helpers should call this instead of
// reading DeepIntShieldContextKeyTenantID directly so they observe the
// switched scope without disturbing the legacy email-keyed partition.
func activeTenantFromCtx(ctx *fasthttp.RequestCtx) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyActiveTenantID).(string); ok {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	if v, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// checkOrgMembershipCached caches "user X has membership on tenant Y"
// answers for ~60s in the same auth cache that already memoises session
// → user identity. The cache key is "<userID>:<tenantID>"; positive and
// negative results are both cached so repeated unauthorised header
// attempts don't hammer the DB either.
func checkOrgMembershipCached(store configstore.ConfigStore, tenantID, userID string) bool {
	if cached, ok := globalAuthCache.getMembership(userID, tenantID); ok {
		return cached
	}
	mem, err := store.GetOrgMembership(context.Background(), tenantID, userID)
	allowed := err == nil && mem != nil
	globalAuthCache.putMembership(userID, tenantID, allowed)
	return allowed
}

func lookupSessionUserRole(store configstore.ConfigStore, userID string) (string, bool) {
	if store == nil || strings.TrimSpace(userID) == "" {
		return "", false
	}

	defer func() {
		if recover() != nil {
		}
	}()

	user, err := store.GetUserByID(context.Background(), userID)
	if err != nil || user == nil {
		return "", false
	}
	return configstoreTables.NormalizeAuthUserRole(user.Role), true
}

func currentSessionUserRole(ctx *fasthttp.RequestCtx) string {
	if ctx == nil {
		return ""
	}
	return strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyUserRole)))
}

func shouldAllowViewerRequest(ctx *fasthttp.RequestCtx) bool {
	if ctx == nil {
		return false
	}

	method := string(ctx.Method())
	path := string(ctx.Path())
	if method == fasthttp.MethodHead {
		method = fasthttp.MethodGet
	}

	// Viewers are read-only by definition. Allow every GET (and HEAD,
	// which canonicalises to GET above) - per-resource access control
	// inside each handler (CanReadWorkspace / CanManageTenant / tenant-
	// scope GORM callback) is what actually gates which rows the viewer
	// can see; the role is just the mutation boundary. Without this,
	// the dashboard turns into a maze of 403s as the UI calls /api/
	// governance/teams, /api/virtual-keys, /api/customers, etc. to
	// hydrate widgets the viewer is expected to look at.
	if method == fasthttp.MethodGet {
		return true
	}

	// Mutations a viewer is allowed to make: just sign-out and the
	// websocket-handshake ticket. Everything else (create / update /
	// delete) requires a higher role.
	return method == fasthttp.MethodPost && (path == "/api/session/logout" || path == "/api/session/ws-ticket")
}

func enforceViewerPermissions(ctx *fasthttp.RequestCtx) bool {
	if currentSessionUserRole(ctx) != configstoreTables.UserRoleViewer {
		return false
	}
	if shouldAllowViewerRequest(ctx) {
		return false
	}

	SendError(ctx, fasthttp.StatusForbidden, "Viewer access is read-only and limited to logs and dashboards")
	return true
}

// authResolutionRoutes are unauthenticated endpoints whose job is to
// identify which tenant the caller belongs to (Google/Entra/email
// sign-in, signup, email verification). Stamping a tenant on the
// request context here is harmful: the GORM tenant-scoping callback
// would filter the auth_users / sessions lookup by that tenant, miss
// the row when it doesn't match, and push the caller into a
// duplicate-account creation path. Since auth_users.google_subject
// (and the email + entra_subject indexes) are global unique indexes,
// the duplicate then surfaces as a 500 instead of resolving to the
// existing identity.
//
// The handlers themselves know which tenant the user belongs to by
// the time they call createSessionAndSetCookie / recordLegalConsent,
// so skipping the upfront stamping costs nothing.
var authResolutionRoutes = map[string]struct{}{
	"/api/session/signup":              {},
	"/api/session/login":               {},
	"/api/session/google":              {},
	"/api/session/entra/start":         {},
	"/api/session/entra/callback":      {},
	"/api/session/verify-email":        {},
	"/api/session/resend-verification": {},
}

func isAuthResolutionRoute(path string) bool {
	_, ok := authResolutionRoutes[path]
	return ok
}

// tryAttachSessionIdentity opportunistically attaches the logged-in dashboard
// session to the request context without enforcing authentication.
//
// This is important for tenant isolation when auth is disabled globally or
// explicitly skipped for a route, because logged-in browser requests should
// still resolve to the user's email-scoped tenant partition.
func tryAttachSessionIdentity(ctx *fasthttp.RequestCtx, store configstore.ConfigStore, wsTicketStore *WSTicketStore) bool {
	if ctx == nil || store == nil {
		return false
	}

	if strings.EqualFold(string(ctx.Request.Header.Peek("Upgrade")), "websocket") {
		path := string(ctx.Path())
		if !isInferenceWSEndpoint(path) {
			if ticket := string(ctx.Request.URI().QueryArgs().Peek("ticket")); ticket != "" && wsTicketStore != nil {
				if sessionToken := wsTicketStore.Consume(ticket); sessionToken != "" && validateSession(ctx, store, sessionToken) {
					ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, sessionToken)
					return true
				}
			}
			if token := string(ctx.Request.URI().QueryArgs().Peek("token")); token != "" && validateSession(ctx, store, token) {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, token)
				return true
			}
		}
	}

	authorization := strings.TrimSpace(string(ctx.Request.Header.Peek("Authorization")))
	if strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		token := strings.TrimSpace(authorization[7:])
		if token != "" && validateSession(ctx, store, token) {
			ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, token)
			return true
		}
	}

	if cookieToken := string(ctx.Request.Header.Cookie("token")); cookieToken != "" && validateSession(ctx, store, cookieToken) {
		ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, cookieToken)
		return true
	}

	return false
}

type singleTenantResolver interface {
	GetSingleTenantID(ctx context.Context) (string, error)
}

// tryAttachSingleTenantIdentity attaches the only configured tenant when auth is
// disabled and the local stack has exactly one dashboard workspace. This keeps
// config APIs reading the DB-backed tenant scope even when there is no active
// session cookie to provide tenant context.
func tryAttachSingleTenantIdentity(ctx *fasthttp.RequestCtx, store configstore.ConfigStore) bool {
	if ctx == nil || store == nil {
		return false
	}

	if tenantID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID))); tenantID != "" {
		return false
	}

	resolver, ok := store.(singleTenantResolver)
	if !ok {
		return false
	}

	tenantID, err := resolver.GetSingleTenantID(context.Background())
	if err != nil {
		return false
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false
	}

	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, tenantID)
	return true
}

// isInferenceWSEndpoint returns true for WebSocket endpoints that should use
// standard inference auth (Bearer/Basic/VK) rather than dashboard session tokens.
func isInferenceWSEndpoint(path string) bool {
	return path == "/v1/responses" || path == "/v1/realtime"
}

// AuthMiddleware is a middleware that handles authentication for the API.
type AuthMiddleware struct {
	store         configstore.ConfigStore
	authConfig    atomic.Pointer[configstore.AuthConfig]
	wsTicketStore *WSTicketStore
}

// InitAuthMiddleware initializes the auth middleware.
func InitAuthMiddleware(store configstore.ConfigStore, wsTicketStore *WSTicketStore) (*AuthMiddleware, error) {
	if store == nil {
		return nil, fmt.Errorf("store is not present")
	}
	authConfig, err := store.GetAuthConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get auth config from store: %v", err)
	}
	am := &AuthMiddleware{
		store:         store,
		authConfig:    atomic.Pointer[configstore.AuthConfig]{},
		wsTicketStore: wsTicketStore,
	}
	am.authConfig.Store(authConfig)
	return am, nil
}

func (m *AuthMiddleware) UpdateAuthConfig(authConfig *configstore.AuthConfig) {
	m.authConfig.Store(authConfig)
}

// InferenceMiddleware is for inference requests (including MCP routes) if authConfig is set, it will skip authentication if disableAuthOnInference is true.
func (m *AuthMiddleware) InferenceMiddleware() schemas.DeepIntShieldHTTPMiddleware {
	return m.middleware(func(authConfig *configstore.AuthConfig, url string) bool {
		return authConfig.DisableAuthOnInference
	})
}

// APIMiddleware is for API requests if authConfig is set, it will verify authentication based on the request type.
// Three authentication methods are supported:
//   - Basic auth: Uses username + password validation (no session tracking). Used for inference API calls.
//   - Bearer token: Uses session validation via validateSession(). Used for dashboard calls.
//   - WebSocket: Uses session validation via validateSession() with token from query parameters.
//
// Basic auth may be acceptable for limited use cases, while Bearer and WebSocket flows provide
// session-based authentication suitable for production environments.
func (m *AuthMiddleware) APIMiddleware() schemas.DeepIntShieldHTTPMiddleware {
	whitelistedRoutes := []string{
		"/api/session/is-auth-enabled",
		"/api/session/invitation",
		"/api/session/signup",
		"/api/session/login",
		"/api/session/google",
		"/api/session/entra/connections",
		"/api/session/entra/start",
		"/api/session/entra/callback",
		// Generic SSO (Okta / Auth0 / Google-via-SSO / Generic OIDC) -
		// Phase C of SSO_IMPLEMENTATION_PLAN.md. These three need to be
		// public so an unauthenticated user on /login can list the
		// available connections, hit Start to receive the IdP redirect
		// URL, and land back on Callback with the auth code.
		"/api/session/sso/connections",
		"/api/session/sso/start",
		"/api/session/sso/callback",
		// SAML 2.0 - Phase E of SSO_IMPLEMENTATION_PLAN.md. Same
		// rationale: pre-auth listing of connections, start of the
		// AuthnRequest, and the IdP's POST to the ACS all happen before
		// the user is signed in. The {connection_id} segment is
		// covered by the prefix entries below since it's variable.
		"/api/session/saml/connections",
		"/api/session/verify-email",
		"/api/session/resend-verification",
		"/api/oauth/callback",
		"/health",
	}
	whitelistedPrefixes := []string{
		"/api/oauth/callback",
		// Per-connection SAML routes: /api/session/saml/<id>/metadata
		// /api/session/saml/<id>/login, /acs, /slo all carry a variable
		// connection_id segment so they have to match by prefix rather
		// than exact route.
		"/api/session/saml/",
	}
	return m.middleware(func(authConfig *configstore.AuthConfig, url string) bool {
		if slices.Contains(whitelistedRoutes, url) ||
			slices.IndexFunc(whitelistedPrefixes, func(prefix string) bool {
				return strings.HasPrefix(url, prefix)
			}) != -1 {
			return true
		}
		return false
	})
}

// middleware is the core authentication middleware that checks if the request should be authenticated or not.
func (m *AuthMiddleware) middleware(shouldSkip func(*configstore.AuthConfig, string) bool) schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			authConfig := m.authConfig.Load()
			path := string(ctx.Path())
			if authConfig == nil || !authConfig.IsEnabled {
				logger.Debug("auth middleware is disabled because auth config is not present or not enabled")
				ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, "")
				if !isAuthResolutionRoute(path) {
					tryAttachSessionIdentity(ctx, m.store, m.wsTicketStore)
					tryAttachSingleTenantIdentity(ctx, m.store)
				}
				next(ctx)
				return
			}
			// IMPORTANT: match the whitelist against the path only, not
			// the full RequestURI. RequestURI() includes the query
			// string ("?token=…"), so a URL like
			// /api/session/invitation?token=abc would never match the
			// whitelist entry "/api/session/invitation" via slices.Contains
			// - and an unauthenticated invitee landing on the signup
			// page got 401'd while the UI tried to fetch the invitation
			// details. Whitelist entries are paths; compare paths.
			url := path
			// We skip authorization for the login route
			if shouldSkip(authConfig, url) {
				if !isAuthResolutionRoute(path) {
					tryAttachSessionIdentity(ctx, m.store, m.wsTicketStore)
					tryAttachSingleTenantIdentity(ctx, m.store)
				}
				next(ctx)
				return
			}
			if supportsVirtualKeyAPIAuth(ctx) {
				if authorized, handled := tryAttachValidVirtualKey(ctx, m.store); handled {
					if !authorized {
						return
					}
					next(ctx)
					return
				}
			}
			// If inference is disabled, we skip authorization
			// Get the authorization header
			authorization := string(ctx.Request.Header.Peek("Authorization"))
			if authorization == "" {
				if string(ctx.Request.Header.Peek("Upgrade")) == "websocket" {
					path := string(ctx.Path())
					if isInferenceWSEndpoint(path) {
						// Inference WS endpoints (/v1/responses, /v1/realtime) use the same
						// auth as HTTP inference: Bearer/Basic headers or governance VK validation.
						// If no Authorization header, fall through to return 401 below
						// (or the shouldSkip check above already passed them through).
					} else {
						// Prefer short-lived ticket-based auth (from POST /api/session/ws-ticket)
						ticket := string(ctx.Request.URI().QueryArgs().Peek("ticket"))
						if ticket != "" && m.wsTicketStore != nil {
							sessionToken := m.wsTicketStore.Consume(ticket)
							if sessionToken != "" && validateSession(ctx, m.store, sessionToken) {
								ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, sessionToken)
								if enforceViewerPermissions(ctx) {
									return
								}
								next(ctx)
								return
							}
							SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
							return
						}
						// Fallback: legacy ?token= param (for backward compatibility)
						token := string(ctx.Request.URI().QueryArgs().Peek("token"))
						if token != "" {
							if validateSession(ctx, m.store, token) {
								ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, token)
								if enforceViewerPermissions(ctx) {
									return
								}
								next(ctx)
								return
							}
							SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
							return
						}
						// Fallback: cookie-based WS auth
						cookieToken := string(ctx.Request.Header.Cookie("token"))
						if cookieToken != "" && validateSession(ctx, m.store, cookieToken) {
							ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, cookieToken)
							if enforceViewerPermissions(ctx) {
								return
							}
							next(ctx)
							return
						}
						SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
						return
					}
				}
				// Cookie-based auth fallback: if no Authorization header, check for the HTTPOnly session cookie.
				// This supports the dashboard which relies on cookies instead of localStorage tokens.
				cookieToken := string(ctx.Request.Header.Cookie("token"))
				if cookieToken != "" && validateSession(ctx, m.store, cookieToken) {
					ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, cookieToken)
					if enforceViewerPermissions(ctx) {
						return
					}
					next(ctx)
					return
				}
				SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
				return
			}
			// Split the authorization header into the scheme and the token
			scheme, token, ok := strings.Cut(authorization, " ")
			if !ok {
				SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
				return
			}
			// Checking basic auth for inference calls
			if scheme == "Basic" {
				// Decode the base64 token
				decodedBytes, err := base64.StdEncoding.DecodeString(token)
				if err != nil {
					SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
					return
				}
				// Split the decoded token into the username and password
				username, password, ok := strings.Cut(string(decodedBytes), ":")
				if !ok {
					SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
					return
				}
				// Verify the username and password
				if authConfig.AdminUserName == nil || username != authConfig.AdminUserName.GetValue() {
					SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
					return
				}
				if authConfig.AdminPassword == nil {
					SendError(ctx, fasthttp.StatusInternalServerError, "Authentication not properly configured")
					return
				}
				compare, err := encrypt.CompareHash(authConfig.AdminPassword.GetValue(), password)
				if err != nil {
					SendError(ctx, fasthttp.StatusInternalServerError, "Internal Server Error")
					return
				}
				if !compare {
					SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
					return
				}
				// Continue with the next handler
				next(ctx)
				return
			}
			// Checking bearer auth for dashboard calls
			if scheme == "Bearer" {
				// Verify the session
				if !validateSession(ctx, m.store, token) {
					// Here we will check if its the base64 of username:password
					// This is for backward compatibility with the old auth system
					decodedBytes, err := base64.StdEncoding.DecodeString(token)
					if err != nil {
						SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
						return
					}
					username, password, ok := strings.Cut(string(decodedBytes), ":")
					if !ok {
						SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
						return
					}
					// Verify the username and password
					if authConfig.AdminUserName == nil || username != authConfig.AdminUserName.GetValue() {
						SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
						return
					}
					if authConfig.AdminPassword == nil {
						SendError(ctx, fasthttp.StatusInternalServerError, "Authentication not properly configured")
						return
					}
					compare, err := encrypt.CompareHash(authConfig.AdminPassword.GetValue(), password)
					if err != nil {
						SendError(ctx, fasthttp.StatusInternalServerError, "Internal Server Error")
						return
					}
					if !compare {
						SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
						return
					}
					// Continue with the next handler
					next(ctx)
					return
				}
				// setting up session in the request
				ctx.SetUserValue(schemas.DeepIntShieldContextKeySessionToken, token)
				if enforceViewerPermissions(ctx) {
					return
				}
				// Continue with the next handler
				next(ctx)
				return
			}
			SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		}
	}
}

// TracingMiddleware creates distributed traces for requests and forwards completed traces
// to observability plugins after the response has been written.
//
// The middleware:
// 1. Extracts parent trace ID from incoming W3C traceparent header (if present)
// 2. Creates a new trace in the store (only the lightweight trace ID is stored in context)
// 3. Calls the next handler to process the request
// 4. After response is written, asynchronously completes the trace and forwards it to observability plugins
//
// This middleware should be placed early in the middleware chain to capture the full request lifecycle.
type TracingMiddleware struct {
	tracer     atomic.Pointer[tracing.Tracer]
	obsPlugins atomic.Pointer[[]schemas.ObservabilityPlugin]
}

// NewTracingMiddleware creates a new tracing middleware
func NewTracingMiddleware(tracer *tracing.Tracer, obsPlugins []schemas.ObservabilityPlugin) *TracingMiddleware {
	tm := &TracingMiddleware{
		tracer:     atomic.Pointer[tracing.Tracer]{},
		obsPlugins: atomic.Pointer[[]schemas.ObservabilityPlugin]{},
	}
	tm.tracer.Store(tracer)
	tm.obsPlugins.Store(&obsPlugins)
	return tm
}

// SetObservabilityPlugins sets the observability plugins for the tracing middleware
func (m *TracingMiddleware) SetObservabilityPlugins(obsPlugins []schemas.ObservabilityPlugin) {
	m.obsPlugins.Store(&obsPlugins)
}

// SetTracer sets the tracer for the tracing middleware
func (m *TracingMiddleware) SetTracer(tracer *tracing.Tracer) {
	m.tracer.Store(tracer)
}

// Middleware returns the middleware function that creates distributed traces for requests and forwards completed traces
func (m *TracingMiddleware) Middleware() schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			// Skip if store is nil
			if m.tracer.Load() == nil {
				next(ctx)
				return
			}
			// Extract trace ID from W3C traceparent header (if present)
			// This is the 32-char trace ID that links all spans in a distributed trace
			inheritedTraceID := tracing.ExtractParentID(&ctx.Request.Header)
			// Create trace in store - only ID returned (trace data stays in store)
			traceID := m.tracer.Load().CreateTrace(inheritedTraceID)
			// Only trace ID goes into context (lightweight, no bloat)
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyTraceID, traceID)

			// Extract parent span ID from W3C traceparent header (if present)
			// This is the 16-char span ID from the upstream service that should be
			// set as the ParentID of our root span for proper trace linking in Datadog/etc.
			parentSpanID := tracing.ExtractTraceParentSpanID(&ctx.Request.Header)
			if parentSpanID != "" {
				ctx.SetUserValue(schemas.DeepIntShieldContextKeyParentSpanID, parentSpanID)
			}

			// Store a trace completion callback for streaming handlers to use
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyTraceCompleter, func() {
				m.completeAndFlushTrace(traceID)
			})
			// Create root span for the HTTP request
			spanCtx, rootSpan := m.tracer.Load().StartSpan(ctx, string(ctx.RequestURI()), schemas.SpanKindHTTPRequest)
			if rootSpan != nil {
				m.tracer.Load().SetAttribute(rootSpan, "http.method", string(ctx.Method()))
				m.tracer.Load().SetAttribute(rootSpan, "http.url", string(ctx.RequestURI()))
				m.tracer.Load().SetAttribute(rootSpan, "http.user_agent", string(ctx.Request.Header.UserAgent()))
				// Set root span ID in context for child span creation
				if spanID, ok := spanCtx.Value(schemas.DeepIntShieldContextKeySpanID).(string); ok {
					ctx.SetUserValue(schemas.DeepIntShieldContextKeySpanID, spanID)
				}
			}
			defer func() {
				// Record response status on the root span
				if rootSpan != nil {
					m.tracer.Load().SetAttribute(rootSpan, "http.status_code", ctx.Response.StatusCode())
					if ctx.Response.StatusCode() >= 400 {
						m.tracer.Load().EndSpan(rootSpan, schemas.SpanStatusError, fmt.Sprintf("HTTP %d", ctx.Response.StatusCode()))
					} else {
						m.tracer.Load().EndSpan(rootSpan, schemas.SpanStatusOk, "")
					}
				}
				// Check if trace completion is deferred (for streaming requests)
				// If deferred, the streaming handler will complete the trace after stream ends
				if deferred, ok := ctx.UserValue(schemas.DeepIntShieldContextKeyDeferTraceCompletion).(bool); ok && deferred {
					return
				}
				// After response written - async flush
				m.completeAndFlushTrace(traceID)
			}()

			next(ctx)
		}
	}
}

// completeAndFlushTrace completes the trace and forwards it to observability plugins.
// This is called either by the middleware defer (for non-streaming) or by streaming handlers.
func (m *TracingMiddleware) completeAndFlushTrace(traceID string) {
	go func() {
		// Clean up the stream accumulator for this trace

		// Get completed trace from store
		completedTrace := m.tracer.Load().EndTrace(traceID)
		if completedTrace == nil {
			return
		}
		// Forward to all observability plugins
		for _, plugin := range *m.obsPlugins.Load() {
			if plugin == nil {
				continue
			}
			// Call inject with a background context (request context is done)
			if err := plugin.Inject(context.Background(), completedTrace); err != nil {
				logger.Warn("observability plugin %s failed to inject trace: %v", plugin.GetName(), err)
			}
		}
		// Return trace to pool for reuse
		m.tracer.Load().ReleaseTrace(completedTrace)
	}()
}

// GetTracer returns the tracer instance for use by streaming handlers
func (m *TracingMiddleware) GetTracer() *tracing.Tracer {
	return m.tracer.Load()
}

// GetObservabilityPlugins filters and returns only observability plugins from a list of plugins.
// Uses Go type assertion to identify plugins implementing the ObservabilityPlugin interface.
func GetObservabilityPlugins(plugins []schemas.BasePlugin) []schemas.ObservabilityPlugin {
	if len(plugins) == 0 {
		return nil
	}

	obsPlugins := make([]schemas.ObservabilityPlugin, 0)
	for _, plugin := range plugins {
		if obsPlugin, ok := plugin.(schemas.ObservabilityPlugin); ok {
			obsPlugins = append(obsPlugins, obsPlugin)
		}
	}

	return obsPlugins
}
