package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/valyala/fasthttp"
)

type auditRequestSnapshot struct {
	Method        string
	Path          string
	Query         string
	RequestID     string
	ActorEmail    string
	ChangedFields []string
	BodyFields    map[string]any
}

func AuditLogsMiddleware(store logstore.AuditLogStore, configStore configstore.ConfigStore) schemas.DeepIntShieldHTTPMiddleware {
	if store == nil {
		return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
			return next
		}
	}

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			snapshot := captureAuditRequestSnapshot(ctx)
			next(ctx)

			entry, tenantID, ok := buildAuditLogEntry(ctx, snapshot, configStore)
			if !ok || tenantID == "" {
				return
			}

			storeCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
			if strings.TrimSpace(entry.Actor.UserID) != "" {
				storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyUserID, strings.TrimSpace(entry.Actor.UserID))
			}
			if err := store.CreateAuditLog(storeCtx, entry); err != nil {
				logger.Warn("failed to persist audit log for %s %s: %v", snapshot.Method, snapshot.Path, err)
			}
		}
	}
}

func captureAuditRequestSnapshot(ctx *fasthttp.RequestCtx) auditRequestSnapshot {
	snapshot := auditRequestSnapshot{
		Method:    string(ctx.Method()),
		Path:      string(ctx.Path()),
		Query:     string(ctx.QueryArgs().QueryString()),
		RequestID: strings.TrimSpace(string(ctx.Request.Header.Peek("X-Request-Id"))),
	}

	if requestID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyRequestID))); requestID != "" {
		snapshot.RequestID = requestID
	}

	body := ctx.PostBody()
	if len(body) == 0 || len(body) > 1<<20 {
		return snapshot
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return snapshot
	}

	snapshot.BodyFields = payload
	if email := strings.TrimSpace(readStringField(payload, "email", "user_email", "username")); email != "" {
		snapshot.ActorEmail = normalizeEmail(email)
	}
	snapshot.ChangedFields = collectChangedFields(payload)
	return snapshot
}

func buildAuditLogEntry(ctx *fasthttp.RequestCtx, snapshot auditRequestSnapshot, configStore configstore.ConfigStore) (*AuditLogEntry, string, bool) {
	path := snapshot.Path
	method := snapshot.Method
	statusCode := ctx.Response.StatusCode()

	if !shouldAuditRequest(path, method, statusCode) {
		return nil, "", false
	}

	actorUserID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyUserID)))
	actorEmail := strings.TrimSpace(snapshot.ActorEmail)
	if actorEmail == "" && actorUserID != "" && configStore != nil {
		user, err := configStore.GetUserByID(context.Background(), actorUserID)
		if err == nil && user != nil {
			actorEmail = normalizeEmail(user.Email)
		}
	}

	tenantID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID)))
	if tenantID == "" && actorEmail != "" {
		tenantID = canonicalTenantForEmail(context.Background(), configStore, actorEmail)
	}

	classification, ok := classifyAuditRequest(path, method, statusCode)
	if !ok {
		return nil, "", false
	}

	details := make(map[string]any)
	if classification.AuthMethod != "" {
		details["auth_method"] = classification.AuthMethod
	}
	if len(snapshot.ChangedFields) > 0 {
		details["changed_fields"] = snapshot.ChangedFields
	}
	if snapshot.Query != "" {
		details["query"] = snapshot.Query
	}
	if format := strings.TrimSpace(readStringField(snapshot.BodyFields, "format")); format != "" {
		details["format"] = strings.ToLower(format)
	}
	if destination := strings.TrimSpace(readStringField(snapshot.BodyFields, "destination")); destination != "" {
		details["destination"] = strings.ToLower(destination)
	}
	if statusCode >= 400 {
		details["http_status_code"] = statusCode
	}

	resourceID := classifyResourceID(path)
	entry := &AuditLogEntry{
		EventID:       "evt_" + uuid.NewString(),
		Timestamp:     time.Now().UTC(),
		EventType:     classification.EventType,
		Action:        classification.Action,
		Status:        classification.Status,
		Severity:      classification.Severity,
		ResourceType:  classification.ResourceType,
		ResourceID:    resourceID,
		RequestID:     snapshot.RequestID,
		RequestPath:   path,
		RequestMethod: method,
		Actor: AuditLogActor{
			UserID:    actorUserID,
			Email:     actorEmail,
			IPAddress: requestIPAddress(ctx),
		},
		Details: details,
	}

	return entry, tenantID, true
}

type auditClassification struct {
	EventType    string
	Action       string
	Status       string
	Severity     string
	ResourceType string
	AuthMethod   string
}

func shouldAuditRequest(path, method string, statusCode int) bool {
	switch {
	case strings.HasPrefix(path, "/api/session/"),
		strings.HasPrefix(path, "/api/oauth/"),
		strings.HasPrefix(path, "/api/scim/"),
		strings.HasPrefix(path, "/api/audit-logs"),
		strings.HasPrefix(path, "/api/logs"),
		strings.HasPrefix(path, "/api/mcp-logs"),
		strings.HasPrefix(path, "/api/providers"),
		strings.HasPrefix(path, "/api/config"),
		strings.HasPrefix(path, "/api/plugins"),
		strings.HasPrefix(path, "/api/governance"),
		strings.HasPrefix(path, "/api/mcp"),
		strings.HasPrefix(path, "/api/organization"):
		return true
	case strings.HasPrefix(path, "/v1/"):
		return statusCode == fasthttp.StatusUnauthorized || statusCode == fasthttp.StatusForbidden || statusCode == fasthttp.StatusTooManyRequests
	default:
		return false
	}
}

func classifyAuditRequest(path, method string, statusCode int) (auditClassification, bool) {
	resourceType := classifyResourceType(path)
	status := classifyAuditStatus(statusCode)
	severity := classifyAuditSeverity(statusCode, method)

	switch {
	case strings.HasPrefix(path, "/api/session/login"):
		return auditClassification{EventType: "authentication", Action: "user_login", Status: status, Severity: severity, ResourceType: "session", AuthMethod: "password"}, true
	case strings.HasPrefix(path, "/api/session/google"):
		return auditClassification{EventType: "authentication", Action: "user_login", Status: status, Severity: severity, ResourceType: "session", AuthMethod: "google"}, true
	case strings.HasPrefix(path, "/api/session/entra/start"):
		return auditClassification{EventType: "authentication", Action: "sso_redirect", Status: status, Severity: severity, ResourceType: "session", AuthMethod: "oidc"}, true
	case strings.HasPrefix(path, "/api/session/entra/callback"):
		return auditClassification{EventType: "authentication", Action: "user_login", Status: status, Severity: severity, ResourceType: "session", AuthMethod: "oidc"}, true
	case strings.HasPrefix(path, "/api/oauth/"):
		return auditClassification{EventType: "authentication", Action: "sso_redirect", Status: status, Severity: severity, ResourceType: "oidc", AuthMethod: "oidc"}, true
	case strings.HasPrefix(path, "/api/scim/provider/test") || (strings.HasPrefix(path, "/api/scim/providers/") && strings.HasSuffix(path, "/test")):
		return auditClassification{EventType: "configuration_change", Action: "oidc_tested", Status: status, Severity: severity, ResourceType: "oidc"}, true
	case strings.HasPrefix(path, "/api/scim/provider/sync") || (strings.HasPrefix(path, "/api/scim/providers/") && strings.HasSuffix(path, "/sync")):
		return auditClassification{EventType: "configuration_change", Action: "scim_sync_triggered", Status: status, Severity: severity, ResourceType: "user_provisioning"}, true
	case strings.HasPrefix(path, "/api/session/logout"):
		return auditClassification{EventType: "authentication", Action: "user_logout", Status: status, Severity: severity, ResourceType: "session"}, true
	case statusCode == fasthttp.StatusUnauthorized || statusCode == fasthttp.StatusForbidden:
		return auditClassification{EventType: "authorization", Action: "permission_denied", Status: status, Severity: "high", ResourceType: resourceType}, true
	case statusCode == fasthttp.StatusTooManyRequests:
		return auditClassification{EventType: "security_event", Action: "rate_limit_violation", Status: "blocked", Severity: "high", ResourceType: resourceType}, true
	case method == fasthttp.MethodGet && (strings.HasSuffix(path, "/download") && (strings.HasPrefix(path, "/api/audit-logs/exports/") || strings.HasPrefix(path, "/api/log-exports/"))):
		return auditClassification{EventType: "data_access", Action: "data_export_downloaded", Status: status, Severity: "medium", ResourceType: "export"}, true
	case method == fasthttp.MethodGet || method == fasthttp.MethodHead:
		action := "resource_accessed"
		if strings.HasPrefix(path, "/api/audit-logs") || strings.HasPrefix(path, "/api/logs") || strings.HasPrefix(path, "/api/mcp-logs") || strings.HasPrefix(path, "/api/log-exports") {
			action = "log_query_executed"
		}
		return auditClassification{EventType: "data_access", Action: action, Status: status, Severity: severity, ResourceType: resourceType}, true
	case method == fasthttp.MethodPost && (strings.HasPrefix(path, "/api/audit-logs/exports") || strings.HasPrefix(path, "/api/log-exports")):
		return auditClassification{EventType: "data_access", Action: "data_export_requested", Status: status, Severity: "medium", ResourceType: "export"}, true
	case method == fasthttp.MethodPost || method == fasthttp.MethodPut || method == fasthttp.MethodPatch || method == fasthttp.MethodDelete:
		return auditClassification{
			EventType:    "configuration_change",
			Action:       fmt.Sprintf("%s_%s", resourceType, mutateActionSuffix(method)),
			Status:       status,
			Severity:     maxAuditSeverity("medium", severity),
			ResourceType: resourceType,
		}, true
	default:
		return auditClassification{}, false
	}
}

func classifyAuditResourceType(path string) string {
	return classifyResourceType(path)
}

func classifyResourceType(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/governance/virtual-keys"):
		return "virtual_key"
	case strings.HasPrefix(path, "/api/governance/teams"):
		return "team"
	case strings.HasPrefix(path, "/api/governance/customers"), strings.HasPrefix(path, "/api/governance/members"):
		return "member"
	case strings.HasPrefix(path, "/api/governance/users"):
		return "user_provisioning"
	case strings.HasPrefix(path, "/api/providers"):
		return "model_provider"
	case strings.HasPrefix(path, "/api/scim"):
		return "oidc"
	case strings.HasPrefix(path, "/api/plugins"):
		return "plugin"
	case strings.HasPrefix(path, "/api/audit-logs"):
		return "audit_logs"
	case strings.HasPrefix(path, "/api/log-exports"):
		return "export"
	case strings.HasPrefix(path, "/api/logs"), strings.HasPrefix(path, "/api/mcp-logs"):
		return "logs"
	case strings.HasPrefix(path, "/api/mcp"):
		return "mcp_gateway"
	case strings.HasPrefix(path, "/api/config"):
		return "settings"
	case strings.HasPrefix(path, "/api/session"), strings.HasPrefix(path, "/api/oauth"):
		return "session"
	case strings.HasPrefix(path, "/v1/"):
		return "inference"
	default:
		return "resource"
	}
}

func classifyResourceID(path string) string {
	trimmed := strings.Trim(strings.TrimSpace(path), "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	switch last {
	case "api", "session", "oauth", "scim", "provider", "test", "sync", "audit-logs", "exports", "query", "summary", "logs", "mcp-logs", "log-exports", "download", "providers", "config", "plugins", "governance", "teams", "virtual-keys", "customers", "members", "users", "mcp", "organization", "chat", "completions", "responses", "messages":
		return ""
	default:
		return last
	}
}

func classifyAuditStatus(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "success"
	case statusCode == fasthttp.StatusUnauthorized || statusCode == fasthttp.StatusForbidden:
		return "denied"
	case statusCode == fasthttp.StatusTooManyRequests:
		return "blocked"
	case statusCode >= 500:
		return "failed"
	default:
		return "failed"
	}
}

func classifyAuditSeverity(statusCode int, method string) string {
	switch {
	case statusCode >= 500:
		return "high"
	case statusCode == fasthttp.StatusUnauthorized || statusCode == fasthttp.StatusForbidden || statusCode == fasthttp.StatusTooManyRequests:
		return "high"
	case method == fasthttp.MethodDelete || method == fasthttp.MethodPatch || method == fasthttp.MethodPut:
		return "medium"
	default:
		return "low"
	}
}

func maxAuditSeverity(left, right string) string {
	ranks := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if ranks[strings.ToLower(strings.TrimSpace(right))] > ranks[strings.ToLower(strings.TrimSpace(left))] {
		return right
	}
	return left
}

func mutateActionSuffix(method string) string {
	switch method {
	case fasthttp.MethodDelete:
		return "deleted"
	case fasthttp.MethodPatch, fasthttp.MethodPut:
		return "updated"
	default:
		return "created"
	}
}

func readStringField(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if payload == nil {
			return ""
		}
		if raw, ok := payload[key]; ok {
			if value, ok := raw.(string); ok {
				return value
			}
		}
	}
	return ""
}

func collectChangedFields(payload map[string]any) []string {
	if len(payload) == 0 {
		return nil
	}
	excluded := map[string]struct{}{
		"password":      {},
		"password_hash": {},
		"client_secret": {},
		"api_key":       {},
		"token":         {},
		"credential":    {},
		"secret":        {},
	}
	fields := make([]string, 0, len(payload))
	for key := range payload {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if _, ok := excluded[normalized]; ok {
			continue
		}
		fields = append(fields, normalized)
	}
	if len(fields) == 0 {
		return nil
	}
	sort.Strings(fields)
	return fields
}

func requestIPAddress(ctx *fasthttp.RequestCtx) string {
	if forwarded := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-For"))); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if realIP := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Real-Ip"))); realIP != "" {
		return realIP
	}
	if ctx == nil || ctx.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(ctx.RemoteAddr().String())
	if err == nil {
		return host
	}
	return ctx.RemoteAddr().String()
}
