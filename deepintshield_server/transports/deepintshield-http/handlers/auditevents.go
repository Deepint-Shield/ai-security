package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
)

func PersistAuditLogForRequestLog(ctx context.Context, store logstore.AuditLogStore, entry *logstore.Log) error {
	if store == nil || entry == nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(entry.Status), "processing") {
		return nil
	}

	auditEntry, auditCtx, ok := buildAuditEntryFromRequestLog(ctx, entry)
	if !ok {
		return nil
	}
	return store.CreateAuditLog(auditCtx, auditEntry)
}

func PersistAuditLogForMCPToolLog(ctx context.Context, store logstore.AuditLogStore, entry *logstore.MCPToolLog) error {
	if store == nil || entry == nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(entry.Status), "processing") {
		return nil
	}

	auditEntry, auditCtx, ok := buildAuditEntryFromMCPToolLog(ctx, entry)
	if !ok {
		return nil
	}
	return store.CreateAuditLog(auditCtx, auditEntry)
}

func buildAuditEntryFromRequestLog(ctx context.Context, entry *logstore.Log) (*logstore.AuditLogEntry, context.Context, bool) {
	tenantID := resolveAuditTenantID(ctx, entry.TenantID)
	if tenantID == "" {
		return nil, nil, false
	}

	classification := classifyRuntimeRequestAudit(entry)
	actor := logstore.AuditLogActor{
		UserID:    resolveAuditUserID(ctx),
		Email:     resolveAuditActorEmail(ctx, tenantID, entry.MetadataParsed),
		IPAddress: resolveAuditActorIP(entry.MetadataParsed),
	}

	details := map[string]any{
		"provider":          entry.Provider,
		"model":             entry.Model,
		"request_object":    entry.Object,
		"request_status":    entry.Status,
		"number_of_retries": entry.NumberOfRetries,
		"fallback_index":    entry.FallbackIndex,
	}
	if entry.SelectedKeyID != "" {
		details["selected_key_id"] = entry.SelectedKeyID
	}
	if entry.SelectedKeyName != "" {
		details["selected_key_name"] = entry.SelectedKeyName
	}
	if entry.VirtualKeyID != nil && *entry.VirtualKeyID != "" {
		details["virtual_key_id"] = *entry.VirtualKeyID
	}
	if entry.VirtualKeyName != nil && *entry.VirtualKeyName != "" {
		details["virtual_key_name"] = *entry.VirtualKeyName
	}
	if entry.RoutingRuleID != nil && *entry.RoutingRuleID != "" {
		details["routing_rule_id"] = *entry.RoutingRuleID
	}
	if entry.RoutingRuleName != nil && *entry.RoutingRuleName != "" {
		details["routing_rule_name"] = *entry.RoutingRuleName
	}
	if entry.Latency != nil {
		details["latency_ms"] = *entry.Latency
	}
	if entry.Cost != nil {
		details["cost_usd"] = *entry.Cost
	}
	if entry.PromptTokens > 0 {
		details["prompt_tokens"] = entry.PromptTokens
	}
	if entry.CompletionTokens > 0 {
		details["completion_tokens"] = entry.CompletionTokens
	}
	if entry.TotalTokens > 0 {
		details["total_tokens"] = entry.TotalTokens
	}
	if entry.CachedReadTokens > 0 {
		details["cached_read_tokens"] = entry.CachedReadTokens
	}
	if len(entry.RoutingEnginesUsed) > 0 {
		details["routing_engines_used"] = entry.RoutingEnginesUsed
	}
	if entry.CacheDebugParsed != nil {
		details["cache_hit"] = entry.CacheDebugParsed.CacheHit
		if entry.CacheDebugParsed.HitType != nil && *entry.CacheDebugParsed.HitType != "" {
			details["cache_hit_type"] = *entry.CacheDebugParsed.HitType
		}
		if entry.CacheDebugParsed.Similarity != nil {
			details["cache_similarity"] = *entry.CacheDebugParsed.Similarity
		}
	}
	if entry.MetadataParsed != nil {
		details["metadata_keys"] = sortedAuditMetadataKeys(entry.MetadataParsed)
	}
	if entry.ErrorDetailsParsed != nil {
		if entry.ErrorDetailsParsed.StatusCode != nil {
			details["http_status_code"] = *entry.ErrorDetailsParsed.StatusCode
		}
		if entry.ErrorDetailsParsed.Error != nil {
			details["error_message"] = strings.TrimSpace(entry.ErrorDetailsParsed.Error.Message)
			if entry.ErrorDetailsParsed.Error.Code != nil && *entry.ErrorDetailsParsed.Error.Code != "" {
				details["error_code"] = *entry.ErrorDetailsParsed.Error.Code
			}
			if entry.ErrorDetailsParsed.Error.Type != nil && *entry.ErrorDetailsParsed.Error.Type != "" {
				details["error_type"] = *entry.ErrorDetailsParsed.Error.Type
			}
		}
	}

	storeCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
	if actor.UserID != "" {
		storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyUserID, actor.UserID)
	}

	return &logstore.AuditLogEntry{
		EventID:       runtimeAuditEventID("request_log", tenantID, entry.ID),
		Timestamp:     entry.Timestamp.UTC(),
		EventType:     classification.EventType,
		Action:        classification.Action,
		Status:        classification.Status,
		Severity:      classification.Severity,
		ResourceType:  classification.ResourceType,
		ResourceID:    classification.ResourceID,
		RequestID:     entry.ID,
		RequestPath:   entry.Object,
		RequestMethod: resolveAuditRequestMethod(entry),
		Actor:         actor,
		Details:       details,
	}, storeCtx, true
}

func buildAuditEntryFromMCPToolLog(ctx context.Context, entry *logstore.MCPToolLog) (*logstore.AuditLogEntry, context.Context, bool) {
	tenantID := resolveAuditTenantID(ctx, entry.TenantID)
	if tenantID == "" {
		return nil, nil, false
	}

	status := "success"
	severity := "low"
	action := "mcp_tool_executed"
	if strings.EqualFold(strings.TrimSpace(entry.Status), "error") {
		status = "failed"
		severity = "medium"
		action = "mcp_tool_failed"
	}

	actor := logstore.AuditLogActor{
		UserID: resolveAuditUserID(ctx),
		Email:  resolveAuditActorEmail(ctx, tenantID, entry.MetadataParsed),
	}
	if actor.IPAddress == "" {
		actor.IPAddress = resolveAuditActorIP(entry.MetadataParsed)
	}

	details := map[string]any{
		"tool_name":    entry.ToolName,
		"server_label": entry.ServerLabel,
		"tool_status":  entry.Status,
	}
	if entry.LLMRequestID != nil && *entry.LLMRequestID != "" {
		details["llm_request_id"] = *entry.LLMRequestID
	}
	if entry.VirtualKeyID != nil && *entry.VirtualKeyID != "" {
		details["virtual_key_id"] = *entry.VirtualKeyID
	}
	if entry.VirtualKeyName != nil && *entry.VirtualKeyName != "" {
		details["virtual_key_name"] = *entry.VirtualKeyName
	}
	if entry.Latency != nil {
		details["latency_ms"] = *entry.Latency
	}
	if entry.Cost != nil {
		details["cost_usd"] = *entry.Cost
	}
	if entry.MetadataParsed != nil {
		details["metadata_keys"] = sortedAuditMetadataKeys(entry.MetadataParsed)
	}
	if entry.ErrorDetailsParsed != nil {
		if entry.ErrorDetailsParsed.StatusCode != nil {
			details["http_status_code"] = *entry.ErrorDetailsParsed.StatusCode
		}
		if entry.ErrorDetailsParsed.Error != nil {
			details["error_message"] = strings.TrimSpace(entry.ErrorDetailsParsed.Error.Message)
		}
	}

	resourceID := entry.ToolName
	if entry.ServerLabel != "" {
		resourceID = fmt.Sprintf("%s:%s", entry.ServerLabel, entry.ToolName)
	}

	storeCtx := context.WithValue(context.Background(), schemas.DeepIntShieldContextKeyTenantID, tenantID)
	if actor.UserID != "" {
		storeCtx = context.WithValue(storeCtx, schemas.DeepIntShieldContextKeyUserID, actor.UserID)
	}

	return &logstore.AuditLogEntry{
		EventID:       runtimeAuditEventID("mcp_tool_log", tenantID, entry.ID),
		Timestamp:     entry.Timestamp.UTC(),
		EventType:     "data_access",
		Action:        action,
		Status:        status,
		Severity:      severity,
		ResourceType:  "mcp_gateway",
		ResourceID:    resourceID,
		RequestID:     entry.ID,
		RequestPath:   entry.ToolName,
		RequestMethod: "MCP",
		Actor:         actor,
		Details:       details,
	}, storeCtx, true
}

type runtimeAuditClassification struct {
	EventType    string
	Action       string
	Status       string
	Severity     string
	ResourceType string
	ResourceID   string
}

func classifyRuntimeRequestAudit(entry *logstore.Log) runtimeAuditClassification {
	status := "success"
	severity := "low"
	action := "model_access_allowed"
	eventType := "authorization"

	httpStatusCode := 0
	if entry.ErrorDetailsParsed != nil && entry.ErrorDetailsParsed.StatusCode != nil {
		httpStatusCode = *entry.ErrorDetailsParsed.StatusCode
	}
	errorMessage := ""
	if entry.ErrorDetailsParsed != nil && entry.ErrorDetailsParsed.Error != nil {
		errorMessage = strings.ToLower(strings.TrimSpace(entry.ErrorDetailsParsed.Error.Message))
	}

	switch {
	case strings.Contains(errorMessage, "prompt injection"):
		eventType = "security_event"
		action = "prompt_injection_attempt"
		status = "blocked"
		severity = "critical"
	case strings.Contains(errorMessage, "jailbreak"):
		eventType = "security_event"
		action = "jailbreak_attempt"
		status = "blocked"
		severity = "critical"
	case strings.Contains(errorMessage, "guardrail"):
		eventType = "security_event"
		action = "guardrail_violation"
		status = "blocked"
		severity = "high"
	case httpStatusCode == 429 || strings.Contains(errorMessage, "rate limit"):
		eventType = "security_event"
		action = "rate_limit_violation"
		status = "blocked"
		severity = "high"
	case strings.Contains(errorMessage, "budget") || strings.Contains(errorMessage, "spend limit") || strings.Contains(errorMessage, "token limit"):
		action = "budget_limit_exceeded"
		status = "blocked"
		severity = "high"
	case httpStatusCode == 401 || httpStatusCode == 403:
		action = "model_access_denied"
		status = "denied"
		severity = "high"
	case strings.EqualFold(strings.TrimSpace(entry.Status), "error"):
		action = "model_access_failed"
		status = "failed"
		if httpStatusCode >= 500 {
			severity = "high"
		} else {
			severity = "medium"
		}
	}

	resourceType := "inference"
	resourceID := entry.ID
	if entry.VirtualKeyID != nil && *entry.VirtualKeyID != "" {
		resourceType = "virtual_key"
		resourceID = *entry.VirtualKeyID
	} else if strings.TrimSpace(entry.Provider) != "" {
		resourceType = "model_provider"
		resourceID = entry.Provider
	}

	return runtimeAuditClassification{
		EventType:    eventType,
		Action:       action,
		Status:       status,
		Severity:     severity,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

func resolveAuditTenantID(ctx context.Context, fallback string) string {
	if tenantID := strings.TrimSpace(fallback); tenantID != "" {
		return tenantID
	}
	if ctx == nil {
		return ""
	}
	if tenantID, ok := ctx.Value(schemas.DeepIntShieldContextKeyTenantID).(string); ok {
		return strings.TrimSpace(tenantID)
	}
	return ""
}

func resolveAuditUserID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if userID, ok := ctx.Value(schemas.DeepIntShieldContextKeyUserID).(string); ok {
		return strings.TrimSpace(userID)
	}
	return ""
}

func resolveAuditActorEmail(ctx context.Context, tenantID string, metadata map[string]interface{}) string {
	for _, key := range []string{"actor_email", "user_email", "email", "x-user-email"} {
		if value := strings.TrimSpace(readMetadataString(metadata, key)); value != "" {
			return value
		}
	}
	if strings.Contains(tenantID, "@") {
		return tenantID
	}
	if ctx == nil {
		return ""
	}
	if raw, ok := ctx.Value(schemas.DeepIntShieldContextKeyTenantID).(string); ok && strings.Contains(raw, "@") {
		return strings.TrimSpace(raw)
	}
	return ""
}

func resolveAuditActorIP(metadata map[string]interface{}) string {
	for _, key := range []string{"ip_address", "client_ip", "x-forwarded-for"} {
		if value := strings.TrimSpace(readMetadataString(metadata, key)); value != "" {
			return value
		}
	}
	return ""
}

func readMetadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	raw, ok := metadata[key]
	if !ok {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case int:
		return strconv.Itoa(value)
	default:
		return fmt.Sprint(value)
	}
}

func resolveAuditRequestMethod(entry *logstore.Log) string {
	object := strings.ToLower(strings.TrimSpace(entry.Object))
	switch {
	case strings.Contains(object, "list"), strings.Contains(object, "retrieve"), strings.Contains(object, "download"):
		return "GET"
	case strings.Contains(object, "delete"):
		return "DELETE"
	default:
		return "POST"
	}
}

func runtimeAuditEventID(sourceType, tenantID, sourceID string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{sourceType, tenantID, sourceID}, "|")))
	return "evt_" + sourceType + "_" + hex.EncodeToString(sum[:16])
}

func sortedAuditMetadataKeys(metadata map[string]interface{}) []string {
	if len(metadata) == 0 {
		return nil
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		key = strings.TrimSpace(key)
		if key != "" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return keys
}
