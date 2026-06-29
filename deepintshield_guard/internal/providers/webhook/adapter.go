package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/providers"
)

type Adapter struct {
	httpClient *http.Client
}

func New() *Adapter {
	return &Adapter{
		httpClient: providers.NewHTTPClient(3 * time.Second),
	}
}

func (a *Adapter) Name() string { return "webhook" }

func (a *Adapter) Evaluate(ctx context.Context, req providers.Request) ([]providers.Finding, error) {
	endpoint := strings.TrimSpace(req.ProviderConfig.Endpoint)
	if endpoint == "" {
		endpoint = providers.StringValue(req.ProviderConfig.Credentials, "webhook_url", "url")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("webhook provider requires endpoint or credentials.webhook_url")
	}

	headers := map[string]string{}
	if rawHeaders := req.ProviderConfig.ConnectionMeta["headers"]; rawHeaders != nil {
		switch typed := rawHeaders.(type) {
		case map[string]any:
			for key, value := range typed {
				if rendered := strings.TrimSpace(fmt.Sprintf("%v", value)); rendered != "" {
					headers[key] = rendered
				}
			}
		case map[string]string:
			for key, value := range typed {
				if strings.TrimSpace(value) != "" {
					headers[key] = strings.TrimSpace(value)
				}
			}
		}
	}

	payload := map[string]any{
		"request": map[string]any{
			"text": req.Content,
		},
		"response": map[string]any{
			"text": "",
		},
		"provider":    req.Provider,
		"requestType": requestTypeForStage(req.Stage),
		"metadata":    req.Metadata,
		"eventType":   eventTypeForStage(req.Stage),
		"actor": map[string]any{
			"type":        req.Actor.Type,
			"id":          req.Actor.ID,
			"role":        req.Actor.Role,
			"customer_id": req.Actor.CustomerID,
			"team_id":     req.Actor.TeamID,
		},
	}
	if req.Stage == "output" {
		payload["request"] = map[string]any{"text": ""}
		payload["response"] = map[string]any{"text": req.Content}
	}
	if req.MCP != nil {
		payload["mcp"] = req.MCP
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("webhook provider returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded struct {
		Verdict         *bool          `json:"verdict"`
		Outcome         string         `json:"outcome"`
		Severity        string         `json:"severity"`
		Summary         string         `json:"summary"`
		Confidence      float64        `json:"confidence"`
		Details         map[string]any `json:"details"`
		TransformedData struct {
			Request struct {
				Text string `json:"text"`
			} `json:"request"`
			Response struct {
				Text string `json:"text"`
			} `json:"response"`
		} `json:"transformedData"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	verdict := true
	if decoded.Verdict != nil {
		verdict = *decoded.Verdict
	}
	if verdict && strings.TrimSpace(decoded.Outcome) == "" {
		return nil, nil
	}

	outcome := normalizeWebhookOutcome(decoded.Outcome)
	if !verdict && outcome == "allow" {
		outcome = "deny"
	}
	summary := strings.TrimSpace(decoded.Summary)
	if summary == "" {
		summary = "Webhook guardrail detected a violation"
	}
	details := decoded.Details
	if details == nil {
		details = map[string]any{}
	}
	if req.Stage == "input" && strings.TrimSpace(decoded.TransformedData.Request.Text) != "" {
		details["sanitized_input"] = decoded.TransformedData.Request.Text
	}
	if req.Stage == "output" && strings.TrimSpace(decoded.TransformedData.Response.Text) != "" {
		details["sanitized_output"] = decoded.TransformedData.Response.Text
	}

	return []providers.Finding{{
		Category:   "webhook_guardrail",
		Severity:   normalizeWebhookSeverity(decoded.Severity),
		Outcome:    outcome,
		Summary:    summary,
		Confidence: normalizeWebhookConfidence(decoded.Confidence),
		Details:    details,
	}}, nil
}

func eventTypeForStage(stage string) string {
	if strings.EqualFold(strings.TrimSpace(stage), "output") {
		return "afterRequestHook"
	}
	return "beforeRequestHook"
}

func requestTypeForStage(stage string) string {
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "mcp", "action":
		return "tool"
	case "rag":
		return "retrieve"
	default:
		return "chatComplete"
	}
}

func normalizeWebhookOutcome(outcome string) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "deny", "block":
		return "deny"
	case "redact", "allow_with_redaction":
		return "redact"
	case "approval", "human_approval", "review":
		return "approval"
	case "sandbox":
		return "sandbox"
	default:
		return "allow"
	}
}

func normalizeWebhookSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func normalizeWebhookConfidence(confidence float64) float64 {
	if confidence > 0 {
		return confidence
	}
	return 0.85
}
