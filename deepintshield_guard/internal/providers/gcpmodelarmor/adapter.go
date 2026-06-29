package gcpmodelarmor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/providers"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Adapter struct {
	httpClient *http.Client

	// Token source cache: avoids re-deriving JWT on every Evaluate call.
	mu             sync.Mutex
	cachedKeyHash  [32]byte
	cachedTokenSrc oauth2.TokenSource
}

func New() *Adapter {
	return &Adapter{
		httpClient: providers.NewHTTPClient(2 * time.Second),
	}
}

func (a *Adapter) Name() string { return "gcp_model_armor" }

func (a *Adapter) Evaluate(ctx context.Context, req providers.Request) ([]providers.Finding, error) {
	projectID := providers.StringValue(req.ProviderConfig.Credentials, "project_id")
	location := strings.TrimSpace(req.ProviderConfig.Region)
	if location == "" {
		location = providers.StringValue(req.ProviderConfig.Credentials, "location", "region")
	}
	templateID := providers.StringValue(req.ProviderConfig.Credentials, "template_id", "template")
	if projectID == "" || location == "" || templateID == "" {
		return nil, fmt.Errorf("gcp model armor requires project_id, location, and template_id")
	}
	accessToken, err := a.gcpAccessToken(ctx, req.ProviderConfig.Credentials)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, nil
	}

	operation := "sanitizeUserPrompt"
	payload := map[string]any{"userPromptData": map[string]any{"text": content}}
	if strings.EqualFold(req.Stage, "output") {
		operation = "sanitizeModelResponse"
		payload = map[string]any{"text": content}
	}
	if multiLingual, ok := req.Policy.Definition["enable_multi_language_detection"].(bool); ok && multiLingual {
		payload["multiLanguageDetectionMetadata"] = map[string]any{"enableMultiLanguageDetection": true}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf(
		"https://modelarmor.%s.rep.googleapis.com/v1/projects/%s/locations/%s/templates/%s:%s",
		location,
		projectID,
		location,
		templateID,
		operation,
	)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("gcp model armor returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded struct {
		SanitizationResult struct {
			FilterMatchState string                   `json:"filterMatchState"`
			InvocationResult string                   `json:"invocationResult"`
			FilterResults    []map[string]interface{} `json:"filterResults"`
		} `json:"sanitizationResult"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	if !strings.EqualFold(decoded.SanitizationResult.FilterMatchState, "MATCH_FOUND") {
		return nil, nil
	}

	findings := make([]providers.Finding, 0, len(decoded.SanitizationResult.FilterResults))
	for _, item := range decoded.SanitizationResult.FilterResults {
		for category, raw := range item {
			rendered, _ := json.Marshal(raw)
			outcome := "redact"
			severity := "medium"
			confidence := 0.78
			if strings.Contains(strings.ToLower(category), "jailbreak") || strings.Contains(strings.ToLower(category), "malicious") {
				outcome = "deny"
				severity = "high"
				confidence = 0.9
			}
			findings = append(findings, providers.Finding{
				Category:   "gcp_model_armor_" + strings.ToLower(strings.TrimSpace(category)),
				Severity:   severity,
				Outcome:    outcome,
				Confidence: confidence,
				Summary:    fmt.Sprintf("Google Model Armor matched filter %s", category),
				Details: map[string]any{
					"invocation_result": decoded.SanitizationResult.InvocationResult,
					"filter_result":     json.RawMessage(rendered),
				},
			})
		}
	}
	return findings, nil
}

// gcpAccessToken returns a valid GCP access token, caching the token source
// so that JWT signing only happens on first call or when credentials change.
// oauth2.ReuseTokenSource handles token expiry/refresh automatically.
func (a *Adapter) gcpAccessToken(ctx context.Context, credentials map[string]any) (string, error) {
	if token := providers.StringValue(credentials, "access_token", "bearer_token"); token != "" {
		return token, nil
	}
	serviceAccountJSON := providers.JSONString(credentials, "service_account_json", "credentials_json")
	if serviceAccountJSON == "" {
		return "", fmt.Errorf("gcp model armor access_token or service_account_json is required")
	}

	keyHash := sha256.Sum256([]byte(serviceAccountJSON))

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cachedTokenSrc != nil && a.cachedKeyHash == keyHash {
		token, err := a.cachedTokenSrc.Token()
		if err == nil && token != nil && strings.TrimSpace(token.AccessToken) != "" {
			return token.AccessToken, nil
		}
		// Token source failed - rebuild it below.
	}

	baseSource, err := google.JWTAccessTokenSourceFromJSON([]byte(serviceAccountJSON), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return "", fmt.Errorf("failed to create gcp token source: %w", err)
	}
	reusable := oauth2.ReuseTokenSource(nil, baseSource)
	a.cachedKeyHash = keyHash
	a.cachedTokenSrc = reusable

	token, err := reusable.Token()
	if err != nil {
		return "", fmt.Errorf("failed to fetch gcp access token: %w", err)
	}
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return "", fmt.Errorf("gcp token source returned an empty access token")
	}
	return token.AccessToken, nil
}
