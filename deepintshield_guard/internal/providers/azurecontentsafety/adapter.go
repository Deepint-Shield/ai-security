package azurecontentsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/providers"
)

const apiVersion = "2024-09-01"

type Adapter struct {
	httpClient *http.Client
}

func New() *Adapter {
	return &Adapter{
		httpClient: providers.NewHTTPClient(2 * time.Second),
	}
}

func (a *Adapter) Name() string { return "azure_content_safety" }

func (a *Adapter) Evaluate(ctx context.Context, req providers.Request) ([]providers.Finding, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(req.ProviderConfig.Endpoint), "/")
	if endpoint == "" {
		endpoint = strings.TrimRight(providers.StringValue(req.ProviderConfig.Credentials, "endpoint"), "/")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("azure content safety endpoint is not configured")
	}
	apiKey := providers.StringValue(req.ProviderConfig.Credentials, "api_key", "key")
	if apiKey == "" {
		return nil, fmt.Errorf("azure content safety API key is not configured")
	}
	if strings.TrimSpace(req.Content) == "" {
		return nil, nil
	}

	u, err := url.Parse(endpoint + "/contentsafety/text:analyze")
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", apiVersion)
	u.RawQuery = query.Encode()

	payload := map[string]any{
		"text":       req.Content,
		"outputType": "FourSeverityLevels",
	}
	if categories := providers.StringSliceValue(req.Policy.Definition["azure_categories"]); len(categories) > 0 {
		payload["categories"] = categories
	}
	if blocklists := providers.StringSliceValue(req.Policy.Definition["azure_blocklists"]); len(blocklists) > 0 {
		payload["blocklistNames"] = blocklists
		payload["haltOnBlocklistHit"] = false
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Ocp-Apim-Subscription-Key", apiKey)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("azure content safety returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded struct {
		CategoriesAnalysis []struct {
			Category string `json:"category"`
			Severity int    `json:"severity"`
		} `json:"categoriesAnalysis"`
		BlocklistsMatch []struct {
			BlocklistName string `json:"blocklistName"`
			Offset        int    `json:"offset"`
			Length        int    `json:"length"`
		} `json:"blocklistsMatch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	findings := make([]providers.Finding, 0, len(decoded.CategoriesAnalysis)+len(decoded.BlocklistsMatch))
	for _, category := range decoded.CategoriesAnalysis {
		if category.Severity < 2 {
			continue
		}
		outcome := "redact"
		severity := "medium"
		switch {
		case category.Severity >= 4:
			outcome = "deny"
			severity = "critical"
		case category.Severity == 3:
			outcome = "approval"
			severity = "high"
		}
		findings = append(findings, providers.Finding{
			Category:   "azure_content_safety_" + strings.ToLower(strings.TrimSpace(category.Category)),
			Severity:   severity,
			Outcome:    outcome,
			Confidence: float64(category.Severity) / 4.0,
			Summary:    fmt.Sprintf("Azure Content Safety flagged %s with severity %d", category.Category, category.Severity),
			Details: map[string]any{
				"category": category.Category,
				"severity": category.Severity,
			},
		})
	}
	for _, match := range decoded.BlocklistsMatch {
		findings = append(findings, providers.Finding{
			Category:   "azure_blocklist_match",
			Severity:   "high",
			Outcome:    "deny",
			Confidence: 0.95,
			Summary:    fmt.Sprintf("Azure Content Safety matched blocklist %s", match.BlocklistName),
			Details: map[string]any{
				"blocklist_name": match.BlocklistName,
				"offset":         match.Offset,
				"length":         match.Length,
			},
		})
	}
	return findings, nil
}
