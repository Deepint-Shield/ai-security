package awsbedrock

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/providers"
)

type Adapter struct {
	httpClient *http.Client
}

func New() *Adapter {
	return &Adapter{
		httpClient: providers.NewHTTPClient(2 * time.Second),
	}
}

func (a *Adapter) Name() string { return "aws_bedrock" }

func (a *Adapter) Evaluate(ctx context.Context, req providers.Request) ([]providers.Finding, error) {
	region := strings.TrimSpace(req.ProviderConfig.Region)
	if region == "" {
		region = providers.StringValue(req.ProviderConfig.Credentials, "region")
	}
	guardrailID := providers.StringValue(req.ProviderConfig.Credentials, "guardrail_id", "guardrail_identifier")
	guardrailVersion := providers.StringValue(req.ProviderConfig.Credentials, "guardrail_version", "version")
	accessKeyID := providers.StringValue(req.ProviderConfig.Credentials, "access_key_id", "aws_access_key_id")
	secretAccessKey := providers.StringValue(req.ProviderConfig.Credentials, "secret_access_key", "aws_secret_access_key")
	sessionToken := providers.StringValue(req.ProviderConfig.Credentials, "session_token", "aws_session_token")
	if region == "" || guardrailID == "" || guardrailVersion == "" || accessKeyID == "" || secretAccessKey == "" {
		return nil, fmt.Errorf("aws bedrock requires region, guardrail_id, guardrail_version, access_key_id, and secret_access_key")
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		return nil, nil
	}

	endpoint := strings.TrimRight(strings.TrimSpace(req.ProviderConfig.Endpoint), "/")
	if endpoint == "" {
		endpoint = "https://bedrock-runtime." + region + ".amazonaws.com"
	}
	requestPath := fmt.Sprintf("/guardrail/%s/version/%s/apply", url.PathEscape(guardrailID), url.PathEscape(guardrailVersion))
	payload := map[string]any{
		"source":      strings.ToUpper(strings.TrimSpace(req.Stage)),
		"outputScope": "INTERVENTIONS",
		"content": []map[string]any{
			{
				"text": map[string]any{
					"text": content,
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	requestURL := endpoint + requestPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if sessionToken != "" {
		httpReq.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	if err := signAWSRequest(httpReq, body, region, "bedrock", accessKeyID, secretAccessKey, sessionToken, time.Now().UTC()); err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("aws bedrock returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded struct {
		Action       string `json:"action"`
		ActionReason string `json:"actionReason"`
		Outputs      []struct {
			Text string `json:"text"`
		} `json:"outputs"`
		Assessments []struct {
			TopicPolicy struct {
				Topics []struct {
					Name     string `json:"name"`
					Type     string `json:"type"`
					Action   string `json:"action"`
					Detected bool   `json:"detected"`
				} `json:"topics"`
			} `json:"topicPolicy"`
			ContentPolicy struct {
				Filters []struct {
					Type       string `json:"type"`
					Action     string `json:"action"`
					Confidence string `json:"confidence"`
					Detected   bool   `json:"detected"`
				} `json:"filters"`
			} `json:"contentPolicy"`
			SensitiveInformationPolicy struct {
				PIIEntities []struct {
					Type   string `json:"type"`
					Action string `json:"action"`
					Match  string `json:"match"`
				} `json:"piiEntities"`
			} `json:"sensitiveInformationPolicy"`
		} `json:"assessments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	findings := make([]providers.Finding, 0)
	for _, assessment := range decoded.Assessments {
		for _, topic := range assessment.TopicPolicy.Topics {
			if !topic.Detected {
				continue
			}
			findings = append(findings, providers.Finding{
				Category:   "aws_bedrock_topic_" + strings.ToLower(strings.TrimSpace(topic.Name)),
				Severity:   "high",
				Outcome:    normalizeBedrockAction(topic.Action),
				Confidence: 0.9,
				Summary:    fmt.Sprintf("AWS Bedrock Guardrails flagged topic %s", topic.Name),
				Details: map[string]any{
					"topic":  topic.Name,
					"type":   topic.Type,
					"action": topic.Action,
				},
			})
		}
		for _, filter := range assessment.ContentPolicy.Filters {
			if !filter.Detected {
				continue
			}
			findings = append(findings, providers.Finding{
				Category:   "aws_bedrock_content_" + strings.ToLower(strings.TrimSpace(filter.Type)),
				Severity:   confidenceToSeverity(filter.Confidence),
				Outcome:    normalizeBedrockAction(filter.Action),
				Confidence: confidenceToFloat(filter.Confidence),
				Summary:    fmt.Sprintf("AWS Bedrock Guardrails content policy matched %s", filter.Type),
				Details: map[string]any{
					"type":       filter.Type,
					"action":     filter.Action,
					"confidence": filter.Confidence,
				},
			})
		}
		for _, entity := range assessment.SensitiveInformationPolicy.PIIEntities {
			findings = append(findings, providers.Finding{
				Category:   "aws_bedrock_pii_" + strings.ToLower(strings.TrimSpace(entity.Type)),
				Severity:   "high",
				Outcome:    normalizeBedrockAction(entity.Action),
				Confidence: 0.92,
				Summary:    fmt.Sprintf("AWS Bedrock Guardrails detected sensitive information %s", entity.Type),
				Details: map[string]any{
					"type":   entity.Type,
					"action": entity.Action,
					"match":  entity.Match,
				},
			})
		}
	}
	if len(findings) == 0 && strings.EqualFold(decoded.Action, "GUARDRAIL_INTERVENED") {
		summary := strings.TrimSpace(decoded.ActionReason)
		if summary == "" && len(decoded.Outputs) > 0 {
			summary = decoded.Outputs[0].Text
		}
		findings = append(findings, providers.Finding{
			Category:   "aws_bedrock_guardrail_intervened",
			Severity:   "high",
			Outcome:    "deny",
			Confidence: 0.9,
			Summary:    summary,
			Details: map[string]any{
				"action":        decoded.Action,
				"action_reason": decoded.ActionReason,
				"outputs":       decoded.Outputs,
			},
		})
	}
	return findings, nil
}

func normalizeBedrockAction(action string) string {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "BLOCKED", "BLOCK", "DENY":
		return "deny"
	case "ANONYMIZED", "MASKED":
		return "redact"
	default:
		return "approval"
	}
}

func confidenceToSeverity(confidence string) string {
	switch strings.ToUpper(strings.TrimSpace(confidence)) {
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	default:
		return "low"
	}
}

func confidenceToFloat(confidence string) float64 {
	switch strings.ToUpper(strings.TrimSpace(confidence)) {
	case "HIGH":
		return 0.9
	case "MEDIUM":
		return 0.7
	default:
		return 0.55
	}
}

func signAWSRequest(req *http.Request, body []byte, region, service, accessKeyID, secretAccessKey, sessionToken string, now time.Time) error {
	hashedPayload := sha256Hex(body)
	timestamp := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	req.Header.Set("X-Amz-Date", timestamp)
	req.Header.Set("X-Amz-Content-Sha256", hashedPayload)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := req.URL.Query().Encode()
	headerKeys := make([]string, 0, len(req.Header)+1)
	for header := range req.Header {
		headerKeys = append(headerKeys, strings.ToLower(header))
	}
	headerKeys = append(headerKeys, "host")
	sort.Strings(headerKeys)
	headerKeys = uniqueStrings(headerKeys)
	canonicalHeadersBuilder := strings.Builder{}
	for _, key := range headerKeys {
		value := req.Host
		if key != "host" {
			value = req.Header.Get(key)
			if value == "" {
				value = req.Header.Get(http.CanonicalHeaderKey(key))
			}
		}
		canonicalHeadersBuilder.WriteString(key)
		canonicalHeadersBuilder.WriteByte(':')
		canonicalHeadersBuilder.WriteString(strings.Join(strings.Fields(value), " "))
		canonicalHeadersBuilder.WriteByte('\n')
	}
	signedHeaders := strings.Join(headerKeys, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeadersBuilder.String(),
		signedHeaders,
		hashedPayload,
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		timestamp,
		fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service),
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signingKey := deriveAWSV4Key(secretAccessKey, date, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set(
		"Authorization",
		fmt.Sprintf(
			"AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
			accessKeyID,
			date,
			region,
			service,
			signedHeaders,
			signature,
		),
	)
	return nil
}

// signingKeyCache caches the derived AWS SigV4 signing key. The key only
// changes when the date, region, service, or secret rotates - so caching
// by composite key eliminates 4 HMAC rounds on every request within the
// same UTC date.
var (
	signingKeyCacheMu    sync.Mutex
	signingKeyCacheKey   string
	signingKeyCacheValue []byte
)

func deriveAWSV4Key(secretAccessKey, date, region, service string) []byte {
	cacheKey := date + "/" + region + "/" + service + "/" + secretAccessKey

	signingKeyCacheMu.Lock()
	defer signingKeyCacheMu.Unlock()

	if cacheKey == signingKeyCacheKey && signingKeyCacheValue != nil {
		return signingKeyCacheValue
	}

	dateKey := hmacSHA256([]byte("AWS4"+secretAccessKey), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, service)
	derived := hmacSHA256(serviceKey, "aws4_request")

	signingKeyCacheKey = cacheKey
	signingKeyCacheValue = derived
	return derived
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	unique := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
