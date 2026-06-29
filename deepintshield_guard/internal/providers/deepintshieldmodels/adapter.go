package deepintshieldmodels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/providers"
)

// defaultModelsEndpoint is the in-cluster sidecar URL used when neither the
// provider config nor DEEPINTSHIELD_MODELS_ENDPOINT supplies one. Matches the
// compose service DNS so a fresh `docker compose up` works without the
// operator having to fill in any field on the UI provider form.
const defaultModelsEndpoint = "http://deepintshield-models:8093"

type Adapter struct {
	httpClient *http.Client
}

func New() *Adapter {
	// 30s HTTP budget. The sidecar's first-call latency is dominated by
	// PyTorch JIT + tokenizer init on detectors that weren't preloaded
	// (warm path is sub-300ms once everything's resident). Three seconds
	// - the previous value - was reliably truncating cold starts on CPU
	// images that batch four or more detectors per request, surfacing as
	// "context deadline exceeded" in the runtime decision chain. The
	// runtime engine still enforces its own per-policy timeout above
	// this, so this number is the ceiling, not the typical wait.
	return &Adapter{
		httpClient: providers.NewHTTPClient(30 * time.Second),
	}
}

func (a *Adapter) Name() string { return "deepintshield_models" }

func (a *Adapter) Evaluate(ctx context.Context, req providers.Request) ([]providers.Finding, error) {
	// Endpoint resolution order:
	//   1. ProviderConfig.Endpoint (operator-supplied via API)
	//   2. ProviderConfig.Credentials.service_url / url / endpoint (legacy)
	//   3. DEEPINTSHIELD_MODELS_ENDPOINT env (deployment-time default - the
	//      preferred slot now that the UI no longer asks for it)
	//   4. Compose default (works on fresh dev boxes)
	endpoint := strings.TrimSpace(req.ProviderConfig.Endpoint)
	if endpoint == "" {
		endpoint = providers.StringValue(req.ProviderConfig.Credentials, "service_url", "url", "endpoint")
	}
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("DEEPINTSHIELD_MODELS_ENDPOINT"))
	}
	if endpoint == "" {
		endpoint = defaultModelsEndpoint
	}
	endpoint = strings.TrimRight(endpoint, "/")
	if !strings.HasSuffix(endpoint, "/v1/evaluate") {
		endpoint += "/v1/evaluate"
	}

	detectors := providers.StringSliceValue(req.ProviderConfig.ConnectionMeta["detectors"])
	if len(detectors) == 0 {
		detectors = providers.StringSliceValue(req.Policy.Metadata["model_detectors"])
	}

	payload := map[string]any{
		"tenant_id": req.TenantID,
		"stage":     req.Stage,
		"model":     req.Model,
		"provider":  req.Provider,
		"text":      req.Content,
		"detectors": detectors,
		"metadata":  req.Metadata,
		"actor": map[string]any{
			"type":        req.Actor.Type,
			"id":          req.Actor.ID,
			"role":        req.Actor.Role,
			"customer_id": req.Actor.CustomerID,
			"team_id":     req.Actor.TeamID,
		},
		"policy": map[string]any{
			"id":               req.Policy.PolicyID,
			"version_id":       req.Policy.PolicyVersionID,
			"name":             req.Policy.Name,
			"scope":            req.Policy.Scope,
			"enforcement_mode": req.Policy.EnforcementMode,
			"metadata":         req.Policy.Metadata,
		},
		"provider_config": map[string]any{
			"id":              req.ProviderConfig.ID,
			"name":            req.ProviderConfig.Name,
			"provider_type":   req.ProviderConfig.ProviderType,
			"connection_meta": req.ProviderConfig.ConnectionMeta,
		},
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

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("deepintshield_models returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded struct {
		Findings []struct {
			Detector   string         `json:"detector"`
			Category   string         `json:"category"`
			Severity   string         `json:"severity"`
			Outcome    string         `json:"outcome"`
			Summary    string         `json:"summary"`
			Confidence float64        `json:"confidence"`
			Details    map[string]any `json:"details"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	findings := make([]providers.Finding, 0, len(decoded.Findings))
	for _, finding := range decoded.Findings {
		category := strings.TrimSpace(finding.Category)
		if category == "" {
			category = "model_" + strings.TrimSpace(strings.ToLower(finding.Detector))
		}
		summary := strings.TrimSpace(finding.Summary)
		if summary == "" {
			summary = fmt.Sprintf("%s detector flagged the content", strings.TrimSpace(finding.Detector))
		}
		details := finding.Details
		if details == nil {
			details = map[string]any{}
		}
		if strings.TrimSpace(finding.Detector) != "" {
			details["detector"] = finding.Detector
		}
		findings = append(findings, providers.Finding{
			Category:   category,
			Severity:   strings.TrimSpace(finding.Severity),
			Outcome:    strings.TrimSpace(finding.Outcome),
			Summary:    summary,
			Confidence: finding.Confidence,
			Details:    details,
		})
	}
	// Pass through the originally requested detector list so the dedupe
	// step can apply precedence: when a precise detector is enabled and
	// did NOT trigger, an over-aggressive sibling in the same group
	// (e.g. jailbreak_detector firing while prompt_injection stays
	// silent) is treated as a false positive and dropped.
	return dedupeOverlappingDetectors(findings, detectors), nil
}

// concernByDetector maps each ML detector name to its coarse "concern"
// bucket. Detectors in the same bucket overlap in what they catch - the
// dedupeOverlappingDetectors logic uses these groupings to drop redundant
// findings so operators can enable all 8 detectors without surfacing 3-5
// near-identical blocks per request.
var concernByDetector = map[string]string{
	"prompt_injection":   "prompt_injection",
	"jailbreak_detector": "prompt_injection",
	"toxicity":           "toxicity",
	"hate_speech":        "toxicity",
	"content_moderation": "toxicity",
	"pii":                "pii",
	"pii_extended":       "pii",
}

// preciseDetectorByConcern picks the AUTHORITATIVE detector per concern -
// the one whose presence-or-absence settles the verdict for the group.
// Rationale per README:
//   - prompt_injection: ProtectAI DeBERTa is balanced; jailbreak_detector
//     over-flags directive-style prompts at 0.9+ confidence.
//   - toxicity: Unitary's multi-label model is the documented baseline;
//     hate_speech / content_moderation are narrower complements.
//   - pii: BERT-small PII is opt-in due to business-data false-positives;
//     pii_extended even more so. When pii_extended (the broader) fires
//     but pii (the more conservative) did not, treat as false positive.
var preciseDetectorByConcern = map[string]string{
	"prompt_injection": "prompt_injection",
	"toxicity":         "toxicity",
	"pii":              "pii",
}

func concernOfFinding(f providers.Finding) string {
	if name, ok := f.Details["detector"].(string); ok {
		if c, ok := concernByDetector[strings.ToLower(strings.TrimSpace(name))]; ok {
			return c
		}
	}
	cat := strings.ToLower(strings.TrimSpace(f.Category))
	switch {
	case strings.HasPrefix(cat, "prompt_injection"):
		return "prompt_injection"
	case strings.HasPrefix(cat, "toxicity") || strings.HasPrefix(cat, "hate_speech"):
		return "toxicity"
	case strings.HasPrefix(cat, "pii"):
		return "pii"
	}
	return ""
}

// dedupeOverlappingDetectors collapses findings from multiple ML detectors
// that target the same concern into one finding per concern. Two-pass:
//
//  1. False-positive suppression: when the AUTHORITATIVE detector for a
//     concern was REQUESTED but didn't fire, drop every other detector's
//     finding in the same concern. The over-aggressive detectors in the
//     group (jailbreak_detector for prompt_injection; pii_extended for pii)
//     are systematically biased - when the precise sibling stays silent,
//     a sole fire from the broader detector is almost always a false
//     positive on directive prompts or operational business data.
//  2. Confidence collapse: of the remaining findings per concern, keep
//     the one with highest confidence. Track which sibling detectors
//     agreed in Details["concurring_detectors"] so the AI Logs detail
//     panel can still surface the full picture.
//
// Findings outside any known concern pass through unchanged so custom
// detectors are unaffected by this dedupe.
func dedupeOverlappingDetectors(findings []providers.Finding, requestedDetectors []string) []providers.Finding {
	if len(findings) == 0 {
		return findings
	}
	// Note: do NOT early-return on len==1. A single over-aggressive
	// detector firing while its precise sibling stayed silent is THE
	// canonical false-positive case the suppression pass below targets
	// - checking the >=2 case here would defeat the dedupe for the most
	// common false-positive scenario (just jailbreak_detector firing on
	// a directive-style prompt, while ProtectAI prompt_injection stayed
	// silent and was the authoritative classifier the operator asked for).
	requested := make(map[string]struct{}, len(requestedDetectors))
	for _, name := range requestedDetectors {
		requested[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	firedByConcern := make(map[string]bool, 4)
	for _, f := range findings {
		if c := concernOfFinding(f); c != "" {
			if name, ok := f.Details["detector"].(string); ok {
				if precise, hasPrecise := preciseDetectorByConcern[c]; hasPrecise {
					if strings.EqualFold(strings.TrimSpace(name), precise) {
						firedByConcern[c] = true
					}
				}
			}
		}
	}
	// Pass 1: drop over-aggressive findings whose precise sibling was
	// asked but stayed silent.
	filtered := make([]providers.Finding, 0, len(findings))
	for _, f := range findings {
		concern := concernOfFinding(f)
		if concern == "" {
			filtered = append(filtered, f)
			continue
		}
		precise, hasPrecise := preciseDetectorByConcern[concern]
		if hasPrecise {
			_, preciseRequested := requested[precise]
			if preciseRequested && !firedByConcern[concern] {
				if name, ok := f.Details["detector"].(string); ok && !strings.EqualFold(strings.TrimSpace(name), precise) {
					// Drop: the authoritative detector ran and didn't
					// flag, so a sibling firing is treated as false
					// positive. Skipping the append keeps the finding
					// out of the response entirely.
					continue
				}
			}
		}
		filtered = append(filtered, f)
	}
	// Pass 2: highest-confidence keep per concern.
	bestByConcern := make(map[string]int, 4)
	keep := make([]bool, len(filtered))
	for i, f := range filtered {
		concern := concernOfFinding(f)
		if concern == "" {
			keep[i] = true
			continue
		}
		current, exists := bestByConcern[concern]
		if !exists || filtered[i].Confidence > filtered[current].Confidence {
			bestByConcern[concern] = i
		}
	}
	for _, idx := range bestByConcern {
		keep[idx] = true
	}
	out := make([]providers.Finding, 0, len(filtered))
	for i, f := range filtered {
		if !keep[i] {
			continue
		}
		if concern := concernOfFinding(f); concern != "" {
			agreed := make([]string, 0, 3)
			for j, peer := range filtered {
				if j == i {
					continue
				}
				if concernOfFinding(peer) != concern {
					continue
				}
				if name, ok := peer.Details["detector"].(string); ok && name != "" {
					agreed = append(agreed, name)
				}
			}
			if len(agreed) > 0 {
				f.Details["concurring_detectors"] = agreed
			}
		}
		out = append(out, f)
	}
	return out
}
