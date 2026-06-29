package gemini

import (
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldCountTokensResponse converts a Gemini count tokens response to DeepIntShield format.
func (resp *GeminiCountTokensResponse) ToDeepIntShieldCountTokensResponse(model string) *schemas.DeepIntShieldCountTokensResponse {
	if resp == nil {
		return nil
	}

	// Sum prompt tokens and map modality-specific counts
	inputTokens := 0
	inputDetails := &schemas.ResponsesResponseInputTokens{}

	for _, m := range resp.PromptTokensDetails {
		if m == nil {
			continue
		}
		inputTokens += int(m.TokenCount)
		mod := strings.ToLower(string(m.Modality))
		// handle audio modality
		if strings.Contains(mod, "audio") {
			inputDetails.AudioTokens += int(m.TokenCount)
		}
	}

	// Set cached tokens from top-level field if present
	if resp.CachedContentTokenCount != 0 {
		inputDetails.CachedReadTokens = int(resp.CachedContentTokenCount)
	} else if resp.CacheTokensDetails != nil {
		// If cache tokens details present, sum them
		cachedSum := 0
		for _, m := range resp.CacheTokensDetails {
			if m == nil {
				continue
			}
			cachedSum += int(m.TokenCount)
			if strings.Contains(strings.ToLower(string(m.Modality)), "audio") {
				// also populate audio tokens from cache into AudioTokens (additive)
				inputDetails.AudioTokens += int(m.TokenCount)
			}
		}
		inputDetails.CachedReadTokens = cachedSum
	}

	total := int(resp.TotalTokens)

	return &schemas.DeepIntShieldCountTokensResponse{
		Model:              model,
		Object:             "response.input_tokens",
		InputTokens:        inputTokens,
		InputTokensDetails: inputDetails,
		TotalTokens:        &total,
		ExtraFields:        schemas.DeepIntShieldResponseExtraFields{},
	}
}

// ToGeminiCountTokensResponse converts a DeepIntShield count tokens response to Gemini format.
func ToGeminiCountTokensResponse(deepintshieldResp *schemas.DeepIntShieldCountTokensResponse) *GeminiCountTokensResponse {
	if deepintshieldResp == nil {
		return nil
	}

	response := &GeminiCountTokensResponse{
		TotalTokens: int32(deepintshieldResp.InputTokens),
	}

	// Map cached content token count if available
	if deepintshieldResp.InputTokensDetails != nil && deepintshieldResp.InputTokensDetails.CachedReadTokens > 0 {
		response.CachedContentTokenCount = int32(deepintshieldResp.InputTokensDetails.CachedReadTokens)
	} else {
		response.CachedContentTokenCount = 0
	}

	return response
}
