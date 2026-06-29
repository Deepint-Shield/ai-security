package vertex

import (
	"github.com/deepint-shield/ai-security/core/schemas"
)

func (resp *VertexCountTokensResponse) ToDeepIntShieldCountTokensResponse(model string) *schemas.DeepIntShieldCountTokensResponse {
	if resp == nil {
		return nil
	}

	inputDetails := &schemas.ResponsesResponseInputTokens{}
	inputTokens := int(resp.TotalTokens) // Vertex response typically represents prompt tokens for countTokens
	total := int(resp.TotalTokens)

	if resp.CachedContentTokenCount > 0 {
		inputDetails.CachedReadTokens = int(resp.CachedContentTokenCount)
	}

	return &schemas.DeepIntShieldCountTokensResponse{
		Model:              model,
		Object:             "response.input_tokens",
		InputTokens:        inputTokens,
		InputTokensDetails: inputDetails,
		TotalTokens:        &total,
	}
}
