package anthropic

import (
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldCountTokensResponse converts an Anthropic count tokens response to DeepIntShield format
func (resp *AnthropicCountTokensResponse) ToDeepIntShieldCountTokensResponse(model string) *schemas.DeepIntShieldCountTokensResponse {
	if resp == nil {
		return nil
	}

	totalTokens := resp.InputTokens

	deepintshieldResp := &schemas.DeepIntShieldCountTokensResponse{
		Model:       model,
		InputTokens: resp.InputTokens,
		TotalTokens: &totalTokens,
		Object:      "response.input_tokens",
	}

	return deepintshieldResp
}

// ToAnthropicCountTokensResponse converts a DeepIntShield count tokens response to Anthropic format.
func ToAnthropicCountTokensResponse(deepintshieldResp *schemas.DeepIntShieldCountTokensResponse) *AnthropicCountTokensResponse {
	if deepintshieldResp == nil {
		return nil
	}

	return &AnthropicCountTokensResponse{
		InputTokens: deepintshieldResp.InputTokens,
	}
}
