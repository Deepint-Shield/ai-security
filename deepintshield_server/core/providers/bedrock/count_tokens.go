package bedrock

import (
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

const estimatedBytesPerToken = 4

// ToDeepIntShieldCountTokensResponse converts a Bedrock count tokens response to DeepIntShield format
func (resp *BedrockCountTokensResponse) ToDeepIntShieldCountTokensResponse(model string) *schemas.DeepIntShieldCountTokensResponse {
	if resp == nil {
		return nil
	}

	totalTokens := resp.InputTokens

	return &schemas.DeepIntShieldCountTokensResponse{
		Model:       model,
		InputTokens: resp.InputTokens,
		TotalTokens: &totalTokens,
		Object:      "response.input_tokens",
	}
}

// ToBedrockCountTokensResponse converts a DeepIntShield count tokens response to Bedrock native format
func ToBedrockCountTokensResponse(resp *schemas.DeepIntShieldCountTokensResponse) *BedrockCountTokensResponse {
	if resp == nil {
		return nil
	}

	return &BedrockCountTokensResponse{
		InputTokens: resp.InputTokens,
	}
}

// isCountTokensUnsupported checks whether a DeepIntShieldError indicates that the
// Bedrock model does not support the count-tokens operation.
func isCountTokensUnsupported(err *schemas.DeepIntShieldError) bool {
	if err == nil || err.Error == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error.Message), "doesn't support counting tokens")
}

// estimateTokenCount returns a rough token count derived from the byte length
// of the serialized request body. Claude's tokenizer averages ~4 bytes per
// token on mixed content; this intentionally rounds up so that context-window
// management decisions stay on the conservative side.
func estimateTokenCount(requestBody []byte) int {
	n := len(requestBody)
	if n == 0 {
		return 0
	}
	return (n + estimatedBytesPerToken - 1) / estimatedBytesPerToken
}
