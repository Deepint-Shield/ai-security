package anthropic

import (
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToAnthropicTextCompletionRequest converts a DeepIntShield text completion request to Anthropic format
func ToAnthropicTextCompletionRequest(deepintshieldReq *schemas.DeepIntShieldTextCompletionRequest) *AnthropicTextRequest {
	if deepintshieldReq == nil {
		return nil
	}

	prompt := ""
	if deepintshieldReq.Input.PromptStr != nil {
		prompt = *deepintshieldReq.Input.PromptStr
	} else if len(deepintshieldReq.Input.PromptArray) > 0 {
		prompt = strings.Join(deepintshieldReq.Input.PromptArray, "\n\n")
	}

	anthropicReq := &AnthropicTextRequest{
		Model:             deepintshieldReq.Model,
		Prompt:            fmt.Sprintf("\n\nHuman: %s\n\nAssistant:", prompt),
		MaxTokensToSample: AnthropicDefaultMaxTokens, // Default value
	}

	// Convert parameters
	if deepintshieldReq.Params != nil {
		if deepintshieldReq.Params.MaxTokens != nil {
			anthropicReq.MaxTokensToSample = *deepintshieldReq.Params.MaxTokens
		}
		anthropicReq.Temperature = deepintshieldReq.Params.Temperature
		anthropicReq.TopP = deepintshieldReq.Params.TopP
		anthropicReq.StopSequences = deepintshieldReq.Params.Stop

		if deepintshieldReq.Params.ExtraParams != nil {
			anthropicReq.ExtraParams = deepintshieldReq.Params.ExtraParams
			if topK, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["top_k"]); ok {
				delete(anthropicReq.ExtraParams, "top_k")
				anthropicReq.TopK = topK
			}
		}
	}

	return anthropicReq
}

// ToDeepIntShieldTextCompletionRequest converts an Anthropic text request back to DeepIntShield format
func (req *AnthropicTextRequest) ToDeepIntShieldTextCompletionRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldTextCompletionRequest {
	if req == nil {
		return nil
	}

	provider, model := schemas.ParseModelString(req.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.Anthropic))

	deepintshieldReq := &schemas.DeepIntShieldTextCompletionRequest{
		Provider: provider,
		Model:    model,
		Input: &schemas.TextCompletionInput{
			PromptStr: &req.Prompt,
		},
		Params: &schemas.TextCompletionParameters{
			MaxTokens:   &req.MaxTokensToSample,
			Temperature: req.Temperature,
			TopP:        req.TopP,
			Stop:        req.StopSequences,
		},
		Fallbacks: schemas.ParseFallbacks(req.Fallbacks),
	}

	// Add extra params if present
	if req.TopK != nil {
		deepintshieldReq.Params.ExtraParams = map[string]interface{}{
			"top_k": *req.TopK,
		}
	}

	return deepintshieldReq
}

// ToDeepIntShieldTextCompletionResponse converts an Anthropic text response back to DeepIntShield format
func (response *AnthropicTextResponse) ToDeepIntShieldTextCompletionResponse() *schemas.DeepIntShieldTextCompletionResponse {
	if response == nil {
		return nil
	}
	return &schemas.DeepIntShieldTextCompletionResponse{
		ID:     response.ID,
		Object: "text_completion",
		Choices: []schemas.DeepIntShieldResponseChoice{
			{
				Index: 0,
				TextCompletionResponseChoice: &schemas.TextCompletionResponseChoice{
					Text: &response.Completion,
				},
			},
		},
		Usage: &schemas.DeepIntShieldLLMUsage{
			PromptTokens:     response.Usage.InputTokens,
			CompletionTokens: response.Usage.OutputTokens,
			TotalTokens:      response.Usage.InputTokens + response.Usage.OutputTokens,
		},
		Model: response.Model,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.TextCompletionRequest,
			Provider:    schemas.Anthropic,
		},
	}
}

// ToAnthropicTextCompletionResponse converts a DeepIntShieldResponse back to Anthropic text completion format
func ToAnthropicTextCompletionResponse(deepintshieldResp *schemas.DeepIntShieldTextCompletionResponse) *AnthropicTextResponse {
	if deepintshieldResp == nil {
		return nil
	}

	anthropicResp := &AnthropicTextResponse{
		ID:    deepintshieldResp.ID,
		Type:  "completion",
		Model: deepintshieldResp.Model,
	}

	// Convert choices to completion text
	if len(deepintshieldResp.Choices) > 0 {
		choice := deepintshieldResp.Choices[0] // Anthropic text API typically returns one choice

		if choice.TextCompletionResponseChoice != nil && choice.TextCompletionResponseChoice.Text != nil {
			anthropicResp.Completion = *choice.TextCompletionResponseChoice.Text
		}
	}

	// Convert usage information
	if deepintshieldResp.Usage != nil {
		anthropicResp.Usage.InputTokens = deepintshieldResp.Usage.PromptTokens
		anthropicResp.Usage.OutputTokens = deepintshieldResp.Usage.CompletionTokens
	}

	return anthropicResp
}
