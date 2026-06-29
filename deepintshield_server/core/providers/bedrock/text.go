package bedrock

import (
	"strings"

	"github.com/deepint-shield/ai-security/core/providers/anthropic"
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToBedrockTextCompletionRequest converts a DeepIntShield text completion request to Bedrock format
func ToBedrockTextCompletionRequest(deepintshieldReq *schemas.DeepIntShieldTextCompletionRequest) *BedrockTextCompletionRequest {
	if deepintshieldReq == nil || (deepintshieldReq.Input.PromptStr == nil && len(deepintshieldReq.Input.PromptArray) == 0) {
		return nil
	}

	// Extract the raw prompt from deepintshieldReq
	prompt := ""
	if deepintshieldReq.Input != nil {
		if deepintshieldReq.Input.PromptStr != nil {
			prompt = *deepintshieldReq.Input.PromptStr
		} else if len(deepintshieldReq.Input.PromptArray) > 0 && deepintshieldReq.Input.PromptArray != nil {
			prompt = strings.Join(deepintshieldReq.Input.PromptArray, "\n\n")
		}
	}

	bedrockReq := &BedrockTextCompletionRequest{
		Prompt: prompt,
	}

	// Apply parameters
	if deepintshieldReq.Params != nil {
		bedrockReq.Temperature = deepintshieldReq.Params.Temperature
		bedrockReq.TopP = deepintshieldReq.Params.TopP

		if deepintshieldReq.Params.ExtraParams != nil {
			bedrockReq.ExtraParams = deepintshieldReq.Params.ExtraParams
			if topK, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["top_k"]); ok {
				delete(bedrockReq.ExtraParams, "top_k")
				bedrockReq.TopK = topK
			}
		}
	}

	// Apply model-specific formatting and field naming
	if strings.Contains(deepintshieldReq.Model, "anthropic.") || strings.Contains(deepintshieldReq.Model, "claude") {
		// For Claude models, wrap the prompt in Anthropic format and use Anthropic field names
		anthropicReq := anthropic.ToAnthropicTextCompletionRequest(deepintshieldReq)
		bedrockReq.Prompt = anthropicReq.Prompt
		bedrockReq.MaxTokensToSample = &anthropicReq.MaxTokensToSample
		bedrockReq.StopSequences = anthropicReq.StopSequences
	} else {
		// For other models, use standard field names with raw prompt
		if deepintshieldReq.Params != nil {
			bedrockReq.MaxTokens = deepintshieldReq.Params.MaxTokens
			bedrockReq.Stop = deepintshieldReq.Params.Stop
		}
	}

	return bedrockReq
}

// ToDeepIntShieldTextCompletionRequest converts a Bedrock text completion request to DeepIntShield format
func (request *BedrockTextCompletionRequest) ToDeepIntShieldTextCompletionRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldTextCompletionRequest {
	if request == nil {
		return nil
	}

	prompt := request.Prompt
	// Fallback for Claude 3 Messages API
	if prompt == "" && len(request.Messages) > 0 {
		var parts []string
		for _, msg := range request.Messages {
			for _, content := range msg.Content {
				if content.Text != nil {
					parts = append(parts, *content.Text)
				}
			}
		}
		prompt = strings.Join(parts, "\n\n")
	}

	provider, model := schemas.ParseModelString(request.ModelID, utils.CheckAndSetDefaultProvider(ctx, schemas.Bedrock))

	deepintshieldReq := &schemas.DeepIntShieldTextCompletionRequest{
		Provider: provider,
		Model:    model,
		Input: &schemas.TextCompletionInput{
			PromptStr: &prompt,
		},
		Params: &schemas.TextCompletionParameters{
			Temperature: request.Temperature,
			TopP:        request.TopP,
		},
	}

	if request.MaxTokens != nil {
		deepintshieldReq.Params.MaxTokens = request.MaxTokens
	} else if request.MaxTokensToSample != nil {
		deepintshieldReq.Params.MaxTokens = request.MaxTokensToSample
	}

	if len(request.Stop) > 0 {
		deepintshieldReq.Params.Stop = request.Stop
	} else if len(request.StopSequences) > 0 {
		deepintshieldReq.Params.Stop = request.StopSequences
	}

	return deepintshieldReq
}

// ToDeepIntShieldTextCompletionResponse converts a Bedrock Anthropic text response to DeepIntShield format
func (response *BedrockAnthropicTextResponse) ToDeepIntShieldTextCompletionResponse() *schemas.DeepIntShieldTextCompletionResponse {
	if response == nil {
		return nil
	}

	return &schemas.DeepIntShieldTextCompletionResponse{
		Object: "text_completion",
		Choices: []schemas.DeepIntShieldResponseChoice{
			{
				Index: 0,
				TextCompletionResponseChoice: &schemas.TextCompletionResponseChoice{
					Text: &response.Completion,
				},
				FinishReason: &response.StopReason,
			},
		},
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.TextCompletionRequest,
			Provider:    schemas.Bedrock,
		},
	}
}

// ToDeepIntShieldTextCompletionResponse converts a Bedrock Mistral text response to DeepIntShield format
func (response *BedrockMistralTextResponse) ToDeepIntShieldTextCompletionResponse() *schemas.DeepIntShieldTextCompletionResponse {
	if response == nil {
		return nil
	}

	var choices []schemas.DeepIntShieldResponseChoice
	for i, output := range response.Outputs {
		choices = append(choices, schemas.DeepIntShieldResponseChoice{
			Index: i,
			TextCompletionResponseChoice: &schemas.TextCompletionResponseChoice{
				Text: &output.Text,
			},
			FinishReason: &output.StopReason,
		})
	}

	return &schemas.DeepIntShieldTextCompletionResponse{
		Object:  "text_completion",
		Choices: choices,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.TextCompletionRequest,
			Provider:    schemas.Bedrock,
		},
	}
}

// ToBedrockTextCompletionResponse converts a DeepIntShieldTextCompletionResponse back to Bedrock text completion format
// Returns either *BedrockAnthropicTextResponse or *BedrockMistralTextResponse based on the model
func ToBedrockTextCompletionResponse(deepintshieldResp *schemas.DeepIntShieldTextCompletionResponse) interface{} {
	if deepintshieldResp == nil {
		return nil
	}

	// Determine response format based on model
	// Use ModelRequested from ExtraFields if available, otherwise use Model
	model := deepintshieldResp.Model
	if deepintshieldResp.ExtraFields.ModelRequested != "" {
		model = deepintshieldResp.ExtraFields.ModelRequested
	}

	if strings.Contains(model, "anthropic.") || strings.Contains(model, "claude") {
		// Convert to Anthropic format
		bedrockResp := &BedrockAnthropicTextResponse{}

		// Convert choices to completion text
		if len(deepintshieldResp.Choices) > 0 {
			choice := deepintshieldResp.Choices[0] // Anthropic text API typically returns one choice
			if choice.TextCompletionResponseChoice != nil && choice.TextCompletionResponseChoice.Text != nil {
				bedrockResp.Completion = *choice.TextCompletionResponseChoice.Text
			}
			if choice.FinishReason != nil {
				bedrockResp.StopReason = *choice.FinishReason
			}
		}

		return bedrockResp
	} else if strings.Contains(model, "mistral.") {
		// Convert to Mistral format
		bedrockResp := &BedrockMistralTextResponse{}

		// Convert choices to outputs
		for _, choice := range deepintshieldResp.Choices {
			var output struct {
				Text       string `json:"text"`
				StopReason string `json:"stop_reason"`
			}

			if choice.TextCompletionResponseChoice != nil && choice.TextCompletionResponseChoice.Text != nil {
				output.Text = *choice.TextCompletionResponseChoice.Text
			}
			if choice.FinishReason != nil {
				output.StopReason = *choice.FinishReason
			}

			bedrockResp.Outputs = append(bedrockResp.Outputs, output)
		}

		return bedrockResp
	}

	// Default to Anthropic format if model type cannot be determined
	bedrockResp := &BedrockAnthropicTextResponse{}
	if len(deepintshieldResp.Choices) > 0 {
		choice := deepintshieldResp.Choices[0]
		if choice.TextCompletionResponseChoice != nil && choice.TextCompletionResponseChoice.Text != nil {
			bedrockResp.Completion = *choice.TextCompletionResponseChoice.Text
		}
		if choice.FinishReason != nil {
			bedrockResp.StopReason = *choice.FinishReason
		}
	}

	return bedrockResp
}
