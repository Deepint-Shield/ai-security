package openai

import (
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToOpenAITextCompletionRequest converts a DeepIntShield text completion request to OpenAI format
func ToOpenAITextCompletionRequest(deepintshieldReq *schemas.DeepIntShieldTextCompletionRequest) *OpenAITextCompletionRequest {
	if deepintshieldReq == nil {
		return nil
	}
	params := deepintshieldReq.Params
	openaiReq := &OpenAITextCompletionRequest{
		Model:  deepintshieldReq.Model,
		Prompt: deepintshieldReq.Input,
	}
	if params != nil {
		openaiReq.TextCompletionParameters = *params
		// Drop user field if it exceeds OpenAI's 64 character limit
		openaiReq.TextCompletionParameters.User = SanitizeUserField(openaiReq.TextCompletionParameters.User)
	}
	if deepintshieldReq.Params != nil {
		openaiReq.ExtraParams = deepintshieldReq.Params.ExtraParams
	}
	return openaiReq
}

// ToDeepIntShieldTextCompletionRequest converts an OpenAI text completion request to DeepIntShield format
func (req *OpenAITextCompletionRequest) ToDeepIntShieldTextCompletionRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldTextCompletionRequest {
	if req == nil {
		return nil
	}

	provider, model := schemas.ParseModelString(req.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.OpenAI))

	return &schemas.DeepIntShieldTextCompletionRequest{
		Provider:  provider,
		Model:     model,
		Input:     req.Prompt,
		Params:    &req.TextCompletionParameters,
		Fallbacks: schemas.ParseFallbacks(req.Fallbacks),
	}
}
