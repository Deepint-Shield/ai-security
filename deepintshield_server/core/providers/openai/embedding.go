package openai

import (
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldEmbeddingRequest converts an OpenAI embedding request to DeepIntShield format
func (request *OpenAIEmbeddingRequest) ToDeepIntShieldEmbeddingRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldEmbeddingRequest {
	provider, model := schemas.ParseModelString(request.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.OpenAI))

	return &schemas.DeepIntShieldEmbeddingRequest{
		Provider:  provider,
		Model:     model,
		Input:     request.Input,
		Params:    &request.EmbeddingParameters,
		Fallbacks: schemas.ParseFallbacks(request.Fallbacks),
	}
}

// ToOpenAIEmbeddingRequest converts a DeepIntShield embedding request to OpenAI format
func ToOpenAIEmbeddingRequest(deepintshieldReq *schemas.DeepIntShieldEmbeddingRequest) *OpenAIEmbeddingRequest {
	if deepintshieldReq == nil {
		return nil
	}

	params := deepintshieldReq.Params

	openaiReq := &OpenAIEmbeddingRequest{
		Model: deepintshieldReq.Model,
		Input: deepintshieldReq.Input,
	}

	// Map parameters
	if params != nil {
		openaiReq.EmbeddingParameters = *params
	}

	if deepintshieldReq.Params != nil {
		openaiReq.ExtraParams = deepintshieldReq.Params.ExtraParams
	}
	return openaiReq
}
