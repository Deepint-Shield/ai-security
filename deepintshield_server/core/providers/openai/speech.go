package openai

import (
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldSpeechRequest converts an OpenAI speech request to DeepIntShield format
func (request *OpenAISpeechRequest) ToDeepIntShieldSpeechRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldSpeechRequest {
	provider, model := schemas.ParseModelString(request.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.OpenAI))

	return &schemas.DeepIntShieldSpeechRequest{
		Provider:  provider,
		Model:     model,
		Input:     &schemas.SpeechInput{Input: request.Input},
		Params:    &request.SpeechParameters,
		Fallbacks: schemas.ParseFallbacks(request.Fallbacks),
	}
}

// ToOpenAISpeechRequest converts a DeepIntShield speech request to OpenAI format
func ToOpenAISpeechRequest(deepintshieldReq *schemas.DeepIntShieldSpeechRequest) *OpenAISpeechRequest {
	if deepintshieldReq == nil || deepintshieldReq.Input.Input == "" {
		return nil
	}

	speechInput := deepintshieldReq.Input
	params := deepintshieldReq.Params

	openaiReq := &OpenAISpeechRequest{
		Model: deepintshieldReq.Model,
		Input: speechInput.Input,
	}

	if params != nil {
		openaiReq.SpeechParameters = *params
	}

	if deepintshieldReq.Params != nil {
		openaiReq.ExtraParams = deepintshieldReq.Params.ExtraParams
	}
	return openaiReq
}
