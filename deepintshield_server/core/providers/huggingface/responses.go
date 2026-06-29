package huggingface

import (
	"fmt"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToHuggingFaceResponsesRequest converts a DeepIntShield Responses request into the Hugging Face
// chat-completions payload that the provider already understands.
func ToHuggingFaceResponsesRequest(deepintshieldReq *schemas.DeepIntShieldResponsesRequest) (*HuggingFaceChatRequest, error) {
	if deepintshieldReq == nil {
		return nil, nil
	}

	chatReq := deepintshieldReq.ToChatRequest()
	if chatReq == nil {
		return nil, fmt.Errorf("failed to convert responses request to chat request")
	}

	hfReq, err := ToHuggingFaceChatCompletionRequest(chatReq)
	if err != nil {
		return nil, err
	}
	if hfReq == nil {
		return nil, fmt.Errorf("failed to convert chat request to Hugging Face request")
	}

	return hfReq, nil
}

// ToDeepIntShieldResponsesResponseFromHuggingFace converts a DeepIntShield chat response into the
// DeepIntShield Responses response shape, preserving provider metadata.
func ToDeepIntShieldResponsesResponseFromHuggingFace(resp *schemas.DeepIntShieldChatResponse, requestedModel string) (*schemas.DeepIntShieldResponsesResponse, error) {
	if resp == nil {
		return nil, nil
	}

	// Ensure model is set
	if resp.Model == "" {
		resp.Model = requestedModel
	}

	responsesResp := resp.ToDeepIntShieldResponsesResponse()
	if responsesResp != nil {
		responsesResp.ExtraFields.Provider = schemas.HuggingFace
		responsesResp.ExtraFields.ModelRequested = requestedModel
		responsesResp.ExtraFields.RequestType = schemas.ResponsesRequest
	}

	return responsesResp, nil
}
