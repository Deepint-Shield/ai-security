package bedrock

import (
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/providers/cohere"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToBedrockTitanEmbeddingRequest converts a DeepIntShield embedding request to Bedrock Titan format
func ToBedrockTitanEmbeddingRequest(deepintshieldReq *schemas.DeepIntShieldEmbeddingRequest) (*BedrockTitanEmbeddingRequest, error) {
	if deepintshieldReq == nil {
		return nil, fmt.Errorf("deepintshield embedding request is nil")
	}

	// Validate that only single text input is provided for Titan models
	if deepintshieldReq.Input.Text == nil && len(deepintshieldReq.Input.Texts) == 0 {
		return nil, fmt.Errorf("no input text provided for embedding")
	}

	// Validate dimensions parameter - Titan models do not support it
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.Dimensions != nil {
		return nil, fmt.Errorf("amazon Titan embedding models do not support custom dimensions parameter")
	}

	titanReq := &BedrockTitanEmbeddingRequest{}

	// Set input text
	if deepintshieldReq.Input.Text != nil {
		titanReq.InputText = *deepintshieldReq.Input.Text
	} else if len(deepintshieldReq.Input.Texts) > 0 {
		var embeddingText string
		for _, text := range deepintshieldReq.Input.Texts {
			embeddingText += text + " \n"
		}
		titanReq.InputText = embeddingText
	}
	if deepintshieldReq.Params != nil {
		titanReq.ExtraParams = deepintshieldReq.Params.ExtraParams
	}

	return titanReq, nil
}

// ToDeepIntShieldEmbeddingResponse converts a Bedrock Titan embedding response to DeepIntShield format
func (response *BedrockTitanEmbeddingResponse) ToDeepIntShieldEmbeddingResponse() *schemas.DeepIntShieldEmbeddingResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldEmbeddingResponse{
		Object: "list",
		Data: []schemas.EmbeddingData{
			{
				Index:  0,
				Object: "embedding",
				Embedding: schemas.EmbeddingStruct{
					EmbeddingArray: response.Embedding,
				},
			},
		},
		Usage: &schemas.DeepIntShieldLLMUsage{
			PromptTokens: response.InputTextTokenCount,
			TotalTokens:  response.InputTextTokenCount,
		},
	}

	return deepintshieldResponse
}

// ToBedrockCohereEmbeddingRequest converts a DeepIntShield embedding request to Bedrock Cohere format
// Reuses the Cohere converter since the format is identical
func ToBedrockCohereEmbeddingRequest(deepintshieldReq *schemas.DeepIntShieldEmbeddingRequest) (*cohere.CohereEmbeddingRequest, error) {
	if deepintshieldReq == nil {
		return nil, fmt.Errorf("deepintshield embedding request is nil")
	}

	// Reuse Cohere's converter - the format is identical for Bedrock
	cohereReq := cohere.ToCohereEmbeddingRequest(deepintshieldReq)
	if cohereReq == nil {
		return nil, fmt.Errorf("failed to convert to Cohere embedding request")
	}

	return cohereReq, nil
}

// DetermineEmbeddingModelType determines the embedding model type from the model name
func DetermineEmbeddingModelType(model string) (string, error) {
	switch {
	case strings.Contains(model, "amazon.titan-embed-text"):
		return "titan", nil
	case strings.Contains(model, "cohere.embed"):
		return "cohere", nil
	default:
		return "", fmt.Errorf("unsupported embedding model: %s", model)
	}
}
