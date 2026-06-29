package cohere

import (
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToCohereEmbeddingRequest converts a DeepIntShield embedding request to Cohere format
func ToCohereEmbeddingRequest(deepintshieldReq *schemas.DeepIntShieldEmbeddingRequest) *CohereEmbeddingRequest {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil || (deepintshieldReq.Input.Text == nil && deepintshieldReq.Input.Texts == nil) {
		return nil
	}

	embeddingInput := deepintshieldReq.Input
	cohereReq := &CohereEmbeddingRequest{
		Model: deepintshieldReq.Model,
	}

	texts := []string{}
	if embeddingInput.Text != nil {
		texts = append(texts, *embeddingInput.Text)
	} else {
		texts = embeddingInput.Texts
	}

	// Convert texts from DeepIntShield format
	if len(texts) > 0 {
		cohereReq.Texts = texts
	}

	// Set default input type if not specified in extra params
	cohereReq.InputType = "search_document" // Default value

	if deepintshieldReq.Params != nil {
		cohereReq.OutputDimension = deepintshieldReq.Params.Dimensions
		cohereReq.ExtraParams = deepintshieldReq.Params.ExtraParams
		if deepintshieldReq.Params.ExtraParams != nil {
			if maxTokens, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["max_tokens"]); ok {
				delete(cohereReq.ExtraParams, "max_tokens")
				cohereReq.MaxTokens = maxTokens
			}
		}
	}

	// Handle extra params
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.ExtraParams != nil {
		// Input type
		if inputType, ok := schemas.SafeExtractString(deepintshieldReq.Params.ExtraParams["input_type"]); ok {
			delete(cohereReq.ExtraParams, "input_type")
			cohereReq.InputType = inputType
		}

		// Embedding types
		if embeddingTypes, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["embedding_types"]); ok {
			if len(embeddingTypes) > 0 {
				delete(cohereReq.ExtraParams, "embedding_types")
				cohereReq.EmbeddingTypes = embeddingTypes
			}
		}

		// Truncate
		if truncate, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["truncate"]); ok {
			delete(cohereReq.ExtraParams, "truncate")
			cohereReq.Truncate = truncate
		}
	}

	return cohereReq
}

// ToDeepIntShieldEmbeddingRequest converts a Cohere embedding request to DeepIntShield format
func (req *CohereEmbeddingRequest) ToDeepIntShieldEmbeddingRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldEmbeddingRequest {
	if req == nil {
		return nil
	}

	provider, model := schemas.ParseModelString(req.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.Cohere))

	deepintshieldReq := &schemas.DeepIntShieldEmbeddingRequest{
		Provider: provider,
		Model:    model,
		Input:    &schemas.EmbeddingInput{},
		Params:   &schemas.EmbeddingParameters{},
	}

	// Convert texts
	if len(req.Texts) > 0 {
		if len(req.Texts) == 1 {
			deepintshieldReq.Input.Text = &req.Texts[0]
		} else {
			deepintshieldReq.Input.Texts = req.Texts
		}
	}

	// Convert parameters
	if req.OutputDimension != nil {
		deepintshieldReq.Params.Dimensions = req.OutputDimension
	}

	// Convert extra params
	extraParams := make(map[string]interface{})
	if req.InputType != "" {
		extraParams["input_type"] = req.InputType
	}
	if req.EmbeddingTypes != nil {
		extraParams["embedding_types"] = req.EmbeddingTypes
	}
	if req.Truncate != nil {
		extraParams["truncate"] = *req.Truncate
	}
	if req.MaxTokens != nil {
		extraParams["max_tokens"] = *req.MaxTokens
	}
	if len(extraParams) > 0 {
		deepintshieldReq.Params.ExtraParams = extraParams
	}

	return deepintshieldReq
}

// ToDeepIntShieldEmbeddingResponse converts a Cohere embedding response to DeepIntShield format
func (response *CohereEmbeddingResponse) ToDeepIntShieldEmbeddingResponse() *schemas.DeepIntShieldEmbeddingResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldEmbeddingResponse{
		Object: "list",
	}

	// Convert embeddings data
	if response.Embeddings != nil {
		var deepintshieldEmbeddings []schemas.EmbeddingData

		// Handle different embedding types - prioritize float embeddings
		if response.Embeddings.Float != nil {
			for i, embedding := range response.Embeddings.Float {
				deepintshieldEmbedding := schemas.EmbeddingData{
					Object: "embedding",
					Index:  i,
					Embedding: schemas.EmbeddingStruct{
						EmbeddingArray: embedding,
					},
				}
				deepintshieldEmbeddings = append(deepintshieldEmbeddings, deepintshieldEmbedding)
			}
		} else if response.Embeddings.Base64 != nil {
			// Handle base64 embeddings as strings
			for i, embedding := range response.Embeddings.Base64 {
				deepintshieldEmbedding := schemas.EmbeddingData{
					Object: "embedding",
					Index:  i,
					Embedding: schemas.EmbeddingStruct{
						EmbeddingStr: &embedding,
					},
				}
				deepintshieldEmbeddings = append(deepintshieldEmbeddings, deepintshieldEmbedding)
			}
		}
		// Note: Int8, Uint8, Binary, Ubinary types would need special handling
		// depending on how DeepIntShield wants to represent them

		deepintshieldResponse.Data = deepintshieldEmbeddings
	}

	// Convert usage information
	if response.Meta != nil {
		if response.Meta.Tokens != nil {
			deepintshieldResponse.Usage = &schemas.DeepIntShieldLLMUsage{}
			if response.Meta.Tokens.InputTokens != nil {
				deepintshieldResponse.Usage.PromptTokens = int(*response.Meta.Tokens.InputTokens)
			}
			if response.Meta.Tokens.OutputTokens != nil {
				deepintshieldResponse.Usage.CompletionTokens = int(*response.Meta.Tokens.OutputTokens)
			}
			deepintshieldResponse.Usage.TotalTokens = deepintshieldResponse.Usage.PromptTokens + deepintshieldResponse.Usage.CompletionTokens
		} else if response.Meta.BilledUnits != nil {
			deepintshieldResponse.Usage = &schemas.DeepIntShieldLLMUsage{}
			if response.Meta.BilledUnits.InputTokens != nil {
				deepintshieldResponse.Usage.PromptTokens = int(*response.Meta.BilledUnits.InputTokens)
			}
			if response.Meta.BilledUnits.OutputTokens != nil {
				deepintshieldResponse.Usage.CompletionTokens = int(*response.Meta.BilledUnits.OutputTokens)
			}
			deepintshieldResponse.Usage.TotalTokens = deepintshieldResponse.Usage.PromptTokens + deepintshieldResponse.Usage.CompletionTokens
		}
	}

	return deepintshieldResponse
}
