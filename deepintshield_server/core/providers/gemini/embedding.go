package gemini

import (
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToGeminiEmbeddingRequest converts a DeepIntShieldRequest with embedding input to Gemini's batch embedding request format
// GeminiGenerationRequest contains requests array for batch embed content endpoint
func ToGeminiEmbeddingRequest(deepintshieldReq *schemas.DeepIntShieldEmbeddingRequest) *GeminiBatchEmbeddingRequest {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil || (deepintshieldReq.Input.Text == nil && deepintshieldReq.Input.Texts == nil) {
		return nil
	}

	embeddingInput := deepintshieldReq.Input

	// Collect all texts to embed
	var texts []string
	if embeddingInput.Text != nil {
		texts = append(texts, *embeddingInput.Text)
	}
	if len(embeddingInput.Texts) > 0 {
		texts = append(texts, embeddingInput.Texts...)
	}

	if len(texts) == 0 {
		return nil
	}

	// Create batch embedding request with one request per text
	batchRequest := &GeminiBatchEmbeddingRequest{
		Requests: make([]GeminiEmbeddingRequest, len(texts)),
	}
	if deepintshieldReq.Params != nil {
		batchRequest.ExtraParams = deepintshieldReq.Params.ExtraParams
	}

	// Create individual embedding requests for each text
	for i, text := range texts {
		embeddingReq := GeminiEmbeddingRequest{
			Model: "models/" + deepintshieldReq.Model,
			Content: &Content{
				Parts: []*Part{
					{
						Text: text,
					},
				},
			},
		}

		// Add parameters if available
		if deepintshieldReq.Params != nil {
			if deepintshieldReq.Params.Dimensions != nil {
				embeddingReq.OutputDimensionality = deepintshieldReq.Params.Dimensions
			}

			// Handle extra parameters
			if deepintshieldReq.Params.ExtraParams != nil {
				if taskType, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["taskType"]); ok {
					delete(batchRequest.ExtraParams, "taskType")
					embeddingReq.TaskType = taskType
				}
				if title, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["title"]); ok {
					delete(batchRequest.ExtraParams, "title")
					embeddingReq.Title = title
				}
			}
		}

		batchRequest.Requests[i] = embeddingReq
	}

	return batchRequest
}

// ToGeminiEmbeddingResponse converts a DeepIntShieldResponse with embedding data to Gemini's embedding response format
func ToGeminiEmbeddingResponse(deepintshieldResp *schemas.DeepIntShieldEmbeddingResponse) *GeminiEmbeddingResponse {
	if deepintshieldResp == nil || len(deepintshieldResp.Data) == 0 {
		return nil
	}

	geminiResp := &GeminiEmbeddingResponse{
		Embeddings: make([]GeminiEmbedding, len(deepintshieldResp.Data)),
	}

	// Convert each embedding from DeepIntShield format to Gemini format
	for i, embedding := range deepintshieldResp.Data {
		var values []float32

		// Extract embedding values from DeepIntShieldEmbeddingResponse
		if embedding.Embedding.EmbeddingArray != nil {
			values = embedding.Embedding.EmbeddingArray
		} else if len(embedding.Embedding.Embedding2DArray) > 0 {
			// If it's a 2D array, take the first array
			values = embedding.Embedding.Embedding2DArray[0]
		}

		geminiEmbedding := GeminiEmbedding{
			Values: values,
		}

		// Add statistics if available (token count from usage metadata)
		if deepintshieldResp.Usage != nil {
			geminiEmbedding.Statistics = &ContentEmbeddingStatistics{
				TokenCount: int32(deepintshieldResp.Usage.PromptTokens),
			}
		}

		geminiResp.Embeddings[i] = geminiEmbedding
	}

	// Set metadata if available (for Vertex API compatibility)
	if deepintshieldResp.Usage != nil {
		geminiResp.Metadata = &EmbedContentMetadata{
			BillableCharacterCount: int32(deepintshieldResp.Usage.PromptTokens),
		}
	}

	return geminiResp
}

// ToDeepIntShieldEmbeddingResponse converts a Gemini embedding response to DeepIntShieldEmbeddingResponse format
func ToDeepIntShieldEmbeddingResponse(geminiResp *GeminiEmbeddingResponse, model string) *schemas.DeepIntShieldEmbeddingResponse {
	if geminiResp == nil || len(geminiResp.Embeddings) == 0 {
		return nil
	}

	deepintshieldResp := &schemas.DeepIntShieldEmbeddingResponse{
		Data:   make([]schemas.EmbeddingData, len(geminiResp.Embeddings)),
		Model:  model,
		Object: "list",
	}

	// Convert each embedding from Gemini format to DeepIntShield format
	for i, geminiEmbedding := range geminiResp.Embeddings {
		embeddingData := schemas.EmbeddingData{
			Index:  i,
			Object: "embedding",
			Embedding: schemas.EmbeddingStruct{
				EmbeddingArray: geminiEmbedding.Values,
			},
		}

		deepintshieldResp.Data[i] = embeddingData
	}

	// Convert usage metadata if available
	if geminiResp.Metadata != nil || (len(geminiResp.Embeddings) > 0 && geminiResp.Embeddings[0].Statistics != nil) {
		deepintshieldResp.Usage = &schemas.DeepIntShieldLLMUsage{}

		// Use statistics from the first embedding if available
		if geminiResp.Embeddings[0].Statistics != nil {
			deepintshieldResp.Usage.PromptTokens = int(geminiResp.Embeddings[0].Statistics.TokenCount)
		} else if geminiResp.Metadata != nil {
			// Fall back to metadata if statistics are not available
			deepintshieldResp.Usage.PromptTokens = int(geminiResp.Metadata.BillableCharacterCount)
		}

		// Set total tokens same as prompt tokens for embeddings
		deepintshieldResp.Usage.TotalTokens = deepintshieldResp.Usage.PromptTokens
	}

	return deepintshieldResp
}

// ToDeepIntShieldEmbeddingRequest converts a GeminiGenerationRequest to DeepIntShieldEmbeddingRequest format
func (request *GeminiGenerationRequest) ToDeepIntShieldEmbeddingRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldEmbeddingRequest {
	if request == nil {
		return nil
	}

	provider, model := schemas.ParseModelString(request.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.Gemini))

	// Create the embedding request
	deepintshieldReq := &schemas.DeepIntShieldEmbeddingRequest{
		Provider:  provider,
		Model:     model,
		Fallbacks: schemas.ParseFallbacks(request.Fallbacks),
	}

	// SDK batch embedding request contains multiple embedding requests with same parameters but different text fields.
	if len(request.Requests) > 0 {
		var texts []string
		for _, req := range request.Requests {
			if req.Content != nil && len(req.Content.Parts) > 0 {
				for _, part := range req.Content.Parts {
					if part != nil && part.Text != "" {
						texts = append(texts, part.Text)
					}
				}
			}
		}
		if len(texts) > 0 {
			deepintshieldReq.Input = &schemas.EmbeddingInput{}
			if len(texts) == 1 {
				deepintshieldReq.Input.Text = &texts[0]
			} else {
				deepintshieldReq.Input.Texts = texts
			}
		}

		embeddingRequest := request.Requests[0]

		// Convert parameters
		if embeddingRequest.OutputDimensionality != nil || embeddingRequest.TaskType != nil || embeddingRequest.Title != nil {
			deepintshieldReq.Params = &schemas.EmbeddingParameters{}

			if embeddingRequest.OutputDimensionality != nil {
				deepintshieldReq.Params.Dimensions = embeddingRequest.OutputDimensionality
			}

			// Handle extra parameters
			if embeddingRequest.TaskType != nil || embeddingRequest.Title != nil {
				deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
				if embeddingRequest.TaskType != nil {
					deepintshieldReq.Params.ExtraParams["taskType"] = embeddingRequest.TaskType
				}
				if embeddingRequest.Title != nil {
					deepintshieldReq.Params.ExtraParams["title"] = embeddingRequest.Title
				}
			}
		}
	}

	// Generation-style requests (e.g., non-Imagen :predict) carry text in contents[].parts[].
	// If no SDK requests[] were provided, derive embedding input from contents.
	if deepintshieldReq.Input == nil {
		var texts []string
		for _, content := range request.Contents {
			for _, part := range content.Parts {
				if part != nil && part.Text != "" {
					texts = append(texts, part.Text)
				}
			}
		}
		if len(texts) > 0 {
			deepintshieldReq.Input = &schemas.EmbeddingInput{}
			if len(texts) == 1 {
				deepintshieldReq.Input.Text = &texts[0]
			} else {
				deepintshieldReq.Input.Texts = texts
			}
		}
	}

	return deepintshieldReq
}
