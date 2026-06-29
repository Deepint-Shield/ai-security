package vertex

import (
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToVertexEmbeddingRequest converts a DeepIntShield embedding request to Vertex AI format
func ToVertexEmbeddingRequest(deepintshieldReq *schemas.DeepIntShieldEmbeddingRequest) *VertexEmbeddingRequest {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil || (deepintshieldReq.Input.Text == nil && deepintshieldReq.Input.Texts == nil) {
		return nil
	}
	// Create the request
	vertexReq := &VertexEmbeddingRequest{}
	if deepintshieldReq.Params != nil {
		vertexReq.ExtraParams = deepintshieldReq.Params.ExtraParams
	}
	var texts []string
	if deepintshieldReq.Input.Text != nil {
		texts = []string{*deepintshieldReq.Input.Text}
	} else {
		texts = deepintshieldReq.Input.Texts
	}

	// Create instances for each text
	instances := make([]VertexEmbeddingInstance, 0, len(texts))
	for _, text := range texts {
		instance := VertexEmbeddingInstance{
			Content: text,
		}

		// Add optional task_type and title from params
		if deepintshieldReq.Params != nil {
			if taskTypeStr, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["task_type"]); ok {
				delete(vertexReq.ExtraParams, "task_type")
				instance.TaskType = taskTypeStr
			}
			if title, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["title"]); ok {
				delete(vertexReq.ExtraParams, "title")
				instance.Title = title
			}
		}

		instances = append(instances, instance)
	}
	vertexReq.Instances = instances
	// Add parameters if present
	if deepintshieldReq.Params != nil {
		parameters := &VertexEmbeddingParameters{}

		// Set autoTruncate (defaults to true)
		autoTruncate := true
		if deepintshieldReq.Params.ExtraParams != nil {
			if autoTruncateVal, ok := schemas.SafeExtractBool(deepintshieldReq.Params.ExtraParams["autoTruncate"]); ok {
				delete(vertexReq.ExtraParams, "autoTruncate")
				autoTruncate = autoTruncateVal
			}
		}
		parameters.AutoTruncate = &autoTruncate

		// Add outputDimensionality if specified
		if deepintshieldReq.Params.Dimensions != nil {
			delete(vertexReq.ExtraParams, "dimensions")
			parameters.OutputDimensionality = deepintshieldReq.Params.Dimensions
		}

		vertexReq.Parameters = parameters
	}

	return vertexReq
}

// ToDeepIntShieldEmbeddingResponse converts a Vertex AI embedding response to DeepIntShield format
func (response *VertexEmbeddingResponse) ToDeepIntShieldEmbeddingResponse() *schemas.DeepIntShieldEmbeddingResponse {
	if response == nil || len(response.Predictions) == 0 {
		return nil
	}

	// Convert predictions to DeepIntShield embeddings
	embeddings := make([]schemas.EmbeddingData, 0, len(response.Predictions))
	var usage *schemas.DeepIntShieldLLMUsage

	for i, prediction := range response.Predictions {
		if prediction.Embeddings == nil || len(prediction.Embeddings.Values) == 0 {
			continue
		}

		// Convert float64 values to float32 for DeepIntShield format
		embeddingFloat32 := make([]float32, 0, len(prediction.Embeddings.Values))
		for _, v := range prediction.Embeddings.Values {
			embeddingFloat32 = append(embeddingFloat32, float32(v))
		}

		// Create embedding object
		embedding := schemas.EmbeddingData{
			Object: "embedding",
			Embedding: schemas.EmbeddingStruct{
				EmbeddingArray: embeddingFloat32,
			},
			Index: i,
		}

		// Extract statistics if available
		if prediction.Embeddings.Statistics != nil {
			if usage == nil {
				usage = &schemas.DeepIntShieldLLMUsage{}
			}
			usage.TotalTokens += prediction.Embeddings.Statistics.TokenCount
			usage.PromptTokens += prediction.Embeddings.Statistics.TokenCount
		}

		embeddings = append(embeddings, embedding)
	}

	return &schemas.DeepIntShieldEmbeddingResponse{
		Object: "list",
		Data:   embeddings,
		Usage:  usage,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.EmbeddingRequest,
			Provider:    schemas.Vertex,
		},
	}
}
