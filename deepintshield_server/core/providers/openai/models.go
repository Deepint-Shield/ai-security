package openai

import (
	"slices"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldListModelsResponse converts an OpenAI list models response to a DeepIntShield list models response
func (response *OpenAIListModelsResponse) ToDeepIntShieldListModelsResponse(providerKey schemas.ModelProvider, allowedModels []string, unfiltered bool) *schemas.DeepIntShieldListModelsResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldListModelsResponse{
		Data: make([]schemas.Model, 0, len(response.Data)),
	}

	includedModels := make(map[string]bool)
	for _, model := range response.Data {
		if !unfiltered && len(allowedModels) > 0 && !slices.Contains(allowedModels, model.ID) {
			continue
		}
		deepintshieldResponse.Data = append(deepintshieldResponse.Data, schemas.Model{
			ID:            string(providerKey) + "/" + model.ID,
			Created:       model.Created,
			OwnedBy:       schemas.Ptr(model.OwnedBy),
			ContextLength: model.ContextWindow,
		})
		includedModels[model.ID] = true
	}

	// Backfill allowed models that were not in the response
	if !unfiltered && len(allowedModels) > 0 {
		for _, allowedModel := range allowedModels {
			if !includedModels[allowedModel] {
				deepintshieldResponse.Data = append(deepintshieldResponse.Data, schemas.Model{
					ID:   string(providerKey) + "/" + allowedModel,
					Name: schemas.Ptr(allowedModel),
				})
			}
		}
	}

	return deepintshieldResponse
}

// ToOpenAIListModelsResponse converts a DeepIntShield list models response to an OpenAI list models response
func ToOpenAIListModelsResponse(response *schemas.DeepIntShieldListModelsResponse) *OpenAIListModelsResponse {
	if response == nil {
		return nil
	}
	openaiResponse := &OpenAIListModelsResponse{
		Data: make([]OpenAIModel, 0, len(response.Data)),
	}
	for _, model := range response.Data {
		openaiModel := OpenAIModel{
			ID:     model.ID,
			Object: "model",
		}
		if model.Created != nil {
			openaiModel.Created = model.Created
		}
		if model.OwnedBy != nil {
			openaiModel.OwnedBy = *model.OwnedBy
		}

		openaiResponse.Data = append(openaiResponse.Data, openaiModel)

	}
	return openaiResponse
}
