package mistral

import (
	"slices"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func (response *MistralListModelsResponse) ToDeepIntShieldListModelsResponse(allowedModels []string) *schemas.DeepIntShieldListModelsResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldListModelsResponse{
		Data: make([]schemas.Model, 0, len(response.Data)),
	}

	includedModels := make(map[string]bool)
	for _, model := range response.Data {
		if len(allowedModels) > 0 && !slices.Contains(allowedModels, model.ID) {
			continue
		}
		deepintshieldResponse.Data = append(deepintshieldResponse.Data, schemas.Model{
			ID:            string(schemas.Mistral) + "/" + model.ID,
			Name:          schemas.Ptr(model.Name),
			Description:   schemas.Ptr(model.Description),
			Created:       schemas.Ptr(model.Created),
			ContextLength: schemas.Ptr(int(model.MaxContextLength)),
			OwnedBy:       schemas.Ptr(model.OwnedBy),
		})
		includedModels[model.ID] = true
	}

	// Backfill allowed models that were not in the response
	if len(allowedModels) > 0 {
		for _, allowedModel := range allowedModels {
			if !includedModels[allowedModel] {
				deepintshieldResponse.Data = append(deepintshieldResponse.Data, schemas.Model{
					ID:   string(schemas.Mistral) + "/" + allowedModel,
					Name: schemas.Ptr(allowedModel),
				})
				includedModels[allowedModel] = true
			}
		}
	}

	return deepintshieldResponse
}
