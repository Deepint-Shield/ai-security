package elevenlabs

import (
	"slices"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func (response *ElevenlabsListModelsResponse) ToDeepIntShieldListModelsResponse(providerKey schemas.ModelProvider, allowedModels []string, unfiltered bool) *schemas.DeepIntShieldListModelsResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldListModelsResponse{
		Data: make([]schemas.Model, 0, len(*response)),
	}

	includedModels := make(map[string]bool)
	for _, model := range *response {
		if !unfiltered && len(allowedModels) > 0 && !slices.Contains(allowedModels, model.ModelID) {
			continue
		}
		deepintshieldResponse.Data = append(deepintshieldResponse.Data, schemas.Model{
			ID:   string(providerKey) + "/" + model.ModelID,
			Name: schemas.Ptr(model.Name),
		})
		includedModels[model.ModelID] = true
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
