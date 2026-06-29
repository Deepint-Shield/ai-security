package anthropic

import (
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func (response *AnthropicListModelsResponse) ToDeepIntShieldListModelsResponse(providerKey schemas.ModelProvider, allowedModels []string, unfiltered bool) *schemas.DeepIntShieldListModelsResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldListModelsResponse{
		Data:    make([]schemas.Model, 0, len(response.Data)),
		FirstID: response.FirstID,
		LastID:  response.LastID,
		HasMore: schemas.Ptr(response.HasMore),
	}

	// Map Anthropic's cursor-based pagination to DeepIntShield's token-based pagination
	// If there are more results, set next_page_token to last_id so it can be used in the next request
	if response.HasMore && response.LastID != nil {
		deepintshieldResponse.NextPageToken = *response.LastID
	}

	includedModels := make(map[string]bool)
	for _, model := range response.Data {
		modelID := model.ID
		if !unfiltered && len(allowedModels) > 0 {
			allowed := false
			for _, allowedModel := range allowedModels {
				if schemas.SameBaseModel(model.ID, allowedModel) {
					modelID = allowedModel
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}
		deepintshieldResponse.Data = append(deepintshieldResponse.Data, schemas.Model{
			ID:      string(providerKey) + "/" + modelID,
			Name:    schemas.Ptr(model.DisplayName),
			Created: schemas.Ptr(model.CreatedAt.Unix()),
		})
		includedModels[modelID] = true
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

func ToAnthropicListModelsResponse(response *schemas.DeepIntShieldListModelsResponse) *AnthropicListModelsResponse {
	if response == nil {
		return nil
	}

	anthropicResponse := &AnthropicListModelsResponse{
		Data: make([]AnthropicModel, 0, len(response.Data)),
	}
	if response.FirstID != nil {
		anthropicResponse.FirstID = response.FirstID
	}
	if response.LastID != nil {
		anthropicResponse.LastID = response.LastID
	}

	for _, model := range response.Data {
		anthropicModel := AnthropicModel{
			ID: model.ID,
		}
		if model.Name != nil {
			anthropicModel.DisplayName = *model.Name
		}
		if model.Created != nil {
			anthropicModel.CreatedAt = time.Unix(*model.Created, 0)
		}
		anthropicResponse.Data = append(anthropicResponse.Data, anthropicModel)
	}

	return anthropicResponse
}
