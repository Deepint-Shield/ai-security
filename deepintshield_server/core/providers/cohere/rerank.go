package cohere

import (
	"sort"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"gopkg.in/yaml.v3"
)

// ToCohereRerankRequest converts a DeepIntShield rerank request to Cohere format
func ToCohereRerankRequest(deepintshieldReq *schemas.DeepIntShieldRerankRequest) *CohereRerankRequest {
	if deepintshieldReq == nil {
		return nil
	}

	cohereReq := &CohereRerankRequest{
		Model: deepintshieldReq.Model,
		Query: deepintshieldReq.Query,
	}

	// Cohere v2 expects documents as a list of strings.
	documents := make([]string, len(deepintshieldReq.Documents))
	for i, doc := range deepintshieldReq.Documents {
		documents[i] = formatCohereRerankDocument(doc)
	}
	cohereReq.Documents = documents

	if deepintshieldReq.Params != nil {
		cohereReq.TopN = deepintshieldReq.Params.TopN
		cohereReq.MaxTokensPerDoc = deepintshieldReq.Params.MaxTokensPerDoc
		cohereReq.Priority = deepintshieldReq.Params.Priority
		cohereReq.ExtraParams = deepintshieldReq.Params.ExtraParams
	}

	return cohereReq
}

// ToDeepIntShieldRerankRequest converts a Cohere rerank request to DeepIntShield format
func (req *CohereRerankRequest) ToDeepIntShieldRerankRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldRerankRequest {
	if req == nil {
		return nil
	}

	provider, model := schemas.ParseModelString(req.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.Cohere))

	deepintshieldReq := &schemas.DeepIntShieldRerankRequest{
		Provider: provider,
		Model:    model,
		Query:    req.Query,
		Params:   &schemas.RerankParameters{},
	}

	// Convert documents
	for _, doc := range req.Documents {
		deepintshieldReq.Documents = append(deepintshieldReq.Documents, schemas.RerankDocument{
			Text: doc,
		})
	}

	if req.TopN != nil {
		deepintshieldReq.Params.TopN = req.TopN
	}
	if req.MaxTokensPerDoc != nil {
		deepintshieldReq.Params.MaxTokensPerDoc = req.MaxTokensPerDoc
	}
	if req.Priority != nil {
		deepintshieldReq.Params.Priority = req.Priority
	}
	if req.ExtraParams != nil {
		deepintshieldReq.Params.ExtraParams = req.ExtraParams
	}

	return deepintshieldReq
}

// ToDeepIntShieldRerankResponse converts a Cohere rerank response to DeepIntShield format.
func (response *CohereRerankResponse) ToDeepIntShieldRerankResponse(documents []schemas.RerankDocument, returnDocuments bool) *schemas.DeepIntShieldRerankResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldRerankResponse{
		ID: response.ID,
	}

	// Convert results
	for _, result := range response.Results {
		rerankResult := schemas.RerankResult{
			Index:          result.Index,
			RelevanceScore: result.RelevanceScore,
		}

		// Convert document if present
		if len(result.Document) > 0 {
			var docMap map[string]interface{}
			if err := sonic.Unmarshal(result.Document, &docMap); err == nil {
				doc := &schemas.RerankDocument{}
				populated := false
				if text, ok := docMap["text"].(string); ok {
					doc.Text = text
					populated = true
				}
				if id, ok := docMap["id"].(string); ok {
					doc.ID = &id
					populated = true
				}
				// Collect metadata: unwrap "metadata"/"meta" keys to avoid nesting
				meta := make(map[string]interface{})
				if rawMeta, ok := docMap["metadata"].(map[string]interface{}); ok {
					for k, v := range rawMeta {
						meta[k] = v
					}
				} else if rawMeta, ok := docMap["meta"].(map[string]interface{}); ok {
					for k, v := range rawMeta {
						meta[k] = v
					}
				}
				for k, v := range docMap {
					if k != "text" && k != "id" && k != "metadata" && k != "meta" {
						meta[k] = v
					}
				}
				if len(meta) > 0 {
					doc.Meta = meta
					populated = true
				}
				if populated {
					rerankResult.Document = doc
				}
			}
		}

		deepintshieldResponse.Results = append(deepintshieldResponse.Results, rerankResult)
	}
	sort.SliceStable(deepintshieldResponse.Results, func(i, j int) bool {
		if deepintshieldResponse.Results[i].RelevanceScore == deepintshieldResponse.Results[j].RelevanceScore {
			return deepintshieldResponse.Results[i].Index < deepintshieldResponse.Results[j].Index
		}
		return deepintshieldResponse.Results[i].RelevanceScore > deepintshieldResponse.Results[j].RelevanceScore
	})
	if returnDocuments {
		for i := range deepintshieldResponse.Results {
			resultIndex := deepintshieldResponse.Results[i].Index
			if resultIndex >= 0 && resultIndex < len(documents) {
				deepintshieldResponse.Results[i].Document = schemas.Ptr(documents[resultIndex])
			}
		}
	}

	// Convert usage information
	if response.Meta != nil {
		promptTokens := 0
		completionTokens := 0
		hasTokenUsage := false
		if response.Meta.Tokens != nil {
			if response.Meta.Tokens.InputTokens != nil {
				promptTokens = int(*response.Meta.Tokens.InputTokens)
				hasTokenUsage = true
			}
			if response.Meta.Tokens.OutputTokens != nil {
				completionTokens = int(*response.Meta.Tokens.OutputTokens)
				hasTokenUsage = true
			}
		} else if response.Meta.BilledUnits != nil {
			if response.Meta.BilledUnits.InputTokens != nil {
				promptTokens = int(*response.Meta.BilledUnits.InputTokens)
				hasTokenUsage = true
			}
			if response.Meta.BilledUnits.OutputTokens != nil {
				completionTokens = int(*response.Meta.BilledUnits.OutputTokens)
				hasTokenUsage = true
			}
		}
		if hasTokenUsage {
			deepintshieldResponse.Usage = &schemas.DeepIntShieldLLMUsage{
				PromptTokens:     promptTokens,
				CompletionTokens: completionTokens,
				TotalTokens:      promptTokens + completionTokens,
			}
		}
	}

	return deepintshieldResponse
}

func formatCohereRerankDocument(doc schemas.RerankDocument) string {
	if doc.ID == nil && len(doc.Meta) == 0 {
		return doc.Text
	}

	// Keep metadata/id available by encoding a structured string document.
	documentPayload := map[string]interface{}{
		"text": doc.Text,
	}
	if doc.ID != nil {
		documentPayload["id"] = *doc.ID
	}
	if len(doc.Meta) > 0 {
		documentPayload["metadata"] = doc.Meta
	}

	encoded, err := yaml.Marshal(documentPayload)
	if err != nil {
		return doc.Text
	}
	return string(encoded)
}
