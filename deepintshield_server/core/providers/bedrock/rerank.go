package bedrock

import (
	"fmt"
	"sort"
	"strings"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToBedrockRerankRequest converts a DeepIntShield rerank request into Bedrock Agent Runtime format.
func ToBedrockRerankRequest(deepintshieldReq *schemas.DeepIntShieldRerankRequest, modelARN string) (*BedrockRerankRequest, error) {
	if deepintshieldReq == nil {
		return nil, fmt.Errorf("deepintshield rerank request is nil")
	}
	if strings.TrimSpace(modelARN) == "" {
		return nil, fmt.Errorf("bedrock rerank model ARN is empty")
	}
	if len(deepintshieldReq.Documents) == 0 {
		return nil, fmt.Errorf("documents are required for rerank request")
	}

	bedrockReq := &BedrockRerankRequest{
		Queries: []BedrockRerankQuery{
			{
				Type: bedrockRerankQueryTypeText,
				TextQuery: BedrockRerankTextRef{
					Text: deepintshieldReq.Query,
				},
			},
		},
		Sources: make([]BedrockRerankSource, len(deepintshieldReq.Documents)),
		RerankingConfiguration: BedrockRerankingConfiguration{
			Type: bedrockRerankConfigurationTypeBedrock,
			BedrockRerankingConfiguration: BedrockRerankingModelConfiguration{
				ModelConfiguration: BedrockRerankModelConfiguration{
					ModelARN: modelARN,
				},
			},
		},
	}

	for i, doc := range deepintshieldReq.Documents {
		bedrockReq.Sources[i] = BedrockRerankSource{
			Type: bedrockRerankSourceTypeInline,
			InlineDocumentSource: BedrockRerankInlineSource{
				Type: bedrockRerankInlineDocumentTypeText,
				TextDocument: BedrockRerankTextValue{
					Text: doc.Text,
				},
			},
		}
	}

	if deepintshieldReq.Params == nil {
		return bedrockReq, nil
	}

	if deepintshieldReq.Params.TopN != nil {
		topN := *deepintshieldReq.Params.TopN
		if topN < 1 {
			return nil, fmt.Errorf("top_n must be at least 1")
		}
		if topN > len(deepintshieldReq.Documents) {
			topN = len(deepintshieldReq.Documents)
		}
		bedrockReq.RerankingConfiguration.BedrockRerankingConfiguration.NumberOfResults = schemas.Ptr(topN)
	}

	additionalFields := make(map[string]interface{})
	if deepintshieldReq.Params.MaxTokensPerDoc != nil {
		additionalFields["max_tokens_per_doc"] = *deepintshieldReq.Params.MaxTokensPerDoc
	}
	if deepintshieldReq.Params.Priority != nil {
		additionalFields["priority"] = *deepintshieldReq.Params.Priority
	}
	for k, v := range deepintshieldReq.Params.ExtraParams {
		additionalFields[k] = v
	}
	if len(additionalFields) > 0 {
		bedrockReq.RerankingConfiguration.BedrockRerankingConfiguration.ModelConfiguration.AdditionalModelRequestFields = additionalFields
	}

	return bedrockReq, nil
}

// ToDeepIntShieldRerankResponse converts a Bedrock rerank response into DeepIntShield format.
func (response *BedrockRerankResponse) ToDeepIntShieldRerankResponse(documents []schemas.RerankDocument, returnDocuments bool) *schemas.DeepIntShieldRerankResponse {
	if response == nil {
		return nil
	}

	deepintshieldResponse := &schemas.DeepIntShieldRerankResponse{
		Results: make([]schemas.RerankResult, 0, len(response.Results)),
	}

	for _, result := range response.Results {
		rerankResult := schemas.RerankResult{
			Index:          result.Index,
			RelevanceScore: result.RelevanceScore,
		}
		if result.Document != nil && result.Document.TextDocument != nil {
			rerankResult.Document = &schemas.RerankDocument{
				Text: result.Document.TextDocument.Text,
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

	return deepintshieldResponse
}

// ToDeepIntShieldRerankRequest converts a Bedrock Agent Runtime rerank request to DeepIntShield format.
func (req *BedrockRerankRequest) ToDeepIntShieldRerankRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldRerankRequest {
	if req == nil {
		return nil
	}

	modelARN := req.RerankingConfiguration.BedrockRerankingConfiguration.ModelConfiguration.ModelARN
	provider, model := schemas.ParseModelString(modelARN, providerUtils.CheckAndSetDefaultProvider(ctx, schemas.Bedrock))

	deepintshieldReq := &schemas.DeepIntShieldRerankRequest{
		Provider: provider,
		Model:    model,
		Params:   &schemas.RerankParameters{},
	}

	// Extract query from the first query entry
	if len(req.Queries) > 0 {
		deepintshieldReq.Query = req.Queries[0].TextQuery.Text
	}

	// Convert sources to documents
	for _, source := range req.Sources {
		deepintshieldReq.Documents = append(deepintshieldReq.Documents, schemas.RerankDocument{
			Text: source.InlineDocumentSource.TextDocument.Text,
		})
	}

	// Extract TopN from NumberOfResults
	if req.RerankingConfiguration.BedrockRerankingConfiguration.NumberOfResults != nil {
		deepintshieldReq.Params.TopN = req.RerankingConfiguration.BedrockRerankingConfiguration.NumberOfResults
	}

	// Pass AdditionalModelRequestFields as ExtraParams
	if fields := req.RerankingConfiguration.BedrockRerankingConfiguration.ModelConfiguration.AdditionalModelRequestFields; len(fields) > 0 {
		deepintshieldReq.Params.ExtraParams = fields
	}

	return deepintshieldReq
}
