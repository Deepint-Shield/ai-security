package vertex

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

func buildVertexRankingConfig(projectID, rankingConfigOverride string) (string, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", fmt.Errorf("project ID is required for ranking config")
	}

	override := strings.TrimSpace(rankingConfigOverride)
	if override == "" {
		return fmt.Sprintf("projects/%s/locations/global/rankingConfigs/%s", projectID, vertexDefaultRankingConfigID), nil
	}

	override = strings.TrimSuffix(override, ":rank")
	if strings.HasPrefix(override, "projects/") {
		return override, nil
	}
	if strings.Contains(override, "/") {
		return "", fmt.Errorf("invalid ranking_config %q: must be resource name or config ID", rankingConfigOverride)
	}
	return fmt.Sprintf("projects/%s/locations/global/rankingConfigs/%s", projectID, override), nil
}

func getVertexRerankOptions(projectID string, params *schemas.RerankParameters) (*vertexRerankOptions, error) {
	options := &vertexRerankOptions{
		IgnoreRecordDetailsInResponse: true,
	}

	if params == nil || params.ExtraParams == nil {
		rankingConfig, err := buildVertexRankingConfig(projectID, "")
		if err != nil {
			return nil, err
		}
		options.RankingConfig = rankingConfig
		return options, nil
	}

	extraParams := params.ExtraParams

	rankingConfigOverride := ""
	if rawRankingConfig, exists := extraParams["ranking_config"]; exists {
		rankingConfig, ok := schemas.SafeExtractString(rawRankingConfig)
		if !ok {
			return nil, fmt.Errorf("invalid ranking_config: expected string")
		}
		rankingConfigOverride = rankingConfig
	}

	rankingConfig, err := buildVertexRankingConfig(projectID, rankingConfigOverride)
	if err != nil {
		return nil, err
	}
	options.RankingConfig = rankingConfig

	if rawIgnoreRecordDetails, exists := extraParams["ignore_record_details_in_response"]; exists {
		ignoreRecordDetailsInResponse, ok := schemas.SafeExtractBool(rawIgnoreRecordDetails)
		if !ok {
			return nil, fmt.Errorf("invalid ignore_record_details_in_response: expected bool")
		}
		options.IgnoreRecordDetailsInResponse = ignoreRecordDetailsInResponse
	}

	if rawUserLabels, exists := extraParams["user_labels"]; exists {
		userLabels, ok := schemas.SafeExtractStringMap(rawUserLabels)
		if !ok {
			return nil, fmt.Errorf("invalid user_labels: expected map[string]string")
		}
		options.UserLabels = userLabels
	}

	return options, nil
}

// ToVertexRankRequest converts a DeepIntShield rerank request to Discovery Engine rank API format.
func ToVertexRankRequest(deepintshieldReq *schemas.DeepIntShieldRerankRequest, modelDeployment string, options *vertexRerankOptions) (*VertexRankRequest, error) {
	if deepintshieldReq == nil {
		return nil, fmt.Errorf("deepintshield rerank request is nil")
	}
	if options == nil {
		return nil, fmt.Errorf("vertex rerank options are nil")
	}
	if len(deepintshieldReq.Documents) == 0 {
		return nil, fmt.Errorf("documents are required for rerank request")
	}
	if len(deepintshieldReq.Documents) > vertexMaxRerankRecordsPerQuery {
		return nil, fmt.Errorf("vertex rerank supports up to %d records per request", vertexMaxRerankRecordsPerQuery)
	}

	rankRequest := &VertexRankRequest{
		Query:   deepintshieldReq.Query,
		Records: make([]VertexRankRecord, len(deepintshieldReq.Documents)),
	}

	for i, doc := range deepintshieldReq.Documents {
		recordID := fmt.Sprintf("%s%d", vertexSyntheticRecordPrefix, i)
		content := doc.Text
		record := VertexRankRecord{
			ID:      recordID,
			Content: &content,
		}

		if doc.Meta != nil {
			if rawTitle, exists := doc.Meta["title"]; exists {
				if title, ok := schemas.SafeExtractString(rawTitle); ok && strings.TrimSpace(title) != "" {
					record.Title = &title
				}
			}
		}

		rankRequest.Records[i] = record
	}

	if deepintshieldReq.Params != nil && deepintshieldReq.Params.TopN != nil {
		topN := *deepintshieldReq.Params.TopN
		if topN < 1 {
			return nil, fmt.Errorf("top_n must be at least 1")
		}
		if topN > len(deepintshieldReq.Documents) {
			topN = len(deepintshieldReq.Documents)
		}
		rankRequest.TopN = &topN
	}

	if trimmedModel := strings.TrimSpace(modelDeployment); trimmedModel != "" {
		rankRequest.Model = &trimmedModel
	}

	ignoreRecordDetailsInResponse := options.IgnoreRecordDetailsInResponse
	rankRequest.IgnoreRecordDetailsInResponse = &ignoreRecordDetailsInResponse

	if len(options.UserLabels) > 0 {
		rankRequest.UserLabels = options.UserLabels
	}

	return rankRequest, nil
}

// ToDeepIntShieldRerankRequest converts a Discovery Engine rank request to DeepIntShield format.
func (req *VertexRankRequest) ToDeepIntShieldRerankRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldRerankRequest {
	if req == nil {
		return nil
	}

	var provider schemas.ModelProvider
	var model string
	if req.Model != nil {
		provider, model = schemas.ParseModelString(*req.Model, providerUtils.CheckAndSetDefaultProvider(ctx, schemas.Vertex))
	} else {
		provider = providerUtils.CheckAndSetDefaultProvider(ctx, schemas.Vertex)
	}

	deepintshieldReq := &schemas.DeepIntShieldRerankRequest{
		Provider: provider,
		Model:    model,
		Query:    req.Query,
		Params:   &schemas.RerankParameters{},
	}

	// Convert records to documents
	for _, record := range req.Records {
		doc := schemas.RerankDocument{
			ID: &record.ID,
		}
		if record.Content != nil {
			doc.Text = *record.Content
		}
		if record.Title != nil {
			doc.Meta = map[string]interface{}{
				"title": *record.Title,
			}
		}
		deepintshieldReq.Documents = append(deepintshieldReq.Documents, doc)
	}

	// Extract TopN
	if req.TopN != nil {
		deepintshieldReq.Params.TopN = req.TopN
	}

	// Pass extra fields as ExtraParams
	extraParams := make(map[string]interface{})
	if req.IgnoreRecordDetailsInResponse != nil {
		extraParams["ignore_record_details_in_response"] = *req.IgnoreRecordDetailsInResponse
	}
	if len(req.UserLabels) > 0 {
		extraParams["user_labels"] = req.UserLabels
	}
	if len(extraParams) > 0 {
		deepintshieldReq.Params.ExtraParams = extraParams
	}

	return deepintshieldReq
}

func parseVertexSyntheticRecordIndex(recordID string, maxDocs int) (int, error) {
	if !strings.HasPrefix(recordID, vertexSyntheticRecordPrefix) {
		return 0, fmt.Errorf("invalid record id %q: expected prefix %q", recordID, vertexSyntheticRecordPrefix)
	}
	indexStr := strings.TrimPrefix(recordID, vertexSyntheticRecordPrefix)
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		return 0, fmt.Errorf("invalid record id %q: %w", recordID, err)
	}
	if index < 0 || index >= maxDocs {
		return 0, fmt.Errorf("record id %q maps to out-of-range index %d", recordID, index)
	}
	return index, nil
}

// ToDeepIntShieldRerankResponse converts a Discovery Engine rank response to DeepIntShield format.
func (response *VertexRankResponse) ToDeepIntShieldRerankResponse(documents []schemas.RerankDocument, returnDocuments bool) (*schemas.DeepIntShieldRerankResponse, error) {
	if response == nil {
		return nil, fmt.Errorf("vertex rerank response is nil")
	}

	results := make([]schemas.RerankResult, 0, len(response.Records))
	seenIndices := make(map[int]struct{}, len(response.Records))

	for _, record := range response.Records {
		index, err := parseVertexSyntheticRecordIndex(record.ID, len(documents))
		if err != nil {
			return nil, err
		}

		if _, seen := seenIndices[index]; seen {
			return nil, fmt.Errorf("duplicate record id mapping for index %d", index)
		}
		seenIndices[index] = struct{}{}

		result := schemas.RerankResult{
			Index:          index,
			RelevanceScore: record.Score,
		}

		if returnDocuments {
			doc := documents[index]
			result.Document = &doc
		}

		results = append(results, result)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].RelevanceScore == results[j].RelevanceScore {
			return results[i].Index < results[j].Index
		}
		return results[i].RelevanceScore > results[j].RelevanceScore
	})

	return &schemas.DeepIntShieldRerankResponse{
		Results: results,
	}, nil
}

func parseDiscoveryEngineErrorMessage(responseBody []byte) string {
	if len(responseBody) == 0 {
		return ""
	}

	var errorResponse map[string]interface{}
	if err := sonic.Unmarshal(responseBody, &errorResponse); err == nil {
		if rawError, exists := errorResponse["error"]; exists {
			if errorMap, ok := rawError.(map[string]interface{}); ok {
				if message, ok := schemas.SafeExtractString(errorMap["message"]); ok && strings.TrimSpace(message) != "" {
					return message
				}
			}
		}
	}

	rawString := strings.TrimSpace(string(responseBody))
	if rawString == "" {
		return ""
	}

	return rawString
}
