package integrations

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/providers/gemini"
	"github.com/deepint-shield/ai-security/core/providers/vertex"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestCreateGenAIRerankRouteConfig(t *testing.T) {
	route := createGenAIRerankRouteConfig("/genai")

	assert.Equal(t, "/genai/v1/rank", route.Path)
	assert.Equal(t, "POST", route.Method)
	assert.Equal(t, RouteConfigTypeGenAI, route.Type)
	assert.NotNil(t, route.GetHTTPRequestType)
	assert.Equal(t, schemas.RerankRequest, route.GetHTTPRequestType(nil))
	assert.NotNil(t, route.GetRequestTypeInstance)
	assert.NotNil(t, route.RequestConverter)
	assert.NotNil(t, route.RerankResponseConverter)
	assert.NotNil(t, route.ErrorConverter)
	assert.Nil(t, route.PreCallback)

	// Verify request instance type
	reqInstance := route.GetRequestTypeInstance(context.Background())
	_, ok := reqInstance.(*vertex.VertexRankRequest)
	assert.True(t, ok, "GetRequestTypeInstance should return *vertex.VertexRankRequest")
}

func TestCreateGenAIRouteConfigsIncludesRerank(t *testing.T) {
	routes := CreateGenAIRouteConfigs("/genai")

	found := false
	for _, route := range routes {
		if route.Path == "/genai/v1/rank" && route.Method == "POST" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected rerank route in genai route configs")
}

func TestCreateGenAIRouteConfigsIncludesRerankForCompositePrefixes(t *testing.T) {
	prefixes := []string{"/litellm", "/langchain", "/pydanticai"}

	for _, prefix := range prefixes {
		routes := CreateGenAIRouteConfigs(prefix)
		found := false
		for _, route := range routes {
			if route.Path == prefix+"/v1/rank" && route.Method == "POST" {
				found = true
				break
			}
		}
		assert.Truef(t, found, "expected rerank route for prefix %s", prefix)
	}
}

func TestGenAIRerankRequestConverter(t *testing.T) {
	route := createGenAIRerankRouteConfig("/genai")
	require.NotNil(t, route.RequestConverter)

	model := "semantic-ranker-default@latest"
	topN := 2
	content1 := "Paris is capital of France"
	content2 := "Berlin is capital of Germany"
	req := &vertex.VertexRankRequest{
		Model: &model,
		Query: "capital of france",
		Records: []vertex.VertexRankRecord{
			{ID: "rec-1", Content: &content1},
			{ID: "rec-2", Content: &content2},
		},
		TopN: &topN,
	}

	deepintshieldCtx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	deepintshieldReq, err := route.RequestConverter(deepintshieldCtx, req)
	require.NoError(t, err)
	require.NotNil(t, deepintshieldReq)
	require.NotNil(t, deepintshieldReq.RerankRequest)
	assert.Equal(t, schemas.Vertex, deepintshieldReq.RerankRequest.Provider)
	assert.Equal(t, "semantic-ranker-default@latest", deepintshieldReq.RerankRequest.Model)
	assert.Equal(t, "capital of france", deepintshieldReq.RerankRequest.Query)
	require.Len(t, deepintshieldReq.RerankRequest.Documents, 2)
	assert.Equal(t, "Paris is capital of France", deepintshieldReq.RerankRequest.Documents[0].Text)
	assert.Equal(t, "Berlin is capital of Germany", deepintshieldReq.RerankRequest.Documents[1].Text)
	require.NotNil(t, deepintshieldReq.RerankRequest.Params)
	require.NotNil(t, deepintshieldReq.RerankRequest.Params.TopN)
	assert.Equal(t, 2, *deepintshieldReq.RerankRequest.Params.TopN)
}

func TestGenAIRerankResponseConverterUsesRawResponse(t *testing.T) {
	route := createGenAIRerankRouteConfig("/genai")
	require.NotNil(t, route.RerankResponseConverter)

	raw := map[string]interface{}{"records": []interface{}{}}
	resp := &schemas.DeepIntShieldRerankResponse{
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			Provider:    schemas.Vertex,
			RawResponse: raw,
		},
	}
	converted, err := route.RerankResponseConverter(nil, resp)
	require.NoError(t, err)
	assert.Equal(t, raw, converted)
}

func TestGenAIRerankResponseConverterFallsBackWhenNotVertex(t *testing.T) {
	route := createGenAIRerankRouteConfig("/genai")
	require.NotNil(t, route.RerankResponseConverter)

	resp := &schemas.DeepIntShieldRerankResponse{
		Results: []schemas.RerankResult{
			{Index: 0, RelevanceScore: 0.9},
		},
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			Provider: schemas.Cohere,
		},
	}
	converted, err := route.RerankResponseConverter(nil, resp)
	require.NoError(t, err)
	assert.Equal(t, resp, converted)
}

func TestCreateGenAIRouteConfigsIncludesModelMetadataRoute(t *testing.T) {
	routes := CreateGenAIRouteConfigs("/genai")

	found := false
	for _, route := range routes {
		if route.Path == "/genai/v1beta/models/{model}" && route.Method == "GET" {
			found = true
			assert.Equal(t, schemas.ListModelsRequest, route.GetHTTPRequestType(nil))
			require.NotNil(t, route.PreCallback)
			require.NotNil(t, route.ListModelsResponseConverter)
			break
		}
	}

	assert.True(t, found, "expected model metadata route in genai route configs")
}

func TestExtractGeminiModelMetadataParams(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("model", "models/gemini-3-pro-preview")

	listReq := &schemas.DeepIntShieldListModelsRequest{}
	deepintshieldCtx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)

	err := extractGeminiModelMetadataParams(ctx, deepintshieldCtx, listReq)
	require.NoError(t, err)
	assert.Equal(t, schemas.Gemini, listReq.Provider)
	assert.Equal(t, "/models/gemini-3-pro-preview", deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyURLPath))
	assert.Equal(t, "gemini-3-pro-preview", deepintshieldCtx.Value(requestedGeminiModelMetadataContextKey))
}

func TestConvertGeminiModelMetadataResponse(t *testing.T) {
	deepintshieldCtx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	deepintshieldCtx.SetValue(requestedGeminiModelMetadataContextKey, "gemini-2.5-pro")

	resp := &schemas.DeepIntShieldListModelsResponse{
		Data: []schemas.Model{{ID: "gemini/gemini-2.5-pro", Name: schemas.Ptr("Gemini 2.5 Pro")}},
	}

	converted, err := convertGeminiModelMetadataResponse(deepintshieldCtx, resp)
	require.NoError(t, err)

	model, ok := converted.(gemini.GeminiModel)
	require.True(t, ok, "expected gemini.GeminiModel")
	assert.Equal(t, "models/gemini-2.5-pro", model.Name)
	assert.Equal(t, "Gemini 2.5 Pro", model.DisplayName)
}

func TestConvertGeminiModelMetadataResponse_MatchesRequestedModelNotFirst(t *testing.T) {
	deepintshieldCtx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	deepintshieldCtx.SetValue(requestedGeminiModelMetadataContextKey, "gemini-3-pro-preview")

	resp := &schemas.DeepIntShieldListModelsResponse{
		Data: []schemas.Model{
			{ID: "gemini/gemini-1.5-pro", Name: schemas.Ptr("Gemini 1.5 Pro")},
			{ID: "gemini/gemini-3-pro-preview", Name: schemas.Ptr("Gemini 3 Pro Preview")},
		},
	}

	converted, err := convertGeminiModelMetadataResponse(deepintshieldCtx, resp)
	require.NoError(t, err)

	model, ok := converted.(gemini.GeminiModel)
	require.True(t, ok, "expected gemini.GeminiModel")
	assert.Equal(t, "models/gemini-3-pro-preview", model.Name)
	assert.Equal(t, "Gemini 3 Pro Preview", model.DisplayName)
}

func TestConvertGeminiModelMetadataResponse_EmptyReturnsMinimalModel(t *testing.T) {
	deepintshieldCtx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	deepintshieldCtx.SetValue(requestedGeminiModelMetadataContextKey, "gemini-3-pro-preview")

	converted, err := convertGeminiModelMetadataResponse(deepintshieldCtx, &schemas.DeepIntShieldListModelsResponse{Data: []schemas.Model{}})
	require.NoError(t, err)
	model, ok := converted.(gemini.GeminiModel)
	require.True(t, ok, "expected gemini.GeminiModel")
	assert.Equal(t, "models/gemini-3-pro-preview", model.Name)
}
