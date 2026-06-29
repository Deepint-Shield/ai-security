package integrations

import (
	"context"
	"testing"

	"github.com/deepint-shield/ai-security/core/providers/cohere"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCohereRouteConfigsIncludesRerank(t *testing.T) {
	routes := CreateCohereRouteConfigs("/cohere")

	assert.Len(t, routes, 4, "should have 4 cohere routes")

	var rerankRoute *RouteConfig
	for i := range routes {
		if routes[i].Path == "/cohere/v2/rerank" && routes[i].Method == "POST" {
			rerankRoute = &routes[i]
			break
		}
	}

	require.NotNil(t, rerankRoute, "rerank route should exist")
	assert.Equal(t, RouteConfigTypeCohere, rerankRoute.Type)
	assert.NotNil(t, rerankRoute.GetHTTPRequestType)
	assert.Equal(t, schemas.RerankRequest, rerankRoute.GetHTTPRequestType(nil))
	assert.NotNil(t, rerankRoute.GetRequestTypeInstance)
	assert.NotNil(t, rerankRoute.RequestConverter)
	assert.NotNil(t, rerankRoute.RerankResponseConverter)
	assert.NotNil(t, rerankRoute.ErrorConverter)

	reqInstance := rerankRoute.GetRequestTypeInstance(context.Background())
	_, ok := reqInstance.(*cohere.CohereRerankRequest)
	assert.True(t, ok, "rerank request instance should be CohereRerankRequest")
}

func TestCohereRerankRouteRequestConverter(t *testing.T) {
	routes := CreateCohereRouteConfigs("/cohere")

	var rerankRoute *RouteConfig
	for i := range routes {
		if routes[i].Path == "/cohere/v2/rerank" {
			rerankRoute = &routes[i]
			break
		}
	}
	require.NotNil(t, rerankRoute)
	require.NotNil(t, rerankRoute.RequestConverter)

	topN := 1
	req := &cohere.CohereRerankRequest{
		Model:     "rerank-v3.5",
		Query:     "what is deepintshield?",
		Documents: []string{"doc1", "doc2"},
		TopN:      &topN,
	}

	deepintshieldCtx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	deepintshieldReq, err := rerankRoute.RequestConverter(deepintshieldCtx, req)
	require.NoError(t, err)
	require.NotNil(t, deepintshieldReq)
	require.NotNil(t, deepintshieldReq.RerankRequest)

	assert.Equal(t, schemas.Cohere, deepintshieldReq.RerankRequest.Provider)
	assert.Equal(t, "rerank-v3.5", deepintshieldReq.RerankRequest.Model)
	assert.Equal(t, "what is deepintshield?", deepintshieldReq.RerankRequest.Query)
	require.Len(t, deepintshieldReq.RerankRequest.Documents, 2)
	assert.Equal(t, "doc1", deepintshieldReq.RerankRequest.Documents[0].Text)
	assert.Equal(t, "doc2", deepintshieldReq.RerankRequest.Documents[1].Text)
	require.NotNil(t, deepintshieldReq.RerankRequest.Params)
	require.NotNil(t, deepintshieldReq.RerankRequest.Params.TopN)
	assert.Equal(t, 1, *deepintshieldReq.RerankRequest.Params.TopN)
}

func TestCohereRerankResponseConverterUsesRawResponse(t *testing.T) {
	routes := CreateCohereRouteConfigs("/cohere")

	var rerankRoute *RouteConfig
	for i := range routes {
		if routes[i].Path == "/cohere/v2/rerank" {
			rerankRoute = &routes[i]
			break
		}
	}
	require.NotNil(t, rerankRoute)
	require.NotNil(t, rerankRoute.RerankResponseConverter)

	raw := map[string]interface{}{"id": "r-123", "results": []interface{}{}}
	resp := &schemas.DeepIntShieldRerankResponse{
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			Provider:    schemas.Cohere,
			RawResponse: raw,
		},
	}

	converted, err := rerankRoute.RerankResponseConverter(nil, resp)
	require.NoError(t, err)
	assert.Equal(t, raw, converted)
}
