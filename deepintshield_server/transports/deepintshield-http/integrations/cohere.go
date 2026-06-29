package integrations

import (
	"context"
	"errors"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/providers/cohere"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/valyala/fasthttp"
)

// hydrateCohereRequestFromLargePayloadMetadata populates model + stream from
// LargePayloadMetadata when body parsing is skipped under large payload mode.
func hydrateCohereRequestFromLargePayloadMetadata(deepintshieldCtx *schemas.DeepIntShieldContext, req interface{}) {
	if deepintshieldCtx == nil {
		return
	}
	isLargePayload, _ := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyLargePayloadMode).(bool)
	if !isLargePayload {
		return
	}
	metadata := resolveLargePayloadMetadata(deepintshieldCtx)
	if metadata == nil {
		return
	}

	switch r := req.(type) {
	case *cohere.CohereChatRequest:
		if r.Model == "" {
			r.Model = metadata.Model
		}
		if metadata.StreamRequested != nil && r.Stream == nil {
			r.Stream = schemas.Ptr(*metadata.StreamRequested)
		}
	case *cohere.CohereEmbeddingRequest:
		if r.Model == "" {
			r.Model = metadata.Model
		}
	case *cohere.CohereRerankRequest:
		if r.Model == "" {
			r.Model = metadata.Model
		}
	case *cohere.CohereCountTokensRequest:
		if r.Model == "" {
			r.Model = metadata.Model
		}
	}
}

// cohereLargePayloadPreHook populates model + stream from LargePayloadMetadata
// when body parsing is skipped under large payload mode.
func cohereLargePayloadPreHook(_ *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, req interface{}) error {
	hydrateCohereRequestFromLargePayloadMetadata(deepintshieldCtx, req)
	return nil
}

// CohereRouter holds route registrations for Cohere endpoints.
// It supports Cohere's v2 chat, embeddings, and rerank APIs.
type CohereRouter struct {
	*GenericRouter
}

// NewCohereRouter creates a new CohereRouter with the given deepintshield client.
func NewCohereRouter(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, logger schemas.Logger) *CohereRouter {
	return &CohereRouter{
		GenericRouter: NewGenericRouter(client, handlerStore, CreateCohereRouteConfigs("/cohere"), nil, logger),
	}
}

// CreateCohereRouteConfigs creates route configurations for Cohere API endpoints.
func CreateCohereRouteConfigs(pathPrefix string) []RouteConfig {
	var routes []RouteConfig

	// Chat completions endpoint (v2/chat)
	routes = append(routes, RouteConfig{
		Type:        RouteConfigTypeCohere,
		Path:        pathPrefix + "/v2/chat",
		Method:      "POST",
		PreCallback: cohereLargePayloadPreHook,
		GetHTTPRequestType: func(ctx *fasthttp.RequestCtx) schemas.RequestType {
			return schemas.ChatCompletionRequest
		},
		GetRequestTypeInstance: func(ctx context.Context) interface{} {
			return &cohere.CohereChatRequest{}
		},
		RequestConverter: func(ctx *schemas.DeepIntShieldContext, req interface{}) (*schemas.DeepIntShieldRequest, error) {
			if cohereReq, ok := req.(*cohere.CohereChatRequest); ok {
				return &schemas.DeepIntShieldRequest{
					ChatRequest: cohereReq.ToDeepIntShieldChatRequest(ctx),
				}, nil
			}
			return nil, errors.New("invalid request type")
		},
		ChatResponseConverter: func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldChatResponse) (interface{}, error) {
			if resp.ExtraFields.Provider == schemas.Cohere {
				if resp.ExtraFields.RawResponse != nil {
					return resp.ExtraFields.RawResponse, nil
				}
			}
			return resp, nil
		},
		ErrorConverter: func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		},
		StreamConfig: &StreamConfig{
			ChatStreamResponseConverter: func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldChatResponse) (string, interface{}, error) {
				if resp.ExtraFields.Provider == schemas.Cohere {
					if resp.ExtraFields.RawResponse != nil {
						return "", resp.ExtraFields.RawResponse, nil
					}
				}
				return "", resp, nil
			},
			ErrorConverter: func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
				return err
			},
		},
	})

	// Embeddings endpoint (v2/embed)
	routes = append(routes, RouteConfig{
		Type:        RouteConfigTypeCohere,
		Path:        pathPrefix + "/v2/embed",
		Method:      "POST",
		PreCallback: cohereLargePayloadPreHook,
		GetHTTPRequestType: func(ctx *fasthttp.RequestCtx) schemas.RequestType {
			return schemas.EmbeddingRequest
		},
		GetRequestTypeInstance: func(ctx context.Context) interface{} {
			return &cohere.CohereEmbeddingRequest{}
		},
		RequestConverter: func(ctx *schemas.DeepIntShieldContext, req interface{}) (*schemas.DeepIntShieldRequest, error) {
			if cohereReq, ok := req.(*cohere.CohereEmbeddingRequest); ok {
				return &schemas.DeepIntShieldRequest{
					EmbeddingRequest: cohereReq.ToDeepIntShieldEmbeddingRequest(ctx),
				}, nil
			}
			return nil, errors.New("invalid embedding request type")
		},
		EmbeddingResponseConverter: func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldEmbeddingResponse) (interface{}, error) {
			if resp.ExtraFields.Provider == schemas.Cohere {
				if resp.ExtraFields.RawResponse != nil {
					return resp.ExtraFields.RawResponse, nil
				}
			}
			return resp, nil
		},
		ErrorConverter: func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		},
	})

	// Rerank endpoint (v2/rerank)
	routes = append(routes, RouteConfig{
		Type:        RouteConfigTypeCohere,
		Path:        pathPrefix + "/v2/rerank",
		Method:      "POST",
		PreCallback: cohereLargePayloadPreHook,
		GetHTTPRequestType: func(ctx *fasthttp.RequestCtx) schemas.RequestType {
			return schemas.RerankRequest
		},
		GetRequestTypeInstance: func(ctx context.Context) interface{} {
			return &cohere.CohereRerankRequest{}
		},
		RequestConverter: func(ctx *schemas.DeepIntShieldContext, req interface{}) (*schemas.DeepIntShieldRequest, error) {
			if cohereReq, ok := req.(*cohere.CohereRerankRequest); ok {
				return &schemas.DeepIntShieldRequest{
					RerankRequest: cohereReq.ToDeepIntShieldRerankRequest(ctx),
				}, nil
			}
			return nil, errors.New("invalid rerank request type")
		},
		RerankResponseConverter: func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldRerankResponse) (interface{}, error) {
			if resp.ExtraFields.Provider == schemas.Cohere {
				if resp.ExtraFields.RawResponse != nil {
					return resp.ExtraFields.RawResponse, nil
				}
			}
			return resp, nil
		},
		ErrorConverter: func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		},
	})

	// Tokenize endpoint (v1/tokenize)
	routes = append(routes, RouteConfig{
		Type:        RouteConfigTypeCohere,
		Path:        pathPrefix + "/v1/tokenize",
		Method:      "POST",
		PreCallback: cohereLargePayloadPreHook,
		GetHTTPRequestType: func(ctx *fasthttp.RequestCtx) schemas.RequestType {
			return schemas.CountTokensRequest
		},
		GetRequestTypeInstance: func(ctx context.Context) interface{} {
			return &cohere.CohereCountTokensRequest{}
		},
		RequestConverter: func(ctx *schemas.DeepIntShieldContext, req interface{}) (*schemas.DeepIntShieldRequest, error) {
			if cohereReq, ok := req.(*cohere.CohereCountTokensRequest); ok {
				return &schemas.DeepIntShieldRequest{
					CountTokensRequest: cohereReq.ToDeepIntShieldResponsesRequest(ctx),
				}, nil
			}
			return nil, errors.New("invalid count tokens request type")
		},
		CountTokensResponseConverter: func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldCountTokensResponse) (interface{}, error) {
			if resp.ExtraFields.Provider == schemas.Cohere {
				if resp.ExtraFields.RawResponse != nil {
					return resp.ExtraFields.RawResponse, nil
				}
			}
			return resp, nil
		},
		ErrorConverter: func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		},
	})

	return routes
}
