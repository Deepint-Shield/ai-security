package cohere

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"net/http"
	"net/url"

	"github.com/bytedance/sonic"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"

	"github.com/valyala/fasthttp"
)

// cohereResponsePool provides a pool for Cohere v2 response objects.
var cohereResponsePool = sync.Pool{
	New: func() interface{} {
		return &CohereChatResponse{}
	},
}

// cohereEmbeddingResponsePool provides a pool for Cohere embedding response objects.
var cohereEmbeddingResponsePool = sync.Pool{
	New: func() interface{} {
		return &CohereEmbeddingResponse{}
	},
}

// acquireCohereEmbeddingResponse gets a Cohere embedding response from the pool and resets it.
func acquireCohereEmbeddingResponse() *CohereEmbeddingResponse {
	resp := cohereEmbeddingResponsePool.Get().(*CohereEmbeddingResponse)
	*resp = CohereEmbeddingResponse{} // Reset the struct
	return resp
}

// releaseCohereEmbeddingResponse returns a Cohere embedding response to the pool.
func releaseCohereEmbeddingResponse(resp *CohereEmbeddingResponse) {
	if resp != nil {
		cohereEmbeddingResponsePool.Put(resp)
	}
}

// cohereRerankResponsePool provides a pool for Cohere rerank response objects.
var cohereRerankResponsePool = sync.Pool{
	New: func() interface{} {
		return &CohereRerankResponse{}
	},
}

// acquireCohereRerankResponse gets a Cohere rerank response from the pool and resets it.
func acquireCohereRerankResponse() *CohereRerankResponse {
	resp := cohereRerankResponsePool.Get().(*CohereRerankResponse)
	*resp = CohereRerankResponse{} // Reset the struct
	return resp
}

// releaseCohereRerankResponse returns a Cohere rerank response to the pool.
func releaseCohereRerankResponse(resp *CohereRerankResponse) {
	if resp != nil {
		cohereRerankResponsePool.Put(resp)
	}
}

// acquireCohereResponse gets a Cohere v2 response from the pool and resets it.
func acquireCohereResponse() *CohereChatResponse {
	resp := cohereResponsePool.Get().(*CohereChatResponse)
	*resp = CohereChatResponse{} // Reset the struct
	return resp
}

// releaseCohereResponse returns a Cohere v2 response to the pool.
func releaseCohereResponse(resp *CohereChatResponse) {
	if resp != nil {
		cohereResponsePool.Put(resp)
	}
}

// CohereProvider implements the Provider interface for Cohere.
type CohereProvider struct {
	logger               schemas.Logger                // Logger for provider operations
	client               *fasthttp.Client              // HTTP client for API requests
	networkConfig        schemas.NetworkConfig         // Network configuration including extra headers
	sendBackRawRequest   bool                          // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse  bool                          // Whether to include raw response in DeepIntShieldResponse
	customProviderConfig *schemas.CustomProviderConfig // Custom provider config
}

// NewCohereProvider creates a new Cohere provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts and connection limits.
func NewCohereProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*CohereProvider, error) {
	config.CheckAndSetDefaults()

	requestTimeout := time.Second * time.Duration(config.NetworkConfig.DefaultRequestTimeoutInSeconds)
	client := &fasthttp.Client{
		ReadTimeout:         requestTimeout,
		WriteTimeout:        requestTimeout,
		MaxConnsPerHost:     config.NetworkConfig.MaxConnsPerHost,
		MaxIdleConnDuration: 30 * time.Second,
		MaxConnWaitTimeout:  requestTimeout,
		MaxConnDuration:     time.Second * time.Duration(schemas.DefaultMaxConnDurationInSeconds),
		ConnPoolStrategy:    fasthttp.FIFO,
	}

	// Setting proxy and retry policy
	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)
	// Pre-warm response pools
	for i := 0; i < config.ConcurrencyAndBufferSize.Concurrency; i++ {
		cohereResponsePool.Put(&CohereChatResponse{})
		cohereEmbeddingResponsePool.Put(&CohereEmbeddingResponse{})
		cohereRerankResponsePool.Put(&CohereRerankResponse{})
	}

	// Set default BaseURL if not provided
	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = "https://api.cohere.ai"
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &CohereProvider{
		logger:               logger,
		client:               client,
		networkConfig:        config.NetworkConfig,
		customProviderConfig: config.CustomProviderConfig,
		sendBackRawRequest:   config.SendBackRawRequest,
		sendBackRawResponse:  config.SendBackRawResponse,
	}, nil
}

// GetProviderKey returns the provider identifier for Cohere.
func (provider *CohereProvider) GetProviderKey() schemas.ModelProvider {
	return providerUtils.GetProviderName(schemas.Cohere, provider.customProviderConfig)
}

// buildRequestURL constructs the full request URL using the provider's configuration.
func (provider *CohereProvider) buildRequestURL(ctx *schemas.DeepIntShieldContext, defaultPath string, requestType schemas.RequestType) string {
	path, isCompleteURL := providerUtils.GetRequestPath(ctx, defaultPath, provider.customProviderConfig, requestType)
	if isCompleteURL {
		return path
	}
	return providerUtils.ResolveBaseURL(ctx, provider.networkConfig.BaseURL) + path
}

// completeRequest sends a request to Cohere's API and handles the response.
// It constructs the API URL, sets up authentication, and processes the response.
// Returns the response body or an error if the request fails.
func (provider *CohereProvider) completeRequest(ctx *schemas.DeepIntShieldContext, jsonData []byte, url string, key string, meta *providerUtils.RequestMetadata) ([]byte, time.Duration, map[string]string, *schemas.DeepIntShieldError) {
	// Create the request with the JSON body
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	respOwned := true
	defer func() {
		if respOwned {
			fasthttp.ReleaseResponse(resp)
		}
	}()

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.SetRequestURI(url)
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	usedLargePayloadBody := providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.Cohere)
	if !usedLargePayloadBody {
		req.SetBody(jsonData)
	}

	// Send the request with optional large response streaming
	activeClient := providerUtils.PrepareResponseStreaming(ctx, provider.client, resp)
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, activeClient, req, resp)
	defer wait()
	if usedLargePayloadBody {
		providerUtils.DrainLargePayloadRemainder(ctx)
	}
	if deepintshieldErr != nil {
		return nil, latency, nil, deepintshieldErr
	}

	// Extract provider response headers before status check so error responses also forward them
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		providerUtils.MaterializeStreamErrorBody(ctx, resp)
		return nil, latency, providerResponseHeaders, parseCohereError(resp, meta)
	}

	body, isLargeResp, decodeErr := providerUtils.FinalizeResponseWithLargeDetection(ctx, resp, provider.GetProviderKey(), provider.logger)
	if decodeErr != nil {
		return nil, latency, providerResponseHeaders, decodeErr
	}
	if isLargeResp {
		respOwned = false
		return nil, latency, providerResponseHeaders, nil
	}

	return body, latency, providerResponseHeaders, nil
}

// listModelsByKey performs a list models request for a single key.
// Returns the response and latency, or an error if the request fails.
func (provider *CohereProvider) listModelsByKey(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Build base URL first
	baseURL := provider.buildRequestURL(ctx, "/v1/models", schemas.ListModelsRequest)

	// Parse and add query parameters
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to parse request URL", err, providerName)
	}

	q := u.Query()
	q.Set("page_size", strconv.Itoa(schemas.DefaultPageSize))
	if request.ExtraParams != nil {
		if endpoint, ok := request.ExtraParams["endpoint"].(string); ok && endpoint != "" {
			q.Set("endpoint", endpoint)
		}
		if defaultOnly, ok := request.ExtraParams["default_only"].(bool); ok && defaultOnly {
			q.Set("default_only", "true")
		}
	}
	u.RawQuery = q.Encode()

	// Set the final URL
	req.SetRequestURI(u.String())
	req.Header.SetMethod(http.MethodGet)
	req.Header.SetContentType("application/json")
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key.Value.GetValue()))
	}

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Store provider response headers in context before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, parseCohereError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			RequestType: schemas.ListModelsRequest,
		})
	}

	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}

	// Parse Cohere list models response
	var cohereResponse CohereListModelsResponse
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &cohereResponse, nil, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Convert Cohere v2 response to DeepIntShield response
	response := cohereResponse.ToDeepIntShieldListModelsResponse(providerName, key.Models, request.Unfiltered)

	response.ExtraFields.Latency = latency.Milliseconds()

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		response.ExtraFields.RawRequest = rawRequest
	}

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		response.ExtraFields.RawResponse = rawResponse
	}

	return response, nil
}

// ListModels performs a list models request to Cohere's API.
// Requests are made concurrently for improved performance.
func (provider *CohereProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.ListModelsRequest); err != nil {
		return nil, err
	}
	if provider.customProviderConfig != nil && provider.customProviderConfig.IsKeyLess {
		return providerUtils.HandleKeylessListModelsRequest(provider.GetProviderKey(), func() (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
			return provider.listModelsByKey(ctx, schemas.Key{}, request)
		})
	}
	return providerUtils.HandleMultipleListModelsRequests(
		ctx,
		keys,
		request,
		provider.listModelsByKey,
	)
}

// TextCompletion is not supported by the Cohere provider.
// Returns an error indicating that text completion is not supported.
func (provider *CohereProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

// TextCompletionStream performs a streaming text completion request to Cohere's API.
// It formats the request, sends it to Cohere, and processes the response.
// Returns a channel of DeepIntShieldStreamChunk objects or an error if the request fails.
func (provider *CohereProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

// ChatCompletion performs a chat completion request to the Cohere API using v2 converter.
// It formats the request, sends it to Cohere, and processes the response.
// Returns a DeepIntShieldResponse containing the completion results or an error if the request fails.
func (provider *CohereProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	// Check if chat completion is allowed
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.ChatCompletionRequest); err != nil {
		return nil, err
	}

	// Convert to Cohere v2 request
	jsonBody, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToCohereChatCompletionRequest(request)
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, provider.buildRequestURL(ctx, "/v2/chat", schemas.ChatCompletionRequest), key.Value.GetValue(), &providerUtils.RequestMetadata{
		Provider:    provider.GetProviderKey(),
		Model:       request.Model,
		RequestType: schemas.ChatCompletionRequest,
	})
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Large response mode: return lightweight response with metadata only
	if isLargeResp, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); isLargeResp {
		return &schemas.DeepIntShieldChatResponse{
			Model: request.Model,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				Provider:                provider.GetProviderKey(),
				ModelRequested:          request.Model,
				RequestType:             schemas.ChatCompletionRequest,
				Latency:                 latency.Milliseconds(),
				ProviderResponseHeaders: providerResponseHeaders,
			},
		}, nil
	}

	// Create response object from pool
	response := acquireCohereResponse()
	defer releaseCohereResponse(response)

	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, response, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	deepintshieldResponse := response.ToDeepIntShieldChatResponse(request.Model)

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.ChatCompletionRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// ChatCompletionStream performs a streaming chat completion request to the Cohere API.
// It supports real-time streaming of responses using Server-Sent Events (SSE).
// Returns a channel containing DeepIntShieldResponse objects representing the stream or an error if the request fails.
func (provider *CohereProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	// Check if chat completion stream is allowed
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.ChatCompletionStreamRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()
	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			reqBody, err := ToCohereChatCompletionRequest(request)
			if err != nil {
				return nil, err
			}
			reqBody.Stream = schemas.Ptr(true)
			return reqBody, nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	sendBackRawRequest := provider.sendBackRawRequest
	sendBackRawResponse := provider.sendBackRawResponse

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	resp.StreamBody = true
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(http.MethodPost)
	req.SetRequestURI(provider.buildRequestURL(ctx, "/v2/chat", schemas.ChatCompletionStreamRequest))
	req.Header.SetContentType("application/json")

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Set headers
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	usedLargePayloadBody := providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.Cohere)
	if !usedLargePayloadBody {
		req.SetBody(jsonBody)
	}

	// Make the request
	err := providerUtils.ClientFromContext(ctx, provider.client).Do(req, resp)
	if usedLargePayloadBody {
		providerUtils.DrainLargePayloadRemainder(ctx)
	}
	if err != nil {
		defer providerUtils.ReleaseStreamingResponse(resp)
		if errors.Is(err, context.Canceled) {
			return nil, providerUtils.EnrichError(ctx, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Type:    schemas.Ptr(schemas.RequestCancelled),
					Message: schemas.ErrRequestCancelled,
					Error:   err,
				},
			}, jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
		}
		if errors.Is(err, fasthttp.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderRequestTimedOut, err, providerName), jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
		}
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, err, providerName), jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Extract provider response headers before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		return nil, providerUtils.EnrichError(ctx, parseCohereError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.ChatCompletionStreamRequest,
		}), jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Large payload streaming passthrough - pipe raw upstream SSE to client
	if providerUtils.SetupStreamingPassthrough(ctx, resp) {
		responseChan := make(chan *schemas.DeepIntShieldStreamChunk)
		close(responseChan)
		return responseChan, nil
	}

	// Create response channel
	responseChan := make(chan *schemas.DeepIntShieldStreamChunk, schemas.DefaultStreamBufferSize)

	providerUtils.SetStreamIdleTimeoutIfEmpty(ctx, provider.networkConfig.StreamIdleTimeoutInSeconds)

	// Start streaming in a goroutine
	go func() {
		defer func() {
			if ctx.Err() == context.Canceled {
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ChatCompletionStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ChatCompletionStreamRequest, provider.logger)
			}
			close(responseChan)
		}()
		defer providerUtils.ReleaseStreamingResponse(resp)
		// Decompress gzip-encoded streams transparently (no-op for non-gzip)
		reader, releaseGzip := providerUtils.DecompressStreamBody(resp)
		defer releaseGzip()

		// Wrap reader with idle timeout to detect stalled streams.
		reader, stopIdleTimeout := providerUtils.NewIdleTimeoutReader(reader, resp.BodyStream(), providerUtils.GetStreamIdleTimeout(ctx))
		defer stopIdleTimeout()

		// Setup cancellation handler to close the raw network stream on ctx cancellation,
		// which immediately unblocks any in-progress read (including reads blocked inside a gzip decompression layer).
		stopCancellation := providerUtils.SetupStreamCancellation(ctx, resp.BodyStream(), provider.logger)
		defer stopCancellation()

		sseReader := providerUtils.GetSSEDataReader(ctx, reader)
		chunkIndex := 0
		startTime := time.Now()
		lastChunkTime := startTime

		var responseID string

		for {
			// If context was cancelled/timed out, let defer handle it
			if ctx.Err() != nil {
				return
			}
			data, readErr := sseReader.ReadDataLine()
			if readErr != nil {
				if readErr != io.EOF {
					if ctx.Err() != nil {
						return
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					provider.logger.Warn("Error reading stream: %v", readErr)
					providerUtils.ProcessAndSendError(ctx, postHookRunner, readErr, responseChan, schemas.ChatCompletionStreamRequest, providerName, request.Model, provider.logger)
					return
				}
				break
			}

			eventData := string(data)

			// Parse the unified streaming event
			var event CohereStreamEvent
			if err := sonic.Unmarshal(data, &event); err != nil {
				provider.logger.Warn("Failed to parse stream event: %v", err)
				continue
			}

			// Extract response ID from message-start events
			if event.Type == StreamEventMessageStart && event.ID != nil {
				responseID = *event.ID
			}

			response, deepintshieldErr, isLastChunk := event.ToDeepIntShieldChatCompletionStream()
			if deepintshieldErr != nil {
				deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
					RequestType:    schemas.ChatCompletionStreamRequest,
					Provider:       providerName,
					ModelRequested: request.Model,
				}
				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
				break
			}
			if response != nil {
				response.ID = responseID
				response.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
					RequestType:    schemas.ChatCompletionStreamRequest,
					Provider:       providerName,
					ModelRequested: request.Model,
					ChunkIndex:     chunkIndex,
					Latency:        time.Since(lastChunkTime).Milliseconds(),
				}

				lastChunkTime = time.Now()
				chunkIndex++

				if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
					response.ExtraFields.RawResponse = eventData
				}

				if isLastChunk {
					// Set raw request if enabled
					if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
						providerUtils.ParseAndSetRawRequest(&response.ExtraFields, jsonBody)
					}
					response.ExtraFields.Latency = time.Since(startTime).Milliseconds()
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, response, nil, nil, nil, nil), responseChan)
					break
				}
				providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, response, nil, nil, nil, nil), responseChan)
			}
		}
	}()

	return responseChan, nil
}

// Responses performs a responses request to the Cohere API using v2 converter.
func (provider *CohereProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	// Check if chat completion is allowed
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.ResponsesRequest); err != nil {
		return nil, err
	}

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToCohereResponsesRequest(request)
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Convert to Cohere v2 request
	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, provider.buildRequestURL(ctx, "/v2/chat", schemas.ResponsesRequest), key.Value.GetValue(), &providerUtils.RequestMetadata{
		Provider:    provider.GetProviderKey(),
		Model:       request.Model,
		RequestType: schemas.ResponsesRequest,
	})
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Large response mode: return lightweight response with metadata only
	if isLargeResp, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); isLargeResp {
		return &schemas.DeepIntShieldResponsesResponse{
			Model: request.Model,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				Provider:                provider.GetProviderKey(),
				ModelRequested:          request.Model,
				RequestType:             schemas.ResponsesRequest,
				Latency:                 latency.Milliseconds(),
				ProviderResponseHeaders: providerResponseHeaders,
			},
		}, nil
	}

	// Create response object from pool
	response := acquireCohereResponse()
	defer releaseCohereResponse(response)

	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, response, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	deepintshieldResponse := response.ToDeepIntShieldResponsesResponse()

	deepintshieldResponse.Model = request.Model

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.ResponsesRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// ResponsesStream performs a streaming responses request to the Cohere API.
func (provider *CohereProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	// Check if responses stream is allowed
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.ResponsesStreamRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()
	// Convert to Cohere v2 request and add streaming
	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			reqBody, err := ToCohereResponsesRequest(request)
			if err != nil {
				return nil, err
			}
			if reqBody != nil {
				reqBody.Stream = schemas.Ptr(true)
			}
			return reqBody, nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	sendBackRawRequest := provider.sendBackRawRequest
	sendBackRawResponse := provider.sendBackRawResponse

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	resp.StreamBody = true
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(http.MethodPost)
	req.SetRequestURI(provider.buildRequestURL(ctx, "/v2/chat", schemas.ResponsesStreamRequest))
	req.Header.SetContentType("application/json")
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Set headers
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	usedLargePayloadBody := providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.Cohere)
	if !usedLargePayloadBody {
		req.SetBody(jsonBody)
	}

	// Make the request
	err := providerUtils.ClientFromContext(ctx, provider.client).Do(req, resp)
	if usedLargePayloadBody {
		providerUtils.DrainLargePayloadRemainder(ctx)
	}
	if err != nil {
		defer providerUtils.ReleaseStreamingResponse(resp)
		if errors.Is(err, context.Canceled) {
			return nil, providerUtils.EnrichError(ctx, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Type:    schemas.Ptr(schemas.RequestCancelled),
					Message: schemas.ErrRequestCancelled,
					Error:   err,
				},
			}, jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
		}
		if errors.Is(err, fasthttp.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderRequestTimedOut, err, providerName), jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
		}
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, err, providerName), jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Extract provider response headers before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		return nil, providerUtils.EnrichError(ctx, parseCohereError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.ResponsesStreamRequest,
		}), jsonBody, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Large payload streaming passthrough - pipe raw upstream SSE to client
	if providerUtils.SetupStreamingPassthrough(ctx, resp) {
		responseChan := make(chan *schemas.DeepIntShieldStreamChunk)
		close(responseChan)
		return responseChan, nil
	}

	// Create response channel
	responseChan := make(chan *schemas.DeepIntShieldStreamChunk, schemas.DefaultStreamBufferSize)

	providerUtils.SetStreamIdleTimeoutIfEmpty(ctx, provider.networkConfig.StreamIdleTimeoutInSeconds)

	// Start streaming in a goroutine
	go func() {
		defer func() {
			if ctx.Err() == context.Canceled {
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ResponsesStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ResponsesStreamRequest, provider.logger)
			}
			close(responseChan)
		}()
		defer providerUtils.ReleaseStreamingResponse(resp)
		// Decompress gzip-encoded streams transparently (no-op for non-gzip)
		reader, releaseGzip := providerUtils.DecompressStreamBody(resp)
		defer releaseGzip()

		// Wrap reader with idle timeout to detect stalled streams.
		reader, stopIdleTimeout := providerUtils.NewIdleTimeoutReader(reader, resp.BodyStream(), providerUtils.GetStreamIdleTimeout(ctx))
		defer stopIdleTimeout()

		// Setup cancellation handler to close the raw network stream on ctx cancellation,
		// which immediately unblocks any in-progress read (including reads blocked inside a gzip decompression layer).
		stopCancellation := providerUtils.SetupStreamCancellation(ctx, resp.BodyStream(), provider.logger)
		defer stopCancellation()

		sseReader := providerUtils.GetSSEDataReader(ctx, reader)

		chunkIndex := 0

		startTime := time.Now()
		lastChunkTime := startTime

		// Create stream state for stateful conversions (outside loop to persist across events)
		streamState := acquireCohereResponsesStreamState()
		streamState.Model = &request.Model
		defer releaseCohereResponsesStreamState(streamState)

		for {
			// If context was cancelled/timed out, let defer handle it
			if ctx.Err() != nil {
				return
			}
			data, readErr := sseReader.ReadDataLine()
			if readErr != nil {
				if readErr != io.EOF {
					if ctx.Err() != nil {
						return
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					provider.logger.Warn("Error reading %s stream: %v", providerName, readErr)
					providerUtils.ProcessAndSendError(ctx, postHookRunner, readErr, responseChan, schemas.ResponsesStreamRequest, providerName, request.Model, provider.logger)
					return
				}
				break
			}

			eventData := string(data)

			// Parse the unified streaming event
			var event CohereStreamEvent
			if err := sonic.Unmarshal(data, &event); err != nil {
				provider.logger.Warn("Failed to parse stream event: %v", err)
				continue
			}

			// Note: response.created and response.in_progress are now emitted by ToDeepIntShieldResponsesStream
			// from the message_start event, so we don't need to call them manually here

			responses, deepintshieldErr, isLastChunk := event.ToDeepIntShieldResponsesStream(chunkIndex, streamState)
			if deepintshieldErr != nil {
				deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
					RequestType:    schemas.ResponsesStreamRequest,
					Provider:       providerName,
					ModelRequested: request.Model,
				}
				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
				break
			}
			// Handle each response in the slice
			for i, response := range responses {
				if response != nil {
					response.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ResponsesStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(lastChunkTime).Milliseconds(),
					}
					lastChunkTime = time.Now()
					chunkIndex++

					if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
						response.ExtraFields.RawResponse = eventData
					}

					if isLastChunk && i == len(responses)-1 {
						if response.Response == nil {
							response.Response = &schemas.DeepIntShieldResponsesResponse{}
						}
						// Set raw request if enabled
						if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
							providerUtils.ParseAndSetRawRequest(&response.ExtraFields, jsonBody)
						}
						response.ExtraFields.Latency = time.Since(startTime).Milliseconds()
						ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
						providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, response, nil, nil, nil), responseChan)
						return
					}
					providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, response, nil, nil, nil), responseChan)
				}
			}
		}
	}()

	return responseChan, nil
}

// Embedding generates embeddings for the given input text(s) using the Cohere API.
// Supports Cohere's embedding models and returns a DeepIntShieldResponse containing the embedding(s).
func (provider *CohereProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	// Check if embedding is allowed
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.EmbeddingRequest); err != nil {
		return nil, err
	}

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToCohereEmbeddingRequest(request), nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Create DeepIntShield request for conversion
	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, provider.buildRequestURL(ctx, "/v2/embed", schemas.EmbeddingRequest), key.Value.GetValue(), &providerUtils.RequestMetadata{
		Provider:    provider.GetProviderKey(),
		Model:       request.Model,
		RequestType: schemas.EmbeddingRequest,
	})
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Large response mode: return lightweight response with metadata only
	if isLargeResp, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); isLargeResp {
		return &schemas.DeepIntShieldEmbeddingResponse{
			Model: request.Model,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				Provider:                provider.GetProviderKey(),
				ModelRequested:          request.Model,
				RequestType:             schemas.EmbeddingRequest,
				Latency:                 latency.Milliseconds(),
				ProviderResponseHeaders: providerResponseHeaders,
			},
		}, nil
	}

	// Create response object from pool
	response := acquireCohereEmbeddingResponse()
	defer releaseCohereEmbeddingResponse(response)

	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, response, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	deepintshieldResponse := response.ToDeepIntShieldEmbeddingResponse()

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.EmbeddingRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// Rerank performs a rerank request using the Cohere /v2/rerank API.
func (provider *CohereProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	// Check if rerank is allowed
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.RerankRequest); err != nil {
		return nil, err
	}

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToCohereRerankRequest(request), nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, provider.buildRequestURL(ctx, "/v2/rerank", schemas.RerankRequest), key.Value.GetValue(), &providerUtils.RequestMetadata{
		Provider:    provider.GetProviderKey(),
		Model:       request.Model,
		RequestType: schemas.RerankRequest,
	})
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Large response mode: return lightweight response with metadata only
	if isLargeResp, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); isLargeResp {
		return &schemas.DeepIntShieldRerankResponse{
			Model: request.Model,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				Provider:                provider.GetProviderKey(),
				ModelRequested:          request.Model,
				RequestType:             schemas.RerankRequest,
				Latency:                 latency.Milliseconds(),
				ProviderResponseHeaders: providerResponseHeaders,
			},
		}, nil
	}

	// Create response object from pool
	response := acquireCohereRerankResponse()
	defer releaseCohereRerankResponse(response)

	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, response, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	returnDocuments := request.Params != nil && request.Params.ReturnDocuments != nil && *request.Params.ReturnDocuments
	deepintshieldResponse := response.ToDeepIntShieldRerankResponse(request.Documents, returnDocuments)
	deepintshieldResponse.Model = request.Model

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.RerankRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// Speech is not supported by the Cohere provider.
func (provider *CohereProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, provider.GetProviderKey())
}

// SpeechStream is not supported by the Cohere provider.
func (provider *CohereProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

// Transcription is not supported by the Cohere provider.
func (provider *CohereProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, provider.GetProviderKey())
}

// TranscriptionStream is not supported by the Cohere provider.
func (provider *CohereProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

// ImageGeneration is not supported by the Cohere provider.
func (provider *CohereProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, provider.GetProviderKey())
}

// ImageGenerationStream is not supported by the Cohere provider.
func (provider *CohereProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, provider.GetProviderKey())
}

// ImageEdit is not supported by the Cohere provider.
func (provider *CohereProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
}

// ImageEditStream is not supported by the Cohere provider.
func (provider *CohereProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, provider.GetProviderKey())
}

// ImageVariation is not supported by the Cohere provider.
func (provider *CohereProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration is not supported by the Cohere provider.
func (provider *CohereProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, provider.GetProviderKey())
}

// VideoRetrieve is not supported by the Cohere provider.
func (provider *CohereProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, provider.GetProviderKey())
}

// VideoDownload is not supported by the Cohere provider.
func (provider *CohereProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, provider.GetProviderKey())
}

// VideoDelete is not supported by Cohere provider.
func (provider *CohereProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by Cohere provider.
func (provider *CohereProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by Cohere provider.
func (provider *CohereProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// BatchCreate is not supported by Cohere provider.
func (provider *CohereProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by Cohere provider.
func (provider *CohereProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by Cohere provider.
func (provider *CohereProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by Cohere provider.
func (provider *CohereProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by Cohere provider.
func (provider *CohereProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by Cohere provider.
func (provider *CohereProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// FileUpload is not supported by Cohere provider.
func (provider *CohereProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by Cohere provider.
func (provider *CohereProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by Cohere provider.
func (provider *CohereProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by Cohere provider.
func (provider *CohereProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by Cohere provider.
func (provider *CohereProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// CountTokens performs a token counting request via Cohere's /v1/tokenize API.
func (provider *CohereProvider) CountTokens(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Cohere, provider.customProviderConfig, schemas.CountTokensRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToCohereCountTokensRequest(request)
		},
		providerName,
	)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	responseBody, latency, providerResponseHeaders, deepintshieldErr := provider.completeRequest(
		ctx,
		jsonBody,
		provider.buildRequestURL(ctx, "/v1/tokenize", schemas.CountTokensRequest),
		key.Value.GetValue(),
		&providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.CountTokensRequest,
		},
	)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Large response mode: return lightweight response with metadata only
	if isLargeResp, _ := ctx.Value(schemas.DeepIntShieldContextKeyLargeResponseMode).(bool); isLargeResp {
		return &schemas.DeepIntShieldCountTokensResponse{
			Model: request.Model,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				Provider:                providerName,
				ModelRequested:          request.Model,
				RequestType:             schemas.CountTokensRequest,
				Latency:                 latency.Milliseconds(),
				ProviderResponseHeaders: providerResponseHeaders,
			},
		}, nil
	}

	cohereResponse := &CohereCountTokensResponse{}

	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(
		responseBody,
		cohereResponse,
		jsonBody,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
	)
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	deepintshieldResponse := cohereResponse.ToDeepIntShieldCountTokensResponse(request.Model)
	if deepintshieldResponse == nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, fmt.Errorf("nil Cohere count tokens response"), providerName)
	}

	deepintshieldResponse.ExtraFields.Provider = providerName
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.CountTokensRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// ContainerCreate is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Cohere provider.
func (provider *CohereProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Cohere provider.
func (provider *CohereProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *CohereProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
