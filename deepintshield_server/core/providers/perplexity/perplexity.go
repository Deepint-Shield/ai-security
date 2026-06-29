// Package providers implements various LLM providers and their utility functions.
// This file contains the Perplexity provider implementation.
package perplexity

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/providers/openai"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// PerplexityProvider implements the Provider interface for Perplexity's API.
type PerplexityProvider struct {
	logger              schemas.Logger        // Logger for provider operations
	client              *fasthttp.Client      // HTTP client for API requests
	networkConfig       schemas.NetworkConfig // Network configuration including extra headers
	sendBackRawRequest  bool                  // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse bool                  // Whether to include raw response in DeepIntShieldResponse
}

// NewPerplexityProvider creates a new Perplexity provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewPerplexityProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*PerplexityProvider, error) {
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

	// Configure proxy and retry policy
	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)
	// Set default BaseURL if not provided
	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = "https://api.perplexity.ai"
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &PerplexityProvider{
		logger:              logger,
		client:              client,
		networkConfig:       config.NetworkConfig,
		sendBackRawRequest:  config.SendBackRawRequest,
		sendBackRawResponse: config.SendBackRawResponse,
	}, nil
}

// GetProviderKey returns the provider identifier for Perplexity.
func (provider *PerplexityProvider) GetProviderKey() schemas.ModelProvider {
	return schemas.Perplexity
}

// completeRequest sends a request to Perplexity's API and handles the response.
// It constructs the API URL, sets up authentication, and processes the response.
// Returns the response body or an error if the request fails.
func (provider *PerplexityProvider) completeRequest(ctx *schemas.DeepIntShieldContext, jsonData []byte, url string, key string, model string) ([]byte, time.Duration, map[string]string, *schemas.DeepIntShieldError) {
	// Create the request with the JSON body
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.SetRequestURI(url)
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	if !providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.Perplexity) {
		req.SetBody(jsonData)
	}

	// Send the request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, latency, nil, deepintshieldErr
	}

	// Extract provider response headers before status check so error responses also forward them
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		provider.logger.Debug(fmt.Sprintf("error from %s provider: %s", provider.GetProviderKey(), string(resp.Body())))
		return nil, latency, providerResponseHeaders, openai.ParseOpenAIError(resp, schemas.ChatCompletionRequest, provider.GetProviderKey(), model)
	}

	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, latency, providerResponseHeaders, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, provider.GetProviderKey())
	}

	// Read the response body and copy it before releasing the response
	// to avoid use-after-free since resp.Body() references fasthttp's internal buffer
	bodyCopy := append([]byte(nil), body...)

	return bodyCopy, latency, providerResponseHeaders, nil
}

// ListModels performs a list models request to Perplexity's API.
func (provider *PerplexityProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ListModelsRequest, provider.GetProviderKey())
}

// TextCompletion is not supported by the Perplexity provider.
func (provider *PerplexityProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

// TextCompletionStream performs a streaming text completion request to Perplexity's API.
// It formats the request, sends it to Perplexity, and processes the response.
// Returns a channel of DeepIntShieldStreamChunk objects or an error if the request fails.
func (provider *PerplexityProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

// ChatCompletion performs a chat completion request to the Perplexity API.
func (provider *PerplexityProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	// Convert to Perplexity chat completion request
	jsonBody, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToPerplexityChatCompletionRequest(request), nil
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, provider.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, "/chat/completions"), key.Value.GetValue(), request.Model)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	var response PerplexityChatResponse
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, &response, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
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

// ChatCompletionStream performs a streaming chat completion request to the Perplexity API.
// It supports real-time streaming of responses using Server-Sent Events (SSE).
// Uses Perplexity's OpenAI-compatible streaming format.
// Returns a channel containing DeepIntShieldStreamChunk objects representing the stream or an error if the request fails.
func (provider *PerplexityProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	var authHeader map[string]string
	if key.Value.GetValue() != "" {
		authHeader = map[string]string{"Authorization": "Bearer " + key.Value.GetValue()}
	}
	customRequestConverter := func(request *schemas.DeepIntShieldChatRequest) (providerUtils.RequestBodyWithExtraParams, error) {
		reqBody := ToPerplexityChatCompletionRequest(request)
		reqBody.Stream = schemas.Ptr(true)
		return reqBody, nil
	}
	// Use shared OpenAI-compatible streaming logic
	return openai.HandleOpenAIChatCompletionStreaming(
		ctx,
		provider.client,
		provider.networkConfig.BaseURL+"/chat/completions",
		request,
		authHeader,
		provider.networkConfig.ExtraHeaders,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		schemas.Perplexity,
		postHookRunner,
		customRequestConverter,
		nil,
		nil,
		nil,
		nil,
		provider.logger,
	)
}

// Responses performs a responses request to the Perplexity API.
func (provider *PerplexityProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	chatResponse, err := provider.ChatCompletion(ctx, key, request.ToChatRequest())
	if err != nil {
		return nil, err
	}

	response := chatResponse.ToDeepIntShieldResponsesResponse()
	response.ExtraFields.RequestType = schemas.ResponsesRequest
	response.ExtraFields.Provider = provider.GetProviderKey()
	response.ExtraFields.ModelRequested = request.Model

	return response, nil
}

// ResponsesStream performs a streaming responses request to the Perplexity API.
func (provider *PerplexityProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	ctx.SetValue(schemas.DeepIntShieldContextKeyIsResponsesToChatCompletionFallback, true)
	return provider.ChatCompletionStream(
		ctx,
		postHookRunner,
		key,
		request.ToChatRequest(),
	)
}

// Embedding is not supported by the Perplexity provider.
func (provider *PerplexityProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, provider.GetProviderKey())
}

// Speech is not supported by the Perplexity provider.
func (provider *PerplexityProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, provider.GetProviderKey())
}

// Rerank is not supported by the Perplexity provider.
func (provider *PerplexityProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

// SpeechStream is not supported by the Perplexity provider.
func (provider *PerplexityProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

// Transcription is not supported by the Perplexity provider.
func (provider *PerplexityProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, provider.GetProviderKey())
}

// TranscriptionStream is not supported by the Perplexity provider.
func (provider *PerplexityProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

// ImageGeneration is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, provider.GetProviderKey())
}

// ImageGenerationStream is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, provider.GetProviderKey())
}

// ImageEdit is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
}

// ImageEditStream is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, provider.GetProviderKey())
}

// ImageVariation is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration is not supported by the Perplexity provider.
func (provider *PerplexityProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, provider.GetProviderKey())
}

// VideoRetrieve is not supported by the Perplexity provider.
func (provider *PerplexityProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, provider.GetProviderKey())
}

// VideoDownload is not supported by the Perplexity provider.
func (provider *PerplexityProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, provider.GetProviderKey())
}

// VideoDelete is not supported by Perplexity provider.
func (provider *PerplexityProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by Perplexity provider.
func (provider *PerplexityProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by Perplexity provider.
func (provider *PerplexityProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// BatchCreate is not supported by Perplexity provider.
func (provider *PerplexityProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by Perplexity provider.
func (provider *PerplexityProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by Perplexity provider.
func (provider *PerplexityProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by Perplexity provider.
func (provider *PerplexityProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by Perplexity provider.
func (provider *PerplexityProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by Perplexity provider.
func (provider *PerplexityProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// FileUpload is not supported by Perplexity provider.
func (provider *PerplexityProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by Perplexity provider.
func (provider *PerplexityProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by Perplexity provider.
func (provider *PerplexityProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by Perplexity provider.
func (provider *PerplexityProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by Perplexity provider.
func (provider *PerplexityProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// CountTokens is not supported by the Perplexity provider.
func (provider *PerplexityProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Perplexity provider.
func (provider *PerplexityProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Perplexity provider.
func (provider *PerplexityProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *PerplexityProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
