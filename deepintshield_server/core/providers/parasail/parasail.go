// Package providers implements various LLM providers and their utility functions.
// This file contains the Parasail provider implementation.
package parasail

import (
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/providers/openai"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// ParasailProvider implements the Provider interface for Parasail's API.
type ParasailProvider struct {
	logger              schemas.Logger        // Logger for provider operations
	client              *fasthttp.Client      // HTTP client for API requests
	networkConfig       schemas.NetworkConfig // Network configuration including extra headers
	sendBackRawRequest  bool                  // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse bool                  // Whether to include raw response in DeepIntShieldResponse
}

// NewParasailProvider creates a new Parasail provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewParasailProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*ParasailProvider, error) {
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
		config.NetworkConfig.BaseURL = "https://api.parasail.io"
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &ParasailProvider{
		logger:              logger,
		client:              client,
		networkConfig:       config.NetworkConfig,
		sendBackRawRequest:  config.SendBackRawRequest,
		sendBackRawResponse: config.SendBackRawResponse,
	}, nil
}

// GetProviderKey returns the provider identifier for Parasail.
func (provider *ParasailProvider) GetProviderKey() schemas.ModelProvider {
	return schemas.Parasail
}

// ListModels performs a list models request to Parasail's API.
func (provider *ParasailProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	return openai.HandleOpenAIListModelsRequest(
		ctx,
		provider.client,
		request,
		provider.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, "/v1/models"),
		keys,
		provider.networkConfig.ExtraHeaders,
		schemas.Parasail,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
	)
}

// TextCompletion is not supported by the Parasail provider.
func (provider *ParasailProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

// TextCompletionStream performs a streaming text completion request to Parasail's API.
// It formats the request, sends it to Parasail, and processes the response.
// Returns a channel of DeepIntShieldStreamChunk objects or an error if the request fails.
func (provider *ParasailProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

// ChatCompletion performs a chat completion request to the Parasail API.
func (provider *ParasailProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	return openai.HandleOpenAIChatCompletionRequest(
		ctx,
		provider.client,
		provider.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, "/v1/chat/completions"),
		request,
		key,
		provider.networkConfig.ExtraHeaders,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		provider.GetProviderKey(),
		nil,
		nil,
		provider.logger,
	)
}

// ChatCompletionStream performs a streaming chat completion request to the Parasail API.
// It supports real-time streaming of responses using Server-Sent Events (SSE).
// Uses Parasail's OpenAI-compatible streaming format.
// Returns a channel containing DeepIntShieldStreamChunk objects representing the stream or an error if the request fails.
func (provider *ParasailProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	var authHeader map[string]string
	if key.Value.GetValue() != "" {
		authHeader = map[string]string{"Authorization": "Bearer " + key.Value.GetValue()}
	}
	// Use shared OpenAI-compatible streaming logic
	return openai.HandleOpenAIChatCompletionStreaming(
		ctx,
		provider.client,
		provider.networkConfig.BaseURL+"/v1/chat/completions",
		request,
		authHeader,
		provider.networkConfig.ExtraHeaders,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		schemas.Parasail,
		postHookRunner,
		nil,
		nil,
		nil,
		nil,
		nil,
		provider.logger,
	)
}

// Responses performs a responses request to the Parasail API.
func (provider *ParasailProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
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

// ResponsesStream performs a streaming responses request to the Parasail API.
func (provider *ParasailProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	ctx.SetValue(schemas.DeepIntShieldContextKeyIsResponsesToChatCompletionFallback, true)
	return provider.ChatCompletionStream(
		ctx,
		postHookRunner,
		key,
		request.ToChatRequest(),
	)
}

// Embedding is not supported by the Parasail provider.
func (provider *ParasailProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, provider.GetProviderKey())
}

// Speech is not supported by the Parasail provider.
func (provider *ParasailProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, provider.GetProviderKey())
}

// SpeechStream is not supported by the Parasail provider.
func (provider *ParasailProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

// Transcription is not supported by the Parasail provider.
func (provider *ParasailProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, provider.GetProviderKey())
}

// TranscriptionStream is not supported by the Parasail provider.
func (provider *ParasailProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

// Rerank is not supported by the Parasail provider.
func (provider *ParasailProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

// ImageGeneration is not supported by the Parasail provider.
func (provider *ParasailProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, provider.GetProviderKey())
}

// ImageGenerationStream is not supported by the Parasail provider.
func (provider *ParasailProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, provider.GetProviderKey())
}

// ImageEdit is not supported by the Parasail provider.
func (provider *ParasailProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
}

// ImageEditStream is not supported by the Parasail provider.
func (provider *ParasailProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, provider.GetProviderKey())
}

// ImageVariation is not supported by the Parasail provider.
func (provider *ParasailProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration is not supported by the Parasail provider.
func (provider *ParasailProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, provider.GetProviderKey())
}

// VideoRetrieve is not supported by the Parasail provider.
func (provider *ParasailProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, provider.GetProviderKey())
}

// VideoDownload is not supported by the Parasail provider.
func (provider *ParasailProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, provider.GetProviderKey())
}

// VideoDelete is not supported by Parasail provider.
func (provider *ParasailProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by Parasail provider.
func (provider *ParasailProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by Parasail provider.
func (provider *ParasailProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// FileUpload is not supported by Parasail provider.
func (provider *ParasailProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by Parasail provider.
func (provider *ParasailProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by Parasail provider.
func (provider *ParasailProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by Parasail provider.
func (provider *ParasailProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by Parasail provider.
func (provider *ParasailProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// BatchCreate is not supported by Parasail provider.
func (provider *ParasailProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by Parasail provider.
func (provider *ParasailProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by Parasail provider.
func (provider *ParasailProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by Parasail provider.
func (provider *ParasailProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by Parasail provider.
func (provider *ParasailProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by Parasail provider.
func (provider *ParasailProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// CountTokens is not supported by the Parasail provider.
func (provider *ParasailProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Parasail provider.
func (provider *ParasailProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Parasail provider.
func (provider *ParasailProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

// PassthroughStream is not supported by the Parasail provider.
func (provider *ParasailProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
