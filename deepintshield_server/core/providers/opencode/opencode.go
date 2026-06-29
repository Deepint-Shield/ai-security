// Package opencode implements the Opencode Zen and Go AI gateway providers.
// Both gateways expose an OpenAI-compatible API and share the same implementation,
// differing only in default base URL and provider key.
package opencode

import (
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/providers/openai"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// opencodeProvider implements the Provider interface for Opencode Zen and Go gateways.
type opencodeProvider struct {
	providerKey         schemas.ModelProvider
	logger              schemas.Logger
	client              *fasthttp.Client
	networkConfig       schemas.NetworkConfig
	sendBackRawRequest  bool
	sendBackRawResponse bool
}

// NewOpencodeZenProvider creates a new Opencode Zen provider instance.
// Zen is the pay-as-you-go gateway at https://opencode.ai/zen/v1.
func NewOpencodeZenProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*opencodeProvider, error) {
	return newOpencodeProvider(config, schemas.OpencodeZen, "https://opencode.ai/zen", logger)
}

// NewOpencodeGoProvider creates a new Opencode Go provider instance.
// Go is the subscription-based gateway at https://opencode.ai/zen/go/v1.
func NewOpencodeGoProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*opencodeProvider, error) {
	return newOpencodeProvider(config, schemas.OpencodeGo, "https://opencode.ai/zen/go", logger)
}

// newOpencodeProvider initializes the shared provider infrastructure.
func newOpencodeProvider(
	config *schemas.ProviderConfig,
	providerKey schemas.ModelProvider,
	defaultBaseURL string,
	logger schemas.Logger,
) (*opencodeProvider, error) {
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

	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)

	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = defaultBaseURL
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &opencodeProvider{
		providerKey:         providerKey,
		logger:              logger,
		client:              client,
		networkConfig:       config.NetworkConfig,
		sendBackRawRequest:  config.SendBackRawRequest,
		sendBackRawResponse: config.SendBackRawResponse,
	}, nil
}

// GetProviderKey returns the provider identifier stored at construction time.
func (p *opencodeProvider) GetProviderKey() schemas.ModelProvider {
	return p.providerKey
}

// ListModels performs a list models request to the Opencode API.
func (p *opencodeProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	return openai.HandleOpenAIListModelsRequest(
		ctx,
		p.client,
		request,
		p.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, "/v1/models"),
		keys,
		p.networkConfig.ExtraHeaders,
		p.providerKey,
		providerUtils.ShouldSendBackRawRequest(ctx, p.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, p.sendBackRawResponse),
	)
}

// TextCompletion is not supported by Opencode.
func (p *opencodeProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, p.GetProviderKey())
}

// TextCompletionStream is not supported by Opencode.
func (p *opencodeProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, p.GetProviderKey())
}

// ChatCompletion performs a chat completion request to the Opencode API.
func (p *opencodeProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	return openai.HandleOpenAIChatCompletionRequest(
		ctx,
		p.client,
		p.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, "/v1/chat/completions"),
		request,
		key,
		p.networkConfig.ExtraHeaders,
		providerUtils.ShouldSendBackRawRequest(ctx, p.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, p.sendBackRawResponse),
		p.GetProviderKey(),
		nil,
		parseOpencodeError,
		p.logger,
	)
}

// ChatCompletionStream performs a streaming chat completion request to the Opencode API.
func (p *opencodeProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	var authHeader map[string]string
	if v := key.Value.GetValue(); v != "" {
		authHeader = map[string]string{"Authorization": "Bearer " + v}
	}
	return openai.HandleOpenAIChatCompletionStreaming(
		ctx,
		p.client,
		p.networkConfig.BaseURL+providerUtils.GetPathFromContext(ctx, "/v1/chat/completions"),
		request,
		authHeader,
		p.networkConfig.ExtraHeaders,
		providerUtils.ShouldSendBackRawRequest(ctx, p.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, p.sendBackRawResponse),
		p.providerKey,
		postHookRunner,
		nil,
		nil,
		parseOpencodeError,
		nil,
		nil,
		p.logger,
	)
}

// Responses performs a responses request to the Opencode API.
func (p *opencodeProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	chatResponse, err := p.ChatCompletion(ctx, key, request.ToChatRequest())
	if err != nil {
		return nil, err
	}
	return chatResponse.ToDeepIntShieldResponsesResponse(), nil
}

// ResponsesStream performs a streaming responses request to the Opencode API.
func (p *opencodeProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	ctx.SetValue(schemas.DeepIntShieldContextKeyIsResponsesToChatCompletionFallback, true)
	return p.ChatCompletionStream(ctx, postHookRunner, key, request.ToChatRequest())
}

// Embedding is not supported by Opencode.
func (p *opencodeProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, p.GetProviderKey())
}

// Rerank is not supported by Opencode.
func (p *opencodeProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, p.GetProviderKey())
}

// Speech is not supported by Opencode.
func (p *opencodeProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, p.GetProviderKey())
}

// SpeechStream is not supported by Opencode.
func (p *opencodeProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, p.GetProviderKey())
}

// Transcription is not supported by Opencode.
func (p *opencodeProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, p.GetProviderKey())
}

// TranscriptionStream is not supported by Opencode.
func (p *opencodeProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, p.GetProviderKey())
}

// ImageGeneration is not supported by Opencode.
func (p *opencodeProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, p.GetProviderKey())
}

// ImageGenerationStream is not supported by Opencode.
func (p *opencodeProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, p.GetProviderKey())
}

// ImageEdit is not supported by Opencode.
func (p *opencodeProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, p.GetProviderKey())
}

// ImageEditStream is not supported by Opencode.
func (p *opencodeProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, p.GetProviderKey())
}

// ImageVariation is not supported by Opencode.
func (p *opencodeProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, p.GetProviderKey())
}

// VideoGeneration is not supported by Opencode.
func (p *opencodeProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, p.GetProviderKey())
}

// VideoRetrieve is not supported by Opencode.
func (p *opencodeProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, p.GetProviderKey())
}

// VideoDownload is not supported by Opencode.
func (p *opencodeProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, p.GetProviderKey())
}

// VideoDelete is not supported by Opencode.
func (p *opencodeProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, p.GetProviderKey())
}

// VideoList is not supported by Opencode.
func (p *opencodeProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, p.GetProviderKey())
}

// VideoRemix is not supported by Opencode.
func (p *opencodeProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, p.GetProviderKey())
}

// BatchCreate is not supported by Opencode.
func (p *opencodeProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, p.GetProviderKey())
}

// BatchList is not supported by Opencode.
func (p *opencodeProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, p.GetProviderKey())
}

// BatchRetrieve is not supported by Opencode.
func (p *opencodeProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, p.GetProviderKey())
}

// BatchCancel is not supported by Opencode.
func (p *opencodeProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, p.GetProviderKey())
}

// BatchDelete is not supported by Opencode.
func (p *opencodeProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, p.GetProviderKey())
}

// BatchResults is not supported by Opencode.
func (p *opencodeProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, p.GetProviderKey())
}

// FileUpload is not supported by Opencode.
func (p *opencodeProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, p.GetProviderKey())
}

// FileList is not supported by Opencode.
func (p *opencodeProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, p.GetProviderKey())
}

// FileRetrieve is not supported by Opencode.
func (p *opencodeProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, p.GetProviderKey())
}

// FileDelete is not supported by Opencode.
func (p *opencodeProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, p.GetProviderKey())
}

// FileContent is not supported by Opencode.
func (p *opencodeProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, p.GetProviderKey())
}

// CountTokens is not supported by Opencode.
func (p *opencodeProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, p.GetProviderKey())
}

// ContainerCreate is not supported by Opencode.
func (p *opencodeProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, p.GetProviderKey())
}

// ContainerList is not supported by Opencode.
func (p *opencodeProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, p.GetProviderKey())
}

// ContainerRetrieve is not supported by Opencode.
func (p *opencodeProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, p.GetProviderKey())
}

// ContainerDelete is not supported by Opencode.
func (p *opencodeProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, p.GetProviderKey())
}

// ContainerFileCreate is not supported by Opencode.
func (p *opencodeProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, p.GetProviderKey())
}

// ContainerFileList is not supported by Opencode.
func (p *opencodeProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, p.GetProviderKey())
}

// ContainerFileRetrieve is not supported by Opencode.
func (p *opencodeProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, p.GetProviderKey())
}

// ContainerFileContent is not supported by Opencode.
func (p *opencodeProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, p.GetProviderKey())
}

// ContainerFileDelete is not supported by Opencode.
func (p *opencodeProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, p.GetProviderKey())
}

// Passthrough is not supported by Opencode.
func (p *opencodeProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, p.GetProviderKey())
}

// PassthroughStream is not supported by Opencode.
func (p *opencodeProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, p.GetProviderKey())
}
