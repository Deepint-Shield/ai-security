// Package providers implements various LLM providers and their utility functions.
// This file contains the Runway provider implementation.
package runway

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// RunwayProvider implements the Provider interface for Runway's API.
type RunwayProvider struct {
	logger              schemas.Logger        // Logger for provider operations
	client              *fasthttp.Client      // HTTP client for API requests
	networkConfig       schemas.NetworkConfig // Network configuration including extra headers
	sendBackRawRequest  bool                  // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse bool                  // Whether to include raw response in DeepIntShieldResponse
}

// NewRunwayProvider creates a new Runway provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewRunwayProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*RunwayProvider, error) {
	config.CheckAndSetDefaults()

	requestTimeout := time.Second * time.Duration(config.NetworkConfig.DefaultRequestTimeoutInSeconds)
	client := &fasthttp.Client{
		ReadTimeout:         requestTimeout,
		WriteTimeout:        requestTimeout,
		MaxConnsPerHost:     config.NetworkConfig.MaxConnsPerHost,
		MaxIdleConnDuration: 60 * time.Second, // Video provider - longer idle duration to accommodate slower video generation responses
		MaxConnWaitTimeout:  requestTimeout,
		MaxConnDuration:     time.Second * time.Duration(schemas.DefaultMaxConnDurationInSeconds),
		ConnPoolStrategy:    fasthttp.FIFO,
	}

	// Configure proxy if provided
	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)

	// Set default BaseURL if not provided
	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = "https://api.dev.runwayml.com"
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &RunwayProvider{
		logger:              logger,
		client:              client,
		networkConfig:       config.NetworkConfig,
		sendBackRawRequest:  config.SendBackRawRequest,
		sendBackRawResponse: config.SendBackRawResponse,
	}, nil
}

// GetProviderKey returns the provider identifier for Runway.
func (provider *RunwayProvider) GetProviderKey() schemas.ModelProvider {
	return schemas.Runway
}

// ListModels is not supported by the Runway provider.
func (provider *RunwayProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ListModelsRequest, provider.GetProviderKey())
}

// TextCompletion is not supported by the Runway provider.
func (provider *RunwayProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

// TextCompletionStream is not supported by the Runway provider.
func (provider *RunwayProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

// ChatCompletion is not supported by the Runway provider.
func (provider *RunwayProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ChatCompletionRequest, provider.GetProviderKey())
}

// ChatCompletionStream is not supported by the Runway provider.
func (provider *RunwayProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ChatCompletionStreamRequest, provider.GetProviderKey())
}

// Responses is not supported by the Runway provider.
func (provider *RunwayProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ResponsesRequest, provider.GetProviderKey())
}

// ResponsesStream is not supported by the Runway provider.
func (provider *RunwayProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ResponsesStreamRequest, provider.GetProviderKey())
}

// Embedding is not supported by the Runway provider.
func (provider *RunwayProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, provider.GetProviderKey())
}

// Speech is not supported by the Runway provider.
func (provider *RunwayProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, provider.GetProviderKey())
}

// SpeechStream is not supported by the Runway provider.
func (provider *RunwayProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

// Transcription is not supported by the Runway provider.
func (provider *RunwayProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, provider.GetProviderKey())
}

// TranscriptionStream is not supported by the Runway provider.
func (provider *RunwayProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

// Rerank is not supported by the Runway provider.
func (provider *RunwayProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

// ImageGeneration is not supported by the Runway provider.
func (provider *RunwayProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, provider.GetProviderKey())
}

// ImageGenerationStream is not supported by the Runway provider.
func (provider *RunwayProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, provider.GetProviderKey())
}

// ImageEdit is not supported by the Runway provider.
func (provider *RunwayProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
}

// ImageEditStream is not supported by the Runway provider.
func (provider *RunwayProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, provider.GetProviderKey())
}

// ImageVariation is not supported by the Runway provider.
func (provider *RunwayProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration performs a video generation request to Runway's API.
func (provider *RunwayProvider) VideoGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, deepintshieldReq *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()
	model := deepintshieldReq.Model

	// Convert DeepIntShield request to Runway format
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		deepintshieldReq,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToRunwayVideoGenerationRequest(deepintshieldReq)
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Determine the endpoint based on request type
	endpoint := getRunwayEndpoint(deepintshieldReq)

	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)

	// Create HTTP request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Set request URI and headers
	req.SetRequestURI(provider.networkConfig.BaseURL + providerUtils.GetPathFromContext(ctx, endpoint))
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")
	req.Header.Set("X-Runway-Version", "2024-11-06")
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	req.SetBody(jsonData)

	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, providerUtils.EnrichError(ctx, parseRunwayError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       model,
			RequestType: schemas.VideoGenerationRequest,
		}), jsonData, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Decode response body
	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}

	// Parse response
	var taskResp RunwayTaskCreationResponse
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &taskResp, jsonData, sendBackRawRequest, sendBackRawResponse)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Convert to DeepIntShield response
	deepintshieldResp := &schemas.DeepIntShieldVideoGenerationResponse{
		ID:     providerUtils.AddVideoIDProviderSuffix(taskResp.ID, providerName),
		Model:  model,
		Object: "video",
		Status: schemas.VideoStatusQueued,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			Latency:        latency.Milliseconds(),
			Provider:       providerName,
			ModelRequested: model,
			RequestType:    schemas.VideoGenerationRequest,
		},
	}

	if sendBackRawRequest {
		deepintshieldResp.ExtraFields.RawRequest = rawRequest
	}
	if sendBackRawResponse {
		deepintshieldResp.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResp, nil
}

// VideoRetrieve retrieves the status of a video generation task from Runway's API.
func (provider *RunwayProvider) VideoRetrieve(ctx *schemas.DeepIntShieldContext, key schemas.Key, deepintshieldReq *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()
	taskID := providerUtils.StripVideoIDProviderSuffix(deepintshieldReq.ID, providerName)

	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)

	// Create HTTP request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Set request URI and headers
	req.SetRequestURI(provider.networkConfig.BaseURL + providerUtils.GetPathFromContext(ctx, "/v1/tasks/"+taskID))
	req.Header.SetMethod("GET")
	req.Header.Set("X-Runway-Version", "2024-11-06")
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, providerUtils.EnrichError(ctx, parseRunwayError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			RequestType: schemas.VideoRetrieveRequest,
		}), nil, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Decode response body
	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}

	// Parse response
	var taskDetails RunwayTaskDetailsResponse
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &taskDetails, nil, sendBackRawRequest, sendBackRawResponse)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Convert to DeepIntShield response
	deepintshieldResp, deepintshieldErr := ToDeepIntShieldVideoGenerationResponse(&taskDetails)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	deepintshieldResp.ID = providerUtils.AddVideoIDProviderSuffix(deepintshieldResp.ID, providerName)
	deepintshieldResp.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResp.ExtraFields.Provider = providerName
	deepintshieldResp.ExtraFields.RequestType = schemas.VideoRetrieveRequest

	if sendBackRawRequest {
		deepintshieldResp.ExtraFields.RawRequest = rawRequest
	}
	if sendBackRawResponse {
		deepintshieldResp.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResp, nil
}

// VideoDownload retrieves a video from Runway's API.
func (provider *RunwayProvider) VideoDownload(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()
	// Retrieve task status to get the video URL
	deepintshieldVideoRetrieveRequest := &schemas.DeepIntShieldVideoRetrieveRequest{
		Provider: request.Provider,
		ID:       request.ID,
	}
	taskDetails, deepintshieldErr := provider.VideoRetrieve(ctx, key, deepintshieldVideoRetrieveRequest)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}
	// Check if video is ready
	if taskDetails.Status != schemas.VideoStatusCompleted {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			fmt.Sprintf("video not ready, current status: %s", taskDetails.Status),
			nil,
			providerName,
		)
	}
	if len(taskDetails.Videos) == 0 {
		return nil, providerUtils.NewDeepIntShieldOperationError("video URL not available", nil, providerName)
	}
	var videoUrl string
	if taskDetails.Videos[0].URL != nil {
		videoUrl = *taskDetails.Videos[0].URL
	}
	if videoUrl == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("invalid video output type", nil, providerName)
	}
	// Download video from Runway's URL
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(videoUrl)
	req.Header.SetMethod("GET")
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			fmt.Sprintf("failed to download video: HTTP %d", resp.StatusCode()),
			nil,
			providerName,
		)
	}
	// Get content and content type
	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}
	contentType := string(resp.Header.ContentType())
	if contentType == "" {
		contentType = "video/mp4" // Default for Runway
	}
	// Copy the binary content
	content := append([]byte(nil), body...)
	deepintshieldResp := &schemas.DeepIntShieldVideoDownloadResponse{
		VideoID:     request.ID,
		Content:     content,
		ContentType: contentType,
	}

	deepintshieldResp.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResp.ExtraFields.Provider = providerName
	deepintshieldResp.ExtraFields.RequestType = schemas.VideoDownloadRequest

	return deepintshieldResp, nil
}

// VideoDelete cancels or deletes a task in Runway.
// Tasks that are running, pending, or throttled can be canceled by invoking this method.
// Invoking this method for other tasks will delete them.
func (provider *RunwayProvider) VideoDelete(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	if request.ID == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("task_id is required", nil, providerName)
	}

	taskID := providerUtils.StripVideoIDProviderSuffix(request.ID, providerName)

	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.SetRequestURI(provider.networkConfig.BaseURL + providerUtils.GetPathFromContext(ctx, "/v1/tasks/"+taskID))
	req.Header.SetMethod(http.MethodDelete)
	req.Header.Set("X-Runway-Version", "2024-11-06")
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Handle error response - Runway returns 204 No Content on success
	if resp.StatusCode() != fasthttp.StatusNoContent {
		return nil, providerUtils.EnrichError(ctx, parseRunwayError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			RequestType: schemas.VideoDeleteRequest,
		}), nil, nil, sendBackRawRequest, sendBackRawResponse)
	}

	// Build response - Runway returns empty body on 204
	response := &schemas.DeepIntShieldVideoDeleteResponse{
		ID:      request.ID, // Return with provider prefix
		Object:  "video.deleted",
		Deleted: true,
	}

	response.ExtraFields.Latency = latency.Milliseconds()
	response.ExtraFields.Provider = providerName
	response.ExtraFields.RequestType = schemas.VideoDeleteRequest

	return response, nil
}

// VideoList is not supported by Runway provider.
func (provider *RunwayProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by Runway provider.
func (provider *RunwayProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// FileUpload is not supported by Runway provider.
func (provider *RunwayProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by Runway provider.
func (provider *RunwayProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by Runway provider.
func (provider *RunwayProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by Runway provider.
func (provider *RunwayProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by Runway provider.
func (provider *RunwayProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// BatchCreate is not supported by Runway provider.
func (provider *RunwayProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by Runway provider.
func (provider *RunwayProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by Runway provider.
func (provider *RunwayProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by Runway provider.
func (provider *RunwayProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by Runway provider.
func (provider *RunwayProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by Runway provider.
func (provider *RunwayProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// CountTokens is not supported by the Runway provider.
func (provider *RunwayProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Runway provider.
func (provider *RunwayProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Runway provider.
func (provider *RunwayProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *RunwayProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
