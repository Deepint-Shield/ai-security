// Package mistral implements the Mistral provider.
package mistral

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/providers/openai"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// MistralProvider implements the Provider interface for Mistral's API.
type MistralProvider struct {
	logger              schemas.Logger        // Logger for provider operations
	client              *fasthttp.Client      // HTTP client for API requests
	networkConfig       schemas.NetworkConfig // Network configuration including extra headers
	sendBackRawRequest  bool                  // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse bool                  // Whether to include raw response in DeepIntShieldResponse
}

// NewMistralProvider creates a new Mistral provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewMistralProvider(config *schemas.ProviderConfig, logger schemas.Logger) *MistralProvider {
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

	// Pre-warm response pools
	// for range config.ConcurrencyAndBufferSize.Concurrency {
	// 	mistralResponsePool.Put(&schemas.DeepIntShieldResponse{})
	// }

	// Configure proxy and retry policy
	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)
	// Set default BaseURL if not provided
	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = "https://api.mistral.ai"
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &MistralProvider{
		logger:              logger,
		client:              client,
		networkConfig:       config.NetworkConfig,
		sendBackRawRequest:  config.SendBackRawRequest,
		sendBackRawResponse: config.SendBackRawResponse,
	}
}

// GetProviderKey returns the provider identifier for Mistral.
func (provider *MistralProvider) GetProviderKey() schemas.ModelProvider {
	return schemas.Mistral
}

// listModelsByKey performs a list models request for a single key.
// Returns the response and latency, or an error if the request fails.
func (provider *MistralProvider) listModelsByKey(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.SetRequestURI(providerUtils.ResolveBaseURL(ctx, provider.networkConfig.BaseURL) + providerUtils.GetPathFromContext(ctx, "/v1/models"))
	req.Header.SetMethod(http.MethodGet)
	req.Header.SetContentType("application/json")
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		deepintshieldErr := openai.ParseOpenAIError(resp, schemas.ListModelsRequest, providerName, "")
		return nil, deepintshieldErr
	}

	// Copy response body before releasing
	responseBody := append([]byte(nil), resp.Body()...)

	// Parse Mistral's response
	var mistralResponse MistralListModelsResponse
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, &mistralResponse, nil, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Create final response
	response := mistralResponse.ToDeepIntShieldListModelsResponse(key.Models)

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

// ListModels performs a list models request to Mistral's API.
// Requests are made concurrently for improved performance.
func (provider *MistralProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	return providerUtils.HandleMultipleListModelsRequests(
		ctx,
		keys,
		request,
		provider.listModelsByKey,
	)
}

// TextCompletion is not supported by the Mistral provider.
func (provider *MistralProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

// TextCompletionStream performs a streaming text completion request to Mistral's API.
// It formats the request, sends it to Mistral, and processes the response.
// Returns a channel of DeepIntShieldStreamChunk objects or an error if the request fails.
func (provider *MistralProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

// ChatCompletion performs a chat completion request to the Mistral API.
func (provider *MistralProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	return openai.HandleOpenAIChatCompletionRequest(
		ctx,
		provider.client,
		providerUtils.ResolveBaseURL(ctx, provider.networkConfig.BaseURL)+providerUtils.GetPathFromContext(ctx, "/v1/chat/completions"),
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

// ChatCompletionStream performs a streaming chat completion request to the Mistral API.
// It supports real-time streaming of responses using Server-Sent Events (SSE).
// Uses Mistral's OpenAI-compatible streaming format.
// Returns a channel containing DeepIntShieldStreamChunk objects representing the stream or an error if the request fails.
func (provider *MistralProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
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
		schemas.Mistral,
		postHookRunner,
		nil,
		nil,
		nil,
		nil,
		nil,
		provider.logger,
	)
}

// Responses performs a responses request to the Mistral API.
func (provider *MistralProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
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

// ResponsesStream performs a streaming responses request to the Mistral API.
func (provider *MistralProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	ctx.SetValue(schemas.DeepIntShieldContextKeyIsResponsesToChatCompletionFallback, true)
	return provider.ChatCompletionStream(
		ctx,
		postHookRunner,
		key,
		request.ToChatRequest(),
	)
}

// Embedding generates embeddings for the given input text(s) using the Mistral API.
// Supports Mistral's embedding models and returns a DeepIntShieldResponse containing the embedding(s).
func (provider *MistralProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	// Use the shared embedding request handler
	return openai.HandleOpenAIEmbeddingRequest(
		ctx,
		provider.client,
		providerUtils.ResolveBaseURL(ctx, provider.networkConfig.BaseURL)+providerUtils.GetPathFromContext(ctx, "/v1/embeddings"),
		request,
		key,
		provider.networkConfig.ExtraHeaders,
		schemas.Mistral,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		nil,
		provider.logger,
	)
}

// Speech is not supported by the Mistral provider.
func (provider *MistralProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, provider.GetProviderKey())
}

// Rerank is not supported by the Mistral provider.
func (provider *MistralProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

// SpeechStream is not supported by the Mistral provider.
func (provider *MistralProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

// Transcription performs an audio transcription request to the Mistral API.
// It creates a multipart form with the audio file and sends it to Mistral's transcription endpoint.
// Returns the transcribed text and metadata, or an error if the request fails.
func (provider *MistralProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	// Convert DeepIntShield request to Mistral format
	mistralReq := ToMistralTranscriptionRequest(request)
	if mistralReq == nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("transcription input is not provided", nil, providerName)
	}

	// Create multipart form body
	body, contentType, deepintshieldErr := createMistralTranscriptionMultipartBody(mistralReq, providerName)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Create HTTP request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.SetRequestURI(providerUtils.ResolveBaseURL(ctx, provider.networkConfig.BaseURL) + providerUtils.GetPathFromContext(ctx, "/v1/audio/transcriptions"))
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType(contentType)
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	req.SetBody(body.Bytes())

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
		return nil, openai.ParseOpenAIError(resp, schemas.TranscriptionRequest, providerName, request.Model)
	}

	responseBody, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}

	// Check for empty response
	trimmed := strings.TrimSpace(string(responseBody))
	if len(trimmed) == 0 {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: true,
			Error: &schemas.ErrorField{
				Message: schemas.ErrProviderResponseEmpty,
			},
		}
	}

	copiedResponseBody := append([]byte(nil), responseBody...)

	// Parse Mistral's transcription response
	var mistralResponse MistralTranscriptionResponse
	if err := sonic.Unmarshal(copiedResponseBody, &mistralResponse); err != nil {
		if providerUtils.IsHTMLResponse(resp, copiedResponseBody) {
			return nil, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Message: schemas.ErrProviderResponseHTML,
					Error:   errors.New(string(copiedResponseBody)),
				},
			}
		}
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseUnmarshal, err, providerName)
	}

	// Convert to DeepIntShield format
	response := mistralResponse.ToDeepIntShieldTranscriptionResponse()
	if response == nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to convert transcription response", nil, providerName)
	}

	// Set extra fields
	response.ExtraFields.Latency = latency.Milliseconds()
	response.ExtraFields.RequestType = schemas.TranscriptionRequest
	response.ExtraFields.Provider = providerName
	response.ExtraFields.ModelRequested = request.Model

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		var rawResponse interface{}
		if err := sonic.Unmarshal(copiedResponseBody, &rawResponse); err == nil {
			response.ExtraFields.RawResponse = rawResponse
		}
	}

	return response, nil
}

// TranscriptionStream performs a streaming transcription request to Mistral's API.
// It creates a multipart form with the audio file and streams transcription events.
// Returns a channel of DeepIntShieldStreamChunk objects containing transcription deltas.
func (provider *MistralProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	// Convert DeepIntShield request to Mistral format
	mistralReq := ToMistralTranscriptionRequest(request)
	if mistralReq == nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("transcription input is not provided", nil, providerName)
	}
	mistralReq.Stream = schemas.Ptr(true)

	// Create multipart form body with stream=true
	body, contentType, deepintshieldErr := createMistralTranscriptionMultipartBody(mistralReq, providerName)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Prepare headers for streaming
	headers := map[string]string{
		"Content-Type":  contentType,
		"Accept":        "text/event-stream",
		"Cache-Control": "no-cache",
	}

	if key.Value.GetValue() != "" {
		headers["Authorization"] = "Bearer " + key.Value.GetValue()
	}

	// Create HTTP request for streaming
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	resp.StreamBody = true
	defer fasthttp.ReleaseRequest(req)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.Header.SetMethod(http.MethodPost)
	req.SetRequestURI(providerUtils.ResolveBaseURL(ctx, provider.networkConfig.BaseURL) + providerUtils.GetPathFromContext(ctx, "/v1/audio/transcriptions"))

	// Set headers
	for headerKey, value := range headers {
		req.Header.Set(headerKey, value)
	}

	req.SetBody(body.Bytes())

	// Make the request
	err := provider.client.Do(req, resp)
	if err != nil {
		defer providerUtils.ReleaseStreamingResponse(resp)
		if errors.Is(err, context.Canceled) {
			return nil, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Type:    schemas.Ptr(schemas.RequestCancelled),
					Message: schemas.ErrRequestCancelled,
					Error:   err,
				},
			}
		}
		if errors.Is(err, fasthttp.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderRequestTimedOut, err, providerName)
		}
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, err, providerName)
	}

	// Store provider response headers in context before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
		return nil, openai.ParseOpenAIError(resp, schemas.TranscriptionStreamRequest, providerName, request.Model)
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
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.TranscriptionStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.TranscriptionStreamRequest, provider.logger)
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

		sseReader := providerUtils.GetSSEEventReader(ctx, reader)
		chunkIndex := -1

		startTime := time.Now()
		lastChunkTime := startTime

		for {
			// If context was cancelled/timed out, let defer handle it
			if ctx.Err() != nil {
				return
			}

			eventType, eventDataBytes, readErr := sseReader.ReadEvent()
			if readErr != nil {
				if readErr != io.EOF {
					// If context was cancelled/timed out, let defer handle it
					if ctx.Err() != nil {
						return
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					provider.logger.Warn("Error reading stream: %v", readErr)
					providerUtils.ProcessAndSendError(ctx, postHookRunner, readErr, responseChan, schemas.TranscriptionStreamRequest, providerName, request.Model, provider.logger)
				}
				break
			}

			currentEvent := eventType
			currentData := string(eventDataBytes)
			if currentEvent == "" || currentData == "" {
				continue
			}

			chunkIndex++
			provider.processTranscriptionStreamEvent(ctx, postHookRunner, currentEvent, currentData, request.Model, providerName, chunkIndex, startTime, &lastChunkTime, responseChan)
			// Break on terminal stream indicator (covers both done events and error events
			// that processTranscriptionStreamEvent signals via context).
			if ended, _ := ctx.Value(schemas.DeepIntShieldContextKeyStreamEndIndicator).(bool); ended {
				break
			}
		}
	}()

	return responseChan, nil
}

// processTranscriptionStreamEvent processes a single SSE event and sends it to the response channel.
func (provider *MistralProvider) processTranscriptionStreamEvent(
	ctx *schemas.DeepIntShieldContext,
	postHookRunner schemas.PostHookRunner,
	eventType string,
	jsonData string,
	model string,
	providerName schemas.ModelProvider,
	chunkIndex int,
	startTime time.Time,
	lastChunkTime *time.Time,
	responseChan chan *schemas.DeepIntShieldStreamChunk,
) {
	// Skip empty data
	if strings.TrimSpace(jsonData) == "" {
		return
	}

	// Quick check for error field (allocation-free using sonic.GetFromString)
	if errorNode, _ := sonic.GetFromString(jsonData, "error"); errorNode.Exists() {
		// Only unmarshal when we know there's an error
		var deepintshieldErr schemas.DeepIntShieldError
		if err := sonic.UnmarshalString(jsonData, &deepintshieldErr); err == nil {
			if deepintshieldErr.Error != nil && deepintshieldErr.Error.Message != "" {
				deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
					Provider:       providerName,
					ModelRequested: model,
					RequestType:    schemas.TranscriptionStreamRequest,
				}
				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, &deepintshieldErr, responseChan, provider.logger)
				return
			}
		}
	}

	// Parse the event data
	var eventData MistralTranscriptionStreamData
	if err := sonic.UnmarshalString(jsonData, &eventData); err != nil {
		provider.logger.Warn("Failed to parse stream event data: %v", err)
		return
	}

	// Create the stream event
	streamEvent := &MistralTranscriptionStreamEvent{
		Event: eventType,
		Data:  &eventData,
	}

	// Convert to DeepIntShield format
	response := streamEvent.ToDeepIntShieldTranscriptionStreamResponse()
	if response == nil {
		return
	}

	// Set extra fields
	response.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
		RequestType:    schemas.TranscriptionStreamRequest,
		Provider:       providerName,
		ModelRequested: model,
		ChunkIndex:     chunkIndex,
		Latency:        time.Since(*lastChunkTime).Milliseconds(),
	}
	*lastChunkTime = time.Now()

	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		response.ExtraFields.RawResponse = jsonData
	}

	// Check for done event (handle both "transcription.done" and "transcript.text.done")
	if MistralTranscriptionStreamEventType(eventType) == MistralTranscriptionStreamEventDone || eventType == "transcript.text.done" {
		response.ExtraFields.Latency = time.Since(startTime).Milliseconds()
		ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
		// Ensure response type is set to Done
		response.Type = schemas.TranscriptionStreamResponseTypeDone
	}

	providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, response, nil), responseChan)
}

// BatchCreate is not supported by Mistral provider.
func (provider *MistralProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by Mistral provider.
func (provider *MistralProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by Mistral provider.
func (provider *MistralProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by Mistral provider.
func (provider *MistralProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by Mistral provider.
func (provider *MistralProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by Mistral provider.
func (provider *MistralProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// FileUpload is not supported by Mistral provider.
func (provider *MistralProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by Mistral provider.
func (provider *MistralProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by Mistral provider.
func (provider *MistralProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by Mistral provider.
func (provider *MistralProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by Mistral provider.
func (provider *MistralProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// CountTokens is not supported by the Mistral provider.
func (provider *MistralProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ImageGeneration is not supported by the Mistral provider.
func (provider *MistralProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, provider.GetProviderKey())
}

// ImageGenerationStream is not supported by the Mistral provider.
func (provider *MistralProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, provider.GetProviderKey())
}

// ImageEdit is not supported by the Mistral provider.
func (provider *MistralProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
}

// ImageEditStream is not supported by the Mistral provider.
func (provider *MistralProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, provider.GetProviderKey())
}

// ImageVariation is not supported by the Mistral provider.
func (provider *MistralProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration is not supported by the Mistral provider.
func (provider *MistralProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, provider.GetProviderKey())
}

// VideoRetrieve is not supported by the Mistral provider.
func (provider *MistralProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, provider.GetProviderKey())
}

// VideoDownload is not supported by the Mistral provider.
func (provider *MistralProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, provider.GetProviderKey())
}

// VideoDelete is not supported by the Mistral provider.
func (provider *MistralProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by the Mistral provider.
func (provider *MistralProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by the Mistral provider.
func (provider *MistralProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Mistral provider.
func (provider *MistralProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Mistral provider.
func (provider *MistralProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *MistralProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
