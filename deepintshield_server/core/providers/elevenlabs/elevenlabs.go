package elevenlabs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

type ElevenlabsProvider struct {
	logger               schemas.Logger                // Logger for provider operations
	client               *fasthttp.Client              // HTTP client for API requests
	networkConfig        schemas.NetworkConfig         // Network configuration including extra headers
	sendBackRawRequest   bool                          // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse  bool                          // Whether to include raw response in DeepIntShieldResponse
	customProviderConfig *schemas.CustomProviderConfig // Custom provider config
}

// NewElevenlabsProvider creates a new Elevenlabs provider instance.
// It initializes the HTTP client with the provided configuration.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewElevenlabsProvider(config *schemas.ProviderConfig, logger schemas.Logger) *ElevenlabsProvider {
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
		config.NetworkConfig.BaseURL = "https://api.elevenlabs.io"
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &ElevenlabsProvider{
		logger:               logger,
		client:               client,
		networkConfig:        config.NetworkConfig,
		customProviderConfig: config.CustomProviderConfig,
		sendBackRawRequest:   config.SendBackRawRequest,
		sendBackRawResponse:  config.SendBackRawResponse,
	}
}

// GetProviderKey returns the provider identifier for Elevenlabs.
func (provider *ElevenlabsProvider) GetProviderKey() schemas.ModelProvider {
	return providerUtils.GetProviderName(schemas.Elevenlabs, provider.customProviderConfig)
}

// listModelsByKey performs a list models request for a single key.
// Returns the response and latency, or an error if the request fails.
func (provider *ElevenlabsProvider) listModelsByKey(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Build URL using centralized URL construction
	req.SetRequestURI(provider.networkConfig.BaseURL + providerUtils.GetPathFromContext(ctx, "/v1/models"))
	req.Header.SetMethod(http.MethodGet)
	req.Header.SetContentType("application/json")

	if key.Value.GetValue() != "" {
		req.Header.Set("xi-api-key", key.Value.GetValue())
	}

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}
	// Extract and set provider response headers so they're available on error paths
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, parseElevenlabsError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			RequestType: schemas.ListModelsRequest,
		})
	}

	var elevenlabsResponse ElevenlabsListModelsResponse
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(resp.Body(), &elevenlabsResponse, nil, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	response := elevenlabsResponse.ToDeepIntShieldListModelsResponse(providerName, key.Models, request.Unfiltered)

	response.ExtraFields.Latency = latency.Milliseconds()
	response.ExtraFields.ProviderResponseHeaders = providerUtils.ExtractProviderResponseHeaders(resp)

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

// ListModels performs a list models request to Elevenlabs' API.
// Requests are made concurrently for improved performance.
func (provider *ElevenlabsProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Elevenlabs, provider.customProviderConfig, schemas.ListModelsRequest); err != nil {
		return nil, err
	}
	return providerUtils.HandleMultipleListModelsRequests(
		ctx,
		keys,
		request,
		provider.listModelsByKey,
	)
}

// TextCompletion is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

// TextCompletionStream is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

// ChatCompletion is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ChatCompletionRequest, provider.GetProviderKey())
}

// ChatCompletionStream is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ChatCompletionStreamRequest, provider.GetProviderKey())
}

// Responses is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ResponsesRequest, provider.GetProviderKey())
}

// ResponsesStream is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ResponsesStreamRequest, provider.GetProviderKey())
}

// Embedding is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, input *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, provider.GetProviderKey())
}

// Speech performs a text to speech request
func (provider *ElevenlabsProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Elevenlabs, provider.customProviderConfig, schemas.SpeechRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	withTimestampsRequest := request.Params != nil && request.Params.WithTimestamps != nil && *request.Params.WithTimestamps

	var endpoint string
	if request.Params != nil && request.Params.VoiceConfig != nil && request.Params.VoiceConfig.Voice != nil {
		voice := *request.Params.VoiceConfig.Voice
		// Determine if timestamps are requested
		if withTimestampsRequest {
			endpoint = "/v1/text-to-speech/" + voice + "/with-timestamps"
		} else {
			endpoint = "/v1/text-to-speech/" + voice
		}
	} else {
		return nil, providerUtils.NewDeepIntShieldOperationError("voice parameter is required", nil, providerName)
	}

	requestURL := provider.buildBaseSpeechRequestURL(ctx, endpoint, schemas.SpeechRequest, request)
	req.SetRequestURI(requestURL)

	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")
	if key.Value.GetValue() != "" {
		req.Header.Set("xi-api-key", key.Value.GetValue())
	}

	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToElevenlabsSpeechRequest(request), nil
		},
		providerName)

	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	if !providerUtils.ApplyLargePayloadRequestBody(ctx, req) {
		req.SetBody(jsonData)
	}

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}
	// Extract and set provider response headers so they're available on error paths
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		provider.logger.Debug(fmt.Sprintf("error from %s provider: %s", providerName, string(resp.Body())))
		return nil, providerUtils.EnrichError(ctx, parseElevenlabsError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.SpeechRequest,
		}), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Get the response body
	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Create response based on whether timestamps were requested
	deepintshieldResponse := &schemas.DeepIntShieldSpeechResponse{
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType:             schemas.SpeechRequest,
			Provider:                providerName,
			ModelRequested:          request.Model,
			Latency:                 latency.Milliseconds(),
			ProviderResponseHeaders: providerUtils.ExtractProviderResponseHeaders(resp),
		},
	}

	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&deepintshieldResponse.ExtraFields, jsonData)
	}

	if withTimestampsRequest {
		var timestampResponse ElevenlabsSpeechWithTimestampsResponse
		if err := sonic.Unmarshal(body, &timestampResponse); err != nil {
			return nil, providerUtils.NewDeepIntShieldOperationError("failed to parse with-timestamps response", err, providerName)
		}

		deepintshieldResponse.AudioBase64 = &timestampResponse.AudioBase64

		if timestampResponse.Alignment != nil {
			deepintshieldResponse.Alignment = &schemas.SpeechAlignment{
				CharStartTimesMs: timestampResponse.Alignment.CharStartTimesMs,
				CharEndTimesMs:   timestampResponse.Alignment.CharEndTimesMs,
				Characters:       timestampResponse.Alignment.Characters,
			}
		}

		if timestampResponse.NormalizedAlignment != nil {
			deepintshieldResponse.NormalizedAlignment = &schemas.SpeechAlignment{
				CharStartTimesMs: timestampResponse.NormalizedAlignment.CharStartTimesMs,
				CharEndTimesMs:   timestampResponse.NormalizedAlignment.CharEndTimesMs,
				Characters:       timestampResponse.NormalizedAlignment.Characters,
			}
		}

		return deepintshieldResponse, nil
	}

	deepintshieldResponse.Audio = body
	return deepintshieldResponse, nil
}

// Rerank is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

// SpeechStream performs a text to speech stream request
func (provider *ElevenlabsProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Elevenlabs, provider.customProviderConfig, schemas.SpeechStreamRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToElevenlabsSpeechRequest(request), nil
		},
		providerName)

	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Create HTTP request for streaming
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	resp.StreamBody = true
	defer fasthttp.ReleaseRequest(req)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	if request.Params == nil || request.Params.VoiceConfig == nil || request.Params.VoiceConfig.Voice == nil {
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError("voice parameter is required", nil, providerName), jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	req.SetRequestURI(provider.buildBaseSpeechRequestURL(ctx, "/v1/text-to-speech/"+*request.Params.VoiceConfig.Voice+"/stream", schemas.SpeechStreamRequest, request))

	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")
	if key.Value.GetValue() != "" {
		req.Header.Set("xi-api-key", key.Value.GetValue())
	}

	if !providerUtils.ApplyLargePayloadRequestBody(ctx, req) {
		req.SetBody(jsonBody)
	}

	// Make request
	startTime := time.Now()
	err := providerUtils.ClientFromContext(ctx, provider.client).Do(req, resp)
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
			}, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
		if errors.Is(err, fasthttp.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderRequestTimedOut, err, providerName), jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, err, providerName), jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Extract provider response headers before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		return nil, providerUtils.EnrichError(ctx, parseElevenlabsError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.SpeechStreamRequest,
		}), jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Create response channel
	responseChan := make(chan *schemas.DeepIntShieldStreamChunk, schemas.DefaultStreamBufferSize)

	providerUtils.SetStreamIdleTimeoutIfEmpty(ctx, provider.networkConfig.StreamIdleTimeoutInSeconds)

	go func() {
		defer func() {
			if ctx.Err() == context.Canceled {
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.SpeechStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.SpeechStreamRequest, provider.logger)
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

		// read binary audio chunks from the stream
		// 4KB buffer for reading chunks
		buffer := make([]byte, 4096)
		bodyStream := reader
		chunkIndex := -1
		lastChunkTime := time.Now()

		for {
			// If context was cancelled/timed out, let defer handle it
			if ctx.Err() != nil {
				return
			}
			n, err := bodyStream.Read(buffer)
			if err != nil {
				// If context was cancelled/timed out, let defer handle it
				if ctx.Err() != nil {
					return
				}
				if err == io.EOF {
					break
				}
				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				provider.logger.Warn("Error reading stream: %v", err)
				providerUtils.ProcessAndSendError(ctx, postHookRunner, err, responseChan, schemas.SpeechStreamRequest, providerName, request.Model, provider.logger)
				return
			}

			if n > 0 {
				chunkIndex++
				audioChunk := make([]byte, n)
				copy(audioChunk, buffer[:n])

				response := &schemas.DeepIntShieldSpeechStreamResponse{
					Type:  schemas.SpeechStreamResponseTypeDelta,
					Audio: audioChunk,
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.SpeechStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(lastChunkTime).Milliseconds(),
					},
				}

				lastChunkTime = time.Now()

				if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
					response.ExtraFields.RawResponse = audioChunk
				}

				providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, response, nil, nil), responseChan)
			}
		}

		// Send final response after natural loop termination (similar to Gemini pattern)
		finalResponse := &schemas.DeepIntShieldSpeechStreamResponse{
			Type:  schemas.SpeechStreamResponseTypeDone,
			Audio: []byte{},
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				RequestType:    schemas.SpeechStreamRequest,
				Provider:       providerName,
				ModelRequested: request.Model,
				ChunkIndex:     chunkIndex + 1,
				Latency:        time.Since(startTime).Milliseconds(),
			},
		}

		// Set raw request if enabled
		if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
			providerUtils.ParseAndSetRawRequest(&finalResponse.ExtraFields, jsonBody)
		}
		ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
		providerUtils.ProcessAndSendResponse(ctx, postHookRunner, providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, finalResponse, nil, nil), responseChan)
	}()

	return responseChan, nil
}

// Transcription performs a transcription request
func (provider *ElevenlabsProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Elevenlabs, provider.customProviderConfig, schemas.TranscriptionRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()

	reqBody := ToElevenlabsTranscriptionRequest(request)
	if reqBody == nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("transcription request is not provided", nil, providerName)
	}

	hasFile := len(reqBody.File) > 0
	hasURL := reqBody.CloudStorageURL != nil && strings.TrimSpace(*reqBody.CloudStorageURL) != ""
	if hasFile && hasURL {
		return nil, providerUtils.NewDeepIntShieldOperationError("provide either a file or cloud_storage_url, not both", nil, providerName)
	}
	if !hasFile && !hasURL {
		return nil, providerUtils.NewDeepIntShieldOperationError("either a transcription file or cloud_storage_url must be provided", nil, providerName)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if deepintshieldErr := writeTranscriptionMultipart(writer, reqBody, providerName); deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	contentType := writer.FormDataContentType()
	if err := writer.Close(); err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to finalize multipart transcription request", err, providerName)
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	requestPath, isCompleteURL := providerUtils.GetRequestPath(ctx, "/v1/speech-to-text", provider.customProviderConfig, schemas.TranscriptionRequest)
	if isCompleteURL {
		req.SetRequestURI(requestPath)
	} else {
		req.SetRequestURI(provider.networkConfig.BaseURL + requestPath)
	}
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType(contentType)
	if key.Value.GetValue() != "" {
		req.Header.Set("xi-api-key", key.Value.GetValue())
	}
	req.SetBody(body.Bytes())

	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}
	// Extract and set provider response headers so they're available on error paths
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))
	if resp.StatusCode() != fasthttp.StatusOK {
		provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
		return nil, parseElevenlabsError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.TranscriptionRequest,
		})
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

	chunks, err := parseTranscriptionResponse(responseBody)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(err.Error(), nil, providerName)
	}

	if len(chunks) == 0 {
		return nil, providerUtils.NewDeepIntShieldOperationError("no chunks found in transcription response", nil, providerName)
	}

	response := ToDeepIntShieldTranscriptionResponse(chunks)
	response.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
		RequestType:             schemas.TranscriptionRequest,
		Provider:                providerName,
		ModelRequested:          request.Model,
		Latency:                 latency.Milliseconds(),
		ProviderResponseHeaders: providerUtils.ExtractProviderResponseHeaders(resp),
	}

	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		var rawResponse interface{}
		if err := sonic.Unmarshal(responseBody, &rawResponse); err != nil {
			return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderRawResponseUnmarshal, err, providerName)
		}
		response.ExtraFields.RawResponse = rawResponse
	}

	return response, nil
}

func writeTranscriptionMultipart(writer *multipart.Writer, reqBody *ElevenlabsTranscriptionRequest, providerName schemas.ModelProvider) *schemas.DeepIntShieldError {
	if err := writer.WriteField("model_id", reqBody.ModelID); err != nil {
		return providerUtils.NewDeepIntShieldOperationError("failed to write model_id field", err, providerName)
	}

	if len(reqBody.File) > 0 {
		filename := reqBody.Filename
		if filename == "" {
			filename = providerUtils.AudioFilenameFromBytes(reqBody.File)
		}
		fileWriter, err := writer.CreateFormFile("file", filename)
		if err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to create file field", err, providerName)
		}
		if _, err := fileWriter.Write(reqBody.File); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write file data", err, providerName)
		}
	}

	if reqBody.CloudStorageURL != nil && strings.TrimSpace(*reqBody.CloudStorageURL) != "" {
		if err := writer.WriteField("cloud_storage_url", *reqBody.CloudStorageURL); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write cloud_storage_url field", err, providerName)
		}
	}

	if reqBody.LanguageCode != nil && strings.TrimSpace(*reqBody.LanguageCode) != "" {
		if err := writer.WriteField("language_code", *reqBody.LanguageCode); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write language_code field", err, providerName)
		}
	}

	if reqBody.TagAudioEvents != nil {
		if err := writer.WriteField("tag_audio_events", strconv.FormatBool(*reqBody.TagAudioEvents)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write tag_audio_events field", err, providerName)
		}
	}

	if reqBody.NumSpeakers != nil && *reqBody.NumSpeakers > 0 {
		if err := writer.WriteField("num_speakers", strconv.Itoa(*reqBody.NumSpeakers)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write num_speakers field", err, providerName)
		}
	}

	if reqBody.TimestampsGranularity != nil && *reqBody.TimestampsGranularity != "" {
		if err := writer.WriteField("timestamps_granularity", string(*reqBody.TimestampsGranularity)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write timestamps_granularity field", err, providerName)
		}
	}

	if reqBody.Diarize != nil {
		if err := writer.WriteField("diarize", strconv.FormatBool(*reqBody.Diarize)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write diarize field", err, providerName)
		}
	}

	if reqBody.DiarizationThreshold != nil {
		if err := writer.WriteField("diarization_threshold", strconv.FormatFloat(*reqBody.DiarizationThreshold, 'f', -1, 64)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write diarization_threshold field", err, providerName)
		}
	}

	if len(reqBody.AdditionalFormats) > 0 {
		payload, err := sonic.Marshal(reqBody.AdditionalFormats)
		if err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to marshal additional_formats", err, providerName)
		}
		if err := writer.WriteField("additional_formats", string(payload)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write additional_formats field", err, providerName)
		}
	}

	if reqBody.FileFormat != nil && *reqBody.FileFormat != "" {
		if err := writer.WriteField("file_format", string(*reqBody.FileFormat)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write file_format field", err, providerName)
		}
	}

	if reqBody.Webhook != nil {
		if err := writer.WriteField("webhook", strconv.FormatBool(*reqBody.Webhook)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write webhook field", err, providerName)
		}
	}

	if reqBody.WebhookID != nil && strings.TrimSpace(*reqBody.WebhookID) != "" {
		if err := writer.WriteField("webhook_id", *reqBody.WebhookID); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write webhook_id field", err, providerName)
		}
	}

	if reqBody.Temperature != nil {
		if err := writer.WriteField("temperature", strconv.FormatFloat(*reqBody.Temperature, 'f', -1, 64)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write temperature field", err, providerName)
		}
	}

	if reqBody.Seed != nil {
		if err := writer.WriteField("seed", strconv.Itoa(*reqBody.Seed)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write seed field", err, providerName)
		}
	}

	if reqBody.UseMultiChannel != nil {
		if err := writer.WriteField("use_multi_channel", strconv.FormatBool(*reqBody.UseMultiChannel)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write use_multi_channel field", err, providerName)
		}
	}

	if reqBody.WebhookMetadata != nil {
		switch v := reqBody.WebhookMetadata.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				if err := writer.WriteField("webhook_metadata", v); err != nil {
					return providerUtils.NewDeepIntShieldOperationError("failed to write webhook_metadata field", err, providerName)
				}
			}
		default:
			payload, err := sonic.Marshal(v)
			if err != nil {
				return providerUtils.NewDeepIntShieldOperationError("failed to marshal webhook_metadata", err, providerName)
			}
			if err := writer.WriteField("webhook_metadata", string(payload)); err != nil {
				return providerUtils.NewDeepIntShieldOperationError("failed to write webhook_metadata field", err, providerName)
			}
		}
	}

	return nil
}

// TranscriptionStream is not supported by the Elevenlabs provider
func (provider *ElevenlabsProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

// ImageGeneration is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationRequest, provider.GetProviderKey())
}

// ImageGenerationStream is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageGenerationStreamRequest, provider.GetProviderKey())
}

// ImageEdit is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
}

// ImageEditStream is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditStreamRequest, provider.GetProviderKey())
}

// ImageVariation is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration is not supported by the ElevenLabs provider.
func (provider *ElevenlabsProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, provider.GetProviderKey())
}

// VideoRetrieve is not supported by the ElevenLabs provider.
func (provider *ElevenlabsProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, provider.GetProviderKey())
}

// VideoDownload is not supported by the ElevenLabs provider.
func (provider *ElevenlabsProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, provider.GetProviderKey())
}

// VideoDelete is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// buildSpeechRequestURL constructs the full request URL using the provider's configuration for speech.
func (provider *ElevenlabsProvider) buildBaseSpeechRequestURL(ctx *schemas.DeepIntShieldContext, defaultPath string, requestType schemas.RequestType, request *schemas.DeepIntShieldSpeechRequest) string {
	baseURL := provider.networkConfig.BaseURL
	requestPath, isCompleteURL := providerUtils.GetRequestPath(ctx, defaultPath, provider.customProviderConfig, requestType)

	var finalURL string
	if isCompleteURL {
		finalURL = requestPath
	} else {
		u, parseErr := url.Parse(baseURL)
		if parseErr != nil {
			finalURL = baseURL + requestPath
		} else {
			u.Path = path.Join(u.Path, requestPath)
			finalURL = u.String()
		}
	}

	// Parse the final URL to add query parameters
	u, parseErr := url.Parse(finalURL)
	if parseErr != nil {
		return finalURL
	}

	q := u.Query()

	if request.Params != nil {
		if request.Params.EnableLogging != nil {
			q.Set("enable_logging", strconv.FormatBool(*request.Params.EnableLogging))
		}

		convertedFormat := ConvertDeepIntShieldSpeechFormatToElevenlabs(request.Params.ResponseFormat)
		if convertedFormat != "" {
			q.Set("output_format", convertedFormat)
		}

		if request.Params.OptimizeStreamingLatency != nil {
			q.Set("optimize_streaming_latency", strconv.FormatBool(*request.Params.OptimizeStreamingLatency))
		}
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// BatchCreate is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// FileUpload is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by Elevenlabs provider.
func (provider *ElevenlabsProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// CountTokens is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Elevenlabs provider.
func (provider *ElevenlabsProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *ElevenlabsProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
