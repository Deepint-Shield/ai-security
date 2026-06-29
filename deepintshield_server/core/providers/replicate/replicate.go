// Package providers implements various LLM providers and their utility functions.
// This file contains the replicate provider implementation.
package replicate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// ReplicateProvider implements the Provider interface for Replicate's API.
type ReplicateProvider struct {
	logger               schemas.Logger        // Logger for provider operations
	client               *fasthttp.Client      // HTTP client for API requests
	networkConfig        schemas.NetworkConfig // Network configuration including extra headers
	sendBackRawRequest   bool                  // Whether to include raw request in DeepIntShieldResponse
	sendBackRawResponse  bool                  // Whether to include raw response in DeepIntShieldResponse
	customProviderConfig *schemas.CustomProviderConfig
}

// NewReplicateProvider creates a new Replicate provider instance.
// It initializes the HTTP client with the provided configuration and sets up response pools.
// The client is configured with timeouts, concurrency limits, and optional proxy settings.
func NewReplicateProvider(config *schemas.ProviderConfig, logger schemas.Logger) (*ReplicateProvider, error) {
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
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = replicateAPIBaseURL
	}

	return &ReplicateProvider{
		logger:               logger,
		client:               client,
		networkConfig:        config.NetworkConfig,
		sendBackRawRequest:   config.SendBackRawRequest,
		sendBackRawResponse:  config.SendBackRawResponse,
		customProviderConfig: config.CustomProviderConfig,
	}, nil
}

// GetProviderKey returns the provider identifier for Replicate.
func (provider *ReplicateProvider) GetProviderKey() schemas.ModelProvider {
	return schemas.Replicate
}

// buildRequestURL builds the request URL with custom provider config support
func (provider *ReplicateProvider) buildRequestURL(ctx *schemas.DeepIntShieldContext, defaultPath string, requestType schemas.RequestType) string {
	path, isCompleteURL := providerUtils.GetRequestPath(ctx, defaultPath, provider.customProviderConfig, requestType)
	if isCompleteURL {
		return path
	}
	return provider.networkConfig.BaseURL + path
}

const (
	replicateAPIBaseURL = "https://api.replicate.com"
	pollingInterval     = 2 * time.Second
)

// createPrediction creates a new prediction on Replicate API
// Supports both sync (with Prefer: wait header) and async modes
// stripPrefer should be true for streaming requests to exclude the Prefer header
func createPrediction(
	ctx *schemas.DeepIntShieldContext,
	client *fasthttp.Client,
	jsonBody []byte,
	key schemas.Key,
	url string,
	extraHeaders map[string]string,
	stripPrefer bool,
	logger schemas.Logger,
	sendBackRawRequest bool,
	sendBackRawResponse bool,
) (*ReplicatePredictionResponse, interface{}, time.Duration, map[string]string, *schemas.DeepIntShieldError) {
	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set URL
	req.SetRequestURI(url)
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")

	// Set authorization header
	if value := key.Value.GetValue(); value != "" {
		req.Header.Set("Authorization", "Bearer "+value)
	}

	// Set any extra headers from network config
	// Strip Prefer header for streaming requests to ensure async mode
	headersToUse := extraHeaders
	if stripPrefer {
		headersToUse = stripPreferHeader(extraHeaders)
	}
	providerUtils.SetExtraHeaders(ctx, req, headersToUse, nil)

	if !providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.Replicate) {
		req.SetBody(jsonBody)
	}

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, nil, latency, nil, deepintshieldErr
	}

	// Extract provider response headers before releasing the response
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK && resp.StatusCode() != fasthttp.StatusCreated {
		logger.Debug(fmt.Sprintf("error from replicate provider: %s", string(resp.Body())))
		return nil, nil, latency, providerResponseHeaders, parseReplicateError(resp.Body(), resp.StatusCode())
	}

	// Parse response
	body, decodeErr := providerUtils.CheckAndDecodeBody(resp)
	if decodeErr != nil {
		return nil, nil, latency, providerResponseHeaders, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, decodeErr, schemas.Replicate)
	}

	var prediction ReplicatePredictionResponse
	_, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &prediction, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, nil, latency, providerResponseHeaders, deepintshieldErr
	}

	return &prediction, rawResponse, latency, providerResponseHeaders, nil
}

// getPrediction retrieves the current state of a prediction
func getPrediction(
	ctx *schemas.DeepIntShieldContext,
	client *fasthttp.Client,
	predictionURL string,
	key schemas.Key,
	logger schemas.Logger,
	sendBackRawResponse bool,
) (*ReplicatePredictionResponse, interface{}, map[string]string, *schemas.DeepIntShieldError) {
	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set URL
	req.SetRequestURI(predictionURL)
	req.Header.SetMethod(http.MethodGet)

	// Set authorization header
	if value := key.Value.GetValue(); value != "" {
		req.Header.Set("Authorization", "Bearer "+value)
	}

	// Make request
	_, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, nil, nil, deepintshieldErr
	}

	// Extract provider response headers before releasing the response
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		logger.Debug(fmt.Sprintf("error from replicate provider: %s", string(resp.Body())))
		return nil, nil, providerResponseHeaders, parseReplicateError(resp.Body(), resp.StatusCode())
	}

	// Parse response
	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, nil, providerResponseHeaders, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, schemas.Replicate)
	}

	prediction := &ReplicatePredictionResponse{}
	_, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, prediction, nil, false, sendBackRawResponse)
	if deepintshieldErr != nil {
		return nil, nil, providerResponseHeaders, deepintshieldErr
	}

	return prediction, rawResponse, providerResponseHeaders, nil
}

// pollPrediction polls a prediction URL until it reaches a terminal state or timeout
func pollPrediction(
	ctx *schemas.DeepIntShieldContext,
	client *fasthttp.Client,
	predictionURL string,
	key schemas.Key,
	timeoutSeconds int,
	logger schemas.Logger,
	sendBackRawResponse bool,
) (*ReplicatePredictionResponse, interface{}, map[string]string, *schemas.DeepIntShieldError) {
	// Create context with timeout
	pollCtx, cancel := schemas.NewDeepIntShieldContextWithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	ticker := time.NewTicker(pollingInterval)
	defer ticker.Stop()

	// Poll immediately first time
	prediction, rawResponse, providerResponseHeaders, err := getPrediction(pollCtx, client, predictionURL, key, logger, sendBackRawResponse)
	if err != nil {
		return nil, nil, providerResponseHeaders, err
	}

	// If already in terminal state, return immediately
	if isTerminalStatus(prediction.Status) {
		return prediction, rawResponse, providerResponseHeaders, checkForErrorStatus(prediction)
	}

	logger.Debug(fmt.Sprintf("polling replicate prediction %s, status: %s", prediction.ID, prediction.Status))

	// Continue polling until terminal state or timeout
	for {
		select {
		case <-pollCtx.Done():
			return nil, nil, providerResponseHeaders, providerUtils.NewDeepIntShieldOperationError(
				schemas.ErrProviderRequestTimedOut,
				fmt.Errorf("prediction polling timed out after %d seconds", timeoutSeconds),
				schemas.Replicate,
			)
		case <-ticker.C:
			prediction, rawResponse, providerResponseHeaders, err = getPrediction(pollCtx, client, predictionURL, key, logger, sendBackRawResponse)
			if err != nil {
				return nil, nil, providerResponseHeaders, err
			}

			logger.Debug(fmt.Sprintf("prediction %s status: %s", prediction.ID, prediction.Status))

			if isTerminalStatus(prediction.Status) {
				return prediction, rawResponse, providerResponseHeaders, checkForErrorStatus(prediction)
			}
		}
	}
}

// listDeploymentsByKey performs a list deployments request for a single key.
// Deployments are account-specific, so this needs to be called per key.
func (provider *ReplicateProvider) listDeploymentsByKey(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()
	client := provider.client
	extraHeaders := provider.networkConfig.ExtraHeaders

	// Build deployments URL
	deploymentsURL := provider.buildRequestURL(ctx, "/v1/deployments", schemas.ListModelsRequest)

	// Initialize pagination variables
	currentURL := deploymentsURL
	allDeployments := []ReplicateDeployment{}

	// Follow pagination until there are no more pages
	for currentURL != "" {
		// Create request
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		// Set up request
		req.SetRequestURI(currentURL)
		req.Header.SetMethod(http.MethodGet)
		req.Header.SetContentType("application/json")

		// Set authorization header if key is provided
		if key.Value.GetValue() != "" {
			req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
		}

		// Set extra headers from network config
		providerUtils.SetExtraHeaders(ctx, req, extraHeaders, nil)

		// Make request
		_, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, client, req, resp)

		// Release resources
		wait()
		fasthttp.ReleaseRequest(req)

		if deepintshieldErr != nil {
			fasthttp.ReleaseResponse(resp)
			return nil, deepintshieldErr
		}

		// Handle error response
		if resp.StatusCode() != fasthttp.StatusOK {
			errorResponse := parseReplicateError(resp.Body(), resp.StatusCode())
			fasthttp.ReleaseResponse(resp)
			return nil, errorResponse
		}

		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

		// Make a copy of the response body before releasing
		bodyCopy := make([]byte, len(resp.Body()))
		copy(bodyCopy, resp.Body())

		fasthttp.ReleaseResponse(resp)

		// Parse response from the copy
		var pageResponse ReplicateDeploymentListResponse
		if err := sonic.Unmarshal(bodyCopy, &pageResponse); err != nil {
			return nil, providerUtils.NewDeepIntShieldOperationError(
				"failed to parse deployments response",
				err,
				schemas.Replicate,
			)
		}

		// Append results from this page
		allDeployments = append(allDeployments, pageResponse.Results...)

		// Check if there's a next page
		if pageResponse.Next != nil && *pageResponse.Next != "" {
			currentURL = *pageResponse.Next
		} else {
			currentURL = ""
		}
	}

	// Wrap deployments in response structure
	deploymentsResponse := &ReplicateDeploymentListResponse{
		Results: allDeployments,
	}

	// Convert deployments to DeepIntShield response (no public models here)
	response := ToDeepIntShieldListModelsResponse(
		deploymentsResponse,
		providerName,
		key.Models,
		request.Unfiltered,
	)

	return response, nil
}

// ListModels performs a list models request to Replicate's API.
func (provider *ReplicateProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ListModelsRequest); err != nil {
		return nil, err
	}

	if provider.networkConfig.BaseURL == "" {
		return nil, providerUtils.NewConfigurationError("base_url is not set", provider.GetProviderKey())
	}

	startTime := time.Now()
	providerName := provider.GetProviderKey()

	response, err := providerUtils.HandleMultipleListModelsRequests(
		ctx,
		keys,
		request,
		provider.listDeploymentsByKey,
	)
	if err != nil {
		return nil, err
	}

	// Update metadata with total latency
	latency := time.Since(startTime)
	response.ExtraFields.Provider = providerName
	response.ExtraFields.RequestType = schemas.ListModelsRequest
	response.ExtraFields.Latency = latency.Milliseconds()

	return response, nil
}

// TextCompletion performs a text completion request to the replicate API.
func (provider *ReplicateProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.TextCompletionRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// build replicate request
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) { return ToReplicateTextRequest(request) },
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Check for Prefer: wait header from context for sync mode
	isSync := parsePreferHeader(provider.networkConfig.ExtraHeaders)

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.TextCompletionRequest,
		isDeployment,
	)

	// create prediction
	prediction, rawResponse, latency, providerResponseHeaders, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		false,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// if not sync, poll until done
	if !isSync && !isTerminalStatus(prediction.Status) {
		prediction, rawResponse, providerResponseHeaders, err = pollPrediction(
			ctx,
			provider.client,
			prediction.URLs.Get,
			key,
			provider.networkConfig.DefaultRequestTimeoutInSeconds,
			provider.logger,
			providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		)
		if err != nil {
			return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
	}

	// Check for terminal error status (failed/canceled) after sync mode or polling
	if err := checkForErrorStatus(prediction); err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}

	// Convert to DeepIntShield response
	deepintshieldResponse := prediction.ToDeepIntShieldTextCompletionResponse()

	// Set extra fields
	deepintshieldResponse.ExtraFields.Provider = schemas.Replicate
	deepintshieldResponse.ExtraFields.RequestType = schemas.TextCompletionRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&deepintshieldResponse.ExtraFields, jsonData)
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// TextCompletionStream performs a streaming text completion request to replicate's API.
// It formats the request, sends it to replicate, and processes the response.
// Returns a channel of DeepIntShieldStream objects or an error if the request fails.
func (provider *ReplicateProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.TextCompletionStreamRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Convert DeepIntShield request to Replicate format with streaming enabled
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			replicateReq, err := ToReplicateTextRequest(request)
			if err != nil {
				return nil, err
			}
			replicateReq.Stream = schemas.Ptr(true)
			return replicateReq, nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.TextCompletionStreamRequest,
		isDeployment,
	)

	// Create prediction
	prediction, _, _, _, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		true, // Streaming request, strip Prefer header for async mode
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Verify stream URL is available
	if prediction.URLs == nil || prediction.URLs.Stream == nil || *prediction.URLs.Stream == "" {
		deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
			"stream URL not available in prediction response",
			fmt.Errorf("prediction response missing stream URL"),
			provider.GetProviderKey(),
		)
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	streamURL := *prediction.URLs.Stream

	// Connect to stream URL
	_, resp, deepintshieldErr := listenToReplicateStreamURL(ctx, provider.client, streamURL, key)
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Store provider response headers in context for transport layer
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

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
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, provider.GetProviderKey(), request.Model, schemas.TextCompletionStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, provider.GetProviderKey(), request.Model, schemas.TextCompletionStreamRequest, provider.logger)
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

		startTime := time.Now()
		lastChunkTime := startTime
		chunkIndex := 0

		// Setup SSE event reader for event+data format
		sseReader := providerUtils.GetSSEEventReader(ctx, reader)

		messageID := prediction.ID

		for {
			// Check for context cancellation
			select {
			case <-ctx.Done():
				return
			default:
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
					enrichedErr := providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, readErr, provider.GetProviderKey()), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
				}
				break
			}

			eventData := string(eventDataBytes)
			if eventType == "" && eventData == "" {
				continue
			}

			// Process the complete event
			switch eventType {
			case "output":
				// Accumulate content from data field
				if eventData != "" {
					// Create a streaming chunk with text completion response
					text := eventData
					response := &schemas.DeepIntShieldTextCompletionResponse{
						ID:     messageID,
						Model:  request.Model,
						Object: "text_completion",
						Choices: []schemas.DeepIntShieldResponseChoice{
							{
								Index: 0,
								TextCompletionResponseChoice: &schemas.TextCompletionResponseChoice{
									Text: &text,
								},
							},
						},
						ExtraFields: schemas.DeepIntShieldResponseExtraFields{
							RequestType:    schemas.TextCompletionStreamRequest,
							Provider:       provider.GetProviderKey(),
							ModelRequested: request.Model,
							ChunkIndex:     chunkIndex,
							Latency:        time.Since(lastChunkTime).Milliseconds(),
						},
					}

					// Set raw response if enabled (per-chunk event as JSON string)
					if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
						rawEvent := ReplicateSSEEvent{Event: eventType, Data: eventData}
						if eventJSON, err := sonic.Marshal(rawEvent); err == nil {
							response.ExtraFields.RawResponse = string(eventJSON)
						}
					}

					lastChunkTime = time.Now()
					chunkIndex++

					providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
						providerUtils.GetDeepIntShieldResponseForStreamResponse(response, nil, nil, nil, nil, nil),
						responseChan)
				}

			case "done":
				// Parse done event data
				var doneData ReplicateDoneEvent
				if eventData != "" && eventData != "{}" {
					if err := sonic.Unmarshal(eventDataBytes, &doneData); err != nil {
						provider.logger.Warn(fmt.Sprintf("Failed to parse done event data: %v", err))
					}
				}

				// Check for cancellation or error
				switch doneData.Reason {
				case "canceled":
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"prediction was canceled",
						fmt.Errorf("stream ended: prediction canceled"),
						provider.GetProviderKey(),
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       provider.GetProviderKey(),
						ModelRequested: request.Model,
						RequestType:    schemas.TextCompletionStreamRequest,
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					enrichedErr := providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
					// Explicitly close the body stream to terminate connection to Replicate
					resp.CloseBodyStream()
					return

				case "error":
					errorMsg := "prediction failed"
					if doneData.Output != nil {
						errorMsg = fmt.Sprintf("prediction failed: %v", doneData.Output)
					}
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						errorMsg,
						fmt.Errorf("stream ended with error"),
						provider.GetProviderKey(),
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       provider.GetProviderKey(),
						ModelRequested: request.Model,
						RequestType:    schemas.TextCompletionStreamRequest,
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					enrichedErr := providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
					// Explicitly close the body stream to terminate connection to Replicate
					resp.CloseBodyStream()
					return
				}

				// Send final chunk with finish reason
				finishReason := schemas.Ptr("stop")
				finalResponse := providerUtils.CreateDeepIntShieldTextCompletionChunkResponse(
					messageID,
					nil, // usage - not available in done event
					finishReason,
					chunkIndex,
					schemas.TextCompletionStreamRequest,
					provider.GetProviderKey(),
					request.Model,
				)

				// Set raw request if enabled
				if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
					providerUtils.ParseAndSetRawRequest(&finalResponse.ExtraFields, jsonData)
				}

				finalResponse.ExtraFields.Latency = time.Since(startTime).Milliseconds()

				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(finalResponse, nil, nil, nil, nil, nil),
					responseChan)
				resp.CloseBodyStream()
				return
			}
		}
	}()

	return responseChan, nil
}

// ChatCompletion performs a chat completion request to the replicate API.
func (provider *ReplicateProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ChatCompletionRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// build replicate request
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) { return ToReplicateChatRequest(request) },
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Check for Prefer: wait header from context for sync mode
	isSync := parsePreferHeader(provider.networkConfig.ExtraHeaders)

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ChatCompletionRequest,
		isDeployment,
	)

	// create prediction
	prediction, rawResponse, latency, providerResponseHeaders, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		false,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// if not sync, poll until done
	if !isSync && !isTerminalStatus(prediction.Status) {
		prediction, rawResponse, providerResponseHeaders, err = pollPrediction(
			ctx,
			provider.client,
			prediction.URLs.Get,
			key,
			provider.networkConfig.DefaultRequestTimeoutInSeconds,
			provider.logger,
			providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		)
		if err != nil {
			return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
	}

	// Check for terminal error status (failed/canceled) after sync mode or polling
	if err := checkForErrorStatus(prediction); err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}

	// Convert to DeepIntShield response
	deepintshieldResponse := prediction.ToDeepIntShieldChatResponse()

	// Set extra fields
	deepintshieldResponse.ExtraFields.Provider = schemas.Replicate
	deepintshieldResponse.ExtraFields.RequestType = schemas.ChatCompletionRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&deepintshieldResponse.ExtraFields, jsonData)
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// ChatCompletionStream performs a streaming chat completion request to the replicate API.
// It supports real-time streaming of responses using Server-Sent Events (SSE).
// Returns a channel containing DeepIntShieldResponse objects representing the stream or an error if the request fails.
func (provider *ReplicateProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ChatCompletionStreamRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Convert DeepIntShield request to Replicate format with streaming enabled
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			replicateReq, err := ToReplicateChatRequest(request)
			if err != nil {
				return nil, err
			}
			replicateReq.Stream = schemas.Ptr(true)
			return replicateReq, nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ChatCompletionStreamRequest,
		isDeployment,
	)

	// Create prediction
	prediction, _, _, _, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		true,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Verify stream URL is available
	if prediction.URLs == nil || prediction.URLs.Stream == nil || *prediction.URLs.Stream == "" {
		deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
			"stream URL not available in prediction response",
			fmt.Errorf("prediction response missing stream URL"),
			provider.GetProviderKey(),
		)
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	streamURL := *prediction.URLs.Stream

	// Connect to stream URL
	_, resp, deepintshieldErr := listenToReplicateStreamURL(ctx, provider.client, streamURL, key)
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Store provider response headers in context for transport layer
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

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
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, provider.GetProviderKey(), request.Model, schemas.ChatCompletionStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, provider.GetProviderKey(), request.Model, schemas.ChatCompletionStreamRequest, provider.logger)
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

		startTime := time.Now()
		lastChunkTime := startTime
		chunkIndex := 0

		// Setup SSE event reader for event+data format
		sseReader := providerUtils.GetSSEEventReader(ctx, reader)

		messageID := prediction.ID

		for {
			// Check for context cancellation
			select {
			case <-ctx.Done():
				return
			default:
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
					enrichedErr := providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, readErr, provider.GetProviderKey()), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
				}
				break
			}

			eventData := string(eventDataBytes)
			if eventType == "" && eventData == "" {
				continue
			}

			// Process the complete event
			switch eventType {
			case "output":
				// Accumulate content from data field
				if eventData != "" {
					// Create a streaming chunk
					content := eventData
					role := string(schemas.ChatMessageRoleAssistant)
					delta := &schemas.ChatStreamResponseChoiceDelta{
						Content: &content,
						Role:    &role,
					}

					response := &schemas.DeepIntShieldChatResponse{
						ID:      messageID,
						Model:   request.Model,
						Object:  "chat.completion.chunk",
						Created: int(time.Now().Unix()),
						Choices: []schemas.DeepIntShieldResponseChoice{
							{
								Index: 0,
								ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
									Delta: delta,
								},
							},
						},
						ExtraFields: schemas.DeepIntShieldResponseExtraFields{
							RequestType:    schemas.ChatCompletionStreamRequest,
							Provider:       provider.GetProviderKey(),
							ModelRequested: request.Model,
							ChunkIndex:     chunkIndex,
							Latency:        time.Since(lastChunkTime).Milliseconds(),
						},
					}

					// Set raw response if enabled (per-chunk event as JSON string)
					if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
						rawEvent := ReplicateSSEEvent{Event: eventType, Data: eventData}
						if eventJSON, err := sonic.Marshal(rawEvent); err == nil {
							response.ExtraFields.RawResponse = string(eventJSON)
						}
					}

					lastChunkTime = time.Now()
					chunkIndex++

					providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
						providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, response, nil, nil, nil, nil),
						responseChan)
				}

			case "done":
				// Parse done event data
				var doneData ReplicateDoneEvent
				if eventData != "" && eventData != "{}" {
					if err := sonic.Unmarshal(eventDataBytes, &doneData); err != nil {
						provider.logger.Warn(fmt.Sprintf("Failed to parse done event data: %v", err))
					}
				}

				// Check for cancellation or error
				switch doneData.Reason {
				case "canceled":
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"prediction was canceled",
						fmt.Errorf("stream ended: prediction canceled"),
						provider.GetProviderKey(),
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       provider.GetProviderKey(),
						ModelRequested: request.Model,
						RequestType:    schemas.ChatCompletionStreamRequest,
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					enrichedErr := providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
					// Explicitly close the body stream to terminate connection to Replicate
					resp.CloseBodyStream()
					return

				case "error":
					errorMsg := "prediction failed"
					if doneData.Output != nil {
						errorMsg = fmt.Sprintf("prediction failed: %v", doneData.Output)
					}
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						errorMsg,
						fmt.Errorf("stream ended with error"),
						provider.GetProviderKey(),
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       provider.GetProviderKey(),
						ModelRequested: request.Model,
						RequestType:    schemas.ChatCompletionStreamRequest,
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					enrichedErr := providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
					// Explicitly close the body stream to terminate connection to Replicate
					resp.CloseBodyStream()
					return
				}

				// Send final chunk with finish reason
				finishReason := "stop"
				finalResponse := &schemas.DeepIntShieldChatResponse{
					ID:      messageID,
					Model:   request.Model,
					Object:  "chat.completion.chunk",
					Created: int(time.Now().Unix()),
					Choices: []schemas.DeepIntShieldResponseChoice{
						{
							Index:        0,
							FinishReason: &finishReason,
							ChatStreamResponseChoice: &schemas.ChatStreamResponseChoice{
								Delta: &schemas.ChatStreamResponseChoiceDelta{},
							},
						},
					},
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ChatCompletionStreamRequest,
						Provider:       provider.GetProviderKey(),
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(startTime).Milliseconds(),
					},
				}

				// Set raw request if enabled
				if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
					providerUtils.ParseAndSetRawRequest(&finalResponse.ExtraFields, jsonData)
				}

				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, finalResponse, nil, nil, nil, nil),
					responseChan)
				resp.CloseBodyStream()
				return
			}
		}
	}()

	return responseChan, nil
}

// Responses performs a responses request to the replicate API.
func (provider *ReplicateProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ResponsesRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// build replicate request
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) { return ToReplicateResponsesRequest(request) },
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Check for Prefer: wait header from context for sync mode
	isSync := parsePreferHeader(provider.networkConfig.ExtraHeaders)

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ResponsesRequest,
		isDeployment,
	)

	// create prediction
	prediction, rawResponse, latency, providerResponseHeaders, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		false,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// if not sync, poll until done
	if !isSync && !isTerminalStatus(prediction.Status) {
		prediction, rawResponse, providerResponseHeaders, err = pollPrediction(
			ctx,
			provider.client,
			prediction.URLs.Get,
			key,
			provider.networkConfig.DefaultRequestTimeoutInSeconds,
			provider.logger,
			providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		)
		if err != nil {
			return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
	}

	// Check for terminal error status (failed/canceled) after sync mode or polling
	if err := checkForErrorStatus(prediction); err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}

	// Convert to DeepIntShield response
	response := prediction.ToDeepIntShieldResponsesResponse()
	response.ExtraFields.RequestType = schemas.ResponsesRequest
	response.ExtraFields.Provider = provider.GetProviderKey()
	response.ExtraFields.ModelRequested = request.Model
	response.ExtraFields.Latency = latency.Milliseconds()
	response.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&response.ExtraFields, jsonData)
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		response.ExtraFields.RawResponse = rawResponse
	}
	return response, nil
}

// ResponsesStream performs a streaming responses request to the replicate API.
func (provider *ReplicateProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ResponsesStreamRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Build replicate request
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) { return ToReplicateResponsesRequest(request) },
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Enable streaming
	var replicateReq ReplicatePredictionRequest
	if err := sonic.Unmarshal(jsonData, &replicateReq); err == nil {
		replicateReq.Stream = schemas.Ptr(true)
		var streamErr error
		jsonData, streamErr = sonic.Marshal(replicateReq)
		if streamErr != nil {
			return nil, providerUtils.NewDeepIntShieldOperationError("failed to marshal request", streamErr, provider.GetProviderKey())
		}
	}

	// Build prediction URL
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ResponsesStreamRequest,
		isDeployment,
	)

	// Create prediction
	prediction, _, _, _, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		true, // Streaming request, strip Prefer header for async mode
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Verify stream URL is available
	if prediction.URLs == nil || prediction.URLs.Stream == nil || *prediction.URLs.Stream == "" {
		deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
			"stream URL not available in prediction response",
			fmt.Errorf("prediction response missing stream URL"),
			provider.GetProviderKey(),
		)
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	streamURL := *prediction.URLs.Stream

	// Setup request for streaming
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	resp.StreamBody = true
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(http.MethodGet)
	req.SetRequestURI(streamURL)
	req.Header.Set("Accept", "text/event-stream")

	// Set authorization
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	// Set extra headers
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Make the streaming request
	streamErr := providerUtils.ClientFromContext(ctx, provider.client).Do(req, resp)
	if streamErr != nil {
		defer providerUtils.ReleaseStreamingResponse(resp)
		if errors.Is(streamErr, context.Canceled) {
			return nil, providerUtils.EnrichError(ctx, &schemas.DeepIntShieldError{
				IsDeepIntShieldError: false,
				Error: &schemas.ErrorField{
					Type:    schemas.Ptr(schemas.RequestCancelled),
					Message: schemas.ErrRequestCancelled,
					Error:   streamErr,
				},
			}, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
		if errors.Is(streamErr, fasthttp.ErrTimeout) || errors.Is(streamErr, context.DeadlineExceeded) {
			return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderRequestTimedOut, streamErr, provider.GetProviderKey()), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, streamErr, provider.GetProviderKey()), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Extract provider response headers before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		body := resp.Body()
		return nil, providerUtils.EnrichError(ctx, parseReplicateError(body, resp.StatusCode()), jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
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
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, provider.GetProviderKey(), request.Model, schemas.ResponsesStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, provider.GetProviderKey(), request.Model, schemas.ResponsesStreamRequest, provider.logger)
			}
			close(responseChan)
		}()
		defer providerUtils.ReleaseStreamingResponse(resp)

		// Decompress gzip-encoded streams transparently (no-op for non-gzip)
		reader, releaseGzip := providerUtils.DecompressStreamBody(resp)
		defer releaseGzip()

		if reader == nil {
			deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
				"Provider returned an empty response",
				fmt.Errorf("provider returned an empty response"),
				provider.GetProviderKey(),
			)
			ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
			providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse), responseChan, provider.logger)
			return
		}

		// Wrap reader with idle timeout to detect stalled streams.
		reader, stopIdleTimeout := providerUtils.NewIdleTimeoutReader(reader, resp.BodyStream(), providerUtils.GetStreamIdleTimeout(ctx))
		defer stopIdleTimeout()

		// Setup cancellation handler to close the raw network stream on ctx cancellation,
		// which immediately unblocks any in-progress read (including reads blocked inside a gzip decompression layer).
		stopCancellation := providerUtils.SetupStreamCancellation(ctx, resp.BodyStream(), provider.logger)
		defer stopCancellation()

		sseReader := providerUtils.GetSSEEventReader(ctx, reader)
		startTime := time.Now()
		sequenceNumber := 0
		messageID := prediction.ID
		// Generate a unique item ID for the message (needed for accumulator to track deltas)
		itemID := "msg_" + messageID

		// Track lifecycle state
		var hasEmittedCreated, hasEmittedInProgress bool
		var hasEmittedOutputItemAdded, hasEmittedContentPartAdded bool
		var hasReceivedContent bool
		outputIndex := 0
		contentIndex := 0

		// Accumulate raw responses for debugging
		var rawResponseChunks []interface{}
		sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
		sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)

		for {
			if ctx.Err() != nil {
				return
			}

			eventType, eventDataBytes, readErr := sseReader.ReadEvent()
			if readErr != nil {
				if readErr != io.EOF {
					if ctx.Err() != nil {
						return
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					provider.logger.Warn("Error reading stream: %v", readErr)
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderDoRequest, readErr, provider.GetProviderKey())

					// Include accumulated raw responses in error
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
					}

					enrichedErr := providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, sendBackRawRequest, sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
					return
				}
				break
			}

			currentEvent := ReplicateSSEEvent{
				Event: eventType,
				Data:  string(eventDataBytes),
			}

			if currentEvent.Event != "" {
				// Process the event
				switch currentEvent.Event {
				case "output":
					// Text chunk received
					if currentEvent.Data != "" {
						// Accumulate raw response if enabled
						if sendBackRawResponse {
							rawResponseChunks = append(rawResponseChunks, currentEvent)
						}

						// Emit lifecycle events on first content
						if !hasEmittedCreated {
							// response.created
							createdResp := &schemas.DeepIntShieldResponsesStreamResponse{
								Type:           schemas.ResponsesStreamResponseTypeCreated,
								SequenceNumber: sequenceNumber,
								Response: &schemas.DeepIntShieldResponsesResponse{
									ID:        schemas.Ptr(messageID),
									Model:     request.Model,
									CreatedAt: int(startTime.Unix()),
								},
								ExtraFields: schemas.DeepIntShieldResponseExtraFields{
									RequestType:    schemas.ResponsesStreamRequest,
									Provider:       provider.GetProviderKey(),
									ModelRequested: request.Model,
									Latency:        time.Since(startTime).Milliseconds(),
									ChunkIndex:     sequenceNumber,
								},
							}
							if sendBackRawRequest {
								providerUtils.ParseAndSetRawRequest(&createdResp.ExtraFields, jsonData)
							}
							providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
								providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, createdResp, nil, nil, nil),
								responseChan)
							sequenceNumber++
							hasEmittedCreated = true
						}

						if !hasEmittedInProgress {
							// response.in_progress
							inProgressResp := &schemas.DeepIntShieldResponsesStreamResponse{
								Type:           schemas.ResponsesStreamResponseTypeInProgress,
								SequenceNumber: sequenceNumber,
								Response: &schemas.DeepIntShieldResponsesResponse{
									ID:        schemas.Ptr(messageID),
									CreatedAt: int(startTime.Unix()),
								},
								ExtraFields: schemas.DeepIntShieldResponseExtraFields{
									RequestType:    schemas.ResponsesStreamRequest,
									Provider:       provider.GetProviderKey(),
									ModelRequested: request.Model,
									ChunkIndex:     sequenceNumber,
								},
							}
							providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
								providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, inProgressResp, nil, nil, nil),
								responseChan)
							sequenceNumber++
							hasEmittedInProgress = true
						}

						if !hasEmittedOutputItemAdded {
							// response.output_item.added
							messageType := schemas.ResponsesMessageTypeMessage
							role := schemas.ResponsesInputMessageRoleAssistant
							status := "in_progress"
							itemAddedResp := &schemas.DeepIntShieldResponsesStreamResponse{
								Type:           schemas.ResponsesStreamResponseTypeOutputItemAdded,
								SequenceNumber: sequenceNumber,
								OutputIndex:    schemas.Ptr(outputIndex),
								Item: &schemas.ResponsesMessage{
									ID:     schemas.Ptr(itemID),
									Type:   &messageType,
									Role:   &role,
									Status: &status,
									Content: &schemas.ResponsesMessageContent{
										ContentBlocks: []schemas.ResponsesMessageContentBlock{},
									},
								},
								ExtraFields: schemas.DeepIntShieldResponseExtraFields{
									RequestType:    schemas.ResponsesStreamRequest,
									Provider:       provider.GetProviderKey(),
									ModelRequested: request.Model,
									ChunkIndex:     sequenceNumber,
								},
							}
							providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
								providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, itemAddedResp, nil, nil, nil),
								responseChan)
							sequenceNumber++
							hasEmittedOutputItemAdded = true
						}

						if !hasEmittedContentPartAdded {
							// response.content_part.added
							emptyText := ""
							partAddedResp := &schemas.DeepIntShieldResponsesStreamResponse{
								Type:           schemas.ResponsesStreamResponseTypeContentPartAdded,
								SequenceNumber: sequenceNumber,
								OutputIndex:    schemas.Ptr(outputIndex),
								ContentIndex:   schemas.Ptr(contentIndex),
								ItemID:         schemas.Ptr(itemID),
								Part: &schemas.ResponsesMessageContentBlock{
									Type: schemas.ResponsesOutputMessageContentTypeText,
									Text: &emptyText,
									ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
										Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
										LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
									},
								},
								ExtraFields: schemas.DeepIntShieldResponseExtraFields{
									RequestType:    schemas.ResponsesStreamRequest,
									Provider:       provider.GetProviderKey(),
									ModelRequested: request.Model,
									ChunkIndex:     sequenceNumber,
								},
							}
							providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
								providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, partAddedResp, nil, nil, nil),
								responseChan)
							sequenceNumber++
							hasEmittedContentPartAdded = true
						}

						// response.output_text.delta
						deltaResp := &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeOutputTextDelta,
							SequenceNumber: sequenceNumber,
							OutputIndex:    schemas.Ptr(outputIndex),
							ContentIndex:   schemas.Ptr(contentIndex),
							ItemID:         schemas.Ptr(itemID),
							Delta:          schemas.Ptr(currentEvent.Data),
							LogProbs:       []schemas.ResponsesOutputMessageContentTextLogProb{},
							ExtraFields: schemas.DeepIntShieldResponseExtraFields{
								RequestType:    schemas.ResponsesStreamRequest,
								Provider:       provider.GetProviderKey(),
								ModelRequested: request.Model,
								ChunkIndex:     sequenceNumber,
							},
						}
						providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
							providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, deltaResp, nil, nil, nil),
							responseChan)
						sequenceNumber++
						hasReceivedContent = true
					}
				case "done":
					// Accumulate done event in raw responses if enabled
					if sendBackRawResponse {
						rawResponseChunks = append(rawResponseChunks, currentEvent)
					}

					// Stream completed
					if hasReceivedContent {
						// response.output_text.done
						textDoneResp := &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeOutputTextDone,
							SequenceNumber: sequenceNumber,
							OutputIndex:    schemas.Ptr(outputIndex),
							ContentIndex:   schemas.Ptr(contentIndex),
							ItemID:         schemas.Ptr(itemID),
							LogProbs:       []schemas.ResponsesOutputMessageContentTextLogProb{},
							ExtraFields: schemas.DeepIntShieldResponseExtraFields{
								RequestType:    schemas.ResponsesStreamRequest,
								Provider:       provider.GetProviderKey(),
								ModelRequested: request.Model,
								ChunkIndex:     sequenceNumber,
							},
						}
						providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
							providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, textDoneResp, nil, nil, nil),
							responseChan)
						sequenceNumber++

						// response.content_part.done
						partDoneResp := &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
							SequenceNumber: sequenceNumber,
							OutputIndex:    schemas.Ptr(outputIndex),
							ContentIndex:   schemas.Ptr(contentIndex),
							ItemID:         schemas.Ptr(itemID),
							Part: &schemas.ResponsesMessageContentBlock{
								Type: schemas.ResponsesOutputMessageContentTypeText,
								ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
									Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
									LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
								},
							},
							ExtraFields: schemas.DeepIntShieldResponseExtraFields{
								RequestType:    schemas.ResponsesStreamRequest,
								Provider:       provider.GetProviderKey(),
								ModelRequested: request.Model,
								ChunkIndex:     sequenceNumber,
							},
						}
						providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
							providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, partDoneResp, nil, nil, nil),
							responseChan)
						sequenceNumber++

						// response.output_item.done
						messageType := schemas.ResponsesMessageTypeMessage
						role := schemas.ResponsesInputMessageRoleAssistant
						status := "completed"
						itemDoneResp := &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
							SequenceNumber: sequenceNumber,
							OutputIndex:    schemas.Ptr(outputIndex),
							Item: &schemas.ResponsesMessage{
								ID:     schemas.Ptr(itemID),
								Type:   &messageType,
								Role:   &role,
								Status: &status,
								Content: &schemas.ResponsesMessageContent{
									ContentBlocks: []schemas.ResponsesMessageContentBlock{
										{
											Type: schemas.ResponsesOutputMessageContentTypeText,
											ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
												Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
												LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
											},
										},
									},
								},
							},
							ExtraFields: schemas.DeepIntShieldResponseExtraFields{
								RequestType:    schemas.ResponsesStreamRequest,
								Provider:       provider.GetProviderKey(),
								ModelRequested: request.Model,
								ChunkIndex:     sequenceNumber,
							},
						}
						providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
							providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, itemDoneResp, nil, nil, nil),
							responseChan)
						sequenceNumber++
					}

					// response.completed
					completedResp := &schemas.DeepIntShieldResponsesStreamResponse{
						Type:           schemas.ResponsesStreamResponseTypeCompleted,
						SequenceNumber: sequenceNumber,
						Response: &schemas.DeepIntShieldResponsesResponse{
							ID:          schemas.Ptr(messageID),
							Model:       request.Model,
							CreatedAt:   int(startTime.Unix()),
							CompletedAt: schemas.Ptr(int(time.Now().Unix())),
						},
						ExtraFields: schemas.DeepIntShieldResponseExtraFields{
							RequestType:    schemas.ResponsesStreamRequest,
							Provider:       provider.GetProviderKey(),
							ModelRequested: request.Model,
							Latency:        time.Since(startTime).Milliseconds(),
							ChunkIndex:     sequenceNumber,
						},
					}

					// Set raw request if enabled (on final chunk only)
					if sendBackRawRequest {
						providerUtils.ParseAndSetRawRequest(&completedResp.ExtraFields, jsonData)
					}

					// Set raw response if enabled
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						completedResp.ExtraFields.RawResponse = rawResponseChunks
					}

					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
						providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, completedResp, nil, nil, nil),
						responseChan)
					resp.CloseBodyStream()
					return
				case "error":
					// Accumulate error event in raw responses if enabled
					if sendBackRawResponse {
						rawResponseChunks = append(rawResponseChunks, currentEvent)
					}

					// Handle error
					errorMsg := "stream error"
					if currentEvent.Data != "" {
						errorMsg = currentEvent.Data
					}
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						errorMsg,
						fmt.Errorf("stream error: %s", errorMsg),
						provider.GetProviderKey(),
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       provider.GetProviderKey(),
						ModelRequested: request.Model,
						RequestType:    schemas.ResponsesStreamRequest,
					}

					// Include accumulated raw responses in error
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
					}

					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					enrichedErr := providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, nil, sendBackRawRequest, sendBackRawResponse)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, enrichedErr, responseChan, provider.logger)
					resp.CloseBodyStream()
					return
				}
			}
		}
	}()

	return responseChan, nil
}

// Embedding is not supported by the replicate provider.
func (provider *ReplicateProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.EmbeddingRequest, provider.GetProviderKey())
}

// Speech is not supported by the replicate provider.
func (provider *ReplicateProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechRequest, provider.GetProviderKey())
}

// Rerank is not supported by the Replicate provider.
func (provider *ReplicateProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

// SpeechStream is not supported by the replicate provider.
func (provider *ReplicateProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

// Transcription is not supported by the replicate provider.
func (provider *ReplicateProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionRequest, provider.GetProviderKey())
}

// TranscriptionStream is not supported by the replicate provider.
func (provider *ReplicateProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

// ImageGeneration performs an image generation request to the replicate API using predictions.
func (provider *ReplicateProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ImageGenerationRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Convert DeepIntShield request to Replicate format
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToReplicateImageGenerationInput(request), nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Check for Prefer: wait header from context for sync mode
	isSync := parsePreferHeader(provider.networkConfig.ExtraHeaders)

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ImageGenerationRequest,
		isDeployment,
	)

	// Create prediction with appropriate mode
	prediction, rawResponse, latency, providerResponseHeaders, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		false,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// If async mode and not complete, poll until done
	if !isSync && !isTerminalStatus(prediction.Status) {
		prediction, rawResponse, providerResponseHeaders, err = pollPrediction(
			ctx,
			provider.client,
			prediction.URLs.Get,
			key,
			provider.networkConfig.DefaultRequestTimeoutInSeconds,
			provider.logger,
			providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		)
		if err != nil {
			return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
	}

	// Check for terminal error status (failed/canceled) after sync mode or polling
	if err := checkForErrorStatus(prediction); err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}

	// Convert to DeepIntShield response
	deepintshieldResponse, err := ToDeepIntShieldImageGenerationResponse(prediction)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Set extra fields
	deepintshieldResponse.ExtraFields.Provider = schemas.Replicate
	deepintshieldResponse.ExtraFields.RequestType = schemas.ImageGenerationRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&deepintshieldResponse.ExtraFields, jsonData)
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// ImageGenerationStream performs a streaming image generation request to the replicate API.
// It creates a prediction with streaming enabled and listens to the stream URL for progressive updates.
func (provider *ReplicateProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ImageGenerationStreamRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Convert DeepIntShield request to Replicate format with streaming enabled
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			replicateReq := ToReplicateImageGenerationInput(request)
			replicateReq.Stream = schemas.Ptr(true)
			return replicateReq, nil
		},
		providerName)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ImageGenerationStreamRequest,
		isDeployment,
	)
	// Create prediction
	prediction, _, _, _, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		true, // Streaming request, strip Prefer header for async mode
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Verify stream URL is available
	if prediction.URLs == nil || prediction.URLs.Stream == nil || *prediction.URLs.Stream == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			"stream URL not available in prediction response",
			fmt.Errorf("prediction response missing stream URL"),
			providerName,
		)
	}

	streamURL := *prediction.URLs.Stream

	// Connect to stream URL
	_, resp, deepintshieldErr := listenToReplicateStreamURL(ctx, provider.client, streamURL, key)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Store provider response headers in context for transport layer
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

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
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ImageGenerationStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ImageGenerationStreamRequest, provider.logger)
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

		startTime := time.Now()
		lastChunkTime := startTime
		chunkIndex := 0

		// Setup SSE event reader for event+data format
		sseReader := providerUtils.GetSSEEventReader(ctx, reader)

		// Track last image data for final chunk
		var lastB64Data string
		var lastOutputFormat string
		// Accumulate all raw response chunks for complete stream history
		var rawResponseChunks []interface{}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			eventType, eventDataBytes, readErr := sseReader.ReadEvent()
			if readErr != nil {
				if readErr != io.EOF {
					if ctx.Err() != nil {
						return
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					provider.logger.Warn(fmt.Sprintf("Error reading SSE stream: %v", readErr))
					providerUtils.ProcessAndSendError(ctx, postHookRunner, readErr, responseChan, schemas.ImageGenerationStreamRequest, providerName, request.Model, provider.logger)
				}
				break
			}

			eventData := string(eventDataBytes)
			if eventType == "" && eventData == "" {
				continue
			}

			// Process the complete event
			switch eventType {
			case "output":
				// Check if data is a data URI (image) or plain text
				var b64Data, outputFormat string
				if strings.HasPrefix(eventData, "data:") {
					// Parse image data from data URI
					var mimeType string
					b64Data, mimeType = parseDataURIImage(eventData)

					// Extract output format from MIME type
					if mimeType != "" {
						// Convert "image/webp" to "webp"
						parts := strings.Split(mimeType, "/")
						if len(parts) == 2 {
							outputFormat = parts[1]
						}
					}
				} else {
					// For non-data-URI output (e.g., text), store as-is
					// This shouldn't happen for image generation but handle it gracefully
					provider.logger.Debug(fmt.Sprintf("Received non-data-URI output: %s", eventData[:min(100, len(eventData))]))
					// Skip non-image output for image generation
					continue
				}

				// Create chunk
				chunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
					Type:         schemas.ImageGenerationEventTypePartial,
					Index:        0, // Single image for now
					ChunkIndex:   chunkIndex,
					B64JSON:      b64Data,
					CreatedAt:    time.Now().Unix(),
					OutputFormat: outputFormat,
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ImageGenerationStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(lastChunkTime).Milliseconds(),
					},
				}

				// Accumulate raw response chunks if enabled
				if sendBackRawResponse {
					rawResponseChunks = append(rawResponseChunks, ReplicateSSEEvent{Event: eventType, Data: eventData})
				}

				// Track last image data for final chunk
				lastB64Data = b64Data
				lastOutputFormat = outputFormat

				lastChunkTime = time.Now()
				chunkIndex++

				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, chunk),
					responseChan)

			case "done":
				// Parse done event data
				var doneData ReplicateDoneEvent
				if eventData != "" && eventData != "{}" {
					if err := sonic.Unmarshal(eventDataBytes, &doneData); err != nil {
						provider.logger.Warn(fmt.Sprintf("Failed to parse done event data: %v", err))
					}
				}

				// Check for cancellation or error
				switch doneData.Reason {
				case "canceled":
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"prediction was canceled",
						fmt.Errorf("stream ended: prediction canceled"),
						providerName,
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageGenerationStreamRequest,
					}
					// Include accumulated raw responses in error
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
					return
				case "error":
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"prediction failed",
						fmt.Errorf("stream ended with error"),
						providerName,
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageGenerationStreamRequest,
					}
					// Include accumulated raw responses in error
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
					return
				}

				// Send completion chunk (success case when reason is empty or not present)
				finalChunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
					Type:         schemas.ImageGenerationEventTypeCompleted,
					Index:        0,
					ChunkIndex:   chunkIndex,
					B64JSON:      lastB64Data,      // Include last image data
					OutputFormat: lastOutputFormat, // Include output format
					CreatedAt:    time.Now().Unix(),
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ImageGenerationStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(startTime).Milliseconds(),
					},
				}

				// Set raw request only on final chunk if enabled
				if sendBackRawRequest {
					providerUtils.ParseAndSetRawRequest(&finalChunk.ExtraFields, jsonData)
				}

				// Set accumulated raw responses on final chunk if enabled
				if sendBackRawResponse {
					// Append the final done event to the accumulated chunks
					rawResponseChunks = append(rawResponseChunks, ReplicateSSEEvent{Event: eventType, Data: eventData})
					finalChunk.ExtraFields.RawResponse = rawResponseChunks
				}

				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, finalChunk),
					responseChan)
				return

			case "error":
				// Parse error event data
				var errorData ReplicateErrorEvent
				errorMsg := "stream error"

				if eventData != "" {
					if err := sonic.Unmarshal(eventDataBytes, &errorData); err != nil {
						provider.logger.Warn(fmt.Sprintf("Failed to parse error event data: %v", err))
						// Fallback to raw data
						errorMsg = eventData
					} else if errorData.Detail != "" {
						errorMsg = errorData.Detail
					}
				}

				deepintshieldErr := &schemas.DeepIntShieldError{
					IsDeepIntShieldError: false,
					Error: &schemas.ErrorField{
						Message: errorMsg,
					},
					ExtraFields: schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageGenerationStreamRequest,
					},
				}
				// Include accumulated raw responses in error
				if sendBackRawResponse {
					rawResponseChunks = append(rawResponseChunks, ReplicateSSEEvent{Event: eventType, Data: eventData})
					deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
				}
				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
				return
			}
		}
	}()

	return responseChan, nil
}

// ImageEdit is not supported by the Replicate provider.
func (provider *ReplicateProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ImageEditRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Convert DeepIntShield request to Replicate format
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToReplicateImageEditInput(request), nil
		},
		provider.GetProviderKey())
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Check for Prefer: wait header from context for sync mode
	isSync := parsePreferHeader(provider.networkConfig.ExtraHeaders)

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ImageEditRequest,
		isDeployment,
	)

	// Create prediction with appropriate mode
	prediction, rawResponse, latency, providerResponseHeaders, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		false,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// If async mode and not complete, poll until done
	if !isSync && !isTerminalStatus(prediction.Status) {
		prediction, rawResponse, providerResponseHeaders, err = pollPrediction(
			ctx,
			provider.client,
			prediction.URLs.Get,
			key,
			provider.networkConfig.DefaultRequestTimeoutInSeconds,
			provider.logger,
			providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		)
		if err != nil {
			return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
	}

	// Check for terminal error status (failed/canceled) after sync mode or polling
	if err := checkForErrorStatus(prediction); err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}

	// Convert to DeepIntShield response (reuse image generation response format)
	deepintshieldResponse, err := ToDeepIntShieldImageGenerationResponse(prediction)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Set extra fields
	deepintshieldResponse.ExtraFields.Provider = schemas.Replicate
	deepintshieldResponse.ExtraFields.RequestType = schemas.ImageEditRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&deepintshieldResponse.ExtraFields, jsonData)
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// ImageEditStream performs a streaming image edit request to the replicate API.
// It creates a prediction with streaming enabled and listens to the stream URL for progressive updates.
func (provider *ReplicateProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.ImageEditStreamRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	// Convert DeepIntShield request to Replicate format with streaming enabled
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			replicateReq := ToReplicateImageEditInput(request)
			replicateReq.Stream = schemas.Ptr(true)
			return replicateReq, nil
		},
		providerName)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Build prediction URL based on model type (version ID or model name)
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.ImageEditStreamRequest,
		isDeployment,
	)

	// Create prediction
	prediction, _, _, _, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		true, // Streaming request, strip Prefer header for async mode
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Verify stream URL is available
	if prediction.URLs == nil || prediction.URLs.Stream == nil || *prediction.URLs.Stream == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			"stream URL not available in prediction response",
			fmt.Errorf("prediction response missing stream URL"),
			providerName,
		)
	}

	streamURL := *prediction.URLs.Stream

	// Connect to stream URL
	_, resp, deepintshieldErr := listenToReplicateStreamURL(ctx, provider.client, streamURL, key)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Store provider response headers in context for transport layer
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

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
				providerUtils.HandleStreamCancellation(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ImageEditStreamRequest, provider.logger)
			} else if ctx.Err() == context.DeadlineExceeded {
				providerUtils.HandleStreamTimeout(ctx, postHookRunner, responseChan, providerName, request.Model, schemas.ImageEditStreamRequest, provider.logger)
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

		startTime := time.Now()
		lastChunkTime := startTime
		chunkIndex := 0

		// Setup SSE event reader for event+data format
		sseReader := providerUtils.GetSSEEventReader(ctx, reader)

		// Track last image data for final chunk
		var lastB64Data string
		var lastOutputFormat string
		// Accumulate all raw response chunks for complete stream history
		var rawResponseChunks []interface{}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			eventType, eventDataBytes, readErr := sseReader.ReadEvent()
			if readErr != nil {
				if readErr != io.EOF {
					if errors.Is(readErr, context.Canceled) {
						return
					}
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"stream read error",
						readErr,
						providerName,
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageEditStreamRequest,
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
				}
				break
			}

			eventData := string(eventDataBytes)
			if eventType == "" && eventData == "" {
				continue
			}

			// Process the complete event
			switch eventType {
			case "output":
				// Check if data is a data URI (image) or plain text
				var b64Data, outputFormat string
				if strings.HasPrefix(eventData, "data:") {
					// Parse image data from data URI
					var mimeType string
					b64Data, mimeType = parseDataURIImage(eventData)

					// Extract output format from MIME type
					if mimeType != "" {
						// Convert "image/webp" to "webp"
						parts := strings.Split(mimeType, "/")
						if len(parts) == 2 {
							outputFormat = parts[1]
						}
					}
				} else {
					// For non-data-URI output, skip for image edit
					provider.logger.Debug(fmt.Sprintf("Received non-data-URI output: %s", eventData[:min(100, len(eventData))]))
					continue
				}

				// Create chunk (use ImageEditEventTypePartial)
				chunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
					Type:         schemas.ImageEditEventTypePartial,
					Index:        0,
					ChunkIndex:   chunkIndex,
					B64JSON:      b64Data,
					CreatedAt:    time.Now().Unix(),
					OutputFormat: outputFormat,
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ImageEditStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(lastChunkTime).Milliseconds(),
					},
				}

				// Accumulate raw response chunks if enabled
				if sendBackRawResponse {
					rawResponseChunks = append(rawResponseChunks, ReplicateSSEEvent{Event: eventType, Data: eventData})
				}

				// Track last image data for final chunk
				lastB64Data = b64Data
				lastOutputFormat = outputFormat

				lastChunkTime = time.Now()
				chunkIndex++

				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, chunk),
					responseChan)

			case "done":
				// Parse done event data
				var doneData ReplicateDoneEvent
				if eventData != "" && eventData != "{}" {
					if err := sonic.Unmarshal(eventDataBytes, &doneData); err != nil {
						provider.logger.Warn(fmt.Sprintf("Failed to parse done event data: %v", err))
					}
				}

				// Check for cancellation or error
				switch doneData.Reason {
				case "canceled":
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"prediction was canceled",
						fmt.Errorf("stream ended: prediction canceled"),
						providerName,
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageEditStreamRequest,
					}
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
					return
				case "error":
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						"prediction failed",
						fmt.Errorf("stream ended with error"),
						providerName,
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageEditStreamRequest,
					}
					if sendBackRawResponse && len(rawResponseChunks) > 0 {
						deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
					return
				}

				// Send completion chunk (success case)
				finalChunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
					Type:         schemas.ImageEditEventTypeCompleted,
					Index:        0,
					ChunkIndex:   chunkIndex,
					B64JSON:      lastB64Data,
					CreatedAt:    time.Now().Unix(),
					OutputFormat: lastOutputFormat,
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ImageEditStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(startTime).Milliseconds(),
					},
				}

				if sendBackRawRequest {
					providerUtils.ParseAndSetRawRequest(&finalChunk.ExtraFields, jsonData)
				}
				if sendBackRawResponse {
					rawResponseChunks = append(rawResponseChunks, ReplicateSSEEvent{Event: eventType, Data: eventData})
					finalChunk.ExtraFields.RawResponse = rawResponseChunks
				}

				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, finalChunk),
					responseChan)
				return

			case "error":
				// Parse error event
				var errorData ReplicateErrorEvent
				if err := sonic.Unmarshal(eventDataBytes, &errorData); err != nil {
					provider.logger.Warn(fmt.Sprintf("Failed to parse error event: %v", err))
					errorData.Detail = eventData
				}

				deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
					"stream error",
					fmt.Errorf("%s", errorData.Detail),
					providerName,
				)
				deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
					Provider:       providerName,
					ModelRequested: request.Model,
					RequestType:    schemas.ImageEditStreamRequest,
				}
				if sendBackRawResponse {
					rawResponseChunks = append(rawResponseChunks, ReplicateSSEEvent{Event: eventType, Data: eventData})
					deepintshieldErr.ExtraFields.RawResponse = rawResponseChunks
				}
				ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
				providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
				return
			}
		}
	}()

	return responseChan, nil
}

// ImageVariation is not supported by the Replicate provider.
func (provider *ReplicateProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration performs a video generation request to Replicate's API.
func (provider *ReplicateProvider) VideoGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.VideoGenerationRequest); err != nil {
		return nil, err
	}

	deployment, isDeployment := resolveDeploymentModel(request.Model, key)
	if isDeployment {
		request.Model = deployment
	}

	providerName := provider.GetProviderKey()

	// Convert DeepIntShield request to Replicate format
	jsonData, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToReplicateVideoGenerationInput(request)
		},
		providerName)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Create prediction asynchronously and return job ID without polling.
	predictionURL := buildPredictionURL(
		ctx,
		provider.networkConfig.BaseURL,
		request.Model,
		provider.customProviderConfig,
		schemas.VideoGenerationRequest,
		isDeployment,
	)

	// Create prediction with appropriate mode
	prediction, rawResponse, latency, providerResponseHeaders, err := createPrediction(
		ctx,
		provider.client,
		jsonData,
		key,
		providerUtils.GetPathFromContext(ctx, predictionURL),
		provider.networkConfig.ExtraHeaders,
		false,
		provider.logger,
		provider.sendBackRawRequest,
		provider.sendBackRawResponse,
	)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}

	// Convert to DeepIntShield response
	deepintshieldResponse, err := ToDeepIntShieldVideoGenerationResponse(prediction)
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}
	deepintshieldResponse.ID = providerUtils.AddVideoIDProviderSuffix(deepintshieldResponse.ID, providerName)

	// Set extra fields
	deepintshieldResponse.ExtraFields.Provider = providerName
	deepintshieldResponse.ExtraFields.RequestType = schemas.VideoGenerationRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		providerUtils.ParseAndSetRawRequest(&deepintshieldResponse.ExtraFields, jsonData)
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// VideoRetrieve fetches the status/output of a Replicate video generation job.
func (provider *ReplicateProvider) VideoRetrieve(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.VideoRetrieveRequest); err != nil {
		return nil, err
	}

	providerName := provider.GetProviderKey()
	if request.ID == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("video_id is required", nil, providerName)
	}

	videoID := providerUtils.StripVideoIDProviderSuffix(request.ID, providerName)
	// Build URL to fetch the prediction by ID.
	predictionURL := provider.buildRequestURL(ctx, "/v1/predictions/"+videoID, schemas.VideoRetrieveRequest)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)
	req.SetRequestURI(predictionURL)
	req.Header.SetMethod(http.MethodGet)
	req.Header.SetContentType("application/json")
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, providerUtils.EnrichError(
			ctx,
			parseReplicateError(resp.Body(), resp.StatusCode()),
			nil,
			nil,
			provider.sendBackRawRequest,
			provider.sendBackRawResponse,
		)
	}

	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)

	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}

	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	var prediction ReplicatePredictionResponse
	_, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &prediction, nil, false, sendBackRawResponse)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	deepintshieldResponse, convertErr := ToDeepIntShieldVideoGenerationResponse(&prediction)
	if convertErr != nil {
		return nil, providerUtils.EnrichError(ctx, convertErr, nil, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}
	deepintshieldResponse.ID = providerUtils.AddVideoIDProviderSuffix(deepintshieldResponse.ID, providerName)

	deepintshieldResponse.ExtraFields.Provider = providerName
	deepintshieldResponse.ExtraFields.RequestType = schemas.VideoRetrieveRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if sendBackRawResponse {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	return deepintshieldResponse, nil
}

// VideoDownload is not supported by the Replicate provider.
func (provider *ReplicateProvider) VideoDownload(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.Replicate, provider.customProviderConfig, schemas.VideoDownloadRequest); err != nil {
		return nil, err
	}
	providerName := provider.GetProviderKey()
	if request.ID == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("video_id is required", nil, providerName)
	}
	// Retrieve latest status/output first.
	deepintshieldVideoRetrieveRequest := &schemas.DeepIntShieldVideoRetrieveRequest{
		Provider: request.Provider,
		ID:       request.ID,
	}
	videoResp, deepintshieldErr := provider.VideoRetrieve(ctx, key, deepintshieldVideoRetrieveRequest)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}
	if videoResp.Status != schemas.VideoStatusCompleted {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			fmt.Sprintf("video not ready, current status: %s", videoResp.Status),
			nil,
			providerName,
		)
	}
	if len(videoResp.Videos) == 0 {
		return nil, providerUtils.NewDeepIntShieldOperationError("video URL not available", nil, providerName)
	}
	var videoUrl string
	if videoResp.Videos[0].URL != nil {
		videoUrl = *videoResp.Videos[0].URL
	}
	if videoUrl == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("invalid video output type", nil, providerName)
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(videoUrl)
	req.Header.SetMethod(http.MethodGet)
	// Some output URLs are signed and don't need auth, but keep auth if present.
	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}
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

	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)

	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}
	contentType := string(resp.Header.ContentType())
	if contentType == "" {
		contentType = "video/mp4"
	}
	content := append([]byte(nil), body...)
	deepintshieldResp := &schemas.DeepIntShieldVideoDownloadResponse{
		VideoID:     request.ID,
		Content:     content,
		ContentType: contentType,
	}

	deepintshieldResp.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResp.ExtraFields.Provider = providerName
	deepintshieldResp.ExtraFields.RequestType = schemas.VideoDownloadRequest
	deepintshieldResp.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	return deepintshieldResp, nil
}

// VideoDelete is not supported by replicate provider.
func (provider *ReplicateProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by replicate provider.
func (provider *ReplicateProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by replicate provider.
func (provider *ReplicateProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// BatchCreate is not supported by replicate provider.
func (provider *ReplicateProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by replicate provider.
func (provider *ReplicateProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by replicate provider.
func (provider *ReplicateProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by replicate provider.
func (provider *ReplicateProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by replicate provider.
func (provider *ReplicateProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by replicate provider.
func (provider *ReplicateProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// FileUpload uploads a file to Replicate's Files API.
func (provider *ReplicateProvider) FileUpload(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	if len(request.File) == 0 {
		return nil, providerUtils.NewDeepIntShieldOperationError("file content is required", nil, providerName)
	}

	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file field (content)
	filename := request.Filename
	if filename == "" {
		filename = "file"
	}

	// Determine content type - use from request or infer from filename
	contentType := "application/octet-stream"
	if request.ContentType != nil && *request.ContentType != "" {
		contentType = *request.ContentType
	} else {
		// Try to infer from filename extension
		if strings.HasSuffix(filename, ".json") {
			contentType = "application/json"
		} else if strings.HasSuffix(filename, ".jsonl") {
			contentType = "application/x-ndjson"
		} else if strings.HasSuffix(filename, ".txt") {
			contentType = "text/plain"
		} else if strings.HasSuffix(filename, ".zip") {
			contentType = "application/zip"
		}
	}

	// Create form file with proper headers
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="content"; filename="%s"`, filename))
	h.Set("Content-Type", contentType)

	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to create form file", err, providerName)
	}
	if _, err := part.Write(request.File); err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to write file content", err, providerName)
	}

	// Add filename field if provided
	if filename != "" {
		if err := writer.WriteField("filename", filename); err != nil {
			return nil, providerUtils.NewDeepIntShieldOperationError("failed to write filename field", err, providerName)
		}
	}

	// Add type field (content type)
	if err := writer.WriteField("type", contentType); err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to write type field", err, providerName)
	}

	// Add metadata field if provided
	if request.ExtraParams != nil {
		if metadata, ok := request.ExtraParams["metadata"].(map[string]interface{}); ok {
			if len(metadata) > 0 {
				metadataJSON, err := sonic.Marshal(metadata)
				if err != nil {
					return nil, providerUtils.NewDeepIntShieldOperationError("failed to marshal metadata", err, providerName)
				}
				h := make(textproto.MIMEHeader)
				h.Set("Content-Disposition", `form-data; name="metadata"`)
				h.Set("Content-Type", "application/json")
				metadataPart, err := writer.CreatePart(h)
				if err != nil {
					return nil, providerUtils.NewDeepIntShieldOperationError("failed to create metadata part", err, providerName)
				}
				if _, err := metadataPart.Write(metadataJSON); err != nil {
					return nil, providerUtils.NewDeepIntShieldOperationError("failed to write metadata", err, providerName)
				}
			}
		}
	}

	if err := writer.Close(); err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("failed to close multipart writer", err, providerName)
	}

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set headers
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)
	req.SetRequestURI(provider.networkConfig.BaseURL + "/v1/files")
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType(writer.FormDataContentType())

	if key.Value.GetValue() != "" {
		req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
	}

	req.SetBody(buf.Bytes())

	// Make request
	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK && resp.StatusCode() != fasthttp.StatusCreated {
		provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
		return nil, parseReplicateError(resp.Body(), resp.StatusCode())
	}

	body, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
	}

	var replicateResp ReplicateFileResponse
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &replicateResp, nil, sendBackRawRequest, sendBackRawResponse)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	fileResponse := replicateResp.ToDeepIntShieldFileUploadResponse(providerName, latency, sendBackRawRequest, sendBackRawResponse, rawRequest, rawResponse)
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
	fileResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	return fileResponse, nil
}

// FileList lists files using serial pagination across keys.
// Exhausts all pages from one key before moving to the next.
func (provider *ReplicateProvider) FileList(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)

	// Initialize serial pagination helper (Replicate uses cursor-based pagination)
	helper, err := providerUtils.NewSerialListHelper(keys, request.After, provider.logger)
	if err != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("invalid pagination cursor", err, providerName)
	}

	// Get current key to query
	key, nativeCursor, ok := helper.GetCurrentKey()
	if !ok {
		// All keys exhausted
		return &schemas.DeepIntShieldFileListResponse{
			Object:  "list",
			Data:    []schemas.FileObject{},
			HasMore: false,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				RequestType: schemas.FileListRequest,
				Provider:    providerName,
			},
		}, nil
	}

	// Create request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Build URL with query params
	requestURL := provider.networkConfig.BaseURL + "/v1/files"
	values := url.Values{}
	if request.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", request.Limit))
	}
	// Use native cursor from serial helper (Replicate pagination URL)
	if nativeCursor != "" {
		// For Replicate, the cursor is actually the full next URL
		requestURL = nativeCursor
	} else if encodedValues := values.Encode(); encodedValues != "" {
		requestURL += "?" + encodedValues
	}

	// Set headers
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)
	req.SetRequestURI(requestURL)
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
		provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
		return nil, parseReplicateError(resp.Body(), resp.StatusCode())
	}

	body, decodeErr := providerUtils.CheckAndDecodeBody(resp)
	if decodeErr != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, decodeErr, providerName)
	}

	var replicateResp ReplicateFileListResponse
	_, _, deepintshieldErr = providerUtils.HandleProviderResponse(body, &replicateResp, nil, sendBackRawRequest, sendBackRawResponse)
	if deepintshieldErr != nil {
		return nil, deepintshieldErr
	}

	// Convert files to DeepIntShield format
	files := make([]schemas.FileObject, 0, len(replicateResp.Results))
	for _, file := range replicateResp.Results {
		files = append(files, schemas.FileObject{
			ID:        file.ID,
			Object:    "file",
			Bytes:     file.Size,
			CreatedAt: ParseReplicateTimestamp(file.CreatedAt),
			Filename:  file.Name,
			Purpose:   schemas.FilePurposeBatch,
			Status:    ToDeepIntShieldFileStatus(&file),
		})
	}

	// Build cursor for next request
	// Replicate uses full URL for pagination
	var nextCursor string
	hasMore := false
	if replicateResp.Next != nil && *replicateResp.Next != "" {
		nextCursor = *replicateResp.Next
		hasMore = true
	}

	// Use helper to build proper cursor with key index
	finalCursor, finalHasMore := helper.BuildNextCursor(hasMore, nextCursor)

	// Convert to DeepIntShield response
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)

	deepintshieldResp := &schemas.DeepIntShieldFileListResponse{
		Object:  "list",
		Data:    files,
		HasMore: finalHasMore,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType:             schemas.FileListRequest,
			Provider:                providerName,
			Latency:                 latency.Milliseconds(),
			ProviderResponseHeaders: providerResponseHeaders,
		},
	}
	if finalCursor != "" {
		deepintshieldResp.After = &finalCursor
	}

	return deepintshieldResp, nil
}

// FileRetrieve retrieves file metadata from Replicate's Files API by trying each key until found.
func (provider *ReplicateProvider) FileRetrieve(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	if request.FileID == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("file_id is required", nil, providerName)
	}

	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)

	var lastErr *schemas.DeepIntShieldError
	for _, key := range keys {
		// Create request
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		// Set headers
		providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)
		req.SetRequestURI(provider.networkConfig.BaseURL + "/v1/files/" + url.PathEscape(request.FileID))
		req.Header.SetMethod(http.MethodGet)
		req.Header.SetContentType("application/json")

		if key.Value.GetValue() != "" {
			req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
		}

		// Make request
		latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
		wait()
		if deepintshieldErr != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			lastErr = deepintshieldErr
			continue
		}

		// Handle error response
		if resp.StatusCode() != fasthttp.StatusOK {
			provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
			lastErr = parseReplicateError(resp.Body(), resp.StatusCode())
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			continue
		}

		body, err := providerUtils.CheckAndDecodeBody(resp)
		if err != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			lastErr = providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
			continue
		}

		var replicateResp ReplicateFileResponse
		rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &replicateResp, nil, sendBackRawRequest, sendBackRawResponse)
		if deepintshieldErr != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			lastErr = deepintshieldErr
			continue
		}

		providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)

		fileRetrieveResponse := replicateResp.ToDeepIntShieldFileRetrieveResponse(providerName, latency, sendBackRawRequest, sendBackRawResponse, rawRequest, rawResponse)
		fileRetrieveResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
		return fileRetrieveResponse, nil
	}

	return nil, lastErr
}

// FileDelete deletes a file from Replicate's Files API by trying each key until successful.
func (provider *ReplicateProvider) FileDelete(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	if request.FileID == "" {
		return nil, providerUtils.NewDeepIntShieldOperationError("file_id is required", nil, providerName)
	}

	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)

	var lastErr *schemas.DeepIntShieldError
	for _, key := range keys {
		// Create request
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		// Set headers
		providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)
		req.SetRequestURI(provider.networkConfig.BaseURL + "/v1/files/" + url.PathEscape(request.FileID))
		req.Header.SetMethod(http.MethodDelete)
		req.Header.SetContentType("application/json")

		if key.Value.GetValue() != "" {
			req.Header.Set("Authorization", "Bearer "+key.Value.GetValue())
		}

		// Make request
		latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
		wait()
		if deepintshieldErr != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			lastErr = deepintshieldErr
			continue
		}

		// Handle success response (204 No Content is expected for DELETE)
		if resp.StatusCode() == fasthttp.StatusNoContent {
			providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
			return &schemas.DeepIntShieldFileDeleteResponse{
				ID:      request.FileID,
				Object:  "file",
				Deleted: true,
				ExtraFields: schemas.DeepIntShieldResponseExtraFields{
					RequestType:             schemas.FileDeleteRequest,
					Provider:                providerName,
					Latency:                 latency.Milliseconds(),
					ProviderResponseHeaders: providerResponseHeaders,
				},
			}, nil
		}

		// Handle error response
		if resp.StatusCode() != fasthttp.StatusOK {
			provider.logger.Debug("error from %s provider: %s", providerName, string(resp.Body()))
			lastErr = parseReplicateError(resp.Body(), resp.StatusCode())
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			continue
		}

		// Some APIs return 200 with body, parse it
		body, err := providerUtils.CheckAndDecodeBody(resp)
		if err != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			lastErr = providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
			continue
		}

		// Try to parse response body if present
		var deleteResp map[string]interface{}
		rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(body, &deleteResp, nil, sendBackRawRequest, sendBackRawResponse)
		if deepintshieldErr != nil {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			lastErr = deepintshieldErr
			continue
		}

		providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)

		result := &schemas.DeepIntShieldFileDeleteResponse{
			ID:      request.FileID,
			Object:  "file",
			Deleted: true,
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				RequestType:             schemas.FileDeleteRequest,
				Provider:                providerName,
				Latency:                 latency.Milliseconds(),
				ProviderResponseHeaders: providerResponseHeaders,
			},
		}

		if sendBackRawRequest {
			result.ExtraFields.RawRequest = rawRequest
		}

		if sendBackRawResponse {
			result.ExtraFields.RawResponse = rawResponse
		}

		return result, nil
	}

	return nil, lastErr
}

// FileContent is not supported by replicate provider.
func (provider *ReplicateProvider) FileContent(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

func (provider *ReplicateProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by replicate provider.
func (provider *ReplicateProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Replicate provider.
func (provider *ReplicateProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *ReplicateProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
