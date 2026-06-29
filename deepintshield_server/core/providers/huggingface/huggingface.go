package huggingface

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/providers/openai"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// HuggingFaceProvider implements the Provider interface for Hugging Face's inference APIs.
type HuggingFaceProvider struct {
	logger                    schemas.Logger
	client                    *fasthttp.Client
	networkConfig             schemas.NetworkConfig
	sendBackRawResponse       bool
	sendBackRawRequest        bool
	customProviderConfig      *schemas.CustomProviderConfig
	modelProviderMappingCache *sync.Map
}

var huggingFaceTranscriptionResponsePool = sync.Pool{
	New: func() any {
		return &HuggingFaceTranscriptionResponse{}
	},
}

var huggingFaceSpeechResponsePool = sync.Pool{
	New: func() any {
		return &HuggingFaceSpeechResponse{}
	},
}

func acquireHuggingFaceTranscriptionResponse() *HuggingFaceTranscriptionResponse {
	resp := huggingFaceTranscriptionResponsePool.Get().(*HuggingFaceTranscriptionResponse)
	*resp = HuggingFaceTranscriptionResponse{} // Reset the struct
	return resp
}

func releaseHuggingFaceTranscriptionResponse(resp *HuggingFaceTranscriptionResponse) {
	if resp != nil {
		huggingFaceTranscriptionResponsePool.Put(resp)
	}
}

func acquireHuggingFaceSpeechResponse() *HuggingFaceSpeechResponse {
	resp := huggingFaceSpeechResponsePool.Get().(*HuggingFaceSpeechResponse)
	*resp = HuggingFaceSpeechResponse{} // Reset the struct
	return resp
}

func releaseHuggingFaceSpeechResponse(resp *HuggingFaceSpeechResponse) {
	if resp != nil {
		huggingFaceSpeechResponsePool.Put(resp)
	}
}

// NewHuggingFaceProvider creates a new Hugging Face provider instance configured with the provided settings.
func NewHuggingFaceProvider(config *schemas.ProviderConfig, logger schemas.Logger) *HuggingFaceProvider {
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
	for i := 0; i < config.ConcurrencyAndBufferSize.Concurrency; i++ {
		huggingFaceSpeechResponsePool.Put(&HuggingFaceSpeechResponse{})
		huggingFaceTranscriptionResponsePool.Put(&HuggingFaceTranscriptionResponse{})
	}

	client = providerUtils.ConfigureProxy(client, config.ProxyConfig, logger)
	client = providerUtils.ConfigureDialer(client)
	client = providerUtils.ConfigureTLS(client, config.NetworkConfig, logger)
	if config.NetworkConfig.BaseURL == "" {
		config.NetworkConfig.BaseURL = defaultInferenceBaseURL
	}
	config.NetworkConfig.BaseURL = strings.TrimRight(config.NetworkConfig.BaseURL, "/")

	return &HuggingFaceProvider{
		logger:                    logger,
		client:                    client,
		networkConfig:             config.NetworkConfig,
		sendBackRawResponse:       config.SendBackRawResponse,
		sendBackRawRequest:        config.SendBackRawRequest,
		customProviderConfig:      config.CustomProviderConfig,
		modelProviderMappingCache: &sync.Map{},
	}
}

// GetProviderKey returns the provider key, taking custom providers into account.
func (provider *HuggingFaceProvider) GetProviderKey() schemas.ModelProvider {
	return providerUtils.GetProviderName(schemas.HuggingFace, provider.customProviderConfig)
}

// buildRequestURL composes the final request URL based on context overrides.
func (provider *HuggingFaceProvider) buildRequestURL(ctx *schemas.DeepIntShieldContext, defaultPath string, requestType schemas.RequestType) string {
	path, isCompleteURL := providerUtils.GetRequestPath(ctx, defaultPath, provider.customProviderConfig, requestType)
	if isCompleteURL {
		return path
	}
	return provider.networkConfig.BaseURL + path
}

// completeRequestWithModelAliasCache performs a request and retries once on 404 by clearing the cache and refetching model info
func (provider *HuggingFaceProvider) completeRequestWithModelAliasCache(
	ctx *schemas.DeepIntShieldContext,
	jsonData []byte,
	key string,
	isHFInferenceAudioRequest bool,
	isHFInferenceImageRequest bool,
	inferenceProvider inferenceProvider,
	originalModelName string,
	requiredTask string,
	requestType schemas.RequestType,
) ([]byte, time.Duration, map[string]string, *schemas.DeepIntShieldError) {

	// Build URL with original model name
	url, urlErr := provider.getInferenceProviderRouteURL(ctx, inferenceProvider, originalModelName, requestType)
	if urlErr != nil {
		return nil, 0, nil, providerUtils.NewUnsupportedOperationError(requestType, provider.GetProviderKey())
	}

	// For fal-ai, nebius, and together image generation, skip validation (model format is already correct)
	skipValidation := (inferenceProvider == falAI || inferenceProvider == nebius || inferenceProvider == together) && requestType == schemas.ImageGenerationRequest
	var modelName string
	var err *schemas.DeepIntShieldError
	if skipValidation {
		// Use original model name for validation skip case (though we won't use it for these providers)
		modelName = originalModelName
	} else {
		modelName, err = provider.getValidatedProviderModelID(ctx, inferenceProvider, originalModelName, requiredTask, requestType)
		if err != nil {
			return nil, 0, nil, err
		}
	}

	// Update the model field in the JSON body if it's not an audio request
	updatedJSONData := jsonData
	// Skip body modification for fal-ai, nebius, and together image generation - they have special requirements
	skipBodyModification := (inferenceProvider == falAI || inferenceProvider == nebius || inferenceProvider == together) && requestType == schemas.ImageGenerationRequest
	if !isHFInferenceAudioRequest && !skipBodyModification && (requestType == schemas.EmbeddingRequest || requestType == schemas.ImageGenerationRequest) {
		// Use sjson to update model field in-place, preserving key ordering for prompt caching.
		// NOTE: For fal-ai image generation, model is in URL path, not in body
		// For nebius and together image generation, use original model name (already set in ToHuggingFaceImageGenerationRequest)
		if newJSON, err := providerUtils.SetJSONField(jsonData, "model", modelName); err == nil {
			updatedJSONData = newJSON
		}
	}

	// Make the request
	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, updatedJSONData, url, key, isHFInferenceAudioRequest, isHFInferenceImageRequest)
	if err != nil {
		// If we got a 404, clear cache and retry once
		if err.StatusCode != nil && *err.StatusCode == 404 {
			provider.modelProviderMappingCache.Delete(originalModelName)

			// Retry: re-fetch the validated model ID (skip validation for fal-ai, nebius, and together image generation)
			if skipValidation {
				// Keep original model name for validation skip case
				modelName = originalModelName
			} else {
				var retryErr *schemas.DeepIntShieldError
				modelName, retryErr = provider.getValidatedProviderModelID(ctx, inferenceProvider, originalModelName, requiredTask, requestType)
				if retryErr != nil {
					return nil, 0, nil, retryErr
				}
			}

			// Update the model field in the JSON body for retry
			// Skip body modification for fal-ai, nebius, and together image generation - they have special requirements
			if !isHFInferenceAudioRequest && !skipBodyModification && (requestType == schemas.EmbeddingRequest || requestType == schemas.ImageGenerationRequest) {
				// Use sjson to update model field in-place, preserving key ordering.
				if newJSON, err := providerUtils.SetJSONField(jsonData, "model", modelName); err == nil {
					updatedJSONData = newJSON
				}
			}

			// Rebuild URL with new model name (use original for fal-ai, nebius, and together since validation is skipped)
			retryModelName := originalModelName
			if !skipValidation {
				retryModelName = modelName
			}
			url, urlErr = provider.getInferenceProviderRouteURL(ctx, inferenceProvider, retryModelName, requestType)
			if urlErr != nil {
				return nil, 0, nil, providerUtils.NewUnsupportedOperationError(requestType, provider.GetProviderKey())
			}

			// Retry the request
			responseBody, latency, providerResponseHeaders, err = provider.completeRequest(ctx, updatedJSONData, url, key, isHFInferenceAudioRequest, isHFInferenceImageRequest)
			if err != nil {
				return nil, 0, nil, err
			}
		} else {
			return nil, 0, nil, err
		}
	}

	return responseBody, latency, providerResponseHeaders, nil
}

func (provider *HuggingFaceProvider) completeRequest(ctx *schemas.DeepIntShieldContext, jsonData []byte, url string, key string, isHFInferenceAudioRequest bool, _ bool) ([]byte, time.Duration, map[string]string, *schemas.DeepIntShieldError) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	req.SetRequestURI(url)
	req.Header.SetMethod(http.MethodPost)

	if isHFInferenceAudioRequest {
		audioType := providerUtils.DetectAudioMimeType(jsonData)
		mimeType := getMimeTypeForAudioType(audioType)
		req.Header.Set("Content-Type", mimeType)
	} else {
		req.Header.SetContentType("application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	if !providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.HuggingFace) {
		req.SetBody(jsonData)
	}

	latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
	defer wait()
	if deepintshieldErr != nil {
		return nil, latency, nil, deepintshieldErr
	}

	// Extract provider response headers before status check so error responses also forward them
	providerResponseHeaders := providerUtils.ExtractProviderResponseHeaders(resp)

	// Handle error response
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, latency, providerResponseHeaders, parseHuggingFaceImageError(resp, nil)
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

func (provider *HuggingFaceProvider) listModelsByKey(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {
	providerName := provider.GetProviderKey()

	type providerResult struct {
		provider inferenceProvider
		response *HuggingFaceListModelsResponse
		latency  int64
		rawResp  map[string]interface{}
		err      *schemas.DeepIntShieldError
	}

	resultsChan := make(chan providerResult, len(INFERENCE_PROVIDERS))
	var wg sync.WaitGroup

	for _, infProvider := range INFERENCE_PROVIDERS {
		wg.Add(1)
		go func(inferProvider inferenceProvider) {
			defer wg.Done()

			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

			modelHubURL := provider.buildModelHubURL(request, inferProvider)
			req.SetRequestURI(modelHubURL)
			req.Header.SetMethod(http.MethodGet)
			req.Header.SetContentType("application/json")
			if key.Value.GetValue() != "" {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key.Value.GetValue()))
			}

			latency, deepintshieldErr, wait := providerUtils.MakeRequestWithContext(ctx, provider.client, req, resp)
			defer wait()
			if deepintshieldErr != nil {
				resultsChan <- providerResult{provider: inferProvider, err: deepintshieldErr}
				return
			}

			if resp.StatusCode() != fasthttp.StatusOK {
				var errorResp HuggingFaceHubError
				deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)
				if deepintshieldErr.Error == nil {
					deepintshieldErr.Error = &schemas.ErrorField{}
				}
				if strings.TrimSpace(errorResp.Message) != "" {
					deepintshieldErr.Error.Message = errorResp.Message
				}
				resultsChan <- providerResult{provider: inferProvider, err: deepintshieldErr}
				return
			}

			body, err := providerUtils.CheckAndDecodeBody(resp)
			if err != nil {
				resultsChan <- providerResult{provider: inferProvider, err: providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)}
				return
			}

			var huggingfaceAPIResponse HuggingFaceListModelsResponse
			var rawResponse interface{}
			var rawRequest interface{}
			rawRequest, rawResponse, deepintshieldErr = providerUtils.HandleProviderResponse(body, &huggingfaceAPIResponse, nil, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
			if deepintshieldErr != nil {
				resultsChan <- providerResult{provider: inferProvider, err: deepintshieldErr}
				return
			}
			var rawRespMap map[string]interface{}
			if rawResponse != nil {
				if converted, ok := rawResponse.(map[string]interface{}); ok {
					rawRespMap = converted
				}
			}
			// If raw request was requested, attach it to the raw response map
			if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) && rawRequest != nil {
				if rawRespMap == nil {
					rawRespMap = make(map[string]interface{})
				}
				rawRespMap["raw_request"] = rawRequest
			}

			resultsChan <- providerResult{
				provider: inferProvider,
				response: &huggingfaceAPIResponse,
				latency:  latency.Milliseconds(),
				rawResp:  rawRespMap,
			}
		}(infProvider)
	}

	// Close results channel after all goroutines complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Aggregate results
	aggregatedResponse := &schemas.DeepIntShieldListModelsResponse{
		Data: make([]schemas.Model, 0),
	}
	var totalLatency int64
	var successCount int
	var firstError *schemas.DeepIntShieldError
	var rawResponses []map[string]interface{}

	for result := range resultsChan {
		if result.err != nil {
			if firstError == nil {
				firstError = result.err
			}
			continue
		}

		if result.response != nil {
			providerResponse := result.response.ToDeepIntShieldListModelsResponse(providerName, result.provider, key.Models, request.Unfiltered)
			if providerResponse != nil {
				aggregatedResponse.Data = append(aggregatedResponse.Data, providerResponse.Data...)
				totalLatency += result.latency
				successCount++
				if result.rawResp != nil {
					rawResponses = append(rawResponses, result.rawResp)
				}
			}
		}
	}

	// If all requests failed, return the first error
	if successCount == 0 && firstError != nil {
		return nil, firstError
	}

	// Calculate average latency
	if successCount > 0 {
		aggregatedResponse.ExtraFields.Latency = totalLatency / int64(successCount)
	}

	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) && len(rawResponses) > 0 {
		// Combine all raw responses into a single map
		combinedRaw := make(map[string]interface{})
		for i, raw := range rawResponses {
			combinedRaw[fmt.Sprintf("provider_%d", i)] = raw
		}
		aggregatedResponse.ExtraFields.RawResponse = combinedRaw
	}

	return aggregatedResponse, nil
}

// ListModels queries the Hugging Face model hub API to list models served by the inference provider.
func (provider *HuggingFaceProvider) ListModels(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, request *schemas.DeepIntShieldListModelsRequest) (*schemas.DeepIntShieldListModelsResponse, *schemas.DeepIntShieldError) {

	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ListModelsRequest); err != nil {
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

func (provider *HuggingFaceProvider) TextCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (*schemas.DeepIntShieldTextCompletionResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionRequest, provider.GetProviderKey())
}

func (provider *HuggingFaceProvider) TextCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTextCompletionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TextCompletionStreamRequest, provider.GetProviderKey())
}

func (provider *HuggingFaceProvider) ChatCompletion(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ChatCompletionRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.ChatCompletionRequest,
			},
		}
	}
	if inferenceProvider != "" {
		request.Model = fmt.Sprintf("%s:%s", modelName, inferenceProvider)
	} else {
		request.Model = modelName
	}

	jsonBody, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			reqBody, err := ToHuggingFaceChatCompletionRequest(request)
			if err != nil {
				return nil, err
			}
			if reqBody != nil {
				reqBody.Stream = schemas.Ptr(false)
			}
			return reqBody, nil
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	requestURL := provider.buildRequestURL(ctx, "/v1/chat/completions", schemas.ChatCompletionRequest)

	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, requestURL, key.Value.GetValue(), false, false)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	deepintshieldResponse := &schemas.DeepIntShieldChatResponse{}

	var rawResponse interface{}
	var rawRequest interface{}
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, deepintshieldResponse, jsonBody, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Ensure model is set correctly
	if deepintshieldResponse.Model == "" {
		deepintshieldResponse.Model = request.Model
	}

	// Set object if not already set
	if deepintshieldResponse.Object == "" {
		deepintshieldResponse.Object = "chat.completion"
	}

	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.ChatCompletionRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	return deepintshieldResponse, nil
}

func (provider *HuggingFaceProvider) ChatCompletionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldChatRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ChatCompletionStreamRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.ChatCompletionStreamRequest,
			},
		}
	}
	if inferenceProvider != "" {
		request.Model = fmt.Sprintf("%s:%s", modelName, inferenceProvider)
	} else {
		request.Model = modelName
	}

	var authHeader map[string]string
	if key.Value.GetValue() != "" {
		authHeader = map[string]string{"Authorization": "Bearer " + key.Value.GetValue()}
	}

	customRequestConverter := func(request *schemas.DeepIntShieldChatRequest) (providerUtils.RequestBodyWithExtraParams, error) {
		reqBody, err := ToHuggingFaceChatCompletionRequest(request)
		if err != nil {
			return nil, err
		}
		if reqBody != nil {
			reqBody.Stream = schemas.Ptr(true)
		}
		return reqBody, nil
	}

	// Use shared OpenAI-compatible streaming logic
	return openai.HandleOpenAIChatCompletionStreaming(
		ctx,
		provider.client,
		provider.buildRequestURL(ctx, "/v1/chat/completions", schemas.ChatCompletionStreamRequest),
		request,
		authHeader,
		provider.networkConfig.ExtraHeaders,
		providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest),
		providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse),
		provider.GetProviderKey(),
		postHookRunner,
		customRequestConverter,
		nil,
		nil,
		nil,
		nil,
		provider.logger,
	)
}

func (provider *HuggingFaceProvider) Responses(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ResponsesRequest); err != nil {
		return nil, err
	}

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

func (provider *HuggingFaceProvider) ResponsesStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldResponsesRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ResponsesStreamRequest); err != nil {
		return nil, err
	}

	ctx.SetValue(schemas.DeepIntShieldContextKeyIsResponsesToChatCompletionFallback, true)
	return provider.ChatCompletionStream(
		ctx,
		postHookRunner,
		key,
		request.ToChatRequest(),
	)
}

func (provider *HuggingFaceProvider) Embedding(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldEmbeddingRequest) (*schemas.DeepIntShieldEmbeddingResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.EmbeddingRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.EmbeddingRequest,
			},
		}
	}

	jsonBody, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			req, err := ToHuggingFaceEmbeddingRequest(request)
			return req, err
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequestWithModelAliasCache(
		ctx,
		jsonBody,
		key.Value.GetValue(),
		false,
		false,
		inferenceProvider,
		modelName,
		"feature-extraction",
		schemas.EmbeddingRequest,
	)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Handle raw request/response for tracking
	var rawResponse interface{}
	var rawRequest interface{}
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		if err := sonic.Unmarshal(jsonBody, &rawRequest); err != nil {
			rawRequest = string(jsonBody)
		}
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		if err := sonic.Unmarshal(responseBody, &rawResponse); err != nil {
			rawResponse = string(responseBody)
		}
	}

	// Unmarshal directly to DeepIntShieldEmbeddingResponse with custom logic
	deepintshieldResponse, convErr := UnmarshalHuggingFaceEmbeddingResponse(responseBody, request.Model)
	if convErr != nil {
		return nil, providerUtils.EnrichError(ctx, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, convErr, provider.GetProviderKey()), jsonBody, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.EmbeddingRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	return deepintshieldResponse, nil
}

func (provider *HuggingFaceProvider) Speech(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (*schemas.DeepIntShieldSpeechResponse, *schemas.DeepIntShieldError) {
	// Check if Speech is allowed for this provider
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.SpeechRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.SpeechRequest,
			},
		}
	}

	jsonData, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToHuggingFaceSpeechRequest(request)
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequestWithModelAliasCache(
		ctx,
		jsonData,
		key.Value.GetValue(),
		false,
		false,
		inferenceProvider,
		modelName,
		"text-to-speech",
		schemas.SpeechRequest,
	)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	response := acquireHuggingFaceSpeechResponse()
	defer releaseHuggingFaceSpeechResponse(response)

	var rawResponse interface{}
	var rawRequest interface{}
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, response, jsonData, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Download the audio file from the URL
	audioData, downloadErr := provider.downloadAudioFromURL(ctx, response.Audio.URL)
	if downloadErr != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, downloadErr, provider.GetProviderKey())
	}

	deepintshieldResponse, convErr := response.ToDeepIntShieldSpeechResponse(request.Model, audioData)
	if convErr != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, convErr, provider.GetProviderKey())
	}

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.SpeechRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	return deepintshieldResponse, nil
}

// Rerank is not supported by the HuggingFace provider.
func (provider *HuggingFaceProvider) Rerank(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldRerankRequest) (*schemas.DeepIntShieldRerankResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.RerankRequest, provider.GetProviderKey())
}

func (provider *HuggingFaceProvider) SpeechStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldSpeechRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.SpeechStreamRequest, provider.GetProviderKey())
}

func (provider *HuggingFaceProvider) Transcription(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (*schemas.DeepIntShieldTranscriptionResponse, *schemas.DeepIntShieldError) {
	// Check if Transcription is allowed for this provider
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.TranscriptionRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.TranscriptionRequest,
			},
		}
	}

	var jsonData []byte
	var err *schemas.DeepIntShieldError
	// hf-inference expects raw audio bytes with an audio content type instead of JSON
	isHFInferenceAudioRequest := inferenceProvider == hfInference
	if inferenceProvider == hfInference {
		if request.Input == nil || len(request.Input.File) == 0 {
			return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderCreateRequest, fmt.Errorf("input file data is required for hf-inference transcription requests"), provider.GetProviderKey())
		}
		jsonData = request.Input.File
	} else {
		// Prepare request body using Transcription-specific function
		jsonData, err = providerUtils.CheckContextAndGetRequestBody(
			ctx,
			request,
			func() (providerUtils.RequestBodyWithExtraParams, error) {
				return ToHuggingFaceTranscriptionRequest(request)
			},
			provider.GetProviderKey())
		if err != nil {
			return nil, err
		}
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequestWithModelAliasCache(
		ctx,
		jsonData,
		key.Value.GetValue(),
		isHFInferenceAudioRequest,
		false,
		inferenceProvider,
		modelName,
		"automatic-speech-recognition",
		schemas.TranscriptionRequest,
	)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		// Don't wrap raw audio bytes (when isHFInferenceAudioRequest is true)
		if !isHFInferenceAudioRequest {
			return nil, providerUtils.EnrichError(ctx, err, jsonData, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
		return nil, err
	}

	response := acquireHuggingFaceTranscriptionResponse()
	defer releaseHuggingFaceTranscriptionResponse(response)

	var rawResponse interface{}
	var rawRequest interface{}
	// Only pass jsonData if it's not raw audio bytes
	var requestBodyForHandling []byte
	if !isHFInferenceAudioRequest {
		requestBodyForHandling = jsonData
	}
	rawRequest, rawResponse, deepintshieldErr := providerUtils.HandleProviderResponse(responseBody, response, requestBodyForHandling, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
	if deepintshieldErr != nil {
		if !isHFInferenceAudioRequest {
			return nil, providerUtils.EnrichError(ctx, deepintshieldErr, jsonData, responseBody, provider.sendBackRawRequest, provider.sendBackRawResponse)
		}
		return nil, deepintshieldErr
	}

	deepintshieldResponse, convErr := response.ToDeepIntShieldTranscriptionResponse(request.Model)
	if convErr != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, convErr, provider.GetProviderKey())
	}

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.TranscriptionRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	return deepintshieldResponse, nil

}

// TranscriptionStream is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) TranscriptionStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldTranscriptionRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.TranscriptionStreamRequest, provider.GetProviderKey())
}

func (provider *HuggingFaceProvider) ImageGeneration(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ImageGenerationRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.ImageGenerationRequest,
			},
		}
	}

	jsonBody, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			req, err := ToHuggingFaceImageGenerationRequest(request)
			return req, err
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequestWithModelAliasCache(
		ctx,
		jsonBody,
		key.Value.GetValue(),
		false,
		true,
		inferenceProvider,
		modelName,
		"text-to-image",
		schemas.ImageGenerationRequest,
	)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Handle raw request/response for tracking
	var rawResponse interface{}
	var rawRequest interface{}
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		if err := sonic.Unmarshal(jsonBody, &rawRequest); err != nil {
			rawRequest = string(jsonBody)
		}
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		if err := sonic.Unmarshal(responseBody, &rawResponse); err != nil {
			rawResponse = string(responseBody)
		}
	}

	// Unmarshal response using Nebius converter
	deepintshieldResponse, convErr := UnmarshalHuggingFaceImageGenerationResponse(responseBody, request.Model)
	if convErr != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, convErr, provider.GetProviderKey())
	}

	deepintshieldResponse.Created = time.Now().Unix()

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.ImageGenerationRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	return deepintshieldResponse, nil
}

// ImageGenerationStream handles streaming for fal-ai image generation.
// Only fal-ai inference provider supports streaming for HuggingFace.
func (provider *HuggingFaceProvider) ImageGenerationStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageGenerationRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ImageGenerationStreamRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.ImageGenerationStreamRequest,
			},
		}
	}

	// Only fal-ai supports streaming for HuggingFace
	if inferenceProvider != falAI {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			fmt.Sprintf("image generation streaming is only supported for fal-ai inference provider, got: %s", inferenceProvider),
			nil,
			provider.GetProviderKey(),
		)
	}
	providerName := provider.GetProviderKey()

	// Set headers
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Accept":        "text/event-stream",
		"Cache-Control": "no-cache",
	}

	if value := key.Value.GetValue(); value != "" {
		headers["Authorization"] = "Bearer " + value
	}

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToHuggingFaceImageStreamRequest(request)
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

	// Build streaming URL - append /stream to the fal-ai route, honoring path overrides
	defaultPath := fmt.Sprintf("/fal-ai/%s/stream", modelName)
	url := provider.buildRequestURL(ctx, defaultPath, schemas.ImageGenerationStreamRequest)

	// Setup request
	req.Header.SetMethod(http.MethodPost)
	req.SetRequestURI(url)
	req.Header.SetContentType("application/json")

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if !providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.HuggingFace) {
		req.SetBody(jsonBody)
	}

	// Capture start time before making the HTTP request for latency calculation
	startTime := time.Now()

	// Make the request
	err := providerUtils.ClientFromContext(ctx, provider.client).Do(req, resp)
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

	// Extract provider response headers before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		return nil, providerUtils.EnrichError(ctx, parseHuggingFaceImageError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.ImageGenerationStreamRequest,
		}), jsonBody, nil, providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest), providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse))
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
		defer providerUtils.ReleaseStreamingResponse(resp)
		defer close(responseChan)

		if resp.BodyStream() == nil {
			deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
				"Provider returned an empty response",
				fmt.Errorf("provider returned an empty response"),
				providerName,
			)
			ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
			providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
			return
		}

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

		lastChunkTime := startTime
		chunkIndex := 0
		var lastB64Data, lastURLData, lastJsonData string
		var lastIndex int

		for {
			if ctx.Err() != nil {
				return
			}

			data, readErr := sseReader.ReadDataLine()
			if readErr != nil {
				if readErr != io.EOF {
					if ctx.Err() != nil {
						return
					}
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						fmt.Sprintf("Error reading fal-ai stream: %v", readErr),
						readErr,
						providerName,
					)
					deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
						Provider:       providerName,
						ModelRequested: request.Model,
						RequestType:    schemas.ImageGenerationStreamRequest,
					}
					ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
					providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
					return
				}
				break
			}

			jsonData := string(data)

			// Quick check for error/message fields (allocation-free using sonic.GetFromString)
			errorNode, _ := sonic.GetFromString(jsonData, "error")
			messageNode, _ := sonic.GetFromString(jsonData, "message")
			if errorNode.Exists() || messageNode.Exists() {
				// Only unmarshal when we know there might be an error
				var errorResp HuggingFaceResponseError
				if err := sonic.UnmarshalString(jsonData, &errorResp); err == nil {
					if errorResp.Error != "" || errorResp.Message != "" {
						deepintshieldErr := &schemas.DeepIntShieldError{
							IsDeepIntShieldError: false,
							Error: &schemas.ErrorField{
								Message: errorResp.Message,
							},
							ExtraFields: schemas.DeepIntShieldErrorExtraFields{
								Provider:       providerName,
								ModelRequested: request.Model,
								RequestType:    schemas.ImageGenerationStreamRequest,
							},
						}
						if errorResp.Error != "" {
							deepintshieldErr.Error.Message = errorResp.Error
						}
						ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
						providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
						return
					}
				}
			}

			// Parse fal-ai response
			var response HuggingFaceFalAIImageStreamResponse
			if err := sonic.UnmarshalString(jsonData, &response); err != nil {
				provider.logger.Warn(fmt.Sprintf("Failed to parse fal-ai stream response: %v", err))
				continue
			}
			// Extract images from response (handles both Data.Images and top-level Images)
			images := extractImagesFromStreamResponse(&response)
			// Process each image in the response
			for i, img := range images {
				// Create a fresh chunk for each image to avoid data race
				chunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
					Type: schemas.ImageGenerationEventTypePartial,
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ImageGenerationStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(lastChunkTime).Milliseconds(),
					},
				}

				if img.URL != "" {
					chunk.URL = img.URL
				} else if img.B64JSON != "" {
					chunk.B64JSON = img.B64JSON
				}
				chunk.Index = i

				if chunk.CreatedAt == 0 {
					chunk.CreatedAt = time.Now().Unix()
				}
				// Set raw response if enabled
				if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
					chunk.ExtraFields.RawResponse = jsonData
				}

				lastChunkTime = time.Now()
				chunkIndex++

				// Track last chunk data for completion
				lastURLData = img.URL
				lastB64Data = img.B64JSON
				lastIndex = i
				lastJsonData = jsonData

				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, chunk),
					responseChan)
			}
		}

		// Stream closed - send completion chunk
		if chunkIndex > 0 {
			finalChunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
				Type:  schemas.ImageGenerationEventTypeCompleted,
				Index: lastIndex,
				ExtraFields: schemas.DeepIntShieldResponseExtraFields{
					RequestType:    schemas.ImageGenerationStreamRequest,
					Provider:       providerName,
					ModelRequested: request.Model,
					ChunkIndex:     chunkIndex,
					Latency:        time.Since(startTime).Milliseconds(),
				},
			}
			finalChunk.BackfillParams(&schemas.DeepIntShieldRequest{
				ImageGenerationRequest: request,
			})
			if lastURLData != "" {
				finalChunk.URL = lastURLData
			} else if lastB64Data != "" {
				finalChunk.B64JSON = lastB64Data
			}
			if finalChunk.CreatedAt == 0 {
				finalChunk.CreatedAt = time.Now().Unix()
			}
			if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
				providerUtils.ParseAndSetRawRequest(&finalChunk.ExtraFields, jsonBody)
			}
			if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
				finalChunk.ExtraFields.RawResponse = lastJsonData
			}
			ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
			providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
				providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, finalChunk),
				responseChan)

		}
	}()

	return responseChan, nil
}

func (provider *HuggingFaceProvider) ImageEdit(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ImageEditRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.ImageEditRequest,
			},
		}
	}

	// Only fal-ai supports image edit for HuggingFace
	if inferenceProvider != falAI {
		return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
	}

	jsonBody, err := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			req, err := ToHuggingFaceImageEditRequest(request)
			return req, err
		},
		provider.GetProviderKey())
	if err != nil {
		return nil, err
	}

	// Build URL for image edit
	url, urlErr := provider.getInferenceProviderRouteURL(ctx, inferenceProvider, modelName, schemas.ImageEditRequest)
	if urlErr != nil {
		return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageEditRequest, provider.GetProviderKey())
	}

	responseBody, latency, providerResponseHeaders, err := provider.completeRequest(ctx, jsonBody, url, key.Value.GetValue(), false, true)
	if providerResponseHeaders != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerResponseHeaders)
	}
	if err != nil {
		return nil, providerUtils.EnrichError(ctx, err, jsonBody, nil, provider.sendBackRawRequest, provider.sendBackRawResponse)
	}

	// Handle raw request/response for tracking
	var rawResponse interface{}
	var rawRequest interface{}
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		if err := sonic.Unmarshal(jsonBody, &rawRequest); err != nil {
			rawRequest = string(jsonBody)
		}
	}
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		if err := sonic.Unmarshal(responseBody, &rawResponse); err != nil {
			rawResponse = string(responseBody)
		}
	}

	// Unmarshal response
	deepintshieldResponse, convErr := UnmarshalHuggingFaceImageGenerationResponse(responseBody, request.Model)
	if convErr != nil {
		return nil, providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, convErr, provider.GetProviderKey())
	}

	deepintshieldResponse.Created = time.Now().Unix()

	// Set ExtraFields
	deepintshieldResponse.ExtraFields.Provider = provider.GetProviderKey()
	deepintshieldResponse.ExtraFields.ModelRequested = request.Model
	deepintshieldResponse.ExtraFields.RequestType = schemas.ImageEditRequest
	deepintshieldResponse.ExtraFields.Latency = latency.Milliseconds()
	deepintshieldResponse.ExtraFields.ProviderResponseHeaders = providerResponseHeaders

	// Set raw response if enabled
	if providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse) {
		deepintshieldResponse.ExtraFields.RawResponse = rawResponse
	}

	// Set raw request if enabled
	if providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest) {
		deepintshieldResponse.ExtraFields.RawRequest = rawRequest
	}

	return deepintshieldResponse, nil
}

// ImageEditStream handles streaming for fal-ai image edit.
// Only fal-ai inference provider supports streaming for HuggingFace.
func (provider *HuggingFaceProvider) ImageEditStream(ctx *schemas.DeepIntShieldContext, postHookRunner schemas.PostHookRunner, key schemas.Key, request *schemas.DeepIntShieldImageEditRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	if err := providerUtils.CheckOperationAllowed(schemas.HuggingFace, provider.customProviderConfig, schemas.ImageEditStreamRequest); err != nil {
		return nil, err
	}

	inferenceProvider, modelName, nameErr := splitIntoModelProvider(request.Model)
	if nameErr != nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			Error: &schemas.ErrorField{
				Message: nameErr.Error(),
				Error:   nameErr,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider:    provider.GetProviderKey(),
				RequestType: schemas.ImageEditStreamRequest,
			},
		}
	}

	// Only fal-ai supports streaming for HuggingFace image edit
	if inferenceProvider != falAI {
		return nil, providerUtils.NewDeepIntShieldOperationError(
			fmt.Sprintf("image edit streaming is only supported for fal-ai inference provider, got: %s", inferenceProvider),
			nil,
			provider.GetProviderKey(),
		)
	}

	var authHeader map[string]string

	if value := key.Value.GetValue(); value != "" {
		authHeader = map[string]string{"Authorization": "Bearer " + value}
	}

	// Build streaming URL - append /stream to the fal-ai edit route, honoring path overrides
	defaultPath := fmt.Sprintf("/fal-ai/%s/stream", modelName)
	streamURL := provider.buildRequestURL(ctx, defaultPath, schemas.ImageEditStreamRequest)

	// Set headers
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Accept":        "text/event-stream",
		"Cache-Control": "no-cache",
	}

	if authHeader != nil {
		maps.Copy(headers, authHeader)
	}

	sendBackRawRequest := providerUtils.ShouldSendBackRawRequest(ctx, provider.sendBackRawRequest)
	sendBackRawResponse := providerUtils.ShouldSendBackRawResponse(ctx, provider.sendBackRawResponse)
	providerName := provider.GetProviderKey()

	jsonBody, deepintshieldErr := providerUtils.CheckContextAndGetRequestBody(
		ctx,
		request,
		func() (providerUtils.RequestBodyWithExtraParams, error) {
			return ToHuggingFaceImageEditRequest(request)
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

	// Setup request
	req.Header.SetMethod(http.MethodPost)
	req.SetRequestURI(streamURL)
	req.Header.SetContentType("application/json")

	// Set any extra headers from network config
	providerUtils.SetExtraHeaders(ctx, req, provider.networkConfig.ExtraHeaders, nil)

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if !providerUtils.ApplyLargePayloadRequestBodyWithModelNormalization(ctx, req, schemas.HuggingFace) {
		req.SetBody(jsonBody)
	}

	// Capture start time before making the HTTP request for latency calculation
	startTime := time.Now()

	// Make the request
	err := providerUtils.ClientFromContext(ctx, provider.client).Do(req, resp)
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

	// Extract provider response headers before status check so error responses also forward them
	ctx.SetValue(schemas.DeepIntShieldContextKeyProviderResponseHeaders, providerUtils.ExtractProviderResponseHeaders(resp))

	// Check for HTTP errors
	if resp.StatusCode() != fasthttp.StatusOK {
		defer providerUtils.ReleaseStreamingResponse(resp)
		return nil, providerUtils.EnrichError(ctx, parseHuggingFaceImageError(resp, &providerUtils.RequestMetadata{
			Provider:    providerName,
			Model:       request.Model,
			RequestType: schemas.ImageEditStreamRequest,
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
		defer providerUtils.ReleaseStreamingResponse(resp)
		defer close(responseChan)

		if resp.BodyStream() == nil {
			deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
				"Provider returned an empty response",
				fmt.Errorf("provider returned an empty response"),
				providerName,
			)
			ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
			providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
			return
		}

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

		lastChunkTime := startTime
		chunkIndex := 0
		var lastB64Data, lastURLData, lastJsonData string
		var lastIndex int

		for {
			if ctx.Err() != nil {
				return
			}

			data, readErr := sseReader.ReadDataLine()
			if readErr != nil {
				if readErr != io.EOF {
					if ctx.Err() != nil {
						return
					}
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(
						fmt.Sprintf("Error reading fal-ai stream: %v", readErr),
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
					return
				}
				break
			}

			jsonData := string(data)

			// Quick check for error/message fields (allocation-free using sonic.GetFromString)
			errorNode, _ := sonic.GetFromString(jsonData, "error")
			messageNode, _ := sonic.GetFromString(jsonData, "message")
			if errorNode.Exists() || messageNode.Exists() {
				// Only unmarshal when we know there might be an error
				var errorResp HuggingFaceResponseError
				if err := sonic.UnmarshalString(jsonData, &errorResp); err == nil {
					if errorResp.Error != "" || errorResp.Message != "" {
						deepintshieldErr := &schemas.DeepIntShieldError{
							IsDeepIntShieldError: false,
							Error: &schemas.ErrorField{
								Message: errorResp.Message,
							},
							ExtraFields: schemas.DeepIntShieldErrorExtraFields{
								Provider:       providerName,
								ModelRequested: request.Model,
								RequestType:    schemas.ImageEditStreamRequest,
							},
						}
						if errorResp.Error != "" {
							deepintshieldErr.Error.Message = errorResp.Error
						}
						ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
						providerUtils.ProcessAndSendDeepIntShieldError(ctx, postHookRunner, deepintshieldErr, responseChan, provider.logger)
						return
					}
				}
			}

			// Parse fal-ai response
			var response HuggingFaceFalAIImageStreamResponse
			if err := sonic.UnmarshalString(jsonData, &response); err != nil {
				provider.logger.Warn(fmt.Sprintf("Failed to parse fal-ai stream response: %v", err))
				continue
			}
			// Extract images from response (handles both Data.Images and top-level Images)
			images := extractImagesFromStreamResponse(&response)
			// Process each image in the response
			for i, img := range images {
				// Create a fresh chunk for each image to avoid data race
				chunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
					Type: schemas.ImageEditEventTypePartial,
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{
						RequestType:    schemas.ImageEditStreamRequest,
						Provider:       providerName,
						ModelRequested: request.Model,
						ChunkIndex:     chunkIndex,
						Latency:        time.Since(lastChunkTime).Milliseconds(),
					},
				}

				if img.URL != "" {
					chunk.URL = img.URL
				} else if img.B64JSON != "" {
					chunk.B64JSON = img.B64JSON
				}
				chunk.Index = i

				if chunk.CreatedAt == 0 {
					chunk.CreatedAt = time.Now().Unix()
				}
				// Set raw response if enabled
				if sendBackRawResponse {
					chunk.ExtraFields.RawResponse = jsonData
				}

				lastChunkTime = time.Now()
				chunkIndex++

				// Track last chunk data for completion
				lastURLData = img.URL
				lastB64Data = img.B64JSON
				lastIndex = i
				lastJsonData = jsonData

				providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
					providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, chunk),
					responseChan)
			}
		}

		// Stream closed - send completion chunk
		if chunkIndex > 0 {
			finalChunk := &schemas.DeepIntShieldImageGenerationStreamResponse{
				Type:  schemas.ImageEditEventTypeCompleted,
				Index: lastIndex,
				ExtraFields: schemas.DeepIntShieldResponseExtraFields{
					RequestType:    schemas.ImageEditStreamRequest,
					Provider:       providerName,
					ModelRequested: request.Model,
					ChunkIndex:     chunkIndex,
					Latency:        time.Since(startTime).Milliseconds(),
				},
			}
			finalChunk.BackfillParams(&schemas.DeepIntShieldRequest{
				ImageEditRequest: request,
			})
			if lastURLData != "" {
				finalChunk.URL = lastURLData
			} else if lastB64Data != "" {
				finalChunk.B64JSON = lastB64Data
			}
			if finalChunk.CreatedAt == 0 {
				finalChunk.CreatedAt = time.Now().Unix()
			}
			if sendBackRawRequest {
				providerUtils.ParseAndSetRawRequest(&finalChunk.ExtraFields, jsonBody)
			}
			if sendBackRawResponse {
				finalChunk.ExtraFields.RawResponse = lastJsonData
			}
			ctx.SetValue(schemas.DeepIntShieldContextKeyStreamEndIndicator, true)
			providerUtils.ProcessAndSendResponse(ctx, postHookRunner,
				providerUtils.GetDeepIntShieldResponseForStreamResponse(nil, nil, nil, nil, nil, finalChunk),
				responseChan)

		}
	}()

	return responseChan, nil
}

// ImageVariation is not supported by the HuggingFace provider.
func (provider *HuggingFaceProvider) ImageVariation(ctx *schemas.DeepIntShieldContext, key schemas.Key, request *schemas.DeepIntShieldImageVariationRequest) (*schemas.DeepIntShieldImageGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ImageVariationRequest, provider.GetProviderKey())
}

// VideoGeneration is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) VideoGeneration(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoGenerationRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoGenerationRequest, provider.GetProviderKey())
}

// VideoRetrieve is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) VideoRetrieve(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRetrieveRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRetrieveRequest, provider.GetProviderKey())
}

// VideoDownload is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) VideoDownload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDownloadRequest) (*schemas.DeepIntShieldVideoDownloadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDownloadRequest, provider.GetProviderKey())
}

// VideoDelete is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) VideoDelete(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoDeleteRequest) (*schemas.DeepIntShieldVideoDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoDeleteRequest, provider.GetProviderKey())
}

// VideoList is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) VideoList(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoListRequest) (*schemas.DeepIntShieldVideoListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoListRequest, provider.GetProviderKey())
}

// VideoRemix is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) VideoRemix(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldVideoRemixRequest) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.VideoRemixRequest, provider.GetProviderKey())
}

// BatchCreate is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) BatchCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldBatchCreateRequest) (*schemas.DeepIntShieldBatchCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCreateRequest, provider.GetProviderKey())
}

// BatchList is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) BatchList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchListRequest) (*schemas.DeepIntShieldBatchListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchListRequest, provider.GetProviderKey())
}

// BatchRetrieve is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) BatchRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchRetrieveRequest) (*schemas.DeepIntShieldBatchRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchRetrieveRequest, provider.GetProviderKey())
}

// BatchCancel is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) BatchCancel(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchCancelRequest) (*schemas.DeepIntShieldBatchCancelResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchCancelRequest, provider.GetProviderKey())
}

// BatchDelete is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) BatchDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchDeleteRequest) (*schemas.DeepIntShieldBatchDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchDeleteRequest, provider.GetProviderKey())
}

// BatchResults is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) BatchResults(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldBatchResultsRequest) (*schemas.DeepIntShieldBatchResultsResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.BatchResultsRequest, provider.GetProviderKey())
}

// FileUpload is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) FileUpload(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldFileUploadRequest) (*schemas.DeepIntShieldFileUploadResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileUploadRequest, provider.GetProviderKey())
}

// FileList is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) FileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileListRequest) (*schemas.DeepIntShieldFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileListRequest, provider.GetProviderKey())
}

// FileRetrieve is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) FileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileRetrieveRequest) (*schemas.DeepIntShieldFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileRetrieveRequest, provider.GetProviderKey())
}

// FileDelete is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) FileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileDeleteRequest) (*schemas.DeepIntShieldFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileDeleteRequest, provider.GetProviderKey())
}

// FileContent is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) FileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldFileContentRequest) (*schemas.DeepIntShieldFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.FileContentRequest, provider.GetProviderKey())
}

// CountTokens is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) CountTokens(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldCountTokensResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.CountTokensRequest, provider.GetProviderKey())
}

// ContainerCreate is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerCreateRequest) (*schemas.DeepIntShieldContainerCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerCreateRequest, provider.GetProviderKey())
}

// ContainerList is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerListRequest) (*schemas.DeepIntShieldContainerListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerListRequest, provider.GetProviderKey())
}

// ContainerRetrieve is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerRetrieveRequest) (*schemas.DeepIntShieldContainerRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerRetrieveRequest, provider.GetProviderKey())
}

// ContainerDelete is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerDeleteRequest) (*schemas.DeepIntShieldContainerDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerDeleteRequest, provider.GetProviderKey())
}

// ContainerFileCreate is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerFileCreate(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldContainerFileCreateRequest) (*schemas.DeepIntShieldContainerFileCreateResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileCreateRequest, provider.GetProviderKey())
}

// ContainerFileList is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerFileList(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileListRequest) (*schemas.DeepIntShieldContainerFileListResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileListRequest, provider.GetProviderKey())
}

// ContainerFileRetrieve is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerFileRetrieve(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileRetrieveRequest) (*schemas.DeepIntShieldContainerFileRetrieveResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileRetrieveRequest, provider.GetProviderKey())
}

// ContainerFileContent is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerFileContent(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileContentRequest) (*schemas.DeepIntShieldContainerFileContentResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileContentRequest, provider.GetProviderKey())
}

// ContainerFileDelete is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) ContainerFileDelete(_ *schemas.DeepIntShieldContext, _ []schemas.Key, _ *schemas.DeepIntShieldContainerFileDeleteRequest) (*schemas.DeepIntShieldContainerFileDeleteResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.ContainerFileDeleteRequest, provider.GetProviderKey())
}

// Passthrough is not supported by the Hugging Face provider.
func (provider *HuggingFaceProvider) Passthrough(_ *schemas.DeepIntShieldContext, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (*schemas.DeepIntShieldPassthroughResponse, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughRequest, provider.GetProviderKey())
}

func (provider *HuggingFaceProvider) PassthroughStream(_ *schemas.DeepIntShieldContext, _ schemas.PostHookRunner, _ schemas.Key, _ *schemas.DeepIntShieldPassthroughRequest) (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
	return nil, providerUtils.NewUnsupportedOperationError(schemas.PassthroughStreamRequest, provider.GetProviderKey())
}
