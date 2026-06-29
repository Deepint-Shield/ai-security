// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains completion request handlers for text and chat completions.
package handlers

import (
	"context"

	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/fasthttp/router"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/modelcatalog"
	"github.com/deepint-shield/ai-security/framework/safegoroutine"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/integrations"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/valyala/fasthttp"
)

// forwardProviderHeaders forwards provider response headers to the HTTP response.
func forwardProviderHeaders(ctx *fasthttp.RequestCtx, headers map[string]string) {
	for key, value := range headers {
		ctx.Response.Header.Set(key, value)
	}
}

// forwardProviderHeadersFromContext extracts provider response headers from the deepintshield context
// and forwards them to the HTTP response. This ensures error responses also include provider headers.
func forwardProviderHeadersFromContext(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext) {
	if headers, ok := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyProviderResponseHeaders).(map[string]string); ok {
		forwardProviderHeaders(ctx, headers)
	}
}

// CompletionHandler manages HTTP requests for completion operations
type CompletionHandler struct {
	client       *deepintshield.DeepIntShield
	handlerStore lib.HandlerStore
	config       *lib.Config
}

// NewInferenceHandler creates a new completion handler instance
func NewInferenceHandler(client *deepintshield.DeepIntShield, config *lib.Config) *CompletionHandler {
	if config != nil && config.ModelCatalog != nil {
		modelCatalogRef = config.ModelCatalog
	}
	return &CompletionHandler{
		client:       client,
		handlerStore: config,
		config:       config,
	}
}

// modelCatalogRef holds the process-wide model catalog so the unprefixed-model
// resolver can reach it without threading it through every prepare* function.
// It is assigned once in NewInferenceHandler (at handler construction, before any
// request is served) and only read thereafter, so there is no data race. When nil,
// resolveModelProvider degrades to the historical "provider prefix required"
// behavior - never panics.
var modelCatalogRef *modelcatalog.ModelCatalog

// resolveModelProvider parses a "provider/model" string exactly as
// schemas.ParseModelString always has. When the caller omits the provider prefix
// (provider == ""), it falls back to the in-memory model catalog to choose a
// provider deterministically so a bare model name (e.g. "gpt-4o-mini") routes to
// the right backend instead of failing validation.
//
// Performance & correctness contract:
//   - Prefixed requests (the existing common path) never touch the catalog - the
//     early return keeps their behavior and latency byte-for-byte identical.
//   - The catalog lookup is an in-memory, RLock-guarded map read (no I/O), so the
//     unprefixed path adds only a sub-microsecond lookup and is safe under load.
//   - Selection is deterministic (consistency): these are OpenAI-format endpoints,
//     so OpenAI is preferred when it serves the model; otherwise the
//     alphabetically-first candidate is chosen, so the same model always resolves
//     to the same provider across requests, restarts, and processes.
//   - When the catalog has no match, the provider is left empty and the caller's
//     existing "provider/model format" error fires unchanged.
func resolveModelProvider(modelStr string) (schemas.ModelProvider, string) {
	provider, model := schemas.ParseModelString(modelStr, "")
	if provider != "" || model == "" || modelCatalogRef == nil {
		return provider, model
	}
	candidates := modelCatalogRef.GetProvidersForModel(model)
	if len(candidates) == 0 {
		return provider, model
	}
	slices.SortFunc(candidates, func(a, b schemas.ModelProvider) int {
		return strings.Compare(string(a), string(b))
	})
	for _, c := range candidates {
		if c == schemas.OpenAI {
			return schemas.OpenAI, model
		}
	}
	return candidates[0], model
}

// AgenticCacheBridgeHook returns a no-op closure in the open-source build.
// The agentic runtime that consumed semantic-cache → agentic-cache analytics
// is part of the commercial build; the closure is retained so the compat
// integration wiring keeps compiling.
func (h *CompletionHandler) AgenticCacheBridgeHook() integrations.AgenticCacheBridgeHook {
	return func(_ *fasthttp.RequestCtx, _ *schemas.DeepIntShieldContext, _ *schemas.DeepIntShieldResponse) {}
}

// recordLLMCacheOutcome is a no-op in the open-source build (no agentic
// runtime to attribute cache outcomes to). Retained so the per-route call
// sites compile unchanged.
func (h *CompletionHandler) recordLLMCacheOutcome(_ *fasthttp.RequestCtx, _ *schemas.DeepIntShieldContext, _ *schemas.DeepIntShieldResponse) {
}

// recordAgenticLLMUsage is a no-op in the open-source build (no agentic
// observability runtime). Retained so the per-route call sites compile
// unchanged.
func (h *CompletionHandler) recordAgenticLLMUsage(_ *fasthttp.RequestCtx, _ string, _ *schemas.DeepIntShieldResponse) {
}

// AgenticLLMUsageHook returns a no-op closure in the open-source build. The
// agentic LLM cost/token rollups are part of the commercial build; the
// closure is retained so the compat integration wiring keeps compiling.
func (h *CompletionHandler) AgenticLLMUsageHook() integrations.AgenticLLMUsageHook {
	return func(_ *fasthttp.RequestCtx, _ *schemas.DeepIntShieldContext, _ *schemas.DeepIntShieldRequest, _ *schemas.DeepIntShieldResponse) {
	}
}

// Known fields for CompletionRequest
var textParamsKnownFields = map[string]bool{
	"prompt":            true,
	"model":             true,
	"fallbacks":         true,
	"best_of":           true,
	"echo":              true,
	"frequency_penalty": true,
	"logit_bias":        true,
	"logprobs":          true,
	"max_tokens":        true,
	"n":                 true,
	"presence_penalty":  true,
	"seed":              true,
	"stop":              true,
	"suffix":            true,
	"temperature":       true,
	"top_p":             true,
	"user":              true,
}

// Known fields for CompletionRequest
var chatParamsKnownFields = map[string]bool{
	"model":                 true,
	"messages":              true,
	"fallbacks":             true,
	"stream":                true,
	"frequency_penalty":     true,
	"logit_bias":            true,
	"logprobs":              true,
	"max_completion_tokens": true,
	"metadata":              true,
	"modalities":            true,
	"parallel_tool_calls":   true,
	"presence_penalty":      true,
	"prompt_cache_key":      true,
	"reasoning":             true,
	"response_format":       true,
	"safety_identifier":     true,
	"service_tier":          true,
	"stream_options":        true,
	"store":                 true,
	"temperature":           true,
	"tool_choice":           true,
	"tools":                 true,
	"truncation":            true,
	"user":                  true,
	"verbosity":             true,
}

var responsesParamsKnownFields = map[string]bool{
	"model":                true,
	"input":                true,
	"fallbacks":            true,
	"stream":               true,
	"background":           true,
	"conversation":         true,
	"include":              true,
	"instructions":         true,
	"max_output_tokens":    true,
	"max_tool_calls":       true,
	"metadata":             true,
	"parallel_tool_calls":  true,
	"previous_response_id": true,
	"prompt_cache_key":     true,
	"reasoning":            true,
	"safety_identifier":    true,
	"service_tier":         true,
	"stream_options":       true,
	"store":                true,
	"temperature":          true,
	"text":                 true,
	"top_logprobs":         true,
	"top_p":                true,
	"tool_choice":          true,
	"tools":                true,
	"truncation":           true,
}

var embeddingParamsKnownFields = map[string]bool{
	"model":           true,
	"input":           true,
	"fallbacks":       true,
	"encoding_format": true,
	"dimensions":      true,
}

var rerankParamsKnownFields = map[string]bool{
	"model":              true,
	"query":              true,
	"documents":          true,
	"fallbacks":          true,
	"top_n":              true,
	"max_tokens_per_doc": true,
	"priority":           true,
	"return_documents":   true,
}

var speechParamsKnownFields = map[string]bool{
	"model":           true,
	"input":           true,
	"fallbacks":       true,
	"stream_format":   true,
	"voice":           true,
	"instructions":    true,
	"response_format": true,
	"speed":           true,
}

// imageGenerationParamsKnownFields contains known fields for image generation requests
// Based on ImageGenerationInput and ImageGenerationParameters structs
var imageGenerationParamsKnownFields = map[string]bool{
	"model":               true,
	"prompt":              true,
	"fallbacks":           true,
	"stream":              true,
	"n":                   true,
	"background":          true,
	"moderation":          true,
	"partial_images":      true,
	"size":                true,
	"quality":             true,
	"output_compression":  true,
	"output_format":       true,
	"style":               true,
	"response_format":     true,
	"seed":                true,
	"negative_prompt":     true,
	"num_inference_steps": true,
	"user":                true,
}

// imageEditParamsKnownFields contains known fields for image edit requests
// Based on ImageEditInput and ImageEditParameters structs
var imageEditParamsKnownFields = map[string]bool{
	"model":               true,
	"prompt":              true,
	"fallbacks":           true,
	"image":               true,
	"image[]":             true,
	"mask":                true,
	"type":                true,
	"background":          true,
	"input_fidelity":      true,
	"n":                   true,
	"output_compression":  true,
	"output_format":       true,
	"partial_images":      true,
	"quality":             true,
	"response_format":     true,
	"size":                true,
	"user":                true,
	"negative_prompt":     true,
	"seed":                true,
	"num_inference_steps": true,
	"stream":              true,
}

// imageVariationParamsKnownFields contains known fields for image variation requests
// Based on ImageVariationInput and ImageVariationParameters structs
var imageVariationParamsKnownFields = map[string]bool{
	"model":           true,
	"fallbacks":       true,
	"image":           true,
	"image[]":         true,
	"n":               true,
	"response_format": true,
	"size":            true,
	"user":            true,
}

// videoGenerationParamsKnownFields contains known fields for video generation requests
// Based on VideoGenerationInput and VideoGenerationParameters structs
var videoGenerationParamsKnownFields = map[string]bool{
	"model":           true,
	"prompt":          true,
	"input_reference": true,
	"seconds":         true,
	"size":            true,
	"negative_prompt": true,
	"seed":            true,
	"video_uri":       true,
	"audio":           true,
	"fallbacks":       true,
}

var videoRemixParamsKnownFields = map[string]bool{
	"prompt":    true,
	"fallbacks": true,
}

var transcriptionParamsKnownFields = map[string]bool{
	"model":           true,
	"file":            true,
	"fallbacks":       true,
	"stream":          true,
	"language":        true,
	"prompt":          true,
	"response_format": true,
	"file_format":     true,
}

var countTokensParamsKnownFields = map[string]bool{
	"model":        true,
	"messages":     true,
	"fallbacks":    true,
	"tools":        true,
	"instructions": true,
	"text":         true,
}

var batchCreateParamsKnownFields = map[string]bool{
	"model":             true,
	"input_file_id":     true,
	"requests":          true,
	"endpoint":          true,
	"completion_window": true,
	"metadata":          true,
}

var containerCreateParamsKnownFields = map[string]bool{
	"provider":      true,
	"name":          true,
	"expires_after": true,
	"file_ids":      true,
	"memory_limit":  true,
	"metadata":      true,
}

type DeepIntShieldParams struct {
	Model        string   `json:"model"`                   // Model to use in "provider/model" format
	Fallbacks    []string `json:"fallbacks"`               // Fallback providers and models in "provider/model" format
	Stream       *bool    `json:"stream"`                  // Whether to stream the response
	StreamFormat *string  `json:"stream_format,omitempty"` // For speech
}

type TextRequest struct {
	Prompt *schemas.TextCompletionInput `json:"prompt"`
	DeepIntShieldParams
	*schemas.TextCompletionParameters
}

type ChatRequest struct {
	Messages []schemas.ChatMessage `json:"messages"`
	DeepIntShieldParams
	*schemas.ChatParameters

	// rawFields is populated during UnmarshalJSON so that extractExtraParams
	// can reuse the already-decoded field map instead of re-parsing the body.
	rawFields map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON implements custom JSON unmarshalling for ChatRequest.
// This is needed because ChatParameters has a custom UnmarshalJSON method,
// which interferes with sonic's handling of the embedded DeepIntShieldParams struct.
//
// The implementation first decodes the body into a raw field map, extracts the
// flat DeepIntShieldParams and Messages from individual fields, then forwards
// the full data to ChatParameters' custom unmarshaler.  The raw field map is
// retained so extractExtraParams can iterate it without re-parsing the body.
func (cr *ChatRequest) UnmarshalJSON(data []byte) error {
	// Single parse into raw field map.
	var rawMap map[string]json.RawMessage
	if err := sonic.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	cr.rawFields = rawMap

	// Extract flat DeepIntShieldParams fields from the map.
	if v, ok := rawMap["model"]; ok {
		_ = sonic.Unmarshal(v, &cr.DeepIntShieldParams.Model)
	}
	if v, ok := rawMap["fallbacks"]; ok {
		_ = sonic.Unmarshal(v, &cr.DeepIntShieldParams.Fallbacks)
	}
	if v, ok := rawMap["stream"]; ok {
		_ = sonic.Unmarshal(v, &cr.DeepIntShieldParams.Stream)
	}
	if v, ok := rawMap["stream_format"]; ok {
		_ = sonic.Unmarshal(v, &cr.DeepIntShieldParams.StreamFormat)
	}

	// Extract messages.
	if v, ok := rawMap["messages"]; ok {
		if err := sonic.Unmarshal(v, &cr.Messages); err != nil {
			return err
		}
	}

	// Forward full data to ChatParameters' custom unmarshaler (1 parse).
	if cr.ChatParameters == nil {
		cr.ChatParameters = &schemas.ChatParameters{}
	}
	return sonic.Unmarshal(data, cr.ChatParameters)
}

// extractExtraParamsFromRaw extracts unknown fields from a pre-decoded raw
// field map, avoiding a full re-parse of the request body.
func extractExtraParamsFromRaw(rawFields map[string]json.RawMessage, knownFields map[string]bool) map[string]any {
	extraParams := make(map[string]any)
	for key, value := range rawFields {
		if !knownFields[key] {
			var v any
			if err := sonic.Unmarshal(value, &v); err != nil {
				continue
			}
			extraParams[key] = v
		}
	}
	return extraParams
}

// ResponsesRequestInput is a union of string and array of responses messages
type ResponsesRequestInput struct {
	ResponsesRequestInputStr   *string
	ResponsesRequestInputArray []schemas.ResponsesMessage
}

type ImageGenerationHTTPRequest struct {
	*schemas.ImageGenerationInput
	*schemas.ImageGenerationParameters
	DeepIntShieldParams
}

type ImageEditHTTPRequest struct {
	*schemas.ImageEditInput
	*schemas.ImageEditParameters
	DeepIntShieldParams
}

type ImageVariationHTTPRequest struct {
	*schemas.ImageVariationInput
	*schemas.ImageVariationParameters
	DeepIntShieldParams
}

type VideoGenerationHTTPRequest struct {
	*schemas.VideoGenerationInput
	*schemas.VideoGenerationParameters
	DeepIntShieldParams
}

// UnmarshalJSON unmarshals the responses request input
func (r *ResponsesRequestInput) UnmarshalJSON(data []byte) error {
	var str string
	if err := sonic.Unmarshal(data, &str); err == nil {
		r.ResponsesRequestInputStr = &str
		r.ResponsesRequestInputArray = nil
		return nil
	}
	var array []schemas.ResponsesMessage
	if err := sonic.Unmarshal(data, &array); err == nil {
		r.ResponsesRequestInputStr = nil
		r.ResponsesRequestInputArray = array
		return nil
	}
	return fmt.Errorf("invalid responses request input")
}

// UnmarshalJSON implements custom JSON unmarshalling for ResponsesRequest.
// This is needed because ResponsesParameters has a custom UnmarshalJSON method,
// which interferes with sonic's handling of the embedded DeepIntShieldParams struct.
func (rr *ResponsesRequest) UnmarshalJSON(data []byte) error {
	// First, unmarshal DeepIntShieldParams fields directly
	type deepintshieldAlias DeepIntShieldParams
	var bp deepintshieldAlias
	if err := sonic.Unmarshal(data, &bp); err != nil {
		return err
	}
	rr.DeepIntShieldParams = DeepIntShieldParams(bp)

	// Unmarshal messages
	var inputStruct struct {
		Input ResponsesRequestInput `json:"input"`
	}
	if err := sonic.Unmarshal(data, &inputStruct); err != nil {
		return err
	}
	rr.Input = inputStruct.Input

	// Unmarshal ResponsesParameters (which has its own custom unmarshaller)
	if rr.ResponsesParameters == nil {
		rr.ResponsesParameters = &schemas.ResponsesParameters{}
	}
	if err := sonic.Unmarshal(data, rr.ResponsesParameters); err != nil {
		return err
	}

	return nil
}

// ResponsesRequest is a deepintshield responses request
type ResponsesRequest struct {
	Input ResponsesRequestInput `json:"input"`
	DeepIntShieldParams
	*schemas.ResponsesParameters
}

// EmbeddingRequest is a deepintshield embedding request
type EmbeddingRequest struct {
	Input *schemas.EmbeddingInput `json:"input"`
	DeepIntShieldParams
	*schemas.EmbeddingParameters
}

// RerankRequest is a deepintshield rerank request
type RerankRequest struct {
	Query     string                   `json:"query"`
	Documents []schemas.RerankDocument `json:"documents"`
	DeepIntShieldParams
	*schemas.RerankParameters
}

type SpeechRequest struct {
	*schemas.SpeechInput
	DeepIntShieldParams
	*schemas.SpeechParameters
}

type TranscriptionRequest struct {
	*schemas.TranscriptionInput
	DeepIntShieldParams
	*schemas.TranscriptionParameters
}

type VideoGenerationRequest struct {
	*schemas.VideoGenerationInput
	DeepIntShieldParams
	*schemas.VideoGenerationParameters
}
type VideoRemixRequest struct {
	*schemas.VideoGenerationInput
	DeepIntShieldParams
	ExtraParams map[string]any `json:"extra_params,omitempty"`
}

// BatchCreateRequest is a deepintshield batch create request
type BatchCreateRequest struct {
	Model            string                     `json:"model"`                       // Model in "provider/model" format
	InputFileID      string                     `json:"input_file_id,omitempty"`     // OpenAI-style file ID
	Requests         []schemas.BatchRequestItem `json:"requests,omitempty"`          // Anthropic-style inline requests
	Endpoint         string                     `json:"endpoint,omitempty"`          // e.g., "/v1/chat/completions"
	CompletionWindow string                     `json:"completion_window,omitempty"` // e.g., "24h"
	Metadata         map[string]string          `json:"metadata,omitempty"`
}

// BatchListRequest is a deepintshield batch list request
type BatchListRequest struct {
	Provider string  `json:"provider"`         // Provider name
	Limit    int     `json:"limit,omitempty"`  // Maximum number of batches to return
	After    *string `json:"after,omitempty"`  // Cursor for pagination
	Before   *string `json:"before,omitempty"` // Cursor for pagination
}

// ContainerCreateRequest is a deepintshield container create request
type ContainerCreateRequest struct {
	Provider     string                         `json:"provider"`                // Provider name
	Name         string                         `json:"name"`                    // Name of the container
	ExpiresAfter *schemas.ContainerExpiresAfter `json:"expires_after,omitempty"` // Expiration configuration
	FileIDs      []string                       `json:"file_ids,omitempty"`      // IDs of existing files to copy into this container
	MemoryLimit  string                         `json:"memory_limit,omitempty"`  // Memory limit (e.g., "1g", "4g")
	Metadata     map[string]string              `json:"metadata,omitempty"`      // User-provided metadata
}

// Helper functions

// enableRawRequestResponseForContainer sets context flags to always capture raw request/response
// for container operations. Container operations don't have model-specific content, so raw
// data is useful for debugging and should be enabled by default.
func enableRawRequestResponseForContainer(deepintshieldCtx *schemas.DeepIntShieldContext) {
	deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeySendBackRawRequest, true)
	deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeySendBackRawResponse, true)
	deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyRawRequestResponseForLogging, true)
}

// parseFallbacks extracts fallbacks from string array and converts to Fallback structs
func parseFallbacks(fallbackStrings []string) ([]schemas.Fallback, error) {
	fallbacks := make([]schemas.Fallback, 0, len(fallbackStrings))
	for _, fallback := range fallbackStrings {
		fallbackProvider, fallbackModelName := schemas.ParseModelString(fallback, "")
		if fallbackProvider != "" && fallbackModelName != "" {
			fallbacks = append(fallbacks, schemas.Fallback{
				Provider: fallbackProvider,
				Model:    fallbackModelName,
			})
		}
	}
	return fallbacks, nil
}

// extractExtraParams processes unknown fields from JSON data into ExtraParams
func extractExtraParams(data []byte, knownFields map[string]bool) (map[string]any, error) {
	// Parse JSON to extract unknown fields
	var rawData map[string]json.RawMessage
	if err := sonic.Unmarshal(data, &rawData); err != nil {
		return nil, err
	}

	// Extract unknown fields
	extraParams := make(map[string]any)
	for key, value := range rawData {
		if !knownFields[key] {
			var v any
			if err := sonic.Unmarshal(value, &v); err != nil {
				continue // Skip fields that can't be unmarshaled
			}
			extraParams[key] = v
		}
	}

	return extraParams, nil
}

const (
	// Maximum file size (25MB)
	MaxFileSize = 25 * 1024 * 1024

	// Primary MIME types for audio formats
	AudioMimeMP3   = "audio/mpeg"   // Covers MP3, MPEG, MPGA
	AudioMimeMP4   = "audio/mp4"    // MP4 audio
	AudioMimeM4A   = "audio/x-m4a"  // M4A specific
	AudioMimeOGG   = "audio/ogg"    // OGG audio
	AudioMimeWAV   = "audio/wav"    // WAV audio
	AudioMimeWEBM  = "audio/webm"   // WEBM audio
	AudioMimeFLAC  = "audio/flac"   // FLAC audio
	AudioMimeFLAC2 = "audio/x-flac" // Alternative FLAC
)

// PathToTypeMapping maps exact paths to request types (only for non-parameterized paths)
// Parameterized paths are set per-route in RegisterRoutes
var PathToTypeMapping = map[string]schemas.RequestType{
	"/v1/completions":            schemas.TextCompletionRequest,
	"/v1/chat/completions":       schemas.ChatCompletionRequest,
	"/v1/responses":              schemas.ResponsesRequest,
	"/v1/embeddings":             schemas.EmbeddingRequest,
	"/v1/rerank":                 schemas.RerankRequest,
	"/v1/audio/speech":           schemas.SpeechRequest,
	"/v1/audio/transcriptions":   schemas.TranscriptionRequest,
	"/v1/images/generations":     schemas.ImageGenerationRequest,
	"/v1/responses/input_tokens": schemas.CountTokensRequest,
	"/v1/images/edits":           schemas.ImageEditRequest,
	"/v1/images/variations":      schemas.ImageVariationRequest,
	"/v1/models":                 schemas.ListModelsRequest,
}

// createRequestTypeMiddleware creates a middleware that sets the request type for a specific route
func createRequestTypeMiddleware(requestType schemas.RequestType) schemas.DeepIntShieldHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyHTTPRequestType, requestType)
			next(ctx)
		}
	}
}

// RegisterRequestTypeMiddleware handles exact path matching for non-parameterized routes
func RegisterRequestTypeMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())
		if requestType, ok := PathToTypeMapping[path]; ok {
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyHTTPRequestType, requestType)
		}
		next(ctx)
	}
}

// RegisterRoutes registers all completion-related routes
func (h *CompletionHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// Base middlewares for all routes
	baseMiddlewares := append([]schemas.DeepIntShieldHTTPMiddleware{RegisterRequestTypeMiddleware}, middlewares...)

	// Model endpoints
	r.GET("/v1/models", lib.ChainMiddlewares(h.listModels, baseMiddlewares...))

	// Completion endpoints (non-parameterized)
	r.POST("/v1/completions", lib.ChainMiddlewares(h.textCompletion, baseMiddlewares...))
	r.POST("/v1/chat/completions", lib.ChainMiddlewares(h.chatCompletion, baseMiddlewares...))
	r.POST("/v1/responses", lib.ChainMiddlewares(h.responses, baseMiddlewares...))
	r.POST("/v1/embeddings", lib.ChainMiddlewares(h.embeddings, baseMiddlewares...))
	r.POST("/v1/rerank", lib.ChainMiddlewares(h.rerank, baseMiddlewares...))
	r.POST("/v1/audio/speech", lib.ChainMiddlewares(h.speech, baseMiddlewares...))
	r.POST("/v1/audio/transcriptions", lib.ChainMiddlewares(h.transcription, baseMiddlewares...))
	r.POST("/v1/images/generations", lib.ChainMiddlewares(h.imageGeneration, baseMiddlewares...))
	r.POST("/v1/responses/input_tokens", lib.ChainMiddlewares(h.countTokens, baseMiddlewares...))
	r.POST("/v1/images/edits", lib.ChainMiddlewares(h.imageEdit, baseMiddlewares...))
	r.POST("/v1/images/variations", lib.ChainMiddlewares(h.imageVariation, baseMiddlewares...))
	r.POST("/v1/videos", lib.ChainMiddlewares(h.videoGeneration, baseMiddlewares...))

	// Video API endpoints (parameterized routes need explicit request type middleware)
	videoListMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.VideoListRequest)}, middlewares...)
	videoRetrieveMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.VideoRetrieveRequest)}, middlewares...)
	videoDownloadMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.VideoDownloadRequest)}, middlewares...)
	videoDeleteMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.VideoDeleteRequest)}, middlewares...)
	videoRemixMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.VideoRemixRequest)}, middlewares...)
	r.GET("/v1/videos", lib.ChainMiddlewares(h.videoList, videoListMW...))
	r.GET("/v1/videos/{video_id}", lib.ChainMiddlewares(h.videoRetrieve, videoRetrieveMW...))
	r.GET("/v1/videos/{video_id}/content", lib.ChainMiddlewares(h.videoDownload, videoDownloadMW...))
	r.DELETE("/v1/videos/{video_id}", lib.ChainMiddlewares(h.videoDelete, videoDeleteMW...))
	r.POST("/v1/videos/{video_id}/remix", lib.ChainMiddlewares(h.videoRemix, videoRemixMW...))

	// Batch API endpoints (parameterized routes need explicit request type middleware)
	batchCreateMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.BatchCreateRequest)}, middlewares...)
	batchListMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.BatchListRequest)}, middlewares...)
	batchRetrieveMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.BatchRetrieveRequest)}, middlewares...)
	batchCancelMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.BatchCancelRequest)}, middlewares...)
	batchResultsMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.BatchResultsRequest)}, middlewares...)

	r.POST("/v1/batches", lib.ChainMiddlewares(h.batchCreate, batchCreateMW...))
	r.GET("/v1/batches", lib.ChainMiddlewares(h.batchList, batchListMW...))
	r.GET("/v1/batches/{batch_id}", lib.ChainMiddlewares(h.batchRetrieve, batchRetrieveMW...))
	r.POST("/v1/batches/{batch_id}/cancel", lib.ChainMiddlewares(h.batchCancel, batchCancelMW...))
	r.GET("/v1/batches/{batch_id}/results", lib.ChainMiddlewares(h.batchResults, batchResultsMW...))

	// File API endpoints (parameterized routes need explicit request type middleware)
	fileUploadMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.FileUploadRequest)}, middlewares...)
	fileListMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.FileListRequest)}, middlewares...)
	fileRetrieveMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.FileRetrieveRequest)}, middlewares...)
	fileDeleteMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.FileDeleteRequest)}, middlewares...)
	fileContentMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.FileContentRequest)}, middlewares...)

	r.POST("/v1/files", lib.ChainMiddlewares(h.fileUpload, fileUploadMW...))
	r.GET("/v1/files", lib.ChainMiddlewares(h.fileList, fileListMW...))
	r.GET("/v1/files/{file_id}", lib.ChainMiddlewares(h.fileRetrieve, fileRetrieveMW...))
	r.DELETE("/v1/files/{file_id}", lib.ChainMiddlewares(h.fileDelete, fileDeleteMW...))
	r.GET("/v1/files/{file_id}/content", lib.ChainMiddlewares(h.fileContent, fileContentMW...))

	// Container API endpoints (parameterized routes need explicit request type middleware)
	containerCreateMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerCreateRequest)}, middlewares...)
	containerListMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerListRequest)}, middlewares...)
	containerRetrieveMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerRetrieveRequest)}, middlewares...)
	containerDeleteMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerDeleteRequest)}, middlewares...)

	r.POST("/v1/containers", lib.ChainMiddlewares(h.containerCreate, containerCreateMW...))
	r.GET("/v1/containers", lib.ChainMiddlewares(h.containerList, containerListMW...))
	r.GET("/v1/containers/{container_id}", lib.ChainMiddlewares(h.containerRetrieve, containerRetrieveMW...))
	r.DELETE("/v1/containers/{container_id}", lib.ChainMiddlewares(h.containerDelete, containerDeleteMW...))

	// Container Files API endpoints (parameterized routes need explicit request type middleware)
	containerFileCreateMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerFileCreateRequest)}, middlewares...)
	containerFileListMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerFileListRequest)}, middlewares...)
	containerFileRetrieveMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerFileRetrieveRequest)}, middlewares...)
	containerFileContentMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerFileContentRequest)}, middlewares...)
	containerFileDeleteMW := append([]schemas.DeepIntShieldHTTPMiddleware{createRequestTypeMiddleware(schemas.ContainerFileDeleteRequest)}, middlewares...)

	r.POST("/v1/containers/{container_id}/files", lib.ChainMiddlewares(h.containerFileCreate, containerFileCreateMW...))
	r.GET("/v1/containers/{container_id}/files", lib.ChainMiddlewares(h.containerFileList, containerFileListMW...))
	r.GET("/v1/containers/{container_id}/files/{file_id}", lib.ChainMiddlewares(h.containerFileRetrieve, containerFileRetrieveMW...))
	r.GET("/v1/containers/{container_id}/files/{file_id}/content", lib.ChainMiddlewares(h.containerFileContent, containerFileContentMW...))
	r.DELETE("/v1/containers/{container_id}/files/{file_id}", lib.ChainMiddlewares(h.containerFileDelete, containerFileDeleteMW...))
}

// listModels handles GET /v1/models - Process list models requests
// If provider is not specified, lists all models from all configured providers
func (h *CompletionHandler) listModels(ctx *fasthttp.RequestCtx) {
	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel() // Ensure cleanup on function exit
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	var resp *schemas.DeepIntShieldListModelsResponse
	var deepintshieldErr *schemas.DeepIntShieldError

	pageSize := 0
	if pageSizeStr := ctx.QueryArgs().Peek("page_size"); len(pageSizeStr) > 0 {
		if n, err := strconv.Atoi(string(pageSizeStr)); err == nil && n >= 0 {
			pageSize = n
		}
	}
	pageToken := string(ctx.QueryArgs().Peek("page_token"))

	deepintshieldListModelsReq := &schemas.DeepIntShieldListModelsRequest{
		Provider:  schemas.ModelProvider(provider),
		PageSize:  pageSize,
		PageToken: pageToken,
	}

	// Pass-through unknown query params for provider-specific features
	extraParams := map[string]interface{}{}
	for k, v := range ctx.QueryArgs().All() {
		s := string(k)
		if s != "provider" && s != "page_size" && s != "page_token" {
			extraParams[s] = string(v)
		}
	}
	if len(extraParams) > 0 {
		deepintshieldListModelsReq.ExtraParams = extraParams
	}

	// If provider is empty, list all models from all providers
	if provider == "" {
		resp, deepintshieldErr = h.client.ListAllModels(deepintshieldCtx, deepintshieldListModelsReq)
	} else {
		resp, deepintshieldErr = h.client.ListModelsRequest(deepintshieldCtx, deepintshieldListModelsReq)
	}

	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}

	// Add pricing data to the response
	if len(resp.Data) > 0 && h.config.ModelCatalog != nil {
		for i, modelEntry := range resp.Data {
			provider, modelName := schemas.ParseModelString(modelEntry.ID, "")
			pricingEntry := h.config.ModelCatalog.GetPricingEntryForModel(modelName, provider)
			if pricingEntry == nil && modelEntry.Deployment != nil {
				// Retry with deployment
				pricingEntry = h.config.ModelCatalog.GetPricingEntryForModel(*modelEntry.Deployment, provider)
			}
			if pricingEntry != nil && modelEntry.Pricing == nil {
				pricing := &schemas.Pricing{
					Prompt:     deepintshield.Ptr(fmt.Sprintf("%.10f", pricingEntry.InputCostPerToken)),
					Completion: deepintshield.Ptr(fmt.Sprintf("%.10f", pricingEntry.OutputCostPerToken)),
				}
				if pricingEntry.InputCostPerImage != nil {
					pricing.Image = deepintshield.Ptr(fmt.Sprintf("%.10f", *pricingEntry.InputCostPerImage))
				}
				if pricingEntry.CacheReadInputTokenCost != nil {
					pricing.InputCacheRead = deepintshield.Ptr(fmt.Sprintf("%.10f", *pricingEntry.CacheReadInputTokenCost))
				}
				resp.Data[i].Pricing = pricing
			}
		}
	}
	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// prepareTextCompletionRequest prepares a DeepIntShieldTextCompletionRequest from the HTTP request body
func prepareTextCompletionRequest(ctx *fasthttp.RequestCtx) (*TextRequest, *schemas.DeepIntShieldTextCompletionRequest, error) {
	var req TextRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, err
	}
	if req.Prompt == nil || (req.Prompt.PromptStr == nil && req.Prompt.PromptArray == nil) {
		return nil, nil, fmt.Errorf("prompt is required for text completion")
	}
	if req.TextCompletionParameters == nil {
		req.TextCompletionParameters = &schemas.TextCompletionParameters{}
	}
	extraParams, err := extractExtraParams(ctx.PostBody(), textParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.TextCompletionParameters.ExtraParams = extraParams
	}
	deepintshieldTextReq := &schemas.DeepIntShieldTextCompletionRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.Prompt,
		Params:    req.TextCompletionParameters,
		Fallbacks: fallbacks,
	}
	return &req, deepintshieldTextReq, nil
}

// textCompletion handles POST /v1/completions - Process text completion requests
func (h *CompletionHandler) textCompletion(ctx *fasthttp.RequestCtx) {
	req, deepintshieldTextReq, err := prepareTextCompletionRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	if req.Stream != nil && *req.Stream {
		h.handleStreamingTextCompletion(ctx, deepintshieldTextReq, deepintshieldCtx, cancel)
		return
	}

	// NOTE: these defers wont work as expected when a non-streaming request is cancelled on flight.
	// valyala/fasthttp does not support cancelling a request in the middle of a request.
	// This is a known issue of valyala/fasthttp. And will be fixed here once it is fixed upstream.
	defer cancel() // Ensure cleanup on function exit

	resp, deepintshieldErr := h.client.TextCompletionRequest(deepintshieldCtx, deepintshieldTextReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	h.recordLLMCacheOutcome(ctx, deepintshieldCtx, &schemas.DeepIntShieldResponse{TextCompletionResponse: resp})
	h.recordAgenticLLMUsage(ctx, "", &schemas.DeepIntShieldResponse{TextCompletionResponse: resp})

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// prepareChatCompletionRequest prepares a DeepIntShieldChatRequest from a ChatRequest
func prepareChatCompletionRequest(ctx *fasthttp.RequestCtx) (*ChatRequest, *schemas.DeepIntShieldChatRequest, error) {
	req := ChatRequest{
		ChatParameters: &schemas.ChatParameters{},
	}
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}

	// Create DeepIntShieldChatRequest directly using segregated structure
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}

	// Parse fallbacks using helper function
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse fallbacks: %v", err)
	}

	if len(req.Messages) == 0 {
		return nil, nil, fmt.Errorf("messages is required for chat completion")
	}

	// Extract extra params from the pre-decoded raw field map when available,
	// avoiding a full re-parse of the request body.
	if req.ChatParameters == nil {
		req.ChatParameters = &schemas.ChatParameters{}
	}

	var extraParams map[string]any
	if req.rawFields != nil {
		extraParams = extractExtraParamsFromRaw(req.rawFields, chatParamsKnownFields)
	} else {
		extraParams, err = extractExtraParams(ctx.PostBody(), chatParamsKnownFields)
	}
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		// Handle max_tokens -> max_completion_tokens mapping after extracting extra params
		// If max_completion_tokens is nil and max_tokens is present in extra params, map it
		// This is to support the legacy max_tokens field, which is still used by some implementations.
		if req.ChatParameters.MaxCompletionTokens == nil {
			if maxTokensVal, exists := extraParams["max_tokens"]; exists {
				// Type check and convert to int
				// JSON numbers are unmarshaled as float64, so we need to handle that
				var maxTokens int
				if maxTokensFloat, ok := maxTokensVal.(float64); ok {
					maxTokens = int(maxTokensFloat)
					req.ChatParameters.MaxCompletionTokens = &maxTokens
					// Remove max_tokens from extra params since we've mapped it
					delete(extraParams, "max_tokens")
				} else if maxTokensInt, ok := maxTokensVal.(int); ok {
					req.ChatParameters.MaxCompletionTokens = &maxTokensInt
					// Remove max_tokens from extra params since we've mapped it
					delete(extraParams, "max_tokens")
				}
			}
		}
		req.ChatParameters.ExtraParams = extraParams
	}

	// Create segregated DeepIntShieldChatRequest
	deepintshieldChatReq := &schemas.DeepIntShieldChatRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.Messages,
		Params:    req.ChatParameters,
		Fallbacks: fallbacks,
	}

	return &req, deepintshieldChatReq, nil
}

// chatCompletion handles POST /v1/chat/completions - Process chat completion requests
func (h *CompletionHandler) chatCompletion(ctx *fasthttp.RequestCtx) {
	req, deepintshieldChatReq, err := prepareChatCompletionRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	if req.Stream != nil && *req.Stream {
		h.handleStreamingChatCompletion(ctx, deepintshieldChatReq, deepintshieldCtx, cancel)
		return
	}
	defer cancel() // Ensure cleanup on function exit
	// Complete the request
	resp, deepintshieldErr := h.client.ChatCompletionRequest(deepintshieldCtx, deepintshieldChatReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}
	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	h.recordLLMCacheOutcome(ctx, deepintshieldCtx, &schemas.DeepIntShieldResponse{ChatResponse: resp})
	h.recordAgenticLLMUsage(ctx, "", &schemas.DeepIntShieldResponse{ChatResponse: resp})

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// prepareResponsesRequest prepares a DeepIntShieldResponsesRequest from a ResponsesRequest
func prepareResponsesRequest(ctx *fasthttp.RequestCtx) (*ResponsesRequest, *schemas.DeepIntShieldResponsesRequest, error) {
	var req ResponsesRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}

	// Create DeepIntShieldResponsesRequest directly using segregated structure
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}

	// Parse fallbacks using helper function
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse fallbacks: %v", err)
	}

	if len(req.Input.ResponsesRequestInputArray) == 0 && req.Input.ResponsesRequestInputStr == nil {
		return nil, nil, fmt.Errorf("input is required for responses")
	}

	// Extract extra params
	if req.ResponsesParameters == nil {
		req.ResponsesParameters = &schemas.ResponsesParameters{}
	}

	extraParams, err := extractExtraParams(ctx.PostBody(), responsesParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.ResponsesParameters.ExtraParams = extraParams
	}

	input := req.Input.ResponsesRequestInputArray
	if input == nil {
		input = []schemas.ResponsesMessage{
			{
				Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleUser),
				Content: &schemas.ResponsesMessageContent{ContentStr: req.Input.ResponsesRequestInputStr},
			},
		}
	}

	// Create segregated DeepIntShieldResponsesRequest
	deepintshieldResponsesReq := &schemas.DeepIntShieldResponsesRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     input,
		Params:    req.ResponsesParameters,
		Fallbacks: fallbacks,
	}

	return &req, deepintshieldResponsesReq, nil
}

// responses handles POST /v1/responses - Process responses requests
func (h *CompletionHandler) responses(ctx *fasthttp.RequestCtx) {
	req, deepintshieldResponsesReq, err := prepareResponsesRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	if req.Stream != nil && *req.Stream {
		h.handleStreamingResponses(ctx, deepintshieldResponsesReq, deepintshieldCtx, cancel)
		return
	}

	defer cancel() // Ensure cleanup on function exit

	resp, deepintshieldErr := h.client.ResponsesRequest(deepintshieldCtx, deepintshieldResponsesReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	h.recordLLMCacheOutcome(ctx, deepintshieldCtx, &schemas.DeepIntShieldResponse{ResponsesResponse: resp})
	h.recordAgenticLLMUsage(ctx, "", &schemas.DeepIntShieldResponse{ResponsesResponse: resp})

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// prepareEmbeddingRequest prepares a DeepIntShieldEmbeddingRequest from the HTTP request body
func prepareEmbeddingRequest(ctx *fasthttp.RequestCtx) (*EmbeddingRequest, *schemas.DeepIntShieldEmbeddingRequest, error) {
	var req EmbeddingRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, err
	}
	if req.Input == nil || (req.Input.Text == nil && req.Input.Texts == nil && req.Input.Embedding == nil && req.Input.Embeddings == nil) {
		return nil, nil, fmt.Errorf("input is required for embeddings")
	}
	if req.EmbeddingParameters == nil {
		req.EmbeddingParameters = &schemas.EmbeddingParameters{}
	}
	extraParams, err := extractExtraParams(ctx.PostBody(), embeddingParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.EmbeddingParameters.ExtraParams = extraParams
	}
	deepintshieldEmbeddingReq := &schemas.DeepIntShieldEmbeddingRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.Input,
		Params:    req.EmbeddingParameters,
		Fallbacks: fallbacks,
	}
	return &req, deepintshieldEmbeddingReq, nil
}

// embeddings handles POST /v1/embeddings - Process embeddings requests
func (h *CompletionHandler) embeddings(ctx *fasthttp.RequestCtx) {
	_, deepintshieldEmbeddingReq, err := prepareEmbeddingRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.EmbeddingRequest(deepintshieldCtx, deepintshieldEmbeddingReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// prepareRerankRequest prepares a DeepIntShieldRerankRequest from the HTTP request body
func prepareRerankRequest(ctx *fasthttp.RequestCtx) (*RerankRequest, *schemas.DeepIntShieldRerankRequest, error) {
	var req RerankRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}

	// Parse model
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}

	// Parse fallbacks
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse fallbacks: %v", err)
	}

	if strings.TrimSpace(req.Query) == "" {
		return nil, nil, fmt.Errorf("query is required for rerank")
	}

	if len(req.Documents) == 0 {
		return nil, nil, fmt.Errorf("documents are required for rerank")
	}
	for i, doc := range req.Documents {
		if strings.TrimSpace(doc.Text) == "" {
			return nil, nil, fmt.Errorf("document text is required for rerank at index %d", i)
		}
	}

	// Extract extra params
	if req.RerankParameters == nil {
		req.RerankParameters = &schemas.RerankParameters{}
	}
	if req.RerankParameters.TopN != nil && *req.RerankParameters.TopN < 1 {
		return nil, nil, fmt.Errorf("top_n must be at least 1")
	}

	extraParams, err := extractExtraParams(ctx.PostBody(), rerankParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.RerankParameters.ExtraParams = extraParams
	}

	// Create DeepIntShieldRerankRequest
	deepintshieldRerankReq := &schemas.DeepIntShieldRerankRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Query:     req.Query,
		Documents: req.Documents,
		Params:    req.RerankParameters,
		Fallbacks: fallbacks,
	}

	return &req, deepintshieldRerankReq, nil
}

// rerank handles POST /v1/rerank - Process rerank requests
func (h *CompletionHandler) rerank(ctx *fasthttp.RequestCtx) {
	_, deepintshieldRerankReq, err := prepareRerankRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.RerankRequest(deepintshieldCtx, deepintshieldRerankReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// prepareSpeechRequest prepares a DeepIntShieldSpeechRequest from the HTTP request body
func prepareSpeechRequest(ctx *fasthttp.RequestCtx) (*SpeechRequest, *schemas.DeepIntShieldSpeechRequest, error) {
	var req SpeechRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, err
	}
	if req.SpeechInput == nil || req.SpeechInput.Input == "" {
		return nil, nil, fmt.Errorf("input is required for speech completion")
	}
	if req.SpeechParameters == nil || req.VoiceConfig == nil || (req.VoiceConfig.Voice == nil && len(req.VoiceConfig.MultiVoiceConfig) == 0) {
		return nil, nil, fmt.Errorf("voice is required for speech completion")
	}
	if req.SpeechParameters == nil {
		req.SpeechParameters = &schemas.SpeechParameters{}
	}
	extraParams, err := extractExtraParams(ctx.PostBody(), speechParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.SpeechParameters.ExtraParams = extraParams
	}
	deepintshieldSpeechReq := &schemas.DeepIntShieldSpeechRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.SpeechInput,
		Params:    req.SpeechParameters,
		Fallbacks: fallbacks,
	}
	return &req, deepintshieldSpeechReq, nil
}

// speech handles POST /v1/audio/speech - Process speech completion requests
func (h *CompletionHandler) speech(ctx *fasthttp.RequestCtx) {
	req, deepintshieldSpeechReq, err := prepareSpeechRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	if req.StreamFormat != nil && *req.StreamFormat == "sse" {
		h.handleStreamingSpeech(ctx, deepintshieldSpeechReq, deepintshieldCtx, cancel)
		return
	}

	defer cancel() // Ensure cleanup on function exit

	resp, deepintshieldErr := h.client.SpeechRequest(deepintshieldCtx, deepintshieldSpeechReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	// Preserve the attachment header through the large-response shortcut; the
	// normal binary path sets this explicitly after the stream check.
	if !(deepintshieldSpeechReq.Provider == schemas.Elevenlabs && req.WithTimestamps != nil && *req.WithTimestamps) {
		deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyLargeResponseContentDisposition, "attachment; filename=speech.mp3")
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}

	// Send successful response
	// When with_timestamps is true, Elevenlabs returns base64 encoded audio
	hasTimestamps := req.WithTimestamps != nil && *req.WithTimestamps

	if deepintshieldSpeechReq.Provider == schemas.Elevenlabs && hasTimestamps {
		ctx.Response.Header.Set("Content-Type", "application/json")
		SendJSON(ctx, resp)
		return
	}

	if resp.Audio == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Speech response is missing audio data")
		return
	}

	ctx.Response.Header.Set("Content-Type", "audio/mpeg")
	ctx.Response.Header.Set("Content-Disposition", "attachment; filename=speech.mp3")
	ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(resp.Audio)))
	ctx.Response.SetBody(resp.Audio)
}

// prepareTranscriptionRequest prepares a DeepIntShieldTranscriptionRequest from a multipart form.
// Returns the request, whether streaming was requested, and any error.
func prepareTranscriptionRequest(ctx *fasthttp.RequestCtx) (*schemas.DeepIntShieldTranscriptionRequest, bool, error) {
	form, err := ctx.MultipartForm()
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse multipart form: %v", err)
	}
	modelValues := form.Value["model"]
	if len(modelValues) == 0 || modelValues[0] == "" {
		return nil, false, fmt.Errorf("model is required")
	}
	provider, modelName := resolveModelProvider(modelValues[0])
	if provider == "" || modelName == "" {
		return nil, false, fmt.Errorf("model should be in provider/model format")
	}
	fileHeaders := form.File["file"]
	if len(fileHeaders) == 0 {
		return nil, false, fmt.Errorf("file is required")
	}
	fileHeader := fileHeaders[0]
	file, err := fileHeader.Open()
	if err != nil {
		return nil, false, fmt.Errorf("failed to open uploaded file: %v", err)
	}
	defer file.Close()
	fileData, err := io.ReadAll(file)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read uploaded file: %v", err)
	}
	transcriptionInput := &schemas.TranscriptionInput{
		File:     fileData,
		Filename: fileHeader.Filename,
	}
	transcriptionParams := &schemas.TranscriptionParameters{}
	if languageValues := form.Value["language"]; len(languageValues) > 0 && languageValues[0] != "" {
		transcriptionParams.Language = &languageValues[0]
	}
	if promptValues := form.Value["prompt"]; len(promptValues) > 0 && promptValues[0] != "" {
		transcriptionParams.Prompt = &promptValues[0]
	}
	if responseFormatValues := form.Value["response_format"]; len(responseFormatValues) > 0 && responseFormatValues[0] != "" {
		transcriptionParams.ResponseFormat = &responseFormatValues[0]
	}
	if transcriptionParams.ExtraParams == nil {
		transcriptionParams.ExtraParams = make(map[string]interface{})
	}
	for key, value := range form.Value {
		if len(value) > 0 && value[0] != "" && !transcriptionParamsKnownFields[key] {
			transcriptionParams.ExtraParams[key] = value[0]
		}
	}
	stream := false
	if streamValues := form.Value["stream"]; len(streamValues) > 0 && streamValues[0] == "true" {
		stream = true
	}
	deepintshieldTranscriptionReq := &schemas.DeepIntShieldTranscriptionRequest{
		Model:    modelName,
		Provider: schemas.ModelProvider(provider),
		Input:    transcriptionInput,
		Params:   transcriptionParams,
	}
	return deepintshieldTranscriptionReq, stream, nil
}

// transcription handles POST /v1/audio/transcriptions - Process transcription requests
func (h *CompletionHandler) transcription(ctx *fasthttp.RequestCtx) {
	deepintshieldTranscriptionReq, stream, err := prepareTranscriptionRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	if stream {
		h.handleStreamingTranscriptionRequest(ctx, deepintshieldTranscriptionReq, deepintshieldCtx, cancel)
		return
	}

	defer cancel()

	resp, deepintshieldErr := h.client.TranscriptionRequest(deepintshieldCtx, deepintshieldTranscriptionReq)

	// Handle response
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	// Send successful response
	SendJSON(ctx, resp)
}

// countTokens handles POST /v1/responses/input_tokens - Process count tokens requests
func (h *CompletionHandler) countTokens(ctx *fasthttp.RequestCtx) {
	_, deepintshieldResponsesReq, err := prepareResponsesRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	response, deepintshieldErr := h.client.CountTokensRequest(deepintshieldCtx, deepintshieldResponsesReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	forwardProviderHeaders(ctx, response.ExtraFields.ProviderResponseHeaders)
	// Send successful response
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, response)
}

// handleStreamingTextCompletion handles streaming text completion requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingTextCompletion(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldTextCompletionRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.TextCompletionStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// handleStreamingChatCompletion handles streaming chat completion requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingChatCompletion(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldChatRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.ChatCompletionStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// handleStreamingResponses handles streaming responses requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingResponses(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldResponsesRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.ResponsesStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// handleStreamingSpeech handles streaming speech requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingSpeech(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldSpeechRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.SpeechStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// handleStreamingTranscriptionRequest handles streaming transcription requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingTranscriptionRequest(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldTranscriptionRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.TranscriptionStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// handleStreamingResponse is a generic function to handle streaming responses using Server-Sent Events (SSE)
// The cancel function is called ONLY when client disconnects are detected via write errors.
// DeepIntShield handles cleanup internally for normal completion and errors, so we only cancel
// upstream streams when write errors indicate the client has disconnected.
func (h *CompletionHandler) handleStreamingResponse(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, getStream func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError), cancel context.CancelFunc) {
	// Get the streaming channel - called BEFORE setting SSE headers so that
	// provider errors return proper HTTP status codes + JSON content type.
	stream, deepintshieldErr := getStream()
	if deepintshieldErr != nil {
		cancel()
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	// SSE headers set only after successful stream setup
	ctx.SetContentType("text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")

	// Forward provider response headers stored in context by streaming handlers
	if headers, ok := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyProviderResponseHeaders).(map[string]string); ok {
		forwardProviderHeaders(ctx, headers)
	}

	// Signal to tracing middleware that trace completion should be deferred
	// The streaming callback will complete the trace after the stream ends
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyDeferTraceCompletion, true)

	// Get the trace completer function for use in the streaming callback
	traceCompleter, _ := ctx.UserValue(schemas.DeepIntShieldContextKeyTraceCompleter).(func())

	// Get stream chunk interceptor for plugin hooks
	interceptor := h.config.GetStreamChunkInterceptor()
	var httpReq *schemas.HTTPRequest
	if interceptor != nil {
		httpReq = lib.BuildHTTPRequestFromFastHTTP(ctx)
	}
	// Use SSEStreamReader to bypass fasthttp's internal pipe (fasthttputil.PipeConns)
	// which batches multiple SSE events into single TCP segments.
	// Each event is delivered individually via a channel, ensuring one HTTP chunk per event.
	reader := lib.NewSSEStreamReader()
	ctx.Response.SetBodyStream(reader, -1)

	// Producer goroutine: processes the stream channel, formats SSE events, sends to reader
	go func() {
		defer safegoroutine.Recover(logger, "inference.sse-stream-producer")
		defer func() {
			schemas.ReleaseHTTPRequest(httpReq)
			reader.Done()
			// Complete the trace after streaming finishes
			// This ensures all spans (including llm.call) are properly ended before the trace is sent to OTEL
			if traceCompleter != nil {
				traceCompleter()
			}
		}()

		var includeEventType bool
		var skipDoneMarker bool

		// Process streaming responses
		for chunk := range stream {
			if chunk == nil {
				continue
			}

			includeEventType = false
			if chunk.DeepIntShieldResponsesStreamResponse != nil ||
				chunk.DeepIntShieldImageGenerationStreamResponse != nil ||
				(chunk.DeepIntShieldError != nil && (chunk.DeepIntShieldError.ExtraFields.RequestType == schemas.ResponsesStreamRequest || chunk.DeepIntShieldError.ExtraFields.RequestType == schemas.ImageGenerationStreamRequest || chunk.DeepIntShieldError.ExtraFields.RequestType == schemas.ImageEditStreamRequest)) {
				includeEventType = true
			}

			// Image generation streams don't use [DONE] marker
			if chunk.DeepIntShieldImageGenerationStreamResponse != nil {
				skipDoneMarker = true
			}

			// Allow plugins to modify/filter the chunk via StreamChunkInterceptor
			if interceptor != nil {
				var err error
				chunk, err = interceptor.InterceptChunk(deepintshieldCtx, httpReq, chunk)
				if err != nil {
					if chunk == nil {
						errorJSON, marshalErr := sonic.Marshal(map[string]string{"error": err.Error()})
						if marshalErr != nil {
							cancel() // Payload invalid
							return
						}
						// Return error event and stop streaming
						reader.SendError(errorJSON)
						cancel()
						return
					}
					// Else add warn log and continue
					logger.Warn("%v", err)
				}
				if chunk == nil {
					// Skip chunk if plugin wants to skip it
					continue
				}
			}

			// Convert response to JSON
			chunkJSON, err := sonic.Marshal(chunk)
			if err != nil {
				logger.Warn("Failed to marshal streaming response: %v", err)
				continue
			}

			// Format and send as SSE data
			var eventType string
			if includeEventType {
				// For responses and image gen API, use OpenAI-compatible format with event line
				if chunk.DeepIntShieldResponsesStreamResponse != nil {
					eventType = string(chunk.DeepIntShieldResponsesStreamResponse.Type)
				} else if chunk.DeepIntShieldImageGenerationStreamResponse != nil {
					eventType = string(chunk.DeepIntShieldImageGenerationStreamResponse.Type)
				} else if chunk.DeepIntShieldError != nil {
					eventType = string(schemas.ResponsesStreamResponseTypeError)
				}
			}

			if !reader.SendEvent(eventType, chunkJSON) {
				cancel() // Client disconnected, cancel upstream stream
				return
			}
		}

		if !includeEventType && !skipDoneMarker {
			// Send the [DONE] marker to indicate the end of the stream (only for non-responses/image-gen APIs)
			if !reader.SendDone() {
				cancel()
				return
			}
		}
		// Note: OpenAI responses API doesn't use [DONE] marker, it ends when the stream closes
		// Stream completed normally, DeepIntShield handles cleanup internally

		cancel()
	}()
}

// validateAudioFile checks if the file size and format are valid
func (h *CompletionHandler) validateAudioFile(fileHeader *multipart.FileHeader) error {
	// Check file size
	if fileHeader.Size > MaxFileSize {
		return fmt.Errorf("file size exceeds maximum limit of %d MB", MaxFileSize/1024/1024)
	}

	// Get file extension
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))

	// Check file extension
	validExtensions := map[string]bool{
		".flac": true,
		".mp3":  true,
		".mp4":  true,
		".mpeg": true,
		".mpga": true,
		".m4a":  true,
		".ogg":  true,
		".wav":  true,
		".webm": true,
	}

	if !validExtensions[ext] {
		return fmt.Errorf("unsupported file format: %s. Supported formats: flac, mp3, mp4, mpeg, mpga, m4a, ogg, wav, webm", ext)
	}

	// Open file to check MIME type
	file, err := fileHeader.Open()
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Read first 512 bytes for MIME type detection
	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read file header: %v", err)
	}

	// Check MIME type
	mimeType := http.DetectContentType(buffer)
	validMimeTypes := map[string]bool{
		// Primary MIME types
		AudioMimeMP3:   true, // Covers MP3, MPEG, MPGA
		AudioMimeMP4:   true,
		AudioMimeM4A:   true,
		AudioMimeOGG:   true,
		AudioMimeWAV:   true,
		AudioMimeWEBM:  true,
		AudioMimeFLAC:  true,
		AudioMimeFLAC2: true,

		// Alternative MIME types
		"audio/mpeg3":       true,
		"audio/x-wav":       true,
		"audio/vnd.wave":    true,
		"audio/x-mpeg":      true,
		"audio/x-mpeg3":     true,
		"audio/x-mpg":       true,
		"audio/x-mpegaudio": true,
	}

	if !validMimeTypes[mimeType] {
		return fmt.Errorf("invalid file type: %s. Supported audio formats: flac, mp3, mp4, mpeg, mpga, m4a, ogg, wav, webm", mimeType)
	}

	// Reset file pointer for subsequent reads
	_, err = file.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("failed to reset file pointer: %v", err)
	}

	return nil
}

// prepareImageGenerationRequest prepares a DeepIntShieldImageGenerationRequest from the HTTP request body
func prepareImageGenerationRequest(ctx *fasthttp.RequestCtx) (*ImageGenerationHTTPRequest, *schemas.DeepIntShieldImageGenerationRequest, error) {
	var req ImageGenerationHTTPRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		return nil, nil, fmt.Errorf("invalid request format: %v", err)
	}
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}
	if req.ImageGenerationInput == nil || req.Prompt == "" {
		return nil, nil, fmt.Errorf("prompt cannot be empty")
	}
	if req.ImageGenerationParameters == nil {
		req.ImageGenerationParameters = &schemas.ImageGenerationParameters{}
	}
	extraParams, err := extractExtraParams(ctx.PostBody(), imageGenerationParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.ImageGenerationParameters.ExtraParams = extraParams
	}
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, err
	}
	deepintshieldReq := &schemas.DeepIntShieldImageGenerationRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.ImageGenerationInput,
		Params:    req.ImageGenerationParameters,
		Fallbacks: fallbacks,
	}
	return &req, deepintshieldReq, nil
}

// imageGeneration handles POST /v1/images/generations - Processes image generation requests
func (h *CompletionHandler) imageGeneration(ctx *fasthttp.RequestCtx) {
	req, deepintshieldReq, err := prepareImageGenerationRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		cancel()
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	// Handle streaming image generation
	if req.DeepIntShieldParams.Stream != nil && *req.DeepIntShieldParams.Stream {
		h.handleStreamingImageGeneration(ctx, deepintshieldReq, deepintshieldCtx, cancel)
		return
	}
	defer cancel()

	// Execute request
	resp, deepintshieldErr := h.client.ImageGenerationRequest(deepintshieldCtx, deepintshieldReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// handleStreamingImageGeneration handles streaming image generation requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingImageGeneration(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldImageGenerationRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context
	// Pass the context directly instead of copying to avoid copying lock values

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.ImageGenerationStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// prepareImageEditRequest prepares a DeepIntShieldImageEditRequest from a multipart form
func prepareImageEditRequest(ctx *fasthttp.RequestCtx) (*ImageEditHTTPRequest, *schemas.DeepIntShieldImageEditRequest, error) {
	var req ImageEditHTTPRequest
	form, err := ctx.MultipartForm()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse multipart form: %v", err)
	}
	modelValues := form.Value["model"]
	if len(modelValues) == 0 || modelValues[0] == "" {
		return nil, nil, fmt.Errorf("model is required")
	}
	req.Model = modelValues[0]
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		return nil, nil, fmt.Errorf("model should be in provider/model format")
	}
	var editType string
	if typeValues := form.Value["type"]; len(typeValues) > 0 && typeValues[0] != "" {
		editType = typeValues[0]
	}
	promptValues := form.Value["prompt"]
	if editType != "background_removal" {
		if len(promptValues) == 0 || promptValues[0] == "" {
			return nil, nil, fmt.Errorf("prompt is required")
		}
	}
	var imageFiles []*multipart.FileHeader
	if imageFilesArray := form.File["image[]"]; len(imageFilesArray) > 0 {
		imageFiles = imageFilesArray
	} else if imageFilesSingle := form.File["image"]; len(imageFilesSingle) > 0 {
		imageFiles = imageFilesSingle
	}
	if len(imageFiles) == 0 {
		return nil, nil, fmt.Errorf("at least one image is required")
	}
	images := make([]schemas.ImageInput, 0, len(imageFiles))
	for _, fh := range imageFiles {
		f, err := fh.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open uploaded file: %v", err)
		}
		fileData, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read uploaded file: %v", err)
		}
		images = append(images, schemas.ImageInput{Image: fileData})
	}
	prompt := ""
	if len(promptValues) > 0 && promptValues[0] != "" {
		prompt = promptValues[0]
	}
	req.ImageEditInput = &schemas.ImageEditInput{
		Images: images,
		Prompt: prompt,
	}
	req.ImageEditParameters = &schemas.ImageEditParameters{}
	if nValues := form.Value["n"]; len(nValues) > 0 && nValues[0] != "" {
		n, err := strconv.Atoi(nValues[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid n value: %v", err)
		}
		req.ImageEditParameters.N = &n
	}
	if backgroundValues := form.Value["background"]; len(backgroundValues) > 0 && backgroundValues[0] != "" {
		req.ImageEditParameters.Background = &backgroundValues[0]
	}
	if inputFidelityValues := form.Value["input_fidelity"]; len(inputFidelityValues) > 0 && inputFidelityValues[0] != "" {
		req.ImageEditParameters.InputFidelity = &inputFidelityValues[0]
	}
	if partialImagesValues := form.Value["partial_images"]; len(partialImagesValues) > 0 && partialImagesValues[0] != "" {
		partialImages, err := strconv.Atoi(partialImagesValues[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid partial_images value: %v", err)
		}
		req.ImageEditParameters.PartialImages = &partialImages
	}
	if sizeValues := form.Value["size"]; len(sizeValues) > 0 && sizeValues[0] != "" {
		req.ImageEditParameters.Size = &sizeValues[0]
	}
	if qualityValues := form.Value["quality"]; len(qualityValues) > 0 && qualityValues[0] != "" {
		req.ImageEditParameters.Quality = &qualityValues[0]
	}
	if outputFormatValues := form.Value["output_format"]; len(outputFormatValues) > 0 && outputFormatValues[0] != "" {
		req.ImageEditParameters.OutputFormat = &outputFormatValues[0]
	}
	if numInferenceStepsValues := form.Value["num_inference_steps"]; len(numInferenceStepsValues) > 0 && numInferenceStepsValues[0] != "" {
		numInferenceSteps, err := strconv.Atoi(numInferenceStepsValues[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid num_inference_steps value: %v", err)
		}
		req.ImageEditParameters.NumInferenceSteps = &numInferenceSteps
	}
	if seedValues := form.Value["seed"]; len(seedValues) > 0 && seedValues[0] != "" {
		seed, err := strconv.Atoi(seedValues[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid seed value: %v", err)
		}
		req.ImageEditParameters.Seed = &seed
	}
	if outputCompressionValues := form.Value["output_compression"]; len(outputCompressionValues) > 0 && outputCompressionValues[0] != "" {
		outputCompression, err := strconv.Atoi(outputCompressionValues[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid output_compression value: %v", err)
		}
		req.ImageEditParameters.OutputCompression = &outputCompression
	}
	if negativePromptValues := form.Value["negative_prompt"]; len(negativePromptValues) > 0 && negativePromptValues[0] != "" {
		req.ImageEditParameters.NegativePrompt = &negativePromptValues[0]
	}
	if responseFormatValues := form.Value["response_format"]; len(responseFormatValues) > 0 && responseFormatValues[0] != "" {
		req.ImageEditParameters.ResponseFormat = &responseFormatValues[0]
	}
	if userValues := form.Value["user"]; len(userValues) > 0 && userValues[0] != "" {
		req.ImageEditParameters.User = &userValues[0]
	}
	if editType != "" {
		req.ImageEditParameters.Type = &editType
	}
	if maskFiles := form.File["mask"]; len(maskFiles) > 0 {
		maskFile := maskFiles[0]
		f, err := maskFile.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open mask file: %v", err)
		}
		maskData, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read mask file: %v", err)
		}
		req.ImageEditParameters.Mask = maskData
	}
	if req.ImageEditParameters.ExtraParams == nil {
		req.ImageEditParameters.ExtraParams = make(map[string]interface{})
	}
	for key, value := range form.Value {
		if len(value) > 0 && value[0] != "" && !imageEditParamsKnownFields[key] {
			req.ImageEditParameters.ExtraParams[key] = value[0]
		}
	}
	if fallbackValues := form.Value["fallbacks"]; len(fallbackValues) > 0 {
		req.Fallbacks = fallbackValues
	}
	if streamValues := form.Value["stream"]; len(streamValues) > 0 && streamValues[0] != "" {
		stream := streamValues[0] == "true"
		req.Stream = &stream
	}
	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		return nil, nil, err
	}
	deepintshieldReq := &schemas.DeepIntShieldImageEditRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.ImageEditInput,
		Params:    req.ImageEditParameters,
		Fallbacks: fallbacks,
	}
	return &req, deepintshieldReq, nil
}

// imageEdit handles POST /v1/images/edits - Processes image edit requests
func (h *CompletionHandler) imageEdit(ctx *fasthttp.RequestCtx) {
	req, deepintshieldReq, err := prepareImageEditRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	// Handle streaming image edit
	if req.Stream != nil && *req.Stream {
		h.handleStreamingImageEditRequest(ctx, deepintshieldReq, deepintshieldCtx, cancel)
		return
	}
	defer cancel()

	// Execute request
	resp, deepintshieldErr := h.client.ImageEditRequest(deepintshieldCtx, deepintshieldReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// handleStreamingImageEditRequest handles streaming image edit requests using Server-Sent Events (SSE)
func (h *CompletionHandler) handleStreamingImageEditRequest(ctx *fasthttp.RequestCtx, req *schemas.DeepIntShieldImageEditRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// See router.go for detailed explanation of why we need a cancellable context

	getStream := func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
		return h.client.ImageEditStreamRequest(deepintshieldCtx, req)
	}

	h.handleStreamingResponse(ctx, deepintshieldCtx, getStream, cancel)
}

// prepareImageVariationRequest prepares a DeepIntShieldImageVariationRequest from a multipart form
func prepareImageVariationRequest(ctx *fasthttp.RequestCtx) (*schemas.DeepIntShieldImageVariationRequest, error) {
	rawBody := ctx.Request.Body()
	form, err := ctx.MultipartForm()
	if err != nil {
		return nil, fmt.Errorf("failed to parse multipart form: %v", err)
	}
	modelValues := form.Value["model"]
	if len(modelValues) == 0 || modelValues[0] == "" {
		return nil, fmt.Errorf("model is required")
	}
	provider, modelName := resolveModelProvider(modelValues[0])
	if provider == "" || modelName == "" {
		return nil, fmt.Errorf("model should be in provider/model format")
	}
	var imageFiles []*multipart.FileHeader
	if imageFilesArray := form.File["image[]"]; len(imageFilesArray) > 0 {
		imageFiles = imageFilesArray
	} else if imageFilesSingle := form.File["image"]; len(imageFilesSingle) > 0 {
		imageFiles = imageFilesSingle
	}
	if len(imageFiles) == 0 {
		return nil, fmt.Errorf("at least one image is required")
	}
	images := make([][]byte, 0, len(imageFiles))
	for _, fileHeader := range imageFiles {
		file, err := fileHeader.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open uploaded file: %v", err)
		}
		fileData, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read uploaded file: %v", err)
		}
		images = append(images, fileData)
	}
	variationInput := &schemas.ImageVariationInput{
		Image: schemas.ImageInput{
			Image: images[0],
		},
	}
	variationParams := &schemas.ImageVariationParameters{}
	if nValues := form.Value["n"]; len(nValues) > 0 && nValues[0] != "" {
		n, err := strconv.Atoi(nValues[0])
		if err != nil {
			return nil, fmt.Errorf("invalid n value: %v", err)
		}
		variationParams.N = &n
	}
	if responseFormatValues := form.Value["response_format"]; len(responseFormatValues) > 0 && responseFormatValues[0] != "" {
		variationParams.ResponseFormat = &responseFormatValues[0]
	}
	if sizeValues := form.Value["size"]; len(sizeValues) > 0 && sizeValues[0] != "" {
		variationParams.Size = &sizeValues[0]
	}
	if userValues := form.Value["user"]; len(userValues) > 0 && userValues[0] != "" {
		variationParams.User = &userValues[0]
	}
	if variationParams.ExtraParams == nil {
		variationParams.ExtraParams = make(map[string]interface{})
	}
	if len(images) > 1 {
		variationParams.ExtraParams["images"] = images[1:]
	}
	for key, value := range form.Value {
		if len(value) > 0 && value[0] != "" && !imageVariationParamsKnownFields[key] {
			variationParams.ExtraParams[key] = value[0]
		}
	}
	if fallbackValues := form.Value["fallbacks"]; len(fallbackValues) > 0 {
		fallbacks, err := parseFallbacks(fallbackValues)
		if err != nil {
			return nil, err
		}
		return &schemas.DeepIntShieldImageVariationRequest{
			Provider:       schemas.ModelProvider(provider),
			Model:          modelName,
			Input:          variationInput,
			Params:         variationParams,
			Fallbacks:      fallbacks,
			RawRequestBody: rawBody,
		}, nil
	}
	return &schemas.DeepIntShieldImageVariationRequest{
		Provider:       schemas.ModelProvider(provider),
		Model:          modelName,
		Input:          variationInput,
		Params:         variationParams,
		RawRequestBody: rawBody,
	}, nil
}

// imageVariation handles POST /v1/images/variations - Processes image variation requests
func (h *CompletionHandler) imageVariation(ctx *fasthttp.RequestCtx) {
	deepintshieldReq, err := prepareImageVariationRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	// Execute request (no streaming for variations)
	resp, deepintshieldErr := h.client.ImageVariationRequest(deepintshieldCtx, deepintshieldReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// videoGeneration handles POST /v1/videos - Processes video generation requests
func (h *CompletionHandler) videoGeneration(ctx *fasthttp.RequestCtx) {
	var req VideoGenerationRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Create DeepIntShieldVideoGenerationRequest directly using segregated structure
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" || modelName == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "model should be in provider/model format")
		return
	}

	fallbacks, err := parseFallbacks(req.Fallbacks)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.VideoGenerationInput == nil || req.Prompt == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "prompt cannot be empty")
		return
	}

	if req.VideoGenerationParameters == nil {
		req.VideoGenerationParameters = &schemas.VideoGenerationParameters{}
	}

	extraParams, err := extractExtraParams(ctx.PostBody(), videoGenerationParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.VideoGenerationParameters.ExtraParams = extraParams
	}

	deepintshieldReq := &schemas.DeepIntShieldVideoGenerationRequest{
		Provider:  schemas.ModelProvider(provider),
		Model:     modelName,
		Input:     req.VideoGenerationInput,
		Params:    req.VideoGenerationParameters,
		Fallbacks: fallbacks,
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		cancel()
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	resp, deepintshieldErr := h.client.VideoGenerationRequest(deepintshieldCtx, deepintshieldReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// videoRetrieve handles GET /v1/videos/{video_id} - Retrieve a video generation job
func (h *CompletionHandler) videoRetrieve(ctx *fasthttp.RequestCtx) {
	// Get video ID from URL parameter
	videoID, ok := ctx.UserValue("video_id").(string)
	if !ok || videoID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id is required")
		return
	}

	// Decode URL-encoded video ID
	decodedID, err := url.PathUnescape(videoID)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "invalid video_id encoding")
		return
	}
	idParts := strings.SplitN(decodedID, ":", 2)
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id must be in id:provider format")
		return
	}

	provider := schemas.ModelProvider(idParts[1])

	// Build DeepIntShield video retrieve request
	deepintshieldVideoReq := &schemas.DeepIntShieldVideoRetrieveRequest{
		Provider: provider,
		ID:       idParts[0],
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.VideoRetrieveRequest(deepintshieldCtx, deepintshieldVideoReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// videoDownload handles GET /v1/videos/{video_id}/content - Download video content
func (h *CompletionHandler) videoDownload(ctx *fasthttp.RequestCtx) {
	// Get video ID from URL parameter
	videoID, ok := ctx.UserValue("video_id").(string)
	if !ok || videoID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id is required")
		return
	}

	// Decode URL-encoded video ID
	decodedID, err := url.PathUnescape(videoID)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "invalid video_id encoding")
		return
	}
	idParts := strings.SplitN(decodedID, ":", 2)
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id must be in id:provider format")
		return
	}

	// take variant from query parameters
	variant := string(ctx.QueryArgs().Peek("variant"))

	// Build DeepIntShield video download request
	deepintshieldVideoReq := &schemas.DeepIntShieldVideoDownloadRequest{
		Provider: schemas.ModelProvider(idParts[1]),
		ID:       idParts[0],
	}

	if variant != "" {
		deepintshieldVideoReq.Variant = schemas.Ptr(schemas.VideoDownloadVariant(variant))
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.VideoDownloadRequest(deepintshieldCtx, deepintshieldVideoReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}

	// Set appropriate headers for binary download
	ctx.Response.Header.Set("Content-Type", resp.ContentType)
	ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(resp.Content)))
	ctx.Response.SetBody(resp.Content)
}

// videoList handles GET /v1/videos - List video generation jobs
func (h *CompletionHandler) videoList(ctx *fasthttp.RequestCtx) {
	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield video list request
	deepintshieldVideoReq := &schemas.DeepIntShieldVideoListRequest{
		Provider: schemas.ModelProvider(provider),
	}

	// Parse optional query parameters
	if afterBytes := ctx.QueryArgs().Peek("after"); len(afterBytes) > 0 {
		after := string(afterBytes)
		deepintshieldVideoReq.After = &after
	}

	if limitBytes := ctx.QueryArgs().Peek("limit"); len(limitBytes) > 0 {
		limit, err := strconv.Atoi(string(limitBytes))
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, "invalid limit parameter")
			return
		}
		deepintshieldVideoReq.Limit = &limit
	}

	if orderBytes := ctx.QueryArgs().Peek("order"); len(orderBytes) > 0 {
		order := string(orderBytes)
		deepintshieldVideoReq.Order = &order
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.VideoListRequest(deepintshieldCtx, deepintshieldVideoReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// videoDelete handles DELETE /v1/videos/{video_id} - Delete a video generation job
func (h *CompletionHandler) videoDelete(ctx *fasthttp.RequestCtx) {
	// Get video ID from URL parameter
	videoID, ok := ctx.UserValue("video_id").(string)
	if !ok || videoID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id is required")
		return
	}

	// Decode URL-encoded video ID
	decodedID, err := url.PathUnescape(videoID)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "invalid video_id encoding")
		return
	}
	idParts := strings.SplitN(decodedID, ":", 2)
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id must be in id:provider format")
		return
	}

	// Build DeepIntShield video delete request
	deepintshieldVideoReq := &schemas.DeepIntShieldVideoDeleteRequest{
		Provider: schemas.ModelProvider(idParts[1]),
		ID:       idParts[0],
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.VideoDeleteRequest(deepintshieldCtx, deepintshieldVideoReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// videoRemix handles POST /v1/videos/{video_id}/remix - Remix an existing video
func (h *CompletionHandler) videoRemix(ctx *fasthttp.RequestCtx) {
	// Get video ID from URL parameter
	videoID, ok := ctx.UserValue("video_id").(string)
	if !ok || videoID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id is required")
		return
	}

	// Decode URL-encoded video ID
	decodedID, err := url.PathUnescape(videoID)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "invalid video_id encoding")
		return
	}
	idParts := strings.SplitN(decodedID, ":", 2)
	if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "video_id must be in id:provider format")
		return
	}

	// Parse request body
	var req VideoRemixRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Validate prompt
	if req.VideoGenerationInput == nil || req.VideoGenerationInput.Prompt == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "prompt is required")
		return
	}

	provider := schemas.ModelProvider(idParts[1])

	extraParams, err := extractExtraParams(ctx.PostBody(), videoRemixParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	} else {
		req.ExtraParams = extraParams
	}

	// Build DeepIntShield video remix request
	deepintshieldVideoReq := &schemas.DeepIntShieldVideoRemixRequest{
		Provider: provider,
		ID:       idParts[0],
		Input: &schemas.VideoGenerationInput{
			Prompt: req.VideoGenerationInput.Prompt,
		},
		ExtraParams: req.ExtraParams,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.VideoRemixRequest(deepintshieldCtx, deepintshieldVideoReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// batchCreate handles POST /v1/batches - Create a new batch job
func (h *CompletionHandler) batchCreate(ctx *fasthttp.RequestCtx) {
	var req BatchCreateRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Parse provider from model string
	provider, modelName := resolveModelProvider(req.Model)
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "model should be in provider/model format or provider must be specified")
		return
	}

	// Validate that at least one of InputFileID or Requests is provided
	if req.InputFileID == "" && len(req.Requests) == 0 {
		SendError(ctx, fasthttp.StatusBadRequest, "either input_file_id or requests is required")
		return
	}

	// Extract extra params
	extraParams, err := extractExtraParams(ctx.PostBody(), batchCreateParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	}

	var model *string
	if modelName != "" {
		model = schemas.Ptr(modelName)
	}

	// Build DeepIntShield batch create request
	deepintshieldBatchReq := &schemas.DeepIntShieldBatchCreateRequest{
		Provider:         schemas.ModelProvider(provider),
		Model:            model,
		InputFileID:      req.InputFileID,
		Requests:         req.Requests,
		Endpoint:         schemas.BatchEndpoint(req.Endpoint),
		CompletionWindow: req.CompletionWindow,
		Metadata:         req.Metadata,
		ExtraParams:      extraParams,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.BatchCreateRequest(deepintshieldCtx, deepintshieldBatchReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// batchList handles GET /v1/batches - List batch jobs
func (h *CompletionHandler) batchList(ctx *fasthttp.RequestCtx) {
	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Parse limit parameter
	limit := 0
	if limitStr := ctx.QueryArgs().Peek("limit"); len(limitStr) > 0 {
		if n, err := strconv.Atoi(string(limitStr)); err == nil && n > 0 {
			limit = n
		}
	}

	// Parse pagination parameters
	var after, before *string
	if afterStr := ctx.QueryArgs().Peek("after"); len(afterStr) > 0 {
		s := string(afterStr)
		after = &s
	}
	if beforeStr := ctx.QueryArgs().Peek("before"); len(beforeStr) > 0 {
		s := string(beforeStr)
		before = &s
	}

	// Build DeepIntShield batch list request
	deepintshieldBatchReq := &schemas.DeepIntShieldBatchListRequest{
		Provider: schemas.ModelProvider(provider),
		Limit:    limit,
		After:    after,
		BeforeID: before,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.BatchListRequest(deepintshieldCtx, deepintshieldBatchReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// batchRetrieve handles GET /v1/batches/{batch_id} - Retrieve a batch job
func (h *CompletionHandler) batchRetrieve(ctx *fasthttp.RequestCtx) {
	// Get batch ID from URL parameter
	batchID, ok := ctx.UserValue("batch_id").(string)
	if !ok || batchID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "batch_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield batch retrieve request
	deepintshieldBatchReq := &schemas.DeepIntShieldBatchRetrieveRequest{
		Provider: schemas.ModelProvider(provider),
		BatchID:  batchID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.BatchRetrieveRequest(deepintshieldCtx, deepintshieldBatchReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// batchCancel handles POST /v1/batches/{batch_id}/cancel - Cancel a batch job
func (h *CompletionHandler) batchCancel(ctx *fasthttp.RequestCtx) {
	// Get batch ID from URL parameter
	batchID := ctx.UserValue("batch_id").(string)
	if batchID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "batch_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield batch cancel request
	deepintshieldBatchReq := &schemas.DeepIntShieldBatchCancelRequest{
		Provider: schemas.ModelProvider(provider),
		BatchID:  batchID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.BatchCancelRequest(deepintshieldCtx, deepintshieldBatchReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// batchResults handles GET /v1/batches/{batch_id}/results - Get batch results
func (h *CompletionHandler) batchResults(ctx *fasthttp.RequestCtx) {
	// Get batch ID from URL parameter
	batchID := ctx.UserValue("batch_id").(string)
	if batchID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "batch_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield batch results request
	deepintshieldBatchReq := &schemas.DeepIntShieldBatchResultsRequest{
		Provider: schemas.ModelProvider(provider),
		BatchID:  batchID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.BatchResultsRequest(deepintshieldCtx, deepintshieldBatchReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// fileUpload handles POST /v1/files - Upload a file
func (h *CompletionHandler) fileUpload(ctx *fasthttp.RequestCtx) {
	// Parse multipart form
	form, err := ctx.MultipartForm()
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Failed to parse multipart form: %v", err))
		return
	}

	// Get provider from query parameters or header
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		// Try to get from header (for OpenAI SDK compatibility)
		provider = string(ctx.Request.Header.Peek("x-model-provider"))
		// Try to get from extra_body
		if provider == "" && len(form.Value["provider"]) > 0 {
			provider = string(form.Value["provider"][0])
		}
	}

	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter or x-model-provider header is required")
		return
	}

	// Extract purpose (required)
	purposeValues := form.Value["purpose"]
	if len(purposeValues) == 0 || purposeValues[0] == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "purpose is required")
		return
	}
	purpose := purposeValues[0]

	// Extract file (required)
	fileHeaders := form.File["file"]
	if len(fileHeaders) == 0 {
		SendError(ctx, fasthttp.StatusBadRequest, "file is required")
		return
	}

	fileHeader := fileHeaders[0]

	// Open and read the file
	file, err := fileHeader.Open()
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Internal Server Error")
		return
	}
	defer file.Close()

	// Read file data
	fileData, err := io.ReadAll(file)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Build DeepIntShield file upload request
	deepintshieldFileReq := &schemas.DeepIntShieldFileUploadRequest{
		Provider: schemas.ModelProvider(provider),
		File:     fileData,
		Filename: fileHeader.Filename,
		Purpose:  schemas.FilePurpose(purpose),
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.FileUploadRequest(deepintshieldCtx, deepintshieldFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// fileList handles GET /v1/files - List files
func (h *CompletionHandler) fileList(ctx *fasthttp.RequestCtx) {
	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("x-model-provider"))
	if provider == "" {
		// Try to get from header
		provider = string(ctx.Request.Header.Peek("x-model-provider"))
		if provider == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "x-model-provider query parameter or x-model-provider header is required")
			return
		}
	}

	// Parse optional parameters
	purpose := string(ctx.QueryArgs().Peek("purpose"))

	limit := 0
	if limitStr := ctx.QueryArgs().Peek("limit"); len(limitStr) > 0 {
		if n, err := strconv.Atoi(string(limitStr)); err == nil && n > 0 {
			limit = n
		}
	}

	var after, order *string
	if afterStr := ctx.QueryArgs().Peek("after"); len(afterStr) > 0 {
		s := string(afterStr)
		after = &s
	}
	if orderStr := ctx.QueryArgs().Peek("order"); len(orderStr) > 0 {
		s := string(orderStr)
		order = &s
	}

	// Build DeepIntShield file list request
	deepintshieldFileReq := &schemas.DeepIntShieldFileListRequest{
		Provider: schemas.ModelProvider(provider),
		Purpose:  schemas.FilePurpose(purpose),
		Limit:    limit,
		After:    after,
		Order:    order,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.FileListRequest(deepintshieldCtx, deepintshieldFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// fileRetrieve handles GET /v1/files/{file_id} - Retrieve file metadata
func (h *CompletionHandler) fileRetrieve(ctx *fasthttp.RequestCtx) {
	// Get file ID from URL parameter
	fileID := ctx.UserValue("file_id").(string)
	if fileID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "file_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield file retrieve request
	deepintshieldFileReq := &schemas.DeepIntShieldFileRetrieveRequest{
		Provider: schemas.ModelProvider(provider),
		FileID:   fileID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.FileRetrieveRequest(deepintshieldCtx, deepintshieldFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// fileDelete handles DELETE /v1/files/{file_id} - Delete a file
func (h *CompletionHandler) fileDelete(ctx *fasthttp.RequestCtx) {
	// Get file ID from URL parameter
	fileID := ctx.UserValue("file_id").(string)
	if fileID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "file_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield file delete request
	deepintshieldFileReq := &schemas.DeepIntShieldFileDeleteRequest{
		Provider: schemas.ModelProvider(provider),
		FileID:   fileID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.FileDeleteRequest(deepintshieldCtx, deepintshieldFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// fileContent handles GET /v1/files/{file_id}/content - Download file content
func (h *CompletionHandler) fileContent(ctx *fasthttp.RequestCtx) {
	// Get file ID from URL parameter
	fileID := ctx.UserValue("file_id").(string)
	if fileID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "file_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield file content request
	deepintshieldFileReq := &schemas.DeepIntShieldFileContentRequest{
		Provider: schemas.ModelProvider(provider),
		FileID:   fileID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}

	resp, deepintshieldErr := h.client.FileContentRequest(deepintshieldCtx, deepintshieldFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}

	// Set appropriate headers for file download
	ctx.Response.Header.Set("Content-Type", resp.ContentType)
	ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(resp.Content)))
	ctx.Response.SetBody(resp.Content)
}

// containerCreate handles POST /v1/containers - Create a new container
func (h *CompletionHandler) containerCreate(ctx *fasthttp.RequestCtx) {
	var req ContainerCreateRequest
	if err := sonic.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Validate required fields
	if req.Provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider is required")
		return
	}

	if req.Name == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "name is required")
		return
	}

	// Extract extra params
	extraParams, err := extractExtraParams(ctx.PostBody(), containerCreateParamsKnownFields)
	if err != nil {
		logger.Warn("Failed to extract extra params: %v", err)
	}

	// Build DeepIntShield container create request
	deepintshieldContainerReq := &schemas.DeepIntShieldContainerCreateRequest{
		Provider:     schemas.ModelProvider(req.Provider),
		Name:         req.Name,
		ExpiresAfter: req.ExpiresAfter,
		FileIDs:      req.FileIDs,
		MemoryLimit:  req.MemoryLimit,
		Metadata:     req.Metadata,
		ExtraParams:  extraParams,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerCreateRequest(deepintshieldCtx, deepintshieldContainerReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// containerList handles GET /v1/containers - List containers
func (h *CompletionHandler) containerList(ctx *fasthttp.RequestCtx) {
	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Parse limit parameter
	limit := 0
	if limitStr := ctx.QueryArgs().Peek("limit"); len(limitStr) > 0 {
		if n, err := strconv.Atoi(string(limitStr)); err == nil && n > 0 {
			limit = n
		}
	}

	// Parse pagination parameters
	var after, order *string
	if afterStr := ctx.QueryArgs().Peek("after"); len(afterStr) > 0 {
		after = deepintshield.Ptr(string(afterStr))
	}
	if orderStr := ctx.QueryArgs().Peek("order"); len(orderStr) > 0 {
		order = deepintshield.Ptr(string(orderStr))
	}

	// Build DeepIntShield container list request
	deepintshieldContainerReq := &schemas.DeepIntShieldContainerListRequest{
		Provider: schemas.ModelProvider(provider),
		Limit:    limit,
		After:    after,
		Order:    order,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerListRequest(deepintshieldCtx, deepintshieldContainerReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// containerRetrieve handles GET /v1/containers/{container_id} - Retrieve a container
func (h *CompletionHandler) containerRetrieve(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container retrieve request
	deepintshieldContainerReq := &schemas.DeepIntShieldContainerRetrieveRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerRetrieveRequest(deepintshieldCtx, deepintshieldContainerReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// containerDelete handles DELETE /v1/containers/{container_id} - Delete a container
func (h *CompletionHandler) containerDelete(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container delete request
	deepintshieldContainerReq := &schemas.DeepIntShieldContainerDeleteRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerDeleteRequest(deepintshieldCtx, deepintshieldContainerReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// =============================================================================
// CONTAINER FILES HANDLERS
// =============================================================================

// containerFileCreate handles POST /v1/containers/{container_id}/files - Create a file in a container
func (h *CompletionHandler) containerFileCreate(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container file create request
	deepintshieldContainerFileReq := &schemas.DeepIntShieldContainerFileCreateRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
	}

	// Check if this is a multipart request or JSON request
	contentType := string(ctx.Request.Header.ContentType())
	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Handle multipart file upload
		fileHeader, err := ctx.FormFile("file")
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, "file is required for multipart upload")
			return
		}
		file, err := fileHeader.Open()
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Internal Server Error")
			return
		}
		defer file.Close()

		fileContent, err := io.ReadAll(file)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Internal Server Error")
			return
		}
		deepintshieldContainerFileReq.File = fileContent
		// Extract optional file_path from multipart form
		if filePath := ctx.FormValue("file_path"); len(filePath) > 0 {
			deepintshieldContainerFileReq.Path = deepintshield.Ptr(string(filePath))
		}
	} else {
		// Handle JSON request with file_id
		var reqBody struct {
			FileID   string `json:"file_id"`
			FilePath string `json:"file_path,omitempty"`
		}
		if err := sonic.Unmarshal(ctx.PostBody(), &reqBody); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, "Invalid JSON body")
			return
		}
		if reqBody.FileID == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "file_id is required in JSON body")
			return
		}
		deepintshieldContainerFileReq.FileID = deepintshield.Ptr(reqBody.FileID)
		if reqBody.FilePath != "" {
			deepintshieldContainerFileReq.Path = deepintshield.Ptr(reqBody.FilePath)
		}
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerFileCreateRequest(deepintshieldCtx, deepintshieldContainerFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// containerFileList handles GET /v1/containers/{container_id}/files - List files in a container
func (h *CompletionHandler) containerFileList(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container file list request
	deepintshieldContainerFileReq := &schemas.DeepIntShieldContainerFileListRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
	}

	// Parse pagination parameters
	if limit := ctx.QueryArgs().Peek("limit"); len(limit) > 0 {
		if limitInt, err := strconv.Atoi(string(limit)); err == nil && limitInt > 0 {
			deepintshieldContainerFileReq.Limit = limitInt
		}
	}
	if after := string(ctx.QueryArgs().Peek("after")); after != "" {
		deepintshieldContainerFileReq.After = deepintshield.Ptr(after)
	}
	if order := string(ctx.QueryArgs().Peek("order")); order != "" {
		deepintshieldContainerFileReq.Order = deepintshield.Ptr(order)
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerFileListRequest(deepintshieldCtx, deepintshieldContainerFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// containerFileRetrieve handles GET /v1/containers/{container_id}/files/{file_id} - Retrieve a file from a container
func (h *CompletionHandler) containerFileRetrieve(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get file ID from URL parameter
	fileID, ok := ctx.UserValue("file_id").(string)
	if !ok || fileID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "file_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container file retrieve request
	deepintshieldContainerFileReq := &schemas.DeepIntShieldContainerFileRetrieveRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
		FileID:      fileID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerFileRetrieveRequest(deepintshieldCtx, deepintshieldContainerFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}

// containerFileContent handles GET /v1/containers/{container_id}/files/{file_id}/content - Retrieve file content from a container
func (h *CompletionHandler) containerFileContent(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get file ID from URL parameter
	fileID, ok := ctx.UserValue("file_id").(string)
	if !ok || fileID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "file_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container file content request
	deepintshieldContainerFileReq := &schemas.DeepIntShieldContainerFileContentRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
		FileID:      fileID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerFileContentRequest(deepintshieldCtx, deepintshieldContainerFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}

	// Send binary content with appropriate content type
	ctx.SetContentType(resp.ContentType)
	ctx.SetBody(resp.Content)
}

// containerFileDelete handles DELETE /v1/containers/{container_id}/files/{file_id} - Delete a file from a container
func (h *CompletionHandler) containerFileDelete(ctx *fasthttp.RequestCtx) {
	// Get container ID from URL parameter
	containerID, ok := ctx.UserValue("container_id").(string)
	if !ok || containerID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "container_id is required")
		return
	}

	// Get file ID from URL parameter
	fileID, ok := ctx.UserValue("file_id").(string)
	if !ok || fileID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "file_id is required")
		return
	}

	// Get provider from query parameters
	provider := string(ctx.QueryArgs().Peek("provider"))
	if provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "provider query parameter is required")
		return
	}

	// Build DeepIntShield container file delete request
	deepintshieldContainerFileReq := &schemas.DeepIntShieldContainerFileDeleteRequest{
		Provider:    schemas.ModelProvider(provider),
		ContainerID: containerID,
		FileID:      fileID,
	}

	// Convert context
	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	defer cancel()
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	enableRawRequestResponseForContainer(deepintshieldCtx)

	resp, deepintshieldErr := h.client.ContainerFileDeleteRequest(deepintshieldCtx, deepintshieldContainerFileReq)
	if deepintshieldErr != nil {
		forwardProviderHeadersFromContext(ctx, deepintshieldCtx)
		SendDeepIntShieldError(ctx, deepintshieldErr)
		return
	}

	if resp != nil && resp.ExtraFields.ProviderResponseHeaders != nil {
		forwardProviderHeaders(ctx, resp.ExtraFields.ProviderResponseHeaders)
	}
	if streamLargeResponseIfActive(ctx, deepintshieldCtx) {
		return
	}
	SendJSON(ctx, resp)
}
