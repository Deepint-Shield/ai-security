package handlers

import (
	"fmt"
	"strconv"

	"github.com/fasthttp/router"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/valyala/fasthttp"
)

// --- HTTP Handler ---

// AsyncHandler handles async job HTTP endpoints.
type AsyncHandler struct {
	client       *deepintshield.DeepIntShield
	executor     *logstore.AsyncJobExecutor
	handlerStore lib.HandlerStore
	config       *lib.Config
}

// AsyncPathToTypeMapping maps exact paths to request types (only for non-parameterized paths)
// Parameterized paths are set per-route in RegisterRoutes
var AsyncPathToTypeMapping = map[string]schemas.RequestType{
	"/v1/async/completions":          schemas.TextCompletionRequest,
	"/v1/async/chat/completions":     schemas.ChatCompletionRequest,
	"/v1/async/responses":            schemas.ResponsesRequest,
	"/v1/async/embeddings":           schemas.EmbeddingRequest,
	"/v1/async/audio/speech":         schemas.SpeechRequest,
	"/v1/async/audio/transcriptions": schemas.TranscriptionRequest,
	"/v1/async/images/generations":   schemas.ImageGenerationRequest,
	"/v1/async/images/edits":         schemas.ImageEditRequest,
	"/v1/async/images/variations":    schemas.ImageVariationRequest,
	"/v1/async/rerank":               schemas.RerankRequest,
}

// RegisterAsyncRequestTypeMiddleware handles exact path matching for non-parameterized routes
func RegisterAsyncRequestTypeMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())
		if requestType, ok := AsyncPathToTypeMapping[path]; ok {
			ctx.SetUserValue(schemas.DeepIntShieldContextKeyHTTPRequestType, requestType)
		}
		next(ctx)
	}
}

// NewAsyncHandler creates a new AsyncHandler.
// If the async job executor is not available (e.g., LogsStore or governance plugin not configured),
// the handler is created with a nil executor and RegisterRoutes will skip async route registration.
func NewAsyncHandler(client *deepintshield.DeepIntShield, config *lib.Config) *AsyncHandler {
	return &AsyncHandler{
		client:       client,
		executor:     config.GetAsyncJobExecutor(),
		handlerStore: config,
		config:       config,
	}
}

// RegisterRoutes registers async job endpoints.
func (h *AsyncHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	if h.executor == nil {
		return // LogStore not configured, skip async routes
	}

	baseMiddlewares := append([]schemas.DeepIntShieldHTTPMiddleware{RegisterAsyncRequestTypeMiddleware}, middlewares...)

	// Async submission endpoints (non-parameterized, request type set via AsyncPathToTypeMapping)
	r.POST("/v1/async/completions", lib.ChainMiddlewares(h.asyncTextCompletion, baseMiddlewares...))
	r.POST("/v1/async/chat/completions", lib.ChainMiddlewares(h.asyncChatCompletion, baseMiddlewares...))
	r.POST("/v1/async/responses", lib.ChainMiddlewares(h.asyncResponses, baseMiddlewares...))
	r.POST("/v1/async/embeddings", lib.ChainMiddlewares(h.asyncEmbeddings, baseMiddlewares...))
	r.POST("/v1/async/audio/speech", lib.ChainMiddlewares(h.asyncSpeech, baseMiddlewares...))
	r.POST("/v1/async/audio/transcriptions", lib.ChainMiddlewares(h.asyncTranscription, baseMiddlewares...))
	r.POST("/v1/async/images/generations", lib.ChainMiddlewares(h.asyncImageGeneration, baseMiddlewares...))
	r.POST("/v1/async/images/edits", lib.ChainMiddlewares(h.asyncImageEdit, baseMiddlewares...))
	r.POST("/v1/async/images/variations", lib.ChainMiddlewares(h.asyncImageVariation, baseMiddlewares...))
	r.POST("/v1/async/rerank", lib.ChainMiddlewares(h.asyncRerank, baseMiddlewares...))

	// Async job retrieval endpoints
	r.GET("/v1/async/completions/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.TextCompletionRequest), middlewares...))
	r.GET("/v1/async/chat/completions/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.ChatCompletionRequest), middlewares...))
	r.GET("/v1/async/responses/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.ResponsesRequest), middlewares...))
	r.GET("/v1/async/embeddings/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.EmbeddingRequest), middlewares...))
	r.GET("/v1/async/audio/speech/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.SpeechRequest), middlewares...))
	r.GET("/v1/async/audio/transcriptions/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.TranscriptionRequest), middlewares...))
	r.GET("/v1/async/images/generations/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.ImageGenerationRequest), middlewares...))
	r.GET("/v1/async/images/edits/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.ImageEditRequest), middlewares...))
	r.GET("/v1/async/images/variations/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.ImageVariationRequest), middlewares...))
	r.GET("/v1/async/rerank/{job_id}", lib.ChainMiddlewares(h.getJob(schemas.RerankRequest), middlewares...))
}

// --- Async submission handlers ---

// asyncTextCompletion handles POST /v1/async/completions
func (h *AsyncHandler) asyncTextCompletion(ctx *fasthttp.RequestCtx) {
	req, deepintshieldTextReq, err := prepareTextCompletionRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.Stream != nil && *req.Stream {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async text completions")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.TextCompletionRequest(bgCtx, deepintshieldTextReq)
		},
		schemas.TextCompletionRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncChatCompletion handles POST /v1/async/chat/completions
func (h *AsyncHandler) asyncChatCompletion(ctx *fasthttp.RequestCtx) {
	req, deepintshieldChatReq, err := prepareChatCompletionRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.Stream != nil && *req.Stream {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async chat completions")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.ChatCompletionRequest(bgCtx, deepintshieldChatReq)
		},
		schemas.ChatCompletionRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncResponses handles POST /v1/async/responses
func (h *AsyncHandler) asyncResponses(ctx *fasthttp.RequestCtx) {
	req, deepintshieldResponsesReq, err := prepareResponsesRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.Stream != nil && *req.Stream {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async responses")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.ResponsesRequest(bgCtx, deepintshieldResponsesReq)
		},
		schemas.ResponsesRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Failed to create async job: %v", err))
		return
	}

	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncEmbeddings handles POST /v1/async/embeddings
func (h *AsyncHandler) asyncEmbeddings(ctx *fasthttp.RequestCtx) {
	_, deepintshieldEmbeddingReq, err := prepareEmbeddingRequest(ctx)
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

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.EmbeddingRequest(bgCtx, deepintshieldEmbeddingReq)
		},
		schemas.EmbeddingRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncSpeech handles POST /v1/async/audio/speech
func (h *AsyncHandler) asyncSpeech(ctx *fasthttp.RequestCtx) {
	req, deepintshieldSpeechReq, err := prepareSpeechRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.StreamFormat != nil && *req.StreamFormat == "sse" {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async speech")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.SpeechRequest(bgCtx, deepintshieldSpeechReq)
		},
		schemas.SpeechRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncTranscription handles POST /v1/async/audio/transcriptions
func (h *AsyncHandler) asyncTranscription(ctx *fasthttp.RequestCtx) {
	deepintshieldTranscriptionReq, stream, err := prepareTranscriptionRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if stream {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async transcriptions")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.TranscriptionRequest(bgCtx, deepintshieldTranscriptionReq)
		},
		schemas.TranscriptionRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncImageGeneration handles POST /v1/async/images/generations
func (h *AsyncHandler) asyncImageGeneration(ctx *fasthttp.RequestCtx) {
	req, deepintshieldReq, err := prepareImageGenerationRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.DeepIntShieldParams.Stream != nil && *req.DeepIntShieldParams.Stream {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async image generations")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.ImageGenerationRequest(bgCtx, deepintshieldReq)
		},
		schemas.ImageGenerationRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncImageEdit handles POST /v1/async/images/edits
func (h *AsyncHandler) asyncImageEdit(ctx *fasthttp.RequestCtx) {
	req, deepintshieldReq, err := prepareImageEditRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	if req.Stream != nil && *req.Stream {
		SendError(ctx, fasthttp.StatusBadRequest, "stream is not supported for async image edits")
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.ImageEditRequest(bgCtx, deepintshieldReq)
		},
		schemas.ImageEditRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncImageVariation handles POST /v1/async/images/variations
func (h *AsyncHandler) asyncImageVariation(ctx *fasthttp.RequestCtx) {
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

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.ImageVariationRequest(bgCtx, deepintshieldReq)
		},
		schemas.ImageVariationRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// asyncRerank handles POST /v1/async/rerank
func (h *AsyncHandler) asyncRerank(ctx *fasthttp.RequestCtx) {
	_, deepintshieldReq, err := prepareRerankRequest(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
	if deepintshieldCtx == nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to convert context")
		return
	}
	defer cancel()

	virtualKeyValue := getVirtualKeyFromContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, h.config.ClientConfig.AsyncJobResultTTL)

	job, err := h.executor.SubmitJob(
		deepintshieldCtx,
		virtualKeyValue,
		resultTTL,
		func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
			return h.client.RerankRequest(bgCtx, deepintshieldReq)
		},
		schemas.RerankRequest,
	)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}
	SendJSONWithStatus(ctx, job.ToResponse(), fasthttp.StatusAccepted)
}

// --- Job retrieval handler ---

// getJob handles GET /v1/async/{type}/{job_id}
func (h *AsyncHandler) getJob(operationType schemas.RequestType) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		jobID, ok := ctx.UserValue("job_id").(string)
		if !ok || jobID == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "job_id is required")
			return
		}

		// Get the requesting user's VK for auth check
		deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, h.handlerStore.ShouldAllowDirectKeys(), h.config.GetHeaderMatcher())
		if deepintshieldCtx == nil {
			SendError(ctx, fasthttp.StatusBadRequest, "Failed to convert context")
			return
		}
		defer cancel()

		job, err := h.executor.RetrieveJob(deepintshieldCtx, jobID, getVirtualKeyFromContext(deepintshieldCtx), operationType)
		if err != nil {
			SendError(ctx, fasthttp.StatusNotFound, err.Error())
			return
		}

		resp := job.ToResponse()

		// Return 202 for pending/processing, 200 for completed/failed
		switch job.Status {
		case schemas.AsyncJobStatusPending, schemas.AsyncJobStatusProcessing:
			SendJSONWithStatus(ctx, resp, fasthttp.StatusAccepted)
		default:
			SendJSON(ctx, resp)
		}
	}
}

// --- Helper functions ---

// getVirtualKeyFromContext extracts the virtual key value from context.
// Returns nil if no VK is present (e.g., direct key mode or no governance).
func getVirtualKeyFromContext(ctx *schemas.DeepIntShieldContext) *string {
	vkValue := deepintshield.GetStringFromContext(ctx, schemas.DeepIntShieldContextKeyVirtualKey)
	if vkValue == "" {
		return nil
	}
	return &vkValue
}

func getResultTTLFromHeaderWithDefault(ctx *fasthttp.RequestCtx, defaultTTL int) int {
	resultTTL := string(ctx.Request.Header.Peek(schemas.AsyncHeaderResultTTL))
	if resultTTL == "" {
		return defaultTTL
	}
	resultTTLInt, err := strconv.Atoi(resultTTL)
	if err != nil || resultTTLInt < 0 {
		return defaultTTL
	}
	return resultTTLInt
}
