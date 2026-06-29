// Package integrations provides a generic router framework for handling different LLM provider APIs.
//
// CENTRALIZED STREAMING ARCHITECTURE:
//
// This package implements a centralized streaming approach where all stream handling logic
// is consolidated in the GenericRouter, eliminating the need for provider-specific StreamHandler
// implementations. The key components are:
//
// 1. StreamConfig: Defines streaming configuration for each route, including:
//   - ResponseConverter: Converts DeepIntShieldResponse to provider-specific streaming format
//   - ErrorConverter: Converts DeepIntShieldError to provider-specific streaming error format
//
// 2. Centralized Stream Processing: The GenericRouter handles all streaming logic:
//   - SSE header management
//   - Stream channel processing
//   - Error handling and conversion
//   - Response formatting and flushing
//   - Stream closure (handled automatically by provider implementation)
//
// 3. Provider-Specific Type Conversion: Integration types.go files only handle type conversion:
//   - Derive{Provider}StreamFromDeepIntShieldResponse: Convert responses to streaming format
//   - Derive{Provider}StreamFromDeepIntShieldError: Convert errors to streaming error format
//
// BENEFITS:
// - Eliminates code duplication across provider-specific stream handlers
// - Centralizes streaming logic for consistency and maintainability
// - Separates concerns: routing logic vs type conversion
// - Automatic stream closure management by provider implementations
// - Consistent error handling across all providers
//
// USAGE EXAMPLE:
//
//	routes := []RouteConfig{
//	  {
//	    Path: "/openai/chat/completions",
//	    Method: "POST",
//	    // ... other configs ...
//	    StreamConfig: &StreamConfig{
//	      ResponseConverter: func(resp *schemas.DeepIntShieldResponse) (interface{}, error) {
//	        return DeriveOpenAIStreamFromDeepIntShieldResponse(resp), nil
//	      },
//	      ErrorConverter: func(err *schemas.DeepIntShieldError) interface{} {
//	        return DeriveOpenAIStreamFromDeepIntShieldError(err)
//	      },
//	    },
//	  },
//	}
package integrations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/bytedance/sonic"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/providers/bedrock"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

// ExtensionRouter defines the interface that all integration routers must implement
// to register their routes with the main HTTP router.
type ExtensionRouter interface {
	RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware)
}

// StreamingRequest interface for requests that support streaming
type StreamingRequest interface {
	IsStreamingRequested() bool
}

// RequestWithSettableExtraParams is implemented by request types that accept
// provider-specific extra parameters via the extra_params JSON key. The
// integration router extracts extra_params from the raw request body and
// passes them through so they propagate to the downstream provider.
type RequestWithSettableExtraParams interface {
	SetExtraParams(params map[string]interface{})
}

// BatchRequest wraps a DeepIntShield batch request with its type information.
type BatchRequest struct {
	Type            schemas.RequestType
	CreateRequest   *schemas.DeepIntShieldBatchCreateRequest
	ListRequest     *schemas.DeepIntShieldBatchListRequest
	RetrieveRequest *schemas.DeepIntShieldBatchRetrieveRequest
	CancelRequest   *schemas.DeepIntShieldBatchCancelRequest
	DeleteRequest   *schemas.DeepIntShieldBatchDeleteRequest
	ResultsRequest  *schemas.DeepIntShieldBatchResultsRequest
}

// FileRequest wraps a DeepIntShield file request with its type information.
type FileRequest struct {
	Type            schemas.RequestType
	UploadRequest   *schemas.DeepIntShieldFileUploadRequest
	ListRequest     *schemas.DeepIntShieldFileListRequest
	RetrieveRequest *schemas.DeepIntShieldFileRetrieveRequest
	DeleteRequest   *schemas.DeepIntShieldFileDeleteRequest
	ContentRequest  *schemas.DeepIntShieldFileContentRequest
}

// ContainerRequest wraps a DeepIntShield container request with its type information.
type ContainerRequest struct {
	Type            schemas.RequestType
	CreateRequest   *schemas.DeepIntShieldContainerCreateRequest
	ListRequest     *schemas.DeepIntShieldContainerListRequest
	RetrieveRequest *schemas.DeepIntShieldContainerRetrieveRequest
	DeleteRequest   *schemas.DeepIntShieldContainerDeleteRequest
}

// ContainerFileRequest is a wrapper for DeepIntShield container file requests.
type ContainerFileRequest struct {
	Type            schemas.RequestType
	CreateRequest   *schemas.DeepIntShieldContainerFileCreateRequest
	ListRequest     *schemas.DeepIntShieldContainerFileListRequest
	RetrieveRequest *schemas.DeepIntShieldContainerFileRetrieveRequest
	ContentRequest  *schemas.DeepIntShieldContainerFileContentRequest
	DeleteRequest   *schemas.DeepIntShieldContainerFileDeleteRequest
}

// BatchRequestConverter is a function that converts integration-specific batch requests to DeepIntShield format.
type BatchRequestConverter func(ctx *schemas.DeepIntShieldContext, req interface{}) (*BatchRequest, error)

// FileRequestConverter is a function that converts integration-specific file requests to DeepIntShield format.
type FileRequestConverter func(ctx *schemas.DeepIntShieldContext, req interface{}) (*FileRequest, error)

// ContainerRequestConverter is a function that converts integration-specific container requests to DeepIntShield format.
type ContainerRequestConverter func(ctx *schemas.DeepIntShieldContext, req interface{}) (*ContainerRequest, error)

// ContainerFileRequestConverter is a function that converts integration-specific container file requests to DeepIntShield format.
type ContainerFileRequestConverter func(ctx *schemas.DeepIntShieldContext, req interface{}) (*ContainerFileRequest, error)

// RequestConverter is a function that converts integration-specific requests to DeepIntShield format.
// It takes the parsed request object and returns a DeepIntShieldRequest ready for processing.
type RequestConverter func(ctx *schemas.DeepIntShieldContext, req interface{}) (*schemas.DeepIntShieldRequest, error)

// ListModelsResponseConverter is a function that converts DeepIntShieldListModelsResponse to integration-specific format.
// It takes a DeepIntShieldListModelsResponse and returns the format expected by the specific integration.
type ListModelsResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldListModelsResponse) (interface{}, error)

// TextResponseConverter is a function that converts DeepIntShieldTextCompletionResponse to integration-specific format.
// It takes a DeepIntShieldTextCompletionResponse and returns the format expected by the specific integration.
type TextResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldTextCompletionResponse) (interface{}, error)

// ChatResponseConverter is a function that converts DeepIntShieldChatResponse to integration-specific format.
// It takes a DeepIntShieldChatResponse and returns the format expected by the specific integration.
type ChatResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldChatResponse) (interface{}, error)

// AsyncChatResponseConverter is a function that converts an async job response to an integration-specific format.
// It takes an async job response and a method to convert the chat response, and returns the integration-specific format, extra headers, and an error.
type AsyncChatResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.AsyncJobResponse, chatResponseConverter ChatResponseConverter) (interface{}, map[string]string, error)

// ResponsesResponseConverter is a function that converts DeepIntShieldResponsesResponse to integration-specific format.
// It takes a DeepIntShieldResponsesResponse and returns the format expected by the specific integration.
type ResponsesResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponsesResponse) (interface{}, error)

// AsyncResponsesResponseConverter is a function that converts an async job response to an integration-specific format.
// It takes an async job response and a method to convert the responses response, and returns the integration-specific format, extra headers, and an error.
type AsyncResponsesResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.AsyncJobResponse, responsesResponseConverter ResponsesResponseConverter) (interface{}, map[string]string, error)

// EmbeddingResponseConverter is a function that converts DeepIntShieldEmbeddingResponse to integration-specific format.
// It takes a DeepIntShieldEmbeddingResponse and returns the format expected by the specific integration.
type EmbeddingResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldEmbeddingResponse) (interface{}, error)

// RerankResponseConverter is a function that converts DeepIntShieldRerankResponse to integration-specific format.
// It takes a DeepIntShieldRerankResponse and returns the format expected by the specific integration.
type RerankResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldRerankResponse) (interface{}, error)

// SpeechResponseConverter is a function that converts DeepIntShieldSpeechResponse to integration-specific format.
// It takes a DeepIntShieldSpeechResponse and returns the format expected by the specific integration.
type SpeechResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldSpeechResponse) (interface{}, error)

// TranscriptionResponseConverter is a function that converts DeepIntShieldTranscriptionResponse to integration-specific format.
// It takes a DeepIntShieldTranscriptionResponse and returns the format expected by the specific integration.
type TranscriptionResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldTranscriptionResponse) (interface{}, error)

// BatchCreateResponseConverter is a function that converts DeepIntShieldBatchCreateResponse to integration-specific format.
// It takes a DeepIntShieldBatchCreateResponse and returns the format expected by the specific integration.
type BatchCreateResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldBatchCreateResponse) (interface{}, error)

// BatchListResponseConverter is a function that converts DeepIntShieldBatchListResponse to integration-specific format.
// It takes a DeepIntShieldBatchListResponse and returns the format expected by the specific integration.
type BatchListResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldBatchListResponse) (interface{}, error)

// BatchRetrieveResponseConverter is a function that converts DeepIntShieldBatchRetrieveResponse to integration-specific format.
// It takes a DeepIntShieldBatchRetrieveResponse and returns the format expected by the specific integration.
type BatchRetrieveResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldBatchRetrieveResponse) (interface{}, error)

// BatchCancelResponseConverter is a function that converts DeepIntShieldBatchCancelResponse to integration-specific format.
// It takes a DeepIntShieldBatchCancelResponse and returns the format expected by the specific integration.
type BatchCancelResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldBatchCancelResponse) (interface{}, error)

// BatchResultsResponseConverter is a function that converts DeepIntShieldBatchResultsResponse to integration-specific format.
// It takes a DeepIntShieldBatchResultsResponse and returns the format expected by the specific integration.
type BatchResultsResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldBatchResultsResponse) (interface{}, error)

// BatchDeleteResponseConverter is a function that converts DeepIntShieldBatchDeleteResponse to integration-specific format.
// It takes a DeepIntShieldBatchDeleteResponse and returns the format expected by the specific integration.
type BatchDeleteResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldBatchDeleteResponse) (interface{}, error)

// FileUploadResponseConverter is a function that converts DeepIntShieldFileUploadResponse to integration-specific format.
// It takes a DeepIntShieldFileUploadResponse and returns the format expected by the specific integration.
type FileUploadResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldFileUploadResponse) (interface{}, error)

// FileListResponseConverter is a function that converts DeepIntShieldFileListResponse to integration-specific format.
// It takes a DeepIntShieldFileListResponse and returns the format expected by the specific integration.
type FileListResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldFileListResponse) (interface{}, error)

// FileRetrieveResponseConverter is a function that converts DeepIntShieldFileRetrieveResponse to integration-specific format.
// It takes a DeepIntShieldFileRetrieveResponse and returns the format expected by the specific integration.
type FileRetrieveResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldFileRetrieveResponse) (interface{}, error)

// FileDeleteResponseConverter is a function that converts DeepIntShieldFileDeleteResponse to integration-specific format.
// It takes a DeepIntShieldFileDeleteResponse and returns the format expected by the specific integration.
type FileDeleteResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldFileDeleteResponse) (interface{}, error)

// FileContentResponseConverter is a function that converts DeepIntShieldFileContentResponse to integration-specific format.
// It takes a DeepIntShieldFileContentResponse and returns the format expected by the specific integration.
// Note: This may return binary data or a wrapper object depending on the integration.
type FileContentResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldFileContentResponse) (interface{}, error)

// ContainerCreateResponseConverter is a function that converts DeepIntShieldContainerCreateResponse to integration-specific format.
// It takes a DeepIntShieldContainerCreateResponse and returns the format expected by the specific integration.
type ContainerCreateResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerCreateResponse) (interface{}, error)

// ContainerListResponseConverter is a function that converts DeepIntShieldContainerListResponse to integration-specific format.
// It takes a DeepIntShieldContainerListResponse and returns the format expected by the specific integration.
type ContainerListResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerListResponse) (interface{}, error)

// ContainerRetrieveResponseConverter is a function that converts DeepIntShieldContainerRetrieveResponse to integration-specific format.
// It takes a DeepIntShieldContainerRetrieveResponse and returns the format expected by the specific integration.
type ContainerRetrieveResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerRetrieveResponse) (interface{}, error)

// ContainerDeleteResponseConverter is a function that converts DeepIntShieldContainerDeleteResponse to integration-specific format.
// It takes a DeepIntShieldContainerDeleteResponse and returns the format expected by the specific integration.
type ContainerDeleteResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerDeleteResponse) (interface{}, error)

// ContainerFileCreateResponseConverter is a function that converts DeepIntShieldContainerFileCreateResponse to integration-specific format.
// It takes a DeepIntShieldContainerFileCreateResponse and returns the format expected by the specific integration.
type ContainerFileCreateResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerFileCreateResponse) (interface{}, error)

// ContainerFileListResponseConverter is a function that converts DeepIntShieldContainerFileListResponse to integration-specific format.
// It takes a DeepIntShieldContainerFileListResponse and returns the format expected by the specific integration.
type ContainerFileListResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerFileListResponse) (interface{}, error)

// ContainerFileRetrieveResponseConverter is a function that converts DeepIntShieldContainerFileRetrieveResponse to integration-specific format.
// It takes a DeepIntShieldContainerFileRetrieveResponse and returns the format expected by the specific integration.
type ContainerFileRetrieveResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerFileRetrieveResponse) (interface{}, error)

// ContainerFileContentResponseConverter is a function that converts DeepIntShieldContainerFileContentResponse to integration-specific format.
// It takes a DeepIntShieldContainerFileContentResponse and returns the format expected by the specific integration.
type ContainerFileContentResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerFileContentResponse) (interface{}, error)

// ContainerFileDeleteResponseConverter is a function that converts DeepIntShieldContainerFileDeleteResponse to integration-specific format.
// It takes a DeepIntShieldContainerFileDeleteResponse and returns the format expected by the specific integration.
type ContainerFileDeleteResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldContainerFileDeleteResponse) (interface{}, error)

// CountTokensResponseConverter is a function that converts DeepIntShieldCountTokensResponse to integration-specific format.
// It takes a DeepIntShieldCountTokensResponse and returns the format expected by the specific integration.
type CountTokensResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldCountTokensResponse) (interface{}, error)

// TextStreamResponseConverter is a function that converts DeepIntShieldTextCompletionResponse to integration-specific streaming format.
// It takes a DeepIntShieldTextCompletionResponse and returns the event type and the streaming format expected by the specific integration.
type TextStreamResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldTextCompletionResponse) (string, interface{}, error)

// ChatStreamResponseConverter is a function that converts DeepIntShieldChatResponse to integration-specific streaming format.
// It takes a DeepIntShieldChatResponse and returns the event type and the streaming format expected by the specific integration.
type ChatStreamResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldChatResponse) (string, interface{}, error)

// ResponsesStreamResponseConverter is a function that converts DeepIntShieldResponsesStreamResponse to integration-specific streaming format.
// It takes a DeepIntShieldResponsesStreamResponse and returns a single event type and payload, which can itself encode one or more SSE events if needed by the integration.
type ResponsesStreamResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponsesStreamResponse) (string, interface{}, error)

// SpeechStreamResponseConverter is a function that converts DeepIntShieldSpeechStreamResponse to integration-specific streaming format.
// It takes a DeepIntShieldSpeechStreamResponse and returns the event type and the streaming format expected by the specific integration.
type SpeechStreamResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldSpeechStreamResponse) (string, interface{}, error)

// TranscriptionStreamResponseConverter is a function that converts DeepIntShieldTranscriptionStreamResponse to integration-specific streaming format.
// It takes a DeepIntShieldTranscriptionStreamResponse and returns the event type and the streaming format expected by the specific integration.
type TranscriptionStreamResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldTranscriptionStreamResponse) (string, interface{}, error)

// ImageGenerationResponseConverter is a function that converts DeepIntShieldImageGenerationResponse to integration-specific format.
// It takes a DeepIntShieldImageGenerationResponse and returns the format expected by the specific integration.
type ImageGenerationResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldImageGenerationResponse) (interface{}, error)

// ImageGenerationStreamResponseConverter is a function that converts DeepIntShieldImageGenerationStreamResponse to integration-specific streaming format.
// It takes a DeepIntShieldImageGenerationStreamResponse and returns the event type and the streaming format expected by the specific integration.
type ImageGenerationStreamResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldImageGenerationStreamResponse) (string, interface{}, error)

// ImageEditResponseConverter is a function that converts DeepIntShieldImageGenerationResponse to integration-specific format.
// It takes a DeepIntShieldImageGenerationResponse and returns the format expected by the specific integration.
type ImageEditResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldImageGenerationResponse) (interface{}, error)

// VideoGenerationResponseConverter is a function that converts DeepIntShieldVideoGenerationResponse to integration-specific format.
// It takes a DeepIntShieldVideoGenerationResponse and returns the format expected by the specific integration.
type VideoGenerationResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldVideoGenerationResponse) (interface{}, error)

// VideoDownloadResponseConverter is a function that converts DeepIntShieldVideoDownloadResponse to integration-specific format.
// It takes a DeepIntShieldVideoDownloadResponse and returns the format expected by the specific integration.
type VideoDownloadResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldVideoDownloadResponse) (interface{}, error)

// VideoRetrieveAsDownloadConverter is a function that converts DeepIntShieldVideoGenerationResponse to integration-specific format.
// It takes a DeepIntShieldVideoGenerationResponse and returns the format expected by the specific integration.
type VideoRetrieveAsDownloadConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldVideoGenerationResponse) (interface{}, error)

// VideoDeleteResponseConverter is a function that converts DeepIntShieldVideoDeleteResponse to integration-specific format.
// It takes a DeepIntShieldVideoDeleteResponse and returns the format expected by the specific integration.
type VideoDeleteResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldVideoDeleteResponse) (interface{}, error)

// VideoListResponseConverter is a function that converts DeepIntShieldVideoListResponse to integration-specific format.
// It takes a DeepIntShieldVideoListResponse and returns the format expected by the specific integration.
type VideoListResponseConverter func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldVideoListResponse) (interface{}, error)

// ErrorConverter is a function that converts DeepIntShieldError to integration-specific format.
// It takes a DeepIntShieldError and returns the format expected by the specific integration.
type ErrorConverter func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{}

// StreamErrorConverter is a function that converts DeepIntShieldError to integration-specific streaming error format.
// It takes a DeepIntShieldError and returns the streaming error format expected by the specific integration.
type StreamErrorConverter func(ctx *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{}

// RequestParser is a function that handles custom request body parsing.
// It replaces the default JSON parsing when configured (e.g., for multipart/form-data).
// The parser should populate the provided request object from the fasthttp context.
// If it returns an error, the request processing stops.
type RequestParser func(ctx *fasthttp.RequestCtx, req interface{}) error

// PreRequestCallback is called after parsing the request but before processing through DeepIntShield.
// It can be used to modify the request object (e.g., extract model from URL parameters)
// or perform validation. If it returns an error, the request processing stops.
// It can also modify the deepintshield context based on the request context before it is given to DeepIntShield.
type PreRequestCallback func(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, req interface{}) error

// PostRequestCallback is called after processing the request but before sending the response.
// It can be used to modify the response or perform additional logging/metrics.
// If it returns an error, an error response is sent instead of the success response.
type PostRequestCallback func(ctx *fasthttp.RequestCtx, req interface{}, resp interface{}) error

// HTTPRequestTypeGetter is a function type that accepts only a *fasthttp.RequestCtx and
// returns a schemas.RequestType indicating the HTTP request type derived from the context.
type HTTPRequestTypeGetter func(ctx *fasthttp.RequestCtx) schemas.RequestType

// ShortCircuit is a function that determines if the request should be short-circuited.
type ShortCircuit func(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, req interface{}) (bool, error)

// StreamConfig defines streaming-specific configuration for an integration
//
// SSE FORMAT BEHAVIOR:
//
// The ResponseConverter and ErrorConverter functions in StreamConfig can return either:
//
// 1. OBJECTS (interface{} that's not a string):
//   - Will be JSON marshaled and sent as standard SSE: data: {json}\n\n
//   - Use this for most providers (OpenAI, Google, etc.)
//   - Example: return map[string]interface{}{"delta": {"content": "hello"}}
//   - Result: data: {"delta":{"content":"hello"}}\n\n
//
// 2. STRINGS:
//   - Will be sent directly as-is without any modification
//   - Use this for providers requiring custom SSE event types (Anthropic, etc.)
//   - Example: return "event: content_block_delta\ndata: {\"type\":\"text\"}\n\n"
//   - Result: event: content_block_delta
//     data: {"type":"text"}
//
// Choose the appropriate return type based on your provider's SSE specification.
type StreamConfig struct {
	TextStreamResponseConverter            TextStreamResponseConverter            // Function to convert DeepIntShieldTextCompletionResponse to streaming format
	ChatStreamResponseConverter            ChatStreamResponseConverter            // Function to convert DeepIntShieldChatResponse to streaming format
	ResponsesStreamResponseConverter       ResponsesStreamResponseConverter       // Function to convert DeepIntShieldResponsesResponse to streaming format
	SpeechStreamResponseConverter          SpeechStreamResponseConverter          // Function to convert DeepIntShieldSpeechResponse to streaming format
	TranscriptionStreamResponseConverter   TranscriptionStreamResponseConverter   // Function to convert DeepIntShieldTranscriptionResponse to streaming format
	ImageGenerationStreamResponseConverter ImageGenerationStreamResponseConverter // Function to convert DeepIntShieldImageGenerationStreamResponse to streaming format
	ErrorConverter                         StreamErrorConverter                   // Function to convert DeepIntShieldError to streaming error format
}

type RouteConfigType string

const (
	RouteConfigTypeOpenAI    RouteConfigType = "openai"
	RouteConfigTypeAnthropic RouteConfigType = "anthropic"
	RouteConfigTypeGenAI     RouteConfigType = "genai"
	RouteConfigTypeBedrock   RouteConfigType = "bedrock"
	RouteConfigTypeCohere    RouteConfigType = "cohere"
)

// RouteConfig defines the configuration for a single route in an integration.
// It specifies the path, method, and handlers for request/response conversion.
type RouteConfig struct {
	Type                                   RouteConfigType                        // Type of the route
	Path                                   string                                 // HTTP path pattern (e.g., "/openai/v1/chat/completions")
	Method                                 string                                 // HTTP method (POST, GET, PUT, DELETE)
	GetHTTPRequestType                     HTTPRequestTypeGetter                  // Function to get the HTTP request type from the context (SHOULD NOT BE NIL)
	GetRequestTypeInstance                 func(ctx context.Context) interface{}  // Factory function to create request instance (SHOULD NOT BE NIL)
	RequestParser                          RequestParser                          // Optional: custom request parsing (e.g., multipart/form-data)
	RequestConverter                       RequestConverter                       // Function to convert request to DeepIntShieldRequest (for inference requests)
	BatchRequestConverter                  BatchRequestConverter                  // Function to convert request to BatchRequest (for batch operations)
	FileRequestConverter                   FileRequestConverter                   // Function to convert request to FileRequest (for file operations)
	ContainerRequestConverter              ContainerRequestConverter              // Function to convert request to ContainerRequest (for container operations)
	ContainerFileRequestConverter          ContainerFileRequestConverter          // Function to convert request to ContainerFileRequest (for container file operations)
	ListModelsResponseConverter            ListModelsResponseConverter            // Function to convert DeepIntShieldListModelsResponse to integration format (SHOULD NOT BE NIL)
	TextResponseConverter                  TextResponseConverter                  // Function to convert DeepIntShieldTextCompletionResponse to integration format (SHOULD NOT BE NIL)
	ChatResponseConverter                  ChatResponseConverter                  // Function to convert DeepIntShieldChatResponse to integration format (SHOULD NOT BE NIL)
	AsyncChatResponseConverter             AsyncChatResponseConverter             // Function to convert AsyncJobResponse to integration format (SHOULD NOT BE NIL)
	ResponsesResponseConverter             ResponsesResponseConverter             // Function to convert DeepIntShieldResponsesResponse to integration format (SHOULD NOT BE NIL)
	AsyncResponsesResponseConverter        AsyncResponsesResponseConverter        // Function to convert AsyncJobResponse to integration format (SHOULD NOT BE NIL)
	EmbeddingResponseConverter             EmbeddingResponseConverter             // Function to convert DeepIntShieldEmbeddingResponse to integration format (SHOULD NOT BE NIL)
	RerankResponseConverter                RerankResponseConverter                // Function to convert DeepIntShieldRerankResponse to integration format
	SpeechResponseConverter                SpeechResponseConverter                // Function to convert DeepIntShieldSpeechResponse to integration format (SHOULD NOT BE NIL)
	TranscriptionResponseConverter         TranscriptionResponseConverter         // Function to convert DeepIntShieldTranscriptionResponse to integration format (SHOULD NOT BE NIL)
	ImageGenerationResponseConverter       ImageGenerationResponseConverter       // Function to convert DeepIntShieldImageGenerationResponse to integration format (SHOULD NOT BE NIL)
	VideoGenerationResponseConverter       VideoGenerationResponseConverter       // Function to convert DeepIntShieldVideoGenerationResponse to integration format (SHOULD NOT BE NIL)
	VideoDownloadResponseConverter         VideoDownloadResponseConverter         // Function to convert DeepIntShieldVideoDownloadResponse to integration format (SHOULD NOT BE NIL)
	VideoDeleteResponseConverter           VideoDeleteResponseConverter           // Function to convert DeepIntShieldVideoDeleteResponse to integration format (SHOULD NOT BE NIL)
	VideoListResponseConverter             VideoListResponseConverter             // Function to convert DeepIntShieldVideoListResponse to integration format (SHOULD NOT BE NIL)
	BatchCreateResponseConverter           BatchCreateResponseConverter           // Function to convert DeepIntShieldBatchCreateResponse to integration format
	BatchListResponseConverter             BatchListResponseConverter             // Function to convert DeepIntShieldBatchListResponse to integration format
	BatchRetrieveResponseConverter         BatchRetrieveResponseConverter         // Function to convert DeepIntShieldBatchRetrieveResponse to integration format
	BatchCancelResponseConverter           BatchCancelResponseConverter           // Function to convert DeepIntShieldBatchCancelResponse to integration format
	BatchDeleteResponseConverter           BatchDeleteResponseConverter           // Function to convert DeepIntShieldBatchDeleteResponse to integration format
	BatchResultsResponseConverter          BatchResultsResponseConverter          // Function to convert DeepIntShieldBatchResultsResponse to integration format
	FileUploadResponseConverter            FileUploadResponseConverter            // Function to convert DeepIntShieldFileUploadResponse to integration format
	FileListResponseConverter              FileListResponseConverter              // Function to convert DeepIntShieldFileListResponse to integration format
	FileRetrieveResponseConverter          FileRetrieveResponseConverter          // Function to convert DeepIntShieldFileRetrieveResponse to integration format
	FileDeleteResponseConverter            FileDeleteResponseConverter            // Function to convert DeepIntShieldFileDeleteResponse to integration format
	FileContentResponseConverter           FileContentResponseConverter           // Function to convert DeepIntShieldFileContentResponse to integration format
	ContainerCreateResponseConverter       ContainerCreateResponseConverter       // Function to convert DeepIntShieldContainerCreateResponse to integration format
	ContainerListResponseConverter         ContainerListResponseConverter         // Function to convert DeepIntShieldContainerListResponse to integration format
	ContainerRetrieveResponseConverter     ContainerRetrieveResponseConverter     // Function to convert DeepIntShieldContainerRetrieveResponse to integration format
	ContainerDeleteResponseConverter       ContainerDeleteResponseConverter       // Function to convert DeepIntShieldContainerDeleteResponse to integration format
	ContainerFileCreateResponseConverter   ContainerFileCreateResponseConverter   // Function to convert DeepIntShieldContainerFileCreateResponse to integration format
	ContainerFileListResponseConverter     ContainerFileListResponseConverter     // Function to convert DeepIntShieldContainerFileListResponse to integration format
	ContainerFileRetrieveResponseConverter ContainerFileRetrieveResponseConverter // Function to convert DeepIntShieldContainerFileRetrieveResponse to integration format
	ContainerFileContentResponseConverter  ContainerFileContentResponseConverter  // Function to convert DeepIntShieldContainerFileContentResponse to integration format
	ContainerFileDeleteResponseConverter   ContainerFileDeleteResponseConverter   // Function to convert DeepIntShieldContainerFileDeleteResponse to integration format
	CountTokensResponseConverter           CountTokensResponseConverter           // Function to convert DeepIntShieldCountTokensResponse to integration format
	ErrorConverter                         ErrorConverter                         // Function to convert DeepIntShieldError to integration format (SHOULD NOT BE NIL)
	StreamConfig                           *StreamConfig                          // Optional: Streaming configuration (if nil, streaming not supported)
	PreCallback                            PreRequestCallback                     // Optional: called after parsing but before DeepIntShield processing
	PostCallback                           PostRequestCallback                    // Optional: called after request processing
	ShortCircuit                           ShortCircuit
}

type PassthroughConfig struct {
	Provider         schemas.ModelProvider                                              // which provider's key pool to draw from
	ProviderDetector func(ctx *fasthttp.RequestCtx, model string) schemas.ModelProvider // optional: dynamic provider detection
	StripPrefix      []string                                                           // e.g. "/openai" - stripped before forwarding
}

// LargePayloadHook is called before body parsing to detect and set up large payload streaming.
// If it returns skipBodyParse=true, the router skips JSON parsing of the request body.
// The hook is responsible for setting all relevant context keys (DeepIntShieldContextKeyLargePayloadMode,
// DeepIntShieldContextKeyLargePayloadReader, DeepIntShieldContextKeyLargePayloadContentLength,
// DeepIntShieldContextKeyLargePayloadMetadata) when activating large payload mode.
type LargePayloadHook func(
	ctx *fasthttp.RequestCtx,
	deepintshieldCtx *schemas.DeepIntShieldContext,
	routeType RouteConfigType,
) (skipBodyParse bool, err error)

// LargeResponseHook is called before streaming a large response body to the client.
// Enterprise uses this to wrap the response reader with Phase B scanning (e.g., usage extraction
// from the full response stream when usage is beyond the Phase A prefetch window).
// The hook receives the deepintshield context with DeepIntShieldContextKeyLargeResponseReader already set
// and may replace the reader on context with a wrapped version.
type LargeResponseHook func(
	ctx *fasthttp.RequestCtx,
	deepintshieldCtx *schemas.DeepIntShieldContext,
)

// GenericRouter provides a reusable router implementation for all integrations.
// It handles the common flow of: parse request → convert to DeepIntShield → execute → convert response.
// Integration-specific logic is handled through the RouteConfig callbacks and converters.
type GenericRouter struct {
	client            *deepintshield.DeepIntShield // DeepIntShield client for executing requests
	handlerStore      lib.HandlerStore             // Config provider for the router
	routes            []RouteConfig                // List of route configurations
	passthroughCfg    *PassthroughConfig
	logger            schemas.Logger    // Logger for the router
	largePayloadHook  LargePayloadHook  // Optional: enterprise hook for large payload detection
	largeResponseHook LargeResponseHook // Optional: enterprise hook for large response scanning
	// agenticCacheHook bridges semantic-cache hit/miss signals from this
	// integration path (openai/v1/chat/completions, /genai/..., /anthropic/...)
	// into the agentic-cache analytics. Without it, the dashboard's cache
	// counters only see traffic through the direct /v1/chat/completions
	// route used by older clients - the OpenAI-compat / Anthropic-compat /
	// Gemini-compat surfaces silently bypass the bridge and the Agentic
	// Cache tab stays at zero.
	agenticCacheHook AgenticCacheBridgeHook

	// agenticUsageHook attributes an LLM call's tokens / cost to the calling
	// agent's observability trace (Cost & Tokens / Top Models / Tokens-per-$
	// panels). Unlike the cache hook it needs the unified response shape, so
	// it is invoked from handleNonStreamingRequest where the
	// *schemas.DeepIntShieldResponse still exists - before conversion to the
	// provider-specific (OpenAI / Gemini / Anthropic) wire format. Without it,
	// agent traffic on the compat surfaces never feeds agentic_traces.cost_usd
	// and those panels stay empty. Fail-open; the underlying sink is async.
	agenticUsageHook AgenticLLMUsageHook
}

// AgenticCacheBridgeHook is invoked after every successful, non-streaming
// response on the GenericRouter path. Implementations should attribute the
// observed semantic-cache outcome (hit/miss) to the agentic cache's per-
// (tenant, workspace, vk) counters. Fail-open - the hook must never block
// or panic the response.
//
// The hit/miss signal is read from the unified response's CacheDebug
// (the semanticcache plugin attaches it on every attempted lookup), so
// the hook receives the response the same way AgenticLLMUsageHook does.
// Token + cost extraction would require the native response shape
// (OpenAI / Gemini / Anthropic differ), so the hook intentionally
// records the OUTCOME (hit/miss) without token-level $/savings detail.
// The dashboards still get a working hit rate; the direct
// /v1/chat/completions route records the full breakdown via the
// original recordLLMCacheOutcome path.
type AgenticCacheBridgeHook func(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse)

// SetAgenticCacheBridgeHook wires the bridge. Server bootstrap calls this
// after the agentic runtime is constructed so the OpenAI-compat surface
// emits cache events the same way the direct route does.
func (g *GenericRouter) SetAgenticCacheBridgeHook(hook AgenticCacheBridgeHook) {
	g.agenticCacheHook = hook
}

// AgenticLLMUsageHook is invoked after every successful, non-streaming chat /
// text / responses call on the GenericRouter path, with the unified
// DeepIntShieldResponse so the implementation can read token usage uniformly
// across provider shapes. Implementations attribute the tokens / cost to the
// agent's observability trace (gated to agent VKs). Fail-open - the hook must
// never block or panic the response, and its sink is async.
type AgenticLLMUsageHook func(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, resp *schemas.DeepIntShieldResponse)

// SetAgenticLLMUsageHook wires the agentic LLM-usage bridge for the compat
// surfaces. Server bootstrap calls this after the agentic runtime + completion
// handler are constructed so the OpenAI/Gemini/Anthropic-compat routes feed the
// Cost & Tokens panels identically to the direct /v1/chat/completions route.
func (g *GenericRouter) SetAgenticLLMUsageHook(hook AgenticLLMUsageHook) {
	g.agenticUsageHook = hook
}

// SetLargePayloadHook sets the hook for large payload detection and streaming.
// This is used by enterprise to inject large payload optimization without
// embedding the logic in the OSS router.
func (g *GenericRouter) SetLargePayloadHook(hook LargePayloadHook) {
	g.largePayloadHook = hook
}

// SetLargeResponseHook sets the hook for large response scanning.
// Enterprise uses this to inject Phase B usage extraction into the response stream
// without embedding scanning logic in the OSS router.
func (g *GenericRouter) SetLargeResponseHook(hook LargeResponseHook) {
	g.largeResponseHook = hook
}

// NewGenericRouter creates a new generic router with the given deepintshield client and route configurations.
// Each integration should create their own routes and pass them to this constructor.
func NewGenericRouter(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, routes []RouteConfig, passthroughCfg *PassthroughConfig, logger schemas.Logger) *GenericRouter {
	return &GenericRouter{
		client:         client,
		handlerStore:   handlerStore,
		routes:         routes,
		passthroughCfg: passthroughCfg,
		logger:         logger,
	}
}

// RegisterRoutes registers all configured routes on the given fasthttp router.
// This method implements the ExtensionRouter interface.
func (g *GenericRouter) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	for _, route := range g.routes {
		// Validate route configuration at startup to fail fast
		method := strings.ToUpper(route.Method)

		if route.GetRequestTypeInstance == nil {
			g.logger.Warn("route configuration is invalid: GetRequestTypeInstance cannot be nil for route " + route.Path)
			continue
		}

		// Test that GetRequestTypeInstance returns a valid instance
		if testInstance := route.GetRequestTypeInstance(context.Background()); testInstance == nil {
			g.logger.Warn("route configuration is invalid: GetRequestTypeInstance returned nil for route " + route.Path)
			continue
		}

		// Determine route type: inference, batch, file, container, or container file
		isBatchRoute := route.BatchRequestConverter != nil
		isFileRoute := route.FileRequestConverter != nil
		isContainerRoute := route.ContainerRequestConverter != nil
		isContainerFileRoute := route.ContainerFileRequestConverter != nil
		isInferenceRoute := !isBatchRoute && !isFileRoute && !isContainerRoute && !isContainerFileRoute

		// For inference routes, require RequestConverter
		if isInferenceRoute && route.RequestConverter == nil {
			g.logger.Warn("route configuration is invalid: RequestConverter cannot be nil for inference route " + route.Path)
			continue
		}

		if route.ErrorConverter == nil {
			g.logger.Warn("route configuration is invalid: ErrorConverter cannot be nil for route " + route.Path)
			continue
		}

		registerRequestTypeMiddleware := func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
			return func(ctx *fasthttp.RequestCtx) {
				if route.GetHTTPRequestType != nil {
					ctx.SetUserValue(schemas.DeepIntShieldContextKeyHTTPRequestType, route.GetHTTPRequestType(ctx))
				}
				next(ctx)
			}
		}

		// Create a fresh middlewares list for this route (don't mutate the original)
		// This ensures each route only has its own middleware plus the originally passed middlewares
		routeMiddlewares := append([]schemas.DeepIntShieldHTTPMiddleware{registerRequestTypeMiddleware}, middlewares...)

		handler := g.createHandler(route)
		switch method {
		case fasthttp.MethodPost:
			r.POST(route.Path, lib.ChainMiddlewares(handler, routeMiddlewares...))
		case fasthttp.MethodGet:
			r.GET(route.Path, lib.ChainMiddlewares(handler, routeMiddlewares...))
		case fasthttp.MethodPut:
			r.PUT(route.Path, lib.ChainMiddlewares(handler, routeMiddlewares...))
		case fasthttp.MethodDelete:
			r.DELETE(route.Path, lib.ChainMiddlewares(handler, routeMiddlewares...))
		case fasthttp.MethodHead:
			r.HEAD(route.Path, lib.ChainMiddlewares(handler, routeMiddlewares...))
		default:
			r.POST(route.Path, lib.ChainMiddlewares(handler, routeMiddlewares...)) // Default to POST
		}
	}

	if g.passthroughCfg != nil {
		catchAll := lib.ChainMiddlewares(g.handlePassthrough, middlewares...)
		// Register for all methods that need forwarding
		for _, method := range []string{fasthttp.MethodGet, fasthttp.MethodPost, fasthttp.MethodPut, fasthttp.MethodDelete, fasthttp.MethodPatch, fasthttp.MethodHead} {
			for _, prefix := range g.passthroughCfg.StripPrefix {
				r.Handle(method, prefix+"/{path:*}", catchAll)
			}
		}
	}
}

// createHandler creates a fasthttp handler for the given route configuration.
// The handler follows this flow:
// 1. Parse JSON request body into the configured request type (for methods that expect bodies)
// 2. Execute pre-callback (if configured) for request modification/validation
// 3. Convert request to DeepIntShieldRequest using the configured converter
// 4. Execute the request through DeepIntShield (streaming or non-streaming)
// 5. Execute post-callback (if configured) for response modification
// 6. Convert and send the response using the configured response converter
func (g *GenericRouter) createHandler(config RouteConfig) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		method := string(ctx.Method())

		// Parse request body into the integration-specific request type
		// Note: config validation is performed at startup in RegisterRoutes
		req := config.GetRequestTypeInstance(ctx)
		var rawBody []byte

		// Execute the request through DeepIntShield
		deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, g.handlerStore.ShouldAllowDirectKeys(), g.handlerStore.GetHeaderMatcher())

		// Set integration type to context
		deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyIntegrationType, string(config.Type))

		// Set available providers to context
		availableProviders := g.handlerStore.GetAvailableProviders()
		deepintshieldCtx.SetValue(schemas.DeepIntShieldContextKeyAvailableProviders, availableProviders)

		// Async retrieve: check x-bf-async-id header early (before body parsing)
		if asyncID := string(ctx.Request.Header.Peek(schemas.AsyncHeaderGetID)); asyncID != "" {
			defer cancel()
			g.handleAsyncRetrieve(ctx, config, deepintshieldCtx)
			return
		}

		// Parse request body based on configuration
		if method != fasthttp.MethodGet && method != fasthttp.MethodHead {
			// Hook executes before JSON parsing so large requests can remain streaming.
			isLargePayload := false
			if g.largePayloadHook != nil {
				var err error
				isLargePayload, err = g.largePayloadHook(ctx, deepintshieldCtx, config.Type)
				if err != nil {
					cancel()
					g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "large payload detection failed"))
					return
				}
			}

			if isLargePayload {
				// Large payload mode: body streams directly to provider via
				// DeepIntShieldContextKeyLargePayloadReader. Skip all body parsing
				// (JSON and multipart) - metadata was already extracted by the hook.
			} else if config.RequestParser != nil {
				// Use custom parser (e.g., for multipart/form-data)
				if err := config.RequestParser(ctx, req); err != nil {
					cancel()
					g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to parse request"))
					return
				}
			} else {
				// Use default JSON parsing
				rawBody = ctx.Request.Body()
				if len(rawBody) > 0 {
					if err := sonic.Unmarshal(rawBody, req); err != nil {
						cancel()
						g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "Invalid JSON"))
						return
					}
				}
			}

			// Extract the "extra_params" JSON key when passthrough is
			// explicitly enabled via x-bf-passthrough-extra-params: true.
			// Provider-specific fields (e.g. Bedrock guardrailConfig)
			// must be nested under "extra_params" in the request body.
			// Runs after both RequestParser and default JSON paths.
			if !isLargePayload && deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyPassthroughExtraParams) == true {
				if rws, ok := req.(RequestWithSettableExtraParams); ok {
					if rawBody == nil {
						rawBody = ctx.Request.Body()
					}
					if len(rawBody) > 0 {
						var wrapper struct {
							ExtraParams map[string]interface{} `json:"extra_params"`
						}
						if err := sonic.Unmarshal(rawBody, &wrapper); err == nil && len(wrapper.ExtraParams) > 0 {
							rws.SetExtraParams(wrapper.ExtraParams)
						}
					}
				}
			}
		}

		// Execute pre-request callback if configured
		// This is typically used for extracting data from URL parameters
		// or performing request validation after parsing
		if config.PreCallback != nil {
			if err := config.PreCallback(ctx, deepintshieldCtx, req); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute pre-request callback: "+err.Error()))
				return
			}
		}

		// Execute short-circuit handler if configured.
		// If it returns handled=true the callback has already written a response
		// to ctx and we return immediately, bypassing the DeepIntShield flow entirely.
		if config.ShortCircuit != nil {
			handled, err := config.ShortCircuit(ctx, deepintshieldCtx, req)
			if err != nil {
				defer cancel()
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "short-circuit handler error: "+err.Error()))
				return
			}
			if handled {
				defer cancel()
				return
			}
		}

		// Handle batch requests if BatchRequestConverter is set
		// GenAI has two cases: (1) Dedicated batch routes (list/retrieve) have only BatchRequestConverter - always use batch path.
		// (2) The models path has both BatchRequestConverter and RequestConverter - use batch path only for batch create.
		isGenAIBatchCreate := config.Type == RouteConfigTypeGenAI && deepintshieldCtx.Value(isGeminiBatchCreateRequestContextKey) != nil
		useBatchPath := config.BatchRequestConverter != nil && (config.RequestConverter == nil || config.Type != RouteConfigTypeGenAI || isGenAIBatchCreate)
		if useBatchPath {
			defer cancel()
			batchReq, err := config.BatchRequestConverter(deepintshieldCtx, req)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert batch request"))
				return
			}
			if batchReq == nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch request"))
				return
			}
			g.handleBatchRequest(ctx, config, req, batchReq, deepintshieldCtx)
			return
		}
		// Handle file requests if FileRequestConverter is set
		if config.FileRequestConverter != nil {
			defer cancel()
			fileReq, err := config.FileRequestConverter(deepintshieldCtx, req)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert file request"))
				return
			}
			if fileReq == nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid file request"))
				return
			}
			g.handleFileRequest(ctx, config, req, fileReq, deepintshieldCtx)
			return
		}

		// Handle container requests if ContainerRequestConverter is set
		if config.ContainerRequestConverter != nil {
			defer cancel()
			containerReq, err := config.ContainerRequestConverter(deepintshieldCtx, req)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert container request"))
				return
			}
			if containerReq == nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container request"))
				return
			}
			g.handleContainerRequest(ctx, config, req, containerReq, deepintshieldCtx)
			return
		}

		// Handle container file requests if ContainerFileRequestConverter is set
		if config.ContainerFileRequestConverter != nil {
			defer cancel()
			containerFileReq, err := config.ContainerFileRequestConverter(deepintshieldCtx, req)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert container file request"))
				return
			}
			if containerFileReq == nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container file request"))
				return
			}
			g.handleContainerFileRequest(ctx, config, req, containerFileReq, deepintshieldCtx)
			return
		}

		// Convert the integration-specific request to DeepIntShield format (inference requests)
		deepintshieldReq, err := config.RequestConverter(deepintshieldCtx, req)
		if err != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert request to DeepIntShield format"))
			return
		}
		if deepintshieldReq == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid request"))
			return
		}
		if sendRawRequestBody, ok := (*deepintshieldCtx).Value(schemas.DeepIntShieldContextKeyUseRawRequestBody).(bool); ok && sendRawRequestBody {
			deepintshieldReq.SetRawRequestBody(rawBody)
		}

		// Extract and parse fallbacks from the request if present
		if err := g.extractAndParseFallbacks(req, deepintshieldReq); err != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to parse fallbacks: "+err.Error()))
			return
		}

		// Async create: check x-bf-async header (needs parsed deepintshieldReq)
		if string(ctx.Request.Header.Peek(schemas.AsyncHeaderCreate)) != "" {
			defer cancel()
			g.handleAsyncCreate(ctx, config, req, deepintshieldReq, deepintshieldCtx)
			return
		}

		// Check if streaming is requested
		isStreaming := false
		if streamingReq, ok := req.(StreamingRequest); ok {
			isStreaming = streamingReq.IsStreamingRequested()
		}

		if isStreaming {
			g.handleStreamingRequest(ctx, config, deepintshieldReq, deepintshieldCtx, cancel)
		} else {
			defer cancel() // Ensure cleanup on function exit
			g.handleNonStreamingRequest(ctx, config, req, deepintshieldReq, deepintshieldCtx)
		}
	}
}

// handleNonStreamingRequest handles regular (non-streaming) requests
func (g *GenericRouter) handleNonStreamingRequest(ctx *fasthttp.RequestCtx, config RouteConfig, req interface{}, deepintshieldReq *schemas.DeepIntShieldRequest, deepintshieldCtx *schemas.DeepIntShieldContext) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// While we can't detect client disconnects until we try to write, having a cancellable context
	// allows providers that check ctx.Done() to cancel early if needed. This is less critical than
	// streaming requests (where we actively detect write errors), but still provides a mechanism
	// for providers to respect cancellation.
	var response interface{}

	var err error

	var providerResponseHeaders map[string]string

	switch {
	case deepintshieldReq.ListModelsRequest != nil:
		// Get provider from header - if not set or "all", list from all providers
		// Otherwise, list models from the specified provider
		listModelsProvider := strings.ToLower(string(ctx.Request.Header.Peek("x-bf-list-models-provider")))

		var listModelsResponse *schemas.DeepIntShieldListModelsResponse
		var deepintshieldErr *schemas.DeepIntShieldError

		if listModelsProvider == "" || listModelsProvider == "all" {
			// No specific provider requested - list from all providers
			listModelsResponse, deepintshieldErr = g.client.ListAllModels(deepintshieldCtx, deepintshieldReq.ListModelsRequest)
		} else {
			// Specific provider requested - override the provider in the request
			deepintshieldReq.ListModelsRequest.Provider = schemas.ModelProvider(listModelsProvider)
			listModelsResponse, deepintshieldErr = g.client.ListModelsRequest(deepintshieldCtx, deepintshieldReq.ListModelsRequest)
		}

		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, listModelsResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if listModelsResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		response, err = config.ListModelsResponseConverter(deepintshieldCtx, listModelsResponse)
		providerResponseHeaders = listModelsResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.TextCompletionRequest != nil:
		textCompletionResponse, deepintshieldErr := g.client.TextCompletionRequest(deepintshieldCtx, deepintshieldReq.TextCompletionRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, textCompletionResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if textCompletionResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if g.agenticUsageHook != nil {
			g.agenticUsageHook(ctx, deepintshieldCtx, deepintshieldReq, &schemas.DeepIntShieldResponse{TextCompletionResponse: textCompletionResponse})
		}
		if g.agenticCacheHook != nil {
			g.agenticCacheHook(ctx, deepintshieldCtx, &schemas.DeepIntShieldResponse{TextCompletionResponse: textCompletionResponse})
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.TextResponseConverter(deepintshieldCtx, textCompletionResponse)
		providerResponseHeaders = textCompletionResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.ChatRequest != nil:
		chatResponse, deepintshieldErr := g.client.ChatCompletionRequest(deepintshieldCtx, deepintshieldReq.ChatRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, chatResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if chatResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if g.agenticUsageHook != nil {
			g.agenticUsageHook(ctx, deepintshieldCtx, deepintshieldReq, &schemas.DeepIntShieldResponse{ChatResponse: chatResponse})
		}
		if g.agenticCacheHook != nil {
			g.agenticCacheHook(ctx, deepintshieldCtx, &schemas.DeepIntShieldResponse{ChatResponse: chatResponse})
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.ChatResponseConverter(deepintshieldCtx, chatResponse)
		providerResponseHeaders = chatResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.ResponsesRequest != nil:
		responsesResponse, deepintshieldErr := g.client.ResponsesRequest(deepintshieldCtx, deepintshieldReq.ResponsesRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, responsesResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if responsesResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if g.agenticUsageHook != nil {
			g.agenticUsageHook(ctx, deepintshieldCtx, deepintshieldReq, &schemas.DeepIntShieldResponse{ResponsesResponse: responsesResponse})
		}
		if g.agenticCacheHook != nil {
			g.agenticCacheHook(ctx, deepintshieldCtx, &schemas.DeepIntShieldResponse{ResponsesResponse: responsesResponse})
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.ResponsesResponseConverter(deepintshieldCtx, responsesResponse)
		providerResponseHeaders = responsesResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.EmbeddingRequest != nil:
		embeddingResponse, deepintshieldErr := g.client.EmbeddingRequest(deepintshieldCtx, deepintshieldReq.EmbeddingRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, embeddingResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if embeddingResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}
		providerResponseHeaders = embeddingResponse.ExtraFields.ProviderResponseHeaders
		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.EmbeddingResponseConverter(deepintshieldCtx, embeddingResponse)
	case deepintshieldReq.RerankRequest != nil:
		rerankResponse, deepintshieldErr := g.client.RerankRequest(deepintshieldCtx, deepintshieldReq.RerankRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, rerankResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if rerankResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}
		providerResponseHeaders = rerankResponse.ExtraFields.ProviderResponseHeaders
		if config.RerankResponseConverter != nil {
			response, err = config.RerankResponseConverter(deepintshieldCtx, rerankResponse)
		} else {
			response = rerankResponse
		}

	case deepintshieldReq.SpeechRequest != nil:
		speechResponse, deepintshieldErr := g.client.SpeechRequest(deepintshieldCtx, deepintshieldReq.SpeechRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, speechResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if speechResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		providerResponseHeaders = speechResponse.ExtraFields.ProviderResponseHeaders

		if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
			return
		}

		if config.SpeechResponseConverter != nil {
			response, err = config.SpeechResponseConverter(deepintshieldCtx, speechResponse)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert speech response"))
				return
			}
			g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
			return
		} else {
			ctx.Response.Header.Set("Content-Type", "audio/mpeg")
			ctx.Response.Header.Set("Content-Disposition", "attachment; filename=speech.mp3")
			ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(speechResponse.Audio)))
			ctx.Response.SetBody(speechResponse.Audio)
			return
		}
	case deepintshieldReq.TranscriptionRequest != nil:
		transcriptionResponse, deepintshieldErr := g.client.TranscriptionRequest(deepintshieldCtx, deepintshieldReq.TranscriptionRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, transcriptionResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if transcriptionResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
			return
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.TranscriptionResponseConverter(deepintshieldCtx, transcriptionResponse)
		providerResponseHeaders = transcriptionResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.ImageGenerationRequest != nil:
		imageGenerationResponse, deepintshieldErr := g.client.ImageGenerationRequest(deepintshieldCtx, deepintshieldReq.ImageGenerationRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, imageGenerationResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if imageGenerationResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.ImageGenerationResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing ImageGenerationResponseConverter for integration"))
			return
		}

		if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
			return
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.ImageGenerationResponseConverter(deepintshieldCtx, imageGenerationResponse)
		providerResponseHeaders = imageGenerationResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.ImageEditRequest != nil:
		imageEditResponse, deepintshieldErr := g.client.ImageEditRequest(deepintshieldCtx, deepintshieldReq.ImageEditRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, imageEditResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if imageEditResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.ImageGenerationResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing ImageGenerationResponseConverter for integration"))
			return
		}

		if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
			return
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.ImageGenerationResponseConverter(deepintshieldCtx, imageEditResponse)
		providerResponseHeaders = imageEditResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.ImageVariationRequest != nil:
		imageVariationResponse, deepintshieldErr := g.client.ImageVariationRequest(deepintshieldCtx, deepintshieldReq.ImageVariationRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, imageVariationResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if imageVariationResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.ImageGenerationResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing ImageGenerationResponseConverter for integration"))
			return
		}

		if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
			return
		}

		// Convert DeepIntShield response to integration-specific format and send
		response, err = config.ImageGenerationResponseConverter(deepintshieldCtx, imageVariationResponse)
		providerResponseHeaders = imageVariationResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.VideoGenerationRequest != nil:
		videoGenerationResponse, deepintshieldErr := g.client.VideoGenerationRequest(deepintshieldCtx, deepintshieldReq.VideoGenerationRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, videoGenerationResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if videoGenerationResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.VideoGenerationResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing VideoGenerationResponseConverter for integration"))
			return
		}

		response, err = config.VideoGenerationResponseConverter(deepintshieldCtx, videoGenerationResponse)
		providerResponseHeaders = videoGenerationResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.VideoRetrieveRequest != nil:
		videoRetrieveResponse, deepintshieldErr := g.client.VideoRetrieveRequest(deepintshieldCtx, deepintshieldReq.VideoRetrieveRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, videoRetrieveResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if videoRetrieveResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.VideoGenerationResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing VideoGenerationResponseConverter for integration"))
			return
		}
		response, err = config.VideoGenerationResponseConverter(deepintshieldCtx, videoRetrieveResponse)
		providerResponseHeaders = videoRetrieveResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.VideoDownloadRequest != nil:
		videoDownloadResponse, deepintshieldErr := g.client.VideoDownloadRequest(deepintshieldCtx, deepintshieldReq.VideoDownloadRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, videoDownloadResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if videoDownloadResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.VideoDownloadResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing VideoDownloadResponseConverter for integration"))
			return
		}

		response, err = config.VideoDownloadResponseConverter(deepintshieldCtx, videoDownloadResponse)
		providerResponseHeaders = videoDownloadResponse.ExtraFields.ProviderResponseHeaders

		// If converter returns binary content, write directly with content-type.
		if err == nil {
			if rawBytes, ok := response.([]byte); ok {
				contentType := videoDownloadResponse.ContentType
				if contentType == "" {
					contentType = "application/octet-stream"
				}
				ctx.Response.Header.Set("Content-Type", contentType)
				ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(rawBytes)))
				ctx.Response.SetBody(rawBytes)
				return
			}
		}
	case deepintshieldReq.VideoDeleteRequest != nil:
		videoDeleteResponse, deepintshieldErr := g.client.VideoDeleteRequest(deepintshieldCtx, deepintshieldReq.VideoDeleteRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, videoDeleteResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if videoDeleteResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.VideoDeleteResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing VideoDeleteResponseConverter for integration"))
			return
		}

		response, err = config.VideoDeleteResponseConverter(deepintshieldCtx, videoDeleteResponse)
		providerResponseHeaders = videoDeleteResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.VideoRemixRequest != nil:
		videoRemixResponse, deepintshieldErr := g.client.VideoRemixRequest(deepintshieldCtx, deepintshieldReq.VideoRemixRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, videoRemixResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if videoRemixResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.VideoGenerationResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing VideoGenerationResponseConverter for integration"))
			return
		}

		response, err = config.VideoGenerationResponseConverter(deepintshieldCtx, videoRemixResponse)
		providerResponseHeaders = videoRemixResponse.ExtraFields.ProviderResponseHeaders
	case deepintshieldReq.VideoListRequest != nil:

		// extract provider from header
		providerHeader := strings.ToLower(string(ctx.Request.Header.Peek("x-bf-video-list-provider")))
		if providerHeader != "" {
			deepintshieldReq.VideoListRequest.Provider = schemas.ModelProvider(providerHeader)
		} else if deepintshieldReq.VideoListRequest.Provider == "" {
			deepintshieldReq.VideoListRequest.Provider = schemas.OpenAI
		}
		videoListResponse, deepintshieldErr := g.client.VideoListRequest(deepintshieldCtx, deepintshieldReq.VideoListRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, videoListResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if videoListResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		if config.VideoListResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "missing VideoListResponseConverter for integration"))
			return
		}

		response, err = config.VideoListResponseConverter(deepintshieldCtx, videoListResponse)
		providerResponseHeaders = videoListResponse.ExtraFields.ProviderResponseHeaders

	case deepintshieldReq.CountTokensRequest != nil:
		countTokensResponse, deepintshieldErr := g.client.CountTokensRequest(deepintshieldCtx, deepintshieldReq.CountTokensRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}

		// Execute post-request callback if configured
		// This is typically used for response modification or additional processing
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, countTokensResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}

		if countTokensResponse == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "DeepIntShield response is nil after post-request callback"))
			return
		}

		// Convert DeepIntShield response to integration-specific format and send
		if config.CountTokensResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "CountTokensResponseConverter not configured"))
			return
		}
		response, err = config.CountTokensResponseConverter(deepintshieldCtx, countTokensResponse)
		providerResponseHeaders = countTokensResponse.ExtraFields.ProviderResponseHeaders
	default:
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "Invalid request type"))
		return
	}

	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to encode response"))
		return
	}

	// Forward provider response headers only after conversion succeeds
	for key, value := range providerResponseHeaders {
		ctx.Response.Header.Set(key, value)
	}

	if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
		return
	}

	g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
}

// --- Async integration handlers ---

// handleAsyncCreate submits an async job for the current inference request.
// It stores the raw DeepIntShield response in the DB; the response converter is applied at retrieval time.
func (g *GenericRouter) handleAsyncCreate(
	ctx *fasthttp.RequestCtx,
	config RouteConfig,
	req interface{},
	deepintshieldReq *schemas.DeepIntShieldRequest,
	deepintshieldCtx *schemas.DeepIntShieldContext,
) {
	executor := g.handlerStore.GetAsyncJobExecutor()
	if executor == nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(nil, "async operations not available: logs store not configured"))
		return
	}

	// Reject streaming + async
	if streamingReq, ok := req.(StreamingRequest); ok && streamingReq.IsStreamingRequested() {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(nil, "streaming is not supported for async requests"))
		return
	}

	// Reject non-inference routes (batch, file, container)
	if config.BatchRequestConverter != nil || config.FileRequestConverter != nil ||
		config.ContainerRequestConverter != nil || config.ContainerFileRequestConverter != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(nil, "async is not supported for batch, file, or container operations"))
		return
	}

	switch config.GetHTTPRequestType(ctx) {
	case schemas.ChatCompletionRequest:
		if config.AsyncChatResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "async operation is not supported on this route"))
			return
		}
	case schemas.ResponsesRequest:
		if config.AsyncResponsesResponseConverter == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "async operation is not supported on this route"))
			return
		}
	default:
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "async operation is not supported on this route"))
		return
	}

	operationType := config.GetHTTPRequestType(ctx)
	vkValue := getVirtualKeyFromDeepIntShieldContext(deepintshieldCtx)
	resultTTL := getResultTTLFromHeaderWithDefault(ctx, g.handlerStore.GetAsyncJobResultTTL())

	// The operation closure runs the DeepIntShield client call in the background.
	// It returns the raw typed DeepIntShield response (NOT provider-converted).
	// The response converter is applied at retrieval time via handleAsyncRetrieve.
	operation := func(bgCtx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError) {
		switch {
		case deepintshieldReq.ChatRequest != nil:
			return g.client.ChatCompletionRequest(bgCtx, deepintshieldReq.ChatRequest)
		case deepintshieldReq.ResponsesRequest != nil:
			return g.client.ResponsesRequest(bgCtx, deepintshieldReq.ResponsesRequest)
		default:
			return nil, newDeepIntShieldError(nil, "unsupported request type for async execution")
		}
	}

	job, err := executor.SubmitJob(deepintshieldCtx, vkValue, resultTTL, operation, operationType)
	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(err, "failed to create async job"))
		return
	}

	g.handleAsyncJobResponse(ctx, deepintshieldCtx, config, job)
	return
}

// handleAsyncRetrieve retrieves an async job by ID and returns the response
// using the route's response converter for completed jobs.
func (g *GenericRouter) handleAsyncRetrieve(
	ctx *fasthttp.RequestCtx,
	config RouteConfig,
	deepintshieldCtx *schemas.DeepIntShieldContext,
) {
	executor := g.handlerStore.GetAsyncJobExecutor()
	if executor == nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(nil, "async operations not available: logs store not configured"))
		return
	}

	jobID := string(ctx.Request.Header.Peek(schemas.AsyncHeaderGetID))
	if jobID == "" {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(nil, "x-bf-async-id header value is empty"))
		return
	}

	vkValue := getVirtualKeyFromDeepIntShieldContext(deepintshieldCtx)

	job, err := executor.RetrieveJob(deepintshieldCtx, jobID, vkValue, config.GetHTTPRequestType(ctx))
	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter,
			newDeepIntShieldError(err, "job not found or expired"))
		return
	}

	g.handleAsyncJobResponse(ctx, deepintshieldCtx, config, job)
	return
}

func (g *GenericRouter) handleAsyncJobResponse(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, config RouteConfig, job *logstore.AsyncJob) {
	ctx.SetContentType("application/json")

	resp := job.ToResponse()

	switch job.Status {
	case schemas.AsyncJobStatusPending, schemas.AsyncJobStatusProcessing, schemas.AsyncJobStatusCompleted:
		switch job.RequestType {
		case schemas.ChatCompletionRequest:
			if config.AsyncChatResponseConverter == nil || config.ChatResponseConverter == nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "async operation is not supported on this route"))
				return
			}
			response, extraHeaders, err := config.AsyncChatResponseConverter(deepintshieldCtx, resp, config.ChatResponseConverter)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert async chat response"))
				return
			}
			g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, extraHeaders)
			return
		case schemas.ResponsesRequest:
			if config.AsyncResponsesResponseConverter == nil || config.ResponsesResponseConverter == nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "either async responses response converter or responses response converter not configured"))
				return
			}
			response, extraHeaders, err := config.AsyncResponsesResponseConverter(deepintshieldCtx, resp, config.ResponsesResponseConverter)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert async responses response"))
				return
			}
			g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, extraHeaders)
			return
		default:
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "unknown request type"))
			return
		}

	case schemas.AsyncJobStatusFailed:
		var err schemas.DeepIntShieldError
		// Deserialize the stored DeepIntShieldError and send through provider error converter
		if job.Error != "" {
			if unmarshalErr := sonic.Unmarshal([]byte(job.Error), &err); unmarshalErr != nil {
				// If unmarshal fails, create a basic error with the raw error string
				err = schemas.DeepIntShieldError{
					Error: &schemas.ErrorField{
						Message: job.Error,
					},
				}
			}
		}
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, &err)
	}
}

// handleBatchRequest handles batch API requests (create, list, retrieve, cancel, results)
func (g *GenericRouter) handleBatchRequest(ctx *fasthttp.RequestCtx, config RouteConfig, req interface{}, batchReq *BatchRequest, deepintshieldCtx *schemas.DeepIntShieldContext) {
	var response interface{}
	var err error

	switch batchReq.Type {
	case schemas.BatchCreateRequest:
		if batchReq.CreateRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch create request"))
			return
		}
		batchResponse, deepintshieldErr := g.client.BatchCreateRequest(deepintshieldCtx, batchReq.CreateRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, batchResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.BatchCreateResponseConverter != nil {
			response, err = config.BatchCreateResponseConverter(deepintshieldCtx, batchResponse)
		} else {
			response = batchResponse
		}

	case schemas.BatchListRequest:
		if batchReq.ListRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch list request"))
			return
		}
		batchResponse, deepintshieldErr := g.client.BatchListRequest(deepintshieldCtx, batchReq.ListRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, batchResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.BatchListResponseConverter != nil {
			response, err = config.BatchListResponseConverter(deepintshieldCtx, batchResponse)
		} else {
			response = batchResponse
		}

	case schemas.BatchRetrieveRequest:
		if batchReq.RetrieveRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch retrieve request"))
			return
		}
		batchResponse, deepintshieldErr := g.client.BatchRetrieveRequest(deepintshieldCtx, batchReq.RetrieveRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, batchResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.BatchRetrieveResponseConverter != nil {
			response, err = config.BatchRetrieveResponseConverter(deepintshieldCtx, batchResponse)
		} else {
			response = batchResponse
		}

	case schemas.BatchCancelRequest:
		if batchReq.CancelRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch cancel request"))
			return
		}
		batchResponse, deepintshieldErr := g.client.BatchCancelRequest(deepintshieldCtx, batchReq.CancelRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, batchResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.BatchCancelResponseConverter != nil {
			response, err = config.BatchCancelResponseConverter(deepintshieldCtx, batchResponse)
		} else {
			response = batchResponse
		}
	case schemas.BatchDeleteRequest:
		if batchReq.DeleteRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch delete request"))
			return
		}
		batchResponse, deepintshieldErr := g.client.BatchDeleteRequest(deepintshieldCtx, batchReq.DeleteRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, batchResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.BatchDeleteResponseConverter != nil {
			response, err = config.BatchDeleteResponseConverter(deepintshieldCtx, batchResponse)
		} else {
			response = batchResponse
		}

	case schemas.BatchResultsRequest:
		if batchReq.ResultsRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid batch results request"))
			return
		}
		batchResponse, deepintshieldErr := g.client.BatchResultsRequest(deepintshieldCtx, batchReq.ResultsRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, batchResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.BatchResultsResponseConverter != nil {
			response, err = config.BatchResultsResponseConverter(deepintshieldCtx, batchResponse)
		} else {
			response = batchResponse
		}

	default:
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "Unknown batch request type"))
		return
	}

	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert batch response"))
		return
	}

	g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
}

// handleFileRequest handles file API requests (upload, list, retrieve, delete, content)
func (g *GenericRouter) handleFileRequest(ctx *fasthttp.RequestCtx, config RouteConfig, req interface{}, fileReq *FileRequest, deepintshieldCtx *schemas.DeepIntShieldContext) {

	var response interface{}
	var err error

	switch fileReq.Type {
	case schemas.FileUploadRequest:
		if fileReq.UploadRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid file upload request"))
			return
		}
		fileResponse, deepintshieldErr := g.client.FileUploadRequest(deepintshieldCtx, fileReq.UploadRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, fileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.FileUploadResponseConverter != nil {
			response, err = config.FileUploadResponseConverter(deepintshieldCtx, fileResponse)
		} else {
			response = fileResponse
		}

	case schemas.FileListRequest:
		if fileReq.ListRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid file list request"))
			return
		}
		fileResponse, deepintshieldErr := g.client.FileListRequest(deepintshieldCtx, fileReq.ListRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, fileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.FileListResponseConverter != nil {
			response, err = config.FileListResponseConverter(deepintshieldCtx, fileResponse)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert file list response"))
				return
			}
			// Handle raw byte responses (e.g., XML for S3 APIs)
			if rawBytes, ok := response.([]byte); ok {
				ctx.SetBody(rawBytes)
				return
			}
		} else {
			response = fileResponse
		}

	case schemas.FileRetrieveRequest:
		if fileReq.RetrieveRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid file retrieve request"))
			return
		}
		fileResponse, deepintshieldErr := g.client.FileRetrieveRequest(deepintshieldCtx, fileReq.RetrieveRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, fileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.FileRetrieveResponseConverter != nil {
			response, err = config.FileRetrieveResponseConverter(deepintshieldCtx, fileResponse)
		} else {
			response = fileResponse
		}

	case schemas.FileDeleteRequest:
		if fileReq.DeleteRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid file delete request"))
			return
		}
		fileResponse, deepintshieldErr := g.client.FileDeleteRequest(deepintshieldCtx, fileReq.DeleteRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, fileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.FileDeleteResponseConverter != nil {
			response, err = config.FileDeleteResponseConverter(deepintshieldCtx, fileResponse)
		} else {
			response = fileResponse
		}

	case schemas.FileContentRequest:
		if fileReq.ContentRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid file content request"))
			return
		}
		fileResponse, deepintshieldErr := g.client.FileContentRequest(deepintshieldCtx, fileReq.ContentRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, fileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		// For file content, handle binary response specially if no converter is set
		if config.FileContentResponseConverter != nil {
			response, err = config.FileContentResponseConverter(deepintshieldCtx, fileResponse)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert file content response"))
				return
			}
			// Check if response is raw bytes - write directly without JSON encoding
			if rawBytes, ok := response.([]byte); ok {
				ctx.Response.Header.Set("Content-Type", fileResponse.ContentType)
				ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(rawBytes)))
				ctx.Response.SetBody(rawBytes)
			} else {
				g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
			}
		} else {
			// Return raw file content
			ctx.Response.Header.Set("Content-Type", fileResponse.ContentType)
			ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(fileResponse.Content)))
			ctx.Response.SetBody(fileResponse.Content)
		}
		return

	default:
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "Unknown file request type"))
		return
	}

	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert file response"))
		return
	}

	// If response is nil, PostCallback has set headers/status - return without body
	if response == nil {
		return
	}

	g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
}

// handleContainerRequest handles container API requests (create, list, retrieve, delete)
func (g *GenericRouter) handleContainerRequest(ctx *fasthttp.RequestCtx, config RouteConfig, req interface{}, containerReq *ContainerRequest, deepintshieldCtx *schemas.DeepIntShieldContext) {
	var response interface{}
	var err error

	switch containerReq.Type {
	case schemas.ContainerCreateRequest:
		if containerReq.CreateRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container create request"))
			return
		}
		containerResponse, deepintshieldErr := g.client.ContainerCreateRequest(deepintshieldCtx, containerReq.CreateRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerCreateResponseConverter != nil {
			response, err = config.ContainerCreateResponseConverter(deepintshieldCtx, containerResponse)
		} else {
			response = containerResponse
		}

	case schemas.ContainerListRequest:
		if containerReq.ListRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container list request"))
			return
		}
		containerResponse, deepintshieldErr := g.client.ContainerListRequest(deepintshieldCtx, containerReq.ListRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerListResponseConverter != nil {
			response, err = config.ContainerListResponseConverter(deepintshieldCtx, containerResponse)
		} else {
			response = containerResponse
		}

	case schemas.ContainerRetrieveRequest:
		if containerReq.RetrieveRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container retrieve request"))
			return
		}
		containerResponse, deepintshieldErr := g.client.ContainerRetrieveRequest(deepintshieldCtx, containerReq.RetrieveRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerRetrieveResponseConverter != nil {
			response, err = config.ContainerRetrieveResponseConverter(deepintshieldCtx, containerResponse)
		} else {
			response = containerResponse
		}

	case schemas.ContainerDeleteRequest:
		if containerReq.DeleteRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container delete request"))
			return
		}
		containerResponse, deepintshieldErr := g.client.ContainerDeleteRequest(deepintshieldCtx, containerReq.DeleteRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerDeleteResponseConverter != nil {
			response, err = config.ContainerDeleteResponseConverter(deepintshieldCtx, containerResponse)
		} else {
			response = containerResponse
		}

	default:
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "Unknown container request type"))
		return
	}

	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert container response"))
		return
	}

	g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
}

// handleContainerFileRequest handles container file API requests (create, list, retrieve, content, delete)
func (g *GenericRouter) handleContainerFileRequest(ctx *fasthttp.RequestCtx, config RouteConfig, req interface{}, containerFileReq *ContainerFileRequest, deepintshieldCtx *schemas.DeepIntShieldContext) {
	var response interface{}
	var err error

	switch containerFileReq.Type {
	case schemas.ContainerFileCreateRequest:
		if containerFileReq.CreateRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container file create request"))
			return
		}
		containerFileResponse, deepintshieldErr := g.client.ContainerFileCreateRequest(deepintshieldCtx, containerFileReq.CreateRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerFileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerFileCreateResponseConverter != nil {
			response, err = config.ContainerFileCreateResponseConverter(deepintshieldCtx, containerFileResponse)
		} else {
			response = containerFileResponse
		}

	case schemas.ContainerFileListRequest:
		if containerFileReq.ListRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container file list request"))
			return
		}
		containerFileResponse, deepintshieldErr := g.client.ContainerFileListRequest(deepintshieldCtx, containerFileReq.ListRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerFileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerFileListResponseConverter != nil {
			response, err = config.ContainerFileListResponseConverter(deepintshieldCtx, containerFileResponse)
		} else {
			response = containerFileResponse
		}

	case schemas.ContainerFileRetrieveRequest:
		if containerFileReq.RetrieveRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container file retrieve request"))
			return
		}
		containerFileResponse, deepintshieldErr := g.client.ContainerFileRetrieveRequest(deepintshieldCtx, containerFileReq.RetrieveRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerFileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerFileRetrieveResponseConverter != nil {
			response, err = config.ContainerFileRetrieveResponseConverter(deepintshieldCtx, containerFileResponse)
		} else {
			response = containerFileResponse
		}

	case schemas.ContainerFileContentRequest:
		if containerFileReq.ContentRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container file content request"))
			return
		}
		containerFileResponse, deepintshieldErr := g.client.ContainerFileContentRequest(deepintshieldCtx, containerFileReq.ContentRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerFileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		// For content requests, handle binary response specially if converter is set
		if config.ContainerFileContentResponseConverter != nil {
			response, err = config.ContainerFileContentResponseConverter(deepintshieldCtx, containerFileResponse)
			if err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert container file content response"))
				return
			}
			// Check if response is raw bytes - write directly without JSON encoding
			if rawBytes, ok := response.([]byte); ok {
				ctx.Response.Header.Set("Content-Type", containerFileResponse.ContentType)
				ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(rawBytes)))
				ctx.Response.SetBody(rawBytes)
			} else {
				g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
			}
		} else {
			// Return raw binary content
			ctx.Response.Header.Set("Content-Type", containerFileResponse.ContentType)
			ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(containerFileResponse.Content)))
			ctx.Response.SetBody(containerFileResponse.Content)
		}
		return

	case schemas.ContainerFileDeleteRequest:
		if containerFileReq.DeleteRequest == nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "invalid container file delete request"))
			return
		}
		containerFileResponse, deepintshieldErr := g.client.ContainerFileDeleteRequest(deepintshieldCtx, containerFileReq.DeleteRequest)
		if deepintshieldErr != nil {
			g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
			return
		}
		if config.PostCallback != nil {
			if err := config.PostCallback(ctx, req, containerFileResponse); err != nil {
				g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to execute post-request callback"))
				return
			}
		}
		if config.ContainerFileDeleteResponseConverter != nil {
			response, err = config.ContainerFileDeleteResponseConverter(deepintshieldCtx, containerFileResponse)
		} else {
			response = containerFileResponse
		}

	default:
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "Unknown container file request type"))
		return
	}

	if err != nil {
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(err, "failed to convert container file response"))
		return
	}

	g.sendSuccess(ctx, deepintshieldCtx, config.ErrorConverter, response, nil)
}

// handleStreamingRequest handles streaming requests using Server-Sent Events (SSE)
func (g *GenericRouter) handleStreamingRequest(ctx *fasthttp.RequestCtx, config RouteConfig, deepintshieldReq *schemas.DeepIntShieldRequest, deepintshieldCtx *schemas.DeepIntShieldContext, cancel context.CancelFunc) {
	// Use the cancellable context from ConvertToDeepIntShieldContext
	// ctx.Done() never fires here in practice: fasthttp.RequestCtx.Done only closes when the whole server shuts down, not when an individual connection drops.
	// As a result we'll leave the provider stream running until it naturally completes, even if the client went away (write error, network drop, etc.).
	// That keeps goroutines and upstream tokens alive long after the SSE writer has exited.
	//
	// We now get a cancellable context from ConvertToDeepIntShieldContext so we can cancel the upstream stream immediately when the client disconnects.
	var stream chan *schemas.DeepIntShieldStreamChunk
	var deepintshieldErr *schemas.DeepIntShieldError

	// Handle different request types
	if deepintshieldReq.TextCompletionRequest != nil {
		stream, deepintshieldErr = g.client.TextCompletionStreamRequest(deepintshieldCtx, deepintshieldReq.TextCompletionRequest)
	} else if deepintshieldReq.ChatRequest != nil {
		stream, deepintshieldErr = g.client.ChatCompletionStreamRequest(deepintshieldCtx, deepintshieldReq.ChatRequest)
	} else if deepintshieldReq.ResponsesRequest != nil {
		stream, deepintshieldErr = g.client.ResponsesStreamRequest(deepintshieldCtx, deepintshieldReq.ResponsesRequest)
	} else if deepintshieldReq.SpeechRequest != nil {
		stream, deepintshieldErr = g.client.SpeechStreamRequest(deepintshieldCtx, deepintshieldReq.SpeechRequest)
	} else if deepintshieldReq.TranscriptionRequest != nil {
		stream, deepintshieldErr = g.client.TranscriptionStreamRequest(deepintshieldCtx, deepintshieldReq.TranscriptionRequest)
	} else if deepintshieldReq.ImageGenerationRequest != nil {
		stream, deepintshieldErr = g.client.ImageGenerationStreamRequest(deepintshieldCtx, deepintshieldReq.ImageGenerationRequest)
	} else if deepintshieldReq.ImageEditRequest != nil {
		stream, deepintshieldErr = g.client.ImageEditStreamRequest(deepintshieldCtx, deepintshieldReq.ImageEditRequest)
	}

	// Provider error before streaming started - return proper HTTP error status
	// (SSE headers not yet committed, so we can still set status code + JSON body)
	if deepintshieldErr != nil {
		cancel()
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, deepintshieldErr)
		return
	}

	// No request type matched - stream is nil. Return error without spawning
	// a drain goroutine (for-range on nil channel blocks forever).
	if stream == nil {
		cancel()
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "streaming is not supported for this request type"))
		return
	}

	// Forward provider response headers stored in context by streaming handlers
	if headers, ok := deepintshieldCtx.Value(schemas.DeepIntShieldContextKeyProviderResponseHeaders).(map[string]string); ok {
		for key, value := range headers {
			ctx.Response.Header.Set(key, value)
		}
	}

	// Large payload streaming passthrough - bypass SSE event processing, pipe raw upstream
	if g.tryStreamLargeResponse(ctx, deepintshieldCtx) {
		ctx.Response.Header.Set("Cache-Control", "no-cache")
		ctx.Response.Header.Set("Connection", "keep-alive")
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		cancel()
		go func() {
			for range stream {
			}
		}()
		return
	}

	// Check if streaming is configured for this route
	if config.StreamConfig == nil {
		cancel()
		// Drain the stream channel to prevent goroutine leaks
		go func() {
			for range stream {
			}
		}()
		g.sendError(ctx, deepintshieldCtx, config.ErrorConverter, newDeepIntShieldError(nil, "streaming is not supported for this integration"))
		return
	}

	// SSE headers set only after successful stream setup - errors above get proper HTTP status codes
	if config.Type == RouteConfigTypeBedrock {
		ctx.SetContentType("application/vnd.amazon.eventstream")
		ctx.Response.Header.Set("x-amzn-bedrock-content-type", "application/json")
	} else {
		ctx.SetContentType("text/event-stream")
	}

	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	// Handle streaming using the centralized approach
	// Pass cancel function so it can be called when the writer exits (errors, completion, etc.)
	g.handleStreaming(ctx, deepintshieldCtx, config, deepintshieldReq, stream, cancel)
}

// handleStreaming processes a stream of DeepIntShieldResponse objects and sends them as Server-Sent Events (SSE).
// It handles both successful responses and errors in the streaming format.
//
// SSE FORMAT HANDLING:
//
// By default, all responses and errors are sent in the standard SSE format:
//
//	data: {"response": "content"}\n\n
//
// However, some providers (like Anthropic) require custom SSE event formats with explicit event types:
//
//	event: content_block_delta
//	data: {"type": "content_block_delta", "delta": {...}}
//
//	event: message_stop
//	data: {"type": "message_stop"}
//
// STREAMCONFIG CONVERTER BEHAVIOR:
//
// The StreamConfig.ResponseConverter and StreamConfig.ErrorConverter functions can return:
//
// 1. OBJECTS (default behavior):
//   - Return any Go struct/map/interface{}
//   - Will be JSON marshaled and wrapped as: data: {json}\n\n
//   - Example: return map[string]interface{}{"content": "hello"}
//   - Result: data: {"content":"hello"}\n\n
//
// 2. STRINGS (custom SSE format):
//   - Return a complete SSE string with custom event types and formatting
//   - Will be sent directly without any wrapping or modification
//   - Example: return "event: content_block_delta\ndata: {\"type\":\"text\"}\n\n"
//   - Result: event: content_block_delta
//     data: {"type":"text"}
//
// IMPLEMENTATION GUIDELINES:
//
// For standard providers (OpenAI, etc.): Return objects from converters
// For custom SSE providers (Anthropic, etc.): Return pre-formatted SSE strings
//
// When returning strings, ensure they:
// - Include proper event: lines (if needed)
// - Include data: lines with JSON content
// - End with \n\n for proper SSE formatting
// - Follow the provider's specific SSE event specification
//
// CONTEXT CANCELLATION:
//
// The cancel function is called ONLY when client disconnects are detected via write errors.
// DeepIntShield handles cleanup internally for normal completion and errors, so we only cancel
// upstream streams when write errors indicate the client has disconnected.
func (g *GenericRouter) handleStreaming(ctx *fasthttp.RequestCtx, deepintshieldCtx *schemas.DeepIntShieldContext, config RouteConfig, deepintshieldReq *schemas.DeepIntShieldRequest, streamChan chan *schemas.DeepIntShieldStreamChunk, cancel context.CancelFunc) {
	// Signal to tracing middleware that trace completion should be deferred
	// The streaming callback will complete the trace after the stream ends
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyDeferTraceCompletion, true)

	// Get the trace completer function for use in the streaming callback
	traceCompleter, _ := ctx.UserValue(schemas.DeepIntShieldContextKeyTraceCompleter).(func())

	// Get stream chunk interceptor for plugin hooks
	interceptor := g.handlerStore.GetStreamChunkInterceptor()
	var httpReq *schemas.HTTPRequest
	if interceptor != nil {
		httpReq = lib.BuildHTTPRequestFromFastHTTP(ctx)
	}

	// Use SSEStreamReader to bypass fasthttp's internal pipe (fasthttputil.PipeConns)
	// which batches multiple SSE events into single TCP segments.
	reader := lib.NewSSEStreamReader()
	ctx.Response.SetBodyStream(reader, -1)

	// Producer goroutine: processes the stream channel, formats events, sends to reader
	go func() {
		defer func() {
			schemas.ReleaseHTTPRequest(httpReq)
			reader.Done()
			// Complete the trace after streaming finishes
			// This ensures all spans (including llm.call) are properly ended before the trace is sent to OTEL
			if traceCompleter != nil {
				traceCompleter()
			}
		}()

		// Create encoder for AWS Event Stream if needed
		var eventStreamEncoder *eventstream.Encoder
		if config.Type == RouteConfigTypeBedrock {
			eventStreamEncoder = eventstream.NewEncoder()
		}

		shouldSendDoneMarker := true
		if config.Type == RouteConfigTypeAnthropic || strings.Contains(config.Path, "/responses") || strings.Contains(config.Path, "/images/generations") {
			shouldSendDoneMarker = false
		}

		// F2: accumulate streamed chat usage/model/text so an agent's streaming
		// run on the compat surfaces feeds the same cost/tokens/judge pipeline as
		// a non-streaming one. Only when the agentic usage hook is wired; the
		// per-chunk cost is a pointer capture + a small append, and the post-loop
		// dispatch is gated to agent VKs inside the hook (no-op otherwise).
		agenticStream := g.agenticUsageHook != nil
		var streamUsage *schemas.DeepIntShieldLLMUsage
		var streamModel string
		var streamText strings.Builder

		// Process streaming responses
		for chunk := range streamChan {
			if chunk == nil {
				continue
			}

			if agenticStream {
				if cr := chunk.DeepIntShieldChatResponse; cr != nil {
					if cr.Usage != nil {
						streamUsage = cr.Usage
					}
					if cr.Model != "" {
						streamModel = cr.Model
					}
					for _, dch := range cr.Choices {
						if dch.ChatStreamResponseChoice != nil && dch.ChatStreamResponseChoice.Delta != nil &&
							dch.ChatStreamResponseChoice.Delta.Content != nil {
							streamText.WriteString(*dch.ChatStreamResponseChoice.Delta.Content)
						}
					}
				}
			}

			// Note: We no longer check ctx.Done() here because fasthttp.RequestCtx.Done()
			// only closes when the whole server shuts down, not when an individual client disconnects.
			// Client disconnects are detected via write errors on reader.Send(), which returns false.

			// Handle errors
			if chunk.DeepIntShieldError != nil {
				var errorResponse interface{}

				// Use stream error converter if available, otherwise fallback to regular error converter
				if config.StreamConfig != nil && config.StreamConfig.ErrorConverter != nil {
					errorResponse = config.StreamConfig.ErrorConverter(deepintshieldCtx, chunk.DeepIntShieldError)
				} else if config.ErrorConverter != nil {
					errorResponse = config.ErrorConverter(deepintshieldCtx, chunk.DeepIntShieldError)
				} else {
					// Default error response
					errorResponse = map[string]interface{}{
						"error": map[string]interface{}{
							"type":    "internal_error",
							"message": "An error occurred while processing your request",
						},
					}
				}

				// Check if the error converter returned a raw SSE string or JSON object
				if sseErrorString, ok := errorResponse.(string); ok {
					// CUSTOM SSE FORMAT: The converter returned a complete SSE string
					// This is used by providers like Anthropic that need custom event types
					reader.Send([]byte(sseErrorString))
				} else {
					// STANDARD SSE FORMAT: The converter returned an object
					errorJSON, err := sonic.Marshal(errorResponse)
					if err != nil {
						// Fallback to basic error if marshaling fails
						basicError := map[string]interface{}{
							"error": map[string]interface{}{
								"type":    "internal_error",
								"message": "An error occurred while processing your request",
							},
						}
						if errorJSON, err = sonic.Marshal(basicError); err != nil {
							cancel()
							return
						}
					}

					// Send error as SSE data
					reader.SendEvent("", errorJSON)
				}

				return // End stream on error, DeepIntShield handles cleanup internally
			} else {
				// Allow plugins to modify/filter the chunk via StreamChunkInterceptor
				if interceptor != nil {
					var err error
					chunk, err = interceptor.InterceptChunk(deepintshieldCtx, httpReq, chunk)
					if err != nil {
						if chunk == nil {
							errorJSON, marshalErr := sonic.Marshal(map[string]string{"error": err.Error()})
							if marshalErr != nil {
								cancel()
								return
							}
							// Return error event and stop streaming
							reader.SendError(errorJSON)
							cancel()
							return
						}
						// Else add warn log and continue
						g.logger.Warn("%v", err)
					}
					if chunk == nil {
						// Skip chunk if plugin wants to skip it
						continue
					}
				}
				// Handle successful responses
				// Convert response to integration-specific streaming format
				var eventType string
				var convertedResponse interface{}
				var err error

				switch {
				case chunk.DeepIntShieldTextCompletionResponse != nil:
					eventType, convertedResponse, err = config.StreamConfig.TextStreamResponseConverter(deepintshieldCtx, chunk.DeepIntShieldTextCompletionResponse)
				case chunk.DeepIntShieldChatResponse != nil:
					eventType, convertedResponse, err = config.StreamConfig.ChatStreamResponseConverter(deepintshieldCtx, chunk.DeepIntShieldChatResponse)
				case chunk.DeepIntShieldResponsesStreamResponse != nil:
					eventType, convertedResponse, err = config.StreamConfig.ResponsesStreamResponseConverter(deepintshieldCtx, chunk.DeepIntShieldResponsesStreamResponse)
				case chunk.DeepIntShieldSpeechStreamResponse != nil:
					eventType, convertedResponse, err = config.StreamConfig.SpeechStreamResponseConverter(deepintshieldCtx, chunk.DeepIntShieldSpeechStreamResponse)
				case chunk.DeepIntShieldTranscriptionStreamResponse != nil:
					eventType, convertedResponse, err = config.StreamConfig.TranscriptionStreamResponseConverter(deepintshieldCtx, chunk.DeepIntShieldTranscriptionStreamResponse)
				case chunk.DeepIntShieldImageGenerationStreamResponse != nil:
					eventType, convertedResponse, err = config.StreamConfig.ImageGenerationStreamResponseConverter(deepintshieldCtx, chunk.DeepIntShieldImageGenerationStreamResponse)
				default:
					requestType := safeGetRequestType(chunk)
					convertedResponse, err = nil, fmt.Errorf("no response converter found for request type: %s", requestType)
				}

				if convertedResponse == nil && err == nil {
					// Skip streaming chunk if no response is available and no error is returned
					continue
				}

				if err != nil {
					// Log conversion error but continue processing
					g.logger.Warn("Failed to convert streaming response: %v", err)
					continue
				}

				// Handle Bedrock Event Stream format
				if config.Type == RouteConfigTypeBedrock && eventStreamEncoder != nil {
					// We need to cast to BedrockStreamEvent to determine event type and structure
					if bedrockEvent, ok := convertedResponse.(*bedrock.BedrockStreamEvent); ok {
						// Convert to sequence of specific Bedrock events
						events := bedrockEvent.ToEncodedEvents()

						// Send all collected events
						for _, evt := range events {
							jsonData, err := sonic.Marshal(evt.Payload)
							if err != nil {
								g.logger.Warn("Failed to marshal bedrock payload: %v", err)
								continue
							}

							headers := eventstream.Headers{
								{
									Name:  ":content-type",
									Value: eventstream.StringValue("application/json"),
								},
								{
									Name:  ":event-type",
									Value: eventstream.StringValue(evt.EventType),
								},
								{
									Name:  ":message-type",
									Value: eventstream.StringValue("event"),
								},
							}

							message := eventstream.Message{
								Headers: headers,
								Payload: jsonData,
							}

							var msgBuf bytes.Buffer
							if err := eventStreamEncoder.Encode(&msgBuf, message); err != nil {
								g.logger.Warn("[Bedrock Stream] Failed to encode message: %v", err)
								cancel()
								return
							}

							if !reader.Send(msgBuf.Bytes()) {
								g.logger.Warn("[Bedrock Stream] Client disconnected")
								cancel()
								return
							}
						}
					}
					// Continue to next chunk (we handled sending internally)
					continue
				}

				// Build and send SSE event
				var buf []byte
				var sent bool
				if sseString, ok := convertedResponse.(string); ok {
					if strings.HasPrefix(sseString, "data: ") || strings.HasPrefix(sseString, "event: ") {
						// Pre-formatted SSE string (e.g. Anthropic custom event types)
						if eventType != "" {
							// Prepend event type line to pre-formatted data
							buf = make([]byte, 0, 7+len(eventType)+1+len(sseString))
							buf = append(buf, "event: "...)
							buf = append(buf, eventType...)
							buf = append(buf, '\n')
							buf = append(buf, sseString...)
							sent = reader.Send(buf)
						} else {
							sent = reader.Send([]byte(sseString))
						}
					} else {
						sent = reader.SendEvent(eventType, []byte(sseString))
					}
				} else {
					responseJSON, err := sonic.Marshal(convertedResponse)
					if err != nil {
						g.logger.Warn("Failed to marshal streaming response: %v", err)
						continue
					}
					sent = reader.SendEvent(eventType, responseJSON)
				}

				if !sent {
					cancel() // Client disconnected, cancel upstream stream
					return
				}
			}
		}

		// Only send the [DONE] marker for plain SSE APIs that expect it.
		// Do NOT send [DONE] for the following cases:
		//   - OpenAI "responses" API and Anthropic messages API: they signal completion by simply closing the stream, not sending [DONE].
		//   - Bedrock: uses AWS Event Stream format rather than SSE with [DONE].
		// DeepIntShield handles any additional cleanup internally on normal stream completion.
		if shouldSendDoneMarker && config.Type != RouteConfigTypeGenAI && config.Type != RouteConfigTypeBedrock {
			if !reader.SendDone() {
				g.logger.Warn("Failed to write SSE done marker: client disconnected")
				cancel()
				return
			}
		}

		// F2: stream finished normally - attribute accumulated usage to the
		// agent's run via the same hook the non-streaming path uses, with a
		// synthesized response carrying the usage/model/text. Off the hot path
		// (body already streamed); gated to agent VKs inside the hook.
		if agenticStream && streamUsage != nil {
			streamContent := streamText.String()
			g.agenticUsageHook(ctx, deepintshieldCtx, deepintshieldReq, &schemas.DeepIntShieldResponse{
				ChatResponse: &schemas.DeepIntShieldChatResponse{
					Model: streamModel,
					Usage: streamUsage,
					Choices: []schemas.DeepIntShieldResponseChoice{{
						ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{
							Message: &schemas.ChatMessage{Content: &schemas.ChatMessageContent{ContentStr: &streamContent}},
						},
					}},
					ExtraFields: schemas.DeepIntShieldResponseExtraFields{ModelRequested: streamModel},
				},
			})
		}
	}()
}

// extractPassthroughModel extracts the model from the passthrough request path and/or body.
// Path patterns: models/{model}, models/{model}:suffix (GenAI), .../models/{model} (Vertex), tunedModels/{model}.
// Body is pre-parsed by parsePassthroughBody to avoid redundant unmarshaling.
func extractPassthroughModel(path string, bodyModel string) string {
	if model := extractModelFromPath(path); model != "" {
		return model
	}
	return bodyModel
}

func extractModelFromPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "models" || p == "tunedModels" {
			if i+1 < len(parts) {
				model := parts[i+1]
				// Strip :suffix for GenAI (e.g. :generateContent, :streamGenerateContent)
				if idx := strings.Index(model, ":"); idx > 0 {
					model = model[:idx]
				}
				return strings.TrimSpace(model)
			}
			break
		}
	}
	return ""
}

// parsePassthroughBody extracts model and streaming flag from the request body in a
// single unmarshal pass. Pass the raw Content-Type header value so multipart boundaries
// are resolved from the header rather than scraped from the body bytes.
func parsePassthroughBody(contentType string, body []byte) (model string, isStream bool) {
	if len(body) == 0 {
		return
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		if boundary := params["boundary"]; boundary != "" {
			return parseMultipartPassthroughBody(body, boundary)
		}
	}
	// JSON (or unknown) body - one unmarshal for both fields.
	var parsed struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := sonic.Unmarshal(body, &parsed); err == nil {
		model = strings.TrimSpace(parsed.Model)
		isStream = parsed.Stream
	}
	return
}

// parseMultipartPassthroughBody scans multipart parts and extracts model and stream.
//   - Form fields (Content-Disposition name="model"/"stream"): read as plain text.
func parseMultipartPassthroughBody(body []byte, boundary string) (model string, isStream bool) {
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		// Plain form field - check by name.
		switch part.FormName() {
		case "model":
			val, _ := io.ReadAll(part)
			part.Close()
			model = strings.TrimSpace(string(val))
		case "stream":
			val, _ := io.ReadAll(part)
			part.Close()
			s := strings.TrimSpace(strings.ToLower(string(val)))
			isStream = s == "true" || s == "1"
		default:
			part.Close()
		}

		if model != "" && isStream {
			break
		}
	}
	return
}

func (g *GenericRouter) handlePassthrough(ctx *fasthttp.RequestCtx) {
	cfg := g.passthroughCfg

	safeHeaders := make(map[string]string)
	ctx.Request.Header.All()(func(key, value []byte) bool {
		keyStr := strings.ToLower(string(key))
		switch keyStr {
		case "authorization", "api-key", "x-api-key", "x-goog-api-key",
			"host", "connection", "transfer-encoding", "cookie", "set-cookie", "proxy-authorization", "accept-encoding":
		default:
			if strings.HasPrefix(keyStr, "x-bf-") {
				return true // drop internal gateway headers
			}
			safeHeaders[keyStr] = string(value)
		}
		return true
	})

	deepintshieldCtx, cancel := lib.ConvertToDeepIntShieldContext(ctx, g.handlerStore.ShouldAllowDirectKeys(), g.handlerStore.GetHeaderMatcher())

	path := string(ctx.Path())
	for _, prefix := range g.passthroughCfg.StripPrefix {
		if strings.HasPrefix(path, prefix) {
			path = path[len(prefix):]
			break
		}
	}

	body := ctx.Request.Body()
	// Parse body once to get both model and stream flag.
	contentType := string(ctx.Request.Header.ContentType())
	bodyModel, bodyStream := parsePassthroughBody(contentType, body)
	resolvedModel := extractPassthroughModel(path, bodyModel)
	provider := cfg.Provider
	if cfg.ProviderDetector != nil {
		provider = cfg.ProviderDetector(ctx, resolvedModel)
	}
	provider = getProviderFromHeader(ctx, provider)
	isStreaming := strings.Contains(strings.ToLower(path), "stream") || bodyStream

	passthroughReq := &schemas.DeepIntShieldPassthroughRequest{
		Method:      string(ctx.Method()),
		Path:        path,
		RawQuery:    string(ctx.URI().QueryString()),
		Body:        body,
		SafeHeaders: safeHeaders,
		Provider:    provider,
		Model:       resolvedModel,
	}

	if isStreaming {
		g.handlePassthroughStream(ctx, deepintshieldCtx, cancel, provider, passthroughReq)
	} else {
		g.handlePassthroughNonStream(ctx, deepintshieldCtx, cancel, provider, passthroughReq)
	}
}

func (g *GenericRouter) handlePassthroughNonStream(
	ctx *fasthttp.RequestCtx,
	deepintshieldCtx *schemas.DeepIntShieldContext,
	cancel context.CancelFunc,
	provider schemas.ModelProvider,
	req *schemas.DeepIntShieldPassthroughRequest,
) {
	defer cancel()

	resp, deepintshieldErr := g.client.Passthrough(deepintshieldCtx, provider, req)
	if deepintshieldErr != nil {
		g.sendError(ctx, deepintshieldCtx, func(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		}, deepintshieldErr)
		return
	}

	ctx.SetStatusCode(resp.StatusCode)
	for k, v := range resp.Headers {
		switch strings.ToLower(k) {
		case "connection", "transfer-encoding", "set-cookie", "proxy-authenticate", "www-authenticate":
			// drop
		default:
			ctx.Response.Header.Set(k, v)
		}
	}
	ctx.Response.SetBody(resp.Body)
}

func (g *GenericRouter) handlePassthroughStream(
	ctx *fasthttp.RequestCtx,
	deepintshieldCtx *schemas.DeepIntShieldContext,
	cancel context.CancelFunc,
	provider schemas.ModelProvider,
	req *schemas.DeepIntShieldPassthroughRequest,
) {
	stream, deepintshieldErr := g.client.PassthroughStream(deepintshieldCtx, provider, req)
	if deepintshieldErr != nil {
		cancel()
		g.sendError(ctx, deepintshieldCtx, func(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		}, deepintshieldErr)
		return
	}

	// Read the first chunk to extract status code and headers before streaming begins.
	firstChunk, ok := <-stream
	if !ok {
		cancel()
		g.sendError(ctx, deepintshieldCtx, func(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		}, newDeepIntShieldError(nil, "passthrough stream ended before headers were received"))
		return
	}
	if firstChunk == nil {
		cancel()
		g.sendError(ctx, deepintshieldCtx, func(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		}, newDeepIntShieldError(nil, "passthrough stream returned nil first chunk"))
		return
	}
	if firstChunk.DeepIntShieldError != nil {
		cancel()
		g.sendError(ctx, deepintshieldCtx, func(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		}, firstChunk.DeepIntShieldError)
		return
	}

	passthroughResp := firstChunk.DeepIntShieldPassthroughResponse
	if passthroughResp == nil {
		cancel()
		g.sendError(ctx, deepintshieldCtx, func(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError) interface{} {
			return err
		}, newDeepIntShieldError(nil, "passthrough stream returned empty first chunk"))
		return
	}

	// Skip post-hook body materialization - ctx.Response.Body() would buffer the entire stream.
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyDeferTraceCompletion, true)

	ctx.SetStatusCode(passthroughResp.StatusCode)
	ctx.SetConnectionClose()
	for k, v := range passthroughResp.Headers {
		switch strings.ToLower(k) {
		case "connection", "transfer-encoding", "content-length", "set-cookie", "proxy-authenticate", "www-authenticate":
			// drop - content-length is invalid for a streaming response
		default:
			ctx.Response.Header.Set(k, v)
		}
	}

	// Use SSEStreamReader to bypass fasthttp's internal pipe batching
	reader := lib.NewSSEStreamReader()
	ctx.Response.SetBodyStream(reader, -1)

	go func() {
		defer func() {
			reader.Done()
			cancel()
		}()

		// Write the first chunk's data.
		if len(passthroughResp.Body) > 0 {
			if !reader.Send(passthroughResp.Body) {
				cancel()
				return
			}
		}

		for chunk := range stream {
			if chunk == nil {
				continue
			}
			if chunk.DeepIntShieldError != nil {
				break
			}
			if chunk.DeepIntShieldPassthroughResponse != nil && len(chunk.DeepIntShieldPassthroughResponse.Body) > 0 {
				if !reader.Send(chunk.DeepIntShieldPassthroughResponse.Body) {
					cancel()
					return
				}
			}
		}
	}()
}
