package litellmcompat

import (
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/modelcatalog"
)

// transformTextToChatRequest converts a text completion request to a chat completion request
// if the model doesn't support text completion natively.
// It updates the TransformContext with the transformation state.
func transformTextToChatRequest(_ *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest, tc *TransformContext, mc *modelcatalog.ModelCatalog, logger schemas.Logger) *schemas.DeepIntShieldRequest {
	// Only process text completion requests
	if req.RequestType != schemas.TextCompletionRequest && req.RequestType != schemas.TextCompletionStreamRequest {
		return req
	}

	// Check if text completion request is present
	if req.TextCompletionRequest == nil || tc == nil {
		return req
	}

	// Check if the model supports text completion via model catalog
	if mc != nil {
		provider := req.TextCompletionRequest.Provider
		model := req.TextCompletionRequest.Model
		if mc.IsTextCompletionSupported(model, provider) {
			if logger != nil {
				logger.Debug("litellmcompat: model %s/%s supports text completion, skipping conversion", provider, model)
			}
			return req
		}
	}

	// Convert text completion to chat completion
	chatRequest := req.TextCompletionRequest.ToDeepIntShieldChatRequest()
	if chatRequest == nil {
		return req
	}

	// Track the transformation
	tc.TextToChatApplied = true
	tc.OriginalRequestType = req.RequestType
	tc.OriginalModel = req.TextCompletionRequest.Model
	tc.IsStreaming = req.RequestType == schemas.TextCompletionStreamRequest

	// Create a new request with the chat completion
	transformedReq := &schemas.DeepIntShieldRequest{
		ChatRequest: chatRequest,
	}

	// Set the appropriate request type
	if tc.IsStreaming {
		transformedReq.RequestType = schemas.ChatCompletionStreamRequest
	} else {
		transformedReq.RequestType = schemas.ChatCompletionRequest
	}

	if logger != nil {
		logger.Debug("litellmcompat: converted text completion to chat completion for model %s (text completion not supported)", tc.OriginalModel)
	}

	return transformedReq
}

// transformTextToChatResponse converts a chat response back to text completion format
// if the original request was a text completion that was converted.
func transformTextToChatResponse(_ *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, tc *TransformContext, logger schemas.Logger) *schemas.DeepIntShieldResponse {
	// Only transform if we converted text completion to chat
	if !tc.TextToChatApplied {
		return resp
	}

	// Check if we have a chat response to transform
	if resp == nil || resp.ChatResponse == nil {
		return resp
	}

	// Convert chat response to text completion response
	textCompletionResponse := resp.ChatResponse.ToTextCompletionResponse()
	if textCompletionResponse == nil {
		return resp
	}

	// Restore original request type metadata
	textCompletionResponse.ExtraFields.RequestType = tc.OriginalRequestType
	textCompletionResponse.ExtraFields.ModelRequested = tc.OriginalModel
	textCompletionResponse.ExtraFields.LiteLLMCompat = true

	if logger != nil {
		logger.Debug("litellmcompat: converted chat response back to text completion for model %s", tc.OriginalModel)
	}

	// Return a new response with the text completion
	return &schemas.DeepIntShieldResponse{
		TextCompletionResponse: textCompletionResponse,
	}
}

// transformTextToChatError ensures error metadata reflects the original request type
// if a text completion request was converted to chat.
func transformTextToChatError(_ *schemas.DeepIntShieldContext, err *schemas.DeepIntShieldError, tc *TransformContext) *schemas.DeepIntShieldError {
	if tc == nil || err == nil {
		return err
	}

	// Only transform if we converted text completion to chat
	if !tc.TextToChatApplied {
		return err
	}

	// Restore original request type in error metadata
	err.ExtraFields.RequestType = tc.OriginalRequestType
	err.ExtraFields.ModelRequested = tc.OriginalModel
	err.ExtraFields.LiteLLMCompat = true

	return err
}

// TransformTextToChatStreamResponse transforms a streaming chat response back to text completion format.
// This is exported for use by streaming handlers.
func TransformTextToChatStreamResponse(ctx *schemas.DeepIntShieldContext, stream *schemas.DeepIntShieldStreamChunk, tc *TransformContext) *schemas.DeepIntShieldStreamChunk {
	if tc == nil {
		return stream
	}

	// Only transform if we converted text completion to chat
	if !tc.TextToChatApplied {
		return stream
	}

	// Check if we have a chat response in the stream to transform
	if stream == nil || stream.DeepIntShieldChatResponse == nil {
		return stream
	}

	// Convert chat response to text completion response
	textCompletionResponse := stream.DeepIntShieldChatResponse.ToTextCompletionResponse()
	if textCompletionResponse == nil {
		return stream
	}

	// Restore original request type metadata
	textCompletionResponse.ExtraFields.RequestType = tc.OriginalRequestType
	textCompletionResponse.ExtraFields.ModelRequested = tc.OriginalModel
	textCompletionResponse.ExtraFields.LiteLLMCompat = true

	// Return a new stream with the text completion response
	return &schemas.DeepIntShieldStreamChunk{
		DeepIntShieldTextCompletionResponse: textCompletionResponse,
	}
}
