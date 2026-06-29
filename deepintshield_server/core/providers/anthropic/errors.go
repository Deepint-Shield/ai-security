package anthropic

import (
	"fmt"

	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// ToAnthropicChatCompletionError converts a DeepIntShieldError to AnthropicMessageError
func ToAnthropicChatCompletionError(deepintshieldErr *schemas.DeepIntShieldError) *AnthropicMessageError {
	if deepintshieldErr == nil {
		return nil
	}

	// Safely extract type and message from nested error
	errorType := "api_error"
	message := ""
	if deepintshieldErr.Error != nil {
		if deepintshieldErr.Error.Type != nil && *deepintshieldErr.Error.Type != "" {
			errorType = *deepintshieldErr.Error.Type
		}
		message = deepintshieldErr.Error.Message
	}

	// Handle nested error fields with nil checks
	errorStruct := AnthropicMessageErrorStruct{
		Type:    errorType,
		Message: message,
	}

	return &AnthropicMessageError{
		Type:  "error", // always "error" for Anthropic
		Error: errorStruct,
	}
}

// ToAnthropicResponsesStreamError converts a DeepIntShieldError to Anthropic responses streaming error in SSE format
func ToAnthropicResponsesStreamError(deepintshieldErr *schemas.DeepIntShieldError) string {
	if deepintshieldErr == nil {
		return ""
	}

	anthropicErr := ToAnthropicChatCompletionError(deepintshieldErr)

	// Marshal to JSON
	jsonData, err := sonic.Marshal(anthropicErr)
	if err != nil {
		return ""
	}

	// Format as Anthropic SSE error event
	return fmt.Sprintf("event: error\ndata: %s\n\n", jsonData)
}

func parseAnthropicError(resp *fasthttp.Response, meta *providerUtils.RequestMetadata) *schemas.DeepIntShieldError {
	var errorResp AnthropicError
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)
	if errorResp.Error != nil {
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		deepintshieldErr.Error.Type = &errorResp.Error.Type
		deepintshieldErr.Error.Message = errorResp.Error.Message
	}
	if meta != nil {
		deepintshieldErr.ExtraFields.Provider = meta.Provider
		deepintshieldErr.ExtraFields.ModelRequested = meta.Model
		deepintshieldErr.ExtraFields.RequestType = meta.RequestType
	}
	return deepintshieldErr
}
