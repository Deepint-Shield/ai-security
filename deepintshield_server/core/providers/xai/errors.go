package xai

import (
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// XAIErrorResponse represents xAI's error response format
type XAIErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// ParseXAIError parses xAI-specific error responses.
// xAI returns errors in format: {"code": "...", "error": "..."}
// Unlike OpenAI which uses: {"error": {"message": "...", "type": "...", "code": "..."}}
func ParseXAIError(resp *fasthttp.Response, requestType schemas.RequestType, providerName schemas.ModelProvider, model string) *schemas.DeepIntShieldError {
	// Try to parse xAI error format
	var xaiErr XAIErrorResponse
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &xaiErr)

	if deepintshieldErr == nil {
		return nil
	}

	// If we successfully parsed xAI format, extract the fields
	if xaiErr.Error != "" {
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		deepintshieldErr.Error.Message = xaiErr.Error
		if xaiErr.Code != "" {
			deepintshieldErr.Error.Code = schemas.Ptr(xaiErr.Code)
		}
	}

	// Set ExtraFields individually to preserve RawResponse from HandleProviderAPIError
	deepintshieldErr.ExtraFields.Provider = providerName
	deepintshieldErr.ExtraFields.ModelRequested = model
	deepintshieldErr.ExtraFields.RequestType = requestType

	return deepintshieldErr
}
