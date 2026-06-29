package openai

import (
	"fmt"
	"strings"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// ErrorConverter is a function that converts provider-specific error responses to DeepIntShieldError.
type ErrorConverter func(resp *fasthttp.Response, requestType schemas.RequestType, providerName schemas.ModelProvider, model string) *schemas.DeepIntShieldError

// ParseOpenAIError parses OpenAI error responses.
func ParseOpenAIError(resp *fasthttp.Response, requestType schemas.RequestType, providerName schemas.ModelProvider, model string) *schemas.DeepIntShieldError {
	var errorResp schemas.DeepIntShieldError

	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)

	if errorResp.EventID != nil {
		deepintshieldErr.EventID = errorResp.EventID
	}

	if errorResp.Error != nil {
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		deepintshieldErr.Error.Type = errorResp.Error.Type
		deepintshieldErr.Error.Code = errorResp.Error.Code
		if errorResp.Error.Message != "" {
			deepintshieldErr.Error.Message = errorResp.Error.Message
		}
		deepintshieldErr.Error.Param = errorResp.Error.Param
		if errorResp.Error.EventID != nil {
			deepintshieldErr.Error.EventID = errorResp.Error.EventID
		}
	}

	if deepintshieldErr.Error == nil {
		deepintshieldErr.Error = &schemas.ErrorField{}
	}
	if strings.TrimSpace(deepintshieldErr.Error.Message) == "" {
		if deepintshieldErr.StatusCode != nil {
			deepintshieldErr.Error.Message = fmt.Sprintf("provider API error (status %d)", *deepintshieldErr.StatusCode)
		} else {
			deepintshieldErr.Error.Message = "provider API error"
		}
	}

	// Set ExtraFields unconditionally so provider/model/request metadata is always attached
	if deepintshieldErr != nil {
		deepintshieldErr.ExtraFields.Provider = providerName
		deepintshieldErr.ExtraFields.ModelRequested = model
		deepintshieldErr.ExtraFields.RequestType = requestType
	}

	return deepintshieldErr
}
