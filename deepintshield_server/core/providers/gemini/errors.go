package gemini

import (
	"strconv"
	"strings"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// ToGeminiError derives a GeminiGenerationError from a DeepIntShieldError
func ToGeminiError(deepintshieldErr *schemas.DeepIntShieldError) *GeminiGenerationError {
	if deepintshieldErr == nil {
		return nil
	}
	code := 500
	status := ""
	if deepintshieldErr.Error != nil && deepintshieldErr.Error.Type != nil {
		status = *deepintshieldErr.Error.Type
	}
	message := ""
	if deepintshieldErr.Error != nil && deepintshieldErr.Error.Message != "" {
		message = deepintshieldErr.Error.Message
	}
	if deepintshieldErr.StatusCode != nil {
		code = *deepintshieldErr.StatusCode
	}
	return &GeminiGenerationError{
		Error: &GeminiGenerationErrorStruct{
			Code:    code,
			Message: message,
			Status:  status,
		},
	}
}

// parseGeminiError parses Gemini error responses
func parseGeminiError(resp *fasthttp.Response, meta *providerUtils.RequestMetadata) *schemas.DeepIntShieldError {
	// Try to parse as []GeminiGenerationError
	var errorResps []GeminiGenerationError
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResps)
	if len(errorResps) > 0 {
		var message string
		var firstError *GeminiGenerationErrorStruct
		for _, errorResp := range errorResps {
			if errorResp.Error != nil {
				if firstError == nil {
					firstError = errorResp.Error
				}
				message = message + errorResp.Error.Message + "\n"
			}
		}
		// Trim trailing newline
		message = strings.TrimSuffix(message, "\n")
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		// Set Code from first error if available
		if firstError != nil {
			deepintshieldErr.Error.Code = schemas.Ptr(strconv.Itoa(firstError.Code))
		}
		// Set Message to trimmed concatenated message
		deepintshieldErr.Error.Message = message
		if meta != nil {
			deepintshieldErr.ExtraFields.Provider = meta.Provider
			deepintshieldErr.ExtraFields.ModelRequested = meta.Model
			deepintshieldErr.ExtraFields.RequestType = meta.RequestType
		}
		return deepintshieldErr
	}

	// Try to parse as GeminiGenerationError
	var errorResp GeminiGenerationError
	deepintshieldErr = providerUtils.HandleProviderAPIError(resp, &errorResp)
	if errorResp.Error != nil {
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		deepintshieldErr.Error.Code = schemas.Ptr(strconv.Itoa(errorResp.Error.Code))
		deepintshieldErr.Error.Message = errorResp.Error.Message
	}
	if meta != nil {
		deepintshieldErr.ExtraFields.Provider = meta.Provider
		deepintshieldErr.ExtraFields.ModelRequested = meta.Model
		deepintshieldErr.ExtraFields.RequestType = meta.RequestType
	}
	return deepintshieldErr
}
