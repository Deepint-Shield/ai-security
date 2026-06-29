package elevenlabs

import (
	"strings"

	"github.com/valyala/fasthttp"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

func parseElevenlabsError(resp *fasthttp.Response, meta *providerUtils.RequestMetadata) *schemas.DeepIntShieldError {
	var errorResp ElevenlabsError
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)
	if errorResp.Detail != nil {
		var message string
		// Handle validation errors (array format)
		if len(errorResp.Detail.ValidationErrors) > 0 {
			var messages []string
			var locations []string
			var errorTypes []string

			for _, validationErr := range errorResp.Detail.ValidationErrors {
				// Get message from either Message or Msg field
				msg := validationErr.Message
				if msg == "" {
					msg = validationErr.Msg
				}
				if msg != "" {
					messages = append(messages, msg)
				}

				// Collect location if available
				if len(validationErr.Loc) > 0 {
					locations = append(locations, strings.Join(validationErr.Loc, "."))
				}

				// Collect error type if available
				if validationErr.Type != "" {
					errorTypes = append(errorTypes, validationErr.Type)
				}
			}

			// Build combined message
			if len(messages) > 0 {
				message = strings.Join(messages, "; ")
			}
			if len(locations) > 0 {
				locationStr := strings.Join(locations, ", ")
				message = message + " [" + locationStr + "]"
			}

			errorType := ""
			if len(errorTypes) > 0 {
				errorType = strings.Join(errorTypes, ", ")
			}

			if message != "" {
				result := &schemas.DeepIntShieldError{
					IsDeepIntShieldError: false,
					StatusCode:     schemas.Ptr(resp.StatusCode()),
					Error: &schemas.ErrorField{
						Type:    schemas.Ptr(errorType),
						Message: message,
					},
				}
				if meta != nil {
					result.ExtraFields.Provider = meta.Provider
					result.ExtraFields.ModelRequested = meta.Model
					result.ExtraFields.RequestType = meta.RequestType
				}
				return result
			}
		}

		// Handle non-validation errors (single object format)
		if errorResp.Detail.Message != nil {
			message = *errorResp.Detail.Message
		}

		errorType := ""
		if errorResp.Detail.Status != nil {
			errorType = *errorResp.Detail.Status
		}

		if message != "" {
			if deepintshieldErr.Error == nil {
				deepintshieldErr.Error = &schemas.ErrorField{}
			}
			deepintshieldErr.Error.Type = schemas.Ptr(errorType)
			deepintshieldErr.Error.Message = message
		}
	}
	if meta != nil {
		deepintshieldErr.ExtraFields.Provider = meta.Provider
		deepintshieldErr.ExtraFields.ModelRequested = meta.Model
		deepintshieldErr.ExtraFields.RequestType = meta.RequestType
	}
	return deepintshieldErr
}
