package runway

import (
	"strings"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// parseRunwayError parses Runway API error responses and converts them to DeepIntShieldError.
func parseRunwayError(resp *fasthttp.Response, meta *providerUtils.RequestMetadata) *schemas.DeepIntShieldError {
	// Parse as RunwayAPIError
	var errorResp RunwayAPIError
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)

	// Set error message if available
	if errorResp.Error != "" {
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		deepintshieldErr.Error.Message = errorResp.Error
	} else if deepintshieldErr.Error != nil && deepintshieldErr.Error.Message == "" {
		// If no error message was extracted, use a generic one
		deepintshieldErr.Error.Message = "Runway API request failed"
	} else if deepintshieldErr.Error == nil {
		deepintshieldErr.Error = &schemas.ErrorField{
			Message: "Runway API request failed",
		}
	}

	// Remove trailing newlines
	if deepintshieldErr.Error != nil && deepintshieldErr.Error.Message != "" {
		deepintshieldErr.Error.Message = strings.TrimRight(deepintshieldErr.Error.Message, "\n")
	}

	// Set metadata
	if meta != nil {
		deepintshieldErr.ExtraFields.Provider = meta.Provider
		deepintshieldErr.ExtraFields.ModelRequested = meta.Model
		deepintshieldErr.ExtraFields.RequestType = meta.RequestType
	}

	return deepintshieldErr
}
