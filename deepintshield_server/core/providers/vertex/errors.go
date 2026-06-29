package vertex

import (
	"errors"
	"strings"

	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

func parseVertexError(resp *fasthttp.Response, meta *providerUtils.RequestMetadata) *schemas.DeepIntShieldError {
	var providerName schemas.ModelProvider
	if meta != nil {
		providerName = meta.Provider
	}

	var openAIErr schemas.DeepIntShieldError
	var vertexErr []VertexError

	decodedBody, err := providerUtils.CheckAndDecodeBody(resp)
	if err != nil {
		deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseDecode, err, providerName)
		if meta != nil {
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				Provider:       meta.Provider,
				ModelRequested: meta.Model,
				RequestType:    meta.RequestType,
			}
		}
		return deepintshieldErr
	}

	// Check for empty response
	trimmed := strings.TrimSpace(string(decodedBody))
	if len(trimmed) == 0 {
		deepintshieldErr := &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			StatusCode:     schemas.Ptr(resp.StatusCode()),
			Error: &schemas.ErrorField{
				Message: schemas.ErrProviderResponseEmpty,
			},
		}
		if meta != nil {
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				Provider:       meta.Provider,
				ModelRequested: meta.Model,
				RequestType:    meta.RequestType,
			}
		}
		return deepintshieldErr
	}

	// Check for HTML error response before attempting JSON parsing
	if providerUtils.IsHTMLResponse(resp, decodedBody) {
		deepintshieldErr := &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			StatusCode:     schemas.Ptr(resp.StatusCode()),
			Error: &schemas.ErrorField{
				Message: schemas.ErrProviderResponseHTML,
				Error:   errors.New(string(decodedBody)),
			},
		}
		if meta != nil {
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				Provider:       meta.Provider,
				ModelRequested: meta.Model,
				RequestType:    meta.RequestType,
			}
		}
		return deepintshieldErr
	}

	createError := func(message string) *schemas.DeepIntShieldError {
		deepintshieldErr := providerUtils.NewProviderAPIError(message, nil, resp.StatusCode(), providerName, nil, nil)
		if meta != nil {
			deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
				Provider:       meta.Provider,
				ModelRequested: meta.Model,
				RequestType:    meta.RequestType,
			}
		}
		return deepintshieldErr
	}

	if err := sonic.Unmarshal(decodedBody, &openAIErr); err != nil || openAIErr.Error == nil {
		// Try Vertex error format if OpenAI format fails or is incomplete
		if err := sonic.Unmarshal(decodedBody, &vertexErr); err != nil {
			//try with single Vertex error format
			var vertexErr VertexError
			if err := sonic.Unmarshal(decodedBody, &vertexErr); err != nil {
				// Try VertexValidationError format (validation errors from Mistral endpoint)
				var validationErr VertexValidationError
				if err := sonic.Unmarshal(decodedBody, &validationErr); err != nil {
					deepintshieldErr := providerUtils.NewDeepIntShieldOperationError(schemas.ErrProviderResponseUnmarshal, err, providerName)
					if meta != nil {
						deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
							Provider:       meta.Provider,
							ModelRequested: meta.Model,
							RequestType:    meta.RequestType,
						}
					}
					return deepintshieldErr
				}
				if len(validationErr.Detail) > 0 {
					return createError(validationErr.Detail[0].Msg)
				}
				return createError("Unknown error")
			}
			return createError(vertexErr.Error.Message)
		}
		if len(vertexErr) > 0 {
			return createError(vertexErr[0].Error.Message)
		}
		return createError("Unknown error")
	}
	// OpenAI error format succeeded with valid Error field
	return createError(openAIErr.Error.Message)
}
