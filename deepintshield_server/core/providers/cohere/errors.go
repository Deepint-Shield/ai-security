package cohere

import (
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

func parseCohereError(resp *fasthttp.Response, meta *providerUtils.RequestMetadata) *schemas.DeepIntShieldError {
	var errorResp CohereError
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)
	deepintshieldErr.Type = &errorResp.Type
	if deepintshieldErr.Error == nil {
		deepintshieldErr.Error = &schemas.ErrorField{}
	}
	deepintshieldErr.Error.Message = errorResp.Message
	if errorResp.Code != nil {
		deepintshieldErr.Error.Code = errorResp.Code
	}
	if meta != nil {
		deepintshieldErr.ExtraFields.Provider = meta.Provider
		deepintshieldErr.ExtraFields.ModelRequested = meta.Model
		deepintshieldErr.ExtraFields.RequestType = meta.RequestType
	}
	return deepintshieldErr
}
