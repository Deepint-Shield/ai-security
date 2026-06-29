package bedrock

import (
	"net/http"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

func parseBedrockHTTPError(statusCode int, headers http.Header, body []byte) *schemas.DeepIntShieldError {
	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(fastResp)

	fastResp.SetStatusCode(statusCode)
	for k, values := range headers {
		for _, value := range values {
			fastResp.Header.Add(k, value)
		}
	}
	fastResp.SetBody(body)

	var errorResp BedrockError
	deepintshieldErr := providerUtils.HandleProviderAPIError(fastResp, &errorResp)
	if errorResp.Message != "" {
		if deepintshieldErr.Error == nil {
			deepintshieldErr.Error = &schemas.ErrorField{}
		}
		deepintshieldErr.Error.Message = errorResp.Message
		deepintshieldErr.Error.Code = errorResp.Code
	}

	return deepintshieldErr
}
