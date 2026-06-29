package vllm

import (
	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

func HandleVLLMResponse[T any](responseBody []byte, response *T, requestBody []byte, sendBackRawRequest bool, sendBackRawResponse bool) (rawRequest interface{}, rawResponse interface{}, deepintshieldErr *schemas.DeepIntShieldError) {
	var errorResp schemas.DeepIntShieldError
	rawRequest, rawResponse, deepintshieldErr = providerUtils.HandleProviderResponse(responseBody, response, requestBody, sendBackRawRequest, sendBackRawResponse)
	if deepintshieldErr != nil {
		return rawRequest, rawResponse, deepintshieldErr
	}
	if err := sonic.Unmarshal(responseBody, &errorResp); err == nil && errorResp.Error != nil && errorResp.Error.Message != "" {
		errorResp.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
			Provider: schemas.VLLM,
		}
		return rawRequest, rawResponse, &errorResp
	}
	return rawRequest, rawResponse, nil
}
