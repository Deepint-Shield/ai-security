package replicate

import (
	"github.com/bytedance/sonic"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

// parseReplicateError parses Replicate API error response
func parseReplicateError(body []byte, statusCode int) *schemas.DeepIntShieldError {
	var replicateErr ReplicateError
	if err := sonic.Unmarshal(body, &replicateErr); err == nil && replicateErr.Detail != "" {
		return &schemas.DeepIntShieldError{
			IsDeepIntShieldError: false,
			StatusCode:     &statusCode,
			Error: &schemas.ErrorField{
				Message: replicateErr.Detail,
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider: schemas.Replicate,
			},
		}
	}

	// Fallback to generic error
	return &schemas.DeepIntShieldError{
		IsDeepIntShieldError: false,
		StatusCode:     &statusCode,
		Error: &schemas.ErrorField{
			Message: string(body),
		},
		ExtraFields: schemas.DeepIntShieldErrorExtraFields{
			Provider: schemas.Replicate,
		},
	}
}
