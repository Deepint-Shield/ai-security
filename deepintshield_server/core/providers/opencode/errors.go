package opencode

import (
	"fmt"
	"strings"

	"github.com/bytedance/sonic"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// opencodeErrorBody is the JSON envelope returned by Opencode Zen/Go API errors.
// Format: {"type": "error", "error": {"type": "...", "message": "..."}}
type opencodeErrorBody struct {
	Type  string             `json:"type"`
	Error opencodeErrorInner `json:"error"`
}

type opencodeErrorInner struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// parseOpencodeError parses Opencode-specific error responses.
// Opencode uses {"type":"error","error":{"type":"...","message":"..."}} instead
// of OpenAI's {"error":{"message":"...","type":"...","code":...}}.
// It satisfies the openai.ErrorConverter signature; the request type, provider
// name, and model are not needed to decode Opencode's error envelope.
func parseOpencodeError(resp *fasthttp.Response, _ schemas.RequestType, _ schemas.ModelProvider, _ string) *schemas.DeepIntShieldError {
	var providerErr schemas.DeepIntShieldError

	// First, let the generic handler parse HTTP status and set base fields.
	_ = providerUtils.HandleProviderAPIError(resp, &providerErr)

	// Ensure Error is non-nil before accessing its fields.
	if providerErr.Error == nil {
		providerErr.Error = &schemas.ErrorField{}
	}

	// Then overlay Opencode-specific error details from the body.
	if body := resp.Body(); len(body) > 0 {
		var parsed opencodeErrorBody
		if err := sonic.Unmarshal(body, &parsed); err == nil && parsed.Type == "error" {
			if parsed.Error.Message != "" {
				providerErr.Error.Message = parsed.Error.Message
			}
			if parsed.Error.Type != "" {
				providerErr.Error.Type = &parsed.Error.Type
			}
		}
	}

	// Ensure we always have a non-empty error message.
	if strings.TrimSpace(providerErr.Error.Message) == "" {
		if providerErr.StatusCode != nil {
			providerErr.Error.Message = fmt.Sprintf("provider API error (status %d)", *providerErr.StatusCode)
		} else {
			providerErr.Error.Message = "provider API error"
		}
	}

	return &providerErr
}
