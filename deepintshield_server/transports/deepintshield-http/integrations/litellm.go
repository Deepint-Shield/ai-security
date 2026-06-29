package integrations

import (
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
)

// LiteLLMRouter holds route registrations for LiteLLM endpoints.
// It supports standard chat completions and image-enabled vision capabilities.
// LiteLLM is fully OpenAI-compatible, so we reuse OpenAI types
// with aliases for clarity and minimal LiteLLM-specific extensions
type LiteLLMRouter struct {
	*GenericRouter
}

// NewLiteLLMRouter creates a new LiteLLMRouter with the given deepintshield client.
func NewLiteLLMRouter(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, logger schemas.Logger) *LiteLLMRouter {
	routes := []RouteConfig{}

	// Add OpenAI routes to LiteLLM for OpenAI API compatibility
	routes = append(routes, CreateOpenAIRouteConfigs("/litellm", handlerStore)...)

	// Add Anthropic routes to LiteLLM for Anthropic API compatibility
	routes = append(routes, CreateAnthropicRouteConfigs("/litellm", logger)...)

	// Add GenAI routes to LiteLLM for Vertex AI compatibility
	routes = append(routes, CreateGenAIRouteConfigs("/litellm")...)

	// Add Bedrock routes to LiteLLM for AWS Bedrock API compatibility
	routes = append(routes, CreateBedrockRouteConfigs("/litellm", handlerStore)...)

	// Add Cohere routes to LiteLLM for Cohere API compatibility
	routes = append(routes, CreateCohereRouteConfigs("/litellm")...)

	return &LiteLLMRouter{
		GenericRouter: NewGenericRouter(client, handlerStore, routes, nil, logger),
	}
}
