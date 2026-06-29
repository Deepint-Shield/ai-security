// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains integration management handlers for AI provider integrations.
package handlers

import (
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/integrations"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
)

// IntegrationHandler manages HTTP requests for AI provider integrations
type IntegrationHandler struct {
	extensions  []integrations.ExtensionRouter
	wsResponses *WSResponsesHandler
}

// NewIntegrationHandler creates a new integration handler instance.
// wsResponses may be nil if WebSocket support is not configured.
func NewIntegrationHandler(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, wsResponses *WSResponsesHandler) *IntegrationHandler {
	// Initialize all available integration routers
	extensions := []integrations.ExtensionRouter{
		integrations.NewOpenAIRouter(client, handlerStore, logger),
		integrations.NewAnthropicRouter(client, handlerStore, logger),
		integrations.NewGenAIRouter(client, handlerStore, logger),
		integrations.NewLiteLLMRouter(client, handlerStore, logger),
		integrations.NewCohereRouter(client, handlerStore, logger),
		integrations.NewLangChainRouter(client, handlerStore, logger),
		integrations.NewPydanticAIRouter(client, handlerStore, logger),
		integrations.NewBedrockRouter(client, handlerStore, logger),
		// passthrough routers
		integrations.NewGenAIPassthroughRouter(client, handlerStore, logger),
		integrations.NewOpenAIPassthroughRouter(client, handlerStore, logger),
		integrations.NewAnthropicPassthroughRouter(client, handlerStore, logger),
		integrations.NewCursorRouter(client, handlerStore, logger),
	}

	return &IntegrationHandler{
		extensions:  extensions,
		wsResponses: wsResponses,
	}
}

// RegisterRoutes registers all integration routes for AI provider compatibility endpoints
func (h *IntegrationHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// Register routes for each integration extension
	for _, extension := range h.extensions {
		extension.RegisterRoutes(r, middlewares...)
	}
	// Register WebSocket routes (base path + integration paths)
	if h.wsResponses != nil {
		h.wsResponses.RegisterRoutes(r, middlewares...)
	}
}

// SetLargePayloadHook sets the large payload detection hook on all integration routers
// that support it. This is used by enterprise to inject large payload optimization.
func (h *IntegrationHandler) SetLargePayloadHook(hook integrations.LargePayloadHook) {
	for _, extension := range h.extensions {
		if setter, ok := extension.(interface {
			SetLargePayloadHook(integrations.LargePayloadHook)
		}); ok {
			setter.SetLargePayloadHook(hook)
		}
	}
}

// SetLargeResponseHook sets the large response scanning hook on all integration routers
// that support it. Enterprise uses this to inject Phase B usage extraction into the
// response stream without embedding scanning logic in the OSS router.
func (h *IntegrationHandler) SetLargeResponseHook(hook integrations.LargeResponseHook) {
	for _, extension := range h.extensions {
		if setter, ok := extension.(interface {
			SetLargeResponseHook(integrations.LargeResponseHook)
		}); ok {
			setter.SetLargeResponseHook(hook)
		}
	}
}

// SetAgenticCacheBridgeHook fans the agentic-cache bridge to every integration
// router that supports it (every router built on top of GenericRouter). After
// this wiring, every /openai/v1/..., /genai/..., /anthropic/... non-streaming
// response also fires the semantic-cache → agentic-cache bridge - so the
// Agentic Cache dashboard tab populates from the same traffic the LLM
// dashboards already see.
func (h *IntegrationHandler) SetAgenticCacheBridgeHook(hook integrations.AgenticCacheBridgeHook) {
	for _, extension := range h.extensions {
		if setter, ok := extension.(interface {
			SetAgenticCacheBridgeHook(integrations.AgenticCacheBridgeHook)
		}); ok {
			setter.SetAgenticCacheBridgeHook(hook)
		}
	}
}

// SetAgenticLLMUsageHook fans the agentic LLM-usage bridge to every integration
// router built on GenericRouter. After this wiring, every /openai/v1/...,
// /genai/..., /anthropic/... non-streaming chat/text/responses call attributes
// its tokens / cost to the agent's observability trace (gated to agent VKs) -
// so the Cost & Tokens / Top Models / Tokens-per-$ panels populate from the
// compat surfaces, not just the direct /v1/chat/completions route.
func (h *IntegrationHandler) SetAgenticLLMUsageHook(hook integrations.AgenticLLMUsageHook) {
	for _, extension := range h.extensions {
		if setter, ok := extension.(interface {
			SetAgenticLLMUsageHook(integrations.AgenticLLMUsageHook)
		}); ok {
			setter.SetAgenticLLMUsageHook(hook)
		}
	}
}
