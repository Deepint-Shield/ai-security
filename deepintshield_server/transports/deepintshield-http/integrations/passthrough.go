package integrations

import (
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
)

// PassthroughRouter is a catch-all router that forwards all requests directly
// to the provider without matching against known route patterns.
type PassthroughRouter struct {
	*GenericRouter
}

// NewPassthroughRouter creates a passthrough-only router for any prefix/provider combo.
func NewPassthroughRouter(
	client *deepintshield.DeepIntShield,
	handlerStore lib.HandlerStore,
	logger schemas.Logger,
	cfg *PassthroughConfig,
) *PassthroughRouter {
	if cfg == nil {
		cfg = &PassthroughConfig{}
	}
	return &PassthroughRouter{
		GenericRouter: NewGenericRouter(client, handlerStore, nil, cfg, logger),
	}
}

// NewAnthropicPassthroughRouter creates a passthrough router for /anthropic_passthrough.
func NewAnthropicPassthroughRouter(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, logger schemas.Logger) *PassthroughRouter {
	return NewPassthroughRouter(client, handlerStore, logger, &PassthroughConfig{
		Provider: schemas.Anthropic,
		StripPrefix: []string{
			"/anthropic_passthrough",
		},
	})
}

// NewOpenAIPassthroughRouter creates a passthrough router for /openai_passthrough.
func NewOpenAIPassthroughRouter(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, logger schemas.Logger) *PassthroughRouter {
	return NewPassthroughRouter(client, handlerStore, logger, &PassthroughConfig{
		Provider: schemas.OpenAI,
		StripPrefix: []string{
			"/openai_passthrough",
		},
	})
}

// NewGenAIPassthroughRouter creates a passthrough router for /genai_passthrough.
func NewGenAIPassthroughRouter(client *deepintshield.DeepIntShield, handlerStore lib.HandlerStore, logger schemas.Logger) *PassthroughRouter {
	return NewPassthroughRouter(client, handlerStore, logger, &PassthroughConfig{
		Provider:         schemas.Gemini,
		ProviderDetector: detectProviderFromGenAIRequest,
		StripPrefix: []string{
			"/genai_passthrough/v1beta1",
			"/genai_passthrough/v1beta",
			"/genai_passthrough/v1",
			"/genai_passthrough",
		},
	})
}
