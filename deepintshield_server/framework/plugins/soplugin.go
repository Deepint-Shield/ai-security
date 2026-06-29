package plugins

import (
	"context"
	"plugin"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// DynamicPlugin is a generic dynamic plugin that can implement any combination of plugin interfaces
// It uses optional function pointers - nil pointers indicate the interface is not implemented
type DynamicPlugin struct {
	Enabled bool
	Path    string
	Config  any

	filename string
	plugin   *plugin.Plugin

	// BasePlugin (required)
	getName func() string
	cleanup func() error

	// HTTPTransportPlugin (optional)
	httpTransportPreHook         func(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error)
	httpTransportPostHook        func(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error
	httpTransportStreamChunkHook func(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, stream *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error)

	// LLMPlugin (optional)
	preLLMHook  func(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error)
	postLLMHook func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error)

	// MCPPlugin (optional)
	preMCPHook  func(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, error)
	postMCPHook func(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError, error)

	// ObservabilityPlugin (optional)
	inject func(ctx context.Context, trace *schemas.Trace) error
}

// GetName returns the name of the plugin (BasePlugin interface)
func (dp *DynamicPlugin) GetName() string {
	return dp.getName()
}

// Cleanup is invoked by core/deepintshield.go during plugin unload, reload, and shutdown (BasePlugin interface)
func (dp *DynamicPlugin) Cleanup() error {
	return dp.cleanup()
}

// HTTPTransportPreHook intercepts HTTP requests at the transport layer before entering DeepIntShield core (HTTPTransportPlugin interface)
func (dp *DynamicPlugin) HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	if dp.httpTransportPreHook == nil {
		return nil, nil // No-op if not implemented
	}
	return dp.httpTransportPreHook(ctx, req)
}

// HTTPTransportPostHook intercepts HTTP responses at the transport layer after exiting DeepIntShield core (HTTPTransportPlugin interface)
func (dp *DynamicPlugin) HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	if dp.httpTransportPostHook == nil {
		return nil // No-op if not implemented
	}
	return dp.httpTransportPostHook(ctx, req, resp)
}

// HTTPTransportStreamChunkHook intercepts streaming chunks before they are written to the client
func (dp *DynamicPlugin) HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, stream *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	if dp.httpTransportStreamChunkHook == nil {
		return stream, nil // No-op if not implemented
	}
	return dp.httpTransportStreamChunkHook(ctx, req, stream)
}

// PreLLMHook is invoked before LLM provider calls (LLMPlugin interface)
func (dp *DynamicPlugin) PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	if dp.preLLMHook == nil {
		return req, nil, nil // No-op if not implemented
	}
	return dp.preLLMHook(ctx, req)
}

// PostLLMHook is invoked after LLM provider calls (LLMPlugin interface)
func (dp *DynamicPlugin) PostLLMHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	if dp.postLLMHook == nil {
		return resp, deepintshieldErr, nil // No-op if not implemented
	}
	return dp.postLLMHook(ctx, resp, deepintshieldErr)
}

// PreMCPHook is invoked before MCP calls (MCPPlugin interface)
func (dp *DynamicPlugin) PreMCPHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if dp.preMCPHook == nil {
		return req, nil, nil // No-op if not implemented
	}
	return dp.preMCPHook(ctx, req)
}

// PostMCPHook is invoked after MCP calls (MCPPlugin interface)
func (dp *DynamicPlugin) PostMCPHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldMCPResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldMCPResponse, *schemas.DeepIntShieldError, error) {
	if dp.postMCPHook == nil {
		return resp, deepintshieldErr, nil // No-op if not implemented
	}
	return dp.postMCPHook(ctx, resp, deepintshieldErr)
}

// Inject receives completed traces for observability backends (ObservabilityPlugin interface)
func (dp *DynamicPlugin) Inject(ctx context.Context, trace *schemas.Trace) error {
	if dp.inject == nil {
		return nil // No-op if not implemented
	}
	return dp.inject(ctx, trace)
}
