package main

import (
	"fmt"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func Init(config any) error {
	fmt.Println("Init called")
	return nil
}

// GetName returns the name of the plugin (required)
// This is the system identifier - not editable by users
// Users can set a custom display_name in the config for the UI
func GetName() string {
	return "hello-world"
}

func HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	fmt.Println("HTTPTransportPreHook called")
	// Modify request in-place
	req.Headers["x-hello-world-plugin"] = "transport-pre-hook-value"
	// Store value in context for PreLLMHook/PostLLMHook
	ctx.SetValue(schemas.DeepIntShieldContextKey("hello-world-plugin-transport-pre-hook"), "transport-pre-hook-value")	
	// Return nil to continue processing, or return &schemas.HTTPResponse{} to short-circuit
	return nil, nil
}

func HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	fmt.Println("HTTPTransportPostHook called")
	// Modify response in-place
	resp.Headers["x-hello-world-plugin"] = "transport-post-hook-value"
	// Store value in context
	ctx.SetValue(schemas.DeepIntShieldContextKey("hello-world-plugin-transport-post-hook"), "transport-post-hook-value")
	// Return nil to continue processing
	return nil
}

func HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, chunk *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	fmt.Println("HTTPTransportStreamChunkHook called")
	// Modify chunk in-place
	if chunk.DeepIntShieldChatResponse != nil && chunk.DeepIntShieldChatResponse.Choices != nil && len(chunk.DeepIntShieldChatResponse.Choices) > 0 && chunk.DeepIntShieldChatResponse.Choices[0].ChatStreamResponseChoice != nil && chunk.DeepIntShieldChatResponse.Choices[0].ChatStreamResponseChoice.Delta != nil && chunk.DeepIntShieldChatResponse.Choices[0].ChatStreamResponseChoice.Delta.Content != nil {
		*chunk.DeepIntShieldChatResponse.Choices[0].ChatStreamResponseChoice.Delta.Content += " - modified by hello-world-plugin"
	}
	// Return the modified chunk
	return chunk, nil
}

func PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	value1 := ctx.Value(schemas.DeepIntShieldContextKey("hello-world-plugin-transport-pre-hook"))
	fmt.Println("value1:", value1)
	ctx.SetValue(schemas.DeepIntShieldContextKey("hello-world-plugin-pre-hook"), "pre-hook-value")
	fmt.Println("PreLLMHook called")
	return req, nil, nil
}

func PostLLMHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	fmt.Println("PostLLMHook called")
	value1 := ctx.Value(schemas.DeepIntShieldContextKey("hello-world-plugin-transport-pre-hook"))
	fmt.Println("value1:", value1)
	value2 := ctx.Value(schemas.DeepIntShieldContextKey("hello-world-plugin-pre-hook"))
	fmt.Println("value2:", value2)
	return resp, deepintshieldErr, nil
}

func Cleanup() error {
	fmt.Println("Cleanup called")
	return nil
}
