//go:build !tinygo && !wasm

package mcp

import (
	"context"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// MCPManagerInterface defines the interface for MCP management functionality.
// This interface allows different implementations (OSS and Enterprise) to be used
// interchangeably in the DeepIntShield core.
type MCPManagerInterface interface {
	// Tool Operations
	// AddToolsToRequest parses available MCP tools and adds them to the request
	AddToolsToRequest(ctx context.Context, req *schemas.DeepIntShieldRequest) *schemas.DeepIntShieldRequest

	// GetAvailableTools returns all available MCP tools for the given context
	GetAvailableTools(ctx context.Context) []schemas.ChatTool

	// ExecuteToolCall executes a single tool call and returns the result
	ExecuteToolCall(ctx *schemas.DeepIntShieldContext, request *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPResponse, error)

	// UpdateToolManagerConfig updates the configuration for the tool manager
	UpdateToolManagerConfig(config *schemas.MCPToolManagerConfig)

	// Agent Mode Operations
	// CheckAndExecuteAgentForChatRequest handles agent mode for Chat Completions API
	CheckAndExecuteAgentForChatRequest(
		ctx *schemas.DeepIntShieldContext,
		req *schemas.DeepIntShieldChatRequest,
		response *schemas.DeepIntShieldChatResponse,
		makeReq func(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldChatRequest) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError),
		executeTool func(ctx *schemas.DeepIntShieldContext, request *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPResponse, error),
	) (*schemas.DeepIntShieldChatResponse, *schemas.DeepIntShieldError)

	// CheckAndExecuteAgentForResponsesRequest handles agent mode for Responses API
	CheckAndExecuteAgentForResponsesRequest(
		ctx *schemas.DeepIntShieldContext,
		req *schemas.DeepIntShieldResponsesRequest,
		response *schemas.DeepIntShieldResponsesResponse,
		makeReq func(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldResponsesRequest) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError),
		executeTool func(ctx *schemas.DeepIntShieldContext, request *schemas.DeepIntShieldMCPRequest) (*schemas.DeepIntShieldMCPResponse, error),
	) (*schemas.DeepIntShieldResponsesResponse, *schemas.DeepIntShieldError)

	// Client Management
	// GetClients returns all MCP clients
	GetClients() []schemas.MCPClientState

	// AddClient adds a new MCP client with the given configuration
	AddClient(config *schemas.MCPClientConfig) error

	// RemoveClient removes an MCP client by ID
	RemoveClient(id string) error

	// UpdateClient updates an existing MCP client configuration
	UpdateClient(id string, updatedConfig *schemas.MCPClientConfig) error

	// ReconnectClient reconnects an MCP client by ID
	ReconnectClient(id string) error

	// Tool Registration
	// RegisterTool registers a local tool with the MCP server
	RegisterTool(name, description string, toolFunction MCPToolFunction[any], toolSchema schemas.ChatTool) error

	// Lifecycle
	// Cleanup performs cleanup of all MCP resources
	Cleanup() error
}

// Ensure MCPManager implements MCPManagerInterface
var _ MCPManagerInterface = (*MCPManager)(nil)
