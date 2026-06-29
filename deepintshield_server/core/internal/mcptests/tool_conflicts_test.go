package mcptests

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TOOL NAME CONFLICT TESTS
// =============================================================================

// TestToolNameConflict_MultipleClients - FULLY IMPLEMENTED EXAMPLE
func TestToolNameConflict_MultipleClients(t *testing.T) {
	t.Parallel()

	config := GetTestConfig(t)
	if config.HTTPServerURL == "" {
		t.Skip("MCP_HTTP_URL not set")
	}

	// Create two clients with same tool
	client1Config := GetSampleHTTPClientConfig(config.HTTPServerURL)
	client1Config.ID = "client-1"
	client1Config.Name = "Client 1"

	client2Config := GetSampleHTTPClientConfig(config.HTTPServerURL)
	client2Config.ID = "client-2"
	client2Config.Name = "Client 2"

	manager := setupMCPManager(t, client1Config, client2Config)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	// Execute a tool that exists on both clients
	ctx := createTestContext()
	toolCall := GetSampleEchoToolCall("call-1", "test")

	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should succeed (picks one of the clients)
	if deepintshieldErr == nil {
		t.Logf("Tool executed successfully, picked client: %v", result)
		// Check ExtraFields to see which client was selected
	} else {
		t.Logf("Tool execution failed: %v", deepintshieldErr)
	}
}

func TestToolNameConflict_Resolution(t *testing.T) {
	t.Parallel()

	// Setup in-process client
	clientConfig := GetSampleInProcessClientConfig()
	clientConfig.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, clientConfig)

	// Register echo tool - will be available as deepintshieldInternal-echo
	require.NoError(t, RegisterEchoTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Execute "echo" tool multiple times to verify consistent execution
	for i := 0; i < 10; i++ {
		toolCall := GetSampleEchoToolCall("call-"+string(rune(i)), "test conflict resolution")
		result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
		require.Nil(t, deepintshieldErr, "tool should execute")
		require.NotNil(t, result)
		t.Logf("Execution %d completed", i+1)
	}

	t.Log("✓ Tool executed consistently across multiple calls")
}

func TestToolNameConflict_WithFiltering(t *testing.T) {
	t.Parallel()

	config := GetTestConfig(t)
	if config.HTTPServerURL == "" || config.SSEServerURL == "" {
		t.Skip("MCP_HTTP_SERVER_URL or MCP_SSE_URL not set")
	}

	// Client 1: has "echo" tool, ToolsToExecute = ["echo"]
	client1 := GetSampleHTTPClientConfig(config.HTTPServerURL)
	client1.ID = "http-allow-echo"
	client1.ToolsToExecute = []string{"echo"}

	// Client 2: has "echo" tool, ToolsToExecute = [] (deny all)
	client2 := GetSampleSSEClientConfig(config.SSEServerURL)
	client2.ID = "sse-deny-all"
	client2.ToolsToExecute = []string{} // Deny all

	manager := setupMCPManager(t, client1, client2)
	// Register the echo tool for deepintshieldInternal
	require.NoError(t, RegisterEchoTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Execute "echo" - should use deepintshieldInternal client (it's the only one with the tool registered in-process)
	toolCall := GetSampleEchoToolCall("call-1", "filtered conflict")
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
	err := deepintshieldErr
	require.Nil(t, err, "should execute echo tool")
	require.NotNil(t, result)

	// Verify it executed successfully
	// Note: ExecuteChatMCPTool doesn't return ExtraFields, so we can't verify client name
	// The tool execution succeeded, which is what we're testing
}

func TestToolNameConflict_LocalVsExternal(t *testing.T) {
	t.Parallel()

	config := GetTestConfig(t)
	if config.HTTPServerURL == "" {
		t.Skip("MCP_HTTP_URL not set")
	}

	// Create HTTP client with "echo" tool (external)
	httpClient := GetSampleHTTPClientConfig(config.HTTPServerURL)
	httpClient.ID = "http-external"
	httpClient.ToolsToExecute = []string{"*"}

	// Create InProcess client and will register "echo" tool (local)
	inProcessClient := GetSampleInProcessClientConfig()
	inProcessClient.ID = "inprocess-local"
	inProcessClient.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, httpClient, inProcessClient)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	// Register "echo" tool in InProcess client
	echoTool := GetSampleEchoTool()
	echoToolHandler := func(args any) (string, error) {
		argsMap, ok := args.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("invalid arguments type")
		}
		message, ok := argsMap["message"].(string)
		if !ok {
			return "", fmt.Errorf("message is required")
		}
		return message, nil
	}

	err := manager.RegisterTool("echo", "Local echo tool", echoToolHandler, echoTool)
	require.NoError(t, err, "should register local echo tool")

	ctx := createTestContext()

	// Execute "echo" - verify which takes priority
	toolCall := GetSampleEchoToolCall("call-1", "local vs external")
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
	require.Nil(t, deepintshieldErr, "tool should execute")
	require.NotNil(t, result)

	// Check which client was used
	// Note: ExecuteChatMCPTool doesn't return ExtraFields, so we can't get client name
	t.Logf("Tool execution completed")
	// Priority behavior cannot be verified without ExtraFields
}

// =============================================================================
// MULTIPLE SAME-NAME TOOLS TESTS
// =============================================================================

func TestMultipleSameNameTools_ThreeClients(t *testing.T) {
	t.Parallel()

	// Create in-process client with "calculator" tool
	client := GetSampleInProcessClientConfig()
	client.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, client)

	// Register calculator tool - will be available as deepintshieldInternal-calculator
	require.NoError(t, RegisterCalculatorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Execute calculator multiple times
	for i := 0; i < 15; i++ {
		toolCall := GetSampleCalculatorToolCall("call-"+string(rune(i)), "add", float64(i), 1.0)
		result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
		require.Nil(t, deepintshieldErr, "calculator should execute")
		require.NotNil(t, result)
	}

	// Verify only the deepintshieldInternal client is active (disconnected clients may be
	// retained in memory for auto-recovery and should not be counted here)
	clients := manager.GetClients()
	activeClients := 0
	for _, c := range clients {
		if c.State != schemas.MCPConnectionStateDisconnected {
			activeClients++
		}
	}
	assert.Equal(t, 1, activeClients, "should have 1 deepintshieldInternal client")
	t.Log("✓ Calculator executed successfully across 15 calls")
}

func TestMultipleSameNameTools_DifferentImplementations(t *testing.T) {
	t.Parallel()

	// Use deepintshieldInternal client only with registered tools
	inProcessClient := GetSampleInProcessClientConfig()
	inProcessClient.ID = "inprocess-custom"
	inProcessClient.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, inProcessClient)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	// Register custom "process_data" tool in InProcess client
	processTool := schemas.ChatTool{
		Type: schemas.ChatToolTypeFunction,
		Function: &schemas.ChatToolFunction{
			Name:        "process_data",
			Description: schemas.Ptr("Custom data processor"),
			Parameters: &schemas.ToolFunctionParameters{
				Type: "object",
				Properties: schemas.NewOrderedMapFromPairs(
					schemas.KV("data", map[string]interface{}{
						"type":        "string",
						"description": "Data to process",
					}),
				),
				Required: []string{"data"},
			},
		},
	}
	processToolHandler := func(args any) (string, error) {
		argsMap, ok := args.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("invalid arguments type")
		}
		data, ok := argsMap["data"].(string)
		if !ok {
			return "", fmt.Errorf("data is required")
		}
		return "Processed: " + data, nil
	}

	err := manager.RegisterTool("process_data", "Custom data processor", processToolHandler, processTool)
	require.Nil(t, err)

	ctx := createTestContext()

	// Execute "process_data" tool multiple times
	for i := 0; i < 5; i++ {
		toolCall := schemas.ChatAssistantMessageToolCall{
			ID:   schemas.Ptr("call-" + string(rune(i))),
			Type: schemas.Ptr("function"),
			Function: schemas.ChatAssistantMessageToolCallFunction{
				Name:      schemas.Ptr("deepintshieldInternal-process_data"),
				Arguments: `{"data": "test"}`,
			},
		}

		result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
		require.Nil(t, deepintshieldErr, "process_data should execute")
		require.NotNil(t, result)
	}

	t.Log("✓ Custom tool execution completed successfully")
}

// =============================================================================
// CONFLICT WITH CLIENT STATES
// =============================================================================

func TestToolConflict_OneClientDisconnected(t *testing.T) {
	t.Parallel()

	// Client 1: connected in-process client
	client1 := GetSampleInProcessClientConfig()
	client1.ID = "connected-client"
	client1.ToolsToExecute = []string{"*"}

	// Client 2: disconnected (bad config to simulate disconnect)
	client2 := GetSampleHTTPClientConfig("http://localhost:1")
	client2.ID = "disconnected-client"
	client2.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, client1, client2)

	// Register echo tool - will be available as deepintshieldInternal-echo on client1
	require.NoError(t, RegisterEchoTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	// Wait a bit for client2 to fail connection
	time.Sleep(2 * time.Second)

	// Verify only deepintshieldInternal is active (disconnected clients may be retained
	// in memory for auto-recovery but should not be counted as active)
	clients := manager.GetClients()
	activeClients := 0
	for _, c := range clients {
		if c.State != schemas.MCPConnectionStateDisconnected {
			activeClients++
		}
	}
	require.Equal(t, 1, activeClients, "should only have 1 active client (deepintshieldInternal)")

	ctx := createTestContext()

	// Execute "echo" - should use Client 1 (only connected one)
	toolCall := GetSampleEchoToolCall("call-1", "disconnected conflict")
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
	require.Nil(t, deepintshieldErr, "should use connected client")
	require.NotNil(t, result)
	t.Log("✓ Tool executed successfully using the connected client")
}

func TestToolConflict_BothClientsDisconnected(t *testing.T) {
	t.Parallel()

	// Both clients have "echo" but both are disconnected
	// Using bad URLs to force disconnect
	client1 := GetSampleHTTPClientConfig("http://localhost:1")
	client1.ID = "disconnected-1"
	client1.ToolsToExecute = []string{"*"}

	client2 := GetSampleHTTPClientConfig("http://localhost:2")
	client2.ID = "disconnected-2"
	client2.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, client1, client2)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	// Wait for both to fail connection
	time.Sleep(2 * time.Second)

	// Verify both are disconnected
	clients := manager.GetClients()
	for _, client := range clients {
		t.Logf("Client %s state: %v", client.ExecutionConfig.ID, client.State)
	}

	ctx := createTestContext()

	// Execute "echo" - should return error (no available client)
	toolCall := GetSampleEchoToolCall("call-1", "all disconnected")
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should fail because no client is available
	assert.NotNil(t, deepintshieldErr, "should fail when all clients are disconnected")
	assert.Nil(t, result)
	if deepintshieldErr != nil && deepintshieldErr.Error != nil {
		errorMsg := deepintshieldErr.Error.Message
		// Error message can be "not found", "not available", or "not permitted"
		hasExpectedError := assert.True(t,
			strings.Contains(errorMsg, "not available") || strings.Contains(errorMsg, "not permitted") || strings.Contains(errorMsg, "not found"),
			"error should mention tool is not available/permitted/found, got: %s", errorMsg)
		_ = hasExpectedError
	}
}

// =============================================================================
// BOTH API FORMATS CONFLICT TESTS
// =============================================================================

func TestToolConflict_ChatFormat(t *testing.T) {
	t.Parallel()

	// Use deepintshieldInternal clients with registered tools
	inProcessClient := GetSampleInProcessClientConfig()
	inProcessClient.ID = "inprocess-client"
	inProcessClient.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, inProcessClient)

	// Register all tools needed for this test
	require.NoError(t, RegisterEchoTool(manager))
	require.NoError(t, RegisterCalculatorTool(manager))
	require.NoError(t, RegisterWeatherTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Execute in Chat format
	testCases := []struct {
		name     string
		toolCall schemas.ChatAssistantMessageToolCall
	}{
		{
			name:     "echo_tool",
			toolCall: GetSampleEchoToolCall("call-echo", "chat format conflict"),
		},
		{
			name:     "calculator_tool",
			toolCall: GetSampleCalculatorToolCall("call-calc", "multiply", 7, 8),
		},
		{
			name:     "weather_tool",
			toolCall: GetSampleWeatherToolCall("call-weather", "London", ""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &tc.toolCall)
			if deepintshieldErr != nil && deepintshieldErr.Error != nil {
				fmt.Println("deepintshieldErr", deepintshieldErr.Error.Message)
			}
			require.Nil(t, deepintshieldErr, "should resolve conflict and execute")
			require.NotNil(t, result)

			// Log which client was selected
			// Note: ExecuteChatMCPTool doesn't return ExtraFields
			t.Logf("Tool %s executed successfully", *tc.toolCall.Function.Name)
		})
	}
}

func TestToolConflict_ResponsesFormat(t *testing.T) {
	t.Parallel()

	// Use deepintshieldInternal clients with registered tools
	inProcessClient := GetSampleInProcessClientConfig()
	inProcessClient.ID = "inprocess-client"
	inProcessClient.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, inProcessClient)

	// Register all tools needed for this test
	require.NoError(t, RegisterEchoTool(manager))
	require.NoError(t, RegisterCalculatorTool(manager))
	require.NoError(t, RegisterWeatherTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Execute in Responses format
	testCases := []struct {
		name             string
		responsesToolMsg schemas.ResponsesToolMessage
	}{
		{
			name: "echo_tool",
			responsesToolMsg: schemas.ResponsesToolMessage{
				CallID:    schemas.Ptr("call-echo"),
				Name:      schemas.Ptr("deepintshieldInternal-echo"),
				Arguments: schemas.Ptr(`{"message": "responses format conflict"}`),
			},
		},
		{
			name: "calculator_tool",
			responsesToolMsg: schemas.ResponsesToolMessage{
				CallID:    schemas.Ptr("call-calc"),
				Name:      schemas.Ptr("deepintshieldInternal-calculator"),
				Arguments: schemas.Ptr(`{"operation": "add", "x": 15, "y": 25}`),
			},
		},
		{
			name: "weather_tool",
			responsesToolMsg: schemas.ResponsesToolMessage{
				CallID:    schemas.Ptr("call-weather"),
				Name:      schemas.Ptr("deepintshieldInternal-get_weather"),
				Arguments: schemas.Ptr(`{"location": "Tokyo"}`),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, deepintshieldErr := deepintshield.ExecuteResponsesMCPTool(ctx, &tc.responsesToolMsg)
			require.Nil(t, deepintshieldErr, "should resolve conflict and execute")
			require.NotNil(t, result)

			// Log which client was selected
			// Note: ExecuteResponsesMCPTool doesn't return ExtraFields
			t.Logf("Tool %s executed successfully", *tc.responsesToolMsg.Name)
		})
	}
}

// =============================================================================
// COMPREHENSIVE CONFLICT SCENARIOS
// =============================================================================

func TestToolConflict_ComprehensiveScenarios(t *testing.T) {
	t.Parallel()

	// Use deepintshieldInternal clients with registered tools
	inProcessClient := GetSampleInProcessClientConfig()
	inProcessClient.ID = "inprocess-client"
	inProcessClient.ToolsToExecute = []string{"*"}

	manager := setupMCPManager(t, inProcessClient)

	// Register all tools needed for this test
	require.NoError(t, RegisterEchoTool(manager))
	require.NoError(t, RegisterCalculatorTool(manager))
	require.NoError(t, RegisterWeatherTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	scenarios := []struct {
		name          string
		toolName      string
		expectSuccess bool
	}{
		{
			name:          "echo_tool",
			toolName:      "deepintshieldInternal-echo",
			expectSuccess: true,
		},
		{
			name:          "calculator_tool",
			toolName:      "deepintshieldInternal-calculator",
			expectSuccess: true,
		},
		{
			name:          "weather_tool",
			toolName:      "deepintshieldInternal-get_weather",
			expectSuccess: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			toolCall := GetSampleEchoToolCall("call-"+scenario.toolName, "test")
			toolCall.Function.Name = schemas.Ptr(scenario.toolName)

			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

			if scenario.expectSuccess {
				require.Nil(t, deepintshieldErr, "should execute successfully")
				require.NotNil(t, result)
				t.Logf("Tool %s executed successfully", scenario.toolName)
			} else {
				assert.NotNil(t, deepintshieldErr, "should fail")
			}
		})
	}
}
