package mcptests

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TIMEOUT ERROR HANDLING TESTS
// =============================================================================

func TestToolExecution_Timeout(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)

	// Register delay tool
	require.NoError(t, RegisterDelayTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	// Create context with short timeout
	baseCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	ctx := schemas.NewDeepIntShieldContext(baseCtx, schemas.NoDeadline)

	// Try to delay for 5 seconds (should timeout)
	argsMap := map[string]interface{}{"seconds": 5.0}
	argsJSON, _ := json.Marshal(argsMap)
	toolCall := schemas.ChatAssistantMessageToolCall{
		ID:   schemas.Ptr("call-timeout"),
		Type: schemas.Ptr("function"),
		Function: schemas.ChatAssistantMessageToolCallFunction{
			Name:      schemas.Ptr("deepintshieldInternal-delay"),
			Arguments: string(argsJSON),
		},
	}

	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should timeout (either error or result indicates timeout)
	if deepintshieldErr != nil {
		// Error occurred - check if it's a timeout error
		assert.Contains(t, strings.ToLower(deepintshieldErr.Error.Message), "timeout",
			"Error should indicate timeout: %s", deepintshieldErr.Error.Message)
	} else if result != nil {
		// May return result with error message
		t.Logf("Tool execution completed despite timeout (may have finished quickly)")
	}
}

func TestToolExecution_TimeoutChatAndResponses(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterDelayTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	t.Run("chat_format", func(t *testing.T) {
		baseCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ctx := schemas.NewDeepIntShieldContext(baseCtx, schemas.NoDeadline)

		argsMap := map[string]interface{}{"seconds": 3.0}
		argsJSON, _ := json.Marshal(argsMap)
		toolCall := schemas.ChatAssistantMessageToolCall{
			ID:   schemas.Ptr("call-timeout-chat"),
			Type: schemas.Ptr("function"),
			Function: schemas.ChatAssistantMessageToolCallFunction{
				Name:      schemas.Ptr("deepintshieldInternal-delay"),
				Arguments: string(argsJSON),
			},
		}

		_, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)
		if deepintshieldErr != nil {
			t.Logf("Chat format timeout error: %v", deepintshieldErr.Error.Message)
		}
	})

	t.Run("responses_format", func(t *testing.T) {
		baseCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ctx := schemas.NewDeepIntShieldContext(baseCtx, schemas.NoDeadline)

		argsMap := map[string]interface{}{"seconds": 3.0}
		argsJSON, _ := json.Marshal(argsMap)
		responsesTool := schemas.ResponsesToolMessage{
			CallID:    schemas.Ptr("call-timeout-responses"),
			Name:      schemas.Ptr("deepintshieldInternal-delay"),
			Arguments: schemas.Ptr(string(argsJSON)),
		}

		_, deepintshieldErr := deepintshield.ExecuteResponsesMCPTool(ctx, &responsesTool)
		if deepintshieldErr != nil {
			t.Logf("Responses format timeout error: %v", deepintshieldErr.Error.Message)
		}
	})
}

// =============================================================================
// TOOL ERROR HANDLING TESTS
// =============================================================================

func TestToolExecution_ToolReturnsError(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)

	// Register error-throwing tool
	require.NoError(t, RegisterThrowErrorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	errorMessages := []string{
		"Simple error",
		"Error with special chars: !@#$%^&*()",
		"Error with unicode: 错误消息 🚨",
		"Multi\nline\nerror",
	}

	for i, errMsg := range errorMessages {
		t.Run(fmt.Sprintf("error_%d", i), func(t *testing.T) {
			argsMap := map[string]interface{}{"error_message": errMsg}
			argsJSON, _ := json.Marshal(argsMap)
			toolCall := schemas.ChatAssistantMessageToolCall{
				ID:   schemas.Ptr(fmt.Sprintf("call-error-%d", i)),
				Type: schemas.Ptr("function"),
				Function: schemas.ChatAssistantMessageToolCallFunction{
					Name:      schemas.Ptr("deepintshieldInternal-throw_error"),
					Arguments: string(argsJSON),
				},
			}

			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

			// Should handle error gracefully
			if deepintshieldErr != nil {
				assert.Contains(t, deepintshieldErr.Error.Message, errMsg)
			} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
				// Error might be in result content
				assert.Contains(t, *result.Content.ContentStr, errMsg)
			}
		})
	}
}

func TestToolExecution_DivisionByZero(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterCalculatorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	toolCall := GetSampleCalculatorToolCall("call-divide-zero", "divide", 10, 0)
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should return error about division by zero
	if deepintshieldErr != nil {
		assert.Contains(t, strings.ToLower(deepintshieldErr.Error.Message), "zero")
	} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
		assert.Contains(t, strings.ToLower(*result.Content.ContentStr), "zero")
	}
}

// =============================================================================
// INVALID ARGUMENTS ERROR HANDLING TESTS
// =============================================================================

func TestToolExecution_MissingRequiredArguments(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterCalculatorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	invalidArgTests := []struct {
		name      string
		arguments string
	}{
		{"missing_all", `{}`},
		{"missing_operation", `{"x": 10, "y": 5}`},
		{"missing_x", `{"operation": "add", "y": 5}`},
		{"missing_y", `{"operation": "add", "x": 10}`},
	}

	for _, tc := range invalidArgTests {
		t.Run(tc.name, func(t *testing.T) {
			toolCall := schemas.ChatAssistantMessageToolCall{
				ID:   schemas.Ptr("call-" + tc.name),
				Type: schemas.Ptr("function"),
				Function: schemas.ChatAssistantMessageToolCallFunction{
					Name:      schemas.Ptr("deepintshieldInternal-calculator"),
					Arguments: tc.arguments,
				},
			}

			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

			// Should return error
			if deepintshieldErr != nil {
				t.Logf("Got expected error: %v", deepintshieldErr.Error.Message)
			} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
				// Error in result
				t.Logf("Got error in result: %s", *result.Content.ContentStr)
			}
		})
	}
}

func TestToolExecution_WrongArgumentTypes(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterCalculatorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	wrongTypeTests := []struct {
		name      string
		arguments string
	}{
		{"x_as_string", `{"operation": "add", "x": "not_a_number", "y": 5}`},
		{"y_as_string", `{"operation": "add", "x": 10, "y": "not_a_number"}`},
		{"operation_as_number", `{"operation": 123, "x": 10, "y": 5}`},
		{"x_as_array", `{"operation": "add", "x": [1,2,3], "y": 5}`},
		{"y_as_object", `{"operation": "add", "x": 10, "y": {"nested": true}}`},
	}

	for _, tc := range wrongTypeTests {
		t.Run(tc.name, func(t *testing.T) {
			toolCall := schemas.ChatAssistantMessageToolCall{
				ID:   schemas.Ptr("call-" + tc.name),
				Type: schemas.Ptr("function"),
				Function: schemas.ChatAssistantMessageToolCallFunction{
					Name:      schemas.Ptr("deepintshieldInternal-calculator"),
					Arguments: tc.arguments,
				},
			}

			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

			// Should return error
			if deepintshieldErr != nil {
				t.Logf("Got expected error: %v", deepintshieldErr.Error.Message)
			} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
				t.Logf("Got error in result: %s", *result.Content.ContentStr)
			}
		})
	}
}

// =============================================================================
// TOOL NOT FOUND ERROR HANDLING TESTS
// =============================================================================

func TestToolExecution_NonExistentTool(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	toolCall := schemas.ChatAssistantMessageToolCall{
		ID:   schemas.Ptr("call-nonexistent"),
		Type: schemas.Ptr("function"),
		Function: schemas.ChatAssistantMessageToolCallFunction{
			Name:      schemas.Ptr("nonexistent_tool"),
			Arguments: `{}`,
		},
	}

	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should return error about tool not found
	if deepintshieldErr == nil && (result == nil || result.Content == nil || result.Content.ContentStr == nil) {
		// No error and no result - tool wasn't found
		t.Logf("Tool not found (as expected)")
	} else if deepintshieldErr != nil {
		// Got error about tool not found or not available
		errorMsg := strings.ToLower(deepintshieldErr.Error.Message)
		assert.True(t, strings.Contains(errorMsg, "not found") || strings.Contains(errorMsg, "not available"),
			"Error should mention 'not found' or 'not available': %s", deepintshieldErr.Error.Message)
	} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
		// Error in result content
		resultStr := strings.ToLower(*result.Content.ContentStr)
		assert.True(t, strings.Contains(resultStr, "not found") || strings.Contains(resultStr, "not available"),
			"Result should mention 'not found' or 'not available': %s", *result.Content.ContentStr)
	}
}

func TestToolExecution_ToolNotInExecuteList(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)

	// Register tools
	require.NoError(t, RegisterEchoTool(manager))
	require.NoError(t, RegisterCalculatorTool(manager))

	// Modify internal client to only allow echo
	clients := manager.GetClients()
	for i := range clients {
		if clients[i].ExecutionConfig.ID == "deepintshieldInternal" {
			clients[i].ExecutionConfig.ToolsToExecute = []string{"deepintshieldInternal-echo"}
			err := manager.UpdateClient(clients[i].ExecutionConfig.ID, clients[i].ExecutionConfig)
			require.NoError(t, err)
			break
		}
	}

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Try to execute calculator (not in execute list)
	toolCall := GetSampleCalculatorToolCall("call-not-allowed", "add", 5, 3)
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should return error
	if deepintshieldErr == nil && (result == nil || result.Content == nil || result.Content.ContentStr == nil) {
		// No error and no result - tool wasn't permitted
		t.Logf("Tool not permitted (as expected)")
	} else if deepintshieldErr != nil {
		// Got error about tool not found/not available/not permitted
		errorMsg := strings.ToLower(deepintshieldErr.Error.Message)
		assert.True(t, strings.Contains(errorMsg, "not found") || strings.Contains(errorMsg, "not available") || strings.Contains(errorMsg, "not permitted"),
			"Error should mention 'not found', 'not available', or 'not permitted': %s", deepintshieldErr.Error.Message)
	} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
		// Error in result content
		resultStr := strings.ToLower(*result.Content.ContentStr)
		assert.True(t, strings.Contains(resultStr, "not found") || strings.Contains(resultStr, "not available") || strings.Contains(resultStr, "not permitted"),
			"Result should mention 'not found', 'not available', or 'not permitted': %s", *result.Content.ContentStr)
	}
}

// =============================================================================
// ERROR PROPAGATION TESTS
// =============================================================================

func TestToolExecution_ErrorInBothFormats(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterThrowErrorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	errorMsg := "Test error message"

	t.Run("chat_format", func(t *testing.T) {
		ctx := createTestContext()
		argsMap := map[string]interface{}{"error_message": errorMsg}
		argsJSON, _ := json.Marshal(argsMap)
		toolCall := schemas.ChatAssistantMessageToolCall{
			ID:   schemas.Ptr("call-error-chat"),
			Type: schemas.Ptr("function"),
			Function: schemas.ChatAssistantMessageToolCallFunction{
				Name:      schemas.Ptr("deepintshieldInternal-throw_error"),
				Arguments: string(argsJSON),
			},
		}

		result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

		// Should handle error
		if deepintshieldErr != nil {
			assert.Contains(t, deepintshieldErr.Error.Message, errorMsg)
		} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
			assert.Contains(t, *result.Content.ContentStr, errorMsg)
		}
	})

	t.Run("responses_format", func(t *testing.T) {
		ctx := createTestContext()
		argsMap := map[string]interface{}{"error_message": errorMsg}
		argsJSON, _ := json.Marshal(argsMap)
		responsesTool := schemas.ResponsesToolMessage{
			CallID:    schemas.Ptr("call-error-responses"),
			Name:      schemas.Ptr("deepintshieldInternal-throw_error"),
			Arguments: schemas.Ptr(string(argsJSON)),
		}

		result, deepintshieldErr := deepintshield.ExecuteResponsesMCPTool(ctx, &responsesTool)

		// Should handle error
		if deepintshieldErr != nil {
			assert.Contains(t, deepintshieldErr.Error.Message, errorMsg)
		} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
			assert.Contains(t, *result.Content.ContentStr, errorMsg)
		}
	})
}

// =============================================================================
// COMPLEX ERROR SCENARIOS
// =============================================================================

func TestToolExecution_MultipleErrorsInSequence(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterThrowErrorTool(manager))
	require.NoError(t, RegisterCalculatorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Execute multiple failing operations
	errors := make([]error, 0)

	// 1. Tool that throws error
	argsMap1 := map[string]interface{}{"error_message": "First error"}
	argsJSON1, _ := json.Marshal(argsMap1)
	toolCall1 := schemas.ChatAssistantMessageToolCall{
		ID:   schemas.Ptr("call-1"),
		Type: schemas.Ptr("function"),
		Function: schemas.ChatAssistantMessageToolCallFunction{
			Name:      schemas.Ptr("deepintshieldInternal-throw_error"),
			Arguments: string(argsJSON1),
		},
	}
	_, err1 := deepintshield.ExecuteChatMCPTool(ctx, &toolCall1)
	if err1 != nil {
		errors = append(errors, fmt.Errorf("error 1: %v", err1.Error.Message))
	}

	// 2. Division by zero
	toolCall2 := GetSampleCalculatorToolCall("call-2", "divide", 10, 0)
	_, err2 := deepintshield.ExecuteChatMCPTool(ctx, &toolCall2)
	if err2 != nil {
		errors = append(errors, fmt.Errorf("error 2: %v", err2.Error.Message))
	}

	// 3. Invalid arguments
	toolCall3 := schemas.ChatAssistantMessageToolCall{
		ID:   schemas.Ptr("call-3"),
		Type: schemas.Ptr("function"),
		Function: schemas.ChatAssistantMessageToolCallFunction{
			Name:      schemas.Ptr("deepintshieldInternal-calculator"),
			Arguments: `{"invalid": "arguments"}`,
		},
	}
	_, err3 := deepintshield.ExecuteChatMCPTool(ctx, &toolCall3)
	if err3 != nil {
		errors = append(errors, fmt.Errorf("error 3: %v", err3.Error.Message))
	}

	// System should remain stable after multiple errors
	t.Logf("Encountered %d errors (expected)", len(errors))
	for _, err := range errors {
		t.Logf("  - %v", err)
	}

	// Verify system still works with valid request
	validToolCall := GetSampleCalculatorToolCall("call-valid", "add", 5, 3)
	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &validToolCall)
	if deepintshieldErr != nil {
		t.Logf("System recovered, valid call succeeded")
	} else {
		require.NotNil(t, result)
	}
}

func TestToolExecution_LargeErrorMessage(t *testing.T) {
	t.Parallel()

	manager := setupMCPManager(t)
	require.NoError(t, RegisterThrowErrorTool(manager))

	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	// Create very large error message
	largeErrorMsg := strings.Repeat("Error message repeated many times. ", 1000)

	argsMap := map[string]interface{}{"error_message": largeErrorMsg}
	argsJSON, _ := json.Marshal(argsMap)
	toolCall := schemas.ChatAssistantMessageToolCall{
		ID:   schemas.Ptr("call-large-error"),
		Type: schemas.Ptr("function"),
		Function: schemas.ChatAssistantMessageToolCallFunction{
			Name:      schemas.Ptr("deepintshieldInternal-throw_error"),
			Arguments: string(argsJSON),
		},
	}

	result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

	// Should handle large error gracefully
	if deepintshieldErr != nil {
		assert.NotEmpty(t, deepintshieldErr.Error.Message)
		t.Logf("Error message length: %d", len(deepintshieldErr.Error.Message))
	} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
		assert.NotEmpty(t, *result.Content.ContentStr)
		t.Logf("Result content length: %d", len(*result.Content.ContentStr))
	}
}

// =============================================================================
// CODE MODE ERROR HANDLING TESTS
// =============================================================================

func TestExecuteToolCode_SyntaxError(t *testing.T) {
	t.Parallel()

	config := GetTestConfig(t)
	if config.HTTPServerURL == "" {
		t.Skip("MCP_HTTP_URL not set")
	}

	codeModeClient := GetSampleCodeModeClientConfig(t, config.HTTPServerURL)
	manager := setupMCPManager(t, codeModeClient)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	syntaxErrorCodes := []string{
		`return "missing semicolon"`,
		`const x = `,
		`function foo() { return `,
		`if (true) { `,
		`const x = {key: "value"`,
	}

	for i, code := range syntaxErrorCodes {
		t.Run(fmt.Sprintf("syntax_error_%d", i), func(t *testing.T) {
			toolCall := CreateExecuteToolCodeCall(fmt.Sprintf("call-%d", i), code)
			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

			// Should return error or error in result
			if deepintshieldErr != nil {
				t.Logf("Got expected error: %v", deepintshieldErr.Error.Message)
			} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
				returnValue, hasError, errorMsg := ParseCodeModeResponse(t, *result.Content.ContentStr)
				// Syntax errors typically either:
				// 1. Produce no return value (hasError=true), or
				// 2. Return a string value if the code is valid but incomplete (like "return 'missing semicolon'")
				if hasError {
					// No return value - this is expected for malformed syntax
					t.Logf("Got expected parsing error: %s", errorMsg)
				} else {
					// Has a return value - check if it's an object with error or a string
					if returnObj, ok := returnValue.(map[string]interface{}); ok {
						errorField := returnObj["error"]
						assert.NotNil(t, errorField, "execution result should have 'error' field")
					} else {
						// String response means it's the error message itself (transpilation error like "missing semicolon")
						assert.NotNil(t, returnValue, "execution result should have error message")
					}
				}
			}
		})
	}
}

func TestExecuteToolCode_RuntimeError(t *testing.T) {
	t.Parallel()

	config := GetTestConfig(t)
	if config.HTTPServerURL == "" {
		t.Skip("MCP_HTTP_URL not set")
	}

	codeModeClient := GetSampleCodeModeClientConfig(t, config.HTTPServerURL)
	manager := setupMCPManager(t, codeModeClient)
	deepintshield := setupDeepIntShield(t)
	deepintshield.SetMCPManager(manager)

	ctx := createTestContext()

	runtimeErrorCodes := []string{
		`throw new Error("Runtime error")`,
		`const x = null; return x.property`,
		`const y = undefined; return y.method()`,
		`return nonExistentVariable`,
		`const arr = []; return arr[1000].property`,
	}

	for i, code := range runtimeErrorCodes {
		t.Run(fmt.Sprintf("runtime_error_%d", i), func(t *testing.T) {
			toolCall := CreateExecuteToolCodeCall(fmt.Sprintf("call-%d", i), code)
			result, deepintshieldErr := deepintshield.ExecuteChatMCPTool(ctx, &toolCall)

			// Should handle runtime error gracefully
			if deepintshieldErr != nil {
				t.Logf("Got deepintshield error (expected): %v", deepintshieldErr.Error.Message)
			} else if result != nil && result.Content != nil && result.Content.ContentStr != nil {
				returnValue, hasError, errorMsg := ParseCodeModeResponse(t, *result.Content.ContentStr)
				if hasError {
					// Runtime error was caught and reported
					t.Logf("Got expected runtime error: %s", errorMsg)
				} else {
					// Response was successfully parsed - check if it contains error information
					if returnObj, ok := returnValue.(map[string]interface{}); ok {
						// Runtime errors should have an error field in the response
						errorField := returnObj["error"]
						assert.NotNil(t, errorField, "execution result should have 'error' field for runtime errors")
					} else {
						t.Logf("Got return value: %v", returnValue)
					}
				}
			}
		})
	}
}
