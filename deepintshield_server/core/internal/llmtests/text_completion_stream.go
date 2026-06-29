package llmtests

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// RunTextCompletionStreamTest executes the text completion streaming test scenario
func RunTextCompletionStreamTest(t *testing.T, client *deepintshield.DeepIntShield, ctx context.Context, testConfig ComprehensiveTestConfig) {
	if !testConfig.Scenarios.TextCompletionStream {
		t.Logf("Text completion stream not supported for provider %s", testConfig.Provider)
		return
	}

	t.Run("TextCompletionStream", func(t *testing.T) {
		if os.Getenv("SKIP_PARALLEL_TESTS") != "true" {
			t.Parallel()
		}

		// Create a text completion prompt
		prompt := "Write a short story about a robot learning to paint. Keep it under 150 words."

		input := &schemas.TextCompletionInput{
			PromptStr: &prompt,
		}

		// Use TextModel if available, otherwise fall back to ChatModel
		model := testConfig.TextModel
		if model == "" {
			model = testConfig.ChatModel
		}

		request := &schemas.DeepIntShieldTextCompletionRequest{
			Provider: testConfig.Provider,
			Model:    model,
			Input:    input,
			Params: &schemas.TextCompletionParameters{
				MaxTokens: deepintshield.Ptr(150),
			},
			Fallbacks: testConfig.TextCompletionFallbacks,
		}

		// Use retry framework for stream requests
		retryConfig := StreamingRetryConfig()
		retryContext := TestRetryContext{
			ScenarioName: "TextCompletionStream",
			ExpectedBehavior: map[string]interface{}{
				"should_stream_content": true,
				"should_tell_story":     true,
				"topic":                 "robot painting",
			},
			TestMetadata: map[string]interface{}{
				"provider": testConfig.Provider,
				"model":    model,
			},
		}

		// Use proper streaming retry wrapper for the stream request
		responseChannel, err := WithStreamRetry(t, retryConfig, retryContext, func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
			bfCtx := schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
			return client.TextCompletionStreamRequest(bfCtx, request)
		})

		// Enhanced error handling
		RequireNoError(t, err, "Text completion stream request failed")
		if responseChannel == nil {
			t.Fatal("Response channel should not be nil")
		}

		var fullContent strings.Builder
		var responseCount int
		var lastResponse *schemas.DeepIntShieldStreamChunk

		// Create a timeout context for the stream reading
		streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		t.Logf("📡 Starting to read text completion streaming response...")

		// Read streaming responses
		for {
			select {
			case response, ok := <-responseChannel:
				if !ok {
					// Channel closed, streaming completed
					t.Logf("✅ Text completion streaming completed. Total chunks received: %d", responseCount)
					goto streamComplete
				}

				if response == nil {
					t.Fatal("Streaming response should not be nil")
				}
				lastResponse = DeepCopyDeepIntShieldStreamChunk(response)

				// Basic validation of streaming response structure
				if response.DeepIntShieldTextCompletionResponse != nil {
					if response.DeepIntShieldTextCompletionResponse.ExtraFields.Provider != testConfig.Provider {
						t.Logf("⚠️ Warning: Provider mismatch - expected %s, got %s", testConfig.Provider, response.DeepIntShieldTextCompletionResponse.ExtraFields.Provider)
					}
					if response.DeepIntShieldTextCompletionResponse.ID == "" {
						t.Logf("⚠️ Warning: Response ID is empty")
					}

					// Log latency for each chunk (can be 0 for inter-chunks)
					t.Logf("📊 Chunk %d latency: %d ms", responseCount+1, response.DeepIntShieldTextCompletionResponse.ExtraFields.Latency)

					// Validate text completion response structure
					if response.DeepIntShieldTextCompletionResponse.Choices == nil {
						t.Logf("⚠️ Warning: Choices should not be nil in text completion streaming")
					}

					// Process each choice in the response (similar to chat completion)
					for _, choice := range response.DeepIntShieldTextCompletionResponse.Choices {
						// For text completion, we expect either streaming deltas or text completion choices
						if choice.TextCompletionResponseChoice != nil {
							// Handle direct text completion response choice (converted by providers)
							if choice.TextCompletionResponseChoice.Text != nil {
								fullContent.WriteString(*choice.TextCompletionResponseChoice.Text)
								t.Logf("✍️ Text completion: %s", *choice.TextCompletionResponseChoice.Text)
							}

							// Check finish reason if present
							if choice.FinishReason != nil {
								t.Logf("🏁 Finish reason: %s", *choice.FinishReason)
							}
						} else {
							t.Logf("⚠️ Warning: Choice %d has no text completion or stream response content", choice.Index)
						}
					}
				}

				responseCount++

				// Safety check to prevent infinite loops in case of issues
				if responseCount > 500 {
					t.Fatal("Received too many streaming chunks, something might be wrong")
				}

			case <-streamCtx.Done():
				t.Fatal("Timeout waiting for text completion streaming response")
			}
		}

	streamComplete:
		// Validate final streaming response
		finalContent := strings.TrimSpace(fullContent.String())

		// Create a consolidated response for validation
		consolidatedResponse := createConsolidatedTextCompletionResponse(finalContent, lastResponse, testConfig.Provider)

		// Enhanced validation expectations for text completion streaming
		expectations := GetExpectationsForScenario("TextCompletionStream", testConfig, map[string]interface{}{})
		expectations = ModifyExpectationsForProvider(expectations, testConfig.Provider)
		expectations.ShouldContainKeywords = append(expectations.ShouldContainKeywords, []string{"robot"}...) // Should include story elements

		// Validate the consolidated text completion streaming response
		validationResult := ValidateTextCompletionResponse(t, consolidatedResponse, nil, expectations, "TextCompletionStream")

		// Basic streaming validation
		if responseCount == 0 {
			t.Fatal("Should receive at least one streaming response")
		}

		if finalContent == "" {
			t.Fatal("Final content should not be empty")
		}

		if len(finalContent) < 5 {
			t.Fatal("Final content should be substantial")
		}

		// Validate latency is present in the last chunk (total latency)
		if lastResponse != nil && lastResponse.DeepIntShieldTextCompletionResponse != nil {
			if lastResponse.DeepIntShieldTextCompletionResponse.ExtraFields.Latency <= 0 {
				t.Fatalf("❌ Last streaming chunk missing latency information (got %d ms)", lastResponse.DeepIntShieldTextCompletionResponse.ExtraFields.Latency)
			} else {
				t.Logf("✅ Total streaming latency: %d ms", lastResponse.DeepIntShieldTextCompletionResponse.ExtraFields.Latency)
			}
		}

		if !validationResult.Passed {
			t.Fatalf("❌ Text completion streaming validation failed: %v", validationResult.Errors)
		}

		t.Logf("📊 Text completion streaming metrics: %d chunks, %d chars", responseCount, len(finalContent))

		t.Logf("✅ Text completion streaming test completed successfully")
		t.Logf("📝 Final content (%d chars): %s", len(finalContent), finalContent)
	})

	// Test text completion streaming with different prompts
	t.Run("TextCompletionStreamVariedPrompts", func(t *testing.T) {
		if os.Getenv("SKIP_PARALLEL_TESTS") != "true" {
			t.Parallel()
		}

		// Use TextModel if available, otherwise fall back to ChatModel
		model := testConfig.TextModel
		if model == "" {
			model = testConfig.ChatModel
		}
		testPrompts := []struct {
			name   string
			prompt string
			expect string
		}{
			{
				name:   "SimpleCompletion",
				prompt: "The quick brown fox",
				expect: "completion",
			},
			{
				name:   "Question",
				prompt: "What is artificial intelligence? AI is",
				expect: "definition",
			},
			{
				name:   "CodeCompletion",
				prompt: "def fibonacci(n):\n    if n <= 1:",
				expect: "code",
			},
		}

		for _, testCase := range testPrompts {
			t.Run(testCase.name, func(t *testing.T) {
				if os.Getenv("SKIP_PARALLEL_TESTS") != "true" {
					t.Parallel()
				}

				input := &schemas.TextCompletionInput{
					PromptStr: &testCase.prompt,
				}

				request := &schemas.DeepIntShieldTextCompletionRequest{
					Provider: testConfig.Provider,
					Model:    model,
					Input:    input,
					Params: &schemas.TextCompletionParameters{
						MaxTokens:   deepintshield.Ptr(50),
						Temperature: deepintshield.Ptr(0.7),
					},
					Fallbacks: testConfig.TextCompletionFallbacks,
				}

				// Use retry framework for stream requests
				retryConfig := StreamingRetryConfig()
				retryContext := TestRetryContext{
					ScenarioName: fmt.Sprintf("TextCompletionStreamVariedPrompts_%s", testCase.name),
					ExpectedBehavior: map[string]interface{}{
						"should_stream_content": true,
						"prompt_type":           testCase.name,
					},
					TestMetadata: map[string]interface{}{
						"provider": testConfig.Provider,
						"model":    model,
					},
				}

				responseChannel, err := WithStreamRetry(t, retryConfig, retryContext, func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
					bfCtx := schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
					return client.TextCompletionStreamRequest(bfCtx, request)
				})

				RequireNoError(t, err, "Text completion stream with varied prompts failed")
				if responseChannel == nil {
					t.Fatal("Response channel should not be nil")
				}

				var responseCount int
				var content strings.Builder

				streamCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()

				t.Logf("Testing text completion streaming with prompt: %s", testCase.name)

				for {
					select {
					case response, ok := <-responseChannel:
						if !ok {
							goto variedPromptComplete
						}

						if response == nil {
							t.Fatal("Streaming response should not be nil")
						}
						responseCount++

						// Extract content from choices
						if response.DeepIntShieldTextCompletionResponse != nil {
							for _, choice := range response.DeepIntShieldTextCompletionResponse.Choices {
								if choice.TextCompletionResponseChoice != nil {
									delta := choice.TextCompletionResponseChoice.Text
									if delta != nil {
										content.WriteString(*delta)
									}
								}
							}
						}

						if responseCount > 100 {
							goto variedPromptComplete
						}

					case <-streamCtx.Done():
						t.Fatal("Timeout waiting for text completion streaming response")
					}
				}

			variedPromptComplete:
				finalContent := strings.TrimSpace(content.String())

				if responseCount == 0 {
					t.Fatal("Should receive at least one streaming response")
				}

				if finalContent == "" {
					t.Logf("⚠️ Warning: No content generated for prompt: %s", testCase.prompt)
				} else {
					t.Logf("✅ Generated content for %s: %s", testCase.name, finalContent)
				}
			})
		}
	})

	// Test text completion streaming with different parameters
	t.Run("TextCompletionStreamParameters", func(t *testing.T) {
		if os.Getenv("SKIP_PARALLEL_TESTS") != "true" {
			t.Parallel()
		}

		// Use TextModel if available, otherwise fall back to ChatModel
		model := testConfig.TextModel
		if model == "" {
			model = testConfig.ChatModel
		}

		prompt := "Once upon a time in a distant galaxy"

		parameterTests := []struct {
			name        string
			temperature *float64
			maxTokens   *int
			topP        *float64
		}{
			{
				name:        "HighCreativity",
				temperature: deepintshield.Ptr(0.9),
				maxTokens:   deepintshield.Ptr(100),
				topP:        deepintshield.Ptr(0.9),
			},
			{
				name:        "LowCreativity",
				temperature: deepintshield.Ptr(0.1),
				maxTokens:   deepintshield.Ptr(50),
				topP:        deepintshield.Ptr(0.5),
			},
			{
				name:        "Balanced",
				temperature: deepintshield.Ptr(0.5),
				maxTokens:   deepintshield.Ptr(75),
				topP:        deepintshield.Ptr(0.8),
			},
		}

		for _, paramTest := range parameterTests {
			t.Run(paramTest.name, func(t *testing.T) {
				if os.Getenv("SKIP_PARALLEL_TESTS") != "true" {
					t.Parallel()
				}

				input := &schemas.TextCompletionInput{
					PromptStr: &prompt,
				}

				request := &schemas.DeepIntShieldTextCompletionRequest{
					Provider: testConfig.Provider,
					Model:    model,
					Input:    input,
					Params: &schemas.TextCompletionParameters{
						MaxTokens:   paramTest.maxTokens,
						Temperature: paramTest.temperature,
						TopP:        paramTest.topP,
					},
					Fallbacks: testConfig.TextCompletionFallbacks,
				}

				// Use retry framework for stream requests
				retryConfig := StreamingRetryConfig()
				retryContext := TestRetryContext{
					ScenarioName: fmt.Sprintf("TextCompletionStreamParameters_%s", paramTest.name),
					ExpectedBehavior: map[string]interface{}{
						"should_stream_content": true,
						"parameter_test":        paramTest.name,
					},
					TestMetadata: map[string]interface{}{
						"provider": testConfig.Provider,
						"model":    model,
					},
				}

				responseChannel, err := WithStreamRetry(t, retryConfig, retryContext, func() (chan *schemas.DeepIntShieldStreamChunk, *schemas.DeepIntShieldError) {
					bfCtx := schemas.NewDeepIntShieldContext(ctx, schemas.NoDeadline)
					return client.TextCompletionStreamRequest(bfCtx, request)
				})

				RequireNoError(t, err, "Text completion stream with parameters failed")
				if responseChannel == nil {
					t.Fatal("Response channel should not be nil")
				}

				var responseCount int
				streamCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()

				t.Logf("🔧 Testing text completion streaming with parameters: %s", paramTest.name)

				for {
					select {
					case response, ok := <-responseChannel:
						if !ok {
							goto parameterTestComplete
						}

						if response != nil {
							responseCount++
						}

						if responseCount > 150 {
							goto parameterTestComplete
						}

					case <-streamCtx.Done():
						t.Fatal("Timeout waiting for text completion streaming response")
					}
				}

			parameterTestComplete:
				if responseCount == 0 {
					t.Fatal("Should receive at least one streaming response")
				}

				t.Logf("✅ Parameter test %s completed with %d chunks", paramTest.name, responseCount)
			})
		}
	})
}

// createConsolidatedTextCompletionResponse creates a consolidated response for validation
func createConsolidatedTextCompletionResponse(finalContent string, lastResponse *schemas.DeepIntShieldStreamChunk, provider schemas.ModelProvider) *schemas.DeepIntShieldTextCompletionResponse {
	consolidatedResponse := &schemas.DeepIntShieldTextCompletionResponse{
		Object: "text_completion",
		Choices: []schemas.DeepIntShieldResponseChoice{
			{
				Index: 0,
				TextCompletionResponseChoice: &schemas.TextCompletionResponseChoice{
					Text: &finalContent,
				},
			},
		},
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			Provider:    provider,
			RequestType: schemas.TextCompletionRequest,
		},
	}

	// Copy usage and other metadata from last response if available
	if lastResponse != nil && lastResponse.DeepIntShieldTextCompletionResponse != nil {
		consolidatedResponse.Usage = lastResponse.DeepIntShieldTextCompletionResponse.Usage
		consolidatedResponse.Model = lastResponse.DeepIntShieldTextCompletionResponse.Model
		consolidatedResponse.ID = lastResponse.DeepIntShieldTextCompletionResponse.ID

		// Copy finish reason from last choice if available
		if len(lastResponse.DeepIntShieldTextCompletionResponse.Choices) > 0 && lastResponse.DeepIntShieldTextCompletionResponse.Choices[0].FinishReason != nil {
			consolidatedResponse.Choices[0].FinishReason = lastResponse.DeepIntShieldTextCompletionResponse.Choices[0].FinishReason
		}

		consolidatedResponse.ExtraFields = lastResponse.DeepIntShieldTextCompletionResponse.ExtraFields
	}

	return consolidatedResponse
}
