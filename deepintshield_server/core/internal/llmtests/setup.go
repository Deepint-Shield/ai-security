// Package llmtests provides comprehensive test utilities and configurations for the DeepIntShield system.
// It includes comprehensive test implementations covering all major AI provider scenarios,
// including text completion, chat, tool calling, image processing, and end-to-end workflows.
package llmtests

import (
	"context"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// Constants for test configuration
const (
	// TestTimeout defines the maximum duration for comprehensive tests
	// Set to 20 minutes to allow for complex multi-step operations
	TestTimeout = 20 * time.Minute
)

// getDeepIntShield initializes and returns a DeepIntShield instance for comprehensive testing.
// It sets up the comprehensive test account, plugin, and logger configuration.
//
// Environment variables are expected to be set by the system or test runner before calling this function.
// The account configuration will read API keys and settings from these environment variables.
//
// Returns:
//   - *deepintshield.DeepIntShield: A configured DeepIntShield instance ready for comprehensive testing
//   - error: Any error that occurred during DeepIntShield initialization
//
// The function:
//  1. Creates a comprehensive test account instance
//  2. Configures DeepIntShield with the account and default logger
func getDeepIntShield(ctx context.Context) (*deepintshield.DeepIntShield, error) {
	account := ComprehensiveTestAccount{}

	// Initialize DeepIntShield
	b, err := deepintshield.Init(ctx, schemas.DeepIntShieldConfig{
		Account: &account,
		Logger:  deepintshield.NewDefaultLogger(schemas.LogLevelDebug),
	})
	if err != nil {
		return nil, err
	}

	return b, nil
}

// SetupTest initializes a test environment with timeout context
func SetupTest() (*deepintshield.DeepIntShield, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	client, err := getDeepIntShield(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	return client, ctx, cancel, nil
}
