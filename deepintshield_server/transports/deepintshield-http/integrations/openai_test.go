package integrations

import (
	"encoding/json"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeOpenAICompatibleSDKRawResponse_ChatUsageNulls(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"chatcmpl-1",
		"object":"chat.completion",
		"service_tier":"priority",
		"usage":{
			"prompt_tokens":12,
			"completion_tokens":8,
			"total_tokens":20,
			"prompt_tokens_details":{"cached_tokens":null},
			"completion_tokens_details":{"reasoning_tokens":null}
		}
	}`)

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	promptDetails, ok := usage["prompt_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), promptDetails["cached_tokens"])

	completionDetails, ok := usage["completion_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), completionDetails["reasoning_tokens"])
	assert.Equal(t, "priority", payload["service_tier"])
}

func TestNormalizeOpenAICompatibleSDKRawResponse_ResponsesUsageNullsAndEmptyServiceTier(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"resp-1",
		"object":"response",
		"service_tier":"",
		"usage":{
			"input_tokens":18,
			"output_tokens":6,
			"total_tokens":24,
			"input_tokens_details":{"cached_tokens":null},
			"output_tokens_details":{"reasoning_tokens":null}
		}
	}`)

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	inputDetails, ok := usage["input_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), inputDetails["cached_tokens"])

	outputDetails, ok := usage["output_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), outputDetails["reasoning_tokens"])

	_, hasServiceTier := payload["service_tier"]
	assert.False(t, hasServiceTier)
}

func TestNormalizeOpenAICompatibleSDKRawResponse_ChatUsageMissingTierSensitiveFields(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"chatcmpl-3",
		"object":"chat.completion",
		"service_tier":"priority",
		"usage":{
			"prompt_tokens":12,
			"completion_tokens":8,
			"total_tokens":20
		}
	}`)

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	promptDetails, ok := usage["prompt_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), promptDetails["cached_tokens"])

	completionDetails, ok := usage["completion_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), completionDetails["reasoning_tokens"])
}

func TestNormalizeOpenAICompatibleSDKRawResponse_ChatUsageEmptyCompletionDetailsWithServiceTier(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"chatcmpl-4",
		"object":"chat.completion",
		"service_tier":"priority",
		"usage":{
			"prompt_tokens":26,
			"prompt_tokens_details":{"cached_tokens":0},
			"completion_tokens":37,
			"completion_tokens_details":{},
			"total_tokens":63
		}
	}`)

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	completionDetails, ok := usage["completion_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), completionDetails["reasoning_tokens"])
}

func TestNormalizeOpenAICompatibleSDKRawResponse_ResponsesUsageMissingTierSensitiveFields(t *testing.T) {
	raw := json.RawMessage(`{
		"id":"resp-3",
		"object":"response",
		"service_tier":"flex",
		"usage":{
			"input_tokens":18,
			"output_tokens":6,
			"total_tokens":24
		}
	}`)

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	inputDetails, ok := usage["input_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), inputDetails["cached_tokens"])

	outputDetails, ok := usage["output_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), outputDetails["reasoning_tokens"])
}

func TestNormalizeOpenAICompatibleSDKRawResponse_StringInput(t *testing.T) {
	raw := `{
		"id":"chatcmpl-2",
		"object":"chat.completion",
		"service_tier":"priority",
		"usage":{
			"prompt_tokens":10,
			"completion_tokens":4,
			"total_tokens":14,
			"completion_tokens_details":{"reasoning_tokens":null,"audio_tokens":null}
		}
	}`

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	completionDetails, ok := usage["completion_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), completionDetails["reasoning_tokens"])
	assert.Equal(t, float64(0), completionDetails["audio_tokens"])
}

func TestNormalizeOpenAICompatibleSDKRawResponse_ByteInput(t *testing.T) {
	raw := []byte(`{
		"id":"resp-2",
		"object":"response",
		"service_tier":"",
		"usage":{
			"input_tokens":8,
			"output_tokens":5,
			"total_tokens":13,
			"output_tokens_details":{"reasoning_tokens":null,"audio_tokens":null}
		}
	}`)

	normalized, ok := normalizeOpenAICompatibleSDKRawResponse(raw).(json.RawMessage)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, sonic.Unmarshal(normalized, &payload))

	usage, ok := payload["usage"].(map[string]any)
	require.True(t, ok)

	outputDetails, ok := usage["output_tokens_details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(0), outputDetails["reasoning_tokens"])
	assert.Equal(t, float64(0), outputDetails["audio_tokens"])

	_, hasServiceTier := payload["service_tier"]
	assert.False(t, hasServiceTier)
}
