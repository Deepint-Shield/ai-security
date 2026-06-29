package streaming

import (
	"fmt"
	"sort"
	"strings"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

// buildCompleteMessageFromAudioStreamChunks builds a complete message from accumulated audio chunks
func (a *Accumulator) buildCompleteMessageFromAudioStreamChunks(chunks []*AudioStreamChunk) *schemas.DeepIntShieldSpeechResponse {
	completeMessage := &schemas.DeepIntShieldSpeechResponse{}
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].ChunkIndex < chunks[j].ChunkIndex
	})
	for _, chunk := range chunks {
		if chunk.Delta != nil {
			completeMessage.Audio = append(completeMessage.Audio, chunk.Delta.Audio...)
		}
	}
	return completeMessage
}

// processAccumulatedAudioStreamingChunks processes all accumulated audio chunks in order
func (a *Accumulator) processAccumulatedAudioStreamingChunks(requestID string, deepintshieldErr *schemas.DeepIntShieldError, isFinalChunk bool) (*AccumulatedData, error) {
	accumulator := a.getOrCreateStreamAccumulator(requestID)
	// Lock the accumulator
	accumulator.mu.Lock()
	defer accumulator.mu.Unlock()
	// Note: Cleanup is handled by CleanupStreamAccumulator when refcount reaches 0
	// This is called from completeDeferredSpan after streaming ends

	// Calculate Time to First Token (TTFT) in milliseconds
	var ttft int64
	if !accumulator.StartTimestamp.IsZero() && !accumulator.FirstChunkTimestamp.IsZero() {
		ttft = accumulator.FirstChunkTimestamp.Sub(accumulator.StartTimestamp).Nanoseconds() / 1e6
	}

	data := &AccumulatedData{
		RequestID:        requestID,
		Status:           "success",
		Stream:           true,
		StartTimestamp:   accumulator.StartTimestamp,
		EndTimestamp:     accumulator.FinalTimestamp,
		Latency:          0,
		TimeToFirstToken: ttft,
		OutputMessage:    nil,
		ToolCalls:        nil,
		ErrorDetails:     nil,
		TokenUsage:       nil,
		CacheDebug:       nil,
		Cost:             nil,
	}
	completeMessage := a.buildCompleteMessageFromAudioStreamChunks(accumulator.AudioStreamChunks)
	if !isFinalChunk {
		data.AudioOutput = completeMessage
		return data, nil
	}
	data.Status = "success"
	if deepintshieldErr != nil {
		data.Status = "error"
	}
	if accumulator.StartTimestamp.IsZero() || accumulator.FinalTimestamp.IsZero() {
		data.Latency = 0
	} else {
		data.Latency = accumulator.FinalTimestamp.Sub(accumulator.StartTimestamp).Nanoseconds() / 1e6
	}
	data.EndTimestamp = accumulator.FinalTimestamp
	data.AudioOutput = completeMessage
	data.ErrorDetails = deepintshieldErr
	// Update metadata from the chunk with highest index (contains TokenUsage, Cost, CacheDebug)
	if lastChunk := accumulator.getLastAudioChunkLocked(); lastChunk != nil {
		if lastChunk.TokenUsage != nil {
			data.TokenUsage = &schemas.DeepIntShieldLLMUsage{
				PromptTokens:     lastChunk.TokenUsage.InputTokens,
				CompletionTokens: lastChunk.TokenUsage.OutputTokens,
				TotalTokens:      lastChunk.TokenUsage.TotalTokens,
			}
		}
		if lastChunk.Cost != nil {
			data.Cost = lastChunk.Cost
		}
		if lastChunk.SemanticCacheDebug != nil {
			data.CacheDebug = lastChunk.SemanticCacheDebug
		}
	}
	// Accumulate raw response using strings.Builder to avoid O(n^2) string concatenation
	if len(accumulator.AudioStreamChunks) > 0 {
		// Sort chunks by chunk index
		sort.Slice(accumulator.AudioStreamChunks, func(i, j int) bool {
			return accumulator.AudioStreamChunks[i].ChunkIndex < accumulator.AudioStreamChunks[j].ChunkIndex
		})
		var rawBuilder strings.Builder
		hasRawChunk := false
		for _, chunk := range accumulator.AudioStreamChunks {
			if chunk.RawResponse != nil {
				if hasRawChunk {
					rawBuilder.WriteString("\n\n")
				}
				rawBuilder.WriteString(*chunk.RawResponse)
				hasRawChunk = true
			}
		}
		if hasRawChunk {
			s := rawBuilder.String()
			data.RawResponse = &s
		}
	}
	return data, nil
}

// processAudioStreamingResponse processes a audio streaming response
func (a *Accumulator) processAudioStreamingResponse(ctx *schemas.DeepIntShieldContext, result *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*ProcessedStreamResponse, error) {
	// Extract accumulator ID from context
	requestID, ok := getAccumulatorID(ctx)
	if !ok || requestID == "" {
		// Log error but don't fail the request
		return nil, fmt.Errorf("accumulator-id not found in context or is empty")
	}
	_, provider, model := deepintshield.GetResponseFields(result, deepintshieldErr)
	isFinalChunk := deepintshield.IsFinalChunk(ctx)
	// For audio, all the data comes in the final chunk
	chunk := a.getAudioStreamChunk()
	chunk.Timestamp = time.Now()
	chunk.ErrorDetails = deepintshieldErr
	if deepintshieldErr != nil {
		chunk.FinishReason = deepintshield.Ptr("error")
	} else if result != nil && result.SpeechStreamResponse != nil {
		// We create a deep copy of the delta to avoid pointing to stack memory
		newDelta := &schemas.DeepIntShieldSpeechStreamResponse{
			Type:  result.SpeechStreamResponse.Type,
			Usage: result.SpeechStreamResponse.Usage,
			Audio: result.SpeechStreamResponse.Audio,
		}
		chunk.Delta = newDelta
		if result.SpeechStreamResponse.ExtraFields.RawResponse != nil {
			chunk.RawResponse = deepintshield.Ptr(fmt.Sprintf("%v", result.SpeechStreamResponse.ExtraFields.RawResponse))
		}
		if result.SpeechStreamResponse.Usage != nil {
			chunk.TokenUsage = result.SpeechStreamResponse.Usage
		}
		chunk.ChunkIndex = result.SpeechStreamResponse.ExtraFields.ChunkIndex
		if isFinalChunk {
			if a.pricingManager != nil {
				cost := a.pricingManager.CalculateCost(result)
				chunk.Cost = deepintshield.Ptr(cost)
			}
			chunk.SemanticCacheDebug = result.GetExtraFields().CacheDebug
		}
	}
	if addErr := a.addAudioStreamChunk(requestID, chunk, isFinalChunk); addErr != nil {
		return nil, fmt.Errorf("failed to add stream chunk for request %s: %w", requestID, addErr)
	}
	// Always return data on final chunk - multiple plugins may need the result
	if isFinalChunk {
		// Get the accumulator and mark as complete (idempotent)
		accumulator := a.getOrCreateStreamAccumulator(requestID)
		accumulator.mu.Lock()
		if !accumulator.IsComplete {
			accumulator.IsComplete = true
		}
		accumulator.mu.Unlock()

		// Always process and return data on final chunk
		// Multiple plugins can call this - the processing is idempotent
		data, processErr := a.processAccumulatedAudioStreamingChunks(requestID, deepintshieldErr, isFinalChunk)
		if processErr != nil {
			a.logger.Error("failed to process accumulated chunks for request %s: %v", requestID, processErr)
			return nil, processErr
		}
		var rawRequest interface{}
		if result != nil && result.SpeechStreamResponse != nil && result.SpeechStreamResponse.ExtraFields.RawRequest != nil {
			rawRequest = result.SpeechStreamResponse.ExtraFields.RawRequest
		}
		return &ProcessedStreamResponse{
			RequestID:  requestID,
			StreamType: StreamTypeAudio,
			Model:      model,
			Provider:   provider,
			Data:       data,
			RawRequest: &rawRequest,
		}, nil
	}
	// Non-final chunk: skip expensive rebuild since no consumer uses intermediate data.
	// The logging plugin returns early when !isFinalChunk.
	return &ProcessedStreamResponse{
		RequestID:  requestID,
		StreamType: StreamTypeAudio,
		Model:      model,
		Provider:   provider,
		Data:       nil,
	}, nil
}
