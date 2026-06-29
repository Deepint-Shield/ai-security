package streaming

import (
	"sync"
	"sync/atomic"
	"time"

	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

type StreamType string

const (
	StreamTypeText          StreamType = "text.completion"
	StreamTypeChat          StreamType = "chat.completion"
	StreamTypeAudio         StreamType = "audio.speech"
	StreamTypeImage         StreamType = "image.generation"
	StreamTypeTranscription StreamType = "audio.transcription"
	StreamTypeResponses     StreamType = "responses"
)

// AccumulatedData contains the accumulated data for a stream
type AccumulatedData struct {
	RequestID             string
	Model                 string
	Status                string
	Stream                bool
	Latency               int64 // in milliseconds
	TimeToFirstToken      int64 // Time to first token in milliseconds (streaming only)
	StartTimestamp        time.Time
	EndTimestamp          time.Time
	OutputMessage         *schemas.ChatMessage
	OutputMessages        []schemas.ResponsesMessage // For responses API
	ToolCalls             []schemas.ChatAssistantMessageToolCall
	ErrorDetails          *schemas.DeepIntShieldError
	TokenUsage            *schemas.DeepIntShieldLLMUsage
	CacheDebug            *schemas.DeepIntShieldCacheDebug
	Cost                  *float64
	AudioOutput           *schemas.DeepIntShieldSpeechResponse
	TranscriptionOutput   *schemas.DeepIntShieldTranscriptionResponse
	ImageGenerationOutput *schemas.DeepIntShieldImageGenerationResponse
	FinishReason          *string
	LogProbs              *schemas.DeepIntShieldLogProbs
	RawResponse           *string
}

// AudioStreamChunk represents a single streaming chunk
type AudioStreamChunk struct {
	Timestamp          time.Time                            // When chunk was received
	Delta              *schemas.DeepIntShieldSpeechStreamResponse // The actual delta content
	FinishReason       *string                              // If this is the final chunk
	TokenUsage         *schemas.SpeechUsage                 // Token usage if available
	SemanticCacheDebug *schemas.DeepIntShieldCacheDebug           // Semantic cache debug if available
	Cost               *float64                             // Cost in dollars from pricing plugin
	ErrorDetails       *schemas.DeepIntShieldError                // Error if any
	ChunkIndex         int                                  // Index of the chunk in the stream
	RawResponse        *string
}

// TranscriptionStreamChunk represents a single transcription streaming chunk
type TranscriptionStreamChunk struct {
	Timestamp          time.Time                                   // When chunk was received
	Delta              *schemas.DeepIntShieldTranscriptionStreamResponse // The actual delta content
	FinishReason       *string                                     // If this is the final chunk
	TokenUsage         *schemas.TranscriptionUsage                 // Token usage if available
	SemanticCacheDebug *schemas.DeepIntShieldCacheDebug                  // Semantic cache debug if available
	Cost               *float64                                    // Cost in dollars from pricing plugin
	ErrorDetails       *schemas.DeepIntShieldError                       // Error if any
	ChunkIndex         int                                         // Index of the chunk in the stream
	RawResponse        *string
}

// ChatStreamChunk represents a single streaming chunk
type ChatStreamChunk struct {
	Timestamp          time.Time                              // When chunk was received
	Delta              *schemas.ChatStreamResponseChoiceDelta // The actual delta content
	FinishReason       *string                                // If this is the final chunk
	LogProbs           *schemas.DeepIntShieldLogProbs               // LogProbs if available
	TokenUsage         *schemas.DeepIntShieldLLMUsage               // Token usage if available
	SemanticCacheDebug *schemas.DeepIntShieldCacheDebug             // Semantic cache debug if available
	Cost               *float64                               // Cost in dollars from pricing plugin
	ErrorDetails       *schemas.DeepIntShieldError                  // Error if any
	ChunkIndex         int                                    // Index of the chunk in the stream
	RawResponse        *string                                // Raw response if available
}

// ResponsesStreamChunk represents a single responses streaming chunk
type ResponsesStreamChunk struct {
	Timestamp          time.Time                               // When chunk was received
	StreamResponse     *schemas.DeepIntShieldResponsesStreamResponse // The actual stream response
	FinishReason       *string                                 // If this is the final chunk
	TokenUsage         *schemas.DeepIntShieldLLMUsage                // Token usage if available
	SemanticCacheDebug *schemas.DeepIntShieldCacheDebug              // Semantic cache debug if available
	Cost               *float64                                // Cost in dollars from pricing plugin
	ErrorDetails       *schemas.DeepIntShieldError                   // Error if any
	ChunkIndex         int                                     // Index of the chunk in the stream
	RawResponse        *string
}

// ImageStreamChunk represents a single image streaming chunk
type ImageStreamChunk struct {
	Timestamp          time.Time                                     // When chunk was received
	Delta              *schemas.DeepIntShieldImageGenerationStreamResponse // The actual stream response
	FinishReason       *string                                       // If this is the final chunk
	ChunkIndex         int                                           // Index of the chunk in the stream
	ImageIndex         int                                           // Index of the image in the stream
	ErrorDetails       *schemas.DeepIntShieldError                         // Error if any
	Cost               *float64                                      // Cost in dollars from pricing plugin
	SemanticCacheDebug *schemas.DeepIntShieldCacheDebug                    // Semantic cache debug if available
	TokenUsage         *schemas.ImageUsage                           // Token usage if available
	RawResponse        *string                                       // Raw response if available
}

// StreamAccumulator manages accumulation of streaming chunks
type StreamAccumulator struct {
	RequestID                 string
	StartTimestamp            time.Time
	FirstChunkTimestamp       time.Time // Timestamp when the first chunk was received (for TTFT calculation)
	ChatStreamChunks          []*ChatStreamChunk
	ResponsesStreamChunks     []*ResponsesStreamChunk
	TranscriptionStreamChunks []*TranscriptionStreamChunk
	AudioStreamChunks         []*AudioStreamChunk
	ImageStreamChunks         []*ImageStreamChunk

	// De-dup maps to prevent chunk loss on out-of-order arrival
	ChatChunksSeen          map[int]struct{}
	ResponsesChunksSeen     map[int]struct{}
	TranscriptionChunksSeen map[int]struct{}
	AudioChunksSeen         map[int]struct{}
	ImageChunksSeen         map[string]struct{} // Composite key: "imageIndex:chunkIndex" to scope de-dup per image

	// Track highest ChunkIndex for metadata extraction (TokenUsage, Cost, FinishReason)
	MaxChatChunkIndex          int
	MaxResponsesChunkIndex     int
	MaxTranscriptionChunkIndex int
	MaxAudioChunkIndex         int

	IsComplete     bool
	FinalTimestamp time.Time
	mu             sync.Mutex
	Timestamp      time.Time
	refCount       atomic.Int64
}

// getLastChatChunk returns the chunk with the highest ChunkIndex (contains metadata like TokenUsage, Cost)
func (sa *StreamAccumulator) getLastChatChunk() *ChatStreamChunk {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	return sa.getLastChatChunkLocked()
}

// getLastChatChunkLocked returns the chunk with the highest ChunkIndex.
// MUST be called with sa.mu already held.
func (sa *StreamAccumulator) getLastChatChunkLocked() *ChatStreamChunk {
	if sa.MaxChatChunkIndex < 0 {
		return nil
	}
	for _, chunk := range sa.ChatStreamChunks {
		if chunk.ChunkIndex == sa.MaxChatChunkIndex {
			return chunk
		}
	}
	return nil
}

// getLastResponsesChunk returns the chunk with the highest ChunkIndex (contains metadata like TokenUsage, Cost)
func (sa *StreamAccumulator) getLastResponsesChunk() *ResponsesStreamChunk {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	return sa.getLastResponsesChunkLocked()
}

// getLastResponsesChunkLocked returns the chunk with the highest ChunkIndex.
// MUST be called with sa.mu already held.
func (sa *StreamAccumulator) getLastResponsesChunkLocked() *ResponsesStreamChunk {
	if sa.MaxResponsesChunkIndex < 0 {
		return nil
	}
	for _, chunk := range sa.ResponsesStreamChunks {
		if chunk.ChunkIndex == sa.MaxResponsesChunkIndex {
			return chunk
		}
	}
	return nil
}

// getLastTranscriptionChunk returns the chunk with the highest ChunkIndex (contains metadata like TokenUsage, Cost)
func (sa *StreamAccumulator) getLastTranscriptionChunk() *TranscriptionStreamChunk {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	return sa.getLastTranscriptionChunkLocked()
}

// getLastTranscriptionChunkLocked returns the chunk with the highest ChunkIndex.
// MUST be called with sa.mu already held.
func (sa *StreamAccumulator) getLastTranscriptionChunkLocked() *TranscriptionStreamChunk {
	if sa.MaxTranscriptionChunkIndex < 0 {
		return nil
	}
	for _, chunk := range sa.TranscriptionStreamChunks {
		if chunk.ChunkIndex == sa.MaxTranscriptionChunkIndex {
			return chunk
		}
	}
	return nil
}

// getLastAudioChunk returns the chunk with the highest ChunkIndex (contains metadata like TokenUsage, Cost)
func (sa *StreamAccumulator) getLastAudioChunk() *AudioStreamChunk {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	return sa.getLastAudioChunkLocked()
}

// getLastAudioChunkLocked returns the chunk with the highest ChunkIndex.
// MUST be called with sa.mu already held.
func (sa *StreamAccumulator) getLastAudioChunkLocked() *AudioStreamChunk {
	if sa.MaxAudioChunkIndex < 0 {
		return nil
	}
	for _, chunk := range sa.AudioStreamChunks {
		if chunk.ChunkIndex == sa.MaxAudioChunkIndex {
			return chunk
		}
	}
	return nil
}

// ProcessedStreamResponse represents a processed streaming response
type ProcessedStreamResponse struct {
	RequestID  string
	StreamType StreamType
	Provider   schemas.ModelProvider
	Model      string
	Data       *AccumulatedData
	RawRequest *interface{}
}

// ToDeepIntShieldResponse converts a ProcessedStreamResponse to a DeepIntShieldResponse
func (p *ProcessedStreamResponse) ToDeepIntShieldResponse() *schemas.DeepIntShieldResponse {
	if p.Data == nil {
		return nil
	}

	resp := &schemas.DeepIntShieldResponse{}

	switch p.StreamType {
	case StreamTypeText:
		text := ""
		if p.Data.OutputMessage != nil && p.Data.OutputMessage.Content != nil && p.Data.OutputMessage.Content.ContentStr != nil {
			text = *p.Data.OutputMessage.Content.ContentStr
		}
		textResp := &schemas.DeepIntShieldTextCompletionResponse{
			ID:     p.RequestID,
			Object: "text_completion",
			Model:  p.Model,
			Choices: []schemas.DeepIntShieldResponseChoice{
				{
					Index:        0,
					FinishReason: p.Data.FinishReason,
					LogProbs:     p.Data.LogProbs,
					TextCompletionResponseChoice: &schemas.TextCompletionResponseChoice{
						Text: &text,
					},
				},
			},
			Usage: p.Data.TokenUsage,
		}

		resp.TextCompletionResponse = textResp
		resp.TextCompletionResponse.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
			RequestType:    schemas.TextCompletionRequest,
			Provider:       p.Provider,
			ModelRequested: p.Model,
			Latency:        p.Data.Latency,
		}
		if p.RawRequest != nil {
			resp.TextCompletionResponse.ExtraFields.RawRequest = p.RawRequest
		}
		if p.Data.RawResponse != nil {
			resp.TextCompletionResponse.ExtraFields.RawResponse = *p.Data.RawResponse
		}
		if p.Data.CacheDebug != nil {
			resp.TextCompletionResponse.ExtraFields.CacheDebug = p.Data.CacheDebug
		}
	case StreamTypeChat:
		var message *schemas.ChatMessage
		if p.Data.OutputMessage != nil {
			message = &schemas.ChatMessage{
				Role:                 p.Data.OutputMessage.Role,
				Content:              p.Data.OutputMessage.Content,
				ChatAssistantMessage: p.Data.OutputMessage.ChatAssistantMessage,
				ChatToolMessage:      p.Data.OutputMessage.ChatToolMessage,
				Name:                 p.Data.OutputMessage.Name,
			}
		}
		chatResp := &schemas.DeepIntShieldChatResponse{
			ID:      p.RequestID,
			Object:  "chat.completion",
			Model:   p.Model,
			Created: int(p.Data.StartTimestamp.Unix()),
			Choices: []schemas.DeepIntShieldResponseChoice{
				{
					Index:        0,
					FinishReason: p.Data.FinishReason,
					LogProbs:     p.Data.LogProbs,
					ChatNonStreamResponseChoice: &schemas.ChatNonStreamResponseChoice{
						Message: message,
					},
				},
			},
			Usage: p.Data.TokenUsage,
		}

		resp.ChatResponse = chatResp
		resp.ChatResponse.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
			RequestType:    schemas.ChatCompletionRequest,
			Provider:       p.Provider,
			ModelRequested: p.Model,
			Latency:        p.Data.Latency,
		}
		if p.RawRequest != nil {
			resp.ChatResponse.ExtraFields.RawRequest = p.RawRequest
		}
		if p.Data.RawResponse != nil {
			resp.ChatResponse.ExtraFields.RawResponse = *p.Data.RawResponse
		}
		if p.Data.CacheDebug != nil {
			resp.ChatResponse.ExtraFields.CacheDebug = p.Data.CacheDebug
		}
	case StreamTypeResponses:
		responsesResp := &schemas.DeepIntShieldResponsesResponse{}

		if p.Data.OutputMessages != nil {
			responsesResp.Output = p.Data.OutputMessages
		}
		if p.Data.TokenUsage != nil {
			responsesResp.Usage = p.Data.TokenUsage.ToResponsesResponseUsage()
		}
		responsesResp.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
			RequestType:    schemas.ResponsesRequest,
			Provider:       p.Provider,
			ModelRequested: p.Model,
			Latency:        p.Data.Latency,
		}
		if p.RawRequest != nil {
			responsesResp.ExtraFields.RawRequest = p.RawRequest
		}
		if p.Data.RawResponse != nil {
			responsesResp.ExtraFields.RawResponse = *p.Data.RawResponse
		}
		if p.Data.CacheDebug != nil {
			responsesResp.ExtraFields.CacheDebug = p.Data.CacheDebug
		}
		resp.ResponsesResponse = responsesResp
	case StreamTypeAudio:
		speechResp := p.Data.AudioOutput
		if speechResp == nil {
			speechResp = &schemas.DeepIntShieldSpeechResponse{}
		}
		resp.SpeechResponse = speechResp
		resp.SpeechResponse.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
			RequestType:    schemas.SpeechRequest,
			Provider:       p.Provider,
			ModelRequested: p.Model,
			Latency:        p.Data.Latency,
		}
		if p.RawRequest != nil {
			resp.SpeechResponse.ExtraFields.RawRequest = p.RawRequest
		}
		if p.Data.RawResponse != nil {
			resp.SpeechResponse.ExtraFields.RawResponse = *p.Data.RawResponse
		}
		if p.Data.CacheDebug != nil {
			resp.SpeechResponse.ExtraFields.CacheDebug = p.Data.CacheDebug
		}
	case StreamTypeTranscription:
		transcriptionResp := p.Data.TranscriptionOutput
		if transcriptionResp == nil {
			transcriptionResp = &schemas.DeepIntShieldTranscriptionResponse{}
		}
		resp.TranscriptionResponse = transcriptionResp
		resp.TranscriptionResponse.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
			RequestType:    schemas.TranscriptionRequest,
			Provider:       p.Provider,
			ModelRequested: p.Model,
			Latency:        p.Data.Latency,
		}
		if p.RawRequest != nil {
			resp.TranscriptionResponse.ExtraFields.RawRequest = p.RawRequest
		}
	case StreamTypeImage:
		imageResp := p.Data.ImageGenerationOutput
		if imageResp == nil {
			imageResp = &schemas.DeepIntShieldImageGenerationResponse{
				Data: make([]schemas.ImageData, 0),
			}
			if p.RequestID != "" {
				imageResp.ID = p.RequestID
			}
			if p.Model != "" {
				imageResp.Model = p.Model
			}
		}
		// Ensure Data is never nil to serialize as [] instead of null
		if imageResp.Data == nil {
			imageResp.Data = make([]schemas.ImageData, 0)
		}
		resp.ImageGenerationResponse = imageResp
		resp.ImageGenerationResponse.ExtraFields = schemas.DeepIntShieldResponseExtraFields{
			RequestType:    schemas.ImageGenerationRequest,
			Provider:       p.Provider,
			ModelRequested: p.Model,
			Latency:        p.Data.Latency,
		}
		if p.RawRequest != nil {
			resp.ImageGenerationResponse.ExtraFields.RawRequest = p.RawRequest
		}
		if p.Data.RawResponse != nil {
			resp.ImageGenerationResponse.ExtraFields.RawResponse = *p.Data.RawResponse
		}
		if p.Data.CacheDebug != nil {
			resp.ImageGenerationResponse.ExtraFields.CacheDebug = p.Data.CacheDebug
		}

	}
	return resp
}
