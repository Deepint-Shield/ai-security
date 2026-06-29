// Package mistral implements transcription support for Mistral's audio API.
package mistral

import (
	"bytes"
	"mime/multipart"
	"strconv"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToMistralTranscriptionRequest converts a DeepIntShield transcription request to Mistral format.
func ToMistralTranscriptionRequest(deepintshieldReq *schemas.DeepIntShieldTranscriptionRequest) *MistralTranscriptionRequest {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil || len(deepintshieldReq.Input.File) == 0 {
		return nil
	}

	req := &MistralTranscriptionRequest{
		Model:    deepintshieldReq.Model,
		File:     deepintshieldReq.Input.File,
		Filename: deepintshieldReq.Input.Filename,
	}

	if deepintshieldReq.Params != nil {
		req.Language = deepintshieldReq.Params.Language
		req.Prompt = deepintshieldReq.Params.Prompt
		req.ResponseFormat = deepintshieldReq.Params.ResponseFormat

		// Handle extra params for Mistral-specific fields
		if deepintshieldReq.Params.ExtraParams != nil {
			if temp, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["temperature"]); ok {
				req.Temperature = temp
			}
			if granularities, ok := deepintshieldReq.Params.ExtraParams["timestamp_granularities"].([]string); ok {
				req.TimestampGranularities = granularities
			}
		}
	}

	return req
}

// ToDeepIntShieldTranscriptionResponse converts a Mistral transcription response to DeepIntShield format.
func (r *MistralTranscriptionResponse) ToDeepIntShieldTranscriptionResponse() *schemas.DeepIntShieldTranscriptionResponse {
	if r == nil {
		return nil
	}

	response := &schemas.DeepIntShieldTranscriptionResponse{
		Text:     r.Text,
		Duration: r.Duration,
		Language: r.Language,
		Task:     schemas.Ptr("transcribe"),
	}

	// Convert segments
	if len(r.Segments) > 0 {
		response.Segments = make([]schemas.TranscriptionSegment, len(r.Segments))
		for i, seg := range r.Segments {
			response.Segments[i] = schemas.TranscriptionSegment{
				ID:               seg.ID,
				Seek:             seg.Seek,
				Start:            seg.Start,
				End:              seg.End,
				Text:             seg.Text,
				Tokens:           seg.Tokens,
				Temperature:      seg.Temperature,
				AvgLogProb:       seg.AvgLogProb,
				CompressionRatio: seg.CompressionRatio,
				NoSpeechProb:     seg.NoSpeechProb,
			}
		}
	}

	// Convert words
	if len(r.Words) > 0 {
		response.Words = make([]schemas.TranscriptionWord, len(r.Words))
		for i, word := range r.Words {
			response.Words[i] = schemas.TranscriptionWord{
				Word:  word.Word,
				Start: word.Start,
				End:   word.End,
			}
		}
	}

	return response
}

// createMistralTranscriptionMultipartBody creates the multipart form body for a transcription request.
func createMistralTranscriptionMultipartBody(req *MistralTranscriptionRequest, providerName schemas.ModelProvider) (*bytes.Buffer, string, *schemas.DeepIntShieldError) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if err := parseTranscriptionFormDataBodyFromRequest(writer, req, providerName); err != nil {
		return nil, "", err
	}

	return &body, writer.FormDataContentType(), nil
}

// parseTranscriptionFormDataBodyFromRequest writes the transcription request to a multipart form.
func parseTranscriptionFormDataBodyFromRequest(writer *multipart.Writer, req *MistralTranscriptionRequest, providerName schemas.ModelProvider) *schemas.DeepIntShieldError {
	// Add file field - Mistral uses "file" as the form field name
	filename := req.Filename
	if filename == "" {
		filename = providerUtils.AudioFilenameFromBytes(req.File)
	}
	fileWriter, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return providerUtils.NewDeepIntShieldOperationError("failed to create form file", err, providerName)
	}
	if _, err := fileWriter.Write(req.File); err != nil {
		return providerUtils.NewDeepIntShieldOperationError("failed to write file data", err, providerName)
	}

	// Add model field (required)
	if err := writer.WriteField("model", req.Model); err != nil {
		return providerUtils.NewDeepIntShieldOperationError("failed to write model field", err, providerName)
	}

	// Add stream field if streaming
	if req.Stream != nil && *req.Stream {
		if err := writer.WriteField("stream", "true"); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write stream field", err, providerName)
		}
	}

	// Add optional fields
	if req.Language != nil {
		if err := writer.WriteField("language", *req.Language); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write language field", err, providerName)
		}
	}

	if req.Prompt != nil {
		if err := writer.WriteField("prompt", *req.Prompt); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write prompt field", err, providerName)
		}
	}

	if req.ResponseFormat != nil {
		if err := writer.WriteField("response_format", *req.ResponseFormat); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write response_format field", err, providerName)
		}
	}

	if req.Temperature != nil {
		if err := writer.WriteField("temperature", formatFloat64(*req.Temperature)); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write temperature field", err, providerName)
		}
	}

	for _, granularity := range req.TimestampGranularities {
		if err := writer.WriteField("timestamp_granularities[]", granularity); err != nil {
			return providerUtils.NewDeepIntShieldOperationError("failed to write timestamp_granularities field", err, providerName)
		}
	}

	// Close the multipart writer to finalize the form
	if err := writer.Close(); err != nil {
		return providerUtils.NewDeepIntShieldOperationError("failed to close multipart writer", err, providerName)
	}

	return nil
}

// formatFloat64 converts a float64 to string for form fields.
func formatFloat64(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// ToDeepIntShieldTranscriptionStreamResponse converts a Mistral streaming event to DeepIntShield format.
func (e *MistralTranscriptionStreamEvent) ToDeepIntShieldTranscriptionStreamResponse() *schemas.DeepIntShieldTranscriptionStreamResponse {
	if e == nil {
		return nil
	}

	response := &schemas.DeepIntShieldTranscriptionStreamResponse{}

	switch MistralTranscriptionStreamEventType(e.Event) {
	case MistralTranscriptionStreamEventTextDelta:
		response.Type = schemas.TranscriptionStreamResponseTypeDelta
		if e.Data != nil {
			response.Delta = &e.Data.Text
			response.Text = e.Data.Text
		}

	case MistralTranscriptionStreamEventLanguage:
		response.Type = schemas.TranscriptionStreamResponseTypeDelta
		if e.Data != nil {
			response.Text = "" // Language event doesn't have text content
		}

	case MistralTranscriptionStreamEventSegment:
		response.Type = schemas.TranscriptionStreamResponseTypeDelta
		if e.Data != nil && e.Data.Segment != nil {
			response.Text = e.Data.Segment.Text
			response.Delta = &e.Data.Segment.Text
		}

	case MistralTranscriptionStreamEventDone:
		response.Type = schemas.TranscriptionStreamResponseTypeDone
		if e.Data != nil && e.Data.Usage != nil {
			totalTokens := e.Data.Usage.TotalTokens
			inputTokens := e.Data.Usage.PromptTokens
			outputTokens := e.Data.Usage.CompletionTokens
			response.Usage = &schemas.TranscriptionUsage{
				Type:         "tokens",
				TotalTokens:  &totalTokens,
				InputTokens:  &inputTokens,
				OutputTokens: &outputTokens,
			}
		}
	}

	return response
}
