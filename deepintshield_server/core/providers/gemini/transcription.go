package gemini

import (
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldTranscriptionRequest converts a GeminiGenerationRequest to a DeepIntShieldTranscriptionRequest
func (request *GeminiGenerationRequest) ToDeepIntShieldTranscriptionRequest(ctx *schemas.DeepIntShieldContext) (*schemas.DeepIntShieldTranscriptionRequest, error) {
	provider, model := schemas.ParseModelString(request.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.Gemini))

	deepintshieldReq := &schemas.DeepIntShieldTranscriptionRequest{
		Provider: provider,
		Model:    model,
	}

	// Extract audio data and prompt from contents
	var promptText string
	var audioData []byte
	var audioMimeType string

	for _, content := range request.Contents {
		for _, part := range content.Parts {
			// Extract text prompt
			if part.Text != "" {
				if promptText != "" {
					promptText += " "
				}
				promptText += part.Text
			}

			// Extract audio data from inline data
			if part.InlineData != nil && strings.HasPrefix(strings.ToLower(part.InlineData.MIMEType), "audio/") {
				decodedData, err := decodeBase64StringToBytes(part.InlineData.Data)
				if err != nil {
					return nil, fmt.Errorf("failed to decode base64 audio data: %v", err)
				}
				audioData = append(audioData, decodedData...)
				if audioMimeType == "" {
					audioMimeType = part.InlineData.MIMEType
				}
			}

			// Extract audio data from file data (would need to be fetched separately in real scenario)
			// For now, we just note the file URI in extra params
			if part.FileData != nil && strings.HasPrefix(strings.ToLower(part.FileData.MIMEType), "audio/") {
				if deepintshieldReq.Params == nil {
					deepintshieldReq.Params = &schemas.TranscriptionParameters{}
				}
				if deepintshieldReq.Params.ExtraParams == nil {
					deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
				}
				deepintshieldReq.Params.ExtraParams["file_uri"] = part.FileData.FileURI
				if audioMimeType == "" {
					audioMimeType = part.FileData.MIMEType
				}
			}
		}
	}

	// Set the audio input
	deepintshieldReq.Input = &schemas.TranscriptionInput{
		File: audioData,
	}

	// Set parameters
	if deepintshieldReq.Params == nil {
		deepintshieldReq.Params = &schemas.TranscriptionParameters{}
	}

	// Set prompt if provided
	if promptText != "" {
		deepintshieldReq.Params.Prompt = &promptText
	}

	// Handle safety settings from request
	if len(request.SafetySettings) > 0 {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}
		deepintshieldReq.Params.ExtraParams["safety_settings"] = request.SafetySettings
	}

	// Handle cached content
	if request.CachedContent != "" {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}
		deepintshieldReq.Params.ExtraParams["cached_content"] = request.CachedContent
	}

	// Handle labels
	if len(request.Labels) > 0 {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}
		deepintshieldReq.Params.ExtraParams["labels"] = request.Labels
	}

	return deepintshieldReq, nil
}

func ToGeminiTranscriptionRequest(deepintshieldReq *schemas.DeepIntShieldTranscriptionRequest) *GeminiGenerationRequest {
	if deepintshieldReq == nil {
		return nil
	}

	// Create the base Gemini generation request
	geminiReq := &GeminiGenerationRequest{
		Model: deepintshieldReq.Model,
	}

	// Convert parameters to generation config
	if deepintshieldReq.Params != nil {
		geminiReq.ExtraParams = deepintshieldReq.Params.ExtraParams
		// Handle extra parameters
		if deepintshieldReq.Params.ExtraParams != nil {
			// Safety settings
			if safetySettings, ok := schemas.SafeExtractFromMap(deepintshieldReq.Params.ExtraParams, "safety_settings"); ok {
				delete(geminiReq.ExtraParams, "safety_settings")
				if settings, ok := SafeExtractSafetySettings(safetySettings); ok {
					geminiReq.SafetySettings = settings
				}
			}

			// Cached content
			if cachedContent, ok := schemas.SafeExtractString(deepintshieldReq.Params.ExtraParams["cached_content"]); ok {
				delete(geminiReq.ExtraParams, "cached_content")
				geminiReq.CachedContent = cachedContent
			}

			// Labels
			if labels, ok := schemas.SafeExtractFromMap(deepintshieldReq.Params.ExtraParams, "labels"); ok {
				if labelMap, ok := schemas.SafeExtractStringMap(labels); ok {
					delete(geminiReq.ExtraParams, "labels")
					geminiReq.Labels = labelMap
				}
			}
		}
	}

	// Determine the prompt text
	var prompt string
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.Prompt != nil {
		prompt = *deepintshieldReq.Params.Prompt
	} else {
		prompt = "Generate a transcript of the speech."
	}

	// Create parts for the transcription request
	parts := []*Part{
		{
			Text: prompt,
		},
	}

	// Add audio file if present
	if len(deepintshieldReq.Input.File) > 0 {
		parts = append(parts, &Part{
			InlineData: &Blob{
				MIMEType: utils.DetectAudioMimeType(deepintshieldReq.Input.File),
				Data:     encodeBytesToBase64String(deepintshieldReq.Input.File),
			},
		})
	}

	geminiReq.Contents = []Content{
		{
			Parts: parts,
		},
	}

	return geminiReq
}

// ToDeepIntShieldTranscriptionResponse converts a GenerateContentResponse to a DeepIntShieldTranscriptionResponse
func (response *GenerateContentResponse) ToDeepIntShieldTranscriptionResponse() *schemas.DeepIntShieldTranscriptionResponse {
	deepintshieldResp := &schemas.DeepIntShieldTranscriptionResponse{}

	// Process candidates to extract text content
	if len(response.Candidates) > 0 {
		candidate := response.Candidates[0]
		if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
			var textContent string

			// Extract text content from all parts
			for _, part := range candidate.Content.Parts {
				if part.Text != "" {
					textContent += part.Text
				}
			}

			if textContent != "" {
				deepintshieldResp.Text = textContent
				deepintshieldResp.Task = schemas.Ptr("transcribe")

				// Set usage information with modality details
				deepintshieldResp.Usage = convertGeminiUsageMetadataToTranscriptionUsage(response.UsageMetadata)
			}
		}
	}

	return deepintshieldResp
}

// ToGeminiTranscriptionResponse converts a DeepIntShieldTranscriptionResponse to Gemini's GenerateContentResponse
func ToGeminiTranscriptionResponse(deepintshieldResp *schemas.DeepIntShieldTranscriptionResponse) *GenerateContentResponse {
	if deepintshieldResp == nil {
		return nil
	}

	genaiResp := &GenerateContentResponse{}

	candidate := &Candidate{
		Content: &Content{
			Parts: []*Part{
				{
					Text: deepintshieldResp.Text,
				},
			},
			Role: string(RoleModel),
		},
	}

	// Set usage metadata from transcription usage with modality details
	genaiResp.UsageMetadata = convertDeepIntShieldTranscriptionUsageToGeminiUsageMetadata(deepintshieldResp.Usage)

	genaiResp.Candidates = []*Candidate{candidate}
	return genaiResp
}
