package gemini

import (
	"context"
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToDeepIntShieldSpeechRequest converts a GeminiGenerationRequest to a DeepIntShieldSpeechRequest
func (request *GeminiGenerationRequest) ToDeepIntShieldSpeechRequest(ctx *schemas.DeepIntShieldContext) *schemas.DeepIntShieldSpeechRequest {
	provider, model := schemas.ParseModelString(request.Model, utils.CheckAndSetDefaultProvider(ctx, schemas.Gemini))

	deepintshieldReq := &schemas.DeepIntShieldSpeechRequest{
		Provider: provider,
		Model:    model,
	}

	// Extract text input from contents
	var textInput string
	for _, content := range request.Contents {
		for _, part := range content.Parts {
			if part.Text != "" {
				textInput += part.Text
			}
		}
	}

	deepintshieldReq.Input = &schemas.SpeechInput{
		Input: textInput,
	}

	// Convert generation config to parameters
	if request.GenerationConfig.SpeechConfig != nil || len(request.GenerationConfig.ResponseModalities) > 0 {
		deepintshieldReq.Params = &schemas.SpeechParameters{}

		// Extract voice config from speech config
		if request.GenerationConfig.SpeechConfig != nil {
			// Handle single-speaker voice config
			if request.GenerationConfig.SpeechConfig.VoiceConfig != nil {
				deepintshieldReq.Params.VoiceConfig = &schemas.SpeechVoiceInput{}

				if request.GenerationConfig.SpeechConfig.VoiceConfig.PrebuiltVoiceConfig != nil {
					voiceName := request.GenerationConfig.SpeechConfig.VoiceConfig.PrebuiltVoiceConfig.VoiceName
					deepintshieldReq.Params.VoiceConfig.Voice = &voiceName
				}
			} else if request.GenerationConfig.SpeechConfig.MultiSpeakerVoiceConfig != nil {
				// Handle multi-speaker voice config
				// Convert to DeepIntShield's MultiVoiceConfig format
				if len(request.GenerationConfig.SpeechConfig.MultiSpeakerVoiceConfig.SpeakerVoiceConfigs) > 0 {
					deepintshieldReq.Params.VoiceConfig = &schemas.SpeechVoiceInput{}
					multiVoiceConfig := make([]schemas.VoiceConfig, 0, len(request.GenerationConfig.SpeechConfig.MultiSpeakerVoiceConfig.SpeakerVoiceConfigs))

					for _, speakerConfig := range request.GenerationConfig.SpeechConfig.MultiSpeakerVoiceConfig.SpeakerVoiceConfigs {
						if speakerConfig.VoiceConfig != nil && speakerConfig.VoiceConfig.PrebuiltVoiceConfig != nil {
							multiVoiceConfig = append(multiVoiceConfig, schemas.VoiceConfig{
								Speaker: speakerConfig.Speaker,
								Voice:   speakerConfig.VoiceConfig.PrebuiltVoiceConfig.VoiceName,
							})
						}
					}

					deepintshieldReq.Params.VoiceConfig.MultiVoiceConfig = multiVoiceConfig
				}
			}
		}

		// Store response modalities in extra params if needed
		if len(request.GenerationConfig.ResponseModalities) > 0 {
			if deepintshieldReq.Params.ExtraParams == nil {
				deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
			}
			modalities := make([]string, len(request.GenerationConfig.ResponseModalities))
			for i, mod := range request.GenerationConfig.ResponseModalities {
				modalities[i] = string(mod)
			}
			deepintshieldReq.Params.ExtraParams["response_modalities"] = modalities
		}
	}

	return deepintshieldReq
}

// ToGeminiSpeechRequest converts a DeepIntShieldSpeechRequest to a GeminiGenerationRequest
func ToGeminiSpeechRequest(deepintshieldReq *schemas.DeepIntShieldSpeechRequest) (*GeminiGenerationRequest, error) {
	if deepintshieldReq == nil {
		return nil, fmt.Errorf("deepintshieldReq is nil")
	}
	// Here we confirm if the response_format is wav or empty string
	// If its anything else, we will return an error
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.ResponseFormat != "" && deepintshieldReq.Params.ResponseFormat != "wav" {
		return nil, fmt.Errorf("gemini does not support response_format: %s. Only wav or empty string is supported which defaults to wav", deepintshieldReq.Params.ResponseFormat)
	}
	// Create the base Gemini generation request
	geminiReq := &GeminiGenerationRequest{
		Model: deepintshieldReq.Model,
	}
	// Convert parameters to generation config
	geminiReq.GenerationConfig.ResponseModalities = []Modality{ModalityAudio}
	// Convert speech input to Gemini format
	if deepintshieldReq.Input != nil && deepintshieldReq.Input.Input != "" {
		geminiReq.Contents = []Content{
			{
				Parts: []*Part{
					{
						Text: deepintshieldReq.Input.Input,
					},
				},
			},
		}
		// Add speech config to generation config if voice config is provided
		if deepintshieldReq.Params != nil && deepintshieldReq.Params.VoiceConfig != nil {
			// Handle both single voice and multi-voice configurations
			if deepintshieldReq.Params.VoiceConfig.Voice != nil || len(deepintshieldReq.Params.VoiceConfig.MultiVoiceConfig) > 0 {
				addSpeechConfigToGenerationConfig(&geminiReq.GenerationConfig, deepintshieldReq.Params.VoiceConfig)
			}
			geminiReq.ExtraParams = deepintshieldReq.Params.ExtraParams
		}
	}
	return geminiReq, nil
}

// ToDeepIntShieldSpeechResponse converts a GenerateContentResponse to a DeepIntShieldSpeechResponse
func (response *GenerateContentResponse) ToDeepIntShieldSpeechResponse(ctx context.Context) (*schemas.DeepIntShieldSpeechResponse, error) {
	deepintshieldResp := &schemas.DeepIntShieldSpeechResponse{}

	// Process candidates to extract audio content
	if len(response.Candidates) > 0 {
		candidate := response.Candidates[0]
		if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
			var audioData []byte
			// Extract audio data from all parts
			for _, part := range candidate.Content.Parts {
				if part.InlineData != nil && len(part.InlineData.Data) > 0 {
					// Check if this is audio data
					if strings.HasPrefix(part.InlineData.MIMEType, "audio/") {
						decodedData, err := decodeBase64StringToBytes(part.InlineData.Data)
						if err != nil {
							return nil, fmt.Errorf("failed to decode base64 audio data: %v", err)
						}
						audioData = append(audioData, decodedData...)
					}
				}
			}
			if len(audioData) > 0 {
				responseFormat := ctx.Value(DeepIntShieldContextKeyResponseFormat).(string)
				// Gemini returns PCM audio (s16le, 24000 Hz, mono)
				// Convert to WAV for standard playable output format
				if responseFormat == "wav" {
					wavData, err := utils.ConvertPCMToWAV(audioData, utils.DefaultGeminiPCMConfig())
					if err != nil {
						return nil, fmt.Errorf("failed to convert PCM to WAV: %v", err)
					}
					deepintshieldResp.Audio = wavData
				} else {
					deepintshieldResp.Audio = audioData
				}
			}

			// Set usage information
			if response.UsageMetadata != nil {
				deepintshieldResp.Usage = convertGeminiUsageMetadataToSpeechUsage(response.UsageMetadata)
			}
		}
	}
	return deepintshieldResp, nil
}

// ToGeminiSpeechResponse converts a DeepIntShieldSpeechResponse to Gemini's GenerateContentResponse
func ToGeminiSpeechResponse(deepintshieldResp *schemas.DeepIntShieldSpeechResponse) *GenerateContentResponse {
	if deepintshieldResp == nil {
		return nil
	}

	genaiResp := &GenerateContentResponse{}

	candidate := &Candidate{
		Content: &Content{
			Parts: []*Part{
				{
					InlineData: &Blob{
						Data:     encodeBytesToBase64String(deepintshieldResp.Audio),
						MIMEType: utils.DetectAudioMimeType(deepintshieldResp.Audio),
					},
				},
			},
			Role: string(RoleModel),
		},
	}

	// Set usage metadata if present
	if deepintshieldResp.Usage != nil {
		genaiResp.UsageMetadata = convertDeepIntShieldSpeechUsageToGeminiUsageMetadata(deepintshieldResp.Usage)
	}

	genaiResp.Candidates = []*Candidate{candidate}
	return genaiResp
}
