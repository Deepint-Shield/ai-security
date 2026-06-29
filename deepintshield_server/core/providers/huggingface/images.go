package huggingface

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	nebiusProvider "github.com/deepint-shield/ai-security/core/providers/nebius"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

// Models that support multiple images (image_urls)
var falAIMultiImageEditModels = map[string]bool{
	"fal-ai/flux-2/edit":     true,
	"fal-ai/flux-2-pro/edit": true,
}

// Models that only support single image (image_url)
var falAISingleImageEditModels = map[string]bool{
	"fal-ai/flux-pro/kontext":        true,
	"fal-ai/flux/dev/image-to-image": true,
}

// ToHuggingFaceImageGenerationRequest converts a DeepIntShield image generation request to provider-specific format
func ToHuggingFaceImageGenerationRequest(deepintshieldReq *schemas.DeepIntShieldImageGenerationRequest) (providerUtils.RequestBodyWithExtraParams, error) {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil {
		return nil, fmt.Errorf("deepintshield request is nil or input is nil")
	}

	inferenceProvider, model, nameErr := splitIntoModelProvider(deepintshieldReq.Model)
	if nameErr != nil {
		return nil, nameErr
	}

	switch inferenceProvider {
	case nebius:
		req := &nebiusProvider.NebiusImageGenerationRequest{
			Model:  &model,
			Prompt: &deepintshieldReq.Input.Prompt,
		}

		if deepintshieldReq.Params != nil {
			if deepintshieldReq.Params.ResponseFormat != nil {
				req.ResponseFormat = deepintshieldReq.Params.ResponseFormat
			}

			if deepintshieldReq.Params.Size != nil && strings.ToLower(*deepintshieldReq.Params.Size) != "auto" {
				size := strings.Split(strings.ToLower(*deepintshieldReq.Params.Size), "x")
				if len(size) != 2 {
					return nil, fmt.Errorf("invalid size format: expected 'WIDTHxHEIGHT', got %q", *deepintshieldReq.Params.Size)
				}

				width, err := strconv.Atoi(size[0])
				if err != nil {
					return nil, fmt.Errorf("invalid width in size %q: %w", *deepintshieldReq.Params.Size, err)
				}

				height, err := strconv.Atoi(size[1])
				if err != nil {
					return nil, fmt.Errorf("invalid height in size %q: %w", *deepintshieldReq.Params.Size, err)
				}

				req.Width = &width
				req.Height = &height
			}
			if deepintshieldReq.Params.OutputFormat != nil {
				req.ResponseExtension = deepintshieldReq.Params.OutputFormat
			}

			// Handle nebius inconsistency - normalize ResponseExtension case-insensitively
			if req.ResponseExtension != nil && strings.ToLower(*req.ResponseExtension) == "jpeg" {
				req.ResponseExtension = schemas.Ptr("jpg")
			}

			// Map seed from direct field
			if deepintshieldReq.Params.Seed != nil {
				req.Seed = deepintshieldReq.Params.Seed
			}

			// Map negative_prompt from direct field
			if deepintshieldReq.Params.NegativePrompt != nil {
				req.NegativePrompt = deepintshieldReq.Params.NegativePrompt
			}

			// Handle extra params for nebius
			if deepintshieldReq.Params.ExtraParams != nil {
				req.ExtraParams = deepintshieldReq.Params.ExtraParams
				// Map num_inference_steps
				if v, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["num_inference_steps"]); ok {
					delete(req.ExtraParams, "num_inference_steps")
					req.NumInferenceSteps = v
				}

				// Map guidance_scale
				if v, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["guidance_scale"]); ok {
					delete(req.ExtraParams, "guidance_scale")
					req.GuidanceScale = v
				}

				// Map loras
				if lorasValue, exists := deepintshieldReq.Params.ExtraParams["loras"]; exists && lorasValue != nil {
					delete(req.ExtraParams, "loras")
					if lorasArray, ok := lorasValue.([]interface{}); ok {
						for _, item := range lorasArray {
							if loraMap, ok := item.(map[string]interface{}); ok {
								if url, ok := schemas.SafeExtractString(loraMap["url"]); ok {
									if scale, ok := schemas.SafeExtractInt(loraMap["scale"]); ok {
										req.Loras = append(req.Loras, nebiusProvider.NebiusLora{URL: url, Scale: scale})
									}
								}
							}
						}
					}
				}
			}
		}
		return req, nil

	case hfInference:
		req := &HuggingFaceHFInferenceImageGenerationRequest{
			Inputs: deepintshieldReq.Input.Prompt,
		}
		if deepintshieldReq.Params != nil {
			req.ExtraParams = deepintshieldReq.Params.ExtraParams
		}
		return req, nil

	case falAI:
		req := &HuggingFaceFalAIImageGenerationRequest{
			Prompt: deepintshieldReq.Input.Prompt,
		}

		if deepintshieldReq.Params != nil {
			// Map n to num_images for fal-ai
			if deepintshieldReq.Params.N != nil {
				req.NumImages = deepintshieldReq.Params.N
			}

			// Pass through response_format
			if deepintshieldReq.Params.ResponseFormat != nil {
				req.ResponseFormat = deepintshieldReq.Params.ResponseFormat
			}

			// Pass through output_format
			if deepintshieldReq.Params.OutputFormat != nil {
				if strings.ToLower(*deepintshieldReq.Params.OutputFormat) == "jpg" {
					req.OutputFormat = schemas.Ptr("jpeg")
				} else {
					req.OutputFormat = deepintshieldReq.Params.OutputFormat
				}
			}

			// Convert size from "WxH" format to fal-ai's image_size object
			if deepintshieldReq.Params.Size != nil && strings.ToLower(*deepintshieldReq.Params.Size) != "auto" {
				size := strings.Split(*deepintshieldReq.Params.Size, "x")
				if len(size) == 2 {
					width, err := strconv.Atoi(size[0])
					if err == nil {
						height, err := strconv.Atoi(size[1])
						if err == nil {
							req.ImageSize = &HuggingFaceFalAISize{
								Width:  width,
								Height: height,
							}
						}
					}
				}
			}

			if deepintshieldReq.Params.ResponseFormat != nil && *deepintshieldReq.Params.ResponseFormat == "b64_json" {
				req.SyncMode = schemas.Ptr(true)
			}

			if deepintshieldReq.Params.Moderation != nil && *deepintshieldReq.Params.Moderation == "low" {
				req.EnableSafetyChecker = schemas.Ptr(false)
			}

			// Map seed from direct field
			if deepintshieldReq.Params.Seed != nil {
				req.Seed = deepintshieldReq.Params.Seed
			}

			// Map negative_prompt from direct field
			if deepintshieldReq.Params.NegativePrompt != nil {
				req.NegativePrompt = deepintshieldReq.Params.NegativePrompt
			}

			// Map num_inference_steps from direct field
			if deepintshieldReq.Params.NumInferenceSteps != nil {
				req.NumInferenceSteps = deepintshieldReq.Params.NumInferenceSteps
			}

			// Parse fal-ai specific params from ExtraParams
			if deepintshieldReq.Params.ExtraParams != nil {
				req.ExtraParams = deepintshieldReq.Params.ExtraParams
				// Map guidance_scale
				if v, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["guidance_scale"]); ok {
					delete(req.ExtraParams, "guidance_scale")
					req.GuidanceScale = v
				}

				// Map acceleration
				if v, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["acceleration"]); ok {
					delete(req.ExtraParams, "acceleration")
					req.Acceleration = v
				}

				// Map enable_prompt_expansion
				if v, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["enable_prompt_expansion"]); ok {
					delete(req.ExtraParams, "enable_prompt_expansion")
					req.EnablePromptExpansion = v
				}

				// Map enable_safety_checker
				if v, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["enable_safety_checker"]); ok {
					delete(req.ExtraParams, "enable_safety_checker")
					req.EnableSafetyChecker = v
				}
			}
		}
		return req, nil

	case together:
		req := &HuggingFaceTogetherImageGenerationRequest{
			Prompt: deepintshieldReq.Input.Prompt,
			Model:  model,
		}

		if deepintshieldReq.Params != nil {
			req.ExtraParams = deepintshieldReq.Params.ExtraParams
			if deepintshieldReq.Params.ResponseFormat != nil {
				req.ResponseFormat = deepintshieldReq.Params.ResponseFormat
			}

			if deepintshieldReq.Params.Size != nil {
				req.Size = deepintshieldReq.Params.Size
			}

			if deepintshieldReq.Params.N != nil {
				req.N = deepintshieldReq.Params.N
			}
			if deepintshieldReq.Params.ResponseFormat != nil && *deepintshieldReq.Params.ResponseFormat == "b64_json" {
				req.ResponseFormat = schemas.Ptr("base64")
			}
			if deepintshieldReq.Params.NumInferenceSteps != nil {
				req.Steps = deepintshieldReq.Params.NumInferenceSteps
			}
		}
		return req, nil

	default:
		return nil, fmt.Errorf("unsupported inference provider for image generation: %s", inferenceProvider)
	}
}

// ToHuggingFaceImageStreamRequest converts a DeepIntShield image generation request to fal-ai streaming format
func ToHuggingFaceImageStreamRequest(deepintshieldReq *schemas.DeepIntShieldImageGenerationRequest) (*HuggingFaceFalAIImageStreamRequest, error) {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil {
		return nil, fmt.Errorf("deepintshield request is nil or input is nil")
	}

	req := &HuggingFaceFalAIImageStreamRequest{
		Prompt: deepintshieldReq.Input.Prompt,
	}

	if deepintshieldReq.Params != nil {
		req.ExtraParams = deepintshieldReq.Params.ExtraParams
		// Map n to num_images for fal-ai
		if deepintshieldReq.Params.N != nil {
			req.NumImages = deepintshieldReq.Params.N
		}

		// Pass through response_format
		if deepintshieldReq.Params.ResponseFormat != nil {
			req.ResponseFormat = deepintshieldReq.Params.ResponseFormat
		}

		// Pass through output_format
		// Convert "jpg" to "jpeg" for fal-ai (fal-ai only accepts "jpeg", "png", "webp")
		if deepintshieldReq.Params.OutputFormat != nil {
			if strings.ToLower(*deepintshieldReq.Params.OutputFormat) == "jpg" {
				req.OutputFormat = schemas.Ptr("jpeg")
			} else {
				req.OutputFormat = deepintshieldReq.Params.OutputFormat
			}
		}

		// Convert size from "WxH" format to fal-ai's image_size object
		if deepintshieldReq.Params.Size != nil && strings.ToLower(*deepintshieldReq.Params.Size) != "auto" {
			size := strings.Split(*deepintshieldReq.Params.Size, "x")
			if len(size) == 2 {
				width, err := strconv.Atoi(size[0])
				if err == nil {
					height, err := strconv.Atoi(size[1])
					if err == nil {
						req.ImageSize = &HuggingFaceFalAISize{
							Width:  width,
							Height: height,
						}
					}
				}
			}
		}
		if deepintshieldReq.Params.Seed != nil {
			req.Seed = deepintshieldReq.Params.Seed
		}
		if deepintshieldReq.Params.NumInferenceSteps != nil {
			req.NumInferenceSteps = deepintshieldReq.Params.NumInferenceSteps
		}
		if deepintshieldReq.Params.ResponseFormat != nil && *deepintshieldReq.Params.ResponseFormat == "b64_json" {
			req.SyncMode = schemas.Ptr(true)
		}
		if deepintshieldReq.Params.Moderation != nil && *deepintshieldReq.Params.Moderation == "low" {
			req.EnableSafetyChecker = schemas.Ptr(false)
		}

		// Parse fal-ai specific params from ExtraParams
		if deepintshieldReq.Params.ExtraParams != nil {
			if v, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["guidance_scale"]); ok {
				delete(req.ExtraParams, "guidance_scale")
				req.GuidanceScale = v
			}
			if v, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["acceleration"]); ok {
				delete(req.ExtraParams, "acceleration")
				req.Acceleration = v
			}
			if v, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["enable_prompt_expansion"]); ok {
				delete(req.ExtraParams, "enable_prompt_expansion")
				req.EnablePromptExpansion = v
			}
			if v, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["enable_safety_checker"]); ok {
				delete(req.ExtraParams, "enable_safety_checker")
				req.EnableSafetyChecker = v
			}
		}
	}

	return req, nil
}

// UnmarshalHuggingFaceImageGenerationResponse unmarshals HuggingFace image generation response to DeepIntShield format
func UnmarshalHuggingFaceImageGenerationResponse(data []byte, model string) (*schemas.DeepIntShieldImageGenerationResponse, error) {
	if data == nil {
		return nil, fmt.Errorf("response data is nil")
	}
	inferenceProvider, _, err := splitIntoModelProvider(model)
	if err != nil {
		return nil, err
	}

	switch inferenceProvider {
	case nebius:
		// Unmarshal into Nebius response format
		var nebiusResponse nebiusProvider.NebiusImageGenerationResponse
		if err := sonic.Unmarshal(data, &nebiusResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Nebius response: %w", err)
		}

		// Convert to DeepIntShield format using Nebius converter
		deepintshieldResponse := nebiusProvider.ToDeepIntShieldImageResponse(&nebiusResponse)
		if deepintshieldResponse == nil {
			return nil, fmt.Errorf("failed to convert Nebius response to DeepIntShield format")
		}

		// Set model field (Nebius converter doesn't set it, similar to embeddings pattern)
		if deepintshieldResponse.Model == "" {
			deepintshieldResponse.Model = model
		}

		return deepintshieldResponse, nil

	case hfInference:
		// Handle raw byte data - encode to base64
		b64Data := base64.StdEncoding.EncodeToString(data)
		return &schemas.DeepIntShieldImageGenerationResponse{
			Model: model,
			Data: []schemas.ImageData{
				{
					B64JSON: b64Data,
					Index:   0,
				},
			},
		}, nil

	case falAI:
		// Handle fal-ai JSON response
		var falResponse HuggingFaceFalAIImageGenerationResponse
		if err := sonic.Unmarshal(data, &falResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal fal-ai response: %w", err)
		}

		imageData := make([]schemas.ImageData, len(falResponse.Images))
		for i, img := range falResponse.Images {
			// Handle both URL and base64 responses
			imageData[i] = schemas.ImageData{
				URL:     img.URL,
				B64JSON: img.B64JSON,
				Index:   i,
			}
		}

		return &schemas.DeepIntShieldImageGenerationResponse{
			Model: model,
			Data:  imageData,
		}, nil

	case together:
		// Handle together JSON response
		var togetherResponse HuggingFaceTogetherImageGenerationResponse
		if err := sonic.Unmarshal(data, &togetherResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal together response: %w", err)
		}

		imageData := make([]schemas.ImageData, len(togetherResponse.Data))
		for i, img := range togetherResponse.Data {
			imageData[i] = schemas.ImageData{
				B64JSON: img.B64JSON,
				URL:     img.URL,
				Index:   i,
			}
		}

		return &schemas.DeepIntShieldImageGenerationResponse{
			Model: model,
			Data:  imageData,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported inference provider: %s", inferenceProvider)
	}
}

// imageBytesToBase64DataURL converts raw image bytes to base64 data URL format
func imageBytesToBase64DataURL(imageBytes []byte) string {
	mimeType := http.DetectContentType(imageBytes)
	b64Data := base64.StdEncoding.EncodeToString(imageBytes)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, b64Data)
}

// mapFalAIImageEditParams maps common parameters from DeepIntShield request to fal-ai request
func mapFalAIImageEditParams(deepintshieldReq *schemas.DeepIntShieldImageEditRequest, req *HuggingFaceFalAIImageEditRequest) {
	if deepintshieldReq.Params == nil {
		return
	}

	// Map n to num_images for fal-ai
	if deepintshieldReq.Params.N != nil {
		req.NumImages = deepintshieldReq.Params.N
	}

	// Pass through output_format
	if deepintshieldReq.Params.OutputFormat != nil {
		if strings.ToLower(*deepintshieldReq.Params.OutputFormat) == "jpg" {
			req.OutputFormat = schemas.Ptr("jpeg")
		} else {
			req.OutputFormat = deepintshieldReq.Params.OutputFormat
		}
	}

	if deepintshieldReq.Params.ResponseFormat != nil && *deepintshieldReq.Params.ResponseFormat == "b64_json" {
		req.SyncMode = schemas.Ptr(true)
	}

	// Convert size from "WxH" format to fal-ai's image_size object
	if deepintshieldReq.Params.Size != nil && strings.ToLower(*deepintshieldReq.Params.Size) != "auto" {
		size := strings.Split(*deepintshieldReq.Params.Size, "x")
		if len(size) == 2 {
			width, err := strconv.Atoi(size[0])
			if err == nil {
				height, err := strconv.Atoi(size[1])
				if err == nil {
					req.ImageSize = &HuggingFaceFalAISize{
						Width:  width,
						Height: height,
					}
				}
			}
		}
	}

	// Pass-through num_inference_steps
	if deepintshieldReq.Params.NumInferenceSteps != nil {
		req.NumInferenceSteps = deepintshieldReq.Params.NumInferenceSteps
	}

	// Pass-through seed
	if deepintshieldReq.Params.Seed != nil {
		req.Seed = deepintshieldReq.Params.Seed
	}

	// Parse fal-ai specific params from ExtraParams
	if deepintshieldReq.Params.ExtraParams != nil {
		// Map guidance_scale
		if v, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["guidance_scale"]); ok {
			delete(req.ExtraParams, "guidance_scale")
			req.GuidanceScale = v
		}

		// Map acceleration
		if v, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["acceleration"]); ok {
			delete(req.ExtraParams, "acceleration")
			req.Acceleration = v
		}

		// Map enable_safety_checker
		if v, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["enable_safety_checker"]); ok {
			delete(req.ExtraParams, "enable_safety_checker")
			req.EnableSafetyChecker = v
		}
	}
}

// ToHuggingFaceImageEditRequest converts a DeepIntShield image edit request to fal-ai format
func ToHuggingFaceImageEditRequest(deepintshieldReq *schemas.DeepIntShieldImageEditRequest) (*HuggingFaceFalAIImageEditRequest, error) {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil {
		return nil, fmt.Errorf("deepintshield request is nil or input is nil")
	}

	if len(deepintshieldReq.Input.Images) == 0 {
		return nil, fmt.Errorf("at least one image is required")
	}

	// Convert images to base64 data URLs
	imageURLs := make([]string, 0, len(deepintshieldReq.Input.Images))
	for _, img := range deepintshieldReq.Input.Images {
		if len(img.Image) == 0 {
			continue
		}
		imageURLs = append(imageURLs, imageBytesToBase64DataURL(img.Image))
	}

	if len(imageURLs) == 0 {
		return nil, fmt.Errorf("no valid images found")
	}

	// Extract model name to determine image field strategy
	_, modelName, err := splitIntoModelProvider(deepintshieldReq.Model)
	if err != nil {
		return nil, fmt.Errorf("failed to split model name: %w", err)
	}

	req := &HuggingFaceFalAIImageEditRequest{
		Prompt: deepintshieldReq.Input.Prompt,
	}

	// Check for explicit override in ExtraParams
	var useMultiImage *bool
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.ExtraParams != nil {
		req.ExtraParams = deepintshieldReq.Params.ExtraParams
		if v, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["use_image_urls"]); ok {
			delete(req.ExtraParams, "use_image_urls")
			useMultiImage = v
		}
	}

	// Determine which image field to use based on model capabilities
	if useMultiImage != nil {
		// Explicit override from user
		if *useMultiImage {
			req.ImageURLs = imageURLs
		} else if len(imageURLs) == 1 {
			req.ImageURL = &imageURLs[0]
		} else {
			return nil, fmt.Errorf("use_image_urls is false but multiple images provided (%d images)", len(imageURLs))
		}
	} else if falAIMultiImageEditModels[modelName] {
		// Model supports multiple images - always use image_urls
		req.ImageURLs = imageURLs
	} else if falAISingleImageEditModels[modelName] {
		// Model only supports single image - validate and use image_url
		if len(imageURLs) == 1 {
			req.ImageURL = &imageURLs[0]
		} else {
			return nil, fmt.Errorf("model %s only supports single image, got %d images", modelName, len(imageURLs))
		}
	} else {
		// Unknown model - fallback to count-based logic
		if len(imageURLs) == 1 {
			req.ImageURL = &imageURLs[0]
		} else {
			req.ImageURLs = imageURLs
		}
	}

	// Map common parameters
	mapFalAIImageEditParams(deepintshieldReq, req)
	return req, nil
}

// extractImagesFromStreamResponse extracts images from a fal-ai streaming response.
// Handles both API envelope structure (Data.Images) and legacy flattened format (top-level Images).
func extractImagesFromStreamResponse(response *HuggingFaceFalAIImageStreamResponse) []FalAIImage {
	// Prefer Data.Images if available (API envelope structure)
	if response.Data != nil && len(response.Data.Images) > 0 {
		return response.Data.Images
	}
	// Fall back to top-level Images (legacy format)
	return response.Images
}
