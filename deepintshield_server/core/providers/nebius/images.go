package nebius

import (
	"fmt"
	"strconv"
	"strings"

	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

// ToNebiusImageGenerationRequest converts a deepintshield image generation request to nebius format.
func (provider *NebiusProvider) ToNebiusImageGenerationRequest(deepintshieldReq *schemas.DeepIntShieldImageGenerationRequest) (*NebiusImageGenerationRequest, error) {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil {
		return nil, fmt.Errorf("deepintshield request is nil or input is nil")
	}

	req := &NebiusImageGenerationRequest{
		Model:  &deepintshieldReq.Model,
		Prompt: &deepintshieldReq.Input.Prompt,
	}

	if deepintshieldReq.Params != nil {

		if deepintshieldReq.Params.ResponseFormat != nil {
			req.ResponseFormat = deepintshieldReq.Params.ResponseFormat
		}

		if deepintshieldReq.Params.Size != nil && strings.TrimSpace(strings.ToLower(*deepintshieldReq.Params.Size)) != "auto" {
			size := strings.Split(strings.TrimSpace(strings.ToLower(*deepintshieldReq.Params.Size)), "x")
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
		if req.ResponseExtension != nil && strings.ToLower(*req.ResponseExtension) == "jpeg" {
			req.ResponseExtension = schemas.Ptr("jpg")
		}
		if deepintshieldReq.Params.Seed != nil {
			req.Seed = deepintshieldReq.Params.Seed
		}
		if deepintshieldReq.Params.NegativePrompt != nil {
			req.NegativePrompt = deepintshieldReq.Params.NegativePrompt
		}
		if deepintshieldReq.Params.NumInferenceSteps != nil {
			req.NumInferenceSteps = deepintshieldReq.Params.NumInferenceSteps
		}
		// Handle extra params
		if deepintshieldReq.Params.ExtraParams != nil {
			req.ExtraParams = deepintshieldReq.Params.ExtraParams
			// Map guidance_scale
			if v, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["guidance_scale"]); ok {
				delete(req.ExtraParams, "guidance_scale")
				req.GuidanceScale = v
			}

			// Map loras in array format [{"url": "...", "scale": ...}]
			if lorasValue, exists := deepintshieldReq.Params.ExtraParams["loras"]; exists && lorasValue != nil {
				delete(req.ExtraParams, "loras")
				// Check if lorasValue is an array of maps
				if lorasArray, ok := lorasValue.([]interface{}); ok {
					for _, item := range lorasArray {
						if loraMap, ok := item.(map[string]interface{}); ok {
							if url, ok := schemas.SafeExtractString(loraMap["url"]); ok {
								if scale, ok := schemas.SafeExtractInt(loraMap["scale"]); ok {
									req.Loras = append(req.Loras, NebiusLora{URL: url, Scale: scale})
								}
							}
						}
					}
				}
			}
		}
	}
	return req, nil
}

// ToDeepIntShieldImageResponse converts a nebius image generation response to deepintshield format.
func ToDeepIntShieldImageResponse(nebiusResponse *NebiusImageGenerationResponse) *schemas.DeepIntShieldImageGenerationResponse {
	if nebiusResponse == nil {
		return nil
	}

	data := make([]schemas.ImageData, len(nebiusResponse.Data))
	for i, img := range nebiusResponse.Data {
		data[i] = schemas.ImageData{
			URL:           img.URL,
			B64JSON:       img.B64JSON,
			RevisedPrompt: img.RevisedPrompt,
			Index:         i,
		}
	}
	return &schemas.DeepIntShieldImageGenerationResponse{
		ID:   nebiusResponse.Id,
		Data: data,
	}
}
