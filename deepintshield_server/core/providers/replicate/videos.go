package replicate

import (
	"fmt"
	"strconv"
	"strings"

	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

func ToReplicateVideoGenerationInput(deepintshieldReq *schemas.DeepIntShieldVideoGenerationRequest) (*ReplicatePredictionRequest, error) {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil {
		return nil, fmt.Errorf("deepintshield request or input is nil")
	}

	input := &ReplicatePredictionRequestInput{
		Prompt: &deepintshieldReq.Input.Prompt,
	}

	if deepintshieldReq.Input.InputReference != nil {
		// convert input reference to base64
		// if provider is openai, set input reference to base64
		sanitizedURL, err := schemas.SanitizeImageURL(*deepintshieldReq.Input.InputReference)
		if err != nil {
			return nil, fmt.Errorf("invalid input reference: %w", err)
		}
		if strings.HasPrefix(deepintshieldReq.Model, string(schemas.OpenAI)) {
			input.InputReference = schemas.Ptr(sanitizedURL)
		} else {
			input.Image = schemas.Ptr(sanitizedURL)
		}
	}

	// Map parameters if available
	if deepintshieldReq.Params != nil {
		params := deepintshieldReq.Params

		if params.Seconds != nil {
			seconds, err := strconv.Atoi(*params.Seconds)
			if err != nil {
				return nil, fmt.Errorf("invalid seconds value: %w", err)
			}
			input.Duration = &seconds
		}

		if params.Seed != nil {
			input.Seed = params.Seed
		}

		if params.NegativePrompt != nil {
			input.NegativePrompt = params.NegativePrompt
		}

		if params.ExtraParams != nil {
			input.ExtraParams = params.ExtraParams
		}
	}

	request := &ReplicatePredictionRequest{
		Input: input,
	}

	// Check if model is a version ID and set version field accordingly
	if isVersionID(deepintshieldReq.Model) {
		request.Version = &deepintshieldReq.Model
	}

	if deepintshieldReq.Params != nil && deepintshieldReq.Params.ExtraParams != nil {
		request.ExtraParams = deepintshieldReq.Params.ExtraParams
		if webhook, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["webhook"]); ok {
			delete(request.ExtraParams, "webhook")
			request.Webhook = webhook
		}
		if webhookEventsFilter, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["webhook_events_filter"]); ok {
			delete(request.ExtraParams, "webhook_events_filter")
			request.WebhookEventsFilter = webhookEventsFilter
		}
	}

	return request, nil
}

func ToDeepIntShieldVideoGenerationResponse(prediction *ReplicatePredictionResponse) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if prediction == nil {
		return nil, &schemas.DeepIntShieldError{
			IsDeepIntShieldError: true,
			Error: &schemas.ErrorField{
				Message: "prediction response is nil",
			},
			ExtraFields: schemas.DeepIntShieldErrorExtraFields{
				Provider: schemas.Replicate,
			},
		}
	}

	response := &schemas.DeepIntShieldVideoGenerationResponse{
		ID:        prediction.ID,
		CreatedAt: ParseReplicateTimestamp(prediction.CreatedAt),
		Model:     prediction.Model,
		Object:    "video",
	}

	// Map Replicate status to DeepIntShield video status.
	switch prediction.Status {
	case ReplicatePredictionStatusStarting:
		response.Status = schemas.VideoStatusQueued
	case ReplicatePredictionStatusProcessing:
		response.Status = schemas.VideoStatusInProgress
	case ReplicatePredictionStatusSucceeded:
		response.Status = schemas.VideoStatusCompleted
	case ReplicatePredictionStatusFailed, ReplicatePredictionStatusCanceled:
		response.Status = schemas.VideoStatusFailed
	default:
		response.Status = schemas.VideoStatusQueued
	}

	// Surface provider error details on failed terminal states.
	if response.Status == schemas.VideoStatusFailed {
		errorMsg := "prediction failed"
		errorCode := string(prediction.Status)
		if prediction.Error != nil && *prediction.Error != "" {
			errorMsg = *prediction.Error
		}
		response.Error = &schemas.VideoCreateError{
			Code:    errorCode,
			Message: errorMsg,
		}
	}

	if prediction.CompletedAt != nil {
		response.CompletedAt = schemas.Ptr(ParseReplicateTimestamp(*prediction.CompletedAt))
	}

	// Convert output to ImageData
	// Replicate output can be either a string (single URL) or array of strings
	if prediction.Output != nil {
		if prediction.Output.OutputStr != nil && *prediction.Output.OutputStr != "" {
			response.Videos = append(response.Videos, schemas.VideoOutput{
				Type:        schemas.VideoOutputTypeURL,
				URL:         schemas.Ptr(*prediction.Output.OutputStr),
				ContentType: "video/mp4",
			})
		} else if len(prediction.Output.OutputArray) > 0 {
			for _, url := range prediction.Output.OutputArray {
				response.Videos = append(response.Videos, schemas.VideoOutput{
					Type:        schemas.VideoOutputTypeURL,
					URL:         schemas.Ptr(url),
					ContentType: "video/mp4",
				})
			}
		}
	}

	return response, nil
}
