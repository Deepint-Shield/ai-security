package runway

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	schemas "github.com/deepint-shield/ai-security/core/schemas"
)

func ToRunwayVideoGenerationRequest(deepintshieldReq *schemas.DeepIntShieldVideoGenerationRequest) (*RunwayVideoGenerationRequest, error) {
	// three types of video generation requests in runway api
	// 1. image to video
	// 2. text to video
	// 3. video to video
	if deepintshieldReq.Input == nil {
		return nil, fmt.Errorf("input is required")
	}

	request := &RunwayVideoGenerationRequest{
		Model: deepintshieldReq.Model,
		Ratio: schemas.Ptr("1280:720"),
	}

	if isRunwayVeoModel(deepintshieldReq.Model) {
		request.Duration = schemas.Ptr(4)
	} else if isRunwayGenModel(deepintshieldReq.Model) {
		request.Duration = schemas.Ptr(2)
	}

	if deepintshieldReq.Input.Prompt != "" {
		request.PromptText = &deepintshieldReq.Input.Prompt
	}
	if deepintshieldReq.Input.InputReference != nil {
		sanitizedURL, err := schemas.SanitizeImageURL(*deepintshieldReq.Input.InputReference)
		if err != nil {
			return nil, fmt.Errorf("invalid input reference: %w", err)
		}
		request.PromptImage = &PromptImage{
			PromptImageStr: schemas.Ptr(sanitizedURL),
		}
	}

	if deepintshieldReq.Params != nil {
		if deepintshieldReq.Params.Seconds != nil {
			seconds, err := strconv.Atoi(*deepintshieldReq.Params.Seconds)
			if err != nil {
				return nil, fmt.Errorf("invalid seconds value: %w", err)
			}
			request.Duration = &seconds
		}

		if deepintshieldReq.Params.Size != "" {
			// convert 1280x720 to 1280:720
			request.Ratio = schemas.Ptr(strings.Replace(deepintshieldReq.Params.Size, "x", ":", 1))
		}

		if isRunwayVeoModel(deepintshieldReq.Model) {
			if deepintshieldReq.Params.Audio != nil {
				request.Audio = deepintshieldReq.Params.Audio
			}
		}

		if isRunwayGenModel(deepintshieldReq.Model) {
			if deepintshieldReq.Params.Seed != nil {
				request.Seed = deepintshieldReq.Params.Seed
			}
		}

		if deepintshieldReq.Params.VideoURI != nil {
			if !supportsVideoToVideo(deepintshieldReq.Model) {
				return nil, fmt.Errorf("video_uri is not supported for model %s", deepintshieldReq.Model)
			}
			request.VideoURI = deepintshieldReq.Params.VideoURI
		}

		if deepintshieldReq.Params.ExtraParams != nil {
			request.ExtraParams = deepintshieldReq.Params.ExtraParams
			// Handle references for video-to-video generation
			if refsVal := deepintshieldReq.Params.ExtraParams["references"]; refsVal != nil {
				if refs, ok := refsVal.([]Reference); ok && refs != nil {
					request.References = refs
					delete(request.ExtraParams, "references")
				} else if data, err := sonic.Marshal(refsVal); err == nil {
					var refs []Reference
					if sonic.Unmarshal(data, &refs) == nil {
						request.References = refs
						delete(request.ExtraParams, "references")
					}
				}
			}

			// Handle reference images for video generation
			if refImagesVal := deepintshieldReq.Params.ExtraParams["reference_images"]; refImagesVal != nil {
				if refImages, ok := refImagesVal.([]ReferenceImage); ok && refImages != nil {
					delete(request.ExtraParams, "reference_images")
					request.ReferenceImages = refImages
				} else if data, err := sonic.Marshal(refImagesVal); err == nil {
					var refImages []ReferenceImage
					if sonic.Unmarshal(data, &refImages) == nil {
						delete(request.ExtraParams, "reference_images")
						request.ReferenceImages = refImages
					}
				}
			}

			// add content moderation
			if isRunwayVeoModel(deepintshieldReq.Model) {
				if cmVal := deepintshieldReq.Params.ExtraParams["content_moderation"]; cmVal != nil {
					if cm, ok := cmVal.(*ContentModeration); ok && cm != nil {
						delete(request.ExtraParams, "content_moderation")
						request.ContentModeration = cm
					} else if data, err := sonic.Marshal(cmVal); err == nil {
						var cm ContentModeration
						if sonic.Unmarshal(data, &cm) == nil {
							delete(request.ExtraParams, "content_moderation")
							request.ContentModeration = &cm
						}
					}
				}
			}
		}
	}

	return request, nil
}

// ToDeepIntShieldVideoGenerationResponse converts Runway task details to DeepIntShield video generation response format.
func ToDeepIntShieldVideoGenerationResponse(taskDetails *RunwayTaskDetailsResponse) (*schemas.DeepIntShieldVideoGenerationResponse, *schemas.DeepIntShieldError) {
	if taskDetails == nil {
		return nil, providerUtils.NewDeepIntShieldOperationError("task details is nil", nil, schemas.Runway)
	}

	response := &schemas.DeepIntShieldVideoGenerationResponse{
		ID:        taskDetails.ID,
		Object:    "video",
		CreatedAt: time.Now().Unix(),
	}

	// Map Runway task status to DeepIntShield video status
	switch taskDetails.Status {
	case RunwayTaskStatusPending, RunwayTaskStatusThrottled:
		response.Status = schemas.VideoStatusQueued
	case RunwayTaskStatusRunning:
		response.Status = schemas.VideoStatusInProgress
	case RunwayTaskStatusSucceeded:
		response.Status = schemas.VideoStatusCompleted
	case RunwayTaskStatusFailed, RunwayTaskStatusCancelled:
		response.Status = schemas.VideoStatusFailed
		// Set error message for failed tasks
		errorMsg := fmt.Sprintf("Task %s", taskDetails.Status)
		response.Error = &schemas.VideoCreateError{
			Code:    string(taskDetails.Status),
			Message: errorMsg,
		}
	default:
		response.Status = schemas.VideoStatusQueued
	}

	if len(taskDetails.Output) > 0 {
		response.Videos = make([]schemas.VideoOutput, len(taskDetails.Output))
		for i, url := range taskDetails.Output {
			response.Videos[i] = schemas.VideoOutput{
				Type:        schemas.VideoOutputTypeURL,
				URL:         schemas.Ptr(url),
				ContentType: "video/mp4",
			}
		}
	}

	// Parse created_at timestamp if available
	if taskDetails.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, taskDetails.CreatedAt); err == nil {
			response.CreatedAt = t.Unix()
		}
	}

	return response, nil
}
