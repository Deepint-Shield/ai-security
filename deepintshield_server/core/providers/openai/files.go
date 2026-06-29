package openai

import (
	"bytes"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/schemas"
)

// OpenAI File API Types

// OpenAIFileResponse represents an OpenAI file response.
type OpenAIFileResponse struct {
	ID            string              `json:"id"`
	Object        string              `json:"object"`
	Bytes         int64               `json:"bytes"`
	CreatedAt     int64               `json:"created_at"`
	Filename      string              `json:"filename"`
	Purpose       schemas.FilePurpose `json:"purpose"`
	Status        string              `json:"status,omitempty"`
	StatusDetails *string             `json:"status_details,omitempty"`
}

// OpenAIFileListResponse represents the response from listing files.
type OpenAIFileListResponse struct {
	Object  string               `json:"object"`
	Data    []OpenAIFileResponse `json:"data"`
	HasMore bool                 `json:"has_more,omitempty"`
}

// OpenAIFileDeleteResponse represents the response from deleting a file.
type OpenAIFileDeleteResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Deleted bool   `json:"deleted"`
}

// ToDeepIntShieldFileStatus converts OpenAI status to DeepIntShield status.
func ToDeepIntShieldFileStatus(status string) schemas.FileStatus {
	switch status {
	case "uploaded":
		return schemas.FileStatusUploaded
	case "processed", "completed":
		return schemas.FileStatusProcessed
	case "processing", "in_progress":
		return schemas.FileStatusProcessing
	case "error", "failed":
		return schemas.FileStatusError
	case "deleted", "cancelled":
		return schemas.FileStatusDeleted
	default:
		return schemas.FileStatus(status)
	}
}

// ToDeepIntShieldFileUploadResponse converts OpenAI file response to DeepIntShield file upload response.
func (r *OpenAIFileResponse) ToDeepIntShieldFileUploadResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldFileUploadResponse {
	resp := &schemas.DeepIntShieldFileUploadResponse{
		ID:             r.ID,
		Object:         r.Object,
		Bytes:          r.Bytes,
		CreatedAt:      r.CreatedAt,
		Filename:       r.Filename,
		Purpose:        r.Purpose,
		Status:         ToDeepIntShieldFileStatus(r.Status),
		StatusDetails:  r.StatusDetails,
		StorageBackend: schemas.FileStorageAPI,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.FileUploadRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}

	return resp
}

// ToDeepIntShieldFileRetrieveResponse converts OpenAI file response to DeepIntShield file retrieve response.
func (r *OpenAIFileResponse) ToDeepIntShieldFileRetrieveResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldFileRetrieveResponse {
	resp := &schemas.DeepIntShieldFileRetrieveResponse{
		ID:             r.ID,
		Object:         r.Object,
		Bytes:          r.Bytes,
		CreatedAt:      r.CreatedAt,
		Filename:       r.Filename,
		Purpose:        r.Purpose,
		Status:         ToDeepIntShieldFileStatus(r.Status),
		StatusDetails:  r.StatusDetails,
		StorageBackend: schemas.FileStorageAPI,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.FileRetrieveRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}
	return resp
}

// ConvertRequestsToJSONL converts batch request items to JSONL format.
func ConvertRequestsToJSONL(requests []schemas.BatchRequestItem) ([]byte, error) {
	var buf bytes.Buffer
	for _, req := range requests {
		line, err := sonic.Marshal(req)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}
