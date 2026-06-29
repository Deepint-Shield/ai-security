package replicate

import (
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// Replicate File API Converters

// ToDeepIntShieldFileStatus converts Replicate file status to DeepIntShield file status.
// Replicate doesn't explicitly provide status, so we infer from the response.
func ToDeepIntShieldFileStatus(fileResp *ReplicateFileResponse) schemas.FileStatus {
	// If file has all required fields and is accessible, it's processed
	if fileResp.ID != "" && fileResp.Size > 0 {
		return schemas.FileStatusProcessed
	}
	return schemas.FileStatusUploaded
}

// ToDeepIntShieldFileUploadResponse converts Replicate file response to DeepIntShield file upload response.
func (r *ReplicateFileResponse) ToDeepIntShieldFileUploadResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldFileUploadResponse {
	resp := &schemas.DeepIntShieldFileUploadResponse{
		ID:             r.ID,
		Object:         "file",
		Bytes:          r.Size,
		CreatedAt:      ParseReplicateTimestamp(r.CreatedAt),
		Filename:       r.Name,
		Purpose:        schemas.FilePurposeBatch, // Replicate uses files primarily for batch/general purposes
		Status:         ToDeepIntShieldFileStatus(r),
		StorageBackend: schemas.FileStorageAPI,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.FileUploadRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	// Add ExpiresAt if present
	if r.ExpiresAt != "" {
		expiresAt := ParseReplicateTimestamp(r.ExpiresAt)
		if expiresAt > 0 {
			resp.ExpiresAt = &expiresAt
		}
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}

	return resp
}

// ToDeepIntShieldFileRetrieveResponse converts Replicate file response to DeepIntShield file retrieve response.
func (r *ReplicateFileResponse) ToDeepIntShieldFileRetrieveResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldFileRetrieveResponse {
	resp := &schemas.DeepIntShieldFileRetrieveResponse{
		ID:             r.ID,
		Object:         "file",
		Bytes:          r.Size,
		CreatedAt:      ParseReplicateTimestamp(r.CreatedAt),
		Filename:       r.Name,
		Purpose:        schemas.FilePurposeBatch,
		Status:         ToDeepIntShieldFileStatus(r),
		StorageBackend: schemas.FileStorageAPI,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.FileRetrieveRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	// Add ExpiresAt if present
	if r.ExpiresAt != "" {
		expiresAt := ParseReplicateTimestamp(r.ExpiresAt)
		if expiresAt > 0 {
			resp.ExpiresAt = &expiresAt
		}
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}

	return resp
}
