package openai

import (
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// OpenAI Batch API Types

// OpenAIBatchRequest represents the request body for creating a batch.
type OpenAIBatchRequest struct {
	InputFileID        string                    `json:"input_file_id"`
	Endpoint           string                    `json:"endpoint"`
	CompletionWindow   string                    `json:"completion_window"`
	Metadata           map[string]string         `json:"metadata,omitempty"`
	OutputExpiresAfter *schemas.BatchExpiresAfter `json:"output_expires_after,omitempty"`
}

// OpenAIBatchResponse represents an OpenAI batch response.
type OpenAIBatchResponse struct {
	ID               string                    `json:"id"`
	Object           string                    `json:"object"`
	Endpoint         string                    `json:"endpoint"`
	Errors           *schemas.BatchErrors      `json:"errors,omitempty"`
	InputFileID      string                    `json:"input_file_id"`
	CompletionWindow string                    `json:"completion_window"`
	Status           string                    `json:"status"`
	OutputFileID     *string                   `json:"output_file_id,omitempty"`
	ErrorFileID      *string                   `json:"error_file_id,omitempty"`
	CreatedAt        int64                     `json:"created_at"`
	InProgressAt     *int64                    `json:"in_progress_at,omitempty"`
	ExpiresAt        *int64                    `json:"expires_at,omitempty"`
	FinalizingAt     *int64                    `json:"finalizing_at,omitempty"`
	CompletedAt      *int64                    `json:"completed_at,omitempty"`
	FailedAt         *int64                    `json:"failed_at,omitempty"`
	ExpiredAt        *int64                    `json:"expired_at,omitempty"`
	CancellingAt     *int64                    `json:"cancelling_at,omitempty"`
	CancelledAt      *int64                    `json:"cancelled_at,omitempty"`
	RequestCounts    *OpenAIBatchRequestCounts `json:"request_counts,omitempty"`
	Metadata         map[string]string         `json:"metadata,omitempty"`
}

// OpenAIBatchRequestCounts represents the request counts for a batch.
type OpenAIBatchRequestCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// OpenAIBatchListResponse represents the response from listing batches.
type OpenAIBatchListResponse struct {
	Object  string                `json:"object"`
	Data    []OpenAIBatchResponse `json:"data"`
	FirstID *string               `json:"first_id,omitempty"`
	LastID  *string               `json:"last_id,omitempty"`
	HasMore bool                  `json:"has_more"`
}

// ToDeepIntShieldBatchStatus converts OpenAI status to DeepIntShield status.
func ToDeepIntShieldBatchStatus(status string) schemas.BatchStatus {
	switch status {
	case "validating":
		return schemas.BatchStatusValidating
	case "failed":
		return schemas.BatchStatusFailed
	case "in_progress":
		return schemas.BatchStatusInProgress
	case "finalizing":
		return schemas.BatchStatusFinalizing
	case "completed":
		return schemas.BatchStatusCompleted
	case "expired":
		return schemas.BatchStatusExpired
	case "cancelling":
		return schemas.BatchStatusCancelling
	case "cancelled":
		return schemas.BatchStatusCancelled
	default:
		return schemas.BatchStatus(status)
	}
}

// ToDeepIntShieldBatchCreateResponse converts OpenAI batch response to DeepIntShield batch response.
func (r *OpenAIBatchResponse) ToDeepIntShieldBatchCreateResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldBatchCreateResponse {
	resp := &schemas.DeepIntShieldBatchCreateResponse{
		ID:               r.ID,
		Object:           r.Object,
		Endpoint:         r.Endpoint,
		InputFileID:      r.InputFileID,
		CompletionWindow: r.CompletionWindow,
		Status:           ToDeepIntShieldBatchStatus(r.Status),
		Metadata:         r.Metadata,
		CreatedAt:        r.CreatedAt,
		OutputFileID:     r.OutputFileID,
		ErrorFileID:      r.ErrorFileID,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.BatchCreateRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	if r.ExpiresAt != nil {
		resp.ExpiresAt = r.ExpiresAt
	}

	if r.RequestCounts != nil {
		resp.RequestCounts = schemas.BatchRequestCounts{
			Total:     r.RequestCounts.Total,
			Completed: r.RequestCounts.Completed,
			Failed:    r.RequestCounts.Failed,
		}
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}

	return resp
}

// ToDeepIntShieldBatchRetrieveResponse converts OpenAI batch response to DeepIntShield batch retrieve response.
func (r *OpenAIBatchResponse) ToDeepIntShieldBatchRetrieveResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldBatchRetrieveResponse {
	resp := &schemas.DeepIntShieldBatchRetrieveResponse{
		ID:               r.ID,
		Object:           r.Object,
		Endpoint:         r.Endpoint,
		InputFileID:      r.InputFileID,
		CompletionWindow: r.CompletionWindow,
		Status:           ToDeepIntShieldBatchStatus(r.Status),
		Metadata:         r.Metadata,
		CreatedAt:        r.CreatedAt,
		InProgressAt:     r.InProgressAt,
		FinalizingAt:     r.FinalizingAt,
		CompletedAt:      r.CompletedAt,
		FailedAt:         r.FailedAt,
		ExpiredAt:        r.ExpiredAt,
		CancellingAt:     r.CancellingAt,
		CancelledAt:      r.CancelledAt,
		OutputFileID:     r.OutputFileID,
		ErrorFileID:      r.ErrorFileID,
		Errors:           r.Errors,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.BatchRetrieveRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	if r.ExpiresAt != nil {
		resp.ExpiresAt = r.ExpiresAt
	}

	if r.RequestCounts != nil {
		resp.RequestCounts = schemas.BatchRequestCounts{
			Total:     r.RequestCounts.Total,
			Completed: r.RequestCounts.Completed,
			Failed:    r.RequestCounts.Failed,
		}
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}

	return resp
}

// splitJSONL splits JSONL content into individual lines.
func splitJSONL(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				end := i
				// Strip trailing \r if present (handle CRLF)
				if end > start && data[end-1] == '\r' {
					end--
				}
				if end > start {
					lines = append(lines, data[start:end])
				}
			}
			start = i + 1
		}
	}
	if start < len(data) {
		end := len(data)
		// Strip trailing \r if present
		if end > start && data[end-1] == '\r' {
			end--
		}
		if end > start {
			lines = append(lines, data[start:end])
		}
	}
	return lines
}
