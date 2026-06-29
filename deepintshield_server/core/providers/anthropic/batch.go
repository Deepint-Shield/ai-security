package anthropic

import (
	"time"

	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/valyala/fasthttp"
)

// Anthropic Batch API Types

// AnthropicBatchRequestItem represents a single request in a batch.
type AnthropicBatchRequestItem struct {
	CustomID string         `json:"custom_id"`
	Params   map[string]any `json:"params"`
}

// AnthropicBatchCreateRequest represents the request body for creating a batch.
type AnthropicBatchCreateRequest struct {
	Requests []AnthropicBatchRequestItem `json:"requests"`
}

// AnthropicBatchCancelRequest represents the request body for canceling a batch.
type AnthropicBatchCancelRequest struct {
	BatchID string `json:"batch_id"`
}

// AnthropicBatchRetrieveRequest represents the request body for retrieving a batch.
type AnthropicBatchRetrieveRequest struct {
	BatchID string `json:"batch_id"`
}

// AnthropicBatchListRequest represents the request body for listing batches.
type AnthropicBatchListRequest struct {
	PageToken *string `json:"page_token"`
	PageSize  int     `json:"page_size"`
}

// AnthropicBatchResultsRequest represents the request body for retrieving batch results.
type AnthropicBatchResultsRequest struct {
	BatchID string `json:"batch_id"`
}

// AnthropicBatchResponse represents an Anthropic batch response.
type AnthropicBatchResponse struct {
	ID                string                       `json:"id"`
	Type              string                       `json:"type"`
	ProcessingStatus  string                       `json:"processing_status"`
	RequestCounts     *AnthropicBatchRequestCounts `json:"request_counts,omitempty"`
	EndedAt           *string                      `json:"ended_at,omitempty"`
	CreatedAt         string                       `json:"created_at"`
	ExpiresAt         string                       `json:"expires_at"`
	ArchivedAt        *string                      `json:"archived_at,omitempty"`
	CancelInitiatedAt *string                      `json:"cancel_initiated_at,omitempty"`
	ResultsURL        *string                      `json:"results_url,omitempty"`
}

// AnthropicBatchRequestCounts represents the request counts for a batch.
type AnthropicBatchRequestCounts struct {
	Processing int `json:"processing"`
	Succeeded  int `json:"succeeded"`
	Errored    int `json:"errored"`
	Canceled   int `json:"canceled"`
	Expired    int `json:"expired"`
}

// AnthropicBatchListResponse represents the response from listing batches.
type AnthropicBatchListResponse struct {
	Data    []AnthropicBatchResponse `json:"data"`
	HasMore bool                     `json:"has_more"`
	FirstID *string                  `json:"first_id,omitempty"`
	LastID  *string                  `json:"last_id,omitempty"`
}

// AnthropicBatchResultItem represents a single result from a batch.
type AnthropicBatchResultItem struct {
	CustomID string                   `json:"custom_id"`
	Result   AnthropicBatchResultData `json:"result"`
}

// AnthropicBatchResultData represents the result data.
type AnthropicBatchResultData struct {
	Type    string                 `json:"type"` // "succeeded", "errored", "expired", "canceled"
	Message map[string]interface{} `json:"message,omitempty"`
	Error   *AnthropicBatchError   `json:"error,omitempty"`
}

// AnthropicBatchError represents an error in batch results.
type AnthropicBatchError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// ToDeepIntShieldBatchStatus converts Anthropic processing_status to DeepIntShield status.
func ToDeepIntShieldBatchStatus(status string) schemas.BatchStatus {
	switch status {
	case "in_progress":
		return schemas.BatchStatusInProgress
	case "canceling":
		return schemas.BatchStatusCancelling
	case "ended":
		return schemas.BatchStatusEnded
	default:
		return schemas.BatchStatus(status)
	}
}

// parseAnthropicTimestamp converts Anthropic ISO timestamp to Unix timestamp.
func parseAnthropicTimestamp(timestamp string) int64 {
	if timestamp == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return 0
	}
	return t.Unix()
}

// ToDeepIntShieldObjectType converts Anthropic type to DeepIntShield object type.
func ToDeepIntShieldObjectType(anthropicType string) string {
	switch anthropicType {
	case "message_batch":
		return "batch"
	default:
		return anthropicType
	}
}

// ToDeepIntShieldBatchCreateResponse converts Anthropic batch response to DeepIntShield batch create response.
func (r *AnthropicBatchResponse) ToDeepIntShieldBatchCreateResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldBatchCreateResponse {
	expiresAt := parseAnthropicTimestamp(r.ExpiresAt)
	resp := &schemas.DeepIntShieldBatchCreateResponse{
		ID:               r.ID,
		Object:           ToDeepIntShieldObjectType(r.Type),
		Status:           ToDeepIntShieldBatchStatus(r.ProcessingStatus),
		ProcessingStatus: &r.ProcessingStatus,
		ResultsURL:       r.ResultsURL,
		CreatedAt:        parseAnthropicTimestamp(r.CreatedAt),
		ExpiresAt:        &expiresAt,
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.BatchCreateRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	if r.RequestCounts != nil {
		resp.RequestCounts = schemas.BatchRequestCounts{
			Total:     r.RequestCounts.Processing + r.RequestCounts.Succeeded + r.RequestCounts.Errored + r.RequestCounts.Canceled + r.RequestCounts.Expired,
			Completed: r.RequestCounts.Succeeded,
			Failed:    r.RequestCounts.Errored,
			Succeeded: r.RequestCounts.Succeeded,
			Expired:   r.RequestCounts.Expired,
			Canceled:  r.RequestCounts.Canceled,
			Pending:   r.RequestCounts.Processing,
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

// ToDeepIntShieldBatchRetrieveResponse converts Anthropic batch response to DeepIntShield batch retrieve response.
func (r *AnthropicBatchResponse) ToDeepIntShieldBatchRetrieveResponse(providerName schemas.ModelProvider, latency time.Duration, sendBackRawRequest bool, sendBackRawResponse bool, rawRequest interface{}, rawResponse interface{}) *schemas.DeepIntShieldBatchRetrieveResponse {
	resp := &schemas.DeepIntShieldBatchRetrieveResponse{
		ID:               r.ID,
		Object:           ToDeepIntShieldObjectType(r.Type),
		Status:           ToDeepIntShieldBatchStatus(r.ProcessingStatus),
		ProcessingStatus: &r.ProcessingStatus,
		ResultsURL:       r.ResultsURL,
		CreatedAt:        parseAnthropicTimestamp(r.CreatedAt),
		ExtraFields: schemas.DeepIntShieldResponseExtraFields{
			RequestType: schemas.BatchRetrieveRequest,
			Provider:    providerName,
			Latency:     latency.Milliseconds(),
		},
	}

	if sendBackRawRequest {
		resp.ExtraFields.RawRequest = rawRequest
	}

	expiresAt := parseAnthropicTimestamp(r.ExpiresAt)
	if expiresAt > 0 {
		resp.ExpiresAt = &expiresAt
	}

	if r.EndedAt != nil {
		endedAt := parseAnthropicTimestamp(*r.EndedAt)
		resp.CompletedAt = &endedAt
	}

	if r.ArchivedAt != nil {
		archivedAt := parseAnthropicTimestamp(*r.ArchivedAt)
		resp.ArchivedAt = &archivedAt
	}

	if r.CancelInitiatedAt != nil {
		cancellingAt := parseAnthropicTimestamp(*r.CancelInitiatedAt)
		resp.CancellingAt = &cancellingAt
	}

	if r.RequestCounts != nil {
		resp.RequestCounts = schemas.BatchRequestCounts{
			Total:     r.RequestCounts.Processing + r.RequestCounts.Succeeded + r.RequestCounts.Errored + r.RequestCounts.Canceled + r.RequestCounts.Expired,
			Completed: r.RequestCounts.Succeeded,
			Failed:    r.RequestCounts.Errored,
			Succeeded: r.RequestCounts.Succeeded,
			Expired:   r.RequestCounts.Expired,
			Canceled:  r.RequestCounts.Canceled,
			Pending:   r.RequestCounts.Processing,
		}
	}

	if sendBackRawResponse {
		resp.ExtraFields.RawResponse = rawResponse
	}

	return resp
}

// ParseAnthropicError parses Anthropic error responses for batch operations.
func ParseAnthropicError(resp *fasthttp.Response, requestType schemas.RequestType, providerName schemas.ModelProvider, model string) *schemas.DeepIntShieldError {
	var errorResp AnthropicError
	deepintshieldErr := providerUtils.HandleProviderAPIError(resp, &errorResp)
	if errorResp.Error != nil {
		if errorResp.Error.Type != "" {
			deepintshieldErr.Error.Type = &errorResp.Error.Type
		}
		if errorResp.Error.Message != "" {
			deepintshieldErr.Error.Message = errorResp.Error.Message
		}
	}
	deepintshieldErr.ExtraFields = schemas.DeepIntShieldErrorExtraFields{
		RequestType:    requestType,
		Provider:       providerName,
		ModelRequested: model,
	}
	return deepintshieldErr
}

// ToAnthropicBatchCreateResponse converts a DeepIntShield batch create response to Anthropic format.
func ToAnthropicBatchCreateResponse(resp *schemas.DeepIntShieldBatchCreateResponse) *AnthropicBatchResponse {
	result := &AnthropicBatchResponse{
		ID:               resp.ID,
		Type:             "message_batch",
		ProcessingStatus: toAnthropicProcessingStatus(resp.Status),
		CreatedAt:        formatAnthropicTimestamp(resp.CreatedAt),
		ResultsURL:       resp.ResultsURL,
	}
	if resp.ExpiresAt != nil {
		result.ExpiresAt = formatAnthropicTimestamp(*resp.ExpiresAt)
	} else {
		// This is a fallback for worst case scenario where expires_at is not available
		// Which is never expected to happen, but just in case.
		result.ExpiresAt = formatAnthropicTimestamp(time.Now().Add(24 * time.Hour).Unix())
	}
	if resp.RequestCounts.Total > 0 {
		result.RequestCounts = &AnthropicBatchRequestCounts{
			Processing: resp.RequestCounts.Pending,
			Succeeded:  resp.RequestCounts.Succeeded,
			Errored:    resp.RequestCounts.Failed,
			Canceled:   resp.RequestCounts.Canceled,
			Expired:    resp.RequestCounts.Expired,
		}
	}
	return result
}

// ToAnthropicBatchListResponse converts a DeepIntShield batch list response to Anthropic format.
func ToAnthropicBatchListResponse(resp *schemas.DeepIntShieldBatchListResponse) *AnthropicBatchListResponse {
	result := &AnthropicBatchListResponse{
		Data:    make([]AnthropicBatchResponse, len(resp.Data)),
		HasMore: resp.HasMore,
		FirstID: resp.FirstID,
		LastID:  resp.LastID,
	}

	for i, batch := range resp.Data {
		result.Data[i] = *ToAnthropicBatchRetrieveResponse(&batch)
	}

	return result
}

// ToAnthropicBatchRetrieveResponse converts a DeepIntShield batch retrieve response to Anthropic format.
func ToAnthropicBatchRetrieveResponse(resp *schemas.DeepIntShieldBatchRetrieveResponse) *AnthropicBatchResponse {
	result := &AnthropicBatchResponse{
		ID:               resp.ID,
		Type:             "message_batch",
		ProcessingStatus: toAnthropicProcessingStatus(resp.Status),
		CreatedAt:        formatAnthropicTimestamp(resp.CreatedAt),
		ResultsURL:       resp.ResultsURL,
	}

	if resp.ExpiresAt != nil {
		result.ExpiresAt = formatAnthropicTimestamp(*resp.ExpiresAt)
	}

	if resp.CompletedAt != nil {
		endedAt := formatAnthropicTimestamp(*resp.CompletedAt)
		result.EndedAt = &endedAt
	}

	if resp.ArchivedAt != nil {
		archivedAt := formatAnthropicTimestamp(*resp.ArchivedAt)
		result.ArchivedAt = &archivedAt
	}

	if resp.CancellingAt != nil {
		cancelInitiatedAt := formatAnthropicTimestamp(*resp.CancellingAt)
		result.CancelInitiatedAt = &cancelInitiatedAt
	}

	if resp.RequestCounts.Total > 0 {
		result.RequestCounts = &AnthropicBatchRequestCounts{
			Processing: resp.RequestCounts.Pending,
			Succeeded:  resp.RequestCounts.Succeeded,
			Errored:    resp.RequestCounts.Failed,
			Canceled:   resp.RequestCounts.Canceled,
			Expired:    resp.RequestCounts.Expired,
		}
	}

	return result
}

// ToAnthropicBatchCancelResponse converts a DeepIntShield batch cancel response to Anthropic format.
func ToAnthropicBatchCancelResponse(resp *schemas.DeepIntShieldBatchCancelResponse) *AnthropicBatchResponse {
	result := &AnthropicBatchResponse{
		ID:               resp.ID,
		Type:             "message_batch",
		ProcessingStatus: toAnthropicProcessingStatus(resp.Status),
	}

	if resp.CancellingAt != nil {
		cancelInitiatedAt := formatAnthropicTimestamp(*resp.CancellingAt)
		result.CancelInitiatedAt = &cancelInitiatedAt
	}

	if resp.RequestCounts.Total > 0 {
		result.RequestCounts = &AnthropicBatchRequestCounts{
			Processing: resp.RequestCounts.Pending,
			Succeeded:  resp.RequestCounts.Succeeded,
			Canceled:   resp.RequestCounts.Canceled,
			Expired:    resp.RequestCounts.Expired,
			Errored:    resp.RequestCounts.Failed,
		}
	}

	return result
}

// toAnthropicProcessingStatus converts DeepIntShield batch status to Anthropic processing_status.
func toAnthropicProcessingStatus(status schemas.BatchStatus) string {
	switch status {
	case schemas.BatchStatusInProgress:
		fallthrough
	case schemas.BatchStatusValidating:
		return "in_progress"
	case schemas.BatchStatusCancelling:
		return "canceling"
	case schemas.BatchStatusEnded, schemas.BatchStatusCompleted, schemas.BatchStatusCancelled:
		return "ended"
	default:
		return string(status)
	}
}

// formatAnthropicTimestamp converts Unix timestamp to Anthropic ISO timestamp format.
func formatAnthropicTimestamp(unixTime int64) string {
	if unixTime == 0 {
		return ""
	}
	return time.Unix(unixTime, 0).UTC().Format(time.RFC3339)
}
