// Package schemas defines the core schemas and types used by the DeepIntShield system.
package schemas

import (
	"encoding/json"
	"maps"
	"time"
)

const (
	DefaultMaxRetries                 = 0
	DefaultRetryBackoffInitial        = 500 * time.Millisecond
	DefaultRetryBackoffMax            = 5 * time.Second
	DefaultRequestTimeoutInSeconds    = 30
	DefaultMaxConnDurationInSeconds   = 300 // 5 minutes - forces connection recycling to prevent stale connections from NAT/LB silent drops
	DefaultBufferSize                 = 5000
	DefaultConcurrency                = 1000
	DefaultStreamBufferSize           = 256
	DefaultStreamIdleTimeoutInSeconds = 60 // Idle timeout per stream chunk - if no data for this many seconds, deepintshield closes the connection
	DefaultMaxConnsPerHost            = 5000
	MaxConnsPerHostUpperBound         = 10000
	DefaultMaxIdleConnsPerHost        = 40
)

// Pre-defined errors for provider operations
const (
	ErrProviderRequestTimedOut      = "request timed out (default is 30 seconds). You can increase it by setting the default_request_timeout_in_seconds in the network_config or in UI - Providers > Provider Name > Network Config."
	ErrRequestCancelled             = "request cancelled by caller"
	ErrRequestBodyConversion        = "failed to convert deepintshield request to the expected provider request body"
	ErrProviderRequestMarshal       = "failed to marshal request body to JSON"
	ErrProviderCreateRequest        = "failed to create HTTP request to provider API"
	ErrProviderDoRequest            = "failed to execute HTTP request to provider API"
	ErrProviderNetworkError         = "network error occurred while connecting to provider API (DNS lookup, connection refused, etc.)"
	ErrProviderResponseDecode       = "failed to decode response body from provider API"
	ErrProviderResponseUnmarshal    = "failed to unmarshal response from provider API"
	ErrProviderResponseEmpty        = "empty response received from provider"
	ErrProviderResponseHTML         = "HTML response received from provider"
	ErrProviderRawRequestUnmarshal  = "failed to unmarshal raw request from provider API"
	ErrProviderRawResponseUnmarshal = "failed to unmarshal raw response from provider API"
	ErrProviderResponseDecompress   = "failed to decompress provider's response"
)

// NetworkConfig represents the network configuration for provider connections.
// ExtraHeaders is automatically copied during provider initialization to prevent data races.
//
// RetryBackoffInitial and RetryBackoffMax are stored internally as time.Duration (nanoseconds),
// but are serialized/deserialized to/from JSON as milliseconds (integers).
// This means:
//   - In JSON: values are represented as milliseconds (e.g., 1000 means 1000ms)
//   - In Go: values are time.Duration (e.g., 1000ms = 1000000000 nanoseconds)
//   - When unmarshaling from JSON: a value of 1000 is interpreted as 1000ms, not 1000ns
//   - When marshaling to JSON: a time.Duration is converted to milliseconds
type NetworkConfig struct {
	// BaseURL is supported for OpenAI, Anthropic, Cohere, Mistral, and Ollama providers (required for Ollama)
	BaseURL                        string            `json:"base_url,omitempty"`                       // Base URL for the provider (optional)
	ExtraHeaders                   map[string]string `json:"extra_headers,omitempty"`                  // Additional headers to include in requests (optional)
	DefaultRequestTimeoutInSeconds int               `json:"default_request_timeout_in_seconds"`       // Default timeout for requests
	MaxRetries                     int               `json:"max_retries"`                              // Maximum number of retries
	RetryBackoffInitial            time.Duration     `json:"retry_backoff_initial"`                    // Initial backoff duration (stored as nanoseconds, JSON as milliseconds)
	RetryBackoffMax                time.Duration     `json:"retry_backoff_max"`                        // Maximum backoff duration (stored as nanoseconds, JSON as milliseconds)
	InsecureSkipVerify             bool              `json:"insecure_skip_verify,omitempty"`           // Disables TLS certificate verification for provider connections
	CACertPEM                      string            `json:"ca_cert_pem,omitempty"`                    // PEM-encoded CA certificate to trust for provider endpoint connections
	StreamIdleTimeoutInSeconds     int               `json:"stream_idle_timeout_in_seconds,omitempty"` // Idle timeout per stream chunk (0 = use default 60s)
	MaxConnsPerHost                int               `json:"max_conns_per_host,omitempty"`             // Max TCP connections per provider host (default: 5000)
	EnforceHTTP2                   bool              `json:"enforce_http2,omitempty"`                  // Force HTTP/2 on provider connections (relevant for net/http-based providers like Bedrock)
}

// UnmarshalJSON customizes JSON unmarshaling for NetworkConfig.
// RetryBackoffInitial and RetryBackoffMax are interpreted as milliseconds in JSON,
// but stored as time.Duration (nanoseconds) internally.
func (nc *NetworkConfig) UnmarshalJSON(data []byte) error {
	// Use an alias type to avoid infinite recursion
	type NetworkConfigAlias struct {
		BaseURL                        string            `json:"base_url,omitempty"`
		ExtraHeaders                   map[string]string `json:"extra_headers,omitempty"`
		DefaultRequestTimeoutInSeconds int               `json:"default_request_timeout_in_seconds"`
		MaxRetries                     int               `json:"max_retries"`
		RetryBackoffInitial            int64             `json:"retry_backoff_initial"` // milliseconds in JSON
		RetryBackoffMax                int64             `json:"retry_backoff_max"`     // milliseconds in JSON
		InsecureSkipVerify             bool              `json:"insecure_skip_verify,omitempty"`
		CACertPEM                      string            `json:"ca_cert_pem,omitempty"`
		StreamIdleTimeoutInSeconds     int               `json:"stream_idle_timeout_in_seconds,omitempty"`
		MaxConnsPerHost                int               `json:"max_conns_per_host,omitempty"`
		EnforceHTTP2                   bool              `json:"enforce_http2,omitempty"`
	}

	var alias NetworkConfigAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	// Copy all fields
	nc.BaseURL = alias.BaseURL
	nc.ExtraHeaders = alias.ExtraHeaders
	nc.DefaultRequestTimeoutInSeconds = alias.DefaultRequestTimeoutInSeconds
	nc.MaxRetries = alias.MaxRetries
	nc.InsecureSkipVerify = alias.InsecureSkipVerify
	nc.CACertPEM = alias.CACertPEM
	nc.StreamIdleTimeoutInSeconds = alias.StreamIdleTimeoutInSeconds
	nc.MaxConnsPerHost = alias.MaxConnsPerHost
	nc.EnforceHTTP2 = alias.EnforceHTTP2

	// Convert milliseconds to time.Duration (nanoseconds)
	// Only convert if value is greater than 0
	if alias.RetryBackoffInitial > 0 {
		nc.RetryBackoffInitial = time.Duration(alias.RetryBackoffInitial) * time.Millisecond
	}
	if alias.RetryBackoffMax > 0 {
		nc.RetryBackoffMax = time.Duration(alias.RetryBackoffMax) * time.Millisecond
	}

	return nil
}

// MarshalJSON customizes JSON marshaling for NetworkConfig.
// RetryBackoffInitial and RetryBackoffMax are converted from time.Duration (nanoseconds)
// to milliseconds (integers) in JSON.
func (nc NetworkConfig) MarshalJSON() ([]byte, error) {
	// Use an alias type to avoid infinite recursion
	type NetworkConfigAlias struct {
		BaseURL                        string            `json:"base_url,omitempty"`
		ExtraHeaders                   map[string]string `json:"extra_headers,omitempty"`
		DefaultRequestTimeoutInSeconds int               `json:"default_request_timeout_in_seconds"`
		MaxRetries                     int               `json:"max_retries"`
		RetryBackoffInitial            int64             `json:"retry_backoff_initial"` // milliseconds in JSON
		RetryBackoffMax                int64             `json:"retry_backoff_max"`     // milliseconds in JSON
		InsecureSkipVerify             bool              `json:"insecure_skip_verify,omitempty"`
		CACertPEM                      string            `json:"ca_cert_pem,omitempty"`
		StreamIdleTimeoutInSeconds     int               `json:"stream_idle_timeout_in_seconds,omitempty"`
		MaxConnsPerHost                int               `json:"max_conns_per_host,omitempty"`
		EnforceHTTP2                   bool              `json:"enforce_http2,omitempty"`
	}

	alias := NetworkConfigAlias{
		BaseURL:                        nc.BaseURL,
		ExtraHeaders:                   nc.ExtraHeaders,
		DefaultRequestTimeoutInSeconds: nc.DefaultRequestTimeoutInSeconds,
		MaxRetries:                     nc.MaxRetries,
		// Convert time.Duration (nanoseconds) to milliseconds
		RetryBackoffInitial:        int64(nc.RetryBackoffInitial / time.Millisecond),
		RetryBackoffMax:            int64(nc.RetryBackoffMax / time.Millisecond),
		InsecureSkipVerify:         nc.InsecureSkipVerify,
		CACertPEM:                  nc.CACertPEM,
		StreamIdleTimeoutInSeconds: nc.StreamIdleTimeoutInSeconds,
		MaxConnsPerHost:            nc.MaxConnsPerHost,
		EnforceHTTP2:               nc.EnforceHTTP2,
	}

	return json.Marshal(alias)
}

// Redacted returns a redacted copy of the network configuration with CACertPEM masked.
func (nc *NetworkConfig) Redacted() *NetworkConfig {
	if nc == nil {
		return nil
	}
	redacted := *nc
	if nc.CACertPEM != "" {
		redacted.CACertPEM = "<REDACTED>"
	}
	return &redacted
}

// DefaultNetworkConfig is the default network configuration for provider connections.
var DefaultNetworkConfig = NetworkConfig{
	DefaultRequestTimeoutInSeconds: DefaultRequestTimeoutInSeconds,
	MaxRetries:                     DefaultMaxRetries,
	RetryBackoffInitial:            DefaultRetryBackoffInitial,
	RetryBackoffMax:                DefaultRetryBackoffMax,
	StreamIdleTimeoutInSeconds:     DefaultStreamIdleTimeoutInSeconds,
	MaxConnsPerHost:                DefaultMaxConnsPerHost,
}

// ConcurrencyAndBufferSize represents configuration for concurrent operations and buffer sizes.
type ConcurrencyAndBufferSize struct {
	Concurrency int `json:"concurrency"` // Number of concurrent operations. Also used as the initial pool size for the provider reponses.
	BufferSize  int `json:"buffer_size"` // Size of the buffer
}

// DefaultConcurrencyAndBufferSize is the default concurrency and buffer size for provider operations.
var DefaultConcurrencyAndBufferSize = ConcurrencyAndBufferSize{
	Concurrency: DefaultConcurrency,
	BufferSize:  DefaultBufferSize,
}

// ProxyType defines the type of proxy to use for connections.
type ProxyType string

const (
	// NoProxy indicates no proxy should be used
	NoProxy ProxyType = "none"
	// HTTPProxy indicates an HTTP proxy should be used
	HTTPProxy ProxyType = "http"
	// Socks5Proxy indicates a SOCKS5 proxy should be used
	Socks5Proxy ProxyType = "socks5"
	// EnvProxy indicates the proxy should be read from environment variables
	EnvProxy ProxyType = "environment"
)

// ProxyConfig holds the configuration for proxy settings.
type ProxyConfig struct {
	Type      ProxyType `json:"type"`        // Type of proxy to use
	URL       string    `json:"url"`         // URL of the proxy server
	Username  string    `json:"username"`    // Username for proxy authentication
	Password  string    `json:"password"`    // Password for proxy authentication
	CACertPEM string    `json:"ca_cert_pem"` // PEM-encoded CA certificate to trust for TLS connections through the proxy
}

// IsRedactedValue returns true if the value is redacted.
func (pc *ProxyConfig) IsRedactedValue(value string) bool {
	return value == "<REDACTED>" || value == "********"
}

// Redacted returns a redacted copy of the proxy configuration.
func (pc *ProxyConfig) Redacted() *ProxyConfig {
	// Create redacted config with same structure but redacted values
	redactedConfig := ProxyConfig{
		Type:     pc.Type,
		URL:      pc.URL,
		Username: pc.Username,
	}
	if pc.Password != "" {
		redactedConfig.Password = "<REDACTED>"
	}
	if pc.CACertPEM != "" {
		redactedConfig.CACertPEM = "<REDACTED>"
	}
	return &redactedConfig
}

// AllowedRequests controls which operations are permitted.
// A nil *AllowedRequests means "all operations allowed."
// A non-nil value only allows fields set to true; omitted or false fields are disallowed.
type AllowedRequests struct {
	ListModels            bool `json:"list_models"`
	TextCompletion        bool `json:"text_completion"`
	TextCompletionStream  bool `json:"text_completion_stream"`
	ChatCompletion        bool `json:"chat_completion"`
	ChatCompletionStream  bool `json:"chat_completion_stream"`
	Responses             bool `json:"responses"`
	ResponsesStream       bool `json:"responses_stream"`
	CountTokens           bool `json:"count_tokens"`
	Embedding             bool `json:"embedding"`
	Rerank                bool `json:"rerank"`
	Speech                bool `json:"speech"`
	SpeechStream          bool `json:"speech_stream"`
	Transcription         bool `json:"transcription"`
	TranscriptionStream   bool `json:"transcription_stream"`
	ImageGeneration       bool `json:"image_generation"`
	ImageGenerationStream bool `json:"image_generation_stream"`
	ImageEdit             bool `json:"image_edit"`
	ImageEditStream       bool `json:"image_edit_stream"`
	ImageVariation        bool `json:"image_variation"`
	VideoGeneration       bool `json:"video_generation"`
	VideoRetrieve         bool `json:"video_retrieve"`
	VideoDownload         bool `json:"video_download"`
	VideoDelete           bool `json:"video_delete"`
	VideoList             bool `json:"video_list"`
	VideoRemix            bool `json:"video_remix"`
	BatchCreate           bool `json:"batch_create"`
	BatchList             bool `json:"batch_list"`
	BatchRetrieve         bool `json:"batch_retrieve"`
	BatchCancel           bool `json:"batch_cancel"`
	BatchDelete           bool `json:"batch_delete"`
	BatchResults          bool `json:"batch_results"`
	FileUpload            bool `json:"file_upload"`
	FileList              bool `json:"file_list"`
	FileRetrieve          bool `json:"file_retrieve"`
	FileDelete            bool `json:"file_delete"`
	FileContent           bool `json:"file_content"`
	ContainerCreate       bool `json:"container_create"`
	ContainerList         bool `json:"container_list"`
	ContainerRetrieve     bool `json:"container_retrieve"`
	ContainerDelete       bool `json:"container_delete"`
	ContainerFileCreate   bool `json:"container_file_create"`
	ContainerFileList     bool `json:"container_file_list"`
	ContainerFileRetrieve bool `json:"container_file_retrieve"`
	ContainerFileContent  bool `json:"container_file_content"`
	ContainerFileDelete   bool `json:"container_file_delete"`
	Passthrough           bool `json:"passthrough"`
	PassthroughStream     bool `json:"passthrough_stream"`
	WebSocketResponses    bool `json:"websocket_responses"`
	Realtime              bool `json:"realtime"`
}

// IsOperationAllowed checks if a specific operation is allowed
func (ar *AllowedRequests) IsOperationAllowed(operation RequestType) bool {
	if ar == nil {
		return true // Default to allowed if no restrictions
	}

	switch operation {
	case ListModelsRequest:
		return ar.ListModels
	case TextCompletionRequest:
		return ar.TextCompletion
	case TextCompletionStreamRequest:
		return ar.TextCompletionStream
	case ChatCompletionRequest:
		return ar.ChatCompletion
	case ChatCompletionStreamRequest:
		return ar.ChatCompletionStream
	case ResponsesRequest:
		return ar.Responses
	case ResponsesStreamRequest:
		return ar.ResponsesStream
	case CountTokensRequest:
		return ar.CountTokens
	case EmbeddingRequest:
		return ar.Embedding
	case RerankRequest:
		return ar.Rerank
	case SpeechRequest:
		return ar.Speech
	case SpeechStreamRequest:
		return ar.SpeechStream
	case TranscriptionRequest:
		return ar.Transcription
	case TranscriptionStreamRequest:
		return ar.TranscriptionStream
	case ImageGenerationRequest:
		return ar.ImageGeneration
	case ImageGenerationStreamRequest:
		return ar.ImageGenerationStream
	case ImageEditRequest:
		return ar.ImageEdit
	case ImageEditStreamRequest:
		return ar.ImageEditStream
	case ImageVariationRequest:
		return ar.ImageVariation
	case VideoGenerationRequest:
		return ar.VideoGeneration
	case VideoRetrieveRequest:
		return ar.VideoRetrieve
	case VideoDownloadRequest:
		return ar.VideoDownload
	case VideoDeleteRequest:
		return ar.VideoDelete
	case VideoListRequest:
		return ar.VideoList
	case VideoRemixRequest:
		return ar.VideoRemix
	case BatchCreateRequest:
		return ar.BatchCreate
	case BatchListRequest:
		return ar.BatchList
	case BatchRetrieveRequest:
		return ar.BatchRetrieve
	case BatchCancelRequest:
		return ar.BatchCancel
	case BatchDeleteRequest:
		return ar.BatchDelete
	case BatchResultsRequest:
		return ar.BatchResults
	case FileUploadRequest:
		return ar.FileUpload
	case FileListRequest:
		return ar.FileList
	case FileRetrieveRequest:
		return ar.FileRetrieve
	case FileDeleteRequest:
		return ar.FileDelete
	case FileContentRequest:
		return ar.FileContent
	case ContainerCreateRequest:
		return ar.ContainerCreate
	case ContainerListRequest:
		return ar.ContainerList
	case ContainerRetrieveRequest:
		return ar.ContainerRetrieve
	case ContainerDeleteRequest:
		return ar.ContainerDelete
	case ContainerFileCreateRequest:
		return ar.ContainerFileCreate
	case ContainerFileListRequest:
		return ar.ContainerFileList
	case ContainerFileRetrieveRequest:
		return ar.ContainerFileRetrieve
	case ContainerFileContentRequest:
		return ar.ContainerFileContent
	case ContainerFileDeleteRequest:
		return ar.ContainerFileDelete
	case PassthroughRequest:
		return ar.Passthrough
	case PassthroughStreamRequest:
		return ar.PassthroughStream
	case WebSocketResponsesRequest:
		return ar.WebSocketResponses
	case RealtimeRequest:
		return ar.Realtime
	default:
		return false // Default to not allowed for unknown operations
	}
}

type CustomProviderConfig struct {
	CustomProviderKey    string                 `json:"-"`                                // Custom provider key, internally set by DeepIntShield
	IsKeyLess            bool                   `json:"is_key_less"`                      // Whether the custom provider requires a key (not allowed for Bedrock)
	BaseProviderType     ModelProvider          `json:"base_provider_type"`               // Base provider type
	AllowedRequests      *AllowedRequests       `json:"allowed_requests,omitempty"`       // Allowed requests for the custom provider
	RequestPathOverrides map[RequestType]string `json:"request_path_overrides,omitempty"` // Mapping of request type to its custom path which will override the default path of the provider (not allowed for Bedrock)
}

type PricingOverrideMatchType string

const (
	PricingOverrideMatchExact    PricingOverrideMatchType = "exact"
	PricingOverrideMatchWildcard PricingOverrideMatchType = "wildcard"
	PricingOverrideMatchRegex    PricingOverrideMatchType = "regex"
)

// ProviderPricingOverride contains a partial pricing patch applied at lookup time.
// Any nil field falls back to the base pricing data.
type ProviderPricingOverride struct {
	ModelPattern string                   `json:"model_pattern"`
	MatchType    PricingOverrideMatchType `json:"match_type"`
	RequestTypes []RequestType            `json:"request_types,omitempty"`

	// Basic token pricing
	InputCostPerToken  *float64 `json:"input_cost_per_token,omitempty"`
	OutputCostPerToken *float64 `json:"output_cost_per_token,omitempty"`

	// Additional pricing for media
	InputCostPerVideoPerSecond *float64 `json:"input_cost_per_video_per_second,omitempty"`
	InputCostPerAudioPerSecond *float64 `json:"input_cost_per_audio_per_second,omitempty"`

	// Character-based pricing
	InputCostPerCharacter *float64 `json:"input_cost_per_character,omitempty"`

	// Pricing above 128k tokens
	InputCostPerTokenAbove128kTokens          *float64 `json:"input_cost_per_token_above_128k_tokens,omitempty"`
	InputCostPerImageAbove128kTokens          *float64 `json:"input_cost_per_image_above_128k_tokens,omitempty"`
	InputCostPerVideoPerSecondAbove128kTokens *float64 `json:"input_cost_per_video_per_second_above_128k_tokens,omitempty"`
	InputCostPerAudioPerSecondAbove128kTokens *float64 `json:"input_cost_per_audio_per_second_above_128k_tokens,omitempty"`
	OutputCostPerTokenAbove128kTokens         *float64 `json:"output_cost_per_token_above_128k_tokens,omitempty"`

	// Pricing above 200k tokens
	InputCostPerTokenAbove200kTokens           *float64 `json:"input_cost_per_token_above_200k_tokens,omitempty"`
	OutputCostPerTokenAbove200kTokens          *float64 `json:"output_cost_per_token_above_200k_tokens,omitempty"`
	CacheCreationInputTokenCostAbove200kTokens *float64 `json:"cache_creation_input_token_cost_above_200k_tokens,omitempty"`
	CacheReadInputTokenCostAbove200kTokens     *float64 `json:"cache_read_input_token_cost_above_200k_tokens,omitempty"`

	// Cache and batch pricing
	CacheReadInputTokenCost     *float64 `json:"cache_read_input_token_cost,omitempty"`
	CacheCreationInputTokenCost *float64 `json:"cache_creation_input_token_cost,omitempty"`
	InputCostPerTokenBatches    *float64 `json:"input_cost_per_token_batches,omitempty"`
	OutputCostPerTokenBatches   *float64 `json:"output_cost_per_token_batches,omitempty"`

	// Image generation pricing
	InputCostPerImageToken                        *float64 `json:"input_cost_per_image_token,omitempty"`
	OutputCostPerImageToken                       *float64 `json:"output_cost_per_image_token,omitempty"`
	InputCostPerImage                             *float64 `json:"input_cost_per_image,omitempty"`
	OutputCostPerImage                            *float64 `json:"output_cost_per_image,omitempty"`
	OutputCostPerImageAbove1024x1024Pixels        *float64 `json:"output_cost_per_image_above_1024_and_1024_pixels,omitempty"`
	OutputCostPerImageAbove1024x1024PixelsPremium *float64 `json:"output_cost_per_image_above_1024_and_1024_pixels_and_premium_image,omitempty"`
	OutputCostPerImageAbove2048x2048Pixels        *float64 `json:"output_cost_per_image_above_2048_and_2048_pixels,omitempty"`
	OutputCostPerImageAbove4096x4096Pixels        *float64 `json:"output_cost_per_image_above_4096_and_4096_pixels,omitempty"`
	OutputCostPerImageLowQuality                  *float64 `json:"output_cost_per_image_low_quality,omitempty"`
	OutputCostPerImageMediumQuality               *float64 `json:"output_cost_per_image_medium_quality,omitempty"`
	OutputCostPerImageHighQuality                 *float64 `json:"output_cost_per_image_high_quality,omitempty"`
	OutputCostPerImageAutoQuality                 *float64 `json:"output_cost_per_image_auto_quality,omitempty"`
	CacheReadInputImageTokenCost                  *float64 `json:"cache_read_input_image_token_cost,omitempty"`
}

// IsOperationAllowed checks if a specific operation is allowed for this custom provider
func (cpc *CustomProviderConfig) IsOperationAllowed(operation RequestType) bool {
	if cpc == nil || cpc.AllowedRequests == nil {
		return true // Default to allowed if no restrictions
	}
	return cpc.AllowedRequests.IsOperationAllowed(operation)
}

// ProviderConfig represents the complete configuration for a provider.
// An array of ProviderConfig needs to be provided in GetConfigForProvider
// in your account interface implementation.
type ProviderConfig struct {
	NetworkConfig            NetworkConfig            `json:"network_config"`              // Network configuration
	ConcurrencyAndBufferSize ConcurrencyAndBufferSize `json:"concurrency_and_buffer_size"` // Concurrency settings
	// Logger instance, can be provided by the user or deepintshield default logger is used if not provided
	Logger                  Logger                    `json:"-"`
	ProxyConfig             *ProxyConfig              `json:"proxy_config,omitempty"`     // Proxy configuration
	SendBackRawRequest      bool                      `json:"send_back_raw_request"`      // Send raw request back in the deepintshield response (default: false)
	SendBackRawResponse     bool                      `json:"send_back_raw_response"`     // Send raw response back in the deepintshield response (default: false)
	StoreRawRequestResponse bool                      `json:"store_raw_request_response"` // Capture raw request/response for internal logging only; strip from API responses returned to clients (default: false)
	CustomProviderConfig    *CustomProviderConfig     `json:"custom_provider_config,omitempty"`
	PricingOverrides        []ProviderPricingOverride `json:"pricing_overrides,omitempty"`
}

func (config *ProviderConfig) CheckAndSetDefaults() {
	if config.ConcurrencyAndBufferSize.Concurrency == 0 {
		config.ConcurrencyAndBufferSize.Concurrency = DefaultConcurrency
	}

	if config.ConcurrencyAndBufferSize.BufferSize == 0 {
		config.ConcurrencyAndBufferSize.BufferSize = DefaultBufferSize
	}

	if config.NetworkConfig.DefaultRequestTimeoutInSeconds <= 0 {
		config.NetworkConfig.DefaultRequestTimeoutInSeconds = DefaultRequestTimeoutInSeconds
	}

	if config.NetworkConfig.MaxRetries == 0 {
		config.NetworkConfig.MaxRetries = DefaultMaxRetries
	}

	if config.NetworkConfig.RetryBackoffInitial == 0 {
		config.NetworkConfig.RetryBackoffInitial = DefaultRetryBackoffInitial
	}

	if config.NetworkConfig.RetryBackoffMax == 0 {
		config.NetworkConfig.RetryBackoffMax = DefaultRetryBackoffMax
	}

	if config.NetworkConfig.StreamIdleTimeoutInSeconds <= 0 {
		config.NetworkConfig.StreamIdleTimeoutInSeconds = DefaultStreamIdleTimeoutInSeconds
	}

	if config.NetworkConfig.MaxConnsPerHost <= 0 {
		config.NetworkConfig.MaxConnsPerHost = DefaultMaxConnsPerHost
	} else if config.NetworkConfig.MaxConnsPerHost > MaxConnsPerHostUpperBound {
		config.NetworkConfig.MaxConnsPerHost = MaxConnsPerHostUpperBound
	}

	// Create a defensive copy of ExtraHeaders to prevent data races
	if config.NetworkConfig.ExtraHeaders != nil {
		headersCopy := make(map[string]string, len(config.NetworkConfig.ExtraHeaders))
		maps.Copy(headersCopy, config.NetworkConfig.ExtraHeaders)
		config.NetworkConfig.ExtraHeaders = headersCopy
	}
}

type PostHookRunner func(ctx *DeepIntShieldContext, result *DeepIntShieldResponse, err *DeepIntShieldError) (*DeepIntShieldResponse, *DeepIntShieldError)

// Provider defines the interface for AI model providers.
type Provider interface {
	// GetProviderKey returns the provider's identifier
	GetProviderKey() ModelProvider
	// ListModels performs a list models request
	ListModels(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldListModelsRequest) (*DeepIntShieldListModelsResponse, *DeepIntShieldError)
	// TextCompletion performs a text completion request
	TextCompletion(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldTextCompletionRequest) (*DeepIntShieldTextCompletionResponse, *DeepIntShieldError)
	// TextCompletionStream performs a text completion stream request
	TextCompletionStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key, request *DeepIntShieldTextCompletionRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// ChatCompletion performs a chat completion request
	ChatCompletion(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldChatRequest) (*DeepIntShieldChatResponse, *DeepIntShieldError)
	// ChatCompletionStream performs a chat completion stream request
	ChatCompletionStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key, request *DeepIntShieldChatRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// Responses performs a completion request using the Responses API (uses chat completion request internally for non-openai providers)
	Responses(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldResponsesRequest) (*DeepIntShieldResponsesResponse, *DeepIntShieldError)
	// ResponsesStream performs a completion request using the Responses API stream (uses chat completion stream request internally for non-openai providers)
	ResponsesStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key, request *DeepIntShieldResponsesRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// CountTokens performs a count tokens request
	CountTokens(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldResponsesRequest) (*DeepIntShieldCountTokensResponse, *DeepIntShieldError)
	// Embedding performs an embedding request
	Embedding(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldEmbeddingRequest) (*DeepIntShieldEmbeddingResponse, *DeepIntShieldError)
	// Rerank performs a rerank request to reorder documents by relevance to a query
	Rerank(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldRerankRequest) (*DeepIntShieldRerankResponse, *DeepIntShieldError)
	// Speech performs a text to speech request
	Speech(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldSpeechRequest) (*DeepIntShieldSpeechResponse, *DeepIntShieldError)
	// SpeechStream performs a text to speech stream request
	SpeechStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key, request *DeepIntShieldSpeechRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// Transcription performs a transcription request
	Transcription(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldTranscriptionRequest) (*DeepIntShieldTranscriptionResponse, *DeepIntShieldError)
	// TranscriptionStream performs a transcription stream request
	TranscriptionStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key, request *DeepIntShieldTranscriptionRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// ImageGeneration performs an image generation request
	ImageGeneration(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldImageGenerationRequest) (
		*DeepIntShieldImageGenerationResponse, *DeepIntShieldError)
	// ImageGenerationStream performs an image generation stream request
	ImageGenerationStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key,
		request *DeepIntShieldImageGenerationRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// ImageEdit performs an image edit request
	ImageEdit(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldImageEditRequest) (*DeepIntShieldImageGenerationResponse, *DeepIntShieldError)
	// ImageEditStream performs an image edit stream request
	ImageEditStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key,
		request *DeepIntShieldImageEditRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
	// ImageVariation performs an image variation request
	ImageVariation(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldImageVariationRequest) (*DeepIntShieldImageGenerationResponse, *DeepIntShieldError)
	// VideoGeneration performs a video generation request
	VideoGeneration(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldVideoGenerationRequest) (*DeepIntShieldVideoGenerationResponse, *DeepIntShieldError)
	// VideoRetrieve retrieves a video from the provider
	VideoRetrieve(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldVideoRetrieveRequest) (*DeepIntShieldVideoGenerationResponse, *DeepIntShieldError)
	// VideoDownload downloads a video from the provider
	VideoDownload(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldVideoDownloadRequest) (*DeepIntShieldVideoDownloadResponse, *DeepIntShieldError)
	// VideoDelete deletes a video from the provider
	VideoDelete(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldVideoDeleteRequest) (*DeepIntShieldVideoDeleteResponse, *DeepIntShieldError)
	// VideoList lists videos from the provider
	VideoList(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldVideoListRequest) (*DeepIntShieldVideoListResponse, *DeepIntShieldError)
	// VideoRemix remixes a video from the provider
	VideoRemix(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldVideoRemixRequest) (*DeepIntShieldVideoGenerationResponse, *DeepIntShieldError)
	// BatchCreate creates a new batch job for asynchronous processing
	BatchCreate(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldBatchCreateRequest) (*DeepIntShieldBatchCreateResponse, *DeepIntShieldError)
	// BatchList lists batch jobs
	BatchList(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldBatchListRequest) (*DeepIntShieldBatchListResponse, *DeepIntShieldError)
	// BatchRetrieve retrieves a specific batch job
	BatchRetrieve(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldBatchRetrieveRequest) (*DeepIntShieldBatchRetrieveResponse, *DeepIntShieldError)
	// BatchCancel cancels a batch job
	BatchCancel(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldBatchCancelRequest) (*DeepIntShieldBatchCancelResponse, *DeepIntShieldError)
	// BatchDelete deletes a batch job
	BatchDelete(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldBatchDeleteRequest) (*DeepIntShieldBatchDeleteResponse, *DeepIntShieldError)
	// BatchResults retrieves results from a completed batch job
	BatchResults(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldBatchResultsRequest) (*DeepIntShieldBatchResultsResponse, *DeepIntShieldError)
	// FileUpload uploads a file to the provider
	FileUpload(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldFileUploadRequest) (*DeepIntShieldFileUploadResponse, *DeepIntShieldError)
	// FileList lists files from the provider
	FileList(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldFileListRequest) (*DeepIntShieldFileListResponse, *DeepIntShieldError)
	// FileRetrieve retrieves file metadata from the provider
	FileRetrieve(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldFileRetrieveRequest) (*DeepIntShieldFileRetrieveResponse, *DeepIntShieldError)
	// FileDelete deletes a file from the provider
	FileDelete(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldFileDeleteRequest) (*DeepIntShieldFileDeleteResponse, *DeepIntShieldError)
	// FileContent downloads file content from the provider
	FileContent(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldFileContentRequest) (*DeepIntShieldFileContentResponse, *DeepIntShieldError)
	// ContainerCreate creates a new container
	ContainerCreate(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldContainerCreateRequest) (*DeepIntShieldContainerCreateResponse, *DeepIntShieldError)
	// ContainerList lists containers
	ContainerList(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerListRequest) (*DeepIntShieldContainerListResponse, *DeepIntShieldError)
	// ContainerRetrieve retrieves a specific container
	ContainerRetrieve(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerRetrieveRequest) (*DeepIntShieldContainerRetrieveResponse, *DeepIntShieldError)
	// ContainerDelete deletes a container
	ContainerDelete(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerDeleteRequest) (*DeepIntShieldContainerDeleteResponse, *DeepIntShieldError)
	// ContainerFileCreate creates a file in a container
	ContainerFileCreate(ctx *DeepIntShieldContext, key Key, request *DeepIntShieldContainerFileCreateRequest) (*DeepIntShieldContainerFileCreateResponse, *DeepIntShieldError)
	// ContainerFileList lists files in a container
	ContainerFileList(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerFileListRequest) (*DeepIntShieldContainerFileListResponse, *DeepIntShieldError)
	// ContainerFileRetrieve retrieves a file from a container
	ContainerFileRetrieve(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerFileRetrieveRequest) (*DeepIntShieldContainerFileRetrieveResponse, *DeepIntShieldError)
	// ContainerFileContent retrieves the content of a file from a container
	ContainerFileContent(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerFileContentRequest) (*DeepIntShieldContainerFileContentResponse, *DeepIntShieldError)
	// ContainerFileDelete deletes a file from a container
	ContainerFileDelete(ctx *DeepIntShieldContext, keys []Key, request *DeepIntShieldContainerFileDeleteRequest) (*DeepIntShieldContainerFileDeleteResponse, *DeepIntShieldError)
	// Passthrough executes a non-streaming passthrough; body is fully buffered.
	Passthrough(ctx *DeepIntShieldContext, key Key, req *DeepIntShieldPassthroughRequest) (*DeepIntShieldPassthroughResponse, *DeepIntShieldError)
	// PassthroughStream executes a streaming passthrough, forwarding raw response bytes as DeepIntShieldStreamChunks.
	PassthroughStream(ctx *DeepIntShieldContext, postHookRunner PostHookRunner, key Key, req *DeepIntShieldPassthroughRequest) (chan *DeepIntShieldStreamChunk, *DeepIntShieldError)
}

// WebSocketCapableProvider is an optional interface that providers can implement
// to indicate support for the OpenAI Responses API WebSocket Mode.
// Checked via type assertion: provider.(WebSocketCapableProvider).
// Providers that implement this interface will have native WS upstream connections
// instead of the HTTP bridge fallback for Responses WS mode.
type WebSocketCapableProvider interface {
	// SupportsWebSocketMode returns true if the provider supports the Responses API WebSocket Mode.
	SupportsWebSocketMode() bool
	// WebSocketResponsesURL returns the WebSocket URL for the Responses API.
	WebSocketResponsesURL(key Key) string
	// WebSocketHeaders returns the headers required for the upstream WebSocket connection.
	WebSocketHeaders(key Key) map[string]string
}
