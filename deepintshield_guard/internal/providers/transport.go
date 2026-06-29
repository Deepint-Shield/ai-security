package providers

import (
	"net/http"
	"time"
)

// SharedTransport is a pooled HTTP transport shared across all guardrail
// provider adapters (AWS Bedrock, Azure Content Safety, GCP Model Armor,
// webhook, DeepintShield models). Sharing the transport enables connection
// reuse and keep-alive, avoiding per-request TLS handshake overhead.
var SharedTransport = &http.Transport{
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:  3 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
}

// NewHTTPClient creates an *http.Client using the SharedTransport with the
// given timeout. All provider adapters should use this instead of creating
// bare http.Client instances.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: SharedTransport,
	}
}
