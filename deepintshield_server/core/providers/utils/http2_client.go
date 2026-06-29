package utils

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// HTTP/2-capable net/http client for provider outbound calls.
//
// Why this exists separately from the fasthttp transport every
// provider currently uses: fasthttp does not implement HTTP/2 as a
// client. OpenAI / Anthropic / Google / etc. all serve HTTP/2 and
// downgrade us to HTTP/1.1, which means:
//   - No request multiplexing on a single connection. Concurrent
//     calls open separate sockets and pay TLS handshake cost more
//     often.
//   - Head-of-line blocking on slow responses.
//   - Keep-alive pool churn under spike load.
//
// Switching every provider's transport at once is risky. This file
// provides a separate, HTTP/2-capable net/http client that providers
// can opt into call-by-call (for now) or migrate fully to over time.
// The shape mirrors fasthttp's "shared HostClient per host" pattern
// - one client per process, one connection pool, with a reasonable
// max-conns-per-host so the runtime doesn't exhaust file descriptors
// at scale.

var (
	http2ClientOnce sync.Once
	http2Client     *http.Client
)

// SharedHTTP2Client returns the process-wide http.Client configured
// for HTTP/2 with sensible production defaults. Idempotent + safe
// for concurrent use.
//
// Callers issue requests through the standard net/http API:
//
//	resp, err := utils.SharedHTTP2Client().Do(req.WithContext(ctx))
//
// The returned client:
//   - Uses ForceAttemptHTTP2 + http2.ConfigureTransport to ensure
//     HTTP/2 is negotiated when the server advertises it via ALPN.
//   - Holds 200 idle conns total / 50 per host for steady-state
//     pooling under multi-tenant burst load.
//   - 10-second response-header timeout so a stuck upstream doesn't
//     hold a goroutine forever.
//   - 90-second idle-conn timeout so dead sockets get pruned.
//
// Note: per-request total timeout is the caller's responsibility
// via context. Don't set http.Client.Timeout - that aborts streams
// mid-flight.
func SharedHTTP2Client() *http.Client {
	http2ClientOnce.Do(func() {
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   50,
			MaxConnsPerHost:       100,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
		}
		// Explicitly configure HTTP/2 on the transport. This is
		// belt-and-braces: ForceAttemptHTTP2 normally suffices but
		// some Go versions / TLS configs only complete the upgrade
		// when ConfigureTransport has been called.
		_ = http2.ConfigureTransport(transport)
		http2Client = &http.Client{Transport: transport}
	})
	return http2Client
}
