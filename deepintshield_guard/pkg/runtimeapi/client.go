package runtimeapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	json "github.com/deepint-shield/ai-security-guard/internal/jsonfast"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip" // registers the gzip compressor
	"google.golang.org/grpc/keepalive"
)

type ClientConfig struct {
	HTTPURL      string
	GRPCTarget   string
	SharedSecret string
	Timeout      time.Duration
	PreferGRPC   bool
}

type Client struct {
	httpURL      string
	sharedSecret string
	timeout      time.Duration
	httpClient   *http.Client
	grpcConn     *grpc.ClientConn
	preferGRPC   bool
}

func NewClient(config ClientConfig) (*Client, error) {
	httpURL := strings.TrimRight(strings.TrimSpace(config.HTTPURL), "/")
	grpcTarget := strings.TrimSpace(config.GRPCTarget)
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if httpURL == "" && grpcTarget == "" {
		return nil, nil
	}
	// Tuned HTTP transport. The stdlib default caps idle conns at 100 total
	// and 2 per host - too low for a high-RPS guard gateway that hammers a
	// single runtime URL. Bump per-host idles, force HTTP/2 keepalive, and
	// set realistic timeouts so a hung backend can't pin a goroutine.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		MaxConnsPerHost:       512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &Client{
		httpURL:      httpURL,
		sharedSecret: strings.TrimSpace(config.SharedSecret),
		timeout:      timeout,
		preferGRPC:   config.PreferGRPC,
		httpClient:   &http.Client{Timeout: timeout, Transport: transport},
	}
	if grpcTarget != "" {
		dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err := grpc.DialContext(
			dialCtx,
			grpcTarget,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.ForceCodec(jsonCodec{}),
				// gzip kicks in only for payloads above ~1KB; HTTP/2 frame
				// overhead means tiny messages would lose more than they save.
				grpc.UseCompressor("gzip"),
				grpc.MaxCallRecvMsgSize(16<<20),
			),
			// Keepalive: ping every 30s, allow 10s for pong, permit ping
			// while idle so connections survive low-traffic periods.
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                30 * time.Second,
				Timeout:             10 * time.Second,
				PermitWithoutStream: true,
			}),
			grpc.WithChainUnaryInterceptor(AuthUnaryClientInterceptor(client.sharedSecret)),
		)
		if err != nil && httpURL == "" {
			return nil, fmt.Errorf("failed to dial guard runtime gRPC target: %w", err)
		}
		client.grpcConn = conn
	}
	return client, nil
}

func (c *Client) Close() error {
	if c == nil || c.grpcConn == nil {
		return nil
	}
	return c.grpcConn.Close()
}

func (c *Client) Ping(ctx context.Context) (*PingResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("runtime client not configured")
	}
	if c.preferGRPC && c.grpcConn != nil {
		response := &PingResponse{}
		if err := c.grpcConn.Invoke(ctx, FullMethodPing, &PingRequest{}, response); err == nil {
			return response, nil
		}
	}
	if c.httpURL == "" {
		return nil, fmt.Errorf("runtime client has no reachable transport")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.httpURL+"/v1/runtime/ping", nil)
	if err != nil {
		return nil, err
	}
	AttachHTTPAuth(request, "POST /v1/runtime/ping", nil, c.sharedSecret, time.Now().UTC())
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return nil, httpError(response)
	}
	var decoded PingResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (c *Client) RefreshTenant(ctx context.Context, request *RefreshTenantRequest) (*RefreshTenantResponse, error) {
	if c == nil || request == nil {
		return nil, fmt.Errorf("runtime client is not configured")
	}
	if c.preferGRPC && c.grpcConn != nil {
		response := &RefreshTenantResponse{}
		if err := c.grpcConn.Invoke(ctx, FullMethodRefresh, request, response); err == nil {
			return response, nil
		}
	}
	return c.refreshTenantHTTP(ctx, request)
}

func (c *Client) Evaluate(ctx context.Context, request *EvaluateRequest) (*EvaluateResponse, error) {
	if c == nil || request == nil {
		return nil, fmt.Errorf("runtime client is not configured")
	}
	if c.preferGRPC && c.grpcConn != nil {
		response := &EvaluateResponse{}
		if err := c.grpcConn.Invoke(ctx, grpcMethodForStage(request.Stage), request, response); err == nil {
			return response, nil
		}
	}
	return c.evaluateHTTP(ctx, request)
}

func (c *Client) refreshTenantHTTP(ctx context.Context, request *RefreshTenantRequest) (*RefreshTenantResponse, error) {
	if c.httpURL == "" {
		return nil, fmt.Errorf("runtime client has no HTTP base URL configured")
	}
	body, releaseBody, err := json.MarshalPooled(request)
	if err != nil {
		return nil, err
	}
	defer releaseBody()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.httpURL+"/v1/runtime/refresh-tenant", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	AttachHTTPAuth(httpReq, "POST /v1/runtime/refresh-tenant", body, c.sharedSecret, time.Now().UTC())
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, httpError(resp)
	}
	var decoded RefreshTenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (c *Client) evaluateHTTP(ctx context.Context, request *EvaluateRequest) (*EvaluateResponse, error) {
	if c.httpURL == "" {
		return nil, fmt.Errorf("runtime client has no HTTP base URL configured")
	}
	body, releaseBody, err := json.MarshalPooled(request)
	if err != nil {
		return nil, err
	}
	defer releaseBody()
	path := "/v1/runtime/evaluate/" + normalizeStage(request.Stage)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.httpURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	AttachHTTPAuth(httpReq, "POST "+path, body, c.sharedSecret, time.Now().UTC())
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, httpError(resp)
	}
	var decoded EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func grpcMethodForStage(stage string) string {
	switch normalizeStage(stage) {
	case StageOutput:
		return FullMethodOutput
	case StageAction:
		return FullMethodAction
	case StageMCP:
		return FullMethodMCP
	case StageRAG:
		return FullMethodRAG
	default:
		return FullMethodInput
	}
}

func normalizeStage(stage string) string {
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case StageOutput:
		return StageOutput
	case StageAction:
		return StageAction
	case StageMCP:
		return StageMCP
	case StageRAG:
		return StageRAG
	default:
		return StageInput
	}
}

func httpError(response *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("runtime returned %d: %s", response.StatusCode, strings.TrimSpace(string(raw)))
}
