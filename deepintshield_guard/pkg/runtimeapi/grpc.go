package runtimeapi

import (
	"context"
	"fmt"
	"time"

	json "github.com/deepint-shield/ai-security-guard/internal/jsonfast"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	ServiceName       = "deepintshield.guardruntime.v1.GuardRuntime"
	FullMethodPing    = "/" + ServiceName + "/Ping"
	FullMethodRefresh = "/" + ServiceName + "/RefreshTenant"
	FullMethodInput   = "/" + ServiceName + "/EvaluateInput"
	FullMethodOutput  = "/" + ServiceName + "/EvaluateOutput"
	FullMethodAction  = "/" + ServiceName + "/EvaluateAction"
	FullMethodMCP     = "/" + ServiceName + "/EvaluateMCP"
	FullMethodRAG     = "/" + ServiceName + "/EvaluateRAG"
)

// rawBytesHolder is implemented by request types that can cache the raw JSON
// bytes from gRPC decode.  The auth interceptor uses these cached bytes for
// HMAC computation instead of re-marshaling the request.
type rawBytesHolder interface {
	SetRawBytes([]byte)
	GetRawBytes() []byte
}

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	// Capture raw bytes on request types that support it so the auth
	// interceptor can skip a redundant json.Marshal round-trip.
	if holder, ok := v.(rawBytesHolder); ok {
		cp := make([]byte, len(data))
		copy(cp, data)
		holder.SetRawBytes(cp)
	}
	return nil
}
func (jsonCodec) Name() string { return "json" }

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

func JSONCodec() encoding.Codec {
	return jsonCodec{}
}

type GuardRuntimeServer interface {
	Ping(context.Context, *PingRequest) (*PingResponse, error)
	RefreshTenant(context.Context, *RefreshTenantRequest) (*RefreshTenantResponse, error)
	EvaluateInput(context.Context, *EvaluateRequest) (*EvaluateResponse, error)
	EvaluateOutput(context.Context, *EvaluateRequest) (*EvaluateResponse, error)
	EvaluateAction(context.Context, *EvaluateRequest) (*EvaluateResponse, error)
	EvaluateMCP(context.Context, *EvaluateRequest) (*EvaluateResponse, error)
	EvaluateRAG(context.Context, *EvaluateRequest) (*EvaluateResponse, error)
}

func RegisterGuardRuntimeServer(server *grpc.Server, implementation GuardRuntimeServer) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*GuardRuntimeServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Ping", Handler: unaryPingHandler(implementation)},
			{MethodName: "RefreshTenant", Handler: unaryRefreshHandler(implementation)},
			{MethodName: "EvaluateInput", Handler: unaryEvaluateHandler(implementation.EvaluateInput)},
			{MethodName: "EvaluateOutput", Handler: unaryEvaluateHandler(implementation.EvaluateOutput)},
			{MethodName: "EvaluateAction", Handler: unaryEvaluateHandler(implementation.EvaluateAction)},
			{MethodName: "EvaluateMCP", Handler: unaryEvaluateHandler(implementation.EvaluateMCP)},
			{MethodName: "EvaluateRAG", Handler: unaryEvaluateHandler(implementation.EvaluateRAG)},
		},
	}, implementation)
}

func unaryPingHandler(server GuardRuntimeServer) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := &PingRequest{}
		if err := dec(request); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return server.Ping(ctx, request)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: FullMethodPing}
		handler := func(ctx context.Context, req any) (any, error) {
			return server.Ping(ctx, req.(*PingRequest))
		}
		return interceptor(ctx, request, info, handler)
	}
}

func unaryRefreshHandler(server GuardRuntimeServer) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := &RefreshTenantRequest{}
		if err := dec(request); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return server.RefreshTenant(ctx, request)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: FullMethodRefresh}
		handler := func(ctx context.Context, req any) (any, error) {
			return server.RefreshTenant(ctx, req.(*RefreshTenantRequest))
		}
		return interceptor(ctx, request, info, handler)
	}
}

func unaryEvaluateHandler(fn func(context.Context, *EvaluateRequest) (*EvaluateResponse, error)) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := &EvaluateRequest{}
		if err := dec(request); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return fn(ctx, request)
		}
		fullMethod := FullMethodInput
		switch request.Stage {
		case StageOutput:
			fullMethod = FullMethodOutput
		case StageAction:
			fullMethod = FullMethodAction
		case StageMCP:
			fullMethod = FullMethodMCP
		case StageRAG:
			fullMethod = FullMethodRAG
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethod}
		handler := func(ctx context.Context, req any) (any, error) {
			return fn(ctx, req.(*EvaluateRequest))
		}
		return interceptor(ctx, request, info, handler)
	}
}

func AuthUnaryServerInterceptor(secret string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if secret == "" {
			return handler(ctx, req)
		}
		md, _ := metadata.FromIncomingContext(ctx)
		// Reuse the raw bytes captured during gRPC decode to avoid a
		// redundant json.Marshal round-trip for HMAC computation.
		var body []byte
		if holder, ok := req.(rawBytesHolder); ok {
			body = holder.GetRawBytes()
		}
		if len(body) == 0 {
			var err error
			body, err = json.Marshal(req)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to marshal request for auth: %v", err)
			}
		}
		if err := ValidateGRPCAuth(md, info.FullMethod, body, secret, time.Now().UTC()); err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(ctx, req)
	}
}

func AuthUnaryClientInterceptor(secret string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if secret == "" {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request for auth: %w", err)
		}
		authenticatedCtx := AttachGRPCAuth(ctx, method, body, secret, time.Now().UTC())
		return invoker(authenticatedCtx, method, req, reply, cc, opts...)
	}
}
