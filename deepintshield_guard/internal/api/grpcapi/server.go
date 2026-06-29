package grpcapi

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/engine"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
	"google.golang.org/grpc"
)

type Server struct {
	runtime *engine.Runtime
	grpc    *grpc.Server
}

func NewServer(runtime *engine.Runtime, sharedSecret string) *Server {
	server := &Server{
		runtime: runtime,
		grpc: grpc.NewServer(
			grpc.ForceServerCodec(runtimeapi.JSONCodec()),
			grpc.UnaryInterceptor(runtimeapi.AuthUnaryServerInterceptor(strings.TrimSpace(sharedSecret))),
		),
	}
	runtimeapi.RegisterGuardRuntimeServer(server.grpc, server)
	return server
}

func (s *Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.grpc.Serve(listener)
}

func (s *Server) Stop() {
	if s != nil && s.grpc != nil {
		s.grpc.GracefulStop()
	}
}

func (s *Server) Ping(ctx context.Context, req *runtimeapi.PingRequest) (*runtimeapi.PingResponse, error) {
	_ = req
	return &runtimeapi.PingResponse{
		OK:      true,
		Service: "deepintshield_guard",
		Time:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *Server) RefreshTenant(ctx context.Context, req *runtimeapi.RefreshTenantRequest) (*runtimeapi.RefreshTenantResponse, error) {
	_ = ctx
	if req != nil {
		if strings.TrimSpace(req.Bundle.TenantID) == "" {
			req.Bundle.TenantID = strings.TrimSpace(req.TenantID)
		}
		s.runtime.RefreshTenant(req.Bundle)
		return &runtimeapi.RefreshTenantResponse{
			OK:         true,
			TenantID:   req.Bundle.TenantID,
			Revision:   req.Bundle.Revision,
			HydratedAt: req.Bundle.RefreshedAt,
			Message:    "tenant policy cache refreshed",
		}, nil
	}
	return &runtimeapi.RefreshTenantResponse{OK: true, Message: "no tenant bundle provided"}, nil
}

func (s *Server) EvaluateInput(ctx context.Context, req *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	response := s.runtime.Evaluate(ctx, withStage(req, runtimeapi.StageInput))
	return &response, nil
}

func (s *Server) EvaluateOutput(ctx context.Context, req *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	response := s.runtime.Evaluate(ctx, withStage(req, runtimeapi.StageOutput))
	return &response, nil
}

func (s *Server) EvaluateAction(ctx context.Context, req *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	response := s.runtime.Evaluate(ctx, withStage(req, runtimeapi.StageAction))
	return &response, nil
}

func (s *Server) EvaluateMCP(ctx context.Context, req *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	response := s.runtime.Evaluate(ctx, withStage(req, runtimeapi.StageMCP))
	return &response, nil
}

func (s *Server) EvaluateRAG(ctx context.Context, req *runtimeapi.EvaluateRequest) (*runtimeapi.EvaluateResponse, error) {
	response := s.runtime.Evaluate(ctx, withStage(req, runtimeapi.StageRAG))
	return &response, nil
}

func withStage(req *runtimeapi.EvaluateRequest, stage string) runtimeapi.EvaluateRequest {
	if req == nil {
		return runtimeapi.EvaluateRequest{Stage: stage}
	}
	copy := *req
	copy.Stage = stage
	return copy
}
