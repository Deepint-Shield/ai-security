package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security-guard/internal/engine"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

type Server struct {
	engine       *engine.Runtime
	mux          *http.ServeMux
	sharedSecret string
}

func NewServer(runtime *engine.Runtime, sharedSecret string) *Server {
	s := &Server{
		engine:       runtime,
		mux:          http.NewServeMux(),
		sharedSecret: strings.TrimSpace(sharedSecret),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/runtime/ping", s.handlePing)
	s.mux.HandleFunc("/v1/runtime/refresh-tenant", s.handleRefreshTenant)
	s.mux.HandleFunc("/v1/runtime/evaluate/input", s.handleEvaluate)
	s.mux.HandleFunc("/v1/runtime/evaluate/output", s.handleEvaluate)
	s.mux.HandleFunc("/v1/runtime/evaluate/action", s.handleEvaluate)
	s.mux.HandleFunc("/v1/runtime/evaluate/mcp", s.handleEvaluate)
	s.mux.HandleFunc("/v1/runtime/evaluate/rag", s.handleEvaluate)
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "deepintshield_guard",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost && !s.authenticateRequest(w, r, "POST /v1/runtime/ping") {
		return
	}
	writeJSON(w, http.StatusOK, runtimeapi.PingResponse{
		OK:      true,
		Service: "deepintshield_guard",
		Time:    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleRefreshTenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, ok := s.authenticateAndReadBody(w, r, "POST /v1/runtime/refresh-tenant")
	if !ok {
		return
	}
	var req RefreshTenantRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("invalid request: %v", err)})
			return
		}
	}
	if strings.TrimSpace(req.Bundle.TenantID) == "" {
		req.Bundle.TenantID = strings.TrimSpace(req.TenantID)
	}
	if s.engine != nil {
		s.engine.RefreshTenant(req.Bundle)
	}
	writeJSON(w, http.StatusOK, runtimeapi.RefreshTenantResponse{
		OK:         true,
		TenantID:   strings.TrimSpace(req.Bundle.TenantID),
		Revision:   strings.TrimSpace(req.Bundle.Revision),
		HydratedAt: req.Bundle.RefreshedAt,
		Message:    "tenant policy cache refreshed",
	})
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operation := "POST " + r.URL.Path
	body, ok := s.authenticateAndReadBody(w, r, operation)
	if !ok {
		return
	}
	var req EvaluateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("invalid request: %v", err),
		})
		return
	}
	if strings.TrimSpace(req.Stage) == "" {
		req.Stage = stageFromPath(r.URL.Path)
	}
	req.Stage = runtimeapi.NormalizeStage(req.Stage)
	result := s.engine.Evaluate(r.Context(), req)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authenticateRequest(w http.ResponseWriter, r *http.Request, operation string) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("failed to read request body: %v", err)})
		return false
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := runtimeapi.ValidateSignature(
		operation,
		body,
		r.Header.Get(runtimeapi.HeaderTimestamp),
		r.Header.Get(runtimeapi.HeaderSignature),
		r.Header.Get(runtimeapi.HeaderContentHash),
		s.sharedSecret,
		time.Now().UTC(),
	); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return false
	}
	return true
}

func (s *Server) authenticateAndReadBody(w http.ResponseWriter, r *http.Request, operation string) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("failed to read request body: %v", err)})
		return nil, false
	}
	if err := runtimeapi.ValidateSignature(
		operation,
		body,
		r.Header.Get(runtimeapi.HeaderTimestamp),
		r.Header.Get(runtimeapi.HeaderSignature),
		r.Header.Get(runtimeapi.HeaderContentHash),
		s.sharedSecret,
		time.Now().UTC(),
	); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return nil, false
	}
	return body, true
}

func stageFromPath(path string) string {
	switch {
	case strings.HasSuffix(path, "/output"):
		return runtimeapi.StageOutput
	case strings.HasSuffix(path, "/action"):
		return runtimeapi.StageAction
	case strings.HasSuffix(path, "/mcp"):
		return runtimeapi.StageMCP
	case strings.HasSuffix(path, "/rag"):
		return runtimeapi.StageRAG
	default:
		return runtimeapi.StageInput
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
