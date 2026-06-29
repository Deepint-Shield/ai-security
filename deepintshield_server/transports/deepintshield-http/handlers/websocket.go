// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains WebSocket handlers for real-time log streaming.
package handlers

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/fasthttp/websocket"
	"github.com/valyala/fasthttp"
)

// WebSocketClient represents a connected WebSocket client with its own mutex
type WebSocketClient struct {
	conn        *websocket.Conn
	tenantID    string
	workspaceID string     // Snapshot of X-Active-Workspace-Id at connect time. Used to gate workspace-scoped broadcasts so dev-ws traffic stops flashing into prod-ws live feeds. Empty = legacy connection, receives everything in the tenant.
	mu          sync.Mutex // Per-connection mutex for thread-safe writes
}

// WebSocketHandler manages WebSocket connections for real-time updates
type WebSocketHandler struct {
	ctx            context.Context
	allowedOrigins []string
	clients        map[*websocket.Conn]*WebSocketClient
	mu             sync.RWMutex
	stopChan       chan struct{} // Channel to signal heartbeat goroutine to stop
	done           chan struct{} // Channel to signal when heartbeat goroutine has stopped
}

// NewWebSocketHandler creates a new WebSocket handler instance
func NewWebSocketHandler(ctx context.Context, allowedOrigins []string) *WebSocketHandler {
	return &WebSocketHandler{
		ctx:            ctx,
		allowedOrigins: allowedOrigins,
		clients:        make(map[*websocket.Conn]*WebSocketClient),
		stopChan:       make(chan struct{}),
		done:           make(chan struct{}),
	}
}

// RegisterRoutes registers all WebSocket-related routes
func (h *WebSocketHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/ws", lib.ChainMiddlewares(h.connectStream, middlewares...))
}

// getUpgrader returns a WebSocket upgrader configured with the current allowed origins
func (h *WebSocketHandler) getUpgrader() websocket.FastHTTPUpgrader {
	return websocket.FastHTTPUpgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(ctx *fasthttp.RequestCtx) bool {
			origin := string(ctx.Request.Header.Peek("Origin"))
			if origin == "" {
				// If no Origin header, check the Host header for direct connections
				host := string(ctx.Request.Header.Peek("Host"))
				return isLocalhost(host)
			}
			// Check if origin is allowed (localhost always allowed + configured origins)
			return IsOriginAllowed(origin, h.allowedOrigins)
		},
	}
}

// isLocalhost checks if the given host is localhost
func isLocalhost(host string) bool {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check for localhost variations
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1" ||
		host == ""
}

// connectStream handles WebSocket connections for real-time streaming
func (h *WebSocketHandler) connectStream(ctx *fasthttp.RequestCtx) {
	upgrader := h.getUpgrader()
	err := upgrader.Upgrade(ctx, func(ws *websocket.Conn) {
		// Read safety & liveness
		ws.SetReadLimit(50 << 20) // 50 MiB
		ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})
		// Create a new client with its own mutex
		// Workspace is read from BOTH the context (stamped by middleware
		// from X-Active-Workspace-Id) and the query string (fallback for
		// clients that can't set custom headers on a WebSocket upgrade -
		// browsers can't, so the UI passes it as ?workspace_id=).
		wsID := strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyWorkspaceID)))
		if wsID == "" {
			wsID = strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id")))
		}
		client := &WebSocketClient{
			conn:        ws,
			tenantID:    strings.TrimSpace(stringValue(ctx.UserValue(schemas.DeepIntShieldContextKeyTenantID))),
			workspaceID: wsID,
		}

		// Register new client
		h.mu.Lock()
		h.clients[ws] = client
		h.mu.Unlock()

		// Clean up on disconnect
		defer func() {
			h.mu.Lock()
			delete(h.clients, ws)
			h.mu.Unlock()
			ws.Close()
		}()

		// Keep connection alive and handle client messages
		// This loop continuously reads and discards incoming WebSocket messages to:
		// 1. Keep the connection alive by processing client pings and control frames
		// 2. Detect when the client disconnects by watching for close frames or errors
		// 3. Maintain proper WebSocket protocol handling without accumulating messages
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				// Only log unexpected close errors
				if websocket.IsUnexpectedCloseError(err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseAbnormalClosure,
					websocket.CloseNoStatusReceived) {
					logger.Error("websocket read error: %v", err)
				}
				break
			}
		}
	})

	if err != nil {
		logger.Error("websocket upgrade error: %v", err)
		return
	}
}

// sendMessageSafely sends a message to a client with proper locking and error handling
func (h *WebSocketHandler) sendMessageSafely(client *WebSocketClient, messageType int, data []byte) error {
	client.mu.Lock()
	defer client.mu.Unlock()

	// Set a write deadline to prevent hanging connections
	client.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer client.conn.SetWriteDeadline(time.Time{}) // Clear the deadline

	err := client.conn.WriteMessage(messageType, data)
	if err != nil {
		// Remove the client from the map if write fails
		go func() {
			h.mu.Lock()
			delete(h.clients, client.conn)
			h.mu.Unlock()
			client.conn.Close()
		}()
	}

	return err
}

// BroadcastLogUpdate sends a log update to all connected WebSocket clients
func (h *WebSocketHandler) BroadcastLogUpdate(logEntry *logstore.Log) {
	// Nil guard to prevent panics
	if logEntry == nil {
		return
	}

	// Add panic recovery to prevent server crashes
	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic in BroadcastLogUpdate: %v", r)
		}
	}()

	// Determine operation type based on log status and timestamp
	operationType := "update"
	if logEntry.Status == "processing" && logEntry.CreatedAt.Equal(logEntry.Timestamp) {
		operationType = "create"
	}

	// Trim payload for table view: keep only the last input message and nil out
	// large output fields that the table never renders.
	if len(logEntry.InputHistoryParsed) > 1 {
		logEntry.InputHistoryParsed = logEntry.InputHistoryParsed[len(logEntry.InputHistoryParsed)-1:]
	}
	if len(logEntry.ResponsesInputHistoryParsed) > 1 {
		logEntry.ResponsesInputHistoryParsed = logEntry.ResponsesInputHistoryParsed[len(logEntry.ResponsesInputHistoryParsed)-1:]
	}
	logEntry.OutputMessageParsed = nil
	logEntry.ResponsesOutputParsed = nil
	logEntry.EmbeddingOutputParsed = nil
	logEntry.RerankOutputParsed = nil
	logEntry.ParamsParsed = nil
	logEntry.ToolsParsed = nil
	logEntry.ToolCallsParsed = nil
	logEntry.SpeechOutputParsed = nil
	logEntry.TranscriptionOutputParsed = nil
	logEntry.ImageGenerationOutputParsed = nil
	logEntry.ListModelsOutputParsed = nil

	message := struct {
		Type      string        `json:"type"`
		Operation string        `json:"operation"` // "create" or "update"
		Payload   *logstore.Log `json:"payload"`
	}{
		Type:      "log",
		Operation: operationType,
		Payload:   logEntry,
	}

	data, err := sonic.Marshal(message)
	if err != nil {
		logger.Error("failed to marshal log entry: %v", err)
		return
	}

	workspaceID := ""
	if logEntry.WorkspaceID != nil {
		workspaceID = strings.TrimSpace(*logEntry.WorkspaceID)
	}
	h.broadcastMarshaledMessageToWorkspace(logEntry.TenantID, workspaceID, data)
}

// BroadcastMCPLogUpdate sends an MCP tool log update to all connected WebSocket clients
func (h *WebSocketHandler) BroadcastMCPLogUpdate(logEntry *logstore.MCPToolLog) {
	// Nil guard to prevent panics
	if logEntry == nil {
		return
	}

	// Add panic recovery to prevent server crashes
	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic in BroadcastMCPLogUpdate: %v", r)
		}
	}()

	// Determine operation type based on log status and timestamp
	operationType := "update"
	if logEntry.Status == "processing" && logEntry.CreatedAt.Equal(logEntry.Timestamp) {
		operationType = "create"
	}

	message := struct {
		Type      string               `json:"type"`
		Operation string               `json:"operation"` // "create" or "update"
		Payload   *logstore.MCPToolLog `json:"payload"`
	}{
		Type:      "mcp_log",
		Operation: operationType,
		Payload:   logEntry,
	}

	data, err := sonic.Marshal(message)
	if err != nil {
		logger.Error("failed to marshal MCP log entry: %v", err)
		return
	}

	workspaceID := ""
	if logEntry.WorkspaceID != nil {
		workspaceID = strings.TrimSpace(*logEntry.WorkspaceID)
	}
	h.broadcastMarshaledMessageToWorkspace(logEntry.TenantID, workspaceID, data)
}

// BroadcastUpdatesToClients sends a store update notification to all connected WebSocket clients
// The tags parameter should match RTK Query tagTypes (e.g., "Providers", "VirtualKeys", "MCPClients")
func (h *WebSocketHandler) BroadcastUpdatesToClients(tags []string) {
	message := struct {
		Type string   `json:"type"`
		Tags []string `json:"tags"`
	}{
		Type: "store_update",
		Tags: tags,
	}

	data, err := sonic.Marshal(message)
	if err != nil {
		logger.Error("failed to marshal store update: %v", err)
		return
	}

	h.BroadcastMarshaledMessage(data)
}

// BroadcastEvent sends a typed event to all connected WebSocket clients.
// Any subsystem can use this to push real-time updates to the frontend.
func (h *WebSocketHandler) BroadcastEvent(eventType string, data interface{}) {
	message := struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: eventType,
		Data: data,
	}

	bytes, err := sonic.Marshal(message)
	if err != nil {
		logger.Error("failed to marshal event %s: %v", eventType, err)
		return
	}

	h.BroadcastMarshaledMessage(bytes)
}

// BroadcastMarshaledMessage sends an adaptive routing update to all connected WebSocket clients
func (h *WebSocketHandler) BroadcastMarshaledMessage(data []byte) {
	clients := h.snapshotAllClients()

	// Send message to each client safely
	for _, client := range clients {
		if err := h.sendMessageSafely(client, websocket.TextMessage, data); err != nil {
			logger.Error("failed to send message to client: %v", err)
		}
	}
}

func (h *WebSocketHandler) broadcastMarshaledMessageToTenant(tenantID string, data []byte) {
	clients := h.snapshotClientsForTenant(tenantID)

	// Send message to each client safely
	for _, client := range clients {
		if err := h.sendMessageSafely(client, websocket.TextMessage, data); err != nil {
			logger.Error("failed to send message to client: %v", err)
		}
	}
}

// broadcastMarshaledMessageToWorkspace fans out to clients matching BOTH the
// tenant and the workspace. Use it for payloads with a workspace_id (logs,
// MCP tool logs) so a request made on dev-ws never reaches a prod-ws live
// feed.
//
// Empty-workspace semantics: about half of the live log broadcasts arrive
// with an empty workspace_id because workspace stamping happens later in
// the persistence path (tenant_context.go) than the in-memory broadcast.
// We refuse to fan empty-workspace payloads out to workspace-pinned clients
// - they get dropped at the gate rather than treated as tenant-wide. The
// row still hits the database with its real workspace_id, and the next
// fetch on the UI picks it up correctly. Legacy clients (workspaceID == "")
// still receive everything so SDK/CLI consumers don't go silent.
func (h *WebSocketHandler) broadcastMarshaledMessageToWorkspace(tenantID, workspaceID string, data []byte) {
	clients := h.snapshotClientsForWorkspace(tenantID, workspaceID)
	for _, client := range clients {
		if err := h.sendMessageSafely(client, websocket.TextMessage, data); err != nil {
			logger.Error("failed to send message to client: %v", err)
		}
	}
}

func (h *WebSocketHandler) snapshotClientsForWorkspace(tenantID, workspaceID string) []*WebSocketClient {
	h.mu.RLock()
	defer h.mu.RUnlock()
	clients := make([]*WebSocketClient, 0, len(h.clients))
	msgWS := strings.TrimSpace(workspaceID)
	for _, client := range h.clients {
		if !shouldReceiveTenantBroadcast(client.tenantID, tenantID) {
			continue
		}
		// Strict rule for workspace-pinned clients (UI tabs): the payload's
		// workspace MUST match the client's. Empty payload workspace is
		// rejected for pinned clients - better to miss the live tick than
		// to flash a sibling workspace's row. The REST refetch fills the
		// gap a few seconds later with correctly-scoped rows.
		if client.workspaceID != "" {
			if client.workspaceID != msgWS {
				continue
			}
		}
		// client.workspaceID == "" → legacy SDK/CLI consumer; receive
		// everything in the tenant (unchanged behaviour for non-UI callers).
		clients = append(clients, client)
	}
	return clients
}

func (h *WebSocketHandler) snapshotAllClients() []*WebSocketClient {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]*WebSocketClient, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client)
	}
	return clients
}

func (h *WebSocketHandler) snapshotClientsForTenant(tenantID string) []*WebSocketClient {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]*WebSocketClient, 0, len(h.clients))
	for _, client := range h.clients {
		if shouldReceiveTenantBroadcast(client.tenantID, tenantID) {
			clients = append(clients, client)
		}
	}
	return clients
}

func shouldReceiveTenantBroadcast(clientTenantID, messageTenantID string) bool {
	return strings.TrimSpace(clientTenantID) == strings.TrimSpace(messageTenantID)
}

func stringValue(value any) string {
	if raw, ok := value.(string); ok {
		return raw
	}
	return ""
}

// StartHeartbeat starts sending periodic heartbeat messages to keep connections alive
func (h *WebSocketHandler) StartHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer func() {
			ticker.Stop()
			close(h.done)
		}()

		for {
			select {
			case <-h.ctx.Done():
				logger.Info("got context cancel(), stopping webserver")
				return
			case <-ticker.C:
				// Get a snapshot of clients to avoid holding the lock during writes
				h.mu.RLock()
				clients := make([]*WebSocketClient, 0, len(h.clients))
				for _, client := range h.clients {
					clients = append(clients, client)
				}
				h.mu.RUnlock()

				// Send heartbeat to each client safely
				for _, client := range clients {
					if err := h.sendMessageSafely(client, websocket.PingMessage, nil); err != nil {
						logger.Error("failed to send heartbeat: %v", err)
					}
				}
			case <-h.stopChan:
				return
			}
		}
	}()
}

// Stop gracefully shuts down the WebSocket handler
func (h *WebSocketHandler) Stop() {
	close(h.stopChan) // Signal heartbeat goroutine to stop
	<-h.done          // Wait for heartbeat goroutine to finish

	// Close all client connections
	h.mu.Lock()
	for _, client := range h.clients {
		client.conn.Close()
	}
	h.clients = make(map[*websocket.Conn]*WebSocketClient)
	h.mu.Unlock()
}
