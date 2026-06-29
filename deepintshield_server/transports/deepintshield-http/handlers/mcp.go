// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains MCP (Model Context Protocol) tool execution handlers.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/mcp"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/entitlements"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

type MCPManager interface {
	AddMCPClient(ctx context.Context, clientConfig *schemas.MCPClientConfig) error
	RemoveMCPClient(ctx context.Context, id string) error
	UpdateMCPClient(ctx context.Context, id string, updatedConfig *schemas.MCPClientConfig) error
	ReconnectMCPClient(ctx context.Context, id string) error
}

type MCPRuntimeClient interface {
	GetMCPClients() ([]schemas.MCPClient, error)
}

// MCPHandler manages HTTP requests for MCP tool operations
type MCPHandler struct {
	client     MCPRuntimeClient
	store      *lib.Config
	mcpManager MCPManager
}

// NewMCPHandler creates a new MCP handler instance
func NewMCPHandler(mcpManager MCPManager, client *deepintshield.DeepIntShield, store *lib.Config) *MCPHandler {
	return &MCPHandler{
		client:     client,
		store:      store,
		mcpManager: mcpManager,
	}
}

// RegisterRoutes registers all MCP-related routes
func (h *MCPHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/mcp/clients", lib.ChainMiddlewares(h.getMCPClients, middlewares...))
	r.POST("/api/mcp/client", lib.ChainMiddlewares(h.addMCPClient, middlewares...))
	r.PUT("/api/mcp/client/{id}", lib.ChainMiddlewares(h.updateMCPClient, middlewares...))
	r.PATCH("/api/mcp/client/{id}/workspace", lib.ChainMiddlewares(h.moveMCPClientWorkspace, middlewares...))
	r.DELETE("/api/mcp/client/{id}", lib.ChainMiddlewares(h.deleteMCPClient, middlewares...))
	r.POST("/api/mcp/client/{id}/reconnect", lib.ChainMiddlewares(h.reconnectMCPClient, middlewares...))
	r.POST("/api/mcp/client/{id}/complete-oauth", lib.ChainMiddlewares(h.completeMCPClientOAuth, middlewares...))
}

// MCPClientResponse represents the response structure for MCP clients
type MCPClientResponse struct {
	Config *schemas.MCPClientConfig   `json:"config"`
	Tools  []schemas.ChatToolFunction `json:"tools"`
	State  schemas.MCPConnectionState `json:"state"`
}

func (h *MCPHandler) isTenantScoped(ctx context.Context) bool {
	return h.store != nil && h.store.ConfigStore != nil && tenantctx.TenantIDFromContext(ctx) != ""
}

// moveMCPClientWorkspace handles PATCH /api/mcp/client/{id}/workspace -
// moves a client to a different workspace within the same tenant.
// Permission: caller must be able to manage both source and target
// workspaces (system admin / tenant admin / per-workspace admin on
// each side). Cross-tenant moves are rejected.
func (h *MCPHandler) moveMCPClientWorkspace(ctx *fasthttp.RequestCtx) {
	if h.store == nil || h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "MCP operations unavailable: config store is disabled")
		return
	}
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid id: %v", err))
		return
	}
	dbClient, err := h.store.ConfigStore.GetMCPClientByID(ctx, id)
	if err != nil || dbClient == nil {
		SendError(ctx, fasthttp.StatusNotFound, "MCP client not found")
		return
	}
	var req moveMCPClientWorkspaceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid JSON")
		return
	}
	target := strings.TrimSpace(req.WorkspaceID)
	if target == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "workspace_id is required")
		return
	}
	targetWS, err := h.store.ConfigStore.GetWorkspaceByID(ctx, target)
	if err != nil || targetWS == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Target workspace not found")
		return
	}
	if targetWS.OrgID != dbClient.TenantID {
		SendError(ctx, fasthttp.StatusBadRequest, "Cannot move MCP client across tenants")
		return
	}
	currentWS := ""
	if dbClient.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*dbClient.WorkspaceID)
	}
	if currentSessionUserRole(ctx) != configstoreTables.UserRoleAdmin {
		user := cachedAuthUserFromCtx(ctx)
		if user == nil {
			respondAuthError(ctx, errUnauthorizedSession)
			return
		}
		if currentWS != "" {
			if !CanManageWorkspaceByID(ctx, h.store.ConfigStore, user, currentWS) {
				SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the source workspace")
				return
			}
		} else if !CanManageTenant(ctx, h.store.ConfigStore, user, dbClient.TenantID) {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the source tenant")
			return
		}
		if !CanManageWorkspace(ctx, h.store.ConfigStore, user, targetWS) {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the target workspace")
			return
		}
	}
	dbClient.WorkspaceID = &target
	if err := h.store.ConfigStore.UpdateMCPClientConfig(ctx, id, dbClient); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to move MCP client: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"message": "MCP client moved",
		"from":    currentWS,
		"to":      target,
	})
}

type moveMCPClientWorkspaceRequest struct {
	WorkspaceID string `json:"workspace_id"`
}

// requireMCPClientWriteAccess gates destructive writes (update / delete)
// against the target client's workspace pinning. If the client is pinned
// to a workspace, the caller must hold workspace-admin (or org-level)
// rights on it; otherwise a tenant-level admin check applies. Returns
// non-nil error after writing the HTTP response - callers should bail
// out immediately. Uses context-cached identity to avoid a DB round-trip.
func (h *MCPHandler) requireMCPClientWriteAccess(ctx *fasthttp.RequestCtx, clientID string) error {
	// Fast path: system admins bypass.
	if currentSessionUserRole(ctx) == configstoreTables.UserRoleAdmin {
		return nil
	}
	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		respondAuthError(ctx, errUnauthorizedSession)
		return errUnauthorizedSession
	}
	dbClient, err := h.store.ConfigStore.GetMCPClientByID(ctx, clientID)
	if err != nil {
		// 404 / load errors are reported by the caller with friendlier
		// messaging; don't pre-empt them - fall through.
		return nil
	}
	if dbClient == nil {
		return nil
	}
	allowed := false
	if dbClient.WorkspaceID != nil && strings.TrimSpace(*dbClient.WorkspaceID) != "" {
		allowed = CanManageWorkspaceByID(ctx, h.store.ConfigStore, user, *dbClient.WorkspaceID)
	} else {
		allowed = CanManageTenant(ctx, h.store.ConfigStore, user, strings.TrimSpace(user.TenantID))
	}
	if !allowed {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins, tenant owners/admins, or system admins can modify MCP clients")
		return fmt.Errorf("forbidden")
	}
	return nil
}

func mcpClientConfigFromTable(dbClient *configstoreTables.TableMCPClient) *schemas.MCPClientConfig {
	if dbClient == nil {
		return nil
	}

	isPingAvailable := true
	if dbClient.IsPingAvailable != nil {
		isPingAvailable = *dbClient.IsPingAvailable
	}

	return &schemas.MCPClientConfig{
		ID:                 dbClient.ClientID,
		Name:               dbClient.Name,
		IsCodeModeClient:   dbClient.IsCodeModeClient,
		ConnectionType:     schemas.MCPConnectionType(dbClient.ConnectionType),
		ConnectionString:   dbClient.ConnectionString,
		StdioConfig:        dbClient.StdioConfig,
		AuthType:           schemas.MCPAuthType(dbClient.AuthType),
		OauthConfigID:      dbClient.OauthConfigID,
		ToolsToExecute:     dbClient.ToolsToExecute,
		ToolsToAutoExecute: dbClient.ToolsToAutoExecute,
		Headers:            dbClient.Headers,
		IsPingAvailable:    isPingAvailable,
		ToolSyncInterval:   time.Duration(dbClient.ToolSyncInterval) * time.Minute,
		ToolPricing:        dbClient.ToolPricing,
	}
}

func (h *MCPHandler) loadStoredMCPClientConfigs(ctx context.Context) ([]*schemas.MCPClientConfig, error) {
	if h.isTenantScoped(ctx) {
		storeConfig, err := h.store.ConfigStore.GetMCPConfig(ctx)
		if err != nil {
			return nil, err
		}
		if storeConfig == nil {
			return nil, nil
		}
		return storeConfig.ClientConfigs, nil
	}

	if h.store == nil || h.store.MCPConfig == nil {
		return nil, nil
	}
	return h.store.MCPConfig.ClientConfigs, nil
}

func (h *MCPHandler) getStoredMCPClientConfig(ctx context.Context, id string) (*schemas.MCPClientConfig, error) {
	if h.isTenantScoped(ctx) {
		dbClient, err := h.store.ConfigStore.GetMCPClientByID(ctx, id)
		if err != nil {
			return nil, err
		}
		return mcpClientConfigFromTable(dbClient), nil
	}

	if h.store != nil && h.store.MCPConfig != nil {
		for i, client := range h.store.MCPConfig.ClientConfigs {
			if client.ID == id {
				return h.store.MCPConfig.ClientConfigs[i], nil
			}
		}
	}

	if h.store == nil || h.store.ConfigStore == nil {
		return nil, configstore.ErrNotFound
	}
	dbClient, err := h.store.ConfigStore.GetMCPClientByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return mcpClientConfigFromTable(dbClient), nil
}

func (h *MCPHandler) buildMCPClientResponses(configs []*schemas.MCPClientConfig) ([]MCPClientResponse, error) {
	if h.client == nil {
		return nil, fmt.Errorf("MCP runtime client is not configured")
	}

	clientsInDeepIntShield, err := h.client.GetMCPClients()
	if err != nil {
		return nil, fmt.Errorf("failed to get MCP clients from DeepIntShield: %w", err)
	}

	connectedClientsMap := make(map[string]schemas.MCPClient, len(clientsInDeepIntShield))
	for _, client := range clientsInDeepIntShield {
		connectedClientsMap[client.Config.ID] = client
	}

	clients := make([]MCPClientResponse, 0, len(configs))
	for _, configClient := range configs {
		redactedConfig := h.store.RedactMCPClientConfig(configClient)
		if connectedClient, exists := connectedClientsMap[configClient.ID]; exists {
			sortedTools := make([]schemas.ChatToolFunction, len(connectedClient.Tools))
			copy(sortedTools, connectedClient.Tools)
			sort.Slice(sortedTools, func(i, j int) bool {
				return sortedTools[i].Name < sortedTools[j].Name
			})

			clients = append(clients, MCPClientResponse{
				Config: redactedConfig,
				Tools:  sortedTools,
				State:  connectedClient.State,
			})
			continue
		}

		clients = append(clients, MCPClientResponse{
			Config: redactedConfig,
			Tools:  []schemas.ChatToolFunction{},
			State:  schemas.MCPConnectionStateError,
		})
	}

	return clients, nil
}

// getMCPClients handles GET /api/mcp/clients - Get all MCP clients
func (h *MCPHandler) getMCPClients(ctx *fasthttp.RequestCtx) {
	emptyResponse := map[string]interface{}{
		"clients":     []MCPClientResponse{},
		"count":       0,
		"total_count": 0,
		"limit":       0,
		"offset":      0,
	}
	if h.store.ConfigStore == nil {
		SendJSON(ctx, emptyResponse)
		return
	}

	// Check if pagination params are present - if so, use paginated DB path
	limitStr := string(ctx.QueryArgs().Peek("limit"))
	offsetStr := string(ctx.QueryArgs().Peek("offset"))
	searchStr := string(ctx.QueryArgs().Peek("search"))

	if limitStr != "" || offsetStr != "" || searchStr != "" {
		h.getMCPClientsPaginated(ctx, limitStr, offsetStr, searchStr)
		return
	}

	configsInStore, err := h.loadStoredMCPClientConfigs(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get MCP client config: %v", err))
		return
	}
	if len(configsInStore) == 0 {
		SendJSON(ctx, emptyResponse)
		return
	}

	clients, err := h.buildMCPClientResponses(configsInStore)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"clients":     clients,
		"count":       len(clients),
		"total_count": len(clients),
		"limit":       len(clients),
		"offset":      0,
	})
}

// getMCPClientsPaginated handles the paginated path for GET /api/mcp/clients
func (h *MCPHandler) getMCPClientsPaginated(ctx *fasthttp.RequestCtx, limitStr, offsetStr, searchStr string) {
	// Optional ?workspace_id= query param wins; otherwise fall back to the
	// sidebar's active workspace stamped on the request context. Empty
	// returns the full tenant view (legacy behaviour).
	workspaceID := strings.TrimSpace(string(ctx.QueryArgs().Peek("workspace_id")))
	if workspaceID == "" {
		workspaceID = tenantctx.WorkspaceIDFromContext(ctx)
	}
	params := configstore.MCPClientsQueryParams{
		Search:      searchStr,
		WorkspaceID: workspaceID,
	}
	if limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil {
			SendError(ctx, 400, "Invalid limit parameter: must be a number")
			return
		}
		if n < 0 {
			SendError(ctx, 400, "Invalid limit parameter: must be non-negative")
			return
		}
		params.Limit = n
	}
	if offsetStr != "" {
		n, err := strconv.Atoi(offsetStr)
		if err != nil {
			SendError(ctx, 400, "Invalid offset parameter: must be a number")
			return
		}
		if n < 0 {
			SendError(ctx, 400, "Invalid offset parameter: must be non-negative")
			return
		}
		params.Offset = n
	}

	dbClients, totalCount, err := h.store.ConfigStore.GetMCPClientsPaginated(ctx, params)
	if err != nil {
		logger.Error("failed to retrieve MCP clients: %v", err)
		SendError(ctx, 500, "Failed to retrieve MCP clients")
		return
	}

	configs := make([]*schemas.MCPClientConfig, 0, len(dbClients))
	for i := range dbClients {
		configs = append(configs, mcpClientConfigFromTable(&dbClients[i]))
	}

	clients, err := h.buildMCPClientResponses(configs)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"clients":     clients,
		"count":       len(clients),
		"total_count": totalCount,
		"limit":       params.Limit,
		"offset":      params.Offset,
	})
}

// reconnectMCPClient handles POST /api/mcp/client/{id}/reconnect - Reconnect an MCP client
func (h *MCPHandler) reconnectMCPClient(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "MCP operations unavailable: config store is disabled")
		return
	}
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid id: %v", err))
		return
	}
	if err := h.mcpManager.ReconnectMCPClient(ctx, id); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to reconnect MCP client: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "MCP client reconnected successfully",
	})
}

// OAuthConfigRequest represents OAuth configuration in the request
type OAuthConfigRequest struct {
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	AuthorizeURL    string   `json:"authorize_url"`
	TokenURL        string   `json:"token_url"`
	RegistrationURL string   `json:"registration_url"`
	Scopes          []string `json:"scopes"`
}

// MCPClientRequest represents the full MCP client creation request with OAuth support
type MCPClientRequest struct {
	configstoreTables.TableMCPClient
	OauthConfig *OAuthConfigRequest `json:"oauth_config,omitempty"`
}

// addMCPClient handles POST /api/mcp/client - Add a new MCP client
func (h *MCPHandler) addMCPClient(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "MCP operations unavailable: config store is disabled")
		return
	}
	// Workspace-write permission check. Fast paths: system admins bypass;
	// non-tenant-scoped (legacy) deployments bypass entirely.
	if h.isTenantScoped(ctx) && currentSessionUserRole(ctx) != configstoreTables.UserRoleAdmin {
		user := cachedAuthUserFromCtx(ctx)
		if user == nil {
			respondAuthError(ctx, errUnauthorizedSession)
			return
		}
		ws := tenantctx.WorkspaceIDFromContext(ctx)
		allowed := false
		if ws != "" {
			allowed = CanManageWorkspaceByID(ctx, h.store.ConfigStore, user, ws)
		} else {
			allowed = CanManageTenant(ctx, h.store.ConfigStore, user, strings.TrimSpace(user.TenantID))
		}
		if !allowed {
			SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins, tenant owners/admins, or system admins can create MCP clients")
			return
		}
	}
	var req MCPClientRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Generate a unique client ID if not provided
	if req.ClientID == "" {
		req.ClientID = uuid.New().String()
	}

	if err := validateToolsToExecute(req.ToolsToExecute); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid tools_to_execute: %v", err))
		return
	}
	// Auto-clear tools_to_auto_execute if tools_to_execute is empty
	// If no tools are allowed to execute, no tools can be auto-executed
	if len(req.ToolsToExecute) == 0 {
		req.ToolsToAutoExecute = []string{}
	}
	if err := validateToolsToAutoExecute(req.ToolsToAutoExecute, req.ToolsToExecute); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid tools_to_auto_execute: %v", err))
		return
	}
	if err := mcp.ValidateMCPClientName(req.Name); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid client name: %v", err))
		return
	}

	// Plan-tier quota: block creates over the cap. Count is taken from
	// the mcp_clients table itself so it stays consistent with on-disk
	// truth across retries; -1 = unlimited (Enterprise) short-circuits
	// cleanly inside EnforceQuota.
	if org, _, orgErr := CurrentOrgFromCtx(ctx, h.store.ConfigStore); orgErr == nil && org != nil {
		var serverCount int64
		if db := h.store.ConfigStore.DB(); db != nil {
			_ = db.WithContext(ctx).
				Model(&configstoreTables.TableMCPClient{}).
				Where("tenant_id = ?", org.ID).
				Count(&serverCount).Error
		}
		if err := entitlements.EnforceQuota(ctx, h.store.ConfigStore.DB(), org, entitlements.LimitMCPServers, serverCount); err != nil {
			if qe, ok := err.(*entitlements.QuotaError); ok {
				SendJSONWithStatus(ctx, map[string]any{
					"error":     err.Error(),
					"code":      "QUOTA_EXCEEDED",
					"limit_key": qe.LimitKey,
					"limit":     qe.Limit,
					"current":   qe.Current,
					"plan":      qe.Plan,
					"feature":   qe.Feature,
				}, fasthttp.StatusPaymentRequired)
				return
			}
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
	}

	// OAuth-authenticated MCP clients are part of the commercial build.
	if req.AuthType == "oauth" {
		SendError(ctx, fasthttp.StatusNotImplemented, "OAuth-authenticated MCP clients are not available in the open-source build")
		return
	}

	toolSyncInterval := mcp.DefaultToolSyncInterval
	if req.ToolSyncInterval != 0 {
		toolSyncInterval = time.Duration(req.ToolSyncInterval) * time.Minute
	} else {
		config, err := h.store.ConfigStore.GetClientConfig(ctx)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get client config: %v", err))
			return
		}
		if config != nil {
			toolSyncInterval = time.Duration(config.MCPToolSyncInterval) * time.Minute
		}
	}

	// Convert to schemas.MCPClientConfig for runtime deepintshield client (without tool_pricing)
	// Dereference IsPingAvailable pointer, defaulting to true if nil (new clients default to ping available)
	isPingAvailable := true
	if req.IsPingAvailable != nil {
		isPingAvailable = *req.IsPingAvailable
	}
	schemasConfig := &schemas.MCPClientConfig{
		ID:                 req.ClientID,
		Name:               req.Name,
		IsCodeModeClient:   req.IsCodeModeClient,
		ConnectionType:     schemas.MCPConnectionType(req.ConnectionType),
		ConnectionString:   req.ConnectionString,
		StdioConfig:        req.StdioConfig,
		ToolsToExecute:     req.ToolsToExecute,
		ToolsToAutoExecute: req.ToolsToAutoExecute,
		Headers:            req.Headers,
		AuthType:           schemas.MCPAuthType(req.AuthType),
		OauthConfigID:      req.OauthConfigID,
		IsPingAvailable:    isPingAvailable,
		ToolSyncInterval:   toolSyncInterval,
		ToolPricing:        req.ToolPricing,
	}

	// Creating MCP client config in config store
	if h.store.ConfigStore != nil {
		if err := h.store.ConfigStore.CreateMCPClientConfig(ctx, schemasConfig); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create MCP config: %v", err))
			return
		}
	}
	if err := h.mcpManager.AddMCPClient(ctx, schemasConfig); err != nil {
		// Delete the created config from config store
		if h.store.ConfigStore != nil {
			if err := h.store.ConfigStore.DeleteMCPClientConfig(ctx, schemasConfig.ID); err != nil {
				logger.Error(fmt.Sprintf("Failed to delete MCP client config from database: %v. please restart deepintshield to keep core and database in sync", err))
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete MCP client config from database: %v. please restart deepintshield to keep core and database in sync", err))
				return
			}
		}
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to connect MCP client: %v", err))
		return
	}

	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "MCP client connected successfully",
	})
}

// updateMCPClient handles PUT /api/mcp/client/{id} - Edit MCP client
func (h *MCPHandler) updateMCPClient(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "MCP operations unavailable: config store is disabled")
		return
	}
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid id: %v", err))
		return
	}
	if h.isTenantScoped(ctx) {
		if err := h.requireMCPClientWriteAccess(ctx, id); err != nil {
			return
		}
	}
	// Accept the full table client config to support tool_pricing
	var req *configstoreTables.TableMCPClient
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	req.ClientID = id
	// Validate tools_to_execute
	if err := validateToolsToExecute(req.ToolsToExecute); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid tools_to_execute: %v", err))
		return
	}
	// Auto-clear tools_to_auto_execute if tools_to_execute is empty
	// If no tools are allowed to execute, no tools can be auto-executed
	if len(req.ToolsToExecute) == 0 {
		req.ToolsToAutoExecute = []string{}
	}
	// Validate tools_to_auto_execute
	if err := validateToolsToAutoExecute(req.ToolsToAutoExecute, req.ToolsToExecute); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid tools_to_auto_execute: %v", err))
		return
	}
	// Validate client name
	if err := mcp.ValidateMCPClientName(req.Name); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid client name: %v", err))
		return
	}
	existingConfig, err := h.getStoredMCPClientConfig(ctx, id)
	if err != nil {
		if err == configstore.ErrNotFound {
			SendError(ctx, fasthttp.StatusNotFound, "MCP client not found")
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get existing mcp client config: %v", err))
		return
	}

	// Merge redacted values - preserve old values if incoming values are redacted and unchanged
	req = mergeMCPRedactedValues(req, existingConfig, h.store.RedactMCPClientConfig(existingConfig))
	// Save existing DB config before update so we can rollback if memory update fails
	var oldDBConfig *configstoreTables.TableMCPClient
	if h.store.ConfigStore != nil {
		var err error
		oldDBConfig, err = h.store.ConfigStore.GetMCPClientByID(ctx, id)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get existing mcp client config: %v", err))
			return
		}
	}
	// Persist changes to config store
	if h.store.ConfigStore != nil {
		if err := h.store.ConfigStore.UpdateMCPClientConfig(ctx, id, req); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to update mcp client config in store: %v", err))
			return
		}
	}
	toolSyncInterval := mcp.DefaultToolSyncInterval
	if req.ToolSyncInterval != 0 {
		toolSyncInterval = time.Duration(req.ToolSyncInterval) * time.Minute
	} else {
		config, err := h.store.ConfigStore.GetClientConfig(ctx)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get client config: %v", err))
			return
		}
		if config != nil {
			toolSyncInterval = time.Duration(config.MCPToolSyncInterval) * time.Minute
		}
	}
	// Convert to schemas.MCPClientConfig for runtime deepintshield client (without tool_pricing)
	isPingAvailable := true
	if req.IsPingAvailable != nil {
		isPingAvailable = *req.IsPingAvailable
	}
	schemasConfig := &schemas.MCPClientConfig{
		ID:                 req.ClientID,
		Name:               req.Name,
		IsCodeModeClient:   req.IsCodeModeClient,
		ConnectionType:     existingConfig.ConnectionType,
		ConnectionString:   existingConfig.ConnectionString,
		StdioConfig:        existingConfig.StdioConfig,
		ToolsToExecute:     req.ToolsToExecute,
		ToolsToAutoExecute: req.ToolsToAutoExecute,
		Headers:            req.Headers,
		AuthType:           existingConfig.AuthType,
		OauthConfigID:      existingConfig.OauthConfigID,
		IsPingAvailable:    isPingAvailable,
		ToolSyncInterval:   toolSyncInterval,
		ToolPricing:        req.ToolPricing,
	}
	// Update MCP client in memory
	if err := h.mcpManager.UpdateMCPClient(ctx, id, schemasConfig); err != nil {
		// Rollback DB update to keep DB and memory in sync
		if h.store.ConfigStore != nil && oldDBConfig != nil {
			if rollbackErr := h.store.ConfigStore.UpdateMCPClientConfig(ctx, id, oldDBConfig); rollbackErr != nil {
				logger.Error(fmt.Sprintf("Failed to rollback MCP client DB update: %v. please restart deepintshield to keep core and database in sync", rollbackErr))
			}
		}
		logger.Error(fmt.Sprintf("Failed to update MCP client: %v", err))
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to update mcp client: %v", err))
		return
	}

	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "MCP client edited successfully",
	})
}

// deleteMCPClient handles DELETE /api/mcp/client/{id} - Remove an MCP client
func (h *MCPHandler) deleteMCPClient(ctx *fasthttp.RequestCtx) {
	if h.store.ConfigStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "MCP operations unavailable: config store is disabled")
		return
	}
	id, err := getIDFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid id: %v", err))
		return
	}
	if h.isTenantScoped(ctx) {
		if err := h.requireMCPClientWriteAccess(ctx, id); err != nil {
			return
		}
	}
	// Delete from DB first to avoid memory/DB inconsistency if DB delete fails
	if h.store.ConfigStore != nil {
		if err := h.store.ConfigStore.DeleteMCPClientConfig(ctx, id); err != nil {
			logger.Error(fmt.Sprintf("Failed to delete MCP client config from database: %v", err))
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to delete MCP config: %v", err))
			return
		}
	}
	if err := h.mcpManager.RemoveMCPClient(ctx, id); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to remove MCP client: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"status":  "success",
		"message": "MCP client removed successfully",
	})
}

func getIDFromCtx(ctx *fasthttp.RequestCtx) (string, error) {
	idValue := ctx.UserValue("id")
	if idValue == nil {
		return "", fmt.Errorf("missing id parameter")
	}
	idStr, ok := idValue.(string)
	if !ok {
		return "", fmt.Errorf("invalid id parameter type")
	}

	return idStr, nil
}

func validateToolsToExecute(toolsToExecute []string) error {
	if len(toolsToExecute) > 0 {
		// Check if wildcard "*" is combined with other tool names
		hasWildcard := slices.Contains(toolsToExecute, "*")
		if hasWildcard && len(toolsToExecute) > 1 {
			return fmt.Errorf("invalid tools_to_execute: wildcard '*' cannot be combined with other tool names")
		}

		// Check for duplicate entries
		seen := make(map[string]bool)
		for _, tool := range toolsToExecute {
			if seen[tool] {
				return fmt.Errorf("invalid tools_to_execute: duplicate tool name '%s'", tool)
			}
			seen[tool] = true
		}
	}

	return nil
}

func validateToolsToAutoExecute(toolsToAutoExecute []string, toolsToExecute []string) error {
	if len(toolsToAutoExecute) > 0 {
		// Check if wildcard "*" is combined with other tool names
		hasWildcard := slices.Contains(toolsToAutoExecute, "*")
		if hasWildcard && len(toolsToAutoExecute) > 1 {
			return fmt.Errorf("wildcard '*' cannot be combined with other tool names")
		}

		// Check for duplicate entries
		seen := make(map[string]bool)
		for _, tool := range toolsToAutoExecute {
			if seen[tool] {
				return fmt.Errorf("duplicate tool name '%s'", tool)
			}
			seen[tool] = true
		}

		// Check that all tools in ToolsToAutoExecute are also in ToolsToExecute
		// Create a set of allowed tools from ToolsToExecute
		allowedTools := make(map[string]bool)
		hasWildcardInExecute := slices.Contains(toolsToExecute, "*")
		if hasWildcardInExecute {
			// If "*" is in ToolsToExecute, all tools are allowed
			return nil
		}
		for _, tool := range toolsToExecute {
			allowedTools[tool] = true
		}

		// Validate each tool in ToolsToAutoExecute
		for _, tool := range toolsToAutoExecute {
			if tool == "*" {
				// Wildcard is allowed if "*" is in ToolsToExecute
				if !hasWildcardInExecute {
					return fmt.Errorf("tool '%s' in tools_to_auto_execute is not in tools_to_execute", tool)
				}
			} else if !allowedTools[tool] {
				return fmt.Errorf("tool '%s' in tools_to_auto_execute is not in tools_to_execute", tool)
			}
		}
	}

	return nil
}

// mergeMCPRedactedValues merges incoming MCP client config with existing config,
// preserving old values when incoming values are redacted and unchanged.
// This follows the same pattern as provider config updates.
func mergeMCPRedactedValues(incoming *configstoreTables.TableMCPClient, oldRaw, oldRedacted *schemas.MCPClientConfig) *configstoreTables.TableMCPClient {
	merged := incoming

	// Handle ConnectionString - if incoming is redacted and equals old redacted, keep old raw value
	if incoming.ConnectionString != nil && oldRaw.ConnectionString != nil && oldRedacted.ConnectionString != nil {
		if incoming.ConnectionString.IsRedacted() && incoming.ConnectionString.Equals(oldRedacted.ConnectionString) {
			merged.ConnectionString = oldRaw.ConnectionString
		}
	}

	// Handle Headers - merge incoming with old, preserving redacted values
	if incoming.Headers != nil {
		incomingHeaders := incoming.Headers
		merged.Headers = make(map[string]schemas.EnvVar, len(incomingHeaders))
		for key, incomingValue := range incomingHeaders {
			if oldRaw.Headers != nil && oldRedacted.Headers != nil {
				if oldRedactedValue, existsInRedacted := oldRedacted.Headers[key]; existsInRedacted {
					if oldRawValue, existsInRaw := oldRaw.Headers[key]; existsInRaw {
						if incomingValue.IsRedacted() && incomingValue.Equals(&oldRedactedValue) {
							merged.Headers[key] = oldRawValue
							continue
						}
					}
				}
			}
			merged.Headers[key] = incomingValue
		}
	} else if oldRaw.Headers != nil {
		merged.Headers = oldRaw.Headers
	}

	// Preserve IsPingAvailable if not explicitly set in incoming request
	// This prevents the zero-value (false) from overwriting the existing DB value
	if incoming.IsPingAvailable == nil {
		merged.IsPingAvailable = deepintshield.Ptr(oldRaw.IsPingAvailable)
	}

	return merged
}

// completeMCPClientOAuth handles POST /api/mcp/client/{id}/complete-oauth.
// OAuth-authenticated MCP clients are part of the commercial build, so the
// open-source build replies 501.
func (h *MCPHandler) completeMCPClientOAuth(ctx *fasthttp.RequestCtx) {
	SendError(ctx, fasthttp.StatusNotImplemented, "OAuth-authenticated MCP clients are not available in the open-source build")
}
