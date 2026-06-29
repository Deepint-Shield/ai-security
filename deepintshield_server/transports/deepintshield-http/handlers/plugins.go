package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/plugins"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

type PluginsLoader interface {
	ReloadPlugin(ctx context.Context, name string, path *string, pluginConfig any, placement *schemas.PluginPlacement, order *int) error
	RemovePlugin(ctx context.Context, name string) error
	GetPluginStatus(ctx context.Context) map[string]schemas.PluginStatus
}

// PluginsHandler is the handler for the plugins API
type PluginsHandler struct {
	configStore   configstore.ConfigStore
	pluginsLoader PluginsLoader
}

// NewPluginsHandler creates a new PluginsHandler
func NewPluginsHandler(pluginsLoader PluginsLoader, configStore configstore.ConfigStore) *PluginsHandler {
	return &PluginsHandler{
		pluginsLoader: pluginsLoader,
		configStore:   configStore,
	}
}

// CreatePluginRequest is the request body for creating a plugin
type CreatePluginRequest struct {
	Name      string                   `json:"name"`
	Enabled   bool                     `json:"enabled"`
	Config    map[string]any           `json:"config"`
	Path      *string                  `json:"path"`
	Placement *schemas.PluginPlacement `json:"placement,omitempty"`
	Order     *int                     `json:"order,omitempty"`
}

// UpdatePluginRequest is the request body for updating a plugin
type UpdatePluginRequest struct {
	Enabled   bool                     `json:"enabled"`
	Path      *string                  `json:"path"`
	Config    map[string]any           `json:"config"`
	Placement *schemas.PluginPlacement `json:"placement,omitempty"`
	Order     *int                     `json:"order,omitempty"`
}

// RegisterRoutes registers the routes for the PluginsHandler
func (h *PluginsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/plugins", lib.ChainMiddlewares(h.getPlugins, middlewares...))
	r.GET("/api/plugins/{name}", lib.ChainMiddlewares(h.getPlugin, middlewares...))
	r.POST("/api/plugins", lib.ChainMiddlewares(h.createPlugin, middlewares...))
	r.PUT("/api/plugins/{name}", lib.ChainMiddlewares(h.updatePlugin, middlewares...))
	r.PATCH("/api/plugins/{name}/workspace", lib.ChainMiddlewares(h.movePluginWorkspace, middlewares...))
	r.DELETE("/api/plugins/{name}", lib.ChainMiddlewares(h.deletePlugin, middlewares...))
}

type PluginResponse struct {
	Name       string                   `json:"name"`
	ActualName string                   `json:"actualName"`
	Enabled    bool                     `json:"enabled"`
	Config     any                      `json:"config"`
	IsCustom   bool                     `json:"isCustom"`
	Path       *string                  `json:"path"`
	Placement  *schemas.PluginPlacement `json:"placement,omitempty"`
	Order      *int                     `json:"order,omitempty"`
	Status     schemas.PluginStatus     `json:"status"`
}

type movePluginWorkspaceRequest struct {
	WorkspaceID string `json:"workspace_id"`
}

// movePluginWorkspace handles PATCH /api/plugins/{name}/workspace -
// moves a plugin to a different workspace within the same tenant.
// Permission: caller must manage source AND target workspaces.
func (h *PluginsHandler) movePluginWorkspace(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Plugin operations require a config store")
		return
	}
	name, ok := ctx.UserValue("name").(string)
	if !ok || strings.TrimSpace(name) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Plugin name is required")
		return
	}
	plugin, err := h.configStore.GetPlugin(ctx, name)
	if err != nil || plugin == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Plugin not found")
		return
	}
	var req movePluginWorkspaceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid JSON")
		return
	}
	target := strings.TrimSpace(req.WorkspaceID)
	if target == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "workspace_id is required")
		return
	}
	targetWS, err := h.configStore.GetWorkspaceByID(ctx, target)
	if err != nil || targetWS == nil {
		SendError(ctx, fasthttp.StatusNotFound, "Target workspace not found")
		return
	}
	if targetWS.OrgID != plugin.TenantID {
		SendError(ctx, fasthttp.StatusBadRequest, "Cannot move plugin across tenants")
		return
	}
	currentWS := ""
	if plugin.WorkspaceID != nil {
		currentWS = strings.TrimSpace(*plugin.WorkspaceID)
	}
	if currentSessionUserRole(ctx) != configstoreTables.UserRoleAdmin {
		user := cachedAuthUserFromCtx(ctx)
		if user == nil {
			respondAuthError(ctx, errUnauthorizedSession)
			return
		}
		if currentWS != "" {
			if !CanManageWorkspaceByID(ctx, h.configStore, user, currentWS) {
				SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the source workspace")
				return
			}
		} else if !CanManageTenant(ctx, h.configStore, user, plugin.TenantID) {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the source tenant")
			return
		}
		if !CanManageWorkspace(ctx, h.configStore, user, targetWS) {
			SendError(ctx, fasthttp.StatusForbidden, "Forbidden: caller cannot manage the target workspace")
			return
		}
	}
	plugin.WorkspaceID = &target
	if err := h.configStore.UpdatePlugin(ctx, plugin); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to move plugin: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"message": "Plugin moved",
		"from":    currentWS,
		"to":      target,
	})
}

// requireWorkspaceWrite gates destructive plugin writes against the
// caller's workspace permission. Empty workspaceID falls back to a
// tenant-level admin check. Mirrors GovernanceHandler.requireWorkspaceWrite
// - see that comment for the fast-path rationale.
func (h *PluginsHandler) requireWorkspaceWrite(ctx *fasthttp.RequestCtx, workspaceID string) bool {
	if h.configStore == nil {
		return true
	}
	if tenantctx.TenantIDFromContext(ctx) == "" {
		return true
	}
	if currentSessionUserRole(ctx) == configstoreTables.UserRoleAdmin {
		return true
	}
	user := cachedAuthUserFromCtx(ctx)
	if user == nil {
		respondAuthError(ctx, errUnauthorizedSession)
		return false
	}
	allowed := false
	if strings.TrimSpace(workspaceID) != "" {
		allowed = CanManageWorkspaceByID(ctx, h.configStore, user, workspaceID)
	} else {
		allowed = CanManageTenant(ctx, h.configStore, user, strings.TrimSpace(user.TenantID))
	}
	if !allowed {
		SendError(ctx, fasthttp.StatusForbidden, "Only workspace admins, tenant owners/admins, or system admins can modify plugins")
		return false
	}
	return true
}

// buildPluginResponse constructs a PluginResponse with status for a given TablePlugin.
func (h *PluginsHandler) buildPluginResponse(ctx context.Context, plugin *configstoreTables.TablePlugin) PluginResponse {
	pluginStatus := schemas.PluginStatus{
		Name:   plugin.Name,
		Status: schemas.PluginStatusUninitialized,
		Logs:   []string{},
	}
	if !plugin.Enabled {
		pluginStatus.Status = schemas.PluginStatusDisabled
	} else {
		for _, status := range h.pluginsLoader.GetPluginStatus(ctx) {
			if plugin.Name == status.Name {
				pluginStatus = status
				break
			}
		}
	}
	return PluginResponse{
		Name:       plugin.Name,
		ActualName: pluginStatus.Name,
		Enabled:    plugin.Enabled,
		Config:     plugin.Config,
		IsCustom:   plugin.IsCustom,
		Path:       plugin.Path,
		Placement:  plugin.Placement,
		Order:      plugin.Order,
		Status:     pluginStatus,
	}
}

// getPlugins gets all plugins
func (h *PluginsHandler) getPlugins(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		pluginStatus := h.pluginsLoader.GetPluginStatus(ctx)
		finalPlugins := []PluginResponse{}
		for name, pluginStatus := range pluginStatus {
			finalPlugins = append(finalPlugins, PluginResponse{
				Name:       pluginStatus.Name,
				ActualName: name,
				Enabled:    true,
				Config:     map[string]any{},
				IsCustom:   true,
				Path:       nil,
				Status:     pluginStatus,
			})
		}
		SendJSON(ctx, map[string]any{
			"plugins": finalPlugins,
			"count":   len(finalPlugins),
		})
		return
	}
	plugins, err := h.configStore.GetPlugins(ctx)
	if err != nil {
		logger.Error("failed to get plugins: %v", err)
		SendError(ctx, 500, "Failed to retrieve plugins")
		return
	}
	// Fetching status
	pluginStatuses := h.pluginsLoader.GetPluginStatus(ctx)
	// Creating ephemeral struct for the plugins
	finalPlugins := []PluginResponse{}

	// Iterating over plugin status to get the plugin info
	for _, plugin := range plugins {
		pluginStatus := schemas.PluginStatus{
			Name:   plugin.Name,
			Status: schemas.PluginStatusUninitialized,
			Logs:   []string{},
		}
		if !plugin.Enabled {
			pluginStatus.Status = schemas.PluginStatusDisabled
		}
		for _, status := range pluginStatuses {
			if plugin.Name == status.Name {
				pluginStatus = status
				break
			}
		}
		finalPlugins = append(finalPlugins, PluginResponse{
			Name:       plugin.Name,
			ActualName: pluginStatus.Name,
			Enabled:    plugin.Enabled,
			Config:     plugin.Config,
			IsCustom:   plugin.IsCustom,
			Path:       plugin.Path,
			Placement:  plugin.Placement,
			Order:      plugin.Order,
			Status:     pluginStatus,
		})
	}
	// Creating ephemeral struct
	SendJSON(ctx, map[string]any{
		"plugins": finalPlugins,
		"count":   len(finalPlugins),
	})
}

// getPlugin gets a plugin by name
func (h *PluginsHandler) getPlugin(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		pluginStatus := h.pluginsLoader.GetPluginStatus(ctx)
		pluginInfo := PluginResponse{}
		for name, pluginStatus := range pluginStatus {
			if pluginStatus.Name == ctx.UserValue("name") {
				pluginInfo = PluginResponse{
					Name:       pluginStatus.Name,
					ActualName: name,
					Enabled:    true,
					Config:     map[string]any{},
					IsCustom:   true,
					Path:       nil,
					Status:     pluginStatus,
				}
				break
			}
		}
		SendJSON(ctx, pluginInfo)
		return
	}
	// Safely validate the "name" parameter
	nameValue := ctx.UserValue("name")
	if nameValue == nil {
		logger.Warn("missing required 'name' parameter in request")
		SendError(ctx, 400, "Missing required 'name' parameter")
		return
	}

	name, ok := nameValue.(string)
	if !ok {
		logger.Warn("invalid 'name' parameter type, expected string but got %T", nameValue)
		SendError(ctx, 400, "Invalid 'name' parameter type, expected string")
		return
	}

	if name == "" {
		logger.Warn("empty 'name' parameter provided")
		SendError(ctx, 400, "Empty 'name' parameter not allowed")
		return
	}

	plugin, err := h.configStore.GetPlugin(ctx, name)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, "Plugin not found")
			return
		}
		logger.Error("failed to get plugin: %v", err)
		SendError(ctx, 500, "Failed to retrieve plugin")
		return
	}
	SendJSON(ctx, plugin)
}

// createPlugin creates a new plugin
func (h *PluginsHandler) createPlugin(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, 400, "Plugins creation is  not supported when configstore is disabled")
		return
	}
	if !h.requireWorkspaceWrite(ctx, tenantctx.WorkspaceIDFromContext(ctx)) {
		return
	}
	var request CreatePluginRequest
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		logger.Error("failed to unmarshal create plugin request: %v", err)
		SendError(ctx, 400, "Invalid request body")
		return
	}
	// Validate required fields
	if request.Name == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Plugin name is required")
		return
	}
	// Validate placement value
	if request.Placement != nil && *request.Placement != "" &&
		*request.Placement != schemas.PluginPlacementPreBuiltin &&
		*request.Placement != schemas.PluginPlacementPostBuiltin {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid placement value. Must be 'pre_builtin' or 'post_builtin'")
		return
	}
	if request.Placement != nil && *request.Placement == "" {
		request.Placement = nil
	}
	// Normalize empty path to nil (treat empty string as built-in plugin)
	if request.Path != nil && *request.Path == "" {
		request.Path = nil
	}
	// Check if plugin already exists
	existingPlugin, err := h.configStore.GetPlugin(ctx, request.Name)
	if err == nil && existingPlugin != nil {
		SendError(ctx, fasthttp.StatusConflict, "Plugin already exists")
		return
	}
	// Determine if this is a built-in or custom plugin
	isBuiltin := lib.IsBuiltinPlugin(request.Name)
	// Built-in plugins should not have a path
	if isBuiltin && request.Path != nil {
		request.Path = nil
	}
	// Create DB entry first to avoid orphaned in-memory state if DB write fails
	if err := h.configStore.CreatePlugin(ctx, &configstoreTables.TablePlugin{
		Name:      request.Name,
		Enabled:   request.Enabled,
		Config:    request.Config,
		Path:      request.Path,
		IsCustom:  !isBuiltin,
		Placement: request.Placement,
		Order:     request.Order,
	}); err != nil {
		logger.Error("failed to create plugin: %v", err)
		SendError(ctx, 500, "Failed to create plugin")
		return
	}

	// Reload the plugin into memory if it's enabled
	if request.Enabled {
		if err := h.pluginsLoader.ReloadPlugin(ctx, request.Name, request.Path, request.Config, request.Placement, request.Order); err != nil {
			logger.Error("failed to load plugin: %v", err)
			if rbErr := h.configStore.DeletePlugin(ctx, request.Name); rbErr != nil {
				logger.Error("failed to rollback plugin creation: %v", rbErr)
			}
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Plugin created in database but failed to load: %v", err))
			return
		}
	}

	plugin, err := h.configStore.GetPlugin(ctx, request.Name)
	if err != nil {
		logger.Error("failed to get plugin: %v", err)
		SendError(ctx, 500, "Failed to retrieve plugin")
		return
	}

	ctx.SetStatusCode(fasthttp.StatusCreated)
	SendJSON(ctx, map[string]any{
		"message": "Plugin created successfully",
		"plugin":  h.buildPluginResponse(ctx, plugin),
	})
}

// updatePlugin updates an existing plugin
func (h *PluginsHandler) updatePlugin(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, 400, "Plugins update is not supported when configstore is disabled")
		return
	}
	if !h.requireWorkspaceWrite(ctx, tenantctx.WorkspaceIDFromContext(ctx)) {
		return
	}
	// Safely validate the "name" parameter
	nameValue := ctx.UserValue("name")
	if nameValue == nil {
		logger.Warn("missing required 'name' parameter in update plugin request")
		SendError(ctx, 400, "Missing required 'name' parameter")
		return
	}

	name, ok := nameValue.(string)
	if !ok {
		logger.Warn("invalid 'name' parameter type in update plugin request, expected string but got %T", nameValue)
		SendError(ctx, 400, "Invalid 'name' parameter type, expected string")
		return
	}

	if name == "" {
		logger.Warn("empty 'name' parameter provided in update plugin request")
		SendError(ctx, 400, "Empty 'name' parameter not allowed")
		return
	}
	var plugin *configstoreTables.TablePlugin
	var existingPlugin *configstoreTables.TablePlugin
	var err error
	// Check if plugin exists
	existingPlugin, err = h.configStore.GetPlugin(ctx, name)
	if err != nil {
		// If doesn't exist, create it
		if errors.Is(err, configstore.ErrNotFound) {
			plugin = &configstoreTables.TablePlugin{
				Name:     name,
				Enabled:  false,
				Config:   map[string]any{},
				Path:     nil,
				IsCustom: false,
			}
			if err := h.configStore.CreatePlugin(ctx, plugin); err != nil {
				logger.Error("failed to create plugin: %v", err)
				SendError(ctx, 500, "Failed to create plugin")
				return
			}
		} else {
			logger.Error("failed to get plugin: %v", err)
			SendError(ctx, 500, "Failed to update plugin")
			return
		}
	}

	// Unmarshalling the request body
	var request UpdatePluginRequest
	if err := json.Unmarshal(ctx.PostBody(), &request); err != nil {
		logger.Error("failed to unmarshal update plugin request: %v", err)
		SendError(ctx, 400, "Invalid request body")
		return
	}

	// Plan-tier gate: enabling a tier-gated plugin (semantic cache, mcpcache,
	// otel / telemetry, response_consistency, mocker) requires the org's
	// plan to grant the matching entitlement. Only the disabled->enabled
	// transition is gated, so editing an already-enabled plugin's config (or
	// disabling it) never 402s - existing functionality is never broken.
	wasEnabled := existingPlugin != nil && existingPlugin.Enabled
	if request.Enabled && !wasEnabled {
		if !gatePluginEnable(ctx, h.configStore, name) {
			return
		}
	}
	// Validate placement value
	if request.Placement != nil && *request.Placement != "" &&
		*request.Placement != schemas.PluginPlacementPreBuiltin &&
		*request.Placement != schemas.PluginPlacementPostBuiltin {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid placement value. Must be 'pre_builtin' or 'post_builtin'")
		return
	}
	if request.Placement != nil && *request.Placement == "" {
		request.Placement = nil
	}
	// Normalize empty path to nil (treat empty string as built-in plugin)
	if request.Path != nil && *request.Path == "" {
		request.Path = nil
	}
	// Determine if this is a built-in plugin
	isBuiltin := lib.IsBuiltinPlugin(name)
	// Built-in plugins should not have a path
	if isBuiltin && request.Path != nil {
		request.Path = nil
	}
	// Updating the plugin
	if err := h.configStore.UpdatePlugin(ctx, &configstoreTables.TablePlugin{
		Name:      name,
		Enabled:   request.Enabled,
		Config:    request.Config,
		Path:      request.Path,
		IsCustom:  !isBuiltin,
		Placement: request.Placement,
		Order:     request.Order,
	}); err != nil {
		logger.Error("failed to update plugin: %v", err)
		SendError(ctx, 500, "Failed to update plugin")
		return
	}
	plugin, err = h.configStore.GetPlugin(ctx, name)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, "Plugin not found")
			return
		}
		logger.Error("failed to get plugin: %v", err)
		SendError(ctx, 500, "Failed to retrieve plugin")
		return
	}
	// We reload the plugin if its enabled, otherwise we stop it
	if request.Enabled {
		if err := h.pluginsLoader.ReloadPlugin(ctx, name, request.Path, request.Config, request.Placement, request.Order); err != nil {
			logger.Error("failed to load plugin: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Plugin updated in database but failed to load: %v", err))
			return
		}
	} else {
		ctx.SetUserValue(PluginDisabledKey, true)
		if err := h.pluginsLoader.RemovePlugin(ctx, name); err != nil {
			if !errors.Is(err, plugins.ErrPluginNotFound) {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Plugin updated in database but failed to stop: %v", err))
				return
			}
			// If not found then we don't need to do anything
		}
	}

	SendJSON(ctx, map[string]interface{}{
		"message": "Plugin updated successfully",
		"plugin":  h.buildPluginResponse(ctx, plugin),
	})
}

// deletePlugin deletes an existing plugin
func (h *PluginsHandler) deletePlugin(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, 400, "Plugins deletion is not supported when configstore is disabled")
		return
	}
	if !h.requireWorkspaceWrite(ctx, tenantctx.WorkspaceIDFromContext(ctx)) {
		return
	}
	// Safely validate the "name" parameter
	nameValue := ctx.UserValue("name")
	if nameValue == nil {
		logger.Warn("missing required 'name' parameter in delete plugin request")
		SendError(ctx, 400, "Missing required 'name' parameter")
		return
	}

	name, ok := nameValue.(string)
	if !ok {
		logger.Warn("invalid 'name' parameter type in delete plugin request, expected string but got %T", nameValue)
		SendError(ctx, 400, "Invalid 'name' parameter type, expected string")
		return
	}

	if name == "" {
		logger.Warn("empty 'name' parameter provided in delete plugin request")
		SendError(ctx, 400, "Empty 'name' parameter not allowed")
		return
	}

	if err := h.configStore.DeletePlugin(ctx, name); err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, "Plugin not found")
			return
		}
		logger.Error("failed to delete plugin: %v", err)
		SendError(ctx, 500, "Failed to delete plugin")
		return
	}

	if err := h.pluginsLoader.RemovePlugin(ctx, name); err != nil {
		if !errors.Is(err, plugins.ErrPluginNotFound) {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Plugin deleted in database but failed to stop: %v", err))
			return
		}
	}
	SendJSON(ctx, map[string]interface{}{
		"message": "Plugin deleted successfully",
	})
}
