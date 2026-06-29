// Package handlers provides HTTP request handlers for the DeepIntShield HTTP transport.
// This file contains all provider management functionality including CRUD operations.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// ModelsManager defines the interface for managing provider models
type ModelsManager interface {
	ReloadProvider(ctx context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error)
	RemoveProvider(ctx context.Context, provider schemas.ModelProvider) error
	GetModelsForProvider(provider schemas.ModelProvider) []string
	GetUnfilteredModelsForProvider(provider schemas.ModelProvider) []string
}

// ProviderHandler manages HTTP requests for provider operations
type ProviderHandler struct {
	dbStore       configstore.ConfigStore
	inMemoryStore *lib.Config
	client        *deepintshield.DeepIntShield
	modelsManager ModelsManager
}

// NewProviderHandler creates a new provider handler instance
func NewProviderHandler(modelsManager ModelsManager, inMemoryStore *lib.Config, client *deepintshield.DeepIntShield) *ProviderHandler {
	return &ProviderHandler{
		dbStore:       inMemoryStore.ConfigStore,
		inMemoryStore: inMemoryStore,
		client:        client,
		modelsManager: modelsManager,
	}
}

type ProviderStatus = string

const (
	ProviderStatusActive  ProviderStatus = "active"  // Provider is active and working
	ProviderStatusError   ProviderStatus = "error"   // Provider failed to initialize
	ProviderStatusDeleted ProviderStatus = "deleted" // Provider is deleted from the store
)

// ProviderResponse represents the response for provider operations
type ProviderResponse struct {
	Name                     schemas.ModelProvider             `json:"name"`
	Keys                     []schemas.Key                     `json:"keys"`                             // API keys for the provider
	NetworkConfig            schemas.NetworkConfig             `json:"network_config"`                   // Network-related settings
	ConcurrencyAndBufferSize schemas.ConcurrencyAndBufferSize  `json:"concurrency_and_buffer_size"`      // Concurrency settings
	ProxyConfig              *schemas.ProxyConfig              `json:"proxy_config"`                     // Proxy configuration
	SendBackRawRequest       bool                              `json:"send_back_raw_request"`            // Include raw request in DeepIntShieldResponse
	SendBackRawResponse      bool                              `json:"send_back_raw_response"`           // Include raw response in DeepIntShieldResponse
	CustomProviderConfig     *schemas.CustomProviderConfig     `json:"custom_provider_config,omitempty"` // Custom provider configuration
	PricingOverrides         []schemas.ProviderPricingOverride `json:"pricing_overrides,omitempty"`      // Provider-level pricing overrides
	ProviderStatus           ProviderStatus                    `json:"provider_status"`                  // Health/initialization status of the provider
	Status                   string                            `json:"status,omitempty"`                 // Operational status (e.g., list_models_failed)
	Description              string                            `json:"description,omitempty"`            // Error/status description
	ConfigHash               string                            `json:"config_hash,omitempty"`            // Hash of config.json version, used for change detection
}

// ListProvidersResponse represents the response for listing all providers
type ListProvidersResponse struct {
	Providers []ProviderResponse `json:"providers"`
	Total     int                `json:"total"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// UpdateProviderRequest tracks which fields were explicitly provided so edit-only
// flows can update provider settings without implicitly deleting keys or resetting
// unrelated config.
type UpdateProviderRequest struct {
	Keys                           []schemas.Key                     `json:"keys"`
	KeysExists                     bool                              `json:"-"`
	NetworkConfig                  *schemas.NetworkConfig            `json:"network_config,omitempty"`
	NetworkConfigExists            bool                              `json:"-"`
	ConcurrencyAndBufferSize       *schemas.ConcurrencyAndBufferSize `json:"concurrency_and_buffer_size,omitempty"`
	ConcurrencyAndBufferSizeExists bool                              `json:"-"`
	ProxyConfig                    *schemas.ProxyConfig              `json:"proxy_config,omitempty"`
	ProxyConfigExists              bool                              `json:"-"`
	SendBackRawRequest             *bool                             `json:"send_back_raw_request,omitempty"`
	SendBackRawResponse            *bool                             `json:"send_back_raw_response,omitempty"`
	CustomProviderConfig           *schemas.CustomProviderConfig     `json:"custom_provider_config,omitempty"`
	CustomProviderConfigExists     bool                              `json:"-"`
	PricingOverrides               []schemas.ProviderPricingOverride `json:"pricing_overrides,omitempty"`
	PricingOverridesExists         bool                              `json:"-"`
}

// UnmarshalJSON records whether optional fields were present in the request body.
func (r *UpdateProviderRequest) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if v, ok := raw["keys"]; ok {
		if err := json.Unmarshal(v, &r.Keys); err != nil {
			return err
		}
		r.KeysExists = true
	}
	if v, ok := raw["network_config"]; ok {
		if err := json.Unmarshal(v, &r.NetworkConfig); err != nil {
			return err
		}
		r.NetworkConfigExists = true
	}
	if v, ok := raw["concurrency_and_buffer_size"]; ok {
		if err := json.Unmarshal(v, &r.ConcurrencyAndBufferSize); err != nil {
			return err
		}
		r.ConcurrencyAndBufferSizeExists = true
	}
	if v, ok := raw["proxy_config"]; ok {
		if err := json.Unmarshal(v, &r.ProxyConfig); err != nil {
			return err
		}
		r.ProxyConfigExists = true
	}
	if v, ok := raw["send_back_raw_request"]; ok {
		if err := json.Unmarshal(v, &r.SendBackRawRequest); err != nil {
			return err
		}
	}
	if v, ok := raw["send_back_raw_response"]; ok {
		if err := json.Unmarshal(v, &r.SendBackRawResponse); err != nil {
			return err
		}
	}
	if v, ok := raw["custom_provider_config"]; ok {
		if err := json.Unmarshal(v, &r.CustomProviderConfig); err != nil {
			return err
		}
		r.CustomProviderConfigExists = true
	}
	if v, ok := raw["pricing_overrides"]; ok {
		if err := json.Unmarshal(v, &r.PricingOverrides); err != nil {
			return err
		}
		r.PricingOverridesExists = true
	}

	return nil
}

type providerModelStore interface {
	ReplaceProviderModels(ctx context.Context, provider schemas.ModelProvider, modelNames []string) error
}

func (h *ProviderHandler) providerExists(ctx context.Context, provider schemas.ModelProvider) (bool, error) {
	if h.isTenantScoped(ctx) {
		_, err := h.dbStore.GetProviderConfig(ctx, provider)
		if err != nil {
			if errors.Is(err, configstore.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}

	_, err := h.inMemoryStore.GetProviderConfigRedacted(provider)
	if err != nil {
		if errors.Is(err, lib.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (h *ProviderHandler) isTenantScoped(ctx context.Context) bool {
	return h.dbStore != nil && tenantctx.TenantIDFromContext(ctx) != ""
}

func (h *ProviderHandler) getStoredProvidersConfig(ctx context.Context) (map[schemas.ModelProvider]configstore.ProviderConfig, error) {
	if h.isTenantScoped(ctx) {
		return h.dbStore.GetProvidersConfig(ctx)
	}

	h.inMemoryStore.Mu.RLock()
	defer h.inMemoryStore.Mu.RUnlock()

	providers := make(map[schemas.ModelProvider]configstore.ProviderConfig, len(h.inMemoryStore.Providers))
	for providerName, provider := range h.inMemoryStore.Providers {
		providers[providerName] = provider
	}
	return providers, nil
}

func (h *ProviderHandler) getStoredProviderConfigRaw(ctx context.Context, provider schemas.ModelProvider) (*configstore.ProviderConfig, error) {
	if h.isTenantScoped(ctx) {
		return h.dbStore.GetProviderConfig(ctx, provider)
	}
	return h.inMemoryStore.GetProviderConfigRaw(provider)
}

func (h *ProviderHandler) getStoredProviderConfigRedacted(ctx context.Context, provider schemas.ModelProvider) (*configstore.ProviderConfig, error) {
	if h.isTenantScoped(ctx) {
		config, err := h.dbStore.GetProviderConfig(ctx, provider)
		if err != nil {
			return nil, err
		}
		return config.Redacted(), nil
	}
	return h.inMemoryStore.GetProviderConfigRedacted(provider)
}

func (h *ProviderHandler) listStoredKeys(ctx context.Context) ([]tables.TableKey, error) {
	providers, err := h.getStoredProvidersConfig(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]tables.TableKey, 0)
	for providerName, provider := range providers {
		for _, key := range provider.Keys {
			models := key.Models
			if models == nil {
				models = []string{}
			}
			keys = append(keys, tables.TableKey{
				KeyID:       key.ID,
				Name:        key.Name,
				Value:       *schemas.NewEnvVar(""),
				Models:      models,
				Weight:      deepintshield.Ptr(key.Weight),
				Provider:    string(providerName),
				ConfigHash:  key.ConfigHash,
				UseForCache: key.UseForCache,
				Status:      string(key.Status),
				Description: key.Description,
			})
		}
	}

	return keys, nil
}

func (h *ProviderHandler) persistTenantProviderModels(ctx context.Context, provider schemas.ModelProvider, config *configstore.ProviderConfig) error {
	modelStore, ok := h.dbStore.(providerModelStore)
	if !ok || config == nil {
		return nil
	}
	return modelStore.ReplaceProviderModels(ctx, provider, configuredModelNames(config))
}

func (h *ProviderHandler) fallbackProviderModelNames(provider schemas.ModelProvider, unfiltered bool) []string {
	if h.modelsManager == nil {
		return []string{}
	}
	if unfiltered {
		return uniqueStringValues(h.modelsManager.GetUnfilteredModelsForProvider(provider))
	}
	return uniqueStringValues(h.modelsManager.GetModelsForProvider(provider))
}

func (h *ProviderHandler) reloadTenantProviderModels(ctx context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error) {
	if h.modelsManager == nil {
		return nil, nil
	}

	if _, err := h.modelsManager.ReloadProvider(ctx, provider); err != nil {
		return nil, err
	}

	if h.dbStore == nil {
		return nil, nil
	}

	reloadedProvider, err := h.dbStore.GetProvider(ctx, provider)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return reloadedProvider, nil
}

func (h *ProviderHandler) getTenantProviderModelNames(ctx context.Context, provider schemas.ModelProvider, unfiltered bool) ([]string, error) {
	if unfiltered {
		modelNames := h.fallbackProviderModelNames(provider, true)
		if len(modelNames) > 0 {
			return modelNames, nil
		}

		if _, reloadErr := h.reloadTenantProviderModels(ctx, provider); reloadErr != nil {
			logger.Warn("failed to reload tenant-scoped unfiltered models for provider %s: %v", provider, reloadErr)
		}

		modelNames = h.fallbackProviderModelNames(provider, true)
		if len(modelNames) > 0 {
			return modelNames, nil
		}
	}

	providerInfo, err := h.dbStore.GetProvider(ctx, provider)
	if err != nil {
		return nil, err
	}

	modelNames := tableModelNames(providerInfo.Models)
	if len(modelNames) > 0 {
		return modelNames, nil
	}

	config, err := h.dbStore.GetProviderConfig(ctx, provider)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			return h.fallbackProviderModelNames(provider, unfiltered), nil
		}
		return nil, err
	}
	modelNames = configuredModelNames(config)
	if len(modelNames) > 0 {
		return modelNames, nil
	}

	reloadedProvider, reloadErr := h.reloadTenantProviderModels(ctx, provider)
	if reloadErr != nil {
		logger.Warn("failed to reload tenant-scoped models for provider %s: %v", provider, reloadErr)
	} else if reloadedProvider != nil {
		modelNames = tableModelNames(reloadedProvider.Models)
		if len(modelNames) > 0 {
			return modelNames, nil
		}
	}

	return h.fallbackProviderModelNames(provider, unfiltered), nil
}

func (h *ProviderHandler) getTenantProviderModels(ctx context.Context, unfiltered bool) (map[schemas.ModelProvider][]string, error) {
	providers, err := h.dbStore.GetProviders(ctx)
	if err != nil {
		return nil, err
	}

	providerModels := make(map[schemas.ModelProvider][]string, len(providers))
	for _, providerInfo := range providers {
		provider := schemas.ModelProvider(providerInfo.Name)
		modelNames, err := h.getTenantProviderModelNames(ctx, provider, unfiltered)
		if err != nil {
			if errors.Is(err, configstore.ErrNotFound) {
				continue
			}
			return nil, err
		}
		providerModels[provider] = modelNames
	}

	return providerModels, nil
}

func (h *ProviderHandler) getTenantBaseModels(ctx context.Context) ([]string, error) {
	providerModels, err := h.getTenantProviderModels(ctx, false)
	if err != nil {
		return nil, err
	}

	modelPrices, err := h.dbStore.GetModelPrices(ctx)
	if err != nil {
		return nil, err
	}

	baseModelLookup := make(map[string]string, len(modelPrices))
	for _, modelPrice := range modelPrices {
		if strings.TrimSpace(modelPrice.BaseModel) == "" {
			continue
		}
		key := baseModelLookupKey(schemas.ModelProvider(modelPrice.Provider), modelPrice.Model)
		if _, exists := baseModelLookup[key]; exists {
			continue
		}
		baseModelLookup[key] = modelPrice.BaseModel
	}

	baseModels := make([]string, 0)
	seen := make(map[string]struct{})
	for provider, modelNames := range providerModels {
		for _, modelName := range modelNames {
			baseModel := modelName
			if mapped, ok := baseModelLookup[baseModelLookupKey(provider, modelName)]; ok && strings.TrimSpace(mapped) != "" {
				baseModel = mapped
			}
			if _, exists := seen[baseModel]; exists {
				continue
			}
			seen[baseModel] = struct{}{}
			baseModels = append(baseModels, baseModel)
		}
	}

	sort.Strings(baseModels)
	return baseModels, nil
}

func configuredModelNames(config *configstore.ProviderConfig) []string {
	if config == nil {
		return []string{}
	}

	modelNames := make([]string, 0)
	for _, key := range config.Keys {
		modelNames = append(modelNames, key.Models...)
	}
	return uniqueStringValues(modelNames)
}

func tableModelNames(models []tables.TableModel) []string {
	modelNames := make([]string, 0, len(models))
	for _, model := range models {
		modelNames = append(modelNames, model.Name)
	}
	return uniqueStringValues(modelNames)
}

func uniqueStringValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func resolveProviderKeyChanges(oldKeys []schemas.Key, payloadKeys []schemas.Key) (keysToAdd []schemas.Key, keysToDelete []schemas.Key, keysToUpdate []schemas.Key) {
	oldByID := make(map[string]schemas.Key, len(oldKeys))
	oldByName := make(map[string]schemas.Key, len(oldKeys))
	for _, oldKey := range oldKeys {
		if keyID := strings.TrimSpace(oldKey.ID); keyID != "" {
			oldByID[keyID] = oldKey
		}
		if keyName := strings.TrimSpace(oldKey.Name); keyName != "" {
			oldByName[keyName] = oldKey
		}
	}

	matchedOldIDs := make(map[string]struct{}, len(payloadKeys))
	for _, key := range payloadKeys {
		incomingID := strings.TrimSpace(key.ID)
		incomingName := strings.TrimSpace(key.Name)

		if incomingID != "" {
			if oldKey, exists := oldByID[incomingID]; exists {
				matchedOldIDs[oldKey.ID] = struct{}{}
				keysToUpdate = append(keysToUpdate, key)
				continue
			}
		}

		if incomingName != "" {
			if oldKey, exists := oldByName[incomingName]; exists {
				key.ID = oldKey.ID
				matchedOldIDs[oldKey.ID] = struct{}{}
				keysToUpdate = append(keysToUpdate, key)
				continue
			}
		}

		if incomingID == "" {
			key.ID = uuid.NewString()
		}
		key.Enabled = deepintshield.Ptr(true)
		keysToAdd = append(keysToAdd, key)
	}

	for _, oldKey := range oldKeys {
		if _, exists := matchedOldIDs[oldKey.ID]; exists {
			continue
		}
		keysToDelete = append(keysToDelete, oldKey)
	}

	return keysToAdd, keysToDelete, keysToUpdate
}

func baseModelLookupKey(provider schemas.ModelProvider, model string) string {
	return string(provider) + ":" + model
}

// RegisterRoutes registers all provider management routes
func (h *ProviderHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// Provider CRUD operations
	r.GET("/api/providers", lib.ChainMiddlewares(h.listProviders, middlewares...))
	r.GET("/api/providers/{provider}", lib.ChainMiddlewares(h.getProvider, middlewares...))
	r.POST("/api/providers", lib.ChainMiddlewares(h.addProvider, middlewares...))
	r.PUT("/api/providers/{provider}", lib.ChainMiddlewares(h.updateProvider, middlewares...))
	r.DELETE("/api/providers/{provider}", lib.ChainMiddlewares(h.deleteProvider, middlewares...))
	r.GET("/api/keys", lib.ChainMiddlewares(h.listKeys, middlewares...))
	r.GET("/api/models", lib.ChainMiddlewares(h.listModels, middlewares...))
	r.GET("/api/models/parameters", lib.ChainMiddlewares(h.getModelParameters, middlewares...))
	r.GET("/api/models/base", lib.ChainMiddlewares(h.listBaseModels, middlewares...))
}

// listProviders handles GET /api/providers - List all providers
func (h *ProviderHandler) listProviders(ctx *fasthttp.RequestCtx) {
	providers, err := h.getStoredProvidersConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get providers: %v", err))
		return
	}
	providersInClient := []schemas.ModelProvider{}
	if !h.isTenantScoped(ctx) {
		providersInClient, err = h.client.GetConfiguredProviders()
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get providers from client: %v", err))
			return
		}
	}
	providerResponses := []ProviderResponse{}

	for providerName, provider := range providers {
		config := provider.Redacted()

		providerStatus := ProviderStatusActive
		if !h.isTenantScoped(ctx) {
			providerStatus = ProviderStatusError
			if slices.Contains(providersInClient, providerName) {
				providerStatus = ProviderStatusActive
			}
		}
		providerResponses = append(providerResponses, h.getProviderResponseFromConfig(providerName, *config, providerStatus))
	}
	// Sort providers alphabetically
	sort.Slice(providerResponses, func(i, j int) bool {
		return providerResponses[i].Name < providerResponses[j].Name
	})
	response := ListProvidersResponse{
		Providers: providerResponses,
		Total:     len(providerResponses),
	}

	SendJSON(ctx, response)
}

// getProvider handles GET /api/providers/{provider} - Get specific provider
func (h *ProviderHandler) getProvider(ctx *fasthttp.RequestCtx) {
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid provider: %v", err))
		return
	}

	providersInClient := []schemas.ModelProvider{}
	if !h.isTenantScoped(ctx) {
		providersInClient, err = h.client.GetConfiguredProviders()
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get providers from client: %v", err))
			return
		}
	}

	config, err := h.getStoredProviderConfigRaw(ctx, provider)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) || errors.Is(err, lib.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, fmt.Sprintf("Provider not found: %v", err))
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get provider config: %v", err))
		return
	}
	redactedConfig := config.Redacted()

	providerStatus := ProviderStatusActive
	if !h.isTenantScoped(ctx) {
		providerStatus = ProviderStatusError
		if slices.Contains(providersInClient, provider) {
			providerStatus = ProviderStatusActive
		}
	}

	response := h.getProviderResponseFromConfig(provider, *redactedConfig, providerStatus)

	SendJSON(ctx, response)
}

// addProvider handles POST /api/providers - Add a new provider
// NOTE: This only gets called when a new custom provider is added
func (h *ProviderHandler) addProvider(ctx *fasthttp.RequestCtx) {
	// Payload structure
	var payload = struct {
		Provider                 schemas.ModelProvider             `json:"provider"`
		Keys                     []schemas.Key                     `json:"keys"`                                  // API keys for the provider
		NetworkConfig            *schemas.NetworkConfig            `json:"network_config,omitempty"`              // Network-related settings
		ConcurrencyAndBufferSize *schemas.ConcurrencyAndBufferSize `json:"concurrency_and_buffer_size,omitempty"` // Concurrency settings
		ProxyConfig              *schemas.ProxyConfig              `json:"proxy_config,omitempty"`                // Proxy configuration
		SendBackRawRequest       *bool                             `json:"send_back_raw_request,omitempty"`       // Include raw request in DeepIntShieldResponse
		SendBackRawResponse      *bool                             `json:"send_back_raw_response,omitempty"`      // Include raw response in DeepIntShieldResponse
		CustomProviderConfig     *schemas.CustomProviderConfig     `json:"custom_provider_config,omitempty"`      // Custom provider configuration
		PricingOverrides         []schemas.ProviderPricingOverride `json:"pricing_overrides,omitempty"`           // Provider-level pricing overrides
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	// Validate provider
	if payload.Provider == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Missing provider")
		return
	}
	if payload.CustomProviderConfig != nil {
		// custom provider key should not be same as standard provider names
		if deepintshield.IsStandardProvider(payload.Provider) {
			SendError(ctx, fasthttp.StatusBadRequest, "Custom provider cannot be same as a standard provider")
			return
		}
		if payload.CustomProviderConfig.BaseProviderType == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "BaseProviderType is required when CustomProviderConfig is provided")
			return
		}
		// check if base provider is a supported base provider
		if !deepintshield.IsSupportedBaseProvider(payload.CustomProviderConfig.BaseProviderType) {
			SendError(ctx, fasthttp.StatusBadRequest, "BaseProviderType must be a standard provider")
			return
		}
	}
	if payload.ConcurrencyAndBufferSize != nil {
		if payload.ConcurrencyAndBufferSize.Concurrency == 0 {
			SendError(ctx, fasthttp.StatusBadRequest, "Concurrency must be greater than 0")
			return
		}
		if payload.ConcurrencyAndBufferSize.BufferSize == 0 {
			SendError(ctx, fasthttp.StatusBadRequest, "Buffer size must be greater than 0")
			return
		}
		if payload.ConcurrencyAndBufferSize.Concurrency > payload.ConcurrencyAndBufferSize.BufferSize {
			SendError(ctx, fasthttp.StatusBadRequest, "Concurrency must be less than or equal to buffer size")
			return
		}
	}
	if err := validatePricingOverrides(payload.PricingOverrides); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid pricing overrides: %v", err))
		return
	}
	// Validate retry backoff values if NetworkConfig is provided
	if payload.NetworkConfig != nil {
		if err := validateRetryBackoff(payload.NetworkConfig); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid retry backoff: %v", err))
			return
		}
	}
	exists, err := h.providerExists(ctx, payload.Provider)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to check provider config: %v", err))
		return
	}
	if exists {
		SendError(ctx, fasthttp.StatusConflict, fmt.Sprintf("Provider %s already exists", payload.Provider))
		return
	}

	// Construct ProviderConfig from individual fields
	config := configstore.ProviderConfig{
		Keys:                     payload.Keys,
		NetworkConfig:            payload.NetworkConfig,
		ProxyConfig:              payload.ProxyConfig,
		ConcurrencyAndBufferSize: payload.ConcurrencyAndBufferSize,
		SendBackRawRequest:       payload.SendBackRawRequest != nil && *payload.SendBackRawRequest,
		SendBackRawResponse:      payload.SendBackRawResponse != nil && *payload.SendBackRawResponse,
		CustomProviderConfig:     payload.CustomProviderConfig,
		PricingOverrides:         payload.PricingOverrides,
	}
	// Validate custom provider configuration before persisting
	if err := lib.ValidateCustomProvider(config, payload.Provider); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid custom provider config: %v", err))
		return
	}
	if h.isTenantScoped(ctx) {
		if err := h.dbStore.AddProvider(ctx, payload.Provider, config); err != nil {
			logger.Warn("Failed to add tenant-scoped provider %s: %v", payload.Provider, err)
			if errors.Is(err, configstore.ErrAlreadyExists) {
				SendError(ctx, fasthttp.StatusConflict, fmt.Sprintf("Provider %s already exists", payload.Provider))
				return
			}
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err))
			return
		}
		if err := h.persistTenantProviderModels(ctx, payload.Provider, &config); err != nil {
			logger.Warn("Failed to persist tenant-scoped provider models for %s: %v", payload.Provider, err)
		}
		if err := h.attemptModelDiscovery(ctx, payload.Provider, payload.CustomProviderConfig); err != nil {
			logger.Warn("Tenant-scoped model discovery failed for provider %s: %v", payload.Provider, err)
		}

		redactedConfig, err := h.getStoredProviderConfigRedacted(ctx, payload.Provider)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get provider config: %v", err))
			return
		}

		SendJSON(ctx, h.getProviderResponseFromConfig(payload.Provider, *redactedConfig, ProviderStatusActive))
		return
	}
	// Add provider to store (env vars will be processed by store)
	if err := h.inMemoryStore.AddProvider(ctx, payload.Provider, config); err != nil {
		logger.Warn("Failed to add provider %s: %v", payload.Provider, err)
		if errors.Is(err, lib.ErrAlreadyExists) {
			SendError(ctx, fasthttp.StatusConflict, err.Error())
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err))
		return
	}
	if h.inMemoryStore.ModelCatalog != nil {
		if err := h.inMemoryStore.ModelCatalog.SetProviderPricingOverrides(payload.Provider, config.PricingOverrides); err != nil {
			logger.Warn("Failed to set pricing overrides for provider %s: %v", payload.Provider, err)
		}
	}
	logger.Info("Provider %s added successfully", payload.Provider)

	// Attempt model discovery
	err = h.attemptModelDiscovery(ctx, payload.Provider, payload.CustomProviderConfig)

	if err != nil {
		logger.Warn("Model discovery failed for provider %s: %v", payload.Provider, err)
	}

	// Get redacted config for response (in-memory store is now updated by updateKeyStatus)
	redactedConfig, err := h.getStoredProviderConfigRedacted(ctx, payload.Provider)
	if err != nil {
		logger.Warn("Failed to get redacted config for provider %s: %v", payload.Provider, err)
		// Fall back to the raw config (no keys)
		response := h.getProviderResponseFromConfig(payload.Provider, configstore.ProviderConfig{
			NetworkConfig:            config.NetworkConfig,
			ConcurrencyAndBufferSize: config.ConcurrencyAndBufferSize,
			ProxyConfig:              config.ProxyConfig,
			SendBackRawRequest:       config.SendBackRawRequest,
			SendBackRawResponse:      config.SendBackRawResponse,
			CustomProviderConfig:     config.CustomProviderConfig,
			PricingOverrides:         config.PricingOverrides,
			Status:                   config.Status,
			Description:              config.Description,
		}, ProviderStatusActive)
		SendJSON(ctx, response)
		return
	}

	response := h.getProviderResponseFromConfig(payload.Provider, *redactedConfig, ProviderStatusActive)

	SendJSON(ctx, response)
}

// updateProvider handles PUT /api/providers/{provider} - Update provider config.
// Omitted fields preserve their stored values so edit-only flows do not reset
// unrelated provider settings.
func (h *ProviderHandler) updateProvider(ctx *fasthttp.RequestCtx) {
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		// If not found, then first we create and then update
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid provider: %v", err))
		return
	}

	var payload UpdateProviderRequest

	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	if payload.PricingOverridesExists {
		if err := validatePricingOverrides(payload.PricingOverrides); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("invalid pricing overrides: %v", err))
			return
		}
	}

	// Get the raw config to access actual values for merging with redacted request values
	oldConfigRaw, err := h.getStoredProviderConfigRaw(ctx, provider)
	if err != nil {
		if !errors.Is(err, lib.ErrNotFound) && !errors.Is(err, configstore.ErrNotFound) {
			logger.Warn("Failed to get old config for provider %s: %v", provider, err)
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
	}

	if oldConfigRaw == nil {
		oldConfigRaw = &configstore.ProviderConfig{}
	}

	oldConfigRedacted, err := h.getStoredProviderConfigRedacted(ctx, provider)
	if err != nil {
		if !errors.Is(err, lib.ErrNotFound) && !errors.Is(err, configstore.ErrNotFound) {
			logger.Warn("Failed to get old redacted config for provider %s: %v", provider, err)
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
	}

	if oldConfigRedacted == nil {
		oldConfigRedacted = &configstore.ProviderConfig{}
	}

	// Construct ProviderConfig from the existing values, then apply only fields
	// that were explicitly supplied in this request.
	config := configstore.ProviderConfig{
		Keys:                     oldConfigRaw.Keys,
		NetworkConfig:            oldConfigRaw.NetworkConfig,
		ConcurrencyAndBufferSize: oldConfigRaw.ConcurrencyAndBufferSize,
		ProxyConfig:              oldConfigRaw.ProxyConfig,
		CustomProviderConfig:     oldConfigRaw.CustomProviderConfig,
		PricingOverrides:         oldConfigRaw.PricingOverrides,
		Status:                   oldConfigRaw.Status,
		Description:              oldConfigRaw.Description,
		SendBackRawRequest:       oldConfigRaw.SendBackRawRequest,
		SendBackRawResponse:      oldConfigRaw.SendBackRawResponse,
		StoreRawRequestResponse:  oldConfigRaw.StoreRawRequestResponse,
		ConfigHash:               oldConfigRaw.ConfigHash,
	}

	// Environment variable cleanup is handled automatically by mergeKeys.
	if payload.KeysExists {
		keysToAdd, keysToDelete, keysToUpdate := resolveProviderKeyChanges(oldConfigRaw.Keys, payload.Keys)

		keys, err := h.mergeKeys(oldConfigRaw.Keys, oldConfigRedacted.Keys, keysToAdd, keysToDelete, keysToUpdate)
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid keys: %v", err))
			return
		}
		config.Keys = keys
	}

	if payload.ConcurrencyAndBufferSizeExists {
		if payload.ConcurrencyAndBufferSize == nil {
			SendError(ctx, fasthttp.StatusBadRequest, "Concurrency and buffer size cannot be null")
			return
		}
		if payload.ConcurrencyAndBufferSize.Concurrency == 0 {
			SendError(ctx, fasthttp.StatusBadRequest, "Concurrency must be greater than 0")
			return
		}
		if payload.ConcurrencyAndBufferSize.BufferSize == 0 {
			SendError(ctx, fasthttp.StatusBadRequest, "Buffer size must be greater than 0")
			return
		}
		if payload.ConcurrencyAndBufferSize.Concurrency > payload.ConcurrencyAndBufferSize.BufferSize {
			SendError(ctx, fasthttp.StatusBadRequest, "Concurrency must be less than or equal to buffer size")
			return
		}
		config.ConcurrencyAndBufferSize = payload.ConcurrencyAndBufferSize
	}

	if payload.NetworkConfigExists {
		if payload.NetworkConfig != nil && oldConfigRaw.NetworkConfig != nil &&
			(payload.NetworkConfig.CACertPEM == "<REDACTED>" || payload.NetworkConfig.CACertPEM == "********") {
			payload.NetworkConfig.CACertPEM = oldConfigRaw.NetworkConfig.CACertPEM
		}
		if err := validateRetryBackoff(payload.NetworkConfig); err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid retry backoff: %v", err))
			return
		}
		config.NetworkConfig = payload.NetworkConfig
	}

	if payload.ProxyConfigExists {
		if payload.ProxyConfig != nil && oldConfigRaw.ProxyConfig != nil {
			if payload.ProxyConfig.IsRedactedValue(payload.ProxyConfig.Password) {
				payload.ProxyConfig.Password = oldConfigRaw.ProxyConfig.Password
			}
			if payload.ProxyConfig.IsRedactedValue(payload.ProxyConfig.CACertPEM) {
				payload.ProxyConfig.CACertPEM = oldConfigRaw.ProxyConfig.CACertPEM
			}
		}
		config.ProxyConfig = payload.ProxyConfig
	}

	if payload.CustomProviderConfigExists {
		config.CustomProviderConfig = payload.CustomProviderConfig
	}

	if payload.PricingOverridesExists {
		config.PricingOverrides = payload.PricingOverrides
	}

	if payload.SendBackRawRequest != nil {
		config.SendBackRawRequest = *payload.SendBackRawRequest
	}
	if payload.SendBackRawResponse != nil {
		config.SendBackRawResponse = *payload.SendBackRawResponse
	}

	if err := lib.ValidateCustomProviderUpdate(config, *oldConfigRaw, provider); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid custom provider config: %v", err))
		return
	}
	if h.isTenantScoped(ctx) {
		exists, err := h.providerExists(ctx, provider)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get provider: %v", err))
			return
		}
		if !exists {
			if err := h.dbStore.AddProvider(ctx, provider, config); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err))
				return
			}
		} else {
			if err := h.dbStore.UpdateProvider(ctx, provider, config); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update provider: %v", err))
				return
			}
		}
		if err := h.persistTenantProviderModels(ctx, provider, &config); err != nil {
			logger.Warn("Failed to persist tenant-scoped provider models for %s: %v", provider, err)
		}
		if err := h.attemptModelDiscovery(ctx, provider, payload.CustomProviderConfig); err != nil {
			logger.Warn("Tenant-scoped model discovery failed for provider %s: %v", provider, err)
		}
		// Per-tenant network config (PER_TENANT_NETWORK_CONFIG): drop the cached
		// tenant-scoped config so the new network_config (e.g. request timeout)
		// applies on the next live request without a restart. No-op when the
		// feature is off; the short cache TTL is the backstop if the keyed
		// invalidation ever misses (e.g. workspace-scope mismatch).
		h.client.InvalidateTenantProviderConfig(ctx, provider)

		redactedConfig, err := h.getStoredProviderConfigRedacted(ctx, provider)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get provider config: %v", err))
			return
		}
		SendJSON(ctx, h.getProviderResponseFromConfig(provider, *redactedConfig, ProviderStatusActive))
		return
	}

	// Add provider to store if it doesn't exist (upsert behavior)
	if _, err := h.inMemoryStore.GetProviderConfigRaw(provider); err != nil {
		if !errors.Is(err, lib.ErrNotFound) {
			logger.Warn("Failed to get provider %s: %v", provider, err)
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get provider: %v", err))
			return
		}
		// Adding the provider to store
		if err := h.inMemoryStore.AddProvider(ctx, provider, config); err != nil {
			// In an upsert flow, "already exists" is not fatal - the provider may have been
			// added concurrently or exist in the DB from a previous failed attempt.
			if !errors.Is(err, lib.ErrAlreadyExists) {
				logger.Warn("Failed to add provider %s: %v", provider, err)
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err))
				return
			}
			logger.Info("Provider %s already exists during upsert, proceeding with update", provider)
		}
	}

	// Update provider config in store (env vars will be processed by store)
	if err := h.inMemoryStore.UpdateProviderConfig(ctx, provider, config); err != nil {
		logger.Warn("Failed to update provider %s: %v", provider, err)
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update provider: %v", err))
		return
	}
	if h.inMemoryStore.ModelCatalog != nil {
		if err := h.inMemoryStore.ModelCatalog.SetProviderPricingOverrides(provider, config.PricingOverrides); err != nil {
			logger.Warn("Failed to set pricing overrides for provider %s: %v", provider, err)
		}
	}

	// Attempt model discovery
	err = h.attemptModelDiscovery(ctx, provider, payload.CustomProviderConfig)

	if err != nil {
		logger.Warn("Model discovery failed for provider %s: %v", provider, err)
	}

	// Get redacted config for response (in-memory store is now updated by updateKeyStatus)
	redactedConfig, err := h.getStoredProviderConfigRedacted(ctx, provider)
	if err != nil {
		logger.Warn("Failed to get redacted config for provider %s: %v", provider, err)
		// Fall back to sanitized config (no keys)
		response := h.getProviderResponseFromConfig(provider, configstore.ProviderConfig{
			NetworkConfig:            config.NetworkConfig,
			ConcurrencyAndBufferSize: config.ConcurrencyAndBufferSize,
			ProxyConfig:              config.ProxyConfig,
			SendBackRawRequest:       config.SendBackRawRequest,
			SendBackRawResponse:      config.SendBackRawResponse,
			CustomProviderConfig:     config.CustomProviderConfig,
			PricingOverrides:         config.PricingOverrides,
			Status:                   config.Status,
			Description:              config.Description,
		}, ProviderStatusActive)
		SendJSON(ctx, response)
		return
	}

	response := h.getProviderResponseFromConfig(provider, *redactedConfig, ProviderStatusActive)

	SendJSON(ctx, response)
}

// deleteProvider handles DELETE /api/providers/{provider} - Remove provider
func (h *ProviderHandler) deleteProvider(ctx *fasthttp.RequestCtx) {
	provider, err := getProviderFromCtx(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid provider: %v", err))
		return
	}

	if h.isTenantScoped(ctx) {
		exists, err := h.providerExists(ctx, provider)
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Failed to get provider: %v", err))
			return
		}
		if exists {
			if err := h.dbStore.DeleteProvider(ctx, provider); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete provider: %v", err))
				return
			}
		}

		SendJSON(ctx, ProviderResponse{Name: provider})
		return
	}

	// Check if provider exists
	if _, err := h.inMemoryStore.GetProviderConfigRedacted(provider); err != nil && !errors.Is(err, lib.ErrNotFound) {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Failed to get provider: %v", err))
		return
	}

	if err := h.modelsManager.RemoveProvider(ctx, provider); err != nil {
		logger.Warn("Failed to delete models for provider %s: %v", provider, err)
	}

	response := ProviderResponse{
		Name: provider,
	}

	SendJSON(ctx, response)
}

// listKeys handles GET /api/keys - List all keys
func (h *ProviderHandler) listKeys(ctx *fasthttp.RequestCtx) {
	keys, err := h.listStoredKeys(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get keys: %v", err))
		return
	}

	SendJSON(ctx, keys)
}

// ModelResponse represents a single model in the response
type ModelResponse struct {
	Name             string   `json:"name"`
	Provider         string   `json:"provider"`
	AccessibleByKeys []string `json:"accessible_by_keys,omitempty"`
}

// ListModelsResponse represents the response for listing models
type ListModelsResponse struct {
	Models []ModelResponse `json:"models"`
	Total  int             `json:"total"`
}

// listModels handles GET /api/models - List models with filtering
// Query parameters:
//   - query: Filter models by name (case-insensitive partial match)
//   - provider: Filter by specific provider name
//   - keys: Comma-separated list of key IDs to filter models accessible by those keys
//   - limit: Maximum number of results to return (default: 5)
func (h *ProviderHandler) listModels(ctx *fasthttp.RequestCtx) {
	// Parse query parameters
	queryParam := string(ctx.QueryArgs().Peek("query"))
	providerParam := string(ctx.QueryArgs().Peek("provider"))
	keysParam := string(ctx.QueryArgs().Peek("keys"))
	limitParam := string(ctx.QueryArgs().Peek("limit"))
	unfilteredParam := string(ctx.QueryArgs().Peek("unfiltered"))

	unfiltered := unfilteredParam == "true"

	// Parse limit with default
	limit := 5
	if limitParam != "" {
		if n, err := ctx.QueryArgs().GetUint("limit"); err == nil {
			limit = n
		}
	}

	var allModels []ModelResponse

	// If provider is specified, get models for that provider only
	if providerParam != "" {
		provider := schemas.ModelProvider(providerParam)
		if h.isTenantScoped(ctx) {
			exists, err := h.providerExists(ctx, provider)
			if err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get provider: %v", err))
				return
			}
			if !exists {
				SendJSON(ctx, ListModelsResponse{Models: []ModelResponse{}, Total: 0})
				return
			}
		}

		var models []string
		if h.isTenantScoped(ctx) {
			var err error
			models, err = h.getTenantProviderModelNames(ctx, provider, unfiltered)
			if err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get models: %v", err))
				return
			}
		} else {
			if unfiltered {
				models = h.modelsManager.GetUnfilteredModelsForProvider(provider)
			} else {
				models = h.modelsManager.GetModelsForProvider(provider)
			}
		}
		if !unfiltered && keysParam != "" {
			keyIDs := strings.Split(keysParam, ",")
			models = h.filterModelsByKeys(ctx, provider, models, keyIDs)
		}
		for _, model := range models {
			allModels = append(allModels, ModelResponse{
				Name:     model,
				Provider: string(provider),
			})
		}
	} else {
		keyIDs := []string(nil)
		if !unfiltered && keysParam != "" {
			keyIDs = strings.Split(keysParam, ",")
		}

		if h.isTenantScoped(ctx) {
			providerModels, err := h.getTenantProviderModels(ctx, unfiltered)
			if err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get providers: %v", err))
				return
			}
			providers := make([]schemas.ModelProvider, 0, len(providerModels))
			for provider := range providerModels {
				providers = append(providers, provider)
			}
			sort.Slice(providers, func(i, j int) bool {
				return providers[i] < providers[j]
			})
			for _, provider := range providers {
				models := providerModels[provider]
				if len(keyIDs) > 0 {
					models = h.filterModelsByKeys(ctx, provider, models, keyIDs)
				}
				for _, model := range models {
					allModels = append(allModels, ModelResponse{
						Name:     model,
						Provider: string(provider),
					})
				}
			}
		} else {
			providersConfig, err := h.getStoredProvidersConfig(ctx)
			if err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get providers: %v", err))
				return
			}
			providers := make([]schemas.ModelProvider, 0, len(providersConfig))
			for provider := range providersConfig {
				providers = append(providers, provider)
			}

			// Collect models from all providers
			for _, provider := range providers {
				var models []string
				if unfiltered {
					models = h.modelsManager.GetUnfilteredModelsForProvider(provider)
				} else {
					models = h.modelsManager.GetModelsForProvider(provider)
				}
				if len(keyIDs) > 0 {
					models = h.filterModelsByKeys(ctx, provider, models, keyIDs)
				}
				for _, model := range models {
					allModels = append(allModels, ModelResponse{
						Name:     model,
						Provider: string(provider),
					})
				}
			}
		}
	}

	// Apply query filter if provided (fuzzy search)
	// We are currently doing it in memory to later make use of in memory model pools
	if queryParam != "" {
		filtered := []ModelResponse{}
		queryLower := strings.ToLower(queryParam)
		// Remove common separators for more flexible matching
		queryNormalized := strings.ReplaceAll(strings.ReplaceAll(queryLower, "-", ""), "_", "")

		for _, model := range allModels {
			modelLower := strings.ToLower(model.Name)
			modelNormalized := strings.ReplaceAll(strings.ReplaceAll(modelLower, "-", ""), "_", "")

			// Match if:
			// 1. Direct substring match
			// 2. Normalized substring match (ignoring - and _)
			// 3. All query characters appear in order (fuzzy match)
			if strings.Contains(modelLower, queryLower) ||
				strings.Contains(modelNormalized, queryNormalized) ||
				fuzzyMatch(modelLower, queryLower) {
				filtered = append(filtered, model)
			}
		}
		allModels = filtered
	}

	// Apply limit
	total := len(allModels)
	if limit > 0 && limit < len(allModels) {
		allModels = allModels[:limit]
	}

	response := ListModelsResponse{
		Models: allModels,
		Total:  total,
	}

	SendJSON(ctx, response)
}

// getModelParameters handles GET /api/models/parameters - Get model parameters for a specific model
// Query parameters:
//   - model: The model name to get parameters for (required)
func (h *ProviderHandler) getModelParameters(ctx *fasthttp.RequestCtx) {
	modelParam := string(ctx.QueryArgs().Peek("model"))
	if modelParam == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "model query parameter is required")
		return
	}

	if h.dbStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "database store not available")
		return
	}

	params, err := h.dbStore.GetModelParameters(ctx, modelParam)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			SendError(ctx, fasthttp.StatusNotFound, fmt.Sprintf("no parameters found for model %s", modelParam))
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get model parameters: %v", err))
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(params.Data)
}

// filterModelsByKeys filters models based on key-level model restrictions
func (h *ProviderHandler) filterModelsByKeys(ctx context.Context, provider schemas.ModelProvider, models []string, keyIDs []string) []string {
	// Get provider config to access keys
	config, err := h.getStoredProviderConfigRaw(ctx, provider)
	if err != nil {
		logger.Warn("Failed to get config for provider %s: %v", provider, err)
		return models
	}
	// Build a set of allowed models from the specified keys
	// Track whether we have any unrestricted keys (which grant access to all models)
	// and whether we have any restricted keys (which limit to specific models)
	allowedModels := make(map[string]bool)
	hasRestrictedKey := false
	hasUnrestrictedKey := false
	for _, keyID := range keyIDs {
		for _, key := range config.Keys {
			if key.ID == keyID {
				if len(key.Models) > 0 {
					// Key has model restrictions - add them to allowedModels
					hasRestrictedKey = true
					for _, model := range key.Models {
						allowedModels[model] = true
					}
				} else {
					// Key has no model restrictions - grants access to all models
					hasUnrestrictedKey = true
				}
				break
			}
		}
	}
	// If any key is unrestricted, return all models (union of "all" and restricted subsets is "all")
	if hasUnrestrictedKey {
		return models
	}
	// If no keys have model restrictions (e.g., unknown key IDs), return all models
	if !hasRestrictedKey {
		return models
	}
	// Filter models based on restrictions from restricted keys only
	filtered := []string{}
	for _, model := range models {
		if allowedModels[model] {
			filtered = append(filtered, model)
		}
	}
	return filtered
}

// ListBaseModelsResponse represents the response for listing base models
type ListBaseModelsResponse struct {
	Models []string `json:"models"`
	Total  int      `json:"total"`
}

// listBaseModels handles GET /api/models/base - List distinct base model names from the catalog
// Query parameters:
//   - query: Filter base models by name (case-insensitive partial match)
//   - limit: Maximum number of results to return (default: 20)
func (h *ProviderHandler) listBaseModels(ctx *fasthttp.RequestCtx) {
	queryParam := string(ctx.QueryArgs().Peek("query"))
	limitParam := string(ctx.QueryArgs().Peek("limit"))

	limit := 20
	if limitParam != "" {
		if n, err := ctx.QueryArgs().GetUint("limit"); err == nil {
			limit = n
		}
	}

	var baseModels []string
	if h.isTenantScoped(ctx) {
		var err error
		baseModels, err = h.getTenantBaseModels(ctx)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get base models: %v", err))
			return
		}
	} else {
		modelCatalog := h.inMemoryStore.ModelCatalog
		if modelCatalog == nil {
			SendJSON(ctx, ListBaseModelsResponse{Models: []string{}, Total: 0})
			return
		}
		baseModels = modelCatalog.GetDistinctBaseModelNames()
		sort.Strings(baseModels)
	}

	// Apply query filter if provided
	if queryParam != "" {
		filtered := []string{}
		queryLower := strings.ToLower(queryParam)
		queryNormalized := strings.ReplaceAll(strings.ReplaceAll(queryLower, "-", ""), "_", "")

		for _, model := range baseModels {
			modelLower := strings.ToLower(model)
			modelNormalized := strings.ReplaceAll(strings.ReplaceAll(modelLower, "-", ""), "_", "")

			if strings.Contains(modelLower, queryLower) ||
				strings.Contains(modelNormalized, queryNormalized) ||
				fuzzyMatch(modelLower, queryLower) {
				filtered = append(filtered, model)
			}
		}
		baseModels = filtered
	}

	total := len(baseModels)
	if limit > 0 && limit < len(baseModels) {
		baseModels = baseModels[:limit]
	}

	SendJSON(ctx, ListBaseModelsResponse{Models: baseModels, Total: total})
}

// mergeKeys merges new keys with old, preserving values that are redacted in the new config
func (h *ProviderHandler) mergeKeys(oldRawKeys []schemas.Key, oldRedactedKeys []schemas.Key, keysToAdd []schemas.Key, keysToDelete []schemas.Key, keysToUpdate []schemas.Key) ([]schemas.Key, error) {
	// Create a map of indices to delete
	toDelete := make(map[int]bool)
	for _, key := range keysToDelete {
		for i, oldKey := range oldRawKeys {
			if oldKey.ID == key.ID {
				toDelete[i] = true
				break
			}
		}
	}

	// Create a map of updates by ID for quick lookup
	updates := make(map[string]schemas.Key)
	for _, key := range keysToUpdate {
		updates[key.ID] = key
	}

	// Map old redacted keys by ID for reliable lookup
	redactedByID := make(map[string]schemas.Key)
	for _, rk := range oldRedactedKeys {
		redactedByID[rk.ID] = rk
	}

	// Process existing keys (handle updates and deletions)
	var resultKeys []schemas.Key
	for i, oldRawKey := range oldRawKeys {
		// Skip if this key should be deleted
		if toDelete[i] {
			continue
		}
		// Check if this key should be updated
		if updateKey, exists := updates[oldRawKey.ID]; exists {
			oldRedactedKey, ok := redactedByID[oldRawKey.ID]
			if !ok {
				oldRedactedKey = schemas.Key{}
			}
			mergedKey := updateKey

			// Handle redacted values - preserve old value if new value is redacted/env var AND it's the same as old redacted value
			if updateKey.Value.IsRedacted() &&
				updateKey.Value.Equals(&oldRedactedKey.Value) {
				mergedKey.Value = oldRawKey.Value
			}

			// Handle Azure config redacted values
			if updateKey.AzureKeyConfig != nil && oldRedactedKey.AzureKeyConfig != nil && oldRawKey.AzureKeyConfig != nil {
				if updateKey.AzureKeyConfig.Endpoint.IsRedacted() &&
					updateKey.AzureKeyConfig.Endpoint.Equals(&oldRedactedKey.AzureKeyConfig.Endpoint) {
					mergedKey.AzureKeyConfig.Endpoint = oldRawKey.AzureKeyConfig.Endpoint
				}
				if updateKey.AzureKeyConfig.APIVersion != nil &&
					oldRedactedKey.AzureKeyConfig.APIVersion != nil &&
					oldRawKey.AzureKeyConfig != nil {
					if updateKey.AzureKeyConfig.APIVersion.IsRedacted() &&
						updateKey.AzureKeyConfig.APIVersion.Equals(oldRedactedKey.AzureKeyConfig.APIVersion) {
						mergedKey.AzureKeyConfig.APIVersion = oldRawKey.AzureKeyConfig.APIVersion
					}
				}
				// handle client id and secret and tenant id
				if updateKey.AzureKeyConfig.ClientID != nil &&
					oldRedactedKey.AzureKeyConfig.ClientID != nil &&
					oldRawKey.AzureKeyConfig != nil {
					if updateKey.AzureKeyConfig.ClientID.IsRedacted() &&
						updateKey.AzureKeyConfig.ClientID.Equals(oldRedactedKey.AzureKeyConfig.ClientID) {
						mergedKey.AzureKeyConfig.ClientID = oldRawKey.AzureKeyConfig.ClientID
					}
				}
				if updateKey.AzureKeyConfig.ClientSecret != nil &&
					oldRedactedKey.AzureKeyConfig.ClientSecret != nil &&
					oldRawKey.AzureKeyConfig != nil {
					if updateKey.AzureKeyConfig.ClientSecret.IsRedacted() &&
						updateKey.AzureKeyConfig.ClientSecret.Equals(oldRedactedKey.AzureKeyConfig.ClientSecret) {
						mergedKey.AzureKeyConfig.ClientSecret = oldRawKey.AzureKeyConfig.ClientSecret
					}
				}
				if updateKey.AzureKeyConfig.TenantID != nil &&
					oldRedactedKey.AzureKeyConfig.TenantID != nil &&
					oldRawKey.AzureKeyConfig != nil {
					if updateKey.AzureKeyConfig.TenantID.IsRedacted() &&
						updateKey.AzureKeyConfig.TenantID.Equals(oldRedactedKey.AzureKeyConfig.TenantID) {
						mergedKey.AzureKeyConfig.TenantID = oldRawKey.AzureKeyConfig.TenantID
					}
				}
			}

			// Handle Vertex config redacted values
			if updateKey.VertexKeyConfig != nil && oldRedactedKey.VertexKeyConfig != nil && oldRawKey.VertexKeyConfig != nil {
				if updateKey.VertexKeyConfig.ProjectID.IsRedacted() &&
					updateKey.VertexKeyConfig.ProjectID.Equals(&oldRedactedKey.VertexKeyConfig.ProjectID) {
					mergedKey.VertexKeyConfig.ProjectID = oldRawKey.VertexKeyConfig.ProjectID
				}
				if updateKey.VertexKeyConfig.ProjectNumber.IsRedacted() &&
					updateKey.VertexKeyConfig.ProjectNumber.Equals(&oldRedactedKey.VertexKeyConfig.ProjectNumber) {
					mergedKey.VertexKeyConfig.ProjectNumber = oldRawKey.VertexKeyConfig.ProjectNumber
				}
				if updateKey.VertexKeyConfig.Region.IsRedacted() &&
					updateKey.VertexKeyConfig.Region.Equals(&oldRedactedKey.VertexKeyConfig.Region) {
					mergedKey.VertexKeyConfig.Region = oldRawKey.VertexKeyConfig.Region
				}
				if updateKey.VertexKeyConfig.AuthCredentials.IsRedacted() &&
					updateKey.VertexKeyConfig.AuthCredentials.Equals(&oldRedactedKey.VertexKeyConfig.AuthCredentials) {
					mergedKey.VertexKeyConfig.AuthCredentials = oldRawKey.VertexKeyConfig.AuthCredentials
				}
			}

			// Handle Bedrock config redacted values
			if updateKey.BedrockKeyConfig != nil && oldRedactedKey.BedrockKeyConfig != nil && oldRawKey.BedrockKeyConfig != nil {
				if updateKey.BedrockKeyConfig.AccessKey.IsRedacted() &&
					updateKey.BedrockKeyConfig.AccessKey.Equals(&oldRedactedKey.BedrockKeyConfig.AccessKey) {
					mergedKey.BedrockKeyConfig.AccessKey = oldRawKey.BedrockKeyConfig.AccessKey
				}
				if updateKey.BedrockKeyConfig.SecretKey.IsRedacted() &&
					updateKey.BedrockKeyConfig.SecretKey.Equals(&oldRedactedKey.BedrockKeyConfig.SecretKey) {
					mergedKey.BedrockKeyConfig.SecretKey = oldRawKey.BedrockKeyConfig.SecretKey
				}
				if updateKey.BedrockKeyConfig.SessionToken != nil &&
					oldRedactedKey.BedrockKeyConfig.SessionToken != nil &&
					oldRawKey.BedrockKeyConfig != nil {
					if updateKey.BedrockKeyConfig.SessionToken.IsRedacted() &&
						updateKey.BedrockKeyConfig.SessionToken.Equals(oldRedactedKey.BedrockKeyConfig.SessionToken) {
						mergedKey.BedrockKeyConfig.SessionToken = oldRawKey.BedrockKeyConfig.SessionToken
					}
				}
				if updateKey.BedrockKeyConfig.Region != nil &&
					oldRedactedKey.BedrockKeyConfig.Region != nil &&
					oldRawKey.BedrockKeyConfig != nil {
					if updateKey.BedrockKeyConfig.Region.IsRedacted() &&
						updateKey.BedrockKeyConfig.Region.Equals(oldRedactedKey.BedrockKeyConfig.Region) {
						mergedKey.BedrockKeyConfig.Region = oldRawKey.BedrockKeyConfig.Region
					}
				}
				if updateKey.BedrockKeyConfig.ARN != nil &&
					oldRedactedKey.BedrockKeyConfig.ARN != nil &&
					oldRawKey.BedrockKeyConfig != nil {
					if updateKey.BedrockKeyConfig.ARN.IsRedacted() &&
						updateKey.BedrockKeyConfig.ARN.Equals(oldRedactedKey.BedrockKeyConfig.ARN) {
						mergedKey.BedrockKeyConfig.ARN = oldRawKey.BedrockKeyConfig.ARN
					}
				}
				if updateKey.BedrockKeyConfig.RoleARN != nil &&
					oldRedactedKey.BedrockKeyConfig.RoleARN != nil &&
					oldRawKey.BedrockKeyConfig != nil {
					if updateKey.BedrockKeyConfig.RoleARN.IsRedacted() &&
						updateKey.BedrockKeyConfig.RoleARN.Equals(oldRedactedKey.BedrockKeyConfig.RoleARN) {
						mergedKey.BedrockKeyConfig.RoleARN = oldRawKey.BedrockKeyConfig.RoleARN
					}
				}
				if updateKey.BedrockKeyConfig.ExternalID != nil &&
					oldRedactedKey.BedrockKeyConfig.ExternalID != nil &&
					oldRawKey.BedrockKeyConfig != nil {
					if updateKey.BedrockKeyConfig.ExternalID.IsRedacted() &&
						updateKey.BedrockKeyConfig.ExternalID.Equals(oldRedactedKey.BedrockKeyConfig.ExternalID) {
						mergedKey.BedrockKeyConfig.ExternalID = oldRawKey.BedrockKeyConfig.ExternalID
					}
				}
				if updateKey.BedrockKeyConfig.RoleSessionName != nil &&
					oldRedactedKey.BedrockKeyConfig.RoleSessionName != nil &&
					oldRawKey.BedrockKeyConfig != nil {
					if updateKey.BedrockKeyConfig.RoleSessionName.IsRedacted() &&
						updateKey.BedrockKeyConfig.RoleSessionName.Equals(oldRedactedKey.BedrockKeyConfig.RoleSessionName) {
						mergedKey.BedrockKeyConfig.RoleSessionName = oldRawKey.BedrockKeyConfig.RoleSessionName
					}
				}
			}

			// Handle VLLM config redacted values
			if updateKey.VLLMKeyConfig != nil && oldRedactedKey.VLLMKeyConfig != nil && oldRawKey.VLLMKeyConfig != nil {
				if updateKey.VLLMKeyConfig.URL.IsRedacted() &&
					updateKey.VLLMKeyConfig.URL.Equals(&oldRedactedKey.VLLMKeyConfig.URL) {
					mergedKey.VLLMKeyConfig.URL = oldRawKey.VLLMKeyConfig.URL
				}
			}

			// Preserve ConfigHash from old key (UI doesn't send it back)
			mergedKey.ConfigHash = oldRawKey.ConfigHash

			// Preserve Status and Description from old key (UI doesn't send them back, they're updated by model discovery)
			mergedKey.Status = oldRawKey.Status
			mergedKey.Description = oldRawKey.Description

			resultKeys = append(resultKeys, mergedKey)
		} else {
			// Keep unchanged key
			resultKeys = append(resultKeys, oldRawKey)
		}
	}

	// Add new keys
	resultKeys = append(resultKeys, keysToAdd...)

	return resultKeys, nil
}

// attemptModelDiscovery performs model discovery with timeout
func (h *ProviderHandler) attemptModelDiscovery(ctx context.Context, provider schemas.ModelProvider, customProviderConfig *schemas.CustomProviderConfig) error {
	if h.modelsManager == nil {
		return nil
	}

	// Determine if we should attempt model discovery
	shouldDiscoverModels := customProviderConfig == nil ||
		!customProviderConfig.IsKeyLess

	if !shouldDiscoverModels {
		return nil
	}

	// Attempt model discovery with reasonable timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err := h.modelsManager.ReloadProvider(ctxWithTimeout, provider)

	if err != nil {
		return err
	}

	return nil
}

func (h *ProviderHandler) getProviderResponseFromConfig(provider schemas.ModelProvider, config configstore.ProviderConfig, status ProviderStatus) ProviderResponse {
	if config.NetworkConfig == nil {
		config.NetworkConfig = &schemas.DefaultNetworkConfig
	}
	if config.ConcurrencyAndBufferSize == nil {
		config.ConcurrencyAndBufferSize = &schemas.DefaultConcurrencyAndBufferSize
	}

	return ProviderResponse{
		Name:                     provider,
		Keys:                     config.Keys,
		NetworkConfig:            *config.NetworkConfig,
		ConcurrencyAndBufferSize: *config.ConcurrencyAndBufferSize,
		ProxyConfig:              config.ProxyConfig,
		SendBackRawRequest:       config.SendBackRawRequest,
		SendBackRawResponse:      config.SendBackRawResponse,
		CustomProviderConfig:     config.CustomProviderConfig,
		PricingOverrides:         config.PricingOverrides,
		ProviderStatus:           status,
		Status:                   config.Status,
		Description:              config.Description,
		ConfigHash:               config.ConfigHash,
	}
}

func validatePricingOverrides(overrides []schemas.ProviderPricingOverride) error {
	for i, override := range overrides {
		if strings.TrimSpace(override.ModelPattern) == "" {
			return fmt.Errorf("override[%d]: model_pattern is required", i)
		}

		switch override.MatchType {
		case schemas.PricingOverrideMatchExact:
			if strings.Contains(override.ModelPattern, "*") {
				return fmt.Errorf("override[%d]: exact match_type cannot include '*'", i)
			}
		case schemas.PricingOverrideMatchWildcard:
			if !strings.Contains(override.ModelPattern, "*") {
				return fmt.Errorf("override[%d]: wildcard match_type requires '*' in model_pattern", i)
			}
		case schemas.PricingOverrideMatchRegex:
			if _, err := regexp.Compile(override.ModelPattern); err != nil {
				return fmt.Errorf("override[%d]: invalid regex pattern: %w", i, err)
			}
		default:
			return fmt.Errorf("override[%d]: unsupported match_type %q", i, override.MatchType)
		}

		for _, requestType := range override.RequestTypes {
			if !isSupportedOverrideRequestType(requestType) {
				return fmt.Errorf("override[%d]: unsupported request_type %q", i, requestType)
			}
		}

		if err := validatePricingOverrideNonNegativeFields(i, override); err != nil {
			return err
		}
	}

	return nil
}

func isSupportedOverrideRequestType(requestType schemas.RequestType) bool {
	switch requestType {
	case schemas.TextCompletionRequest,
		schemas.TextCompletionStreamRequest,
		schemas.ChatCompletionRequest,
		schemas.ChatCompletionStreamRequest,
		schemas.ResponsesRequest,
		schemas.ResponsesStreamRequest,
		schemas.EmbeddingRequest,
		schemas.RerankRequest,
		schemas.SpeechRequest,
		schemas.SpeechStreamRequest,
		schemas.TranscriptionRequest,
		schemas.TranscriptionStreamRequest,
		schemas.ImageGenerationRequest,
		schemas.ImageGenerationStreamRequest:
		return true
	default:
		return false
	}
}

func validatePricingOverrideNonNegativeFields(index int, override schemas.ProviderPricingOverride) error {
	optionalValues := map[string]*float64{
		"input_cost_per_token":                              override.InputCostPerToken,
		"output_cost_per_token":                             override.OutputCostPerToken,
		"input_cost_per_video_per_second":                   override.InputCostPerVideoPerSecond,
		"input_cost_per_audio_per_second":                   override.InputCostPerAudioPerSecond,
		"input_cost_per_character":                          override.InputCostPerCharacter,
		"input_cost_per_token_above_128k_tokens":            override.InputCostPerTokenAbove128kTokens,
		"input_cost_per_image_above_128k_tokens":            override.InputCostPerImageAbove128kTokens,
		"input_cost_per_video_per_second_above_128k_tokens": override.InputCostPerVideoPerSecondAbove128kTokens,
		"input_cost_per_audio_per_second_above_128k_tokens": override.InputCostPerAudioPerSecondAbove128kTokens,
		"output_cost_per_token_above_128k_tokens":           override.OutputCostPerTokenAbove128kTokens,
		"input_cost_per_token_above_200k_tokens":            override.InputCostPerTokenAbove200kTokens,
		"output_cost_per_token_above_200k_tokens":           override.OutputCostPerTokenAbove200kTokens,
		"cache_creation_input_token_cost_above_200k_tokens": override.CacheCreationInputTokenCostAbove200kTokens,
		"cache_read_input_token_cost_above_200k_tokens":     override.CacheReadInputTokenCostAbove200kTokens,
		"cache_read_input_token_cost":                       override.CacheReadInputTokenCost,
		"cache_creation_input_token_cost":                   override.CacheCreationInputTokenCost,
		"input_cost_per_token_batches":                      override.InputCostPerTokenBatches,
		"output_cost_per_token_batches":                     override.OutputCostPerTokenBatches,
		"input_cost_per_image_token":                        override.InputCostPerImageToken,
		"output_cost_per_image_token":                       override.OutputCostPerImageToken,
		"input_cost_per_image":                              override.InputCostPerImage,
		"output_cost_per_image":                             override.OutputCostPerImage,
		"cache_read_input_image_token_cost":                 override.CacheReadInputImageTokenCost,
	}

	for fieldName, value := range optionalValues {
		if value != nil && *value < 0 {
			return fmt.Errorf("override[%d]: %s must be non-negative", index, fieldName)
		}
	}

	return nil
}

func getProviderFromCtx(ctx *fasthttp.RequestCtx) (schemas.ModelProvider, error) {
	providerValue := ctx.UserValue("provider")
	if providerValue == nil {
		return "", fmt.Errorf("missing provider parameter")
	}
	providerStr, ok := providerValue.(string)
	if !ok {
		return "", fmt.Errorf("invalid provider parameter type")
	}

	decoded, err := url.PathUnescape(providerStr)
	if err != nil {
		return "", fmt.Errorf("invalid provider parameter encoding: %v", err)
	}

	return schemas.ModelProvider(decoded), nil
}

func validateRetryBackoff(networkConfig *schemas.NetworkConfig) error {
	if networkConfig != nil {
		if networkConfig.RetryBackoffInitial > 0 {
			if networkConfig.RetryBackoffInitial < lib.MinRetryBackoff {
				return fmt.Errorf("retry backoff initial must be at least %v", lib.MinRetryBackoff)
			}
			if networkConfig.RetryBackoffInitial > lib.MaxRetryBackoff {
				return fmt.Errorf("retry backoff initial must be at most %v", lib.MaxRetryBackoff)
			}
		}
		if networkConfig.RetryBackoffMax > 0 {
			if networkConfig.RetryBackoffMax < lib.MinRetryBackoff {
				return fmt.Errorf("retry backoff max must be at least %v", lib.MinRetryBackoff)
			}
			if networkConfig.RetryBackoffMax > lib.MaxRetryBackoff {
				return fmt.Errorf("retry backoff max must be at most %v", lib.MaxRetryBackoff)
			}
		}
		if networkConfig.RetryBackoffInitial > 0 && networkConfig.RetryBackoffMax > 0 {
			if networkConfig.RetryBackoffInitial > networkConfig.RetryBackoffMax {
				return fmt.Errorf("retry backoff initial must be less than or equal to retry backoff max")
			}
		}
	}
	return nil
}
