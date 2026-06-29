package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	deepintshield "github.com/deepint-shield/ai-security/core"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/encrypt"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/framework/migrator"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/framework/vectorstore"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RDBConfigStore represents a configuration store that uses a relational database.
type RDBConfigStore struct {
	db     *gorm.DB
	logger schemas.Logger
}

// NewRDBConfigStoreFromDB wraps a pre-configured *gorm.DB in an
// RDBConfigStore without running migrations or registering tenant
// callbacks. Intended for tests in other packages that need a working
// ConfigStore against an in-memory SQLite they've already set up - the
// full NewConfigStore path is heavy (runs every migration in
// migrations.go) and currently trips a pre-existing SQLite syntax bug in
// the orphan-guardrail-wrapper migration.
func NewRDBConfigStoreFromDB(db *gorm.DB, logger schemas.Logger) *RDBConfigStore {
	return &RDBConfigStore{db: db, logger: logger}
}

// getWeight safely dereferences a *float64 weight pointer, returning 1.0 as default if nil.
// This allows distinguishing between "not set" (nil -> 1.0) and "explicitly set to 0" (0.0).
func getWeight(w *float64) float64 {
	if w == nil {
		return 1.0
	}
	return *w
}

// UpdateClientConfig updates the client configuration in the database.
// In multi-tenant mode, this deletes only the current tenant's config row
// before re-creating it, preserving other tenants' configurations.
func (s *RDBConfigStore) UpdateClientConfig(ctx context.Context, config *ClientConfig) error {
	dbConfig := tables.TableClientConfig{
		DropExcessRequests:              config.DropExcessRequests,
		InitialPoolSize:                 config.InitialPoolSize,
		EnableLogging:                   config.EnableLogging,
		DisableContentLogging:           config.DisableContentLogging,
		DisableDBPingsInHealth:          config.DisableDBPingsInHealth,
		LogRetentionDays:                config.LogRetentionDays,
		EnforceAuthOnInference:          config.EnforceAuthOnInference,
		EnforceGovernanceHeader:         config.EnforceGovernanceHeader,
		EnforceSCIMAuth:                 config.EnforceSCIMAuth,
		AllowDirectKeys:                 config.AllowDirectKeys,
		PrometheusLabels:                config.PrometheusLabels,
		AllowedOrigins:                  config.AllowedOrigins,
		AllowedHeaders:                  config.AllowedHeaders,
		MaxRequestBodySizeMB:            config.MaxRequestBodySizeMB,
		EnableLiteLLMFallbacks:          config.EnableLiteLLMFallbacks,
		MCPAgentDepth:                   config.MCPAgentDepth,
		MCPToolExecutionTimeout:         config.MCPToolExecutionTimeout,
		MCPCodeModeBindingLevel:         config.MCPCodeModeBindingLevel,
		MCPToolSyncInterval:             config.MCPToolSyncInterval,
		MCPCacheEnabled:                 config.MCPCacheEnabled,
		MCPCacheTTLSeconds:              config.MCPCacheTTLSeconds,
		AsyncJobResultTTL:               config.AsyncJobResultTTL,
		RequiredHeaders:                 config.RequiredHeaders,
		LoggingHeaders:                  config.LoggingHeaders,
		HideDeletedVirtualKeysInFilters: config.HideDeletedVirtualKeysInFilters,
		HeaderFilterConfig:              config.HeaderFilterConfig,
		LoadBalancerEnabled:             config.LoadBalancerEnabled,
		ConfigHash:                      config.ConfigHash,
	}
	// Delete existing client config for this tenant and create new one in a transaction.
	// Use Where("1=1") to satisfy GORM's safety check while still letting the
	// tenant-scoping callback add the tenant_id filter automatically.
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1=1").Delete(&tables.TableClientConfig{}).Error; err != nil {
			return err
		}
		return tx.Create(&dbConfig).Error
	})
}

// Ping checks if the database is reachable.
func (s *RDBConfigStore) Ping(ctx context.Context) error {
	return s.db.WithContext(ctx).Exec("SELECT 1").Error
}

// DB returns the underlying database connection.
func (s *RDBConfigStore) DB() *gorm.DB {
	return s.db
}

// parseGormError parses GORM errors to provide user-friendly error messages.
// Currently handles unique constraint violations and is designed to be extended
// for other error types in the future (e.g., foreign key violations, not null constraints).
func (s *RDBConfigStore) parseGormError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}

	errMsg := err.Error()

	// Check for unique constraint violations
	// SQLite format: "UNIQUE constraint failed: table_name.column_name"
	// PostgreSQL format: "ERROR: duplicate key value violates unique constraint"

	if strings.Contains(errMsg, "UNIQUE constraint failed") ||
		strings.Contains(errMsg, "duplicate key value violates unique constraint") {

		// Extract column name from error message
		var columnName string

		// SQLite: extract from "UNIQUE constraint failed: table.column"
		if strings.Contains(errMsg, "UNIQUE constraint failed") {
			parts := strings.Split(errMsg, "UNIQUE constraint failed:")
			if len(parts) > 1 {
				tableColumn := strings.TrimSpace(parts[1])
				// Extract column name after the last dot
				if dotIndex := strings.LastIndex(tableColumn, "."); dotIndex != -1 {
					columnName = tableColumn[dotIndex+1:]
				} else {
					columnName = tableColumn
				}
			}
		} else if strings.Contains(errMsg, "duplicate key value violates unique constraint") {
			// PostgreSQL: try to extract from constraint name or detail
			// Example: duplicate key value violates unique constraint "idx_key_name"
			// Detail: Key (name)=(value) already exists.

			// First try to extract from Detail
			if strings.Contains(errMsg, "Key (") {
				startIdx := strings.Index(errMsg, "Key (")
				if startIdx != -1 {
					rest := errMsg[startIdx+5:]
					endIdx := strings.Index(rest, ")")
					if endIdx != -1 {
						columnName = rest[:endIdx]
					}
				}
			}
			// If not found, try to parse from constraint name
			if columnName == "" {
				// Extract constraint name
				if strings.Contains(errMsg, `"`) {
					parts := strings.Split(errMsg, `"`)
					if len(parts) >= 2 {
						constraintName := parts[1]
						// Remove idx_ prefix and try to extract column name
						if strings.HasPrefix(constraintName, "idx_") {
							constraintName = constraintName[4:]
							// Find the last underscore to get column name
							if lastUnderscore := strings.LastIndex(constraintName, "_"); lastUnderscore != -1 {
								columnName = constraintName[lastUnderscore+1:]
							} else {
								columnName = constraintName
							}
						}
					}
				}
			}
		}
		// Clean up column name (remove underscores, convert to readable format)
		if columnName != "" {
			// Convert snake_case to space-separated words
			columnName = strings.ReplaceAll(columnName, "_", " ")
			return fmt.Errorf("a record with this %s %w. Please use a different value", columnName, ErrAlreadyExists)
		}
		// Fallback message if we couldn't parse the column name
		return fmt.Errorf("a record with this value %w. Please use a different value", ErrAlreadyExists)
	}

	// For other errors, return the original error
	// Future: add handling for foreign key violations, not null constraints, etc.
	return err
}

// UpdateFrameworkConfig updates the framework configuration in the database.
func (s *RDBConfigStore) UpdateFrameworkConfig(ctx context.Context, config *tables.TableFrameworkConfig) error {
	// Update the framework configuration
	return s.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1=1").Delete(&tables.TableFrameworkConfig{}).Error; err != nil {
			return err
		}
		return tx.Create(config).Error
	})
}

// GetFrameworkConfig retrieves the framework configuration from the database.
func (s *RDBConfigStore) GetFrameworkConfig(ctx context.Context) (*tables.TableFrameworkConfig, error) {
	var dbConfig tables.TableFrameworkConfig
	if err := s.db.WithContext(ctx).First(&dbConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &dbConfig, nil
}

// GetClientConfig retrieves the client configuration from the database.
func (s *RDBConfigStore) GetClientConfig(ctx context.Context) (*ClientConfig, error) {
	var dbConfig tables.TableClientConfig
	if err := s.db.WithContext(ctx).First(&dbConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &ClientConfig{
		DropExcessRequests:              dbConfig.DropExcessRequests,
		InitialPoolSize:                 dbConfig.InitialPoolSize,
		PrometheusLabels:                dbConfig.PrometheusLabels,
		EnableLogging:                   dbConfig.EnableLogging,
		DisableContentLogging:           dbConfig.DisableContentLogging,
		DisableDBPingsInHealth:          dbConfig.DisableDBPingsInHealth,
		LogRetentionDays:                dbConfig.LogRetentionDays,
		EnforceAuthOnInference:          dbConfig.EnforceAuthOnInference,
		EnforceGovernanceHeader:         dbConfig.EnforceGovernanceHeader,
		EnforceSCIMAuth:                 dbConfig.EnforceSCIMAuth,
		AllowDirectKeys:                 dbConfig.AllowDirectKeys,
		AllowedOrigins:                  dbConfig.AllowedOrigins,
		AllowedHeaders:                  dbConfig.AllowedHeaders,
		MaxRequestBodySizeMB:            dbConfig.MaxRequestBodySizeMB,
		EnableLiteLLMFallbacks:          dbConfig.EnableLiteLLMFallbacks,
		MCPAgentDepth:                   dbConfig.MCPAgentDepth,
		MCPToolExecutionTimeout:         dbConfig.MCPToolExecutionTimeout,
		MCPCodeModeBindingLevel:         dbConfig.MCPCodeModeBindingLevel,
		MCPToolSyncInterval:             dbConfig.MCPToolSyncInterval,
		MCPCacheEnabled:                 dbConfig.MCPCacheEnabled,
		MCPCacheTTLSeconds:              dbConfig.MCPCacheTTLSeconds,
		AsyncJobResultTTL:               dbConfig.AsyncJobResultTTL,
		RequiredHeaders:                 dbConfig.RequiredHeaders,
		LoggingHeaders:                  dbConfig.LoggingHeaders,
		HideDeletedVirtualKeysInFilters: dbConfig.HideDeletedVirtualKeysInFilters,
		HeaderFilterConfig:              dbConfig.HeaderFilterConfig,
		LoadBalancerEnabled:             dbConfig.LoadBalancerEnabled,
		ConfigHash:                      dbConfig.ConfigHash,
	}, nil
}

// UpdateProvidersConfig updates the client configuration in the database.
func (s *RDBConfigStore) UpdateProvidersConfig(ctx context.Context, providers map[schemas.ModelProvider]ProviderConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	tenantID := tenantctx.TenantIDFromContext(ctx)
	for providerName, providerConfig := range providers {
		dbProvider := tables.TableProvider{
			TenantID:                 tenantID,
			Name:                     string(providerName),
			NetworkConfig:            providerConfig.NetworkConfig,
			ConcurrencyAndBufferSize: providerConfig.ConcurrencyAndBufferSize,
			ProxyConfig:              providerConfig.ProxyConfig,
			SendBackRawRequest:       providerConfig.SendBackRawRequest,
			SendBackRawResponse:      providerConfig.SendBackRawResponse,
			StoreRawRequestResponse:  providerConfig.StoreRawRequestResponse,
			CustomProviderConfig:     providerConfig.CustomProviderConfig,
			PricingOverrides:         providerConfig.PricingOverrides,
			ConfigHash:               providerConfig.ConfigHash,
			Status:                   providerConfig.Status,
			Description:              providerConfig.Description,
		}

		// Upsert provider (create or update if exists). Conflict target
		// is the new (tenant_id, workspace_id, name) unique index - the
		// older two-column index was swapped out by
		// migrationProviderUniqueIndexAddWorkspace so that the same
		// provider can co-exist in sibling workspaces. Without aligning
		// the OnConflict columns, the server crashes on boot with
		// "no unique or exclusion constraint matching the ON CONFLICT
		// specification (SQLSTATE 42P10)".
		//
		// Stamp the workspace_id from context (matches AddProvider) so
		// the upsert targets the right row even on initial create.
		if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
			dbProvider.WorkspaceID = &ws
		}
		// Manual lookup-then-update-or-insert. ON CONFLICT
		// (tenant_id, workspace_id, name) doesn't fire on SQLite
		// (and isn't strictly portable on Postgres either) when
		// workspace_id is NULL - SQLite treats NULLs as distinct in
		// unique indexes, so the conflict never matches and a
		// duplicate provider row is inserted instead of updating the
		// existing one. The result was orphaned keys (linked to the
		// stale provider_id) plus 0-key reads on the next
		// GetProvidersConfig.
		lookupQ := txDB.WithContext(ctx).
			Where("tenant_id = ? AND name = ?", dbProvider.TenantID, dbProvider.Name)
		if dbProvider.WorkspaceID != nil {
			lookupQ = lookupQ.Where("workspace_id = ?", *dbProvider.WorkspaceID)
		} else {
			lookupQ = lookupQ.Where("workspace_id IS NULL")
		}
		var existing tables.TableProvider
		findErr := lookupQ.First(&existing).Error
		if findErr == nil {
			dbProvider.ID = existing.ID
			if err := txDB.WithContext(ctx).Save(&dbProvider).Error; err != nil {
				return s.parseGormError(err)
			}
		} else if errors.Is(findErr, gorm.ErrRecordNotFound) {
			if err := txDB.WithContext(ctx).Create(&dbProvider).Error; err != nil {
				return s.parseGormError(err)
			}
		} else {
			return s.parseGormError(findErr)
		}

		// Create keys for this provider
		dbKeys := make([]tables.TableKey, 0, len(providerConfig.Keys))
		for _, key := range providerConfig.Keys {
			// Use existing ConfigHash if set (came from reconciliation with DB),
			// otherwise generate new hash (new key from config.json)
			keyHash := key.ConfigHash
			if keyHash == "" {
				var err error
				keyHash, err = GenerateKeyHash(key)
				if err != nil {
					return fmt.Errorf("failed to generate key hash: %w", err)
				}
			}
			dbKey := tables.TableKey{
				TenantID:           tenantID,
				Provider:           dbProvider.Name,
				ProviderID:         dbProvider.ID,
				KeyID:              key.ID,
				Name:               key.Name,
				Value:              key.Value,
				Models:             key.Models,
				Weight:             &key.Weight,
				Enabled:            key.Enabled,
				UseForBatchAPI:     key.UseForBatchAPI,
				UseForCache:        key.UseForCache,
				AzureKeyConfig:     key.AzureKeyConfig,
				VertexKeyConfig:    key.VertexKeyConfig,
				BedrockKeyConfig:   key.BedrockKeyConfig,
				ReplicateKeyConfig: key.ReplicateKeyConfig,
				VLLMKeyConfig:      key.VLLMKeyConfig,
				ConfigHash:         keyHash,
				Status:             string(key.Status),
				Description:        key.Description,
			}

			// Handle Azure config
			if key.AzureKeyConfig != nil {
				dbKey.AzureEndpoint = &key.AzureKeyConfig.Endpoint
				dbKey.AzureAPIVersion = key.AzureKeyConfig.APIVersion
			}

			// Handle Vertex config
			if key.VertexKeyConfig != nil {
				dbKey.VertexProjectID = &key.VertexKeyConfig.ProjectID
				dbKey.VertexProjectNumber = &key.VertexKeyConfig.ProjectNumber
				dbKey.VertexRegion = &key.VertexKeyConfig.Region
				dbKey.VertexAuthCredentials = &key.VertexKeyConfig.AuthCredentials
			}

			// Handle Bedrock config
			if key.BedrockKeyConfig != nil {
				dbKey.BedrockAccessKey = &key.BedrockKeyConfig.AccessKey
				dbKey.BedrockSecretKey = &key.BedrockKeyConfig.SecretKey
				dbKey.BedrockSessionToken = key.BedrockKeyConfig.SessionToken
				dbKey.BedrockRegion = key.BedrockKeyConfig.Region
				dbKey.BedrockARN = key.BedrockKeyConfig.ARN
				dbKey.BedrockRoleARN = key.BedrockKeyConfig.RoleARN
				dbKey.BedrockExternalID = key.BedrockKeyConfig.ExternalID
				dbKey.BedrockRoleSessionName = key.BedrockKeyConfig.RoleSessionName
				if key.BedrockKeyConfig.BatchS3Config != nil {
					data, err := sonic.Marshal(key.BedrockKeyConfig.BatchS3Config)
					if err != nil {
						return err
					}
					s := string(data)
					dbKey.BedrockBatchS3ConfigJSON = &s
				}
			} else {
				dbKey.BedrockBatchS3ConfigJSON = nil
			}

			dbKeys = append(dbKeys, dbKey)
		}

		persistedKeyIDs := make([]uint, 0, len(dbKeys))
		// Upsert keys to handle duplicates properly. Both lookups
		// (by key_id and by name) must scope to the parent provider's
		// workspace; without that, a key with the same KeyID/Name in a
		// sibling workspace would silently match here and we'd overwrite
		// THAT workspace's key. The caller already stamps dbKey.WorkspaceID
		// from the parent provider, so we use the same scope here.
		for i := range dbKeys {
			dbKey := &dbKeys[i]
			// First try to find existing key by KeyID within scope
			var existingKey tables.TableKey
			keyQ := txDB.WithContext(ctx).Where("key_id = ?", dbKey.KeyID)
			if dbKey.WorkspaceID != nil {
				keyQ = keyQ.Where("workspace_id = ?", *dbKey.WorkspaceID)
			}
			result := keyQ.First(&existingKey)

			if result.Error == nil {
				// Update existing key with new data
				dbKey.ID = existingKey.ID                             // Keep the same database ID
				dbKey.ProviderID = existingKey.ProviderID             // Preserve the existing ProviderID
				dbKey.Enabled = existingKey.Enabled                   // Preserve the existing Enabled status
				dbKey.Status = existingKey.Status                     // Preserve status (UI-managed)
				dbKey.Description = existingKey.Description           // Preserve description (UI-managed)
				dbKey.EncryptionStatus = existingKey.EncryptionStatus // Preserve encryption status
				if err := txDB.WithContext(ctx).Save(dbKey).Error; err != nil {
					return s.parseGormError(err)
				}
			} else if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				// KeyID not found, try fallback lookup by Name (handles config reload with new UUID)
				nameQ := txDB.WithContext(ctx).Where("name = ?", dbKey.Name)
				if dbKey.WorkspaceID != nil {
					nameQ = nameQ.Where("workspace_id = ?", *dbKey.WorkspaceID)
				}
				result = nameQ.First(&existingKey)
				if result.Error == nil {
					// Found by name - update existing key, preserve original KeyID
					dbKey.ID = existingKey.ID                             // Keep the same database ID
					dbKey.KeyID = existingKey.KeyID                       // Preserve original KeyID
					dbKey.ProviderID = existingKey.ProviderID             // Preserve the existing ProviderID
					dbKey.Enabled = existingKey.Enabled                   // Preserve the existing Enabled status
					dbKey.Status = existingKey.Status                     // Preserve status (UI-managed)
					dbKey.Description = existingKey.Description           // Preserve description (UI-managed)
					dbKey.EncryptionStatus = existingKey.EncryptionStatus // Preserve encryption status
					if err := txDB.WithContext(ctx).Save(dbKey).Error; err != nil {
						return s.parseGormError(err)
					}
				} else if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					// Neither KeyID nor Name found - create new key
					if err := txDB.WithContext(ctx).Create(dbKey).Error; err != nil {
						return s.parseGormError(err)
					}
				} else {
					// Other error occurred during name lookup
					return result.Error
				}
			} else {
				// Other error occurred
				return result.Error
			}

			persistedKeyIDs = append(persistedKeyIDs, dbKey.ID)
		}

		keysToDelete := txDB.WithContext(ctx).Where("provider_id = ?", dbProvider.ID)
		if len(persistedKeyIDs) > 0 {
			keysToDelete = keysToDelete.Where("id NOT IN ?", persistedKeyIDs)
		}
		if err := keysToDelete.Delete(&tables.TableKey{}).Error; err != nil {
			return s.parseGormError(err)
		}
	}
	return nil
}

// UpdateProvider updates a single provider configuration in the database without deleting/recreating.
//
// When called from a dashboard request with an active workspace
// (X-Active-Workspace-Id), the lookup narrows to that workspace's row.
// Without this narrowing, a provider name like "openai" that exists in
// two sibling workspaces resolves to whichever row GORM's `First`
// happens to pick (lowest id) - the symptom is "I added a key in
// workspace B but it shows up in workspace A". SDK / config-file
// callers without workspace context fall back to the first match,
// matching pre-workspace behaviour.
func (s *RDBConfigStore) UpdateProvider(ctx context.Context, provider schemas.ModelProvider, config ProviderConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Find the existing provider
	var dbProvider tables.TableProvider
	q := txDB.WithContext(ctx).Where("name = ?", string(provider))
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&dbProvider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	// Create a deep copy of the config to avoid modifying the original
	configCopy, err := deepCopy(config)
	if err != nil {
		return err
	}
	// Preserve ConfigHash (it has json:"-" tag so deepCopy via JSON doesn't copy it)
	configCopy.ConfigHash = config.ConfigHash
	if configCopy.ConfigHash == "" {
		configHash, hashErr := config.GenerateConfigHash(string(provider))
		if hashErr != nil {
			return fmt.Errorf("failed to generate provider hash: %w", hashErr)
		}
		configCopy.ConfigHash = configHash
	}
	// Update provider fields
	dbProvider.NetworkConfig = configCopy.NetworkConfig
	dbProvider.ConcurrencyAndBufferSize = configCopy.ConcurrencyAndBufferSize
	dbProvider.ProxyConfig = configCopy.ProxyConfig
	dbProvider.SendBackRawRequest = configCopy.SendBackRawRequest
	dbProvider.SendBackRawResponse = configCopy.SendBackRawResponse
	dbProvider.StoreRawRequestResponse = configCopy.StoreRawRequestResponse
	dbProvider.CustomProviderConfig = configCopy.CustomProviderConfig
	dbProvider.PricingOverrides = configCopy.PricingOverrides
	dbProvider.ConfigHash = configCopy.ConfigHash

	// Save the updated provider
	if err := txDB.WithContext(ctx).Save(&dbProvider).Error; err != nil {
		return s.parseGormError(err)
	}

	// Get existing keys for this provider
	var existingKeys []tables.TableKey
	if err := txDB.WithContext(ctx).Where("provider_id = ?", dbProvider.ID).Find(&existingKeys).Error; err != nil {
		return err
	}

	// Create a map of existing keys by KeyID for quick lookup
	existingKeysMap := make(map[string]tables.TableKey)
	existingKeysByName := make(map[string]tables.TableKey)
	for _, key := range existingKeys {
		existingKeysMap[key.KeyID] = key
		existingKeysByName[key.Name] = key
	}

	// Process each key in the new config
	for _, key := range configCopy.Keys {
		// Generate key hash
		keyHash, err := GenerateKeyHash(key)
		if err != nil {
			return fmt.Errorf("failed to generate key hash: %w", err)
		}
		dbKey := tables.TableKey{
			TenantID:           dbProvider.TenantID,
			Provider:           dbProvider.Name,
			ProviderID:         dbProvider.ID,
			KeyID:              key.ID,
			Name:               key.Name,
			Value:              key.Value,
			Models:             key.Models,
			Weight:             &key.Weight,
			Enabled:            key.Enabled,
			UseForBatchAPI:     key.UseForBatchAPI,
			UseForCache:        key.UseForCache,
			AzureKeyConfig:     key.AzureKeyConfig,
			VertexKeyConfig:    key.VertexKeyConfig,
			BedrockKeyConfig:   key.BedrockKeyConfig,
			ReplicateKeyConfig: key.ReplicateKeyConfig,
			VLLMKeyConfig:      key.VLLMKeyConfig,
			ConfigHash:         keyHash,
			Status:             string(key.Status),
			Description:        key.Description,
		}
		// Inherit the parent provider's workspace_id so key rows stay
		// scoped to the same workspace as their provider - matches what
		// AddProvider does on initial create.
		if dbProvider.WorkspaceID != nil {
			ws := *dbProvider.WorkspaceID
			dbKey.WorkspaceID = &ws
		}

		// Handle Azure config
		if key.AzureKeyConfig != nil {
			dbKey.AzureEndpoint = &key.AzureKeyConfig.Endpoint
			dbKey.AzureAPIVersion = key.AzureKeyConfig.APIVersion
		}

		// Handle Vertex config
		if key.VertexKeyConfig != nil {
			dbKey.VertexProjectID = &key.VertexKeyConfig.ProjectID
			dbKey.VertexProjectNumber = &key.VertexKeyConfig.ProjectNumber
			dbKey.VertexRegion = &key.VertexKeyConfig.Region
			dbKey.VertexAuthCredentials = &key.VertexKeyConfig.AuthCredentials
		}

		// Handle Bedrock config
		if key.BedrockKeyConfig != nil {
			dbKey.BedrockAccessKey = &key.BedrockKeyConfig.AccessKey
			dbKey.BedrockSecretKey = &key.BedrockKeyConfig.SecretKey
			dbKey.BedrockSessionToken = key.BedrockKeyConfig.SessionToken
			dbKey.BedrockRegion = key.BedrockKeyConfig.Region
			dbKey.BedrockARN = key.BedrockKeyConfig.ARN
			dbKey.BedrockRoleARN = key.BedrockKeyConfig.RoleARN
			dbKey.BedrockExternalID = key.BedrockKeyConfig.ExternalID
			dbKey.BedrockRoleSessionName = key.BedrockKeyConfig.RoleSessionName
			if key.BedrockKeyConfig.BatchS3Config != nil {
				data, err := sonic.Marshal(key.BedrockKeyConfig.BatchS3Config)
				if err != nil {
					return err
				}
				s := string(data)
				dbKey.BedrockBatchS3ConfigJSON = &s
			} else {
				dbKey.BedrockBatchS3ConfigJSON = nil
			}
		}

		// Check if this key already exists
		if existingKey, exists := existingKeysMap[key.ID]; exists {
			tenantID := existingKey.TenantID
			if strings.TrimSpace(tenantID) == "" {
				tenantID = dbProvider.TenantID
			}
			dbKey.ID = existingKey.ID        // Keep the same database ID
			dbKey.TenantID = tenantID        // Repair missing tenant scoping from legacy rows
			dbKey.ProviderID = dbProvider.ID // Keep the key bound to the current provider row
			dbKey.Provider = dbProvider.Name
			dbKey.ConfigHash = existingKey.ConfigHash             // Preserve config hash
			dbKey.Status = existingKey.Status                     // Preserve status (UI-managed)
			dbKey.Description = existingKey.Description           // Preserve description (UI-managed)
			dbKey.EncryptionStatus = existingKey.EncryptionStatus // Preserve encryption status
			if err := txDB.WithContext(ctx).Save(&dbKey).Error; err != nil {
				return s.parseGormError(err)
			}
			delete(existingKeysMap, key.ID)
			delete(existingKeysByName, existingKey.Name)
		} else if existingKey, exists := existingKeysByName[key.Name]; exists {
			tenantID := existingKey.TenantID
			if strings.TrimSpace(tenantID) == "" {
				tenantID = dbProvider.TenantID
			}
			dbKey.ID = existingKey.ID        // Keep the same database ID
			dbKey.TenantID = tenantID        // Repair missing tenant scoping from legacy rows
			dbKey.KeyID = existingKey.KeyID  // Preserve original KeyID
			dbKey.ProviderID = dbProvider.ID // Keep the key bound to the current provider row
			dbKey.Provider = dbProvider.Name
			dbKey.ConfigHash = existingKey.ConfigHash             // Preserve config hash
			dbKey.Status = existingKey.Status                     // Preserve status (UI-managed)
			dbKey.Description = existingKey.Description           // Preserve description (UI-managed)
			dbKey.EncryptionStatus = existingKey.EncryptionStatus // Preserve encryption status
			if err := txDB.WithContext(ctx).Save(&dbKey).Error; err != nil {
				return s.parseGormError(err)
			}
			delete(existingKeysMap, existingKey.KeyID)
			delete(existingKeysByName, existingKey.Name)
		} else {
			if err := txDB.WithContext(ctx).Create(&dbKey).Error; err != nil {
				return s.parseGormError(err)
			}
		}
	}

	// Delete keys that are no longer in the new config
	for _, keyToDelete := range existingKeysMap {
		if err := txDB.WithContext(ctx).Delete(&keyToDelete).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
	}

	return nil
}

// AddProvider creates a new provider configuration in the database.
func (s *RDBConfigStore) AddProvider(ctx context.Context, provider schemas.ModelProvider, config ProviderConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Create a deep copy of the config to avoid modifying the original
	configCopy, err := deepCopy(config)
	if err != nil {
		return err
	}
	// Preserve ConfigHash (it has json:"-" tag so deepCopy via JSON doesn't copy it)
	configCopy.ConfigHash = config.ConfigHash
	if configCopy.ConfigHash == "" {
		configHash, hashErr := config.GenerateConfigHash(string(provider))
		if hashErr != nil {
			return fmt.Errorf("failed to generate provider hash: %w", hashErr)
		}
		configCopy.ConfigHash = configHash
	}
	// Create new provider
	dbProvider := tables.TableProvider{
		Name:                     string(provider),
		NetworkConfig:            configCopy.NetworkConfig,
		ConcurrencyAndBufferSize: configCopy.ConcurrencyAndBufferSize,
		ProxyConfig:              configCopy.ProxyConfig,
		SendBackRawRequest:       configCopy.SendBackRawRequest,
		SendBackRawResponse:      configCopy.SendBackRawResponse,
		StoreRawRequestResponse:  configCopy.StoreRawRequestResponse,
		CustomProviderConfig:     configCopy.CustomProviderConfig,
		PricingOverrides:         configCopy.PricingOverrides,
		ConfigHash:               configCopy.ConfigHash,
	}
	// Stamp the active workspace from the request context. Empty leaves
	// WorkspaceID NULL, which means tenant-wide (default behaviour for
	// SDK / config-file callers that don't carry a workspace context).
	activeWS := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	if activeWS != "" {
		dbProvider.WorkspaceID = &activeWS
	}
	// Create the provider
	if err := txDB.WithContext(ctx).Create(&dbProvider).Error; err != nil {
		return s.parseGormError(err)
	}
	// Create keys for this provider. Stamp workspace_id from context so
	// the key row is co-scoped with its parent provider - a separate
	// uniqueness/lookup path uses the keys table directly (e.g. the
	// runtime model client) and would otherwise see keys leaking across
	// workspaces. The provider FK alone isn't enough because some
	// queries on config_keys filter by (provider_id) only and don't
	// traverse into config_providers for workspace.
	for _, key := range configCopy.Keys {
		keyHash := key.ConfigHash
		if keyHash == "" {
			var hashErr error
			keyHash, hashErr = GenerateKeyHash(key)
			if hashErr != nil {
				return fmt.Errorf("failed to generate key hash: %w", hashErr)
			}
		}
		dbKey := tables.TableKey{
			Provider:           dbProvider.Name,
			ProviderID:         dbProvider.ID,
			KeyID:              key.ID,
			Name:               key.Name,
			Value:              key.Value,
			Models:             key.Models,
			Weight:             &key.Weight,
			Enabled:            key.Enabled,
			UseForBatchAPI:     key.UseForBatchAPI,
			UseForCache:        key.UseForCache,
			AzureKeyConfig:     key.AzureKeyConfig,
			VertexKeyConfig:    key.VertexKeyConfig,
			BedrockKeyConfig:   key.BedrockKeyConfig,
			ReplicateKeyConfig: key.ReplicateKeyConfig,
			VLLMKeyConfig:      key.VLLMKeyConfig,
			ConfigHash:         keyHash,
			Status:             string(key.Status),
			Description:        key.Description,
		}
		// Co-scope the key with its parent provider's workspace.
		if activeWS != "" {
			dbKey.WorkspaceID = &activeWS
		}
		// Handle Azure config
		if key.AzureKeyConfig != nil {
			dbKey.AzureEndpoint = &key.AzureKeyConfig.Endpoint
			dbKey.AzureAPIVersion = key.AzureKeyConfig.APIVersion
		}
		// Handle Vertex config
		if key.VertexKeyConfig != nil {
			dbKey.VertexProjectID = &key.VertexKeyConfig.ProjectID
			dbKey.VertexProjectNumber = &key.VertexKeyConfig.ProjectNumber
			dbKey.VertexRegion = &key.VertexKeyConfig.Region
			dbKey.VertexAuthCredentials = &key.VertexKeyConfig.AuthCredentials
		}
		// Handle Bedrock config
		if key.BedrockKeyConfig != nil {
			dbKey.BedrockAccessKey = &key.BedrockKeyConfig.AccessKey
			dbKey.BedrockSecretKey = &key.BedrockKeyConfig.SecretKey
			dbKey.BedrockSessionToken = key.BedrockKeyConfig.SessionToken
			dbKey.BedrockRegion = key.BedrockKeyConfig.Region
			dbKey.BedrockARN = key.BedrockKeyConfig.ARN
			dbKey.BedrockRoleARN = key.BedrockKeyConfig.RoleARN
			dbKey.BedrockExternalID = key.BedrockKeyConfig.ExternalID
			dbKey.BedrockRoleSessionName = key.BedrockKeyConfig.RoleSessionName
			if key.BedrockKeyConfig.BatchS3Config != nil {
				data, err := sonic.Marshal(key.BedrockKeyConfig.BatchS3Config)
				if err != nil {
					return err
				}
				s := string(data)
				dbKey.BedrockBatchS3ConfigJSON = &s
			} else {
				dbKey.BedrockBatchS3ConfigJSON = nil
			}
		}

		// Create the key
		if err := txDB.WithContext(ctx).Create(&dbKey).Error; err != nil {
			return s.parseGormError(err)
		}
	}

	return nil
}

// DeleteProvider deletes a single provider and all its associated keys from the database.
// Narrows to the active workspace when one is in scope so a delete in
// workspace A doesn't accidentally remove the same-named provider from
// workspace B.
func (s *RDBConfigStore) DeleteProvider(ctx context.Context, provider schemas.ModelProvider, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Find the existing provider
	var dbProvider tables.TableProvider
	q := txDB.WithContext(ctx).Where("name = ?", string(provider))
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&dbProvider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	// Store the budget and rate limit IDs before deleting
	budgetID := dbProvider.BudgetID
	rateLimitID := dbProvider.RateLimitID

	// Delete the provider first (keys will be deleted due to CASCADE constraint)
	if err := txDB.WithContext(ctx).Delete(&dbProvider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	// Delete the budget if it exists
	if budgetID != nil {
		if err := txDB.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", *budgetID).Error; err != nil {
			return err
		}
	}
	// Delete the rate limit if it exists
	if rateLimitID != nil {
		if err := txDB.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", *rateLimitID).Error; err != nil {
			return err
		}
	}

	return nil
}

func (s *RDBConfigStore) repairProviderKeyTenantScope(provider *tables.TableProvider) error {
	if provider == nil || strings.TrimSpace(provider.TenantID) == "" {
		return nil
	}

	return s.db.WithContext(tenantMigrationContext(context.Background())).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&tables.TableKey{}).
		Where(
			"provider_id = ? AND (COALESCE(tenant_id, '') <> ? OR provider <> ?)",
			provider.ID,
			provider.TenantID,
			provider.Name,
		).
		Updates(map[string]any{
			"tenant_id":   provider.TenantID,
			"provider_id": provider.ID,
			"provider":    provider.Name,
		}).Error
}

// GetProvidersConfig retrieves the provider configuration from the database.
func (s *RDBConfigStore) GetProvidersConfig(ctx context.Context) (map[schemas.ModelProvider]ProviderConfig, error) {
	var dbProviders []tables.TableProvider
	q := s.db.WithContext(ctx)
	// Strict per-workspace scoping when the dashboard's scope switcher
	// supplies an active workspace (X-Active-Workspace-Id header). Same
	// rationale as GetProviders - callers without a workspace context
	// (SDK / config-file bootstrap) get the unfiltered tenant view.
	//
	// This was the actual code path taken by GET /api/providers in the
	// dashboard; GetProviders (without "Config" suffix) is used by the
	// runtime client. Both must scope identically or the UI shows a
	// different list than the gateway uses, which is exactly the leak
	// the workspace flag was meant to fix.
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.Find(&dbProviders).Error; err != nil {
		return nil, err
	}
	if len(dbProviders) == 0 {
		// No providers in database, auto-detect from environment
		return nil, nil
	}
	for i := range dbProviders {
		if err := s.repairProviderKeyTenantScope(&dbProviders[i]); err != nil {
			return nil, err
		}
	}
	// Re-load with Keys preloaded - apply the same workspace narrowing.
	preloadQ := s.db.WithContext(ctx).Preload("Keys")
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		preloadQ = preloadQ.Where("workspace_id = ?", ws)
	}
	if err := preloadQ.Find(&dbProviders).Error; err != nil {
		return nil, err
	}
	processedProviders := make(map[schemas.ModelProvider]ProviderConfig)
	for _, dbProvider := range dbProviders {
		provider := schemas.ModelProvider(dbProvider.Name)
		// Convert database keys to schemas.Key
		keys := make([]schemas.Key, len(dbProvider.Keys))
		for i, dbKey := range dbProvider.Keys {
			keys[i] = schemas.Key{
				ID:                 dbKey.KeyID,
				Name:               dbKey.Name,
				Value:              dbKey.Value,
				Models:             dbKey.Models,
				Weight:             getWeight(dbKey.Weight),
				Enabled:            dbKey.Enabled,
				UseForBatchAPI:     dbKey.UseForBatchAPI,
				UseForCache:        dbKey.UseForCache,
				AzureKeyConfig:     dbKey.AzureKeyConfig,
				VertexKeyConfig:    dbKey.VertexKeyConfig,
				BedrockKeyConfig:   dbKey.BedrockKeyConfig,
				ReplicateKeyConfig: dbKey.ReplicateKeyConfig,
				VLLMKeyConfig:      dbKey.VLLMKeyConfig,
				ConfigHash:         dbKey.ConfigHash,
				Status:             schemas.KeyStatusType(dbKey.Status),
				Description:        dbKey.Description,
			}
		}
		providerConfig := ProviderConfig{
			Keys:                     keys,
			NetworkConfig:            dbProvider.NetworkConfig,
			ConcurrencyAndBufferSize: dbProvider.ConcurrencyAndBufferSize,
			ProxyConfig:              dbProvider.ProxyConfig,
			SendBackRawRequest:       dbProvider.SendBackRawRequest,
			SendBackRawResponse:      dbProvider.SendBackRawResponse,
			StoreRawRequestResponse:  dbProvider.StoreRawRequestResponse,
			CustomProviderConfig:     dbProvider.CustomProviderConfig,
			PricingOverrides:         dbProvider.PricingOverrides,
			ConfigHash:               dbProvider.ConfigHash,
			Status:                   dbProvider.Status,
			Description:              dbProvider.Description,
		}
		processedProviders[provider] = providerConfig
	}
	return processedProviders, nil
}

// GetProviderConfig retrieves the provider configuration from the database.
//
// When called from a dashboard request that carries an active workspace
// (X-Active-Workspace-Id), only that workspace's row matches - preventing
// the singular endpoint (/api/providers/{name}) from leaking another
// workspace's provider with the same name into the current view.
// Workspace-less callers (SDK / config-file) get the legacy first-row
// behaviour.
func (s *RDBConfigStore) GetProviderConfig(ctx context.Context, provider schemas.ModelProvider) (*ProviderConfig, error) {
	var dbProvider tables.TableProvider
	q := s.db.WithContext(ctx).Where("name = ?", string(provider))
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&dbProvider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := s.repairProviderKeyTenantScope(&dbProvider); err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Preload("Keys").Where("id = ?", dbProvider.ID).First(&dbProvider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	keys := make([]schemas.Key, len(dbProvider.Keys))
	for i, dbKey := range dbProvider.Keys {
		keys[i] = schemas.Key{
			ID:                 dbKey.KeyID,
			Name:               dbKey.Name,
			Value:              dbKey.Value,
			Models:             dbKey.Models,
			Weight:             getWeight(dbKey.Weight),
			Enabled:            dbKey.Enabled,
			UseForBatchAPI:     dbKey.UseForBatchAPI,
			UseForCache:        dbKey.UseForCache,
			AzureKeyConfig:     dbKey.AzureKeyConfig,
			VertexKeyConfig:    dbKey.VertexKeyConfig,
			BedrockKeyConfig:   dbKey.BedrockKeyConfig,
			ReplicateKeyConfig: dbKey.ReplicateKeyConfig,
			VLLMKeyConfig:      dbKey.VLLMKeyConfig,
			ConfigHash:         dbKey.ConfigHash,
			Status:             schemas.KeyStatusType(dbKey.Status),
			Description:        dbKey.Description,
		}
	}
	return &ProviderConfig{
		Keys:                     keys,
		NetworkConfig:            dbProvider.NetworkConfig,
		ConcurrencyAndBufferSize: dbProvider.ConcurrencyAndBufferSize,
		ProxyConfig:              dbProvider.ProxyConfig,
		SendBackRawRequest:       dbProvider.SendBackRawRequest,
		SendBackRawResponse:      dbProvider.SendBackRawResponse,
		StoreRawRequestResponse:  dbProvider.StoreRawRequestResponse,
		CustomProviderConfig:     dbProvider.CustomProviderConfig,
		PricingOverrides:         dbProvider.PricingOverrides,
		ConfigHash:               dbProvider.ConfigHash,
		Status:                   dbProvider.Status,
		Description:              dbProvider.Description,
	}, nil
}

// GetProviders retrieves all providers from the database with their governance relationships.
func (s *RDBConfigStore) GetProviders(ctx context.Context) ([]tables.TableProvider, error) {
	var providers []tables.TableProvider
	q := s.db.WithContext(ctx).
		Preload("Budget").
		Preload("RateLimit").
		Preload("Models")
	// Strict workspace scoping when the dashboard's scope switcher
	// supplies an active workspace (X-Active-Workspace-Id header). Each
	// workspace under a tenant maintains its own provider list - no
	// implicit cross-workspace visibility, even for legacy providers
	// stored with workspace_id NULL. A backfill migration pins any
	// pre-existing NULLs to the parent tenant's Default workspace so
	// they remain visible after this change.
	//
	// SDK / CLI callers (no workspace context) get the unfiltered tenant
	// view - tenant_id partitioning via the GORM callback is enough for
	// them, and they pre-date the workspace concept.
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

// GetProvider retrieves a provider by name from the database with governance relationships.
// Narrows to the active workspace when one is in scope on the request - see
// UpdateProvider for the rationale.
func (s *RDBConfigStore) GetProvider(ctx context.Context, provider schemas.ModelProvider) (*tables.TableProvider, error) {
	var providerInfo tables.TableProvider
	q := s.db.WithContext(ctx).
		Preload("Budget").
		Preload("RateLimit").
		Preload("Models").
		Where("name = ?", string(provider))
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&providerInfo).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &providerInfo, nil
}

// GetProviderByName retrieves a provider by name from the database with governance relationships.
// Narrows to the active workspace when one is in scope (same rationale as GetProvider).
func (s *RDBConfigStore) GetProviderByName(ctx context.Context, name string) (*tables.TableProvider, error) {
	var provider tables.TableProvider
	q := s.db.WithContext(ctx).
		Preload("Budget").
		Preload("RateLimit").
		Preload("Models").
		Where("name = ?", name)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&provider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &provider, nil
}

// UpdateStatus updates the status for either a key or provider.
// - If keyID is non-empty: updates the key's status (for keyed providers)
// - If keyID is empty and provider is non-empty: updates the provider's status (for keyless providers)
func (s *RDBConfigStore) UpdateStatus(ctx context.Context, provider schemas.ModelProvider, keyID string, status, description string) error {
	// Update key-level status (for keyed providers)
	if keyID != "" {
		result := s.db.WithContext(ctx).
			Model(&tables.TableKey{}).
			Where("key_id = ?", keyID).
			Updates(map[string]interface{}{
				"status":      status,
				"description": description,
			})
		if result.Error != nil {
			return s.parseGormError(result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	}

	// Update provider-level status (for keyless providers)
	if provider != "" {
		result := s.db.WithContext(ctx).
			Model(&tables.TableProvider{}).
			Where("name = ?", string(provider)).
			Updates(map[string]interface{}{
				"status":      status,
				"description": description,
			})
		if result.Error != nil {
			return s.parseGormError(result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	}

	return fmt.Errorf("either keyID or provider must be non-empty")
}

// GetMCPConfig retrieves the MCP configuration from the database.
// Workspace-strict: when a workspace is pinned on the request context only
// rows for that workspace are returned. Without this filter the UI's non-
// paginated MCP Hub view leaked clients from every workspace under the
// same tenant - the same shape of bug the cost-opt rollout fixed for
// plugins.
func (s *RDBConfigStore) GetMCPConfig(ctx context.Context) (*schemas.MCPConfig, error) {
	var dbMCPClients []tables.TableMCPClient
	q := s.db.WithContext(ctx)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.Find(&dbMCPClients).Error; err != nil {
		return nil, err
	}
	if len(dbMCPClients) == 0 {
		return nil, nil
	}
	var clientConfig tables.TableClientConfig
	if err := s.db.WithContext(ctx).First(&clientConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return MCP config with default ToolManagerConfig if no client config exists
			// This will never happen, but just in case.
			clientConfigs := make([]*schemas.MCPClientConfig, len(dbMCPClients))
			for i, dbClient := range dbMCPClients {
				// Dereference IsPingAvailable pointer, defaulting to true if nil
				isPingAvailable := true
				if dbClient.IsPingAvailable != nil {
					isPingAvailable = *dbClient.IsPingAvailable
				}
				clientConfigs[i] = &schemas.MCPClientConfig{
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
			return &schemas.MCPConfig{
				ClientConfigs: clientConfigs,
				ToolManagerConfig: &schemas.MCPToolManagerConfig{
					ToolExecutionTimeout: 30 * time.Second, // default from TableClientConfig
					MaxAgentDepth:        10,               // default from TableClientConfig
				},
			}, nil
		}
		return nil, err
	}
	toolManagerConfig := schemas.MCPToolManagerConfig{
		ToolExecutionTimeout: time.Duration(clientConfig.MCPToolExecutionTimeout) * time.Second,
		MaxAgentDepth:        clientConfig.MCPAgentDepth,
		CodeModeBindingLevel: schemas.CodeModeBindingLevel(clientConfig.MCPCodeModeBindingLevel),
		CacheEnabled:         clientConfig.MCPCacheEnabled,
		CacheTTLSeconds:      clientConfig.MCPCacheTTLSeconds,
	}
	clientConfigs := make([]*schemas.MCPClientConfig, len(dbMCPClients))
	for i, dbClient := range dbMCPClients {
		// Dereference IsPingAvailable pointer, defaulting to true if nil
		isPingAvailable := true
		if dbClient.IsPingAvailable != nil {
			isPingAvailable = *dbClient.IsPingAvailable
		}
		clientConfigs[i] = &schemas.MCPClientConfig{
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
	return &schemas.MCPConfig{
		ClientConfigs:     clientConfigs,
		ToolManagerConfig: &toolManagerConfig,
	}, nil
}

// GetMCPClientsPaginated retrieves MCP clients with pagination and optional search.
func (s *RDBConfigStore) GetMCPClientsPaginated(ctx context.Context, params MCPClientsQueryParams) ([]tables.TableMCPClient, int64, error) {
	baseQuery := s.db.WithContext(ctx).Model(&tables.TableMCPClient{})

	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		baseQuery = baseQuery.Where("LOWER(name) LIKE ?", search)
	}
	// Workspace-scope filter: include rows scoped to the workspace plus
	// tenant-wide rows (workspace_id IS NULL). Empty WorkspaceID returns
	// the full tenant view (legacy behaviour).
	if ws := strings.TrimSpace(params.WorkspaceID); ws != "" {
		// Strict per-workspace scoping. Each workspace under a tenant owns
		// its own configuration - providers, routing rules, virtual keys,
		// plugins. Legacy NULL rows are migrated to the parent tenant's
		// Default workspace by migrationBackfillNullWorkspaceIDs so they
		// stay visible after this filter tightens.
		baseQuery = baseQuery.Where("workspace_id = ?", ws)
	}

	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	offset := params.Offset

	if limit <= 0 {
		limit = 25
	} else if limit > 100 {
		limit = 100
	}

	if offset < 0 {
		offset = 0
	}

	var clients []tables.TableMCPClient
	if err := baseQuery.
		Order("created_at ASC, client_id ASC").
		Offset(offset).
		Limit(limit).
		Find(&clients).Error; err != nil {
		return nil, 0, err
	}
	return clients, totalCount, nil
}

// GetMCPClientByID retrieves an MCP client by ID from the database. When a
// workspace is pinned on the request context the lookup is scoped to that
// workspace; without a pinned workspace it falls back to a tenant-wide
// search (admin / bootstrap paths). Strict scoping prevents one workspace
// from seeing another's clients via shared client_id collisions.
func (s *RDBConfigStore) GetMCPClientByID(ctx context.Context, id string) (*tables.TableMCPClient, error) {
	var mcpClient tables.TableMCPClient
	q := s.db.WithContext(ctx).Where("client_id = ?", id)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&mcpClient).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &mcpClient, nil
}

// GetMCPClientByName retrieves an MCP client by name from the database.
// Workspace-strict for the same reason as GetMCPClientByID - the runtime VK
// MCP-config wiring (handlers/governance.go createVirtualKey) resolves
// client_id from client_name and must not bind a workspace A virtual key to
// a workspace B MCP client.
func (s *RDBConfigStore) GetMCPClientByName(ctx context.Context, name string) (*tables.TableMCPClient, error) {
	var mcpClient tables.TableMCPClient
	q := s.db.WithContext(ctx).Where("name = ?", name)
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.First(&mcpClient).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &mcpClient, nil
}

// CreateMCPClientConfig creates a new MCP client configuration in the database.
func (s *RDBConfigStore) CreateMCPClientConfig(ctx context.Context, clientConfig *schemas.MCPClientConfig) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Check if a client with the same name already exists
		if _, err := s.GetMCPClientByName(ctx, clientConfig.Name); err == nil {
			return fmt.Errorf("MCP client with name '%s' already exists", clientConfig.Name)
		}
		// Create a deep copy to avoid modifying the original
		clientConfigCopy, err := deepCopy(*clientConfig)
		if err != nil {
			return err
		}
		// Create new client
		dbClient := tables.TableMCPClient{
			ClientID:           clientConfigCopy.ID,
			Name:               clientConfigCopy.Name,
			IsCodeModeClient:   clientConfigCopy.IsCodeModeClient,
			ConnectionType:     string(clientConfigCopy.ConnectionType),
			ConnectionString:   clientConfigCopy.ConnectionString,
			StdioConfig:        clientConfigCopy.StdioConfig,
			AuthType:           string(clientConfigCopy.AuthType),
			OauthConfigID:      clientConfigCopy.OauthConfigID,
			ToolsToExecute:     clientConfigCopy.ToolsToExecute,
			ToolsToAutoExecute: clientConfigCopy.ToolsToAutoExecute,
			Headers:            clientConfigCopy.Headers,
			IsPingAvailable:    &clientConfigCopy.IsPingAvailable,
			ToolSyncInterval:   int(clientConfigCopy.ToolSyncInterval.Minutes()),
		}
		// Resolve effective workspace: explicit > sidebar context > tenant
		// default. Workspace-aware resources are never created with a NULL
		// workspace_id any more - the design moved away from "tenant-wide
		// = NULL" to "every resource pinned to exactly one workspace".
		if ws := s.resolveEffectiveWorkspaceID(ctx, ""); ws != "" {
			dbClient.WorkspaceID = &ws
		}
		if err := tx.WithContext(ctx).Create(&dbClient).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
}

// UpdateMCPClientConfig updates an existing MCP client configuration in the database.
func (s *RDBConfigStore) UpdateMCPClientConfig(ctx context.Context, id string, clientConfig *tables.TableMCPClient) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Find existing client
		var existingClient tables.TableMCPClient
		if err := tx.WithContext(ctx).Where("client_id = ?", id).First(&existingClient).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("MCP client with id '%s' not found", id)
			}
			return err
		}

		// Create a deep copy to avoid modifying the original
		clientConfigCopy, err := deepCopy(clientConfig)
		if err != nil {
			return err
		}

		// Serialize the virtual fields to JSON before updating
		// This is normally done in BeforeSave hook, but we need to do it manually for map updates
		// Normalize nil slices/maps to avoid storing JSON "null"
		if clientConfigCopy.ToolsToExecute == nil {
			clientConfigCopy.ToolsToExecute = []string{}
		}
		toolsToExecuteJSON, err := json.Marshal(clientConfigCopy.ToolsToExecute)
		if err != nil {
			return fmt.Errorf("failed to marshal tools_to_execute: %w", err)
		}
		if clientConfigCopy.ToolsToAutoExecute == nil {
			clientConfigCopy.ToolsToAutoExecute = []string{}
		}
		toolsToAutoExecuteJSON, err := json.Marshal(clientConfigCopy.ToolsToAutoExecute)
		if err != nil {
			return fmt.Errorf("failed to marshal tools_to_auto_execute: %w", err)
		}
		// Serialize headers to map[string]string matching BeforeSave logic
		headersToSerialize := make(map[string]string)
		if clientConfigCopy.Headers != nil {
			for key, value := range clientConfigCopy.Headers {
				if value.IsFromEnv() {
					headersToSerialize[key] = value.EnvVar
				} else {
					headersToSerialize[key] = value.GetValue()
				}
			}
		}
		headersJSON, err := json.Marshal(headersToSerialize)
		if err != nil {
			return fmt.Errorf("failed to marshal headers: %w", err)
		}

		if clientConfigCopy.ToolPricing == nil {
			clientConfigCopy.ToolPricing = map[string]float64{}
		}
		toolPricingJSON, err := json.Marshal(clientConfigCopy.ToolPricing)
		if err != nil {
			return fmt.Errorf("failed to marshal tool_pricing: %w", err)
		}

		headersJSONStr := string(headersJSON)
		if encrypt.IsEnabled() && headersJSONStr != "" && headersJSONStr != "{}" {
			encrypted, encErr := encrypt.Encrypt(headersJSONStr)
			if encErr != nil {
				return fmt.Errorf("failed to encrypt mcp headers: %w", encErr)
			}
			headersJSONStr = encrypted
		}

		// Update only editable fields using a map to avoid updating connection info
		// Connection info (ConnectionType, ConnectionString, StdioConfig) is read-only and should not be modified via API
		updates := map[string]interface{}{
			"name":                       clientConfigCopy.Name,
			"is_code_mode_client":        clientConfigCopy.IsCodeModeClient,
			"tools_to_execute_json":      string(toolsToExecuteJSON),
			"tools_to_auto_execute_json": string(toolsToAutoExecuteJSON),
			"headers_json":               headersJSONStr,
			"tool_pricing_json":          string(toolPricingJSON),
			"tool_sync_interval":         clientConfigCopy.ToolSyncInterval,
			"updated_at":                 time.Now(),
		}
		if encrypt.IsEnabled() {
			updates["encryption_status"] = encryptionStatusEncrypted
		}

		// Only update is_ping_available if explicitly provided (non-nil)
		// This preserves the existing DB value when the request omits the field
		if clientConfigCopy.IsPingAvailable != nil {
			updates["is_ping_available"] = *clientConfigCopy.IsPingAvailable
		}

		if err := tx.WithContext(ctx).Model(&existingClient).Updates(updates).Error; err != nil {
			return s.parseGormError(err)
		}
		return nil
	})
}

// DeleteMCPClientConfig deletes an MCP client configuration from the database.
func (s *RDBConfigStore) DeleteMCPClientConfig(ctx context.Context, id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Find existing client
		var existingClient tables.TableMCPClient
		if err := tx.WithContext(ctx).Where("client_id = ?", id).First(&existingClient).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("MCP client with id '%s' not found", id)
			}
			return err
		}

		// Delete any virtual key MCP configs that reference this client
		if err := tx.WithContext(ctx).Where("mcp_client_id = ?", existingClient.ID).Delete(&tables.TableVirtualKeyMCPConfig{}).Error; err != nil {
			return err
		}

		// Delete the client (this will also handle foreign key cascades)
		return tx.WithContext(ctx).Delete(&existingClient).Error
	})
}

// GetVectorStoreConfig retrieves the vector store configuration from the database.
func (s *RDBConfigStore) GetVectorStoreConfig(ctx context.Context) (*vectorstore.Config, error) {
	var vectorStoreTableConfig tables.TableVectorStoreConfig
	if err := s.db.WithContext(ctx).First(&vectorStoreTableConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Return default cache configuration
			return nil, nil
		}
		return nil, err
	}
	configData := "{}"
	if vectorStoreTableConfig.Config != nil && strings.TrimSpace(*vectorStoreTableConfig.Config) != "" {
		configData = *vectorStoreTableConfig.Config
	}

	raw := fmt.Sprintf(`{"enabled":%t,"type":%q,"config":%s}`,
		vectorStoreTableConfig.Enabled,
		vectorStoreTableConfig.Type,
		configData,
	)

	var vectorConfig vectorstore.Config
	if err := json.Unmarshal([]byte(raw), &vectorConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vector store config: %w", err)
	}
	return &vectorConfig, nil
}

// UpdateVectorStoreConfig updates the vector store configuration in the database.
func (s *RDBConfigStore) UpdateVectorStoreConfig(ctx context.Context, config *vectorstore.Config) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Delete existing cache config
		if err := tx.WithContext(ctx).Where("1=1").Delete(&tables.TableVectorStoreConfig{}).Error; err != nil {
			return err
		}
		jsonConfig, err := marshalToStringPtr(config.Config)
		if err != nil {
			return err
		}
		var record = &tables.TableVectorStoreConfig{
			Type:    string(config.Type),
			Enabled: config.Enabled,
			Config:  jsonConfig,
		}
		// Create new cache config
		return tx.WithContext(ctx).Create(record).Error
	})
}

// GetLogsStoreConfig retrieves the logs store configuration from the database.
func (s *RDBConfigStore) GetLogsStoreConfig(ctx context.Context) (*logstore.Config, error) {
	var dbConfig tables.TableLogStoreConfig
	if err := s.db.WithContext(ctx).First(&dbConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if dbConfig.Config == nil || *dbConfig.Config == "" {
		return &logstore.Config{Enabled: dbConfig.Enabled}, nil
	}
	var logStoreConfig logstore.Config
	if err := json.Unmarshal([]byte(*dbConfig.Config), &logStoreConfig); err != nil {
		return nil, err
	}
	return &logStoreConfig, nil
}

// UpdateLogsStoreConfig updates the logs store configuration in the database.
func (s *RDBConfigStore) UpdateLogsStoreConfig(ctx context.Context, config *logstore.Config) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Where("1=1").Delete(&tables.TableLogStoreConfig{}).Error; err != nil {
			return err
		}
		jsonConfig, err := marshalToStringPtr(config)
		if err != nil {
			return err
		}
		var record = &tables.TableLogStoreConfig{
			Enabled: config.Enabled,
			Type:    string(config.Type),
			Config:  jsonConfig,
		}
		return tx.WithContext(ctx).Create(record).Error
	})
}

// GetConfig retrieves a specific config from the database.
func (s *RDBConfigStore) GetConfig(ctx context.Context, key string) (*tables.TableGovernanceConfig, error) {
	var config tables.TableGovernanceConfig
	if err := s.db.WithContext(ctx).First(&config, "key = ?", key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &config, nil
}

// UpdateConfig updates a specific config in the database.
func (s *RDBConfigStore) UpdateConfig(ctx context.Context, config *tables.TableGovernanceConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	return txDB.WithContext(ctx).Save(config).Error
}

func (s *RDBConfigStore) GetSCIMProviderConfig(ctx context.Context, provider string) (*tables.TableSCIMProviderConfig, error) {
	var config tables.TableSCIMProviderConfig
	if err := s.db.WithContext(ctx).
		Where("provider = ?", strings.ToLower(strings.TrimSpace(provider))).
		Order("is_default DESC, enabled DESC, created_at ASC").
		First(&config).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &config, nil
}

func (s *RDBConfigStore) GetSCIMProviderConfigByID(ctx context.Context, id string) (*tables.TableSCIMProviderConfig, error) {
	var config tables.TableSCIMProviderConfig
	if err := s.db.WithContext(ctx).First(&config, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &config, nil
}

func (s *RDBConfigStore) ListSCIMProviderConfigs(ctx context.Context, provider string) ([]tables.TableSCIMProviderConfig, error) {
	query := s.db.WithContext(ctx).Model(&tables.TableSCIMProviderConfig{})
	if trimmedProvider := strings.ToLower(strings.TrimSpace(provider)); trimmedProvider != "" {
		query = query.Where("provider = ?", trimmedProvider)
	}

	var configs []tables.TableSCIMProviderConfig
	if err := query.Order("is_default DESC, enabled DESC, created_at ASC").Find(&configs).Error; err != nil {
		return nil, err
	}
	return configs, nil
}

func (s *RDBConfigStore) CreateSCIMProviderConfig(ctx context.Context, config *tables.TableSCIMProviderConfig) error {
	if config == nil {
		return nil
	}
	config.Provider = strings.ToLower(strings.TrimSpace(config.Provider))
	if config.Provider == "" {
		config.Provider = "entra"
	}
	if config.ID == "" {
		config.ID = uuid.NewString()
	}
	return s.db.WithContext(ctx).Create(config).Error
}

func (s *RDBConfigStore) UpsertSCIMProviderConfig(ctx context.Context, config *tables.TableSCIMProviderConfig) error {
	if config == nil {
		return nil
	}
	config.Provider = strings.ToLower(strings.TrimSpace(config.Provider))
	if config.Provider == "" {
		config.Provider = "entra"
	}
	if config.ID == "" {
		config.ID = uuid.NewString()
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"name",
			"customer_id",
			"is_default",
			"enabled",
			"cloud",
			"directory_tenant_id",
			"client_id",
			"client_secret",
			"audience",
			"app_id_uri",
			"user_id_field",
			"roles_field",
			"team_ids_field",
			"auto_provision_users",
			"sync_groups_to_teams",
			"deactivate_missing_users",
			"token_refresh_enabled",
			"email_domains_json",
			"role_mappings_json",
			"last_tested_at",
			"last_sync_at",
			"last_error",
			"encryption_status",
			"updated_at",
		}),
	}).Create(config).Error
}

func (s *RDBConfigStore) UpdateSCIMProviderConfig(ctx context.Context, config *tables.TableSCIMProviderConfig) error {
	if config == nil {
		return nil
	}
	return s.db.WithContext(ctx).Save(config).Error
}

func (s *RDBConfigStore) DeleteSCIMProviderConfig(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&tables.TableSCIMProviderConfig{}, "id = ?", strings.TrimSpace(id)).Error
}

func (s *RDBConfigStore) ResolveSCIMProviderConfig(ctx context.Context, provider, connectionID, email string) (*tables.TableSCIMProviderConfig, error) {
	if trimmedID := strings.TrimSpace(connectionID); trimmedID != "" {
		return s.GetSCIMProviderConfigByID(ctx, trimmedID)
	}

	configs, err := s.ListSCIMProviderConfigs(ctx, provider)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}

	trimmedEmail := strings.ToLower(strings.TrimSpace(email))
	domain := ""
	if at := strings.LastIndex(trimmedEmail, "@"); at >= 0 && at < len(trimmedEmail)-1 {
		domain = strings.TrimSpace(trimmedEmail[at+1:])
	}
	// Email-domain match is the ONLY automatic resolution path for the
	// multi-tenant SaaS case. With more than one customer enabled at
	// once, falling through to "is_default" or "first enabled" would
	// land an Acme user on Beta Corp's connection - exactly the
	// cross-tenant JIT path the gap analysis flags as item #5. Callers
	// that don't supply a domain (or whose domain matches nothing) MUST
	// pass connection_id explicitly.
	if domain != "" {
		for _, config := range configs {
			if !config.Enabled {
				continue
			}
			for _, candidate := range config.EmailDomains {
				if strings.EqualFold(strings.TrimSpace(candidate), domain) {
					cfg := config
					return &cfg, nil
				}
			}
		}
	}

	// is_default fallback is only safe when exactly one connection is
	// enabled (single-customer / on-prem deployments). The moment there
	// are two enabled connections, defaulting picks a winner that isn't
	// the visitor's, so we refuse and let the caller surface a
	// "connection_id required" error.
	enabledCount := 0
	var onlyEnabled *tables.TableSCIMProviderConfig
	for i := range configs {
		if configs[i].Enabled {
			enabledCount++
			onlyEnabled = &configs[i]
		}
	}
	if enabledCount == 1 {
		return onlyEnabled, nil
	}
	return nil, nil
}

func (s *RDBConfigStore) CreateSCIMLoginState(ctx context.Context, state *tables.TableSCIMLoginState) error {
	if state == nil {
		return nil
	}
	return s.db.WithContext(ctx).Create(state).Error
}

func (s *RDBConfigStore) GetSCIMLoginStateByState(ctx context.Context, state string) (*tables.TableSCIMLoginState, error) {
	var record tables.TableSCIMLoginState
	if err := s.db.WithContext(ctx).First(&record, "state = ?", strings.TrimSpace(state)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

func (s *RDBConfigStore) DeleteSCIMLoginState(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&tables.TableSCIMLoginState{}, "id = ?", strings.TrimSpace(id)).Error
}

// GetModelPrices retrieves all model pricing records from the database.
func (s *RDBConfigStore) GetModelPrices(ctx context.Context) ([]tables.TableModelPricing, error) {
	var modelPrices []tables.TableModelPricing
	if err := s.db.WithContext(ctx).Find(&modelPrices).Error; err != nil {
		return nil, err
	}
	return modelPrices, nil
}

// UpsertModelPrices creates or updates a model pricing record in the database.
// Uses a find-then-create-or-update pattern so it works regardless of dialect
// (SQLite vs PostgreSQL) and constraint naming.
func (s *RDBConfigStore) UpsertModelPrices(ctx context.Context, pricing *tables.TableModelPricing, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	db := txDB.WithContext(ctx)

	var existing tables.TableModelPricing
	err := db.Where("model = ? AND provider = ? AND mode = ?", pricing.Model, pricing.Provider, pricing.Mode).First(&existing).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// No existing row: create
			if err := db.Create(pricing).Error; err != nil {
				return s.parseGormError(err)
			}
			return nil
		}
		return s.parseGormError(err)
	}

	// Existing row: update by setting ID and saving (full replace)
	pricing.ID = existing.ID
	if err := db.Save(pricing).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// DeleteModelPrices deletes all model pricing records from the database.
func (s *RDBConfigStore) DeleteModelPrices(ctx context.Context, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	return txDB.WithContext(ctx).Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&tables.TableModelPricing{}).Error
}

// MODEL PARAMETERS METHODS

// GetModelParameters retrieves model parameters for a specific model.
func (s *RDBConfigStore) GetModelParameters(ctx context.Context, model string) (*tables.TableModelParameters, error) {
	var params tables.TableModelParameters
	if err := s.db.WithContext(ctx).Where("model = ?", model).First(&params).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &params, nil
}

// UpsertModelParameters inserts or updates model parameters for a specific model.
func (s *RDBConfigStore) UpsertModelParameters(ctx context.Context, params *tables.TableModelParameters, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	db := txDB.WithContext(ctx)

	var existing tables.TableModelParameters
	err := db.Where("model = ?", params.Model).First(&existing).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := db.Create(params).Error; err != nil {
				return s.parseGormError(err)
			}
			return nil
		}
		return s.parseGormError(err)
	}

	params.ID = existing.ID
	if err := db.Save(params).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// PLUGINS METHODS

func (s *RDBConfigStore) GetPlugins(ctx context.Context) ([]*tables.TablePlugin, error) {
	// Strict (tenant_id, workspace_id) scoping so each workspace sees only
	// its own plugin config. A request without a workspace in context falls
	// back to "tenant-wide" rows (workspace_id IS NULL) for bootstrap and
	// admin-tooling paths - the UI always pins a workspace via
	// X-Active-Workspace-Id, so user-facing reads never hit that branch.
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	workspaceID := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))

	var rows []*tables.TablePlugin
	q := s.db.WithContext(ctx)
	if tenantID != "" {
		q = q.Where("tenant_id = ? OR tenant_id = ''", tenantID)
	} else {
		q = q.Where("tenant_id = ''")
	}
	if workspaceID != "" {
		q = q.Where("workspace_id = ?", workspaceID)
	} else if activeOrg := strings.TrimSpace(tenantctx.ActiveTenantIDFromContext(ctx)); activeOrg != "" {
		// No workspace selected, but a UI org IS active - restrict to
		// workspaces under that org. Used by admin/listing paths that
		// don't pin a specific workspace.
		ids, err := s.workspaceIDsForOrg(ctx, activeOrg)
		if err == nil {
			if len(ids) == 0 {
				q = q.Where("1 = 0")
			} else {
				q = q.Where("workspace_id IN ?", ids)
			}
		}
	} else {
		q = q.Where("workspace_id IS NULL")
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}

	// De-dup by name, preferring tenant-scoped rows over global defaults.
	byName := make(map[string]*tables.TablePlugin, len(rows))
	for _, r := range rows {
		existing, ok := byName[r.Name]
		if !ok {
			byName[r.Name] = r
			continue
		}
		if existing.TenantID == "" && r.TenantID != "" {
			byName[r.Name] = r
		}
	}
	out := make([]*tables.TablePlugin, 0, len(byName))
	for _, p := range byName {
		out = append(out, p)
	}
	return out, nil
}

// GetPluginsForRuntimeBootstrap returns the merged effective config for every
// plugin name in the database. See the interface doc for the rationale -
// short version: GetPlugins is tenant-scoped and the bootstrap context has no
// tenant, so a vanilla GetPlugins at startup misses every UI-saved row and
// instantiates plugins from the empty global default only. This method
// ignores tenant filtering and picks the most-recently-updated row per name.
// The result is the runtime plugin set the gateway should boot with, after
// applying tenant overrides on top of any global defaults.
func (s *RDBConfigStore) GetPluginsForRuntimeBootstrap(ctx context.Context) ([]*tables.TablePlugin, error) {
	var rows []*tables.TablePlugin
	if err := s.db.WithContext(ctx).
		Order("name ASC, updated_at DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	// Order is (name ASC, updated_at DESC) so the first row per name is the
	// freshest. Drop subsequent rows for the same name.
	byName := make(map[string]*tables.TablePlugin, len(rows))
	out := make([]*tables.TablePlugin, 0, len(rows))
	for _, r := range rows {
		if _, ok := byName[r.Name]; ok {
			continue
		}
		byName[r.Name] = r
		out = append(out, r)
	}
	return out, nil
}

// GetAllPluginsForRuntimeBootstrap returns one row per (name, workspace_id)
// combination - every workspace's saved plugin config plus any global
// (workspace_id IS NULL) defaults. Used by the gateway bootstrap to
// instantiate per-workspace plugin instances so the runtime can dispatch
// the right one per request (see core/deepintshield.go
// effectivePluginsForWorkspace).
//
// Unlike GetPluginsForRuntimeBootstrap (which dedupes to one row per name,
// preserved for callers that want a single instance per name), this method
// keeps every workspace-scoped row alongside any global default. When
// duplicate (name, workspace_id) rows somehow exist - should not happen
// under the new unique index but defensive against legacy data - the most-
// recently-updated row wins.
func (s *RDBConfigStore) GetAllPluginsForRuntimeBootstrap(ctx context.Context) ([]*tables.TablePlugin, error) {
	var rows []*tables.TablePlugin
	if err := s.db.WithContext(ctx).
		Order("name ASC, workspace_id ASC NULLS FIRST, updated_at DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	type key struct {
		name string
		ws   string
	}
	byKey := make(map[key]*tables.TablePlugin, len(rows))
	out := make([]*tables.TablePlugin, 0, len(rows))
	for _, r := range rows {
		ws := ""
		if r.WorkspaceID != nil {
			ws = *r.WorkspaceID
		}
		k := key{name: r.Name, ws: ws}
		if _, ok := byKey[k]; ok {
			continue
		}
		byKey[k] = r
		out = append(out, r)
	}
	return out, nil
}

func (s *RDBConfigStore) GetPlugin(ctx context.Context, name string) (*tables.TablePlugin, error) {
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	workspaceID := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	// Prefer the (tenant, workspace) row, then the tenant-wide row (legacy /
	// admin paths), and finally the global default that the bootstrap upserts
	// from config.json. Workspace pinning is strict - a hit on the tenant-
	// only row is only accepted when the caller didn't pin a workspace.
	if tenantID != "" && workspaceID != "" {
		var p tables.TablePlugin
		if err := s.db.WithContext(ctx).
			Where("name = ? AND tenant_id = ? AND workspace_id = ?", name, tenantID, workspaceID).
			First(&p).Error; err == nil {
			return &p, nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, ErrNotFound
	}
	if tenantID != "" {
		var p tables.TablePlugin
		if err := s.db.WithContext(ctx).
			Where("name = ? AND tenant_id = ? AND workspace_id IS NULL", name, tenantID).
			First(&p).Error; err == nil {
			return &p, nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}
	var p tables.TablePlugin
	if err := s.db.WithContext(ctx).
		Where("name = ? AND tenant_id = '' AND workspace_id IS NULL", name).
		First(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// CreatePlugin creates a new plugin in the database.
func (s *RDBConfigStore) CreatePlugin(ctx context.Context, plugin *tables.TablePlugin, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Mark plugin as custom if path is not empty
	if plugin.Path != nil && strings.TrimSpace(*plugin.Path) != "" {
		plugin.IsCustom = true
	} else {
		plugin.IsCustom = false
	}
	// Scope with the SAME logic GetPlugins uses for reads: context workspace, or
	// tenant-wide (NULL) when none is pinned. Resolving the org default workspace
	// here wrote rows the read path (workspace_id IS NULL) never matched, so UI
	// plugin saves silently never persisted.
	if plugin.WorkspaceID == nil {
		if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
			plugin.WorkspaceID = &ws
		}
	}
	if err := txDB.WithContext(ctx).Create(plugin).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpsertPlugin creates a new plugin in the database if it doesn't exist, otherwise updates it.
func (s *RDBConfigStore) UpsertPlugin(ctx context.Context, plugin *tables.TablePlugin, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	plugin.TenantID = tenantctx.TenantIDFromContext(ctx)
	// Resolve effective workspace: explicit > context > tenant default.
	if plugin.WorkspaceID == nil {
		if ws := s.resolveEffectiveWorkspaceID(ctx, ""); ws != "" {
			plugin.WorkspaceID = &ws
		}
	}
	// Mark plugin as custom if path is not empty
	if plugin.Path != nil && strings.TrimSpace(*plugin.Path) != "" {
		plugin.IsCustom = true
	} else {
		plugin.IsCustom = false
	}
	// Check if plugin exists and compare versions, scoped to the same
	// (tenant_id, workspace_id, name) tuple as the upsert below. Without
	// workspace scoping the bootstrap's version=1 write would be skipped
	// whenever ANY workspace had already saved a customized version=100 row,
	// leaving brand-new workspaces booting with empty config instead of the
	// config.json defaults.
	existQ := txDB.WithContext(ctx).
		Where("name = ? AND tenant_id = ?", plugin.Name, plugin.TenantID)
	if plugin.WorkspaceID != nil {
		existQ = existQ.Where("workspace_id = ?", *plugin.WorkspaceID)
	} else {
		existQ = existQ.Where("workspace_id IS NULL")
	}
	var existing tables.TablePlugin
	err := existQ.First(&existing).Error
	if err == nil && plugin.Version < existing.Version {
		return nil
	}
	// Upsert plugin - INSERT on the (tenant_id, workspace_id, name) unique
	// tuple; on conflict, only overwrite when the incoming version is
	// strictly greater. Postgres-side protection against the bootstrap
	// (version=1) clobbering a customized workspace-saved row (version=100).
	if err := txDB.WithContext(ctx).Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "tenant_id"},
				{Name: "workspace_id"},
				{Name: "name"},
			},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"enabled":     gorm.Expr("EXCLUDED.enabled"),
				"path":        gorm.Expr("EXCLUDED.path"),
				"config_json": gorm.Expr("EXCLUDED.config_json"),
				"version":     gorm.Expr("EXCLUDED.version"),
				"placement":   gorm.Expr("EXCLUDED.placement"),
				"exec_order":  gorm.Expr("EXCLUDED.exec_order"),
				"is_custom":   gorm.Expr("EXCLUDED.is_custom"),
				"updated_at":  gorm.Expr("EXCLUDED.updated_at"),
			}),
			Where: clause.Where{Exprs: []clause.Expression{
				gorm.Expr("config_plugins.version < EXCLUDED.version"),
			}},
		},
	).Create(plugin).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdatePlugin updates an existing plugin in the database.
func (s *RDBConfigStore) UpdatePlugin(ctx context.Context, plugin *tables.TablePlugin, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	var localTx bool

	if len(tx) > 0 {
		txDB = tx[0]
		localTx = false
	} else {
		txDB = s.db.Begin()
		localTx = true
	}

	// Scope writes to the caller's tenant - without this, a tenant save would
	// stomp the global default row (or every tenant's row) for the same plugin
	// name, since the DELETE below would match across tenants.
	plugin.TenantID = strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if plugin.WorkspaceID == nil {
		// Scope writes with the SAME logic GetPlugins uses for reads: the
		// request's context workspace, or tenant-wide (NULL) when none is
		// pinned. Resolving the org's DEFAULT workspace here (the old behavior)
		// wrote the row under a workspace_id the read path - which queries
		// `workspace_id IS NULL` when no workspace is in context - never matched,
		// so UI plugin saves (semantic cache, hallucination control, ...) silently
		// never persisted.
		if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
			plugin.WorkspaceID = &ws
		}
	}

	// Bump the version high enough that the bootstrap's UpsertPlugin (which
	// runs from config.json with version=1) won't overwrite a tenant-saved
	// row on the next gateway restart. Without this, every restart silently
	// resets user-customized plugin settings back to the static config.json
	// defaults - invisible to the operator until they notice their saved
	// settings have stopped applying.
	plugin.Version = 100

	// Mark plugin as custom if path is not empty
	if plugin.Path != nil && strings.TrimSpace(*plugin.Path) != "" {
		plugin.IsCustom = true
	} else {
		plugin.IsCustom = false
	}

	// Replace any existing row(s) for this exact (tenant, workspace, name) scope,
	// then insert. We CANNOT rely on an ON CONFLICT upsert against the
	// (tenant_id, workspace_id, name) unique index here: when workspace_id is
	// NULL (a tenant-wide save - the OSS no-login case), SQLite and Postgres treat
	// NULL as distinct in a unique index, so the conflict never fires and the
	// upsert INSERTs a duplicate row instead of updating. The read path then
	// returns the stale original, which is why plugin config saves (semantic
	// cache, hallucination control, ...) silently never persisted. A scoped
	// delete-then-insert is NULL-safe and also collapses any duplicates a prior
	// broken upsert may have created.
	del := txDB.WithContext(ctx).Where("tenant_id = ? AND name = ?", plugin.TenantID, plugin.Name)
	if plugin.WorkspaceID == nil {
		del = del.Where("workspace_id IS NULL")
	} else {
		del = del.Where("workspace_id = ?", *plugin.WorkspaceID)
	}
	if err := del.Delete(&tables.TablePlugin{}).Error; err != nil {
		if localTx {
			txDB.Rollback()
		}
		return s.parseGormError(err)
	}
	plugin.ID = 0
	if err := txDB.WithContext(ctx).Create(plugin).Error; err != nil {
		if localTx {
			txDB.Rollback()
		}
		return s.parseGormError(err)
	}

	if localTx {
		return txDB.Commit().Error
	}

	return nil
}

func (s *RDBConfigStore) DeletePlugin(ctx context.Context, name string, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Delete is (tenant, workspace)-scoped so a workspace admin cannot
	// accidentally remove another workspace's row or the global default.
	// System/bootstrap callers (no tenant in context) can still target the
	// global row.
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	workspaceID := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx))
	q := txDB.WithContext(ctx).Where("name = ? AND tenant_id = ?", name, tenantID)
	if workspaceID != "" {
		q = q.Where("workspace_id = ?", workspaceID)
	} else {
		q = q.Where("workspace_id IS NULL")
	}
	return q.Delete(&tables.TablePlugin{}).Error
}

// GOVERNANCE METHODS

func (s *RDBConfigStore) GetRedactedVirtualKeys(ctx context.Context, ids []string) ([]tables.TableVirtualKey, error) {
	var virtualKeys []tables.TableVirtualKey

	query := s.db.WithContext(ctx).
		Select("id, name, description, is_active, team_id").
		Preload("Team", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, name")
		})

	if len(ids) > 0 {
		err := query.Where("id IN ?", ids).Find(&virtualKeys).Error
		if err != nil {
			return nil, err
		}
	} else {
		err := query.Find(&virtualKeys).Error
		if err != nil {
			return nil, err
		}
	}
	return virtualKeys, nil
}

// GetVirtualKeys retrieves all virtual keys from the database.
func (s *RDBConfigStore) GetVirtualKeys(ctx context.Context) ([]tables.TableVirtualKey, error) {
	var virtualKeys []tables.TableVirtualKey

	// Preload all relationships for complete information
	if err := s.db.WithContext(ctx).
		Preload("Team").
		Preload("Team.Customer").
		Preload("Customer").
		Preload("Budget").
		Preload("RateLimit").
		Preload("GuardrailPolicies", func(db *gorm.DB) *gorm.DB {
			return db.Order("enabled DESC, created_at ASC, id ASC")
		}).
		Preload("ProviderConfigs").
		Preload("ProviderConfigs.Budget").
		Preload("ProviderConfigs.RateLimit").
		Preload("ProviderConfigs.Keys", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, name, key_id, models_json, provider")
		}).
		Preload("MCPConfigs").
		Preload("MCPConfigs.MCPClient").
		Order("created_at ASC").
		Find(&virtualKeys).Error; err != nil {
		return nil, err
	}
	return virtualKeys, nil
}

// GetVirtualKeysPaginated retrieves virtual keys with pagination, filtering, and search support.
func (s *RDBConfigStore) GetVirtualKeysPaginated(ctx context.Context, params VirtualKeyQueryParams) ([]tables.TableVirtualKey, int64, error) {
	// Build base query with filters
	baseQuery := s.db.WithContext(ctx).Model(&tables.TableVirtualKey{})

	// Virtual keys are either customer-scoped or team-scoped, never both.
	// When both filters are provided, use OR to match keys belonging to either.
	if params.CustomerID != "" && params.TeamID != "" {
		baseQuery = baseQuery.Where("(customer_id = ? OR team_id = ?)", params.CustomerID, params.TeamID)
	} else if params.CustomerID != "" {
		baseQuery = baseQuery.Where("customer_id = ?", params.CustomerID)
	} else if params.TeamID != "" {
		baseQuery = baseQuery.Where("team_id = ?", params.TeamID)
	}
	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		baseQuery = baseQuery.Where("LOWER(name) LIKE ?", search)
	}
	// Workspace filter: include virtual keys explicitly scoped to this
	// workspace plus org-wide keys (workspace_id IS NULL). The OR matters -
	// dropping it would hide tenant-wide legacy keys from every workspace
	// view, which is a regression for callers that haven't migrated yet.
	if params.WorkspaceID != "" {
		baseQuery = baseQuery.Where("(workspace_id = ? OR workspace_id IS NULL)", params.WorkspaceID)
	}

	// Get total count before pagination
	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	// Apply pagination defaults
	limit := params.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}

	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	// Fetch with preloads and pagination
	var virtualKeys []tables.TableVirtualKey
	if err := baseQuery.
		Preload("Team").
		Preload("Team.Customer").
		Preload("Customer").
		Preload("Budget").
		Preload("RateLimit").
		Preload("GuardrailPolicies", func(db *gorm.DB) *gorm.DB {
			return db.Order("enabled DESC, created_at ASC, id ASC")
		}).
		Preload("ProviderConfigs").
		Preload("ProviderConfigs.Budget").
		Preload("ProviderConfigs.RateLimit").
		Preload("ProviderConfigs.Keys", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, name, key_id, models_json, provider")
		}).
		Preload("MCPConfigs").
		Preload("MCPConfigs.MCPClient").
		Order("created_at ASC, id ASC").
		Offset(offset).
		Limit(limit).
		Find(&virtualKeys).Error; err != nil {
		return nil, 0, err
	}
	return virtualKeys, totalCount, nil
}

// GetVirtualKey retrieves a virtual key from the database.
func (s *RDBConfigStore) GetVirtualKey(ctx context.Context, id string) (*tables.TableVirtualKey, error) {
	var virtualKey tables.TableVirtualKey
	if err := s.db.WithContext(ctx).
		Preload("Team").
		Preload("Team.Customer").
		Preload("Customer").
		Preload("Budget").
		Preload("RateLimit").
		Preload("GuardrailPolicies", func(db *gorm.DB) *gorm.DB {
			return db.Order("enabled DESC, created_at ASC, id ASC")
		}).
		Preload("ProviderConfigs").
		Preload("ProviderConfigs.Budget").
		Preload("ProviderConfigs.RateLimit").
		Preload("ProviderConfigs.Keys", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, name, key_id, models_json, provider")
		}).
		Preload("MCPConfigs").
		Preload("MCPConfigs.MCPClient").
		First(&virtualKey, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &virtualKey, nil
}

// GetVirtualKeyByValue retrieves a virtual key by its value using hash-based lookup.
func (s *RDBConfigStore) GetVirtualKeyByValue(ctx context.Context, value string) (*tables.TableVirtualKey, error) {
	valueHash := encrypt.HashSHA256(value)
	var virtualKey tables.TableVirtualKey
	query := s.db.WithContext(ctx).
		Preload("Team").
		Preload("Team.Customer").
		Preload("Customer").
		Preload("Budget").
		Preload("RateLimit").
		Preload("GuardrailPolicies", func(db *gorm.DB) *gorm.DB {
			return db.Order("enabled DESC, created_at ASC, id ASC")
		}).
		Preload("ProviderConfigs").
		Preload("ProviderConfigs.Budget").
		Preload("ProviderConfigs.RateLimit").
		Preload("ProviderConfigs.Keys", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, name, key_id, models_json, provider")
		}).
		Preload("MCPConfigs").
		Preload("MCPConfigs.MCPClient")

	// Use hash-based lookup if hash column is populated, fall back to plaintext for backward compat
	if err := query.Where("value_hash = ?", valueHash).First(&virtualKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Try the parked previous-value hash next so a rotated key
			// stays accepted during its grace window. Expired rows are
			// excluded so the old key truly stops working after the
			// admin-set period.
			now := time.Now().UTC()
			if err := query.
				Where("previous_value_hash = ? AND previous_value_expires_at IS NOT NULL AND previous_value_expires_at > ?", valueHash, now).
				First(&virtualKey).Error; err == nil {
				return &virtualKey, nil
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, err
			}
			// Fallback: try plaintext lookup for rows not yet migrated
			if err := query.Where("value = ?", value).First(&virtualKey).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, ErrNotFound
				}
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return &virtualKey, nil
}

func (s *RDBConfigStore) CreateVirtualKey(ctx context.Context, virtualKey *tables.TableVirtualKey, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Application-level duplicate-name guard. The schema has a unique
	// index on (tenant_id, workspace_id, name) but SQLite (and Postgres
	// with NULL workspace_id) treats NULLs as distinct, so two rows
	// with the same (tenant_id, NULL, name) tuple don't conflict at
	// the DB layer. Catch the duplicate up front so the caller gets a
	// consistent ErrAlreadyExists across dialects.
	var existing tables.TableVirtualKey
	dupQ := txDB.WithContext(ctx).
		Where("tenant_id = ? AND name = ?", virtualKey.TenantID, virtualKey.Name)
	if virtualKey.WorkspaceID != nil {
		dupQ = dupQ.Where("workspace_id = ?", *virtualKey.WorkspaceID)
	} else {
		dupQ = dupQ.Where("workspace_id IS NULL")
	}
	if err := dupQ.First(&existing).Error; err == nil {
		return fmt.Errorf("a record with this name %w. Please use a different value", ErrAlreadyExists)
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return s.parseGormError(err)
	}
	if err := txDB.WithContext(ctx).Create(virtualKey).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

func (s *RDBConfigStore) UpdateVirtualKey(ctx context.Context, virtualKey *tables.TableVirtualKey, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}

	// Check if record exists by ID or Name
	var existing tables.TableVirtualKey
	err := txDB.WithContext(ctx).
		Where("id = ? OR name = ?", virtualKey.ID, virtualKey.Name).
		First(&existing).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return s.parseGormError(err)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := txDB.WithContext(ctx).Create(virtualKey).Error; err != nil {
			return s.parseGormError(err)
		}
	} else {
		virtualKey.ID = existing.ID
		if err := txDB.WithContext(ctx).
			Select(
				"name",
				"description",
				"value",
				"is_active",
				"cache_key",
				"cache_enabled",
				"semantic_cache_enabled",
				"cache_scope_mode",
				"cache_metadata_scope_keys",
				"cache_allow_semantic_when_unscoped",
				"team_id",
				"customer_id",
				"budget_id",
				"rate_limit_id",
				"config_hash",
				"updated_at",
				"encryption_status",
				"value_hash",
				// Agent Scope (unified-VK).
				"bound_identity_provider",
				"identity_provider_id",
				"allowed_tools",
				"autonomy_budget",
				"default_obligations",
				"tool_rate_limit_per_minute",
				"agent_scopes",
			).
			Updates(virtualKey).Error; err != nil {
			return s.parseGormError(err)
		}
	}
	return nil
}

func (s *RDBConfigStore) ReplaceVirtualKeyGuardrailPolicies(ctx context.Context, virtualKeyID string, policyIDs []string, tx ...*gorm.DB) error {
	trimmedVirtualKeyID := strings.TrimSpace(virtualKeyID)
	if trimmedVirtualKeyID == "" {
		return nil
	}
	txDB := s.db
	if len(tx) > 0 && tx[0] != nil {
		txDB = tx[0]
	}
	if err := txDB.WithContext(ctx).
		Where("virtual_key_id = ?", trimmedVirtualKeyID).
		Delete(&tables.TableVirtualKeyGuardrailPolicy{}).Error; err != nil {
		return s.parseGormError(err)
	}
	if len(policyIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(policyIDs))
	bindings := make([]tables.TableVirtualKeyGuardrailPolicy, 0, len(policyIDs))
	now := time.Now().UTC()
	for _, policyID := range policyIDs {
		trimmedPolicyID := strings.TrimSpace(policyID)
		if trimmedPolicyID == "" {
			continue
		}
		if _, ok := seen[trimmedPolicyID]; ok {
			continue
		}
		seen[trimmedPolicyID] = struct{}{}
		bindings = append(bindings, tables.TableVirtualKeyGuardrailPolicy{
			VirtualKeyID:      trimmedVirtualKeyID,
			GuardrailPolicyID: trimmedPolicyID,
			CreatedAt:         now,
		})
	}
	if len(bindings) == 0 {
		return nil
	}
	if err := txDB.WithContext(ctx).Create(&bindings).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// GetKeysByIDs retrieves multiple keys by their IDs
func (s *RDBConfigStore) GetKeysByIDs(ctx context.Context, ids []string) ([]tables.TableKey, error) {
	if len(ids) == 0 {
		return []tables.TableKey{}, nil
	}
	var keys []tables.TableKey
	if err := s.db.WithContext(ctx).Where("key_id IN ?", ids).Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

// GetKeysByProvider retrieves all keys for a specific provider
func (s *RDBConfigStore) GetKeysByProvider(ctx context.Context, provider string) ([]tables.TableKey, error) {
	var keys []tables.TableKey
	if err := s.db.WithContext(ctx).Where("provider = ?", provider).Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

// GetAllRedactedKeys retrieves all redacted keys from the database.
func (s *RDBConfigStore) GetAllRedactedKeys(ctx context.Context, ids []string) ([]schemas.Key, error) {
	var keys []tables.TableKey
	if len(ids) > 0 {
		err := s.db.WithContext(ctx).Select("id, key_id, name, models_json, weight").Where("key_id IN ?", ids).Find(&keys).Error
		if err != nil {
			return nil, err
		}
	} else {
		err := s.db.WithContext(ctx).Select("id, key_id, name, models_json, weight").Find(&keys).Error
		if err != nil {
			return nil, err
		}
	}
	redactedKeys := make([]schemas.Key, len(keys))
	for i, key := range keys {
		models := key.Models
		if models == nil {
			models = []string{} // Ensure models is never nil in JSON response
		}
		redactedKeys[i] = schemas.Key{
			ID:     key.KeyID,
			Name:   key.Name,
			Models: models,
			Weight: getWeight(key.Weight),
		}
	}
	return redactedKeys, nil
}

// DeleteVirtualKey deletes a virtual key from the database.
func (s *RDBConfigStore) DeleteVirtualKey(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var virtualKey tables.TableVirtualKey
		if err := tx.WithContext(ctx).Preload("ProviderConfigs").First(&virtualKey, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		// Collect budget and rate limit IDs from provider configs before deletion
		var providerConfigBudgetIDs []string
		var providerConfigRateLimitIDs []string
		for _, pc := range virtualKey.ProviderConfigs {
			// Delete the keys join table entries
			if err := tx.WithContext(ctx).Exec("DELETE FROM governance_virtual_key_provider_config_keys WHERE table_virtual_key_provider_config_id = ?", pc.ID).Error; err != nil {
				return err
			}
			// Collect budget and rate limit IDs for deletion after provider config
			if pc.BudgetID != nil {
				providerConfigBudgetIDs = append(providerConfigBudgetIDs, *pc.BudgetID)
			}
			if pc.RateLimitID != nil {
				providerConfigRateLimitIDs = append(providerConfigRateLimitIDs, *pc.RateLimitID)
			}
		}

		// Delete all provider configs associated with the virtual key first
		if err := tx.WithContext(ctx).Delete(&tables.TableVirtualKeyProviderConfig{}, "virtual_key_id = ?", id).Error; err != nil {
			return err
		}
		// Now delete the collected budgets and rate limits
		for _, budgetID := range providerConfigBudgetIDs {
			if err := tx.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", budgetID).Error; err != nil {
				return err
			}
		}
		for _, rateLimitID := range providerConfigRateLimitIDs {
			if err := tx.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", rateLimitID).Error; err != nil {
				return err
			}
		}
		// Delete all MCP configs associated with the virtual key
		if err := tx.WithContext(ctx).Delete(&tables.TableVirtualKeyMCPConfig{}, "virtual_key_id = ?", id).Error; err != nil {
			return err
		}
		// Delete the budget associated with the virtual key
		budgetID := virtualKey.BudgetID
		rateLimitID := virtualKey.RateLimitID
		// Delete the virtual key
		if err := tx.WithContext(ctx).Delete(&tables.TableVirtualKey{}, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if budgetID != nil {
			if err := tx.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", *budgetID).Error; err != nil {
				return err
			}
		}
		// Delete the rate limit associated with the virtual key
		if rateLimitID != nil {
			if err := tx.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", *rateLimitID).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// GetVirtualKeyProviderConfigs retrieves all virtual key provider configs from the database.
func (s *RDBConfigStore) GetVirtualKeyProviderConfigs(ctx context.Context, virtualKeyID string) ([]tables.TableVirtualKeyProviderConfig, error) {
	var virtualKey tables.TableVirtualKey
	if err := s.db.WithContext(ctx).First(&virtualKey, "id = ?", virtualKeyID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []tables.TableVirtualKeyProviderConfig{}, nil
		}
		return nil, err
	}
	if virtualKey.ID == "" {
		return nil, nil
	}
	var providerConfigs []tables.TableVirtualKeyProviderConfig
	if err := s.db.WithContext(ctx).Where("virtual_key_id = ?", virtualKey.ID).Find(&providerConfigs).Error; err != nil {
		return nil, err
	}
	return providerConfigs, nil
}

// CreateVirtualKeyProviderConfig creates a new virtual key provider config in the database.
func (s *RDBConfigStore) CreateVirtualKeyProviderConfig(ctx context.Context, virtualKeyProviderConfig *tables.TableVirtualKeyProviderConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Store keys before create
	keysToAssociate := virtualKeyProviderConfig.Keys

	// Resolve keys by name/key_id if they don't have database IDs
	// This handles config file inputs that only specify name
	if len(keysToAssociate) > 0 {
		resolvedKeys := make([]tables.TableKey, 0, len(keysToAssociate))
		var unresolvedKeys []string
		for i, k := range keysToAssociate {
			// If key already has a database ID (from UI), use it directly
			if k.ID > 0 {
				resolvedKeys = append(resolvedKeys, k)
				continue
			}
			// Otherwise resolve by KeyID or Name (from config file)
			var dbKey tables.TableKey
			var resolved bool
			if k.KeyID != "" {
				if err := txDB.WithContext(ctx).Where("key_id = ?", k.KeyID).First(&dbKey).Error; err == nil {
					resolvedKeys = append(resolvedKeys, dbKey)
					resolved = true
				}
			}
			if !resolved && k.Name != "" {
				if err := txDB.WithContext(ctx).Where("name = ? AND provider = ?", k.Name, virtualKeyProviderConfig.Provider).First(&dbKey).Error; err == nil {
					resolvedKeys = append(resolvedKeys, dbKey)
					resolved = true
				}
			}
			if !resolved {
				// Collect identifier for unresolved key
				if k.KeyID != "" {
					unresolvedKeys = append(unresolvedKeys, fmt.Sprintf("key_id=%s", k.KeyID))
				} else if k.Name != "" {
					unresolvedKeys = append(unresolvedKeys, fmt.Sprintf("name=%s", k.Name))
				} else {
					unresolvedKeys = append(unresolvedKeys, fmt.Sprintf("key[%d]", i))
				}
			}
		}
		if len(unresolvedKeys) > 0 {
			return &ErrUnresolvedKeys{Identifiers: unresolvedKeys}
		}
		keysToAssociate = resolvedKeys
	}

	// Clear Keys before Create to prevent GORM from auto-associating unresolved keys (with ID=0)
	// We'll manually associate the resolved keys after Create
	virtualKeyProviderConfig.Keys = nil

	if err := txDB.WithContext(ctx).Create(virtualKeyProviderConfig).Error; err != nil {
		return s.parseGormError(err)
	}

	// Associate keys after the provider config has an ID
	if len(keysToAssociate) > 0 {
		if err := txDB.WithContext(ctx).Model(virtualKeyProviderConfig).Association("Keys").Append(keysToAssociate); err != nil {
			return err
		}
	}
	return nil
}

// UpdateVirtualKeyProviderConfig updates a virtual key provider config in the database.
func (s *RDBConfigStore) UpdateVirtualKeyProviderConfig(ctx context.Context, virtualKeyProviderConfig *tables.TableVirtualKeyProviderConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}

	// Store keys before save
	keysToAssociate := virtualKeyProviderConfig.Keys

	// Resolve keys by name/key_id if they don't have database IDs
	// This handles config file inputs that only specify name
	if len(keysToAssociate) > 0 {
		resolvedKeys := make([]tables.TableKey, 0, len(keysToAssociate))
		var unresolvedKeys []string
		for i, k := range keysToAssociate {
			// If key already has a database ID (from UI), use it directly
			if k.ID > 0 {
				resolvedKeys = append(resolvedKeys, k)
				continue
			}
			// Otherwise resolve by KeyID or Name (from config file)
			var dbKey tables.TableKey
			var resolved bool
			if k.KeyID != "" {
				if err := txDB.WithContext(ctx).Where("key_id = ?", k.KeyID).First(&dbKey).Error; err == nil {
					resolvedKeys = append(resolvedKeys, dbKey)
					resolved = true
				}
			}
			if !resolved && k.Name != "" {
				if err := txDB.WithContext(ctx).Where("name = ? AND provider = ?", k.Name, virtualKeyProviderConfig.Provider).First(&dbKey).Error; err == nil {
					resolvedKeys = append(resolvedKeys, dbKey)
					resolved = true
				}
			}
			if !resolved {
				// Collect identifier for unresolved key
				if k.KeyID != "" {
					unresolvedKeys = append(unresolvedKeys, fmt.Sprintf("key_id=%s", k.KeyID))
				} else if k.Name != "" {
					unresolvedKeys = append(unresolvedKeys, fmt.Sprintf("name=%s", k.Name))
				} else {
					unresolvedKeys = append(unresolvedKeys, fmt.Sprintf("key[%d]", i))
				}
			}
		}
		if len(unresolvedKeys) > 0 {
			return &ErrUnresolvedKeys{Identifiers: unresolvedKeys}
		}
		keysToAssociate = resolvedKeys
	}

	// Clear Keys before Save to prevent GORM from auto-associating unresolved keys (with ID=0)
	// We'll manually manage the association after Save
	virtualKeyProviderConfig.Keys = nil

	if err := txDB.WithContext(ctx).Save(virtualKeyProviderConfig).Error; err != nil {
		return s.parseGormError(err)
	}

	// Clear existing key associations and set new ones
	if err := txDB.WithContext(ctx).Model(virtualKeyProviderConfig).Association("Keys").Clear(); err != nil {
		return err
	}
	if len(keysToAssociate) > 0 {
		if err := txDB.WithContext(ctx).Model(virtualKeyProviderConfig).Association("Keys").Append(keysToAssociate); err != nil {
			return err
		}
	}
	return nil
}

// DeleteVirtualKeyProviderConfig deletes a virtual key provider config from the database.
func (s *RDBConfigStore) DeleteVirtualKeyProviderConfig(ctx context.Context, id uint, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// First fetch the provider config to get budget and rate limit IDs
	var providerConfig tables.TableVirtualKeyProviderConfig
	if err := txDB.WithContext(ctx).First(&providerConfig, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	// Store the budget and rate limit IDs before deleting
	budgetID := providerConfig.BudgetID
	rateLimitID := providerConfig.RateLimitID
	// Delete the provider config first
	if err := txDB.WithContext(ctx).Delete(&tables.TableVirtualKeyProviderConfig{}, "id = ?", id).Error; err != nil {
		return err
	}
	// Delete the budget if it exists
	if budgetID != nil {
		if err := txDB.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", *budgetID).Error; err != nil {
			return err
		}
	}
	// Delete the rate limit if it exists
	if rateLimitID != nil {
		if err := txDB.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", *rateLimitID).Error; err != nil {
			return err
		}
	}
	return nil
}

// GetVirtualKeyMCPConfigs retrieves all virtual key MCP configs from the database.
func (s *RDBConfigStore) GetVirtualKeyMCPConfigs(ctx context.Context, virtualKeyID string) ([]tables.TableVirtualKeyMCPConfig, error) {
	var virtualKey tables.TableVirtualKey
	if err := s.db.WithContext(ctx).First(&virtualKey, "id = ?", virtualKeyID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []tables.TableVirtualKeyMCPConfig{}, nil
		}
		return nil, err
	}
	if virtualKey.ID == "" {
		return nil, nil
	}
	var mcpConfigs []tables.TableVirtualKeyMCPConfig
	if err := s.db.WithContext(ctx).Where("virtual_key_id = ?", virtualKey.ID).Find(&mcpConfigs).Error; err != nil {
		return nil, err
	}
	return mcpConfigs, nil
}

// CreateVirtualKeyMCPConfig creates a new virtual key MCP config in the database.
func (s *RDBConfigStore) CreateVirtualKeyMCPConfig(ctx context.Context, virtualKeyMCPConfig *tables.TableVirtualKeyMCPConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Create(virtualKeyMCPConfig).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateVirtualKeyMCPConfig updates a virtual key provider config in the database.
func (s *RDBConfigStore) UpdateVirtualKeyMCPConfig(ctx context.Context, virtualKeyMCPConfig *tables.TableVirtualKeyMCPConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Save(virtualKeyMCPConfig).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// DeleteVirtualKeyMCPConfig deletes a virtual key provider config from the database.
func (s *RDBConfigStore) DeleteVirtualKeyMCPConfig(ctx context.Context, id uint, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	return txDB.WithContext(ctx).Delete(&tables.TableVirtualKeyMCPConfig{}, "id = ?", id).Error
}

// GetTeams retrieves all teams from the database.
func (s *RDBConfigStore) GetTeams(ctx context.Context, customerID string) ([]tables.TableTeam, error) {
	// Preload relationships for complete information
	query := s.db.WithContext(ctx).Preload("Customer").Preload("Budget").Preload("RateLimit")
	// Optional filtering by customer
	if customerID != "" {
		query = query.Where("customer_id = ?", customerID)
	}
	var teams []tables.TableTeam
	if err := query.Order("created_at ASC").Find(&teams).Error; err != nil {
		return nil, err
	}
	if err := s.attachMembersToTeams(ctx, teams); err != nil {
		return nil, err
	}
	if err := s.attachCustomerMembersToTeams(ctx, teams); err != nil {
		return nil, err
	}
	return teams, nil
}

// GetTeamsPaginated retrieves teams with pagination, filtering, and search support.
func (s *RDBConfigStore) GetTeamsPaginated(ctx context.Context, params TeamsQueryParams) ([]tables.TableTeam, int64, error) {
	baseQuery := s.db.WithContext(ctx).Model(&tables.TableTeam{})

	if params.CustomerID != "" {
		baseQuery = baseQuery.Where("customer_id = ?", params.CustomerID)
	}
	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		baseQuery = baseQuery.Where("LOWER(name) LIKE ?", search)
	}
	// Workspace-scope filter: include teams scoped to this workspace
	// plus tenant-wide teams (workspace_id IS NULL). Same shape as
	// virtual keys / MCP clients so a tenant admin can host teams that
	// apply across all workspaces alongside per-workspace teams.
	if ws := strings.TrimSpace(params.WorkspaceID); ws != "" {
		baseQuery = baseQuery.Where("workspace_id = ? OR workspace_id IS NULL", ws)
	}

	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	offset := params.Offset
	if limit <= 0 {
		limit = 25
	} else if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var teams []tables.TableTeam
	if err := baseQuery.
		Preload("Customer").Preload("Budget").Preload("RateLimit").
		Order("created_at ASC, id ASC").
		Offset(offset).Limit(limit).
		Find(&teams).Error; err != nil {
		return nil, 0, err
	}
	if err := s.attachMembersToTeams(ctx, teams); err != nil {
		return nil, 0, err
	}
	if err := s.attachCustomerMembersToTeams(ctx, teams); err != nil {
		return nil, 0, err
	}

	return teams, totalCount, nil
}

// GetTeam retrieves a specific team from the database.
func (s *RDBConfigStore) GetTeam(ctx context.Context, id string) (*tables.TableTeam, error) {
	var team tables.TableTeam
	if err := s.db.WithContext(ctx).Preload("Customer").Preload("Budget").Preload("RateLimit").First(&team, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	members, err := s.GetTeamMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	team.Members = members
	customerMembers, err := s.getTeamCustomerMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	team.CustomerMembers = customerMembers
	return &team, nil
}

// CreateTeam creates a new team in the database.
func (s *RDBConfigStore) CreateTeam(ctx context.Context, team *tables.TableTeam, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Create(team).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateTeam updates an existing team in the database.
func (s *RDBConfigStore) UpdateTeam(ctx context.Context, team *tables.TableTeam, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Save(team).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

func (s *RDBConfigStore) GetTeamMembers(ctx context.Context, teamID string) ([]tables.TableAuthUser, error) {
	type joinedTeamMember struct {
		TeamID string `gorm:"column:team_id"`
		tables.TableAuthUser
	}

	var rows []joinedTeamMember
	query := s.db.WithContext(ctx).
		Model(&tables.TableTeamMember{}).
		Select("governance_team_members.team_id as team_id, auth_users.*").
		Joins("JOIN auth_users ON auth_users.id = governance_team_members.user_id").
		Where("governance_team_members.team_id = ?", teamID).
		Order("auth_users.first_name ASC, auth_users.last_name ASC, auth_users.email ASC")

	if tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenantID != "" {
		query = query.Where("governance_team_members.tenant_id = ?", tenantID)
	}

	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}

	members := make([]tables.TableAuthUser, 0, len(rows))
	for _, row := range rows {
		members = append(members, row.TableAuthUser)
	}
	return members, nil
}

func (s *RDBConfigStore) ReplaceTeamMembers(ctx context.Context, teamID string, userIDs []string, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}

	normalizedIDs := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		trimmed := strings.TrimSpace(userID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalizedIDs = append(normalizedIDs, trimmed)
	}

	if err := txDB.WithContext(ctx).Where("team_id = ?", teamID).Delete(&tables.TableTeamMember{}).Error; err != nil {
		return err
	}
	if len(normalizedIDs) == 0 {
		return nil
	}

	var users []tables.TableAuthUser
	if err := txDB.WithContext(ctx).Where("id IN ?", normalizedIDs).Find(&users).Error; err != nil {
		return err
	}

	activeUsers := make(map[string]tables.TableAuthUser, len(users))
	for _, user := range users {
		if user.IsEmailVerified {
			activeUsers[user.ID] = user
		}
	}
	if len(activeUsers) != len(normalizedIDs) {
		return fmt.Errorf("all team members must be active workspace users")
	}

	memberships := make([]tables.TableTeamMember, 0, len(normalizedIDs))
	for _, userID := range normalizedIDs {
		memberships = append(memberships, tables.TableTeamMember{
			ID:     uuid.NewString(),
			TeamID: teamID,
			UserID: userID,
		})
	}

	return txDB.WithContext(ctx).Create(&memberships).Error
}

func (s *RDBConfigStore) ReplaceTeamCustomerMembers(ctx context.Context, teamID string, customerIDs []string, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}

	normalizedIDs := make([]string, 0, len(customerIDs))
	seen := make(map[string]struct{}, len(customerIDs))
	for _, customerID := range customerIDs {
		trimmed := strings.TrimSpace(customerID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalizedIDs = append(normalizedIDs, trimmed)
	}

	if err := txDB.WithContext(ctx).Where("team_id = ?", teamID).Delete(&tables.TableTeamCustomerMember{}).Error; err != nil {
		return err
	}
	if len(normalizedIDs) == 0 {
		return nil
	}

	var customers []tables.TableCustomer
	if err := txDB.WithContext(ctx).Where("id IN ?", normalizedIDs).Find(&customers).Error; err != nil {
		return err
	}
	if len(customers) != len(normalizedIDs) {
		return fmt.Errorf("all team members must be valid governance members")
	}

	memberships := make([]tables.TableTeamCustomerMember, 0, len(normalizedIDs))
	for _, customerID := range normalizedIDs {
		memberships = append(memberships, tables.TableTeamCustomerMember{
			ID:         uuid.NewString(),
			TeamID:     teamID,
			CustomerID: customerID,
		})
	}

	return txDB.WithContext(ctx).Create(&memberships).Error
}

func (s *RDBConfigStore) DeleteTeamMembersByUserID(ctx context.Context, userID string, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	return txDB.WithContext(ctx).Delete(&tables.TableTeamMember{}, "user_id = ?", userID).Error
}

// DeleteTeam deletes a team from the database.
func (s *RDBConfigStore) DeleteTeam(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var team tables.TableTeam
		if err := tx.WithContext(ctx).Preload("Budget").Preload("RateLimit").First(&team, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// Set team_id to null for all virtual keys associated with the team
		if err := tx.WithContext(ctx).Model(&tables.TableVirtualKey{}).Where("team_id = ?", id).Update("team_id", nil).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Delete(&tables.TableTeamMember{}, "team_id = ?", id).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Delete(&tables.TableTeamCustomerMember{}, "team_id = ?", id).Error; err != nil {
			return err
		}
		// Store the budget and rate limit IDs before deleting the team
		budgetID := team.BudgetID
		rateLimitID := team.RateLimitID
		// Delete the team first
		if err := tx.WithContext(ctx).Delete(&tables.TableTeam{}, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// Delete the team's budget if it exists
		if budgetID != nil {
			if err := tx.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", *budgetID).Error; err != nil {
				return err
			}
		}
		// Delete the team's rate limit if it exists
		if rateLimitID != nil {
			if err := tx.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", *rateLimitID).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func (s *RDBConfigStore) attachMembersToTeams(ctx context.Context, teams []tables.TableTeam) error {
	if len(teams) == 0 {
		return nil
	}

	type joinedTeamMember struct {
		TeamID string `gorm:"column:team_id"`
		tables.TableAuthUser
	}

	teamIDs := make([]string, 0, len(teams))
	for _, team := range teams {
		teamIDs = append(teamIDs, team.ID)
	}

	query := s.db.WithContext(ctx).
		Model(&tables.TableTeamMember{}).
		Select("governance_team_members.team_id as team_id, auth_users.*").
		Joins("JOIN auth_users ON auth_users.id = governance_team_members.user_id").
		Where("governance_team_members.team_id IN ?", teamIDs).
		Order("auth_users.first_name ASC, auth_users.last_name ASC, auth_users.email ASC")

	if tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenantID != "" {
		query = query.Where("governance_team_members.tenant_id = ?", tenantID)
	}

	var rows []joinedTeamMember
	if err := query.Scan(&rows).Error; err != nil {
		return err
	}

	membersByTeam := make(map[string][]tables.TableAuthUser, len(teamIDs))
	for _, row := range rows {
		membersByTeam[row.TeamID] = append(membersByTeam[row.TeamID], row.TableAuthUser)
	}

	for i := range teams {
		teams[i].Members = membersByTeam[teams[i].ID]
	}

	return nil
}

func (s *RDBConfigStore) getTeamCustomerMembers(ctx context.Context, teamID string) ([]tables.TableCustomer, error) {
	type joinedTeamCustomerMember struct {
		TeamID string `gorm:"column:team_id"`
		tables.TableCustomer
	}

	var rows []joinedTeamCustomerMember
	query := s.db.WithContext(ctx).
		Model(&tables.TableTeamCustomerMember{}).
		Select("governance_team_customer_members.team_id as team_id, governance_customers.*").
		Joins("JOIN governance_customers ON governance_customers.id = governance_team_customer_members.customer_id").
		Where("governance_team_customer_members.team_id = ?", teamID).
		Order("governance_customers.name ASC")

	if tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenantID != "" {
		query = query.Where("governance_team_customer_members.tenant_id = ?", tenantID)
	}

	if err := query.Scan(&rows).Error; err != nil {
		return nil, err
	}

	members := make([]tables.TableCustomer, 0, len(rows))
	for _, row := range rows {
		members = append(members, row.TableCustomer)
	}
	return members, nil
}

func (s *RDBConfigStore) attachCustomerMembersToTeams(ctx context.Context, teams []tables.TableTeam) error {
	if len(teams) == 0 {
		return nil
	}

	type joinedTeamCustomerMember struct {
		TeamID string `gorm:"column:team_id"`
		tables.TableCustomer
	}

	teamIDs := make([]string, 0, len(teams))
	for _, team := range teams {
		teamIDs = append(teamIDs, team.ID)
	}

	query := s.db.WithContext(ctx).
		Model(&tables.TableTeamCustomerMember{}).
		Select("governance_team_customer_members.team_id as team_id, governance_customers.*").
		Joins("JOIN governance_customers ON governance_customers.id = governance_team_customer_members.customer_id").
		Where("governance_team_customer_members.team_id IN ?", teamIDs).
		Order("governance_customers.name ASC")

	if tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx)); tenantID != "" {
		query = query.Where("governance_team_customer_members.tenant_id = ?", tenantID)
	}

	var rows []joinedTeamCustomerMember
	if err := query.Scan(&rows).Error; err != nil {
		return err
	}

	membersByTeam := make(map[string][]tables.TableCustomer, len(teamIDs))
	for _, row := range rows {
		membersByTeam[row.TeamID] = append(membersByTeam[row.TeamID], row.TableCustomer)
	}

	for i := range teams {
		teams[i].CustomerMembers = membersByTeam[teams[i].ID]
	}

	return nil
}

// GetCustomers retrieves all customers from the database.
func (s *RDBConfigStore) GetCustomers(ctx context.Context) ([]tables.TableCustomer, error) {
	var customers []tables.TableCustomer
	if err := s.db.WithContext(ctx).Preload("Teams").Preload("Budget").Preload("RateLimit").Order("created_at ASC").Find(&customers).Error; err != nil {
		return nil, err
	}
	return customers, nil
}

// GetCustomersPaginated retrieves customers with pagination and optional search filtering.
func (s *RDBConfigStore) GetCustomersPaginated(ctx context.Context, params CustomersQueryParams) ([]tables.TableCustomer, int64, error) {
	baseQuery := s.db.WithContext(ctx).Model(&tables.TableCustomer{})
	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		baseQuery = baseQuery.Where("LOWER(name) LIKE ?", search)
	}
	// Workspace-scope filter: include customers scoped to this
	// workspace plus tenant-wide customers (workspace_id IS NULL).
	// Same shape as teams / virtual keys.
	if ws := strings.TrimSpace(params.WorkspaceID); ws != "" {
		baseQuery = baseQuery.Where("workspace_id = ? OR workspace_id IS NULL", ws)
	}
	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}
	limit := params.Limit
	offset := params.Offset
	if limit <= 0 {
		limit = 25
	} else if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var customers []tables.TableCustomer
	if err := baseQuery.
		Preload("Teams").Preload("Budget").Preload("RateLimit").
		Order("created_at ASC, id ASC").
		Offset(offset).Limit(limit).
		Find(&customers).Error; err != nil {
		return nil, 0, err
	}
	return customers, totalCount, nil
}

// GetCustomer retrieves a specific customer from the database.
func (s *RDBConfigStore) GetCustomer(ctx context.Context, id string) (*tables.TableCustomer, error) {
	var customer tables.TableCustomer
	if err := s.db.WithContext(ctx).Preload("Teams").Preload("Budget").Preload("RateLimit").First(&customer, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &customer, nil
}

// CreateCustomer creates a new customer in the database.
func (s *RDBConfigStore) CreateCustomer(ctx context.Context, customer *tables.TableCustomer, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Create(customer).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateCustomer updates an existing customer in the database.
func (s *RDBConfigStore) UpdateCustomer(ctx context.Context, customer *tables.TableCustomer, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Save(customer).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// DeleteCustomer deletes a customer from the database.
func (s *RDBConfigStore) DeleteCustomer(ctx context.Context, id string) error {
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var customer tables.TableCustomer
		if err := tx.WithContext(ctx).Preload("Budget").Preload("RateLimit").First(&customer, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// Set customer_id to null for all virtual keys associated with the customer
		if err := tx.WithContext(ctx).Model(&tables.TableVirtualKey{}).Where("customer_id = ?", id).Update("customer_id", nil).Error; err != nil {
			return err
		}
		// Set customer_id to null for all teams associated with the customer
		if err := tx.WithContext(ctx).Model(&tables.TableTeam{}).Where("customer_id = ?", id).Update("customer_id", nil).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Delete(&tables.TableTeamCustomerMember{}, "customer_id = ?", id).Error; err != nil {
			return err
		}
		// Store the budget and rate limit IDs before deleting the customer
		budgetID := customer.BudgetID
		rateLimitID := customer.RateLimitID
		// Delete the customer first
		if err := tx.WithContext(ctx).Delete(&tables.TableCustomer{}, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// Delete the customer's budget if it exists
		if budgetID != nil {
			if err := tx.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", *budgetID).Error; err != nil {
				return err
			}
		}
		// Delete the customer's rate limit if it exists
		if rateLimitID != nil {
			if err := tx.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", *rateLimitID).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// GetRateLimits retrieves all rate limits from the database.
func (s *RDBConfigStore) GetRateLimits(ctx context.Context) ([]tables.TableRateLimit, error) {
	var rateLimits []tables.TableRateLimit
	if err := s.db.WithContext(ctx).Order("created_at ASC").Find(&rateLimits).Error; err != nil {
		return nil, err
	}
	return rateLimits, nil
}

// GetRateLimit retrieves a specific rate limit from the database.
func (s *RDBConfigStore) GetRateLimit(ctx context.Context, id string, tx ...*gorm.DB) (*tables.TableRateLimit, error) {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	var rateLimit tables.TableRateLimit
	if err := txDB.WithContext(ctx).First(&rateLimit, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &rateLimit, nil
}

// CreateRateLimit creates a new rate limit in the database.
func (s *RDBConfigStore) CreateRateLimit(ctx context.Context, rateLimit *tables.TableRateLimit, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Create(rateLimit).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateRateLimit updates a rate limit in the database.
func (s *RDBConfigStore) UpdateRateLimit(ctx context.Context, rateLimit *tables.TableRateLimit, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Save(rateLimit).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateRateLimits updates multiple rate limits in the database.
func (s *RDBConfigStore) UpdateRateLimits(ctx context.Context, rateLimits []*tables.TableRateLimit, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	for _, rl := range rateLimits {
		if err := txDB.WithContext(ctx).Save(rl).Error; err != nil {
			return s.parseGormError(err)
		}
	}
	return nil
}

// DeleteRateLimit deletes a rate limit from the database.
func (s *RDBConfigStore) DeleteRateLimit(ctx context.Context, id string, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Delete(&tables.TableRateLimit{}, "id = ?", id).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// GetBudgets retrieves all budgets from the database.
func (s *RDBConfigStore) GetBudgets(ctx context.Context) ([]tables.TableBudget, error) {
	var budgets []tables.TableBudget
	if err := s.db.WithContext(ctx).Order("created_at ASC").Find(&budgets).Error; err != nil {
		return nil, err
	}
	return budgets, nil
}

// GetBudget retrieves a specific budget from the database.
func (s *RDBConfigStore) GetBudget(ctx context.Context, id string, tx ...*gorm.DB) (*tables.TableBudget, error) {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	var budget tables.TableBudget
	if err := txDB.WithContext(ctx).First(&budget, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &budget, nil
}

// CreateBudget creates a new budget in the database.
func (s *RDBConfigStore) CreateBudget(ctx context.Context, budget *tables.TableBudget, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Create(budget).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateBudgets updates multiple budgets in the database.
func (s *RDBConfigStore) UpdateBudgets(ctx context.Context, budgets []*tables.TableBudget, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	for _, b := range budgets {
		if err := txDB.WithContext(ctx).Save(b).Error; err != nil {
			return s.parseGormError(err)
		}
	}
	return nil
}

// UpdateBudget updates a budget in the database.
func (s *RDBConfigStore) UpdateBudget(ctx context.Context, budget *tables.TableBudget, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Save(budget).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// DeleteBudget deletes a budget from the database.
func (s *RDBConfigStore) DeleteBudget(ctx context.Context, id string, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Delete(&tables.TableBudget{}, "id = ?", id).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateBudgetUsage updates only the current_usage field of a budget.
// Uses SkipHooks to avoid triggering BeforeSave validation since we're only updating usage.
func (s *RDBConfigStore) UpdateBudgetUsage(ctx context.Context, id string, currentUsage float64) error {
	result := s.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&tables.TableBudget{}).
		Where("id = ?", id).
		Update("current_usage", currentUsage)
	if result.Error != nil {
		return s.parseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateRateLimitUsage updates only the usage fields of a rate limit.
// Uses SkipHooks to avoid triggering BeforeSave validation since we're only updating usage.
func (s *RDBConfigStore) UpdateRateLimitUsage(ctx context.Context, id string, tokenCurrentUsage int64, requestCurrentUsage int64) error {
	result := s.db.WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Model(&tables.TableRateLimit{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"token_current_usage":   tokenCurrentUsage,
			"request_current_usage": requestCurrentUsage,
		})
	if result.Error != nil {
		return s.parseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// loadRoutingRulesOrdered loads routing rules with Targets preloaded, using consistent ordering:
// rules by priority ASC, created_at DESC, id ASC; targets by weight DESC for deterministic ordering.
func (s *RDBConfigStore) loadRoutingRulesOrdered(ctx context.Context, dest *[]tables.TableRoutingRule, scopes ...func(*gorm.DB) *gorm.DB) error {
	q := s.db.WithContext(ctx).
		Preload("Targets", func(db *gorm.DB) *gorm.DB {
			return db.Order("weight DESC").
				Order("COALESCE(provider, '') ASC").
				Order("COALESCE(model, '') ASC").
				Order("COALESCE(key_id, '') ASC")
		}).
		Order("priority ASC, created_at DESC, id ASC")
	for _, scope := range scopes {
		q = scope(q)
	}
	return q.Find(dest).Error
}

// GetRoutingRules retrieves all routing rules from the database.
func (s *RDBConfigStore) GetRoutingRules(ctx context.Context) ([]tables.TableRoutingRule, error) {
	var rules []tables.TableRoutingRule
	if err := s.loadRoutingRulesOrdered(ctx, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// GetRoutingRulesPaginated retrieves routing rules with pagination and optional search filtering.
func (s *RDBConfigStore) GetRoutingRulesPaginated(ctx context.Context, params RoutingRulesQueryParams) ([]tables.TableRoutingRule, int64, error) {
	baseQuery := s.db.WithContext(ctx).Model(&tables.TableRoutingRule{})

	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		baseQuery = baseQuery.Where("LOWER(name) LIKE ?", search)
	}
	// Workspace-scope filter: include rules scoped to the workspace plus
	// tenant-wide rules (workspace_id IS NULL). Empty WorkspaceID returns
	// the full tenant view.
	if ws := strings.TrimSpace(params.WorkspaceID); ws != "" {
		// Strict per-workspace scoping. Each workspace under a tenant owns
		// its own configuration - providers, routing rules, virtual keys,
		// plugins. Legacy NULL rows are migrated to the parent tenant's
		// Default workspace by migrationBackfillNullWorkspaceIDs so they
		// stay visible after this filter tightens.
		baseQuery = baseQuery.Where("workspace_id = ?", ws)
	}

	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	offset := params.Offset

	if limit <= 0 {
		limit = 25
	} else if limit > 100 {
		limit = 100
	}

	if offset < 0 {
		offset = 0
	}

	var rules []tables.TableRoutingRule
	if err := baseQuery.
		Preload("Targets", func(db *gorm.DB) *gorm.DB {
			return db.Order("weight DESC").
				Order("COALESCE(provider, '') ASC").
				Order("COALESCE(model, '') ASC").
				Order("COALESCE(key_id, '') ASC")
		}).
		Order("priority ASC, created_at DESC, id ASC").
		Offset(offset).
		Limit(limit).
		Find(&rules).Error; err != nil {
		return nil, 0, err
	}
	return rules, totalCount, nil
}

// GetRoutingRulesByScope retrieves routing rules by scope and scope ID, ordered by priority ASC.
func (s *RDBConfigStore) GetRoutingRulesByScope(ctx context.Context, scope string, scopeID string) ([]tables.TableRoutingRule, error) {
	if scope != "global" && scopeID == "" {
		return nil, fmt.Errorf("scopeID is required for non-global scope %q", scope)
	}
	var rules []tables.TableRoutingRule
	scopeFilter := func(q *gorm.DB) *gorm.DB {
		if scope == "global" {
			return q.Where("scope = ?", "global")
		}
		return q.Where("scope = ? AND scope_id = ?", scope, scopeID)
	}
	if err := s.loadRoutingRulesOrdered(ctx, &rules, scopeFilter, func(q *gorm.DB) *gorm.DB {
		return q.Where("enabled = ?", true)
	}); err != nil {
		return nil, err
	}
	return rules, nil
}

// GetRoutingRule retrieves a specific routing rule by ID.
func (s *RDBConfigStore) GetRoutingRule(ctx context.Context, id string) (*tables.TableRoutingRule, error) {
	var rules []tables.TableRoutingRule
	if err := s.loadRoutingRulesOrdered(ctx, &rules, func(q *gorm.DB) *gorm.DB {
		return q.Where("id = ?", id)
	}); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, ErrNotFound
	}
	return &rules[0], nil
}

// GetRedactedRoutingRules retrieves redacted routing rules from the database.
func (s *RDBConfigStore) GetRedactedRoutingRules(ctx context.Context, ids []string) ([]tables.TableRoutingRule, error) {
	var routingRules []tables.TableRoutingRule

	if len(ids) > 0 {
		err := s.db.WithContext(ctx).Select("id, name, description, enabled").Where("id IN ?", ids).Find(&routingRules).Error
		if err != nil {
			return nil, err
		}
	} else {
		err := s.db.WithContext(ctx).Select("id, name, description, enabled").Find(&routingRules).Error
		if err != nil {
			return nil, err
		}
	}
	return routingRules, nil
}

// CreateRoutingRule creates a new routing rule in the database.
func (s *RDBConfigStore) CreateRoutingRule(ctx context.Context, rule *tables.TableRoutingRule, tx ...*gorm.DB) error {
	database := s.db
	if len(tx) > 0 && tx[0] != nil {
		database = tx[0]
	}

	// Validate scopeID is required for non-global scope
	if rule.Scope != "" && rule.Scope != "global" && rule.ScopeID == nil {
		return fmt.Errorf("scopeID is required for non-global scope '%s'", rule.Scope)
	}

	// Resolve effective workspace: explicit > context > tenant default.
	if rule.WorkspaceID == nil {
		if ws := s.resolveEffectiveWorkspaceID(ctx, ""); ws != "" {
			rule.WorkspaceID = &ws
		}
	}

	// Check if there is already a routing rule with the same priority for the same scope+scopeID
	var count int64
	query := database.WithContext(ctx).Where("scope = ? AND priority = ? AND id != ?", rule.Scope, rule.Priority, rule.ID)
	if rule.ScopeID != nil {
		query = query.Where("scope_id = ?", *rule.ScopeID)
	} else {
		query = query.Where("scope_id IS NULL")
	}
	if err := query.Model(&tables.TableRoutingRule{}).Count(&count).Error; err != nil {
		return s.parseGormError(err)
	}
	if count > 0 {
		if rule.ScopeID != nil {
			return fmt.Errorf("routing rule with priority %d already exists for scope '%s' with scopeID '%v'", rule.Priority, rule.Scope, rule.ScopeID)
		}
		return fmt.Errorf("routing rule with priority %d already exists for scope '%s'", rule.Priority, rule.Scope)
	}

	return s.parseGormError(database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		targets := rule.Targets
		rule.Targets = nil
		if err := tx.Omit("Targets").Create(rule).Error; err != nil {
			return err
		}
		rule.Targets = targets

		for i := range rule.Targets {
			rule.Targets[i].RuleID = rule.ID
			if err := tx.Create(&rule.Targets[i]).Error; err != nil {
				return err
			}
		}
		return nil
	}))
}

// UpdateRoutingRule updates an existing routing rule in the database.
// It enforces the same unique-priority-per-scope invariant as CreateRoutingRule.
func (s *RDBConfigStore) UpdateRoutingRule(ctx context.Context, rule *tables.TableRoutingRule, tx ...*gorm.DB) error {
	database := s.db
	if len(tx) > 0 && tx[0] != nil {
		database = tx[0]
	}

	// Validate scopeID is required for non-global scope
	if rule.Scope != "" && rule.Scope != "global" && rule.ScopeID == nil {
		return fmt.Errorf("scopeID is required for non-global scope '%s'", rule.Scope)
	}

	// Check for another tables.TableRoutingRule with same scope (Scope + ScopeID) and Priority but different ID
	var count int64
	query := database.WithContext(ctx).Where("scope = ? AND priority = ? AND id != ?", rule.Scope, rule.Priority, rule.ID)
	if rule.ScopeID != nil {
		query = query.Where("scope_id = ?", *rule.ScopeID)
	} else {
		query = query.Where("scope_id IS NULL")
	}
	if err := query.Model(&tables.TableRoutingRule{}).Count(&count).Error; err != nil {
		return s.parseGormError(err)
	}
	if count > 0 {
		if rule.ScopeID != nil {
			return fmt.Errorf("routing rule with priority %d already exists for scope '%s' with scopeID '%v'", rule.Priority, rule.Scope, rule.ScopeID)
		}
		return fmt.Errorf("routing rule with priority %d already exists for scope '%s'", rule.Priority, rule.Scope)
	}

	return s.parseGormError(database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		targets := rule.Targets
		rule.Targets = nil
		if err := tx.Omit("Targets").Save(rule).Error; err != nil {
			return err
		}
		rule.Targets = targets

		if err := tx.Where("rule_id = ?", rule.ID).Delete(&tables.TableRoutingTarget{}).Error; err != nil {
			return err
		}
		for i := range rule.Targets {
			rule.Targets[i].RuleID = rule.ID
			if err := tx.Create(&rule.Targets[i]).Error; err != nil {
				return err
			}
		}
		return nil
	}))
}

// DeleteRoutingRule deletes a routing rule and its targets from the database.
func (s *RDBConfigStore) DeleteRoutingRule(ctx context.Context, id string, tx ...*gorm.DB) error {
	database := s.db
	if len(tx) > 0 && tx[0] != nil {
		database = tx[0]
	}

	return s.parseGormError(database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("rule_id = ?", id).Delete(&tables.TableRoutingTarget{}).Error; err != nil {
			return err
		}
		result := tx.Delete(&tables.TableRoutingRule{}, "id = ?", id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	}))
}

// GetModelConfigs retrieves all model configs from the database.
func (s *RDBConfigStore) GetModelConfigs(ctx context.Context) ([]tables.TableModelConfig, error) {
	var modelConfigs []tables.TableModelConfig
	if err := s.db.WithContext(ctx).Preload("Budget").Preload("RateLimit").Find(&modelConfigs).Error; err != nil {
		return nil, err
	}
	return modelConfigs, nil
}

func (s *RDBConfigStore) GetModelConfigsPaginated(ctx context.Context, params ModelConfigsQueryParams) ([]tables.TableModelConfig, int64, error) {
	baseQuery := s.db.WithContext(ctx).Model(&tables.TableModelConfig{})

	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		baseQuery = baseQuery.Where("LOWER(model_name) LIKE ?", search)
	}
	if ws := strings.TrimSpace(params.WorkspaceID); ws != "" {
		// Strict per-workspace scoping. Each workspace under a tenant owns
		// its own configuration - providers, routing rules, virtual keys,
		// plugins. Legacy NULL rows are migrated to the parent tenant's
		// Default workspace by migrationBackfillNullWorkspaceIDs so they
		// stay visible after this filter tightens.
		baseQuery = baseQuery.Where("workspace_id = ?", ws)
	}

	var totalCount int64
	if err := baseQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	offset := params.Offset

	if limit <= 0 {
		limit = 25
	} else if limit > 100 {
		limit = 100
	}

	if offset < 0 {
		offset = 0
	}

	var modelConfigs []tables.TableModelConfig
	if err := baseQuery.
		Preload("Budget").
		Preload("RateLimit").
		Order("created_at ASC, id ASC").
		Offset(offset).
		Limit(limit).
		Find(&modelConfigs).Error; err != nil {
		return nil, 0, err
	}
	return modelConfigs, totalCount, nil
}

// GetModelConfig retrieves a specific model config from the database by model name and optional provider.
func (s *RDBConfigStore) GetModelConfig(ctx context.Context, modelName string, provider *string) (*tables.TableModelConfig, error) {
	var modelConfig tables.TableModelConfig
	query := s.db.WithContext(ctx).Where("model_name = ?", modelName)
	if provider != nil {
		query = query.Where("provider = ?", *provider)
	} else {
		query = query.Where("provider IS NULL")
	}
	if err := query.Preload("Budget").Preload("RateLimit").First(&modelConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &modelConfig, nil
}

// GetModelConfigByID retrieves a specific model config from the database by ID.
func (s *RDBConfigStore) GetModelConfigByID(ctx context.Context, id string) (*tables.TableModelConfig, error) {
	var modelConfig tables.TableModelConfig
	if err := s.db.WithContext(ctx).Preload("Budget").Preload("RateLimit").First(&modelConfig, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &modelConfig, nil
}

// CreateModelConfig creates a new model config in the database.
func (s *RDBConfigStore) CreateModelConfig(ctx context.Context, modelConfig *tables.TableModelConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	// Resolve effective workspace: explicit > context > tenant default.
	if modelConfig != nil && modelConfig.WorkspaceID == nil {
		if ws := s.resolveEffectiveWorkspaceID(ctx, ""); ws != "" {
			modelConfig.WorkspaceID = &ws
		}
	}
	if err := txDB.WithContext(ctx).Create(modelConfig).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateModelConfig updates a model config in the database.
func (s *RDBConfigStore) UpdateModelConfig(ctx context.Context, modelConfig *tables.TableModelConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	if err := txDB.WithContext(ctx).Save(modelConfig).Error; err != nil {
		return s.parseGormError(err)
	}
	return nil
}

// UpdateModelConfigs updates multiple model configs in the database.
func (s *RDBConfigStore) UpdateModelConfigs(ctx context.Context, modelConfigs []*tables.TableModelConfig, tx ...*gorm.DB) error {
	var txDB *gorm.DB
	if len(tx) > 0 {
		txDB = tx[0]
	} else {
		txDB = s.db
	}
	for _, mc := range modelConfigs {
		if err := txDB.WithContext(ctx).Save(mc).Error; err != nil {
			return s.parseGormError(err)
		}
	}
	return nil
}

// DeleteModelConfig deletes a model config from the database.
func (s *RDBConfigStore) DeleteModelConfig(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// First fetch the model config to get budget and rate limit IDs
		var modelConfig tables.TableModelConfig
		if err := tx.First(&modelConfig, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// Store the budget and rate limit IDs before deleting
		budgetID := modelConfig.BudgetID
		rateLimitID := modelConfig.RateLimitID
		// Delete the model config first
		if err := tx.Delete(&tables.TableModelConfig{}, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return s.parseGormError(err)
		}
		// Delete the budget if it exists
		if budgetID != nil {
			if err := tx.Delete(&tables.TableBudget{}, "id = ?", *budgetID).Error; err != nil {
				return err
			}
		}
		// Delete the rate limit if it exists
		if rateLimitID != nil {
			if err := tx.Delete(&tables.TableRateLimit{}, "id = ?", *rateLimitID).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// GetGovernanceConfig retrieves the governance configuration from the database.
func (s *RDBConfigStore) GetGovernanceConfig(ctx context.Context) (*GovernanceConfig, error) {
	var virtualKeys []tables.TableVirtualKey
	var teams []tables.TableTeam
	var customers []tables.TableCustomer
	var budgets []tables.TableBudget
	var rateLimits []tables.TableRateLimit
	var modelConfigs []tables.TableModelConfig
	var providers []tables.TableProvider
	var routingRules []tables.TableRoutingRule
	var governanceConfigs []tables.TableGovernanceConfig

	if err := s.db.WithContext(ctx).
		Preload("ProviderConfigs").
		Preload("ProviderConfigs.Keys", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, name, key_id, models_json, provider")
		}).
		Find(&virtualKeys).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Find(&teams).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Find(&customers).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Find(&budgets).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Find(&rateLimits).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Find(&modelConfigs).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Find(&providers).Error; err != nil {
		return nil, err
	}
	if err := s.loadRoutingRulesOrdered(ctx, &routingRules); err != nil {
		return nil, err
	}
	// Fetching governance config for username and password
	if err := s.db.WithContext(ctx).Find(&governanceConfigs).Error; err != nil {
		return nil, err
	}
	// Check if any config is present
	if len(virtualKeys) == 0 && len(teams) == 0 && len(customers) == 0 && len(budgets) == 0 && len(rateLimits) == 0 && len(modelConfigs) == 0 && len(providers) == 0 && len(governanceConfigs) == 0 && len(routingRules) == 0 {
		return nil, nil
	}
	var authConfig *AuthConfig
	if len(governanceConfigs) > 0 {
		// Checking if username and password is present
		var username *string
		var password *string
		var isEnabled bool
		disableAuthOnInference := true
		var hasDisableAuthOnInference bool
		for _, entry := range governanceConfigs {
			switch entry.Key {
			case tables.ConfigAdminUsernameKey:
				username = deepintshield.Ptr(entry.Value)
			case tables.ConfigAdminPasswordKey:
				password = deepintshield.Ptr(entry.Value)
			case tables.ConfigIsAuthEnabledKey:
				isEnabled = entry.Value == "true"
			case tables.ConfigDisableAuthOnInferenceKey:
				disableAuthOnInference = entry.Value == "true"
				hasDisableAuthOnInference = true
			}
		}
		if username != nil || password != nil || isEnabled || hasDisableAuthOnInference {
			adminUsername := ""
			adminPassword := ""
			if username != nil {
				adminUsername = *username
			}
			if password != nil {
				adminPassword = *password
			}
			authConfig = &AuthConfig{
				AdminUserName:          schemas.NewEnvVar(adminUsername),
				AdminPassword:          schemas.NewEnvVar(adminPassword),
				IsEnabled:              isEnabled,
				DisableAuthOnInference: disableAuthOnInference,
			}
		}
	}
	return &GovernanceConfig{
		VirtualKeys:  virtualKeys,
		Teams:        teams,
		Customers:    customers,
		Budgets:      budgets,
		RateLimits:   rateLimits,
		ModelConfigs: modelConfigs,
		Providers:    providers,
		RoutingRules: routingRules,
		AuthConfig:   authConfig,
	}, nil
}

// GetAuthConfig retrieves the auth configuration from the database.
func (s *RDBConfigStore) GetAuthConfig(ctx context.Context) (*AuthConfig, error) {
	var username *string
	var password *string
	var isEnabled bool
	disableAuthOnInference := true
	var hasDisableAuthOnInference bool
	if err := s.db.WithContext(ctx).First(&tables.TableGovernanceConfig{}, "key = ?", tables.ConfigAdminUsernameKey).Select("value").Scan(&username).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}
	if err := s.db.WithContext(ctx).First(&tables.TableGovernanceConfig{}, "key = ?", tables.ConfigAdminPasswordKey).Select("value").Scan(&password).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

	}
	if err := s.db.WithContext(ctx).First(&tables.TableGovernanceConfig{}, "key = ?", tables.ConfigIsAuthEnabledKey).Select("value").Scan(&isEnabled).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}
	if err := s.db.WithContext(ctx).First(&tables.TableGovernanceConfig{}, "key = ?", tables.ConfigDisableAuthOnInferenceKey).Select("value").Scan(&disableAuthOnInference).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	} else {
		hasDisableAuthOnInference = true
	}
	if username == nil && password == nil && !isEnabled && !hasDisableAuthOnInference {
		return nil, nil
	}
	adminUsername := ""
	adminPassword := ""
	if username != nil {
		adminUsername = *username
	}
	if password != nil {
		adminPassword = *password
	}
	return &AuthConfig{
		AdminUserName:          schemas.NewEnvVar(adminUsername),
		AdminPassword:          schemas.NewEnvVar(adminPassword),
		IsEnabled:              isEnabled,
		DisableAuthOnInference: disableAuthOnInference,
	}, nil
}

// UpdateAuthConfig updates the auth configuration in the database.
func (s *RDBConfigStore) UpdateAuthConfig(ctx context.Context, config *AuthConfig) error {
	adminUsername := ""
	adminPassword := ""
	if config.AdminUserName != nil {
		adminUsername = config.AdminUserName.GetValue()
	}
	if config.AdminPassword != nil {
		adminPassword = config.AdminPassword.GetValue()
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&tables.TableGovernanceConfig{
			Key:   tables.ConfigAdminUsernameKey,
			Value: adminUsername,
		}).Error; err != nil {
			return err
		}
		if err := tx.Save(&tables.TableGovernanceConfig{
			Key:   tables.ConfigAdminPasswordKey,
			Value: adminPassword,
		}).Error; err != nil {
			return err
		}
		if err := tx.Save(&tables.TableGovernanceConfig{
			Key:   tables.ConfigIsAuthEnabledKey,
			Value: fmt.Sprintf("%t", config.IsEnabled),
		}).Error; err != nil {
			return err
		}
		if err := tx.Save(&tables.TableGovernanceConfig{
			Key:   tables.ConfigDisableAuthOnInferenceKey,
			Value: fmt.Sprintf("%t", config.DisableAuthOnInference),
		}).Error; err != nil {
			return err
		}
		return nil
	})
}

func (s *RDBConfigStore) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&tables.TableAuthUser{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetSingleTenantID returns the only tenant_id configured in auth_users when the
// local stack has exactly one workspace. An empty string means there are zero or
// multiple tenants, so callers should not assume a default tenant.
func (s *RDBConfigStore) GetSingleTenantID(_ context.Context) (string, error) {
	type tenantRow struct {
		TenantID string
	}

	var tenants []tenantRow
	if err := s.db.WithContext(context.Background()).
		Model(&tables.TableAuthUser{}).
		Distinct("tenant_id").
		Where("tenant_id <> ''").
		Limit(2).
		Find(&tenants).Error; err != nil {
		return "", err
	}

	if len(tenants) != 1 {
		return "", nil
	}

	return strings.TrimSpace(tenants[0].TenantID), nil
}

func (s *RDBConfigStore) GetUserByID(ctx context.Context, id string) (*tables.TableAuthUser, error) {
	var user tables.TableAuthUser
	if err := s.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *RDBConfigStore) GetUserByEmail(ctx context.Context, email string) (*tables.TableAuthUser, error) {
	var user tables.TableAuthUser
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if err := s.db.WithContext(ctx).First(&user, "email = ?", normalizedEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *RDBConfigStore) GetUserByPendingEmail(ctx context.Context, email string) (*tables.TableAuthUser, error) {
	var user tables.TableAuthUser
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if err := s.db.WithContext(ctx).First(&user, "pending_email = ?", normalizedEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *RDBConfigStore) GetUserByGoogleSubject(ctx context.Context, subject string) (*tables.TableAuthUser, error) {
	var user tables.TableAuthUser
	if err := s.db.WithContext(ctx).First(&user, "google_subject = ?", subject).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *RDBConfigStore) GetUserByEntraIdentityKey(ctx context.Context, identityKey string) (*tables.TableAuthUser, error) {
	var user tables.TableAuthUser
	if err := s.db.WithContext(ctx).First(&user, "entra_identity_key = ?", strings.TrimSpace(identityKey)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *RDBConfigStore) GetUsersPaginated(ctx context.Context, params UsersQueryParams) ([]tables.TableAuthUser, int64, error) {
	query := s.db.WithContext(ctx).Model(&tables.TableAuthUser{})
	if search := strings.TrimSpace(params.Search); search != "" {
		pattern := "%" + strings.ToLower(search) + "%"
		query = query.Where(
			"LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(organization) LIKE ?",
			pattern, pattern, pattern, pattern,
		)
	}
	if customerID := strings.TrimSpace(params.CustomerID); customerID != "" {
		query = query.Where("customer_id = ?", customerID)
	}
	if connectionID := strings.TrimSpace(params.EntraConnectionID); connectionID != "" {
		query = query.Where("entra_connection_id = ?", connectionID)
	}

	var totalCount int64
	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	offset := params.Offset
	if limit <= 0 {
		limit = 50
	}

	var users []tables.TableAuthUser
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, totalCount, nil
}

// Organization CRUD

func (s *RDBConfigStore) CreateOrganization(ctx context.Context, org *tables.TableOrganization) error {
	return s.db.WithContext(ctx).Create(org).Error
}

func (s *RDBConfigStore) GetOrganizationByID(ctx context.Context, id string) (*tables.TableOrganization, error) {
	var org tables.TableOrganization
	if err := s.db.WithContext(ctx).First(&org, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (s *RDBConfigStore) GetOrganizationBySlug(ctx context.Context, slug string) (*tables.TableOrganization, error) {
	var org tables.TableOrganization
	if err := s.db.WithContext(ctx).First(&org, "slug = ?", slug).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (s *RDBConfigStore) GetOrganizationsByOwnerID(ctx context.Context, ownerID string) ([]tables.TableOrganization, error) {
	var orgs []tables.TableOrganization
	if err := s.db.WithContext(ctx).Where("owner_id = ?", ownerID).Find(&orgs).Error; err != nil {
		return nil, err
	}
	return orgs, nil
}

func (s *RDBConfigStore) UpdateOrganization(ctx context.Context, org *tables.TableOrganization) error {
	return s.db.WithContext(ctx).Save(org).Error
}

func (s *RDBConfigStore) DeleteOrganization(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Delete(&tables.TableWorkspaceMembership{}, "org_id = ?", id).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Delete(&tables.TableWorkspace{}, "org_id = ?", id).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Delete(&tables.TableOrgMembership{}, "org_id = ?", id).Error; err != nil {
			return err
		}
		return tx.WithContext(ctx).Delete(&tables.TableOrganization{}, "id = ?", id).Error
	})
}

func (s *RDBConfigStore) ListOrganizations(ctx context.Context) ([]tables.TableOrganization, error) {
	var orgs []tables.TableOrganization
	if err := s.db.WithContext(ctx).Order("created_at ASC").Find(&orgs).Error; err != nil {
		return nil, err
	}
	return orgs, nil
}

// ─── Governance Org (Phase 19 - top of the 3-tier hierarchy) ────────

func (s *RDBConfigStore) CreateGovernanceOrg(ctx context.Context, org *tables.TableGovernanceOrg) error {
	return s.db.WithContext(ctx).Create(org).Error
}

func (s *RDBConfigStore) GetGovernanceOrgByID(ctx context.Context, id string) (*tables.TableGovernanceOrg, error) {
	var org tables.TableGovernanceOrg
	if err := s.db.WithContext(ctx).First(&org, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (s *RDBConfigStore) GetGovernanceOrgBySlug(ctx context.Context, slug string) (*tables.TableGovernanceOrg, error) {
	var org tables.TableGovernanceOrg
	if err := s.db.WithContext(ctx).First(&org, "slug = ?", strings.TrimSpace(slug)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (s *RDBConfigStore) ListGovernanceOrgsByMember(ctx context.Context, userID string) ([]tables.TableGovernanceOrg, error) {
	var orgs []tables.TableGovernanceOrg
	if err := s.db.WithContext(ctx).
		Joins("JOIN governance_org_memberships m ON m.organization_id = governance_orgs.id").
		Where("m.user_id = ?", userID).
		Order("governance_orgs.created_at ASC").
		Find(&orgs).Error; err != nil {
		return nil, err
	}
	return orgs, nil
}

func (s *RDBConfigStore) ListTenantsByGovernanceOrg(ctx context.Context, orgID string) ([]tables.TableOrganization, error) {
	var tenants []tables.TableOrganization
	if err := s.db.WithContext(ctx).
		Where("organization_id = ?", orgID).
		Order("created_at ASC").
		Find(&tenants).Error; err != nil {
		return nil, err
	}
	return tenants, nil
}

func (s *RDBConfigStore) CreateGovernanceOrgMembership(ctx context.Context, m *tables.TableGovernanceOrgMembership) error {
	return s.db.WithContext(ctx).Create(m).Error
}

func (s *RDBConfigStore) GetGovernanceOrgMembership(ctx context.Context, orgID, userID string) (*tables.TableGovernanceOrgMembership, error) {
	var m tables.TableGovernanceOrgMembership
	if err := s.db.WithContext(ctx).
		Where("organization_id = ? AND user_id = ?", orgID, userID).
		First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// ListGovernanceOrgMemberships returns every membership row for an org.
// Used by the "Make super admin" flow to enumerate owners (last-owner
// guard) and surface each member's org-level role. Keyed on the org
// UUID - never an email.
func (s *RDBConfigStore) ListGovernanceOrgMemberships(ctx context.Context, orgID string) ([]tables.TableGovernanceOrgMembership, error) {
	var rows []tables.TableGovernanceOrgMembership
	if err := s.db.WithContext(ctx).
		Where("organization_id = ?", orgID).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// UpdateGovernanceOrgMembershipRole changes a user's org-level role
// (owner/admin/member) in place. Identity is the (org UUID, user UUID)
// pair, so ownership transfer survives email changes / offboarding.
func (s *RDBConfigStore) UpdateGovernanceOrgMembershipRole(ctx context.Context, orgID, userID, role string) error {
	return s.db.WithContext(ctx).
		Model(&tables.TableGovernanceOrgMembership{}).
		Where("organization_id = ? AND user_id = ?", orgID, userID).
		Updates(map[string]any{"role": role, "updated_at": time.Now().UTC()}).Error
}

// Workspace CRUD

func (s *RDBConfigStore) CreateWorkspace(ctx context.Context, ws *tables.TableWorkspace) error {
	return s.db.WithContext(ctx).Create(ws).Error
}

func (s *RDBConfigStore) GetWorkspaceByID(ctx context.Context, id string) (*tables.TableWorkspace, error) {
	var ws tables.TableWorkspace
	if err := s.db.WithContext(ctx).First(&ws, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &ws, nil
}

func (s *RDBConfigStore) GetWorkspaceBySlug(ctx context.Context, orgID, slug string) (*tables.TableWorkspace, error) {
	var ws tables.TableWorkspace
	if err := s.db.WithContext(ctx).Where("org_id = ? AND slug = ?", orgID, slug).First(&ws).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &ws, nil
}

func (s *RDBConfigStore) GetDefaultWorkspaceForOrg(ctx context.Context, orgID string) (*tables.TableWorkspace, error) {
	var ws tables.TableWorkspace
	if err := s.db.WithContext(ctx).Where("org_id = ? AND is_default = ?", orgID, true).First(&ws).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &ws, nil
}

// resolveEffectiveWorkspaceID picks a non-empty workspace ID for new rows
// when the caller hasn't pinned one. Priority:
//  1. explicit value passed in (e.g. from request body)
//  2. active workspace stamped on the request context (sidebar switcher)
//  3. tenant's Default workspace
//
// Returns "" only when the request has no tenant context AND the caller
// supplied no value - in which case callers should reject the write.
//
// This is the single source of truth that enforces "every workspace-aware
// resource lives in exactly one workspace, never NULL" across the
// codebase. The fallback to the tenant's Default workspace replaces the
// earlier semantics where a NULL workspace_id meant "tenant-wide".
func (s *RDBConfigStore) resolveEffectiveWorkspaceID(ctx context.Context, explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		return ws
	}
	tenantID := strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
	if tenantID == "" {
		return ""
	}
	def, err := s.GetDefaultWorkspaceForOrg(ctx, tenantID)
	if err != nil || def == nil {
		return ""
	}
	return def.ID
}

func (s *RDBConfigStore) ListWorkspacesByOrg(ctx context.Context, orgID string) ([]tables.TableWorkspace, error) {
	var out []tables.TableWorkspace
	if err := s.db.WithContext(ctx).
		Where("org_id = ?", orgID).
		Order("is_default DESC, created_at ASC").
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) ListWorkspacesByUser(ctx context.Context, userID string) ([]tables.TableWorkspace, error) {
	var out []tables.TableWorkspace
	if err := s.db.WithContext(ctx).
		Joins("JOIN workspace_memberships ON workspace_memberships.workspace_id = workspaces.id").
		Where("workspace_memberships.user_id = ?", userID).
		Order("workspaces.org_id ASC, workspaces.is_default DESC, workspaces.created_at ASC").
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) UpdateWorkspace(ctx context.Context, ws *tables.TableWorkspace) error {
	return s.db.WithContext(ctx).Save(ws).Error
}

func (s *RDBConfigStore) DeleteWorkspace(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Delete(&tables.TableWorkspaceMembership{}, "workspace_id = ?", id).Error; err != nil {
			return err
		}
		return tx.WithContext(ctx).Delete(&tables.TableWorkspace{}, "id = ?", id).Error
	})
}

// Org & Workspace memberships

func (s *RDBConfigStore) CreateOrgMembership(ctx context.Context, m *tables.TableOrgMembership) error {
	return s.db.WithContext(ctx).Create(m).Error
}

func (s *RDBConfigStore) GetOrgMembership(ctx context.Context, orgID, userID string) (*tables.TableOrgMembership, error) {
	var m tables.TableOrgMembership
	if err := s.db.WithContext(ctx).Where("org_id = ? AND user_id = ?", orgID, userID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

func (s *RDBConfigStore) ListOrgMembershipsByOrg(ctx context.Context, orgID string) ([]tables.TableOrgMembership, error) {
	var out []tables.TableOrgMembership
	if err := s.db.WithContext(ctx).Where("org_id = ?", orgID).Order("created_at ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) ListOrgMembershipsByUser(ctx context.Context, userID string) ([]tables.TableOrgMembership, error) {
	var out []tables.TableOrgMembership
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) UpdateOrgMembershipRole(ctx context.Context, orgID, userID, role string) error {
	return s.db.WithContext(ctx).Model(&tables.TableOrgMembership{}).
		Where("org_id = ? AND user_id = ?", orgID, userID).
		Update("role", role).Error
}

func (s *RDBConfigStore) DeleteOrgMembership(ctx context.Context, orgID, userID string) error {
	return s.db.WithContext(ctx).Where("org_id = ? AND user_id = ?", orgID, userID).Delete(&tables.TableOrgMembership{}).Error
}

func (s *RDBConfigStore) CreateWorkspaceMembership(ctx context.Context, m *tables.TableWorkspaceMembership) error {
	return s.db.WithContext(ctx).Create(m).Error
}

func (s *RDBConfigStore) GetWorkspaceMembership(ctx context.Context, workspaceID, userID string) (*tables.TableWorkspaceMembership, error) {
	var m tables.TableWorkspaceMembership
	if err := s.db.WithContext(ctx).Where("workspace_id = ? AND user_id = ?", workspaceID, userID).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

func (s *RDBConfigStore) ListWorkspaceMembershipsByWorkspace(ctx context.Context, workspaceID string) ([]tables.TableWorkspaceMembership, error) {
	var out []tables.TableWorkspaceMembership
	if err := s.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).Order("created_at ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) ListWorkspaceMembershipsByUser(ctx context.Context, userID string) ([]tables.TableWorkspaceMembership, error) {
	var out []tables.TableWorkspaceMembership
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) UpdateWorkspaceMembershipRole(ctx context.Context, workspaceID, userID, role string) error {
	return s.db.WithContext(ctx).Model(&tables.TableWorkspaceMembership{}).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Update("role", role).Error
}

func (s *RDBConfigStore) DeleteWorkspaceMembership(ctx context.Context, workspaceID, userID string) error {
	return s.db.WithContext(ctx).Where("workspace_id = ? AND user_id = ?", workspaceID, userID).Delete(&tables.TableWorkspaceMembership{}).Error
}

// Workspace API keys

func (s *RDBConfigStore) CreateWorkspaceAPIKey(ctx context.Context, key *tables.TableWorkspaceAPIKey) error {
	return s.db.WithContext(ctx).Create(key).Error
}

func (s *RDBConfigStore) GetWorkspaceAPIKeyByHash(ctx context.Context, keyHash string) (*tables.TableWorkspaceAPIKey, error) {
	var k tables.TableWorkspaceAPIKey
	if err := s.db.WithContext(ctx).Where("key_hash = ? AND revoked_at IS NULL", keyHash).First(&k).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &k, nil
}

func (s *RDBConfigStore) GetWorkspaceAPIKeyByID(ctx context.Context, id string) (*tables.TableWorkspaceAPIKey, error) {
	var k tables.TableWorkspaceAPIKey
	if err := s.db.WithContext(ctx).First(&k, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &k, nil
}

func (s *RDBConfigStore) ListWorkspaceAPIKeys(ctx context.Context, workspaceID string) ([]tables.TableWorkspaceAPIKey, error) {
	var out []tables.TableWorkspaceAPIKey
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("revoked_at IS NULL DESC, created_at DESC").
		Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (s *RDBConfigStore) RevokeWorkspaceAPIKey(ctx context.Context, id string) error {
	now := time.Now().UTC()
	return s.db.WithContext(ctx).Model(&tables.TableWorkspaceAPIKey{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", now).Error
}

func (s *RDBConfigStore) TouchWorkspaceAPIKeyLastUsed(ctx context.Context, id string, at time.Time) error {
	return s.db.WithContext(ctx).Model(&tables.TableWorkspaceAPIKey{}).
		Where("id = ?", id).
		Update("last_used_at", at).Error
}

// Auth User CRUD

func (s *RDBConfigStore) CreateUser(ctx context.Context, user *tables.TableAuthUser) error {
	return s.db.WithContext(ctx).Create(user).Error
}

func (s *RDBConfigStore) UpdateUser(ctx context.Context, user *tables.TableAuthUser) error {
	return s.db.WithContext(ctx).Save(user).Error
}

func (s *RDBConfigStore) DeleteUser(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Delete(&tables.TableTeamMember{}, "user_id = ?", userID).Error; err != nil {
			return err
		}
		return tx.WithContext(ctx).Delete(&tables.TableAuthUser{}, "id = ?", userID).Error
	})
}

func (s *RDBConfigStore) CreateEmailVerificationToken(ctx context.Context, token *tables.TableEmailVerificationToken) error {
	return s.db.WithContext(ctx).Create(token).Error
}

func (s *RDBConfigStore) GetEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*tables.TableEmailVerificationToken, error) {
	var token tables.TableEmailVerificationToken
	if err := s.db.WithContext(ctx).First(&token, "token_hash = ?", tokenHash).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

func (s *RDBConfigStore) MarkEmailVerificationTokenUsed(ctx context.Context, id string, usedAt time.Time) error {
	return s.db.WithContext(ctx).Model(&tables.TableEmailVerificationToken{}).Where("id = ?", id).Update("used_at", usedAt).Error
}

func (s *RDBConfigStore) DeleteEmailVerificationTokensForUser(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Delete(&tables.TableEmailVerificationToken{}, "user_id = ?", userID).Error
}

func (s *RDBConfigStore) GetUserInvitationByID(ctx context.Context, id string) (*tables.TableUserInvitation, error) {
	var invitation tables.TableUserInvitation
	if err := s.db.WithContext(ctx).First(&invitation, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &invitation, nil
}

func (s *RDBConfigStore) GetUserInvitationByEmail(ctx context.Context, email string) (*tables.TableUserInvitation, error) {
	var invitation tables.TableUserInvitation
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if err := s.db.WithContext(ctx).
		Order("created_at DESC").
		First(&invitation, "email = ?", normalizedEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &invitation, nil
}

func (s *RDBConfigStore) GetUserInvitationByHash(ctx context.Context, tokenHash string) (*tables.TableUserInvitation, error) {
	var invitation tables.TableUserInvitation
	if err := s.db.WithContext(ctx).First(&invitation, "token_hash = ?", tokenHash).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &invitation, nil
}

func (s *RDBConfigStore) GetUserInvitations(ctx context.Context, params UsersQueryParams) ([]tables.TableUserInvitation, int64, error) {
	query := s.db.WithContext(ctx).Model(&tables.TableUserInvitation{})
	if search := strings.TrimSpace(params.Search); search != "" {
		pattern := "%" + strings.ToLower(search) + "%"
		query = query.Where("LOWER(email) LIKE ?", pattern)
	}

	var totalCount int64
	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	limit := params.Limit
	offset := params.Offset
	if limit <= 0 {
		limit = 50
	}

	var invitations []tables.TableUserInvitation
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&invitations).Error; err != nil {
		return nil, 0, err
	}
	return invitations, totalCount, nil
}

func (s *RDBConfigStore) CreateUserInvitation(ctx context.Context, invitation *tables.TableUserInvitation) error {
	return s.db.WithContext(ctx).Create(invitation).Error
}

func (s *RDBConfigStore) UpdateUserInvitation(ctx context.Context, invitation *tables.TableUserInvitation) error {
	return s.db.WithContext(ctx).Save(invitation).Error
}

func (s *RDBConfigStore) DeleteUserInvitation(ctx context.Context, invitationID string) error {
	return s.db.WithContext(ctx).Delete(&tables.TableUserInvitation{}, "id = ?", invitationID).Error
}

// CreateLegalConsent appends a row to the legal_consents audit table. Rows
// are immutable - no caller should ever update or delete them.
func (s *RDBConfigStore) CreateLegalConsent(ctx context.Context, consent *tables.TableLegalConsent) error {
	if consent == nil {
		return fmt.Errorf("legal consent payload is nil")
	}
	if consent.CreatedAt.IsZero() {
		consent.CreatedAt = time.Now().UTC()
	}
	if consent.AcceptedAt.IsZero() {
		consent.AcceptedAt = consent.CreatedAt
	}
	return s.db.WithContext(ctx).Create(consent).Error
}

// GetLegalConsentsForUser returns every consent row recorded for one user,
// most-recent first. Used by the user's own "what did I accept" view.
func (s *RDBConfigStore) GetLegalConsentsForUser(ctx context.Context, userID string) ([]tables.TableLegalConsent, error) {
	var rows []tables.TableLegalConsent
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("accepted_at DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ListLegalConsents returns paginated audit rows with optional filters.
// Used by the admin audit endpoint.
func (s *RDBConfigStore) ListLegalConsents(ctx context.Context, params LegalConsentQuery) ([]tables.TableLegalConsent, int64, error) {
	q := s.db.WithContext(ctx).Model(&tables.TableLegalConsent{})
	if params.UserID != "" {
		q = q.Where("user_id = ?", params.UserID)
	}
	if params.Email != "" {
		q = q.Where("email_at_consent = ?", params.Email)
	}
	if params.DocumentType != "" {
		q = q.Where("document_type = ?", params.DocumentType)
	}
	if params.DocumentVersion != "" {
		q = q.Where("document_version = ?", params.DocumentVersion)
	}
	if params.ConsentMethod != "" {
		q = q.Where("consent_method = ?", params.ConsentMethod)
	}
	if params.From != nil {
		q = q.Where("accepted_at >= ?", *params.From)
	}
	if params.To != nil {
		q = q.Where("accepted_at <= ?", *params.To)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	q = q.Order("accepted_at DESC")
	if params.Limit > 0 {
		q = q.Limit(params.Limit)
	}
	if params.Offset > 0 {
		q = q.Offset(params.Offset)
	}
	var rows []tables.TableLegalConsent
	if err := q.Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// GetProxyConfig retrieves the proxy configuration from the database.
func (s *RDBConfigStore) GetProxyConfig(ctx context.Context) (*tables.GlobalProxyConfig, error) {
	var configEntry tables.TableGovernanceConfig
	if err := s.db.WithContext(ctx).First(&configEntry, "key = ?", tables.ConfigProxyKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if configEntry.Value == "" {
		return nil, nil
	}
	var proxyConfig tables.GlobalProxyConfig
	if err := json.Unmarshal([]byte(configEntry.Value), &proxyConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy config: %w", err)
	}
	// Decrypt the password if it's not empty
	if proxyConfig.Password != "" {
		decryptedPassword, err := encrypt.Decrypt(proxyConfig.Password)
		if err != nil {
			// If decryption fails due to uninitialized key, the password might be stored in plaintext
			// (from before encryption was enabled), so we return it as-is
			if !errors.Is(err, encrypt.ErrEncryptionKeyNotInitialized) {
				return nil, fmt.Errorf("failed to decrypt proxy password: %w", err)
			}
		} else {
			proxyConfig.Password = decryptedPassword
		}
	}
	return &proxyConfig, nil
}

// UpdateProxyConfig updates the proxy configuration in the database.
func (s *RDBConfigStore) UpdateProxyConfig(ctx context.Context, config *tables.GlobalProxyConfig) error {
	// Create a copy to avoid modifying the original config
	configCopy := *config

	// Encrypt the password if it's not empty
	if configCopy.Password != "" {
		encryptedPassword, err := encrypt.Encrypt(configCopy.Password)
		if err != nil {
			return fmt.Errorf("failed to encrypt proxy password: %w", err)
		}
		configCopy.Password = encryptedPassword
	}

	configJSON, err := json.Marshal(&configCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal proxy config: %w", err)
	}
	return s.db.WithContext(ctx).Save(&tables.TableGovernanceConfig{
		Key:   tables.ConfigProxyKey,
		Value: string(configJSON),
	}).Error
}

// GetRestartRequiredConfig retrieves the restart required configuration from the database.
func (s *RDBConfigStore) GetRestartRequiredConfig(ctx context.Context) (*tables.RestartRequiredConfig, error) {
	var configEntry tables.TableGovernanceConfig
	if err := s.db.WithContext(ctx).First(&configEntry, "key = ?", tables.ConfigRestartRequiredKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if configEntry.Value == "" {
		return nil, nil
	}
	var restartConfig tables.RestartRequiredConfig
	if err := json.Unmarshal([]byte(configEntry.Value), &restartConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal restart required config: %w", err)
	}
	return &restartConfig, nil
}

// SetRestartRequiredConfig sets the restart required configuration in the database.
func (s *RDBConfigStore) SetRestartRequiredConfig(ctx context.Context, config *tables.RestartRequiredConfig) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal restart required config: %w", err)
	}
	return s.db.WithContext(ctx).Save(&tables.TableGovernanceConfig{
		Key:   tables.ConfigRestartRequiredKey,
		Value: string(configJSON),
	}).Error
}

// ClearRestartRequiredConfig clears the restart required configuration in the database.
func (s *RDBConfigStore) ClearRestartRequiredConfig(ctx context.Context) error {
	return s.db.WithContext(ctx).Save(&tables.TableGovernanceConfig{
		Key:   tables.ConfigRestartRequiredKey,
		Value: `{"required":false,"reason":""}`,
	}).Error
}

// GetSession retrieves a session from the database.
func (s *RDBConfigStore) GetSession(ctx context.Context, token string) (*tables.SessionsTable, error) {
	var session tables.SessionsTable
	tokenHash := encrypt.HashSHA256(token)
	err := s.db.WithContext(ctx).First(&session, "token_hash = ?", tokenHash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Fall back to plaintext lookup for backward compatibility
			if err := s.db.WithContext(ctx).First(&session, "token = ?", token).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, nil
				}
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return &session, nil
}

// CreateSession creates a new session in the database.
func (s *RDBConfigStore) CreateSession(ctx context.Context, session *tables.SessionsTable) error {
	return s.db.WithContext(ctx).Create(session).Error
}

func (s *RDBConfigStore) UpdateSessionsEmailByUserID(ctx context.Context, userID, email string) error {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	return s.db.WithContext(ctx).Model(&tables.SessionsTable{}).Where("user_id = ?", userID).Update("user_email", normalizedEmail).Error
}

func (s *RDBConfigStore) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Delete(&tables.SessionsTable{}, "user_id = ?", userID).Error
}

// DeleteSession deletes a session from the database.
func (s *RDBConfigStore) DeleteSession(ctx context.Context, token string) error {
	tokenHash := encrypt.HashSHA256(token)
	result := s.db.WithContext(ctx).Delete(&tables.SessionsTable{}, "token_hash = ?", tokenHash)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		// Fall back to plaintext lookup for backward compatibility
		return s.db.WithContext(ctx).Delete(&tables.SessionsTable{}, "token = ?", token).Error
	}
	return nil
}

// FlushSessions flushes all sessions for the current tenant from the database.
func (s *RDBConfigStore) FlushSessions(ctx context.Context) error {
	return s.db.WithContext(ctx).Where("1=1").Delete(&tables.SessionsTable{}).Error
}

// ExecuteTransaction executes a transaction.
func (s *RDBConfigStore) ExecuteTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return s.db.WithContext(ctx).Transaction(fn)
}

// RetryOnNotFound retries a function up to 3 times with 1-second delays if it returns ErrNotFound
func (s *RDBConfigStore) RetryOnNotFound(ctx context.Context, fn func(ctx context.Context) (any, error), maxRetries int, retryDelay time.Duration) (any, error) {
	var lastErr error
	for attempt := range maxRetries {
		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		lastErr = err

		// Don't wait after the last attempt
		if attempt < maxRetries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
				// Continue to next retry
			}
		}
	}
	return nil, lastErr
}

// doesTableExist checks if a table exists in the database.
func (s *RDBConfigStore) doesTableExist(ctx context.Context, tableName string) bool {
	return s.db.WithContext(ctx).Migrator().HasTable(tableName)
}

// removeNullKeys removes null keys from the database.
func (s *RDBConfigStore) removeNullKeys(ctx context.Context) error {
	return s.db.WithContext(ctx).Exec("DELETE FROM config_keys WHERE key_id IS NULL OR value IS NULL").Error
}

// removeDuplicateKeysAndNullKeys removes duplicate keys based on key_id and value combination
// Keeps the record with the smallest ID (oldest record) and deletes duplicates
func (s *RDBConfigStore) removeDuplicateKeysAndNullKeys(ctx context.Context) error {
	s.logger.Debug("removing duplicate keys and null keys from the database")
	// Check if the config_keys table exists first
	if !s.doesTableExist(ctx, "config_keys") {
		return nil
	}
	s.logger.Debug("removing null keys from the database")
	// First, remove null keys
	if err := s.removeNullKeys(ctx); err != nil {
		return fmt.Errorf("failed to remove null keys: %w", err)
	}
	s.logger.Debug("deleting duplicate keys from the database")
	// Find and delete duplicate keys, keeping only the one with the smallest ID
	// This query deletes all records except the one with the minimum ID for each (key_id, value) pair
	result := s.db.WithContext(ctx).Exec(`
		DELETE FROM config_keys
		WHERE id NOT IN (
			SELECT MIN(id)
			FROM config_keys
			GROUP BY key_id, value
		)
	`)

	if result.Error != nil {
		return fmt.Errorf("failed to remove duplicate keys: %w", result.Error)
	}
	s.logger.Debug("migration complete")
	return nil
}

// RunMigration runs a migration.
func (s *RDBConfigStore) RunMigration(ctx context.Context, migration *migrator.Migration) error {
	if migration == nil {
		return fmt.Errorf("migration cannot be nil")
	}
	m := migrator.New(s.db, migrator.DefaultOptions, []*migrator.Migration{migration})
	return m.Migrate()
}

// Close closes the SQLite config store.
func (s *RDBConfigStore) Close(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// TryAcquireLock attempts to insert a lock row. Returns true if the lock was acquired.
// Uses INSERT ... ON CONFLICT DO NOTHING for atomic lock acquisition.
func (s *RDBConfigStore) TryAcquireLock(ctx context.Context, lock *tables.TableDistributedLock) (bool, error) {
	// Set CreatedAt if not already set
	if lock.CreatedAt.IsZero() {
		lock.CreatedAt = time.Now().UTC()
	}

	// Use GORM clause-based insert for dialect-appropriate SQL
	result := s.db.WithContext(ctx).Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "lock_key"}},
			DoNothing: true,
		},
	).Create(lock)

	if result.Error != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", result.Error)
	}

	// If RowsAffected is 1, the lock was acquired
	return result.RowsAffected == 1, nil
}

// GetLock retrieves a lock by its key. Returns nil if the lock doesn't exist.
func (s *RDBConfigStore) GetLock(ctx context.Context, lockKey string) (*tables.TableDistributedLock, error) {
	var lock tables.TableDistributedLock
	result := s.db.WithContext(ctx).Where("lock_key = ?", lockKey).First(&lock)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get lock: %w", result.Error)
	}

	return &lock, nil
}

// UpdateLockExpiry updates the expiration time for an existing lock.
// Only succeeds if the holder ID matches the current lock holder.
func (s *RDBConfigStore) UpdateLockExpiry(ctx context.Context, lockKey, holderID string, expiresAt time.Time) error {
	result := s.db.WithContext(ctx).Model(&tables.TableDistributedLock{}).
		Where("lock_key = ? AND holder_id = ? AND expires_at > ?", lockKey, holderID, time.Now().UTC()).
		Update("expires_at", expiresAt)

	if result.Error != nil {
		return fmt.Errorf("failed to update lock expiry: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrLockNotHeld
	}

	return nil
}

// ReleaseLock deletes a lock if the holder ID matches.
// Returns true if the lock was released, false if it wasn't held by the given holder.
func (s *RDBConfigStore) ReleaseLock(ctx context.Context, lockKey, holderID string) (bool, error) {
	result := s.db.WithContext(ctx).
		Where("lock_key = ? AND holder_id = ?", lockKey, holderID).
		Delete(&tables.TableDistributedLock{})

	if result.Error != nil {
		return false, fmt.Errorf("failed to release lock: %w", result.Error)
	}

	return result.RowsAffected > 0, nil
}

// CleanupExpiredLocks removes all locks that have expired.
// Returns the number of locks cleaned up.
func (s *RDBConfigStore) CleanupExpiredLocks(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).
		Where("expires_at < ?", time.Now().UTC()).
		Delete(&tables.TableDistributedLock{})

	if result.Error != nil {
		return 0, fmt.Errorf("failed to cleanup expired locks: %w", result.Error)
	}

	return result.RowsAffected, nil
}

// CleanupExpiredLockByKey atomically deletes a specific lock only if it has expired.
// Returns true if an expired lock was deleted, false if the lock doesn't exist or hasn't expired.
func (s *RDBConfigStore) CleanupExpiredLockByKey(ctx context.Context, lockKey string) (bool, error) {
	result := s.db.WithContext(ctx).
		Where("lock_key = ? AND expires_at < ?", lockKey, time.Now().UTC()).
		Delete(&tables.TableDistributedLock{})

	if result.Error != nil {
		return false, fmt.Errorf("failed to cleanup expired lock: %w", result.Error)
	}

	return result.RowsAffected > 0, nil
}

// ==================== OAuth Methods ====================

// GetOauthConfigByID retrieves an OAuth config by its ID
func (s *RDBConfigStore) GetOauthConfigByID(ctx context.Context, id string) (*tables.TableOauthConfig, error) {
	var config tables.TableOauthConfig
	result := s.db.WithContext(ctx).Where("id = ?", id).First(&config)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get oauth config: %w", result.Error)
	}
	return &config, nil
}

// GetOauthConfigByState retrieves an OAuth config by its state token
// State is unique per OAuth flow (used for CSRF protection on callback)
func (s *RDBConfigStore) GetOauthConfigByState(ctx context.Context, state string) (*tables.TableOauthConfig, error) {
	var config tables.TableOauthConfig
	result := s.db.WithContext(ctx).Where("state = ?", state).First(&config)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get oauth config by state: %w", result.Error)
	}
	return &config, nil
}

// GetOauthTokenByID retrieves an OAuth token by its ID
func (s *RDBConfigStore) GetOauthTokenByID(ctx context.Context, id string) (*tables.TableOauthToken, error) {
	var token tables.TableOauthToken
	result := s.db.WithContext(ctx).Where("id = ?", id).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get oauth token: %w", result.Error)
	}
	return &token, nil
}

// CreateOauthConfig creates a new OAuth config
func (s *RDBConfigStore) CreateOauthConfig(ctx context.Context, config *tables.TableOauthConfig) error {
	result := s.db.WithContext(ctx).Create(config)
	if result.Error != nil {
		return fmt.Errorf("failed to create oauth config: %w", result.Error)
	}
	return nil
}

// CreateOauthToken creates a new OAuth token
func (s *RDBConfigStore) CreateOauthToken(ctx context.Context, token *tables.TableOauthToken) error {
	result := s.db.WithContext(ctx).Create(token)
	if result.Error != nil {
		return fmt.Errorf("failed to create oauth token: %w", result.Error)
	}
	return nil
}

// UpdateOauthConfig updates an existing OAuth config
func (s *RDBConfigStore) UpdateOauthConfig(ctx context.Context, config *tables.TableOauthConfig) error {
	result := s.db.WithContext(ctx).Save(config)
	if result.Error != nil {
		return fmt.Errorf("failed to update oauth config: %w", result.Error)
	}
	return nil
}

// UpdateOauthToken updates an existing OAuth token
func (s *RDBConfigStore) UpdateOauthToken(ctx context.Context, token *tables.TableOauthToken) error {
	result := s.db.WithContext(ctx).Save(token)
	if result.Error != nil {
		return fmt.Errorf("failed to update oauth token: %w", result.Error)
	}
	return nil
}

// DeleteOauthToken deletes an OAuth token by its ID
func (s *RDBConfigStore) DeleteOauthToken(ctx context.Context, id string) error {
	result := s.db.WithContext(ctx).Where("id = ?", id).Delete(&tables.TableOauthToken{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete oauth token: %w", result.Error)
	}
	return nil
}

// GetExpiringOauthTokens retrieves tokens that are expiring before the given time
func (s *RDBConfigStore) GetExpiringOauthTokens(ctx context.Context, before time.Time) ([]*tables.TableOauthToken, error) {
	var tokens []*tables.TableOauthToken
	result := s.db.WithContext(ctx).
		Where("expires_at < ?", before).
		Find(&tokens)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get expiring tokens: %w", result.Error)
	}
	return tokens, nil
}

// GetOauthConfigByTokenID retrieves an OAuth config that references a specific token
func (s *RDBConfigStore) GetOauthConfigByTokenID(ctx context.Context, tokenID string) (*tables.TableOauthConfig, error) {
	var config tables.TableOauthConfig
	result := s.db.WithContext(ctx).Where("token_id = ?", tokenID).First(&config)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get oauth config by token id: %w", result.Error)
	}
	return &config, nil
}
