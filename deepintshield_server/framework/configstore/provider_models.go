package configstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"gorm.io/gorm"
)

// ReplaceProviderModels replaces the persisted model rows for a provider.
// This is used to keep tenant-scoped model lists database-backed instead of relying on shared memory.
func (s *RDBConfigStore) ReplaceProviderModels(ctx context.Context, provider schemas.ModelProvider, modelNames []string) error {
	var dbProvider tables.TableProvider
	if err := s.db.WithContext(ctx).Where("name = ?", string(provider)).First(&dbProvider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.replaceProviderModelsForRow(ctx, tx, &dbProvider, modelNames)
	})
}

// BackfillProviderModelsFromKeys seeds persisted provider models from explicit key-level model restrictions
// when no provider model rows exist yet. This keeps existing tenants isolated after the move away from
// shared in-memory model catalogs.
func (s *RDBConfigStore) BackfillProviderModelsFromKeys(ctx context.Context) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var providers []tables.TableProvider
		if err := tx.WithContext(ctx).Preload("Keys").Find(&providers).Error; err != nil {
			return err
		}

		for i := range providers {
			var existingCount int64
			if err := tx.WithContext(ctx).Model(&tables.TableModel{}).Where("provider_id = ?", providers[i].ID).Count(&existingCount).Error; err != nil {
				return err
			}
			if existingCount > 0 {
				continue
			}

			modelNames := configuredModelNamesFromTableKeys(providers[i].Keys)
			if len(modelNames) == 0 {
				continue
			}

			if err := s.replaceProviderModelsForRow(ctx, tx, &providers[i], modelNames); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *RDBConfigStore) replaceProviderModelsForRow(ctx context.Context, tx *gorm.DB, provider *tables.TableProvider, modelNames []string) error {
	if provider == nil {
		return fmt.Errorf("provider row is required")
	}

	normalizedModels := normalizeProviderModelNames(modelNames)

	var existingModels []tables.TableModel
	if err := tx.WithContext(ctx).Where("provider_id = ?", provider.ID).Find(&existingModels).Error; err != nil {
		return err
	}

	existingByName := make(map[string]tables.TableModel, len(existingModels))
	for _, model := range existingModels {
		existingByName[model.Name] = model
	}

	desired := make(map[string]struct{}, len(normalizedModels))
	for _, modelName := range normalizedModels {
		desired[modelName] = struct{}{}
		if _, exists := existingByName[modelName]; exists {
			continue
		}
		if err := tx.WithContext(ctx).Create(&tables.TableModel{
			ID:         providerModelID(provider.ID, modelName),
			ProviderID: provider.ID,
			Name:       modelName,
		}).Error; err != nil {
			return err
		}
	}

	for _, existing := range existingModels {
		if _, keep := desired[existing.Name]; keep {
			continue
		}
		if err := tx.WithContext(ctx).Delete(&existing).Error; err != nil {
			return err
		}
	}

	return nil
}

func normalizeProviderModelNames(modelNames []string) []string {
	seen := make(map[string]struct{}, len(modelNames))
	normalized := make([]string, 0, len(modelNames))
	for _, raw := range modelNames {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	sort.Strings(normalized)
	return normalized
}

func configuredModelNamesFromTableKeys(keys []tables.TableKey) []string {
	modelNames := make([]string, 0)
	for _, key := range keys {
		modelNames = append(modelNames, key.Models...)
	}
	return normalizeProviderModelNames(modelNames)
}

func providerModelID(providerID uint, modelName string) string {
	return fmt.Sprintf("%d:%s", providerID, modelName)
}
