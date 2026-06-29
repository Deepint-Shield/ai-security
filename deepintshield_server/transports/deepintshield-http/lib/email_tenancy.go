package lib

import (
	"context"
	"fmt"
)

type emailScopedTenancyBackfiller interface {
	BackfillEmailScopedTenancy(ctx context.Context) (map[string]string, error)
}

type workspaceBackfiller interface {
	EnsureWorkspaceBackfill(ctx context.Context) error
}

type tenantIDMigrator interface {
	MigrateTenantIDs(ctx context.Context, mappings map[string]string) error
}

type providerModelBackfiller interface {
	BackfillProviderModelsFromKeys(ctx context.Context) error
}

func alignEmailScopedTenancy(ctx context.Context, config *Config) error {
	if config == nil || config.ConfigStore == nil {
		return nil
	}

	backfiller, ok := config.ConfigStore.(emailScopedTenancyBackfiller)
	if !ok {
		return nil
	}

	mappings, err := backfiller.BackfillEmailScopedTenancy(ctx)
	if err != nil {
		return fmt.Errorf("failed to backfill email-scoped tenancy: %w", err)
	}

	if len(mappings) > 0 && config.LogsStore != nil {
		logMigrator, ok := config.LogsStore.(tenantIDMigrator)
		if ok {
			if err := logMigrator.MigrateTenantIDs(ctx, mappings); err != nil {
				return fmt.Errorf("failed to backfill email-scoped log tenancy: %w", err)
			}
		}
	}

	// Repair workspace + membership rows now that organizations.id values
	// are settled. The workspace migration ran earlier during triggerMigrations
	// (against the *pre-rename* org IDs) so the rows it created may
	// reference stale IDs; this idempotent pass reseats memberships and
	// ensures every org has a default workspace.
	if wsBackfiller, ok := config.ConfigStore.(workspaceBackfiller); ok {
		if err := wsBackfiller.EnsureWorkspaceBackfill(ctx); err != nil {
			return fmt.Errorf("failed to backfill workspace memberships: %w", err)
		}
	}

	return backfillProviderModels(ctx, config)
}

func backfillProviderModels(ctx context.Context, config *Config) error {
	if config == nil || config.ConfigStore == nil {
		return nil
	}
	backfiller, ok := config.ConfigStore.(providerModelBackfiller)
	if !ok {
		return nil
	}
	if err := backfiller.BackfillProviderModelsFromKeys(ctx); err != nil {
		return fmt.Errorf("failed to backfill provider models from keys: %w", err)
	}
	return nil
}
