package handlers

import (
	"context"
	"fmt"
	"strings"
)

type tenantIDMigrator interface {
	MigrateTenantIDs(ctx context.Context, mappings map[string]string) error
}

func emailTenantID(email string) string {
	return normalizeEmail(email)
}

// canonicalTenantResolver is the slice of the config store needed to map an
// email to its canonical (UUID) tenant.
type canonicalTenantResolver interface {
	ResolveCanonicalTenant(ctx context.Context, aliasKey string) (string, error)
}

// canonicalTenantForEmail returns the canonical (UUID) tenant id for an email
// when it has been re-keyed (a tenant alias exists), else the legacy
// email-derived id. This decouples login/audit tenant resolution from the
// email being the literal tenant key. No-op (returns the email id) until
// aliases exist, so behavior is unchanged pre-migration.
func canonicalTenantForEmail(ctx context.Context, store canonicalTenantResolver, email string) string {
	if store != nil {
		if canonical, err := store.ResolveCanonicalTenant(ctx, email); err == nil && canonical != "" {
			return canonical
		}
	}
	return emailTenantID(email)
}

func buildTenantIDMappings(userID, currentEmail, currentTenantID, newEmail string) map[string]string {
	newTenantID := emailTenantID(newEmail)
	if newTenantID == "" {
		return nil
	}

	mappings := make(map[string]string)
	for _, oldTenantID := range []string{currentTenantID, currentEmail, userID} {
		oldTenantID = strings.TrimSpace(oldTenantID)
		if oldTenantID == "" || oldTenantID == newTenantID {
			continue
		}
		mappings[oldTenantID] = newTenantID
	}
	return mappings
}

func (h *SessionHandler) migrateTenantScopedData(ctx context.Context, mappings map[string]string) error {
	if len(mappings) == 0 {
		return nil
	}

	if migrator, ok := h.configStore.(tenantIDMigrator); ok {
		if err := migrator.MigrateTenantIDs(ctx, mappings); err != nil {
			return fmt.Errorf("failed to migrate config data tenancy: %w", err)
		}
	}

	if migrator, ok := h.logsStore.(tenantIDMigrator); ok {
		if err := migrator.MigrateTenantIDs(ctx, mappings); err != nil {
			return fmt.Errorf("failed to migrate log data tenancy: %w", err)
		}
	}

	return nil
}
