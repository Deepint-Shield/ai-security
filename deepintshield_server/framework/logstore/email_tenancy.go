package logstore

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

var emailScopedLogModels = []any{
	&Log{},
	&MCPToolLog{},
	&AsyncJob{},
	&AuditLogEntry{},
	&AuditExportJob{},
	&LogExportJob{},
	&GuardrailFinding{},
	&GuardrailDecision{},
	&GuardrailTrace{},
	&GuardrailApprovalRequest{},
}

// MigrateTenantIDs reassigns log rows from legacy tenant IDs to the normalized
// email tenant key. It is safe to call repeatedly.
func (s *RDBLogStore) MigrateTenantIDs(ctx context.Context, mappings map[string]string) error {
	if s == nil || s.db == nil {
		return nil
	}

	normalized := normalizeLogTenantMappings(mappings)
	if len(normalized) == 0 {
		return nil
	}

	return s.db.WithContext(logTenantMigrationContext(ctx)).Transaction(func(tx *gorm.DB) error {
		for _, model := range emailScopedLogModels {
			if !tx.Migrator().HasTable(model) {
				continue
			}
			for oldTenantID, newTenantID := range normalized {
				query := tx.Session(&gorm.Session{SkipHooks: true}).Model(model)
				if oldTenantID == "" {
					query = query.Where("(tenant_id = '' OR tenant_id IS NULL)")
				} else {
					query = query.Where("tenant_id = ?", oldTenantID)
				}
				if err := query.UpdateColumn("tenant_id", newTenantID).Error; err != nil {
					return fmt.Errorf("failed to migrate log tenant %q -> %q for %T: %w", oldTenantID, newTenantID, model, err)
				}
			}
		}
		return nil
	})
}

func normalizeLogTenantMappings(mappings map[string]string) map[string]string {
	normalized := make(map[string]string)
	for oldTenantID, newTenantID := range mappings {
		oldTenantID = strings.TrimSpace(oldTenantID)
		newTenantID = strings.ToLower(strings.TrimSpace(newTenantID))
		if newTenantID == "" || (oldTenantID != "" && oldTenantID == newTenantID) {
			continue
		}
		normalized[oldTenantID] = newTenantID
	}
	return normalized
}

func logTenantMigrationContext(context.Context) context.Context {
	return context.Background()
}
