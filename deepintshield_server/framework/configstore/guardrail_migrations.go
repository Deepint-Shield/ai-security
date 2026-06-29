package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/migrator"
	"gorm.io/gorm"
)

func migrationAddGuardrailControlPlaneTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_control_plane_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableGuardrailProvider{},
				&tables.TableGuardrailPolicy{},
				&tables.TableGuardrailPolicyVersion{},
				&tables.TableGuardrailDomainPack{},
				&tables.TableGuardrailPolicyProviderBinding{},
				&tables.TableGuardrailMCPToolPolicy{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running guardrail control plane migration: %s", err.Error())
	}
	return nil
}

func migrationAddGuardrailPolicyDefaultsAndVirtualKeyBindings(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_policy_defaults_and_virtual_key_bindings",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.AutoMigrate(
				&tables.TableGuardrailPolicy{},
				&tables.TableVirtualKeyGuardrailPolicy{},
			); err != nil {
				return err
			}
			if err := tx.SetupJoinTable(&tables.TableVirtualKey{}, "GuardrailPolicies", &tables.TableVirtualKeyGuardrailPolicy{}); err != nil {
				return fmt.Errorf("failed to setup join table for virtual key guardrail policies: %w", err)
			}
			var defaultCount int64
			if err := tx.Model(&tables.TableGuardrailPolicy{}).Where("is_default = ?", true).Count(&defaultCount).Error; err != nil {
				return err
			}
			if defaultCount > 0 {
				return nil
			}
			var firstPolicy tables.TableGuardrailPolicy
			if err := tx.Order("created_at ASC, id ASC").First(&firstPolicy).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil
				}
				return err
			}
			return tx.Model(&tables.TableGuardrailPolicy{}).
				Where("id = ?", firstPolicy.ID).
				Update("is_default", true).Error
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running guardrail policy defaults and virtual key bindings migration: %s", err.Error())
	}
	return nil
}

// migrationAddGuardrailExecutionMode adds the execution_mode and
// shadow_until columns to guardrail_policies. execution_mode lets a
// policy run async (fire-and-forget, log-only) or shadow (inline but
// non-blocking) instead of the default synchronous path. shadow_until
// is the optional auto-expiry that flips a shadow rollout back to
// enforcement after a fixed window so policies don't silently stay in
// shadow forever.
func migrationAddGuardrailExecutionMode(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_execution_mode",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mg := tx.Migrator()
			if !mg.HasColumn(&tables.TableGuardrailPolicy{}, "execution_mode") {
				if err := mg.AddColumn(&tables.TableGuardrailPolicy{}, "ExecutionMode"); err != nil {
					return fmt.Errorf("failed to add execution_mode column: %w", err)
				}
				if err := tx.Model(&tables.TableGuardrailPolicy{}).
					Where("execution_mode IS NULL OR execution_mode = ?", "").
					Update("execution_mode", tables.GuardrailExecutionModeSync).Error; err != nil {
					return fmt.Errorf("failed to backfill execution_mode default: %w", err)
				}
			}
			if !mg.HasColumn(&tables.TableGuardrailPolicy{}, "shadow_until") {
				if err := mg.AddColumn(&tables.TableGuardrailPolicy{}, "ShadowUntil"); err != nil {
					return fmt.Errorf("failed to add shadow_until column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running guardrail execution mode migration: %s", err.Error())
	}
	return nil
}

func migrationAddGuardrailRAGConfigTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_guardrail_rag_config_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&tables.TableGuardrailRAGSettings{},
				&tables.TableGuardrailRAGSource{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while running guardrail rag config migration: %s", err.Error())
	}
	return nil
}
