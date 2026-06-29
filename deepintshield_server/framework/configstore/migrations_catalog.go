package configstore

// Migrations for the Model-Catalog admin features (Pricing Adjustments
// + Model Overrides). Kept in its own file alongside migrations_sso.go
// for isolation from the giant migrations.go runner.

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/migrator"
)

// RunCatalogMigrations runs the model-catalog admin migrations.
// Wired into the main migration runner alongside RunSSOMigrations.
func RunCatalogMigrations(ctx context.Context, db *gorm.DB) error {
	if err := migrationCreatePricingAdjustmentsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationCreateModelOverridesTable(ctx, db); err != nil {
		return err
	}
	return nil
}

func migrationCreatePricingAdjustmentsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_pricing_adjustments_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TablePricingAdjustment{}) {
				return nil
			}
			if err := mig.CreateTable(&tables.TablePricingAdjustment{}); err != nil {
				return fmt.Errorf("failed to create pricing_adjustments: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TablePricingAdjustment{}) {
				if err := mig.DropTable(&tables.TablePricingAdjustment{}); err != nil {
					return fmt.Errorf("failed to drop pricing_adjustments: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error creating pricing_adjustments: %s", err.Error())
	}
	return nil
}

func migrationCreateModelOverridesTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_model_overrides_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TableModelOverride{}) {
				return nil
			}
			if err := mig.CreateTable(&tables.TableModelOverride{}); err != nil {
				return fmt.Errorf("failed to create model_overrides: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TableModelOverride{}) {
				if err := mig.DropTable(&tables.TableModelOverride{}); err != nil {
					return fmt.Errorf("failed to drop model_overrides: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error creating model_overrides: %s", err.Error())
	}
	return nil
}
