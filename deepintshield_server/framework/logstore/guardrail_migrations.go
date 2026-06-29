package logstore

import (
	"context"
	"fmt"

	"github.com/deepint-shield/ai-security/framework/migrator"
	"gorm.io/gorm"
)

func migrationCreateGuardrailEvidenceTables(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "logs_create_guardrail_evidence_tables",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(
				&GuardrailFinding{},
				&GuardrailDecision{},
				&GuardrailTrace{},
				&GuardrailApprovalRequest{},
			)
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while creating guardrail evidence tables: %s", err.Error())
	}
	return nil
}

func migrationAddGuardrailApprovalStageColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "logs_add_guardrail_approval_stage_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&GuardrailApprovalRequest{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding guardrail approval stage column: %s", err.Error())
	}
	return nil
}

func migrationAddGuardrailTraceStageColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "logs_add_guardrail_trace_stage_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&GuardrailTrace{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding guardrail trace stage column: %s", err.Error())
	}
	return nil
}

func migrationAddGuardrailDecisionEngineSourceColumn(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "logs_add_guardrail_decision_engine_source_column",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			return tx.AutoMigrate(&GuardrailDecision{})
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding guardrail decision engine_source column: %s", err.Error())
	}
	return nil
}
