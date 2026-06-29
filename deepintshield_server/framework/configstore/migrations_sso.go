package configstore

// SSO + SCIM 2.0 schema migrations.
//
// Lives in its own file (rather than the multi-thousand-line
// migrations.go) so the SSO/SAML/SCIM workstream can land its
// migrations without conflicting on shared lines. The migration
// runner in `RunMigrations` is responsible for invoking these in
// order - see `RunSSOMigrations` below.

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/migrator"
)

// RunSSOMigrations executes the SSO/SAML/SCIM-related schema migrations.
// Called from the main migration runner in RunMigrations after the
// existing SCIM provider migrations have completed.
func RunSSOMigrations(ctx context.Context, db *gorm.DB) error {
	if err := migrationCreateSAMLProviderConfigsTable(ctx, db); err != nil {
		return err
	}
	if err := migrationAddAllowAutoAccountLinkingToSCIM(ctx, db); err != nil {
		return err
	}
	if err := migrationAddSSOLinkingColumnsToAuthUsers(ctx, db); err != nil {
		return err
	}
	if err := migrationAddSCIMBearerColumns(ctx, db); err != nil {
		return err
	}
	if err := migrationAddInvitationTokenToSCIMLoginState(ctx, db); err != nil {
		return err
	}
	// Future SSO migrations append here.
	return nil
}

// migrationAddInvitationTokenToSCIMLoginState adds the
// `invitation_token` column to scim_login_states. Used by the
// "accept invite with Microsoft" UX: the invitation token from
// /login?mode=signup&invite=<token> is stashed on the login-state
// row so the OIDC callback can consume the invitation and apply
// its tenant + role to the new auth_user.
func migrationAddInvitationTokenToSCIMLoginState(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_invitation_token_to_scim_login_states",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasTable(&tables.TableSCIMLoginState{}) {
				return nil
			}
			if mig.HasColumn(&tables.TableSCIMLoginState{}, "invitation_token") {
				return nil
			}
			if err := mig.AddColumn(&tables.TableSCIMLoginState{}, "InvitationToken"); err != nil {
				return fmt.Errorf("failed to add invitation_token column: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TableSCIMLoginState{}, "invitation_token") {
				if err := mig.DropColumn(&tables.TableSCIMLoginState{}, "invitation_token"); err != nil {
					return fmt.Errorf("failed to drop invitation_token column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error adding invitation_token column: %s", err.Error())
	}
	return nil
}

// migrationAddSCIMBearerColumns adds the SCIM 2.0 inbound bearer
// authentication columns to scim_provider_configs. The hash column has
// an index for the constant-time-ish O(1) lookup that the inbound SCIM
// middleware does (hash the presented bearer, look up by hash, then
// constant-time compare the full hash to defeat timing attacks that
// chunk-leak the index).
// Per SSO_IMPLEMENTATION_PLAN.md Phase D (gap #2).
func migrationAddSCIMBearerColumns(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_scim_bearer_columns_to_scim_provider_configs",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasTable(&tables.TableSCIMProviderConfig{}) {
				return nil
			}
			columns := []struct {
				column string
				field  string
			}{
				{"scim_bearer_hash", "SCIMBearerHash"},
				{"scim_bearer_prefix", "SCIMBearerPrefix"},
			}
			for _, c := range columns {
				if mig.HasColumn(&tables.TableSCIMProviderConfig{}, c.column) {
					continue
				}
				if err := mig.AddColumn(&tables.TableSCIMProviderConfig{}, c.field); err != nil {
					return fmt.Errorf("failed to add %s column: %w", c.column, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			for _, column := range []string{"scim_bearer_prefix", "scim_bearer_hash"} {
				if !mig.HasColumn(&tables.TableSCIMProviderConfig{}, column) {
					continue
				}
				if err := mig.DropColumn(&tables.TableSCIMProviderConfig{}, column); err != nil {
					return fmt.Errorf("failed to drop %s column: %w", column, err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding scim bearer columns: %s", err.Error())
	}
	return nil
}

// migrationAddSSOLinkingColumnsToAuthUsers adds the generic SSO linking
// columns (sso_provider, sso_subject, sso_connection_id, sso_identity_key)
// to the auth_users table. Per SSO_IMPLEMENTATION_PLAN.md Phase C -
// session_sso.go populates these for Okta / Auth0 / Generic OIDC sign-ins;
// the existing Entra columns (entra_subject / entra_connection_id /
// entra_identity_key) keep working for session_entra.go for backward
// compatibility with already-provisioned Entra users.
func migrationAddSSOLinkingColumnsToAuthUsers(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_sso_linking_columns_to_auth_users",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasTable(&tables.TableAuthUser{}) {
				return nil
			}
			columns := []struct {
				column string
				field  string
			}{
				{"sso_provider", "SSOProvider"},
				{"sso_subject", "SSOSubject"},
				{"sso_connection_id", "SSOConnectionID"},
				{"sso_identity_key", "SSOIdentityKey"},
			}
			for _, c := range columns {
				if mig.HasColumn(&tables.TableAuthUser{}, c.column) {
					continue
				}
				if err := mig.AddColumn(&tables.TableAuthUser{}, c.field); err != nil {
					return fmt.Errorf("failed to add %s column: %w", c.column, err)
				}
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			for _, column := range []string{"sso_identity_key", "sso_connection_id", "sso_subject", "sso_provider"} {
				if !mig.HasColumn(&tables.TableAuthUser{}, column) {
					continue
				}
				if err := mig.DropColumn(&tables.TableAuthUser{}, column); err != nil {
					return fmt.Errorf("failed to drop %s column: %w", column, err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding sso linking columns: %s", err.Error())
	}
	return nil
}

// migrationAddAllowAutoAccountLinkingToSCIM adds the
// `allow_auto_account_linking` column to scim_provider_configs. Per
// SSO_IMPLEMENTATION_PLAN.md §5.4: this defaults to false on existing
// rows so the security-conscious posture is preserved on upgrade -
// existing tenants must explicitly opt in to auto-linking.
func migrationAddAllowAutoAccountLinkingToSCIM(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "add_allow_auto_account_linking_to_scim_provider_configs",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if !mig.HasTable(&tables.TableSCIMProviderConfig{}) {
				// Cold start - the create-table migration will pick up the
				// field from the struct definition.
				return nil
			}
			if mig.HasColumn(&tables.TableSCIMProviderConfig{}, "allow_auto_account_linking") {
				return nil
			}
			if err := mig.AddColumn(&tables.TableSCIMProviderConfig{}, "AllowAutoAccountLinking"); err != nil {
				return fmt.Errorf("failed to add allow_auto_account_linking column: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasColumn(&tables.TableSCIMProviderConfig{}, "allow_auto_account_linking") {
				if err := mig.DropColumn(&tables.TableSCIMProviderConfig{}, "allow_auto_account_linking"); err != nil {
					return fmt.Errorf("failed to drop allow_auto_account_linking column: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while adding allow_auto_account_linking column: %s", err.Error())
	}
	return nil
}

// migrationCreateSAMLProviderConfigsTable creates `saml_provider_configs`
// - the parallel table to `scim_provider_configs` for SAML 2.0
// connections. Cold-create, no backfill (no prior SAML connections exist).
func migrationCreateSAMLProviderConfigsTable(ctx context.Context, db *gorm.DB) error {
	m := migrator.New(db, migrator.DefaultOptions, []*migrator.Migration{{
		ID: "create_saml_provider_configs_table",
		Migrate: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TableSAMLProviderConfig{}) {
				return nil
			}
			if err := mig.CreateTable(&tables.TableSAMLProviderConfig{}); err != nil {
				return fmt.Errorf("failed to create saml_provider_configs: %w", err)
			}
			return nil
		},
		Rollback: func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			mig := tx.Migrator()
			if mig.HasTable(&tables.TableSAMLProviderConfig{}) {
				if err := mig.DropTable(&tables.TableSAMLProviderConfig{}); err != nil {
					return fmt.Errorf("failed to drop saml_provider_configs: %w", err)
				}
			}
			return nil
		},
	}})
	if err := m.Migrate(); err != nil {
		return fmt.Errorf("error while creating saml_provider_configs: %s", err.Error())
	}
	return nil
}
