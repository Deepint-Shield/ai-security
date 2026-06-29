package configstore

// RDB implementations of the SAML provider config CRUD methods declared in
// ConfigStore, plus the cross-provider SSO-identity lookup used by both
// session_sso.go (OIDC) and auth_saml.go (SAML). Mirrors the SCIM provider
// config methods in rdb.go; kept in its own file so the SSO workstream's
// diff stays isolated from the rest of the RDB layer.

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
)

// GetSCIMConnectionByBearerHash looks up the connection whose
// scim_bearer_hash matches the supplied sha256 hash. The hash is
// indexed; the lookup is O(log n) and short-circuits cleanly when no
// match is found.
func (s *RDBConfigStore) GetSCIMConnectionByBearerHash(ctx context.Context, bearerHash string) (*tables.TableSCIMProviderConfig, error) {
	trimmed := strings.TrimSpace(bearerHash)
	if trimmed == "" {
		return nil, nil
	}
	var config tables.TableSCIMProviderConfig
	if err := s.db.WithContext(ctx).First(&config, "scim_bearer_hash = ?", trimmed).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &config, nil
}

// GetUserBySSOIdentityKey returns the user whose `sso_identity_key`
// column matches the supplied key. Identity-keys are constructed as
// "{connection_id}:{subject}" by the OIDC and SAML callbacks. Returns
// (nil, nil) when no row matches (callers fall through to email-based
// account linking).
func (s *RDBConfigStore) GetUserBySSOIdentityKey(ctx context.Context, identityKey string) (*tables.TableAuthUser, error) {
	var user tables.TableAuthUser
	if err := s.db.WithContext(ctx).First(&user, "sso_identity_key = ?", strings.TrimSpace(identityKey)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (s *RDBConfigStore) GetSAMLProviderConfigByID(ctx context.Context, id string) (*tables.TableSAMLProviderConfig, error) {
	var config tables.TableSAMLProviderConfig
	if err := s.db.WithContext(ctx).First(&config, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &config, nil
}

func (s *RDBConfigStore) ListSAMLProviderConfigs(ctx context.Context) ([]tables.TableSAMLProviderConfig, error) {
	var configs []tables.TableSAMLProviderConfig
	if err := s.db.WithContext(ctx).
		Model(&tables.TableSAMLProviderConfig{}).
		Order("is_default DESC, enabled DESC, created_at ASC").
		Find(&configs).Error; err != nil {
		return nil, err
	}
	return configs, nil
}

func (s *RDBConfigStore) CreateSAMLProviderConfig(ctx context.Context, config *tables.TableSAMLProviderConfig) error {
	if config == nil {
		return nil
	}
	if config.ID == "" {
		config.ID = uuid.NewString()
	}
	return s.db.WithContext(ctx).Create(config).Error
}

func (s *RDBConfigStore) UpdateSAMLProviderConfig(ctx context.Context, config *tables.TableSAMLProviderConfig) error {
	if config == nil {
		return nil
	}
	return s.db.WithContext(ctx).Save(config).Error
}

func (s *RDBConfigStore) DeleteSAMLProviderConfig(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&tables.TableSAMLProviderConfig{}, "id = ?", strings.TrimSpace(id)).Error
}

// ResolveSAMLProviderConfig mirrors ResolveSCIMProviderConfig's routing:
//  1. Explicit connectionID wins.
//  2. Otherwise, the first enabled connection whose EmailDomains contains
//     the user's email-domain wins.
//  3. Otherwise, if there's exactly one enabled connection (legacy
//     single-customer / on-prem mode), that one wins.
//
// Multiple enabled connections without a connection_id and without an
// email-domain match return (nil, nil) - callers must supply a
// connection_id explicitly so we never silently route an Acme user to
// Beta Corp's SAML IdP (gap analysis item #5).
func (s *RDBConfigStore) ResolveSAMLProviderConfig(ctx context.Context, connectionID, email string) (*tables.TableSAMLProviderConfig, error) {
	if trimmedID := strings.TrimSpace(connectionID); trimmedID != "" {
		return s.GetSAMLProviderConfigByID(ctx, trimmedID)
	}

	configs, err := s.ListSAMLProviderConfigs(ctx)
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

	enabledCount := 0
	var onlyEnabled *tables.TableSAMLProviderConfig
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
