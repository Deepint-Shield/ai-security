package configstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (s *RDBConfigStore) GetGuardrailRAGSettings(ctx context.Context) (*tables.TableGuardrailRAGSettings, error) {
	var settings tables.TableGuardrailRAGSettings
	if err := s.db.WithContext(ctx).First(&settings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &settings, nil
}

func (s *RDBConfigStore) UpsertGuardrailRAGSettings(ctx context.Context, settings *tables.TableGuardrailRAGSettings) error {
	if settings == nil {
		return nil
	}
	if strings.TrimSpace(settings.ID) == "" {
		settings.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if settings.CreatedAt.IsZero() {
		settings.CreatedAt = now
	}
	settings.UpdatedAt = now
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1=1").Delete(&tables.TableGuardrailRAGSettings{}).Error; err != nil {
			return err
		}
		return tx.Create(settings).Error
	})
}

func (s *RDBConfigStore) ListGuardrailRAGSources(ctx context.Context) ([]tables.TableGuardrailRAGSource, error) {
	var sources []tables.TableGuardrailRAGSource
	q := s.db.WithContext(ctx)
	// Workspace narrowing: when the caller has an active workspace, return
	// ONLY rows scoped to it. NULL-workspace rows are legacy/unmigrated and
	// must not bleed into sibling workspaces - that was the bug where a
	// dev-ws source showed up under prod-ws's RAG Sources count.
	if ws := strings.TrimSpace(tenantctx.WorkspaceIDFromContext(ctx)); ws != "" {
		q = q.Where("workspace_id = ?", ws)
	}
	if err := q.
		Order("quarantined DESC, updated_at DESC, created_at DESC").
		Find(&sources).Error; err != nil {
		return nil, err
	}
	return sources, nil
}

func (s *RDBConfigStore) GetGuardrailRAGSource(ctx context.Context, id string) (*tables.TableGuardrailRAGSource, error) {
	var source tables.TableGuardrailRAGSource
	if err := s.db.WithContext(ctx).First(&source, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &source, nil
}

func (s *RDBConfigStore) CreateGuardrailRAGSource(ctx context.Context, source *tables.TableGuardrailRAGSource) error {
	if source == nil {
		return nil
	}
	if strings.TrimSpace(source.ID) == "" {
		source.ID = uuid.NewString()
	}
	if source.CreatedAt.IsZero() {
		source.CreatedAt = time.Now().UTC()
	}
	source.UpdatedAt = time.Now().UTC()
	// Resolve effective workspace: explicit > context > tenant default.
	if source.WorkspaceID == nil {
		if ws := s.resolveEffectiveWorkspaceID(ctx, ""); ws != "" {
			source.WorkspaceID = &ws
		}
	}
	return s.db.WithContext(ctx).Create(source).Error
}

func (s *RDBConfigStore) UpdateGuardrailRAGSource(ctx context.Context, source *tables.TableGuardrailRAGSource) error {
	if source == nil {
		return nil
	}
	source.UpdatedAt = time.Now().UTC()
	return s.db.WithContext(ctx).Save(source).Error
}
