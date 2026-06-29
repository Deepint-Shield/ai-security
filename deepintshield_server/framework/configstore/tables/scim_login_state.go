package tables

import (
	"fmt"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/encrypt"
	"gorm.io/gorm"
)

type TableSCIMLoginState struct {
	ID               string    `gorm:"type:varchar(255);primaryKey" json:"id"`
	TenantID         string    `gorm:"column:tenant_id;type:varchar(255);index" json:"-"`
	State            string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"state"`
	ProviderConfigID string    `gorm:"column:provider_config_id;type:varchar(255);not null;index" json:"provider_config_id"`
	EmailHint        string    `gorm:"type:varchar(255)" json:"email_hint,omitempty"`
	Nonce            string    `gorm:"type:text" json:"-"`
	CodeVerifier     string    `gorm:"type:text" json:"-"`
	RedirectURI      string    `gorm:"type:text;not null" json:"redirect_uri"`
	// InvitationToken is set when the OAuth flow was initiated from
	// /login?mode=signup&invite=<token>. The callback handler reads
	// it after a successful Microsoft round-trip, consumes the matching
	// TableUserInvitation row, and applies the invitation's tenant +
	// role to the newly JIT-provisioned user. Empty for normal sign-in
	// flows. Per the "accept invite with Microsoft" UX requirement.
	InvitationToken  string    `gorm:"column:invitation_token;type:varchar(255)" json:"invitation_token,omitempty"`
	ExpiresAt        time.Time `gorm:"index;not null" json:"expires_at"`
	EncryptionStatus string    `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	CreatedAt        time.Time `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableSCIMLoginState) TableName() string { return "scim_login_states" }

func (s *TableSCIMLoginState) BeforeSave(tx *gorm.DB) error {
	s.State = strings.TrimSpace(s.State)
	s.ProviderConfigID = strings.TrimSpace(s.ProviderConfigID)
	s.EmailHint = normalizeAuthEmail(s.EmailHint)
	s.RedirectURI = strings.TrimSpace(s.RedirectURI)

	if encrypt.IsEnabled() {
		encrypted := false
		if s.Nonce != "" {
			if err := encryptString(&s.Nonce); err != nil {
				return fmt.Errorf("failed to encrypt scim login nonce: %w", err)
			}
			encrypted = true
		}
		if s.CodeVerifier != "" {
			if err := encryptString(&s.CodeVerifier); err != nil {
				return fmt.Errorf("failed to encrypt scim login code verifier: %w", err)
			}
			encrypted = true
		}
		if encrypted {
			s.EncryptionStatus = EncryptionStatusEncrypted
		}
	}

	return nil
}

func (s *TableSCIMLoginState) AfterFind(tx *gorm.DB) error {
	if s.EncryptionStatus == EncryptionStatusEncrypted {
		if err := decryptString(&s.Nonce); err != nil {
			return fmt.Errorf("failed to decrypt scim login nonce: %w", err)
		}
		if err := decryptString(&s.CodeVerifier); err != nil {
			return fmt.Errorf("failed to decrypt scim login code verifier: %w", err)
		}
	}
	return nil
}
