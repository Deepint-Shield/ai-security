package tables

import "time"

// Document types we capture acceptance for.
const (
	LegalDocumentTermsOfService = "terms_of_service"
	LegalDocumentPrivacyPolicy  = "privacy_policy"
)

// Methods that can produce a consent record. Audit reviewers should be able
// to tell *how* the consent was given, not just that it was given.
const (
	LegalConsentMethodSignup           = "signup"
	LegalConsentMethodLogin            = "login"
	LegalConsentMethodGoogleLogin      = "google_login"
	LegalConsentMethodEntraLogin       = "entra_login"
	LegalConsentMethodReacceptUpdated  = "reaccept_updated"
	LegalConsentMethodExplicitWithdraw = "explicit_withdraw"
)

// TableLegalConsent is an append-only audit record of when a user accepted
// (or, for withdraw events, withdrew) a versioned legal document.
//
// Storage rules to keep this audit-grade:
//
//   - Rows are immutable. We *append* on each acceptance - we do not update
//     existing rows. Withdrawals are a new row with the withdraw method.
//   - The active acceptance for a (user, document_type) is the most recent
//     row. Surface helpers should ORDER BY accepted_at DESC LIMIT 1.
//   - email_at_consent is captured as a snapshot in case the account email
//     changes later - auditors need to know the email at the time.
//   - document_hash binds the consent to the exact text of the document at
//     the version on file. If a doc is updated post-hoc without a version
//     bump (which it shouldn't be), the hash mismatch flags the row.
//   - ip_address and user_agent are admissibility evidence under §65B of
//     the Indian Evidence Act for any later dispute about consent.
//
// Designed against DPDP Act §6 (notice + consent) and IT Act 2000 §65B
// (admissibility of electronic records).
type TableLegalConsent struct {
	ID              string    `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID        string    `gorm:"column:tenant_id;type:varchar(255);index;default:''" json:"tenant_id"`
	UserID          string    `gorm:"column:user_id;type:varchar(255);index;not null" json:"user_id"`
	EmailAtConsent  string    `gorm:"column:email_at_consent;type:varchar(255);index;not null" json:"email_at_consent"`
	DocumentType    string    `gorm:"column:document_type;type:varchar(64);index;not null" json:"document_type"`
	DocumentVersion string    `gorm:"column:document_version;type:varchar(32);index;not null" json:"document_version"`
	DocumentHash    string    `gorm:"column:document_hash;type:varchar(128);not null" json:"document_hash"`
	ConsentMethod   string    `gorm:"column:consent_method;type:varchar(64);index;not null" json:"consent_method"`
	IPAddress       string    `gorm:"column:ip_address;type:varchar(64)" json:"ip_address,omitempty"`
	UserAgent       string    `gorm:"column:user_agent;type:varchar(1024)" json:"user_agent,omitempty"`
	Locale          string    `gorm:"column:locale;type:varchar(32)" json:"locale,omitempty"`
	AcceptedAt      time.Time `gorm:"column:accepted_at;index;not null" json:"accepted_at"`
	CreatedAt       time.Time `gorm:"index;not null" json:"created_at"`
}

func (TableLegalConsent) TableName() string { return "legal_consents" }
