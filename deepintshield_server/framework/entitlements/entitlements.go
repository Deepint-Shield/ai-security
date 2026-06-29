// Package entitlements is the open-core seam between gateway handlers and the
// closed-source plan/billing enforcement. Handlers call the package-level
// EnforceFeature / EnforceQuota helpers here instead of importing the
// commercial framework/billing package directly.
//
//   - Commercial build: framework/billing registers a billing-backed Enforcer
//     in its init(), so the gates behave exactly as before.
//   - Open-source build: framework/billing is absent, the default no-op Enforcer
//     stands, and every gate allows (the premium backends the gates guard are
//     simply not compiled in).
//
// This lets framework/billing leave the OSS tree via a mechanical
// `billing.` -> `entitlements.` rename, with no behavior change in either build.
// See oss/DECOUPLING_WORKLIST.md §1.
package entitlements

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"gorm.io/gorm"
)

// QuotaError is returned when a tenant tries to create a resource beyond the
// limit allowed by their plan. Handlers translate this into a 402 (or 403) and
// surface Plan / Limit to the UI for upgrade-prompt copy.
type QuotaError struct {
	LimitKey string
	Limit    int64
	Current  int64
	Plan     string
	Feature  string
}

func (e *QuotaError) Error() string {
	if e.Feature != "" {
		return fmt.Sprintf("plan %q reached its %s limit (%d). Upgrade to add more.", e.Plan, e.Feature, e.Limit)
	}
	return fmt.Sprintf("plan %q reached its %s limit (%d). Upgrade to add more.", e.Plan, e.LimitKey, e.Limit)
}

// IsQuotaError reports whether err (or its chain) is a *QuotaError.
func IsQuotaError(err error) bool {
	var q *QuotaError
	return errors.As(err, &q)
}

// FeatureLockedError is returned when a tenant tries to use a boolean feature
// that their plan does not enable. Mirrors QuotaError so handlers can map both
// to the same 402 response shape on the wire.
type FeatureLockedError struct {
	FeatureKey string
	Plan       string
	UpgradeTo  string
}

func (e *FeatureLockedError) Error() string {
	if e.UpgradeTo != "" {
		return fmt.Sprintf("feature %q is not available on the %s plan. Upgrade to %s.", e.FeatureKey, e.Plan, e.UpgradeTo)
	}
	return fmt.Sprintf("feature %q is not available on the %s plan.", e.FeatureKey, e.Plan)
}

// IsFeatureLockedError reports whether err is a *FeatureLockedError.
func IsFeatureLockedError(err error) bool {
	var f *FeatureLockedError
	return errors.As(err, &f)
}

// QuotaStatus reports usage vs cap for a tenant - for UI badges that show
// "X of Y used" without blocking.
type QuotaStatus struct {
	Used      int64  `json:"used"`
	Limit     int64  `json:"limit"`
	Unlimited bool   `json:"unlimited"`
	Plan      string `json:"plan"`
}

// Enforcer is the plan-enforcement backend. The commercial framework/billing
// package implements it; the OSS build uses the no-op default.
type Enforcer interface {
	EnforceFeature(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, featureKey string) error
	EnforceQuota(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, limitKey string, currentCount int64) error
	IsFeatureEnabled(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, featureKey string) bool
	GetQuotaStatus(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, limitKey string, currentCount int64) QuotaStatus
}

// ossDeniedFeatures is the set of premium guardrail capability keys that the
// open-source build must DENY. These guard features whose backends ship only in
// DeepintShield Cloud/Enterprise (partner safety providers that make real cloud
// calls, in-tree ML detectors, the vertical domain packs, and hand-authored
// custom guardrail cards). They are NOT deterministic guardrails: regex_match,
// detect_pii, and content policy on input/output/tool I/O stay fully allowed
// because they are not listed here.
//
// Everything NOT in this set stays allow-all - that is the load-bearing OSS
// seam. A commercial build registers its own Enforcer via SetDefault and never
// consults this map.
var ossDeniedFeatures = map[string]bool{
	FeatureGuardrailsPartnerProviders: true, // AWS Bedrock, Azure Content Safety, GCP Model Armor
	FeatureGuardrailsInTreeML:         true, // DeBERTa / RoBERTa / BERT detectors
	FeatureGuardrailsDomainPacks:      true, // BFSI / Healthcare / Insurance / Copilot / ... packs
	FeatureGuardrailsCustomCard:       true, // hand-authored custom guardrail cards
}

// noopEnforcer is the OSS default. It allows every feature EXCEPT the premium
// guardrail keys in ossDeniedFeatures, which it denies with a FeatureLockedError
// pointing operators at DeepintShield Cloud/Enterprise. The deterministic
// guardrail engine (regex/PII/content) and every non-guardrail feature stay
// allow-all so the OSS seam keeps working unchanged.
type noopEnforcer struct{}

func (noopEnforcer) EnforceFeature(_ context.Context, _ *gorm.DB, org *tables.TableOrganization, featureKey string) error {
	if ossDeniedFeatures[featureKey] {
		plan := "community"
		if org != nil && strings.TrimSpace(org.Plan) != "" {
			plan = org.Plan
		}
		return &FeatureLockedError{
			FeatureKey: featureKey,
			Plan:       plan,
			UpgradeTo:  "DeepintShield Cloud/Enterprise",
		}
	}
	return nil
}
func (noopEnforcer) EnforceQuota(context.Context, *gorm.DB, *tables.TableOrganization, string, int64) error {
	return nil
}
func (noopEnforcer) IsFeatureEnabled(_ context.Context, _ *gorm.DB, _ *tables.TableOrganization, featureKey string) bool {
	return !ossDeniedFeatures[featureKey]
}
func (noopEnforcer) GetQuotaStatus(_ context.Context, _ *gorm.DB, _ *tables.TableOrganization, _ string, currentCount int64) QuotaStatus {
	return QuotaStatus{Used: currentCount, Limit: -1, Unlimited: true, Plan: "community"}
}

// active is the process-wide enforcer. Defaults to no-op; framework/billing
// replaces it in init() on the commercial build.
var active Enforcer = noopEnforcer{}

// SetDefault registers the process enforcer. Called from framework/billing.init.
// Not safe for concurrent use with the helpers; call once at startup.
func SetDefault(e Enforcer) {
	if e != nil {
		active = e
	}
}

// EnforceFeature rejects the request when the tenant's plan does not enable the
// requested boolean feature.
func EnforceFeature(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, featureKey string) error {
	return active.EnforceFeature(ctx, db, org, featureKey)
}

// EnforceQuota rejects the request when currentCount already meets/exceeds the
// tenant's plan limit for limitKey.
func EnforceQuota(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, limitKey string, currentCount int64) error {
	return active.EnforceQuota(ctx, db, org, limitKey, currentCount)
}

// IsFeatureEnabled reports the boolean feature state without raising an error.
func IsFeatureEnabled(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, featureKey string) bool {
	return active.IsFeatureEnabled(ctx, db, org, featureKey)
}

// GetQuotaStatus reports usage vs cap for a tenant without blocking.
func GetQuotaStatus(ctx context.Context, db *gorm.DB, org *tables.TableOrganization, limitKey string, currentCount int64) QuotaStatus {
	return active.GetQuotaStatus(ctx, db, org, limitKey, currentCount)
}
