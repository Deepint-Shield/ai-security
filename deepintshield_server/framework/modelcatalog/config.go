package modelcatalog

import "time"

const (
	DefaultPricingSyncInterval    = 24 * time.Hour
	ConfigLastPricingSyncKey      = "LastModelPricingSync"
	ConfigLastPricingSyncSource   = "LastModelPricingSyncSource"
	ConfigLastParamsSyncKey       = "LastModelParametersSync"
	// DefaultPricingURL is the upstream LiteLLM datasheet - the de-facto
	// open-source pricing catalog every gateway mirrors. Using a real,
	// responsive public source (instead of a hosted endpoint) keeps the
	// open-source gateway's cost catalog populated and avoids hanging the
	// pricing sync at startup when no hosted datasheet is reachable.
	DefaultPricingURL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
	// DefaultModelParametersURL is empty by default: there is no public
	// model-parameters datasheet, so the sync is skipped unless an operator
	// configures a URL. (An empty URL makes loadModelParametersFromURL a no-op
	// rather than dialing a dead host and blocking.)
	DefaultModelParametersURL = ""
	DefaultPricingTimeout         = 45 * time.Second
	DefaultModelParametersTimeout = 45 * time.Second
	// DefaultPricingFallbackURL is the upstream LiteLLM datasheet - same
	// shape as the DeepintShield one (LiteLLM is the de-facto open-source pricing
	// catalog every gateway mirrors). Used only when the primary URL has
	// been unreachable longer than DefaultPricingStaleFallbackThreshold so
	// admin-side cost / billing surfaces don't drift indefinitely on a
	// DeepintShield outage.
	DefaultPricingFallbackURL            = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
	DefaultPricingStaleFallbackThreshold = 48 * time.Hour
	// Source markers stamped on ConfigLastPricingSyncSource so the admin
	// UI and audit log can tell which upstream produced the current cache.
	PricingSyncSourcePrimary  = "deepintshield"
	PricingSyncSourceFallback = "litellm"
)

// Config is the model pricing configuration.
type Config struct {
	PricingURL          *string        `json:"pricing_url,omitempty"`
	PricingSyncInterval *time.Duration `json:"pricing_sync_interval,omitempty"`
	// PricingFallbackURL overrides DefaultPricingFallbackURL (the LiteLLM
	// datasheet). Used only after PricingStaleFallbackThreshold has
	// elapsed since the last successful primary-URL sync.
	PricingFallbackURL *string `json:"pricing_fallback_url,omitempty"`
	// PricingStaleFallbackThreshold overrides DefaultPricingStaleFallbackThreshold
	// (48h). Below this window of staleness the worker keeps serving the
	// DB-cached catalog; beyond it, the fallback URL is tried.
	PricingStaleFallbackThreshold *time.Duration `json:"pricing_stale_fallback_threshold,omitempty"`
}
