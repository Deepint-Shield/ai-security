package modelcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// TestPricingEntry_AcceptsLiteLLMProviderField confirms the JSON decoder
// promotes LiteLLM's `litellm_provider` field into the DeepintShield-shaped
// `Provider` field. Without this, every LiteLLM row would land in the DB
// with an empty provider column and the UI would group them under
// "(unknown)".
func TestPricingEntry_AcceptsLiteLLMProviderField(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantProv string
	}{
		{
			name:     "deepintshield shape uses provider",
			raw:      `{"provider":"openai","mode":"chat","input_cost_per_token":0.0000001,"output_cost_per_token":0.0000003}`,
			wantProv: "openai",
		},
		{
			name:     "litellm shape uses litellm_provider",
			raw:      `{"litellm_provider":"anthropic","mode":"chat","input_cost_per_token":0.0000003,"output_cost_per_token":0.0000015}`,
			wantProv: "anthropic",
		},
		{
			name:     "explicit provider wins when both are present",
			raw:      `{"provider":"openai","litellm_provider":"anthropic","mode":"chat","input_cost_per_token":0.0000001,"output_cost_per_token":0.0000003}`,
			wantProv: "openai",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var entry PricingEntry
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &entry))
			assert.Equal(t, tc.wantProv, entry.Provider)
		})
	}
}

// TestNormalizeProvider_LiteLLMSpellings asserts the existing provider
// normaliser already collapses LiteLLM-style provider names (`vertex_ai`,
// `bedrock`, `cohere*`, `runwayml`) to the DeepintShield canonical values that
// the UI and cost-attribution code expect.
func TestNormalizeProvider_LiteLLMSpellings(t *testing.T) {
	cases := map[string]string{
		"vertex_ai":     string(schemas.Vertex),
		"vertex_ai-x":   string(schemas.Vertex),
		"google-vertex": string(schemas.Vertex),
		"bedrock":       string(schemas.Bedrock),
		"bedrock_us":    string(schemas.Bedrock),
		"cohere":        string(schemas.Cohere),
		"cohere_chat":   string(schemas.Cohere),
		"runwayml":      string(schemas.Runway),
		"openai":        "openai",
		"anthropic":     "anthropic",
	}
	for input, expected := range cases {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, expected, normalizeProvider(input))
		})
	}
}

// TestSyncPricing_PrimarySuccess_StampsDeepintShieldSource confirms the happy
// path tags the catalog with the deepintshield source marker so the admin UI
// can show provenance.
func TestSyncPricing_PrimarySuccess_StampsDeepintShieldSource(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gpt-4o-mini": map[string]any{
				"provider":              "openai",
				"mode":                  "chat",
				"input_cost_per_token":  0.00000015,
				"output_cost_per_token": 0.0000006,
			},
		})
	}))
	defer primary.Close()

	mc, store := newFallbackTestCatalog(t, primary.URL, "" /* fallback unused */)
	require.NoError(t, mc.syncPricing(context.Background()))

	source := mustReadSource(t, store)
	assert.Equal(t, PricingSyncSourcePrimary, source)
}

// TestSyncPricing_RecentCacheSkipsFallback locks in the 48h rule: when
// the primary fails but the DB cache is still recent, the worker must
// keep serving the cache rather than reach for LiteLLM.
func TestSyncPricing_RecentCacheSkipsFallback(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	fallbackCalls := 0
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer fallback.Close()

	mc, store := newFallbackTestCatalog(t, primary.URL, fallback.URL)
	// Pre-stamp a 1h-old successful sync so the cache is "fresh".
	stampLastSync(t, store, time.Now().UTC().Add(-time.Hour))

	require.NoError(t, mc.syncPricing(context.Background()))
	assert.Equal(t, 0, fallbackCalls, "fallback URL must not be hit while DB cache is fresher than the staleness threshold")
}

// TestSyncPricing_StaleCacheTriggersFallback covers the >48h path: the
// primary is down, the cache is older than the threshold, the LiteLLM
// fallback succeeds, and the catalog records the new source.
func TestSyncPricing_StaleCacheTriggersFallback(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"claude-3-5-sonnet": map[string]any{
				"litellm_provider":      "anthropic",
				"mode":                  "chat",
				"input_cost_per_token":  0.000003,
				"output_cost_per_token": 0.000015,
			},
		})
	}))
	defer fallback.Close()

	mc, store := newFallbackTestCatalog(t, primary.URL, fallback.URL)
	// 3 days old: well past the 48h threshold.
	stampLastSync(t, store, time.Now().UTC().Add(-72*time.Hour))

	require.NoError(t, mc.syncPricing(context.Background()))

	assert.Equal(t, PricingSyncSourceFallback, mustReadSource(t, store))

	// The LiteLLM row should have landed in the DB with the
	// DeepintShield-canonical provider value (`anthropic`) so UI lookups by
	// provider don't break.
	rows, err := store.GetModelPrices(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Equal(t, "claude-3-5-sonnet", rows[0].Model)
	assert.Equal(t, "anthropic", rows[0].Provider)
	assert.Equal(t, "chat", rows[0].Mode)
}

// TestSyncPricing_BothUpstreamsDown_KeepsDBCache asserts the terminal
// branch: when DeepintShield is down beyond the threshold AND LiteLLM also
// fails, we must NOT wipe the catalog - we keep whatever the DB already
// has and surface a high-severity log line via the caller.
func TestSyncPricing_BothUpstreamsDown_KeepsDBCache(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down too", http.StatusBadGateway)
	}))
	defer fallback.Close()

	mc, store := newFallbackTestCatalog(t, primary.URL, fallback.URL)
	stampLastSync(t, store, time.Now().UTC().Add(-72*time.Hour))

	// Seed one cached row so the terminal branch sees a populated cache.
	rate := 0.0000001
	require.NoError(t, store.UpsertModelPrices(context.Background(), &configstoreTables.TableModelPricing{
		Model:              "gpt-4o-mini",
		Provider:           "openai",
		Mode:               "chat",
		InputCostPerToken:  rate,
		OutputCostPerToken: rate,
	}))

	require.NoError(t, mc.syncPricing(context.Background()))

	rows, err := store.GetModelPrices(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1, "DB cache must survive when both upstreams fail")
	assert.Equal(t, "gpt-4o-mini", rows[0].Model)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newFallbackTestCatalog spins up a ModelCatalog backed by an in-memory
// SQLite ConfigStore wired via the test-only NewRDBConfigStoreFromDB
// helper - bypassing the heavy full-migration path so this test isn't
// blocked by an unrelated pre-existing SCIM-migration SQL bug.
func newFallbackTestCatalog(t *testing.T, primaryURL, fallbackURL string) (*ModelCatalog, configstore.ConfigStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "modelcatalog-test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&configstoreTables.TableGovernanceConfig{},
		&configstoreTables.TableModelPricing{},
		&configstoreTables.TableModelParameters{},
	))

	store := configstore.NewRDBConfigStoreFromDB(db, silentTestLogger{})

	mc := &ModelCatalog{
		configStore:                   store,
		logger:                        silentTestLogger{},
		pricingURL:                    primaryURL,
		pricingFallbackURL:            fallbackURL,
		pricingStaleFallbackThreshold: DefaultPricingStaleFallbackThreshold,
		pricingSyncInterval:           DefaultPricingSyncInterval,
		pricingData:                   make(map[string]configstoreTables.TableModelPricing),
		compiledOverrides:             make(map[schemas.ModelProvider][]compiledProviderPricingOverride),
		modelPool:                     make(map[schemas.ModelProvider][]string),
		unfilteredModelPool:           make(map[schemas.ModelProvider][]string),
		baseModelIndex:                make(map[string]string),
		done:                          make(chan struct{}),
	}
	return mc, store
}

// silentTestLogger satisfies schemas.Logger without producing output;
// keeps the test runs clean and avoids pulling the real logger package.
type silentTestLogger struct{}

func (silentTestLogger) Debug(string, ...any)                   {}
func (silentTestLogger) Info(string, ...any)                    {}
func (silentTestLogger) Warn(string, ...any)                    {}
func (silentTestLogger) Error(string, ...any)                   {}
func (silentTestLogger) Fatal(string, ...any)                   {}
func (silentTestLogger) SetLevel(schemas.LogLevel)              {}
func (silentTestLogger) SetOutputType(schemas.LoggerOutputType) {}
func (silentTestLogger) LogHTTPRequest(schemas.LogLevel, string) schemas.LogEventBuilder {
	return schemas.NoopLogEvent
}

func stampLastSync(t *testing.T, store configstore.ConfigStore, when time.Time) {
	t.Helper()
	require.NoError(t, store.UpdateConfig(context.Background(), &configstoreTables.TableGovernanceConfig{
		Key:   ConfigLastPricingSyncKey,
		Value: when.Format(time.RFC3339),
	}))
}

func mustReadSource(t *testing.T, store configstore.ConfigStore) string {
	t.Helper()
	config, err := store.GetConfig(context.Background(), ConfigLastPricingSyncSource)
	require.NoError(t, err)
	return config.Value
}
