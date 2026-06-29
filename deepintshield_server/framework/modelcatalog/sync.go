package modelcatalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"gorm.io/gorm"
)

// checkAndSyncPricing determines if pricing data needs to be synced and performs the sync if needed.
// It syncs pricing data in the following scenarios:
//   - No config store available (returns early with no error)
//   - No previous sync record exists
//   - Previous sync timestamp is invalid/corrupted
//   - Sync interval has elapsed since last successful sync
func (mc *ModelCatalog) checkAndSyncPricing(ctx context.Context) error {
	// Skip sync if no config store is available
	if mc.configStore == nil {
		return nil
	}

	// Determine if sync is needed and perform it
	needsSync, reason := mc.shouldSyncPricing(ctx)
	if needsSync {
		mc.logger.Debug("pricing sync needed: %s", reason)
		return mc.syncPricing(ctx)
	}

	return nil
}

// shouldSyncPricing determines if pricing data should be synced and returns the reason
func (mc *ModelCatalog) shouldSyncPricing(ctx context.Context) (bool, string) {
	config, err := mc.configStore.GetConfig(ctx, ConfigLastPricingSyncKey)
	if err != nil {
		return true, "no previous sync record found"
	}

	lastSync, err := time.Parse(time.RFC3339, config.Value)
	if err != nil {
		mc.logger.Warn("invalid last sync timestamp: %v", err)
		return true, "corrupted sync timestamp"
	}

	if time.Since(lastSync) >= mc.getPricingSyncInterval() {
		return true, "sync interval elapsed"
	}

	return false, "sync not needed"
}

// syncPricing syncs pricing data from URL to database and updates cache.
//
// Three-tier resilience (per §3.1 cost/billing freshness):
//
//  1. Try the primary URL (default: DeepintShield datasheet).
//  2. If the primary fails AND the DB cache is fresher than
//     pricingStaleFallbackThreshold (default 48h), keep serving the DB -
//     a single-day DeepintShield blip shouldn't drag the gateway into a
//     fallback URL it doesn't need.
//  3. If the primary fails AND the DB cache is stale beyond the threshold,
//     try the LiteLLM fallback URL (open-source upstream, same shape).
//  4. If both upstreams fail, keep serving whatever the DB already has
//     and surface a high-severity log; only return an error if there's
//     nothing in the DB at all.
//
// The "which source did this catalog come from" question is answered by the
// ConfigLastPricingSyncSource governance-config row, stamped on every
// successful sync so the admin UI / audit log can show the provenance.
func (mc *ModelCatalog) syncPricing(ctx context.Context) error {
	mc.logger.Debug("starting pricing data synchronization for governance")
	if mc.shouldSyncPricingFunc != nil {
		if !mc.shouldSyncPricingFunc(ctx) {
			mc.logger.Debug("pricing sync cancelled by custom function")
			return nil
		}
	}

	primaryURL := mc.getPricingURL()
	pricingData, err := mc.loadPricingFromURLAt(ctx, primaryURL)
	source := PricingSyncSourcePrimary
	if err != nil {
		mc.logger.Warn("pricing sync: primary URL %s failed: %v", primaryURL, err)
		// Decide whether the DB cache is still recent enough to ride
		// out the outage without invoking the open-source fallback.
		staleness, haveLast := mc.pricingCacheStaleness(ctx)
		threshold := mc.getPricingStaleFallbackThreshold()
		if haveLast && staleness < threshold {
			mc.logger.Warn("pricing sync: DB cache is %s old (< %s threshold); skipping fallback URL and continuing with cache", staleness.Round(time.Second), threshold)
			return nil
		}
		fallbackURL := mc.getPricingFallbackURL()
		if fallbackURL == "" {
			return mc.fallbackToDatabaseOrError(ctx, err)
		}
		if haveLast {
			mc.logger.Warn("pricing sync: DB cache is %s old (>= %s threshold); attempting fallback URL %s", staleness.Round(time.Second), threshold, fallbackURL)
		} else {
			mc.logger.Warn("pricing sync: no prior successful sync recorded; attempting fallback URL %s", fallbackURL)
		}
		pricingData, err = mc.loadPricingFromURLAt(ctx, fallbackURL)
		if err != nil {
			mc.logger.Error("pricing sync: fallback URL also failed: %v", err)
			return mc.fallbackToDatabaseOrError(ctx, err)
		}
		source = PricingSyncSourceFallback
		mc.logger.Warn("pricing sync: using fallback source %s (%d records) - primary URL is down and DB cache exceeded staleness threshold", source, len(pricingData))
	}

	// Update database in transaction
	err = mc.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
		// Deduplicate and insert new pricing data
		seen := make(map[string]bool)
		for modelKey, entry := range pricingData {
			pricing := convertPricingDataToTableModelPricing(modelKey, entry)
			// Create composite key for deduplication
			key := makeKey(pricing.Model, pricing.Provider, pricing.Mode)
			// Skip if already seen
			if exists, ok := seen[key]; ok && exists {
				continue
			}
			// Mark as seen
			seen[key] = true
			if err := mc.configStore.UpsertModelPrices(ctx, &pricing, tx); err != nil {
				return fmt.Errorf("failed to create pricing record for model %s: %w", pricing.Model, err)
			}
		}

		// Clear seen map
		seen = nil

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to sync pricing data to database: %w", err)
	}

	// Update last sync time + source
	now := time.Now().UTC()
	if err := mc.configStore.UpdateConfig(ctx, &configstoreTables.TableGovernanceConfig{
		Key:   ConfigLastPricingSyncKey,
		Value: now.Format(time.RFC3339),
	}); err != nil {
		mc.logger.Warn("Failed to update last sync time: %v", err)
	}
	if err := mc.configStore.UpdateConfig(ctx, &configstoreTables.TableGovernanceConfig{
		Key:   ConfigLastPricingSyncSource,
		Value: source,
	}); err != nil {
		mc.logger.Warn("Failed to update last sync source: %v", err)
	}

	// Reload cache from database
	if err := mc.loadPricingFromDatabase(ctx); err != nil {
		return fmt.Errorf("failed to reload pricing cache: %w", err)
	}

	mc.logger.Info("successfully synced %d pricing records from %s", len(pricingData), source)
	return nil
}

// loadPricingFromURL preserves the legacy single-URL call site (used by
// loadPricingIntoMemory when there is no config store). Delegates to the
// URL-parameterised variant against the primary URL.
func (mc *ModelCatalog) loadPricingFromURL(ctx context.Context) (map[string]PricingEntry, error) {
	return mc.loadPricingFromURLAt(ctx, mc.getPricingURL())
}

// loadPricingFromURLAt fetches and decodes the pricing catalog from the
// supplied URL. Kept generic so the same code path handles both the
// primary (DeepintShield) and fallback (LiteLLM) sources - the JSON shape is the
// same once PricingEntry.UnmarshalJSON normalises litellm_provider.
func (mc *ModelCatalog) loadPricingFromURLAt(ctx context.Context, url string) (map[string]PricingEntry, error) {
	if url == "" {
		return nil, fmt.Errorf("pricing URL is empty")
	}
	client := &http.Client{Timeout: DefaultPricingTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download pricing data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download pricing data: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read pricing data response: %w", err)
	}

	var pricingData map[string]PricingEntry
	if err := json.Unmarshal(data, &pricingData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pricing data: %w", err)
	}

	// LiteLLM ships a "sample_spec" template row at the top of the file
	// that isn't a real model - drop it so it doesn't pollute the catalog.
	delete(pricingData, "sample_spec")

	mc.logger.Debug("successfully downloaded and parsed %d pricing records from %s", len(pricingData), url)
	return pricingData, nil
}

// pricingCacheStaleness returns how long it has been since the last
// successful pricing sync (per ConfigLastPricingSyncKey). The boolean
// result is false when no prior sync is recorded - callers treat that as
// "treat the DB as effectively infinitely stale".
func (mc *ModelCatalog) pricingCacheStaleness(ctx context.Context) (time.Duration, bool) {
	if mc.configStore == nil {
		return 0, false
	}
	config, err := mc.configStore.GetConfig(ctx, ConfigLastPricingSyncKey)
	if err != nil {
		return 0, false
	}
	lastSync, err := time.Parse(time.RFC3339, config.Value)
	if err != nil {
		return 0, false
	}
	return time.Since(lastSync), true
}

// fallbackToDatabaseOrError is the terminal "both URLs failed" path. If the
// DB still carries pricing rows we log loudly and let the caller keep using
// them; otherwise we surface the upstream error so init / force-reload can
// fail fast instead of starting up with an empty catalog.
func (mc *ModelCatalog) fallbackToDatabaseOrError(ctx context.Context, upstreamErr error) error {
	if mc.configStore == nil {
		return fmt.Errorf("failed to load pricing data and no DB cache available: %w", upstreamErr)
	}
	pricingRecords, dbErr := mc.configStore.GetModelPrices(ctx)
	if dbErr != nil {
		return fmt.Errorf("failed to load pricing data (%w) and failed to read DB cache (%v)", upstreamErr, dbErr)
	}
	if len(pricingRecords) > 0 {
		mc.logger.Error("pricing sync: all upstream URLs failed; continuing with %d cached rows from DB: %v", len(pricingRecords), upstreamErr)
		return nil
	}
	return fmt.Errorf("failed to load pricing data and DB cache is empty: %w", upstreamErr)
}

// loadPricingIntoMemory loads pricing data from URL into memory cache
func (mc *ModelCatalog) loadPricingIntoMemory(ctx context.Context) error {
	pricingData, err := mc.loadPricingFromURL(ctx)
	if err != nil {
		return fmt.Errorf("failed to load pricing data from URL: %w", err)
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Clear and rebuild the pricing map
	mc.pricingData = make(map[string]configstoreTables.TableModelPricing, len(pricingData))
	for modelKey, entry := range pricingData {
		pricing := convertPricingDataToTableModelPricing(modelKey, entry)
		key := makeKey(pricing.Model, pricing.Provider, pricing.Mode)
		mc.pricingData[key] = pricing
	}
	mc.rebuildPricingAliasIndexLocked()

	return nil
}

// loadPricingFromDatabase loads pricing data from database into memory cache
func (mc *ModelCatalog) loadPricingFromDatabase(ctx context.Context) error {
	if mc.configStore == nil {
		return nil
	}

	pricingRecords, err := mc.configStore.GetModelPrices(ctx)
	if err != nil {
		return fmt.Errorf("failed to load pricing from database: %w", err)
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Clear and rebuild the pricing map
	mc.pricingData = make(map[string]configstoreTables.TableModelPricing, len(pricingRecords))
	for _, pricing := range pricingRecords {
		key := makeKey(pricing.Model, pricing.Provider, pricing.Mode)
		mc.pricingData[key] = pricing
	}
	mc.rebuildPricingAliasIndexLocked()

	mc.logger.Debug("loaded %d pricing records into cache (alias entries: %d)", len(pricingRecords), len(mc.pricingAlias))
	return nil
}

// rebuildPricingAliasIndexLocked walks every entry in pricingData and stamps
// its canonical-form key into pricingAlias. Caller must hold mc.mu in write
// mode. Last-write-wins on collisions: if two pricing rows canonicalize to
// the same key (e.g. multiple Anthropic snapshots), the most recently
// inserted one is preferred - pricing data is generally append-only and
// providers ship the latest at the top of the catalog.
func (mc *ModelCatalog) rebuildPricingAliasIndexLocked() {
	mc.pricingAlias = make(map[string]string, len(mc.pricingData))
	for fullKey, pricing := range mc.pricingData {
		aliasKey := canonicalAliasKey(pricing.Model, pricing.Provider, pricing.Mode)
		if aliasKey == "" {
			continue
		}
		// Don't shadow an exact-match row by its own canonical form.
		// The alias only fires on miss, so a row whose canonical key
		// equals its full key is already covered by pricingData.
		if aliasKey == fullKey {
			continue
		}
		mc.pricingAlias[aliasKey] = fullKey
	}
}

// startSyncWorker starts the background sync worker
func (mc *ModelCatalog) startSyncWorker(ctx context.Context) {
	// Use a ticker that checks every hour, but only sync when needed
	mc.syncTicker = time.NewTicker(1 * time.Hour)
	mc.wg.Add(1)
	go mc.syncWorker(ctx)
}

// syncTick performs a single sync tick with proper lock management
func (mc *ModelCatalog) syncTick(ctx context.Context) {
	if mc.distributedLockManager == nil {
		if err := mc.checkAndSyncPricing(ctx); err != nil {
			mc.logger.Error("background pricing sync failed: %v", err)
		}
		if err := mc.checkAndSyncModelParameters(ctx); err != nil {
			mc.logger.Error("background model parameters sync failed: %v", err)
		}
		return
	}
	lock, err := mc.distributedLockManager.NewLock("model_catalog_pricing_sync")
	if err != nil {
		mc.logger.Error("failed to create model catalog pricing sync lock: %v", err)
		return
	}
	if err := lock.Lock(ctx); err != nil {
		mc.logger.Error("failed to acquire model catalog pricing sync lock: %v", err)
		return
	}
	defer lock.Unlock(ctx)
	if err := mc.checkAndSyncPricing(ctx); err != nil {
		mc.logger.Error("background pricing sync failed: %v", err)
	}
	if err := mc.checkAndSyncModelParameters(ctx); err != nil {
		mc.logger.Error("background model parameters sync failed: %v", err)
	}
}

// syncWorker runs the background sync check
func (mc *ModelCatalog) syncWorker(ctx context.Context) {
	defer mc.wg.Done()
	defer mc.syncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-mc.syncTicker.C:
			mc.syncTick(ctx)
		case <-mc.done:
			return
		}
	}
}

// --- Model Parameters sync ---

// checkAndSyncModelParameters determines if model parameters data needs to be synced and performs the sync if needed.
func (mc *ModelCatalog) checkAndSyncModelParameters(ctx context.Context) error {
	if mc.configStore == nil {
		return nil
	}

	needsSync, reason := mc.shouldSyncModelParameters(ctx)
	if needsSync {
		mc.logger.Debug("model parameters sync needed: %s", reason)
		return mc.syncModelParameters(ctx)
	}

	return nil
}

// shouldSyncModelParameters determines if model parameters data should be synced
func (mc *ModelCatalog) shouldSyncModelParameters(ctx context.Context) (bool, string) {
	config, err := mc.configStore.GetConfig(ctx, ConfigLastParamsSyncKey)
	if err != nil {
		return true, "no previous model parameters sync record found"
	}

	lastSync, err := time.Parse(time.RFC3339, config.Value)
	if err != nil {
		mc.logger.Warn("invalid last model parameters sync timestamp: %v", err)
		return true, "corrupted sync timestamp"
	}

	if time.Since(lastSync) >= mc.getPricingSyncInterval() {
		return true, "sync interval elapsed"
	}

	return false, "sync not needed"
}

// syncModelParameters syncs model parameters data from URL into memory cache
func (mc *ModelCatalog) syncModelParameters(ctx context.Context) error {
	mc.logger.Debug("model-parameters-sync: starting model parameters synchronization")

	paramsData, err := mc.loadModelParametersFromURL(ctx)
	if err != nil {
		return fmt.Errorf("failed to load model parameters from URL: %w", err)
	}

	// Persist to database if config store is available
	if mc.configStore != nil {
		err = mc.configStore.ExecuteTransaction(ctx, func(tx *gorm.DB) error {
			for model, data := range paramsData {
				params := &configstoreTables.TableModelParameters{
					Model: model,
					Data:  string(data),
				}
				if err := mc.configStore.UpsertModelParameters(ctx, params, tx); err != nil {
					return fmt.Errorf("failed to upsert model parameters for model %s: %w", model, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("model-parameters-sync: failed to sync model parameters to database: %w", err)
		}
	}

	// Update last sync time if config store is available
	if mc.configStore != nil {
		config := &configstoreTables.TableGovernanceConfig{
			Key:   ConfigLastParamsSyncKey,
			Value: time.Now().Format(time.RFC3339),
		}
		if err := mc.configStore.UpdateConfig(ctx, config); err != nil {
			mc.logger.Warn("model-parameters-sync: failed to update last model parameters sync time: %v", err)
		}
	}

	mc.logger.Info("model-parameters-sync: successfully synced %d model parameters records", len(paramsData))
	return nil
}

// loadModelParametersFromURL loads model parameters data from the remote URL
func (mc *ModelCatalog) loadModelParametersFromURL(ctx context.Context) (map[string]json.RawMessage, error) {
	// No model-parameters source configured: skip the sync rather than dial a
	// dead/empty host (which would block the worker and any test that inits a
	// catalog). Returns an empty set so the caller is a no-op.
	if DefaultModelParametersURL == "" {
		return map[string]json.RawMessage{}, nil
	}
	client := &http.Client{}
	client.Timeout = DefaultModelParametersTimeout
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DefaultModelParametersURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download model parameters data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download model parameters data: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read model parameters response: %w", err)
	}

	var paramsData map[string]json.RawMessage
	if err := json.Unmarshal(data, &paramsData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal model parameters data: %w", err)
	}

	mc.logger.Debug("model-parameters-sync: successfully downloaded and parsed %d model parameters records", len(paramsData))
	return paramsData, nil
}
