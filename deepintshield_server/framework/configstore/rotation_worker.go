package configstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// virtualKeyRotationCheckInterval is how often the worker polls the DB for
// virtual keys whose next_rotation_at has elapsed. Rotation timestamps are
// day-granularity in practice; a 1-minute tick gives near-real-time response
// after the period expires without hammering the DB.
const virtualKeyRotationCheckInterval = 1 * time.Minute

// virtualKeyPrefix mirrors plugins/governance.VirtualKeyPrefix. Duplicated
// here so the configstore worker doesn't pull the governance package - that
// would create a cycle (governance already depends on configstore).
const virtualKeyPrefix = "sk-bf-"

// defaultRotationNoticeDays is the warning window applied when a VK has
// rotation enabled but RotationNoticeDays is left at zero - matches the
// SOC 2 §3.1 baseline expectation that key owners receive at least a
// week of heads-up before scheduled rotation.
const defaultRotationNoticeDays = 7

// startVirtualKeyRotationWorker kicks off a background goroutine that
// periodically rotates virtual keys whose rotation_period_days schedule
// has elapsed. Each rotation:
//
//  1. Generates a fresh sk-bf-... value via uuid.
//  2. Parks the current Value in PreviousValue with an expiry of
//     now + grace_period_days so existing clients keep working.
//  3. Updates LastRotatedAt + NextRotationAt.
//  4. Emails the tenant owner once before rotation (notice window) and
//     once on completion.
//
// Returns a stop function for graceful shutdown.
func startVirtualKeyRotationWorker(parent context.Context, db *gorm.DB, store *RDBConfigStore) func() {
	// Never run the background ticker under `go test`. Unit tests create many
	// short-lived stores via the sqlite/postgres constructors and discard this
	// stop func, leaking 1-minute tickers that hammer torn-down DBs (panics)
	// and keep opening connections (pool exhaustion / hangs across the package).
	// Production processes are long-lived and take this path normally.
	if testing.Testing() {
		return func() {}
	}
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(virtualKeyRotationCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// If the tick panics - e.g. a unit-test store was closed while its
				// worker kept ticking, leaving a nil/closed conn pool - recover and
				// STOP this worker rather than crash the whole process. Production
				// stores live for the process lifetime, so this only trips in tests
				// (where the constructor discards the stop func / uses a Background
				// context).
				if !runRotationTick(parent, db, store) {
					return
				}
			case <-parent.Done():
				return
			case <-stopCh:
				return
			}
		}
	}()
	return func() { close(stopCh) }
}

// runRotationTick executes one rotation cycle, recovering from a panic (a
// torn-down DB) so a background worker can never crash the process. Returns
// false when the cycle panicked, signalling the caller to stop the worker.
func runRotationTick(parent context.Context, db *gorm.DB, store *RDBConfigStore) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			if store != nil && store.logger != nil {
				store.logger.Warn("virtual key rotation worker stopped after panic (DB likely torn down)")
			}
			ok = false
		}
	}()
	if err := notifyUpcomingVirtualKeyRotations(parent, db, store); err != nil {
		if store != nil && store.logger != nil {
			store.logger.Warn("virtual key rotation worker (notify): " + err.Error())
		}
	}
	if err := rotateDueVirtualKeys(parent, db, store); err != nil {
		if store != nil && store.logger != nil {
			store.logger.Warn("virtual key rotation worker: " + err.Error())
		}
	}
	return true
}

// notifyUpcomingVirtualKeyRotations finds VKs whose next_rotation_at is
// within the per-key notice window AND that haven't been notified for
// this cycle yet, and dispatches the heads-up email. Stamps
// rotation_notified_at so subsequent ticks inside the window stay quiet.
//
// Bounded by maxNotifyBatch so a backlog of overdue notifications can't
// stall the tick - leftovers get sent the next minute.
func notifyUpcomingVirtualKeyRotations(ctx context.Context, db *gorm.DB, store *RDBConfigStore) error {
	const maxNotifyBatch = 100
	now := time.Now().UTC()

	var candidates []tables.TableVirtualKey
	if err := db.WithContext(ctx).
		Where("rotation_period_days IS NOT NULL AND rotation_period_days > 0").
		Where("next_rotation_at IS NOT NULL AND next_rotation_at > ?", now).
		Where("rotation_notified_at IS NULL").
		Limit(maxNotifyBatch).
		Find(&candidates).Error; err != nil {
		return err
	}

	for i := range candidates {
		vk := &candidates[i]
		if vk.NextRotationAt == nil {
			continue
		}
		notice := vk.RotationNoticeDays
		if notice <= 0 {
			notice = defaultRotationNoticeDays
		}
		windowOpensAt := vk.NextRotationAt.Add(-time.Duration(notice) * 24 * time.Hour)
		if now.Before(windowOpensAt) {
			continue
		}

		email, name := resolveRotationRecipient(ctx, db, vk)
		if email != "" {
			grace := vk.RotationGracePeriodDays
			if grace < 0 {
				grace = 0
			}
			if err := notifyVirtualKeyRotationUpcoming(email, name, vk.Name, *vk.NextRotationAt, grace); err != nil {
				if store != nil && store.logger != nil {
					store.logger.Warn("virtual key rotation worker: pre-rotation email failed for VK " + vk.ID + ": " + err.Error())
				}
				// Don't stamp NotifiedAt on send failure - let the next tick retry.
				continue
			}
		}

		// Even when the email isn't deliverable (no recipient resolvable or
		// SMTP not configured), stamp NotifiedAt so the tick doesn't keep
		// re-evaluating the same VK every minute. The dashboard surfaces
		// rotation_notified_at so admins can see we acknowledged the window.
		notifiedAt := time.Now().UTC()
		if err := db.WithContext(ctx).
			Model(&tables.TableVirtualKey{}).
			Where("id = ?", vk.ID).
			Update("rotation_notified_at", notifiedAt).Error; err != nil {
			if store != nil && store.logger != nil {
				store.logger.Warn("virtual key rotation worker: failed to stamp rotation_notified_at for VK " + vk.ID + ": " + err.Error())
			}
		}
	}
	return nil
}

// rotateDueVirtualKeys finds virtual keys whose next_rotation_at <= now()
// and rotates them in a transaction. Bounded by maxBatchSize so a flood of
// overdue rotations can't stall the worker; the next tick will pick up
// stragglers.
func rotateDueVirtualKeys(ctx context.Context, db *gorm.DB, store *RDBConfigStore) error {
	const maxBatchSize = 50
	now := time.Now().UTC()

	var due []tables.TableVirtualKey
	if err := db.WithContext(ctx).
		Where("rotation_period_days IS NOT NULL AND rotation_period_days > 0").
		Where("next_rotation_at IS NOT NULL AND next_rotation_at <= ?", now).
		Limit(maxBatchSize).
		Find(&due).Error; err != nil {
		return err
	}
	if len(due) == 0 {
		return nil
	}

	for i := range due {
		vk := due[i]
		// Generate the new key value and stash the prior one. Hashing +
		// encryption happen in the BeforeSave hook.
		vk.PreviousValue = vk.Value
		grace := vk.RotationGracePeriodDays
		if grace < 0 {
			grace = 0
		}
		if grace > 0 {
			exp := now.Add(time.Duration(grace) * 24 * time.Hour)
			vk.PreviousValueExpiresAt = &exp
		} else {
			vk.PreviousValueExpiresAt = &now
		}
		vk.Value = virtualKeyPrefix + uuid.NewString()
		vk.LastRotatedAt = &now
		if vk.RotationPeriodDays != nil && *vk.RotationPeriodDays > 0 {
			nxt := now.Add(time.Duration(*vk.RotationPeriodDays) * 24 * time.Hour)
			vk.NextRotationAt = &nxt
		} else {
			vk.NextRotationAt = nil
		}
		// Reset the per-cycle notification stamp so the next pre-rotation
		// notice fires in the new window - without this, the worker would
		// silently skip warnings for every cycle after the first.
		vk.RotationNotifiedAt = nil
		if err := db.WithContext(ctx).Save(&vk).Error; err != nil {
			if store != nil && store.logger != nil {
				store.logger.Warn("virtual key rotation worker: failed to rotate VK " + vk.ID + ": " + err.Error())
			}
			continue
		}
		if store != nil && store.logger != nil {
			store.logger.Info("virtual key rotation worker: rotated VK " + vk.ID)
		}

		// Best-effort post-rotation email. Email failures don't roll back
		// the rotation - the key is already replaced; the worst case is the
		// owner has to discover the new value via the dashboard's standard
		// "rotated_at" timestamp instead of an inbox ping.
		email, name := resolveRotationRecipient(ctx, db, &vk)
		if email != "" {
			if err := notifyVirtualKeyRotationCompleted(email, name, vk.Name, now, vk.PreviousValueExpiresAt); err != nil {
				if store != nil && store.logger != nil {
					store.logger.Warn("virtual key rotation worker: rotation-completed email failed for VK " + vk.ID + ": " + err.Error())
				}
			}
		}
	}
	return nil
}
