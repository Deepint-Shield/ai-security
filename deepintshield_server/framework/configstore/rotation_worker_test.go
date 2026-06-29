package configstore

import (
	"context"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(v int) *int { return &v }

// TestNotifyUpcomingVirtualKeyRotations_StampsWhenWindowOpen confirms the
// worker stamps RotationNotifiedAt for VKs that have entered their notice
// window. SMTP isn't configured in the test env, so no email actually
// fires - the stamp itself is the contract: once stamped, the next tick
// won't re-evaluate until the next rotation cycle.
func TestNotifyUpcomingVirtualKeyRotations_StampsWhenWindowOpen(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "owner@example.com")

	now := time.Now().UTC()
	nextRotation := now.Add(2 * 24 * time.Hour) // 2 days out, inside 7-day window

	vk := &tables.TableVirtualKey{
		ID:                 "vk-notice-in-window",
		TenantID:           "owner@example.com",
		Name:               "Within Notice Window",
		Value:              "sk-bf-original",
		IsActive:           true,
		RotationPeriodDays: intPtr(90),
		RotationNoticeDays: 7,
		NextRotationAt:     &nextRotation,
	}
	require.NoError(t, store.db.WithContext(ctx).Create(vk).Error)

	require.NoError(t, notifyUpcomingVirtualKeyRotations(ctx, store.db, store))

	var reloaded tables.TableVirtualKey
	require.NoError(t, store.db.WithContext(ctx).Where("id = ?", vk.ID).Take(&reloaded).Error)
	require.NotNil(t, reloaded.RotationNotifiedAt, "expected RotationNotifiedAt to be stamped after entering the notice window")
}

// TestNotifyUpcomingVirtualKeyRotations_SkipsOutsideWindow confirms a VK
// whose rotation is far in the future doesn't get notified prematurely.
func TestNotifyUpcomingVirtualKeyRotations_SkipsOutsideWindow(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "owner@example.com")

	now := time.Now().UTC()
	nextRotation := now.Add(30 * 24 * time.Hour) // 30 days out - outside 7-day window

	vk := &tables.TableVirtualKey{
		ID:                 "vk-notice-out-of-window",
		TenantID:           "owner@example.com",
		Name:               "Outside Notice Window",
		Value:              "sk-bf-original",
		IsActive:           true,
		RotationPeriodDays: intPtr(90),
		RotationNoticeDays: 7,
		NextRotationAt:     &nextRotation,
	}
	require.NoError(t, store.db.WithContext(ctx).Create(vk).Error)

	require.NoError(t, notifyUpcomingVirtualKeyRotations(ctx, store.db, store))

	var reloaded tables.TableVirtualKey
	require.NoError(t, store.db.WithContext(ctx).Where("id = ?", vk.ID).Take(&reloaded).Error)
	require.Nil(t, reloaded.RotationNotifiedAt, "expected RotationNotifiedAt to remain NULL outside the notice window")
}

// TestNotifyUpcomingVirtualKeyRotations_DoesNotResendOncePerCycle confirms
// a VK that has already been notified for this rotation cycle is skipped
// even if the tick fires again before the rotation lands.
func TestNotifyUpcomingVirtualKeyRotations_DoesNotResendOncePerCycle(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "owner@example.com")

	now := time.Now().UTC()
	alreadyNotified := now.Add(-time.Hour)
	nextRotation := now.Add(24 * time.Hour) // 1 day out - inside notice window

	vk := &tables.TableVirtualKey{
		ID:                 "vk-already-notified",
		TenantID:           "owner@example.com",
		Name:               "Already Notified",
		Value:              "sk-bf-original",
		IsActive:           true,
		RotationPeriodDays: intPtr(90),
		RotationNoticeDays: 7,
		NextRotationAt:     &nextRotation,
		RotationNotifiedAt: &alreadyNotified,
	}
	require.NoError(t, store.db.WithContext(ctx).Create(vk).Error)

	require.NoError(t, notifyUpcomingVirtualKeyRotations(ctx, store.db, store))

	var reloaded tables.TableVirtualKey
	require.NoError(t, store.db.WithContext(ctx).Where("id = ?", vk.ID).Take(&reloaded).Error)
	require.NotNil(t, reloaded.RotationNotifiedAt)
	assert.Equal(t, alreadyNotified.Truncate(time.Second), reloaded.RotationNotifiedAt.Truncate(time.Second),
		"RotationNotifiedAt should not be re-stamped within the same rotation cycle")
}

// TestRotateDueVirtualKeys_ClearsNotifiedAt confirms the rotation path
// resets RotationNotifiedAt so the next cycle's pre-rotation notice can
// fire - without this, every cycle after the first would silently skip
// the warning email.
func TestRotateDueVirtualKeys_ClearsNotifiedAt(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := withTenant(context.Background(), "owner@example.com")

	now := time.Now().UTC()
	previousRotation := now.Add(-time.Hour)
	notifiedAt := now.Add(-7 * 24 * time.Hour)

	vk := &tables.TableVirtualKey{
		ID:                      "vk-due-now",
		TenantID:                "owner@example.com",
		Name:                    "Due Now",
		Value:                   "sk-bf-old-value",
		IsActive:                true,
		RotationPeriodDays:      intPtr(90),
		RotationGracePeriodDays: 3,
		RotationNoticeDays:      7,
		NextRotationAt:          &previousRotation,
		RotationNotifiedAt:      &notifiedAt,
	}
	require.NoError(t, store.db.WithContext(ctx).Create(vk).Error)

	require.NoError(t, rotateDueVirtualKeys(ctx, store.db, store))

	var reloaded tables.TableVirtualKey
	require.NoError(t, store.db.WithContext(ctx).Where("id = ?", vk.ID).Take(&reloaded).Error)
	assert.NotEqual(t, "sk-bf-old-value", reloaded.Value, "VK value should have been rotated")
	assert.NotEmpty(t, reloaded.PreviousValue, "previous value should have been parked")
	require.NotNil(t, reloaded.PreviousValueExpiresAt)
	require.NotNil(t, reloaded.LastRotatedAt)
	require.NotNil(t, reloaded.NextRotationAt)
	assert.True(t, reloaded.NextRotationAt.After(now), "NextRotationAt should advance into the future")
	assert.Nil(t, reloaded.RotationNotifiedAt, "RotationNotifiedAt should reset so the next cycle's notice fires")
}

// TestResolveRotationRecipient_PrefersUserRecordByTenantEmail confirms the
// resolver picks up the user row when tenant_id is an email so the
// notification carries a friendly display name.
func TestResolveRotationRecipient_PrefersUserRecordByTenantEmail(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.db.Create(&tables.TableAuthUser{
		ID:        "user-1",
		Email:     "owner@example.com",
		FirstName: "Alice",
		LastName:  "Owner",
	}).Error)

	vk := &tables.TableVirtualKey{TenantID: "owner@example.com"}
	email, name := resolveRotationRecipient(ctx, store.db, vk)
	assert.Equal(t, "owner@example.com", email)
	assert.Equal(t, "Alice Owner", name)
}

// TestResolveRotationRecipient_FallsBackToTenantEmail confirms an
// email-keyed tenant with no matching user row still gets a notification
// at the tenant address itself rather than going silent.
func TestResolveRotationRecipient_FallsBackToTenantEmail(t *testing.T) {
	store := setupRDBTestStore(t)
	ctx := context.Background()

	vk := &tables.TableVirtualKey{TenantID: "lonely@example.com"}
	email, name := resolveRotationRecipient(ctx, store.db, vk)
	assert.Equal(t, "lonely@example.com", email)
	assert.Equal(t, "lonely@example.com", name)
}
