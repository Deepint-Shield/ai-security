package deepintshield

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

func makeTestKeys(ids ...string) []schemas.Key {
	keys := make([]schemas.Key, len(ids))
	for i, id := range ids {
		keys[i] = schemas.Key{
			ID:     id,
			Name:   id,
			Weight: 1.0,
		}
	}
	return keys
}

func makeTestContext() *schemas.DeepIntShieldContext {
	return schemas.NewDeepIntShieldContext(context.Background(), time.Now().Add(10*time.Second))
}

// --- RoundRobinKeySelector ---

func TestRoundRobinKeySelector_EmptyKeys(t *testing.T) {
	ctx := makeTestContext()
	_, err := RoundRobinKeySelector(ctx, nil, "openai", "gpt-4")
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
}

func TestRoundRobinKeySelector_SingleKey(t *testing.T) {
	ctx := makeTestContext()
	keys := makeTestKeys("key1")
	selected, err := RoundRobinKeySelector(ctx, keys, "openai", "gpt-4-single")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selected.ID != "key1" {
		t.Fatalf("expected key1, got %s", selected.ID)
	}
}

func TestRoundRobinKeySelector_DistributesEvenly(t *testing.T) {
	keys := makeTestKeys("a", "b", "c")
	counts := map[string]int{}
	n := 300

	for i := 0; i < n; i++ {
		ctx := makeTestContext()
		selected, err := RoundRobinKeySelector(ctx, keys, "openai", "gpt-4-rr-even")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		counts[selected.ID]++
	}

	for _, id := range []string{"a", "b", "c"} {
		if counts[id] != 100 {
			t.Errorf("expected key %s to be selected 100 times, got %d", id, counts[id])
		}
	}
}

// --- LeastLoadKeySelector ---

func TestLeastLoadKeySelector_EmptyKeys(t *testing.T) {
	ctx := makeTestContext()
	_, err := LeastLoadKeySelector(ctx, nil, "openai", "gpt-4")
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
}

func TestLeastLoadKeySelector_SingleKey(t *testing.T) {
	ctx := makeTestContext()
	keys := makeTestKeys("key1")
	selected, err := LeastLoadKeySelector(ctx, keys, "openai", "gpt-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selected.ID != "key1" {
		t.Fatalf("expected key1, got %s", selected.ID)
	}
}

func TestLeastLoadKeySelector_PicksLeastLoaded(t *testing.T) {
	tracker := NewKeyLoadTracker()

	// Simulate load: key_a has 10 active, key_b has 2 active, key_c has 5 active
	for i := 0; i < 10; i++ {
		tracker.IncrementActive("key_a")
	}
	for i := 0; i < 2; i++ {
		tracker.IncrementActive("key_b")
	}
	for i := 0; i < 5; i++ {
		tracker.IncrementActive("key_c")
	}

	keys := makeTestKeys("key_a", "key_b", "key_c")
	ctx := makeTestContext()
	ctx.SetValue(schemas.DeepIntShieldContextKeyKeyLoadTracker, tracker)

	// Run multiple times - key_b should be selected most often
	counts := map[string]int{}
	for i := 0; i < 100; i++ {
		selected, err := LeastLoadKeySelector(ctx, keys, "openai", "gpt-4")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		counts[selected.ID]++
	}

	if counts["key_b"] < 90 {
		t.Errorf("expected key_b (least loaded) to be selected most often, got counts: %v", counts)
	}
}

func TestLeastLoadKeySelector_FallsBackWithoutTracker(t *testing.T) {
	keys := makeTestKeys("key1", "key2")
	ctx := makeTestContext()
	// No tracker in context - should fall back to weighted random without error
	_, err := LeastLoadKeySelector(ctx, keys, "openai", "gpt-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- StrategyAwareKeySelector ---

func TestStrategyAwareKeySelector_DefaultToWeightedRandom(t *testing.T) {
	selector := NewStrategyAwareKeySelector(nil)
	keys := makeTestKeys("key1", "key2")
	ctx := makeTestContext()

	// No strategy set in context - should use weighted random
	_, err := selector.Select(ctx, keys, "openai", "gpt-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStrategyAwareKeySelector_RoundRobinStrategy(t *testing.T) {
	selector := NewStrategyAwareKeySelector(nil)
	keys := makeTestKeys("x", "y")

	counts := map[string]int{}
	for i := 0; i < 100; i++ {
		ctx := makeTestContext()
		ctx.SetValue(schemas.DeepIntShieldContextKeyKeySelectionStrategy, schemas.KeySelectionRoundRobin)
		selected, err := selector.Select(ctx, keys, "openai", "gpt-4-strategy-rr")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		counts[selected.ID]++
	}

	if counts["x"] != 50 || counts["y"] != 50 {
		t.Errorf("expected even distribution, got: %v", counts)
	}
}

func TestStrategyAwareKeySelector_LeastLoadStrategy(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.IncrementActive("key_a")
	tracker.IncrementActive("key_a")
	tracker.IncrementActive("key_a")
	// key_b has 0 active

	selector := NewStrategyAwareKeySelector(tracker)
	keys := makeTestKeys("key_a", "key_b")

	ctx := makeTestContext()
	ctx.SetValue(schemas.DeepIntShieldContextKeyKeySelectionStrategy, schemas.KeySelectionLeastLoad)

	selected, err := selector.Select(ctx, keys, "openai", "gpt-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selected.ID != "key_b" {
		t.Errorf("expected key_b (least loaded), got %s", selected.ID)
	}
}

func TestStrategyAwareKeySelector_KeySelectorFunc(t *testing.T) {
	selector := NewStrategyAwareKeySelector(nil)
	fn := selector.KeySelectorFunc()

	keys := makeTestKeys("key1")
	ctx := makeTestContext()
	selected, err := fn(ctx, keys, "openai", "gpt-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selected.ID != "key1" {
		t.Errorf("expected key1, got %s", selected.ID)
	}
}

// --- KeyLoadTracker ---

func TestKeyLoadTracker_NilSafe(t *testing.T) {
	var tracker *KeyLoadTracker
	// All methods should be no-ops on nil
	tracker.IncrementActive("key1")
	tracker.DecrementActive("key1")
	tracker.RecordSuccess("key1", 100)
	tracker.RecordError("key1")
	if tracker.IsCircuitOpen("key1") {
		t.Error("expected IsCircuitOpen to return false on nil tracker")
	}
	health := tracker.GetKeyHealth("key1")
	if health.CircuitState != "closed" {
		t.Errorf("expected closed circuit state, got %s", health.CircuitState)
	}
	if tracker.GetAllKeyHealth() != nil {
		t.Error("expected nil from GetAllKeyHealth on nil tracker")
	}
}

func TestKeyLoadTracker_ActiveRequests(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.IncrementActive("key1")
	tracker.IncrementActive("key1")
	tracker.IncrementActive("key1")
	tracker.DecrementActive("key1")

	health := tracker.GetKeyHealth("key1")
	if health.ActiveRequests != 2 {
		t.Errorf("expected 2 active requests, got %d", health.ActiveRequests)
	}
}

func TestKeyLoadTracker_RecordSuccessAndTokens(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.RecordSuccess("key1", 100)
	tracker.RecordSuccess("key1", 200)

	health := tracker.GetKeyHealth("key1")
	if health.TotalRequests != 2 {
		t.Errorf("expected 2 total requests, got %d", health.TotalRequests)
	}
	if health.TotalTokens != 300 {
		t.Errorf("expected 300 total tokens, got %d", health.TotalTokens)
	}
}

func TestKeyLoadTracker_CircuitBreaker_OpensAfterThreshold(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.ErrorThreshold = 3

	// 2 errors - circuit stays closed
	tracker.RecordError("key1")
	tracker.RecordError("key1")
	if tracker.IsCircuitOpen("key1") {
		t.Error("circuit should be closed after 2 errors (threshold=3)")
	}

	// 3rd error - circuit should open
	tracker.RecordError("key1")
	if !tracker.IsCircuitOpen("key1") {
		t.Error("circuit should be open after 3 errors (threshold=3)")
	}

	health := tracker.GetKeyHealth("key1")
	if health.CircuitState != "open" {
		t.Errorf("expected circuit state 'open', got '%s'", health.CircuitState)
	}
}

func TestKeyLoadTracker_CircuitBreaker_RecoversAfterCooldown(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.ErrorThreshold = 2
	tracker.Cooldown = 50 * time.Millisecond

	// Trip the circuit
	tracker.RecordError("key1")
	tracker.RecordError("key1")
	if !tracker.IsCircuitOpen("key1") {
		t.Error("circuit should be open")
	}

	// Wait for cooldown
	time.Sleep(60 * time.Millisecond)

	// Should transition to half-open and allow probe
	if tracker.IsCircuitOpen("key1") {
		t.Error("circuit should be half-open (allowing probe) after cooldown")
	}

	health := tracker.GetKeyHealth("key1")
	if health.CircuitState != "half_open" {
		t.Errorf("expected circuit state 'half_open', got '%s'", health.CircuitState)
	}

	// Success during half-open should close circuit
	tracker.RecordSuccess("key1", 0)
	health = tracker.GetKeyHealth("key1")
	if health.CircuitState != "closed" {
		t.Errorf("expected circuit to close after success during half-open, got '%s'", health.CircuitState)
	}
}

func TestKeyLoadTracker_CircuitBreaker_ResetsOnSuccess(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.ErrorThreshold = 3

	// 2 errors, then success - counter resets
	tracker.RecordError("key1")
	tracker.RecordError("key1")
	tracker.RecordSuccess("key1", 0)

	// 2 more errors - shouldn't trip because counter was reset
	tracker.RecordError("key1")
	tracker.RecordError("key1")
	if tracker.IsCircuitOpen("key1") {
		t.Error("circuit should be closed - error count was reset by success")
	}

	// 3rd error after reset - should trip now
	tracker.RecordError("key1")
	if !tracker.IsCircuitOpen("key1") {
		t.Error("circuit should be open after 3 consecutive errors")
	}
}

func TestKeyLoadTracker_GetAllKeyHealth(t *testing.T) {
	tracker := NewKeyLoadTracker()
	tracker.IncrementActive("key1")
	tracker.IncrementActive("key2")
	tracker.RecordSuccess("key3", 50)

	health := tracker.GetAllKeyHealth()
	if len(health) != 3 {
		t.Errorf("expected 3 key health entries, got %d", len(health))
	}

	ids := map[string]bool{}
	for _, h := range health {
		ids[h.KeyID] = true
	}
	for _, id := range []string{"key1", "key2", "key3"} {
		if !ids[id] {
			t.Errorf("expected key %s in health results", id)
		}
	}
}

func TestKeyLoadTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewKeyLoadTracker()
	var wg sync.WaitGroup

	// Concurrent increments/decrements across multiple keys
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keyID := "key1"
			if i%2 == 0 {
				keyID = "key2"
			}
			tracker.IncrementActive(keyID)
			tracker.RecordSuccess(keyID, 10)
			tracker.DecrementActive(keyID)
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, active requests should be 0
	h1 := tracker.GetKeyHealth("key1")
	h2 := tracker.GetKeyHealth("key2")
	if h1.ActiveRequests != 0 {
		t.Errorf("expected 0 active requests for key1 after concurrent access, got %d", h1.ActiveRequests)
	}
	if h2.ActiveRequests != 0 {
		t.Errorf("expected 0 active requests for key2 after concurrent access, got %d", h2.ActiveRequests)
	}
	if h1.TotalRequests+h2.TotalRequests != 100 {
		t.Errorf("expected 100 total requests, got %d", h1.TotalRequests+h2.TotalRequests)
	}
}
