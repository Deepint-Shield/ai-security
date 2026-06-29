package deepintshield

import (
	"sync"
	"sync/atomic"
	"time"
)

// KeyLoadState holds per-key runtime metrics for load balancing and circuit breaking.
// All fields use atomic operations for lock-free, concurrent-safe access.
type KeyLoadState struct {
	ActiveRequests  atomic.Int64
	TotalRequests   atomic.Int64
	TotalTokens     atomic.Int64
	ErrorCount      atomic.Int64 // consecutive errors (reset on success)
	LastError       atomic.Value // time.Time
	CircuitState    atomic.Int32 // 0=closed, 1=open, 2=half-open
	CircuitOpenedAt atomic.Value // time.Time
}

// CircuitBreakerState constants.
const (
	CircuitClosed   int32 = 0
	CircuitOpen     int32 = 1
	CircuitHalfOpen int32 = 2
)

// KeyLoadTracker tracks per-key load metrics and circuit breaker state in-memory.
// All operations are lock-free using atomic operations and sync.Map.
// The tracker is nil-safe: all methods are no-ops when called on a nil receiver.
type KeyLoadTracker struct {
	states sync.Map // map[string]*KeyLoadState

	// Circuit breaker configuration
	ErrorThreshold int           // consecutive errors to trip circuit (default: 5)
	Cooldown       time.Duration // how long circuit stays open (default: 30s)
}

// NewKeyLoadTracker creates a new tracker with default circuit breaker settings.
func NewKeyLoadTracker() *KeyLoadTracker {
	return &KeyLoadTracker{
		ErrorThreshold: 5,
		Cooldown:       30 * time.Second,
	}
}

// getOrCreateState retrieves or lazily creates the state for a key.
func (t *KeyLoadTracker) getOrCreateState(keyID string) *KeyLoadState {
	if val, ok := t.states.Load(keyID); ok {
		return val.(*KeyLoadState)
	}
	state := &KeyLoadState{}
	actual, _ := t.states.LoadOrStore(keyID, state)
	return actual.(*KeyLoadState)
}

// IncrementActive increments the active request count for a key.
func (t *KeyLoadTracker) IncrementActive(keyID string) {
	if t == nil {
		return
	}
	t.getOrCreateState(keyID).ActiveRequests.Add(1)
}

// DecrementActive decrements the active request count for a key.
func (t *KeyLoadTracker) DecrementActive(keyID string) {
	if t == nil {
		return
	}
	t.getOrCreateState(keyID).ActiveRequests.Add(-1)
}

// RecordSuccess records a successful response and resets the consecutive error count.
func (t *KeyLoadTracker) RecordSuccess(keyID string, tokens int64) {
	if t == nil {
		return
	}
	state := t.getOrCreateState(keyID)
	state.TotalRequests.Add(1)
	if tokens > 0 {
		state.TotalTokens.Add(tokens)
	}
	// Reset consecutive error count on success
	state.ErrorCount.Store(0)
	// If circuit was half-open, close it on success
	state.CircuitState.CompareAndSwap(CircuitHalfOpen, CircuitClosed)
}

// RecordError records a failed response and potentially opens the circuit breaker.
func (t *KeyLoadTracker) RecordError(keyID string) {
	if t == nil {
		return
	}
	state := t.getOrCreateState(keyID)
	state.TotalRequests.Add(1)
	state.LastError.Store(time.Now())
	newCount := state.ErrorCount.Add(1)

	// Trip circuit breaker if threshold exceeded
	if int(newCount) >= t.ErrorThreshold {
		if state.CircuitState.CompareAndSwap(CircuitClosed, CircuitOpen) {
			state.CircuitOpenedAt.Store(time.Now())
		}
		// Also trip from half-open back to open
		if state.CircuitState.CompareAndSwap(CircuitHalfOpen, CircuitOpen) {
			state.CircuitOpenedAt.Store(time.Now())
		}
	}
}

// IsCircuitOpen returns true if the circuit breaker is open for the given key.
// Returns false if the tracker is nil or the key has no state.
func (t *KeyLoadTracker) IsCircuitOpen(keyID string) bool {
	if t == nil {
		return false
	}
	val, ok := t.states.Load(keyID)
	if !ok {
		return false
	}
	state := val.(*KeyLoadState)
	circuitState := state.CircuitState.Load()

	if circuitState == CircuitClosed {
		return false
	}

	if circuitState == CircuitOpen {
		// Check if cooldown has elapsed - transition to half-open
		if openedAt, ok := state.CircuitOpenedAt.Load().(time.Time); ok {
			if time.Since(openedAt) >= t.Cooldown {
				// Try to transition to half-open (allow one probe request)
				state.CircuitState.CompareAndSwap(CircuitOpen, CircuitHalfOpen)
				return false // allow the probe
			}
		}
		return true // still in cooldown
	}

	// Half-open: allow requests through (probe)
	return false
}

// KeyHealthInfo contains health information about a single key for the status API.
type KeyHealthInfo struct {
	KeyID          string `json:"key_id"`
	ActiveRequests int64  `json:"active_requests"`
	TotalRequests  int64  `json:"total_requests"`
	TotalTokens    int64  `json:"total_tokens"`
	ErrorCount     int64  `json:"error_count"`
	CircuitState   string `json:"circuit_state"`
	LastError      string `json:"last_error,omitempty"`
}

// GetKeyHealth returns health information for a specific key.
func (t *KeyLoadTracker) GetKeyHealth(keyID string) KeyHealthInfo {
	if t == nil {
		return KeyHealthInfo{KeyID: keyID, CircuitState: "closed"}
	}
	val, ok := t.states.Load(keyID)
	if !ok {
		return KeyHealthInfo{KeyID: keyID, CircuitState: "closed"}
	}
	state := val.(*KeyLoadState)

	circuitStr := "closed"
	switch state.CircuitState.Load() {
	case CircuitOpen:
		circuitStr = "open"
	case CircuitHalfOpen:
		circuitStr = "half_open"
	}

	info := KeyHealthInfo{
		KeyID:          keyID,
		ActiveRequests: state.ActiveRequests.Load(),
		TotalRequests:  state.TotalRequests.Load(),
		TotalTokens:    state.TotalTokens.Load(),
		ErrorCount:     state.ErrorCount.Load(),
		CircuitState:   circuitStr,
	}

	if lastErr, ok := state.LastError.Load().(time.Time); ok && !lastErr.IsZero() {
		info.LastError = lastErr.Format(time.RFC3339)
	}

	return info
}

// GetAllKeyHealth returns health information for all tracked keys.
func (t *KeyLoadTracker) GetAllKeyHealth() []KeyHealthInfo {
	if t == nil {
		return nil
	}
	var results []KeyHealthInfo
	t.states.Range(func(key, _ any) bool {
		keyID := key.(string)
		results = append(results, t.GetKeyHealth(keyID))
		return true
	})
	return results
}
