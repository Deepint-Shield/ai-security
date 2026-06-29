package utils

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState is the three-state breaker model: closed (healthy, all
// traffic flows), open (recently broken, all traffic short-circuits to
// fail-fast), half-open (probing - a small number of requests are
// allowed through to test recovery).
type CircuitState int32

const (
	CircuitClosed   CircuitState = 0
	CircuitOpen     CircuitState = 1
	CircuitHalfOpen CircuitState = 2
)

// ErrCircuitOpen is returned by the breaker's Allow method when the
// circuit is in the open state. Callers should treat this as a
// fast-fail and surface a 503 / "upstream unavailable" to clients
// without consuming a network round-trip.
var ErrCircuitOpen = errors.New("upstream circuit breaker is open")

// ProviderCircuitConfig tunes the breaker. Defaults are sane for
// LLM provider calls - providers cluster errors when they're degraded
// (rate limits, capacity, regional outages) and recover within
// ~30 seconds in most cases.
type ProviderCircuitConfig struct {
	// FailureThreshold: number of consecutive failures before tripping.
	FailureThreshold uint32
	// OpenDuration: how long the breaker stays open before allowing a
	// probe through (transitioning to half-open).
	OpenDuration time.Duration
	// HalfOpenSuccessThreshold: number of consecutive probes that must
	// succeed before the breaker closes again.
	HalfOpenSuccessThreshold uint32
	// HalfOpenMaxConcurrent: max simultaneous probe requests in
	// half-open state. Keep small (1-3) so a slow probe doesn't queue
	// up while the breaker is still "testing".
	HalfOpenMaxConcurrent uint32
}

func defaultProviderCircuitConfig() ProviderCircuitConfig {
	return ProviderCircuitConfig{
		FailureThreshold:         5,
		OpenDuration:             30 * time.Second,
		HalfOpenSuccessThreshold: 2,
		HalfOpenMaxConcurrent:    2,
	}
}

// ProviderCircuit is a per-host circuit breaker designed for upstream
// LLM provider calls. It's lock-free on the hot path (atomic state +
// counter reads) so it doesn't contend with concurrent requests.
//
// Usage:
//
//	if err := breaker.Allow(); err != nil {
//	    return ErrCircuitOpen - fail fast, no upstream call
//	}
//	resp, err := upstreamCall(...)
//	breaker.Record(err == nil)
//
// The breaker tracks consecutive failures (not failure rate) because
// LLM providers exhibit bursty failures - a rate-window approach
// requires more state and isn't measurably more accurate at low
// volumes (<1000 req/s/host).
type ProviderCircuit struct {
	cfg               ProviderCircuitConfig
	state             int32  // CircuitState as int32 for atomic ops
	consecutiveFails  uint32 // atomic
	consecutivePasses uint32 // atomic, used in half-open state
	openUntilNs       int64  // atomic, unix-nano
	halfOpenInflight  int32  // atomic
}

func NewProviderCircuit(cfg ProviderCircuitConfig) *ProviderCircuit {
	if cfg.FailureThreshold == 0 {
		cfg = defaultProviderCircuitConfig()
	}
	return &ProviderCircuit{cfg: cfg}
}

// Allow returns nil when the request should be sent to the upstream,
// or ErrCircuitOpen when the breaker is tripped. In half-open state
// it admits up to HalfOpenMaxConcurrent probes and rejects the rest.
func (c *ProviderCircuit) Allow() error {
	switch CircuitState(atomic.LoadInt32(&c.state)) {
	case CircuitClosed:
		return nil
	case CircuitOpen:
		// Time to attempt recovery?
		if time.Now().UnixNano() >= atomic.LoadInt64(&c.openUntilNs) {
			// Try to flip to half-open. Only one goroutine wins.
			if atomic.CompareAndSwapInt32(&c.state, int32(CircuitOpen), int32(CircuitHalfOpen)) {
				atomic.StoreUint32(&c.consecutivePasses, 0)
				atomic.StoreInt32(&c.halfOpenInflight, 0)
			}
			return c.Allow() // re-evaluate under new state
		}
		return ErrCircuitOpen
	case CircuitHalfOpen:
		// Limit concurrent probes.
		if atomic.AddInt32(&c.halfOpenInflight, 1) > int32(c.cfg.HalfOpenMaxConcurrent) {
			atomic.AddInt32(&c.halfOpenInflight, -1)
			return ErrCircuitOpen
		}
		return nil
	}
	return nil
}

// Record reports whether the upstream call succeeded so the breaker
// can update its state. Must be paired with every Allow that returned
// nil.
func (c *ProviderCircuit) Record(success bool) {
	state := CircuitState(atomic.LoadInt32(&c.state))
	if state == CircuitHalfOpen {
		atomic.AddInt32(&c.halfOpenInflight, -1)
	}
	if success {
		atomic.StoreUint32(&c.consecutiveFails, 0)
		if state == CircuitHalfOpen {
			passes := atomic.AddUint32(&c.consecutivePasses, 1)
			if passes >= c.cfg.HalfOpenSuccessThreshold {
				atomic.StoreInt32(&c.state, int32(CircuitClosed))
				atomic.StoreUint32(&c.consecutivePasses, 0)
			}
		}
		return
	}
	// Failure path.
	if state == CircuitHalfOpen {
		// Any failure during probe re-opens the breaker.
		c.tripOpen()
		return
	}
	fails := atomic.AddUint32(&c.consecutiveFails, 1)
	if fails >= c.cfg.FailureThreshold {
		c.tripOpen()
	}
}

func (c *ProviderCircuit) tripOpen() {
	atomic.StoreInt32(&c.state, int32(CircuitOpen))
	atomic.StoreInt64(&c.openUntilNs, time.Now().Add(c.cfg.OpenDuration).UnixNano())
	atomic.StoreUint32(&c.consecutivePasses, 0)
}

// State returns the current breaker state for observability.
func (c *ProviderCircuit) State() CircuitState {
	return CircuitState(atomic.LoadInt32(&c.state))
}

// providerCircuitRegistry holds one breaker per upstream host. We
// share a single registry across all provider clients so all OpenAI
// calls (regardless of which key was selected) coordinate their view
// of OpenAI's health.
type providerCircuitRegistry struct {
	mu       sync.RWMutex
	circuits map[string]*ProviderCircuit
}

var globalProviderCircuits = &providerCircuitRegistry{circuits: make(map[string]*ProviderCircuit, 16)}

// GetProviderCircuit returns the breaker for a given upstream host
// (e.g. "api.openai.com"). One breaker per host across the entire
// process - concurrent goroutines see the same state.
func GetProviderCircuit(host string) *ProviderCircuit {
	if host == "" {
		return nil
	}
	globalProviderCircuits.mu.RLock()
	c, ok := globalProviderCircuits.circuits[host]
	globalProviderCircuits.mu.RUnlock()
	if ok {
		return c
	}
	globalProviderCircuits.mu.Lock()
	if c, ok = globalProviderCircuits.circuits[host]; ok {
		globalProviderCircuits.mu.Unlock()
		return c
	}
	c = NewProviderCircuit(defaultProviderCircuitConfig())
	globalProviderCircuits.circuits[host] = c
	globalProviderCircuits.mu.Unlock()
	return c
}
