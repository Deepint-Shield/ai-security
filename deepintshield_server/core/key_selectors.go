package deepintshield

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// roundRobinCounters stores per-provider+model atomic counters for round-robin selection.
var roundRobinCounters sync.Map // map[string]*atomic.Uint64

// RoundRobinKeySelector selects keys in round-robin order using a per-provider+model
// atomic counter. Lock-free and allocation-free on the hot path.
func RoundRobinKeySelector(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, providerKey schemas.ModelProvider, model string) (schemas.Key, error) {
	if len(keys) == 0 {
		return schemas.Key{}, fmt.Errorf("no keys available for round-robin selection")
	}
	if len(keys) == 1 {
		return keys[0], nil
	}

	counterKey := string(providerKey) + ":" + model
	var counter *atomic.Uint64
	if val, ok := roundRobinCounters.Load(counterKey); ok {
		counter = val.(*atomic.Uint64)
	} else {
		counter = &atomic.Uint64{}
		actual, _ := roundRobinCounters.LoadOrStore(counterKey, counter)
		counter = actual.(*atomic.Uint64)
	}

	idx := counter.Add(1) - 1 // zero-based
	return keys[idx%uint64(len(keys))], nil
}

// LeastLoadKeySelector selects the key with the lowest active request count,
// weighted by the key's configured weight. Falls back to weighted random
// if no load tracker is available in the context.
func LeastLoadKeySelector(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, providerKey schemas.ModelProvider, model string) (schemas.Key, error) {
	if len(keys) == 0 {
		return schemas.Key{}, fmt.Errorf("no keys available for least-load selection")
	}
	if len(keys) == 1 {
		return keys[0], nil
	}

	// Try to get the load tracker from context
	var tracker *KeyLoadTracker
	if ctx != nil {
		if t, ok := ctx.Value(schemas.DeepIntShieldContextKeyKeyLoadTracker).(*KeyLoadTracker); ok {
			tracker = t
		}
	}

	if tracker == nil {
		// No tracker available - fall back to weighted random
		return WeightedRandomKeySelector(ctx, keys, providerKey, model)
	}

	// Find key with lowest load (activeRequests / weight)
	bestIdx := 0
	bestScore := float64(-1)
	for i, key := range keys {
		active := float64(tracker.getOrCreateState(key.ID).ActiveRequests.Load())
		weight := key.Weight
		if weight <= 0 {
			weight = 1 // avoid division by zero; treat unweighted as weight=1
		}
		score := active / weight // lower is better
		if bestScore < 0 || score < bestScore {
			bestScore = score
			bestIdx = i
		} else if score == bestScore {
			// Tie-break with random to avoid herding
			if rand.Intn(2) == 0 {
				bestIdx = i
			}
		}
	}

	return keys[bestIdx], nil
}

// StrategyAwareKeySelector dispatches to the appropriate key selector based on
// the KeySelectionStrategy set in the request context. When no strategy is set
// or strategy is "weighted_random", it delegates to WeightedRandomKeySelector.
//
// This selector is only instantiated when the load balancer feature is enabled.
type StrategyAwareKeySelector struct {
	tracker *KeyLoadTracker
}

// NewStrategyAwareKeySelector creates a new strategy-aware selector.
// The tracker may be nil (circuit breaker and least-load will be no-ops).
func NewStrategyAwareKeySelector(tracker *KeyLoadTracker) *StrategyAwareKeySelector {
	return &StrategyAwareKeySelector{tracker: tracker}
}

// Select implements the key selection logic, reading the strategy from context.
func (s *StrategyAwareKeySelector) Select(ctx *schemas.DeepIntShieldContext, keys []schemas.Key, providerKey schemas.ModelProvider, model string) (schemas.Key, error) {
	strategy := schemas.KeySelectionWeightedRandom // default
	if ctx != nil {
		if st, ok := ctx.Value(schemas.DeepIntShieldContextKeyKeySelectionStrategy).(schemas.KeySelectionStrategy); ok && st != "" {
			strategy = st
		}
	}

	// Inject tracker into context for LeastLoadKeySelector
	if s.tracker != nil && ctx != nil {
		ctx.SetValue(schemas.DeepIntShieldContextKeyKeyLoadTracker, s.tracker)
	}

	switch strategy {
	case schemas.KeySelectionRoundRobin:
		return RoundRobinKeySelector(ctx, keys, providerKey, model)
	case schemas.KeySelectionLeastLoad:
		return LeastLoadKeySelector(ctx, keys, providerKey, model)
	default:
		return WeightedRandomKeySelector(ctx, keys, providerKey, model)
	}
}

// KeySelectorFunc returns the Select method as a schemas.KeySelector function.
func (s *StrategyAwareKeySelector) KeySelectorFunc() schemas.KeySelector {
	return s.Select
}
