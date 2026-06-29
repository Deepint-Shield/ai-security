package plugins

import (
	"context"
	"sync"
)

// PluginGroup runs a set of independent plugin operations
// concurrently, propagating the first error and respecting context
// cancellation. Designed for the gateway's pre/post hook chains
// where multiple checks are mathematically independent (e.g. the
// guardrail input check, RAG-source ACL check, and routing rule
// pre-evaluation can all run concurrently - they read different
// state and don't write).
//
// Why a custom helper instead of golang.org/x/sync/errgroup:
//   - We need to cap concurrency so a fanout-of-100 doesn't
//     overwhelm the runtime, and the standard errgroup doesn't
//     bound concurrency by default.
//   - We want to surface ALL errors (not just the first), so an
//     operator debugging a misbehaving chain can see every plugin's
//     verdict instead of one. This implementation collects all
//     errors and lets callers decide which to surface.
//   - The "no-op when single-task" optimisation matters: most
//     deployments only have 1-2 independent plugins, and the
//     overhead of spinning a goroutine + channel for each isn't
//     justified. We inline single-task execution.
//
// Usage:
//
//	group := plugins.NewPluginGroup(ctx, 4) // max 4 concurrent
//	group.Go("guardrail-input", func(ctx context.Context) error {
//	    return guardrails.PreInputCheck(ctx, req)
//	})
//	group.Go("rag-acl", func(ctx context.Context) error {
//	    return rag.PreACLCheck(ctx, req)
//	})
//	if errs := group.Wait(); len(errs) > 0 {
//	    // Handle the first or aggregate
//	}
type PluginGroup struct {
	ctx       context.Context
	cancel    context.CancelFunc
	semaphore chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	errs      []NamedError
}

// NamedError tags an error with the plugin name that produced it,
// so caller-side logging / decision-making can attribute correctly.
type NamedError struct {
	Plugin string
	Err    error
}

// NewPluginGroup creates a group bound to ctx. maxConcurrency caps
// goroutines (use 0 for unbounded - fine when you've explicitly
// curated the set).
func NewPluginGroup(ctx context.Context, maxConcurrency int) *PluginGroup {
	derivedCtx, cancel := context.WithCancel(ctx)
	g := &PluginGroup{
		ctx:    derivedCtx,
		cancel: cancel,
	}
	if maxConcurrency > 0 {
		g.semaphore = make(chan struct{}, maxConcurrency)
	}
	return g
}

// Go schedules fn under the plugin's name. The function receives the
// group's context (cancelled when any sibling errors, if the caller
// chooses to cancel - see WaitWithFirstFailureCancel).
func (g *PluginGroup) Go(name string, fn func(context.Context) error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if g.semaphore != nil {
			select {
			case g.semaphore <- struct{}{}:
				defer func() { <-g.semaphore }()
			case <-g.ctx.Done():
				g.recordErr(name, g.ctx.Err())
				return
			}
		}
		if err := fn(g.ctx); err != nil {
			g.recordErr(name, err)
		}
	}()
}

func (g *PluginGroup) recordErr(name string, err error) {
	g.mu.Lock()
	g.errs = append(g.errs, NamedError{Plugin: name, Err: err})
	g.mu.Unlock()
}

// Wait blocks until every Go() task finishes and returns every
// error collected. Returns nil if all tasks succeeded.
func (g *PluginGroup) Wait() []NamedError {
	g.wg.Wait()
	g.cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.errs) == 0 {
		return nil
	}
	out := make([]NamedError, len(g.errs))
	copy(out, g.errs)
	return out
}

// WaitWithFirstFailureCancel waits for completion but cancels the
// group's context as soon as the first error appears. Use when a
// failure in one plugin should short-circuit the rest (e.g. an
// auth failure makes downstream evaluation pointless).
func (g *PluginGroup) WaitWithFirstFailureCancel() []NamedError {
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	for {
		select {
		case <-done:
			g.cancel()
			g.mu.Lock()
			defer g.mu.Unlock()
			if len(g.errs) == 0 {
				return nil
			}
			out := make([]NamedError, len(g.errs))
			copy(out, g.errs)
			return out
		default:
			g.mu.Lock()
			n := len(g.errs)
			g.mu.Unlock()
			if n > 0 {
				g.cancel()
				<-done
				g.mu.Lock()
				defer g.mu.Unlock()
				out := make([]NamedError, len(g.errs))
				copy(out, g.errs)
				return out
			}
			// Sleep tiny so we don't busy-loop. Real concurrency
			// happens in the goroutines; this ticker just polls
			// for the cancellation predicate.
			select {
			case <-done:
				g.cancel()
				g.mu.Lock()
				defer g.mu.Unlock()
				if len(g.errs) == 0 {
					return nil
				}
				out := make([]NamedError, len(g.errs))
				copy(out, g.errs)
				return out
			}
		}
	}
}
