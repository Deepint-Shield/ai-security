package schemas

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var NoDeadline time.Time

var reservedKeys = []any{
	DeepIntShieldContextKeyVirtualKey,
	DeepIntShieldContextKeyAPIKeyName,
	DeepIntShieldContextKeyAPIKeyID,
	DeepIntShieldContextKeyRequestID,
	DeepIntShieldContextKeyFallbackRequestID,
	DeepIntShieldContextKeyDirectKey,
	DeepIntShieldContextKeySelectedKeyID,
	DeepIntShieldContextKeySelectedKeyName,
	DeepIntShieldContextKeyNumberOfRetries,
	DeepIntShieldContextKeyFallbackIndex,
	DeepIntShieldContextKeySkipKeySelection,
	DeepIntShieldContextKeyURLPath,
	DeepIntShieldContextKeyDeferTraceCompletion,
}

// DeepIntShieldContext is a custom context.Context implementation that tracks user-set values.
// It supports deadlines, can be derived from other contexts, and provides layered
// value inheritance when derived from another DeepIntShieldContext.
type DeepIntShieldContext struct {
	parent                context.Context
	deadline              time.Time
	hasDeadline           bool
	done                  chan struct{}
	doneOnce              sync.Once
	err                   error
	errMu                 sync.RWMutex
	userValues            map[any]any
	valuesMu              sync.RWMutex
	blockRestrictedWrites atomic.Bool
}

// NewDeepIntShieldContext creates a new DeepIntShieldContext with the given parent context and deadline.
// If the deadline is zero, no deadline is set on this context (though the parent may have one).
// The context will be cancelled when the deadline expires or when the parent context is cancelled.
func NewDeepIntShieldContext(parent context.Context, deadline time.Time) *DeepIntShieldContext {
	if parent == nil {
		parent = context.Background()
	}
	ctx := &DeepIntShieldContext{
		parent:                parent,
		deadline:              deadline,
		hasDeadline:           !deadline.IsZero(),
		done:                  make(chan struct{}),
		userValues:            make(map[any]any),
		blockRestrictedWrites: atomic.Bool{},
	}
	ctx.blockRestrictedWrites.Store(false)
	// Only start goroutine if there's something to watch:
	// - If we have a deadline, we need the timer
	// - If parent can be cancelled (Done() != nil) AND is not a non-cancelling context
	// - If parent has a deadline, we need a timer (parent may not properly cancel via Done())
	_, parentHasDeadline := parent.Deadline()
	parentCanCancel := parent.Done() != nil && !isNonCancellingContext(parent)
	if ctx.hasDeadline || parentCanCancel || parentHasDeadline {
		go ctx.watchCancellation()
	}
	return ctx
}

// NewDeepIntShieldContextWithValue creates a new DeepIntShieldContext with the given value set.
func NewDeepIntShieldContextWithValue(parent context.Context, deadline time.Time, key any, value any) *DeepIntShieldContext {
	ctx := NewDeepIntShieldContext(parent, deadline)
	ctx.SetValue(key, value)
	return ctx
}

// NewDeepIntShieldContextWithTimeout creates a new DeepIntShieldContext with a timeout duration.
// This is a convenience wrapper around NewDeepIntShieldContext.
// Returns the context and a cancel function that should be called to release resources.
func NewDeepIntShieldContextWithTimeout(parent context.Context, timeout time.Duration) (*DeepIntShieldContext, context.CancelFunc) {
	ctx := NewDeepIntShieldContext(parent, time.Now().Add(timeout))
	return ctx, func() { ctx.Cancel() }
}

// NewDeepIntShieldContextWithCancel creates a new DeepIntShieldContext with a cancel function.
// This is a convenience wrapper around NewDeepIntShieldContext.
// Returns the context and a cancel function that should be called to release resources.
func NewDeepIntShieldContextWithCancel(parent context.Context) (*DeepIntShieldContext, context.CancelFunc) {
	ctx := NewDeepIntShieldContext(parent, NoDeadline)
	return ctx, func() { ctx.Cancel() }
}

// WithValue returns a new context with the given value set.
func (bc *DeepIntShieldContext) WithValue(key any, value any) *DeepIntShieldContext {
	bc.SetValue(key, value)
	return bc
}

// BlockRestrictedWrites returns true if restricted writes are blocked.
func (bc *DeepIntShieldContext) BlockRestrictedWrites() {
	bc.blockRestrictedWrites.Store(true)
}

// UnblockRestrictedWrites unblocks restricted writes.
func (bc *DeepIntShieldContext) UnblockRestrictedWrites() {
	bc.blockRestrictedWrites.Store(false)
}

// Cancel cancels the context, closing the Done channel and setting the error to context.Canceled.
func (bc *DeepIntShieldContext) Cancel() {
	bc.cancel(context.Canceled)
}

// watchCancellation monitors for deadline expiration and parent cancellation.
func (bc *DeepIntShieldContext) watchCancellation() {
	var timer <-chan time.Time

	// Use effective deadline (considers both own and parent deadlines)
	// This handles cases where parent has a deadline but doesn't properly
	// cancel via Done() (e.g., fasthttp.RequestCtx)
	if effectiveDeadline, hasDeadline := bc.Deadline(); hasDeadline {
		duration := time.Until(effectiveDeadline)
		if duration <= 0 {
			// Deadline already passed
			bc.cancel(context.DeadlineExceeded)
			return
		}
		t := time.NewTimer(duration)
		defer t.Stop()
		timer = t.C
	}

	// Don't watch parent.Done() for contexts known to never close it
	// (e.g., fasthttp.RequestCtx pools contexts and never cancels them)
	if isNonCancellingContext(bc.parent) {
		select {
		case <-timer:
			bc.cancel(context.DeadlineExceeded)
		case <-bc.done:
			// Already cancelled
		}
		return
	}

	select {
	case <-bc.parent.Done():
		bc.cancel(bc.parent.Err())
	case <-timer:
		bc.cancel(context.DeadlineExceeded)
	case <-bc.done:
		// Already cancelled
	}
}

// cancel closes the done channel and sets the error.
func (bc *DeepIntShieldContext) cancel(err error) {
	bc.doneOnce.Do(func() {
		bc.errMu.Lock()
		bc.err = err
		bc.errMu.Unlock()
		close(bc.done)
	})
}

// Deadline returns the deadline for this context.
// If both this context and the parent have deadlines, the earlier one is returned.
func (bc *DeepIntShieldContext) Deadline() (time.Time, bool) {
	parentDeadline, parentHasDeadline := bc.parent.Deadline()

	if !bc.hasDeadline && !parentHasDeadline {
		return time.Time{}, false
	}

	if !bc.hasDeadline {
		return parentDeadline, true
	}

	if !parentHasDeadline {
		return bc.deadline, true
	}

	// Both have deadlines, return the earlier one
	if bc.deadline.Before(parentDeadline) {
		return bc.deadline, true
	}
	return parentDeadline, true
}

// Done returns a channel that is closed when the context is cancelled.
func (bc *DeepIntShieldContext) Done() <-chan struct{} {
	return bc.done
}

// Err returns the error explaining why the context was cancelled.
// Returns nil if the context has not been cancelled.
func (bc *DeepIntShieldContext) Err() error {
	bc.errMu.RLock()
	defer bc.errMu.RUnlock()
	return bc.err
}

// Value returns the value associated with the key.
// It first checks the internal userValues map, then delegates to the parent context.
func (bc *DeepIntShieldContext) Value(key any) any {
	bc.valuesMu.RLock()
	if val, ok := bc.userValues[key]; ok {
		bc.valuesMu.RUnlock()
		return val
	}
	bc.valuesMu.RUnlock()

	return bc.parent.Value(key)
}

// SetValue sets a value in the internal userValues map.
// This is thread-safe and can be called concurrently.
func (bc *DeepIntShieldContext) SetValue(key, value any) {
	// Check if the key is a reserved key
	if bc.blockRestrictedWrites.Load() && slices.Contains(reservedKeys, key) {
		// we silently drop writes for these reserved keys
		return
	}
	bc.valuesMu.Lock()
	defer bc.valuesMu.Unlock()
	if bc.userValues == nil {
		bc.userValues = make(map[any]any)
	}
	bc.userValues[key] = value
}

// ClearValue clears a value from the internal userValues map.
func (bc *DeepIntShieldContext) ClearValue(key any) {
	// Check if the key is a reserved key
	if bc.blockRestrictedWrites.Load() && slices.Contains(reservedKeys, key) {
		// we silently drop writes for these reserved keys
		return
	}
	bc.valuesMu.Lock()
	defer bc.valuesMu.Unlock()
	if bc.userValues != nil {
		bc.userValues[key] = nil
	}
}

// GetAndSetValue gets a value from the internal userValues map and sets it
func (bc *DeepIntShieldContext) GetAndSetValue(key any, value any) any {
	bc.valuesMu.Lock()
	defer bc.valuesMu.Unlock()
	// Check if the key is a reserved key
	if bc.blockRestrictedWrites.Load() && slices.Contains(reservedKeys, key) {
		// we silently drop writes for these reserved keys
		return bc.userValues[key]
	}
	if bc.userValues == nil {
		bc.userValues = make(map[any]any)
	}
	oldValue := bc.userValues[key]
	bc.userValues[key] = value
	return oldValue
}

// GetUserValues returns a copy of all user-set values in this context.
// If the parent is also a PluginContext, the values are merged with parent values
// (this context's values take precedence over parent values).
func (bc *DeepIntShieldContext) GetUserValues() map[any]any {
	result := make(map[any]any)

	// First, get parent's user values if parent is a PluginContext
	if parentCtx, ok := bc.parent.(*DeepIntShieldContext); ok {
		for k, v := range parentCtx.GetUserValues() {
			result[k] = v
		}
	}

	// Then overlay with our own values (our values take precedence)
	bc.valuesMu.RLock()
	for k, v := range bc.userValues {
		result[k] = v
	}
	bc.valuesMu.RUnlock()

	return result
}

// GetParentCtxWithUserValues returns a copy of the parent context with all user-set values merged in.
func (bc *DeepIntShieldContext) GetParentCtxWithUserValues() context.Context {
	parentCtx := bc.parent
	bc.valuesMu.RLock()
	for k, v := range bc.userValues {
		parentCtx = context.WithValue(parentCtx, k, v)
	}
	bc.valuesMu.RUnlock()
	return parentCtx
}

// AppendRoutingEngineLog appends a routing engine log entry to the context.
// Parameters:
//   - ctx: The DeepIntShield context
//   - engineName: Name of the routing engine (e.g., "governance", "routing-rule")
//   - message: Human-readable log message describing the decision/action
func (bc *DeepIntShieldContext) AppendRoutingEngineLog(engineName string, message string) {
	entry := RoutingEngineLogEntry{
		Engine:    engineName,
		Message:   message,
		Timestamp: time.Now().UnixMilli(),
	}
	AppendToContextList(bc, DeepIntShieldContextKeyRoutingEngineLogs, entry)
}

// GetRoutingEngineLogs retrieves all routing engine logs from the context.
// Parameters:
//   - ctx: The DeepIntShield context
//
// Returns:
//   - []RoutingEngineLogEntry: Slice of routing engine log entries (nil if none)
func (bc *DeepIntShieldContext) GetRoutingEngineLogs() []RoutingEngineLogEntry {
	if val := bc.Value(DeepIntShieldContextKeyRoutingEngineLogs); val != nil {
		if logs, ok := val.([]RoutingEngineLogEntry); ok {
			return logs
		}
	}
	return nil
}

// AppendToContextList appends a value to the context list value.
// Parameters:
//   - ctx: The DeepIntShield context
//   - key: The key to append the value to
//   - value: The value to append
func AppendToContextList[T any](ctx *DeepIntShieldContext, key DeepIntShieldContextKey, value T) {
	if ctx == nil {
		return
	}
	existingValues, ok := ctx.Value(key).([]T)
	if !ok {
		existingValues = []T{}
	}
	ctx.SetValue(key, append(existingValues, value))
}
