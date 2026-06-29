// Package safegoroutine provides a single recovery helper used by every
// detached goroutine in the gateway.
//
// Why this exists: fasthttp's panic handler only catches panics inside the
// request handler call stack. Panics inside `go func()` goroutines spawned
// from plugins, schedulers, or background workers propagate to runtime and
// kill the entire process. Wrapping each goroutine's top with
//
//	defer safegoroutine.Recover(logger, "label")
//
// logs the bug visibly instead of taking the gateway down.
//
// The label should identify the goroutine site so the operator can grep
// logs back to a specific source - e.g. "guardrails.policy-evaluator",
// "semanticcache.async-cache-write", "governance.post-hook-worker".
package safegoroutine

import (
	"runtime/debug"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// Recover should be deferred at the very top of every goroutine body.
// Catches panics, logs the recovered value and stack trace, and lets the
// goroutine exit cleanly without bringing down the process.
//
// Pass a nil logger only in tests; production callers always have one.
func Recover(logger schemas.Logger, label string) {
	r := recover()
	if r == nil {
		return
	}
	// debug.Stack includes the frame where the panic happened - far more
	// useful than the recovered value alone, which is often just the
	// error message and loses the surrounding context.
	stack := debug.Stack()
	if logger != nil {
		logger.Error("[%s] panic recovered: %v\n%s", label, r, stack)
		return
	}
	// Fallback when no logger is available - better than a silent swallow.
	println("[safegoroutine] panic recovered:", label)
	println(string(stack))
}
