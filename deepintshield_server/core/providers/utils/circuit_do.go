package utils

import (
	"github.com/valyala/fasthttp"
)

// fasthttpDoer is satisfied by both *fasthttp.Client and
// *fasthttp.HostClient - the only shape DoWithCircuit needs from the
// underlying transport is a Do(req, resp) call. Defined as an interface
// so providers using either client type can share the same wrapper.
type fasthttpDoer interface {
	Do(req *fasthttp.Request, resp *fasthttp.Response) error
}

// DoWithCircuit wraps a fasthttp Do() call with the per-host circuit
// breaker. Behaviour:
//
//  1. Resolve the breaker for the request's host. Cached after first
//     lookup; one breaker instance per host across the whole process.
//  2. Call breaker.Allow(). If the breaker is open, return
//     ErrCircuitOpen immediately - no upstream call, no socket open,
//     no retry storm.
//  3. Otherwise execute the Do() call. Record success/failure on the
//     breaker so it can flip state on consecutive failures.
//
// Failure detection: any non-nil error OR a 5xx status counts as a
// failure. 4xx (auth, validation, rate limit) does NOT count - those
// are caller-side issues that don't indicate upstream degradation,
// and tripping the breaker on them would create false positives. A
// 429 specifically does count as a failure because that's the
// canonical "we're overloaded" signal from LLM providers and is
// exactly what the breaker should respond to.
//
// Usage at provider call sites:
//
//	if err := utils.DoWithCircuit(client, req, resp); err != nil {
//	    return nil, asDeepIntShieldError(err)
//	}
//
// Streaming endpoints should call breaker.Allow() before establishing
// the stream and breaker.Record(success) after it terminates - see
// the ChatCompletionStream wiring for the canonical example.
func DoWithCircuit(client fasthttpDoer, req *fasthttp.Request, resp *fasthttp.Response) error {
	host := string(req.URI().Host())
	breaker := GetProviderCircuit(host)
	if breaker != nil {
		if err := breaker.Allow(); err != nil {
			return err
		}
	}
	err := client.Do(req, resp)
	if breaker != nil {
		// Treat transport errors and 5xx / 429 as failures. Other 4xx
		// are caller errors and should not trip the breaker.
		failed := err != nil
		if !failed && resp != nil {
			status := resp.StatusCode()
			if status >= 500 || status == fasthttp.StatusTooManyRequests {
				failed = true
			}
		}
		breaker.Record(!failed)
	}
	return err
}
