package agentic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	mathrand "math/rand"
	"os"
	"sync"
	"time"
)

// AuditWriter is the persistence dependency the audit pipeline depends on.
// The configstore's AppendAgenticDecision satisfies it.
type AuditWriter interface {
	WriteDecision(ctx context.Context, rec AuditRecord) error
}

// AuditMode controls what happens when the in-memory audit queue is full -
// i.e. when persistence can't keep up with peak traffic.
//
//   - best_effort (default): drop the record + increment a counter. Never
//     blocks, never affects the verdict. Identical to the original behaviour.
//   - durable: spill the record to an append-only on-disk file; a background
//     janitor replays it into the database as the queue frees. No record is
//     lost as long as the disk is writable. Verdict is unaffected.
//   - fail_closed: durable, plus - if even the disk spill fails - a non-deny
//     verdict is overridden to DENY so a tool never executes without a
//     persisted audit record.
//
// durable / fail_closed add latency ONLY under backpressure (queue full) and
// ONLY in those opt-in modes; the common path and best_effort are unchanged,
// so the hot-path latency budget is preserved.
type AuditMode string

const (
	AuditBestEffort AuditMode = "best_effort"
	AuditDurable    AuditMode = "durable"
	AuditFailClosed AuditMode = "fail_closed"
)

// ParseAuditMode maps an env string to an AuditMode, defaulting to best_effort
// for empty/unknown values (so a typo never silently changes hot-path
// behaviour).
func ParseAuditMode(s string) AuditMode {
	switch AuditMode(s) {
	case AuditDurable:
		return AuditDurable
	case AuditFailClosed:
		return AuditFailClosed
	default:
		return AuditBestEffort
	}
}

// AsyncAudit is the off-hot-path audit pipeline. It implements the
// "audit is fire-and-forget to a bounded in-memory queue drained
// asynchronously; the verdict returns before the write completes"
// invariant from §2.3 of the spec.
//
// Bounded queue + drop-to-stderr (or drop-to-disk in prod) protects the
// hot path from a slow database. The queue capacity should be sized for
// the worst-case burst (peak RPS × max ingestion latency).
type AsyncAudit struct {
	writer    AuditWriter
	ch        chan AuditRecord
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	dropCount uint64
	mu        sync.Mutex

	// Durability (best_effort by default - the fields below are inert unless
	// EnableDurability is called).
	mode           AuditMode
	spillPath      string
	spillMu        sync.Mutex
	spillCount     uint64
	replayStop     chan struct{}
	stopReplayOnce sync.Once
}

// NewAsyncAudit creates an audit pipeline with the given queue size and
// number of background drain workers.
func NewAsyncAudit(writer AuditWriter, queueSize, workers int) *AsyncAudit {
	if queueSize <= 0 {
		queueSize = 4096
	}
	if workers <= 0 {
		workers = 2
	}
	a := &AsyncAudit{
		writer:     writer,
		ch:         make(chan AuditRecord, queueSize),
		replayStop: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	for i := 0; i < workers; i++ {
		a.wg.Add(1)
		go a.drain(ctx)
	}
	return a
}

// Enqueue adds a record to the pipeline (fire-and-forget). Satisfies the
// AuditSink interface; delegates to EnqueueChecked and ignores the result so
// existing callers and mocks are unaffected.
func (a *AsyncAudit) Enqueue(rec AuditRecord) {
	_ = a.EnqueueChecked(rec)
}

// EnqueueChecked adds a record and reports whether it was accepted (queued or
// durably spilled). Never blocks the hot path: a non-blocking channel send in
// the common case; on a full queue it either drops (best_effort) or spills to
// disk (durable / fail_closed). Returns false only when the record could not
// be guaranteed - which fail_closed mode turns into a DENY upstream.
func (a *AsyncAudit) EnqueueChecked(rec AuditRecord) bool {
	if a == nil || a.writer == nil {
		return false
	}
	select {
	case a.ch <- rec:
		return true
	default:
	}
	// Queue full = persistence can't keep up (backpressure).
	if a.mode != AuditDurable && a.mode != AuditFailClosed {
		a.mu.Lock()
		a.dropCount++
		a.mu.Unlock()
		return false
	}
	if err := a.spill(rec); err != nil {
		a.mu.Lock()
		a.dropCount++
		a.mu.Unlock()
		return false
	}
	a.mu.Lock()
	a.spillCount++
	a.mu.Unlock()
	return true
}

// SpillCount returns how many records have been written to the on-disk
// overflow (durable / fail_closed modes). Surfaced on the health endpoint
// alongside Drops as a backpressure signal.
func (a *AsyncAudit) SpillCount() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.spillCount
}

// EnableDurability switches the pipeline into durable / fail_closed mode,
// pointing overflow at spillPath and starting a background janitor that
// replays the spill file into the database (once at startup, then on a
// 30s ticker). No-op for best_effort. Call once, after construction.
func (a *AsyncAudit) EnableDurability(mode AuditMode, spillPath string) {
	if a == nil || (mode != AuditDurable && mode != AuditFailClosed) {
		return
	}
	a.mode = mode
	a.spillPath = spillPath
	go func() {
		_, _ = a.ReplaySpill(context.Background())
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-a.replayStop:
				return
			case <-t.C:
				_, _ = a.ReplaySpill(context.Background())
			}
		}
	}()
}

// spill appends one record as an NDJSON line to the on-disk overflow file.
// Serialised by spillMu so concurrent overflow writers don't interleave.
func (a *AsyncAudit) spill(rec AuditRecord) error {
	if a.spillPath == "" {
		return errors.New("audit: no spill path configured")
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	a.spillMu.Lock()
	defer a.spillMu.Unlock()
	f, err := os.OpenFile(a.spillPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

// ReplaySpill drains the on-disk overflow back into the writer and removes the
// replayed records. Records that still fail to persist are re-spilled for the
// next attempt. Holds spillMu only for the fast read+truncate; DB writes
// happen unlocked. No-op without a spill path.
func (a *AsyncAudit) ReplaySpill(ctx context.Context) (int, error) {
	if a == nil || a.spillPath == "" || a.writer == nil {
		return 0, nil
	}
	a.spillMu.Lock()
	data, err := os.ReadFile(a.spillPath)
	if err != nil {
		a.spillMu.Unlock()
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	_ = os.Truncate(a.spillPath, 0)
	a.spillMu.Unlock()

	replayed := 0
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // skip a corrupt line rather than wedge the whole replay
		}
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		werr := a.writer.WriteDecision(wctx, rec)
		cancel()
		if werr != nil {
			_ = a.spill(rec) // still down - keep it for the next pass
			continue
		}
		replayed++
	}
	return replayed, nil
}

// Drops returns the number of records dropped due to a full queue.
// Observability dashboards surface this; a non-zero value is a
// backpressure signal that the persistence layer is too slow.
func (a *AsyncAudit) Drops() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropCount
}

// Stop drains the queue and joins the workers. Called on graceful
// shutdown.
func (a *AsyncAudit) Stop() {
	if a == nil {
		return
	}
	a.stopReplayOnce.Do(func() {
		if a.replayStop != nil {
			close(a.replayStop)
		}
	})
	a.cancel()
	close(a.ch)
	a.wg.Wait()
}

func (a *AsyncAudit) drain(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case rec, ok := <-a.ch:
			if !ok {
				return
			}
			// Each write gets its own short timeout so a stuck DB does not
			// block draining.
			writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.writer.WriteDecision(writeCtx, rec)
			cancel()
		}
	}
}

// prng returns n-byte hex string for decision IDs. crypto/rand for
// security; falls back to math/rand on failure (never blocks the
// hot path).
var (
	prngFallback = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	prngMu       sync.Mutex
)

func prng(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	prngMu.Lock()
	prngFallback.Read(buf)
	prngMu.Unlock()
	return hex.EncodeToString(buf)
}
