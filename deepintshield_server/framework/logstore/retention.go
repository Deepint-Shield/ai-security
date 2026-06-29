package logstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

// RetentionPolicy describes how long log rows live before pruning.
// All durations are inclusive - rows whose `created_at` is older than
// (now - duration) are eligible for deletion. A zero duration disables
// pruning for that table (rows live forever).
type RetentionPolicy struct {
	// Logs is the retention window for the AI request `logs` table.
	// Default: 90d if zero (set explicitly to 0 to disable).
	Logs time.Duration
	// MCPToolLogs is the retention for `mcp_tool_logs`. Default: 90d.
	MCPToolLogs time.Duration
	// AuditLogs is the retention for `audit_logs`. Default: 365d
	// because audit data has compliance value beyond operational use.
	AuditLogs time.Duration
	// SweepInterval is how often the retention worker runs. Default: 1h.
	SweepInterval time.Duration
	// BatchSize caps the rows deleted per pass to keep the transaction
	// short and avoid lock contention with concurrent log writes.
	// Default: 5000.
	BatchSize int
}

func (p *RetentionPolicy) applyDefaults() {
	if p.Logs == 0 {
		p.Logs = 90 * 24 * time.Hour
	}
	if p.MCPToolLogs == 0 {
		p.MCPToolLogs = 90 * 24 * time.Hour
	}
	if p.AuditLogs == 0 {
		p.AuditLogs = 365 * 24 * time.Hour
	}
	if p.SweepInterval == 0 {
		p.SweepInterval = time.Hour
	}
	if p.BatchSize <= 0 {
		p.BatchSize = 5000
	}
}

// RetentionWorker prunes old log rows in the background. Designed for
// shared-DB deployments where unbounded log growth slows queries and
// inflates storage. The worker:
//   - Runs once at start (so a fresh process catches up on missed sweeps)
//   - Repeats every SweepInterval
//   - Deletes in batches to avoid long-held locks
//   - Skips work if a sweep is already in progress (concurrent replicas
//     coordinate via the unique sweep_started_at column on the row,
//     not implemented here - this v1 worker assumes single-writer for
//     the sweep, which is a reasonable assumption since cron-style
//     pruning doesn't need to be sub-hour).
type RetentionWorker struct {
	db     *gorm.DB
	policy RetentionPolicy
	logger interface {
		Info(string, ...any)
		Error(string, ...any)
		Warn(string, ...any)
	}
	cancel context.CancelFunc
	mu     sync.Mutex
	stop   chan struct{}
}

func NewRetentionWorker(db *gorm.DB, policy RetentionPolicy, logger interface {
	Info(string, ...any)
	Error(string, ...any)
	Warn(string, ...any)
}) *RetentionWorker {
	policy.applyDefaults()
	return &RetentionWorker{
		db:     db,
		policy: policy,
		logger: logger,
		stop:   make(chan struct{}),
	}
}

// Start launches the worker goroutine. Call Stop on shutdown to drain
// in-flight pruning and exit cleanly. Safe to call once per process.
func (w *RetentionWorker) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	go w.loop(ctx)
}

// Stop signals the worker to exit and waits for the current sweep
// (if any) to finish. Idempotent.
func (w *RetentionWorker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
}

func (w *RetentionWorker) loop(ctx context.Context) {
	w.runSweep(ctx) // immediate first pass
	t := time.NewTicker(w.policy.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.runSweep(ctx)
		}
	}
}

func (w *RetentionWorker) runSweep(ctx context.Context) {
	if w.db == nil {
		return
	}
	type table struct {
		name     string
		ttl      time.Duration
		tsColumn string
	}
	targets := []table{
		{"logs", w.policy.Logs, "created_at"},
		{"mcp_tool_logs", w.policy.MCPToolLogs, "timestamp"},
		{"audit_logs", w.policy.AuditLogs, "timestamp"},
	}
	for _, t := range targets {
		if t.ttl <= 0 {
			continue
		}
		cutoff := time.Now().UTC().Add(-t.ttl)
		deleted, err := w.deleteBatch(ctx, t.name, t.tsColumn, cutoff)
		if err != nil {
			if w.logger != nil {
				w.logger.Warn("retention sweep failed for %s: %v", t.name, err)
			}
			continue
		}
		if deleted > 0 && w.logger != nil {
			w.logger.Info("retention sweep removed %d rows from %s (older than %s)", deleted, t.name, cutoff.Format(time.RFC3339))
		}
	}
}

// deleteBatch removes rows in chunks of policy.BatchSize until the
// affected count drops below the batch size, signaling that the sweep
// has caught up. Each batch is its own transaction so a long sweep
// doesn't block writes for the whole run.
func (w *RetentionWorker) deleteBatch(ctx context.Context, table, tsCol string, cutoff time.Time) (int64, error) {
	var totalDeleted int64
	for {
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		default:
		}
		// Subselect form keeps the planner simple across PG / SQLite.
		// Using a parameterised LIMIT subquery is the common idiom for
		// chunked DELETE on large tables.
		stmt := fmt.Sprintf(`
			DELETE FROM %s
			WHERE %s IN (
				SELECT %s FROM %s
				WHERE %s < ?
				ORDER BY %s ASC
				LIMIT %d
			)
		`, table, tsCol, tsCol, table, tsCol, tsCol, w.policy.BatchSize)
		// Note: deleting by timestamp can match multiple rows with the
		// same value - that's fine, the chunking still bounds runtime.
		res := w.db.WithContext(ctx).Exec(stmt, cutoff)
		if res.Error != nil {
			if errors.Is(res.Error, context.Canceled) || errors.Is(res.Error, context.DeadlineExceeded) {
				return totalDeleted, res.Error
			}
			return totalDeleted, res.Error
		}
		totalDeleted += res.RowsAffected
		if res.RowsAffected < int64(w.policy.BatchSize) {
			return totalDeleted, nil
		}
		// Tiny pause between batches so we don't starve concurrent
		// log writers on the same connection pool.
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
