package logstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"github.com/deepint-shield/ai-security/core/schemas"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/valyala/fasthttp"
)

const (
	// DefaultAsyncJobResultTTL is the default TTL for async job results in seconds (1 hour).
	DefaultAsyncJobResultTTL = 3600
)

const (
	asyncJobCleanupInterval      = 1 * time.Minute
	asyncJobCleanupTimeout       = 1 * time.Minute
	asyncJobStaleProcessingHours = 24
)

// --- AsyncJobExecutor ---

// AsyncOperation represents a function that can be executed asynchronously.
// It returns the response and an optional DeepIntShieldError.
type AsyncOperation func(ctx *schemas.DeepIntShieldContext) (interface{}, *schemas.DeepIntShieldError)

// GovernanceStore is an interface that provides access to the governance store.
type GovernanceStore interface {
	GetVirtualKey(ctx context.Context, vkValue string) (*configstoreTables.TableVirtualKey, bool)
}

// AsyncJobExecutor manages async job creation and background execution.
type AsyncJobExecutor struct {
	logstore        LogStore
	governanceStore GovernanceStore
	logger          schemas.Logger
}

// NewAsyncJobExecutor creates a new AsyncJobExecutor.
func NewAsyncJobExecutor(logstore LogStore, governanceStore GovernanceStore, logger schemas.Logger) *AsyncJobExecutor {
	return &AsyncJobExecutor{
		logstore:        logstore,
		governanceStore: governanceStore,
		logger:          logger,
	}
}

// RetrieveJob retrieves a job by its ID.
func (e *AsyncJobExecutor) RetrieveJob(ctx context.Context, jobID string, vkValue *string, operationType schemas.RequestType) (*AsyncJob, error) {
	job, err := e.logstore.FindAsyncJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("job not found or expired")
		}
		return nil, fmt.Errorf("failed to retrieve async job: %w", err)
	}
	if job.VirtualKeyID != nil {
		if vkValue == nil {
			return nil, fmt.Errorf("virtual key is required")
		}
		vk, ok := e.governanceStore.GetVirtualKey(ctx, *vkValue)
		if !ok {
			return nil, fmt.Errorf("virtual key not found")
		}
		if *job.VirtualKeyID != vk.ID {
			return nil, fmt.Errorf("virtual key mismatch")
		}
	}
	if job.RequestType != operationType {
		return nil, fmt.Errorf("operation type mismatch")
	}
	return job, nil
}

// SubmitJob creates a pending job, starts background execution, and returns the job record.
func (e *AsyncJobExecutor) SubmitJob(ctx context.Context, virtualKeyValue *string, resultTTL int, operation AsyncOperation, operationType schemas.RequestType) (*AsyncJob, error) {
	if resultTTL <= 0 {
		resultTTL = DefaultAsyncJobResultTTL
	}

	var virtualKeyID *string
	if virtualKeyValue != nil {
		vk, ok := e.governanceStore.GetVirtualKey(ctx, *virtualKeyValue)
		if !ok {
			return nil, fmt.Errorf("virtual key not found")
		}
		virtualKeyID = &vk.ID
	}

	now := time.Now().UTC()
	job := &AsyncJob{
		ID:           uuid.New().String(),
		TenantID:     tenantctx.TenantIDFromContext(ctx),
		Status:       schemas.AsyncJobStatusPending,
		RequestType:  operationType,
		VirtualKeyID: virtualKeyID,
		ResultTTL:    resultTTL,
		CreatedAt:    now,
	}

	createCtx := ctx
	if createCtx == nil {
		createCtx = context.Background()
	}
	if err := e.logstore.CreateAsyncJob(createCtx, job); err != nil {
		return nil, fmt.Errorf("failed to create async job: %w", err)
	}

	go e.executeJob(job.ID, job.ResultTTL, job.TenantID, operation)

	return job, nil
}

// executeJob runs the operation in the background and updates the job record.
func (e *AsyncJobExecutor) executeJob(jobID string, resultTTL int, tenantID string, operation AsyncOperation) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	if tenantID != "" {
		ctx.SetValue(schemas.DeepIntShieldContextKeyTenantID, tenantID)
		ctx.SetValue(schemas.DeepIntShieldContextKeyUserID, tenantID)
	}

	markFailed := func(msg string) {
		now := time.Now().UTC()
		expiresAt := now.Add(time.Duration(resultTTL) * time.Second)
		errJSON, _ := sonic.Marshal(&schemas.DeepIntShieldError{Error: &schemas.ErrorField{Message: msg}})
		if err := e.logstore.UpdateAsyncJob(ctx, jobID, map[string]interface{}{
			"status":       schemas.AsyncJobStatusFailed,
			"status_code":  fasthttp.StatusInternalServerError,
			"error":        string(errJSON),
			"completed_at": now,
			"expires_at":   expiresAt,
		}); err != nil {
			e.logger.Warn("failed to update async job to failed: %v", err)
		}
	}

	// The deepintshield execution flow is very stable and panics are not expected.
	// This recover is purely defensive to ensure the job always reaches a terminal
	// state rather than being stuck in "processing" if an unexpected panic occurs.
	defer func() {
		if r := recover(); r != nil {
			e.logger.Warn("async job %s panicked: %v", jobID, r)
			markFailed(fmt.Sprintf("internal error: %v", r))
		}
	}()

	// Mark as processing
	if err := e.logstore.UpdateAsyncJob(ctx, jobID, map[string]interface{}{
		"status": schemas.AsyncJobStatusProcessing,
	}); err != nil {
		e.logger.Warn("failed to update async job: %v", err)
	}

	ctx.SetValue(schemas.DeepIntShieldIsAsyncRequest, true)

	// Execute the operation
	resp, deepintshieldErr := operation(ctx)

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(resultTTL) * time.Second)

	if deepintshieldErr != nil {
		errJSON, err := sonic.Marshal(deepintshieldErr)
		if err != nil {
			e.logger.Warn("failed to marshal deepintshield error: %v", err)
			markFailed(fmt.Sprintf("failed to serialize error response: %v", err))
			return
		}
		statusCode := fasthttp.StatusInternalServerError
		if deepintshieldErr.StatusCode != nil {
			statusCode = *deepintshieldErr.StatusCode
		}
		if err := e.logstore.UpdateAsyncJob(ctx, jobID, map[string]interface{}{
			"status":       schemas.AsyncJobStatusFailed,
			"status_code":  statusCode,
			"error":        string(errJSON),
			"completed_at": now,
			"expires_at":   expiresAt,
		}); err != nil {
			e.logger.Warn("failed to update async job: %v", err)
		}
		return
	}

	respJSON, err := sonic.Marshal(resp)
	if err != nil {
		e.logger.Warn("failed to marshal result: %v", err)
		markFailed(fmt.Sprintf("failed to serialize result: %v", err))
		return
	}
	if err := e.logstore.UpdateAsyncJob(ctx, jobID, map[string]interface{}{
		"status":       schemas.AsyncJobStatusCompleted,
		"status_code":  fasthttp.StatusOK,
		"response":     string(respJSON),
		"completed_at": now,
		"expires_at":   expiresAt,
	}); err != nil {
		e.logger.Warn("failed to update async job: %v", err)
	}
}

// --- Cleaner ---

// AsyncJobCleaner manages the cleanup of expired async jobs.
type AsyncJobCleaner struct {
	store       LogStore
	logger      schemas.Logger
	stopCleanup chan struct{}
	mu          sync.Mutex
}

// NewAsyncJobCleaner creates a new AsyncJobCleaner instance.
func NewAsyncJobCleaner(store LogStore, logger schemas.Logger) *AsyncJobCleaner {
	return &AsyncJobCleaner{
		store:  store,
		logger: logger,
	}
}

// StartCleanupRoutine starts a goroutine that periodically cleans up expired async jobs.
func (c *AsyncJobCleaner) StartCleanupRoutine() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopCleanup != nil {
		return
	}

	c.stopCleanup = make(chan struct{})
	stopCh := c.stopCleanup

	go func() {
		// Run initial cleanup
		ctx, cancel := context.WithTimeout(context.Background(), asyncJobCleanupTimeout)
		c.cleanupExpiredJobs(ctx)
		cancel()

		ticker := time.NewTicker(asyncJobCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), asyncJobCleanupTimeout)
				c.cleanupExpiredJobs(ctx)
				cancel()
			case <-stopCh:
				c.logger.Debug("async job cleanup routine stopped")
				return
			}
		}
	}()
	c.logger.Debug("async job cleanup routine started (interval: %s)", asyncJobCleanupInterval)
}

// StopCleanupRoutine gracefully stops the cleanup goroutine.
func (c *AsyncJobCleaner) StopCleanupRoutine() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopCleanup == nil {
		c.logger.Debug("async job cleanup routine already stopped")
		return
	}

	close(c.stopCleanup)
	c.stopCleanup = nil
}

// cleanupExpiredJobs deletes expired async jobs and stale processing jobs.
func (c *AsyncJobCleaner) cleanupExpiredJobs(ctx context.Context) {
	deleted, err := c.store.DeleteExpiredAsyncJobs(ctx)
	if err != nil {
		c.logger.Warn("failed to delete expired async jobs: %v", err)
	} else if deleted > 0 {
		c.logger.Debug("async job cleanup completed: deleted %d expired jobs", deleted)
	}

	// Clean up jobs stuck in "processing" for more than 24 hours
	// This handles edge cases like marshal failures or server crashes
	staleSince := time.Now().UTC().Add(-asyncJobStaleProcessingHours * time.Hour)
	staleDeleted, err := c.store.DeleteStaleAsyncJobs(ctx, staleSince)
	if err != nil {
		c.logger.Warn("failed to delete stale processing async jobs: %v", err)
	} else if staleDeleted > 0 {
		c.logger.Warn("async job cleanup: deleted %d stale processing jobs (stuck > %dh)", staleDeleted, asyncJobStaleProcessingHours)
	}
}
