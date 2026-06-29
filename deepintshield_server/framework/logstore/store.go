package logstore

import (
	"context"
	"fmt"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// LogStoreType represents the type of log store.
type LogStoreType string

// LogStoreTypeSQLite is the type of log store for SQLite.
const (
	LogStoreTypeSQLite   LogStoreType = "sqlite"
	LogStoreTypePostgres LogStoreType = "postgres"
)

// MetadataScope narrows GetDistinctMetadataKeysScoped to one of the three
// logical "audiences" the dashboard pages route to. Defaulting to All keeps
// existing callers (analytics, exports) seeing every key.
type MetadataScope string

const (
	// MetadataScopeAll returns keys from every log row regardless of
	// object_type. This is the legacy GetDistinctMetadataKeys behaviour
	// kept for callers that don't care about the AI/Agentic split.
	MetadataScopeAll MetadataScope = "all"
	// MetadataScopeLLM excludes object_type LIKE 'agentic.%' so AI Logs
	// only sees LLM-call metadata keys. Used by /api/logs/filterdata when
	// the request is for the AI Logs view.
	MetadataScopeLLM MetadataScope = "llm"
	// MetadataScopeAgentic restricts to object_type LIKE 'agentic.%' so
	// Agentic Logs sees only PDP-decision metadata keys.
	MetadataScopeAgentic MetadataScope = "agentic"
)

// LogStore is the interface for the log store.
type LogStore interface {
	Ping(ctx context.Context) error
	Create(ctx context.Context, entry *Log) error
	CreateIfNotExists(ctx context.Context, entry *Log) error
	BatchCreateIfNotExists(ctx context.Context, entries []*Log) error
	FindByID(ctx context.Context, id string) (*Log, error)
	FindFirst(ctx context.Context, query any, fields ...string) (*Log, error)
	FindAll(ctx context.Context, query any, fields ...string) ([]*Log, error)
	FindAllDistinct(ctx context.Context, query any, fields ...string) ([]*Log, error)
	HasLogs(ctx context.Context) (bool, error)
	SearchLogs(ctx context.Context, filters SearchFilters, pagination PaginationOptions) (*SearchResult, error)
	GetStats(ctx context.Context, filters SearchFilters) (*SearchStats, error)
	GetHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*HistogramResult, error)
	GetTokenHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*TokenHistogramResult, error)
	GetCacheHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*CacheHistogramResult, error)
	GetCostHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*CostHistogramResult, error)
	GetOptimizationHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*OptimizationHistogramResult, error)
	GetModelHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ModelHistogramResult, error)
	GetLatencyHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*LatencyHistogramResult, error)
	GetProviderCostHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ProviderCostHistogramResult, error)
	GetProviderTokenHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ProviderTokenHistogramResult, error)
	GetProviderLatencyHistogram(ctx context.Context, filters SearchFilters, bucketSizeSeconds int64) (*ProviderLatencyHistogramResult, error)
	GetModelRankings(ctx context.Context, filters SearchFilters) (*ModelRankingResult, error)
	RefreshDashboardAggregates(ctx context.Context) error
	Update(ctx context.Context, id string, entry any) error
	BulkUpdateCost(ctx context.Context, updates map[string]float64) error
	Flush(ctx context.Context, since time.Time) error
	Close(ctx context.Context) error
	DeleteLog(ctx context.Context, id string) error
	DeleteLogs(ctx context.Context, ids []string) error
	DeleteLogsBatch(ctx context.Context, cutoff time.Time, batchSize int) (deletedCount int64, err error)

	// Distinct value methods for filter data
	GetDistinctModels(ctx context.Context) ([]string, error)
	GetDistinctKeyPairs(ctx context.Context, idCol, nameCol string) ([]KeyPairResult, error)
	GetDistinctRoutingEngines(ctx context.Context) ([]string, error)
	GetDistinctGuardrailStatuses(ctx context.Context) ([]string, error)
	GetDistinctMetadataKeys(ctx context.Context) (map[string][]string, error)
	// GetDistinctMetadataKeysScoped is the same as GetDistinctMetadataKeys
	// but lets the caller include / exclude / scope-to agentic.% rows. AI
	// Logs needs the LLM-only scope so PDP-decision metadata (decision_id,
	// identity_type, verdict, etc.) doesn't leak into its dynamic-column
	// set; Agentic Logs uses the agentic-only scope so those keys are
	// surfaced where they belong. Without this split, both views render
	// the union of metadata keys and AI Logs ends up with 10+
	// permanently-empty columns (the screenshot the operator flagged).
	GetDistinctMetadataKeysScoped(ctx context.Context, scope MetadataScope) (map[string][]string, error) //nolint:lll

	// MCP Tool Log histogram methods
	GetMCPHistogram(ctx context.Context, filters MCPToolLogSearchFilters, bucketSizeSeconds int64) (*MCPHistogramResult, error)
	GetMCPCostHistogram(ctx context.Context, filters MCPToolLogSearchFilters, bucketSizeSeconds int64) (*MCPCostHistogramResult, error)
	GetMCPTopTools(ctx context.Context, filters MCPToolLogSearchFilters, limit int) (*MCPTopToolsResult, error)

	// MCP Tool Log methods
	CreateMCPToolLog(ctx context.Context, entry *MCPToolLog) error
	FindMCPToolLog(ctx context.Context, id string) (*MCPToolLog, error)
	UpdateMCPToolLog(ctx context.Context, id string, entry any) error
	SearchMCPToolLogs(ctx context.Context, filters MCPToolLogSearchFilters, pagination PaginationOptions) (*MCPToolLogSearchResult, error)
	GetMCPToolLogStats(ctx context.Context, filters MCPToolLogSearchFilters) (*MCPToolLogStats, error)
	HasMCPToolLogs(ctx context.Context) (bool, error)
	DeleteMCPToolLogs(ctx context.Context, ids []string) error
	FlushMCPToolLogs(ctx context.Context, since time.Time) error
	GetAvailableToolNames(ctx context.Context) ([]string, error)
	GetAvailableServerLabels(ctx context.Context) ([]string, error)
	GetAvailableMCPVirtualKeys(ctx context.Context) ([]MCPToolLog, error)

	// Async Job methods
	CreateAsyncJob(ctx context.Context, job *AsyncJob) error
	FindAsyncJobByID(ctx context.Context, id string) (*AsyncJob, error)
	UpdateAsyncJob(ctx context.Context, id string, updates map[string]interface{}) error
	DeleteExpiredAsyncJobs(ctx context.Context) (int64, error)
	DeleteStaleAsyncJobs(ctx context.Context, staleSince time.Time) (int64, error)
}

// NewLogStore creates a new log store based on the configuration.
func NewLogStore(ctx context.Context, config *Config, logger schemas.Logger) (LogStore, error) {
	switch config.Type {
	case LogStoreTypeSQLite:
		if sqliteConfig, ok := config.Config.(*SQLiteConfig); ok {
			return newSqliteLogStore(ctx, sqliteConfig, logger)
		}
		return nil, fmt.Errorf("invalid sqlite config: %T", config.Config)
	case LogStoreTypePostgres:
		if postgresConfig, ok := config.Config.(*PostgresConfig); ok {
			return newPostgresLogStore(ctx, postgresConfig, logger)
		}
		return nil, fmt.Errorf("invalid postgres config: %T", config.Config)
	default:
		return nil, fmt.Errorf("unsupported log store type: %s", config.Type)
	}
}
