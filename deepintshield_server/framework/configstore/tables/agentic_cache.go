// Package tables: Agentic Cache - analytics + config store for the
// post-decision, boundary-scoped agentic cache (Part X of the build spec).
//
// Zero-data-retention: this store holds cache *events* (hit/miss/store +
// savings metrics) and *config*, never any cached payload. The payloads live
// only in the ephemeral in-process / Redis caches in framework/agentic.
package tables

import "time"

// Cache-event kinds + sub-cache kinds - keep aligned with the agentic.CacheKind
// constants in framework/agentic/agentic_cache.go.
const (
	AgenticCacheEventHit   = "hit"
	AgenticCacheEventMiss  = "miss"
	AgenticCacheEventStore = "store"
)

// ============================================================================
// TableAgenticCacheEvent - one sampled cache lookup / store (append-only)
// ============================================================================

// TableAgenticCacheEvent powers the time-series savings graphs (Agent Insights
// Caching tab + the additive overlays). It records only the authorization
// boundary and the savings numbers - never the cached content.
type TableAgenticCacheEvent struct {
	Sequence     uint64 `gorm:"column:sequence;primaryKey;autoIncrement" json:"sequence"`
	TenantID     string `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_cache_events_tenant_ts,priority:1" json:"tenant_id"`
	WorkspaceID  string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	VirtualKeyID string `gorm:"column:virtual_key_id;type:varchar(64);index" json:"virtual_key_id,omitempty"`
	CacheKind    string `gorm:"column:cache_kind;type:varchar(32);not null;index" json:"cache_kind"`
	Event        string `gorm:"column:event;type:varchar(16);not null;index" json:"event"` // hit|miss|store
	Tool         string `gorm:"column:tool;type:varchar(255);index" json:"tool,omitempty"`

	TokensSaved    int     `gorm:"column:tokens_saved;not null;default:0" json:"tokens_saved"`
	CostSavedUSD   float64 `gorm:"column:cost_saved_usd;not null;default:0" json:"cost_saved_usd"`
	LatencySavedMs int     `gorm:"column:latency_saved_ms;not null;default:0" json:"latency_saved_ms"`

	CreatedAt time.Time `gorm:"column:created_at;not null;index:idx_agentic_cache_events_tenant_ts,priority:2;index" json:"created_at"`
}

func (TableAgenticCacheEvent) TableName() string { return "agentic_cache_events" }

// ============================================================================
// TableAgenticCacheSettings - per-workspace agentic-cache config (§10.5)
// ============================================================================

// One row per tenant/workspace; mirrors deploy/cache.yaml's agentic block plus
// the console controls (read-only / never-cache-high-risk / encrypt / honor
// obligations). The runtime config is env-seeded; this row lets an operator
// tune per workspace through the console / GitOps.
type TableAgenticCacheSettings struct {
	ID          string `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID    string `gorm:"column:tenant_id;type:varchar(255);not null;uniqueIndex:idx_agentic_cache_settings_tenant_workspace,priority:1" json:"-"`
	WorkspaceID string `gorm:"column:workspace_id;type:varchar(64);uniqueIndex:idx_agentic_cache_settings_tenant_workspace,priority:2;index" json:"workspace_id"`

	// Master switch + per-cache enables.
	Enabled             bool `gorm:"column:enabled;not null;default:true" json:"enabled"`
	ResponseEnabled     bool `gorm:"column:response_enabled;not null;default:true" json:"response_enabled"`
	SemanticEnabled     bool `gorm:"column:semantic_enabled;not null;default:true" json:"semantic_enabled"`
	ToolResultEnabled   bool `gorm:"column:tool_result_enabled;not null;default:true" json:"tool_result_enabled"`
	EmbeddingEnabled    bool `gorm:"column:embedding_enabled;not null;default:true" json:"embedding_enabled"`
	MCPDiscoveryEnabled bool `gorm:"column:mcp_discovery_enabled;not null;default:true" json:"mcp_discovery_enabled"`

	// §10.5 controls.
	SemanticThreshold  float64 `gorm:"column:semantic_threshold;not null;default:0.92" json:"semantic_threshold"`
	SemanticReadOnly   bool    `gorm:"column:semantic_read_only;not null;default:true" json:"semantic_read_only"`
	NeverCacheHighRisk bool    `gorm:"column:never_cache_high_risk;not null;default:true" json:"never_cache_high_risk"`
	EncryptAtRest      bool    `gorm:"column:encrypt_at_rest;not null;default:true" json:"encrypt_at_rest"`
	HonorObligations   bool    `gorm:"column:honor_obligations;not null;default:true" json:"honor_obligations"`

	// TTLs (seconds) for the editable caches.
	ResponseTTLSeconds   int `gorm:"column:response_ttl_seconds;not null;default:3600" json:"response_ttl_seconds"`
	SemanticTTLSeconds   int `gorm:"column:semantic_ttl_seconds;not null;default:1800" json:"semantic_ttl_seconds"`
	ToolResultTTLSeconds int `gorm:"column:tool_result_ttl_seconds;not null;default:600" json:"tool_result_ttl_seconds"`

	CreatedAt time.Time `gorm:"not null;index" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;index" json:"updated_at"`
}

func (TableAgenticCacheSettings) TableName() string { return "agentic_cache_settings" }
