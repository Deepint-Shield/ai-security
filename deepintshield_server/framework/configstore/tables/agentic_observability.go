// Package tables: Agentic Observability - local trace/observation store
// that mirrors the Langfuse data model so the UI can render full agent
// traces (Fig 17) without an external dependency, while still allowing
// outbound OTel fan-out to a self-hosted Langfuse instance.
//
// Important: this is the *observability* (sampled, operational) store -
// distinct from the hash-chained Audit store, which remains the
// compliance system of record (§9.1).
package tables

import (
	"encoding/json"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	// Trace status mirrors the run's outcome.
	AgenticTraceStatusRunning  = "running"
	AgenticTraceStatusComplete = "complete"
	AgenticTraceStatusAwaiting = "awaiting_approval"
	AgenticTraceStatusBlocked  = "blocked"
	AgenticTraceStatusError    = "error"

	// Observation kinds - keep aligned with Langfuse semantic conventions.
	AgenticObservationKindLLMCall    = "llm_call"
	AgenticObservationKindToolCall   = "tool_call"
	AgenticObservationKindGuardrail  = "guardrail"
	AgenticObservationKindObligation = "obligation"
	AgenticObservationKindAgentStep  = "agent_step"
	AgenticObservationKindMessage    = "user_message"

	// Score names used by the platform-supplied evaluators.
	AgenticScoreRedTeamContainment = "redteam_containment"
	AgenticScoreIntentMatch        = "intent_match"
	AgenticScoreLatencyBudget      = "latency_budget"
)

// ============================================================================
// TableAgenticTrace - one run / session of an agent
// ============================================================================

type TableAgenticTrace struct {
	TraceID        string  `gorm:"column:trace_id;type:varchar(64);primaryKey" json:"trace_id"`
	TenantID       string  `gorm:"column:tenant_id;type:varchar(255);not null;index:idx_agentic_traces_tenant_started,priority:1" json:"-"`
	WorkspaceID    string  `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	VirtualKeyID   string  `gorm:"column:virtual_key_id;type:varchar(64);index" json:"virtual_key_id,omitempty"`
	SessionID      string  `gorm:"column:session_id;type:varchar(128);index" json:"session_id,omitempty"`
	UserRef        string  `gorm:"column:user_ref;type:varchar(255);index" json:"user_ref,omitempty"`
	Principal      string  `gorm:"column:principal;type:varchar(255);index" json:"principal,omitempty"`
	AgentChainJSON string  `gorm:"column:agent_chain_json;type:text" json:"-"`
	ToolCallCount  int     `gorm:"column:tool_call_count;not null;default:0" json:"tool_call_count"`
	AllowCount     int     `gorm:"column:allow_count;not null;default:0" json:"allow_count"`
	DenyCount      int     `gorm:"column:deny_count;not null;default:0" json:"deny_count"`
	MaskCount      int     `gorm:"column:mask_count;not null;default:0" json:"mask_count"`
	ApprovalCount  int     `gorm:"column:approval_count;not null;default:0" json:"approval_count"`
	LatencyMs      int     `gorm:"column:latency_ms;not null;default:0" json:"latency_ms"`
	CostUSD        float64 `gorm:"column:cost_usd;not null;default:0" json:"cost_usd"`
	TokensInput    int     `gorm:"column:tokens_input;not null;default:0" json:"tokens_input"`
	TokensOutput   int     `gorm:"column:tokens_output;not null;default:0" json:"tokens_output"`
	Status         string  `gorm:"column:status;type:varchar(32);not null;default:'running';index" json:"status"`
	// PrimaryTool surfaces the most-recent tool name the run touched so
	// the trace list can show "what did this run actually do?" without
	// the UI joining observations on every render. Updated by the trace
	// sink on every observation; eventually consistent.
	PrimaryTool string `gorm:"column:primary_tool;type:varchar(255);index" json:"primary_tool,omitempty"`
	// PrimaryModel is the dominant model seen on LLM observations (last
	// write wins). Empty until an LLM observation is emitted.
	PrimaryModel  string     `gorm:"column:primary_model;type:varchar(128)" json:"primary_model,omitempty"`
	StartedAt     time.Time  `gorm:"column:started_at;not null;index:idx_agentic_traces_tenant_started,priority:2;index" json:"started_at"`
	EndedAt       *time.Time `gorm:"column:ended_at;index" json:"ended_at,omitempty"`
	InitialPrompt string     `gorm:"column:initial_prompt;type:varchar(512)" json:"initial_prompt,omitempty"` // truncated, never PII
	MetadataJSON  string     `gorm:"column:metadata_json;type:text" json:"-"`

	AgentChain []string       `gorm:"-" json:"agent_chain,omitempty"`
	Metadata   map[string]any `gorm:"-" json:"metadata,omitempty"`
}

func (TableAgenticTrace) TableName() string { return "agentic_traces" }

func (t *TableAgenticTrace) BeforeSave(tx *gorm.DB) error {
	if t.AgentChain != nil {
		data, _ := json.Marshal(t.AgentChain)
		t.AgentChainJSON = string(data)
	}
	if t.Metadata != nil {
		data, _ := json.Marshal(t.Metadata)
		t.MetadataJSON = string(data)
	}
	t.Status = strings.ToLower(strings.TrimSpace(t.Status))
	if t.Status == "" {
		t.Status = AgenticTraceStatusRunning
	}
	return nil
}

func (t *TableAgenticTrace) AfterFind(tx *gorm.DB) error {
	if strings.TrimSpace(t.AgentChainJSON) != "" {
		_ = json.Unmarshal([]byte(t.AgentChainJSON), &t.AgentChain)
	}
	return decodeJSONStringMap(t.MetadataJSON, &t.Metadata)
}

// ============================================================================
// TableAgenticObservation - individual span inside a trace
// ============================================================================

type TableAgenticObservation struct {
	ObservationID string `gorm:"column:observation_id;type:varchar(64);primaryKey" json:"observation_id"`
	TraceID       string `gorm:"column:trace_id;type:varchar(64);not null;index" json:"trace_id"`
	ParentID      string `gorm:"column:parent_id;type:varchar(64);index" json:"parent_id,omitempty"`
	TenantID      string `gorm:"column:tenant_id;type:varchar(255);not null;index" json:"-"`
	WorkspaceID   string `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	Kind          string `gorm:"column:kind;type:varchar(32);not null;index" json:"kind"`
	Name          string `gorm:"column:name;type:varchar(255);index" json:"name"`

	// Tool-call specific
	ToolName          string `gorm:"column:tool_name;type:varchar(255);index" json:"tool_name,omitempty"`
	Verdict           string `gorm:"column:verdict;type:varchar(32);index" json:"verdict,omitempty"`
	PolicyID          string `gorm:"column:policy_id;type:varchar(64)" json:"policy_id,omitempty"`
	DecisionID        string `gorm:"column:decision_id;type:varchar(64);index" json:"decision_id,omitempty"`
	DecisionLatencyUS int    `gorm:"column:decision_latency_us" json:"decision_latency_us,omitempty"`
	ObligationsJSON   string `gorm:"column:obligations_json;type:text" json:"-"`

	// LLM specific
	ModelName    string  `gorm:"column:model_name;type:varchar(255);index" json:"model_name,omitempty"`
	TokensInput  int     `gorm:"column:tokens_input;not null;default:0" json:"tokens_input"`
	TokensOutput int     `gorm:"column:tokens_output;not null;default:0" json:"tokens_output"`
	CostUSD      float64 `gorm:"column:cost_usd;not null;default:0" json:"cost_usd"`

	LatencyMs int        `gorm:"column:latency_ms;not null;default:0" json:"latency_ms"`
	StartedAt time.Time  `gorm:"column:started_at;not null;index" json:"started_at"`
	EndedAt   *time.Time `gorm:"column:ended_at" json:"ended_at,omitempty"`
	// No DB default: with a struct Create, GORM omits a zero-value bool that
	// has a `default` tag, so DENY observations (StatusOK=false) were silently
	// stored as true - leaving the Observability "Error Reasons" panel empty.
	// Dropping the default makes GORM persist the explicit value. The writer
	// always sets StatusOK, so there is nothing relying on a DB default.
	StatusOK     bool   `gorm:"column:status_ok;not null" json:"status_ok"`
	StatusReason string `gorm:"column:status_reason;type:varchar(255)" json:"status_reason,omitempty"`

	// Args / output are stored as digest only (zero-data-retention).
	ArgsDigest   string `gorm:"column:args_digest;type:varchar(128)" json:"args_digest,omitempty"`
	OutputDigest string `gorm:"column:output_digest;type:varchar(128)" json:"output_digest,omitempty"`

	// PromptPreview is an OPT-IN, PII-masked + truncated snippet (≤512 chars)
	// of the step's prompt / input, so operators can read "what was asked" per
	// action (Zenity/Entro/OASIS style). Persisted ONLY when the workspace sets
	// TableAgenticObservabilitySettings.CapturePromptPreview; default-off keeps
	// the zero-data-retention guarantee. The ingestion handler masks + truncates
	// before this is ever written - it never holds raw text.
	PromptPreview string `gorm:"column:prompt_preview;type:varchar(512)" json:"prompt_preview,omitempty"`

	AttributesJSON string `gorm:"column:attributes_json;type:text" json:"-"`

	Obligations []string       `gorm:"-" json:"obligations,omitempty"`
	Attributes  map[string]any `gorm:"-" json:"attributes,omitempty"`
}

func (TableAgenticObservation) TableName() string { return "agentic_observations" }

func (o *TableAgenticObservation) BeforeSave(tx *gorm.DB) error {
	if o.Obligations != nil {
		data, _ := json.Marshal(o.Obligations)
		o.ObligationsJSON = string(data)
	}
	if o.Attributes != nil {
		data, _ := json.Marshal(o.Attributes)
		o.AttributesJSON = string(data)
	}
	return nil
}

func (o *TableAgenticObservation) AfterFind(tx *gorm.DB) error {
	if err := decodeJSONStringSlice(o.ObligationsJSON, &o.Obligations); err != nil {
		return err
	}
	return decodeJSONStringMap(o.AttributesJSON, &o.Attributes)
}

// ============================================================================
// TableAgenticScore - eval / judge score attached to a trace
// ============================================================================

type TableAgenticScore struct {
	ID            string    `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID      string    `gorm:"column:tenant_id;type:varchar(255);not null;index" json:"-"`
	WorkspaceID   string    `gorm:"column:workspace_id;type:varchar(64);index" json:"workspace_id"`
	TraceID       string    `gorm:"column:trace_id;type:varchar(64);not null;index" json:"trace_id"`
	ObservationID string    `gorm:"column:observation_id;type:varchar(64);index" json:"observation_id,omitempty"`
	Name          string    `gorm:"column:name;type:varchar(128);not null;index" json:"name"`
	Value         float64   `gorm:"column:value;not null" json:"value"`
	Comment       string    `gorm:"column:comment;type:varchar(512)" json:"comment,omitempty"`
	Source        string    `gorm:"column:source;type:varchar(64)" json:"source,omitempty"` // platform | llm_judge | human
	CreatedAt     time.Time `gorm:"not null;index" json:"created_at"`
}

func (TableAgenticScore) TableName() string { return "agentic_scores" }

// ============================================================================
// TableAgenticObservabilitySettings - per-workspace observability config
// ============================================================================

// One row per tenant/workspace; controls Langfuse endpoint, sampling rates,
// score-toggles, masking/redaction, and dual-export to metrics. Matches
// Fig 18 of the spec.
type TableAgenticObservabilitySettings struct {
	ID          string `gorm:"type:varchar(64);primaryKey" json:"id"`
	TenantID    string `gorm:"column:tenant_id;type:varchar(255);not null;uniqueIndex:idx_agentic_obs_settings_tenant_workspace,priority:1" json:"-"`
	WorkspaceID string `gorm:"column:workspace_id;type:varchar(64);uniqueIndex:idx_agentic_obs_settings_tenant_workspace,priority:2;index" json:"workspace_id"`

	// Backend / transport
	Backend        string `gorm:"column:backend;type:varchar(32);not null;default:'langfuse_self_hosted'" json:"backend"`
	Endpoint       string `gorm:"column:endpoint;type:varchar(512)" json:"endpoint"`
	OtelExporter   string `gorm:"column:otel_exporter;type:varchar(64);not null;default:'otlphttp'" json:"otel_exporter"`
	ProjectMapping string `gorm:"column:project_mapping;type:varchar(64);not null;default:'one_per_workspace'" json:"project_mapping"`

	// Governance / sampling
	MaskBeforeIngest bool `gorm:"column:mask_before_ingest;not null;default:true" json:"mask_before_ingest"`
	ArgsDigestOnly   bool `gorm:"column:args_digest_only;not null;default:true" json:"args_digest_only"`
	// CapturePromptPreview - OPT-IN (default false). When true, the
	// observability ingestion endpoint stores a masked, ≤512-char preview of
	// each step's prompt/input on its observation (PromptPreview) so the
	// execution view can show "what was asked" per action. Default-off keeps
	// zero-data-retention intact; turning it on is an explicit governance choice.
	CapturePromptPreview    bool    `gorm:"column:capture_prompt_preview;not null;default:false" json:"capture_prompt_preview"`
	SecuritySpansSampleRate float64 `gorm:"column:security_spans_sample_rate;not null;default:1.0" json:"security_spans_sample_rate"`
	PayloadSampleRate       float64 `gorm:"column:payload_sample_rate;not null;default:0.2" json:"payload_sample_rate"`
	DualExportMetrics       bool    `gorm:"column:dual_export_metrics;not null;default:true" json:"dual_export_metrics"`

	// Score toggles
	ScoreRedTeam  bool `gorm:"column:score_red_team;not null;default:true" json:"score_red_team"`
	ScoreIntent   bool `gorm:"column:score_intent;not null;default:true" json:"score_intent"`
	ScoreLatency  bool `gorm:"column:score_latency;not null;default:true" json:"score_latency"`
	ScoreLLMJudge bool `gorm:"column:score_llm_judge;not null;default:false" json:"score_llm_judge"`

	// Tool-summary (AI) - config for the "what this tool does" LLM call.
	// SummaryEnabled is the master switch: off ⇒ summaries stay at the
	// deterministic baseline; on ⇒ the summarizer upgrades them via an LLM
	// call routed through the chosen virtual key + model.
	SummaryEnabled      bool   `gorm:"column:summary_enabled;not null;default:false" json:"summary_enabled"`
	SummaryVirtualKeyID string `gorm:"column:summary_virtual_key_id;type:varchar(64)" json:"summary_virtual_key_id,omitempty"`
	SummaryProvider     string `gorm:"column:summary_provider;type:varchar(64)" json:"summary_provider,omitempty"`
	SummaryModel        string `gorm:"column:summary_model;type:varchar(128)" json:"summary_model,omitempty"`

	// Test result
	LastTestedAt *time.Time `gorm:"column:last_tested_at" json:"last_tested_at,omitempty"`
	LastTestOK   bool       `gorm:"column:last_test_ok" json:"last_test_ok"`
	LastError    string     `gorm:"type:text" json:"last_error,omitempty"`

	CreatedAt time.Time `gorm:"not null;index" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;index" json:"updated_at"`
}

func (TableAgenticObservabilitySettings) TableName() string { return "agentic_observability_settings" }
