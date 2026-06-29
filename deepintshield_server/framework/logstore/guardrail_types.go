package logstore

import (
	"errors"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"gorm.io/gorm"
)

var (
	errImmutableGuardrailFinding  = errors.New("guardrail findings are immutable")
	errImmutableGuardrailDecision = errors.New("guardrail decisions are immutable")
	errImmutableGuardrailTrace    = errors.New("guardrail traces are immutable")
)

type GuardrailFinding struct {
	ID       string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_findings_tenant_created,priority:1" json:"-"`
	// WorkspaceID - see GuardrailTrace.WorkspaceID rationale. Same
	// nullable-with-scope-helper fallback strategy.
	WorkspaceID     *string        `gorm:"column:workspace_id;type:varchar(255);index:idx_guardrail_findings_workspace" json:"workspace_id,omitempty"`
	RequestID       string         `gorm:"column:request_id;type:varchar(255);index" json:"request_id"`
	TraceID         string         `gorm:"column:trace_id;type:varchar(255);index" json:"trace_id"`
	Stage           string         `gorm:"type:varchar(32);index" json:"stage"`
	PolicyID        string         `gorm:"column:policy_id;type:varchar(255);index" json:"policy_id"`
	PolicyVersionID string         `gorm:"column:policy_version_id;type:varchar(255);index" json:"policy_version_id"`
	ProviderID      string         `gorm:"column:provider_id;type:varchar(255);index" json:"provider_id,omitempty"`
	Category        string         `gorm:"type:varchar(128);index" json:"category"`
	Severity        string         `gorm:"type:varchar(32);index" json:"severity"`
	Confidence      float64        `gorm:"not null;default:0" json:"confidence"`
	Outcome         string         `gorm:"type:varchar(64);index" json:"outcome"`
	Summary         string         `gorm:"type:text" json:"summary"`
	ActorType       string         `gorm:"column:actor_type;type:varchar(64);index" json:"actor_type,omitempty"`
	ActorID         string         `gorm:"column:actor_id;type:varchar(255);index" json:"actor_id,omitempty"`
	ResourceType    string         `gorm:"column:resource_type;type:varchar(128);index" json:"resource_type,omitempty"`
	ResourceID      string         `gorm:"column:resource_id;type:varchar(255);index" json:"resource_id,omitempty"`
	DetailsJSON     string         `gorm:"column:details_json;type:text" json:"-"`
	CreatedAt       time.Time      `gorm:"index:idx_guardrail_findings_tenant_created,priority:2;not null" json:"created_at"`
	Details         map[string]any `gorm:"-" json:"details,omitempty"`
}

func (GuardrailFinding) TableName() string { return "guardrail_findings" }

func (f *GuardrailFinding) BeforeCreate(tx *gorm.DB) error {
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	return f.SerializeFields()
}

func (f *GuardrailFinding) AfterFind(tx *gorm.DB) error    { return f.DeserializeFields() }
func (f *GuardrailFinding) BeforeUpdate(tx *gorm.DB) error { return errImmutableGuardrailFinding }
func (f *GuardrailFinding) BeforeDelete(tx *gorm.DB) error { return errImmutableGuardrailFinding }

func (f *GuardrailFinding) SerializeFields() error {
	if f.Details != nil {
		raw, err := sonic.Marshal(f.Details)
		if err != nil {
			return err
		}
		f.DetailsJSON = string(raw)
	}
	return nil
}

func (f *GuardrailFinding) DeserializeFields() error {
	f.Details = nil
	if strings.TrimSpace(f.DetailsJSON) == "" {
		return nil
	}
	var decoded map[string]any
	if err := sonic.Unmarshal([]byte(f.DetailsJSON), &decoded); err != nil {
		return err
	}
	f.Details = decoded
	return nil
}

type GuardrailDecision struct {
	ID               string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID         string `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_decisions_tenant_created,priority:1" json:"-"`
	RequestID        string `gorm:"column:request_id;type:varchar(255);index" json:"request_id"`
	TraceID          string `gorm:"column:trace_id;type:varchar(255);index" json:"trace_id"`
	Stage            string `gorm:"type:varchar(32);index" json:"stage"`
	PolicyID         string `gorm:"column:policy_id;type:varchar(255);index" json:"policy_id"`
	PolicyVersionID  string `gorm:"column:policy_version_id;type:varchar(255);index" json:"policy_version_id"`
	Decision         string `gorm:"type:varchar(64);index" json:"decision"`
	Reason           string `gorm:"type:text" json:"reason"`
	ApprovalRequired bool   `gorm:"column:approval_required;not null;default:false" json:"approval_required"`
	LatencyMs        int    `gorm:"column:latency_ms;not null;default:0" json:"latency_ms"`
	// EngineSource is "ai_model" | "policy" | "mixed" | "" set at write time from the evaluated
	// policies' provider bindings. Lets the read-side classifier surface the Engine column on
	// Allow-with-no-findings rows where policy_id stays empty.
	EngineSource      string    `gorm:"column:engine_source;type:varchar(32);index" json:"engine_source,omitempty"`
	RedactionsJSON    string    `gorm:"column:redactions_json;type:text" json:"-"`
	DecisionChainJSON string    `gorm:"column:decision_chain_json;type:text" json:"-"`
	CreatedAt         time.Time `gorm:"index:idx_guardrail_decisions_tenant_created,priority:2;not null" json:"created_at"`
	Redactions        []string  `gorm:"-" json:"redactions,omitempty"`
	DecisionChain     []string  `gorm:"-" json:"decision_chain,omitempty"`
}

func (GuardrailDecision) TableName() string { return "guardrail_decisions" }

func (d *GuardrailDecision) BeforeCreate(tx *gorm.DB) error {
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	if d.Redactions != nil {
		raw, err := sonic.Marshal(d.Redactions)
		if err != nil {
			return err
		}
		d.RedactionsJSON = string(raw)
	}
	if d.DecisionChain != nil {
		raw, err := sonic.Marshal(d.DecisionChain)
		if err != nil {
			return err
		}
		d.DecisionChainJSON = string(raw)
	}
	return nil
}

func (d *GuardrailDecision) AfterFind(tx *gorm.DB) error {
	if strings.TrimSpace(d.RedactionsJSON) != "" {
		if err := sonic.Unmarshal([]byte(d.RedactionsJSON), &d.Redactions); err != nil {
			return err
		}
	}
	if strings.TrimSpace(d.DecisionChainJSON) != "" {
		if err := sonic.Unmarshal([]byte(d.DecisionChainJSON), &d.DecisionChain); err != nil {
			return err
		}
	}
	return nil
}

func (d *GuardrailDecision) BeforeUpdate(tx *gorm.DB) error { return errImmutableGuardrailDecision }
func (d *GuardrailDecision) BeforeDelete(tx *gorm.DB) error { return errImmutableGuardrailDecision }

type GuardrailTrace struct {
	ID       string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_traces_tenant_created,priority:1" json:"-"`
	// WorkspaceID is stamped at write-time so dashboard queries can scope
	// directly without the prior 3-way subquery against logs +
	// agentic_decisions. Nullable for legacy rows that pre-date the
	// column; the scope helper treats NULL as "match" so historical
	// traces stay visible during the transition.
	WorkspaceID  *string `gorm:"column:workspace_id;type:varchar(255);index:idx_guardrail_traces_workspace" json:"workspace_id,omitempty"`
	RequestID    string  `gorm:"column:request_id;type:varchar(255);index" json:"request_id"`
	Stage        string  `gorm:"type:varchar(32);index" json:"stage,omitempty"`
	ActorType    string  `gorm:"column:actor_type;type:varchar(64);index" json:"actor_type"`
	ActorID      string  `gorm:"column:actor_id;type:varchar(255);index" json:"actor_id"`
	Model        string  `gorm:"type:varchar(255);index" json:"model"`
	Provider     string  `gorm:"type:varchar(255);index" json:"provider"`
	InputSummary string  `gorm:"column:input_summary;type:text" json:"input_summary"`
	// OutputSummary must always serialize as a string (even empty) -
	// the dashboard's MCP Security tab does `trace.output_summary.trim()`
	// directly, so `omitempty` makes it `undefined` for stage=mcp traces
	// that have no output yet and the page crashes with "Cannot read
	// properties of undefined (reading 'trim')".
	OutputSummary     string         `gorm:"column:output_summary;type:text" json:"output_summary"`
	Decision          string         `gorm:"type:varchar(64);index" json:"decision"`
	DecisionChainJSON string         `gorm:"column:decision_chain_json;type:text" json:"-"`
	MetadataJSON      string         `gorm:"column:metadata_json;type:text" json:"-"`
	CreatedAt         time.Time      `gorm:"index:idx_guardrail_traces_tenant_created,priority:2;not null" json:"created_at"`
	DecisionChain     []string       `gorm:"-" json:"decision_chain,omitempty"`
	Metadata          map[string]any `gorm:"-" json:"metadata,omitempty"`
}

func (GuardrailTrace) TableName() string { return "guardrail_traces" }

func (t *GuardrailTrace) BeforeCreate(tx *gorm.DB) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	t.Stage = strings.ToLower(strings.TrimSpace(t.Stage))
	if t.DecisionChain != nil {
		raw, err := sonic.Marshal(t.DecisionChain)
		if err != nil {
			return err
		}
		t.DecisionChainJSON = string(raw)
	}
	if t.Metadata != nil {
		raw, err := sonic.Marshal(t.Metadata)
		if err != nil {
			return err
		}
		t.MetadataJSON = string(raw)
	}
	return nil
}

func (t *GuardrailTrace) AfterFind(tx *gorm.DB) error {
	if strings.TrimSpace(t.DecisionChainJSON) != "" {
		if err := sonic.Unmarshal([]byte(t.DecisionChainJSON), &t.DecisionChain); err != nil {
			return err
		}
	}
	if strings.TrimSpace(t.MetadataJSON) != "" {
		if err := sonic.Unmarshal([]byte(t.MetadataJSON), &t.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func (t *GuardrailTrace) BeforeUpdate(tx *gorm.DB) error { return errImmutableGuardrailTrace }
func (t *GuardrailTrace) BeforeDelete(tx *gorm.DB) error { return errImmutableGuardrailTrace }

type GuardrailApprovalRequest struct {
	ID              string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	TenantID        string     `gorm:"column:tenant_id;type:varchar(255);index:idx_guardrail_approvals_tenant_created,priority:1" json:"-"`
	RequestID       string     `gorm:"column:request_id;type:varchar(255);index" json:"request_id"`
	TraceID         string     `gorm:"column:trace_id;type:varchar(255);index" json:"trace_id"`
	Stage           string     `gorm:"type:varchar(32);index" json:"stage,omitempty"`
	PolicyID        string     `gorm:"column:policy_id;type:varchar(255);index" json:"policy_id"`
	PolicyName      string     `gorm:"column:policy_name;type:varchar(255);index" json:"policy_name"`
	Title           string     `gorm:"type:varchar(255)" json:"title"`
	Status          string     `gorm:"type:varchar(64);index" json:"status"`
	RequestedAction string     `gorm:"column:requested_action;type:varchar(64);index" json:"requested_action"`
	ActorType       string     `gorm:"column:actor_type;type:varchar(64);index" json:"actor_type"`
	ActorID         string     `gorm:"column:actor_id;type:varchar(255);index" json:"actor_id"`
	Approver        string     `gorm:"type:varchar(255)" json:"approver,omitempty"`
	DecisionNotes   string     `gorm:"column:decision_notes;type:text" json:"decision_notes,omitempty"`
	RiskSummary     string     `gorm:"column:risk_summary;type:text" json:"risk_summary"`
	ExpiresAt       *time.Time `gorm:"index" json:"expires_at,omitempty"`
	ReviewedAt      *time.Time `gorm:"index" json:"reviewed_at,omitempty"`
	CreatedAt       time.Time  `gorm:"index:idx_guardrail_approvals_tenant_created,priority:2;not null" json:"created_at"`
	UpdatedAt       time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (GuardrailApprovalRequest) TableName() string { return "guardrail_approval_requests" }

func (a *GuardrailApprovalRequest) BeforeSave(tx *gorm.DB) error {
	a.Title = strings.TrimSpace(a.Title)
	a.Stage = strings.ToLower(strings.TrimSpace(a.Stage))
	a.Status = strings.ToLower(strings.TrimSpace(a.Status))
	if a.Status == "" {
		a.Status = "pending"
	}
	a.RequestedAction = strings.ToLower(strings.TrimSpace(a.RequestedAction))
	a.ActorType = strings.TrimSpace(a.ActorType)
	a.ActorID = strings.TrimSpace(a.ActorID)
	a.Approver = strings.TrimSpace(a.Approver)
	a.DecisionNotes = strings.TrimSpace(a.DecisionNotes)
	a.RiskSummary = strings.TrimSpace(a.RiskSummary)
	return nil
}
