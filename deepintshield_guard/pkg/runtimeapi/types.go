package runtimeapi

import (
	"strings"
	"time"
)

const (
	StageInput  = "input"
	StageOutput = "output"
	StageAction = "action"
	StageMCP    = "mcp"
	StageRAG    = "rag"
)

type Actor struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Role       string `json:"role,omitempty"`
	CustomerID string `json:"customer_id,omitempty"`
	TeamID     string `json:"team_id,omitempty"`
}

type MCPContext struct {
	ServerLabel string   `json:"server_label,omitempty"`
	ToolName    string   `json:"tool_name,omitempty"`
	ActionClass string   `json:"action_class,omitempty"`
	Domains     []string `json:"domains,omitempty"`
}

type Content struct {
	Input     string `json:"input,omitempty"`
	Output    string `json:"output,omitempty"`
	ToolInput string `json:"tool_input,omitempty"`
	// Attachments carries non-text artifacts (images, audio, video, documents)
	// alongside the textual fields above. The runtime's modality-extraction
	// stage turns each attachment into text (OCR/STT/keyframe/transcript) that
	// is folded into Input/Output before the existing detectors run. The field
	// is optional and omitempty, so the JSON/gRPC wire contract stays backward
	// compatible: a caller that never sets it produces byte-identical requests.
	Attachments []Attachment `json:"attachments,omitempty"`
}

// AttachmentKind enumerates the modality of a non-text attachment.
const (
	AttachmentKindImage    = "image"
	AttachmentKindAudio    = "audio"
	AttachmentKindVideo    = "video"
	AttachmentKindDocument = "document"
)

// AttachmentRole indicates whether an attachment belongs to the request input
// or the model-generated output, controlling which Content field its extracted
// text is folded into.
const (
	AttachmentRoleInput  = "input"
	AttachmentRoleOutput = "output"
)

// Attachment is a single non-text artifact submitted for modality-aware
// guardrail evaluation. The gateway populates these (flag-gated); the runtime's
// extraction stage resolves them to text. Exactly one of Text/Data/Ref is the
// source of truth, in that precedence order: Text is already-extracted text
// (e.g. a UTF-8 document the gateway decoded), Data is inlined raw bytes (size
// capped), and Ref is an external pointer (URL) used when bytes are not inlined.
type Attachment struct {
	Kind string `json:"kind,omitempty"` // image | audio | video | document
	MIME string `json:"mime,omitempty"` // e.g. image/png, audio/mpeg
	Role string `json:"role,omitempty"` // input | output (default input)
	// Hash is a content fingerprint (sha256 hex) used to dedup extraction work
	// across requests so the same asset is never analyzed twice.
	Hash string `json:"hash,omitempty"`
	Text string `json:"text,omitempty"` // pre-extracted text, if the gateway already has it
	Data []byte `json:"data,omitempty"` // inlined raw bytes (capped); empty when Ref/Text suffices
	Ref  string `json:"ref,omitempty"`  // external reference (URL) when bytes are not inlined
}

type PolicyProviderBinding struct {
	ProviderID   string `json:"provider_id"`
	ProviderType string `json:"provider_type,omitempty"`
	Stage        string `json:"stage,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	Enabled      bool   `json:"enabled"`
}

type PolicyBundle struct {
	PolicyID         string                  `json:"policy_id"`
	PolicyVersionID  string                  `json:"policy_version_id"`
	Name             string                  `json:"name"`
	DomainPackID     string                  `json:"domain_pack_id,omitempty"`
	Scope            string                  `json:"scope"`
	EnforcementMode  string                  `json:"enforcement_mode"`
	Enabled          bool                    `json:"enabled"`
	IsDefault        bool                    `json:"is_default,omitempty"`
	TimeoutMs        int                     `json:"timeout_ms,omitempty"`
	Metadata         map[string]any          `json:"metadata,omitempty"`
	Definition       map[string]any          `json:"definition"`
	ProviderBindings []PolicyProviderBinding `json:"provider_bindings,omitempty"`
}

type ProviderConfig struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	ProviderType   string         `json:"provider_type"`
	Mode           string         `json:"mode,omitempty"`
	CustomerID     string         `json:"customer_id,omitempty"`
	Enabled        bool           `json:"enabled"`
	Region         string         `json:"region,omitempty"`
	Endpoint       string         `json:"endpoint,omitempty"`
	Credentials    map[string]any `json:"credentials,omitempty"`
	ConnectionMeta map[string]any `json:"connection_meta,omitempty"`
}

type MCPToolPolicy struct {
	PolicyID          string   `json:"policy_id"`
	ServerLabel       string   `json:"server_label,omitempty"`
	ToolName          string   `json:"tool_name,omitempty"`
	ActionClass       string   `json:"action_class,omitempty"`
	ApprovalNeeded    bool     `json:"approval_needed"`
	AllowedDomains    []string `json:"allowed_domains,omitempty"`
	AllowedIdentities []string `json:"allowed_identities,omitempty"`
}

type TenantBundle struct {
	TenantID        string           `json:"tenant_id"`
	Revision        string           `json:"revision,omitempty"`
	RefreshedAt     time.Time        `json:"refreshed_at,omitempty"`
	Providers       []ProviderConfig `json:"providers,omitempty"`
	Policies        []PolicyBundle   `json:"policies,omitempty"`
	MCPToolPolicies []MCPToolPolicy  `json:"mcp_tool_policies,omitempty"`
	Metadata        map[string]any   `json:"metadata,omitempty"`
}

type EvaluateRequest struct {
	TenantID  string         `json:"tenant_id"`
	RequestID string         `json:"request_id"`
	Stage     string         `json:"stage"`
	Model     string         `json:"model,omitempty"`
	Provider  string         `json:"provider,omitempty"`
	Actor     Actor          `json:"actor"`
	Content   Content        `json:"content"`
	MCP       *MCPContext    `json:"mcp,omitempty"`
	Policies  []PolicyBundle `json:"policies,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`

	rawBytes []byte `json:"-"` // cached gRPC decode bytes for auth HMAC
}

func (r *EvaluateRequest) SetRawBytes(b []byte) { r.rawBytes = b }
func (r *EvaluateRequest) GetRawBytes() []byte   { return r.rawBytes }

type Finding struct {
	PolicyID        string         `json:"policy_id,omitempty"`
	PolicyVersionID string         `json:"policy_version_id,omitempty"`
	ProviderID      string         `json:"provider_id,omitempty"`
	ProviderType    string         `json:"provider_type,omitempty"`
	Category        string         `json:"category"`
	Severity        string         `json:"severity"`
	Confidence      float64        `json:"confidence"`
	Outcome         string         `json:"outcome"`
	Summary         string         `json:"summary"`
	Details         map[string]any `json:"details,omitempty"`
}

type EvaluateResponse struct {
	Decision         string    `json:"decision"`
	Reason           string    `json:"reason"`
	ApprovalRequired bool      `json:"approval_required"`
	Redactions       []string  `json:"redactions,omitempty"`
	SanitizedInput   string    `json:"sanitized_input,omitempty"`
	SanitizedOutput  string    `json:"sanitized_output,omitempty"`
	Findings         []Finding `json:"findings"`
	DecisionChain    []string  `json:"decision_chain,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	LatencyMs        int       `json:"latency_ms"`
}

type PingRequest struct{}

type PingResponse struct {
	OK      bool   `json:"ok"`
	Service string `json:"service"`
	Time    string `json:"time"`
}

type RefreshTenantRequest struct {
	TenantID string       `json:"tenant_id,omitempty"`
	Bundle   TenantBundle `json:"bundle"`

	rawBytes []byte `json:"-"` // cached gRPC decode bytes for auth HMAC
}

func (r *RefreshTenantRequest) SetRawBytes(b []byte) { r.rawBytes = b }
func (r *RefreshTenantRequest) GetRawBytes() []byte   { return r.rawBytes }

type RefreshTenantResponse struct {
	OK         bool      `json:"ok"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Revision   string    `json:"revision,omitempty"`
	HydratedAt time.Time `json:"hydrated_at,omitempty"`
	Message    string    `json:"message"`
}

func NormalizeStage(stage string) string {
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case StageOutput:
		return StageOutput
	case StageAction:
		return StageAction
	case StageMCP:
		return StageMCP
	case StageRAG:
		return StageRAG
	default:
		return StageInput
	}
}
