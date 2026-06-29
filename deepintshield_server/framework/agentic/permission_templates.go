// Package agentic - Permission Templates catalog.
//
// Curated, in-memory starter configurations admins can adopt with one
// click on the Permission Templates UI page. Pattern + structure are
// inspired by Claude Agent SDK / `.claude/settings.json` (allow / ask /
// deny rules with `Tool(specifier)` patterns), adapted to DeepIntShield's
// `AgenticPolicy` + `AgenticToolTier` shape.
//
// This catalog is *configuration only* - nothing here changes runtime SDK
// behaviour. Operators pick a template, the UI hands the JSON to the
// existing CreatePolicy / UpsertTool endpoints, and the existing
// CompileRego + hash-chained audit flows take over. Adding a template
// here doesn't touch the policy engine, the PEP, or any wire format.
//
// Why curated + in-memory and not a DB table:
//   - Templates ship with the binary so they're versioned with releases
//     and auditable in git diffs
//   - Zero-latency: the gallery is a constant-time response, no query
//   - SOC2 evidence: the template surface is reproducible per-version,
//     not mutable runtime state
package agentic

import (
	"strings"
)

// PermissionRule mirrors the Claude SDK `Tool(specifier)` shape:
//
//	Tool      - the matched tool family (e.g. "Bash", "Read", "MCP")
//	Specifier - the pattern within that family (e.g. "rm *", "./src/**",
//	            "domain:example.com", or "" for the bare-name rule)
//	Negate    - if true, the rule denies / asks when the pattern does NOT
//	            match (mirrors the Claude `!` prefix shorthand)
//
// Rendered as `Tool(specifier)` in the UI so the JSON is copy-pasteable
// into `.claude/settings.json` for engineers already familiar with that
// schema.
type PermissionRule struct {
	Tool      string `json:"tool"`
	Specifier string `json:"specifier,omitempty"`
	Negate    bool   `json:"negate,omitempty"`
}

// PermissionRules is the allow / ask / deny bucket that drives the PEP.
// Evaluation order matches Claude SDK: deny → ask → allow (first match
// wins), which is the same order DeepIntShield's PDP already uses
// (DENY > REQUIRE_APPROVAL > ALLOW).
type PermissionRules struct {
	Allow []PermissionRule `json:"allow,omitempty"`
	Ask   []PermissionRule `json:"ask,omitempty"`
	Deny  []PermissionRule `json:"deny,omitempty"`
}

// SandboxProfile captures runtime capability restrictions that pair with
// a template - adopting a template suggests these capability defaults on
// the matching tools so blast radius is bounded by construction.
type SandboxProfile struct {
	Mode            string   `json:"mode,omitempty"`             // none | wasm | container
	AllowEgress     []string `json:"allow_egress,omitempty"`     // host:port allowlist
	AllowFSRead     []string `json:"allow_fs_read,omitempty"`    // path prefixes
	AllowFSWrite    []string `json:"allow_fs_write,omitempty"`   // path prefixes
	DenyFSRead      []string `json:"deny_fs_read,omitempty"`     // overrides allow
	DenyFSWrite     []string `json:"deny_fs_write,omitempty"`    // overrides allow
	MaxSubprocesses int      `json:"max_subprocesses,omitempty"` // 0 = no spawn
}

// PermissionTemplate is one gallery item. The four fields below the
// metadata are the actionable payload the UI can paste directly into:
//
//	Permissions      - the Allow / Ask / Deny rule bag
//	RecommendedMode  - UX mode hint (shadow / canary / enforce or one of
//	                   Claude's permission modes - UI displays both)
//	Sandbox          - capability defaults to apply to matched tools
//	PolicyDefinition - a ready-to-save AgenticPolicy.definition payload
//	                   so "Create policy from template" is one click
type PermissionTemplate struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Category         string           `json:"category"`
	Description      string           `json:"description"`
	Tags             []string         `json:"tags,omitempty"`
	SOC2Controls     []string         `json:"soc2_controls,omitempty"`
	OWASPCategories  []string         `json:"owasp_categories,omitempty"`
	Source           string           `json:"source"` // attribution
	Permissions      PermissionRules  `json:"permissions"`
	RecommendedMode  string           `json:"recommended_mode"`
	Sandbox          SandboxProfile   `json:"sandbox"`
	PolicyDefinition map[string]any   `json:"policy_definition,omitempty"`
	ToolDefaults     []map[string]any `json:"tool_defaults,omitempty"`
}

// PermissionTemplatesCatalog is the canonical list returned to the UI.
// Order matters: most-conservative-first so a SOC2 audit reads top-down.
// Add new templates *append-only* - existing IDs are referenced by
// operators in change logs.
var PermissionTemplatesCatalog = []PermissionTemplate{
	{
		ID:              "starter-read-only",
		Name:            "Read-Only Discovery",
		Category:        "Starter",
		Description:     "Lock the agent to read-only tools - list, get, search.",
		Tags:            []string{"baseline", "shadow", "safe"},
		SOC2Controls:    []string{"CC6.1", "CC6.6", "CC7.2"},
		OWASPCategories: []string{"ASI02:Tool Misuse & Exploitation"},
		Source:          "Adapted from Claude Agent SDK `plan` mode",
		Permissions: PermissionRules{
			Allow: []PermissionRule{
				{Tool: "Read"},
				{Tool: "Glob"},
				{Tool: "Grep"},
				{Tool: "List"},
				{Tool: "Search"},
			},
			Ask: []PermissionRule{
				{Tool: "WebFetch"},
				{Tool: "MCP", Specifier: "*"},
			},
			Deny: []PermissionRule{
				{Tool: "Write"},
				{Tool: "Edit"},
				{Tool: "Bash"},
				{Tool: "Delete"},
			},
		},
		RecommendedMode: "shadow",
		Sandbox: SandboxProfile{
			Mode:            "wasm",
			AllowFSRead:     []string{"./"},
			DenyFSWrite:     []string{"/"},
			MaxSubprocesses: 0,
		},
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"tool":        map[string]any{"any_tool": []string{"Read", "Glob", "Grep", "List", "Search"}},
			"verdict":     "ALLOW",
			"reason":      "Read-only baseline (Starter - Read-Only Discovery)",
			"obligations": []string{"mask:pii", "redact:secrets"},
		},
	},
	{
		ID:              "developer-prototype",
		Name:            "Developer Prototype",
		Category:        "Development",
		Description:     "Engineers iterating on a new agent. File edits inside the workspace are auto-approved, but every shell command, network call and external MCP tool stays gated. Mirrors Claude SDK `acceptEdits` mode scoped to the active workspace.",
		Tags:            []string{"dev", "prototype", "accept-edits"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI02:Tool Misuse & Exploitation"},
		Source:          "Adapted from Claude Agent SDK `acceptEdits` mode",
		Permissions: PermissionRules{
			Allow: []PermissionRule{
				{Tool: "Read"},
				{Tool: "Glob"},
				{Tool: "Grep"},
				{Tool: "Edit", Specifier: "./src/**"},
				{Tool: "Write", Specifier: "./src/**"},
				{Tool: "Bash", Specifier: "npm run *"},
				{Tool: "Bash", Specifier: "git diff *"},
				{Tool: "Bash", Specifier: "git status"},
			},
			Ask: []PermissionRule{
				{Tool: "Bash", Specifier: "git push *"},
				{Tool: "Bash", Specifier: "git commit *"},
				{Tool: "Edit", Specifier: ".env*"},
				{Tool: "WebFetch"},
			},
			Deny: []PermissionRule{
				{Tool: "Bash", Specifier: "rm -rf *"},
				{Tool: "Bash", Specifier: "curl *"},
				{Tool: "Bash", Specifier: "sudo *"},
				{Tool: "Read", Specifier: "./.env"},
				{Tool: "Read", Specifier: "./secrets/**"},
			},
		},
		RecommendedMode: "canary",
		Sandbox: SandboxProfile{
			Mode:            "container",
			AllowFSRead:     []string{"./"},
			AllowFSWrite:    []string{"./src/", "./test/", "/tmp/"},
			DenyFSRead:      []string{"./.env", "./.env.*", "./secrets/", "~/.ssh/", "~/.aws/"},
			DenyFSWrite:     []string{"/etc/", "/usr/", "/bin/", "/sbin/"},
			MaxSubprocesses: 4,
		},
		PolicyDefinition: map[string]any{
			"subject": map[string]any{"any_role": []string{"developer", "agent"}},
			"tool":    map[string]any{"prefix_tool": []string{"src.", "test.", "git."}},
			"verdict": "ALLOW",
			"reason":  "Developer prototype scope",
		},
	},
	{
		ID:              "production-strict",
		Name:            "Production Strict",
		Category:        "Production",
		Description:     "Production agents. Allow-list of pre-approved tools only; anything not listed is denied (no `canUseTool` fallback). Mirrors Claude SDK `dontAsk` mode + a managed-rules denylist. Pairs with the Rollout → Enforce stage.",
		Tags:            []string{"production", "strict", "managed", "dontAsk"},
		SOC2Controls:    []string{"CC6.1", "CC6.6", "CC6.7", "CC6.8", "CC7.2", "CC7.4"},
		OWASPCategories: []string{"ASI01:Agent Goal Hijack", "ASI02:Tool Misuse & Exploitation"},
		Source:          "Adapted from Claude Agent SDK `dontAsk` mode + managed settings",
		Permissions: PermissionRules{
			Allow: []PermissionRule{
				{Tool: "Read", Specifier: "./reports/**"},
				{Tool: "Search", Specifier: "domain:trusted-corpus.internal"},
				{Tool: "MCP", Specifier: "approved-knowledge-base"},
			},
			Deny: []PermissionRule{
				{Tool: "Bash"},
				{Tool: "Write"},
				{Tool: "Edit"},
				{Tool: "Delete"},
				{Tool: "WebFetch", Specifier: "domain:*.internal"},
				{Tool: "MCP", Specifier: "filesystem"},
			},
		},
		RecommendedMode: "enforce",
		Sandbox: SandboxProfile{
			Mode:            "wasm",
			AllowEgress:     []string{"trusted-corpus.internal:443"},
			AllowFSRead:     []string{"./reports/"},
			DenyFSWrite:     []string{"/"},
			MaxSubprocesses: 0,
		},
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"production-agent"}},
			"tool":        map[string]any{"any_tool": []string{"Read", "Search", "MCP"}},
			"verdict":     "ALLOW",
			"obligations": []string{"mask:pii", "log:full", "rate-limit", "redact:secrets"},
			"reason":      "Production strict - explicit allow-list",
		},
	},
	{
		ID:              "finance-write-with-approval",
		Name:            "Finance Write (Human-in-the-loop)",
		Category:        "Vertical",
		Description:     "Agents that touch ledger / payments / billing. Reads from finance.* auto-approve; any write or transfer escalates to a human approver and is hash-chain audited. The default for any tool with monetary side-effects.",
		Tags:            []string{"finance", "approval", "high-stakes", "hitl"},
		SOC2Controls:    []string{"CC6.1", "CC7.2", "CC7.4", "CC8.1"},
		OWASPCategories: []string{"ASI09:Human-Agent Trust Exploitation", "ASI03:Identity & Privilege Abuse"},
		Source:          "DeepIntShield Vertical Pack - Finance",
		Permissions: PermissionRules{
			Allow: []PermissionRule{
				{Tool: "MCP", Specifier: "finance.read"},
				{Tool: "MCP", Specifier: "finance.report"},
				{Tool: "MCP", Specifier: "ledger.read"},
			},
			Ask: []PermissionRule{
				{Tool: "MCP", Specifier: "ledger.write"},
				{Tool: "MCP", Specifier: "ledger.post"},
				{Tool: "MCP", Specifier: "payments.*"},
				{Tool: "MCP", Specifier: "billing.write"},
			},
			Deny: []PermissionRule{
				{Tool: "MCP", Specifier: "ledger.delete"},
				{Tool: "MCP", Specifier: "payments.refund.bulk"},
			},
		},
		RecommendedMode: "enforce",
		Sandbox: SandboxProfile{
			Mode:        "wasm",
			AllowEgress: []string{"finance-api.internal:443", "ledger-api.internal:443"},
		},
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"finance-analyst", "treasury-agent"}},
			"tool":        map[string]any{"prefix_tool": []string{"finance.", "ledger.", "payments.", "billing."}},
			"verdict":     "REQUIRE_APPROVAL",
			"approvers":   []string{"finance-ops"},
			"obligations": []string{"mask:pii", "log:full", "redact:card-numbers"},
			"reason":      "Finance write requires HITL",
		},
	},
	{
		ID:              "data-egress-controlled",
		Name:            "Data Egress Controlled",
		Category:        "Compliance",
		Description:     "Tight egress allowlist for agents handling regulated data (GDPR, HIPAA, DPDP). Outbound traffic is restricted to approved hosts; PII masking obligation is union'd onto every decision; cross-tenant calls are denied. Pairs with the runtime sandbox to enforce at the network layer.",
		Tags:            []string{"compliance", "gdpr", "hipaa", "dpdp", "egress"},
		SOC2Controls:    []string{"CC6.7", "CC6.8", "CC7.2", "CC7.4"},
		OWASPCategories: []string{"ASI03:Identity & Privilege Abuse", "ASI08:Cascading Failures"},
		Source:          "DeepIntShield Compliance Pack",
		Permissions: PermissionRules{
			Allow: []PermissionRule{
				{Tool: "Read", Specifier: "./compliance/**"},
				{Tool: "WebFetch", Specifier: "domain:api.partner-approved.com"},
				{Tool: "MCP", Specifier: "vault.read"},
			},
			Ask: []PermissionRule{
				{Tool: "MCP", Specifier: "vault.write"},
			},
			Deny: []PermissionRule{
				{Tool: "WebFetch"},
				{Tool: "Bash", Specifier: "curl *"},
				{Tool: "Bash", Specifier: "wget *"},
			},
		},
		RecommendedMode: "enforce",
		Sandbox: SandboxProfile{
			Mode:            "wasm",
			AllowEgress:     []string{"api.partner-approved.com:443", "vault.internal:443"},
			AllowFSRead:     []string{"./compliance/"},
			DenyFSRead:      []string{"./.env", "./secrets/", "~/.aws/", "~/.ssh/"},
			DenyFSWrite:     []string{"/"},
			MaxSubprocesses: 0,
		},
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"compliance-agent"}},
			"tool":        map[string]any{"prefix_tool": []string{"compliance.", "vault.read"}},
			"verdict":     "ALLOW",
			"obligations": []string{"mask:pii", "redact:phi", "deny:cross-tenant", "log:full"},
			"reason":      "Regulated data - egress controlled",
		},
	},
	{
		ID:              "rag-only",
		Name:            "RAG-Only Knowledge Agent",
		Category:        "Vertical",
		Description:     "Knowledge / Q&A agents whose ground truth is a vetted corpus. Only retrieval + search tools allowed; every answer must cite a source from rag_provenance=verified. Anything else escalates. Prevents hallucination via tool scope.",
		Tags:            []string{"rag", "knowledge", "qa", "citation"},
		SOC2Controls:    []string{"CC7.2", "CC8.1"},
		OWASPCategories: []string{"ASI06:Memory & Context Poisoning", "ASI02:Tool Misuse & Exploitation"},
		Source:          "DeepIntShield RAG Pack",
		Permissions: PermissionRules{
			Allow: []PermissionRule{
				{Tool: "Search", Specifier: "domain:approved-corpus"},
				{Tool: "MCP", Specifier: "vectordb.query"},
				{Tool: "Read", Specifier: "./corpus/**"},
			},
			Ask: []PermissionRule{
				{Tool: "WebFetch"},
			},
			Deny: []PermissionRule{
				{Tool: "Write"},
				{Tool: "Edit"},
				{Tool: "Bash"},
				{Tool: "MCP", Specifier: "vectordb.write"},
			},
		},
		RecommendedMode: "enforce",
		Sandbox: SandboxProfile{
			Mode:        "wasm",
			AllowEgress: []string{"vectordb.internal:443"},
			AllowFSRead: []string{"./corpus/"},
			DenyFSWrite: []string{"/"},
		},
		PolicyDefinition: map[string]any{
			"subject": map[string]any{"any_role": []string{"retriever", "qa-agent"}},
			"tool":    map[string]any{"any_tool": []string{"Search", "Read"}, "prefix_tool": []string{"vectordb.query"}},
			"conditions": []map[string]any{
				{"field": "rag_provenance", "operator": "eq", "value": "verified"},
			},
			"verdict": "ALLOW",
			"reason":  "RAG-only - verified provenance required",
		},
	},
	{
		ID:              "incident-response-bypass",
		Name:            "Incident-Response Break-Glass",
		Category:        "Operations",
		Description:     "Emergency-only profile. Every action lands in the Approvals queue with a 10-minute SLA, every decision is hash-chain logged, kill-switch is one click away. Mirrors Claude SDK `bypassPermissions` but every call still flows through the audit - there is no true bypass. Time-boxed: auto-expires after 1 hour.",
		Tags:            []string{"oncall", "break-glass", "audit", "time-boxed"},
		SOC2Controls:    []string{"CC7.3", "CC7.4", "CC7.5"},
		OWASPCategories: []string{"ASI03:Identity & Privilege Abuse", "ASI05:Unexpected Code Execution"},
		Source:          "Adapted from Claude SDK `bypassPermissions` + DeepIntShield kill-switch",
		Permissions: PermissionRules{
			Ask: []PermissionRule{
				{Tool: "Bash"},
				{Tool: "Write"},
				{Tool: "Edit"},
				{Tool: "MCP", Specifier: "*"},
			},
			Deny: []PermissionRule{
				{Tool: "Bash", Specifier: "rm -rf /"},
			},
		},
		RecommendedMode: "canary",
		Sandbox: SandboxProfile{
			Mode:            "container",
			MaxSubprocesses: 8,
		},
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"oncall-engineer"}},
			"tool":        map[string]any{"any_tool": []string{"Bash", "Write", "Edit", "MCP"}},
			"verdict":     "REQUIRE_APPROVAL",
			"approvers":   []string{"oncall-lead"},
			"obligations": []string{"log:full", "time-box:1h", "audit:hash-chain", "ttl:3600"},
			"reason":      "Break-glass - 1h time-boxed, fully audited",
		},
	},

	// ════════════════════════════════════════════════════════════════════
	// OWASP Agentic Top 10 (2026) policy pack - one adoptable policy per ASI
	// entry, expressed entirely with operands the PEP already evaluates
	// (no engine change). Each maps to the matching ASI mitigation guidance.
	// Adopt the whole pack for baseline OWASP coverage, or cherry-pick.
	// ════════════════════════════════════════════════════════════════════
	{
		ID:              "owasp-asi01-goal-hijack",
		Name:            "ASI01 · Agent Goal Hijack",
		Category:        "OWASP Agentic Top 10",
		Description:     "Gate goal-changing / high-impact actions behind human approval. Any tool call whose recovery_cost is high (the autonomy-budget signal) escalates to a security approver and is hash-chain audited, so an injected sub-goal cannot silently redirect the agent. Pair with locked system prompts + intent validation.",
		Tags:            []string{"owasp", "asi01", "goal-hijack", "autonomy-budget"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI01:Agent Goal Hijack"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI01",
		Permissions: PermissionRules{
			Ask:  []PermissionRule{{Tool: "MCP", Specifier: "*"}},
			Deny: []PermissionRule{{Tool: "Bash", Specifier: "rm *"}},
		},
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "REQUIRE_APPROVAL",
			"conditions":  []map[string]any{{"field": "recovery_cost", "operator": "eq", "value": "high"}},
			"approvers":   []string{"security-team"},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "ASI01 - high-impact / goal-changing action requires human approval (autonomy budget)",
		},
	},
	{
		ID:              "owasp-asi02-tool-misuse",
		Name:            "ASI02 · Tool Misuse & Exploitation",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny tool calls whose observed behavior diverges from the tool's declared contract - the Tool Integrity Engine signal. Catches parameter pollution, tool-chaining pivots, and 'approved tool' abuse where the call stays in-scope but the behavior is wrong. Numeric integrity_risk variants available for a softer threshold.",
		Tags:            []string{"owasp", "asi02", "tool-misuse", "integrity"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI02:Tool Misuse & Exploitation"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI02",
		Permissions: PermissionRules{
			Deny: []PermissionRule{{Tool: "Bash"}, {Tool: "Exec"}},
		},
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "behavior_divergence", "operator": "eq", "value": "true"}},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "ASI02 - tool call diverged from its declared contract (Tool Integrity Engine)",
		},
	},
	{
		ID:              "owasp-asi03-identity-privilege",
		Name:            "ASI03 · Identity & Privilege Abuse",
		Category:        "OWASP Agentic Top 10",
		Description:     "Block confused-deputy / cross-boundary privilege abuse: any call that crosses a tenant boundary is denied outright. Combine with agent_risk_level and namespace conditions (set per-VK) so a low-risk agent can't reach high-sensitivity tools, and per-action authorization stays scoped.",
		Tags:            []string{"owasp", "asi03", "identity", "privilege", "least-privilege"},
		SOC2Controls:    []string{"CC6.1", "CC6.3"},
		OWASPCategories: []string{"ASI03:Identity & Privilege Abuse"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI03",
		Permissions:     PermissionRules{},
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "cross_tenant", "operator": "eq", "value": "true"}},
			"obligations": []string{"audit:hash-chain"},
			"reason":      "ASI03 - cross-tenant delegation denied (confused-deputy / privilege abuse)",
		},
	},
	{
		ID:              "owasp-asi04-supply-chain",
		Name:            "ASI04 · Agentic Supply Chain",
		Category:        "OWASP Agentic Top 10",
		Description:     "Hold newly discovered / unverified tools (new.*, untrusted MCP) for review before first use - the runtime half of supply-chain defense. Pair with build-time AIBOM/SBOM signing + pinning. Catches typosquatted tools and tool-descriptor injection that surface as unregistered tool names.",
		Tags:            []string{"owasp", "asi04", "supply-chain", "aibom"},
		SOC2Controls:    []string{"CC7.1", "CC8.1"},
		OWASPCategories: []string{"ASI04:Agentic Supply Chain"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI04",
		Permissions: PermissionRules{
			Ask: []PermissionRule{{Tool: "MCP", Specifier: "*"}},
		},
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"tool":        map[string]any{"prefix_tool": []string{"new.", "mcp.untrusted."}},
			"verdict":     "REQUIRE_APPROVAL",
			"approvers":   []string{"security-team"},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "ASI04 - newly discovered / unverified tool requires review before use (pair with AIBOM)",
		},
	},
	{
		ID:              "owasp-asi05-rce",
		Name:            "ASI05 · Unexpected Code Execution (RCE)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Force human approval + sandbox obligation on code-execution tools (Bash, Shell, Exec, Eval, Code). The Tool Integrity Engine flags injected commands in args; this policy ensures even a 'legitimate' code tool never auto-runs. Pair with non-root sandboxed execution and ban of eval() in production agents.",
		Tags:            []string{"owasp", "asi05", "rce", "sandbox"},
		SOC2Controls:    []string{"CC6.1", "CC6.8"},
		OWASPCategories: []string{"ASI05:Unexpected Code Execution"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI05",
		Permissions: PermissionRules{
			Deny: []PermissionRule{{Tool: "Bash", Specifier: "rm -rf *"}, {Tool: "Eval"}},
		},
		RecommendedMode: "enforce",
		Sandbox:         SandboxProfile{Mode: "container", MaxSubprocesses: 0},
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"tool":        map[string]any{"any_tool": []string{"Bash", "Shell", "Exec", "Eval", "Code"}},
			"verdict":     "REQUIRE_APPROVAL",
			"approvers":   []string{"security-team"},
			"obligations": []string{"sandbox:require", "log:full", "audit:hash-chain"},
			"reason":      "ASI05 - code-execution tool requires approval + sandbox (RCE guard)",
		},
	},
	{
		ID:              "owasp-asi06-memory-poisoning",
		Name:            "ASI06 · Memory & Context Poisoning",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny retrieval whose source provenance is quarantined / untrusted, so poisoned RAG chunks and cross-tenant vector bleed can't enter the agent's reasoning. Pair with per-tenant vector namespaces, trust-scored memory, and 'no auto re-ingestion of own outputs'. Softer variants MASK instead of DENY.",
		Tags:            []string{"owasp", "asi06", "memory-poisoning", "rag", "provenance"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI06:Memory & Context Poisoning"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI06",
		Permissions: PermissionRules{
			Allow: []PermissionRule{{Tool: "Search"}, {Tool: "Read"}},
		},
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "rag_provenance", "operator": "eq", "value": "quarantined"}},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "ASI06 - retrieval from quarantined / untrusted source denied (memory poisoning)",
		},
	},
	{
		ID:              "owasp-asi07-inter-agent-comm",
		Name:            "ASI07 · Insecure Inter-Agent Communication",
		Category:        "OWASP Agentic Top 10",
		Description:     "Gate agent-to-agent delegation tools (a2a.*, agent.delegate) behind approval + hash-chain audit, and deny any that cross a tenant boundary. The broker already verifies attested identity (Entra / ZeroID-SPIFFE / OIDC); this adds the policy layer so forged-descriptor / replay delegations don't auto-execute.",
		Tags:            []string{"owasp", "asi07", "inter-agent", "a2a", "mcp"},
		SOC2Controls:    []string{"CC6.1", "CC6.6"},
		OWASPCategories: []string{"ASI07:Insecure Inter-Agent Communication"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI07",
		Permissions:     PermissionRules{},
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"tool":        map[string]any{"prefix_tool": []string{"a2a.", "agent.delegate"}},
			"verdict":     "REQUIRE_APPROVAL",
			"approvers":   []string{"security-team"},
			"obligations": []string{"audit:hash-chain"},
			"reason":      "ASI07 - agent-to-agent delegation requires review; pair with mTLS / attested identity",
		},
	},
	{
		ID:              "owasp-asi08-cascading-failures",
		Name:            "ASI08 · Cascading Failures",
		Category:        "OWASP Agentic Top 10",
		Description:     "Blast-radius guardrail: high-recovery-cost actions are rate-limited, circuit-broken and gated so one faulty plan can't fan out across agents/sessions. Pair with the Service Graph + Discovery views to spot rapid fan-out, and per-run JIT credentials so a drifting agent can't trigger chain reactions.",
		Tags:            []string{"owasp", "asi08", "cascading", "blast-radius", "rate-limit"},
		SOC2Controls:    []string{"A1.1", "CC7.2"},
		OWASPCategories: []string{"ASI08:Cascading Failures"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI08",
		Permissions:     PermissionRules{},
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "REQUIRE_APPROVAL",
			"conditions":  []map[string]any{{"field": "recovery_cost", "operator": "eq", "value": "high"}},
			"approvers":   []string{"security-team"},
			"obligations": []string{"rate-limit:10/min", "circuit-breaker", "audit:hash-chain"},
			"reason":      "ASI08 - blast-radius guardrail: high-recovery-cost action rate-limited + gated",
		},
	},
	{
		ID:              "owasp-asi09-human-trust",
		Name:            "ASI09 · Human-Agent Trust Exploitation",
		Category:        "OWASP Agentic Top 10",
		Description:     "Require explicit human confirmation for sensitive / irreversible actions (finance.*, payments.*, email.send) and mask PII in the rendered output, so an over-trusted or prompt-injected copilot can't talk a human into a fraudulent wire or data leak. Pair with provenance badges + 'separate preview from effect'.",
		Tags:            []string{"owasp", "asi09", "human-trust", "hitl"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI09:Human-Agent Trust Exploitation"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI09",
		Permissions: PermissionRules{
			Ask: []PermissionRule{{Tool: "Email", Specifier: "send"}},
		},
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"tool":        map[string]any{"prefix_tool": []string{"finance.", "payments.", "email.send"}},
			"verdict":     "REQUIRE_APPROVAL",
			"approvers":   []string{"security-team"},
			"obligations": []string{"mask:pii", "log:full", "audit:hash-chain"},
			"reason":      "ASI09 - sensitive / irreversible action needs explicit human confirmation (trust exploitation)",
		},
	},
	{
		ID:              "owasp-asi10-rogue-agents",
		Name:            "ASI10 · Rogue Agents",
		Category:        "OWASP Agentic Top 10",
		Description:     "Behavioral-integrity tripwire: when the Tool Integrity Engine's divergence risk exceeds 0.7, deny + quarantine and hash-chain the evidence so a drifting / compromised agent is contained. Pair with the kill-switch (Rollout), grant revocation, and the Discovery view to catch unregistered shadow agents.",
		Tags:            []string{"owasp", "asi10", "rogue-agents", "integrity", "kill-switch"},
		SOC2Controls:    []string{"CC7.3", "CC7.4"},
		OWASPCategories: []string{"ASI10:Rogue Agents"},
		Source:          "OWASP Top 10 for Agentic Applications 2026 - ASI10",
		Permissions:     PermissionRules{},
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "integrity_risk", "operator": "gt", "value": "0.7"}},
			"obligations": []string{"quarantine", "audit:hash-chain"},
			"reason":      "ASI10 - behavioral-integrity breach: quarantine + kill-switch (rogue agent)",
		},
	},
	// ── OWASP-gap operand pack: one adoptable policy per new ABAC signal
	// (code_threat / memory_integrity / hallucination_risk / goal_drift /
	// comm_integrity / delegation_depth). Each gates on a single condition that
	// the runtime stamps from the SDK signal (or computes), so adopting them turns
	// the matching threat detection into enforcement with no engine change.
	{
		ID:              "owasp-code-threat-block",
		Name:            "Block Malicious Tool Code (T11/T17)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny any tool whose SOURCE scanned malicious at registration - remote code execution, shell-out, unsafe deserialization, secret exfiltration, destructive ops. The decision is bound to the tool's source fingerprint and cached, so it costs nothing on the hot path. Pair with the workspace code-scan model (Rollout) for the deepest detection.",
		Tags:            []string{"owasp", "asi05", "asi04", "code-threat", "rce", "supply-chain"},
		SOC2Controls:    []string{"CC6.1", "CC8.1"},
		OWASPCategories: []string{"ASI05:Unexpected Code Execution", "ASI04:Agentic Supply Chain"},
		Source:          "OWASP Agentic - T11 Unexpected RCE & T17 Supply Chain",
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "code_threat", "operator": "eq", "value": "true"}},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "malicious tool implementation - denied (code-threat scan, T11/T17)",
		},
	},
	{
		ID:              "owasp-memory-integrity",
		Name:            "Block Poisoned Memory (T1)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny a call whose agent memory failed validation (snapshot/provenance mismatch) - the runtime half of memory-poisoning defense. The SDK sets memory_integrity when a memory check fails. Pair with per-session isolation, source attribution, and pre-commit validation of long-term memory.",
		Tags:            []string{"owasp", "asi06", "memory-poisoning", "integrity"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI06:Memory & Context Poisoning"},
		Source:          "OWASP Agentic - T1 Memory Poisoning",
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "memory_integrity", "operator": "eq", "value": "true"}},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "memory integrity violation - poisoned/unverified memory denied (T1)",
		},
	},
	{
		ID:              "owasp-hallucination-risk",
		Name:            "Gate High-Hallucination Actions (T5)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Require human review when faithfulness/hallucination risk is high (≥ 0.8) - stops a cascading-hallucination chain from auto-executing a tool on fabricated reasoning. Bridges the workspace hallucination engine into the PDP. Tune the threshold to your tolerance.",
		Tags:            []string{"owasp", "asi08", "hallucination", "cascading"},
		SOC2Controls:    []string{"CC7.2"},
		OWASPCategories: []string{"ASI08:Cascading Failures"},
		Source:          "OWASP Agentic - T5 Cascading Hallucination",
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "REQUIRE_APPROVAL",
			"conditions":  []map[string]any{{"field": "hallucination_risk", "operator": "gte", "value": "0.8"}},
			"approvers":   []string{"security-team"},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "high hallucination risk - action gated for review (cascading-failure guard, T5)",
		},
	},
	{
		ID:              "owasp-goal-drift",
		Name:            "Block Goal Drift (T7)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny calls where the agent's behavior has drifted from its declared goal/role - the misaligned/deceptive-behavior signal. Pair with behavior_divergence (Tool Integrity Engine) and goal-consistency validation in the planner.",
		Tags:            []string{"owasp", "asi01", "goal-drift", "misalignment"},
		SOC2Controls:    []string{"CC7.2", "CC7.3"},
		OWASPCategories: []string{"ASI01:Agent Goal Hijack"},
		Source:          "OWASP Agentic - T7 Misaligned & Deceptive Behaviors",
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "goal_drift", "operator": "eq", "value": "true"}},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "goal drift detected - misaligned action denied (T7)",
		},
	},
	{
		ID:              "owasp-comm-integrity",
		Name:            "Block Unauthenticated Inter-Agent Messages (T12)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny a call driven by an inter-agent message that failed authentication / integrity - agent-communication-poisoning defense. The SDK sets comm_integrity when an A2A/MCP message can't be verified. Pair with signed/mTLS inter-agent transport.",
		Tags:            []string{"owasp", "asi07", "inter-agent", "comm-poisoning"},
		SOC2Controls:    []string{"CC6.1", "CC6.6"},
		OWASPCategories: []string{"ASI07:Insecure Inter-Agent Communication"},
		Source:          "OWASP Agentic - T12 Agent Communication Poisoning",
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "comm_integrity", "operator": "eq", "value": "true"}},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "inter-agent message failed integrity check - denied (communication poisoning, T12)",
		},
	},
	{
		ID:              "owasp-delegation-depth",
		Name:            "Cap Delegation Depth (T14)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Require approval when the delegation chain runs deeper than 4 hops - caps runaway multi-agent delegation and confused-deputy escalation across a chain. Computed server-side from the actor chain (no SDK code). Tune the depth to your topology.",
		Tags:            []string{"owasp", "asi07", "asi03", "delegation", "mas"},
		SOC2Controls:    []string{"CC6.1", "CC6.3"},
		OWASPCategories: []string{"ASI07:Insecure Inter-Agent Communication", "ASI03:Identity & Privilege Abuse"},
		Source:          "OWASP Agentic - T14 Human Attacks on Multi-Agent Systems",
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "REQUIRE_APPROVAL",
			"conditions":  []map[string]any{{"field": "delegation_depth", "operator": "gt", "value": "4"}},
			"approvers":   []string{"security-team"},
			"obligations": []string{"audit:hash-chain"},
			"reason":      "delegation chain too deep - review required (multi-agent escalation guard, T14)",
		},
	},
	{
		ID:              "owasp-output-manipulation",
		Name:            "Block Manipulated Output (T15)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Deny when the agent's OUTPUT/response tripped the guardrail - an injected link, fraudulent instruction, or manipulation aimed at the human. The SDK sets output_manipulation after scanning the response. Pair with provenance badges and 'separate preview from effect'.",
		Tags:            []string{"owasp", "asi09", "human-manipulation", "output"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"ASI09:Human-Agent Trust Exploitation"},
		Source:          "OWASP Agentic - T15 Human Manipulation",
		RecommendedMode: "enforce",
		PolicyDefinition: map[string]any{
			"subject":     map[string]any{"any_role": []string{"agent"}},
			"verdict":     "DENY",
			"conditions":  []map[string]any{{"field": "output_manipulation", "operator": "eq", "value": "true"}},
			"obligations": []string{"mask:pii", "log:full", "audit:hash-chain"},
			"reason":      "manipulated agent output blocked (human-manipulation guard, T15)",
		},
	},
	{
		ID:              "owasp-approval-pressure",
		Name:            "Throttle Approval Flood (T10)",
		Category:        "OWASP Agentic Top 10",
		Description:     "Protect human reviewers from decision fatigue: when approvals/minute spike (> 20), auto-deny low-risk approval requests so attackers can't bury a fraudulent one in a flood. High-recovery-cost actions still escalate. Tune the threshold to your reviewer capacity.",
		Tags:            []string{"owasp", "asi09", "hitl", "decision-fatigue"},
		SOC2Controls:    []string{"CC7.2"},
		OWASPCategories: []string{"ASI09:Human-Agent Trust Exploitation"},
		Source:          "OWASP Agentic - T10 Overwhelming Human-in-the-Loop",
		RecommendedMode: "canary",
		PolicyDefinition: map[string]any{
			"subject": map[string]any{"any_role": []string{"agent"}},
			"verdict": "DENY",
			"conditions": []map[string]any{
				{"field": "approval_pressure", "operator": "gt", "value": "20"},
				{"field": "recovery_cost", "operator": "ne", "value": "high"},
			},
			"obligations": []string{"log:full", "audit:hash-chain"},
			"reason":      "approval flood - low-risk request auto-denied to protect reviewers (HITL guard, T10)",
		},
	},
}

// FindPermissionTemplate returns a single template by ID. Returns nil if
// the ID is unknown (the UI handles 404 gracefully).
func FindPermissionTemplate(id string) *PermissionTemplate {
	for i := range PermissionTemplatesCatalog {
		if PermissionTemplatesCatalog[i].ID == strings.TrimSpace(id) {
			return &PermissionTemplatesCatalog[i]
		}
	}
	return nil
}

// PermissionTemplateCategories returns the unique category names in
// catalog order. Used by the UI to render category tabs / filters
// without having to dedupe client-side.
func PermissionTemplateCategories() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, t := range PermissionTemplatesCatalog {
		if seen[t.Category] {
			continue
		}
		seen[t.Category] = true
		out = append(out, t.Category)
	}
	return out
}
