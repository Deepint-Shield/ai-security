// Package agentic - Tool Templates catalog.
//
// Curated, in-memory list of pre-classified tool definitions an admin
// can adopt with one click on the Tool Templates UI page. Each entry
// carries:
//
//  1. UI metadata - Icon name (lucide-react identifier), category,
//     colour hint, short copy.
//  2. The full AgenticToolTier payload (sensitivity / fail_posture /
//     revocation_path / obligations / recovery_cost / args_schema)
//     ready to POST to the existing /api/agentic-security/tools
//     endpoint - no new pipeline, no migration.
//  3. Comprehensive args_schema._meta block carrying every operational
//     knob the runtime considers: glob patterns, network egress
//     allowlists, filesystem scopes, rate limits, timeouts, byte caps,
//     cache TTLs, declared capabilities, behavioural baselines and
//     copy-paste examples.
//  4. SOC2 + OWASP Agentic references inline.
//
// Why in-memory + binary-versioned (not a DB table):
//   - Constant-time response. Zero DB hit on the hot path.
//   - Templates evolve with releases; git diffs are the audit trail.
//   - Scales linearly with catalog size; the entire response gzips to
//     <40 KB even at 200+ templates of this richness.
//
// Adopting a template does NOT change runtime behaviour or the SDK
// wire format - it just pre-fills the existing Tool create / edit
// form. The upsert path, the args_digest pipeline, the PEP, and the
// hash-chained audit all remain exactly as-is.
package agentic

import "strings"

// ToolTemplate is one gallery entry. Mirror the JSON shape carefully:
// the UI uses these field names verbatim to render the icon and to
// pre-fill the upsert form. Add new templates *append-only* - existing
// IDs are referenced by operators in change logs.
type ToolTemplate struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Icon            string   `json:"icon"`             // lucide-react component name
	Accent          string   `json:"accent,omitempty"` // tailwind hue: emerald / amber / rose …
	Description     string   `json:"description"`
	Tags            []string `json:"tags,omitempty"`
	SOC2Controls    []string `json:"soc2_controls,omitempty"`
	OWASPCategories []string `json:"owasp_categories,omitempty"`
	Source          string   `json:"source"`
	// ToolDefaults maps 1-to-1 to the AgenticToolTier upsert body. Keys
	// match the wire format used by /api/agentic-security/tools (PUT) so
	// the UI can POST the same object verbatim.
	ToolDefaults map[string]any `json:"tool_defaults"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────

// metaCommon returns the always-on _meta keys (icon + accent) merged with
// whatever per-tool extras are passed. Centralising this keeps every tool
// template comparable at a glance and prevents drift in the _meta shape.
func metaCommon(icon, accent string, extra map[string]any) map[string]any {
	out := map[string]any{"icon": icon, "accent": accent}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ─── Reusable sub-blocks ──────────────────────────────────────────────────

// noEgress = a sandbox profile with no outbound permissions. Most read-only
// or filesystem tools default to this; the PEP combines it with workspace
// policy to deny any network attempt at runtime.
var noEgress = map[string]any{
	"allow_egress": []string{},
	"deny_egress":  []string{"*"},
}

// permissiveCache = read-heavy tools that benefit from a 5-minute server
// cache so the PEP can short-circuit identical args.
var permissiveCache = map[string]any{
	"cache_seconds":      300,
	"cache_key_includes": []string{"workspace_id", "args_digest"},
	"cache_max_entries":  1024,
}

// strictTimeout = sane SLA defaults for HTTP-style external calls.
var strictTimeout = map[string]any{
	"request_ms":  5000,
	"total_ms":    10000,
	"deadline_ms": 15000,
}

// ─── Catalog ──────────────────────────────────────────────────────────────

var ToolTemplatesCatalog = []ToolTemplate{
	// ─── Knowledge & Retrieval ─────────────────────────────────────────────
	{
		ID:              "tool-search-web",
		Name:            "Web Search",
		Category:        "Knowledge",
		Icon:            "Globe",
		Accent:          "cyan",
		Description:     "Public web search. Read-only, cacheable. Default fail-open with PII masking on responses; outbound limited to public search APIs.",
		Tags:            []string{"search", "read", "web", "cacheable"},
		SOC2Controls:    []string{"CC7.2", "CC6.7"},
		OWASPCategories: []string{"AAI04:Tool Misuse", "AAI07:Sensitive Information Disclosure"},
		Source:          "DeepIntShield Tool Pack - Knowledge",
		ToolDefaults: map[string]any{
			"tool_name":       "search.web",
			"display_name":    "Web Search",
			"sensitivity":     "low",
			"fail_posture":    "open",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"mask:pii",
				"rate-limit:60/min",
				"redact:secrets",
				"cap:response_bytes=1MiB",
				"log:summary",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Globe", "cyan", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"search.web(*)"},
						"deny":  []string{"search.web(query:*site:internal*)", "search.web(query:*site:localhost*)"},
					},
					"network": map[string]any{
						"allow_egress": []string{"www.googleapis.com:443", "duckduckgo.com:443", "api.bing.microsoft.com:443"},
						"deny_egress":  []string{"*.internal:*", "169.254.169.254:*", "metadata.*:*"},
					},
					"rate_limit":   map[string]any{"per_minute": 60, "per_hour": 1000, "burst": 10},
					"timeout":      strictTimeout,
					"max_bytes":    map[string]any{"request": 4096, "response": 1048576},
					"ttl":          permissiveCache,
					"capabilities": []string{"net:egress:allowlisted", "read:public"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 500,
						"expected_response_kb":    []int{1, 200},
						"expected_egress_count":   1,
					},
					"examples": []map[string]any{
						{"query": "Anthropic Claude pricing", "limit": 10},
						{"query": "OWASP Agentic Top 10", "limit": 5},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"minLength":   1,
						"maxLength":   256,
						"description": "Search query string. UTF-8, no control characters.",
					},
					"limit": map[string]any{
						"type":        "integer",
						"minimum":     1,
						"maximum":     50,
						"default":     10,
						"description": "Maximum number of results returned.",
					},
					"region": map[string]any{
						"type":        "string",
						"enum":        []string{"us", "eu", "in", "global"},
						"default":     "global",
						"description": "Geographic bias for results.",
					},
				},
				"required":             []string{"query"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-vectordb-query",
		Name:            "Vector DB Query",
		Category:        "Knowledge",
		Icon:            "Database",
		Accent:          "indigo",
		Description:     "Read-only similarity search over an embedded corpus. Verified RAG provenance required on every answer; ANN search bounded by k + minimum score.",
		Tags:            []string{"rag", "read", "vector", "ann"},
		SOC2Controls:    []string{"CC7.2", "CC8.1"},
		OWASPCategories: []string{"AAI02:Hallucinated Action", "AAI04:Tool Misuse"},
		Source:          "DeepIntShield Tool Pack - RAG",
		ToolDefaults: map[string]any{
			"tool_name":       "vectordb.query",
			"display_name":    "Vector DB Query",
			"sensitivity":     "low",
			"fail_posture":    "open",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"require:rag_provenance=verified",
				"attach:source_documents",
				"limit:k=50",
				"rate-limit:120/min",
				"log:summary",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Database", "indigo", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"vectordb.query(namespace:approved-*)", "vectordb.query(namespace:public-*)"},
						"deny":  []string{"vectordb.query(namespace:secrets-*)", "vectordb.query(namespace:cross-tenant-*)"},
					},
					"network": map[string]any{
						"allow_egress": []string{"vectordb.internal:443"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 120, "per_hour": 5000, "burst": 20},
					"timeout":      map[string]any{"request_ms": 1500, "total_ms": 3000},
					"max_bytes":    map[string]any{"request": 8192, "response": 524288},
					"ttl":          map[string]any{"cache_seconds": 60, "cache_key_includes": []string{"workspace_id", "namespace", "args_digest"}},
					"capabilities": []string{"net:egress:internal-only", "read:vector"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 200,
						"expected_response_kb":    []int{1, 64},
						"expected_egress_count":   1,
					},
					"examples": []map[string]any{
						{"namespace": "approved-docs", "query": "How do approvals escalate?", "k": 5, "min_score": 0.6},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"namespace": map[string]any{
						"type":        "string",
						"pattern":     "^[a-z0-9][a-z0-9-]{0,62}$",
						"description": "Corpus namespace. Allowlisted via PEP pattern.",
					},
					"query": map[string]any{
						"type":      "string",
						"minLength": 1,
						"maxLength": 1024,
					},
					"k":         map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 5},
					"min_score": map[string]any{"type": "number", "minimum": 0, "maximum": 1, "default": 0.5},
					"filter": map[string]any{
						"type":                 "object",
						"description":          "Optional metadata filter applied to ANN results.",
						"additionalProperties": map[string]any{"type": "string"},
					},
				},
				"required":             []string{"namespace", "query"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-fs-read",
		Name:            "Filesystem Read",
		Category:        "Knowledge",
		Icon:            "FileText",
		Accent:          "slate",
		Description:     "Read a single file from the workspace. Path traversal blocked; symlinks resolved against the sandbox root; binary files refused.",
		Tags:            []string{"fs", "read"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"AAI04:Tool Misuse", "AAI07:Sensitive Information Disclosure"},
		Source:          "DeepIntShield Tool Pack - Filesystem",
		ToolDefaults: map[string]any{
			"tool_name":       "fs.read",
			"display_name":    "Filesystem Read",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"redact:secrets",
				"deny:cross-tenant",
				"cap:response_bytes=512KiB",
				"reject:binary",
				"resolve:symlinks-within-root",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("FileText", "slate", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"fs.read(./**)", "fs.read(./docs/**)", "fs.read(./reports/**)"},
						"deny":  []string{"fs.read(./.env)", "fs.read(./.env.*)", "fs.read(./secrets/**)", "fs.read(~/.ssh/**)", "fs.read(~/.aws/**)", "fs.read(/etc/**)", "fs.read(/proc/**)"},
					},
					"filesystem": map[string]any{
						"allow_paths_read":  []string{"./", "./docs/", "./reports/"},
						"deny_paths_read":   []string{"./.env", "./.env.*", "./secrets/", "./.git/objects/", "~/.ssh/", "~/.aws/", "/etc/", "/proc/", "/sys/"},
						"deny_paths_write":  []string{"/"},
						"max_path_depth":    8,
						"follow_symlinks":   false,
						"reject_extensions": []string{".pem", ".key", ".p12", ".pfx", ".keystore"},
					},
					"network":      noEgress,
					"rate_limit":   map[string]any{"per_minute": 240, "burst": 60},
					"timeout":      map[string]any{"request_ms": 1000, "total_ms": 2000},
					"max_bytes":    map[string]any{"request": 2048, "response": 524288},
					"ttl":          map[string]any{"cache_seconds": 30, "cache_key_includes": []string{"workspace_id", "path", "args_digest"}},
					"capabilities": []string{"fs:read:workspace"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 50,
						"expected_response_kb":    []int{1, 256},
						"expected_egress_count":   0,
					},
					"examples": []map[string]any{
						{"path": "./README.md"},
						{"path": "./reports/2026-Q2-summary.md", "encoding": "utf-8"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"pattern":     "^\\./[^\\x00]+$",
						"maxLength":   1024,
						"description": "Workspace-relative path. Must start with ./ - absolute paths refused.",
					},
					"encoding": map[string]any{
						"type":    "string",
						"enum":    []string{"utf-8", "base64"},
						"default": "utf-8",
					},
					"max_lines": map[string]any{"type": "integer", "minimum": 1, "maximum": 5000, "default": 2000},
				},
				"required":             []string{"path"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Filesystem / Mutating ─────────────────────────────────────────────
	{
		ID:              "tool-fs-write",
		Name:            "Filesystem Write",
		Category:        "Filesystem",
		Icon:            "FilePen",
		Accent:          "amber",
		Description:     "Write or overwrite a workspace file. High recovery cost - defaults to fail-closed with real-time revocation, atomic rename, and a backup of the prior content.",
		Tags:            []string{"fs", "write", "mutating", "atomic"},
		SOC2Controls:    []string{"CC6.1", "CC7.4", "CC8.1"},
		OWASPCategories: []string{"AAI04:Tool Misuse", "AAI06:Excessive Agency"},
		Source:          "DeepIntShield Tool Pack - Filesystem",
		ToolDefaults: map[string]any{
			"tool_name":       "fs.write",
			"display_name":    "Filesystem Write",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "medium",
			"enforce":         true,
			"action_class":    "write",
			"obligations": []string{
				"log:full",
				"audit:hash-chain",
				"backup:prior-content",
				"atomic:rename",
				"cap:request_bytes=5MiB",
				"deny:overwrite-without-prev-hash",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("FilePen", "amber", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"fs.write(./src/**)", "fs.write(./test/**)", "fs.write(./out/**)"},
						"deny":  []string{"fs.write(./.env*)", "fs.write(./secrets/**)", "fs.write(/etc/**)", "fs.write(/usr/**)"},
						"ask":   []string{"fs.write(./Dockerfile)", "fs.write(./package.json)", "fs.write(./go.mod)"},
					},
					"filesystem": map[string]any{
						"allow_paths_write": []string{"./src/", "./test/", "./out/", "/tmp/"},
						"deny_paths_write":  []string{"./.env", "./.env.*", "./secrets/", "./.git/", "/etc/", "/usr/", "/bin/", "/sbin/"},
						"reject_extensions": []string{".so", ".dylib", ".dll", ".exe"},
						"follow_symlinks":   false,
						"max_path_depth":    12,
					},
					"network":      noEgress,
					"rate_limit":   map[string]any{"per_minute": 60, "burst": 10},
					"timeout":      map[string]any{"request_ms": 3000, "total_ms": 6000},
					"max_bytes":    map[string]any{"request": 5242880, "response": 1024},
					"capabilities": []string{"fs:write:scoped"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 80,
						"expected_request_kb":     []int{1, 1024},
						"expected_egress_count":   0,
					},
					"examples": []map[string]any{
						{"path": "./src/foo.ts", "content": "export const x = 1;", "if_match_sha256": "abc…"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"pattern":     "^\\./[^\\x00]+$",
						"maxLength":   1024,
						"description": "Workspace-relative destination path.",
					},
					"content": map[string]any{
						"type":        "string",
						"maxLength":   5242880,
						"description": "File contents. UTF-8 unless `encoding` is base64.",
					},
					"encoding": map[string]any{"type": "string", "enum": []string{"utf-8", "base64"}, "default": "utf-8"},
					"mode": map[string]any{
						"type":        "string",
						"enum":        []string{"0600", "0640", "0644"},
						"default":     "0644",
						"description": "POSIX mode bits to apply.",
					},
					"if_match_sha256": map[string]any{
						"type":        "string",
						"pattern":     "^[a-f0-9]{64}$",
						"description": "Optimistic concurrency - operation aborts if the current file digest differs.",
					},
				},
				"required":             []string{"path", "content"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-fs-delete",
		Name:            "Filesystem Delete",
		Category:        "Filesystem",
		Icon:            "Trash2",
		Accent:          "rose",
		Description:     "Destructive - permanent delete. Always requires human approval; soft-delete window of 7 days; protected paths denied at PEP.",
		Tags:            []string{"fs", "destructive", "approval", "soft-delete"},
		SOC2Controls:    []string{"CC6.1", "CC7.4", "CC8.1"},
		OWASPCategories: []string{"AAI06:Excessive Agency"},
		Source:          "DeepIntShield Tool Pack - Filesystem",
		ToolDefaults: map[string]any{
			"tool_name":       "fs.delete",
			"display_name":    "Filesystem Delete",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "high",
			"enforce":         true,
			"action_class":    "delete",
			"obligations": []string{
				"require:approval",
				"log:full",
				"audit:hash-chain",
				"soft-delete:7d",
				"deny:directory-recursive",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Trash2", "rose", map[string]any{
					"patterns": map[string]any{
						"deny": []string{"fs.delete(./)", "fs.delete(/)", "fs.delete(./.git/**)", "fs.delete(./node_modules)"},
						"ask":  []string{"fs.delete(./**)"},
					},
					"filesystem": map[string]any{
						"deny_paths_delete": []string{"./", "./.git/", "./node_modules/", "/", "/etc/", "/usr/"},
						"recursive_allowed": false,
						"follow_symlinks":   false,
					},
					"network":      noEgress,
					"rate_limit":   map[string]any{"per_minute": 6, "per_hour": 30, "burst": 1},
					"timeout":      map[string]any{"request_ms": 2000, "total_ms": 4000},
					"capabilities": []string{"fs:delete:scoped"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 30,
						"expected_egress_count":   0,
					},
					"examples": []map[string]any{
						{"path": "./out/old-report.pdf"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":      "string",
						"pattern":   "^\\./[^\\x00]+$",
						"maxLength": 1024,
					},
					"reason": map[string]any{"type": "string", "minLength": 8, "maxLength": 240, "description": "Required justification recorded in audit chain."},
				},
				"required":             []string{"path", "reason"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Code / Shell ──────────────────────────────────────────────────────
	{
		ID:              "tool-shell-readonly",
		Name:            "Shell - Read-Only",
		Category:        "Code",
		Icon:            "Terminal",
		Accent:          "slate",
		Description:     "Whitelisted read-only shell commands (ls, cat, grep, head, tail, wc). Glob patterns sanitised; redirection / piping disabled; cwd pinned to workspace.",
		Tags:            []string{"shell", "read", "sandbox"},
		SOC2Controls:    []string{"CC6.1", "CC7.2"},
		OWASPCategories: []string{"AAI04:Tool Misuse"},
		Source:          "Adapted from Claude Agent SDK Bash readonly",
		ToolDefaults: map[string]any{
			"tool_name":       "shell.readonly",
			"display_name":    "Shell (read-only)",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"allow:ls,cat,grep,head,tail,wc,file,stat,find",
				"deny:rm,curl,wget,sudo,chmod,chown",
				"deny:redirect,pipe,subshell",
				"cap:response_bytes=512KiB",
				"timeout:10s",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Terminal", "slate", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"shell.readonly(ls *)", "shell.readonly(cat ./*)", "shell.readonly(grep *)", "shell.readonly(head *)", "shell.readonly(tail *)", "shell.readonly(wc *)", "shell.readonly(find ./*)"},
						"deny":  []string{"shell.readonly(rm *)", "shell.readonly(curl *)", "shell.readonly(wget *)", "shell.readonly(sudo *)", "shell.readonly(* | *)", "shell.readonly(* > *)", "shell.readonly(* < *)", "shell.readonly(* `*` *)", "shell.readonly(* $(*) *)"},
					},
					"shell": map[string]any{
						"allow_binaries":     []string{"ls", "cat", "grep", "head", "tail", "wc", "file", "stat", "find"},
						"deny_binaries":      []string{"rm", "curl", "wget", "sudo", "chmod", "chown", "dd", "mkfs", "mount"},
						"deny_operators":     []string{"|", ">", "<", ";", "&", "&&", "||", "`", "$(", ">>"},
						"cwd_pin":            "./",
						"max_argv":           24,
						"max_argv_total_len": 4096,
					},
					"filesystem": map[string]any{
						"allow_paths_read": []string{"./"},
						"deny_paths_read":  []string{"./.env", "./.env.*", "./secrets/", "/etc/shadow"},
					},
					"network":      noEgress,
					"rate_limit":   map[string]any{"per_minute": 60, "burst": 10},
					"timeout":      map[string]any{"request_ms": 10000, "total_ms": 12000, "kill_after_ms": 11000},
					"max_bytes":    map[string]any{"request": 4096, "response": 524288},
					"capabilities": []string{"shell:read:scoped"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 200,
						"expected_response_kb":    []int{0, 256},
						"expected_egress_count":   0,
					},
					"examples": []map[string]any{
						{"cmd": "ls -la ./src"},
						{"cmd": "grep -rn 'TODO' ./src --include='*.ts'"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"cmd": map[string]any{
						"type":        "string",
						"minLength":   1,
						"maxLength":   2048,
						"description": "Single shell command. No pipes, redirects, or subshells.",
					},
					"timeout_ms": map[string]any{"type": "integer", "minimum": 100, "maximum": 10000, "default": 5000},
				},
				"required":             []string{"cmd"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-git-readonly",
		Name:            "Git - Read",
		Category:        "Code",
		Icon:            "GitBranch",
		Accent:          "cyan",
		Description:     "Git diff / log / status / blame / show. No push, no merge, no reset, no rebase. Auto-approves on enforce; pager disabled.",
		Tags:            []string{"git", "read"},
		SOC2Controls:    []string{"CC7.2", "CC8.1"},
		OWASPCategories: []string{"AAI04:Tool Misuse"},
		Source:          "DeepIntShield Tool Pack - Code",
		ToolDefaults: map[string]any{
			"tool_name":       "git.read",
			"display_name":    "Git (read)",
			"sensitivity":     "low",
			"fail_posture":    "open",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"allow:status,diff,log,blame,show,ls-files,rev-parse",
				"deny:push,pull,fetch,merge,rebase,reset,checkout-branch",
				"env:GIT_PAGER=cat,GIT_TERMINAL_PROMPT=0",
				"cap:response_bytes=2MiB",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("GitBranch", "cyan", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"git.read(status*)", "git.read(diff*)", "git.read(log*)", "git.read(blame*)", "git.read(show*)", "git.read(ls-files*)", "git.read(rev-parse*)"},
						"deny":  []string{"git.read(push*)", "git.read(pull*)", "git.read(fetch*)", "git.read(merge*)", "git.read(rebase*)", "git.read(reset*)"},
					},
					"shell": map[string]any{
						"allow_subcommands": []string{"status", "diff", "log", "blame", "show", "ls-files", "rev-parse", "branch", "tag"},
						"deny_subcommands":  []string{"push", "pull", "fetch", "merge", "rebase", "reset", "clone", "remote", "config"},
						"env": map[string]any{
							"GIT_PAGER":           "cat",
							"GIT_TERMINAL_PROMPT": "0",
							"GIT_CONFIG_NOSYSTEM": "1",
						},
						"cwd_pin": "./",
					},
					"network":      noEgress,
					"rate_limit":   map[string]any{"per_minute": 120, "burst": 30},
					"timeout":      map[string]any{"request_ms": 5000, "total_ms": 10000},
					"max_bytes":    map[string]any{"request": 4096, "response": 2097152},
					"ttl":          map[string]any{"cache_seconds": 15, "cache_key_includes": []string{"workspace_id", "cmd", "args_digest"}},
					"capabilities": []string{"git:read"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 150,
						"expected_response_kb":    []int{1, 512},
					},
					"examples": []map[string]any{
						{"cmd": "log", "args": []string{"--oneline", "-n", "20"}},
						{"cmd": "diff", "args": []string{"main", "--stat"}},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"cmd": map[string]any{
						"type":        "string",
						"enum":        []string{"status", "diff", "log", "blame", "show", "ls-files", "rev-parse", "branch", "tag"},
						"description": "Git subcommand. Only read-only subcommands accepted.",
					},
					"args": map[string]any{
						"type":     "array",
						"items":    map[string]any{"type": "string", "maxLength": 256},
						"maxItems": 24,
					},
				},
				"required":             []string{"cmd"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-git-write",
		Name:            "Git - Write",
		Category:        "Code",
		Icon:            "GitCommit",
		Accent:          "amber",
		Description:     "Commit / push / merge. Push to protected branches requires approval; force-push denied; merge to main always escalates; signed commits enforced.",
		Tags:            []string{"git", "write", "approval", "protected-branch"},
		SOC2Controls:    []string{"CC6.1", "CC8.1"},
		OWASPCategories: []string{"AAI06:Excessive Agency"},
		Source:          "DeepIntShield Tool Pack - Code",
		ToolDefaults: map[string]any{
			"tool_name":       "git.write",
			"display_name":    "Git (write)",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "medium",
			"enforce":         true,
			"action_class":    "write",
			"obligations": []string{
				"deny:force-push",
				"deny:branch-delete-protected",
				"approval:protected-branch",
				"approval:merge-to-main",
				"require:signed-commit",
				"audit:hash-chain",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("GitCommit", "amber", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"git.write(commit*)", "git.write(checkout*)", "git.write(branch * -b)"},
						"deny":  []string{"git.write(* --force*)", "git.write(* -f *)", "git.write(branch -D *)", "git.write(reset --hard*)"},
						"ask":   []string{"git.write(push origin main)", "git.write(push origin master)", "git.write(merge main)"},
					},
					"shell": map[string]any{
						"allow_subcommands":      []string{"commit", "push", "merge", "checkout", "branch", "tag"},
						"protected_branches":     []string{"main", "master", "release/*", "prod/*"},
						"deny_force_push":        true,
						"require_signed_commits": true,
						"env": map[string]any{
							"GIT_TERMINAL_PROMPT": "0",
						},
					},
					"network": map[string]any{
						"allow_egress": []string{"github.com:443", "gitlab.com:443", "ssh.github.com:22"},
						"deny_egress":  []string{"*.internal:*"},
					},
					"rate_limit":   map[string]any{"per_minute": 30, "per_hour": 200, "burst": 5},
					"timeout":      map[string]any{"request_ms": 30000, "total_ms": 45000},
					"max_bytes":    map[string]any{"request": 8192, "response": 524288},
					"capabilities": []string{"git:write", "net:egress:scm"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 2000,
					},
					"examples": []map[string]any{
						{"cmd": "commit", "args": []string{"-m", "feat: add fingerprint check", "-S"}},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"cmd": map[string]any{
						"type": "string",
						"enum": []string{"commit", "push", "merge", "checkout", "branch", "tag"},
					},
					"args": map[string]any{
						"type":     "array",
						"items":    map[string]any{"type": "string", "maxLength": 256},
						"maxItems": 24,
					},
				},
				"required":             []string{"cmd"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Database ──────────────────────────────────────────────────────────
	{
		ID:              "tool-db-select",
		Name:            "DB Select",
		Category:        "Database",
		Icon:            "Database",
		Accent:          "cyan",
		Description:     "Parameterized read-only SQL. Schema-pinned, row-limit enforced, PII columns redacted on response. EXPLAIN cost capped to bound runaway queries.",
		Tags:            []string{"db", "sql", "read", "parameterized"},
		SOC2Controls:    []string{"CC6.7", "CC7.2"},
		OWASPCategories: []string{"AAI07:Sensitive Information Disclosure"},
		Source:          "DeepIntShield Tool Pack - Data",
		ToolDefaults: map[string]any{
			"tool_name":       "db.select",
			"display_name":    "DB Select",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"mask:pii",
				"redact:phi",
				"limit:1000",
				"max-cost:100",
				"timeout:10s",
				"deny:multi-statement",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Database", "cyan", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"db.select(SELECT *)"},
						"deny":  []string{"db.select(*INSERT*)", "db.select(*UPDATE*)", "db.select(*DELETE*)", "db.select(*DROP*)", "db.select(*TRUNCATE*)", "db.select(*ALTER*)", "db.select(*;*)"},
					},
					"sql": map[string]any{
						"allow_statements":     []string{"SELECT", "WITH"},
						"deny_statements":      []string{"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"},
						"deny_multi_statement": true,
						"deny_comments":        false,
						"max_explain_cost":     100,
						"redact_columns_regex": "(email|phone|ssn|card|password)",
						"schema_allowlist":     []string{"public", "reporting"},
					},
					"network": map[string]any{
						"allow_egress": []string{"db.internal:5432"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 60, "per_hour": 2000, "burst": 10},
					"timeout":      map[string]any{"request_ms": 10000, "total_ms": 12000, "statement_ms": 9000},
					"max_bytes":    map[string]any{"request": 16384, "response": 1048576},
					"ttl":          map[string]any{"cache_seconds": 60, "cache_key_includes": []string{"workspace_id", "args_digest"}},
					"capabilities": []string{"db:select:scoped", "net:egress:internal-only"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 300,
						"expected_response_kb":    []int{1, 256},
						"expected_row_count":      []int{0, 1000},
					},
					"examples": []map[string]any{
						{"sql": "SELECT id, created_at FROM reports WHERE workspace_id = :ws LIMIT :n", "params": map[string]any{"ws": "ws-…", "n": 20}, "limit": 20},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"sql": map[string]any{
						"type":        "string",
						"minLength":   1,
						"maxLength":   16384,
						"description": "Parameterized SELECT or WITH … SELECT. Bind parameters with :name.",
					},
					"params": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
						"description":          "Named parameter bindings.",
					},
					"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
				},
				"required":             []string{"sql"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-db-write",
		Name:            "DB Write",
		Category:        "Database",
		Icon:            "DatabaseZap",
		Accent:          "rose",
		Description:     "Mutating SQL (INSERT / UPDATE). DELETE / DROP / TRUNCATE escalate to approval. Run inside a transaction with auto-rollback on policy fail; affected-row cap enforced.",
		Tags:            []string{"db", "sql", "write", "approval", "transactional"},
		SOC2Controls:    []string{"CC6.1", "CC7.4", "CC8.1"},
		OWASPCategories: []string{"AAI06:Excessive Agency", "AAI07:Sensitive Information Disclosure"},
		Source:          "DeepIntShield Tool Pack - Data",
		ToolDefaults: map[string]any{
			"tool_name":       "db.write",
			"display_name":    "DB Write",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "high",
			"enforce":         true,
			"action_class":    "write",
			"obligations": []string{
				"deny:delete,drop,truncate,alter",
				"wrap:transaction",
				"limit:affected-rows=500",
				"log:full",
				"audit:hash-chain",
				"require:where-clause",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("DatabaseZap", "rose", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"db.write(INSERT INTO *)", "db.write(UPDATE * SET * WHERE *)"},
						"ask":   []string{"db.write(UPDATE * WHERE id = *)"},
						"deny":  []string{"db.write(DELETE FROM *)", "db.write(DROP *)", "db.write(TRUNCATE *)", "db.write(ALTER *)", "db.write(UPDATE * WHERE 1=1)"},
					},
					"sql": map[string]any{
						"allow_statements":        []string{"INSERT", "UPDATE"},
						"deny_statements":         []string{"DELETE", "DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "CREATE"},
						"deny_multi_statement":    true,
						"require_where_clause":    true,
						"max_affected_rows":       500,
						"transaction":             "auto-wrap",
						"rollback_on_policy_fail": true,
					},
					"network": map[string]any{
						"allow_egress": []string{"db.internal:5432"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 30, "per_hour": 500, "burst": 5},
					"timeout":      map[string]any{"request_ms": 10000, "total_ms": 12000, "statement_ms": 8000},
					"max_bytes":    map[string]any{"request": 65536, "response": 8192},
					"capabilities": []string{"db:write:scoped", "tx:wrap"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 500,
						"expected_affected_rows":  []int{0, 100},
					},
					"examples": []map[string]any{
						{"sql": "UPDATE reports SET status = :s WHERE id = :id", "params": map[string]any{"s": "approved", "id": "rep-…"}},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"sql": map[string]any{
						"type":      "string",
						"minLength": 1,
						"maxLength": 65536,
					},
					"params": map[string]any{
						"type":                 "object",
						"additionalProperties": true,
					},
					"expected_affected": map[string]any{
						"type":        "integer",
						"minimum":     0,
						"maximum":     500,
						"description": "Optional sanity check - fails if actual differs.",
					},
				},
				"required":             []string{"sql"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Communication ─────────────────────────────────────────────────────
	{
		ID:              "tool-email-send",
		Name:            "Email Send",
		Category:        "Communication",
		Icon:            "Mail",
		Accent:          "amber",
		Description:     "Outbound email. Bulk send (>10 recipients) escalates to approval; recipient domain allowlist enforced; templated body required so the LLM can't free-form prompt-injection payloads.",
		Tags:            []string{"email", "outbound", "approval", "templated"},
		SOC2Controls:    []string{"CC6.7", "CC7.4"},
		OWASPCategories: []string{"AAI06:Excessive Agency"},
		Source:          "DeepIntShield Tool Pack - Communication",
		ToolDefaults: map[string]any{
			"tool_name":       "email.send",
			"display_name":    "Email Send",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "high",
			"enforce":         true,
			"action_class":    "external_call",
			"obligations": []string{
				"approval:bulk-or-external-domain",
				"allow-domain:configured",
				"deny:attachments-without-scan",
				"template-required",
				"log:full",
				"audit:hash-chain",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Mail", "amber", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"email.send(to:*@deepintshield.com)"},
						"ask":   []string{"email.send(to:*@partner-approved.com)"},
						"deny":  []string{"email.send(to:*@public.*)", "email.send(to:**@*.* unknown)"},
					},
					"email": map[string]any{
						"allow_domains":      []string{"deepintshield.com", "partner-approved.com"},
						"deny_domains":       []string{"*.public", "tempmail.*", "mailinator.*"},
						"max_recipients":     10,
						"max_recipients_to":  5,
						"max_recipients_cc":  3,
						"max_recipients_bcc": 2,
						"require_template":   true,
						"attachment_scan":    "required",
						"attachment_max_mb":  10,
					},
					"network": map[string]any{
						"allow_egress": []string{"smtp.internal:587", "smtp.partner-approved.com:587"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 10, "per_hour": 60, "burst": 3},
					"timeout":      strictTimeout,
					"max_bytes":    map[string]any{"request": 524288, "response": 4096},
					"capabilities": []string{"net:egress:smtp", "comms:email"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 1500,
					},
					"examples": []map[string]any{
						{"to": []string{"ops@deepintshield.com"}, "subject": "Deploy approved", "template_id": "ops.deploy", "vars": map[string]any{"sha": "abc"}},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"to": map[string]any{
						"type":     "array",
						"items":    map[string]any{"type": "string", "format": "email", "maxLength": 254},
						"minItems": 1,
						"maxItems": 5,
					},
					"cc":          map[string]any{"type": "array", "items": map[string]any{"type": "string", "format": "email"}, "maxItems": 3},
					"bcc":         map[string]any{"type": "array", "items": map[string]any{"type": "string", "format": "email"}, "maxItems": 2},
					"subject":     map[string]any{"type": "string", "minLength": 3, "maxLength": 200},
					"template_id": map[string]any{"type": "string", "pattern": "^[a-z0-9.-]+$", "description": "Required templated body identifier."},
					"vars": map[string]any{
						"type":                 "object",
						"description":          "Template variable bindings.",
						"additionalProperties": true,
					},
					"reply_to": map[string]any{"type": "string", "format": "email"},
				},
				"required":             []string{"to", "subject", "template_id"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-slack-post",
		Name:            "Slack Post",
		Category:        "Communication",
		Icon:            "MessageSquare",
		Accent:          "indigo",
		Description:     "Post to a Slack channel. Bot-token scoped; @channel / @here escalate; rate-limited per channel; markdown sanitised for prompt-injection patterns.",
		Tags:            []string{"slack", "outbound", "sanitised"},
		SOC2Controls:    []string{"CC6.7"},
		OWASPCategories: []string{"AAI04:Tool Misuse"},
		Source:          "DeepIntShield Tool Pack - Communication",
		ToolDefaults: map[string]any{
			"tool_name":       "slack.post",
			"display_name":    "Slack Post",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "external_call",
			"obligations": []string{
				"approval:@channel,@here,@everyone",
				"rate-limit:per-channel",
				"sanitise:markdown",
				"deny:cross-workspace",
				"log:summary",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("MessageSquare", "indigo", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"slack.post(channel:#eng-*)", "slack.post(channel:#oncall-*)"},
						"ask":   []string{"slack.post(channel:#general)", "slack.post(message:*@channel*)", "slack.post(message:*@here*)"},
						"deny":  []string{"slack.post(message:*@everyone*)", "slack.post(channel:#exec-*)"},
					},
					"slack": map[string]any{
						"allow_channels":    []string{"#eng-*", "#oncall-*"},
						"deny_channels":     []string{"#exec-*", "#hr-*"},
						"deny_mentions":     []string{"@everyone"},
						"ask_mentions":      []string{"@channel", "@here"},
						"max_blocks":        10,
						"max_attachments":   0,
						"sanitise_markdown": true,
					},
					"network": map[string]any{
						"allow_egress": []string{"slack.com:443", "*.slack.com:443"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 30, "per_channel_minute": 5, "burst": 5},
					"timeout":      strictTimeout,
					"max_bytes":    map[string]any{"request": 16384, "response": 2048},
					"capabilities": []string{"net:egress:slack", "comms:chat"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 600,
					},
					"examples": []map[string]any{
						{"channel": "#eng-deploys", "message": "Deploy abc landed in canary."},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"channel": map[string]any{
						"type":        "string",
						"pattern":     "^#[a-z0-9][a-z0-9-_]*$",
						"maxLength":   80,
						"description": "Slack channel name including leading #.",
					},
					"message": map[string]any{
						"type":      "string",
						"minLength": 1,
						"maxLength": 4096,
					},
					"thread_ts": map[string]any{"type": "string", "pattern": "^[0-9]{10}\\.[0-9]{6}$"},
					"as_user":   map[string]any{"type": "boolean", "default": false},
				},
				"required":             []string{"channel", "message"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Finance ───────────────────────────────────────────────────────────
	{
		ID:              "tool-finance-read",
		Name:            "Finance Read",
		Category:        "Finance",
		Icon:            "LineChart",
		Accent:          "cyan",
		Description:     "Read account balances, ledger entries, transaction history. PII masking is mandatory; card numbers redacted to last-4; date range capped at 90 days.",
		Tags:            []string{"finance", "read", "pii-masked"},
		SOC2Controls:    []string{"CC6.7", "CC7.2"},
		OWASPCategories: []string{"AAI07:Sensitive Information Disclosure"},
		Source:          "DeepIntShield Tool Pack - Finance",
		ToolDefaults: map[string]any{
			"tool_name":       "finance.read",
			"display_name":    "Finance Read",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"mask:pii",
				"redact:card-numbers",
				"redact:bank-accounts",
				"limit:date-range=90d",
				"log:full",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("LineChart", "cyan", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"finance.read(account_id:acct_*)"},
						"deny":  []string{"finance.read(*)"},
					},
					"network": map[string]any{
						"allow_egress": []string{"finance-api.internal:443"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 60, "per_hour": 1000, "burst": 10},
					"timeout":      strictTimeout,
					"max_bytes":    map[string]any{"request": 4096, "response": 524288},
					"ttl":          map[string]any{"cache_seconds": 30, "cache_key_includes": []string{"workspace_id", "args_digest"}},
					"capabilities": []string{"net:egress:finance", "read:financial"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 800,
					},
					"examples": []map[string]any{
						{"account_id": "acct_123", "from": "2026-05-01", "to": "2026-05-31"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"account_id": map[string]any{"type": "string", "pattern": "^acct_[a-zA-Z0-9]{6,32}$"},
					"from":       map[string]any{"type": "string", "format": "date"},
					"to":         map[string]any{"type": "string", "format": "date"},
					"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
				},
				"required":             []string{"account_id"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-payments-charge",
		Name:            "Payments Charge",
		Category:        "Finance",
		Icon:            "CreditCard",
		Accent:          "rose",
		Description:     "Initiates a charge. Always requires human approval, idempotency key required, hard cap on amount, hash-chain audited; PII completely redacted from the LLM context.",
		Tags:            []string{"finance", "payments", "approval", "high-stakes", "idempotent"},
		SOC2Controls:    []string{"CC6.1", "CC7.4", "CC8.1"},
		OWASPCategories: []string{"AAI06:Excessive Agency"},
		Source:          "DeepIntShield Tool Pack - Finance",
		ToolDefaults: map[string]any{
			"tool_name":       "payments.charge",
			"display_name":    "Payments Charge",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "high",
			"enforce":         true,
			"action_class":    "payment",
			"obligations": []string{
				"require:approval",
				"require:idempotency_key",
				"cap:amount_cents=1000000",
				"cap:per-customer-daily=500000",
				"audit:hash-chain",
				"log:full",
				"redact:card-numbers",
				"deny:retry-after-success",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("CreditCard", "rose", map[string]any{
					"patterns": map[string]any{
						"ask":  []string{"payments.charge(*)"},
						"deny": []string{"payments.charge(amount_cents:[1000001*])", "payments.charge(currency:!USD)", "payments.charge(currency:!EUR)", "payments.charge(currency:!INR)"},
					},
					"finance": map[string]any{
						"max_amount_cents":             1000000,
						"max_per_customer_daily_cents": 500000,
						"allow_currencies":             []string{"USD", "EUR", "INR", "GBP"},
						"idempotency_required":         true,
						"idempotency_ttl_seconds":      86400,
						"approval_required":            true,
						"approval_timeout_seconds":     900,
					},
					"network": map[string]any{
						"allow_egress": []string{"api.stripe.com:443", "api.adyen.com:443", "api.razorpay.com:443"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 6, "per_hour": 100, "burst": 1},
					"timeout":      map[string]any{"request_ms": 15000, "total_ms": 20000},
					"max_bytes":    map[string]any{"request": 4096, "response": 8192},
					"capabilities": []string{"net:egress:psp", "write:payment"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 3000,
					},
					"examples": []map[string]any{
						{"amount_cents": 4999, "currency": "USD", "customer_id": "cus_abc", "idempotency_key": "ord-2026-06-01-001", "description": "Pro plan monthly"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"amount_cents":    map[string]any{"type": "integer", "minimum": 1, "maximum": 1000000, "description": "Charge amount in minor units."},
					"currency":        map[string]any{"type": "string", "enum": []string{"USD", "EUR", "INR", "GBP"}},
					"customer_id":     map[string]any{"type": "string", "pattern": "^cus_[a-zA-Z0-9]{6,32}$"},
					"idempotency_key": map[string]any{"type": "string", "pattern": "^[a-zA-Z0-9._-]{8,64}$"},
					"description":     map[string]any{"type": "string", "maxLength": 200},
					"metadata": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string", "maxLength": 200},
					},
				},
				"required":             []string{"amount_cents", "currency", "customer_id", "idempotency_key"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Web / External Egress ─────────────────────────────────────────────
	{
		ID:              "tool-http-get",
		Name:            "HTTP GET",
		Category:        "Web",
		Icon:            "Globe2",
		Accent:          "slate",
		Description:     "Outbound HTTP GET to an allowlisted host set. SSRF protections active; response body PII-masked before reaching the model; private IPs blocked.",
		Tags:            []string{"http", "external", "egress", "ssrf-protected"},
		SOC2Controls:    []string{"CC6.7", "CC6.8"},
		OWASPCategories: []string{"AAI07:Sensitive Information Disclosure", "AAI10:Unbounded Consumption"},
		Source:          "DeepIntShield Tool Pack - Web",
		ToolDefaults: map[string]any{
			"tool_name":       "http.get",
			"display_name":    "HTTP GET",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "low",
			"enforce":         true,
			"action_class":    "external_call",
			"obligations": []string{
				"egress:allowlist",
				"mask:pii",
				"rate-limit:120/min",
				"timeout:30s",
				"deny:private-ips",
				"deny:metadata-services",
				"strip:set-cookie",
				"max-bytes:1MiB",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Globe2", "slate", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"http.get(url:https://api.partner-approved.com/*)", "http.get(url:https://api.openai.com/*)"},
						"deny":  []string{"http.get(url:http://*)", "http.get(url:*://localhost*)", "http.get(url:*://169.254.*)", "http.get(url:*://10.*)", "http.get(url:*://192.168.*)", "http.get(url:*://172.16.*)"},
					},
					"network": map[string]any{
						"allow_egress":      []string{"api.partner-approved.com:443", "api.openai.com:443", "api.anthropic.com:443"},
						"deny_egress":       []string{"localhost:*", "127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "*.internal:*", "metadata.*:*"},
						"deny_private_ips":  true,
						"deny_redirects_to": []string{"http://*", "*://localhost*", "*://*.internal*"},
						"max_redirects":     3,
						"require_tls":       true,
						"tls_min_version":   "1.2",
					},
					"rate_limit":   map[string]any{"per_minute": 120, "per_host_minute": 30, "burst": 20},
					"timeout":      map[string]any{"request_ms": 5000, "total_ms": 30000, "connect_ms": 2000, "tls_handshake_ms": 2000},
					"max_bytes":    map[string]any{"request": 8192, "response": 1048576},
					"ttl":          map[string]any{"cache_seconds": 60, "cache_respects_headers": true},
					"capabilities": []string{"net:egress:allowlisted"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 1500,
						"expected_response_kb":    []int{1, 256},
					},
					"examples": []map[string]any{
						{"url": "https://api.partner-approved.com/v1/status"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"format":      "uri",
						"pattern":     "^https://[a-zA-Z0-9.-]+(/.*)?$",
						"maxLength":   2048,
						"description": "HTTPS only. Allowlist enforced at the network layer.",
					},
					"headers": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string", "maxLength": 1024},
						"description":          "Request headers. Hop-by-hop headers stripped automatically.",
					},
					"timeout_ms": map[string]any{"type": "integer", "minimum": 100, "maximum": 30000, "default": 5000},
				},
				"required":             []string{"url"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-http-post",
		Name:            "HTTP POST",
		Category:        "Web",
		Icon:            "Send",
		Accent:          "amber",
		Description:     "Outbound HTTP POST. Bulk requests escalate; idempotency key + bounded payload required; same SSRF + private-IP protections as HTTP GET.",
		Tags:            []string{"http", "external", "egress", "approval", "idempotent"},
		SOC2Controls:    []string{"CC6.7", "CC6.8"},
		OWASPCategories: []string{"AAI06:Excessive Agency", "AAI10:Unbounded Consumption"},
		Source:          "DeepIntShield Tool Pack - Web",
		ToolDefaults: map[string]any{
			"tool_name":       "http.post",
			"display_name":    "HTTP POST",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "medium",
			"enforce":         true,
			"action_class":    "external_call",
			"obligations": []string{
				"egress:allowlist",
				"require:idempotency_key",
				"max-bytes:1MiB",
				"deny:private-ips",
				"deny:metadata-services",
				"timeout:30s",
				"log:full",
				"approval:bulk",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Send", "amber", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"http.post(url:https://api.partner-approved.com/*)"},
						"ask":   []string{"http.post(url:*) bulk=true"},
						"deny":  []string{"http.post(url:http://*)", "http.post(url:*://*.internal*)"},
					},
					"network": map[string]any{
						"allow_egress":     []string{"api.partner-approved.com:443", "webhook.deepintshield.com:443"},
						"deny_egress":      []string{"localhost:*", "127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "*.internal:*"},
						"deny_private_ips": true,
						"max_redirects":    0,
						"require_tls":      true,
						"tls_min_version":  "1.2",
					},
					"rate_limit":   map[string]any{"per_minute": 60, "per_host_minute": 15, "burst": 5},
					"timeout":      map[string]any{"request_ms": 10000, "total_ms": 30000, "connect_ms": 2000, "tls_handshake_ms": 2000},
					"max_bytes":    map[string]any{"request": 1048576, "response": 524288},
					"capabilities": []string{"net:egress:allowlisted", "write:external"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 3000,
					},
					"examples": []map[string]any{
						{"url": "https://api.partner-approved.com/v1/events", "body": map[string]any{"type": "deploy"}, "idempotency_key": "evt-…"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":      "string",
						"format":    "uri",
						"pattern":   "^https://[a-zA-Z0-9.-]+(/.*)?$",
						"maxLength": 2048,
					},
					"body": map[string]any{
						"oneOf": []map[string]any{
							{"type": "object", "additionalProperties": true},
							{"type": "string", "maxLength": 1048576},
						},
						"description": "JSON object or string body. Bounded to 1 MiB.",
					},
					"headers": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string", "maxLength": 1024},
					},
					"idempotency_key": map[string]any{
						"type":        "string",
						"pattern":     "^[a-zA-Z0-9._-]{8,128}$",
						"description": "Required - server-side idempotency token.",
					},
					"timeout_ms": map[string]any{"type": "integer", "minimum": 100, "maximum": 30000, "default": 10000},
				},
				"required":             []string{"url", "body", "idempotency_key"},
				"additionalProperties": false,
			},
		},
	},

	// ─── Admin / Ops ───────────────────────────────────────────────────────
	{
		ID:              "tool-secrets-read",
		Name:            "Secrets Read",
		Category:        "Admin",
		Icon:            "KeyRound",
		Accent:          "rose",
		Description:     "Vault read. Always requires approval; values redacted from the model context - only sha256 fingerprints returned. Per-key cooldown enforced.",
		Tags:            []string{"secrets", "vault", "approval", "fingerprint-only"},
		SOC2Controls:    []string{"CC6.1", "CC6.6"},
		OWASPCategories: []string{"AAI07:Sensitive Information Disclosure", "AAI09:Identity Spoofing"},
		Source:          "DeepIntShield Tool Pack - Admin",
		ToolDefaults: map[string]any{
			"tool_name":       "secrets.read",
			"display_name":    "Secrets Read",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "high",
			"enforce":         true,
			"action_class":    "read",
			"obligations": []string{
				"require:approval",
				"redact:value",
				"return:fingerprint-only",
				"log:full",
				"cooldown:per-key=60s",
				"audit:hash-chain",
				"ttl:context=0",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("KeyRound", "rose", map[string]any{
					"patterns": map[string]any{
						"ask":  []string{"secrets.read(key:*)"},
						"deny": []string{"secrets.read(key:root-*)", "secrets.read(key:master-*)"},
					},
					"vault": map[string]any{
						"allow_key_prefixes":   []string{"app/", "team/", "service/"},
						"deny_key_prefixes":    []string{"root/", "master/", "kms/"},
						"return_only":          "fingerprint",
						"fingerprint_alg":      "sha256",
						"approval_required":    true,
						"per_key_cooldown_sec": 60,
					},
					"network": map[string]any{
						"allow_egress": []string{"vault.internal:8200"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 10, "per_hour": 100, "burst": 1},
					"timeout":      strictTimeout,
					"max_bytes":    map[string]any{"request": 1024, "response": 2048},
					"capabilities": []string{"net:egress:vault", "read:secret-fingerprint"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 800,
					},
					"examples": []map[string]any{
						{"key": "app/payments/api_key"},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"key":           map[string]any{"type": "string", "pattern": "^(app|team|service)/[a-zA-Z0-9._-]{1,128}$", "maxLength": 256},
					"justification": map[string]any{"type": "string", "minLength": 12, "maxLength": 240, "description": "Audit-recorded reason; approver sees this."},
				},
				"required":             []string{"key", "justification"},
				"additionalProperties": false,
			},
		},
	},
	{
		ID:              "tool-kube-apply",
		Name:            "Kubernetes Apply",
		Category:        "Admin",
		Icon:            "Boxes",
		Accent:          "rose",
		Description:     "kubectl apply / scale / restart. Production namespaces escalate; delete is denied; dry-run runs first and the diff is shown to the approver.",
		Tags:            []string{"k8s", "ops", "approval", "dry-run"},
		SOC2Controls:    []string{"CC6.1", "CC7.4"},
		OWASPCategories: []string{"AAI06:Excessive Agency"},
		Source:          "DeepIntShield Tool Pack - Admin",
		ToolDefaults: map[string]any{
			"tool_name":       "kube.apply",
			"display_name":    "Kubernetes Apply",
			"sensitivity":     "high",
			"fail_posture":    "closed",
			"revocation_path": "realtime",
			"recovery_cost":   "high",
			"enforce":         true,
			"action_class":    "write",
			"obligations": []string{
				"deny:delete",
				"deny:CustomResourceDefinition",
				"deny:cluster-scoped",
				"approval:namespace=prod,prod-*",
				"dry-run:first",
				"log:full",
				"audit:hash-chain",
				"diff:to-approver",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Boxes", "rose", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"kube.apply(namespace:dev-*)", "kube.apply(namespace:stage-*)"},
						"ask":   []string{"kube.apply(namespace:prod*)"},
						"deny":  []string{"kube.apply(kind:CustomResourceDefinition)", "kube.apply(kind:ClusterRole)", "kube.apply(kind:Namespace)", "kube.apply(action:delete)"},
					},
					"kubernetes": map[string]any{
						"allow_actions":   []string{"apply", "scale", "rollout-restart"},
						"deny_actions":    []string{"delete", "patch-cluster-resource"},
						"allow_kinds":     []string{"Deployment", "StatefulSet", "Service", "ConfigMap", "HorizontalPodAutoscaler"},
						"deny_kinds":      []string{"CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding", "Namespace"},
						"protected_ns":    []string{"prod", "prod-*", "kube-system"},
						"require_dry_run": true,
						"max_manifest_kb": 256,
					},
					"network": map[string]any{
						"allow_egress": []string{"k8s-apiserver.internal:6443"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 6, "per_hour": 60, "burst": 1},
					"timeout":      map[string]any{"request_ms": 30000, "total_ms": 60000},
					"max_bytes":    map[string]any{"request": 262144, "response": 65536},
					"capabilities": []string{"net:egress:k8s", "write:k8s:namespaced"},
					"baseline": map[string]any{
						"expected_latency_ms_p95": 5000,
					},
					"examples": []map[string]any{
						{"namespace": "dev-team-a", "manifest": "apiVersion: apps/v1\nkind: Deployment\n…", "dry_run": true},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"namespace": map[string]any{
						"type":        "string",
						"pattern":     "^[a-z0-9][a-z0-9-]{0,62}$",
						"description": "Target namespace. Protected namespaces escalate.",
					},
					"manifest": map[string]any{
						"type":        "string",
						"maxLength":   262144,
						"description": "Single-document YAML or JSON manifest.",
					},
					"dry_run": map[string]any{"type": "boolean", "default": true},
				},
				"required":             []string{"manifest", "namespace"},
				"additionalProperties": false,
			},
		},
	},

	// ─── MCP / Agentic ─────────────────────────────────────────────────────
	{
		ID:              "tool-mcp-generic",
		Name:            "MCP Tool (Generic)",
		Category:        "MCP",
		Icon:            "Plug",
		Accent:          "indigo",
		Description:     "Generic MCP tool placeholder - clone, rename and adjust sensitivity. Ships in shadow mode by default; fingerprint pinning enabled so server-side changes auto-quarantine.",
		Tags:            []string{"mcp", "placeholder", "shadow"},
		SOC2Controls:    []string{"CC7.2"},
		OWASPCategories: []string{"AAI04:Tool Misuse"},
		Source:          "DeepIntShield Tool Pack - MCP",
		ToolDefaults: map[string]any{
			"tool_name":       "mcp.custom",
			"display_name":    "MCP Tool",
			"sensitivity":     "medium",
			"fail_posture":    "closed",
			"revocation_path": "cached",
			"recovery_cost":   "medium",
			"enforce":         false,
			"action_class":    "external_call",
			"obligations": []string{
				"log:full",
				"fingerprint:pin",
				"behavioural-baseline:enabled",
				"rate-limit:60/min",
			},
			"args_schema": map[string]any{
				"_meta": metaCommon("Plug", "indigo", map[string]any{
					"patterns": map[string]any{
						"allow": []string{"mcp.custom(*)"},
					},
					"mcp": map[string]any{
						"server_pinning":        true,
						"fingerprint_fields":    []string{"name", "json_schema", "description", "server_id"},
						"quarantine_on_drift":   true,
						"behavioural_baseline":  true,
						"baseline_window_hours": 24,
					},
					"network": map[string]any{
						"allow_egress": []string{"mcp-gateway.internal:443"},
						"deny_egress":  []string{"*"},
					},
					"rate_limit":   map[string]any{"per_minute": 60, "burst": 10},
					"timeout":      strictTimeout,
					"max_bytes":    map[string]any{"request": 16384, "response": 524288},
					"capabilities": []string{"net:egress:mcp"},
					"baseline":     map[string]any{"expected_latency_ms_p95": 1000},
					"examples": []map[string]any{
						{"args": map[string]any{"action": "describe"}},
					},
				}),
				"type": "object",
				"properties": map[string]any{
					"args": map[string]any{
						"type":                 "object",
						"description":          "Tool-specific argument bag. Validated against the MCP server's published schema.",
						"additionalProperties": true,
					},
				},
				"additionalProperties": false,
			},
		},
	},
}

// FindToolTemplate returns one template by ID, or nil.
func FindToolTemplate(id string) *ToolTemplate {
	for i := range ToolTemplatesCatalog {
		if ToolTemplatesCatalog[i].ID == strings.TrimSpace(id) {
			return &ToolTemplatesCatalog[i]
		}
	}
	return nil
}

// ToolTemplateCategories returns the unique category names in catalog
// order. Used by the UI to render the category strip.
func ToolTemplateCategories() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	for _, t := range ToolTemplatesCatalog {
		if seen[t.Category] {
			continue
		}
		seen[t.Category] = true
		out = append(out, t.Category)
	}
	return out
}
