package plugins

import (
	"context"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// Workspace-scoped plugin decorators
// ----------------------------------
//
// The runtime previously held one instance per plugin name globally, so
// changing one workspace's Cost-Optimization settings stomped every other
// workspace's behavior at request time. The DB/UI layers are now per-workspace
// (see migrations.migrationPluginWorkspaceUniqueIndex), but the in-memory
// registry still has to learn how to dispatch the right instance per request.
//
// We solve this with thin wrappers: a wrapper embeds the underlying plugin
// (so all existing interface assertions like p.(schemas.LLMPlugin) continue
// to work via promoted methods) and implements schemas.WorkspaceScoped to
// surface the workspace tag. The PluginPipeline reads the tag at dispatch
// time and applies the most-specific-match rule documented on WorkspaceScoped.
//
// A wrapper is only created when workspaceID is non-empty; the empty-string
// case returns the original plugin unchanged so config.json-defined globals
// and existing call sites stay byte-identical.

// llmWorkspacePlugin tags an LLMPlugin with a workspace ID.
type llmWorkspacePlugin struct {
	schemas.LLMPlugin
	workspaceID string
}

func (w *llmWorkspacePlugin) WorkspaceID() string { return w.workspaceID }

// mcpWorkspacePlugin tags an MCPPlugin with a workspace ID.
type mcpWorkspacePlugin struct {
	schemas.MCPPlugin
	workspaceID string
}

func (w *mcpWorkspacePlugin) WorkspaceID() string { return w.workspaceID }

// httpWorkspacePlugin tags an HTTPTransportPlugin with a workspace ID.
type httpWorkspacePlugin struct {
	schemas.HTTPTransportPlugin
	workspaceID string
}

func (w *httpWorkspacePlugin) WorkspaceID() string { return w.workspaceID }

// obsWorkspacePlugin tags an ObservabilityPlugin with a workspace ID.
type obsWorkspacePlugin struct {
	schemas.ObservabilityPlugin
	workspaceID string
}

func (w *obsWorkspacePlugin) WorkspaceID() string { return w.workspaceID }
func (w *obsWorkspacePlugin) Inject(ctx context.Context, trace *schemas.Trace) error {
	return w.ObservabilityPlugin.Inject(ctx, trace)
}

// basePluginWithWS tags a BasePlugin (no interface beyond BasePlugin) with a
// workspace ID. Used when the underlying plugin doesn't satisfy any of the
// richer interfaces above so we still want the workspace tag visible to the
// pipeline filter (which iterates BasePlugins to assemble dispatch sets).
type basePluginWithWS struct {
	schemas.BasePlugin
	workspaceID string
}

func (w *basePluginWithWS) WorkspaceID() string { return w.workspaceID }

// llmHTTPWorkspacePlugin tags a plugin that implements BOTH LLMPlugin and
// HTTPTransportPlugin with a workspace ID. The semantic_cache plugin is the
// canonical case: it serves as an LLM hook for the inference path and also
// implements HTTP-transport hooks for the gateway's REST surface.
//
// Embedding two interfaces would create ambiguity on the shared BasePlugin
// methods (GetName / Cleanup), so we hold concrete references and forward
// every method explicitly. The forwarding is mechanical but it's the only
// way to satisfy both interfaces from a single struct without losing the
// workspace tag (which would happen if we degraded to basePluginWithWS).
type llmHTTPWorkspacePlugin struct {
	llm         schemas.LLMPlugin
	httpT       schemas.HTTPTransportPlugin
	workspaceID string
}

func (w *llmHTTPWorkspacePlugin) WorkspaceID() string { return w.workspaceID }
func (w *llmHTTPWorkspacePlugin) GetName() string     { return w.llm.GetName() }
func (w *llmHTTPWorkspacePlugin) Cleanup() error      { return w.llm.Cleanup() }
func (w *llmHTTPWorkspacePlugin) PreLLMHook(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) (*schemas.DeepIntShieldRequest, *schemas.LLMPluginShortCircuit, error) {
	return w.llm.PreLLMHook(ctx, req)
}
func (w *llmHTTPWorkspacePlugin) PostLLMHook(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse, deepintshieldErr *schemas.DeepIntShieldError) (*schemas.DeepIntShieldResponse, *schemas.DeepIntShieldError, error) {
	return w.llm.PostLLMHook(ctx, resp, deepintshieldErr)
}
func (w *llmHTTPWorkspacePlugin) HTTPTransportPreHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return w.httpT.HTTPTransportPreHook(ctx, req)
}
func (w *llmHTTPWorkspacePlugin) HTTPTransportPostHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, resp *schemas.HTTPResponse) error {
	return w.httpT.HTTPTransportPostHook(ctx, req, resp)
}
func (w *llmHTTPWorkspacePlugin) HTTPTransportStreamChunkHook(ctx *schemas.DeepIntShieldContext, req *schemas.HTTPRequest, chunk *schemas.DeepIntShieldStreamChunk) (*schemas.DeepIntShieldStreamChunk, error) {
	return w.httpT.HTTPTransportStreamChunkHook(ctx, req, chunk)
}

// WrapWithWorkspace returns a workspace-scoped wrapper around plugin so the
// pipeline can route requests with the matching workspace_id to this instance
// instead of any same-named global instance. Returns the original plugin
// unmodified when workspaceID is empty so non-tenant / config.json plugins
// stay global.
//
// The wrapper preserves every interface the wrapped plugin implements by
// composing the richest available wrapper struct: pick the most specific
// wrapper that satisfies all of LLM / MCP / HTTPTransport / Observability
// that the underlying plugin satisfies. For the (rare) case where a plugin
// implements multiple non-base interfaces, we layer wrappers - the outer
// wrapper exposes the WorkspaceID() method, and Go's embedding promotes the
// rest. Callers don't need to know which wrapper they got; they just type-
// assert the interfaces they need.
func WrapWithWorkspace(plugin schemas.BasePlugin, workspaceID string) schemas.BasePlugin {
	workspaceID = strings.TrimSpace(workspaceID)
	if plugin == nil || workspaceID == "" {
		return plugin
	}
	// Pick the most-specific wrapper that still satisfies all the interfaces
	// the underlying plugin implements. LLM + MCP combos are vanishingly rare
	// in practice but we fall back to the basePluginWithWS wrapper so the
	// workspace tag is still visible even for unusual plugins.
	llm := AsLLMPlugin(plugin)
	mcp := AsMCPPlugin(plugin)
	httpT := AsHTTPTransportPlugin(plugin)
	obs := AsObservabilityPlugin(plugin)

	switch {
	case llm != nil && httpT != nil && mcp == nil && obs == nil:
		// semantic_cache hits this branch - both LLM and HTTP hooks. A
		// single-interface wrapper (or the BasePlugin fallback) would lose
		// one of the interface assertions in rebuildInterfaceCaches and the
		// pipeline would silently miss the plugin on whichever surface
		// wasn't wrapped.
		return &llmHTTPWorkspacePlugin{llm: llm, httpT: httpT, workspaceID: workspaceID}
	case llm != nil && mcp == nil && httpT == nil && obs == nil:
		return &llmWorkspacePlugin{LLMPlugin: llm, workspaceID: workspaceID}
	case mcp != nil && llm == nil && httpT == nil && obs == nil:
		return &mcpWorkspacePlugin{MCPPlugin: mcp, workspaceID: workspaceID}
	case httpT != nil && llm == nil && mcp == nil && obs == nil:
		return &httpWorkspacePlugin{HTTPTransportPlugin: httpT, workspaceID: workspaceID}
	case obs != nil && llm == nil && mcp == nil && httpT == nil:
		return &obsWorkspacePlugin{ObservabilityPlugin: obs, workspaceID: workspaceID}
	default:
		// Other multi-interface combos (rare in practice) fall back to the
		// BasePlugin wrapper. Add a dedicated wrapper above if the pipeline
		// needs to dispatch one of the missing interfaces per-workspace.
		return &basePluginWithWS{BasePlugin: plugin, workspaceID: workspaceID}
	}
}

// UnwrapWorkspace returns the underlying BasePlugin from any workspace wrapper.
// Useful for code paths that need to compare plugin identity / inspect plugin
// internals without the wrapper getting in the way. Returns the input
// unchanged if it isn't a wrapper.
func UnwrapWorkspace(plugin schemas.BasePlugin) schemas.BasePlugin {
	switch p := plugin.(type) {
	case *llmWorkspacePlugin:
		return p.LLMPlugin
	case *mcpWorkspacePlugin:
		return p.MCPPlugin
	case *httpWorkspacePlugin:
		return p.HTTPTransportPlugin
	case *obsWorkspacePlugin:
		return p.ObservabilityPlugin
	case *basePluginWithWS:
		return p.BasePlugin
	case *llmHTTPWorkspacePlugin:
		// Return the LLM side - both llm and httpT point at the same
		// underlying *Plugin instance, so either choice unwraps to the
		// canonical plugin object.
		return p.llm
	default:
		return plugin
	}
}

// WorkspaceIDOf returns the workspace tag attached to plugin, or "" when the
// plugin is not workspace-scoped (i.e. is a global / config.json plugin).
func WorkspaceIDOf(plugin schemas.BasePlugin) string {
	if ws, ok := plugin.(schemas.WorkspaceScoped); ok {
		return ws.WorkspaceID()
	}
	return ""
}
