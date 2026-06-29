package lib

import (
	"strings"

	"github.com/valyala/fasthttp"
)

// HeaderActiveTenantID is the header the admin UI sends to communicate the
// tenant currently selected from the sidebar tenant switcher. Handlers that
// list tenant-scoped resources can use it as the effective tenant filter
// when the calling user has access to multiple tenants.
//
// SDK / CLI compatibility: this header is OPTIONAL. Clients that don't
// send it fall through to the user's session tenant, which is what
// existing single-tenant workflows expect. Multi-tenant admin tooling
// (the dashboard) is the primary consumer.
const HeaderActiveTenantID = "X-Active-Tenant-Id"

// HeaderActiveWorkspaceID is the header the admin UI sends to communicate the
// workspace currently selected from the sidebar workspace switcher. Handlers
// that list workspace-scoped resources can use it as the effective workspace
// filter, falling back to query params or "no filter" when the header is
// absent (e.g. CLI / SDK callers that don't have a UI-bound scope).
//
// SDK / CLI compatibility: this header is OPTIONAL. Clients that don't
// send it see the full tenant view (every workspace's data), which
// matches pre-workspace behaviour. To filter explicitly from a
// non-dashboard caller, pass `?workspace_id=<id>` as a query parameter
// on list endpoints - those have higher priority than the header.
const HeaderActiveWorkspaceID = "X-Active-Workspace-Id"

// ActiveTenantHeader returns the trimmed value of HeaderActiveTenantID on
// the request, or "" if absent.
func ActiveTenantHeader(ctx *fasthttp.RequestCtx) string {
	return strings.TrimSpace(string(ctx.Request.Header.Peek(HeaderActiveTenantID)))
}

// ActiveWorkspaceHeader returns the trimmed value of HeaderActiveWorkspaceID
// on the request, or "" if absent.
func ActiveWorkspaceHeader(ctx *fasthttp.RequestCtx) string {
	return strings.TrimSpace(string(ctx.Request.Header.Peek(HeaderActiveWorkspaceID)))
}
