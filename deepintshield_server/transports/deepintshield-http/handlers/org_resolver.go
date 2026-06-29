package handlers

import (
	"context"
	"errors"
	"strings"

	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

// CurrentOrgFromCtx resolves the calling tenant's organization (and the
// session user, when available) from a request context. Used by handlers
// (e.g. the governance handler) that need to resolve the tenant's
// organization before mutating tenant resources.
//
// Tenant resolution order:
//  1. The active 3-tier tenant set by applyActiveScopeOverride (the
//     X-Active-Tenant-Id header or the workspace's parent tenant).
//  2. The user's tenant_id.
//  3. The single-tenant resolver fallback (multi-tenant=false).
//  4. The user's first org-membership (a real tenant).
func CurrentOrgFromCtx(ctx *fasthttp.RequestCtx, store configstore.ConfigStore) (*tables.TableOrganization, *tables.TableAuthUser, error) {
	user, _, userErr := currentAccountUserFromCtx(ctx, store)

	tenantID := strings.TrimSpace(activeTenantFromCtx(ctx))
	if tenantID == "" && user != nil {
		tenantID = strings.TrimSpace(user.TenantID)
	}
	if tenantID == "" {
		if resolver, ok := store.(singleTenantResolver); ok {
			resolvedTenantID, resolveErr := resolver.GetSingleTenantID(context.Background())
			if resolveErr == nil {
				tenantID = strings.TrimSpace(resolvedTenantID)
			}
		}
	}
	if tenantID == "" {
		if userErr != nil {
			return nil, nil, userErr
		}
		return nil, nil, errUnauthorizedSession
	}

	// Dual-resolve: if this id is an alias for a canonical (UUID) tenant,
	// prefer the canonical id. No-op until aliases exist.
	if canonical, aErr := store.ResolveCanonicalTenant(ctx, tenantID); aErr == nil && canonical != "" && canonical != tenantID {
		tenantID = canonical
	}

	org, orgErr := store.GetOrganizationByID(ctx, tenantID)
	if orgErr != nil {
		return nil, nil, orgErr
	}
	// Orphan-tenant fallback: self-serve signups carry a random UUID
	// tenant_id with no organizations row. Walk the user's org_memberships
	// and use the first real tenant.
	if org == nil && user != nil {
		memberships, mErr := store.ListOrgMembershipsByUser(context.Background(), user.ID)
		if mErr == nil {
			for _, m := range memberships {
				cand, _ := store.GetOrganizationByID(context.Background(), strings.TrimSpace(m.OrgID))
				if cand != nil {
					return cand, user, nil
				}
			}
		}
	}
	if org == nil {
		return nil, nil, errors.New("organization not found")
	}
	return org, user, nil
}

// gateAdvancedObservability gates Team+ attribution/observability features.
// In the open-source build there is no plan enforcement, so the gate always
// allows the request through.
func gateAdvancedObservability(_ *fasthttp.RequestCtx, _ any) bool {
	return true
}

// gatePluginEnable gates plan-restricted plugins. The open-source build has no
// plan enforcement, so every plugin is allowed.
func gatePluginEnable(_ *fasthttp.RequestCtx, _ any, _ string) bool {
	return true
}

// gateSCIM gates the SCIM provisioning feature. Always allowed in the
// open-source build.
func gateSCIM(_ *fasthttp.RequestCtx, _ any) bool {
	return true
}
