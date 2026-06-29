package governance

import (
	"context"
	"strings"

	"github.com/deepint-shield/ai-security/framework/tenantctx"
)

const governanceGlobalTenantKey = "__global__"

func governanceTenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	defer func() {
		_ = recover()
	}()
	return strings.TrimSpace(tenantctx.TenantIDFromContext(ctx))
}

func normalizeGovernanceTenantID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return governanceGlobalTenantKey
	}
	return tenantID
}

func governanceMatchesTenant(ctx context.Context, recordTenantID string) bool {
	requestTenantID := governanceTenantIDFromContext(ctx)
	if requestTenantID == "" {
		return true
	}
	return normalizeGovernanceTenantID(recordTenantID) == normalizeGovernanceTenantID(requestTenantID)
}

func governanceTenantScopedKey(tenantID string, key string) string {
	return normalizeGovernanceTenantID(tenantID) + "::" + key
}

func governanceVirtualKeyStoreKey(tenantID string, virtualKeyValue string) string {
	return governanceTenantScopedKey(tenantID, virtualKeyValue)
}

func governanceTeamStoreKey(tenantID string, teamID string) string {
	return governanceTenantScopedKey(tenantID, teamID)
}

func governanceCustomerStoreKey(tenantID string, customerID string) string {
	return governanceTenantScopedKey(tenantID, customerID)
}

func governanceUserStoreKey(tenantID string, userID string) string {
	return governanceTenantScopedKey(tenantID, userID)
}

func governanceProviderStoreKey(tenantID string, providerName string) string {
	return governanceTenantScopedKey(tenantID, providerName)
}

func governanceModelStoreKey(tenantID string, modelName string, providerName *string) string {
	if providerName != nil && strings.TrimSpace(*providerName) != "" {
		return governanceTenantScopedKey(tenantID, modelName+":"+strings.TrimSpace(*providerName))
	}
	return governanceTenantScopedKey(tenantID, modelName)
}

func governanceRoutingScopeStoreKey(tenantID string, scope string, scopeID string) string {
	if scope == "global" {
		return governanceTenantScopedKey(tenantID, "global:")
	}
	return governanceTenantScopedKey(tenantID, scope+":"+scopeID)
}
