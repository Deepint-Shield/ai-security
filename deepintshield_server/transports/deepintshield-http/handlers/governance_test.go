package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	configstoreTables "github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/plugins/governance"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// mockGovernanceManagerForVK embeds the interface so unimplemented methods panic.
// Only GetGovernanceData is needed for the getVirtualKeys handler path.
type mockGovernanceManagerForVK struct {
	GovernanceManager
}

func (m *mockGovernanceManagerForVK) GetGovernanceData(context.Context) *governance.GovernanceData {
	return nil
}

type mockGovernanceManagerForModelConfigs struct {
	GovernanceManager
	data *governance.GovernanceData
}

func (m *mockGovernanceManagerForModelConfigs) GetGovernanceData(context.Context) *governance.GovernanceData {
	return m.data
}

type mockGovernanceManagerForProviders struct {
	GovernanceManager
	data *governance.GovernanceData
}

func (m *mockGovernanceManagerForProviders) GetGovernanceData(context.Context) *governance.GovernanceData {
	return m.data
}

// mockConfigStoreForVK embeds the interface so unimplemented methods panic.
// Only GetVirtualKeysPaginated is called in the non-from_memory path.
type mockConfigStoreForVK struct {
	configstore.ConfigStore
}

func (m *mockConfigStoreForVK) GetVirtualKeysPaginated(_ context.Context, _ configstore.VirtualKeyQueryParams) ([]configstoreTables.TableVirtualKey, int64, error) {
	return nil, 0, nil
}

func (m *mockConfigStoreForVK) GetVirtualKeys(_ context.Context) ([]configstoreTables.TableVirtualKey, error) {
	return nil, nil
}

type tenantAwareMockConfigStoreForVK struct {
	configstore.ConfigStore
	virtualKeysCalled bool
}

func (m *tenantAwareMockConfigStoreForVK) GetVirtualKeys(_ context.Context) ([]configstoreTables.TableVirtualKey, error) {
	m.virtualKeysCalled = true
	return []configstoreTables.TableVirtualKey{
		{
			ID:   "vk-1",
			Name: "Tenant Key",
		},
	}, nil
}

type mockGuardrailPolicyValidationStore struct {
	configstore.ConfigStore
	policies map[string]*configstoreTables.TableGuardrailPolicy
}

func (m *mockGuardrailPolicyValidationStore) GetGuardrailPolicy(_ context.Context, id string) (*configstoreTables.TableGuardrailPolicy, error) {
	if policy, ok := m.policies[id]; ok {
		return policy, nil
	}
	return nil, nil
}

type mockModelConfigValidationStore struct {
	configstore.ConfigStore
	modelConfigByID  *configstoreTables.TableModelConfig
	modelConfigByKey *configstoreTables.TableModelConfig
	getByIDCalled    bool
	getByKeyCalled   bool
	transactionRun   bool
}

func (m *mockModelConfigValidationStore) GetModelConfigByID(_ context.Context, _ string) (*configstoreTables.TableModelConfig, error) {
	m.getByIDCalled = true
	if m.modelConfigByID == nil {
		return nil, configstore.ErrNotFound
	}
	return m.modelConfigByID, nil
}

func (m *mockModelConfigValidationStore) GetModelConfig(_ context.Context, _ string, _ *string) (*configstoreTables.TableModelConfig, error) {
	m.getByKeyCalled = true
	if m.modelConfigByKey == nil {
		return nil, configstore.ErrNotFound
	}
	return m.modelConfigByKey, nil
}

func (m *mockModelConfigValidationStore) ExecuteTransaction(_ context.Context, fn func(*gorm.DB) error) error {
	m.transactionRun = true
	return fn(nil)
}

// TestGetVirtualKeys_PaginatedEndpoint_ResponseShape verifies the JSON response
// from the paginated virtual keys endpoint contains all expected fields.
func TestGetVirtualKeys_PaginatedEndpoint_ResponseShape(t *testing.T) {
	SetLogger(&mockLogger{})

	h := &GovernanceHandler{
		configStore:       &mockConfigStoreForVK{},
		governanceManager: &mockGovernanceManagerForVK{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/governance/virtual-keys?limit=10&offset=0")

	h.getVirtualKeys(ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected status 200, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	// Assert expected fields exist with correct types
	requiredFields := []struct {
		key      string
		wantType string
	}{
		{"virtual_keys", "array"},
		{"total_count", "number"},
		{"count", "number"},
		{"limit", "number"},
		{"offset", "number"},
	}

	for _, f := range requiredFields {
		val, ok := resp[f.key]
		if !ok {
			t.Errorf("response missing required field %q", f.key)
			continue
		}
		switch f.wantType {
		case "array":
			if _, ok := val.([]interface{}); !ok {
				// nil decodes as nil, which is fine - JSON null for empty array
				if val != nil {
					t.Errorf("field %q: expected array, got %T", f.key, val)
				}
			}
		case "number":
			if _, ok := val.(float64); !ok {
				t.Errorf("field %q: expected number, got %T", f.key, val)
			}
		}
	}

	// Verify no unexpected extra top-level fields
	allowedKeys := map[string]bool{
		"virtual_keys": true,
		"total_count":  true,
		"count":        true,
		"limit":        true,
		"offset":       true,
	}
	for key := range resp {
		if !allowedKeys[key] {
			t.Errorf("unexpected field %q in response", key)
		}
	}
}

// TestGetVirtualKeys_PaginatedEndpoint_QueryParams verifies query parameters are
// parsed and reflected in the response.
func TestGetVirtualKeys_PaginatedEndpoint_QueryParams(t *testing.T) {
	SetLogger(&mockLogger{})

	h := &GovernanceHandler{
		configStore:       &mockConfigStoreForVK{},
		governanceManager: &mockGovernanceManagerForVK{},
	}

	tests := []struct {
		name       string
		uri        string
		wantLimit  float64
		wantOffset float64
	}{
		{
			name:       "explicit limit and offset",
			uri:        "/api/governance/virtual-keys?limit=10&offset=5",
			wantLimit:  10,
			wantOffset: 5,
		},
		{
			name:       "no params uses defaults",
			uri:        "/api/governance/virtual-keys",
			wantLimit:  0,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI(tt.uri)

			h.getVirtualKeys(ctx)

			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("expected status 200, got %d", ctx.Response.StatusCode())
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}

			if got := resp["limit"].(float64); got != tt.wantLimit {
				t.Errorf("limit: got %v, want %v", got, tt.wantLimit)
			}
			if got := resp["offset"].(float64); got != tt.wantOffset {
				t.Errorf("offset: got %v, want %v", got, tt.wantOffset)
			}
		})
	}
}

func TestGetVirtualKeys_TenantScopedRequestIgnoresFromMemory(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &tenantAwareMockConfigStoreForVK{}
	h := &GovernanceHandler{
		configStore:       store,
		governanceManager: &mockGovernanceManagerForVK{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/governance/virtual-keys?from_memory=true")
	ctx.SetUserValue(schemas.DeepIntShieldContextKeyTenantID, "alice@example.com")

	h.getVirtualKeys(ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected status 200, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
	if !store.virtualKeysCalled {
		t.Fatalf("expected tenant-scoped request to read virtual keys from database")
	}
}

func TestGetModelConfigs_FromMemorySupportsSearchAndPagination(t *testing.T) {
	SetLogger(&mockLogger{})

	h := &GovernanceHandler{
		configStore: &mockConfigStoreForVK{},
		governanceManager: &mockGovernanceManagerForModelConfigs{
			data: &governance.GovernanceData{
				ModelConfigs: []*configstoreTables.TableModelConfig{
					{ID: "mc-1", ModelName: "gpt-4o-mini"},
					{ID: "mc-2", ModelName: "gpt-5-mini"},
					{ID: "mc-3", ModelName: "claude-sonnet-4-5"},
				},
			},
		},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/governance/model-configs?from_memory=true&limit=1&offset=1&search=gpt")

	h.getModelConfigs(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}

	var resp struct {
		ModelConfigs []configstoreTables.TableModelConfig `json:"model_configs"`
		Count        int                                  `json:"count"`
		TotalCount   int                                  `json:"total_count"`
		Limit        int                                  `json:"limit"`
		Offset       int                                  `json:"offset"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.TotalCount != 2 {
		t.Fatalf("total_count = %d, want 2", resp.TotalCount)
	}
	if resp.Count != 1 {
		t.Fatalf("count = %d, want 1", resp.Count)
	}
	if resp.Limit != 1 || resp.Offset != 1 {
		t.Fatalf("limit/offset = %d/%d, want 1/1", resp.Limit, resp.Offset)
	}
	if len(resp.ModelConfigs) != 1 || resp.ModelConfigs[0].ModelName != "gpt-5-mini" {
		t.Fatalf("unexpected paginated model configs: %+v", resp.ModelConfigs)
	}
}

func TestGetProviderGovernance_FromMemoryReturnsLiveUsage(t *testing.T) {
	SetLogger(&mockLogger{})

	tokenMax := int64(1)
	requestMax := int64(10)
	h := &GovernanceHandler{
		governanceManager: &mockGovernanceManagerForProviders{
			data: &governance.GovernanceData{
				Providers: []*configstoreTables.TableProvider{
					{
						Name: "openai",
						RateLimit: &configstoreTables.TableRateLimit{
							ID:                  "rl-openai",
							TokenMaxLimit:       &tokenMax,
							TokenCurrentUsage:   1,
							RequestMaxLimit:     &requestMax,
							RequestCurrentUsage: 3,
						},
					},
				},
			},
		},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/governance/providers?from_memory=true")

	h.getProviderGovernance(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}

	var resp struct {
		Providers []ProviderGovernanceResponse `json:"providers"`
		Count     int                          `json:"count"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Count != 1 || len(resp.Providers) != 1 {
		t.Fatalf("unexpected provider count: %+v", resp)
	}
	if resp.Providers[0].Provider != "openai" {
		t.Fatalf("unexpected provider name: %+v", resp.Providers[0])
	}
	if resp.Providers[0].RateLimit == nil || resp.Providers[0].RateLimit.TokenCurrentUsage != 1 {
		t.Fatalf("expected live token usage from memory, got %+v", resp.Providers[0].RateLimit)
	}
}

// Ensure mockLogger satisfies schemas.Logger (already defined in middlewares_test.go
// but we reference it here - same package, so no redeclaration needed).
var _ schemas.Logger = (*mockLogger)(nil)

func TestBudgetRemovalRequestDetection(t *testing.T) {
	tests := []struct {
		name string
		req  *UpdateBudgetRequest
		want bool
	}{
		{
			name: "nil request is not removal",
			req:  nil,
			want: false,
		},
		{
			name: "empty object is removal",
			req:  &UpdateBudgetRequest{},
			want: true,
		},
		{
			name: "max limit present is not removal",
			req:  &UpdateBudgetRequest{MaxLimit: deepintshieldFloat(10)},
			want: false,
		},
		{
			name: "reset duration only is not removal",
			req:  &UpdateBudgetRequest{ResetDuration: deepintshieldString("1h")},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBudgetRemovalRequest(tt.req); got != tt.want {
				t.Fatalf("isBudgetRemovalRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateLimitRemovalRequestDetection(t *testing.T) {
	tests := []struct {
		name string
		req  *UpdateRateLimitRequest
		want bool
	}{
		{
			name: "nil request is not removal",
			req:  nil,
			want: false,
		},
		{
			name: "empty object is removal",
			req:  &UpdateRateLimitRequest{},
			want: true,
		},
		{
			name: "token limit present is not removal",
			req:  &UpdateRateLimitRequest{TokenMaxLimit: deepintshieldInt64(100)},
			want: false,
		},
		{
			name: "request limit present is not removal",
			req:  &UpdateRateLimitRequest{RequestMaxLimit: deepintshieldInt64(10)},
			want: false,
		},
		{
			name: "durations only is not removal",
			req: &UpdateRateLimitRequest{
				TokenResetDuration:   deepintshieldString("1h"),
				RequestResetDuration: deepintshieldString("1h"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRateLimitRemovalRequest(tt.req); got != tt.want {
				t.Fatalf("isRateLimitRemovalRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectProviderConfigDeleteIDs(t *testing.T) {
	budgetID := "budget-1"
	rateLimitID := "rate-limit-1"

	tests := []struct {
		name             string
		config           configstoreTables.TableVirtualKeyProviderConfig
		initialBudgetIDs []string
		initialRateIDs   []string
		wantBudgetIDs    []string
		wantRateIDs      []string
	}{
		{
			name: "collects both IDs",
			config: configstoreTables.TableVirtualKeyProviderConfig{
				BudgetID:    &budgetID,
				RateLimitID: &rateLimitID,
			},
			wantBudgetIDs: []string{budgetID},
			wantRateIDs:   []string{rateLimitID},
		},
		{
			name: "appends to existing slices",
			config: configstoreTables.TableVirtualKeyProviderConfig{
				BudgetID:    &budgetID,
				RateLimitID: &rateLimitID,
			},
			initialBudgetIDs: []string{"budget-0"},
			initialRateIDs:   []string{"rate-limit-0"},
			wantBudgetIDs:    []string{"budget-0", budgetID},
			wantRateIDs:      []string{"rate-limit-0", rateLimitID},
		},
		{
			name:   "ignores missing IDs",
			config: configstoreTables.TableVirtualKeyProviderConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBudgetIDs, gotRateIDs := collectProviderConfigDeleteIDs(tt.config, tt.initialBudgetIDs, tt.initialRateIDs)

			if len(gotBudgetIDs) != len(tt.wantBudgetIDs) {
				t.Fatalf("budget IDs length = %d, want %d", len(gotBudgetIDs), len(tt.wantBudgetIDs))
			}
			for i := range gotBudgetIDs {
				if gotBudgetIDs[i] != tt.wantBudgetIDs[i] {
					t.Fatalf("budget IDs[%d] = %q, want %q", i, gotBudgetIDs[i], tt.wantBudgetIDs[i])
				}
			}

			if len(gotRateIDs) != len(tt.wantRateIDs) {
				t.Fatalf("rate limit IDs length = %d, want %d", len(gotRateIDs), len(tt.wantRateIDs))
			}
			for i := range gotRateIDs {
				if gotRateIDs[i] != tt.wantRateIDs[i] {
					t.Fatalf("rate limit IDs[%d] = %q, want %q", i, gotRateIDs[i], tt.wantRateIDs[i])
				}
			}
		})
	}
}

func TestValidateGuardrailPolicyIDsAllowsEmptySelection(t *testing.T) {
	h := &GovernanceHandler{configStore: &mockGuardrailPolicyValidationStore{}}

	got, err := h.validateGuardrailPolicyIDs(context.Background(), nil)
	if err != nil {
		t.Fatalf("validateGuardrailPolicyIDs() unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateGuardrailPolicyIDs() length = %d, want 0", len(got))
	}
}

func TestValidateGuardrailPolicyIDsNormalizesExplicitSelections(t *testing.T) {
	h := &GovernanceHandler{
		configStore: &mockGuardrailPolicyValidationStore{
			policies: map[string]*configstoreTables.TableGuardrailPolicy{
				"policy-a": {ID: "policy-a"},
				"policy-b": {ID: "policy-b"},
			},
		},
	}

	got, err := h.validateGuardrailPolicyIDs(context.Background(), []string{" policy-a ", "policy-b", "policy-a"})
	if err != nil {
		t.Fatalf("validateGuardrailPolicyIDs() unexpected error: %v", err)
	}
	want := []string{"policy-a", "policy-b"}
	if len(got) != len(want) {
		t.Fatalf("validateGuardrailPolicyIDs() length = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("validateGuardrailPolicyIDs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCreateModelConfigRequiresUsageControls(t *testing.T) {
	SetLogger(&mockLogger{})

	store := &mockModelConfigValidationStore{}
	h := &GovernanceHandler{
		configStore:       store,
		governanceManager: &mockGovernanceManagerForVK{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/api/governance/model-configs")
	ctx.Request.SetBodyString(`{"model_name":"gpt-4o-mini"}`)

	h.createModelConfig(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
	if !strings.Contains(string(ctx.Response.Body()), modelConfigUsageControlsRequiredError) {
		t.Fatalf("expected response to mention usage controls requirement, got %s", string(ctx.Response.Body()))
	}
	if store.getByKeyCalled {
		t.Fatalf("expected duplicate lookup to be skipped for invalid create payload")
	}
	if store.transactionRun {
		t.Fatalf("expected transaction to be skipped for invalid create payload")
	}
}

func TestUpdateModelConfigRejectsRemovingLastUsageControl(t *testing.T) {
	SetLogger(&mockLogger{})

	budgetID := "budget-1"
	existing := &configstoreTables.TableModelConfig{
		ID:        "mc-1",
		ModelName: "gpt-4o-mini",
		BudgetID:  &budgetID,
	}
	store := &mockModelConfigValidationStore{
		modelConfigByID:  existing,
		modelConfigByKey: existing,
	}
	h := &GovernanceHandler{
		configStore:       store,
		governanceManager: &mockGovernanceManagerForVK{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.Request.SetRequestURI("/api/governance/model-configs/mc-1")
	ctx.Request.SetBodyString(`{"budget":{}}`)
	ctx.SetUserValue("mc_id", "mc-1")

	h.updateModelConfig(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
	if !strings.Contains(string(ctx.Response.Body()), modelConfigUsageControlsRequiredError) {
		t.Fatalf("expected response to mention usage controls requirement, got %s", string(ctx.Response.Body()))
	}
	if !store.getByIDCalled || !store.getByKeyCalled {
		t.Fatalf("expected existing model config lookups before validation")
	}
	if store.transactionRun {
		t.Fatalf("expected transaction to be skipped when last usage control is removed")
	}
}

func TestUpdateModelConfigRejectsDuplicateTarget(t *testing.T) {
	SetLogger(&mockLogger{})

	existing := &configstoreTables.TableModelConfig{
		ID:        "mc-1",
		ModelName: "gpt-4o-mini",
	}
	conflict := &configstoreTables.TableModelConfig{
		ID:        "mc-2",
		ModelName: "gpt-4o",
	}
	store := &mockModelConfigValidationStore{
		modelConfigByID:  existing,
		modelConfigByKey: conflict,
	}
	h := &GovernanceHandler{
		configStore:       store,
		governanceManager: &mockGovernanceManagerForVK{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.Request.SetRequestURI("/api/governance/model-configs/mc-1")
	ctx.Request.SetBodyString(`{"model_name":"gpt-4o"}`)
	ctx.SetUserValue("mc_id", "mc-1")

	h.updateModelConfig(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusConflict {
		t.Fatalf("expected status 409, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
	if !strings.Contains(string(ctx.Response.Body()), "already exists") {
		t.Fatalf("expected duplicate conflict message, got %s", string(ctx.Response.Body()))
	}
	if store.transactionRun {
		t.Fatalf("expected transaction to be skipped for duplicate target")
	}
}

func TestUpdateModelConfigReturns400ForInvalidRateLimitPayload(t *testing.T) {
	SetLogger(&mockLogger{})

	existing := &configstoreTables.TableModelConfig{
		ID:        "mc-1",
		ModelName: "gpt-4o-mini",
	}
	store := &mockModelConfigValidationStore{
		modelConfigByID:  existing,
		modelConfigByKey: existing,
	}
	h := &GovernanceHandler{
		configStore:       store,
		governanceManager: &mockGovernanceManagerForVK{},
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.Request.SetRequestURI("/api/governance/model-configs/mc-1")
	ctx.Request.SetBodyString(`{"rate_limit":{"token_max_limit":100}}`)
	ctx.SetUserValue("mc_id", "mc-1")

	h.updateModelConfig(ctx)

	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}
	if !strings.Contains(string(ctx.Response.Body()), "rate limit token reset duration is required") {
		t.Fatalf("expected validation error for missing token reset duration, got %s", string(ctx.Response.Body()))
	}
	if store.transactionRun {
		t.Fatalf("expected transaction to be skipped for invalid rate limit payload")
	}
}

func deepintshieldFloat(v float64) *float64 {
	return &v
}

func deepintshieldInt64(v int64) *int64 {
	return &v
}

func deepintshieldString(v string) *string {
	return &v
}
