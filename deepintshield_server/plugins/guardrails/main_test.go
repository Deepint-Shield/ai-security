package guardrails

import (
	"context"
	"strings"
	"testing"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

func TestShouldEvaluateLLMGuardrails(t *testing.T) {
	t.Run("allows text generation request types", func(t *testing.T) {
		requestTypes := []schemas.RequestType{
			schemas.TextCompletionRequest,
			schemas.TextCompletionStreamRequest,
			schemas.ChatCompletionRequest,
			schemas.ChatCompletionStreamRequest,
			schemas.ResponsesRequest,
			schemas.ResponsesStreamRequest,
			schemas.PassthroughRequest,
			schemas.PassthroughStreamRequest,
		}

		for _, requestType := range requestTypes {
			if !shouldEvaluateLLMGuardrails(requestType) {
				t.Fatalf("expected %s to be evaluated", requestType)
			}
		}
	})

	t.Run("skips non generation request types", func(t *testing.T) {
		requestTypes := []schemas.RequestType{
			schemas.ListModelsRequest,
			schemas.EmbeddingRequest,
			schemas.FileListRequest,
			schemas.SpeechRequest,
		}

		for _, requestType := range requestTypes {
			if shouldEvaluateLLMGuardrails(requestType) {
				t.Fatalf("expected %s to be skipped", requestType)
			}
		}
	})

	t.Run("gates in multimodal request types only when flag enabled", func(t *testing.T) {
		multimodal := []schemas.RequestType{
			schemas.ImageGenerationRequest,
			schemas.ImageGenerationStreamRequest,
			schemas.ImageEditRequest,
			schemas.ImageEditStreamRequest,
			schemas.ImageVariationRequest,
			schemas.SpeechRequest,
			schemas.SpeechStreamRequest,
			schemas.TranscriptionRequest,
			schemas.TranscriptionStreamRequest,
			schemas.EmbeddingRequest,
			schemas.RerankRequest,
			schemas.VideoGenerationRequest,
			schemas.VideoRemixRequest,
		}

		// Default (flag off): all skipped - byte-for-byte legacy behavior.
		for _, rt := range multimodal {
			if shouldEvaluateLLMGuardrails(rt) {
				t.Fatalf("expected %s to be skipped when multimodal flag is off", rt)
			}
		}

		// Flag on: all evaluated.
		prev := guardrailsMultimodalEnabled
		guardrailsMultimodalEnabled = true
		defer func() { guardrailsMultimodalEnabled = prev }()
		for _, rt := range multimodal {
			if !shouldEvaluateLLMGuardrails(rt) {
				t.Fatalf("expected %s to be evaluated when multimodal flag is on", rt)
			}
		}
	})
}

func TestExtractRequestInputMultimodal(t *testing.T) {
	negative := "no blood"
	cases := []struct {
		name string
		req  *schemas.DeepIntShieldRequest
		want string
	}{
		{
			name: "image generation prompt and negative prompt",
			req: &schemas.DeepIntShieldRequest{
				ImageGenerationRequest: &schemas.DeepIntShieldImageGenerationRequest{
					Input:  &schemas.ImageGenerationInput{Prompt: "a calm beach"},
					Params: &schemas.ImageGenerationParameters{NegativePrompt: &negative},
				},
			},
			want: "a calm beach\nno blood",
		},
		{
			name: "speech input and instructions",
			req: &schemas.DeepIntShieldRequest{
				SpeechRequest: &schemas.DeepIntShieldSpeechRequest{
					Input:  &schemas.SpeechInput{Input: "hello world"},
					Params: &schemas.SpeechParameters{Instructions: "speak slowly"},
				},
			},
			want: "hello world\nspeak slowly",
		},
		{
			name: "embedding texts joined",
			req: &schemas.DeepIntShieldRequest{
				EmbeddingRequest: &schemas.DeepIntShieldEmbeddingRequest{
					Input: &schemas.EmbeddingInput{Texts: []string{"alpha", "beta"}},
				},
			},
			want: "alpha\nbeta",
		},
		{
			name: "rerank query and documents",
			req: &schemas.DeepIntShieldRequest{
				RerankRequest: &schemas.DeepIntShieldRerankRequest{
					Query:     "best laptop",
					Documents: []schemas.RerankDocument{{Text: "doc one"}, {Text: "doc two"}},
				},
			},
			want: "best laptop\ndoc one\ndoc two",
		},
		{
			name: "video prompt",
			req: &schemas.DeepIntShieldRequest{
				VideoGenerationRequest: &schemas.DeepIntShieldVideoGenerationRequest{
					Input: &schemas.VideoGenerationInput{Prompt: "a flying car"},
				},
			},
			want: "a flying car",
		},
		{
			// Regression for the json.Marshal-default binary leak: a VideoRemix
			// with a base64 reference image must yield ONLY the prompt, never the
			// base64 blob.
			name: "video remix prompt only (no base64 reference leak)",
			req: &schemas.DeepIntShieldRequest{
				VideoRemixRequest: &schemas.DeepIntShieldVideoRemixRequest{
					Input: &schemas.VideoGenerationInput{
						Prompt:         "make it night",
						InputReference: strPtr("data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="),
					},
				},
			},
			want: "make it night",
		},
		{
			name: "transcription has no request-side text",
			req: &schemas.DeepIntShieldRequest{
				TranscriptionRequest: &schemas.DeepIntShieldTranscriptionRequest{},
			},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractRequestInput(tc.req)
			if got != tc.want {
				t.Fatalf("extractRequestInput = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "base64") || strings.Contains(got, "RequestType") {
				t.Fatalf("extractRequestInput leaked envelope/binary into guard input: %q", got)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

func TestExtractRequestInputImageVariationNoBinaryLeak(t *testing.T) {
	// ImageVariation has no prompt - only a source image. Binary bytes that are
	// not valid UTF-8 text must NOT be emitted (and never json.Marshal'd).
	req := &schemas.DeepIntShieldRequest{
		ImageVariationRequest: &schemas.DeepIntShieldImageVariationRequest{
			Input: &schemas.ImageVariationInput{Image: schemas.ImageInput{Image: []byte{0x89, 'P', 'N', 'G', 0x0, 0x1, 0xff}}},
		},
	}
	got := extractRequestInput(req)
	if strings.Contains(got, "RequestType") || strings.ContainsRune(got, 0xff) {
		t.Fatalf("image variation leaked binary/envelope into guard input: %q", got)
	}
}

func TestExtractRequestAttachments(t *testing.T) {
	editReq := &schemas.DeepIntShieldRequest{
		ImageEditRequest: &schemas.DeepIntShieldImageEditRequest{
			Input: &schemas.ImageEditInput{
				Prompt: "make it brighter",
				Images: []schemas.ImageInput{{Image: []byte("PNGDATA-1")}, {Image: []byte("PNGDATA-2")}},
			},
		},
	}

	// Flag off → no attachments (zero overhead, common case).
	if got := extractRequestAttachments(editReq); got != nil {
		t.Fatalf("expected nil attachments when multimodal flag off, got %d", len(got))
	}

	prev := guardrailsMultimodalEnabled
	guardrailsMultimodalEnabled = true
	defer func() { guardrailsMultimodalEnabled = prev }()

	atts := extractRequestAttachments(editReq)
	if len(atts) != 2 {
		t.Fatalf("expected 2 image attachments, got %d", len(atts))
	}
	for _, a := range atts {
		if a.Kind != runtimeapi.AttachmentKindImage || a.Role != runtimeapi.AttachmentRoleInput {
			t.Fatalf("unexpected attachment kind/role: %+v", a)
		}
		if a.Hash == "" {
			t.Fatalf("attachment must be content-hashed for dedup")
		}
		// Inline bytes default OFF → only metadata + hash forwarded.
		if len(a.Data) != 0 {
			t.Fatalf("raw bytes must not be inlined unless GUARDRAILS_MODALITY_INLINE_BYTES is set")
		}
	}

	// Transcription audio is forwarded as an audio attachment.
	transReq := &schemas.DeepIntShieldRequest{
		TranscriptionRequest: &schemas.DeepIntShieldTranscriptionRequest{
			Input: &schemas.TranscriptionInput{File: []byte("AUDIOBYTES")},
		},
	}
	tatts := extractRequestAttachments(transReq)
	if len(tatts) != 1 || tatts[0].Kind != runtimeapi.AttachmentKindAudio {
		t.Fatalf("expected 1 audio attachment, got %+v", tatts)
	}
}

func TestExtractResponseAttachments(t *testing.T) {
	// 1x1 transparent PNG, base64.
	const pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

	imgResp := &schemas.DeepIntShieldResponse{
		ImageGenerationResponse: &schemas.DeepIntShieldImageGenerationResponse{
			Data: []schemas.ImageData{
				{B64JSON: pngB64, RevisedPrompt: "a serene mountain lake"},
				{URL: "https://cdn.example.com/img/2.png"},
			},
		},
	}

	// Flag off → nil (zero overhead).
	if got := extractResponseAttachments(imgResp); got != nil {
		t.Fatalf("expected nil response attachments when flag off, got %d", len(got))
	}

	prev := guardrailsMultimodalEnabled
	guardrailsMultimodalEnabled = true
	defer func() { guardrailsMultimodalEnabled = prev }()

	atts := extractResponseAttachments(imgResp)
	if len(atts) != 2 {
		t.Fatalf("expected 2 image output attachments, got %d", len(atts))
	}
	if atts[0].Role != runtimeapi.AttachmentRoleOutput || atts[0].Kind != runtimeapi.AttachmentKindImage {
		t.Fatalf("unexpected output attachment 0: %+v", atts[0])
	}
	if atts[0].Hash == "" {
		t.Fatalf("base64 image must be decoded and hashed, got %+v", atts[0])
	}
	if atts[1].Ref != "https://cdn.example.com/img/2.png" {
		t.Fatalf("URL-only image must be forwarded by reference, got %+v", atts[1])
	}

	// Revised prompt text is guarded on the output side.
	if got := extractResponseOutput(imgResp); got != "a serene mountain lake" {
		t.Fatalf("expected revised prompt as output text, got %q", got)
	}

	// Speech audio → audio output attachment.
	speechResp := &schemas.DeepIntShieldResponse{
		SpeechResponse: &schemas.DeepIntShieldSpeechResponse{Audio: []byte("RIFFfakeaudio")},
	}
	satts := extractResponseAttachments(speechResp)
	if len(satts) != 1 || satts[0].Kind != runtimeapi.AttachmentKindAudio || satts[0].Role != runtimeapi.AttachmentRoleOutput {
		t.Fatalf("expected 1 audio output attachment, got %+v", satts)
	}
}

func TestExtractResponseOutputMultimodal(t *testing.T) {
	// Transcript text is guarded.
	transcript := &schemas.DeepIntShieldResponse{
		TranscriptionResponse: &schemas.DeepIntShieldTranscriptionResponse{Text: "spoken words"},
	}
	if got := extractResponseOutput(transcript); got != "spoken words" {
		t.Fatalf("transcription output = %q, want %q", got, "spoken words")
	}

	// Binary / vector responses must never serialize their payload into the
	// guard input - they return empty, not a json.Marshal dump.
	binaryResponses := []*schemas.DeepIntShieldResponse{
		{ImageGenerationResponse: &schemas.DeepIntShieldImageGenerationResponse{}},
		{SpeechResponse: &schemas.DeepIntShieldSpeechResponse{Audio: []byte{0x1, 0x2, 0x3}}},
		{VideoGenerationResponse: &schemas.DeepIntShieldVideoGenerationResponse{}},
		{EmbeddingResponse: &schemas.DeepIntShieldEmbeddingResponse{}},
		{RerankResponse: &schemas.DeepIntShieldRerankResponse{}},
	}
	for _, resp := range binaryResponses {
		if got := extractResponseOutput(resp); got != "" {
			t.Fatalf("expected empty guard text for binary response, got %q", got)
		}
	}
}

func TestPreLLMHookSkipsListModelsRequests(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	req := &schemas.DeepIntShieldRequest{
		RequestType: schemas.ListModelsRequest,
		ListModelsRequest: &schemas.DeepIntShieldListModelsRequest{
			Provider: schemas.OpenAI,
		},
	}

	gotReq, shortCircuit, err := (&Plugin{}).PreLLMHook(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if shortCircuit != nil {
		t.Fatalf("expected request to bypass guardrails, got short circuit: %#v", shortCircuit)
	}
	if gotReq != req {
		t.Fatalf("expected original request pointer to be returned")
	}
}

func TestPostLLMHookSkipsListModelsResponses(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	resp := &schemas.DeepIntShieldResponse{
		ListModelsResponse: &schemas.DeepIntShieldListModelsResponse{
			ExtraFields: schemas.DeepIntShieldResponseExtraFields{
				RequestType: schemas.ListModelsRequest,
				Provider:    schemas.OpenAI,
			},
		},
	}

	gotResp, gotErr, err := (&Plugin{}).PostLLMHook(ctx, resp, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gotErr != nil {
		t.Fatalf("expected no deepintshield error, got %#v", gotErr)
	}
	if gotResp != resp {
		t.Fatalf("expected original response pointer to be returned")
	}
}

func TestAttachRuntimePoliciesAddsRequestedVirtualKeyPolicies(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs, []string{"policy-a", "policy-b", "policy-a", ""})

	policies, metadata := (&Plugin{}).attachRuntimePolicies(ctx, runtimeapi.StageInput, map[string]any{"request_type": schemas.ChatCompletionRequest})
	if len(policies) != 0 {
		t.Fatalf("expected no inline policies, got %d", len(policies))
	}
	requestedPolicyIDs, ok := metadata["requested_policy_ids"].([]string)
	if !ok {
		t.Fatalf("expected requested_policy_ids metadata, got %#v", metadata["requested_policy_ids"])
	}
	if len(requestedPolicyIDs) != 2 || requestedPolicyIDs[0] != "policy-a" || requestedPolicyIDs[1] != "policy-b" {
		t.Fatalf("expected normalized requested policy ids, got %#v", requestedPolicyIDs)
	}
	if metadata["merge_tenant_policies"] != true {
		t.Fatalf("expected merge_tenant_policies=true, got %#v", metadata["merge_tenant_policies"])
	}
}

// A VK that has NO explicitly-attached guardrails must NOT skip tenant
// guardrails: the deterministic DEFAULT (IsDefault) baseline policy still has
// to apply so an out-of-the-box VK is protected on every inference path. Only
// VKs that opted into their own guardrails skip the tenant default.
func TestAttachRuntimePoliciesAppliesDefaultForUnassignedVirtualKey(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID, "vk-1")
	// No __bf_vk_has_guards stamped → unassigned VK.

	policies, metadata := (&Plugin{}).attachRuntimePolicies(ctx, runtimeapi.StageInput, map[string]any{"request_type": schemas.ChatCompletionRequest})
	if len(policies) != 0 {
		t.Fatalf("expected no inline policies, got %d", len(policies))
	}
	if _, ok := metadata["skip_tenant_guardrails"]; ok {
		t.Fatalf("expected skip_tenant_guardrails to be unset for an unassigned VK so the default baseline applies, got %#v", metadata["skip_tenant_guardrails"])
	}
	if _, ok := metadata["requested_policy_ids"]; ok {
		t.Fatalf("did not expect requested policy ids, got %#v", metadata["requested_policy_ids"])
	}
}

// A VK that DOES have attached guardrails owns the complete policy set: the
// tenant default must be skipped so the VK doesn't silently inherit unrelated
// tenant policies.
func TestAttachRuntimePoliciesSkipsTenantHydrationForAssignedVirtualKey(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID, "vk-1")
	ctx.SetValue(schemas.DeepIntShieldContextKey("__bf_vk_has_guards"), true)

	policies, metadata := (&Plugin{}).attachRuntimePolicies(ctx, runtimeapi.StageInput, map[string]any{"request_type": schemas.ChatCompletionRequest})
	if len(policies) != 0 {
		t.Fatalf("expected no inline policies, got %d", len(policies))
	}
	if metadata["skip_tenant_guardrails"] != true {
		t.Fatalf("expected skip_tenant_guardrails=true, got %#v", metadata["skip_tenant_guardrails"])
	}
	if _, ok := metadata["requested_policy_ids"]; ok {
		t.Fatalf("did not expect requested policy ids, got %#v", metadata["requested_policy_ids"])
	}
}

func TestAttachRuntimePoliciesReplaceModeKeepsInlinePoliciesOnly(t *testing.T) {
	ctx := schemas.NewDeepIntShieldContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.DeepIntShieldContextKeyGovernanceGuardrailPolicyIDs, []string{"policy-a"})
	ctx.SetValue(schemas.DeepIntShieldContextKeyRequestHeaders, map[string]string{
		"x-bf-guardrails-mode":  "replace",
		"x-bf-input-guardrails": `[{"name":"regex_match","enabled":true,"config":{"rule":"forbidden","summary":"blocked"},"action":{"on_fail":"deny"}}]`,
	})

	policies, metadata := (&Plugin{}).attachRuntimePolicies(ctx, runtimeapi.StageInput, nil)
	if len(policies) != 1 {
		t.Fatalf("expected 1 inline policy, got %d", len(policies))
	}
	if _, ok := metadata["requested_policy_ids"]; ok {
		t.Fatalf("did not expect requested policy ids in replace mode, got %#v", metadata["requested_policy_ids"])
	}
	if _, ok := metadata["merge_tenant_policies"]; ok {
		t.Fatalf("did not expect merge_tenant_policies in replace mode, got %#v", metadata["merge_tenant_policies"])
	}
}

func TestRuntimePolicyMetadataPreservesExplicitMetadataWithoutDefaultFlags(t *testing.T) {
	metadata := runtimePolicyMetadata(tables.TableGuardrailPolicy{
		ID:       "policy-1",
		Name:     "Active Policy",
		Scope:    runtimeapi.StageInput,
		Enabled:  true,
		Metadata: map[string]any{"priority": 10},
	})
	if metadata == nil || metadata["priority"] != 10 {
		t.Fatalf("expected explicit metadata to be preserved, got %#v", metadata)
	}
	if _, ok := metadata["assignment_only"]; ok {
		t.Fatalf("did not expect assignment_only metadata in the active-policy model, got %#v", metadata)
	}
	if _, ok := metadata["is_default"]; ok {
		t.Fatalf("did not expect is_default metadata in the active-policy model, got %#v", metadata)
	}
}
