package engine

import (
	"context"
	"fmt"
	regexp "github.com/grafana/regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deepint-shield/ai-security-guard/pkg/runtimeapi"
)

type ragChunkInput struct {
	ChunkID         string
	DocumentID      string
	DocumentVersion string
	Content         string
	OffsetStart     int
	OffsetEnd       int
	ACLTags         []string
	Labels          []string
	TrustScore      int
	InjectionScore  int
	PIIFlags        []string
	SourceID        string
	SourceName      string
	SourceHealth    string
	Quarantined     bool
}

type ragChunkOutcome struct {
	ChunkID          string   `json:"chunk_id"`
	DocumentID       string   `json:"document_id,omitempty"`
	DocumentVersion  string   `json:"document_version,omitempty"`
	ContentPreview   string   `json:"content_preview,omitempty"`
	OffsetStart      int      `json:"offset_start,omitempty"`
	OffsetEnd        int      `json:"offset_end,omitempty"`
	TrustScore       int      `json:"trust_score,omitempty"`
	InjectionScore   int      `json:"injection_score,omitempty"`
	PIIFlags         []string `json:"pii_flags,omitempty"`
	SourceID         string   `json:"source_id,omitempty"`
	SourceName       string   `json:"source_name,omitempty"`
	SourceHealth     string   `json:"source_health,omitempty"`
	Quarantined      bool     `json:"quarantined,omitempty"`
	Decision         string   `json:"decision"`
	Reason           string   `json:"reason,omitempty"`
	PolicyHits       []string `json:"policy_hits,omitempty"`
	SanitizedContent string   `json:"sanitized_content,omitempty"`
	CitationRequired bool     `json:"citation_required,omitempty"`
}

type ragChunkEval struct {
	outcomes         []ragChunkOutcome
	findings         []runtimeapi.Finding
	redactions       []string
	decisionChain    []string
	quarantineSource map[string]bool
}

type ragPolicyDirectives struct {
	minTrustScore     int
	maxInjectionScore int
	blockOnPII        bool
	citationRequired  bool
	requireApproval   bool
	shadowMode        bool
	allowedRoles      []string
	allowedApps       []string
	trustedSourceIDs  []string
	blockedPatterns   []string
}

// defaultMaxRAGChunkParallelism is the fallback when Runtime.ragChunkParallelism
// is not set. Prefer configuring via RuntimeConfig.RAGChunkParallelism or the
// DEEPINTSHIELD_GUARD_RAG_CHUNK_PARALLELISM env var.
const defaultMaxRAGChunkParallelism = 8

func (r *Runtime) evaluateRAG(ctx context.Context, start time.Time, bundle runtimeapi.TenantBundle, hasBundle bool, policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest, response runtimeapi.EvaluateResponse) runtimeapi.EvaluateResponse {
	compiledPolicies := r.compileRuntimePolicies(policies, runtimeapi.StageRAG)

	portkeyFindings, portkeyRedactions, portkeySanitizedInput, portkeySanitizedOutput, portkeyChain := evaluateRuntimeCheckPolicies(ctx, r.adapterTimeout, compiledPolicies, request)
	response.Findings = append(response.Findings, portkeyFindings...)
	response.Redactions = append(response.Redactions, portkeyRedactions...)
	response.DecisionChain = append(response.DecisionChain, portkeyChain...)

	sanitizedRequest := request
	if strings.TrimSpace(portkeySanitizedInput) != "" && portkeySanitizedInput != request.Content.Input {
		sanitizedRequest.Content.Input = portkeySanitizedInput
	}
	if strings.TrimSpace(portkeySanitizedOutput) != "" && portkeySanitizedOutput != request.Content.Output {
		sanitizedRequest.Content.Output = portkeySanitizedOutput
	}

	localFindings, localRedactions, localSanitizedInput, localSanitizedOutput, localChain := r.evaluateLocalPolicies(compiledPolicies, sanitizedRequest)
	response.Findings = append(response.Findings, localFindings...)
	response.Redactions = append(response.Redactions, localRedactions...)
	response.DecisionChain = append(response.DecisionChain, localChain...)

	if localSanitizedInput != sanitizedRequest.Content.Input {
		response.SanitizedInput = localSanitizedInput
		sanitizedRequest.Content.Input = localSanitizedInput
	} else if portkeySanitizedInput != request.Content.Input && strings.TrimSpace(portkeySanitizedInput) != "" {
		response.SanitizedInput = portkeySanitizedInput
	}
	if localSanitizedOutput != sanitizedRequest.Content.Output {
		response.SanitizedOutput = localSanitizedOutput
		sanitizedRequest.Content.Output = localSanitizedOutput
	} else if portkeySanitizedOutput != request.Content.Output && strings.TrimSpace(portkeySanitizedOutput) != "" {
		response.SanitizedOutput = portkeySanitizedOutput
	}

	// Run provider evaluation concurrently with chunk extraction + evaluation.
	// Provider bindings make outbound HTTP calls and are independent of chunk
	// processing, so overlapping them hides the provider network latency.
	var providerFindings []runtimeapi.Finding
	var providerChain []string
	var chunkEval ragChunkEval
	var ragWg sync.WaitGroup
	if hasBundle {
		ragWg.Add(1)
		go func() {
			defer ragWg.Done()
			providerFindings, providerChain = r.evaluateProviderBindings(ctx, bundle, compiledPolicies, sanitizedRequest)
		}()
	}
	ragWg.Add(1)
	go func() {
		defer ragWg.Done()
		chunks := extractRAGChunks(bundle, sanitizedRequest)
		chunkEval = r.evaluateRAGChunks(ctx, bundle, hasBundle, compiledPolicies, sanitizedRequest, chunks)
	}()
	ragWg.Wait()

	if hasBundle {
		response.Findings = append(response.Findings, providerFindings...)
		response.DecisionChain = append(response.DecisionChain, providerChain...)
	}
	citations := ragCitations(chunkEval.outcomes)
	response.Findings = append(response.Findings, chunkEval.findings...)
	response.Redactions = append(response.Redactions, chunkEval.redactions...)
	response.DecisionChain = append(response.DecisionChain, chunkEval.decisionChain...)

	response.Metadata = map[string]any{
		"rag": map[string]any{
			"query":                strings.TrimSpace(sanitizedRequest.Content.Input),
			"app_name":             metadataString(sanitizedRequest.Metadata, "app_name", "app", "application"),
			"agent_name":           metadataString(sanitizedRequest.Metadata, "agent_name", "agent"),
			"source_id":            metadataString(sanitizedRequest.Metadata, "source_id"),
			"source_name":          metadataString(sanitizedRequest.Metadata, "source_name"),
			"retrieved_chunks":     ragOutcomesToAny(chunkEval.outcomes),
			"rejected_chunks":      ragOutcomesToAny(filterRAGOutcomes(chunkEval.outcomes, "reject", "quarantine")),
			"allowed_chunks":       ragOutcomesToAny(filterRAGOutcomes(chunkEval.outcomes, "allow", "redact")),
			"redacted_chunks":      ragOutcomesToAny(filterRAGOutcomes(chunkEval.outcomes, "redact")),
			"quarantine_sources":   mapKeysSorted(chunkEval.quarantineSource),
			"policy_hits":          collectRAGPolicyHits(response.Findings),
			"citation_required":    anyRAGCitationRequired(chunkEval.outcomes),
			"citations":            citations,
			"requester":            sanitizedRequest.Actor.ID,
			"requester_role":       sanitizedRequest.Actor.Role,
			"runtime_evaluated_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	response.Decision, response.ApprovalRequired, response.Reason = resolveRAGDecision(response.Findings, response.Redactions, chunkEval.outcomes)
	response.LatencyMs = int(time.Since(start).Milliseconds())
	if response.LatencyMs == 0 && (len(response.Findings) > 0 || len(chunkEval.outcomes) > 0 || strings.TrimSpace(request.Content.Input) != "") {
		response.LatencyMs = 1
	}
	return response
}

func (r *Runtime) evaluateRAGChunks(ctx context.Context, bundle runtimeapi.TenantBundle, hasBundle bool, policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest, chunks []ragChunkInput) ragChunkEval {
	result := ragChunkEval{
		outcomes:         make([]ragChunkOutcome, 0, len(chunks)),
		findings:         make([]runtimeapi.Finding, 0, len(chunks)*2),
		redactions:       make([]string, 0, len(chunks)),
		decisionChain:    make([]string, 0, len(chunks)),
		quarantineSource: make(map[string]bool),
	}
	if len(chunks) == 0 {
		return result
	}
	maxParallel := r.ragChunkParallelism
	if maxParallel <= 0 {
		maxParallel = defaultMaxRAGChunkParallelism
	}
	parallelism := len(chunks)
	if parallelism > maxParallel {
		parallelism = maxParallel
	}
	if parallelism < 1 {
		parallelism = 1
	}
	evaluations := make([]ragChunkEval, len(chunks))
	shadowMode := collectRAGChunkDirectives(policies).shadowMode
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for i, chunk := range chunks {
		wg.Add(1)
		go func(index int, chunk ragChunkInput) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			evaluations[index] = r.evaluateRAGChunk(ctx, bundle, hasBundle, policies, request, chunk, shadowMode)
		}(i, chunk)
	}
	wg.Wait()
	for _, evaluation := range evaluations {
		result.outcomes = append(result.outcomes, evaluation.outcomes...)
		result.findings = append(result.findings, evaluation.findings...)
		result.redactions = append(result.redactions, evaluation.redactions...)
		result.decisionChain = append(result.decisionChain, evaluation.decisionChain...)
		for sourceID := range evaluation.quarantineSource {
			result.quarantineSource[sourceID] = true
		}
	}
	return result
}

func (r *Runtime) evaluateRAGChunk(ctx context.Context, bundle runtimeapi.TenantBundle, hasBundle bool, policies []runtimeapi.PolicyBundle, request runtimeapi.EvaluateRequest, chunk ragChunkInput, shadowMode bool) ragChunkEval {
	result := ragChunkEval{
		outcomes:         make([]ragChunkOutcome, 0, 1),
		findings:         make([]runtimeapi.Finding, 0, 8),
		redactions:       make([]string, 0, 2),
		decisionChain:    make([]string, 0, len(policies)+3),
		quarantineSource: make(map[string]bool),
	}
	chunkRequest := request
	chunkRequest.Content = runtimeapi.Content{Input: chunk.Content}
	chunkRequest.Metadata = cloneMap(request.Metadata)
	if chunkRequest.Metadata == nil {
		chunkRequest.Metadata = map[string]any{}
	}
	chunkRequest.Metadata["rag_chunk"] = map[string]any{
		"chunk_id":         chunk.ChunkID,
		"document_id":      chunk.DocumentID,
		"document_version": chunk.DocumentVersion,
		"offset_start":     chunk.OffsetStart,
		"offset_end":       chunk.OffsetEnd,
		"acl_tags":         append([]string(nil), chunk.ACLTags...),
		"labels":           append([]string(nil), chunk.Labels...),
		"trust_score":      chunk.TrustScore,
		"injection_score":  chunk.InjectionScore,
		"pii_flags":        append([]string(nil), chunk.PIIFlags...),
		"source_id":        chunk.SourceID,
		"source_name":      chunk.SourceName,
		"source_health":    chunk.SourceHealth,
		"quarantined":      chunk.Quarantined,
	}

	policyHits := make(stringSet)
	chunkOutcome := ragChunkOutcome{
		ChunkID:         chunk.ChunkID,
		DocumentID:      chunk.DocumentID,
		DocumentVersion: chunk.DocumentVersion,
		ContentPreview:  compactRAGContent(chunk.Content, 180),
		OffsetStart:     chunk.OffsetStart,
		OffsetEnd:       chunk.OffsetEnd,
		TrustScore:      chunk.TrustScore,
		InjectionScore:  chunk.InjectionScore,
		PIIFlags:        append([]string(nil), chunk.PIIFlags...),
		SourceID:        chunk.SourceID,
		SourceName:      chunk.SourceName,
		SourceHealth:    chunk.SourceHealth,
		Quarantined:     chunk.Quarantined,
		Decision:        "allow",
	}

	for _, policy := range policies {
		directives := ragDirectives(policy)
		if !ragPolicyAppliesToRequest(directives, chunkRequest) {
			if directives.requireApproval {
				finding := runtimeapi.Finding{
					PolicyID:        policy.PolicyID,
					PolicyVersionID: policy.PolicyVersionID,
					Category:        "rag_access_scope",
					Severity:        normalizeSeverity(defaultString("", "high")),
					Confidence:      0.92,
					Outcome:         normalizeOutcomeForPolicy(policy, "deny"),
					Summary:         fmt.Sprintf("RAG access is blocked for actor role %s or app %s", defaultString(chunkRequest.Actor.Role, "unknown"), defaultString(metadataString(chunkRequest.Metadata, "app_name", "app", "application"), "unknown")),
					Details: buildRAGFindingDetails(chunk, map[string]any{
						"request_level": true,
						"allowed_roles": directives.allowedRoles,
						"allowed_apps":  directives.allowedApps,
					}),
				}
				result.findings = append(result.findings, finding)
				result.decisionChain = append(result.decisionChain, fmt.Sprintf("%s blocked a restricted RAG request", policy.Name))
			}
			continue
		}
		policyHits.add(policy.Name)
		if directives.requireApproval {
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "rag_restricted_access",
				Severity:        "high",
				Confidence:      0.92,
				Outcome:         normalizeOutcomeForPolicy(policy, "deny"),
				Summary:         "RAG policy blocks retrieved content that was previously marked as approval-only",
				Details:         buildRAGFindingDetails(chunk, map[string]any{"request_level": true}),
			}
			result.findings = append(result.findings, finding)
		}
		if chunk.Quarantined {
			if chunk.SourceID != "" {
				result.quarantineSource[chunk.SourceID] = true
			}
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "source_quarantine",
				Severity:        "critical",
				Confidence:      0.97,
				Outcome:         "allow",
				Summary:         fmt.Sprintf("Retrieved source %s is quarantined", defaultString(chunk.SourceName, chunk.SourceID)),
				Details:         buildRAGFindingDetails(chunk, map[string]any{"chunk_decision_only": true, "chunk_decision": "quarantine"}),
			}
			result.findings = append(result.findings, finding)
			chunkOutcome.Decision = "quarantine"
			chunkOutcome.Reason = finding.Summary
		}
		if len(directives.trustedSourceIDs) > 0 && chunk.SourceID != "" && !containsNormalizedValue(directives.trustedSourceIDs, chunk.SourceID) {
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "trusted_source_miss",
				Severity:        "high",
				Confidence:      0.94,
				Outcome:         "allow",
				Summary:         fmt.Sprintf("Retrieved source %s is outside the trusted source inventory", defaultString(chunk.SourceName, chunk.SourceID)),
				Details:         buildRAGFindingDetails(chunk, map[string]any{"chunk_decision_only": true, "chunk_decision": "reject", "trusted_source_ids": directives.trustedSourceIDs}),
			}
			result.findings = append(result.findings, finding)
			if chunkOutcome.Decision == "allow" {
				chunkOutcome.Decision = "reject"
				chunkOutcome.Reason = finding.Summary
			}
		}
		if directives.minTrustScore > 0 && chunk.TrustScore > 0 && chunk.TrustScore < directives.minTrustScore {
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "source_trust",
				Severity:        "high",
				Confidence:      0.9,
				Outcome:         "allow",
				Summary:         fmt.Sprintf("Retrieved chunk trust score %d is below the required threshold %d", chunk.TrustScore, directives.minTrustScore),
				Details:         buildRAGFindingDetails(chunk, map[string]any{"chunk_decision_only": true, "chunk_decision": "reject", "min_trust_score": directives.minTrustScore}),
			}
			result.findings = append(result.findings, finding)
			if chunkOutcome.Decision == "allow" {
				chunkOutcome.Decision = "reject"
				chunkOutcome.Reason = finding.Summary
			}
		}
		if directives.maxInjectionScore > 0 && chunk.InjectionScore > directives.maxInjectionScore {
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "rag_injection_score",
				Severity:        "critical",
				Confidence:      0.95,
				Outcome:         "allow",
				Summary:         fmt.Sprintf("Retrieved chunk injection score %d exceeds the configured maximum %d", chunk.InjectionScore, directives.maxInjectionScore),
				Details:         buildRAGFindingDetails(chunk, map[string]any{"chunk_decision_only": true, "chunk_decision": "reject", "max_injection_score": directives.maxInjectionScore}),
			}
			result.findings = append(result.findings, finding)
			if chunkOutcome.Decision == "allow" {
				chunkOutcome.Decision = "reject"
				chunkOutcome.Reason = finding.Summary
			}
		}
		if directives.blockOnPII && len(chunk.PIIFlags) > 0 {
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "rag_pii",
				Severity:        "high",
				Confidence:      0.95,
				Outcome:         "allow",
				Summary:         "Retrieved chunk contains flagged PII and must be sanitized",
				Details:         buildRAGFindingDetails(chunk, map[string]any{"chunk_decision_only": true, "chunk_decision": "redact"}),
			}
			result.findings = append(result.findings, finding)
			if chunkOutcome.Decision == "allow" {
				chunkOutcome.Decision = "redact"
				chunkOutcome.Reason = finding.Summary
			}
		}
		if compiled := blockedPatternRegexp(directives.blockedPatterns); compiled != nil && compiled.MatchString(chunk.Content) {
			matches := compiled.FindAllString(chunk.Content, -1)
			finding := runtimeapi.Finding{
				PolicyID:        policy.PolicyID,
				PolicyVersionID: policy.PolicyVersionID,
				Category:        "rag_blocked_pattern",
				Severity:        "high",
				Confidence:      0.93,
				Outcome:         "allow",
				Summary:         "Retrieved chunk matched a blocked pattern",
				Details:         buildRAGFindingDetails(chunk, map[string]any{"chunk_decision_only": true, "chunk_decision": "reject", "matches": matches}),
			}
			result.findings = append(result.findings, finding)
			if chunkOutcome.Decision == "allow" {
				chunkOutcome.Decision = "reject"
				chunkOutcome.Reason = finding.Summary
			}
		}
		if directives.citationRequired {
			chunkOutcome.CitationRequired = true
		}
	}

	portkeyFindings, portkeyRedactions, portkeySanitizedInput, _, portkeyChain := evaluateRuntimeCheckPolicies(ctx, r.adapterTimeout, policies, chunkRequest)
	for _, finding := range portkeyFindings {
		finding.Details = buildRAGFindingDetails(chunk, mergeMaps(finding.Details, map[string]any{
			"chunk_decision_only": true,
			"chunk_decision":      outcomeToRAGChunkDecision(finding.Outcome),
		}))
		result.findings = append(result.findings, finding)
	}
	if len(portkeyRedactions) > 0 {
		result.redactions = append(result.redactions, portkeyRedactions...)
	}
	result.decisionChain = append(result.decisionChain, portkeyChain...)
	if strings.TrimSpace(portkeySanitizedInput) != "" && portkeySanitizedInput != chunk.Content && chunkOutcome.Decision == "allow" {
		chunkOutcome.Decision = "redact"
		chunkOutcome.SanitizedContent = portkeySanitizedInput
		chunkOutcome.Reason = "Chunk content sanitized by runtime guardrail check"
	}

	localFindings, localRedactions, localSanitizedInput, _, localChain := r.evaluateLocalPolicies(policies, chunkRequest)
	for _, finding := range localFindings {
		finding.Details = buildRAGFindingDetails(chunk, mergeMaps(finding.Details, map[string]any{
			"chunk_decision_only": true,
			"chunk_decision":      outcomeToRAGChunkDecision(finding.Outcome),
		}))
		result.findings = append(result.findings, finding)
	}
	if len(localRedactions) > 0 {
		result.redactions = append(result.redactions, localRedactions...)
	}
	result.decisionChain = append(result.decisionChain, localChain...)
	if strings.TrimSpace(localSanitizedInput) != "" && localSanitizedInput != chunk.Content && chunkOutcome.Decision == "allow" {
		chunkOutcome.Decision = "redact"
		chunkOutcome.SanitizedContent = localSanitizedInput
		chunkOutcome.Reason = "Chunk content sanitized by local RAG policy"
	}

	if hasBundle {
		providerFindings, providerChain := r.evaluateProviderBindings(ctx, bundle, policies, chunkRequest)
		for _, finding := range providerFindings {
			finding.Details = buildRAGFindingDetails(chunk, mergeMaps(finding.Details, map[string]any{
				"chunk_decision_only": true,
				"chunk_decision":      outcomeToRAGChunkDecision(finding.Outcome),
			}))
			result.findings = append(result.findings, finding)
		}
		result.decisionChain = append(result.decisionChain, providerChain...)
	}

	if chunkOutcome.Decision == "allow" && len(chunk.PIIFlags) > 0 {
		chunkOutcome.Decision = "redact"
		chunkOutcome.Reason = "Chunk contains precomputed PII flags"
	}
	if shadowMode {
		chunkOutcome.Decision = "allow"
		if strings.TrimSpace(chunkOutcome.Reason) == "" {
			chunkOutcome.Reason = "Shadow mode captured a non-blocking RAG evaluation"
		}
	}
	chunkOutcome.PolicyHits = policyHits.values()
	chunkOutcome = reconcileRAGChunkOutcome(chunkOutcome, result.findings)
	result.outcomes = append(result.outcomes, chunkOutcome)
	return result
}

func extractRAGChunks(bundle runtimeapi.TenantBundle, request runtimeapi.EvaluateRequest) []ragChunkInput {
	metadata := request.Metadata
	if metadata == nil {
		return nil
	}
	sourceInventory := bundleRAGSources(bundle)
	rawChunks, ok := metadata["rag_chunks"]
	if !ok {
		rawChunks = metadata["retrieved_chunks"]
	}
	rawSlice, ok := rawChunks.([]any)
	if !ok {
		return nil
	}
	chunks := make([]ragChunkInput, 0, len(rawSlice))
	for index, raw := range rawSlice {
		record, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		chunkID := strings.TrimSpace(stringValue(record, "chunk_id"))
		if chunkID == "" {
			chunkID = fmt.Sprintf("chunk-%d", index+1)
		}
		content := strings.TrimSpace(stringValue(record, "content"))
		sourceID := defaultString(strings.TrimSpace(stringValue(record, "source_id")), metadataString(metadata, "source_id"))
		sourceDefaults := bundleRAGSource(sourceInventory, sourceID)
		chunks = append(chunks, ragChunkInput{
			ChunkID:         chunkID,
			DocumentID:      strings.TrimSpace(stringValue(record, "document_id")),
			DocumentVersion: strings.TrimSpace(stringValue(record, "document_version")),
			Content:         content,
			OffsetStart:     intValue(record, "offset_start", 0),
			OffsetEnd:       intValue(record, "offset_end", 0),
			ACLTags:         dedupeNonEmptyStrings(append(stringSlice(record["acl_tags"]), stringSlice(sourceDefaults["acl_tags"])...)...),
			Labels:          dedupeNonEmptyStrings(append(stringSlice(record["labels"]), stringSlice(sourceDefaults["labels"])...)...),
			TrustScore:      defaultInt(intValue(record, "trust_score", 0), intValue(sourceDefaults, "trust_score", 0)),
			InjectionScore:  intValue(record, "injection_score", 0),
			PIIFlags:        dedupeNonEmptyStrings(stringSlice(record["pii_flags"])...),
			SourceID:        sourceID,
			SourceName:      defaultString(strings.TrimSpace(stringValue(record, "source_name")), defaultString(stringValue(sourceDefaults, "source_name"), metadataString(metadata, "source_name"))),
			SourceHealth:    defaultString(strings.TrimSpace(stringValue(record, "source_health")), defaultString(stringValue(sourceDefaults, "source_health"), "healthy")),
			Quarantined:     boolValue(record, "quarantined", boolValue(sourceDefaults, "quarantined", false)),
		})
	}
	return chunks
}

func ragDirectives(policy runtimeapi.PolicyBundle) ragPolicyDirectives {
	metadata := cloneMap(policy.Metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	definition := cloneMap(policy.Definition)
	return ragPolicyDirectives{
		minTrustScore:     readRAGInt(metadata, definition, "min_trust_score"),
		maxInjectionScore: readRAGInt(metadata, definition, "max_injection_score"),
		blockOnPII:        readRAGBool(metadata, definition, "block_on_pii"),
		citationRequired:  readRAGBool(metadata, definition, "citation_required"),
		requireApproval:   readRAGBool(metadata, definition, "require_approval"),
		shadowMode:        readRAGBool(metadata, definition, "shadow_mode"),
		allowedRoles:      dedupeNonEmptyStrings(readRAGStrings(metadata, definition, "allowed_roles")...),
		allowedApps:       dedupeNonEmptyStrings(readRAGStrings(metadata, definition, "allowed_apps")...),
		trustedSourceIDs:  dedupeNonEmptyStrings(readRAGStrings(metadata, definition, "trusted_source_ids")...),
		blockedPatterns:   dedupeNonEmptyStrings(readRAGStrings(metadata, definition, "blocked_patterns")...),
	}
}

func collectRAGChunkDirectives(policies []runtimeapi.PolicyBundle) ragPolicyDirectives {
	combined := ragPolicyDirectives{}
	for _, policy := range policies {
		directives := ragDirectives(policy)
		if directives.shadowMode {
			combined.shadowMode = true
		}
	}
	return combined
}

func ragPolicyAppliesToRequest(directives ragPolicyDirectives, request runtimeapi.EvaluateRequest) bool {
	if len(directives.allowedRoles) > 0 && !containsNormalizedValue(directives.allowedRoles, request.Actor.Role) {
		return false
	}
	if len(directives.allowedApps) > 0 {
		appName := metadataString(request.Metadata, "app_name", "app", "application")
		if !containsNormalizedValue(directives.allowedApps, appName) {
			return false
		}
	}
	return true
}

func readRAGInt(metadata map[string]any, definition map[string]any, key string) int {
	if value := intValue(metadata, key, -1); value >= 0 {
		return value
	}
	return intValue(definition, key, 0)
}

func readRAGBool(metadata map[string]any, definition map[string]any, key string) bool {
	if metadata != nil {
		if _, ok := metadata[key]; ok {
			return boolValue(metadata, key, false)
		}
	}
	return boolValue(definition, key, false)
}

func readRAGStrings(metadata map[string]any, definition map[string]any, key string) []string {
	if metadata != nil {
		if raw, ok := metadata[key]; ok {
			return stringSlice(raw)
		}
	}
	if definition != nil {
		if raw, ok := definition[key]; ok {
			return stringSlice(raw)
		}
	}
	return nil
}

func buildRAGFindingDetails(chunk ragChunkInput, extra map[string]any) map[string]any {
	details := map[string]any{
		"chunk_id":         chunk.ChunkID,
		"document_id":      chunk.DocumentID,
		"document_version": chunk.DocumentVersion,
		"offset_start":     chunk.OffsetStart,
		"offset_end":       chunk.OffsetEnd,
		"source_id":        chunk.SourceID,
		"source_name":      chunk.SourceName,
		"trust_score":      chunk.TrustScore,
		"injection_score":  chunk.InjectionScore,
		"pii_flags":        append([]string(nil), chunk.PIIFlags...),
		"quarantined":      chunk.Quarantined,
	}
	for key, value := range extra {
		details[key] = value
	}
	return details
}

func reconcileRAGChunkOutcome(outcome ragChunkOutcome, findings []runtimeapi.Finding) ragChunkOutcome {
	bestRank := ragChunkDecisionRank(outcome.Decision)
	for _, finding := range findings {
		if finding.Details == nil {
			continue
		}
		if !boolValue(finding.Details, "chunk_decision_only", false) {
			continue
		}
		if strings.TrimSpace(stringValue(finding.Details, "chunk_id")) != strings.TrimSpace(outcome.ChunkID) {
			continue
		}
		decision := strings.TrimSpace(stringValue(finding.Details, "chunk_decision"))
		if decision == "" {
			decision = outcomeToRAGChunkDecision(finding.Outcome)
		}
		rank := ragChunkDecisionRank(decision)
		if rank > bestRank {
			bestRank = rank
			outcome.Decision = decision
			outcome.Reason = finding.Summary
		}
		if strings.TrimSpace(outcome.Reason) == "" && decision == outcome.Decision {
			outcome.Reason = finding.Summary
		}
	}
	if outcome.Decision == "redact" && strings.TrimSpace(outcome.SanitizedContent) == "" {
		outcome.SanitizedContent = "[REDACTED]"
	}
	return outcome
}

func resolveRAGDecision(findings []runtimeapi.Finding, redactions []string, outcomes []ragChunkOutcome) (string, bool, string) {
	var (
		requestDenySummary    string
		requestSandboxSummary string
		anyRedaction          bool
		allowedChunks         int
		rejectedChunks        int
	)

	for _, outcome := range outcomes {
		switch outcome.Decision {
		case "allow", "redact":
			allowedChunks++
		case "reject", "quarantine":
			rejectedChunks++
		}
		if outcome.Decision == "redact" {
			anyRedaction = true
		}
	}

	for _, finding := range findings {
		chunkOnly := finding.Details != nil && boolValue(finding.Details, "chunk_decision_only", false)
		if chunkOnly {
			if normalizeOutcome(finding.Outcome) == "redact" {
				anyRedaction = true
			}
			continue
		}
		switch normalizeOutcome(finding.Outcome) {
		case "deny":
			if requestDenySummary == "" {
				requestDenySummary = finding.Summary
			}
		case "sandbox":
			if requestSandboxSummary == "" {
				requestSandboxSummary = finding.Summary
			}
		case "redact":
			anyRedaction = true
		}
	}

	if requestDenySummary != "" {
		return "deny", false, requestDenySummary
	}
	if requestSandboxSummary != "" {
		return "sandbox", false, requestSandboxSummary
	}
	if len(outcomes) > 0 && allowedChunks == 0 && rejectedChunks > 0 {
		return "deny", false, "All retrieved chunks were rejected by RAG guardrails"
	}
	if anyRedaction || len(redactions) > 0 {
		return "allow_with_redaction", false, "Retrieved content was sanitized by RAG guardrails"
	}
	return "allow", false, "RAG content passed guardrail evaluation"
}

func outcomeToRAGChunkDecision(outcome string) string {
	switch normalizeOutcome(outcome) {
	case "deny", "sandbox":
		return "reject"
	case "redact":
		return "redact"
	default:
		return "allow"
	}
}

func ragChunkDecisionRank(decision string) int {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "quarantine":
		return 4
	case "reject":
		return 3
	case "redact":
		return 2
	default:
		return 1
	}
}

func compactRAGContent(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if limit <= 0 || len([]rune(value)) <= limit {
		return value
	}
	runes := []rune(value)
	return strings.TrimSpace(string(runes[:limit])) + "..."
}

func filterRAGOutcomes(outcomes []ragChunkOutcome, decisions ...string) []ragChunkOutcome {
	if len(outcomes) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(decisions))
	for _, decision := range decisions {
		allowed[strings.ToLower(strings.TrimSpace(decision))] = struct{}{}
	}
	filtered := make([]ragChunkOutcome, 0, len(outcomes))
	for _, outcome := range outcomes {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(outcome.Decision))]; ok {
			filtered = append(filtered, outcome)
		}
	}
	return filtered
}

func ragOutcomesToAny(outcomes []ragChunkOutcome) []any {
	if len(outcomes) == 0 {
		return nil
	}
	result := make([]any, 0, len(outcomes))
	for _, outcome := range outcomes {
		result = append(result, map[string]any{
			"chunk_id":          outcome.ChunkID,
			"document_id":       outcome.DocumentID,
			"document_version":  outcome.DocumentVersion,
			"content_preview":   outcome.ContentPreview,
			"offset_start":      outcome.OffsetStart,
			"offset_end":        outcome.OffsetEnd,
			"trust_score":       outcome.TrustScore,
			"injection_score":   outcome.InjectionScore,
			"pii_flags":         append([]string(nil), outcome.PIIFlags...),
			"source_id":         outcome.SourceID,
			"source_name":       outcome.SourceName,
			"source_health":     outcome.SourceHealth,
			"quarantined":       outcome.Quarantined,
			"decision":          outcome.Decision,
			"reason":            outcome.Reason,
			"policy_hits":       append([]string(nil), outcome.PolicyHits...),
			"sanitized_content": outcome.SanitizedContent,
			"citation_required": outcome.CitationRequired,
		})
	}
	return result
}

func collectRAGPolicyHits(findings []runtimeapi.Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	result := make([]string, 0, len(findings))
	for _, finding := range findings {
		if strings.TrimSpace(finding.PolicyID) == "" {
			continue
		}
		if _, ok := seen[finding.PolicyID]; ok {
			continue
		}
		seen[finding.PolicyID] = struct{}{}
		result = append(result, finding.PolicyID)
	}
	sort.Strings(result)
	return result
}

func anyRAGCitationRequired(outcomes []ragChunkOutcome) bool {
	for _, outcome := range outcomes {
		if outcome.CitationRequired {
			return true
		}
	}
	return false
}

func ragCitations(outcomes []ragChunkOutcome) []any {
	if len(outcomes) == 0 {
		return nil
	}
	result := make([]any, 0, len(outcomes))
	for _, outcome := range outcomes {
		if !outcome.CitationRequired {
			continue
		}
		if strings.EqualFold(outcome.Decision, "reject") || strings.EqualFold(outcome.Decision, "quarantine") {
			continue
		}
		result = append(result, map[string]any{
			"source_id":        outcome.SourceID,
			"source_name":      outcome.SourceName,
			"document_id":      outcome.DocumentID,
			"document_version": outcome.DocumentVersion,
			"chunk_id":         outcome.ChunkID,
			"offset_start":     outcome.OffsetStart,
			"offset_end":       outcome.OffsetEnd,
		})
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func mapKeysSorted(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func metadataString(metadata map[string]any, keys ...string) string {
	if metadata == nil {
		return ""
	}
	for _, key := range keys {
		value := strings.TrimSpace(stringValue(metadata, key))
		if value != "" {
			return value
		}
	}
	return ""
}

func mergeMaps(base map[string]any, extras map[string]any) map[string]any {
	result := cloneMap(base)
	if result == nil {
		result = map[string]any{}
	}
	for key, value := range extras {
		result[key] = value
	}
	return result
}

type stringSet map[string]struct{}

func (s stringSet) add(values ...string) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		s[trimmed] = struct{}{}
	}
}

func (s stringSet) values() []string {
	if len(s) == 0 {
		return nil
	}
	values := make([]string, 0, len(s))
	for value := range s {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func blockedPatternRegexp(patterns []string) *regexp.Regexp {
	if len(patterns) == 0 {
		return nil
	}
	escaped := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		escaped = append(escaped, trimmed)
	}
	if len(escaped) == 0 {
		return nil
	}
	compiled, err := cachedRegexpCompile(strings.Join(escaped, "|"))
	if err != nil {
		return nil
	}
	return compiled
}

func bundleRAGSources(bundle runtimeapi.TenantBundle) map[string]map[string]any {
	if bundle.Metadata == nil {
		return nil
	}
	rawSources, ok := bundle.Metadata["rag_sources"].(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]map[string]any, len(rawSources))
	for sourceID, rawSource := range rawSources {
		record, ok := rawSource.(map[string]any)
		if !ok {
			continue
		}
		result[sourceID] = record
	}
	return result
}

func bundleRAGSource(inventory map[string]map[string]any, sourceID string) map[string]any {
	if len(inventory) == 0 {
		return nil
	}
	return inventory[strings.TrimSpace(sourceID)]
}

func defaultInt(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
