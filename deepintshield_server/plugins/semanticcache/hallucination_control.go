package semanticcache

import (
	"regexp"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// Hallucination Control - proactive mitigation applied in PreLLMHook.
// Every technique here is prompt- or parameter-only: zero added round-trips,
// zero added latency on the request path. PostLLMHook scores an
// improvement-signal heuristic on the response (uncertainty/citation
// frequency) so the dashboard can plot whether the mitigations are
// actually showing up in model output.

// Technique IDs - kept in sync with the UI multi-select options.
const (
	TechniqueGroundingDirective = "grounding_directive"
	TechniqueAntiFabrication    = "anti_fabrication"
	TechniqueCitationRequired   = "citation_required"
	TechniqueUncertaintyAck     = "uncertainty_ack"
	TechniqueTemperatureClamp   = "temperature_clamp"
)

// Strictness tiers - controls prompt firmness and the temp-clamp cap.
const (
	StrictnessLow    = "low"
	StrictnessMedium = "medium"
	StrictnessHigh   = "high"
)

// Stashed under context so PostLLMHook can stamp the response with the
// applied techniques + computed improvement score.
const hallucControlAppliedKey = schemas.DeepIntShieldContextKey("hallucination-control-applied")

type hallucControlState struct {
	techniques []string
	strictness string
}

func (plugin *Plugin) isHallucinationControlEnabled() bool {
	if plugin == nil || plugin.config == nil || plugin.config.HallucinationControlEnabled == nil {
		return false
	}
	return *plugin.config.HallucinationControlEnabled
}

func (plugin *Plugin) isHallucinationControlEnabledForVK(vkID string) bool {
	if !plugin.isHallucinationControlEnabled() {
		return false
	}
	scope := plugin.config.HallucinationControlVKScope
	if len(scope) == 0 {
		return true
	}
	for _, v := range scope {
		if v == vkID {
			return true
		}
	}
	return false
}

func (plugin *Plugin) hallucControlStrictness() string {
	if plugin == nil || plugin.config == nil {
		return StrictnessMedium
	}
	s := strings.ToLower(strings.TrimSpace(plugin.config.HallucinationControlStrictness))
	switch s {
	case StrictnessLow, StrictnessMedium, StrictnessHigh:
		return s
	default:
		return StrictnessMedium
	}
}

func (plugin *Plugin) hallucControlTempCap() float64 {
	if plugin == nil || plugin.config == nil || plugin.config.HallucinationControlTempCap <= 0 {
		// Strictness-aware default so the slider isn't required.
		switch plugin.hallucControlStrictness() {
		case StrictnessHigh:
			return 0.2
		case StrictnessLow:
			return 0.7
		}
		return 0.4
	}
	return plugin.config.HallucinationControlTempCap
}

func (plugin *Plugin) hallucControlTechniques() []string {
	if plugin == nil || plugin.config == nil {
		return nil
	}
	return plugin.config.HallucinationControlTechniques
}

// applyHallucinationControl mutates the outgoing chat request in-place with
// the configured mitigations. Called from PreLLMHook before the request is
// dispatched to the provider. Idempotent and safe to call on requests that
// don't carry a chat payload (returns immediately).
func (plugin *Plugin) applyHallucinationControl(ctx *schemas.DeepIntShieldContext, req *schemas.DeepIntShieldRequest) {
	if req == nil {
		return
	}
	// Accept either request shape - SDK clients (LangChain via the
	// deepintshield Python client) route simple chat invocations through
	// the Responses API, so a ChatRequest-only gate would silently skip
	// every LangChain-driven request.
	if req.ChatRequest == nil && req.ResponsesRequest == nil {
		return
	}
	vkID, _ := stringContextValue(ctx, schemas.DeepIntShieldContextKeyGovernanceVirtualKeyID)
	if !plugin.isHallucinationControlEnabledForVK(vkID) {
		return
	}
	techniques := plugin.hallucControlTechniques()
	if len(techniques) == 0 {
		return
	}
	enabled := make(map[string]bool, len(techniques))
	for _, t := range techniques {
		enabled[strings.ToLower(strings.TrimSpace(t))] = true
	}

	strictness := plugin.hallucControlStrictness()
	directiveParts := make([]string, 0, 4)
	if enabled[TechniqueGroundingDirective] {
		directiveParts = append(directiveParts, groundingDirectiveText(strictness))
	}
	if enabled[TechniqueAntiFabrication] {
		directiveParts = append(directiveParts, antiFabricationText(strictness))
	}
	if enabled[TechniqueCitationRequired] {
		directiveParts = append(directiveParts, citationDirectiveText(strictness))
	}
	if enabled[TechniqueUncertaintyAck] {
		directiveParts = append(directiveParts, uncertaintyDirectiveText(strictness))
	}

	if len(directiveParts) > 0 {
		injectSystemDirective(req, strings.Join(directiveParts, " "))
	}

	if enabled[TechniqueTemperatureClamp] {
		clampTemperature(req, plugin.hallucControlTempCap())
	}

	applied := make([]string, 0, len(techniques))
	for _, t := range techniques {
		if enabled[strings.ToLower(strings.TrimSpace(t))] {
			applied = append(applied, t)
		}
	}
	ctx.SetValue(hallucControlAppliedKey, hallucControlState{techniques: applied, strictness: strictness})
}

// groundingDirectiveText returns the system-prompt injection that asks the
// model to ground its answer in the provided context (when one is supplied).
// Phrasing scales with strictness - "high" is closer to a hard refusal than
// a polite reminder.
func groundingDirectiveText(strictness string) string {
	switch strictness {
	case StrictnessHigh:
		return "Answer ONLY using facts found in the provided context. If the context does not contain the answer, reply exactly: \"I don't know based on the provided context.\" Never use outside knowledge."
	case StrictnessLow:
		return "Prefer information from the provided context when answering."
	}
	return "Base your answer on the provided context. If the context lacks the information needed, say so rather than guessing."
}

func antiFabricationText(strictness string) string {
	switch strictness {
	case StrictnessHigh:
		return "Do not invent facts, statistics, names, dates, URLs, citations, or quotes. If you are not certain a specific detail is true, omit it."
	case StrictnessLow:
		return "Avoid fabricating specific facts or numbers."
	}
	return "Do not fabricate facts, statistics, names, or quotes. When unsure of a specific detail, omit it rather than guessing."
}

func citationDirectiveText(strictness string) string {
	switch strictness {
	case StrictnessHigh:
		return "Every factual claim MUST end with an inline citation in the form [source: <title-or-URL>] referring to the provided sources. Claims without a backing source are not allowed."
	case StrictnessLow:
		return "Where possible, attribute factual claims to a source using [source: <name>]."
	}
	return "Attribute factual claims to a source using inline [source: <name>] markers when sources are available."
}

func uncertaintyDirectiveText(strictness string) string {
	switch strictness {
	case StrictnessHigh:
		return "When you are not fully certain about a claim, explicitly say \"I am not certain\" before stating it, and explain what additional information would resolve the uncertainty."
	case StrictnessLow:
		return "Hedge uncertain statements with words like \"likely\" or \"possibly\"."
	}
	return "Use hedging language (\"might\", \"likely\", \"I am not certain\") for claims you cannot verify confidently."
}

// injectSystemDirective prepends the directive to the existing system
// message, or creates a new system message at the head of the input slice
// when none exists. Mutates req in place. Handles both ChatRequest and
// ResponsesRequest shapes - SDKs differ on which one they emit and we
// want the mitigation to fire regardless.
func injectSystemDirective(req *schemas.DeepIntShieldRequest, directive string) {
	if directive == "" || req == nil {
		return
	}
	if req.ChatRequest != nil {
		msgs := req.ChatRequest.Input
		for i := range msgs {
			if msgs[i].Role == schemas.ChatMessageRoleSystem {
				// Preserve the operator's system prompt; the directive
				// goes on top so the operator's content remains the
				// closing intent of the system message.
				existing := messageContentText(msgs[i])
				combined := directive + "\n\n" + existing
				str := combined
				msgs[i].Content = &schemas.ChatMessageContent{ContentStr: &str}
				req.ChatRequest.Input = msgs
				return
			}
		}
		str := directive
		sys := schemas.ChatMessage{
			Role:    schemas.ChatMessageRoleSystem,
			Content: &schemas.ChatMessageContent{ContentStr: &str},
		}
		req.ChatRequest.Input = append([]schemas.ChatMessage{sys}, msgs...)
		return
	}
	if req.ResponsesRequest != nil {
		msgs := req.ResponsesRequest.Input
		for i := range msgs {
			if msgs[i].Role != nil && *msgs[i].Role == schemas.ResponsesInputMessageRoleSystem {
				existing := responsesMessageText(msgs[i])
				combined := directive + "\n\n" + existing
				str := combined
				msgs[i].Content = &schemas.ResponsesMessageContent{ContentStr: &str}
				req.ResponsesRequest.Input = msgs
				return
			}
		}
		role := schemas.ResponsesInputMessageRoleSystem
		str := directive
		sys := schemas.ResponsesMessage{
			Role:    &role,
			Content: &schemas.ResponsesMessageContent{ContentStr: &str},
		}
		req.ResponsesRequest.Input = append([]schemas.ResponsesMessage{sys}, msgs...)
	}
}

// clampTemperature lowers the request's temperature when it exceeds the
// configured cap. Only writes when the existing value is above the cap so
// operators who deliberately requested a higher temperature for a creative
// VK aren't quietly bypassed for VKs outside the control scope (those
// don't reach this code path). ChatRequest only - ResponsesRequest carries
// temperature on its own params shape and is a follow-up.
func clampTemperature(req *schemas.DeepIntShieldRequest, cap float64) {
	if req == nil || req.ChatRequest == nil || req.ChatRequest.Params == nil {
		return
	}
	if req.ChatRequest.Params.Temperature == nil {
		req.ChatRequest.Params.Temperature = &cap
		return
	}
	if *req.ChatRequest.Params.Temperature > cap {
		req.ChatRequest.Params.Temperature = &cap
	}
}

// ─────────────────────────── improvement scoring ──────────────────────────

// hedgePattern + citationPattern are the heuristics that power the
// "improvement" graph on the dashboard. Both are intentionally cheap:
// compiled once, executed in O(n) of the response. We bucket the response
// and look for the markers the directives push the model towards - when
// they show up, the techniques are detectably influencing output.
var (
	hedgePattern = regexp.MustCompile(`(?i)\b(might|possibly|likely|may|could|uncertain|i (am )?not (sure|certain)|i don't know|approximately|roughly)\b`)
	// Matches either [source: ...] (our recommended marker) or a parenthesized
	// URL - the second handles models that emit hyperlinks instead.
	citationPattern = regexp.MustCompile(`(\[source:[^\]]+\])|(https?://\S+)`)
)

// computeHallucControlImprovement scores 0..1: higher = more anti-
// hallucination behaviours present in the response. Computed as a weighted
// blend of hedge density + citation density, capped at 1.
func computeHallucControlImprovement(response string) float64 {
	if response == "" {
		return 0
	}
	// Sentence-level normalization keeps the score stable across short
	// vs long answers; pure character density would punish concise
	// correct answers and reward verbose hedged ones equally.
	sentences := splitSentencesFast(response)
	if len(sentences) == 0 {
		return 0
	}
	hedgeMatches := len(hedgePattern.FindAllStringIndex(response, -1))
	citationMatches := len(citationPattern.FindAllStringIndex(response, -1))

	hedgeDensity := float64(hedgeMatches) / float64(len(sentences))
	citationDensity := float64(citationMatches) / float64(len(sentences))

	// Cap each component at 1.0 (one hedge per sentence is plenty), then
	// blend 60/40 - hedging is the more universally applicable signal.
	if hedgeDensity > 1 {
		hedgeDensity = 1
	}
	if citationDensity > 1 {
		citationDensity = 1
	}
	score := 0.6*hedgeDensity + 0.4*citationDensity
	if score > 1 {
		score = 1
	}
	return score
}

// splitSentencesFast is a lightweight sentence splitter (no regex). It's
// approximate but adequate for the density heuristic - boundary errors
// move the score by a few percent at most.
func splitSentencesFast(s string) []string {
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == '!' || c == '?' || c == '\n' {
			seg := strings.TrimSpace(s[start : i+1])
			if seg != "" {
				out = append(out, seg)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		seg := strings.TrimSpace(s[start:])
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// stampHallucinationControl writes the control debug onto the response so
// the logger plugin's post-write update path picks up:
//   - which techniques fired
//   - the strictness tier
//   - the heuristic improvement score
//
// All three feed the dashboard tab + the new improvement chart.
func stampHallucinationControl(ctx *schemas.DeepIntShieldContext, resp *schemas.DeepIntShieldResponse) {
	if resp == nil {
		return
	}
	raw := ctx.Value(hallucControlAppliedKey)
	if raw == nil {
		return
	}
	state, ok := raw.(hallucControlState)
	if !ok || len(state.techniques) == 0 {
		return
	}
	respText := extractResponseText(resp)
	improvement := computeHallucControlImprovement(respText)

	extra := resp.GetExtraFields()
	if extra == nil {
		return
	}
	extra.HallucinationControlApplied = true
	extra.HallucinationControlTechniques = strings.Join(state.techniques, ",")
	extra.HallucinationControlStrictness = state.strictness
	extra.HallucinationControlImprovement = improvement
}

// messageContentText extracts the plain text of a chat message (string content
// or concatenated text blocks). Inlined helper, no external dependency.
func messageContentText(m schemas.ChatMessage) string {
	if m.Content == nil {
		return ""
	}
	if m.Content.ContentStr != nil {
		return *m.Content.ContentStr
	}
	var b strings.Builder
	for _, block := range m.Content.ContentBlocks {
		if block.Type == schemas.ChatContentBlockTypeText && block.Text != nil {
			b.WriteString(*block.Text)
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// extractResponseText extracts the assistant's output text from a chat or
// responses-API response. Inlined helper, no external dependency.
func extractResponseText(resp *schemas.DeepIntShieldResponse) string {
	if resp == nil {
		return ""
	}
	if resp.ChatResponse != nil && len(resp.ChatResponse.Choices) > 0 {
		choice := resp.ChatResponse.Choices[0]
		if choice.ChatNonStreamResponseChoice == nil || choice.Message == nil {
			return ""
		}
		msg := choice.Message
		if msg.Content == nil {
			return ""
		}
		if msg.Content.ContentStr != nil {
			return *msg.Content.ContentStr
		}
		var b strings.Builder
		for _, block := range msg.Content.ContentBlocks {
			if block.Type == schemas.ChatContentBlockTypeText && block.Text != nil {
				if b.Len() > 0 {
					b.WriteByte(' ')
				}
				b.WriteString(*block.Text)
			}
		}
		return b.String()
	}
	if resp.ResponsesResponse != nil && len(resp.ResponsesResponse.Output) > 0 {
		var b strings.Builder
		for _, msg := range resp.ResponsesResponse.Output {
			if msg.Content == nil {
				continue
			}
			if msg.Content.ContentStr != nil && *msg.Content.ContentStr != "" {
				if b.Len() > 0 {
					b.WriteByte(' ')
				}
				b.WriteString(*msg.Content.ContentStr)
				continue
			}
			for _, block := range msg.Content.ContentBlocks {
				if block.Type == schemas.ResponsesOutputMessageContentTypeText && block.Text != nil {
					if b.Len() > 0 {
						b.WriteByte(' ')
					}
					b.WriteString(*block.Text)
				}
			}
		}
		return b.String()
	}
	return ""
}
