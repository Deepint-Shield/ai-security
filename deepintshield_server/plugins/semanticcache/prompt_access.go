package semanticcache

// Unified prompt access for the cost-optimization sub-features.
//
// Why this exists: every optimizer (prompt compression, RAG rerank,
// summarization, TTFT reorder) was originally written against
// `req.ChatRequest.Input` - the Chat Completions shape. The HTTP
// transport, however, routes any request that originated from the
// Anthropic SDK (and OpenAI Responses-API clients) into
// `req.ResponsesRequest.Input` - a different shape with a different
// message struct (`ResponsesMessage` instead of `ChatMessage`). The
// optimizers' `req.ChatRequest == nil` early-return therefore fired on
// every Anthropic-shaped request, silently disabling the entire
// cost-optimization stack on the only path that gets real customer
// traffic today.
//
// This file replaces the chat-only direct field access with a
// shape-agnostic accessor. Each optimizer now calls `getPromptMessages`
// / `setPromptMessages` / `promptHasTools` and works uniformly across:
//   * Anthropic Messages   → ResponsesRequest
//   * OpenAI Responses API → ResponsesRequest
//   * OpenAI Chat Completions / Gemini / Bedrock / Mistral / Ollama
//     / Cohere / VertexAI → ChatRequest
//
// Provider-specific routing already happens via the `provider` argument
// (the optimizers gate on `compression_providers`, etc.) - this layer
// only fixes the request-SHAPE mismatch, not the provider list.
//
// Design: the accessor returns a slice of normalised `promptMsg` structs
// with `Role`/`Text` plus pointers back to the originating message struct
// so optimizers that mutate in place (RAG single-cell rewrite) can
// preserve metadata while collapse-style mutations (compression,
// summarization, TTFT) just rebuild the underlying slice.

import (
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// Canonical role labels - both ChatMessage and ResponsesMessage use the
// same string values, so the role mapping is a no-op cast.
const (
	roleSystem    = "system"
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"
	roleDeveloper = "developer" // ResponsesRequest only; treat as system
)

// promptMsg is the shape-agnostic view of a single prompt message.
// `Text` flattens whatever the underlying message structure contains
// into one string - for multi-block content we concatenate the text
// blocks (consistent with how the optimizers already concatenated
// ChatMessageContent.ContentBlocks). Multimodal blocks (images, audio)
// are dropped from the view since none of the cost-opt features touch
// them.
type promptMsg struct {
	Role string
	Text string
}

// hasPromptShape returns true when the request carries a prompt the
// optimizers can act on (chat or responses shape). Embedding /
// transcription / image-only requests return false.
func hasPromptShape(req *schemas.DeepIntShieldRequest) bool {
	if req == nil {
		return false
	}
	if req.ChatRequest != nil {
		return true
	}
	if req.ResponsesRequest != nil {
		return true
	}
	return false
}

// promptHasTools returns true ONLY when the message stream itself carries a
// tool call / tool response. Tools merely *advertised* in Params.Tools are
// not a reason to bail out - compression only mutates the user-message text
// and leaves Params.Tools untouched, so a "you have these N tools" entry
// has no effect on what the optimizer reads or writes.
//
// Why this matters: the MCP plugin auto-attaches every bound MCP server's
// tools to Params.Tools on every inference request so the model can choose
// to call them. Treating that auto-attachment as "tool-call shape" disabled
// prompt-compression for every workspace that registered an MCP server -
// which is most of them - even though the user message itself is plain prose.
// We do still skip when an actual tool-call round is present (assistant
// tool_calls or tool-role messages) so compression doesn't mangle a
// mid-flight tool conversation.
func promptHasTools(req *schemas.DeepIntShieldRequest) bool {
	if req == nil {
		return false
	}
	if req.ChatRequest != nil {
		for _, m := range req.ChatRequest.Input {
			if m.ChatAssistantMessage != nil && len(m.ChatAssistantMessage.ToolCalls) > 0 {
				return true
			}
			if m.ChatToolMessage != nil && m.ChatToolMessage.ToolCallID != nil {
				return true
			}
		}
		return false
	}
	if req.ResponsesRequest != nil {
		for _, m := range req.ResponsesRequest.Input {
			if m.ResponsesToolMessage != nil {
				return true
			}
		}
		return false
	}
	return false
}

// getPromptMessages returns the normalised view of every message in the
// request, regardless of shape. Read-only - mutations must go through
// setPromptMessages (or the per-message rewrite helpers).
func getPromptMessages(req *schemas.DeepIntShieldRequest) []promptMsg {
	if req == nil {
		return nil
	}
	if req.ChatRequest != nil {
		out := make([]promptMsg, 0, len(req.ChatRequest.Input))
		for _, m := range req.ChatRequest.Input {
			out = append(out, promptMsg{
				Role: string(m.Role),
				Text: chatMessageText(m),
			})
		}
		return out
	}
	if req.ResponsesRequest != nil {
		out := make([]promptMsg, 0, len(req.ResponsesRequest.Input))
		for _, m := range req.ResponsesRequest.Input {
			role := ""
			if m.Role != nil {
				role = string(*m.Role)
			}
			out = append(out, promptMsg{
				Role: role,
				Text: responsesMessageText(m),
			})
		}
		return out
	}
	return nil
}

// setPromptMessages replaces the request's message list with a new
// normalised list. Used by summarization (collapses prefix into a
// summary system note + tail) and TTFT (reorders messages). The
// helper preserves the request's existing shape - a ChatRequest stays
// a ChatRequest, etc. - so downstream provider conversion still works.
//
// Tool/function metadata on the original messages is NOT preserved
// (these helpers are only called from paths that already excluded
// tool-shaped requests).
func setPromptMessages(req *schemas.DeepIntShieldRequest, msgs []promptMsg) {
	if req == nil {
		return
	}
	if req.ChatRequest != nil {
		newInput := make([]schemas.ChatMessage, 0, len(msgs))
		for _, m := range msgs {
			text := m.Text
			newInput = append(newInput, schemas.ChatMessage{
				Role:    schemas.ChatMessageRole(m.Role),
				Content: &schemas.ChatMessageContent{ContentStr: &text},
			})
		}
		req.ChatRequest.Input = newInput
		return
	}
	if req.ResponsesRequest != nil {
		newInput := make([]schemas.ResponsesMessage, 0, len(msgs))
		for _, m := range msgs {
			text := m.Text
			role := schemas.ResponsesMessageRoleType(m.Role)
			newInput = append(newInput, schemas.ResponsesMessage{
				Role:    &role,
				Content: &schemas.ResponsesMessageContent{ContentStr: &text},
			})
		}
		req.ResponsesRequest.Input = newInput
		return
	}
}

// replaceMessageTextAt rewrites a single message's text content at the
// given index, preserving role and other metadata. Used by the RAG
// optimizer which trims the prompt's chunked context without reshuffling
// the conversation. Out-of-range indices are ignored (defence in depth).
func replaceMessageTextAt(req *schemas.DeepIntShieldRequest, idx int, newText string) {
	if req == nil || idx < 0 {
		return
	}
	if req.ChatRequest != nil {
		if idx >= len(req.ChatRequest.Input) {
			return
		}
		s := newText
		req.ChatRequest.Input[idx].Content = &schemas.ChatMessageContent{ContentStr: &s}
		return
	}
	if req.ResponsesRequest != nil {
		if idx >= len(req.ResponsesRequest.Input) {
			return
		}
		s := newText
		req.ResponsesRequest.Input[idx].Content = &schemas.ResponsesMessageContent{ContentStr: &s}
		return
	}
}

// promptMessageCount returns the number of messages in the prompt
// regardless of shape. 0 for non-prompt requests (embedding, etc.).
func promptMessageCount(req *schemas.DeepIntShieldRequest) int {
	if req == nil {
		return 0
	}
	if req.ChatRequest != nil {
		return len(req.ChatRequest.Input)
	}
	if req.ResponsesRequest != nil {
		return len(req.ResponsesRequest.Input)
	}
	return 0
}

// chatMessageText flattens a ChatMessage's content into a single string.
// Drops non-text content blocks (images, audio, video) - none of the
// cost-opt optimizers touch them, and including them in the
// concatenation would just pollute the token estimate.
//
// Twin: `messageContentText` in ragoptimizer.go already had the same
// logic for the RAG optimizer's needs; this is the new canonical
// version used by every other optimizer.
func chatMessageText(m schemas.ChatMessage) string {
	if m.Content == nil {
		return ""
	}
	if m.Content.ContentStr != nil {
		return *m.Content.ContentStr
	}
	var b strings.Builder
	for _, block := range m.Content.ContentBlocks {
		if block.Type == schemas.ChatContentBlockTypeText && block.Text != nil {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(*block.Text)
		}
	}
	return b.String()
}

// responsesMessageText flattens a ResponsesMessage's content into a single
// string, dropping non-text blocks (mirrors chatMessageText for the Responses
// request shape).
func responsesMessageText(m schemas.ResponsesMessage) string {
	if m.Content == nil {
		return ""
	}
	if m.Content.ContentStr != nil {
		return *m.Content.ContentStr
	}
	var b strings.Builder
	for _, block := range m.Content.ContentBlocks {
		if block.Text != nil {
			b.WriteString(*block.Text)
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}
