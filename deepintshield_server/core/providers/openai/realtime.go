package openai

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/deepint-shield/ai-security/core/schemas"
)

// SupportsRealtimeAPI returns true since OpenAI natively supports the Realtime API.
func (provider *OpenAIProvider) SupportsRealtimeAPI() bool {
	return true
}

// RealtimeWebSocketURL returns the WSS URL for the OpenAI Realtime API.
// Format: wss://api.openai.com/v1/realtime?model=<model>
func (provider *OpenAIProvider) RealtimeWebSocketURL(key schemas.Key, model string) string {
	base := provider.networkConfig.BaseURL
	base = strings.Replace(base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)
	return base + "/v1/realtime?model=" + url.QueryEscape(model)
}

// RealtimeHeaders returns the headers required for the OpenAI Realtime WebSocket connection.
func (provider *OpenAIProvider) RealtimeHeaders(key schemas.Key) map[string]string {
	headers := map[string]string{
		"Authorization": "Bearer " + key.Value.GetValue(),
		"OpenAI-Beta":   "realtime=v1",
	}
	for k, v := range provider.networkConfig.ExtraHeaders {
		headers[k] = v
	}
	return headers
}

// openAIRealtimeEvent is the raw shape of an OpenAI Realtime protocol event.
type openAIRealtimeEvent struct {
	Type         string          `json:"type"`
	EventID      string          `json:"event_id,omitempty"`
	Session      json.RawMessage `json:"session,omitempty"`
	Conversation json.RawMessage `json:"conversation,omitempty"`
	Item         json.RawMessage `json:"item,omitempty"`
	Response     json.RawMessage `json:"response,omitempty"`
	Delta        string          `json:"delta,omitempty"`
	Audio        string          `json:"audio,omitempty"`
	Transcript   string          `json:"transcript,omitempty"`
	Text         string          `json:"text,omitempty"`
	Error        json.RawMessage `json:"error,omitempty"`
	ItemID       string          `json:"item_id,omitempty"`
	OutputIndex  int             `json:"output_index,omitempty"`
	ContentIndex int             `json:"content_index,omitempty"`
	ResponseID   string          `json:"response_id,omitempty"`

	PreviousItemID string `json:"previous_item_id,omitempty"`
}

// openAIRealtimeSession is the session object within an OpenAI Realtime event.
type openAIRealtimeSession struct {
	ID               string          `json:"id,omitempty"`
	Model            string          `json:"model,omitempty"`
	Modalities       []string        `json:"modalities,omitempty"`
	Instructions     string          `json:"instructions,omitempty"`
	Voice            string          `json:"voice,omitempty"`
	Temperature      *float64        `json:"temperature,omitempty"`
	MaxOutputTokens  json.RawMessage `json:"max_output_tokens,omitempty"`
	TurnDetection    json.RawMessage `json:"turn_detection,omitempty"`
	InputAudioFormat string          `json:"input_audio_format,omitempty"`
	OutputAudioType  string          `json:"output_audio_type,omitempty"`
	Tools            json.RawMessage `json:"tools,omitempty"`
}

// openAIRealtimeItem is the item object within an OpenAI Realtime event.
type openAIRealtimeItem struct {
	ID        string          `json:"id,omitempty"`
	Type      string          `json:"type,omitempty"`
	Role      string          `json:"role,omitempty"`
	Status    string          `json:"status,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	Name      string          `json:"name,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Arguments string          `json:"arguments,omitempty"`
	Output    string          `json:"output,omitempty"`
}

// openAIRealtimeError is the error object within an OpenAI Realtime event.
type openAIRealtimeError struct {
	Type    string `json:"type,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Param   string `json:"param,omitempty"`
}

// ToDeepIntShieldRealtimeEvent converts an OpenAI Realtime event (raw JSON) to the unified DeepIntShield format.
func (provider *OpenAIProvider) ToDeepIntShieldRealtimeEvent(providerEvent json.RawMessage) (*schemas.DeepIntShieldRealtimeEvent, error) {
	var raw openAIRealtimeEvent
	if err := json.Unmarshal(providerEvent, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OpenAI realtime event: %w", err)
	}

	event := &schemas.DeepIntShieldRealtimeEvent{
		Type:    schemas.RealtimeEventType(raw.Type),
		EventID: raw.EventID,
		RawData: providerEvent,
	}

	switch {
	case raw.Session != nil:
		var sess openAIRealtimeSession
		if err := json.Unmarshal(raw.Session, &sess); err == nil {
			event.Session = &schemas.RealtimeSession{
				ID:               sess.ID,
				Model:            sess.Model,
				Modalities:       sess.Modalities,
				Instructions:     sess.Instructions,
				Voice:            sess.Voice,
				Temperature:      sess.Temperature,
				MaxOutputTokens:  sess.MaxOutputTokens,
				TurnDetection:    sess.TurnDetection,
				InputAudioFormat: sess.InputAudioFormat,
				OutputAudioType:  sess.OutputAudioType,
				Tools:            sess.Tools,
			}
		}

	case raw.Item != nil:
		var item openAIRealtimeItem
		if err := json.Unmarshal(raw.Item, &item); err == nil {
			event.Item = &schemas.RealtimeItem{
				ID:        item.ID,
				Type:      item.Type,
				Role:      item.Role,
				Status:    item.Status,
				Content:   item.Content,
				Name:      item.Name,
				CallID:    item.CallID,
				Arguments: item.Arguments,
				Output:    item.Output,
			}
		}

	case raw.Error != nil:
		var rtErr openAIRealtimeError
		if err := json.Unmarshal(raw.Error, &rtErr); err == nil {
			event.Error = &schemas.RealtimeError{
				Type:    rtErr.Type,
				Code:    rtErr.Code,
				Message: rtErr.Message,
				Param:   rtErr.Param,
			}
		}
	}

	if isRealtimeDeltaEvent(raw.Type) {
		event.Delta = &schemas.RealtimeDelta{
			Text:       raw.Text,
			Audio:      raw.Audio,
			Transcript: raw.Transcript,
			ItemID:     raw.ItemID,
			OutputIdx:  &raw.OutputIndex,
			ContentIdx: &raw.ContentIndex,
			ResponseID: raw.ResponseID,
		}
		if raw.Delta != "" {
			if event.Delta.Text == "" {
				event.Delta.Text = raw.Delta
			}
		}
	}

	return event, nil
}

// ToProviderRealtimeEvent converts a unified DeepIntShield Realtime event back to OpenAI's native JSON.
func (provider *OpenAIProvider) ToProviderRealtimeEvent(deepintshieldEvent *schemas.DeepIntShieldRealtimeEvent) (json.RawMessage, error) {
	if deepintshieldEvent.RawData != nil {
		return deepintshieldEvent.RawData, nil
	}

	out := map[string]interface{}{
		"type": string(deepintshieldEvent.Type),
	}
	if deepintshieldEvent.EventID != "" {
		out["event_id"] = deepintshieldEvent.EventID
	}

	if deepintshieldEvent.Session != nil {
		sess := map[string]interface{}{}
		if deepintshieldEvent.Session.Model != "" {
			sess["model"] = deepintshieldEvent.Session.Model
		}
		if len(deepintshieldEvent.Session.Modalities) > 0 {
			sess["modalities"] = deepintshieldEvent.Session.Modalities
		}
		if deepintshieldEvent.Session.Instructions != "" {
			sess["instructions"] = deepintshieldEvent.Session.Instructions
		}
		if deepintshieldEvent.Session.Voice != "" {
			sess["voice"] = deepintshieldEvent.Session.Voice
		}
		if deepintshieldEvent.Session.Temperature != nil {
			sess["temperature"] = *deepintshieldEvent.Session.Temperature
		}
		if deepintshieldEvent.Session.MaxOutputTokens != nil {
			sess["max_output_tokens"] = deepintshieldEvent.Session.MaxOutputTokens
		}
		if deepintshieldEvent.Session.TurnDetection != nil {
			sess["turn_detection"] = deepintshieldEvent.Session.TurnDetection
		}
		if deepintshieldEvent.Session.InputAudioFormat != "" {
			sess["input_audio_format"] = deepintshieldEvent.Session.InputAudioFormat
		}
		if deepintshieldEvent.Session.OutputAudioType != "" {
			sess["output_audio_type"] = deepintshieldEvent.Session.OutputAudioType
		}
		if deepintshieldEvent.Session.Tools != nil {
			sess["tools"] = deepintshieldEvent.Session.Tools
		}
		out["session"] = sess
	}

	if deepintshieldEvent.Item != nil {
		item := map[string]interface{}{
			"type": deepintshieldEvent.Item.Type,
		}
		if deepintshieldEvent.Item.ID != "" {
			item["id"] = deepintshieldEvent.Item.ID
		}
		if deepintshieldEvent.Item.Role != "" {
			item["role"] = deepintshieldEvent.Item.Role
		}
		if deepintshieldEvent.Item.Content != nil {
			item["content"] = deepintshieldEvent.Item.Content
		}
		if deepintshieldEvent.Item.Name != "" {
			item["name"] = deepintshieldEvent.Item.Name
		}
		if deepintshieldEvent.Item.CallID != "" {
			item["call_id"] = deepintshieldEvent.Item.CallID
		}
		if deepintshieldEvent.Item.Arguments != "" {
			item["arguments"] = deepintshieldEvent.Item.Arguments
		}
		if deepintshieldEvent.Item.Output != "" {
			item["output"] = deepintshieldEvent.Item.Output
		}
		out["item"] = item
	}

	if deepintshieldEvent.Delta != nil {
		if deepintshieldEvent.Delta.Text != "" {
			out["delta"] = deepintshieldEvent.Delta.Text
		}
		if deepintshieldEvent.Delta.Audio != "" {
			out["audio"] = deepintshieldEvent.Delta.Audio
		}
		if deepintshieldEvent.Delta.Transcript != "" {
			out["transcript"] = deepintshieldEvent.Delta.Transcript
		}
		if deepintshieldEvent.Delta.ItemID != "" {
			out["item_id"] = deepintshieldEvent.Delta.ItemID
		}
		if deepintshieldEvent.Delta.OutputIdx != nil {
			out["output_index"] = *deepintshieldEvent.Delta.OutputIdx
		}
		if deepintshieldEvent.Delta.ContentIdx != nil {
			out["content_index"] = *deepintshieldEvent.Delta.ContentIdx
		}
		if deepintshieldEvent.Delta.ResponseID != "" {
			out["response_id"] = deepintshieldEvent.Delta.ResponseID
		}
	}

	return json.Marshal(out)
}

func isRealtimeDeltaEvent(eventType string) bool {
	switch eventType {
	case "response.text.delta",
		"response.audio.delta",
		"response.audio_transcript.delta",
		"conversation.item.input_audio_transcription.delta":
		return true
	}
	return false
}
