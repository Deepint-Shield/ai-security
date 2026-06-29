package providers

import (
	"encoding/json"
	"fmt"
	"strings"
)

func StringValue(source map[string]any, keys ...string) string {
	for _, key := range keys {
		if source == nil {
			return ""
		}
		raw, ok := source[key]
		if !ok || raw == nil {
			continue
		}
		switch typed := raw.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case fmt.Stringer:
			if strings.TrimSpace(typed.String()) != "" {
				return strings.TrimSpace(typed.String())
			}
		default:
			rendered := strings.TrimSpace(fmt.Sprintf("%v", raw))
			if rendered != "" && rendered != "<nil>" {
				return rendered
			}
		}
	}
	return ""
}

func JSONString(source map[string]any, keys ...string) string {
	for _, key := range keys {
		raw, ok := source[key]
		if !ok || raw == nil {
			continue
		}
		switch typed := raw.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		default:
			encoded, err := json.Marshal(raw)
			if err == nil && len(encoded) > 0 {
				return string(encoded)
			}
		}
	}
	return ""
}

func StringSliceValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			rendered := strings.TrimSpace(fmt.Sprintf("%v", item))
			if rendered != "" && rendered != "<nil>" {
				values = append(values, rendered)
			}
		}
		return values
	default:
		return nil
	}
}
