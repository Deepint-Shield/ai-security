package elevenlabs

import (
	"github.com/deepint-shield/ai-security/core/schemas"
)

func ToElevenlabsSpeechRequest(deepintshieldReq *schemas.DeepIntShieldSpeechRequest) *ElevenlabsSpeechRequest {
	if deepintshieldReq == nil || deepintshieldReq.Input == nil {
		return nil
	}

	elevenlabsReq := &ElevenlabsSpeechRequest{
		ModelID: deepintshieldReq.Model,
		Text:    deepintshieldReq.Input.Input,
	}

	if deepintshieldReq.Params != nil {
		elevenlabsReq.ExtraParams = deepintshieldReq.Params.ExtraParams
		voiceSettings := ElevenlabsVoiceSettings{}
		hasVoiceSettings := false

		if deepintshieldReq.Params.Speed != nil {
			voiceSettings.Speed = *deepintshieldReq.Params.Speed
			hasVoiceSettings = true
		}

		if deepintshieldReq.Params.ExtraParams != nil {
			if stability, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["stability"]); ok {
				delete(elevenlabsReq.ExtraParams, "stability")
				voiceSettings.Stability = *stability
				hasVoiceSettings = true
			}
			if useSpeakerBoost, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["use_speaker_boost"]); ok {
				delete(elevenlabsReq.ExtraParams, "use_speaker_boost")
				voiceSettings.UseSpeakerBoost = *useSpeakerBoost
				hasVoiceSettings = true
			}
			if similarityBoost, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["similarity_boost"]); ok {
				delete(elevenlabsReq.ExtraParams, "similarity_boost")
				voiceSettings.SimilarityBoost = *similarityBoost
				hasVoiceSettings = true
			}
			if style, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["style"]); ok {
				delete(elevenlabsReq.ExtraParams, "style")
				voiceSettings.Style = *style
				hasVoiceSettings = true
			}
			if seed, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["seed"]); ok {
				delete(elevenlabsReq.ExtraParams, "seed")
				elevenlabsReq.Seed = seed
			}
			if previousText, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["previous_text"]); ok {
				delete(elevenlabsReq.ExtraParams, "previous_text")
				elevenlabsReq.PreviousText = previousText
			}
			if nextText, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["next_text"]); ok {
				delete(elevenlabsReq.ExtraParams, "next_text")
				elevenlabsReq.NextText = nextText
			}
			if previousRequestIDs, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["previous_request_ids"]); ok {
				delete(elevenlabsReq.ExtraParams, "previous_request_ids")
				elevenlabsReq.PreviousRequestIDs = previousRequestIDs
			}
			if nextRequestIDs, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["next_request_ids"]); ok {
				delete(elevenlabsReq.ExtraParams, "next_request_ids")
				elevenlabsReq.NextRequestIDs = nextRequestIDs
			}
			if applyTextNormalization, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["apply_text_normalization"]); ok {
				delete(elevenlabsReq.ExtraParams, "apply_text_normalization")
				elevenlabsReq.ApplyTextNormalization = applyTextNormalization
			}
			if applyLanguageTextNormalization, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["apply_language_text_normalization"]); ok {
				delete(elevenlabsReq.ExtraParams, "apply_language_text_normalization")
				elevenlabsReq.ApplyLanguageTextNormalization = applyLanguageTextNormalization
			}
			if usePVCAsIVC, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["use_pvc_as_ivc"]); ok {
				delete(elevenlabsReq.ExtraParams, "use_pvc_as_ivc")
				elevenlabsReq.UsePVCAsIVC = usePVCAsIVC
			}
		}

		if hasVoiceSettings {
			elevenlabsReq.VoiceSettings = &voiceSettings
		}

		if deepintshieldReq.Params.LanguageCode != nil {
			elevenlabsReq.LanguageCode = deepintshieldReq.Params.LanguageCode
		}

		if len(deepintshieldReq.Params.PronunciationDictionaryLocators) > 0 {
			elevenlabsReq.PronunciationDictionaryLocators = make([]ElevenlabsPronunciationDictionaryLocator, len(deepintshieldReq.Params.PronunciationDictionaryLocators))
			for i, locator := range deepintshieldReq.Params.PronunciationDictionaryLocators {
				elevenlabsReq.PronunciationDictionaryLocators[i] = ElevenlabsPronunciationDictionaryLocator{
					PronunciationDictionaryID: locator.PronunciationDictionaryID,
					VersionID:                 locator.VersionID,
				}
			}
		}
	}

	return elevenlabsReq
}
