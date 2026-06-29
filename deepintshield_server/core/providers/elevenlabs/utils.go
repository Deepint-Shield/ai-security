package elevenlabs

var (
	// Maps provider-specific finish reasons to DeepIntShield format
	deepintshieldToElevenlabsSpeechFormat = map[string]string{
		"":     "mp3_44100_128",
		"mp3":  "mp3_44100_128",
		"opus": "opus_48000_128",
		"wav":  "pcm_44100",
		"pcm":  "pcm_44100",
	}

	// Maps DeepIntShield finish reasons to provider-specific format
	elevenlabsSpeechFormatToDeepIntShield = map[string]string{
		"mp3_44100_128":  "mp3",
		"opus_48000_128": "opus",
		"pcm_44100":      "wav",
	}
)

// ConvertDeepIntShieldSpeechFormatToElevenlabs converts DeepIntShield speech format to Elevenlabs format
func ConvertDeepIntShieldSpeechFormatToElevenlabs(format string) string {
	if elevenlabsFormat, ok := deepintshieldToElevenlabsSpeechFormat[format]; ok {
		return elevenlabsFormat
	}
	return format
}

// ConvertElevenlabsSpeechFormatToDeepIntShield converts Elevenlabs speech format to DeepIntShield format
func ConvertElevenlabsSpeechFormatToDeepIntShield(format string) string {
	if deepintshieldFormat, ok := elevenlabsSpeechFormatToDeepIntShield[format]; ok {
		return deepintshieldFormat
	}
	return format
}
