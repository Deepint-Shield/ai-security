package perplexity

import (
	"github.com/deepint-shield/ai-security/core/schemas"
)

// ToPerplexityResponsesRequest converts a DeepIntShieldResponsesRequest to PerplexityChatRequest
func ToPerplexityResponsesRequest(deepintshieldReq *schemas.DeepIntShieldResponsesRequest) *PerplexityChatRequest {
	if deepintshieldReq == nil {
		return nil
	}

	perplexityReq := &PerplexityChatRequest{
		Model: deepintshieldReq.Model,
	}

	// Map basic parameters
	if deepintshieldReq.Params != nil {
		// Core parameters
		perplexityReq.MaxTokens = deepintshieldReq.Params.MaxOutputTokens
		perplexityReq.Temperature = deepintshieldReq.Params.Temperature
		perplexityReq.TopP = deepintshieldReq.Params.TopP

		// Handle reasoning effort mapping
		if deepintshieldReq.Params.Reasoning != nil && deepintshieldReq.Params.Reasoning.Effort != nil {
			if *deepintshieldReq.Params.Reasoning.Effort == "minimal" {
				perplexityReq.ReasoningEffort = schemas.Ptr("low")
			} else {
				perplexityReq.ReasoningEffort = schemas.Ptr(*deepintshieldReq.Params.Reasoning.Effort)
			}
		}

		// Handle extra parameters for Perplexity-specific fields
		if deepintshieldReq.Params.ExtraParams != nil {
			// Search-related parameters
			if searchMode, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["search_mode"]); ok {
				perplexityReq.SearchMode = searchMode
			}

			if languagePreference, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["language_preference"]); ok {
				perplexityReq.LanguagePreference = languagePreference
			}

			if searchDomainFilter, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["search_domain_filter"]); ok {
				perplexityReq.SearchDomainFilter = searchDomainFilter
			}

			if returnImages, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["return_images"]); ok {
				perplexityReq.ReturnImages = returnImages
			}

			if returnRelatedQuestions, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["return_related_questions"]); ok {
				perplexityReq.ReturnRelatedQuestions = returnRelatedQuestions
			}

			if searchRecencyFilter, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["search_recency_filter"]); ok {
				perplexityReq.SearchRecencyFilter = searchRecencyFilter
			}

			if searchAfterDateFilter, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["search_after_date_filter"]); ok {
				perplexityReq.SearchAfterDateFilter = searchAfterDateFilter
			}

			if searchBeforeDateFilter, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["search_before_date_filter"]); ok {
				perplexityReq.SearchBeforeDateFilter = searchBeforeDateFilter
			}

			if lastUpdatedAfterFilter, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["last_updated_after_filter"]); ok {
				perplexityReq.LastUpdatedAfterFilter = lastUpdatedAfterFilter
			}

			if lastUpdatedBeforeFilter, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["last_updated_before_filter"]); ok {
				perplexityReq.LastUpdatedBeforeFilter = lastUpdatedBeforeFilter
			}

			if topK, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["top_k"]); ok {
				perplexityReq.TopK = topK
			}

			if stream, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["stream"]); ok {
				perplexityReq.Stream = stream
			}

			if disableSearch, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["disable_search"]); ok {
				perplexityReq.DisableSearch = disableSearch
			}

			if enableSearchClassifier, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["enable_search_classifier"]); ok {
				perplexityReq.EnableSearchClassifier = enableSearchClassifier
			}

			if presencePenalty, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["presence_penalty"]); ok {
				perplexityReq.PresencePenalty = presencePenalty
			}

			if frequencyPenalty, ok := schemas.SafeExtractFloat64Pointer(deepintshieldReq.Params.ExtraParams["frequency_penalty"]); ok {
				perplexityReq.FrequencyPenalty = frequencyPenalty
			}

			if responseFormat, ok := schemas.SafeExtractFromMap(deepintshieldReq.Params.ExtraParams, "response_format"); ok {
				perplexityReq.ResponseFormat = &responseFormat
			}

			// Perplexity-specific request fields
			if numSearchResults, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["num_search_results"]); ok {
				perplexityReq.NumSearchResults = numSearchResults
			}

			if numImages, ok := schemas.SafeExtractIntPointer(deepintshieldReq.Params.ExtraParams["num_images"]); ok {
				perplexityReq.NumImages = numImages
			}

			if searchLanguageFilter, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["search_language_filter"]); ok {
				perplexityReq.SearchLanguageFilter = searchLanguageFilter
			}

			if imageFormatFilter, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["image_format_filter"]); ok {
				perplexityReq.ImageFormatFilter = imageFormatFilter
			}

			if imageDomainFilter, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["image_domain_filter"]); ok {
				perplexityReq.ImageDomainFilter = imageDomainFilter
			}

			if safeSearch, ok := schemas.SafeExtractBoolPointer(deepintshieldReq.Params.ExtraParams["safe_search"]); ok {
				perplexityReq.SafeSearch = safeSearch
			}

			if streamMode, ok := schemas.SafeExtractStringPointer(deepintshieldReq.Params.ExtraParams["stream_mode"]); ok {
				perplexityReq.StreamMode = streamMode
			}

			// Handle web_search_options
			if webSearchOptionsParam, ok := schemas.SafeExtractFromMap(deepintshieldReq.Params.ExtraParams, "web_search_options"); ok {
				if webSearchOptionsSlice, ok := webSearchOptionsParam.([]interface{}); ok {
					var webSearchOptions []WebSearchOption
					for _, optionInterface := range webSearchOptionsSlice {
						if optionMap, ok := optionInterface.(map[string]interface{}); ok {
							option := WebSearchOption{}

							if searchContextSize, ok := schemas.SafeExtractStringPointer(optionMap["search_context_size"]); ok {
								option.SearchContextSize = searchContextSize
							}

							if imageResultsEnhancedRelevance, ok := schemas.SafeExtractBoolPointer(optionMap["image_results_enhanced_relevance"]); ok {
								option.ImageResultsEnhancedRelevance = imageResultsEnhancedRelevance
							}

							if searchType, ok := schemas.SafeExtractStringPointer(optionMap["search_type"]); ok {
								option.SearchType = searchType
							}

							// Handle user_location
							if userLocationParam, ok := schemas.SafeExtractFromMap(optionMap, "user_location"); ok {
								if userLocationMap, ok := userLocationParam.(map[string]interface{}); ok {
									userLocation := &WebSearchOptionUserLocation{}

									if latitude, ok := schemas.SafeExtractFloat64Pointer(userLocationMap["latitude"]); ok {
										userLocation.Latitude = latitude
									}
									if longitude, ok := schemas.SafeExtractFloat64Pointer(userLocationMap["longitude"]); ok {
										userLocation.Longitude = longitude
									}
									if city, ok := schemas.SafeExtractStringPointer(userLocationMap["city"]); ok {
										userLocation.City = city
									}
									if country, ok := schemas.SafeExtractStringPointer(userLocationMap["country"]); ok {
										userLocation.Country = country
									}
									if region, ok := schemas.SafeExtractStringPointer(userLocationMap["region"]); ok {
										userLocation.Region = region
									}

									option.UserLocation = userLocation
								}
							}

							webSearchOptions = append(webSearchOptions, option)
						}
					}
					perplexityReq.WebSearchOptions = webSearchOptions
				}
			}

			// Handle media_response
			if mediaResponseParam, ok := schemas.SafeExtractFromMap(deepintshieldReq.Params.ExtraParams, "media_response"); ok {
				if mediaResponseMap, ok := mediaResponseParam.(map[string]interface{}); ok {
					mediaResponse := &MediaResponse{}

					if overridesParam, ok := schemas.SafeExtractFromMap(mediaResponseMap, "overrides"); ok {
						if overridesMap, ok := overridesParam.(map[string]interface{}); ok {
							overrides := MediaResponseOverrides{}

							if returnVideos, ok := schemas.SafeExtractBoolPointer(overridesMap["return_videos"]); ok {
								overrides.ReturnVideos = returnVideos
							}
							if returnImages, ok := schemas.SafeExtractBoolPointer(overridesMap["return_images"]); ok {
								overrides.ReturnImages = returnImages
							}

							mediaResponse.Overrides = overrides
						}
					}

					perplexityReq.MediaResponse = mediaResponse
				}
			}
		}
	}

	// Process ResponsesInput (which contains the Responses messages)
	if deepintshieldReq.Input != nil {
		perplexityReq.Messages = schemas.ToChatMessages(deepintshieldReq.Input)
	}

	return perplexityReq
}
