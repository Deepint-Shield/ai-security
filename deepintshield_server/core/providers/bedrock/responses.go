package bedrock

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/deepint-shield/ai-security/core/providers/anthropic"
	providerUtils "github.com/deepint-shield/ai-security/core/providers/utils"
	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/google/uuid"
)

// BedrockResponsesStreamState tracks state during streaming conversion for responses API
type BedrockResponsesStreamState struct {
	ContentIndexToOutputIndex map[int]int    // Maps Bedrock contentBlockIndex to OpenAI output_index
	ToolArgumentBuffers       map[int]string // Maps output_index to accumulated tool argument JSON
	ItemIDs                   map[int]string // Maps output_index to item ID for stable IDs
	ToolCallIDs               map[int]string // Maps output_index to tool call ID (callID)
	ToolCallNames             map[int]string // Maps output_index to tool call name
	ReasoningContentIndices   map[int]bool   // Tracks which content indices are reasoning blocks
	CompletedOutputIndices    map[int]bool   // Tracks which output indices have been completed
	CurrentOutputIndex        int            // Current output index counter
	MessageID                 *string        // Message ID (generated)
	Model                     *string        // Model name
	StopReason                *string        // Stop reason for the message
	CreatedAt                 int            // Timestamp for created_at consistency
	HasEmittedCreated         bool           // Whether we've emitted response.created
	HasEmittedInProgress      bool           // Whether we've emitted response.in_progress
}

// bedrockResponsesStreamStatePool provides a pool for Bedrock responses stream state objects.
var bedrockResponsesStreamStatePool = sync.Pool{
	New: func() interface{} {
		return &BedrockResponsesStreamState{
			ContentIndexToOutputIndex: make(map[int]int),
			ToolArgumentBuffers:       make(map[int]string),
			ItemIDs:                   make(map[int]string),
			ToolCallIDs:               make(map[int]string),
			ToolCallNames:             make(map[int]string),
			ReasoningContentIndices:   make(map[int]bool),
			CompletedOutputIndices:    make(map[int]bool),
			CurrentOutputIndex:        0,
			CreatedAt:                 int(time.Now().Unix()),
			HasEmittedCreated:         false,
			HasEmittedInProgress:      false,
		}
	},
}

// acquireBedrockResponsesStreamState gets a Bedrock responses stream state from the pool.
func acquireBedrockResponsesStreamState() *BedrockResponsesStreamState {
	state := bedrockResponsesStreamStatePool.Get().(*BedrockResponsesStreamState)
	// Clear maps (they're already initialized from New or previous flush)
	// Only initialize if nil (shouldn't happen, but defensive)
	if state.ContentIndexToOutputIndex == nil {
		state.ContentIndexToOutputIndex = make(map[int]int)
	} else {
		clear(state.ContentIndexToOutputIndex)
	}
	if state.ToolArgumentBuffers == nil {
		state.ToolArgumentBuffers = make(map[int]string)
	} else {
		clear(state.ToolArgumentBuffers)
	}
	if state.ItemIDs == nil {
		state.ItemIDs = make(map[int]string)
	} else {
		clear(state.ItemIDs)
	}
	if state.ToolCallIDs == nil {
		state.ToolCallIDs = make(map[int]string)
	} else {
		clear(state.ToolCallIDs)
	}
	if state.ToolCallNames == nil {
		state.ToolCallNames = make(map[int]string)
	} else {
		clear(state.ToolCallNames)
	}
	if state.ReasoningContentIndices == nil {
		state.ReasoningContentIndices = make(map[int]bool)
	} else {
		clear(state.ReasoningContentIndices)
	}
	if state.CompletedOutputIndices == nil {
		state.CompletedOutputIndices = make(map[int]bool)
	} else {
		clear(state.CompletedOutputIndices)
	}
	// Reset other fields
	state.CurrentOutputIndex = 0
	state.MessageID = nil
	state.Model = nil
	state.StopReason = nil
	state.CreatedAt = int(time.Now().Unix())
	state.HasEmittedCreated = false
	state.HasEmittedInProgress = false
	return state
}

// releaseBedrockResponsesStreamState returns a Bedrock responses stream state to the pool.
func releaseBedrockResponsesStreamState(state *BedrockResponsesStreamState) {
	if state != nil {
		state.flush() // Clean before returning to pool
		bedrockResponsesStreamStatePool.Put(state)
	}
}

func (state *BedrockResponsesStreamState) flush() {
	// Clear maps (reuse if already initialized, otherwise initialize)
	if state.ContentIndexToOutputIndex == nil {
		state.ContentIndexToOutputIndex = make(map[int]int)
	} else {
		clear(state.ContentIndexToOutputIndex)
	}
	if state.ToolArgumentBuffers == nil {
		state.ToolArgumentBuffers = make(map[int]string)
	} else {
		clear(state.ToolArgumentBuffers)
	}
	if state.ItemIDs == nil {
		state.ItemIDs = make(map[int]string)
	} else {
		clear(state.ItemIDs)
	}
	if state.ToolCallIDs == nil {
		state.ToolCallIDs = make(map[int]string)
	} else {
		clear(state.ToolCallIDs)
	}
	if state.ToolCallNames == nil {
		state.ToolCallNames = make(map[int]string)
	} else {
		clear(state.ToolCallNames)
	}
	if state.ReasoningContentIndices == nil {
		state.ReasoningContentIndices = make(map[int]bool)
	} else {
		clear(state.ReasoningContentIndices)
	}
	if state.CompletedOutputIndices == nil {
		state.CompletedOutputIndices = make(map[int]bool)
	} else {
		clear(state.CompletedOutputIndices)
	}
	state.CurrentOutputIndex = 0
	state.MessageID = nil
	state.Model = nil
	state.StopReason = nil
	state.CreatedAt = int(time.Now().Unix())
	state.HasEmittedCreated = false
	state.HasEmittedInProgress = false
}

// ToDeepIntShieldResponsesStream converts a Bedrock stream event to a DeepIntShield Responses Stream response
// Returns a slice of responses to support cases where a single event produces multiple responses
func (chunk *BedrockStreamEvent) ToDeepIntShieldResponsesStream(sequenceNumber int, state *BedrockResponsesStreamState) ([]*schemas.DeepIntShieldResponsesStreamResponse, *schemas.DeepIntShieldError, bool) {
	switch {
	case chunk.Role != nil:
		// Message start - emit response.created and response.in_progress (OpenAI-style lifecycle)
		var responses []*schemas.DeepIntShieldResponsesStreamResponse

		// Generate message ID if not already set
		if state.MessageID == nil {
			messageID := fmt.Sprintf("msg_%d", state.CreatedAt)
			state.MessageID = &messageID
		}

		// Emit response.created
		if !state.HasEmittedCreated {
			response := &schemas.DeepIntShieldResponsesResponse{
				ID:        state.MessageID,
				CreatedAt: state.CreatedAt,
			}
			if state.Model != nil {
				response.Model = *state.Model
			}
			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeCreated,
				SequenceNumber: sequenceNumber,
				Response:       response,
			})
			state.HasEmittedCreated = true
		}

		// Emit response.in_progress
		if !state.HasEmittedInProgress {
			response := &schemas.DeepIntShieldResponsesResponse{
				ID:        state.MessageID,
				CreatedAt: state.CreatedAt, // Use same timestamp
			}
			if state.Model != nil {
				response.Model = *state.Model
			}
			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeInProgress,
				SequenceNumber: sequenceNumber + len(responses),
				Response:       response,
			})
			state.HasEmittedInProgress = true
		}

		// Don't pre-create any items here - let each content block create its own item when it first appears

		if len(responses) > 0 {
			return responses, nil, false
		}

	case chunk.Start != nil:
		// Handle content block start (text content or tool use)
		contentBlockIndex := 0
		if chunk.ContentBlockIndex != nil {
			contentBlockIndex = *chunk.ContentBlockIndex
		}

		// Check if this is a tool use start
		if chunk.Start.ToolUse != nil {
			var responses []*schemas.DeepIntShieldResponsesStreamResponse

			// Close any open reasoning blocks first (Anthropic sends content_block_stop before starting new blocks)
			for prevContentIndex := range state.ReasoningContentIndices {
				prevOutputIndex, prevExists := state.ContentIndexToOutputIndex[prevContentIndex]
				if !prevExists {
					continue
				}

				// Skip already completed output indices
				if state.CompletedOutputIndices[prevOutputIndex] {
					continue
				}

				itemID := state.ItemIDs[prevOutputIndex]

				// For reasoning items, content_index is always 0
				reasoningContentIndex := 0

				// Emit reasoning_summary_text.done
				emptyText := ""
				reasoningDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   &reasoningContentIndex,
					Text:           &emptyText,
				}
				if itemID != "" {
					reasoningDoneResponse.ItemID = &itemID
				}
				responses = append(responses, reasoningDoneResponse)

				// Emit content_part.done for reasoning
				part := &schemas.ResponsesMessageContentBlock{
					Type: schemas.ResponsesOutputMessageContentTypeReasoning,
					Text: &emptyText,
				}
				partDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   &reasoningContentIndex,
					Part:           part,
				}
				if itemID != "" {
					partDoneResponse.ItemID = &itemID
				}
				responses = append(responses, partDoneResponse)

				// Emit output_item.done for reasoning
				statusCompleted := "completed"
				messageType := schemas.ResponsesMessageTypeReasoning
				role := schemas.ResponsesInputMessageRoleAssistant
				doneItem := &schemas.ResponsesMessage{
					Type:   &messageType,
					Role:   &role,
					Status: &statusCompleted,
					ResponsesReasoning: &schemas.ResponsesReasoning{
						Summary: []schemas.ResponsesReasoningSummary{},
					},
				}
				if itemID != "" {
					doneItem.ID = &itemID
				}
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   &reasoningContentIndex,
					Item:           doneItem,
				})

				// Mark this output index as completed
				state.CompletedOutputIndices[prevOutputIndex] = true
			}
			// Clear reasoning content indices after closing them
			clear(state.ReasoningContentIndices)

			// Close any open text blocks before starting tool calls
			// This ensures all text content is closed before tool calls begin
			for prevContentIndex, prevOutputIndex := range state.ContentIndexToOutputIndex {
				// Skip reasoning blocks (already handled above)
				if state.ReasoningContentIndices[prevContentIndex] {
					continue
				}

				// Skip already completed output indices
				if state.CompletedOutputIndices[prevOutputIndex] {
					continue
				}

				// Check if this is a text block (not a tool call)
				prevToolCallID := state.ToolCallIDs[prevOutputIndex]
				if prevToolCallID != "" {
					continue // This is a tool call, skip it for now
				}

				// This is a text block - close it
				prevItemID := state.ItemIDs[prevOutputIndex]
				if prevItemID == "" {
					continue
				}

				// Emit output_text.done
				emptyText := ""
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputTextDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   &prevContentIndex,
					ItemID:         &prevItemID,
					Text:           &emptyText,
					LogProbs:       []schemas.ResponsesOutputMessageContentTextLogProb{},
				})

				// Emit content_part.done for text
				part := &schemas.ResponsesMessageContentBlock{
					Type: schemas.ResponsesOutputMessageContentTypeText,
					Text: &emptyText,
					ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
						LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
						Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
					},
				}
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   &prevContentIndex,
					ItemID:         &prevItemID,
					Part:           part,
				})

				// Emit output_item.done for text
				statusCompleted := "completed"
				messageType := schemas.ResponsesMessageTypeMessage
				role := schemas.ResponsesInputMessageRoleAssistant
				doneItem := &schemas.ResponsesMessage{
					Type:   &messageType,
					Role:   &role,
					Status: &statusCompleted,
					Content: &schemas.ResponsesMessageContent{
						ContentBlocks: []schemas.ResponsesMessageContentBlock{},
					},
				}
				if prevItemID != "" {
					doneItem.ID = &prevItemID
				}
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   &prevContentIndex,
					Item:           doneItem,
				})

				// Mark this output index as completed
				state.CompletedOutputIndices[prevOutputIndex] = true
			}

			// Close any open tool call blocks before starting a new one (Anthropic completes each block before starting next)
			for prevContentIndex, prevOutputIndex := range state.ContentIndexToOutputIndex {
				// Skip reasoning blocks (already handled above)
				if state.ReasoningContentIndices[prevContentIndex] {
					continue
				}

				// Skip already completed output indices
				if state.CompletedOutputIndices[prevOutputIndex] {
					continue
				}

				// Check if this is a tool call
				prevToolCallID := state.ToolCallIDs[prevOutputIndex]
				if prevToolCallID == "" {
					continue // Not a tool call
				}

				prevItemID := state.ItemIDs[prevOutputIndex]
				prevToolName := state.ToolCallNames[prevOutputIndex]
				accumulatedArgs := state.ToolArgumentBuffers[prevOutputIndex]

				// Emit content_part.done for tool call
				emptyText := ""
				part := &schemas.ResponsesMessageContentBlock{
					Type: schemas.ResponsesOutputMessageContentTypeText,
					Text: &emptyText,
					ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
						LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
						Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
					},
				}
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   schemas.Ptr(prevContentIndex),
					ItemID:         &prevItemID,
					Part:           part,
				})

				// Emit function_call_arguments.done with full arguments
				if accumulatedArgs != "" {
					var doneItem *schemas.ResponsesMessage
					if prevToolCallID != "" || prevToolName != "" {
						doneItem = &schemas.ResponsesMessage{
							ResponsesToolMessage: &schemas.ResponsesToolMessage{},
						}
						if prevToolCallID != "" {
							doneItem.ResponsesToolMessage.CallID = &prevToolCallID
						}
						if prevToolName != "" {
							doneItem.ResponsesToolMessage.Name = &prevToolName
						}
					}

					argsDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
						Type:           schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone,
						SequenceNumber: sequenceNumber + len(responses),
						OutputIndex:    schemas.Ptr(prevOutputIndex),
						Arguments:      &accumulatedArgs,
					}
					if prevItemID != "" {
						argsDoneResponse.ItemID = &prevItemID
					}
					if doneItem != nil {
						argsDoneResponse.Item = doneItem
					}
					responses = append(responses, argsDoneResponse)
				}

				// Emit output_item.done for tool call
				statusCompleted := "completed"
				toolDoneItem := &schemas.ResponsesMessage{
					ID:     &prevItemID,
					Type:   schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall),
					Status: &statusCompleted,
					ResponsesToolMessage: &schemas.ResponsesToolMessage{
						CallID:    &prevToolCallID,
						Name:      &prevToolName,
						Arguments: &accumulatedArgs,
					},
				}

				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(prevOutputIndex),
					ContentIndex:   schemas.Ptr(prevContentIndex),
					ItemID:         &prevItemID,
					Item:           toolDoneItem,
				})

				// Mark this output index as completed
				state.CompletedOutputIndices[prevOutputIndex] = true
			}

			// Create new output index for this tool use
			outputIndex := state.CurrentOutputIndex
			state.ContentIndexToOutputIndex[contentBlockIndex] = outputIndex
			state.CurrentOutputIndex++ // Increment for next use

			// Store tool use ID as item ID and call ID
			toolUseID := chunk.Start.ToolUse.ToolUseID
			toolName := chunk.Start.ToolUse.Name
			state.ItemIDs[outputIndex] = toolUseID
			state.ToolCallIDs[outputIndex] = toolUseID
			state.ToolCallNames[outputIndex] = toolName

			statusInProgress := "in_progress"
			item := &schemas.ResponsesMessage{
				ID:     &toolUseID,
				Type:   schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall),
				Status: &statusInProgress,
				ResponsesToolMessage: &schemas.ResponsesToolMessage{
					CallID:    &toolUseID,
					Name:      &toolName,
					Arguments: schemas.Ptr(""), // Arguments will be filled by deltas
				},
			}

			// Initialize argument buffer for this tool call
			state.ToolArgumentBuffers[outputIndex] = ""

			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeOutputItemAdded,
				SequenceNumber: sequenceNumber + len(responses),
				OutputIndex:    schemas.Ptr(outputIndex),
				ContentIndex:   schemas.Ptr(contentBlockIndex),
				Item:           item,
			})

			return responses, nil, false
		}
		// Text content start is handled by Role event, so we can ignore Start for text

	case chunk.ContentBlockIndex != nil && chunk.Delta != nil:
		// Handle contentBlockDelta event
		contentBlockIndex := *chunk.ContentBlockIndex
		outputIndex, exists := state.ContentIndexToOutputIndex[contentBlockIndex]
		if !exists {
			// Check if this is a new content block that should close previous reasoning blocks
			var responses []*schemas.DeepIntShieldResponsesStreamResponse

			// If this is a text delta with a new content block index, close any open reasoning blocks
			if chunk.Delta.Text != nil && contentBlockIndex > 0 {
				for prevContentIndex := range state.ReasoningContentIndices {
					if prevContentIndex < contentBlockIndex {
						prevOutputIndex, prevExists := state.ContentIndexToOutputIndex[prevContentIndex]
						if !prevExists {
							continue
						}

						itemID := state.ItemIDs[prevOutputIndex]

						// For reasoning items, content_index is always 0
						reasoningContentIndex := 0

						// Emit reasoning_summary_text.done
						emptyText := ""
						reasoningDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
							SequenceNumber: sequenceNumber + len(responses),
							OutputIndex:    schemas.Ptr(prevOutputIndex),
							ContentIndex:   &reasoningContentIndex,
							Text:           &emptyText,
						}
						if itemID != "" {
							reasoningDoneResponse.ItemID = &itemID
						}
						responses = append(responses, reasoningDoneResponse)

						// Emit content_part.done for reasoning
						part := &schemas.ResponsesMessageContentBlock{
							Type: schemas.ResponsesOutputMessageContentTypeReasoning,
							Text: &emptyText,
						}
						partDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
							SequenceNumber: sequenceNumber + len(responses),
							OutputIndex:    schemas.Ptr(prevOutputIndex),
							ContentIndex:   &reasoningContentIndex,
							Part:           part,
						}
						if itemID != "" {
							partDoneResponse.ItemID = &itemID
						}
						responses = append(responses, partDoneResponse)

						// Emit output_item.done for reasoning
						statusCompleted := "completed"
						messageType := schemas.ResponsesMessageTypeReasoning
						role := schemas.ResponsesInputMessageRoleAssistant
						doneItem := &schemas.ResponsesMessage{
							Type:   &messageType,
							Role:   &role,
							Status: &statusCompleted,
							ResponsesReasoning: &schemas.ResponsesReasoning{
								Summary: []schemas.ResponsesReasoningSummary{},
							},
						}
						if itemID != "" {
							doneItem.ID = &itemID
						}
						responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
							Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
							SequenceNumber: sequenceNumber + len(responses),
							OutputIndex:    schemas.Ptr(prevOutputIndex),
							ContentIndex:   &reasoningContentIndex,
							Item:           doneItem,
						})

						// Clear the reasoning content index tracking
						delete(state.ReasoningContentIndices, prevContentIndex)

						// Mark this output index as completed
						state.CompletedOutputIndices[prevOutputIndex] = true
					}
				}
			}

			// Create new output index for this content block
			outputIndex = state.CurrentOutputIndex
			state.CurrentOutputIndex++
			state.ContentIndexToOutputIndex[contentBlockIndex] = outputIndex

			// If this is a text delta for a new content block, create the text item
			if chunk.Delta.Text != nil {
				// Generate stable ID for text item
				var itemID string
				if state.MessageID == nil {
					itemID = fmt.Sprintf("item_%d", outputIndex)
				} else {
					itemID = fmt.Sprintf("msg_%s_item_%d", *state.MessageID, outputIndex)
				}
				state.ItemIDs[outputIndex] = itemID

				// Create text item
				messageType := schemas.ResponsesMessageTypeMessage
				role := schemas.ResponsesInputMessageRoleAssistant
				item := &schemas.ResponsesMessage{
					ID:   &itemID,
					Type: &messageType,
					Role: &role,
					Content: &schemas.ResponsesMessageContent{
						ContentBlocks: []schemas.ResponsesMessageContentBlock{}, // Empty blocks slice for mutation support
					},
				}

				// Emit output_item.added for text
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputItemAdded,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					Item:           item,
				})

				// Emit content_part.added with empty output_text part
				emptyText := ""
				part := &schemas.ResponsesMessageContentBlock{
					Type: schemas.ResponsesOutputMessageContentTypeText,
					Text: &emptyText,
					ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
						LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
						Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
					},
				}
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeContentPartAdded,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					ItemID:         &itemID,
					Part:           part,
				})
			}

			// If this is a text delta for a new content block, also emit the text delta in the same batch
			if chunk.Delta.Text != nil && *chunk.Delta.Text != "" {
				text := *chunk.Delta.Text
				itemID := state.ItemIDs[outputIndex]
				textDeltaResponse := &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputTextDelta,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					Delta:          &text,
					LogProbs:       []schemas.ResponsesOutputMessageContentTextLogProb{},
				}
				if itemID != "" {
					textDeltaResponse.ItemID = &itemID
				}
				responses = append(responses, textDeltaResponse)
			}

			// If we have responses to return (either from closing reasoning or creating text item), return them first
			if len(responses) > 0 {
				return responses, nil, false
			}
		}

		switch {
		case chunk.Delta.Text != nil:
			// Handle text delta
			text := *chunk.Delta.Text
			if text != "" {
				itemID := state.ItemIDs[outputIndex]
				response := &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputTextDelta,
					SequenceNumber: sequenceNumber,
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					Delta:          &text,
					LogProbs:       []schemas.ResponsesOutputMessageContentTextLogProb{},
				}
				if itemID != "" {
					response.ItemID = &itemID
				}
				return []*schemas.DeepIntShieldResponsesStreamResponse{response}, nil, false
			}

		case chunk.Delta.ToolUse != nil:
			// Handle tool use delta - function call arguments
			toolUseDelta := chunk.Delta.ToolUse

			if toolUseDelta.Input != "" {
				// Accumulate argument deltas
				state.ToolArgumentBuffers[outputIndex] += toolUseDelta.Input

				itemID := state.ItemIDs[outputIndex]
				response := &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
					SequenceNumber: sequenceNumber,
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					Delta:          &toolUseDelta.Input,
				}
				if itemID != "" {
					response.ItemID = &itemID
				}
				return []*schemas.DeepIntShieldResponsesStreamResponse{response}, nil, false
			}

		case chunk.Delta.ReasoningContent != nil:
			// Handle reasoning content delta
			reasoningDelta := chunk.Delta.ReasoningContent

			// Check if this is the first reasoning delta for this content block
			if !state.ReasoningContentIndices[contentBlockIndex] {
				// First reasoning delta - emit output_item.added and content_part.added
				var responses []*schemas.DeepIntShieldResponsesStreamResponse

				// Generate stable ID for reasoning item
				var itemID string
				if state.MessageID == nil {
					itemID = fmt.Sprintf("reasoning_%d", outputIndex)
				} else {
					itemID = fmt.Sprintf("msg_%s_reasoning_%d", *state.MessageID, outputIndex)
				}
				state.ItemIDs[outputIndex] = itemID

				// Create reasoning item
				messageType := schemas.ResponsesMessageTypeReasoning
				role := schemas.ResponsesInputMessageRoleAssistant
				item := &schemas.ResponsesMessage{
					ID:   &itemID,
					Type: &messageType,
					Role: &role,
					ResponsesReasoning: &schemas.ResponsesReasoning{
						Summary: []schemas.ResponsesReasoningSummary{},
					},
				}

				// Preserve signature if present
				if reasoningDelta.Signature != nil {
					item.ResponsesReasoning.EncryptedContent = reasoningDelta.Signature
				}

				// Track that this content index is a reasoning block
				state.ReasoningContentIndices[contentBlockIndex] = true

				// Emit output_item.added
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeOutputItemAdded,
					SequenceNumber: sequenceNumber,
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					Item:           item,
				})

				// Emit content_part.added with empty reasoning_text part
				emptyText := ""
				part := &schemas.ResponsesMessageContentBlock{
					Type: schemas.ResponsesOutputMessageContentTypeReasoning,
					Text: &emptyText,
				}
				// Preserve signature in the content part if present
				if reasoningDelta.Signature != nil {
					part.Signature = reasoningDelta.Signature
				}
				responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeContentPartAdded,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(outputIndex),
					ContentIndex:   &contentBlockIndex,
					ItemID:         &itemID,
					Part:           part,
				})

				// If there's text content, also emit the delta
				if reasoningDelta.Text != nil && *reasoningDelta.Text != "" {
					deltaResponse := &schemas.DeepIntShieldResponsesStreamResponse{
						Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
						SequenceNumber: sequenceNumber + len(responses),
						OutputIndex:    schemas.Ptr(outputIndex),
						ContentIndex:   &contentBlockIndex,
						Delta:          reasoningDelta.Text,
						ItemID:         &itemID,
					}
					responses = append(responses, deltaResponse)
				}

				return responses, nil, false
			} else {
				// Subsequent reasoning deltas - just emit the delta
				if reasoningDelta.Text != nil && *reasoningDelta.Text != "" {
					itemID := state.ItemIDs[outputIndex]
					response := &schemas.DeepIntShieldResponsesStreamResponse{
						Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
						SequenceNumber: sequenceNumber,
						OutputIndex:    schemas.Ptr(outputIndex),
						ContentIndex:   &contentBlockIndex,
						Delta:          reasoningDelta.Text,
					}
					if itemID != "" {
						response.ItemID = &itemID
					}
					return []*schemas.DeepIntShieldResponsesStreamResponse{response}, nil, false
				}

				// Handle signature deltas
				if reasoningDelta.Signature != nil {
					itemID := state.ItemIDs[outputIndex]
					response := &schemas.DeepIntShieldResponsesStreamResponse{
						Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
						SequenceNumber: sequenceNumber,
						OutputIndex:    schemas.Ptr(outputIndex),
						ContentIndex:   &contentBlockIndex,
						Signature:      reasoningDelta.Signature, // Use signature field instead of delta
					}
					if itemID != "" {
						response.ItemID = &itemID
					}
					return []*schemas.DeepIntShieldResponsesStreamResponse{response}, nil, false
				}
			}
		}

	case chunk.StopReason != nil:
		// Stop reason - track it for the final response
		var stopReason string
		switch *chunk.StopReason {
		case "tool_use":
			stopReason = "tool_calls"
		case "end_turn":
			stopReason = "stop"
		case "max_tokens":
			stopReason = "length"
		default:
			stopReason = *chunk.StopReason
		}
		state.StopReason = &stopReason
		// Items should be closed explicitly when content blocks end
		return nil, nil, false
	}

	return nil, nil, false
}

// FinalizeBedrockStream finalizes the stream by closing any open items and emitting completed event
func FinalizeBedrockStream(state *BedrockResponsesStreamState, sequenceNumber int, usage *schemas.ResponsesResponseUsage) []*schemas.DeepIntShieldResponsesStreamResponse {
	var responses []*schemas.DeepIntShieldResponsesStreamResponse

	// Close any open items (text items and tool calls)
	for contentIndex, outputIndex := range state.ContentIndexToOutputIndex {
		// Skip reasoning blocks
		if state.ReasoningContentIndices[contentIndex] {
			continue
		}

		// Skip already completed output indices
		if state.CompletedOutputIndices[outputIndex] {
			continue
		}

		itemID := state.ItemIDs[outputIndex]
		if itemID == "" {
			continue
		}

		// Check if this is a tool call by looking at the tool call IDs
		toolCallID := state.ToolCallIDs[outputIndex]
		isToolCall := toolCallID != ""

		if isToolCall {
			// This is a tool call that needs to be closed

			// Emit content_part.done for tool call
			emptyText := ""
			part := &schemas.ResponsesMessageContentBlock{
				Type: schemas.ResponsesOutputMessageContentTypeText,
				Text: &emptyText,
				ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
					LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
					Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
				},
			}
			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
				SequenceNumber: sequenceNumber + len(responses),
				OutputIndex:    schemas.Ptr(outputIndex),
				ContentIndex:   &contentIndex,
				ItemID:         &itemID,
				Part:           part,
			})

			// Emit function_call_arguments.done with full arguments
			toolName := state.ToolCallNames[outputIndex]
			accumulatedArgs := state.ToolArgumentBuffers[outputIndex]
			if accumulatedArgs != "" {
				var doneItem *schemas.ResponsesMessage
				if toolCallID != "" || toolName != "" {
					doneItem = &schemas.ResponsesMessage{
						ResponsesToolMessage: &schemas.ResponsesToolMessage{},
					}
					if toolCallID != "" {
						doneItem.ResponsesToolMessage.CallID = &toolCallID
					}
					if toolName != "" {
						doneItem.ResponsesToolMessage.Name = &toolName
					}
				}

				response := &schemas.DeepIntShieldResponsesStreamResponse{
					Type:           schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone,
					SequenceNumber: sequenceNumber + len(responses),
					OutputIndex:    schemas.Ptr(outputIndex),
					Arguments:      &accumulatedArgs,
				}
				if itemID != "" {
					response.ItemID = &itemID
				}
				if doneItem != nil {
					response.Item = doneItem
				}
				responses = append(responses, response)
			}

			// Emit output_item.done for tool call
			statusCompleted := "completed"
			doneItem := &schemas.ResponsesMessage{
				ID:     &itemID,
				Type:   schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall),
				Status: &statusCompleted,
				ResponsesToolMessage: &schemas.ResponsesToolMessage{
					CallID:    &toolCallID,
					Name:      &toolName,
					Arguments: &accumulatedArgs,
				},
			}

			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
				SequenceNumber: sequenceNumber + len(responses),
				OutputIndex:    schemas.Ptr(outputIndex),
				ContentIndex:   &contentIndex,
				ItemID:         &itemID,
				Item:           doneItem,
			})
		} else {
			// This is likely a text item that needs to be closed

			// Emit output_text.done (without accumulated text, just the event)
			emptyText := ""
			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeOutputTextDone,
				SequenceNumber: sequenceNumber + len(responses),
				OutputIndex:    schemas.Ptr(outputIndex),
				ContentIndex:   &contentIndex,
				ItemID:         &itemID,
				Text:           &emptyText,
				LogProbs:       []schemas.ResponsesOutputMessageContentTextLogProb{},
			})

			// Emit content_part.done for text
			part := &schemas.ResponsesMessageContentBlock{
				Type: schemas.ResponsesOutputMessageContentTypeText,
				Text: &emptyText,
				ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
					LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
					Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
				},
			}
			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
				SequenceNumber: sequenceNumber + len(responses),
				OutputIndex:    schemas.Ptr(outputIndex),
				ContentIndex:   &contentIndex,
				ItemID:         &itemID,
				Part:           part,
			})

			// Emit output_item.done for text
			statusCompleted := "completed"
			messageType := schemas.ResponsesMessageTypeMessage
			role := schemas.ResponsesInputMessageRoleAssistant
			doneItem := &schemas.ResponsesMessage{
				Type:   &messageType,
				Role:   &role,
				Status: &statusCompleted,
				Content: &schemas.ResponsesMessageContent{
					ContentBlocks: []schemas.ResponsesMessageContentBlock{},
				},
			}
			if itemID != "" {
				doneItem.ID = &itemID
			}
			responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
				Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
				SequenceNumber: sequenceNumber + len(responses),
				OutputIndex:    schemas.Ptr(outputIndex),
				ContentIndex:   &contentIndex,
				Item:           doneItem,
			})
		}

		// Mark this output index as completed
		state.CompletedOutputIndices[outputIndex] = true
	}

	// Close any open reasoning items
	for contentIndex := range state.ReasoningContentIndices {
		outputIndex, exists := state.ContentIndexToOutputIndex[contentIndex]
		if !exists {
			continue
		}

		// Skip already completed output indices
		if state.CompletedOutputIndices[outputIndex] {
			continue
		}

		itemID := state.ItemIDs[outputIndex]

		// For reasoning items, content_index is always 0 (reasoning content is the first and only content part)
		reasoningContentIndex := 0

		// Emit reasoning_summary_text.done
		emptyText := ""
		reasoningDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
			Type:           schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone,
			SequenceNumber: sequenceNumber + len(responses),
			OutputIndex:    schemas.Ptr(outputIndex),
			ContentIndex:   &reasoningContentIndex,
			Text:           &emptyText,
		}
		if itemID != "" {
			reasoningDoneResponse.ItemID = &itemID
		}
		responses = append(responses, reasoningDoneResponse)

		// Emit content_part.done for reasoning
		part := &schemas.ResponsesMessageContentBlock{
			Type: schemas.ResponsesOutputMessageContentTypeReasoning,
			Text: &emptyText,
		}
		partDoneResponse := &schemas.DeepIntShieldResponsesStreamResponse{
			Type:           schemas.ResponsesStreamResponseTypeContentPartDone,
			SequenceNumber: sequenceNumber + len(responses),
			OutputIndex:    schemas.Ptr(outputIndex),
			ContentIndex:   &reasoningContentIndex,
			Part:           part,
		}
		if itemID != "" {
			partDoneResponse.ItemID = &itemID
		}
		responses = append(responses, partDoneResponse)

		// Emit output_item.done for reasoning
		statusCompleted := "completed"
		messageType := schemas.ResponsesMessageTypeReasoning
		role := schemas.ResponsesInputMessageRoleAssistant
		doneItem := &schemas.ResponsesMessage{
			Type:   &messageType,
			Role:   &role,
			Status: &statusCompleted,
			ResponsesReasoning: &schemas.ResponsesReasoning{
				Summary: []schemas.ResponsesReasoningSummary{},
			},
		}
		if itemID != "" {
			doneItem.ID = &itemID
		}
		responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
			Type:           schemas.ResponsesStreamResponseTypeOutputItemDone,
			SequenceNumber: sequenceNumber + len(responses),
			OutputIndex:    schemas.Ptr(outputIndex),
			ContentIndex:   &reasoningContentIndex,
			Item:           doneItem,
		})

		// Mark this output index as completed
		state.CompletedOutputIndices[outputIndex] = true
	}

	// Note: Tool calls are already closed in the first loop above.
	// This section is intentionally left empty to avoid duplicate events.

	if usage.InputTokensDetails != nil {
		usage.InputTokens = usage.InputTokens + usage.InputTokensDetails.CachedReadTokens + usage.InputTokensDetails.CachedWriteTokens
	}

	// Emit response.completed
	response := &schemas.DeepIntShieldResponsesResponse{
		ID:        state.MessageID,
		CreatedAt: state.CreatedAt,
		Usage:     usage,
	}

	if state.Model != nil {
		response.Model = *state.Model
	}
	if state.StopReason != nil {
		response.StopReason = state.StopReason
	} else {
		// Infer stop reason based on whether tool calls are present
		hasToolCalls := false
		for _, toolCallID := range state.ToolCallIDs {
			if toolCallID != "" {
				hasToolCalls = true
				break
			}
		}
		if hasToolCalls {
			response.StopReason = schemas.Ptr("tool_calls")
		} else {
			response.StopReason = schemas.Ptr("stop")
		}
	}

	responses = append(responses, &schemas.DeepIntShieldResponsesStreamResponse{
		Type:           schemas.ResponsesStreamResponseTypeCompleted,
		SequenceNumber: sequenceNumber + len(responses),
		Response:       response,
	})

	return responses
}

// ToBedrockConverseStreamResponse converts a DeepIntShield Responses stream response to Bedrock streaming format
// Returns a BedrockStreamEvent that represents the streaming event in Bedrock's format
func ToBedrockConverseStreamResponse(deepintshieldResp *schemas.DeepIntShieldResponsesStreamResponse) (*BedrockStreamEvent, error) {
	if deepintshieldResp == nil {
		return nil, fmt.Errorf("deepintshield stream response is nil")
	}

	event := &BedrockStreamEvent{}

	switch deepintshieldResp.Type {
	case schemas.ResponsesStreamResponseTypeCreated:
		// Message start - emit role event
		// Always set role for message start event
		role := "assistant"
		event.Role = &role

	case schemas.ResponsesStreamResponseTypeInProgress:
		// In progress - no-op for Bedrock (it doesn't have an explicit in_progress event)
		// Return nil to skip this event
		return nil, nil

	case schemas.ResponsesStreamResponseTypeOutputItemAdded:
		// Content block start
		if deepintshieldResp.Item != nil && deepintshieldResp.Item.ResponsesToolMessage != nil {
			// Tool use start
			if deepintshieldResp.Item.ResponsesToolMessage.Name != nil && deepintshieldResp.Item.ResponsesToolMessage.CallID != nil {
				contentBlockIndex := 0
				if deepintshieldResp.ContentIndex != nil {
					contentBlockIndex = *deepintshieldResp.ContentIndex
				}
				event.ContentBlockIndex = &contentBlockIndex
				event.Start = &BedrockContentBlockStart{
					ToolUse: &BedrockToolUseStart{
						ToolUseID: *deepintshieldResp.Item.ResponsesToolMessage.CallID,
						Name:      *deepintshieldResp.Item.ResponsesToolMessage.Name,
					},
				}
			}
		} else if deepintshieldResp.Item != nil {
			// Text item added - Bedrock doesn't have an explicit text start event, so we skip it
			// Check if it's a text message (has content blocks or is a message type)
			if deepintshieldResp.Item.Content != nil || (deepintshieldResp.Item.Type != nil && *deepintshieldResp.Item.Type == schemas.ResponsesMessageTypeMessage) {
				return nil, nil
			}
		}

	case schemas.ResponsesStreamResponseTypeOutputTextDelta:
		// Text delta
		if deepintshieldResp.Delta != nil && *deepintshieldResp.Delta != "" {
			contentBlockIndex := 0
			if deepintshieldResp.ContentIndex != nil {
				contentBlockIndex = *deepintshieldResp.ContentIndex
			}
			event.ContentBlockIndex = &contentBlockIndex
			event.Delta = &BedrockContentBlockDelta{
				Text: deepintshieldResp.Delta,
			}
		} else {
			// Skip empty deltas
			return nil, nil
		}

	case schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta:
		// Tool use delta (function call arguments)
		if deepintshieldResp.Delta != nil {
			contentBlockIndex := 0
			if deepintshieldResp.ContentIndex != nil {
				contentBlockIndex = *deepintshieldResp.ContentIndex
			}
			event.ContentBlockIndex = &contentBlockIndex
			event.Delta = &BedrockContentBlockDelta{
				ToolUse: &BedrockToolUseDelta{
					Input: *deepintshieldResp.Delta,
				},
			}
		}

	case schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta:
		// Reasoning content delta
		contentBlockIndex := 0
		if deepintshieldResp.ContentIndex != nil {
			contentBlockIndex = *deepintshieldResp.ContentIndex
		}
		event.ContentBlockIndex = &contentBlockIndex

		// Check if this is a signature delta or text delta
		if deepintshieldResp.Signature != nil {
			// This is a signature delta
			event.Delta = &BedrockContentBlockDelta{
				ReasoningContent: &BedrockReasoningContentText{
					Signature: deepintshieldResp.Signature,
				},
			}
		} else if deepintshieldResp.Delta != nil && *deepintshieldResp.Delta != "" {
			// This is reasoning text delta
			event.Delta = &BedrockContentBlockDelta{
				ReasoningContent: &BedrockReasoningContentText{
					Text: deepintshieldResp.Delta,
				},
			}
		} else {
			// Skip empty deltas
			return nil, nil
		}

	case schemas.ResponsesStreamResponseTypeOutputTextDone,
		schemas.ResponsesStreamResponseTypeContentPartDone,
		schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone:
		// Content block done - Bedrock doesn't have explicit done events, so we skip them
		return nil, nil

	case schemas.ResponsesStreamResponseTypeOutputItemDone:
		// Item done - Bedrock doesn't have explicit done events, so we skip them
		return nil, nil

	case schemas.ResponsesStreamResponseTypeCompleted:
		// Message stop - always set stopReason
		stopReason := "end_turn"
		if deepintshieldResp.Response != nil && deepintshieldResp.Response.IncompleteDetails != nil {
			stopReason = deepintshieldResp.Response.IncompleteDetails.Reason
		}
		event.StopReason = &stopReason

		// Add usage if available
		if deepintshieldResp.Response != nil && deepintshieldResp.Response.Usage != nil {
			event.Usage = &BedrockTokenUsage{
				InputTokens:  deepintshieldResp.Response.Usage.InputTokens,
				OutputTokens: deepintshieldResp.Response.Usage.OutputTokens,
				TotalTokens:  deepintshieldResp.Response.Usage.TotalTokens,
			}
		}

	case schemas.ResponsesStreamResponseTypeError:
		// Error - errors are handled separately by the router via DeepIntShieldError in the stream chunk
		// Return nil to skip this chunk
		return nil, nil

	default:
		// Unknown type - skip
		return nil, nil
	}

	return event, nil
}

// BedrockEncodedEvent represents a single event ready for encoding to AWS Event Stream
type BedrockEncodedEvent struct {
	EventType string
	Payload   interface{}
}

// BedrockInvokeStreamChunkEvent represents the chunk event for invoke-with-response-stream
type BedrockInvokeStreamChunkEvent struct {
	Bytes []byte `json:"bytes"`
}

// ToEncodedEvents converts the flat BedrockStreamEvent into a sequence of specific events
func (event *BedrockStreamEvent) ToEncodedEvents() []BedrockEncodedEvent {
	var events []BedrockEncodedEvent

	if event.InvokeModelRawChunk != nil {
		events = append(events, BedrockEncodedEvent{
			EventType: "chunk",
			Payload: BedrockInvokeStreamChunkEvent{
				Bytes: event.InvokeModelRawChunk,
			},
		})
	}

	if event.Role != nil {
		events = append(events, BedrockEncodedEvent{
			EventType: "messageStart",
			Payload: BedrockMessageStartEvent{
				Role: *event.Role,
			},
		})
	}

	if event.Start != nil {
		events = append(events, BedrockEncodedEvent{
			EventType: "contentBlockStart",
			Payload: struct {
				Start             *BedrockContentBlockStart `json:"start"`
				ContentBlockIndex *int                      `json:"contentBlockIndex"`
			}{
				Start:             event.Start,
				ContentBlockIndex: event.ContentBlockIndex,
			},
		})
	}

	if event.Delta != nil {
		events = append(events, BedrockEncodedEvent{
			EventType: "contentBlockDelta",
			Payload: struct {
				Delta             *BedrockContentBlockDelta `json:"delta"`
				ContentBlockIndex *int                      `json:"contentBlockIndex"`
			}{
				Delta:             event.Delta,
				ContentBlockIndex: event.ContentBlockIndex,
			},
		})
	}

	if event.StopReason != nil {
		events = append(events, BedrockEncodedEvent{
			EventType: "messageStop",
			Payload: BedrockMessageStopEvent{
				StopReason: *event.StopReason,
			},
		})
	}

	if event.Usage != nil || event.Metrics != nil {
		events = append(events, BedrockEncodedEvent{
			EventType: "metadata",
			Payload: BedrockMetadataEvent{
				Usage:   event.Usage,
				Metrics: event.Metrics,
				Trace:   event.Trace,
			},
		})
	}

	return events
}

// ToDeepIntShieldResponsesRequest converts a BedrockConverseRequest to DeepIntShield Responses Request format
func (request *BedrockConverseRequest) ToDeepIntShieldResponsesRequest(ctx *schemas.DeepIntShieldContext) (*schemas.DeepIntShieldResponsesRequest, error) {
	if request == nil {
		return nil, fmt.Errorf("bedrock request is nil")
	}

	// Extract provider from model ID (format: "bedrock/model-name")
	provider, model := schemas.ParseModelString(request.ModelID, providerUtils.CheckAndSetDefaultProvider(ctx, schemas.Bedrock))

	deepintshieldReq := &schemas.DeepIntShieldResponsesRequest{
		Provider:  provider,
		Model:     model,
		Params:    &schemas.ResponsesParameters{},
		Fallbacks: schemas.ParseFallbacks(request.Fallbacks),
	}

	// Convert messages using the new conversion method
	convertedMessages := ConvertBedrockMessagesToDeepIntShieldMessages(ctx, request.Messages, request.System, false)
	deepintshieldReq.Input = convertedMessages

	// Convert inference config to parameters
	if request.InferenceConfig != nil {
		if request.InferenceConfig.MaxTokens != nil {
			deepintshieldReq.Params.MaxOutputTokens = request.InferenceConfig.MaxTokens
		}
		if request.InferenceConfig.Temperature != nil {
			deepintshieldReq.Params.Temperature = request.InferenceConfig.Temperature
		}
		if request.InferenceConfig.TopP != nil {
			deepintshieldReq.Params.TopP = request.InferenceConfig.TopP
		}
		if len(request.InferenceConfig.StopSequences) > 0 {
			if deepintshieldReq.Params.ExtraParams == nil {
				deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
			}
			deepintshieldReq.Params.ExtraParams["stop"] = request.InferenceConfig.StopSequences
		}
	}

	// Convert tool config
	if request.ToolConfig != nil && len(request.ToolConfig.Tools) > 0 {
		for _, tool := range request.ToolConfig.Tools {
			if tool.ToolSpec != nil {
				deepintshieldTool := schemas.ResponsesTool{
					Type:                  schemas.ResponsesToolTypeFunction,
					Name:                  &tool.ToolSpec.Name,
					Description:           tool.ToolSpec.Description,
					ResponsesToolFunction: &schemas.ResponsesToolFunction{},
				}

				// Handle different types for InputSchema.JSON
				if len(tool.ToolSpec.InputSchema.JSON) > 0 {
					var params schemas.ToolFunctionParameters
					if err := sonic.Unmarshal(tool.ToolSpec.InputSchema.JSON, &params); err == nil {
						deepintshieldTool.ResponsesToolFunction.Parameters = &params
					} else {
						// Fallback: unmarshal as map and convert
						var paramsMap map[string]interface{}
						if err := sonic.Unmarshal(tool.ToolSpec.InputSchema.JSON, &paramsMap); err == nil {
							params := convertMapToToolFunctionParameters(paramsMap)
							deepintshieldTool.ResponsesToolFunction.Parameters = params
						}
					}
				}

				deepintshieldReq.Params.Tools = append(deepintshieldReq.Params.Tools, deepintshieldTool)
			} else if tool.CachePoint != nil && !schemas.IsNovaModel(deepintshieldReq.Model) {
				// add cache control to last tool in tools array
				if len(deepintshieldReq.Params.Tools) > 0 {
					deepintshieldReq.Params.Tools[len(deepintshieldReq.Params.Tools)-1].CacheControl = &schemas.CacheControl{
						Type: schemas.CacheControlTypeEphemeral,
					}
				}
			}
		}
	}

	// Convert tool choice
	if request.ToolConfig != nil && request.ToolConfig.ToolChoice != nil {
		toolChoice := request.ToolConfig.ToolChoice
		if toolChoice.Auto != nil {
			autoStr := string(schemas.ResponsesToolChoiceTypeAuto)
			deepintshieldReq.Params.ToolChoice = &schemas.ResponsesToolChoice{
				ResponsesToolChoiceStr: &autoStr,
			}
		} else if toolChoice.Any != nil {
			anyStr := string(schemas.ResponsesToolChoiceTypeAny)
			deepintshieldReq.Params.ToolChoice = &schemas.ResponsesToolChoice{
				ResponsesToolChoiceStr: &anyStr,
			}
		} else if toolChoice.Tool != nil {
			deepintshieldReq.Params.ToolChoice = &schemas.ResponsesToolChoice{
				ResponsesToolChoiceStruct: &schemas.ResponsesToolChoiceStruct{
					Type: schemas.ResponsesToolChoiceTypeFunction,
					Name: &toolChoice.Tool.Name,
				},
			}
		}
	}

	// Convert guardrail config to extra params
	if request.GuardrailConfig != nil {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}

		guardrailMap := map[string]interface{}{
			"guardrailIdentifier": request.GuardrailConfig.GuardrailIdentifier,
			"guardrailVersion":    request.GuardrailConfig.GuardrailVersion,
		}
		if request.GuardrailConfig.Trace != nil {
			guardrailMap["trace"] = *request.GuardrailConfig.Trace
		}
		deepintshieldReq.Params.ExtraParams["guardrailConfig"] = guardrailMap
	}

	// Convert additional model request fields to extra params
	if request.AdditionalModelRequestFields.Len() > 0 {
		// Handle Anthropic thinking/reasoning_config format
		reasoningConfig, ok := request.AdditionalModelRequestFields.Get("thinking")
		if !ok {
			reasoningConfig, ok = request.AdditionalModelRequestFields.Get("reasoning_config")
		}
		if ok {
			if reasoningConfigMap, ok := reasoningConfig.(map[string]interface{}); ok {
				if typeStr, ok := schemas.SafeExtractString(reasoningConfigMap["type"]); ok {
					if typeStr == "enabled" || typeStr == "adaptive" {
						var summary *string
						if summaryValue, ok := schemas.SafeExtractStringPointer(request.ExtraParams["reasoning_summary"]); ok {
							summary = summaryValue
						}
						// Check for native output_config.effort first
						if outputConfig, ok := request.AdditionalModelRequestFields.Get("output_config"); ok {
							if outputConfigMap, ok := outputConfig.(map[string]interface{}); ok {
								if effortStr, ok := schemas.SafeExtractString(outputConfigMap["effort"]); ok {
									var maxTokens *int
									if budgetTokens, ok := schemas.SafeExtractInt(reasoningConfigMap["budget_tokens"]); ok {
										maxTokens = schemas.Ptr(budgetTokens)
									}
									deepintshieldReq.Params.Reasoning = &schemas.ResponsesParametersReasoning{
										Effort:    schemas.Ptr(effortStr),
										MaxTokens: maxTokens,
										Summary:   summary,
									}
								}
							}
						} else if maxTokens, ok := schemas.SafeExtractInt(reasoningConfigMap["budget_tokens"]); ok {
							// Fallback: convert budget_tokens to effort
							minBudgetTokens := 0
							defaultMaxTokens := DefaultCompletionMaxTokens
							if request.InferenceConfig != nil && request.InferenceConfig.MaxTokens != nil {
								defaultMaxTokens = *request.InferenceConfig.MaxTokens
							}
							if schemas.IsAnthropicModel(deepintshieldReq.Model) {
								minBudgetTokens = anthropic.MinimumReasoningMaxTokens
							}
							effort := providerUtils.GetReasoningEffortFromBudgetTokens(maxTokens, minBudgetTokens, defaultMaxTokens)
							deepintshieldReq.Params.Reasoning = &schemas.ResponsesParametersReasoning{
								Effort:    schemas.Ptr(effort),
								MaxTokens: schemas.Ptr(maxTokens),
								Summary:   summary,
							}
						} else {
							// Adaptive with no explicit effort - default to "high"
							deepintshieldReq.Params.Reasoning = &schemas.ResponsesParametersReasoning{
								Effort:  schemas.Ptr("high"),
								Summary: summary,
							}
						}
					} else {
						deepintshieldReq.Params.Reasoning = &schemas.ResponsesParametersReasoning{
							Effort: schemas.Ptr("none"),
						}
					}
				}
			}
		}

		// Handle Nova reasoningConfig format (camelCase)
		if novaReasoningConfig, ok := request.AdditionalModelRequestFields.Get("reasoningConfig"); ok {
			if novaReasoningConfigMap, ok := novaReasoningConfig.(map[string]interface{}); ok {
				if typeStr, ok := schemas.SafeExtractString(novaReasoningConfigMap["type"]); ok {
					if typeStr == "enabled" {
						// Extract maxReasoningEffort from Nova format
						if effortStr, ok := schemas.SafeExtractString(novaReasoningConfigMap["maxReasoningEffort"]); ok {
							deepintshieldReq.Params.Reasoning = &schemas.ResponsesParametersReasoning{
								Effort: schemas.Ptr(effortStr),
							}
						}
					} else if typeStr == "disabled" {
						deepintshieldReq.Params.Reasoning = &schemas.ResponsesParametersReasoning{
							Effort: schemas.Ptr("none"),
						}
					}
				}
			}
		}
	}

	if include, ok := schemas.SafeExtractStringSlice(request.ExtraParams["include"]); ok {
		deepintshieldReq.Params.Include = include
	}

	// Convert performance config to extra params
	if request.PerformanceConfig != nil {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}

		perfConfigMap := map[string]interface{}{}
		if request.PerformanceConfig.Latency != nil {
			perfConfigMap["latency"] = *request.PerformanceConfig.Latency
		}
		if len(perfConfigMap) > 0 {
			deepintshieldReq.Params.ExtraParams["performanceConfig"] = perfConfigMap
		}
	}

	// Convert prompt variables to extra params
	if len(request.PromptVariables) > 0 {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}

		promptVarsMap := make(map[string]interface{})
		for key, value := range request.PromptVariables {
			varMap := map[string]interface{}{}
			if value.Text != nil {
				varMap["text"] = *value.Text
			}
			if len(varMap) > 0 {
				promptVarsMap[key] = varMap
			}
		}
		if len(promptVarsMap) > 0 {
			deepintshieldReq.Params.ExtraParams["promptVariables"] = promptVarsMap
		}
	}

	// Convert request metadata to extra params
	if len(request.RequestMetadata) > 0 {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}
		deepintshieldReq.Params.ExtraParams["requestMetadata"] = request.RequestMetadata
	}

	// Convert additional model request fields to extra params
	if request.AdditionalModelRequestFields.Len() > 0 {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}
		deepintshieldReq.Params.ExtraParams["additionalModelRequestFieldPaths"] = request.AdditionalModelRequestFields
	}

	// Convert additional model response field paths to extra params
	if len(request.AdditionalModelResponseFieldPaths) > 0 {
		if deepintshieldReq.Params.ExtraParams == nil {
			deepintshieldReq.Params.ExtraParams = make(map[string]interface{})
		}
		deepintshieldReq.Params.ExtraParams["additionalModelResponseFieldPaths"] = request.AdditionalModelResponseFieldPaths
	}

	return deepintshieldReq, nil
}

// ToBedrockResponsesRequest converts a DeepIntShieldRequest (Responses structure) back to BedrockConverseRequest
func ToBedrockResponsesRequest(ctx *schemas.DeepIntShieldContext, deepintshieldReq *schemas.DeepIntShieldResponsesRequest) (*BedrockConverseRequest, error) {
	if deepintshieldReq == nil {
		return nil, fmt.Errorf("deepintshield request is nil")
	}

	// Validate tools are supported by Bedrock
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.Tools != nil {
		if toolErr := anthropic.ValidateToolsForProvider(deepintshieldReq.Params.Tools, schemas.Bedrock); toolErr != nil {
			return nil, toolErr
		}
	}

	bedrockReq := &BedrockConverseRequest{
		ModelID: deepintshieldReq.Model,
	}

	// map deepintshield messages to bedrock messages using the new conversion method
	if deepintshieldReq.Input != nil {
		messages, systemMessages, err := ConvertDeepIntShieldMessagesToBedrockMessages(deepintshieldReq.Input)
		if err != nil {
			return nil, fmt.Errorf("failed to convert Responses messages: %w", err)
		}
		bedrockReq.Messages = messages
		if len(systemMessages) > 0 {
			bedrockReq.System = systemMessages
		} else {
			if deepintshieldReq.Params != nil && deepintshieldReq.Params.Instructions != nil {
				// if no system messages, check if instructions are present
				bedrockReq.System = []BedrockSystemMessage{
					{
						Text: deepintshieldReq.Params.Instructions,
					},
				}
			}
		}
	}

	// Map basic parameters to inference config
	if deepintshieldReq.Params != nil {
		inferenceConfig := &BedrockInferenceConfig{}

		if deepintshieldReq.Params.MaxOutputTokens != nil {
			inferenceConfig.MaxTokens = deepintshieldReq.Params.MaxOutputTokens
		}
		if deepintshieldReq.Params.Temperature != nil {
			inferenceConfig.Temperature = deepintshieldReq.Params.Temperature
		}
		if deepintshieldReq.Params.TopP != nil {
			inferenceConfig.TopP = deepintshieldReq.Params.TopP
		}
		if deepintshieldReq.Params.Reasoning != nil {
			if bedrockReq.AdditionalModelRequestFields == nil {
				bedrockReq.AdditionalModelRequestFields = schemas.NewOrderedMap()
			}
			if deepintshieldReq.Params.Reasoning.MaxTokens != nil {
				tokenBudget := *deepintshieldReq.Params.Reasoning.MaxTokens
				if *deepintshieldReq.Params.Reasoning.MaxTokens == -1 {
					// bedrock does not support dynamic reasoning budget like gemini
					// setting it to default max tokens
					tokenBudget = anthropic.MinimumReasoningMaxTokens
				}
				if schemas.IsAnthropicModel(deepintshieldReq.Model) && tokenBudget < anthropic.MinimumReasoningMaxTokens {
					return nil, fmt.Errorf("reasoning.max_tokens must be >= %d for anthropic", anthropic.MinimumReasoningMaxTokens)
				}
				if schemas.IsAnthropicModel(deepintshieldReq.Model) {
					bedrockReq.AdditionalModelRequestFields.Set("thinking", map[string]any{
						"type":          "enabled",
						"budget_tokens": tokenBudget,
					})
				} else if schemas.IsNovaModel(deepintshieldReq.Model) {
					minBudgetTokens := MinimumReasoningMaxTokens
					defaultMaxTokens := DefaultCompletionMaxTokens
					if inferenceConfig.MaxTokens != nil {
						defaultMaxTokens = *inferenceConfig.MaxTokens
					} else {
						inferenceConfig.MaxTokens = schemas.Ptr(DefaultCompletionMaxTokens)
					}
					maxReasoningEffort := providerUtils.GetReasoningEffortFromBudgetTokens(tokenBudget, minBudgetTokens, defaultMaxTokens)
					typeStr := "enabled"
					switch maxReasoningEffort {
					case "high":
						inferenceConfig.MaxTokens = nil
						inferenceConfig.Temperature = nil
						inferenceConfig.TopP = nil
					case "minimal":
						maxReasoningEffort = "low"
					case "none":
						typeStr = "disabled"
					}

					config := map[string]any{
						"type": typeStr,
					}
					if typeStr != "disabled" {
						config["maxReasoningEffort"] = maxReasoningEffort
					}

					bedrockReq.AdditionalModelRequestFields.Set("reasoningConfig", config)
				}
			} else {
				if deepintshieldReq.Params.Reasoning.Effort != nil && *deepintshieldReq.Params.Reasoning.Effort != "none" {
					if schemas.IsNovaModel(deepintshieldReq.Model) {
						effort := *deepintshieldReq.Params.Reasoning.Effort
						typeStr := "enabled"
						switch effort {
						case "high":
							// for nova models we need to unset these fields at high effort
							inferenceConfig.MaxTokens = nil
							inferenceConfig.Temperature = nil
							inferenceConfig.TopP = nil
						case "low", "medium":
							// no special handling needed for low and medium
						case "minimal":
							effort = "low"
						case "none":
							typeStr = "disabled"
						}

						config := map[string]any{
							"type": typeStr,
						}
						if typeStr != "disabled" {
							config["maxReasoningEffort"] = effort
						}

						bedrockReq.AdditionalModelRequestFields.Set("reasoningConfig", config)
					} else if schemas.IsAnthropicModel(deepintshieldReq.Model) {
						if anthropic.SupportsAdaptiveThinking(deepintshieldReq.Model) {
							// Opus 4.6+: adaptive thinking + output_config.effort
							effort := anthropic.MapDeepIntShieldEffortToAnthropic(*deepintshieldReq.Params.Reasoning.Effort)
							bedrockReq.AdditionalModelRequestFields.Set("thinking", map[string]any{
								"type": "adaptive",
							})
							bedrockReq.AdditionalModelRequestFields.Set("output_config", map[string]any{
								"effort": effort,
							})
						} else {
							// Opus 4.5 and older Anthropic models: budget_tokens thinking
							defaultMaxTokens := DefaultCompletionMaxTokens
							if inferenceConfig.MaxTokens != nil {
								defaultMaxTokens = *inferenceConfig.MaxTokens
							} else {
								inferenceConfig.MaxTokens = schemas.Ptr(DefaultCompletionMaxTokens)
							}
							budgetTokens, err := providerUtils.GetBudgetTokensFromReasoningEffort(*deepintshieldReq.Params.Reasoning.Effort, anthropic.MinimumReasoningMaxTokens, defaultMaxTokens)
							if err != nil {
								return nil, err
							}
							bedrockReq.AdditionalModelRequestFields.Set("thinking", map[string]any{
								"type":          "enabled",
								"budget_tokens": budgetTokens,
							})
						}
					} else {
						// Non-Anthropic, non-Nova models: budget_tokens only
						minBudgetTokens := MinimumReasoningMaxTokens
						defaultMaxTokens := DefaultCompletionMaxTokens
						if inferenceConfig.MaxTokens != nil {
							defaultMaxTokens = *inferenceConfig.MaxTokens
						} else {
							inferenceConfig.MaxTokens = schemas.Ptr(DefaultCompletionMaxTokens)
						}
						budgetTokens, err := providerUtils.GetBudgetTokensFromReasoningEffort(*deepintshieldReq.Params.Reasoning.Effort, minBudgetTokens, defaultMaxTokens)
						if err != nil {
							return nil, err
						}
						bedrockReq.AdditionalModelRequestFields.Set("reasoning_config", map[string]any{
							"type":          "enabled",
							"budget_tokens": budgetTokens,
						})
					}
				} else {
					if schemas.IsAnthropicModel(deepintshieldReq.Model) {
						bedrockReq.AdditionalModelRequestFields.Set("thinking", map[string]any{
							"type": "disabled",
						})
					} else if schemas.IsNovaModel(deepintshieldReq.Model) {
						bedrockReq.AdditionalModelRequestFields.Set("reasoningConfig", map[string]any{
							"type": "disabled",
						})
					} else {
						bedrockReq.AdditionalModelRequestFields.Set("reasoning_config", map[string]any{
							"type": "disabled",
						})
					}
				}
			}
		}
		if deepintshieldReq.Params.Text != nil {
			if deepintshieldReq.Params.Text.Format != nil {
				responseFormatTool := convertTextFormatToTool(ctx, deepintshieldReq.Params.Text)
				// append to bedrockTools
				if responseFormatTool != nil {
					if bedrockReq.ToolConfig == nil {
						bedrockReq.ToolConfig = &BedrockToolConfig{}
					}
					bedrockReq.ToolConfig.Tools = append(bedrockReq.ToolConfig.Tools, *responseFormatTool)
					// Force the model to use this specific tool (same as ChatCompletion)
					bedrockReq.ToolConfig.ToolChoice = &BedrockToolChoice{
						Tool: &BedrockToolChoiceTool{
							Name: responseFormatTool.ToolSpec.Name,
						},
					}
				}
			}
		}
		if deepintshieldReq.Params.ExtraParams != nil {
			bedrockReq.ExtraParams = deepintshieldReq.Params.ExtraParams
			if stop, ok := schemas.SafeExtractStringSlice(deepintshieldReq.Params.ExtraParams["stop"]); ok {
				delete(bedrockReq.ExtraParams, "stop")
				inferenceConfig.StopSequences = stop
			}

			if requestFields, exists := deepintshieldReq.Params.ExtraParams["additionalModelRequestFieldPaths"]; exists {
				if orderedFields, ok := schemas.SafeExtractOrderedMap(requestFields); ok {
					delete(bedrockReq.ExtraParams, "additionalModelRequestFieldPaths")
					bedrockReq.AdditionalModelRequestFields = orderedFields
				}
			}

			if responseFields, exists := deepintshieldReq.Params.ExtraParams["additionalModelResponseFieldPaths"]; exists {
				if fields, ok := responseFields.([]string); ok {
					bedrockReq.AdditionalModelResponseFieldPaths = fields
				} else if fieldsInterface, ok := responseFields.([]interface{}); ok {
					stringFields := make([]string, 0, len(fieldsInterface))
					for _, field := range fieldsInterface {
						if fieldStr, ok := field.(string); ok {
							stringFields = append(stringFields, fieldStr)
						}
					}
					if len(stringFields) > 0 {
						bedrockReq.AdditionalModelResponseFieldPaths = stringFields
					}
				}
				if len(bedrockReq.AdditionalModelResponseFieldPaths) > 0 {
					delete(bedrockReq.ExtraParams, "additionalModelResponseFieldPaths")
				}
			}
		}

		bedrockReq.InferenceConfig = inferenceConfig

		if deepintshieldReq.Params.ServiceTier != nil {
			bedrockReq.ServiceTier = &BedrockServiceTier{
				Type: *deepintshieldReq.Params.ServiceTier,
			}
		}
	}

	// Convert tools
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.Tools != nil {
		var bedrockTools []BedrockTool
		for _, tool := range deepintshieldReq.Params.Tools {
			if tool.ResponsesToolFunction != nil {
				// Create the complete schema object that Bedrock expects
				var schemaObject interface{}
				if tool.ResponsesToolFunction.Parameters != nil {
					schemaObject = tool.ResponsesToolFunction.Parameters
				} else {
					// Fallback to empty object schema if no parameters
					schemaObject = map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
					}
				}

				if tool.Name == nil || *tool.Name == "" {
					return nil, fmt.Errorf("responses tool is missing required name for Bedrock function conversion")
				}
				name := *tool.Name

				// Use the tool description if available, otherwise use a generic description
				description := "Function tool"
				if tool.Description != nil {
					description = *tool.Description
				}

				schemaObjectBytes, err := providerUtils.MarshalSorted(schemaObject)
				if err != nil {
					return nil, fmt.Errorf("failed to serialize tool schema %q: %w", name, err)
				}
				bedrockTool := BedrockTool{
					ToolSpec: &BedrockToolSpec{
						Name:        name,
						Description: &description,
						InputSchema: BedrockToolInputSchema{
							JSON: json.RawMessage(schemaObjectBytes),
						},
					},
				}
				bedrockTools = append(bedrockTools, bedrockTool)

				if tool.CacheControl != nil && !schemas.IsNovaModel(deepintshieldReq.Model) {
					bedrockTools = append(bedrockTools, BedrockTool{
						CachePoint: &BedrockCachePoint{
							Type: BedrockCachePointTypeDefault,
						},
					})
				}
			}
		}

		if len(bedrockTools) > 0 {
			bedrockReq.ToolConfig = &BedrockToolConfig{
				Tools: bedrockTools,
			}
		}
	}

	// Convert tool choice
	if deepintshieldReq.Params != nil && deepintshieldReq.Params.ToolChoice != nil {
		bedrockToolChoice := convertResponsesToolChoice(*deepintshieldReq.Params.ToolChoice)
		if bedrockToolChoice != nil {
			if bedrockReq.ToolConfig == nil {
				bedrockReq.ToolConfig = &BedrockToolConfig{}
			}
			bedrockReq.ToolConfig.ToolChoice = bedrockToolChoice
		}
	}

	// Ensure tool config is present when tool content exists (similar to Chat Completions)
	ensureResponsesToolConfigForConversation(deepintshieldReq, bedrockReq)

	return bedrockReq, nil
}

// ToDeepIntShieldResponsesResponse converts BedrockConverseResponse to DeepIntShieldResponsesResponse
func (response *BedrockConverseResponse) ToDeepIntShieldResponsesResponse(ctx *schemas.DeepIntShieldContext) (*schemas.DeepIntShieldResponsesResponse, error) {
	if response == nil {
		return nil, fmt.Errorf("bedrock response is nil")
	}

	deepintshieldResp := &schemas.DeepIntShieldResponsesResponse{
		ID:        schemas.Ptr(uuid.New().String()),
		CreatedAt: int(time.Now().Unix()),
	}

	// Convert output message to Responses format using the new conversion method
	if response.Output != nil && response.Output.Message != nil {
		outputMessages := ConvertBedrockMessagesToDeepIntShieldMessages(ctx, []BedrockMessage{*response.Output.Message}, []BedrockSystemMessage{}, true)
		deepintshieldResp.Output = outputMessages
	}

	if response.Usage != nil {
		// Convert usage information
		deepintshieldResp.Usage = &schemas.ResponsesResponseUsage{
			InputTokens:  response.Usage.InputTokens,
			OutputTokens: response.Usage.OutputTokens,
			TotalTokens:  response.Usage.TotalTokens,
		}
		// Handle cached tokens if present
		if response.Usage.CacheReadInputTokens > 0 {
			if deepintshieldResp.Usage.InputTokensDetails == nil {
				deepintshieldResp.Usage.InputTokensDetails = &schemas.ResponsesResponseInputTokens{}
			}
			deepintshieldResp.Usage.InputTokensDetails.CachedReadTokens = response.Usage.CacheReadInputTokens
			deepintshieldResp.Usage.InputTokens = deepintshieldResp.Usage.InputTokens + response.Usage.CacheReadInputTokens
		}
		if response.Usage.CacheWriteInputTokens > 0 {
			if deepintshieldResp.Usage.InputTokensDetails == nil {
				deepintshieldResp.Usage.InputTokensDetails = &schemas.ResponsesResponseInputTokens{}
			}
			deepintshieldResp.Usage.InputTokensDetails.CachedWriteTokens = response.Usage.CacheWriteInputTokens
			deepintshieldResp.Usage.InputTokens = deepintshieldResp.Usage.InputTokens + response.Usage.CacheWriteInputTokens
		}
	}

	if response.ServiceTier != nil && response.ServiceTier.Type != "" {
		deepintshieldResp.ServiceTier = &response.ServiceTier.Type
	}

	return deepintshieldResp, nil
}

// ToBedrockConverseResponse converts DeepIntShield Responses response to Bedrock Converse response
func ToBedrockConverseResponse(deepintshieldResp *schemas.DeepIntShieldResponsesResponse) (*BedrockConverseResponse, error) {
	if deepintshieldResp == nil {
		return nil, fmt.Errorf("deepintshield response is nil")
	}

	bedrockResp := &BedrockConverseResponse{
		Output:  &BedrockConverseOutput{},
		Usage:   &BedrockTokenUsage{},
		Metrics: &BedrockConverseMetrics{},
	}

	var hasToolUse bool
	message := &BedrockMessage{
		Role:    BedrockMessageRoleAssistant,
		Content: []BedrockContentBlock{},
	}

	if len(deepintshieldResp.Output) > 0 {
		// Convert DeepIntShield messages back to Bedrock messages using the new conversion method
		bedrockMessages, _, err := ConvertDeepIntShieldMessagesToBedrockMessages(deepintshieldResp.Output)
		if err != nil {
			return nil, fmt.Errorf("failed to convert deepintshield output messages: %w", err)
		}

		// Merge all content blocks from converted messages into a single message
		for _, bedrockMsg := range bedrockMessages {
			message.Content = append(message.Content, bedrockMsg.Content...)
		}

		// Check for tool use in the content blocks
		for _, block := range message.Content {
			if block.ToolUse != nil {
				hasToolUse = true
				break
			}
		}
	}

	bedrockResp.Output.Message = message

	// Find stop reason from incomplete details or derive from response
	// Priority: IncompleteDetails > tool_use detection > end_turn
	stopReason := "end_turn"
	if deepintshieldResp.IncompleteDetails != nil {
		stopReason = deepintshieldResp.IncompleteDetails.Reason
	} else if hasToolUse {
		stopReason = "tool_use"
	}
	bedrockResp.StopReason = stopReason

	// Convert usage stats
	if deepintshieldResp.Usage != nil {
		bedrockResp.Usage.InputTokens = deepintshieldResp.Usage.InputTokens
		bedrockResp.Usage.OutputTokens = deepintshieldResp.Usage.OutputTokens
		bedrockResp.Usage.TotalTokens = deepintshieldResp.Usage.TotalTokens

		if deepintshieldResp.Usage.InputTokensDetails != nil {
			if deepintshieldResp.Usage.InputTokensDetails.CachedReadTokens > 0 {
				bedrockResp.Usage.CacheReadInputTokens = deepintshieldResp.Usage.InputTokensDetails.CachedReadTokens
				bedrockResp.Usage.InputTokens = bedrockResp.Usage.InputTokens - deepintshieldResp.Usage.InputTokensDetails.CachedReadTokens
			}
			if deepintshieldResp.Usage.InputTokensDetails.CachedWriteTokens > 0 {
				bedrockResp.Usage.CacheWriteInputTokens = deepintshieldResp.Usage.InputTokensDetails.CachedWriteTokens
				bedrockResp.Usage.InputTokens = bedrockResp.Usage.InputTokens - deepintshieldResp.Usage.InputTokensDetails.CachedWriteTokens
			}
		}
	}

	// Set metrics
	if deepintshieldResp.ExtraFields.Latency > 0 {
		bedrockResp.Metrics.LatencyMs = deepintshieldResp.ExtraFields.Latency
	}

	return bedrockResp, nil
}

// Helper functions

// ensureResponsesToolConfigForConversation ensures toolConfig is present when tool content exists
func ensureResponsesToolConfigForConversation(deepintshieldReq *schemas.DeepIntShieldResponsesRequest, bedrockReq *BedrockConverseRequest) {
	if bedrockReq.ToolConfig != nil {
		return // Already has tool config
	}

	hasToolContent, tools := extractToolsFromResponsesConversationHistory(deepintshieldReq.Input)
	if hasToolContent && len(tools) > 0 {
		bedrockReq.ToolConfig = &BedrockToolConfig{Tools: tools}
	}
}

// extractToolsFromResponsesConversationHistory extracts tools from Responses conversation history
func extractToolsFromResponsesConversationHistory(messages []schemas.ResponsesMessage) (bool, []BedrockTool) {
	var hasToolContent bool
	toolMap := make(map[string]*schemas.ResponsesTool) // Use map to deduplicate by name

	for _, msg := range messages {
		// Check if message contains tool use or tool result
		if msg.Type != nil {
			switch *msg.Type {
			case schemas.ResponsesMessageTypeFunctionCall, schemas.ResponsesMessageTypeFunctionCallOutput:
				hasToolContent = true
				// Try to infer tool definition from tool call/result
				if msg.ResponsesToolMessage != nil && msg.ResponsesToolMessage.Name != nil {
					toolName := *msg.ResponsesToolMessage.Name
					if _, exists := toolMap[toolName]; !exists {
						// Create a minimal tool definition
						toolMap[toolName] = &schemas.ResponsesTool{
							Type: "function",
							Name: &toolName,
							ResponsesToolFunction: &schemas.ResponsesToolFunction{
								Parameters: &schemas.ToolFunctionParameters{
									Type:       "object",
									Properties: schemas.NewOrderedMap(),
								},
							},
						}
					}
				}
			}
		}
	}

	// Convert map to slice
	var tools []BedrockTool
	for _, tool := range toolMap {
		if tool.Name != nil && tool.ResponsesToolFunction != nil {
			schemaObject := tool.ResponsesToolFunction.Parameters
			if schemaObject == nil {
				schemaObject = &schemas.ToolFunctionParameters{
					Type:       "object",
					Properties: schemas.NewOrderedMap(),
				}
			}

			description := "Function tool"
			if tool.Description != nil {
				description = *tool.Description
			}

			schemaObjectBytes2, _ := providerUtils.MarshalSorted(schemaObject)
			bedrockTool := BedrockTool{
				ToolSpec: &BedrockToolSpec{
					Name:        *tool.Name,
					Description: &description,
					InputSchema: BedrockToolInputSchema{
						JSON: json.RawMessage(schemaObjectBytes2),
					},
				},
			}
			tools = append(tools, bedrockTool)
		}
	}

	return hasToolContent, tools
}

func convertResponsesToolChoice(toolChoice schemas.ResponsesToolChoice) *BedrockToolChoice {
	// Check if it's a string choice
	if toolChoice.ResponsesToolChoiceStr != nil {
		switch schemas.ResponsesToolChoiceType(*toolChoice.ResponsesToolChoiceStr) {
		case schemas.ResponsesToolChoiceTypeAuto:
			return &BedrockToolChoice{
				Auto: &BedrockToolChoiceAuto{},
			}
		case schemas.ResponsesToolChoiceTypeAny, schemas.ResponsesToolChoiceTypeRequired:
			return &BedrockToolChoice{
				Any: &BedrockToolChoiceAny{},
			}
		case schemas.ResponsesToolChoiceTypeNone:
			// Bedrock doesn't have explicit "none" - just don't include tools
			return nil
		}
	}

	// Check if it's a struct choice
	if toolChoice.ResponsesToolChoiceStruct != nil {
		switch toolChoice.ResponsesToolChoiceStruct.Type {
		case schemas.ResponsesToolChoiceTypeFunction:
			// Extract the actual function name from the struct
			if toolChoice.ResponsesToolChoiceStruct.Name != nil && *toolChoice.ResponsesToolChoiceStruct.Name != "" {
				return &BedrockToolChoice{
					Tool: &BedrockToolChoiceTool{
						Name: *toolChoice.ResponsesToolChoiceStruct.Name,
					},
				}
			}
			// If Name is nil or empty, return nil as we can't construct a valid tool choice
			return nil
		case schemas.ResponsesToolChoiceTypeAuto, schemas.ResponsesToolChoiceTypeAny, schemas.ResponsesToolChoiceTypeRequired:
			return &BedrockToolChoice{
				Any: &BedrockToolChoiceAny{},
			}
		case schemas.ResponsesToolChoiceTypeNone:
			return nil
		}
	}

	return nil
}

// ToolCallState represents the state of a single tool call in the conversion process
type ToolCallState string

const (
	// Tool call states
	ToolCallStateInitialized    ToolCallState = "initialized"     // Tool call message received
	ToolCallStateQueued         ToolCallState = "queued"          // Tool call queued for emission
	ToolCallStateEmitted        ToolCallState = "emitted"         // Tool call emitted in assistant message
	ToolCallStateAwaitingResult ToolCallState = "awaiting_result" // Waiting for tool result
	ToolCallStateCompleted      ToolCallState = "completed"       // Tool call + result complete
)

// ToolCall represents a tool call with its full lifecycle state
type ToolCall struct {
	CallID            string
	ToolName          string
	Arguments         string
	State             ToolCallState
	AssistantMsgIndex int // Index in final bedrockMessages where this call was emitted
	Result            *ToolResult
	CacheControl      *schemas.CacheControl
}

// ToolResult represents the result of a tool call
type ToolResult struct {
	CallID       string
	Content      []BedrockContentBlock
	Status       string
	Emitted      bool
	CacheControl *schemas.CacheControl
}

// ToolCallBatch tracks a group of tool calls that should be emitted together
type ToolCallBatch struct {
	ID                string               // Unique batch identifier
	ToolCalls         map[string]*ToolCall // Maps CallID to ToolCall
	State             ToolCallState
	AssistantMsgIndex int // Where this batch's assistant message is in bedrockMessages
}

// ToolCallStateManager manages the lifecycle of tool calls through conversion
type ToolCallStateManager struct {
	// All tool calls indexed by ID
	toolCalls map[string]*ToolCall

	// Current batch being accumulated
	currentBatch *ToolCallBatch
	batches      []*ToolCallBatch

	// Pending operations
	pendingToolCallIDs []string               // Tool calls waiting to be emitted
	pendingResults     map[string]*ToolResult // Results waiting to be matched
}

// NewToolCallStateManager creates a new state manager
func NewToolCallStateManager() *ToolCallStateManager {
	return &ToolCallStateManager{
		toolCalls:      make(map[string]*ToolCall),
		pendingResults: make(map[string]*ToolResult),
	}
}

// RegisterToolCall registers a new tool call in the system
func (m *ToolCallStateManager) RegisterToolCall(callID, toolName, arguments string, cacheControl *schemas.CacheControl) {
	if m.toolCalls[callID] != nil {
		// Tool call already registered, skip
		return
	}

	toolCall := &ToolCall{
		CallID:            callID,
		ToolName:          toolName,
		Arguments:         arguments,
		State:             ToolCallStateInitialized,
		AssistantMsgIndex: -1,
		CacheControl:      cacheControl,
	}

	m.toolCalls[callID] = toolCall
	m.pendingToolCallIDs = append(m.pendingToolCallIDs, callID)
}

// RegisterToolResult registers a tool result
func (m *ToolCallStateManager) RegisterToolResult(callID string, content []BedrockContentBlock, status string, cacheControl *schemas.CacheControl) {
	// Attemp to deduplicate the result similar to tool call. Need to check in 2 places, since after moving
	// on from pendingResults into a completed toolCall, the same ID might come again.
	if _, ok := m.pendingResults[callID]; ok {
		return
	}

	if toolCall, exists := m.toolCalls[callID]; exists && toolCall.Result != nil {
		// Tool result already processed for this call ID, skip
		return
	}

	result := &ToolResult{
		CallID:       callID,
		Content:      content,
		Status:       status,
		Emitted:      false,
		CacheControl: cacheControl,
	}

	m.pendingResults[callID] = result

	// If we have the corresponding tool call, attach the result
	if toolCall, exists := m.toolCalls[callID]; exists {
		toolCall.Result = result
		if toolCall.State == ToolCallStateEmitted {
			toolCall.State = ToolCallStateCompleted
		} else if toolCall.State == ToolCallStateAwaitingResult {
			toolCall.State = ToolCallStateCompleted
		}
	}
}

// EmitPendingToolCalls prepares all pending tool calls for emission as an assistant message
func (m *ToolCallStateManager) EmitPendingToolCalls() []string {
	if len(m.pendingToolCallIDs) == 0 {
		return nil
	}

	// Create a new batch for these tool calls
	batchID := fmt.Sprintf("batch_%d", len(m.batches))
	batch := &ToolCallBatch{
		ID:        batchID,
		ToolCalls: make(map[string]*ToolCall),
		State:     ToolCallStateQueued,
	}

	// Mark all pending tool calls as queued
	for _, callID := range m.pendingToolCallIDs {
		if toolCall, exists := m.toolCalls[callID]; exists {
			toolCall.State = ToolCallStateQueued
			batch.ToolCalls[callID] = toolCall
		}
	}

	m.batches = append(m.batches, batch)
	m.currentBatch = batch

	// Return the IDs that should be emitted
	emitIDs := make([]string, len(m.pendingToolCallIDs))
	copy(emitIDs, m.pendingToolCallIDs)
	m.pendingToolCallIDs = nil

	return emitIDs
}

// MarkToolCallsEmitted marks tool calls as having been emitted in an assistant message
func (m *ToolCallStateManager) MarkToolCallsEmitted(callIDs []string, assistantMsgIndex int) {
	for _, callID := range callIDs {
		if toolCall, exists := m.toolCalls[callID]; exists {
			toolCall.State = ToolCallStateEmitted
			toolCall.AssistantMsgIndex = assistantMsgIndex
		}
	}

	if m.currentBatch != nil {
		m.currentBatch.State = ToolCallStateEmitted
		m.currentBatch.AssistantMsgIndex = assistantMsgIndex
	}
}

// GetPendingResults returns all pending results that are ready to be emitted
func (m *ToolCallStateManager) GetPendingResults() map[string]*ToolResult {
	return m.pendingResults
}

// MarkResultsEmitted marks results as having been emitted in a user message
func (m *ToolCallStateManager) MarkResultsEmitted(callIDs []string) {
	for _, callID := range callIDs {
		if result, exists := m.pendingResults[callID]; exists {
			result.Emitted = true
			delete(m.pendingResults, callID)

			// Update tool call state
			if toolCall, exists := m.toolCalls[callID]; exists {
				toolCall.State = ToolCallStateCompleted
			}
		}
	}
}

// HasPendingToolCalls checks if there are tool calls waiting to be emitted
func (m *ToolCallStateManager) HasPendingToolCalls() bool {
	return len(m.pendingToolCallIDs) > 0
}

// HasPendingResults checks if there are results waiting to be emitted
func (m *ToolCallStateManager) HasPendingResults() bool {
	return len(m.pendingResults) > 0
}

// ConvertDeepIntShieldMessagesToBedrockMessages converts an array of DeepIntShield ResponsesMessage to Bedrock message format
// This is the main conversion method from DeepIntShield to Bedrock - handles all message types and returns messages + system messages
// Uses a state machine to properly track and manage tool call lifecycles
func ConvertDeepIntShieldMessagesToBedrockMessages(deepintshieldMessages []schemas.ResponsesMessage) ([]BedrockMessage, []BedrockSystemMessage, error) {
	var bedrockMessages []BedrockMessage
	var systemMessages []BedrockSystemMessage
	var pendingReasoningContentBlocks []BedrockContentBlock

	// Initialize the state manager for tracking tool calls and results
	stateManager := NewToolCallStateManager()

	// Helper to flush pending tool result blocks into user messages using state manager
	flushPendingToolResults := func() {
		// Emit any pending results from the state manager
		if stateManager.HasPendingResults() {
			pendingResults := stateManager.GetPendingResults()
			var resultBlocks []BedrockContentBlock
			resultIDs := []string{}
			for callID, result := range pendingResults {
				resultBlocks = append(resultBlocks, BedrockContentBlock{
					ToolResult: &BedrockToolResult{
						ToolUseID: callID,
						Content:   result.Content,
						Status:    schemas.Ptr(result.Status),
					},
				})
				if result.CacheControl != nil {
					resultBlocks = append(resultBlocks, BedrockContentBlock{
						CachePoint: &BedrockCachePoint{Type: BedrockCachePointTypeDefault},
					})
				}
				resultIDs = append(resultIDs, callID)
			}

			if len(resultBlocks) > 0 {
				bedrockMessages = append(bedrockMessages, BedrockMessage{
					Role:    BedrockMessageRoleUser,
					Content: resultBlocks,
				})
				stateManager.MarkResultsEmitted(resultIDs)
			}
		}
	}

	// Helper to flush pending tool call blocks into a single assistant message using state manager
	flushPendingToolCalls := func() {
		if stateManager.HasPendingToolCalls() {
			callIDs := stateManager.EmitPendingToolCalls()
			// Create assistant message with tool calls
			var contentBlocks []BedrockContentBlock

			// Prepend pending reasoning blocks first (Bedrock requires reasoning before tool_use)
			if len(pendingReasoningContentBlocks) > 0 {
				contentBlocks = append(contentBlocks, pendingReasoningContentBlocks...)
				pendingReasoningContentBlocks = nil
			}

			// Add tool use blocks
			for _, callID := range callIDs {
				if toolCall, exists := stateManager.toolCalls[callID]; exists {
					toolUseBlock := &BedrockContentBlock{
						ToolUse: &BedrockToolUse{
							ToolUseID: toolCall.CallID,
							Name:      toolCall.ToolName,
						},
					}
					// Preserve original key ordering of tool arguments for prompt caching.
					var input json.RawMessage
					var buf bytes.Buffer
					if err := json.Compact(&buf, []byte(toolCall.Arguments)); err == nil {
						input = buf.Bytes()
					} else {
						input = json.RawMessage("{}")
					}
					toolUseBlock.ToolUse.Input = input
					contentBlocks = append(contentBlocks, *toolUseBlock)
					if toolCall.CacheControl != nil {
						contentBlocks = append(contentBlocks, BedrockContentBlock{
							CachePoint: &BedrockCachePoint{Type: BedrockCachePointTypeDefault},
						})
					}
				}
			}

			if len(contentBlocks) > 0 {
				bedrockMessages = append(bedrockMessages, BedrockMessage{
					Role:    BedrockMessageRoleAssistant,
					Content: contentBlocks,
				})
				stateManager.MarkToolCallsEmitted(callIDs, len(bedrockMessages)-1)
			}
		}
	}

	for i, msg := range deepintshieldMessages {
		// Handle nil Type as regular message
		msgType := schemas.ResponsesMessageTypeMessage
		if msg.Type != nil {
			msgType = *msg.Type
		}

		// If we're processing a non-reasoning message and have pending reasoning blocks,
		// flush them into the previous assistant message (if it exists)
		if msgType != schemas.ResponsesMessageTypeReasoning && len(pendingReasoningContentBlocks) > 0 {
			if len(bedrockMessages) > 0 && bedrockMessages[len(bedrockMessages)-1].Role == BedrockMessageRoleAssistant {
				// Prepend reasoning blocks to the last assistant message
				lastMsg := &bedrockMessages[len(bedrockMessages)-1]
				lastMsg.Content = append(pendingReasoningContentBlocks, lastMsg.Content...)
				pendingReasoningContentBlocks = nil
			}
		}

		switch msgType {
		case schemas.ResponsesMessageTypeFunctionCall:
			// Register tool call in state manager
			if msg.ResponsesToolMessage != nil && msg.ResponsesToolMessage.CallID != nil {
				toolName := ""
				if msg.ResponsesToolMessage.Name != nil {
					toolName = *msg.ResponsesToolMessage.Name
				}
				arguments := ""
				if msg.ResponsesToolMessage.Arguments != nil {
					arguments = *msg.ResponsesToolMessage.Arguments
				}

				stateManager.RegisterToolCall(*msg.ResponsesToolMessage.CallID, toolName, arguments, msg.CacheControl)
			}

		case schemas.ResponsesMessageTypeFunctionCallOutput:
			// Register tool result in state manager
			if msg.ResponsesToolMessage != nil && msg.ResponsesToolMessage.CallID != nil {
				resultContent := []BedrockContentBlock{}
				status := "success"
				if msg.Status != nil && *msg.Status != "" {
					// Validate status is one of the allowed values
					switch *msg.Status {
					case "success", "error":
						status = *msg.Status
					default:
						// Default to success for unknown status values
						status = "success"
					}
				}

				// Convert result content to Bedrock format
				if msg.ResponsesToolMessage.Output != nil {
					if msg.ResponsesToolMessage.Output.ResponsesToolCallOutputStr != nil {
						resultContent = append(resultContent, tryParseJSONIntoContentBlock(*msg.ResponsesToolMessage.Output.ResponsesToolCallOutputStr))
					} else if msg.ResponsesToolMessage.Output.ResponsesFunctionToolCallOutputBlocks != nil {
						// Handle structured output blocks
						for _, block := range msg.ResponsesToolMessage.Output.ResponsesFunctionToolCallOutputBlocks {
							if block.Text != nil {
								resultContent = append(resultContent, tryParseJSONIntoContentBlock(*block.Text))
							}
						}
					}
				}

				stateManager.RegisterToolResult(*msg.ResponsesToolMessage.CallID, resultContent, status, msg.CacheControl)
			}

			// Check if next message is not a function call output - if so, flush tool calls and results
			isLastResultInSequence := true
			if i+1 < len(deepintshieldMessages) {
				nextMsg := deepintshieldMessages[i+1]
				nextMsgType := schemas.ResponsesMessageTypeMessage
				if nextMsg.Type != nil {
					nextMsgType = *nextMsg.Type
				}
				if nextMsgType == schemas.ResponsesMessageTypeFunctionCallOutput {
					isLastResultInSequence = false
				}
			}

			// If this is the last result in a sequence, flush tool calls and results together
			if isLastResultInSequence {
				// Emit pending tool calls first
				if stateManager.HasPendingToolCalls() {
					callIDs := stateManager.EmitPendingToolCalls()
					var contentBlocks []BedrockContentBlock

					// Prepend pending reasoning blocks first (Bedrock requires reasoning before tool_use)
					if len(pendingReasoningContentBlocks) > 0 {
						contentBlocks = append(contentBlocks, pendingReasoningContentBlocks...)
						pendingReasoningContentBlocks = nil
					}

					// Add tool use blocks
					for _, callID := range callIDs {
						if toolCall, exists := stateManager.toolCalls[callID]; exists {
							toolUseBlock := &BedrockContentBlock{
								ToolUse: &BedrockToolUse{
									ToolUseID: toolCall.CallID,
									Name:      toolCall.ToolName,
								},
							}
							// Preserve original key ordering of tool arguments for prompt caching.
							var input json.RawMessage
							var buf bytes.Buffer
							if err := json.Compact(&buf, []byte(toolCall.Arguments)); err == nil {
								input = buf.Bytes()
							} else {
								input = json.RawMessage("{}")
							}
							toolUseBlock.ToolUse.Input = input
							contentBlocks = append(contentBlocks, *toolUseBlock)
							if toolCall.CacheControl != nil {
								contentBlocks = append(contentBlocks, BedrockContentBlock{
									CachePoint: &BedrockCachePoint{Type: BedrockCachePointTypeDefault},
								})
							}
						}
					}

					if len(contentBlocks) > 0 {
						bedrockMessages = append(bedrockMessages, BedrockMessage{
							Role:    BedrockMessageRoleAssistant,
							Content: contentBlocks,
						})
						stateManager.MarkToolCallsEmitted(callIDs, len(bedrockMessages)-1)
					}
				}

				// Emit pending results after tool calls
				if stateManager.HasPendingResults() {
					pendingResults := stateManager.GetPendingResults()
					var resultBlocks []BedrockContentBlock
					resultIDs := []string{}
					for callID, result := range pendingResults {
						resultBlocks = append(resultBlocks, BedrockContentBlock{
							ToolResult: &BedrockToolResult{
								ToolUseID: callID,
								Content:   result.Content,
								Status:    schemas.Ptr(result.Status),
							},
						})
						if result.CacheControl != nil {
							resultBlocks = append(resultBlocks, BedrockContentBlock{
								CachePoint: &BedrockCachePoint{Type: BedrockCachePointTypeDefault},
							})
						}
						resultIDs = append(resultIDs, callID)
					}

					if len(resultBlocks) > 0 {
						bedrockMessages = append(bedrockMessages, BedrockMessage{
							Role:    BedrockMessageRoleUser,
							Content: resultBlocks,
						})
						stateManager.MarkResultsEmitted(resultIDs)
					}
				}
			}

		case schemas.ResponsesMessageTypeMessage:
			// Check if Role is present, skip message if not
			if msg.Role == nil {
				continue
			}

			// Extract role from the Responses message structure
			role := *msg.Role

			// Always flush pending tool calls and results before processing a new message
			// This ensures tool calls and results are properly paired
			if stateManager.HasPendingToolCalls() {
				callIDs := stateManager.EmitPendingToolCalls()
				// Create assistant message with tool calls
				var toolUseBlocks []BedrockContentBlock
				for _, callID := range callIDs {
					if toolCall, exists := stateManager.toolCalls[callID]; exists {
						toolUseBlock := &BedrockContentBlock{
							ToolUse: &BedrockToolUse{
								ToolUseID: toolCall.CallID,
								Name:      toolCall.ToolName,
							},
						}
						// Preserve original key ordering of tool arguments for prompt caching.
						var input json.RawMessage
						var buf bytes.Buffer
						if err := json.Compact(&buf, []byte(toolCall.Arguments)); err == nil {
							input = buf.Bytes()
						} else {
							input = json.RawMessage("{}")
						}
						toolUseBlock.ToolUse.Input = input
						toolUseBlocks = append(toolUseBlocks, *toolUseBlock)
					}
				}

				if len(toolUseBlocks) > 0 {
					bedrockMessages = append(bedrockMessages, BedrockMessage{
						Role:    BedrockMessageRoleAssistant,
						Content: toolUseBlocks,
					})
					stateManager.MarkToolCallsEmitted(callIDs, len(bedrockMessages)-1)
				}
			}

			// Emit any pending results after tool calls
			if stateManager.HasPendingResults() {
				pendingResults := stateManager.GetPendingResults()
				var resultBlocks []BedrockContentBlock
				resultIDs := []string{}
				for callID, result := range pendingResults {
					resultBlocks = append(resultBlocks, BedrockContentBlock{
						ToolResult: &BedrockToolResult{
							ToolUseID: callID,
							Content:   result.Content,
							Status:    schemas.Ptr(result.Status),
						},
					})
					resultIDs = append(resultIDs, callID)
				}

				if len(resultBlocks) > 0 {
					bedrockMessages = append(bedrockMessages, BedrockMessage{
						Role:    BedrockMessageRoleUser,
						Content: resultBlocks,
					})
					stateManager.MarkResultsEmitted(resultIDs)
				}
			}

			// Convert regular message
			if role == schemas.ResponsesInputMessageRoleSystem {
				// Convert to system message
				systemMsgs := convertDeepIntShieldMessageToBedrockSystemMessages(&msg)
				systemMessages = append(systemMessages, systemMsgs...)
			} else {
				// Convert user/assistant text message
				bedrockMsg := convertDeepIntShieldMessageToBedrockMessage(&msg)
				if bedrockMsg != nil {
					bedrockMessages = append(bedrockMessages, *bedrockMsg)
				}
			}

		case schemas.ResponsesMessageTypeReasoning:
			// Handle reasoning as content in next assistant message
			// For now, just add to pending content blocks
			reasoningBlocks := convertDeepIntShieldReasoningToBedrockReasoning(&msg)
			if len(reasoningBlocks) > 0 {
				pendingReasoningContentBlocks = append(pendingReasoningContentBlocks, reasoningBlocks...)
			}
		}
	}

	// Flush any remaining pending tool calls
	flushPendingToolCalls()

	// Flush any remaining pending tool results
	flushPendingToolResults()

	// For Bedrock compatibility, reasoning blocks must not be the final block in an assistant message
	// If we have pending reasoning blocks and the last message is an assistant message,
	// merge them into a single message with reasoning first
	if len(pendingReasoningContentBlocks) > 0 {
		if len(bedrockMessages) > 0 && bedrockMessages[len(bedrockMessages)-1].Role == BedrockMessageRoleAssistant {
			// Last message is an assistant message - prepend reasoning blocks to it
			lastMsg := &bedrockMessages[len(bedrockMessages)-1]
			lastMsg.Content = append(pendingReasoningContentBlocks, lastMsg.Content...)
			pendingReasoningContentBlocks = nil
		}
		// If no assistant message to merge into, discard the reasoning blocks
		// (they cannot exist alone in Bedrock without violating the constraint)
	}

	// Merge consecutive messages with the same role
	// This ensures document blocks are in the same message as text blocks (Bedrock requirement)
	mergedMessages := []BedrockMessage{}
	for i := 0; i < len(bedrockMessages); i++ {
		currentMsg := bedrockMessages[i]

		// Merge any consecutive messages with the same role
		for i+1 < len(bedrockMessages) && bedrockMessages[i+1].Role == currentMsg.Role {
			i++
			currentMsg.Content = append(currentMsg.Content, bedrockMessages[i].Content...)
		}

		mergedMessages = append(mergedMessages, currentMsg)
	}
	bedrockMessages = mergedMessages

	return bedrockMessages, systemMessages, nil
}

// ConvertBedrockMessagesToDeepIntShieldMessages converts an array of Bedrock messages to DeepIntShield ResponsesMessage format
// This is the main conversion method from Bedrock to DeepIntShield - handles all message types and content blocks
func ConvertBedrockMessagesToDeepIntShieldMessages(ctx *schemas.DeepIntShieldContext, bedrockMessages []BedrockMessage, systemMessages []BedrockSystemMessage, isOutputMessage bool) []schemas.ResponsesMessage {
	var deepintshieldMessages []schemas.ResponsesMessage

	// Convert system messages first
	systemDeepIntShieldMsgs := convertBedrockSystemMessageToDeepIntShieldMessages(systemMessages)
	if len(systemDeepIntShieldMsgs) > 0 {
		deepintshieldMessages = append(deepintshieldMessages, systemDeepIntShieldMsgs...)
	}

	// Convert regular messages
	for _, msg := range bedrockMessages {
		convertedMessages := convertSingleBedrockMessageToDeepIntShieldMessages(ctx, &msg, isOutputMessage)
		deepintshieldMessages = append(deepintshieldMessages, convertedMessages...)
	}

	return deepintshieldMessages
}

// Helper functions for converting individual Bedrock message types

// convertDeepIntShieldMessageToBedrockSystemMessages converts a DeepIntShield system message to Bedrock system messages
func convertDeepIntShieldMessageToBedrockSystemMessages(msg *schemas.ResponsesMessage) []BedrockSystemMessage {
	var systemMessages []BedrockSystemMessage

	if msg.Content != nil {
		if msg.Content.ContentStr != nil {
			systemMessages = append(systemMessages, BedrockSystemMessage{
				Text: msg.Content.ContentStr,
			})
		} else if msg.Content.ContentBlocks != nil {
			for _, block := range msg.Content.ContentBlocks {
				if block.Text != nil {
					systemMessages = append(systemMessages, BedrockSystemMessage{
						Text: block.Text,
					})
					if block.CacheControl != nil {
						systemMessages = append(systemMessages, BedrockSystemMessage{
							CachePoint: &BedrockCachePoint{
								Type: BedrockCachePointTypeDefault,
							},
						})
					}
				}
			}
		}
	}

	return systemMessages
}

// convertDeepIntShieldMessageToBedrockMessage converts a regular DeepIntShield message to Bedrock message
func convertDeepIntShieldMessageToBedrockMessage(msg *schemas.ResponsesMessage) *BedrockMessage {
	// Ensure Content is present
	if msg.Content == nil {
		return nil
	}

	bedrockMsg := BedrockMessage{
		Role: BedrockMessageRole(*msg.Role),
	}

	// Convert content
	contentBlocks, err := convertDeepIntShieldResponsesMessageContentBlocksToBedrockContentBlocks(*msg.Content)
	if err != nil {
		return nil
	}
	bedrockMsg.Content = contentBlocks

	return &bedrockMsg
}

// convertBedrockSystemMessageToDeepIntShieldMessages converts a Bedrock system message to DeepIntShield messages
func convertBedrockSystemMessageToDeepIntShieldMessages(systemMessages []BedrockSystemMessage) []schemas.ResponsesMessage {
	var deepintshieldMessages []schemas.ResponsesMessage

	for _, sysMsg := range systemMessages {
		if sysMsg.CachePoint != nil {
			// add it to last content block of last message
			if len(deepintshieldMessages) > 0 {
				lastMessage := &deepintshieldMessages[len(deepintshieldMessages)-1]
				if lastMessage.Content != nil && len(lastMessage.Content.ContentBlocks) > 0 {
					lastMessage.Content.ContentBlocks[len(lastMessage.Content.ContentBlocks)-1].CacheControl = &schemas.CacheControl{
						Type: schemas.CacheControlTypeEphemeral,
					}
				}
			}
		}
		if sysMsg.Text != nil {
			systemRole := schemas.ResponsesInputMessageRoleSystem
			msgType := schemas.ResponsesMessageTypeMessage
			deepintshieldMessages = append(deepintshieldMessages, schemas.ResponsesMessage{
				Type: &msgType,
				Role: &systemRole,
				Content: &schemas.ResponsesMessageContent{
					ContentBlocks: []schemas.ResponsesMessageContentBlock{
						{
							Type: schemas.ResponsesInputMessageContentBlockTypeText,
							Text: sysMsg.Text,
						},
					},
				},
			})
		}

	}
	return deepintshieldMessages
}

// Helper to convert Bedrock role to DeepIntShield role
func convertBedrockRoleToDeepIntShieldRole(bedrockRole BedrockMessageRole) schemas.ResponsesMessageRoleType {
	switch bedrockRole {
	case BedrockMessageRoleUser:
		return schemas.ResponsesInputMessageRoleUser
	case BedrockMessageRoleAssistant:
		return schemas.ResponsesInputMessageRoleAssistant
	default:
		return schemas.ResponsesInputMessageRoleUser
	}
}

// Helper to create a text message
func createTextMessage(
	text *string,
	role schemas.ResponsesMessageRoleType,
	textBlockType schemas.ResponsesMessageContentBlockType,
	isOutputMessage bool,
) schemas.ResponsesMessage {
	contentBlock := schemas.ResponsesMessageContentBlock{
		Type: textBlockType,
		Text: text,
	}
	if textBlockType == schemas.ResponsesOutputMessageContentTypeText {
		contentBlock.ResponsesOutputMessageContentText = &schemas.ResponsesOutputMessageContentText{
			Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
			LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
		}
	}
	deepintshieldMsg := schemas.ResponsesMessage{
		Type:   schemas.Ptr(schemas.ResponsesMessageTypeMessage),
		Status: schemas.Ptr("completed"),
		Role:   &role,
		Content: &schemas.ResponsesMessageContent{
			ContentBlocks: []schemas.ResponsesMessageContentBlock{contentBlock},
		},
	}
	if isOutputMessage {
		deepintshieldMsg.ID = schemas.Ptr("msg_" + fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	return deepintshieldMsg
}

// convertSingleBedrockMessageToDeepIntShieldMessages converts a single Bedrock message to DeepIntShield messages
func convertSingleBedrockMessageToDeepIntShieldMessages(ctx *schemas.DeepIntShieldContext, msg *BedrockMessage, isOutputMessage bool) []schemas.ResponsesMessage {
	var outputMessages []schemas.ResponsesMessage
	var reasoningContentBlocks []schemas.ResponsesMessageContentBlock

	// Check if we have a structured output tool
	var structuredOutputToolName string
	if ctx != nil {
		if toolName, ok := ctx.Value(schemas.DeepIntShieldContextKeyStructuredOutputToolName).(string); ok {
			structuredOutputToolName = toolName
		}
	}

	for _, block := range msg.Content {
		if block.Text != nil {
			// Text content
			role := convertBedrockRoleToDeepIntShieldRole(msg.Role)

			// For assistant messages (previous model outputs), use output_text type
			// For user/system messages, use input_text type
			textBlockType := schemas.ResponsesInputMessageContentBlockTypeText
			if isOutputMessage || msg.Role == BedrockMessageRoleAssistant {
				textBlockType = schemas.ResponsesOutputMessageContentTypeText
			}

			deepintshieldMsg := createTextMessage(block.Text, role, textBlockType, isOutputMessage)
			if isOutputMessage {
				deepintshieldMsg.ID = schemas.Ptr("msg_" + fmt.Sprintf("%d", time.Now().UnixNano()))
			}
			outputMessages = append(outputMessages, deepintshieldMsg)

		} else if block.ReasoningContent != nil {
			// Reasoning content - collect to create a single reasoning message
			if block.ReasoningContent.ReasoningText != nil {
				reasoningContentBlocks = append(reasoningContentBlocks, schemas.ResponsesMessageContentBlock{
					Type:      schemas.ResponsesOutputMessageContentTypeReasoning,
					Text:      block.ReasoningContent.ReasoningText.Text,
					Signature: block.ReasoningContent.ReasoningText.Signature,
				})
			}

		} else if block.ToolUse != nil {
			// Tool use content
			// Create copies of the values to avoid range loop variable capture
			toolUseID := block.ToolUse.ToolUseID
			toolUseName := block.ToolUse.Name

			// Check if this is a structured output tool - if so, convert to text content
			if structuredOutputToolName != "" && toolUseName == structuredOutputToolName {
				// This is a structured output tool - convert to text message
				role := convertBedrockRoleToDeepIntShieldRole(msg.Role)

				// Marshal the tool input to JSON string
				var contentStr string
				if block.ToolUse.Input != nil {
					contentStr = string(block.ToolUse.Input)
				} else {
					contentStr = "{}"
				}

				deepintshieldMsg := createTextMessage(&contentStr, role, schemas.ResponsesOutputMessageContentTypeText, isOutputMessage)
				if isOutputMessage {
					deepintshieldMsg.ID = schemas.Ptr("msg_" + fmt.Sprintf("%d", time.Now().UnixNano()))
				}
				outputMessages = append(outputMessages, deepintshieldMsg)
			} else {
				// Normal tool call message
				arguments := "{}"
				if block.ToolUse.Input != nil {
					arguments = string(block.ToolUse.Input)
				}
				toolMsg := schemas.ResponsesMessage{
					Type:   schemas.Ptr(schemas.ResponsesMessageTypeFunctionCall),
					Status: schemas.Ptr("completed"),
					ResponsesToolMessage: &schemas.ResponsesToolMessage{
						CallID:    &toolUseID,
						Name:      &toolUseName,
						Arguments: schemas.Ptr(arguments),
					},
				}
				if isOutputMessage {
					toolMsg.ID = schemas.Ptr("msg_" + fmt.Sprintf("%d", time.Now().UnixNano()))
					role := schemas.ResponsesInputMessageRoleAssistant
					toolMsg.Role = &role
				}
				outputMessages = append(outputMessages, toolMsg)
			}

		} else if block.Document != nil {
			// Document content
			role := convertBedrockRoleToDeepIntShieldRole(msg.Role)

			// Convert document to file block
			fileBlock := schemas.ResponsesMessageContentBlock{
				Type:                                  schemas.ResponsesInputMessageContentBlockTypeFile,
				ResponsesInputMessageContentBlockFile: &schemas.ResponsesInputMessageContentBlockFile{},
			}

			// Set filename from document name
			if block.Document.Name != "" {
				fileBlock.ResponsesInputMessageContentBlockFile.Filename = &block.Document.Name
			}

			fileType := "application/pdf"
			// Set file type based on format
			if block.Document.Format != "" {
				switch block.Document.Format {
				case "pdf":
					fileType = "application/pdf"
				case "txt", "md", "html", "csv":
					fileType = "text/plain"
				default:
					fileType = "application/pdf" // Default to PDF
				}
				fileBlock.ResponsesInputMessageContentBlockFile.FileType = &fileType
			}

			// Convert document source data
			if block.Document.Source != nil {
				if block.Document.Source.Text != nil {
					// Plain text content
					fileBlock.ResponsesInputMessageContentBlockFile.FileData = block.Document.Source.Text
				} else if block.Document.Source.Bytes != nil {
					// Base64 encoded bytes (PDF)
					fileDataURL := *block.Document.Source.Bytes
					if !strings.HasPrefix(fileDataURL, "data:") {
						fileDataURL = fmt.Sprintf("data:%s;base64,%s", fileType, fileDataURL)
					}
					fileBlock.ResponsesInputMessageContentBlockFile.FileData = &fileDataURL
				}
			}

			deepintshieldMsg := schemas.ResponsesMessage{
				Type: schemas.Ptr(schemas.ResponsesMessageTypeMessage),
				Role: &role,
				Content: &schemas.ResponsesMessageContent{
					ContentBlocks: []schemas.ResponsesMessageContentBlock{fileBlock},
				},
			}
			if isOutputMessage {
				deepintshieldMsg.ID = schemas.Ptr("msg_" + fmt.Sprintf("%d", time.Now().UnixNano()))
			}
			outputMessages = append(outputMessages, deepintshieldMsg)

		} else if block.ToolResult != nil {
			// Tool result content - typically not in assistant output but handled for completeness
			// Prefer JSON payloads without unmarshalling; fallback to text
			var resultContent string
			if len(block.ToolResult.Content) > 0 {
				// JSON first (no unmarshal; just one marshal to string when present)
				for _, c := range block.ToolResult.Content {
					if c.JSON != nil {
						resultContent = string(c.JSON)
						break
					}
				}
				// Fallback to first available text block
				if resultContent == "" {
					for _, c := range block.ToolResult.Content {
						if c.Text != nil {
							resultContent = *c.Text
							break
						}
					}
				}
			}

			// Create a copy of the value to avoid range loop variable capture
			toolResultID := block.ToolResult.ToolUseID

			resultMsg := schemas.ResponsesMessage{
				Type: schemas.Ptr(schemas.ResponsesMessageTypeFunctionCallOutput),
				ResponsesToolMessage: &schemas.ResponsesToolMessage{
					CallID: &toolResultID,
					Output: &schemas.ResponsesToolMessageOutputStruct{
						ResponsesToolCallOutputStr: &resultContent,
					},
				},
			}
			if isOutputMessage {
				resultMsg.ID = schemas.Ptr("msg_" + fmt.Sprintf("%d", time.Now().UnixNano()))
				role := schemas.ResponsesInputMessageRoleAssistant
				resultMsg.Role = &role
				resultMsg.Content = &schemas.ResponsesMessageContent{
					ContentBlocks: []schemas.ResponsesMessageContentBlock{
						{
							Type: schemas.ResponsesOutputMessageContentTypeText,
							Text: &resultContent,
						},
					},
				}
			}
			outputMessages = append(outputMessages, resultMsg)
		} else if block.CachePoint != nil {
			// Add cache control to last message
			if len(outputMessages) > 0 {
				lastMessage := &outputMessages[len(outputMessages)-1]
				// First try: set on last content block (for text/image messages)
				if lastMessage.Content != nil && len(lastMessage.Content.ContentBlocks) > 0 {
					lastMessage.Content.ContentBlocks[len(lastMessage.Content.ContentBlocks)-1].CacheControl = &schemas.CacheControl{
						Type: schemas.CacheControlTypeEphemeral,
					}
				} else {
					// Fallback: set on message itself (for function_call/function_call_output)
					lastMessage.CacheControl = &schemas.CacheControl{
						Type: schemas.CacheControlTypeEphemeral,
					}
				}
			}
		}
	}

	// Handle reasoning blocks - prepend reasoning message if we collected any
	if len(reasoningContentBlocks) > 0 {
		reasoningMessage := schemas.ResponsesMessage{
			ID:   schemas.Ptr("rs_" + fmt.Sprintf("%d", time.Now().UnixNano())),
			Type: schemas.Ptr(schemas.ResponsesMessageTypeReasoning),
			ResponsesReasoning: &schemas.ResponsesReasoning{
				Summary: []schemas.ResponsesReasoningSummary{},
			},
			Content: &schemas.ResponsesMessageContent{
				ContentBlocks: reasoningContentBlocks,
			},
		}
		// Prepend the reasoning message to the start of the messages list
		outputMessages = append([]schemas.ResponsesMessage{reasoningMessage}, outputMessages...)
	}

	return outputMessages
}

// convertDeepIntShieldReasoningToBedrockReasoning converts a DeepIntShield reasoning message to Bedrock reasoning blocks
func convertDeepIntShieldReasoningToBedrockReasoning(msg *schemas.ResponsesMessage) []BedrockContentBlock {
	var reasoningBlocks []BedrockContentBlock

	if msg.Content != nil && msg.Content.ContentBlocks != nil {
		for _, block := range msg.Content.ContentBlocks {
			if block.Type == schemas.ResponsesOutputMessageContentTypeReasoning && block.Text != nil {
				reasoningBlock := BedrockContentBlock{
					ReasoningContent: &BedrockReasoningContent{
						ReasoningText: &BedrockReasoningContentText{
							Text:      block.Text,
							Signature: block.Signature,
						},
					},
				}
				reasoningBlocks = append(reasoningBlocks, reasoningBlock)
			}
		}
	} else if msg.ResponsesReasoning != nil {
		if msg.ResponsesReasoning.Summary != nil {
			for _, reasoningContent := range msg.ResponsesReasoning.Summary {
				reasoningBlock := BedrockContentBlock{
					ReasoningContent: &BedrockReasoningContent{
						ReasoningText: &BedrockReasoningContentText{
							Text: &reasoningContent.Text,
						},
					},
				}
				reasoningBlocks = append(reasoningBlocks, reasoningBlock)
			}
		} else if msg.ResponsesReasoning.EncryptedContent != nil {
			// Bedrock doesn't have a direct equivalent to encrypted content,
			// so we'll store it as a regular reasoning block with a special marker
			encryptedText := fmt.Sprintf("[ENCRYPTED_REASONING: %s]", *msg.ResponsesReasoning.EncryptedContent)
			reasoningBlock := BedrockContentBlock{
				ReasoningContent: &BedrockReasoningContent{
					ReasoningText: &BedrockReasoningContentText{
						Text: &encryptedText,
					},
				},
			}
			reasoningBlocks = append(reasoningBlocks, reasoningBlock)
		}
	}

	return reasoningBlocks
}

// convertDeepIntShieldResponsesMessageContentBlocksToBedrockContentBlocks converts DeepIntShield content to Bedrock content blocks
func convertDeepIntShieldResponsesMessageContentBlocksToBedrockContentBlocks(content schemas.ResponsesMessageContent) ([]BedrockContentBlock, error) {
	var blocks []BedrockContentBlock

	if content.ContentStr != nil {
		blocks = append(blocks, BedrockContentBlock{
			Text: content.ContentStr,
		})
	} else if content.ContentBlocks != nil {
		for _, block := range content.ContentBlocks {

			bedrockBlock := BedrockContentBlock{}
			switch block.Type {
			case schemas.ResponsesInputMessageContentBlockTypeText, schemas.ResponsesOutputMessageContentTypeText:
				bedrockBlock.Text = block.Text
			case schemas.ResponsesInputMessageContentBlockTypeImage:
				if block.ResponsesInputMessageContentBlockImage != nil && block.ResponsesInputMessageContentBlockImage.ImageURL != nil {
					imageSource, err := convertImageToBedrockSource(*block.ResponsesInputMessageContentBlockImage.ImageURL)
					if err != nil {
						return nil, fmt.Errorf("failed to convert image in responses content block: %w", err)
					}
					bedrockBlock.Image = imageSource
				}
			case schemas.ResponsesOutputMessageContentTypeReasoning:
				if block.Text != nil {
					bedrockBlock.ReasoningContent = &BedrockReasoningContent{
						ReasoningText: &BedrockReasoningContentText{
							Text:      block.Text,
							Signature: block.Signature,
						},
					}
				}
			case schemas.ResponsesOutputMessageContentTypeCompaction:
				// Convert compaction to text block for Bedrock (compaction is Anthropic-specific)
				if block.ResponsesOutputMessageContentCompaction != nil {
					bedrockBlock.Text = &block.ResponsesOutputMessageContentCompaction.Summary
				}
			case schemas.ResponsesInputMessageContentBlockTypeFile:
				if block.ResponsesInputMessageContentBlockFile != nil {
					doc := &BedrockDocumentSource{
						Name:   "document", // Default
						Format: "pdf",      // Default
						Source: &BedrockDocumentSourceData{},
					}

					// Set filename (normalized for Bedrock)
					if block.ResponsesInputMessageContentBlockFile.Filename != nil {
						doc.Name = normalizeBedrockFilename(*block.ResponsesInputMessageContentBlockFile.Filename)
					}

					// Determine format: text or PDF based on FileType
					isTextFile := false
					if block.ResponsesInputMessageContentBlockFile.FileType != nil {
						fileType := *block.ResponsesInputMessageContentBlockFile.FileType
						// Check if it's a text type
						if strings.HasPrefix(fileType, "text/") ||
							fileType == "txt" || fileType == "md" ||
							fileType == "html" {
							doc.Format = "txt"
							isTextFile = true
						} else if strings.Contains(fileType, "pdf") || fileType == "pdf" {
							doc.Format = "pdf"
						}
					}

					// Handle file data
					if block.ResponsesInputMessageContentBlockFile.FileData != nil {
						fileData := *block.ResponsesInputMessageContentBlockFile.FileData

						// Check if it's a data URL (e.g., "data:application/pdf;base64,...")
						if strings.HasPrefix(fileData, "data:") {
							urlInfo := schemas.ExtractURLTypeInfo(fileData)
							if urlInfo.DataURLWithoutPrefix != nil {
								// PDF or other binary - keep as base64
								doc.Source.Bytes = urlInfo.DataURLWithoutPrefix
								bedrockBlock.Document = doc
								break
							}
						}

						// Not a data URL - use as-is
						if isTextFile {
							// bytes is necessary for bedrock
							// base64 string of the text
							doc.Source.Text = &fileData
							encoded := base64.StdEncoding.EncodeToString([]byte(fileData))
							doc.Source.Bytes = &encoded
						} else {
							doc.Source.Bytes = &fileData
						}

						bedrockBlock.Document = doc

					}
				}
			default:
				// Don't add anything for unknown types
				continue
			}

			// Only append if at least one required field is set
			if bedrockBlock.Text != nil ||
				bedrockBlock.Image != nil ||
				bedrockBlock.Document != nil ||
				bedrockBlock.ToolUse != nil ||
				bedrockBlock.ToolResult != nil ||
				bedrockBlock.ReasoningContent != nil ||
				bedrockBlock.CachePoint != nil ||
				bedrockBlock.JSON != nil ||
				bedrockBlock.GuardContent != nil {
				blocks = append(blocks, bedrockBlock)
			}

			if block.CacheControl != nil {
				blocks = append(blocks, BedrockContentBlock{
					CachePoint: &BedrockCachePoint{
						Type: BedrockCachePointTypeDefault,
					},
				})
			}
		}
	}

	return blocks, nil
}
