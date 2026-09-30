package config

import "slices"

// covers is the messages for which one slot satisfies an exclusion field.
// Replacement and truncation satisfy nothing.
func covers(slot EffectiveSlot, field ExclusionField) []string {
	a := slot.Arguments
	if a == nil {
		return nil
	}
	switch field.Kind {
	case HeaderFieldPrefix:
		if slot.Implementation == RemoveHeaders && slices.Contains(a.Headers, field.Header) {
			return []string{MessageRequest}
		}
	case BodyField:
		if slot.Implementation == RemoveBody {
			return a.Messages
		}
	case BodyValuesField:
		if slot.Implementation == RemoveBody || slot.Implementation == ReduceBodyToStructure {
			return a.Messages
		}
	case FormFieldPrefix:
		// Not reduce-body-to-structure: it keeps member names, and a JSON
		// member name can carry a form parameter, as in {"&card_number=4111":1}.
		if (slot.Implementation == RemoveBody && slices.Contains(a.Messages, MessageRequest)) ||
			((slot.Implementation == RemoveFormFields || slot.Implementation == RequestBodyFields) && slices.Contains(a.Names, field.Name)) {
			return []string{MessageRequest}
		}
	case TargetQueryField:
		if slot.Implementation == RemoveQuery {
			return []string{MessageRequest}
		}
	case QueryFieldPrefix:
		if slot.Implementation == RemoveQuery || (slot.Implementation == RemoveQueryParameters && slices.Contains(a.Names, field.Name)) {
			return []string{MessageRequest}
		}
	case JSONFieldPrefix:
		if slot.Implementation == RemoveBody || slot.Implementation == ReduceBodyToStructure {
			return a.Messages
		}
		if slot.Implementation == RemoveJSONFields || slot.Implementation == RequestBodyFields {
			// request-body-fields selects the request only, and its masks
			// replace values, which satisfies no removal.
			messages := a.Messages
			if slot.Implementation == RequestBodyFields {
				messages = []string{MessageRequest}
			}
			want := PointerTokens(field.Pointer)
			for _, pointer := range a.Pointers {
				if tokens := PointerTokens(pointer); len(tokens) <= len(want) && slices.Equal(tokens, want[:len(tokens)]) {
					return messages
				}
			}
		}
	}
	return nil
}
