package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// argumentMembers is each compiled-in operation's exact member set.
var argumentMembers = map[string][]string{
	RemoveHeaders:         {"headers"},
	ReplaceHeaderValues:   {"headers", "value"},
	TruncateHeaderValues:  {"headers", "length"},
	RemoveBody:            {"messages"},
	ReduceBodyToStructure: {"messages"},
	RemoveQuery:           {},
	RemoveJSONFields:      {"messages", "pointers"},
	ReplaceJSONValues:     {"messages", "pointers", "value"},
	RemoveFormFields:      {"names"},
	RemoveQueryParameters: {"names"},
	RequestBodyFields:     {"names", "pointers", "masks"},
}

func compileArguments(implementation string, raw json.RawMessage) (*Arguments, error) {
	var given struct {
		Headers  []string `json:"headers"`
		Value    *string  `json:"value"`
		Length   *int     `json:"length"`
		Messages []string `json:"messages"`
		Pointers []string `json:"pointers"`
		Names    []string `json:"names"`
		Masks    []struct {
			Pointer string  `json:"pointer"`
			Value   *string `json:"value"`
		} `json:"masks"`
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("configuration must be an argument object")
	}
	if err := decode(raw, &given); err != nil {
		return nil, fmt.Errorf("invalid argument object: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, fmt.Errorf("configuration must be an argument object")
	}
	defined, known := argumentMembers[implementation]
	if !known {
		return nil, fmt.Errorf("no argument definition for component")
	}
	for key := range members {
		if !slices.Contains(defined, key) {
			return nil, fmt.Errorf("argument %q is not defined for %s", key, implementation)
		}
	}
	for _, key := range defined {
		if _, present := members[key]; !present {
			return nil, fmt.Errorf("argument %q is required for %s", key, implementation)
		}
	}
	args := &Arguments{}
	if slices.Contains(defined, "headers") {
		if len(given.Headers) == 0 || len(given.Headers) > MaxHeaderNames {
			return nil, fmt.Errorf("headers must contain between 1 and %d exact names", MaxHeaderNames)
		}
		seen := map[string]bool{}
		for _, name := range given.Headers {
			if !headerName(name) {
				return nil, fmt.Errorf("headers must contain exact HTTP token names")
			}
			lower := strings.ToLower(name)
			if seen[lower] {
				return nil, fmt.Errorf("header names must be distinct ignoring case")
			}
			seen[lower] = true
			args.Headers = append(args.Headers, lower)
		}
	}
	if slices.Contains(defined, "messages") {
		messages, err := compileMessages(given.Messages)
		if err != nil {
			return nil, err
		}
		args.Messages = messages
	}
	if slices.Contains(defined, "pointers") {
		// request-body-fields may carry masks in place of removals.
		least := 1
		if implementation == RequestBodyFields {
			least = 0
		}
		if len(given.Pointers) < least || len(given.Pointers) > MaxFieldSelectors {
			return nil, fmt.Errorf("pointers must contain between %d and %d pointers", least, MaxFieldSelectors)
		}
		for i, pointer := range given.Pointers {
			if err := ValidPointer(pointer); err != nil {
				return nil, fmt.Errorf("pointers[%d]: %w", i, err)
			}
			if slices.Contains(args.Pointers, pointer) {
				return nil, fmt.Errorf("pointers must be distinct")
			}
			args.Pointers = append(args.Pointers, pointer)
		}
	}
	if slices.Contains(defined, "names") {
		if len(given.Names) == 0 || len(given.Names) > MaxFieldSelectors {
			return nil, fmt.Errorf("names must contain between 1 and %d parameter names", MaxFieldSelectors)
		}
		for i, name := range given.Names {
			if err := ValidParameterName(name); err != nil {
				return nil, fmt.Errorf("names[%d]: %w", i, err)
			}
			if slices.Contains(args.Names, name) {
				return nil, fmt.Errorf("names must be distinct")
			}
			args.Names = append(args.Names, name)
		}
	}
	if slices.Contains(defined, "masks") {
		if len(given.Masks) > MaxFieldSelectors {
			return nil, fmt.Errorf("masks must contain at most %d masks", MaxFieldSelectors)
		}
		for i, mask := range given.Masks {
			if err := ValidPointer(mask.Pointer); err != nil {
				return nil, fmt.Errorf("masks[%d].pointer: %w", i, err)
			}
			if slices.ContainsFunc(args.Masks, func(m JSONMask) bool { return m.Pointer == mask.Pointer }) {
				return nil, fmt.Errorf("mask pointers must be distinct")
			}
			if mask.Value == nil {
				return nil, fmt.Errorf("masks[%d].value is required and must be a string", i)
			}
			if len(*mask.Value) > MaxJSONValueBytes {
				return nil, fmt.Errorf("masks[%d].value exceeds %d bytes", i, MaxJSONValueBytes)
			}
			if !printable(*mask.Value) {
				return nil, fmt.Errorf("masks[%d].value must contain only printable ASCII", i)
			}
			args.Masks = append(args.Masks, JSONMask{Pointer: mask.Pointer, Value: *mask.Value})
		}
	}
	switch implementation {
	case RequestBodyFields:
		if len(args.Pointers)+len(args.Masks) == 0 {
			return nil, fmt.Errorf("pointers and masks must hold at least one JSON rule between them")
		}
	case ReplaceHeaderValues:
		if given.Value == nil {
			return nil, fmt.Errorf("value is required and must be a string")
		}
		if len(*given.Value) > MaxHeaderValueBytes {
			return nil, fmt.Errorf("value exceeds %d bytes", MaxHeaderValueBytes)
		}
		if !printable(*given.Value) {
			return nil, fmt.Errorf("value must contain only printable ASCII")
		}
		args.Value = *given.Value
	case ReplaceJSONValues:
		if given.Value == nil {
			return nil, fmt.Errorf("value is required and must be a string")
		}
		if len(*given.Value) > MaxJSONValueBytes {
			return nil, fmt.Errorf("value exceeds %d bytes", MaxJSONValueBytes)
		}
		if !printable(*given.Value) {
			return nil, fmt.Errorf("value must contain only printable ASCII")
		}
		args.Value = *given.Value
	case TruncateHeaderValues:
		if given.Length == nil {
			return nil, fmt.Errorf("length is required and must be an integer")
		}
		if *given.Length < 0 || *given.Length > MaxHeaderValueBytes {
			return nil, fmt.Errorf("length must be between 0 and %d bytes", MaxHeaderValueBytes)
		}
		args.Length = *given.Length
	}
	return args, nil
}

// compileMessages resolves a message selection to request-then-response order.
func compileMessages(given []string) ([]string, error) {
	if len(given) == 0 {
		return nil, fmt.Errorf("messages must name request, response or both")
	}
	var request, response int
	for _, m := range given {
		switch m {
		case MessageRequest:
			request++
		case MessageResponse:
			response++
		default:
			return nil, fmt.Errorf("messages may contain only request and response")
		}
	}
	if request > 1 || response > 1 {
		return nil, fmt.Errorf("messages must be distinct")
	}
	var out []string
	if request == 1 {
		out = append(out, MessageRequest)
	}
	if response == 1 {
		out = append(out, MessageResponse)
	}
	return out, nil
}

func printable(value string) bool {
	for _, b := range []byte(value) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

func headerName(name string) bool {
	if name == "" {
		return false
	}
	for _, b := range []byte(name) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			continue
		}
		return false
	}
	return true
}
