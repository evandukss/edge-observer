package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

func compileHeaderArguments(implementation string, raw json.RawMessage) (*HeaderArguments, error) {
	var given struct {
		Headers []string `json:"headers"`
		Value   *string  `json:"value"`
		Length  *int     `json:"length"`
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
	allowed := map[string]bool{"headers": true}
	switch implementation {
	case RemoveHeaders:
	case ReplaceHeaderValues:
		allowed["value"] = true
	case TruncateHeaderValues:
		allowed["length"] = true
	default:
		return nil, fmt.Errorf("no argument definition for component")
	}
	for key := range members {
		if !allowed[key] {
			return nil, fmt.Errorf("argument %q is not defined for %s", key, implementation)
		}
	}
	if len(given.Headers) == 0 || len(given.Headers) > MaxHeaderNames {
		return nil, fmt.Errorf("headers must contain between 1 and %d exact names", MaxHeaderNames)
	}
	seen := map[string]bool{}
	args := &HeaderArguments{}
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
	switch implementation {
	case ReplaceHeaderValues:
		if given.Value == nil {
			return nil, fmt.Errorf("value is required and must be a string")
		}
		if len(*given.Value) > MaxHeaderValueBytes {
			return nil, fmt.Errorf("value exceeds %d bytes", MaxHeaderValueBytes)
		}
		for _, b := range []byte(*given.Value) {
			if b < 32 || b > 126 {
				return nil, fmt.Errorf("value must contain only printable ASCII")
			}
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
