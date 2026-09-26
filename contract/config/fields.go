package config

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ExclusionField is one exclusion field form, parsed. Kind is the field
// constant or the prefix it was written with; Header, Name and Pointer carry
// what follows the prefix for a header, a query or form parameter, and a JSON
// field.
type ExclusionField struct {
	Kind    string
	Header  string
	Name    string
	Pointer string
}

// ParseExclusionField reads an exclusion field form. It accepts exactly the
// forms CONFIG.md lists, and the same function decides a requirement's field
// at compile time and an evidence entry's field in the reader.
func ParseExclusionField(field string) (ExclusionField, error) {
	switch field {
	case BodyField, BodyValuesField, TargetQueryField:
		return ExclusionField{Kind: field}, nil
	}
	if header, ok := strings.CutPrefix(field, HeaderFieldPrefix); ok {
		if !headerName(header) || strings.ToLower(header) != header {
			return ExclusionField{}, errors.New("a header field names a lowercase exact HTTP token")
		}
		return ExclusionField{Kind: HeaderFieldPrefix, Header: header}, nil
	}
	for _, prefix := range []string{QueryFieldPrefix, FormFieldPrefix} {
		if name, ok := strings.CutPrefix(field, prefix); ok {
			if err := ValidParameterName(name); err != nil {
				return ExclusionField{}, err
			}
			return ExclusionField{Kind: prefix, Name: name}, nil
		}
	}
	if pointer, ok := strings.CutPrefix(field, JSONFieldPrefix); ok {
		if err := ValidPointer(pointer); err != nil {
			return ExclusionField{}, err
		}
		return ExclusionField{Kind: JSONFieldPrefix, Pointer: pointer}, nil
	}
	return ExclusionField{}, errors.New("the field is not one of the supported exclusion field forms")
}

// ValidParameterName is the configured-name rule for query and form parameters.
// The refused bytes are the ones the matching readings change or split on, so
// a name holding one could never be compared against what PHP files.
func ValidParameterName(name string) error {
	if name == "" || len(name) > MaxParameterNameBytes {
		return fmt.Errorf("a parameter name is between 1 and %d bytes", MaxParameterNameBytes)
	}
	for _, b := range []byte(name) {
		if b < '!' || b > '~' || strings.IndexByte("&;=%+[].", b) >= 0 {
			return errors.New("a parameter name is printable ASCII without a space or any of & ; = % + . [ ]")
		}
	}
	return nil
}

// ValidPointer is the pointer rule: RFC 6901 syntax, a leading "/", valid
// UTF-8, and the byte and token bounds.
func ValidPointer(pointer string) error {
	if pointer == "" {
		return errors.New("the empty pointer names the whole document; remove-body removes a whole body")
	}
	if pointer[0] != '/' {
		return errors.New("a pointer begins with /")
	}
	if len(pointer) > MaxPointerBytes {
		return fmt.Errorf("a pointer is at most %d bytes", MaxPointerBytes)
	}
	if !utf8.ValidString(pointer) {
		return errors.New("a pointer is valid UTF-8")
	}
	for i := 0; i < len(pointer); i++ {
		if pointer[i] == '~' && (i+1 == len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1')) {
			return errors.New("in a pointer ~ is followed by 0 or 1")
		}
	}
	if strings.Count(pointer, "/") > MaxPointerTokens {
		return fmt.Errorf("a pointer has at most %d reference tokens", MaxPointerTokens)
	}
	return nil
}

// PointerTokens splits a pointer that ValidPointer accepted into its reference
// tokens, with ~1 read as / and ~0 as ~.
func PointerTokens(pointer string) []string {
	parts := strings.Split(pointer, "/")[1:]
	for i, part := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts
}
