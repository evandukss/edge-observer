// Package jsonshape records the shape of a JSON body and nothing about what it
// means: field names, nesting, and each value's kind. It reports no value and
// holds no opinion about any name.
//
// The kinds are syntax: a decimal string is a string written as a decimal
// numeral; short and long are sides of a length bucket.
//
// Everything is bounded: nesting, nodes, fields per object, distinct element
// shapes per array, and name length. A name past its bound is dropped, not
// shortened, since a shortened name is a different name.
package jsonshape

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Kind is what a value was written as.
type Kind uint8

const (
	// Invalid is the zero value and belongs to no value.
	Invalid Kind = iota
	Object
	Array
	// Integer is a JSON number with no fractional part and no exponent.
	Integer
	// Fraction is a JSON number with either.
	Fraction
	Boolean
	Null
	// ShortString is a string within the length bucket.
	ShortString
	// LongString is a string past it.
	LongString
	// DecimalString is a string whose whole content is a decimal numeral: how it
	// was written, not what it holds.
	DecimalString
)

func (k Kind) String() string {
	switch k {
	case Object:
		return "object"
	case Array:
		return "array"
	case Integer:
		return "integer"
	case Fraction:
		return "fraction"
	case Boolean:
		return "boolean"
	case Null:
		return "null"
	case ShortString:
		return "short string"
	case LongString:
		return "long string"
	case DecimalString:
		return "decimal string"
	default:
		return "invalid"
	}
}

// Field is one member of an object.
type Field struct {
	Name string
	// NameElided reports that the name exceeded the bound and was dropped; Name is
	// then empty.
	NameElided bool
	Shape      Shape
}

// Shape is one value's structure.
type Shape struct {
	Kind Kind
	// Fields are an object's members, in the order they were sent, repeats
	// included.
	Fields []Field
	// Elems are the distinct shapes an array's elements had, in first-seen order:
	// ten thousand alike objects are one shape and a count.
	Elems []Shape
	// Count is how many elements an array had, whether or not their shapes
	// were held.
	Count int
	// Elided reports that structure at or under this value was dropped at a
	// bound.
	Elided bool
}

// Limits bounds what one body can make this package follow or hold. A zero
// field takes its default.
type Limits struct {
	MaxDepth         int
	MaxNodes         int
	MaxFields        int
	MaxElemShapes    int
	MaxNameBytes     int
	ShortStringBytes int
}

// DefaultLimits are bounds ordinary API bodies do not reach.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:         32,
		MaxNodes:         4096,
		MaxFields:        512,
		MaxElemShapes:    8,
		MaxNameBytes:     128,
		ShortStringBytes: 64,
	}
}

func (l Limits) orDefaults() Limits {
	d := DefaultLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = d.MaxNodes
	}
	if l.MaxFields <= 0 {
		l.MaxFields = d.MaxFields
	}
	if l.MaxElemShapes <= 0 {
		l.MaxElemShapes = d.MaxElemShapes
	}
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = d.MaxNameBytes
	}
	if l.ShortStringBytes <= 0 {
		l.ShortStringBytes = d.ShortStringBytes
	}
	return l
}

// ErrRefused is what every Extract failure wraps.
var ErrRefused = errors.New("the body is not one whole JSON value read within its bounds")

// Extract reads the shape of one JSON value, which must be the whole of data.
// A fragment, trailing data, two values or non-JSON are refused: a partial
// shape would describe a body nobody sent.
func Extract(data []byte, limits Limits) (Shape, error) {
	e := &extractor{limits: limits.orDefaults()}
	e.decoder = json.NewDecoder(bytes.NewReader(data))
	e.decoder.UseNumber()

	shape, err := e.value(1, true)
	if err != nil {
		return Shape{}, err
	}

	// Nothing but whitespace may follow the value.
	if _, err := e.decoder.Token(); !errors.Is(err, io.EOF) {
		return Shape{}, fmt.Errorf("%w: something follows the value", ErrRefused)
	}

	shape.Elided = shape.Elided || e.elided
	return shape, nil
}

type extractor struct {
	decoder *json.Decoder
	limits  Limits
	nodes   int
	elided  bool
}

// value reads one JSON value; hold says whether its shape is kept. A value past
// the node bound is still read (the rest cannot be reached otherwise) but not
// held.
func (e *extractor) value(depth int, hold bool) (Shape, error) {
	if depth > e.limits.MaxDepth {
		return Shape{}, fmt.Errorf("%w: nesting deeper than %d", ErrRefused, e.limits.MaxDepth)
	}
	e.nodes++

	token, err := e.decoder.Token()
	if err != nil {
		return Shape{}, fmt.Errorf("%w: %v", ErrRefused, err)
	}

	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			return e.object(depth, hold)
		case '[':
			return e.array(depth, hold)
		default:
			return Shape{}, fmt.Errorf("%w: %q where a value was expected", ErrRefused, t)
		}
	case string:
		return Shape{Kind: e.stringKind(t)}, nil
	case json.Number:
		return Shape{Kind: numberKind(string(t))}, nil
	case bool:
		return Shape{Kind: Boolean}, nil
	case nil:
		return Shape{Kind: Null}, nil
	default:
		return Shape{}, fmt.Errorf("%w: a value of no kind this reader knows", ErrRefused)
	}
}

func (e *extractor) object(depth int, hold bool) (Shape, error) {
	shape := Shape{Kind: Object}

	for e.decoder.More() {
		token, err := e.decoder.Token()
		if err != nil {
			return shape, fmt.Errorf("%w: %v", ErrRefused, err)
		}
		name, ok := token.(string)
		if !ok {
			return shape, fmt.Errorf("%w: a member with no name", ErrRefused)
		}

		keep := hold && len(shape.Fields) < e.limits.MaxFields && e.nodes < e.limits.MaxNodes
		child, err := e.value(depth+1, keep)
		if err != nil {
			return shape, err
		}
		if !keep {
			e.elided, shape.Elided = true, true
			continue
		}

		field := Field{Shape: child}
		if len(name) > e.limits.MaxNameBytes {
			field.NameElided = true
		} else {
			field.Name = name
		}
		shape.Fields = append(shape.Fields, field)
	}

	if _, err := e.decoder.Token(); err != nil {
		return shape, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	return shape, nil
}

func (e *extractor) array(depth int, hold bool) (Shape, error) {
	shape := Shape{Kind: Array}

	for e.decoder.More() {
		keep := hold && e.nodes < e.limits.MaxNodes
		child, err := e.value(depth+1, keep)
		if err != nil {
			return shape, err
		}
		shape.Count++
		if !keep {
			e.elided, shape.Elided = true, true
			continue
		}

		if held(shape.Elems, child) {
			continue
		}
		if len(shape.Elems) >= e.limits.MaxElemShapes {
			e.elided, shape.Elided = true, true
			continue
		}
		shape.Elems = append(shape.Elems, child)
	}

	if _, err := e.decoder.Token(); err != nil {
		return shape, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	return shape, nil
}

// held reports whether one of these shapes is already this one; shapes compare
// by rendering.
func held(shapes []Shape, want Shape) bool {
	rendered := want.String()
	for _, shape := range shapes {
		if shape.String() == rendered {
			return true
		}
	}
	return false
}

func (e *extractor) stringKind(s string) Kind {
	switch {
	case isDecimal(s):
		return DecimalString
	case len(s) <= e.limits.ShortStringBytes:
		return ShortString
	default:
		return LongString
	}
}

// isDecimal reports whether the whole of s is a decimal numeral, optionally
// signed and optionally with a fractional part.
func isDecimal(s string) bool {
	s = strings.TrimPrefix(s, "-")
	whole, fraction, dotted := strings.Cut(s, ".")
	if !digits(whole) {
		return false
	}
	return !dotted || digits(fraction)
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func numberKind(s string) Kind {
	if strings.ContainsAny(s, ".eE") {
		return Fraction
	}
	return Integer
}

// String renders the shape as an indented tree. It carries the field names,
// the nesting and the kinds, and no value.
func (s Shape) String() string {
	var b strings.Builder
	s.write(&b, "", "")
	return strings.TrimRight(b.String(), "\n")
}

func (s Shape) write(b *strings.Builder, indent, label string) {
	head := s.Kind.String()
	if s.Kind == Array {
		head = fmt.Sprintf("array of %d", s.Count)
	}
	if s.Elided {
		head += " (elided)"
	}
	b.WriteString(indent + label + head + "\n")

	switch s.Kind {
	case Object:
		for _, field := range s.Fields {
			name := field.Name
			if field.NameElided {
				name = "(elided)"
			}
			field.Shape.write(b, indent+"  ", name+": ")
		}
	case Array:
		for _, elem := range s.Elems {
			elem.write(b, indent+"  ", "")
		}
	}
}
