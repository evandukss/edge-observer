package jsonshape_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/jsonshape"
)

// FuzzExtractHoldsItsBounds: for any body, extraction follows no deeper and
// holds no more nodes than the bounds, and answers the same twice.
func FuzzExtractHoldsItsBounds(f *testing.F) {
	f.Add([]byte(`{"mid":"M-1","amt":"19.95","items":[{"a":1},{"a":2}],"ok":true,"x":null}`))
	f.Add([]byte(`[[[[[[[[[[1]]]]]]]]]]`))
	f.Add([]byte(`{"a":`))
	f.Add([]byte(`"` + strings.Repeat("x", 300) + `"`))
	f.Add([]byte(``))
	f.Add([]byte(`{"a":1}{"b":2}`))

	limits := jsonshape.Limits{
		MaxDepth: 6, MaxNodes: 32, MaxFields: 8, MaxElemShapes: 3,
		MaxNameBytes: 8, ShortStringBytes: 4,
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		shape, err := jsonshape.Extract(body, limits)
		if err != nil {
			// A body that is not one whole JSON value is refused and has no shape.
			if shape.Kind != jsonshape.Invalid {
				t.Fatalf("a refusal came back with the shape %s", shape.Kind)
			}
			return
		}

		nodes, deepest := count(shape, 1)
		if nodes > limits.MaxNodes {
			t.Fatalf("held %d nodes, bound %d", nodes, limits.MaxNodes)
		}
		if deepest > limits.MaxDepth {
			t.Fatalf("held %d levels, bound %d", deepest, limits.MaxDepth)
		}

		if again, err := jsonshape.Extract(body, limits); err != nil || again.String() != shape.String() {
			t.Fatalf("a second reading of one body differs: %v", err)
		}
	})
}

func count(s jsonshape.Shape, depth int) (nodes, deepest int) {
	nodes, deepest = 1, depth
	for _, field := range s.Fields {
		n, d := count(field.Shape, depth+1)
		nodes += n
		deepest = max(deepest, d)
	}
	for _, elem := range s.Elems {
		n, d := count(elem, depth+1)
		nodes += n
		deepest = max(deepest, d)
	}
	return nodes, deepest
}

// FuzzTheRenderingOfABodyCarriesNoneOfItsStringValues: names and string values
// come from disjoint alphabets and no kind word contains the value marker, so a
// value in the rendering can only have come from the value. Numbers, booleans
// and nulls are outside what this proves (an array's count is a number).
func FuzzTheRenderingOfABodyCarriesNoneOfItsStringValues(f *testing.F) {
	f.Add(uint64(1))
	f.Add(uint64(0))
	f.Add(uint64(0xdeadbeefcafe))
	f.Add(^uint64(0))

	f.Fuzz(func(t *testing.T, seed uint64) {
		body, values := generate(&source{state: seed}, 1)
		if !json.Valid([]byte(body)) {
			t.Fatalf("the generator made something that is not JSON: %s", body)
		}

		shape, err := jsonshape.Extract([]byte(body), jsonshape.DefaultLimits())
		if err != nil {
			t.Fatalf("Extract(%s) = %v", body, err)
		}

		rendering := shape.String()
		for _, value := range values {
			if strings.Contains(rendering, value) {
				t.Fatalf("the rendering carries the value %q:\n%s\nfrom %s", value, rendering, body)
			}
		}
	})
}

type source struct{ state uint64 }

func (s *source) next(bound int) int {
	s.state = s.state*6364136223846793005 + 1442695040888963407
	if bound <= 0 {
		return 0
	}
	return int(s.state>>33) % bound
}

// generate builds a JSON body whose string values are markers no name or kind
// word can contain, and returns them.
func generate(s *source, depth int) (string, []string) {
	if depth > 5 {
		return strconv.Itoa(s.next(1000)), nil
	}

	switch s.next(6) {
	case 0, 1:
		var members []string
		var values []string
		for i, n := 0, s.next(5); i < n; i++ {
			body, held := generate(s, depth+1)
			members = append(members, fmt.Sprintf("%q:%s", "nm"+strconv.Itoa(s.next(20)), body))
			values = append(values, held...)
		}
		return "{" + strings.Join(members, ",") + "}", values

	case 2:
		var elements []string
		var values []string
		for i, n := 0, s.next(4); i < n; i++ {
			body, held := generate(s, depth+1)
			elements = append(elements, body)
			values = append(values, held...)
		}
		return "[" + strings.Join(elements, ",") + "]", values

	case 3:
		marker := "zqv" + strconv.Itoa(s.next(100000)) + "vqz"
		return strconv.Quote(marker), []string{marker}

	case 4:
		return []string{"true", "false", "null"}[s.next(3)], nil

	default:
		return strconv.Itoa(s.next(1000000)), nil
	}
}
