package jsonshape_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/jsonshape"
)

func extract(t *testing.T, body string) jsonshape.Shape {
	t.Helper()
	shape, err := jsonshape.Extract([]byte(body), jsonshape.DefaultLimits())
	if err != nil {
		t.Fatalf("Extract(%q) = %v", body, err)
	}
	return shape
}

func TestAFieldsNameAndTheKindOfItsValueAreReported(t *testing.T) {
	shape := extract(t, `{"ref":"order-4001","amt":"1995","count":2,"rate":1.5,"ok":true,"note":null}`)

	if shape.Kind != jsonshape.Object {
		t.Fatalf("Kind = %s, want %s", shape.Kind, jsonshape.Object)
	}

	want := []struct {
		name string
		kind jsonshape.Kind
	}{
		{"ref", jsonshape.ShortString},
		{"amt", jsonshape.DecimalString},
		{"count", jsonshape.Integer},
		{"rate", jsonshape.Fraction},
		{"ok", jsonshape.Boolean},
		{"note", jsonshape.Null},
	}
	if len(shape.Fields) != len(want) {
		t.Fatalf("read %d fields, want %d: %v", len(shape.Fields), len(want), shape.Fields)
	}
	for i, w := range want {
		if got := shape.Fields[i]; got.Name != w.name || got.Shape.Kind != w.kind {
			t.Errorf("field %d = %q %s, want %q %s", i, got.Name, got.Shape.Kind, w.name, w.kind)
		}
	}
}

func TestAStringLongerThanTheBucketIsALongOne(t *testing.T) {
	limits := jsonshape.DefaultLimits()
	limits.ShortStringBytes = 4

	shape, err := jsonshape.Extract([]byte(`{"a":"abcd","b":"abcde"}`), limits)
	if err != nil {
		t.Fatalf("Extract() = %v", err)
	}
	if got, want := shape.Fields[0].Shape.Kind, jsonshape.ShortString; got != want {
		t.Errorf("a = %s, want %s", got, want)
	}
	if got, want := shape.Fields[1].Shape.Kind, jsonshape.LongString; got != want {
		t.Errorf("b = %s, want %s", got, want)
	}
}

func TestNestingIsReported(t *testing.T) {
	shape := extract(t, `{"user":{"name":"1234","created":{"month":3}}}`)

	user := shape.Fields[0]
	if user.Name != "user" || user.Shape.Kind != jsonshape.Object {
		t.Fatalf("outer field = %q %s", user.Name, user.Shape.Kind)
	}
	created := user.Shape.Fields[1]
	if created.Name != "created" || created.Shape.Kind != jsonshape.Object {
		t.Fatalf("inner field = %q %s", created.Name, created.Shape.Kind)
	}
	if got, want := created.Shape.Fields[0].Shape.Kind, jsonshape.Integer; got != want {
		t.Errorf("innermost = %s, want %s", got, want)
	}
}

// An array's shape is its count and its distinct element shapes, not one shape
// per element.
func TestAnArrayReportsItsCountAndTheDistinctShapesOfItsElements(t *testing.T) {
	shape := extract(t, `{"items":[{"a":1},{"a":2},{"b":"x"},7]}`)

	items := shape.Fields[0].Shape
	if items.Kind != jsonshape.Array {
		t.Fatalf("Kind = %s, want %s", items.Kind, jsonshape.Array)
	}
	if got, want := items.Count, 4; got != want {
		t.Errorf("Count = %d, want %d", got, want)
	}
	if got, want := len(items.Elems), 3; got != want {
		t.Fatalf("read %d distinct element shapes, want %d: %v", got, want, items.Elems)
	}
	if got, want := items.Elems[2].Kind, jsonshape.Integer; got != want {
		t.Errorf("third distinct element = %s, want %s", got, want)
	}
}

func TestAnEmptyObjectAndAnEmptyArrayAreNotTheSameShape(t *testing.T) {
	object := extract(t, `{}`)
	array := extract(t, `[]`)

	if object.Kind != jsonshape.Object || len(object.Fields) != 0 {
		t.Errorf("{} = %s with %d fields", object.Kind, len(object.Fields))
	}
	if array.Kind != jsonshape.Array || array.Count != 0 {
		t.Errorf("[] = %s with %d elements", array.Kind, array.Count)
	}
}

// Duplicate field names are all recorded: bodies aimed at two disagreeing
// parsers carry them.
func TestTwoFieldsOfOneNameAreBothRecordedInTheOrderTheyWereSent(t *testing.T) {
	shape := extract(t, `{"amt":"1995","amt":7}`)

	if got, want := len(shape.Fields), 2; got != want {
		t.Fatalf("read %d fields, want %d", got, want)
	}
	if shape.Fields[0].Name != "amt" || shape.Fields[1].Name != "amt" {
		t.Fatalf("fields = %q and %q", shape.Fields[0].Name, shape.Fields[1].Name)
	}
	if shape.Fields[0].Shape.Kind != jsonshape.DecimalString || shape.Fields[1].Shape.Kind != jsonshape.Integer {
		t.Errorf("kinds = %s and %s", shape.Fields[0].Shape.Kind, shape.Fields[1].Shape.Kind)
	}
}

func TestWhatIsNotOneWholeJSONValueIsRefused(t *testing.T) {
	cases := map[string]string{
		"nothing at all":               ``,
		"only whitespace":              "  \n\t ",
		"a fragment of an object":      `{"a":`,
		"an unterminated string":       `{"a":"b`,
		"a second value after the one": `{"a":1} {"b":2}`,
		"rubbish after the value":      `{"a":1}xx`,
		"markup rather than JSON":      `<html><body>no</body></html>`,
		"a trailing comma":             `{"a":1,}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := jsonshape.Extract([]byte(body), jsonshape.DefaultLimits()); err == nil {
				t.Fatalf("Extract(%q) = nil, want an error", body)
			}
		})
	}
}

func TestNestingDeeperThanTheBoundIsRefusedRatherThanFollowed(t *testing.T) {
	limits := jsonshape.DefaultLimits()
	limits.MaxDepth = 4

	body := strings.Repeat(`{"a":`, 64) + `1` + strings.Repeat(`}`, 64)
	if _, err := jsonshape.Extract([]byte(body), limits); err == nil {
		t.Fatal("Extract() = nil, want an error for nesting past the bound")
	}
}

func TestMoreStructureThanTheBoundIsElidedRatherThanHeld(t *testing.T) {
	limits := jsonshape.DefaultLimits()
	limits.MaxNodes = 8

	var fields []string
	for i := 0; i < 200; i++ {
		fields = append(fields, `"f`+string(rune('a'+i%26))+`":1`)
	}
	shape, err := jsonshape.Extract([]byte("{"+strings.Join(fields, ",")+"}"), limits)
	if err != nil {
		t.Fatalf("Extract() = %v", err)
	}
	if !shape.Elided {
		t.Fatal("Elided = false; the shape held everything past its bound")
	}
	if len(shape.Fields) > limits.MaxNodes {
		t.Fatalf("held %d fields, bound %d", len(shape.Fields), limits.MaxNodes)
	}
}

// A name past the bound is dropped, not shortened.
func TestANameLongerThanTheBoundIsDroppedRatherThanShortened(t *testing.T) {
	limits := jsonshape.DefaultLimits()
	limits.MaxNameBytes = 8

	shape, err := jsonshape.Extract([]byte(`{"`+strings.Repeat("n", 40)+`":1}`), limits)
	if err != nil {
		t.Fatalf("Extract() = %v", err)
	}
	field := shape.Fields[0]
	if !field.NameElided {
		t.Fatal("NameElided = false for a name past the bound")
	}
	if field.Name != "" {
		t.Fatalf("Name = %q, want it dropped", field.Name)
	}
}

func TestATopLevelValueThatIsNotAnObjectIsStillAShape(t *testing.T) {
	for body, want := range map[string]jsonshape.Kind{
		`"1995"`: jsonshape.DecimalString,
		`17`:     jsonshape.Integer,
		`true`:   jsonshape.Boolean,
		`null`:   jsonshape.Null,
		`[1,2]`:  jsonshape.Array,
	} {
		if got := extract(t, body).Kind; got != want {
			t.Errorf("Extract(%s) = %s, want %s", body, got, want)
		}
	}
}
