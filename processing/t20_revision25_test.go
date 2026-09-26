package processing_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
)

// PHP splits on & alone, so a value may carry ; and every byte of it is filed
// under the name. Reading the parameters under & alone and under & with ;, and
// removing the union, removes that whole value and also a parameter that only
// the ; reading finds.
func TestT20SeparatorReadingsAreUnioned(t *testing.T) {
	for _, tc := range []struct{ name, implementation, arguments, text, want string }{
		{"value-carries-semicolon", config.RemoveFormFields, `{"names":["card_number"]}`,
			"other=" + t20Other + "&card_number=4111;1111111111111&z=1", "other=" + t20Other + "&z=1"},
		{"semicolon-reading-only", config.RemoveFormFields, `{"names":["card_number"]}`,
			"x=" + t20Other + ";card_number=" + t20Card + "&y=2", "x=" + t20Other + "&y=2"},
		{"value-tail-at-end", config.RemoveFormFields, `{"names":["card_number"]}`,
			"a=" + t20Other + "&card_number=" + t20Card + ";b=2", "a=" + t20Other},
		{"ampersand-kept-after", config.RemoveFormFields, `{"names":["card_number"]}`,
			"x=" + t20Other + ";card_number=" + t20Card + "&y=2;z=3", "x=" + t20Other + "&y=2;z=3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := t20Plan(t, pipeline("exchanges", t20Slot("rule", tc.implementation, tc.arguments)))
			a, _, text := t20Exchange(t, plan, t20Post("/pay", "application/x-www-form-urlencoded", tc.text), goodResponse)
			for _, secret := range []string{t20Card, "4111", "1111111111111"} {
				t20Absent(t, text, secret)
			}
			t20Kept(t, text, t20Other)
			if got := t20Body(t, a, "request"); got != tc.want {
				t.Fatalf("PROPERTY: the union removed the wrong bytes\n got %q\nwant %q", got, tc.want)
			}
		})
	}
	t.Run("query", func(t *testing.T) {
		plan := t20Plan(t, pipeline("exchanges", t20Slot("rule", config.RemoveQueryParameters, `{"names":["card_number"]}`)))
		a, _, text := t20Exchange(t, plan, t20Get("/pay?card_number=4111;1111111111111&other="+t20Other), goodResponse)
		t20Absent(t, text, "1111111111111")
		if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay?other="+t20Other {
			t.Fatalf("PROPERTY: the union removed the wrong bytes of the query: %q", got)
		}
	})
}

// A * token matches every member of an object as well as every element of
// an array, as PHP iterates both alike.
func TestT20WildcardMatchesObjectMembers(t *testing.T) {
	rule := t20Slot("card", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*/number"]}`)
	body := `{"cards":{"first":{"number":"` + t20Card + `","other":"` + t20Other + `"},"second":{"number":"4000000000000002"}}}`
	a, _, text := t20Exchange(t, t20Plan(t, pipeline("exchanges", rule)), t20Post("/pay", "application/json", body), goodResponse)
	t20Absent(t, text, t20Card)
	t20Absent(t, text, "4000000000000002")
	t20Kept(t, text, t20Other)
	if got := t20Body(t, a, "request"); got != `{"cards":{"first":{"other":"`+t20Other+`"},"second":{}}}` {
		t.Fatalf("PROPERTY: bytes outside the removed members changed: %q", got)
	}
}

// reduce-body-to-structure keeps member names, and a JSON member name can
// carry a form value PHP files, so it satisfies no form field exclusion.
func TestT20ReduceDoesNotSatisfyAFormField(t *testing.T) {
	requirement := []cp.Requirement{t20Requirement(config.FormFieldPrefix + "card_number")}
	t20Refused(t, config.ExclusionNotEnforced, requirement,
		pipeline("exchanges", t20Slot("r", config.ReduceBodyToStructure, `{"messages":["request","response"]}`)))
	request := t20Post("/pay", "application/x-www-form-urlencoded", "card_number="+t20Card)
	t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveBody, `{"messages":["request"]}`)))
	t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveFormFields, `{"names":["card_number"]}`)))

	// The case the rule exists for: the structure keeps a name that PHP,
	// reading the same bytes as a form, files the value under.
	plan := t20Plan(t, pipeline("exchanges", t20Slot("r", config.ReduceBodyToStructure, `{"messages":["request"]}`)))
	_, _, text := t20Exchange(t, plan, t20Post("/pay", "application/json", `{"&card_number=`+t20Card+`":1}`), goodResponse)
	if !strings.Contains(text, t20Card) {
		t.Fatal("wiring, not the property: the member name did not survive reduce-body-to-structure, so this case shows nothing about why it cannot satisfy a form field")
	}
}
