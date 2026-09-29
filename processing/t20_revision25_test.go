package processing_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
)

// A * token matches every member of an object as well as every element of
// an array.
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
// carry a form parameter, so it satisfies no form field exclusion.
func TestT20ReduceDoesNotSatisfyAFormField(t *testing.T) {
	requirement := []cp.Requirement{t20Requirement(config.FormFieldPrefix + "card_number")}
	t20Refused(t, config.ExclusionNotEnforced, requirement,
		pipeline("exchanges", t20Slot("r", config.ReduceBodyToStructure, `{"messages":["request","response"]}`)))
	request := t20Post("/pay", "application/x-www-form-urlencoded", "card_number="+t20Card)
	t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveBody, `{"messages":["request"]}`)))
	t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveFormFields, `{"names":["card_number"]}`)))

	// The case the rule exists for: the structure keeps a name that, read as a
	// form split on &, is a card_number parameter carrying the value.
	plan := t20Plan(t, pipeline("exchanges", t20Slot("r", config.ReduceBodyToStructure, `{"messages":["request"]}`)))
	_, _, text := t20Exchange(t, plan, t20Post("/pay", "application/json", `{"&card_number=`+t20Card+`":1}`), goodResponse)
	if !strings.Contains(text, t20Card) {
		t.Fatal("wiring, not the property: the member name did not survive reduce-body-to-structure, so this case shows nothing about why it cannot satisfy a form field")
	}
}
