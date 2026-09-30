package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// A * token matches every member of an object as well as every element of
// an array.
func TestT20WildcardMatchesObjectMembers(t *testing.T) {
	rule := t20Of(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*/number"]}`)
	body := `{"cards":{"first":{"number":"` + t20Card + `","other":"` + t20Other + `"},"second":{"number":"4000000000000002"}}}`
	a, _, text := t20Exchange(t, t20Plan(t, rule.implementation, rule.arguments), t20Post("/pay", "application/json", body), goodResponse)
	t20Absent(t, text, t20Card)
	t20Absent(t, text, "4000000000000002")
	t20Kept(t, text, t20Other)
	if got := t20Body(t, a, "request"); got != `{"cards":{"first":{"other":"`+t20Other+`"},"second":{}}}` {
		t.Fatalf("PROPERTY: bytes outside the removed members changed: %q", got)
	}
}
