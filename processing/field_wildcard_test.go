package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// A * token matches every member of an object as well as every element of
// an array.
func TestWildcardMatchesObjectMembers(t *testing.T) {
	rule := fieldOf(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*/number"]}`)
	body := `{"cards":{"first":{"number":"` + fieldCard + `","other":"` + fieldOther + `"},"second":{"number":"4000000000000002"}}}`
	a, _, text := fieldExchange(t, fieldPlan(t, rule.implementation, rule.arguments), fieldPost("/pay", "application/json", body), goodResponse)
	fieldAbsent(t, text, fieldCard)
	fieldAbsent(t, text, "4000000000000002")
	fieldKept(t, text, fieldOther)
	if got := fieldBody(t, a, "request"); got != `{"cards":{"first":{"other":"`+fieldOther+`"},"second":{}}}` {
		t.Fatalf("PROPERTY: bytes outside the removed members changed: %q", got)
	}
}
