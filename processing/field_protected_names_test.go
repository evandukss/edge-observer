package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// The inputs a literal field-level match gets wrong: in each, an application
// reads the protected value under the name a rule protects, and a literal match
// would keep it.
func TestInputsReadUnderAProtectedNameAreRemoved(t *testing.T) {
	form := fieldOf(config.RemoveFormFields, `{"names":["card_number"]}`)
	multipart := "--XB\r\nContent-Disposition: form-data; name=\"card_number\"\r\n\r\n" + fieldCard + "\r\n--XB--\r\n"
	for _, tc := range []struct {
		name    string
		slot    fieldOp
		request string
		// other is a permitted value in the same component that must survive,
		// or empty where the whole component is removed.
		other string
	}{
		{"multipart-under-form-rule", form, fieldPost("/pay", "multipart/form-data; boundary=XB", multipart), ""},
		{"json-case-folded-member", fieldOf(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card/number"]}`),
			fieldPost("/pay", "application/json", `{"other":"`+fieldOther+`","card":{"NUMBER":"`+fieldCard+`"}}`), fieldOther},
		{"json-array-of-cards", fieldOf(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*/number"]}`),
			fieldPost("/pay", "application/json", `{"other":"`+fieldOther+`","cards":[{"number":"4000000000000002"},{"number":"`+fieldCard+`"}]}`), fieldOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, text := fieldExchange(t, fieldPlan(t, tc.slot.implementation, tc.slot.arguments), tc.request, goodResponse)
			fieldAbsent(t, text, fieldCard)
			if tc.name == "json-array-of-cards" {
				fieldAbsent(t, text, "4000000000000002")
			}
			if tc.other != "" {
				fieldKept(t, text, tc.other)
			}
		})
	}
}
