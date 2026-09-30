package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// The inputs that broke the first field-level design (advisor report 82,
// Round 2): in each, an application reads the protected value under the name
// a rule protects, and a literal match would keep it.
func TestT20Round2InputsAreRemoved(t *testing.T) {
	form := t20Of(config.RemoveFormFields, `{"names":["card_number"]}`)
	multipart := "--XB\r\nContent-Disposition: form-data; name=\"card_number\"\r\n\r\n" + t20Card + "\r\n--XB--\r\n"
	for _, tc := range []struct {
		name    string
		slot    t20Op
		request string
		// other is a permitted value in the same component that must survive,
		// or empty where the whole component is removed.
		other string
	}{
		{"multipart-under-form-rule", form, t20Post("/pay", "multipart/form-data; boundary=XB", multipart), ""},
		{"json-case-folded-member", t20Of(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card/number"]}`),
			t20Post("/pay", "application/json", `{"other":"`+t20Other+`","card":{"NUMBER":"`+t20Card+`"}}`), t20Other},
		{"json-array-of-cards", t20Of(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*/number"]}`),
			t20Post("/pay", "application/json", `{"other":"`+t20Other+`","cards":[{"number":"4000000000000002"},{"number":"`+t20Card+`"}]}`), t20Other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, text := t20Exchange(t, t20Plan(t, tc.slot.implementation, tc.slot.arguments), tc.request, goodResponse)
			t20Absent(t, text, t20Card)
			if tc.name == "json-array-of-cards" {
				t20Absent(t, text, "4000000000000002")
			}
			if tc.other != "" {
				t20Kept(t, text, tc.other)
			}
		})
	}
}
