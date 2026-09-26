package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// The inputs that broke the first field-level design (advisor report 82,
// Round 2): in each, PHP or a common JSON binder reads the protected value
// under the name a rule protects, and a literal match would keep it.
func TestT20Round2InputsAreRemoved(t *testing.T) {
	query := t20Slot("card", config.RemoveQueryParameters, `{"names":["card_number"]}`)
	form := t20Slot("card", config.RemoveFormFields, `{"names":["card_number"]}`)
	multipart := "--XB\r\nContent-Disposition: form-data; name=\"card_number\"\r\n\r\n" + t20Card + "\r\n--XB--\r\n"
	for _, tc := range []struct {
		name    string
		slot    config.Slot
		request string
		// other is a permitted value in the same component that must survive,
		// or empty where the whole component is removed.
		other string
	}{
		{"query-leading-space", query, t20Get("/pay?other=" + t20Other + "&%20card_number=" + t20Card), t20Other},
		{"form-leading-plus", form, t20Post("/pay", "application/x-www-form-urlencoded", "other="+t20Other+"&+card_number="+t20Card), t20Other},
		{"query-unmatched-bracket", query, t20Get("/pay?other=" + t20Other + "&card%5Bnumber=" + t20Card), t20Other},
		{"query-nul-cut", query, t20Get("/pay?other=" + t20Other + "&card_number%00x=" + t20Card), t20Other},
		{"multipart-under-form-rule", form, t20Post("/pay", "multipart/form-data; boundary=XB", multipart), ""},
		{"json-case-folded-member", t20Slot("card", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card/number"]}`),
			t20Post("/pay", "application/json", `{"other":"`+t20Other+`","card":{"NUMBER":"`+t20Card+`"}}`), t20Other},
		{"json-array-of-cards", t20Slot("card", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*/number"]}`),
			t20Post("/pay", "application/json", `{"other":"`+t20Other+`","cards":[{"number":"4000000000000002"},{"number":"`+t20Card+`"}]}`), t20Other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, text := t20Exchange(t, t20Plan(t, pipeline("exchanges", tc.slot)), tc.request, goodResponse)
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
