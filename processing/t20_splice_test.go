package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// Every byte outside the removed member is kept: whitespace, key order,
// escapes and number spelling. Each case states the whole expected body, so a
// re-serialisation, a moved comma or a dropped space fails it.
func TestT20SplicingKeepsEveryOtherByte(t *testing.T) {
	for _, tc := range []struct {
		name, implementation, arguments, body, want string
	}{
		{"json-first-member", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card/number"]}`,
			"{ \"z\" : 1 ,\n  \"card\" : { \"number\" : \"" + t20Card + "\" , \"cvc\":\"123\" } ,\t\"a\\u0062c\":\"x\\\"y\" , \"n\": 1.50e+3 }",
			"{ \"z\" : 1 ,\n  \"card\" : { \"cvc\":\"123\" } ,\t\"a\\u0062c\":\"x\\\"y\" , \"n\": 1.50e+3 }"},
		{"json-last-member", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card"]}`,
			"{\"n\":-0.5E-2,\r\n\"s\":\"\\/\\u00e9\",   \"card\" :\n\"" + t20Card + "\"\n}",
			"{\"n\":-0.5E-2,\r\n\"s\":\"\\/\\u00e9\"\n}"},
		{"json-only-member", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/*/card"]}`,
			"[ { \"card\" : \"" + t20Card + "\" } ]",
			"[ {  } ]"},
		{"json-duplicates-and-escaped-name", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card"]}`,
			"{\"card\":\"" + t20Card + "\", \"keep\":true, \"\\u0063ard\":\"" + t20Card + "\",\"CARD\":0}",
			"{\"keep\":true}"},
		{"json-wildcard-elements", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/cards/*"]}`,
			"{\"cards\" : [ \"" + t20Card + "\" ,\"" + t20Card + "\" ] , \"k\":null}",
			"{\"cards\" : [  ] , \"k\":null}"},
		{"json-index-and-middle-run", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/a/1","/a/2"]}`,
			"{\"a\":[10, \"" + t20Card + "\", \"" + t20Card + "\", 13]}",
			"{\"a\":[10, 13]}"},
		{"json-replace", config.ReplaceJSONValues, `{"messages":["request"],"pointers":["/card/number"],"value":"re\"da\\cted"}`,
			"{ \"card\" : { \"number\" : \"" + t20Card + "\" } }",
			"{ \"card\" : { \"number\" : \"re\\\"da\\\\cted\" } }"},
		{"form-middle", config.RemoveFormFields, `{"names":["card_number"]}`,
			"a=1&card_number=" + t20Card + "&b=%20&&c",
			"a=1&b=%20&&c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contentType := "application/json"
			if tc.implementation == config.RemoveFormFields {
				contentType = "application/x-www-form-urlencoded"
			}
			plan := t20Plan(t, pipeline("exchanges", t20Slot("rule", tc.implementation, tc.arguments)))
			a, _, text := t20Exchange(t, plan, t20Post("/pay", contentType, tc.body), goodResponse)
			t20Absent(t, text, t20Card)
			if got := t20Body(t, a, "request"); got != tc.want {
				t.Fatalf("PROPERTY: bytes outside the removed span changed\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestT20QuerySplicingKeepsEveryOtherByte(t *testing.T) {
	for _, tc := range []struct{ name, implementation, arguments, target, want string }{
		{"parameter-first", config.RemoveQueryParameters, `{"names":["card_number"]}`, "/p/a?card_number=" + t20Card + "&x=%41+b", "/p/a?x=%41+b"},
		{"parameter-only", config.RemoveQueryParameters, `{"names":["card_number"]}`, "/p?card_number=" + t20Card, "/p?"},
		{"parameter-absent", config.RemoveQueryParameters, `{"names":["card_number"]}`, "/p?x=1&card_numbers=2", "/p?x=1&card_numbers=2"},
		{"whole-query", config.RemoveQuery, `{}`, "/p/a?card_number=" + t20Card + "&x=1", "/p/a"},
		{"whole-query-empty", config.RemoveQuery, `{}`, "/p/a?", "/p/a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := t20Plan(t, pipeline("exchanges", t20Slot("rule", tc.implementation, tc.arguments)))
			a, _, text := t20Exchange(t, plan, t20Get(tc.target), goodResponse)
			t20Absent(t, text, t20Card)
			if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != tc.want {
				t.Fatalf("PROPERTY: the target changed outside the removed span\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}
