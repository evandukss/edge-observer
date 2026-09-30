package processing_test

import (
	"fmt"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// t28Rules is one request-body-fields slot carrying a form name, a JSON
// removal and a JSON mask.
const t28Rules = `{"names":["card_number"],"pointers":["/card/number"],"masks":[{"pointer":"/card/holder","value":"withheld"}]}`

// t28Both is valid JSON that, split on & as a form, carries card_number.
const t28Both = `{"note":"x&card_number=` + t20Card + `&y"}`

// t28Request is a request with the given header lines, framed by
// Content-Length, carrying the permitted X-Keep header the wiring guard reads.
func t28Request(headers, body string) string {
	return fmt.Sprintf("POST /pay HTTP/1.1\r\nX-Keep: %s\r\n%sContent-Length: %d\r\n\r\n%s", t20Keep, headers, len(body), body)
}

// t28Chunked is a chunked request whose trailers carry the given lines.
func t28Chunked(headers, body, trailers string) string {
	return fmt.Sprintf("POST /pay HTTP/1.1\r\nX-Keep: %s\r\n%sTransfer-Encoding: chunked\r\nTrailer: Content-Type\r\n\r\n%x\r\n%s\r\n0\r\n%s\r\n",
		t20Keep, headers, len(body), body, trailers)
}

func t28Plan(t *testing.T) *config.ProcessingPlan {
	t.Helper()
	return t20Plan(t, pipeline("exchanges", t20Slot("body", config.RequestBodyFields, t28Rules)))
}

// Strictly valid JSON under no form media type goes to the JSON rules: the
// removal, then the mask, with every other byte kept. The response body is
// not touched.
func TestT28JSONWithoutAFormLabelGoesToTheJSONRules(t *testing.T) {
	body := `{"card":{"number":"` + t20Card + `","holder":"T28HOLDER"},"other":"` + t20Other + `"}`
	want := `{"card":{"holder":"withheld"},"other":"` + t20Other + `"}`
	response := t20Response("application/json", `{"card":{"number":"T28RESPONSE"}}`)
	for _, tc := range []struct{ name, request string }{
		{"application-json", t28Request("Content-Type: application/json\r\n", body)},
		{"text-plain", t28Request("Content-Type: text/plain\r\n", body)},
		{"no-content-type", t28Request("", body)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, text := t20Exchange(t, t28Plan(t), tc.request, response)
			t20Absent(t, text, t20Card)
			t20Absent(t, text, "T28HOLDER")
			t20Kept(t, text, t20Other)
			if got := t20Body(t, a, "request"); got != want {
				t.Fatalf("PROPERTY: the JSON rules did not act on the body as parsed\n got %q\nwant %q", got, want)
			}
			if entries := t20Evidence(a, "request", config.JSONFieldPrefix+"/card/number"); len(entries) != 1 || entries[0].Disposition != processing.DispositionRemoved {
				t.Fatalf("PROPERTY: the JSON removal is not evidenced as remove-json-fields evidences it: %+v", a.PolicyExclusions)
			}
			if len(a.PolicyExclusions) != 1 {
				t.Fatalf("PROPERTY: the mask or the response recorded evidence: %+v", a.PolicyExclusions)
			}
			if got := t20Body(t, a, "response"); got != `{"card":{"number":"T28RESPONSE"}}` {
				t.Fatalf("PROPERTY: the response body was touched: %q", got)
			}
		})
	}
}

// A body that is not strictly valid JSON and is admitted as urlencoded goes to
// the form rules.
func TestT28AnAdmittedFormGoesToTheFormRules(t *testing.T) {
	request := t28Request("Content-Type: application/x-www-form-urlencoded\r\n", "other="+t20Other+"&card_number="+t20Card)
	a, _, text := t20Exchange(t, t28Plan(t), request, goodResponse)
	t20Absent(t, text, t20Card)
	if got := t20Body(t, a, "request"); got != "other="+t20Other {
		t.Fatalf("PROPERTY: the form rules did not act on the body: %q", got)
	}
	if entries := t20Evidence(a, "request", config.FormFieldPrefix+"card_number"); len(entries) != 1 || entries[0].Disposition != processing.DispositionRemoved {
		t.Fatalf("PROPERTY: the form removal is not evidenced as remove-form-fields evidences it: %+v", a.PolicyExclusions)
	}
}

// Valid JSON under any label naming a form media type is a body both grammars
// could read differently, so it goes whole. Each label is one a form rule
// alone does not admit, or admits: removing whole is more than either rule
// decides alone. A multipart body is neither grammar's and goes whole too.
func TestT28ABodyBothGrammarsCouldReadIsRemovedWhole(t *testing.T) {
	multipart := "--XB\r\nContent-Disposition: form-data; name=\"card_number\"\r\n\r\n" + t20Card + "\r\n--XB--\r\n"
	for _, tc := range []struct{ name, request string }{
		{"one-urlencoded-label", t28Request("Content-Type: application/x-www-form-urlencoded\r\n", t28Both)},
		{"two-urlencoded-labels", t28Request("Content-Type: application/x-www-form-urlencoded\r\nContent-Type: application/x-www-form-urlencoded\r\n", t28Both)},
		{"header-and-trailer", t28Chunked("Content-Type: application/x-www-form-urlencoded\r\n", t28Both, "Content-Type: application/x-www-form-urlencoded\r\n")},
		{"form-and-json-in-one-field", t28Request("Content-Type: application/x-www-form-urlencoded, application/json\r\n", t28Both)},
		{"multipart", t28Request("Content-Type: multipart/form-data; boundary=XB\r\n", multipart)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, text := t20Exchange(t, t28Plan(t), tc.request, goodResponse)
			t20Absent(t, text, t20Card)
			t20RemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
			if len(a.PolicyExclusions) != 1 {
				t.Fatalf("PROPERTY: a body removed whole also recorded a field removal: %+v", a.PolicyExclusions)
			}
		})
	}
}
