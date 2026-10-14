package processing_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// requestBodyConfiguration is a configuration a user writes with a form rule, a JSON
// request removal and a JSON request mask, which compile to one
// request-body-fields operation.
const requestBodyConfiguration = `{"version": "observer.config/1", "output": "/var/lib/observer",
  "watch": [{"name": "api", "exe": "/usr/local/bin/api-server"}],
  "remove": {"form": ["card_number"], "json": {"request": ["/card/number"]}},
  "mask": {"json": {"request": {"/card/holder": "withheld"}}}}`

// requestBodyBoth is valid JSON that, split on & as a form, carries card_number.
const requestBodyBoth = `{"note":"x&card_number=` + fieldCard + `&y"}`

// requestBodyRequest is a request with the given header lines, framed by
// Content-Length, carrying the permitted X-Keep header the wiring guard reads.
func requestBodyRequest(headers, body string) string {
	return fmt.Sprintf("POST /pay HTTP/1.1\r\nX-Keep: %s\r\n%sContent-Length: %d\r\n\r\n%s", fieldKeep, headers, len(body), body)
}

// requestBodyChunked is a chunked request whose trailers carry the given lines.
func requestBodyChunked(headers, body, trailers string) string {
	return fmt.Sprintf("POST /pay HTTP/1.1\r\nX-Keep: %s\r\n%sTransfer-Encoding: chunked\r\nTrailer: Content-Type\r\n\r\n%x\r\n%s\r\n0\r\n%s\r\n",
		fieldKeep, headers, len(body), body, trailers)
}

// requestBodyPlan compiles requestBodyConfiguration, and fails as wiring unless the exchanges
// pipeline holds exactly the one request-body-fields operation under test.
func requestBodyPlan(t *testing.T) *config.ProcessingPlan {
	t.Helper()
	compiled, findings := config.Compile([]byte(requestBodyConfiguration), "")
	if compiled == nil || len(findings) > 0 {
		t.Fatalf("wiring, not the property: the configuration was refused: %+v", findings)
	}
	var slots []config.EffectiveSlot
	for _, p := range compiled.Plan.Pipelines() {
		if p.Name == config.ExchangesPipeline {
			slots = p.Slots
		}
	}
	if len(slots) != 1 || slots[0].Implementation != config.RequestBodyFields || slots[0].Arguments == nil {
		t.Fatalf("wiring, not the property: the rules did not compile to one %s operation: %+v", config.RequestBodyFields, slots)
	}
	a := slots[0].Arguments
	if !slices.Equal(a.Names, []string{"card_number"}) || !slices.Equal(a.Pointers, []string{"/card/number"}) ||
		!slices.Equal(a.Masks, []config.JSONMask{{Pointer: "/card/holder", Value: "withheld"}}) {
		t.Fatalf("wiring, not the property: the operation does not carry the rules written: %+v", *a)
	}
	return compiled.Plan
}

// requestBodyExchange runs one exchange through a compiled plan and returns the
// exchanges pipeline's artifact, its approved line and its public text
// rendering. A compiled plan also routes the connections pipeline, so the
// worker writes two artifacts, and only the exchanges one may carry message
// content. The guards fail as WIRING before any property is asserted.
func requestBodyExchange(t *testing.T, plan *config.ProcessingPlan, request, response string) (processing.Artifact, []byte, string) {
	t.Helper()
	out := &outputLog{}
	w, store := worker(t, plan, out)
	enqueue(t, store, batch(t, 1, request, response))
	o := drain(t, w)
	at := slices.IndexFunc(out.artifacts, func(a processing.Artifact) bool { return a.Route.Pipeline == config.ExchangesPipeline })
	if o.Written != 2 || o.ProcessingFailures != 0 || len(out.artifacts) != 2 || at < 0 ||
		out.artifacts[at].Reconstruction == nil || len(out.artifacts[at].Reconstruction.Exchanges) != 1 {
		t.Fatalf("wiring, not the property: the exchange did not reach the exchanges pipeline's approved output, so nothing below measured removal: %+v", o)
	}
	if other := out.artifacts[1-at]; other.Route.Pipeline != config.ConnectionsPipeline || other.Reconstruction != nil {
		t.Fatalf("wiring, not the property: the second artifact is not a connections artifact without message content, so the text below is not all the content written: %+v", other.Route)
	}
	var text bytes.Buffer
	if err := processing.RenderArtifact(&text, out.artifacts[at]); err != nil {
		t.Fatalf("wiring, not the property: the approved artifact cannot be rendered: %v", err)
	}
	if !strings.Contains(request, "X-Keep: "+fieldKeep+"\r\n") {
		t.Fatal("fixture: the request carries no permitted X-Keep header, so the wiring guard below cannot be read")
	}
	if !strings.Contains(text.String(), fieldKeep) {
		t.Fatalf("wiring, not the property: the permitted request header is not in the rendered output, so an absence below would measure nothing\n%s", text.String())
	}
	return out.artifacts[at], out.lines[at], text.String()
}

// Strictly valid JSON under no form media type goes to the JSON rules: the
// removal, then the mask, with every other byte kept. The response body is
// not touched.
func TestJSONWithoutAFormLabelGoesToTheJSONRules(t *testing.T) {
	body := `{"card":{"number":"` + fieldCard + `","holder":"RQBHOLDER"},"other":"` + fieldOther + `"}`
	want := `{"card":{"holder":"withheld"},"other":"` + fieldOther + `"}`
	response := fieldResponse("application/json", `{"card":{"number":"RQBRESPONSE"}}`)
	for _, tc := range []struct{ name, request string }{
		{"application-json", requestBodyRequest("Content-Type: application/json\r\n", body)},
		{"text-plain", requestBodyRequest("Content-Type: text/plain\r\n", body)},
		{"no-content-type", requestBodyRequest("", body)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, text := requestBodyExchange(t, requestBodyPlan(t), tc.request, response)
			fieldAbsent(t, text, fieldCard)
			fieldAbsent(t, text, "RQBHOLDER")
			fieldKept(t, text, fieldOther)
			if got := fieldBody(t, a, "request"); got != want {
				t.Fatalf("PROPERTY: the JSON rules did not act on the body as parsed\n got %q\nwant %q", got, want)
			}
			if entries := fieldEvidence(a, "request", config.JSONFieldPrefix+"/card/number"); len(entries) != 1 || entries[0].Disposition != processing.DispositionRemoved {
				t.Fatalf("PROPERTY: the JSON removal is not evidenced as remove-json-fields evidences it: %+v", a.PolicyExclusions)
			}
			if len(a.PolicyExclusions) != 1 {
				t.Fatalf("PROPERTY: the mask or the response recorded evidence: %+v", a.PolicyExclusions)
			}
			if got := fieldBody(t, a, "response"); got != `{"card":{"number":"RQBRESPONSE"}}` {
				t.Fatalf("PROPERTY: the response body was touched: %q", got)
			}
		})
	}
}

// A body that is not strictly valid JSON and is admitted as urlencoded goes to
// the form rules.
func TestAnAdmittedFormGoesToTheFormRules(t *testing.T) {
	request := requestBodyRequest("Content-Type: application/x-www-form-urlencoded\r\n", "other="+fieldOther+"&card_number="+fieldCard)
	a, _, text := requestBodyExchange(t, requestBodyPlan(t), request, goodResponse)
	fieldAbsent(t, text, fieldCard)
	if got := fieldBody(t, a, "request"); got != "other="+fieldOther {
		t.Fatalf("PROPERTY: the form rules did not act on the body: %q", got)
	}
	if entries := fieldEvidence(a, "request", config.FormFieldPrefix+"card_number"); len(entries) != 1 || entries[0].Disposition != processing.DispositionRemoved {
		t.Fatalf("PROPERTY: the form removal is not evidenced as remove-form-fields evidences it: %+v", a.PolicyExclusions)
	}
}

// Valid JSON under any label naming a form media type is a body both grammars
// could read differently, so it goes whole. Each label is one a form rule
// alone does not admit, or admits: removing whole is more than either rule
// decides alone. A multipart body is neither grammar's and goes whole too.
func TestABodyBothGrammarsCouldReadIsRemovedWhole(t *testing.T) {
	multipart := "--XB\r\nContent-Disposition: form-data; name=\"card_number\"\r\n\r\n" + fieldCard + "\r\n--XB--\r\n"
	for _, tc := range []struct{ name, request string }{
		{"one-urlencoded-label", requestBodyRequest("Content-Type: application/x-www-form-urlencoded\r\n", requestBodyBoth)},
		{"two-urlencoded-labels", requestBodyRequest("Content-Type: application/x-www-form-urlencoded\r\nContent-Type: application/x-www-form-urlencoded\r\n", requestBodyBoth)},
		{"header-and-trailer", requestBodyChunked("Content-Type: application/x-www-form-urlencoded\r\n", requestBodyBoth, "Content-Type: application/x-www-form-urlencoded\r\n")},
		{"form-and-json-in-one-field", requestBodyRequest("Content-Type: application/x-www-form-urlencoded, application/json\r\n", requestBodyBoth)},
		{"multipart", requestBodyRequest("Content-Type: multipart/form-data; boundary=XB\r\n", multipart)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, text := requestBodyExchange(t, requestBodyPlan(t), tc.request, goodResponse)
			fieldAbsent(t, text, fieldCard)
			fieldRemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
			if len(a.PolicyExclusions) != 1 {
				t.Fatalf("PROPERTY: a body removed whole also recorded a field removal: %+v", a.PolicyExclusions)
			}
		})
	}
}
