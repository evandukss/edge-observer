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

// t28Configuration is a configuration a user writes with a form rule, a JSON
// request removal and a JSON request mask, which compile to one
// request-body-fields operation.
const t28Configuration = `{"version": "observer.config/1", "output": "/var/lib/observer",
  "watch": [{"name": "api", "exe": "/usr/local/bin/api-server"}],
  "remove": {"form": ["card_number"], "json": {"request": ["/card/number"]}},
  "mask": {"json": {"request": {"/card/holder": "withheld"}}}}`

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

// t28Plan compiles t28Configuration, and fails as wiring unless the exchanges
// pipeline holds exactly the one request-body-fields operation under test.
func t28Plan(t *testing.T) *config.ProcessingPlan {
	t.Helper()
	compiled, findings := config.Compile([]byte(t28Configuration), "")
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

// t28Exchange runs one exchange through a compiled plan and returns the
// exchanges pipeline's artifact, its approved line and its public text
// rendering. A compiled plan also routes the connections pipeline, so the
// worker writes two artifacts, and only the exchanges one may carry message
// content. The guards fail as WIRING before any property is asserted.
func t28Exchange(t *testing.T, plan *config.ProcessingPlan, request, response string) (processing.Artifact, []byte, string) {
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
	if !strings.Contains(request, "X-Keep: "+t20Keep+"\r\n") {
		t.Fatal("fixture: the request carries no permitted X-Keep header, so the wiring guard below cannot be read")
	}
	if !strings.Contains(text.String(), t20Keep) {
		t.Fatalf("wiring, not the property: the permitted request header is not in the rendered output, so an absence below would measure nothing\n%s", text.String())
	}
	return out.artifacts[at], out.lines[at], text.String()
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
			a, _, text := t28Exchange(t, t28Plan(t), tc.request, response)
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
	a, _, text := t28Exchange(t, t28Plan(t), request, goodResponse)
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
			a, _, text := t28Exchange(t, t28Plan(t), tc.request, goodResponse)
			t20Absent(t, text, t20Card)
			t20RemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
			if len(a.PolicyExclusions) != 1 {
				t.Fatalf("PROPERTY: a body removed whole also recorded a field removal: %+v", a.PolicyExclusions)
			}
		})
	}
}
