package processing_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// fieldCard is the protected value in every body and query case. fieldKeep is a
// permitted header value on every request, so a run where nothing reached the
// output cannot pass as a removal. fieldOther is a permitted value in the same
// component as the protected one, which a field operation must keep.
const (
	fieldCard  = "4111111111111111"
	fieldKeep  = "PRMKEEP7c1e"
	fieldOther = "PRMOTHER5b9d"
)

// fieldExchange runs one exchange through one pipeline and returns its artifact,
// its approved line and the public text rendering, in which bodies are decoded.
// The guards fail as WIRING before any property is asserted.
func fieldExchange(t *testing.T, plan *config.ProcessingPlan, request, response string) (processing.Artifact, []byte, string) {
	t.Helper()
	if plan == nil {
		t.Fatal("wiring, not the property: the fixture configuration was refused, so nothing below measured anything")
	}
	out := &outputLog{}
	w, store := worker(t, plan, out)
	enqueue(t, store, batch(t, 1, request, response))
	o := drain(t, w)
	if o.ProcessingFailures != 0 {
		t.Fatalf("wiring, not the property: the exchange did not reach approved output, so nothing below measured removal: %+v", o)
	}
	counted(t, o, out, 1, 1)
	exchanges, lines := out.routed(config.ExchangesPipeline)
	if exchanges[0].Reconstruction == nil || len(exchanges[0].Reconstruction.Exchanges) != 1 {
		t.Fatalf("wiring, not the property: the exchange did not reach approved output, so nothing below measured removal: %+v", o)
	}
	var text bytes.Buffer
	if err := processing.RenderArtifact(&text, exchanges[0]); err != nil {
		t.Fatalf("wiring, not the property: the approved artifact cannot be rendered: %v", err)
	}
	if !strings.Contains(request, "X-Keep: "+fieldKeep+"\r\n") {
		t.Fatal("fixture: the request carries no permitted X-Keep header, so the wiring guard below cannot be read")
	}
	if !strings.Contains(text.String(), fieldKeep) {
		t.Fatalf("wiring, not the property: the permitted request header is not in the rendered output, so an absence below would measure nothing\n%s", text.String())
	}
	return exchanges[0], lines[0], text.String()
}

// fieldBody is a message's retained body, decoded.
func fieldBody(t *testing.T, a processing.Artifact, message string) string {
	t.Helper()
	e := a.Reconstruction.Exchanges[0]
	m := e.Request.Message
	if message == "response" {
		m = e.Response.Message
	}
	body, err := base64.StdEncoding.DecodeString(m.Body.Kept)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// fieldPost is a request with a body, framed by Content-Length.
func fieldPost(target, contentType, body string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nX-Keep: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", target, fieldKeep, contentType, len(body), body)
}

// fieldGet is a bodiless request for a target.
func fieldGet(target string) string {
	return "GET " + target + " HTTP/1.1\r\nX-Keep: " + fieldKeep + "\r\n\r\n"
}

// fieldResponse is a response with a body, framed by Content-Length.
func fieldResponse(contentType, body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", contentType, len(body), body)
}

// fieldAbsent fails on the property when the protected value is anywhere in the
// public rendering, which carries the target, the headers and decoded bodies.
func fieldAbsent(t *testing.T, text, value string) {
	t.Helper()
	if strings.Contains(text, value) {
		t.Fatalf("PROPERTY: protected value %q reached the approved output\n%s", value, text)
	}
}

// fieldKept fails on the property when a permitted value in the same component
// did not survive: a field operation removed more than it was asked to.
func fieldKept(t *testing.T, text, value string) {
	t.Helper()
	if !strings.Contains(text, value) {
		t.Fatalf("PROPERTY: permitted value %q beside the protected one did not survive\n%s", value, text)
	}
}

// fieldOp is one operation, as the implementation and arguments it compiles to.
type fieldOp struct{ implementation, arguments string }

func fieldOf(implementation, arguments string) fieldOp { return fieldOp{implementation, arguments} }

// fieldPlan is the plan of a configuration writing one operation as the rule a
// user writes for it. The case fails as wiring unless the exchanges pipeline
// holds that operation and no other.
func fieldPlan(t *testing.T, implementation, arguments string) *config.ProcessingPlan {
	t.Helper()
	var a struct {
		Headers  []string `json:"headers"`
		Value    string   `json:"value"`
		Messages []string `json:"messages"`
		Pointers []string `json:"pointers"`
		Names    []string `json:"names"`
	}
	if err := json.Unmarshal([]byte(arguments), &a); err != nil {
		t.Fatalf("fixture: %s arguments %s: %v", implementation, arguments, err)
	}
	byMessage := func(value func() any) map[string]any {
		out := map[string]any{}
		for _, message := range a.Messages {
			out[message] = value()
		}
		return out
	}
	var rules map[string]any
	switch implementation {
	case config.RemoveHeaders:
		rules = map[string]any{"remove": map[string]any{"headers": a.Headers}}
	case config.RemoveBody:
		rules = map[string]any{"remove": map[string]any{"bodies": a.Messages}}
	case config.ReduceBodyToStructure:
		rules = map[string]any{"remove": map[string]any{"body_values": a.Messages}}
	case config.RemoveQuery:
		rules = map[string]any{"remove": map[string]any{"query_string": true}}
	case config.RemoveQueryParameters:
		rules = map[string]any{"remove": map[string]any{"query": a.Names}}
	case config.RemoveFormFields:
		rules = map[string]any{"remove": map[string]any{"form": a.Names}}
	case config.RemoveJSONFields:
		rules = map[string]any{"remove": map[string]any{"json": byMessage(func() any { return a.Pointers })}}
	case config.ReplaceJSONValues:
		rules = map[string]any{"mask": map[string]any{"json": byMessage(func() any {
			values := map[string]any{}
			for _, pointer := range a.Pointers {
				values[pointer] = a.Value
			}
			return values
		})}}
	default:
		t.Fatalf("fixture: no rule a user writes compiles to %s alone", implementation)
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	plan := rulesPlan(t, string(encoded[1:len(encoded)-1]))
	for _, p := range plan.Pipelines() {
		if p.Name != config.ExchangesPipeline {
			continue
		}
		if len(p.Slots) == 0 {
			t.Fatalf("wiring, not the property: %s compiled to no operation", implementation)
		}
		for _, slot := range p.Slots {
			if slot.Implementation != implementation {
				t.Fatalf("wiring, not the property: %s compiled beside %s, so the case would not measure it alone",
					implementation, slot.Implementation)
			}
		}
	}
	return plan
}
