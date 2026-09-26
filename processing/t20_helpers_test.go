package processing_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
	"github.com/evandukss/edge-observer/processing"
)

// t20Card is the protected value in every body and query case. t20Keep is a
// permitted header value on every request, so a run where nothing reached the
// output cannot pass as a removal. t20Other is a permitted value in the same
// component as the protected one, which a field operation must keep.
const (
	t20Card  = "4111111111111111"
	t20Keep  = "T20KEEP7c1e"
	t20Other = "T20OTHER5b9d"
)

// t20Requirement is one mandatory exclusion on the account sink.
func t20Requirement(field string) cp.Requirement {
	return cp.Requirement{ID: "exclude", Target: cp.Target{Kind: "sink", Name: "account"}, Operation: "transform_field",
		Parameters: map[string]any{"field": field, "transformation": "remove"}, FailureAction: cp.DropAndAccount}
}

// t20Compile compiles pipelines into the no-extension configuration with the
// given requirements as its policy.
func t20Compile(t *testing.T, requirements []cp.Requirement, pipelines ...config.Pipeline) (*config.ProcessingPlan, []config.Finding) {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var c config.Configuration
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Pipelines = pipelines
	for n := range c.Pipelines {
		if c.Pipelines[n].Slots == nil {
			c.Pipelines[n].Slots = []config.Slot{}
		}
	}
	c.Packs, c.Subscribers = nil, nil
	c.Sinks = []config.Sink{{Name: "account", Kind: "local_account"}}
	c.Policy = nil
	if len(requirements) > 0 {
		document, err := json.Marshal(cp.Document{Vocabulary: cp.Vocabulary, Requirements: requirements})
		if err != nil {
			t.Fatal(err)
		}
		c.Policy = []json.RawMessage{document}
	}
	raw, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return config.CompileProcessing(raw, nil)
}

// t20Exchange runs one exchange through one pipeline and returns its artifact,
// its approved line and the public text rendering, in which bodies are decoded.
// The guards fail as WIRING before any property is asserted.
func t20Exchange(t *testing.T, plan *config.ProcessingPlan, request, response string) (processing.Artifact, []byte, string) {
	t.Helper()
	if plan == nil {
		t.Fatal("wiring, not the property: the fixture configuration was refused, so nothing below measured anything")
	}
	out := &outputLog{}
	w, store := worker(t, plan, out)
	enqueue(t, store, batch(t, 1, request, response))
	o := drain(t, w)
	if o.Written != 1 || o.ProcessingFailures != 0 || len(out.artifacts) != 1 || out.artifacts[0].Reconstruction == nil || len(out.artifacts[0].Reconstruction.Exchanges) != 1 {
		t.Fatalf("wiring, not the property: the exchange did not reach approved output, so nothing below measured removal: %+v", o)
	}
	var text bytes.Buffer
	if err := processing.RenderArtifact(&text, out.artifacts[0]); err != nil {
		t.Fatalf("wiring, not the property: the approved artifact cannot be rendered: %v", err)
	}
	if !strings.Contains(request, "X-Keep: "+t20Keep+"\r\n") {
		t.Fatal("fixture: the request carries no permitted X-Keep header, so the wiring guard below cannot be read")
	}
	if !strings.Contains(text.String(), t20Keep) {
		t.Fatalf("wiring, not the property: the permitted request header is not in the rendered output, so an absence below would measure nothing\n%s", text.String())
	}
	return out.artifacts[0], out.lines[0], text.String()
}

// t20Body is a message's retained body, decoded.
func t20Body(t *testing.T, a processing.Artifact, message string) string {
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

// t20Post is a request with a body, framed by Content-Length.
func t20Post(target, contentType, body string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nX-Keep: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", target, t20Keep, contentType, len(body), body)
}

// t20Get is a bodiless request for a target.
func t20Get(target string) string {
	return "GET " + target + " HTTP/1.1\r\nX-Keep: " + t20Keep + "\r\n\r\n"
}

// t20Response is a response with a body, framed by Content-Length.
func t20Response(contentType, body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", contentType, len(body), body)
}

// t20Slot is a slot whose failure action is drop_and_account.
func t20Slot(name, implementation, arguments string) config.Slot {
	return slot(name, implementation, arguments)
}

// t20Absent fails on the property when the protected value is anywhere in the
// public rendering, which carries the target, the headers and decoded bodies.
func t20Absent(t *testing.T, text, value string) {
	t.Helper()
	if strings.Contains(text, value) {
		t.Fatalf("PROPERTY: protected value %q reached the approved output\n%s", value, text)
	}
}

// t20Kept fails on the property when a permitted value in the same component
// did not survive: a field operation removed more than it was asked to.
func t20Kept(t *testing.T, text, value string) {
	t.Helper()
	if !strings.Contains(text, value) {
		t.Fatalf("PROPERTY: permitted value %q beside the protected one did not survive\n%s", value, text)
	}
}

// t20Plan compiles pipelines with no policy, and fails as wiring when the
// fixture configuration is refused.
func t20Plan(t *testing.T, pipelines ...config.Pipeline) *config.ProcessingPlan {
	t.Helper()
	plan, findings := t20Compile(t, nil, pipelines...)
	if plan == nil {
		t.Fatalf("wiring, not the property: the fixture configuration was refused: %+v", findings)
	}
	return plan
}
