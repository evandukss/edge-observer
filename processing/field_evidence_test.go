package processing_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// fieldLine is the text rendering of one version 2 entry.
func fieldLine(message, field, section, disposition string) string {
	if section != "" {
		return fmt.Sprintf("policy excluded  exchange=0 message=%q field=%q section=%q disposition=%q (value not retained)", message, field, section, disposition)
	}
	return fmt.Sprintf("policy excluded  exchange=0 message=%q field=%q disposition=%q (value not retained)", message, field, disposition)
}

// Each state of a body and of a target is told apart in the artifact and in
// the public text: no body, removed by policy, removed as undecidable, values
// removed with the structure kept, kept; a query removed, and none to remove.
func TestEvidenceDistinguishesEveryState(t *testing.T) {
	json := `{"card":"` + fieldCard + `"}`
	for _, tc := range []struct {
		name      string
		op        fieldOp
		request   string
		response  string
		entries   [][4]string // message, field, section, disposition
		structure string      // of the request
		kept      bool        // request body bytes kept
	}{
		{"removed-by-policy", fieldOf(config.RemoveBody, `{"messages":["request","response"]}`),
			fieldPost("/pay", "application/json", json), fieldResponse("application/json", json),
			[][4]string{{"request", config.BodyField, "", processing.DispositionRemoved}, {"response", config.BodyField, "", processing.DispositionRemoved}}, record.StructureRemoved, false},
		{"values-removed", fieldOf(config.ReduceBodyToStructure, `{"messages":["request"]}`),
			fieldPost("/pay", "application/json", json), goodResponse,
			[][4]string{{"request", config.BodyValuesField, "", processing.DispositionValuesRemoved}}, record.StructureDerived, false},
		{"reduced-without-structure", fieldOf(config.ReduceBodyToStructure, `{"messages":["request"]}`),
			fieldPost("/pay", "text/plain", "card "+fieldCard), goodResponse,
			[][4]string{{"request", config.BodyField, "", processing.DispositionRemoved}}, record.StructureRemoved, false},
		{"removed-undecidable", fieldOf(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card"]}`),
			fieldPost("/pay", "application/json", json+","), goodResponse,
			[][4]string{{"request", config.BodyField, "", processing.DispositionRemovedUndecidable}}, record.StructureRemoved, false},
		{"no-body", fieldOf(config.RemoveBody, `{"messages":["request"]}`),
			fieldGet("/pay"), goodResponse, nil, record.StructureNone, false},
		{"kept", fieldOf(config.RemoveBody, `{"messages":["response"]}`),
			fieldPost("/pay", "application/json", `{"other":"`+fieldOther+`"}`), goodResponse,
			[][4]string{{"response", config.BodyField, "", processing.DispositionRemoved}}, record.StructureDerived, true},
		{"query-removed", fieldOf(config.RemoveQuery, `{}`),
			fieldGet("/pay?card=" + fieldCard), goodResponse,
			[][4]string{{"request", config.TargetQueryField, "", processing.DispositionRemoved}}, record.StructureNone, false},
		{"no-query", fieldOf(config.RemoveQuery, `{}`),
			fieldGet("/pay"), goodResponse, nil, record.StructureNone, false},
		{"header-removed", fieldOf(config.RemoveHeaders, `{"headers":["authorization"]}`),
			"GET /pay HTTP/1.1\r\nX-Keep: " + fieldKeep + "\r\nAuthorization: " + fieldCard + "\r\n\r\n", goodResponse,
			[][4]string{{"request", config.HeaderFieldPrefix + "authorization", "headers", processing.DispositionRemoved}}, record.StructureNone, false},
		{"parameter-removed", fieldOf(config.RemoveQueryParameters, `{"names":["card"]}`),
			fieldGet("/pay?card=" + fieldCard), goodResponse,
			[][4]string{{"request", config.QueryFieldPrefix + "card", "", processing.DispositionRemoved}}, record.StructureNone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, text := fieldExchange(t, fieldPlan(t, tc.op.implementation, tc.op.arguments), tc.request, tc.response)
			fieldAbsent(t, text, fieldCard)
			if a.Version != processing.ArtifactVersion || processing.ArtifactVersion != "observer.approved/5" {
				t.Fatalf("PROPERTY: the artifact is %q, not observer.approved/5", a.Version)
			}
			if a.PolicyExclusions == nil || len(a.PolicyExclusions) != len(tc.entries) {
				t.Fatalf("PROPERTY: evidence entries: got %+v, want %v", a.PolicyExclusions, tc.entries)
			}
			for _, want := range tc.entries {
				found := false
				for _, e := range a.PolicyExclusions {
					if e.Exchange == 0 && e.Message == want[0] && e.Field == want[1] && e.Section == want[2] && e.Disposition == want[3] && e.Name == "" {
						found = true
					}
				}
				if !found {
					t.Fatalf("PROPERTY: entry %v missing from %+v", want, a.PolicyExclusions)
				}
				if strings.Count(text, fieldLine(want[0], want[1], want[2], want[3])) != 1 {
					t.Fatalf("PROPERTY: entry %v is not rendered exactly once\n%s", want, text)
				}
			}
			if len(tc.entries) == 0 && !strings.Contains(text, "policy exclusions  none excluded") {
				t.Fatalf("PROPERTY: an empty evidence array is not rendered as none excluded\n%s", text)
			}
			m := a.Reconstruction.Exchanges[0].Request.Message
			if m.Structure.State != tc.structure {
				t.Fatalf("PROPERTY: request structure is %q, want %q", m.Structure.State, tc.structure)
			}
			if (m.Body.Kept != "") != tc.kept {
				t.Fatalf("PROPERTY: request body kept=%q, want kept=%v", m.Body.Kept, tc.kept)
			}
			if tc.structure == record.StructureRemoved && m.Body.Length == "0" {
				t.Fatal("PROPERTY: a removed body lost its length, so it reads as no body")
			}
			if !strings.Contains(text, fmt.Sprintf("structure=%q", tc.structure)) {
				t.Fatalf("PROPERTY: the retained body line does not name structure %q\n%s", tc.structure, text)
			}
		})
	}
}

// The reader refuses a version 2 artifact whose evidence contradicts its
// messages, and still reads a version 1 artifact under version 1's rules.
func TestReaderChecksVersionTwoEvidence(t *testing.T) {
	json := `{"card":"` + fieldCard + `"}`
	plan := fieldPlan(t, config.RemoveBody, `{"messages":["request"]}`)
	valid, _, _ := fieldExchange(t, plan, fieldPost("/pay?q=1", "application/json", json), goodResponse)
	render := func(a processing.Artifact) error { return processing.RenderArtifact(&bytes.Buffer{}, a) }
	if len(valid.PolicyExclusions) != 1 || valid.PolicyExclusions[0].Field != config.BodyField ||
		valid.Reconstruction.Exchanges[0].Request.Message.Structure.State != record.StructureRemoved {
		t.Fatalf("wiring, not the property: the fixture's body was not removed with one message.body entry, so no change below starts from a consistent version 2 artifact: %+v", valid.PolicyExclusions)
	}
	if err := render(valid); err != nil {
		t.Fatalf("wiring, not the property: the unaltered artifact is refused: %v", err)
	}
	clone := func() processing.Artifact {
		a := valid
		r := *valid.Reconstruction
		r.Exchanges = append([]record.Exchange(nil), r.Exchanges...)
		request := *r.Exchanges[0].Request.Message
		r.Exchanges[0].Request.Message = &request
		a.Reconstruction = &r
		a.PolicyExclusions = append([]processing.PolicyExclusion(nil), valid.PolicyExclusions...)
		return a
	}
	for _, tc := range []struct {
		name   string
		change func(a *processing.Artifact)
	}{
		{"removed-structure-without-entry", func(a *processing.Artifact) { a.PolicyExclusions = []processing.PolicyExclusion{} }},
		{"body-entry-with-kept-bytes", func(a *processing.Artifact) {
			a.Reconstruction.Exchanges[0].Request.Message.Body.Kept = base64.StdEncoding.EncodeToString([]byte("x"))
		}},
		{"body-entry-without-removed-structure", func(a *processing.Artifact) {
			a.Reconstruction.Exchanges[0].Request.Message.Structure = record.Structure{State: record.StructureNone}
		}},
		{"unknown-disposition", func(a *processing.Artifact) { a.PolicyExclusions[0].Disposition = "hidden" }},
		{"disposition-of-another-field", func(a *processing.Artifact) { a.PolicyExclusions[0].Disposition = processing.DispositionValuesRemoved }},
		{"unknown-field", func(a *processing.Artifact) { a.PolicyExclusions[0].Field = "message.start_line" }},
		{"version-one-name-in-version-two", func(a *processing.Artifact) { a.PolicyExclusions[0].Name = "authorization" }},
		{"section-on-body-entry", func(a *processing.Artifact) { a.PolicyExclusions[0].Section = "headers" }},
		{"query-entry-with-query-present", func(a *processing.Artifact) {
			a.PolicyExclusions = append(a.PolicyExclusions, processing.PolicyExclusion{Exchange: 0, Message: "request", Field: config.TargetQueryField, Disposition: processing.DispositionRemoved})
		}},
		{"query-entry-on-response", func(a *processing.Artifact) {
			a.PolicyExclusions = append(a.PolicyExclusions, processing.PolicyExclusion{Exchange: 0, Message: "response", Field: config.QueryFieldPrefix + "card", Disposition: processing.DispositionRemoved})
		}},
		{"header-entry-on-present-header", func(a *processing.Artifact) {
			a.PolicyExclusions = append(a.PolicyExclusions, processing.PolicyExclusion{Exchange: 0, Message: "request", Field: config.HeaderFieldPrefix + "x-keep", Section: "headers", Disposition: processing.DispositionRemoved})
		}},
		{"removed-structure-in-version-one", func(a *processing.Artifact) {
			a.Version = processing.ArtifactVersion1
			a.PolicyExclusions = []processing.PolicyExclusion{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := clone()
			tc.change(&a)
			if err := render(a); err == nil {
				t.Fatal("PROPERTY: the reader accepted contradictory evidence")
			}
		})
	}

	t.Run("version-one-still-read", func(t *testing.T) {
		out := &outputLog{}
		w, store := worker(t, fieldPlan(t, config.RemoveHeaders, `{"headers":["authorization"]}`), out)
		enqueue(t, store, batch(t, 1, "GET / HTTP/1.1\r\nAuthorization: x\r\n\r\n", goodResponse))
		counted(t, drain(t, w), out, 1, 1)
		exchanges, _ := out.routed(config.ExchangesPipeline)
		retirements, _ := out.routed(config.ConnectionsPipeline)
		a := exchanges[0]
		a.Version = processing.ArtifactVersion1
		// A version 1 line carried its connection's final record.
		a.Connection = retirements[0].Connection
		a.PolicyExclusions = []processing.PolicyExclusion{{Exchange: 0, Message: "request", Section: "headers", Name: "authorization"}}
		var text bytes.Buffer
		if err := processing.RenderArtifact(&text, a); err != nil {
			t.Fatalf("PROPERTY: a version 1 artifact is no longer read: %v", err)
		}
		if !strings.Contains(text.String(), `policy excluded  exchange=0 message="request" section="headers" name="authorization" (value not retained)`) {
			t.Fatalf("PROPERTY: a version 1 entry is not rendered as version 1\n%s", text.String())
		}
		a.PolicyExclusions[0].Field, a.PolicyExclusions[0].Disposition = config.HeaderFieldPrefix+"authorization", processing.DispositionRemoved
		if err := processing.RenderArtifact(&bytes.Buffer{}, a); err == nil {
			t.Fatal("PROPERTY: a version 1 artifact carrying version 2 members was accepted")
		}
	})
}
