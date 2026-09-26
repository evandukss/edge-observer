//go:build attach

package attach_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

var (
	t20iJSON = []t20iHeader{{"Content-Type", "application/json"}}
	t20iForm = []t20iHeader{{"Content-Type", "application/x-www-form-urlencoded"}}
)

// t20iWith is headers with one more.
func t20iWith(headers []t20iHeader, name, value string) []t20iHeader {
	return append(slices.Clone(headers), t20iHeader{name, value})
}

// t20iRemovedEntry is the entry a body removed whole by a component
// operation carries.
func t20iRemovedEntry(message string) t20iEntry {
	return t20iEntry{message, config.BodyField, "", processing.DispositionRemoved}
}

// t20iUndecidableEntry is the entry a body a field operation could not decide
// carries.
func t20iUndecidableEntry(message string) t20iEntry {
	return t20iEntry{message, config.BodyField, "", processing.DispositionRemovedUndecidable}
}

// remove-body on requests only. Every request body with bytes goes whole,
// whatever its grammar or framing, its member names with its values; the
// response body, which the slot does not select, is written unchanged.
func TestT20iRemoveBodyOnRequestsDropsEveryRequestBodyAndKeepsTheResponse(t *testing.T) {
	jsonBody := `{"` + t20iProtected("RB_NAME") + `":"` + t20iProtected("RB_VALUE") + `","note":1}`
	chunks := []string{`{"card":{"number":"T20IPROT_RB_CHU`, `NK_END"},"n":1}`}
	formBody := "card_number=" + t20iProtected("RB_FORM") + "&note=1"
	multipart := t20iMultipart([2]string{"card_number", t20iProtected("RB_PART")})
	response := `{"answer":"` + t20iPermitted("RB_RESPONSE") + `"}`
	answer := t20iResponse{Type: "application/json", Body: []byte(response)}
	removed := func(length int, framing string) func(*testing.T, string, processing.Artifact, record.Exchange) {
		return func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			t20iRemovedWhole(t, x.Request.Message, length, framing)
			t20iHasHeader(t, x.Request.Message, "X-T20i-Keep", t20iPermitted("RB_HEADER"))
			t20iKept(t, x.Response.Message, response)
			if x.Response.Message.Structure.State != record.StructureDerived {
				t.Errorf("the response body the slot does not select lost its structure: %+v", x.Response.Message.Structure)
			}
			t20iEvidence(t, a, x, t20iRemovedEntry("request"))
		}
	}
	keep := t20iHeader{"X-T20i-Keep", t20iPermitted("RB_HEADER")}
	cases := []t20iCase{
		{name: "rb-json", pieces: []string{t20iRequest("POST", "/t20i/rb-json", append(slices.Clone(t20iJSON), keep), jsonBody)},
			response: answer, protected: []string{t20iProtected("RB_NAME"), t20iProtected("RB_VALUE")},
			permitted: []string{t20iPermitted("RB_HEADER"), t20iPermitted("RB_RESPONSE")}, check: removed(len(jsonBody), "content_length")},
		{name: "rb-chunked", pieces: t20iSplit(t, t20iChunked("POST", "/t20i/rb-chunked", append(slices.Clone(t20iJSON), keep), chunks, nil),
			"T20IPROT_R", "\r\nNK"),
			response: answer, protected: []string{"T20IPROT_RB_CHUNK_END"},
			permitted: []string{t20iPermitted("RB_HEADER"), t20iPermitted("RB_RESPONSE")}, check: removed(len(chunks[0]+chunks[1]), "chunked")},
		{name: "rb-form", pieces: []string{t20iRequest("POST", "/t20i/rb-form", append(slices.Clone(t20iForm), keep), formBody)},
			response: answer, protected: []string{t20iProtected("RB_FORM")},
			permitted: []string{t20iPermitted("RB_HEADER"), t20iPermitted("RB_RESPONSE")}, check: removed(len(formBody), "content_length")},
		{name: "rb-multipart", pieces: []string{t20iRequest("POST", "/t20i/rb-multipart",
			[]t20iHeader{{"Content-Type", "multipart/form-data; boundary=XB"}, keep}, multipart)},
			response: answer, protected: []string{t20iProtected("RB_PART")},
			permitted: []string{t20iPermitted("RB_HEADER"), t20iPermitted("RB_RESPONSE")}, check: removed(len(multipart), "content_length")},
		// Never present: no body, and a body of no bytes, carry no entry.
		{name: "rb-none", pieces: []string{t20iRequest("GET", "/t20i/rb-none?keep="+t20iPermitted("RB_NONE"), nil, "")},
			response: answer, permitted: []string{t20iPermitted("RB_NONE"), t20iPermitted("RB_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if x.Request.Message.Structure.State != record.StructureNone || x.Request.Message.Body.Length != "0" {
					t.Errorf("a request with no body reads as %+v, length %q", x.Request.Message.Structure, x.Request.Message.Body.Length)
				}
				t20iKept(t, x.Response.Message, response)
				t20iEvidence(t, a, x)
			}},
		{name: "rb-empty", pieces: []string{t20iRequest("POST", "/t20i/rb-empty?keep="+t20iPermitted("RB_EMPTY"), t20iJSON, "")},
			response: answer, permitted: []string{t20iPermitted("RB_EMPTY"), t20iPermitted("RB_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if x.Request.Message.Structure.State == record.StructureRemoved {
					t.Errorf("a body of no bytes reads as removed: %+v", x.Request.Message.Structure)
				}
				t20iEvidence(t, a, x)
			}},
	}
	setup := t20iSetup{pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"},
		t20iSlot("body", config.RemoveBody, map[string]any{"messages": []string{"request"}}))}}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// remove-body on both messages under the message.body exclusion: both bodies
// go whole, each recorded on its own message, and an exchange with neither
// body records nothing.
func TestT20iRemoveBodyOnBothMessagesSatisfiesTheBodyExclusion(t *testing.T) {
	request := `{"` + t20iProtected("RB2_NAME") + `":"` + t20iProtected("RB2_VALUE") + `"}`
	response := `{"` + t20iProtected("RB2_RNAME") + `":"` + t20iProtected("RB2_RVALUE") + `"}`
	cases := []t20iCase{
		{name: "rb2-both", pieces: []string{t20iRequest("POST", "/t20i/rb2-both?keep="+t20iPermitted("RB2_QUERY"),
			t20iWith(t20iJSON, "X-T20i-Keep", t20iPermitted("RB2_HEADER")), request)},
			response:  t20iResponse{Type: "application/json", Body: []byte(response), Headers: map[string]string{"X-T20i-Keep": t20iPermitted("RB2_RHEADER")}},
			protected: []string{t20iProtected("RB2_NAME"), t20iProtected("RB2_VALUE"), t20iProtected("RB2_RNAME"), t20iProtected("RB2_RVALUE")},
			permitted: []string{t20iPermitted("RB2_QUERY"), t20iPermitted("RB2_HEADER"), t20iPermitted("RB2_RHEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, len(request), "content_length")
				t20iRemovedWhole(t, x.Response.Message, len(response), "content_length")
				t20iHasHeader(t, x.Response.Message, "X-T20i-Keep", t20iPermitted("RB2_RHEADER"))
				if x.Request.Message.Target != "/t20i/rb2-both?keep="+t20iPermitted("RB2_QUERY") {
					t.Errorf("the target changed to %q", x.Request.Message.Target)
				}
				t20iEvidence(t, a, x, t20iRemovedEntry("request"), t20iRemovedEntry("response"))
			}},
		{name: "rb2-neither", pieces: []string{t20iRequest("GET", "/t20i/rb2-neither?keep="+t20iPermitted("RB2_NEITHER"), nil, "")},
			permitted: []string{t20iPermitted("RB2_NEITHER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				for _, m := range []*record.Message{x.Request.Message, x.Response.Message} {
					if m.Structure.State != record.StructureNone {
						t.Errorf("a message with no body reads as %+v", m.Structure)
					}
				}
				t20iEvidence(t, a, x)
			}},
	}
	setup := t20iSetup{
		pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"},
			t20iSlot("body", config.RemoveBody, map[string]any{"messages": []string{"request", "response"}}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-body", config.BodyField)},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// t20iShapeNames is every member name a shape holds, at any depth.
func t20iShapeNames(s *record.Shape) []string {
	if s == nil {
		return nil
	}
	var names []string
	for _, f := range s.Fields {
		names = append(names, f.Name)
		names = append(names, t20iShapeNames(&f.Shape)...)
	}
	for i := range s.Elems {
		names = append(names, t20iShapeNames(&s.Elems[i])...)
	}
	return names
}

// reduce-body-to-structure under message.body.values. A value marker is
// absent and a member-name marker is PRESENT, in the structure: that second
// half is what separates message.body.values from message.body. A body with
// no structure derived goes whole.
func TestT20iReduceBodyToStructureDropsValuesAndKeepsMemberNames(t *testing.T) {
	request := `{"` + t20iPermitted("RD_NAME1") + `":"` + t20iProtected("RD_VALUE1") + `","nested":{"` +
		t20iPermitted("RD_NAME2") + `":"` + t20iProtected("RD_VALUE2") + `","list":["` + t20iProtected("RD_VALUE3") +
		`",{"` + t20iPermitted("RD_NAME3") + `":"` + t20iProtected("RD_VALUE4") + `"}]}}`
	response := `{"` + t20iPermitted("RD_RNAME") + `":"` + t20iProtected("RD_RVALUE") + `"}`
	answer := t20iResponse{Type: "application/json", Body: []byte(response)}
	reducedResponse := func(t *testing.T, x record.Exchange) {
		t.Helper()
		m := x.Response.Message
		if m.Body.Kept != "" || m.Structure.State != record.StructureDerived || !slices.Contains(t20iShapeNames(m.Structure.Shape), t20iPermitted("RD_RNAME")) {
			t.Errorf("the response is not reduced to its structure: kept %q structure %+v", m.Body.Kept, m.Structure)
		}
	}
	text := "plain " + t20iProtected("RD_TEXT")
	form := "card_number=" + t20iProtected("RD_FORM")
	keep := t20iHeader{"X-T20i-Keep", t20iPermitted("RD_HEADER")}
	cases := []t20iCase{
		{name: "rd-json", pieces: []string{t20iRequest("POST", "/t20i/rd-json", append(slices.Clone(t20iJSON), keep), request)},
			response: answer,
			protected: []string{t20iProtected("RD_VALUE1"), t20iProtected("RD_VALUE2"), t20iProtected("RD_VALUE3"),
				t20iProtected("RD_VALUE4"), t20iProtected("RD_RVALUE")},
			permitted: []string{t20iPermitted("RD_NAME1"), t20iPermitted("RD_NAME2"), t20iPermitted("RD_NAME3"),
				t20iPermitted("RD_RNAME"), t20iPermitted("RD_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				m := x.Request.Message
				if m.Body.Kept != "" {
					t.Errorf("a reduced body retains %q", m.Body.Kept)
				}
				if m.Structure.State != record.StructureDerived {
					t.Fatalf("a reduced JSON body lost its structure: %+v", m.Structure)
				}
				names := t20iShapeNames(m.Structure.Shape)
				for _, name := range []string{t20iPermitted("RD_NAME1"), "nested", t20iPermitted("RD_NAME2"), "list", t20iPermitted("RD_NAME3")} {
					if !slices.Contains(names, name) {
						t.Errorf("the reduced structure lost member name %s; names %q", name, names)
					}
				}
				reducedResponse(t, x)
				t20iEvidence(t, a, x,
					t20iEntry{"request", config.BodyValuesField, "", processing.DispositionValuesRemoved},
					t20iEntry{"response", config.BodyValuesField, "", processing.DispositionValuesRemoved})
			}},
		{name: "rd-text", pieces: []string{t20iRequest("POST", "/t20i/rd-text", []t20iHeader{{"Content-Type", "text/plain"}, keep}, text)},
			response: answer, protected: []string{t20iProtected("RD_TEXT"), t20iProtected("RD_RVALUE")},
			permitted: []string{t20iPermitted("RD_HEADER"), t20iPermitted("RD_RNAME")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, len(text), "content_length")
				reducedResponse(t, x)
				t20iEvidence(t, a, x, t20iRemovedEntry("request"),
					t20iEntry{"response", config.BodyValuesField, "", processing.DispositionValuesRemoved})
			}},
		{name: "rd-form", pieces: []string{t20iRequest("POST", "/t20i/rd-form", append(slices.Clone(t20iForm), keep), form)},
			response: answer, protected: []string{t20iProtected("RD_FORM"), t20iProtected("RD_RVALUE")},
			permitted: []string{t20iPermitted("RD_HEADER"), t20iPermitted("RD_RNAME")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, len(form), "content_length")
				t20iEvidence(t, a, x, t20iRemovedEntry("request"),
					t20iEntry{"response", config.BodyValuesField, "", processing.DispositionValuesRemoved})
			}},
		{name: "rd-neither", pieces: []string{t20iRequest("GET", "/t20i/rd-neither?keep="+t20iPermitted("RD_NEITHER"), nil, "")},
			permitted: []string{t20iPermitted("RD_NEITHER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iEvidence(t, a, x)
			}},
	}
	setup := t20iSetup{
		pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"},
			t20iSlot("reduce", config.ReduceBodyToStructure, map[string]any{"messages": []string{"request", "response"}}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-values", config.BodyValuesField)},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// remove-query under message.target.query: the target goes from its first
// "?", whatever follows, and the path and body stay. A target with a "?" and
// nothing after it had the component; one with none did not.
func TestT20iRemoveQueryDropsTheTargetFromItsFirstQuestionMark(t *testing.T) {
	body := `{"note":"` + t20iPermitted("RQ_BODY") + `"}`
	keep := t20iWith(t20iJSON, "X-T20i-Keep", t20iPermitted("RQ_HEADER"))
	answer := t20iResponse{Body: []byte(t20iPermitted("RQ_RESPONSE"))}
	permitted := []string{t20iPermitted("RQ_BODY"), t20iPermitted("RQ_HEADER"), t20iPermitted("RQ_RESPONSE")}
	query := func(name, query, path string, entry bool, protected ...string) t20iCase {
		return t20iCase{name: name, pieces: []string{t20iRequest("POST", "/t20i/"+name+query, keep, body)},
			response: answer, protected: protected, permitted: permitted,
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if x.Request.Message.Target != path {
					t.Errorf("the target written is %q, want %q", x.Request.Message.Target, path)
				}
				t20iKept(t, x.Request.Message, body)
				t20iHasHeader(t, x.Request.Message, "X-T20i-Keep", t20iPermitted("RQ_HEADER"))
				t20iKept(t, x.Response.Message, t20iPermitted("RQ_RESPONSE"))
				if entry {
					t20iEvidence(t, a, x, t20iEntry{"request", config.TargetQueryField, "", processing.DispositionRemoved})
				} else {
					t20iEvidence(t, a, x)
				}
			}}
	}
	semicolon := "rq-semi;k=" + t20iPermitted("RQ_PATH")
	cases := []t20iCase{
		query("rq-basic", "?card="+t20iProtected("RQ_BASIC1")+"&x="+t20iProtected("RQ_BASIC2"), "/t20i/rq-basic", true,
			t20iProtected("RQ_BASIC1"), t20iProtected("RQ_BASIC2")),
		query("rq-bare", "?", "/t20i/rq-bare", true),
		query("rq-none", "", "/t20i/rq-none", false),
		query("rq-double", "?a="+t20iProtected("RQ_DOUBLE1")+"?b="+t20iProtected("RQ_DOUBLE2"), "/t20i/rq-double", true,
			t20iProtected("RQ_DOUBLE1"), t20iProtected("RQ_DOUBLE2")),
		query("rq-enc%3Fpath", "?q="+t20iProtected("RQ_ENCODED"), "/t20i/rq-enc%3Fpath", true, t20iProtected("RQ_ENCODED")),
		query(semicolon, "?q="+t20iProtected("RQ_SEMI"), "/t20i/"+semicolon, true, t20iProtected("RQ_SEMI")),
	}
	cases[len(cases)-1].permitted = append(slices.Clone(permitted), t20iPermitted("RQ_PATH"))
	setup := t20iSetup{
		pipelines:    []map[string]any{t20iPipeline("t20i", []string{"account"}, t20iSlot("query", config.RemoveQuery, map[string]any{}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-query", config.TargetQueryField)},
	}
	if strings.Contains(semicolon, "?") {
		t.Fatal("wiring: the path case holds a question mark")
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}
