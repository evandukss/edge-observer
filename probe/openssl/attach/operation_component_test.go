//go:build attach

package attach_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

var (
	operationJSON = []operationHeader{{"Content-Type", "application/json"}}
	operationForm = []operationHeader{{"Content-Type", "application/x-www-form-urlencoded"}}
)

// operationWith is headers with one more.
func operationWith(headers []operationHeader, name, value string) []operationHeader {
	return append(slices.Clone(headers), operationHeader{name, value})
}

// operationRemovedEntry is the entry a body removed whole by a component
// operation carries.
func operationRemovedEntry(message string) operationEntry {
	return operationEntry{message, config.BodyField, "", processing.DispositionRemoved}
}

// operationUndecidableEntry is the entry a body a field operation could not decide
// carries.
func operationUndecidableEntry(message string) operationEntry {
	return operationEntry{message, config.BodyField, "", processing.DispositionRemovedUndecidable}
}

// remove-body on requests only. Every request body with bytes goes whole,
// whatever its grammar or framing, its member names with its values; the
// response body, which the slot does not select, is written unchanged.
func TestRemoveBodyOnRequestsDropsEveryRequestBodyAndKeepsTheResponse(t *testing.T) {
	jsonBody := `{"` + operationProtected("RB_NAME") + `":"` + operationProtected("RB_VALUE") + `","note":1}`
	chunks := []string{`{"card":{"number":"OPERPROT_RB_CHU`, `NK_END"},"n":1}`}
	formBody := "card_number=" + operationProtected("RB_FORM") + "&note=1"
	multipart := operationMultipart([2]string{"card_number", operationProtected("RB_PART")})
	response := `{"answer":"` + operationPermitted("RB_RESPONSE") + `"}`
	answer := operationResponse{Type: "application/json", Body: []byte(response)}
	removed := func(length int, framing string) func(*testing.T, string, processing.Artifact, record.Exchange) {
		return func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			operationRemovedWhole(t, x.Request.Message, length, framing)
			operationHasHeader(t, x.Request.Message, "X-Oper-Keep", operationPermitted("RB_HEADER"))
			operationKept(t, x.Response.Message, response)
			if x.Response.Message.Structure.State != record.StructureDerived {
				t.Errorf("the response body the slot does not select lost its structure: %+v", x.Response.Message.Structure)
			}
			operationEvidence(t, a, x, operationRemovedEntry("request"))
		}
	}
	keep := operationHeader{"X-Oper-Keep", operationPermitted("RB_HEADER")}
	cases := []operationCase{
		{name: "rb-json", pieces: []string{operationRequest("POST", "/oper/rb-json", append(slices.Clone(operationJSON), keep), jsonBody)},
			response: answer, protected: []string{operationProtected("RB_NAME"), operationProtected("RB_VALUE")},
			permitted: []string{operationPermitted("RB_HEADER"), operationPermitted("RB_RESPONSE")}, check: removed(len(jsonBody), "content_length")},
		{name: "rb-chunked", pieces: operationSplit(t, operationChunked("POST", "/oper/rb-chunked", append(slices.Clone(operationJSON), keep), chunks, nil),
			"OPERPROT_R", "\r\nNK"),
			response: answer, protected: []string{"OPERPROT_RB_CHUNK_END"},
			permitted: []string{operationPermitted("RB_HEADER"), operationPermitted("RB_RESPONSE")}, check: removed(len(chunks[0]+chunks[1]), "chunked")},
		{name: "rb-form", pieces: []string{operationRequest("POST", "/oper/rb-form", append(slices.Clone(operationForm), keep), formBody)},
			response: answer, protected: []string{operationProtected("RB_FORM")},
			permitted: []string{operationPermitted("RB_HEADER"), operationPermitted("RB_RESPONSE")}, check: removed(len(formBody), "content_length")},
		{name: "rb-multipart", pieces: []string{operationRequest("POST", "/oper/rb-multipart",
			[]operationHeader{{"Content-Type", "multipart/form-data; boundary=XB"}, keep}, multipart)},
			response: answer, protected: []string{operationProtected("RB_PART")},
			permitted: []string{operationPermitted("RB_HEADER"), operationPermitted("RB_RESPONSE")}, check: removed(len(multipart), "content_length")},
		// Never present: no body, and a body of no bytes, carry no entry.
		{name: "rb-none", pieces: []string{operationRequest("GET", "/oper/rb-none?keep="+operationPermitted("RB_NONE"), nil, "")},
			response: answer, permitted: []string{operationPermitted("RB_NONE"), operationPermitted("RB_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if x.Request.Message.Structure.State != record.StructureNone || x.Request.Message.Body.Length != "0" {
					t.Errorf("a request with no body reads as %+v, length %q", x.Request.Message.Structure, x.Request.Message.Body.Length)
				}
				operationKept(t, x.Response.Message, response)
				operationEvidence(t, a, x)
			}},
		{name: "rb-empty", pieces: []string{operationRequest("POST", "/oper/rb-empty?keep="+operationPermitted("RB_EMPTY"), operationJSON, "")},
			response: answer, permitted: []string{operationPermitted("RB_EMPTY"), operationPermitted("RB_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if x.Request.Message.Structure.State == record.StructureRemoved {
					t.Errorf("a body of no bytes reads as removed: %+v", x.Request.Message.Structure)
				}
				operationEvidence(t, a, x)
			}},
	}
	setup := operationSetup{rules: map[string]any{"remove": map[string]any{"bodies": []string{"request"}}}}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}

// remove-body on both messages under the message.body exclusion: both bodies
// go whole, each recorded on its own message, and an exchange with neither
// body records nothing.
func TestRemoveBodyOnBothMessagesSatisfiesTheBodyExclusion(t *testing.T) {
	request := `{"` + operationProtected("RB2_NAME") + `":"` + operationProtected("RB2_VALUE") + `"}`
	response := `{"` + operationProtected("RB2_RNAME") + `":"` + operationProtected("RB2_RVALUE") + `"}`
	cases := []operationCase{
		{name: "rb2-both", pieces: []string{operationRequest("POST", "/oper/rb2-both?keep="+operationPermitted("RB2_QUERY"),
			operationWith(operationJSON, "X-Oper-Keep", operationPermitted("RB2_HEADER")), request)},
			response:  operationResponse{Type: "application/json", Body: []byte(response), Headers: map[string]string{"X-Oper-Keep": operationPermitted("RB2_RHEADER")}},
			protected: []string{operationProtected("RB2_NAME"), operationProtected("RB2_VALUE"), operationProtected("RB2_RNAME"), operationProtected("RB2_RVALUE")},
			permitted: []string{operationPermitted("RB2_QUERY"), operationPermitted("RB2_HEADER"), operationPermitted("RB2_RHEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationRemovedWhole(t, x.Request.Message, len(request), "content_length")
				operationRemovedWhole(t, x.Response.Message, len(response), "content_length")
				operationHasHeader(t, x.Response.Message, "X-Oper-Keep", operationPermitted("RB2_RHEADER"))
				if x.Request.Message.Target != "/oper/rb2-both?keep="+operationPermitted("RB2_QUERY") {
					t.Errorf("the target changed to %q", x.Request.Message.Target)
				}
				operationEvidence(t, a, x, operationRemovedEntry("request"), operationRemovedEntry("response"))
			}},
		{name: "rb2-neither", pieces: []string{operationRequest("GET", "/oper/rb2-neither?keep="+operationPermitted("RB2_NEITHER"), nil, "")},
			permitted: []string{operationPermitted("RB2_NEITHER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				for _, m := range []*record.Message{x.Request.Message, x.Response.Message} {
					if m.Structure.State != record.StructureNone {
						t.Errorf("a message with no body reads as %+v", m.Structure)
					}
				}
				operationEvidence(t, a, x)
			}},
	}
	setup := operationSetup{rules: map[string]any{"remove": map[string]any{"bodies": []string{"request", "response"}}}}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}

// operationShapeNames is every member name a shape holds, at any depth.
func operationShapeNames(s *record.Shape) []string {
	if s == nil {
		return nil
	}
	var names []string
	for _, f := range s.Fields {
		names = append(names, f.Name)
		names = append(names, operationShapeNames(&f.Shape)...)
	}
	for i := range s.Elems {
		names = append(names, operationShapeNames(&s.Elems[i])...)
	}
	return names
}

// reduce-body-to-structure under message.body.values. A value marker is
// absent and a member-name marker is PRESENT, in the structure: that second
// half is what separates message.body.values from message.body. A body with
// no structure derived goes whole.
func TestReduceBodyToStructureDropsValuesAndKeepsMemberNames(t *testing.T) {
	request := `{"` + operationPermitted("RD_NAME1") + `":"` + operationProtected("RD_VALUE1") + `","nested":{"` +
		operationPermitted("RD_NAME2") + `":"` + operationProtected("RD_VALUE2") + `","list":["` + operationProtected("RD_VALUE3") +
		`",{"` + operationPermitted("RD_NAME3") + `":"` + operationProtected("RD_VALUE4") + `"}]}}`
	response := `{"` + operationPermitted("RD_RNAME") + `":"` + operationProtected("RD_RVALUE") + `"}`
	answer := operationResponse{Type: "application/json", Body: []byte(response)}
	reducedResponse := func(t *testing.T, x record.Exchange) {
		t.Helper()
		m := x.Response.Message
		if m.Body.Kept != "" || m.Structure.State != record.StructureDerived || !slices.Contains(operationShapeNames(m.Structure.Shape), operationPermitted("RD_RNAME")) {
			t.Errorf("the response is not reduced to its structure: kept %q structure %+v", m.Body.Kept, m.Structure)
		}
	}
	text := "plain " + operationProtected("RD_TEXT")
	form := "card_number=" + operationProtected("RD_FORM")
	keep := operationHeader{"X-Oper-Keep", operationPermitted("RD_HEADER")}
	cases := []operationCase{
		{name: "rd-json", pieces: []string{operationRequest("POST", "/oper/rd-json", append(slices.Clone(operationJSON), keep), request)},
			response: answer,
			protected: []string{operationProtected("RD_VALUE1"), operationProtected("RD_VALUE2"), operationProtected("RD_VALUE3"),
				operationProtected("RD_VALUE4"), operationProtected("RD_RVALUE")},
			permitted: []string{operationPermitted("RD_NAME1"), operationPermitted("RD_NAME2"), operationPermitted("RD_NAME3"),
				operationPermitted("RD_RNAME"), operationPermitted("RD_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				m := x.Request.Message
				if m.Body.Kept != "" {
					t.Errorf("a reduced body retains %q", m.Body.Kept)
				}
				if m.Structure.State != record.StructureDerived {
					t.Fatalf("a reduced JSON body lost its structure: %+v", m.Structure)
				}
				names := operationShapeNames(m.Structure.Shape)
				for _, name := range []string{operationPermitted("RD_NAME1"), "nested", operationPermitted("RD_NAME2"), "list", operationPermitted("RD_NAME3")} {
					if !slices.Contains(names, name) {
						t.Errorf("the reduced structure lost member name %s; names %q", name, names)
					}
				}
				reducedResponse(t, x)
				operationEvidence(t, a, x,
					operationEntry{"request", config.BodyValuesField, "", processing.DispositionValuesRemoved},
					operationEntry{"response", config.BodyValuesField, "", processing.DispositionValuesRemoved})
			}},
		{name: "rd-text", pieces: []string{operationRequest("POST", "/oper/rd-text", []operationHeader{{"Content-Type", "text/plain"}, keep}, text)},
			response: answer, protected: []string{operationProtected("RD_TEXT"), operationProtected("RD_RVALUE")},
			permitted: []string{operationPermitted("RD_HEADER"), operationPermitted("RD_RNAME")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationRemovedWhole(t, x.Request.Message, len(text), "content_length")
				reducedResponse(t, x)
				operationEvidence(t, a, x, operationRemovedEntry("request"),
					operationEntry{"response", config.BodyValuesField, "", processing.DispositionValuesRemoved})
			}},
		{name: "rd-form", pieces: []string{operationRequest("POST", "/oper/rd-form", append(slices.Clone(operationForm), keep), form)},
			response: answer, protected: []string{operationProtected("RD_FORM"), operationProtected("RD_RVALUE")},
			permitted: []string{operationPermitted("RD_HEADER"), operationPermitted("RD_RNAME")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationRemovedWhole(t, x.Request.Message, len(form), "content_length")
				operationEvidence(t, a, x, operationRemovedEntry("request"),
					operationEntry{"response", config.BodyValuesField, "", processing.DispositionValuesRemoved})
			}},
		{name: "rd-neither", pieces: []string{operationRequest("GET", "/oper/rd-neither?keep="+operationPermitted("RD_NEITHER"), nil, "")},
			permitted: []string{operationPermitted("RD_NEITHER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationEvidence(t, a, x)
			}},
	}
	setup := operationSetup{rules: map[string]any{"remove": map[string]any{"body_values": []string{"request", "response"}}}}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}

// remove-query under message.target.query: the target goes from its first
// "?", whatever follows, and the path and body stay. A target with a "?" and
// nothing after it had the component; one with none did not.
func TestRemoveQueryDropsTheTargetFromItsFirstQuestionMark(t *testing.T) {
	body := `{"note":"` + operationPermitted("RQ_BODY") + `"}`
	keep := operationWith(operationJSON, "X-Oper-Keep", operationPermitted("RQ_HEADER"))
	answer := operationResponse{Body: []byte(operationPermitted("RQ_RESPONSE"))}
	permitted := []string{operationPermitted("RQ_BODY"), operationPermitted("RQ_HEADER"), operationPermitted("RQ_RESPONSE")}
	query := func(name, query, path string, entry bool, protected ...string) operationCase {
		return operationCase{name: name, pieces: []string{operationRequest("POST", "/oper/"+name+query, keep, body)},
			response: answer, protected: protected, permitted: permitted,
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if x.Request.Message.Target != path {
					t.Errorf("the target written is %q, want %q", x.Request.Message.Target, path)
				}
				operationKept(t, x.Request.Message, body)
				operationHasHeader(t, x.Request.Message, "X-Oper-Keep", operationPermitted("RQ_HEADER"))
				operationKept(t, x.Response.Message, operationPermitted("RQ_RESPONSE"))
				if entry {
					operationEvidence(t, a, x, operationEntry{"request", config.TargetQueryField, "", processing.DispositionRemoved})
				} else {
					operationEvidence(t, a, x)
				}
			}}
	}
	semicolon := "rq-semi;k=" + operationPermitted("RQ_PATH")
	cases := []operationCase{
		query("rq-basic", "?card="+operationProtected("RQ_BASIC1")+"&x="+operationProtected("RQ_BASIC2"), "/oper/rq-basic", true,
			operationProtected("RQ_BASIC1"), operationProtected("RQ_BASIC2")),
		query("rq-bare", "?", "/oper/rq-bare", true),
		query("rq-none", "", "/oper/rq-none", false),
		query("rq-double", "?a="+operationProtected("RQ_DOUBLE1")+"?b="+operationProtected("RQ_DOUBLE2"), "/oper/rq-double", true,
			operationProtected("RQ_DOUBLE1"), operationProtected("RQ_DOUBLE2")),
		query("rq-enc%3Fpath", "?q="+operationProtected("RQ_ENCODED"), "/oper/rq-enc%3Fpath", true, operationProtected("RQ_ENCODED")),
		query(semicolon, "?q="+operationProtected("RQ_SEMI"), "/oper/"+semicolon, true, operationProtected("RQ_SEMI")),
	}
	cases[len(cases)-1].permitted = append(slices.Clone(permitted), operationPermitted("RQ_PATH"))
	setup := operationSetup{
		rules: map[string]any{"remove": map[string]any{"query_string": true}},
	}
	if strings.Contains(semicolon, "?") {
		t.Fatal("wiring: the path case holds a question mark")
	}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}
