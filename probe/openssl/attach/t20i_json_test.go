//go:build attach

package attach_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// t20iDecoded is a retained body read as JSON, which it must still be.
func t20iDecoded(t *testing.T, m *record.Message) any {
	t.Helper()
	body := t20iBody(t, m)
	var v any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		t.Fatalf("the retained body is no longer JSON: %v\n%s", err, body)
	}
	return v
}

// t20iJSONIs asserts a retained body reads as the JSON want.
func t20iJSONIs(t *testing.T, m *record.Message, want string) {
	t.Helper()
	var expected any
	decoder := json.NewDecoder(strings.NewReader(want))
	decoder.UseNumber()
	if err := decoder.Decode(&expected); err != nil {
		t.Fatalf("wiring: the expected body %q is not JSON: %v", want, err)
	}
	if got := t20iDecoded(t, m); !reflect.DeepEqual(got, expected) {
		t.Errorf("the retained body reads as %v, want %v; bytes %q", got, expected, t20iBody(t, m))
	}
}

func t20iJSONEntry(message, pointer string) t20iEntry {
	return t20iEntry{message, config.JSONFieldPrefix + pointer, "", processing.DispositionRemoved}
}

// remove-json-fields on both messages under message.body.json/card/number.
// Every member a pointer matches goes - in a case variant, under a name
// written with escapes or folding to the token, duplicated, under every array
// element and every object member at a "*" - and every other byte stays. A
// body that is not strictly valid JSON goes whole: its marker sits where no
// pointer reaches, so only whole removal hides it.
func TestT20iRemoveJSONFieldsRemovesEveryMatchAndKeepsEveryOtherByte(t *testing.T) {
	keepHeader := t20iHeader{"X-T20i-Keep", t20iPermitted("J_HEADER")}
	headers := []t20iHeader{{"Content-Type", "application/json"}, keepHeader}
	plainResponse := `{"other":"` + t20iPermitted("J_RESPONSE") + `"}`
	answer := t20iResponse{Type: "application/json", Body: []byte(plainResponse)}
	// decided is a body the operation reads: after it, the body reads as want
	// and the entries are exactly the pointers named.
	decided := func(name, body, want string, protected, permitted []string, pointers ...string) t20iCase {
		return t20iCase{name: name, pieces: []string{t20iRequest("POST", "/t20i/"+name, headers, body)}, response: answer,
			protected: protected, permitted: append(permitted, t20iPermitted("J_HEADER"), t20iPermitted("J_RESPONSE")),
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iJSONIs(t, x.Request.Message, want)
				if x.Request.Message.Structure.State != record.StructureDerived {
					t.Errorf("a body with members removed has structure %+v, want it derived again", x.Request.Message.Structure)
				}
				t20iKept(t, x.Response.Message, plainResponse)
				var entries []t20iEntry
				for _, p := range pointers {
					entries = append(entries, t20iJSONEntry("request", p))
				}
				t20iEvidence(t, a, x, entries...)
			}}
	}
	// undecidable is a body the operation must remove whole.
	undecidable := func(name string, headers []t20iHeader, body string, protected string) t20iCase {
		return t20iCase{name: name, pieces: []string{t20iRequest("POST", "/t20i/"+name, append(slices.Clone(headers), keepHeader), body)}, response: answer,
			protected: []string{protected}, permitted: []string{t20iPermitted("J_HEADER"), t20iPermitted("J_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, len(body), "content_length")
				t20iKept(t, x.Response.Message, plainResponse)
				t20iEvidence(t, a, x, t20iUndecidableEntry("request"))
			}}
	}
	p, k := t20iProtected, t20iPermitted
	deep := func(levels int) string { return strings.Repeat("[", levels) + strings.Repeat("]", levels) }
	splice := `{ "a" : 1.50E+2 ,"card": {"number": "` + p("J_SPLICE") + `" , "holder":"` + k("J_SPLICE") + `\u00e9"}, "z":[1, 2 ] }`
	chunks := []string{`{"card":{"number":"T20IPROT_J_CHU`, `NK_END","holder":"` + k("J_CHUNK") + `"}}`}
	responseMatch := `{"card":{"number":"` + p("J_RNUMBER") + `","holder":"` + k("J_RHOLDER") + `"}}`
	cases := []t20iCase{
		decided("j-value", `{"card":{"number":"`+p("J_VALUE")+`","holder":"`+k("J_VALUE")+`"}}`,
			`{"card":{"holder":"`+k("J_VALUE")+`"}}`, []string{p("J_VALUE")}, []string{k("J_VALUE")}, "/card/number"),
		decided("j-case", `{"CARD":{"Number":"`+p("J_CASE")+`","holder":"`+k("J_CASE")+`"}}`,
			`{"CARD":{"holder":"`+k("J_CASE")+`"}}`, []string{p("J_CASE")}, []string{k("J_CASE")}, "/card/number"),
		// U+017F folds to "s" and U+212A to "k" under simple case folding;
		// the first is written as UTF-8, the second as an escape.
		decided("j-fold", `{"`+"\u017f"+`ecret":"`+p("J_FOLD1")+`","to\u212aens":{"x":"`+p("J_FOLD2")+`"},"keep":"`+k("J_FOLD")+`"}`,
			`{"keep":"`+k("J_FOLD")+`"}`, []string{p("J_FOLD1"), p("J_FOLD2")}, []string{k("J_FOLD")}, "/secret", "/tokens"),
		decided("j-escape", `{"card":{"\u006eumber":"`+p("J_ESCAPE")+`","holder":"`+k("J_ESCAPE")+`"}}`,
			`{"card":{"holder":"`+k("J_ESCAPE")+`"}}`, []string{p("J_ESCAPE")}, []string{k("J_ESCAPE")}, "/card/number"),
		decided("j-duplicate", `{"secret":"`+p("J_DUP1")+`","keep":"`+k("J_DUP")+`","secret":"`+p("J_DUP2")+`"}`,
			`{"keep":"`+k("J_DUP")+`"}`, []string{p("J_DUP1"), p("J_DUP2")}, []string{k("J_DUP")}, "/secret"),
		decided("j-array", `{"cards":[{"number":"`+p("J_ARRAY1")+`","brand":"`+k("J_ARRAY1")+`"},{"number":"`+p("J_ARRAY2")+`","brand":"`+k("J_ARRAY2")+`"}]}`,
			`{"cards":[{"brand":"`+k("J_ARRAY1")+`"},{"brand":"`+k("J_ARRAY2")+`"}]}`,
			[]string{p("J_ARRAY1"), p("J_ARRAY2")}, []string{k("J_ARRAY1"), k("J_ARRAY2")}, "/cards/*/number"),
		// Contract 52 revision 25: "*" matches every object member too, since
		// PHP iterates an object exactly like an array.
		decided("j-object-members", `{"cards":{"a":{"number":"`+p("J_OBJECT1")+`","brand":"`+k("J_OBJECT1")+`"},"0":{"number":"`+p("J_OBJECT2")+`","brand":"`+k("J_OBJECT2")+`"}}}`,
			`{"cards":{"a":{"brand":"`+k("J_OBJECT1")+`"},"0":{"brand":"`+k("J_OBJECT2")+`"}}}`,
			[]string{p("J_OBJECT1"), p("J_OBJECT2")}, []string{k("J_OBJECT1"), k("J_OBJECT2")}, "/cards/*/number"),
		// A member name under a removed member goes with it, from the bytes and
		// from the structure derived again.
		decided("j-name", `{"tokens":{"`+p("J_NAME")+`":1,"inner":"`+p("J_NAME_VALUE")+`"},"keep":"`+k("J_NAME")+`"}`,
			`{"keep":"`+k("J_NAME")+`"}`, []string{p("J_NAME"), p("J_NAME_VALUE")}, []string{k("J_NAME")}, "/tokens"),
		decided("j-whitespace", " \t\r\n"+`{"secret":"`+p("J_SPACE")+`","keep":"`+k("J_SPACE")+`"}`+"\n ",
			`{"keep":"`+k("J_SPACE")+`"}`, []string{p("J_SPACE")}, []string{k("J_SPACE")}, "/secret"),
		decided("j-deep-within", `{"secret":"`+p("J_DEEP_OK")+`","keep":"`+k("J_DEEP_OK")+`","d":`+deep(20)+`}`,
			`{"keep":"`+k("J_DEEP_OK")+`","d":`+deep(20)+`}`, []string{p("J_DEEP_OK")}, []string{k("J_DEEP_OK")}, "/secret"),
		decided("j-none", `{"other":"`+k("J_NONE")+`"}`, `{"other":"`+k("J_NONE")+`"}`, nil, []string{k("J_NONE")}),
		// The removed member goes with the comma after it, or the one before
		// it where it was last, and no other byte changes.
		{name: "j-exact", pieces: []string{t20iRequest("POST", "/t20i/j-exact", headers,
			`{"keep":"`+k("J_EXACT1")+`","card":{"number":"`+p("J_EXACT1")+`","holder":"`+k("J_EXACT2")+`","number":"`+p("J_EXACT2")+`"}}`)},
			response: answer, protected: []string{p("J_EXACT1"), p("J_EXACT2")}, permitted: []string{k("J_EXACT1"), k("J_EXACT2")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iKept(t, x.Request.Message, `{"keep":"`+k("J_EXACT1")+`","card":{"holder":"`+k("J_EXACT2")+`"}}`)
				t20iEvidence(t, a, x, t20iJSONEntry("request", "/card/number"))
			}},
		{name: "j-splice", pieces: []string{t20iRequest("POST", "/t20i/j-splice", headers, splice)},
			response: answer, protected: []string{p("J_SPLICE")}, permitted: []string{k("J_SPLICE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				body := string(t20iBody(t, x.Request.Message))
				for _, span := range []string{`{ "a" : 1.50E+2 ,"card": {`, `"holder":"` + k("J_SPLICE") + `\u00e9"}`, `, "z":[1, 2 ] }`} {
					if !strings.Contains(body, span) {
						t.Errorf("the retained body lost the exact bytes %q: %q", span, body)
					}
				}
				if strings.Contains(body, `"number"`) {
					t.Errorf("the removed member's name was written: %q", body)
				}
				t20iJSONIs(t, x.Request.Message, `{"a":1.50E+2,"card":{"holder":"`+k("J_SPLICE")+`\u00e9"},"z":[1,2]}`)
				t20iEvidence(t, a, x, t20iJSONEntry("request", "/card/number"))
			}},
		// The label is not consulted: JSON labelled as text is read.
		{name: "j-label", pieces: []string{t20iRequest("POST", "/t20i/j-label", []t20iHeader{{"Content-Type", "text/plain"}, keepHeader},
			`{"card":{"number":"`+p("J_LABEL")+`","holder":"`+k("J_LABEL")+`"}}`)},
			response: answer, protected: []string{p("J_LABEL")}, permitted: []string{k("J_LABEL"), k("J_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iJSONIs(t, x.Request.Message, `{"card":{"holder":"`+k("J_LABEL")+`"}}`)
				t20iEvidence(t, a, x, t20iJSONEntry("request", "/card/number"))
			}},
		{name: "j-chunked", pieces: t20iSplit(t, t20iChunked("POST", "/t20i/j-chunked", headers, chunks, nil), "T20IPROT_J", "\r\nNK"),
			response: answer, protected: []string{"T20IPROT_J_CHUNK_END"}, permitted: []string{k("J_CHUNK")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iJSONIs(t, x.Request.Message, `{"card":{"holder":"`+k("J_CHUNK")+`"}}`)
				if x.Request.Message.Framing != "chunked" {
					t.Errorf("the chunked request states framing %q", x.Request.Message.Framing)
				}
				t20iEvidence(t, a, x, t20iJSONEntry("request", "/card/number"))
			}},
		{name: "j-response", pieces: []string{t20iRequest("POST", "/t20i/j-response", headers, `{"other":"`+k("J_REQUEST")+`"}`)},
			response:  t20iResponse{Type: "application/json", Body: []byte(responseMatch)},
			protected: []string{p("J_RNUMBER")}, permitted: []string{k("J_REQUEST"), k("J_RHOLDER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iKept(t, x.Request.Message, `{"other":"`+k("J_REQUEST")+`"}`)
				t20iJSONIs(t, x.Response.Message, `{"card":{"holder":"`+k("J_RHOLDER")+`"}}`)
				t20iEvidence(t, a, x, t20iJSONEntry("response", "/card/number"))
			}},
		undecidable("j-trailing-comma", t20iJSON, `{"unnamed":"`+p("J_COMMA")+`",}`, p("J_COMMA")),
		undecidable("j-bom", t20iJSON, "\xef\xbb\xbf"+`{"unnamed":"`+p("J_BOM")+`"}`, p("J_BOM")),
		undecidable("j-invalid-utf8", t20iJSON, `{"unnamed":"`+p("J_UTF8")+`","x":"`+"\xff"+`"}`, p("J_UTF8")),
		undecidable("j-surrogate", t20iJSON, `{"unnamed":"`+p("J_SURROGATE")+`","x":"\ud800"}`, p("J_SURROGATE")),
		undecidable("j-two-values", t20iJSON, `{"unnamed":"`+p("J_TWO")+`"}{"a":1}`, p("J_TWO")),
		undecidable("j-too-deep", t20iJSON, `{"unnamed":"`+p("J_DEEP")+`","d":`+deep(40)+`}`, p("J_DEEP")),
		undecidable("j-nbsp", t20iJSON, "\u00a0"+`{"unnamed":"`+p("J_NBSP")+`"}`, p("J_NBSP")),
		undecidable("j-text", []t20iHeader{{"Content-Type", "text/plain"}}, "plain "+p("J_TEXT"), p("J_TEXT")),
		undecidable("j-mislabelled", t20iJSON, "card_number="+p("J_MISLABEL"), p("J_MISLABEL")),
	}
	setup := t20iSetup{
		pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"}, t20iSlot("json", config.RemoveJSONFields, map[string]any{
			"messages": []string{"request", "response"}, "pointers": []string{"/card/number", "/cards/*/number", "/secret", "/tokens"}}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-json", config.JSONFieldPrefix+"/card/number")},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// Where one match lies inside another, the outer one is acted on: the whole
// card goes, including the member no pointer names on its own.
func TestT20iRemoveJSONFieldsActsOnTheOuterOfTwoNestedMatches(t *testing.T) {
	body := `{"card":{"number":"` + t20iProtected("JN_NUMBER") + `","holder":"` + t20iProtected("JN_HOLDER") + `"},"keep":"` + t20iPermitted("JN_KEEP") + `"}`
	cases := []t20iCase{{name: "jn-nested", pieces: []string{t20iRequest("POST", "/t20i/jn-nested", t20iJSON, body)},
		protected: []string{t20iProtected("JN_NUMBER"), t20iProtected("JN_HOLDER")}, permitted: []string{t20iPermitted("JN_KEEP")},
		check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			t20iJSONIs(t, x.Request.Message, `{"keep":"`+t20iPermitted("JN_KEEP")+`"}`)
			outer := false
			for _, e := range a.PolicyExclusions {
				if e.Exchange == x.Index && e.Field == config.BodyField {
					t.Errorf("a decidable body carries a whole-body entry: %+v", e)
				}
				outer = outer || (e.Exchange == x.Index && e.Message == "request" && e.Field == config.JSONFieldPrefix+"/card" && e.Disposition == processing.DispositionRemoved)
			}
			if !outer {
				t.Errorf("the outer match carries no entry: %+v", a.PolicyExclusions)
			}
		}}}
	setup := t20iSetup{pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"}, t20iSlot("json", config.RemoveJSONFields,
		map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number", "/card"}}))}}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// replace-json-values writes its value, as a JSON string, over every match,
// and records nothing: a replacement is not a removal. A body it cannot read
// goes whole, as for any field operation.
func TestT20iReplaceJSONValuesReplacesEveryMatchAndRecordsNoRemoval(t *testing.T) {
	const value = `REPL "q" \ T20IKEEP_REPL_END`
	quoted, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	keepHeader := t20iHeader{"X-T20i-Keep", t20iPermitted("V_HEADER")}
	headers := []t20iHeader{{"Content-Type", "application/json"}, keepHeader}
	p, k := t20iProtected, t20iPermitted
	replaced := func(name, body, want string, protected []string, permitted ...string) t20iCase {
		return t20iCase{name: name, pieces: []string{t20iRequest("POST", "/t20i/"+name, headers, body)},
			protected: protected, permitted: append(permitted, k("V_HEADER"), "T20IKEEP_REPL_END"),
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iJSONIs(t, x.Request.Message, strings.ReplaceAll(want, "@", string(quoted)))
				t20iEvidence(t, a, x)
			}}
	}
	const digits = "4111111111111111"
	cases := []t20iCase{
		replaced("v-value", `{"card":{"number":"`+p("V_VALUE")+`","holder":"`+k("V_VALUE")+`"}}`,
			`{"card":{"number":@,"holder":"`+k("V_VALUE")+`"}}`, []string{p("V_VALUE")}, k("V_VALUE")),
		replaced("v-case", `{"Card":{"NUMBER":"`+p("V_CASE")+`","holder":"`+k("V_CASE")+`"}}`,
			`{"Card":{"NUMBER":@,"holder":"`+k("V_CASE")+`"}}`, []string{p("V_CASE")}, k("V_CASE")),
		replaced("v-array", `{"cards":[{"number":"`+p("V_ARRAY1")+`"},{"number":"`+p("V_ARRAY2")+`","brand":"`+k("V_ARRAY")+`"}]}`,
			`{"cards":[{"number":@},{"number":@,"brand":"`+k("V_ARRAY")+`"}]}`, []string{p("V_ARRAY1"), p("V_ARRAY2")}, k("V_ARRAY")),
		replaced("v-object-members", `{"cards":{"x":{"number":"`+p("V_OBJECT")+`","brand":"`+k("V_OBJECT")+`"}}}`,
			`{"cards":{"x":{"number":@,"brand":"`+k("V_OBJECT")+`"}}}`, []string{p("V_OBJECT")}, k("V_OBJECT")),
		replaced("v-number", `{"card":{"number":`+digits+`,"holder":"`+k("V_NUMBER")+`"}}`,
			`{"card":{"number":@,"holder":"`+k("V_NUMBER")+`"}}`, []string{digits}, k("V_NUMBER")),
		replaced("v-object-value", `{"secret":{"deep":"`+p("V_DEEP")+`"},"keep":"`+k("V_DEEP")+`"}`,
			`{"secret":@,"keep":"`+k("V_DEEP")+`"}`, []string{p("V_DEEP")}, k("V_DEEP")),
		{name: "v-duplicate", pieces: []string{t20iRequest("POST", "/t20i/v-duplicate", headers,
			`{"secret":"`+p("V_DUP1")+`","keep":"`+k("V_DUP")+`","secret":"`+p("V_DUP2")+`"}`)},
			protected: []string{p("V_DUP1"), p("V_DUP2")}, permitted: []string{k("V_DUP"), k("V_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				// Decoding into a map keeps only the last duplicate, so the
				// members are read as tokens, in order.
				body := t20iBody(t, x.Request.Message)
				decoder := json.NewDecoder(bytes.NewReader(body))
				var tokens []any
				for {
					token, err := decoder.Token()
					if err != nil {
						break
					}
					tokens = append(tokens, token)
				}
				want := []any{json.Delim('{'), "secret", value, "keep", k("V_DUP"), "secret", value, json.Delim('}')}
				if !reflect.DeepEqual(tokens, want) {
					t.Errorf("the body reads as %v, want %v: %q", tokens, want, body)
				}
				t20iEvidence(t, a, x)
			}},
		{name: "v-invalid", pieces: []string{t20iRequest("POST", "/t20i/v-invalid", headers, `{"unnamed":"`+p("V_INVALID")+`",}`)},
			protected: []string{p("V_INVALID")}, permitted: []string{k("V_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, len(`{"unnamed":"`+p("V_INVALID")+`",}`), "content_length")
				t20iEvidence(t, a, x, t20iUndecidableEntry("request"))
			}},
	}
	setup := t20iSetup{pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"}, t20iSlot("replace", config.ReplaceJSONValues,
		map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number", "/cards/*/number", "/secret"}, "value": value}))}}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}
