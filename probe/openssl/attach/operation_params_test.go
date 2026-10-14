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

// operationVariant is a parameter named card_number, with "@" where the
// protected value goes. exact is true where the rest of the query or body
// after removal is determined: one parameter removed, last, "&" only.
type operationVariant struct {
	name, parameter string
	exact           bool
	markers         []string
}

// operationVariants are the parameters exact matching removes for the configured
// name card_number: the name once, and the name twice.
func operationVariants(prefix string) []operationVariant {
	one := func(name, parameter string) operationVariant {
		marker := operationProtected(prefix + "_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
		return operationVariant{name, strings.ReplaceAll(parameter, "@", marker), true, []string{marker}}
	}
	two := func(name, parameter string) operationVariant {
		base := prefix + "_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		first, second := operationProtected(base+"1"), operationProtected(base+"2")
		return operationVariant{name, strings.NewReplacer("@1", first, "@2", second).Replace(parameter), false, []string{first, second}}
	}
	return []operationVariant{
		one("exact", "card_number=@"),
		two("duplicate", "card_number=@1&card_number=@2"),
	}
}

// operationParameters splits a query or urlencoded body on & and on ;, finer than
// the contract's split on & alone. It is used only to find a parameter that
// must survive, which the finer split still finds.
func operationParameters(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '&' || r == ';' })
}

// remove-query-parameters under message.query.card_number: every parameter
// named card_number goes, with every byte of its value, and every other
// parameter stays.
func TestRemoveQueryParametersRemovesEveryParameterWithTheConfiguredName(t *testing.T) {
	var cases []operationCase
	entry := operationEntry{"request", config.QueryFieldPrefix + "card_number", "", processing.DispositionRemoved}
	for _, v := range operationVariants("QP") {
		keep := operationPermitted("QP_" + strings.ToUpper(strings.ReplaceAll(v.name, "-", "_")))
		name := "qp-" + v.name
		cases = append(cases, operationCase{name: name,
			pieces:    []string{operationRequest("GET", "/oper/"+name+"?note="+keep+"&"+v.parameter, nil, "")},
			protected: v.markers, permitted: []string{keep},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				target := x.Request.Message.Target
				if v.exact && target != "/oper/"+name+"?note="+keep {
					t.Errorf("the target written is %q, want %q", target, "/oper/"+name+"?note="+keep)
				}
				_, query, _ := strings.Cut(target, "?")
				if !slices.Contains(operationParameters(query), "note="+keep) {
					t.Errorf("the permitted parameter did not survive: %q", target)
				}
				operationEvidence(t, a, x, entry)
			}})
	}
	p, k := operationProtected, operationPermitted
	positions := []struct {
		name, query, want string
		protected         string
		permitted         []string
	}{
		{"qp-first", "card_number=" + p("QP_FIRST") + "&note=" + k("QP_FIRST"), "note=" + k("QP_FIRST"),
			p("QP_FIRST"), []string{k("QP_FIRST")}},
		{"qp-middle", "note=" + k("QP_MIDDLE1") + "&card_number=" + p("QP_MIDDLE") + "&other=" + k("QP_MIDDLE2"),
			"note=" + k("QP_MIDDLE1") + "&other=" + k("QP_MIDDLE2"), p("QP_MIDDLE"), []string{k("QP_MIDDLE1"), k("QP_MIDDLE2")}},
	}
	for _, one := range positions {
		cases = append(cases, operationCase{name: one.name, pieces: []string{operationRequest("GET", "/oper/"+one.name+"?"+one.query, nil, "")},
			protected: []string{one.protected}, permitted: one.permitted,
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if one.want != "" && x.Request.Message.Target != "/oper/"+one.name+"?"+one.want {
					t.Errorf("the target written is %q, want %q", x.Request.Message.Target, "/oper/"+one.name+"?"+one.want)
				}
				operationEvidence(t, a, x, entry)
			}})
	}
	untouched := "note=" + k("QP_NONE1") + "&card_numbers=" + k("QP_NONE2") + "&xcard_number=" + k("QP_NONE3")
	cases = append(cases, operationCase{name: "qp-none", pieces: []string{operationRequest("GET", "/oper/qp-none?"+untouched, nil, "")},
		permitted: []string{k("QP_NONE1"), k("QP_NONE2"), k("QP_NONE3")},
		check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			if x.Request.Message.Target != "/oper/qp-none?"+untouched {
				t.Errorf("a query with no matching name changed to %q", x.Request.Message.Target)
			}
			operationEvidence(t, a, x)
		}})
	setup := operationSetup{rules: map[string]any{"remove": map[string]any{"query": []string{"card_number"}}}}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}

// remove-form-fields under message.form.card_number. An admitted urlencoded
// body loses every parameter named card_number and keeps the rest; a
// request body the rule does not admit goes whole; a response body is not
// touched.
func TestRemoveFormFieldsRemovesEveryParameterWithTheConfiguredName(t *testing.T) {
	var cases []operationCase
	entry := operationEntry{"request", config.FormFieldPrefix + "card_number", "", processing.DispositionRemoved}
	keepHeader := operationHeader{"X-Oper-Keep", operationPermitted("FF_HEADER")}
	admitted := func(name string, headers []operationHeader, body, keep, want string, protected ...string) operationCase {
		return operationCase{name: name, pieces: []string{operationRequest("POST", "/oper/"+name, headers, body)},
			protected: protected, permitted: []string{keep},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				retained := string(operationBody(t, x.Request.Message))
				if want != "" && retained != want {
					t.Errorf("the body retained is %q, want %q", retained, want)
				}
				if !slices.Contains(operationParameters(retained), "note="+keep) {
					t.Errorf("the admitted body lost its permitted parameter: %q", retained)
				}
				operationEvidence(t, a, x, entry)
			}}
	}
	for _, v := range operationVariants("FF") {
		keep := operationPermitted("FF_" + strings.ToUpper(strings.ReplaceAll(v.name, "-", "_")))
		want := ""
		if v.exact {
			want = "note=" + keep
		}
		cases = append(cases, admitted("ff-"+v.name, operationForm, "note="+keep+"&"+v.parameter, keep, want, v.markers...))
	}
	p, k := operationProtected, operationPermitted
	cases = append(cases,
		admitted("ff-media-type-case", []operationHeader{{"Content-Type", "APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8"}},
			"card_number="+p("FF_CT_CASE")+"&note="+k("FF_CT_CASE"), k("FF_CT_CASE"), "note="+k("FF_CT_CASE"), p("FF_CT_CASE")),
		admitted("ff-media-type-space", []operationHeader{{"Content-Type", "application/x-www-form-urlencoded \t; charset=utf-8"}},
			"card_number="+p("FF_CT_SPACE")+"&note="+k("FF_CT_SPACE"), k("FF_CT_SPACE"), "note="+k("FF_CT_SPACE"), p("FF_CT_SPACE")),
		// A PUT body is a request body like any other.
		operationCase{name: "ff-put", pieces: []string{operationRequest("PUT", "/oper/ff-put", operationForm, "card_number="+p("FF_PUT")+"&note="+k("FF_PUT"))},
			protected: []string{p("FF_PUT")}, permitted: []string{k("FF_PUT")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationKept(t, x.Request.Message, "note="+k("FF_PUT"))
				operationEvidence(t, a, x, entry)
			}},
		// Split across chunks and across TLS writes, the marker in neither
		// whole; one Content-Type, so the body is admitted.
		operationCase{name: "ff-chunked", pieces: operationSplit(t, operationChunked("POST", "/oper/ff-chunked", operationForm,
			[]string{"note=" + k("FF_CHUNK") + "&card_number=OPERPROT_FF_CHU", "NK_END"}, nil), "OPERPROT_F", "\r\nNK"),
			protected: []string{"OPERPROT_FF_CHUNK_END"}, permitted: []string{k("FF_CHUNK")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationKept(t, x.Request.Message, "note="+k("FF_CHUNK"))
				operationEvidence(t, a, x, entry)
			}},
		// A form input that is valid JSON and, split on & as a urlencoded body,
		// carries a parameter named card_number.
		operationCase{name: "ff-json-named", pieces: []string{operationRequest("POST", "/oper/ff-json-named", append(slices.Clone(operationForm), keepHeader),
			`{"&card_number=`+p("FF_JSON_NAMED")+`":1}`)},
			protected: []string{p("FF_JSON_NAMED")}, permitted: []string{k("FF_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationEvidence(t, a, x, entry)
			}},
		operationCase{name: "ff-response", pieces: []string{operationRequest("POST", "/oper/ff-response", operationForm, "note="+k("FF_REQUEST"))},
			response:  operationResponse{Type: "application/x-www-form-urlencoded", Body: []byte("card_number=" + k("FF_RESPONSE") + "&x=1")},
			permitted: []string{k("FF_REQUEST"), k("FF_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationKept(t, x.Request.Message, "note="+k("FF_REQUEST"))
				operationKept(t, x.Response.Message, "card_number="+k("FF_RESPONSE")+"&x=1")
				operationEvidence(t, a, x)
			}},
		operationCase{name: "ff-none", pieces: []string{operationRequest("GET", "/oper/ff-none?note="+k("FF_NONE"), nil, "")},
			permitted: []string{k("FF_NONE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationEvidence(t, a, x)
			}},
	)
	// Not admitted: every other non-empty request body goes whole.
	whole := func(name string, pieces []string, length int, framing string, protected ...string) operationCase {
		return operationCase{name: name, pieces: pieces, protected: protected, permitted: []string{k("FF_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationRemovedWhole(t, x.Request.Message, length, framing)
				operationEvidence(t, a, x, operationUndecidableEntry("request"))
			}}
	}
	multipart := operationMultipart([2]string{"card_number", p("FF_MULTIPART")}, [2]string{"note", p("FF_MULTIPART_NOTE")})
	jsonBody := `{"card_number":"` + p("FF_JSON") + `"}`
	bare := "card_number=" + p("FF_NO_TYPE") + "&note=1"
	twice := "card_number=" + p("FF_TWO_TYPES") + "&note=1"
	chunks := []string{"card_number=" + p("FF_TRAILER") + "&note=1"}
	cases = append(cases,
		whole("ff-multipart", []string{operationRequest("POST", "/oper/ff-multipart", []operationHeader{{"Content-Type", "multipart/form-data; boundary=XB"}, keepHeader}, multipart)},
			len(multipart), "content_length", p("FF_MULTIPART"), p("FF_MULTIPART_NOTE")),
		whole("ff-json", []string{operationRequest("POST", "/oper/ff-json", append(slices.Clone(operationJSON), keepHeader), jsonBody)},
			len(jsonBody), "content_length", p("FF_JSON")),
		whole("ff-no-type", []string{operationRequest("POST", "/oper/ff-no-type", []operationHeader{keepHeader}, bare)}, len(bare), "content_length", p("FF_NO_TYPE")),
		whole("ff-two-types", []string{operationRequest("POST", "/oper/ff-two-types", append(slices.Clone(operationForm), operationForm[0], keepHeader), twice)},
			len(twice), "content_length", p("FF_TWO_TYPES")),
		// A Content-Type trailer counts: header and trailer are two.
		whole("ff-trailer-type", []string{operationChunked("POST", "/oper/ff-trailer-type", append(slices.Clone(operationForm), keepHeader), chunks, operationForm)},
			len(chunks[0]), "chunked", p("FF_TRAILER")),
	)
	setup := operationSetup{rules: map[string]any{"remove": map[string]any{"form": []string{"card_number"}}}}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}

// Body operations read Content-Type from the message as parsed: a rule that
// removes the label from a urlencoded body does not stop it being admitted, and
// a multipart body under the same rules still goes whole. Relabelling a message
// before a body rule reads it is not a configuration a user can write, since
// every mask runs after every remove.
func TestBodyOperationsReadContentTypeFromTheMessageAsParsed(t *testing.T) {
	p, k := operationProtected, operationPermitted
	multipart := operationMultipart([2]string{"card_number", p("CT_MULTIPART")})
	form := "card_number=" + p("CT_FORM") + "&note=" + k("CT_FORM")
	keepHeader := operationHeader{"X-Oper-Keep", k("CT_HEADER")}
	// The content-type removal is evidence like any other, on both messages.
	unlabelled := func(entries ...operationEntry) []operationEntry {
		for _, message := range []string{"request", "response"} {
			entries = append(entries, operationEntry{message, config.HeaderFieldPrefix + "content-type", "headers", processing.DispositionRemoved})
		}
		return entries
	}
	cases := []operationCase{
		{name: "ct-multipart", pieces: []string{operationRequest("POST", "/oper/ct-multipart", []operationHeader{{"Content-Type", "multipart/form-data; boundary=XB"}, keepHeader}, multipart)},
			protected: []string{p("CT_MULTIPART")}, permitted: []string{k("CT_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationRemovedWhole(t, x.Request.Message, len(multipart), "content_length")
				operationEvidence(t, a, x, unlabelled(operationUndecidableEntry("request"))...)
			}},
		{name: "ct-form", pieces: []string{operationRequest("POST", "/oper/ct-form", append(slices.Clone(operationForm), keepHeader), form)},
			protected: []string{p("CT_FORM")}, permitted: []string{k("CT_FORM"), k("CT_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				operationKept(t, x.Request.Message, "note="+k("CT_FORM"))
				operationEvidence(t, a, x, unlabelled(operationEntry{"request", config.FormFieldPrefix + "card_number", "", processing.DispositionRemoved})...)
			}},
	}
	setup := operationSetup{rules: map[string]any{"remove": map[string]any{"headers": []string{"content-type"}, "form": []string{"card_number"}}}}
	o := operationRun(t, setup, cases)
	operationRemovalPrecedesTheFormRule(t, o.configuration, "content-type")
	operationAssert(t, o, []string{config.ExchangesPipeline}, cases)
}

// operationRemovalPrecedesTheFormRule is the precondition of a test whose subject
// is a header removed BEFORE a body rule reads the message: in the plan the
// session's own configuration compiles to, the slot removing the header comes
// before the form slot. Where it does not, the state the test names cannot
// occur and nothing it asserts would measure it.
func operationRemovalPrecedesTheFormRule(t *testing.T, configuration []byte, header string) {
	t.Helper()
	compiled, findings := config.Compile(configuration, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the session's configuration does not compile here: %+v", findings)
	}
	removal, form := -1, -1
	for _, p := range compiled.Plan.Pipelines() {
		if p.Name != config.ExchangesPipeline {
			continue
		}
		for i, slot := range p.Slots {
			switch {
			case slot.Implementation == config.RemoveHeaders && slot.Arguments != nil && slices.Contains(slot.Arguments.Headers, header):
				removal = i
			case slot.Implementation == config.RemoveFormFields:
				form = i
			}
		}
	}
	if removal < 0 || form < 0 || removal > form {
		t.Fatalf("precondition, not the property: in the compiled plan the %s removal is slot %d and the form rule "+
			"slot %d, so no message has that header removed before the form rule reads it", header, removal, form)
	}
}
