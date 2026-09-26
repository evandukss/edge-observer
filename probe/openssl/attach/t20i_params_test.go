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

// t20iVariant is a parameter PHP files under card_number, with "@" where the
// protected value goes. exact is true where the rest of the query or body
// after removal is determined: one parameter removed, last, "&" only.
type t20iVariant struct {
	name, parameter string
	exact           bool
	markers         []string
}

// t20iVariants are the names the contract's matching covers for the
// configured name card_number, each read by PHP 8.5.1 as card_number.
func t20iVariants(prefix string) []t20iVariant {
	one := func(name, parameter string) t20iVariant {
		marker := t20iProtected(prefix + "_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
		return t20iVariant{name, strings.ReplaceAll(parameter, "@", marker), true, []string{marker}}
	}
	two := func(name, parameter string) t20iVariant {
		base := prefix + "_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		first, second := t20iProtected(base+"1"), t20iProtected(base+"2")
		return t20iVariant{name, strings.NewReplacer("@1", first, "@2", second).Replace(parameter), false, []string{first, second}}
	}
	return []t20iVariant{
		one("exact", "card_number=@"),
		one("dot", "card.number=@"),
		one("plus", "card+number=@"),
		one("space", "card%20number=@"),
		one("leading-plus", "+card_number=@"),
		one("leading-space", "%20card_number=@"),
		one("leading-spaces", "%20+%20card_number=@"),
		one("nul", "card_number%00tail=@"),
		one("brackets", "card_number[]=@"),
		one("key", "card_number[k]=@"),
		one("nested", "card_number[a][b]=@"),
		one("unmatched", "card[number=@"),
		one("encoded-bracket", "card%5Bnumber=@"),
		one("encoded-brackets", "card_number%5B%5D=@"),
		one("encoded-dot", "card%2Enumber=@"),
		one("dot-then-key", "card.number[x]=@"),
		one("marker-in-name", "card_number[@]=v"),
		two("duplicate", "card_number=@1&card_number=@2"),
		// Contract 52 revision 25: PHP reads "@1;@2" as ONE value, since its
		// separator is "&" alone, so all of it goes.
		two("semicolon-in-value", "card_number=@1;@2"),
	}
}

// t20iParameters is a query or urlencoded body split as the contract splits
// it, on both separators.
func t20iParameters(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '&' || r == ';' })
}

// remove-query-parameters under message.query.card_number: every name PHP
// files under card_number goes, with every byte of its value as PHP reads it,
// and every other parameter stays.
func TestT20iRemoveQueryParametersRemovesEveryNamePHPFilesUnderTheConfiguredName(t *testing.T) {
	var cases []t20iCase
	entry := t20iEntry{"request", config.QueryFieldPrefix + "card_number", "", processing.DispositionRemoved}
	for _, v := range t20iVariants("QP") {
		keep := t20iPermitted("QP_" + strings.ToUpper(strings.ReplaceAll(v.name, "-", "_")))
		name := "qp-" + v.name
		cases = append(cases, t20iCase{name: name,
			pieces:    []string{t20iRequest("GET", "/t20i/"+name+"?note="+keep+"&"+v.parameter, nil, "")},
			protected: v.markers, permitted: []string{keep},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				target := x.Request.Message.Target
				if v.exact && target != "/t20i/"+name+"?note="+keep {
					t.Errorf("the target written is %q, want %q", target, "/t20i/"+name+"?note="+keep)
				}
				_, query, _ := strings.Cut(target, "?")
				if !slices.Contains(t20iParameters(query), "note="+keep) {
					t.Errorf("the permitted parameter did not survive: %q", target)
				}
				t20iEvidence(t, a, x, entry)
			}})
	}
	p, k := t20iProtected, t20iPermitted
	positions := []struct {
		name, query, want string
		protected         string
		permitted         []string
	}{
		{"qp-first", "card_number=" + p("QP_FIRST") + "&note=" + k("QP_FIRST"), "note=" + k("QP_FIRST"),
			p("QP_FIRST"), []string{k("QP_FIRST")}},
		{"qp-middle", "note=" + k("QP_MIDDLE1") + "&card_number=" + p("QP_MIDDLE") + "&other=" + k("QP_MIDDLE2"),
			"note=" + k("QP_MIDDLE1") + "&other=" + k("QP_MIDDLE2"), p("QP_MIDDLE"), []string{k("QP_MIDDLE1"), k("QP_MIDDLE2")}},
		// The ";" reading selects the parameter after the ";"; the "&" reading
		// selects nothing here, and the union is what goes.
		{"qp-semicolon-separated", "note=" + k("QP_SEMI") + ";card_number=" + p("QP_SEMI"), "",
			p("QP_SEMI"), []string{k("QP_SEMI")}},
	}
	for _, one := range positions {
		cases = append(cases, t20iCase{name: one.name, pieces: []string{t20iRequest("GET", "/t20i/"+one.name+"?"+one.query, nil, "")},
			protected: []string{one.protected}, permitted: one.permitted,
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				if one.want != "" && x.Request.Message.Target != "/t20i/"+one.name+"?"+one.want {
					t.Errorf("the target written is %q, want %q", x.Request.Message.Target, "/t20i/"+one.name+"?"+one.want)
				}
				t20iEvidence(t, a, x, entry)
			}})
	}
	untouched := "note=" + k("QP_NONE1") + "&card_numbers=" + k("QP_NONE2") + "&xcard_number=" + k("QP_NONE3")
	cases = append(cases, t20iCase{name: "qp-none", pieces: []string{t20iRequest("GET", "/t20i/qp-none?"+untouched, nil, "")},
		permitted: []string{k("QP_NONE1"), k("QP_NONE2"), k("QP_NONE3")},
		check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			if x.Request.Message.Target != "/t20i/qp-none?"+untouched {
				t.Errorf("a query with no matching name changed to %q", x.Request.Message.Target)
			}
			t20iEvidence(t, a, x)
		}})
	setup := t20iSetup{
		pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"},
			t20iSlot("params", config.RemoveQueryParameters, map[string]any{"names": []string{"card_number"}}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-query-card", config.QueryFieldPrefix+"card_number")},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// remove-form-fields under message.form.card_number. An admitted urlencoded
// body loses every name PHP files under card_number and keeps the rest; a
// request body the rule does not admit goes whole; a response body is not
// touched.
func TestT20iRemoveFormFieldsRemovesEveryNamePHPFilesUnderTheConfiguredName(t *testing.T) {
	var cases []t20iCase
	entry := t20iEntry{"request", config.FormFieldPrefix + "card_number", "", processing.DispositionRemoved}
	keepHeader := t20iHeader{"X-T20i-Keep", t20iPermitted("FF_HEADER")}
	admitted := func(name string, headers []t20iHeader, body, keep, want string, protected ...string) t20iCase {
		return t20iCase{name: name, pieces: []string{t20iRequest("POST", "/t20i/"+name, headers, body)},
			protected: protected, permitted: []string{keep},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				retained := string(t20iBody(t, x.Request.Message))
				if want != "" && retained != want {
					t.Errorf("the body retained is %q, want %q", retained, want)
				}
				if !slices.Contains(t20iParameters(retained), "note="+keep) {
					t.Errorf("the admitted body lost its permitted parameter: %q", retained)
				}
				t20iEvidence(t, a, x, entry)
			}}
	}
	for _, v := range t20iVariants("FF") {
		keep := t20iPermitted("FF_" + strings.ToUpper(strings.ReplaceAll(v.name, "-", "_")))
		want := ""
		if v.exact {
			want = "note=" + keep
		}
		cases = append(cases, admitted("ff-"+v.name, t20iForm, "note="+keep+"&"+v.parameter, keep, want, v.markers...))
	}
	p, k := t20iProtected, t20iPermitted
	cases = append(cases,
		admitted("ff-media-type-case", []t20iHeader{{"Content-Type", "APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8"}},
			"card_number="+p("FF_CT_CASE")+"&note="+k("FF_CT_CASE"), k("FF_CT_CASE"), "note="+k("FF_CT_CASE"), p("FF_CT_CASE")),
		admitted("ff-media-type-space", []t20iHeader{{"Content-Type", "application/x-www-form-urlencoded \t; charset=utf-8"}},
			"card_number="+p("FF_CT_SPACE")+"&note="+k("FF_CT_SPACE"), k("FF_CT_SPACE"), "note="+k("FF_CT_SPACE"), p("FF_CT_SPACE")),
		// A PUT body is a request body like any other.
		t20iCase{name: "ff-put", pieces: []string{t20iRequest("PUT", "/t20i/ff-put", t20iForm, "card_number="+p("FF_PUT")+"&note="+k("FF_PUT"))},
			protected: []string{p("FF_PUT")}, permitted: []string{k("FF_PUT")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iKept(t, x.Request.Message, "note="+k("FF_PUT"))
				t20iEvidence(t, a, x, entry)
			}},
		// Split across chunks and across TLS writes, the marker in neither
		// whole; one Content-Type, so the body is admitted.
		t20iCase{name: "ff-chunked", pieces: t20iSplit(t, t20iChunked("POST", "/t20i/ff-chunked", t20iForm,
			[]string{"note=" + k("FF_CHUNK") + "&card_number=T20IPROT_FF_CHU", "NK_END"}, nil), "T20IPROT_F", "\r\nNK"),
			protected: []string{"T20IPROT_FF_CHUNK_END"}, permitted: []string{k("FF_CHUNK")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iKept(t, x.Request.Message, "note="+k("FF_CHUNK"))
				t20iEvidence(t, a, x, entry)
			}},
		// Contract 52 revision 25's form input: valid JSON that PHP reads as a
		// urlencoded body carrying card_number.
		t20iCase{name: "ff-json-named", pieces: []string{t20iRequest("POST", "/t20i/ff-json-named", append(slices.Clone(t20iForm), keepHeader),
			`{"&card_number=`+p("FF_JSON_NAMED")+`":1}`)},
			protected: []string{p("FF_JSON_NAMED")}, permitted: []string{k("FF_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iEvidence(t, a, x, entry)
			}},
		t20iCase{name: "ff-response", pieces: []string{t20iRequest("POST", "/t20i/ff-response", t20iForm, "note="+k("FF_REQUEST"))},
			response:  t20iResponse{Type: "application/x-www-form-urlencoded", Body: []byte("card_number=" + k("FF_RESPONSE") + "&x=1")},
			permitted: []string{k("FF_REQUEST"), k("FF_RESPONSE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iKept(t, x.Request.Message, "note="+k("FF_REQUEST"))
				t20iKept(t, x.Response.Message, "card_number="+k("FF_RESPONSE")+"&x=1")
				t20iEvidence(t, a, x)
			}},
		t20iCase{name: "ff-none", pieces: []string{t20iRequest("GET", "/t20i/ff-none?note="+k("FF_NONE"), nil, "")},
			permitted: []string{k("FF_NONE")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iEvidence(t, a, x)
			}},
	)
	// Not admitted: every other non-empty request body goes whole.
	whole := func(name string, pieces []string, length int, framing string, protected ...string) t20iCase {
		return t20iCase{name: name, pieces: pieces, protected: protected, permitted: []string{k("FF_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, length, framing)
				t20iEvidence(t, a, x, t20iUndecidableEntry("request"))
			}}
	}
	multipart := t20iMultipart([2]string{"card_number", p("FF_MULTIPART")}, [2]string{"note", p("FF_MULTIPART_NOTE")})
	jsonBody := `{"card_number":"` + p("FF_JSON") + `"}`
	bare := "card_number=" + p("FF_NO_TYPE") + "&note=1"
	twice := "card_number=" + p("FF_TWO_TYPES") + "&note=1"
	chunks := []string{"card_number=" + p("FF_TRAILER") + "&note=1"}
	cases = append(cases,
		whole("ff-multipart", []string{t20iRequest("POST", "/t20i/ff-multipart", []t20iHeader{{"Content-Type", "multipart/form-data; boundary=XB"}, keepHeader}, multipart)},
			len(multipart), "content_length", p("FF_MULTIPART"), p("FF_MULTIPART_NOTE")),
		whole("ff-json", []string{t20iRequest("POST", "/t20i/ff-json", append(slices.Clone(t20iJSON), keepHeader), jsonBody)},
			len(jsonBody), "content_length", p("FF_JSON")),
		whole("ff-no-type", []string{t20iRequest("POST", "/t20i/ff-no-type", []t20iHeader{keepHeader}, bare)}, len(bare), "content_length", p("FF_NO_TYPE")),
		whole("ff-two-types", []string{t20iRequest("POST", "/t20i/ff-two-types", append(slices.Clone(t20iForm), t20iForm[0], keepHeader), twice)},
			len(twice), "content_length", p("FF_TWO_TYPES")),
		// A Content-Type trailer counts: header and trailer are two.
		whole("ff-trailer-type", []string{t20iChunked("POST", "/t20i/ff-trailer-type", append(slices.Clone(t20iForm), keepHeader), chunks, t20iForm)},
			len(chunks[0]), "chunked", p("FF_TRAILER")),
	)
	setup := t20iSetup{
		pipelines: []map[string]any{t20iPipeline("t20i", []string{"account"},
			t20iSlot("form", config.RemoveFormFields, map[string]any{"names": []string{"card_number"}}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-form-card", config.FormFieldPrefix+"card_number")},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}

// Body operations read Content-Type from the message as parsed. A slot
// relabelling a multipart body as urlencoded does not get it admitted, and a
// slot removing the label from a urlencoded body does not stop it being
// admitted.
func TestT20iBodyOperationsReadContentTypeFromTheMessageAsParsed(t *testing.T) {
	p, k := t20iProtected, t20iPermitted
	multipart := t20iMultipart([2]string{"card_number", p("CT_MULTIPART")})
	form := "card_number=" + p("CT_FORM") + "&note=" + k("CT_FORM")
	keepHeader := t20iHeader{"X-T20i-Keep", k("CT_HEADER")}
	cases := []t20iCase{
		{name: "ct-multipart", pieces: []string{t20iRequest("POST", "/t20i/ct-multipart", []t20iHeader{{"Content-Type", "multipart/form-data; boundary=XB"}, keepHeader}, multipart)},
			protected: []string{p("CT_MULTIPART")}, permitted: []string{k("CT_HEADER")},
			check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
				t20iRemovedWhole(t, x.Request.Message, len(multipart), "content_length")
				t20iEvidence(t, a, x, t20iUndecidableEntry("request"))
			}},
		{name: "ct-form", pieces: []string{t20iRequest("POST", "/t20i/ct-form", append(slices.Clone(t20iForm), keepHeader), form)},
			protected: []string{p("CT_FORM")}, permitted: []string{k("CT_FORM"), k("CT_HEADER")},
			check: func(t *testing.T, pipeline string, a processing.Artifact, x record.Exchange) {
				t20iKept(t, x.Request.Message, "note="+k("CT_FORM"))
				t20iEvidence(t, a, x, t20iEntry{"request", config.FormFieldPrefix + "card_number", "", processing.DispositionRemoved})
			}},
	}
	relabel := t20iSlot("relabel", config.ReplaceHeaderValues, map[string]any{"headers": []string{"content-type"}, "value": "application/x-www-form-urlencoded"})
	unlabel := t20iSlot("unlabel", config.RemoveHeaders, map[string]any{"headers": []string{"content-type"}})
	form1 := t20iSlot("form", config.RemoveFormFields, map[string]any{"names": []string{"card_number"}})
	setup := t20iSetup{
		pipelines: []map[string]any{
			t20iPipeline("relabelled", []string{"account"}, relabel, form1),
			t20iPipeline("unlabelled", []string{"account"}, unlabel, form1),
		},
		requirements: []cp.Requirement{t20iRequirement("t20i-form-card", config.FormFieldPrefix+"card_number")},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"relabelled", "unlabelled"}, cases)
}
