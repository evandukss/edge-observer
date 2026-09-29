//go:build attach

package attach_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
)

// t20iRefusal is a configuration the contract refuses, beside its neighbour:
// the same configuration with the one change that makes it valid, run live,
// activating and writing. The pair is what shows the named reason is the one
// that decides.
type t20iRefusal struct {
	name    string
	refused t20iSetup
	// reasons must each appear as a finding's reason; where the contract
	// allows either of two, anyOf holds them and one must appear. mention is
	// text the refusal must carry: the route, the requirement, the message
	// left uncovered.
	reasons []string
	anyOf   []string
	mention []string

	neighbour t20iSetup
	pipelines []string
	exchange  t20iCase
}

func t20iRefusals(t *testing.T, refusals []t20iRefusal) {
	t.Helper()
	binary := built(t)
	client := speaking(t, serving(t))
	targets := []map[string]any{target("t20i", client.process)}
	for _, r := range refusals {
		t.Run(r.name, func(t *testing.T) {
			t.Run("refused", func(t *testing.T) {
				out := t20iRefused(t, binary, targets, r.refused, r.reasons...)
				if len(r.anyOf) > 0 && !slices.ContainsFunc(r.anyOf, func(reason string) bool { return strings.Contains(out, ": "+reason+": ") }) {
					t.Errorf("the refusal names none of %q:\n%s", r.anyOf, out)
				}
				for _, text := range r.mention {
					if !strings.Contains(out, text) {
						t.Errorf("the refusal does not name %q:\n%s", text, out)
					}
				}
			})
			t.Run("neighbour", func(t *testing.T) {
				pipelines := r.pipelines
				if pipelines == nil {
					pipelines = []string{"t20i"}
				}
				cases := []t20iCase{r.exchange}
				t20iAssert(t, t20iRun(t, r.neighbour, cases), pipelines, cases)
			})
		})
	}
}

// t20iRoute is the one pipeline t20i to account holding these slots.
func t20iRoute(slots ...map[string]any) []map[string]any {
	return []map[string]any{t20iPipeline("t20i", []string{"account"}, slots...)}
}

func t20iMessages(messages ...string) map[string]any {
	if messages == nil {
		messages = []string{}
	}
	return map[string]any{"messages": messages}
}

// Neighbour exchanges. Each carries protected markers its neighbour removes
// and permitted ones it keeps.
func t20iBodyExchange(name string) t20iCase {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	p, k := t20iProtected(upper), t20iPermitted(upper)
	return t20iCase{name: name,
		pieces: []string{t20iRequest("POST", "/t20i/"+name+"?keep="+k, t20iWith(t20iJSON, "X-T20i-Keep", k),
			`{"card":{"number":"`+p+`"}}`)},
		response:  t20iResponse{Type: "application/json", Body: []byte(`{"r":"` + t20iProtected(upper+"_R") + `"}`)},
		protected: []string{p, t20iProtected(upper + "_R")}, permitted: []string{k}}
}

func t20iJSONExchange(name string) t20iCase {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	p, k := t20iProtected(upper), t20iPermitted(upper)
	return t20iCase{name: name,
		pieces:    []string{t20iRequest("POST", "/t20i/"+name, t20iJSON, `{"card":{"number":"`+p+`"},"keep":"`+k+`"}`)},
		protected: []string{p}, permitted: []string{k}}
}

func t20iFormExchange(name string) t20iCase {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	p, k := t20iProtected(upper), t20iPermitted(upper)
	return t20iCase{name: name,
		pieces:    []string{t20iRequest("POST", "/t20i/"+name, t20iWith(t20iForm, "X-T20i-Keep", k), "card_number="+p+"&note=1")},
		protected: []string{p}, permitted: []string{k}}
}

func t20iQueryExchange(name string) t20iCase {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	p, k := t20iProtected(upper), t20iPermitted(upper)
	return t20iCase{name: name,
		pieces:    []string{t20iRequest("GET", "/t20i/"+name+"?card_number="+p, []t20iHeader{{"X-T20i-Keep", k}}, "")},
		protected: []string{p}, permitted: []string{k}}
}

// The refusals contract 52 and CONFIG.md name for body and query fields,
// each beside the neighbour that activates and writes.
func TestT20iEachRefusalBesideANeighbourThatActivatesAndWrites(t *testing.T) {
	both := t20iMessages("request", "response")
	removeBoth := t20iSlot("body", config.RemoveBody, both)
	bodyRequirement := []cp.Requirement{t20iRequirement("t20i-body", config.BodyField)}
	jsonRequirement := []cp.Requirement{t20iRequirement("t20i-json", config.JSONFieldPrefix+"/card/number")}
	queryRequirement := []cp.Requirement{t20iRequirement("t20i-query-card", config.QueryFieldPrefix+"card_number")}
	formRequirement := []cp.Requirement{t20iRequirement("t20i-form-card", config.FormFieldPrefix+"card_number")}
	jsonFields := func(messages []string, pointers ...string) map[string]any {
		return t20iSlot("json", config.RemoveJSONFields, map[string]any{"messages": messages, "pointers": pointers})
	}
	formFields := func(names ...string) map[string]any {
		return t20iSlot("form", config.RemoveFormFields, map[string]any{"names": names})
	}
	queryParameters := func(names ...string) map[string]any {
		return t20iSlot("params", config.RemoveQueryParameters, map[string]any{"names": names})
	}
	replace := t20iSlot("replace", config.ReplaceJSONValues, map[string]any{"messages": []string{"request", "response"},
		"pointers": []string{"/card/number"}, "value": "withheld"})
	routeNamed := func(requirement string, uncovered ...string) []string {
		return append([]string{"route:t20i->account", requirement}, uncovered...)
	}
	markPack := func(implementation string, configuration map[string]any) map[string]map[string]any {
		pack := t20iPack("t20i-grammar")
		pack["replacements"] = []any{map[string]any{"pipeline": "t20i", "slot": "mark", "implementation": implementation, "configuration": configuration}}
		return map[string]map[string]any{"t20i-grammar": pack}
	}
	mark := t20iSlot("mark", config.RemoveHeaders, map[string]any{"headers": []string{"x-t20i-drop"}})
	gp, gk := t20iProtected("GRAMMAR_PACK"), t20iPermitted("GRAMMAR_PACK")
	grammarPackExchange := t20iCase{name: "grammar-pack",
		pieces: []string{t20iRequest("POST", "/t20i/grammar-pack", t20iWith(t20iWith(t20iForm, "X-T20i-Drop", t20iProtected("GRAMMAR_DROP")), "X-T20i-Keep", gk),
			"card_number="+gp+"&note=1")},
		protected: []string{gp, t20iProtected("GRAMMAR_DROP")}, permitted: []string{gk}}
	vp, vk := t20iProtected("VALUES_SHARED"), t20iPermitted("VALUES_SHARED")
	valuesExchange := t20iCase{name: "values-shared",
		pieces:    []string{t20iRequest("POST", "/t20i/values-shared", t20iJSON, `{"`+vk+`":"`+vp+`"}`)},
		response:  t20iResponse{Type: "application/json", Body: []byte(`{"r":"` + t20iProtected("VALUES_SHARED_R") + `"}`)},
		protected: []string{vp, t20iProtected("VALUES_SHARED_R")}, permitted: []string{vk}}
	sp, sk := t20iProtected("JSON_SHARED"), t20iPermitted("JSON_SHARED")
	jsonSharedExchange := t20iCase{name: "json-shared",
		pieces:    []string{t20iRequest("POST", "/t20i/json-shared", t20iJSON, `{"card":{"number":"`+sp+`","holder":"`+sk+`"}}`)},
		response:  t20iResponse{Type: "application/json", Body: []byte(`{"card":{"number":"` + t20iProtected("JSON_SHARED_R") + `"}}`)},
		protected: []string{sp, t20iProtected("JSON_SHARED_R")}, permitted: []string{sk}}
	np, nk := t20iProtected("FORM_JSON_NAMED"), t20iPermitted("FORM_JSON_NAMED")
	jsonNamedExchange := t20iCase{name: "form-json-named",
		pieces:    []string{t20iRequest("POST", "/t20i/form-json-named", t20iWith(t20iForm, "X-T20i-Keep", nk), `{"&card_number=`+np+`":1}`)},
		protected: []string{np}, permitted: []string{nk}}
	packRoute := func(slots ...map[string]any) map[string]map[string]any {
		return map[string]map[string]any{"t20i-route": t20iPack("t20i-route", t20iPipeline("pack-route", []string{"other"}, slots...))}
	}
	stopping := t20iSlot("body", config.RemoveBody, both)
	stopping["on_failure"] = cp.StopPipeline

	refusals := []t20iRefusal{
		{name: "form-and-json-rules-in-one-pipeline",
			refused: t20iSetup{pipelines: t20iRoute(formFields("card_number"), jsonFields([]string{"request"}, "/card/number"))},
			reasons: []string{string(config.BodyGrammarConflict)},
			neighbour: t20iSetup{pipelines: []map[string]any{
				t20iPipeline("forms", []string{"account"}, formFields("card_number")),
				t20iPipeline("json", []string{"account"}, jsonFields([]string{"request"}, "/card/number"))}},
			pipelines: []string{"forms", "json"}, exchange: t20iFormExchange("grammar-json")},
		{name: "form-and-replace-rules-in-one-pipeline",
			refused: t20iSetup{pipelines: t20iRoute(formFields("card_number"), replace)},
			reasons: []string{string(config.BodyGrammarConflict)},
			neighbour: t20iSetup{pipelines: []map[string]any{
				t20iPipeline("forms", []string{"account"}, formFields("card_number")),
				t20iPipeline("replace", []string{"account"}, replace)}},
			pipelines: []string{"forms", "replace"}, exchange: t20iFormExchange("grammar-replace")},
		// The conflict is over the EFFECTIVE slots: a pack replacing one.
		{name: "a-pack-replacement-brings-a-json-rule-beside-a-form-rule",
			refused: t20iSetup{pipelines: t20iRoute(formFields("card_number"), mark),
				packs: markPack(config.RemoveJSONFields, map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number"}})},
			reasons: []string{string(config.BodyGrammarConflict)},
			neighbour: t20iSetup{pipelines: t20iRoute(formFields("card_number"), mark),
				packs: markPack(config.ReplaceHeaderValues, map[string]any{"headers": []string{"x-t20i-drop"}, "value": "replaced"})},
			exchange: grammarPackExchange},
		{name: "reduce-does-not-satisfy-the-body",
			refused: t20iSetup{pipelines: t20iRoute(t20iSlot("reduce", config.ReduceBodyToStructure, both)), requirements: bodyRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-body"),
			neighbour: t20iSetup{pipelines: t20iRoute(removeBoth), requirements: bodyRequirement}, exchange: t20iBodyExchange("body-by-reduce")},
		{name: "request-only-removal-does-not-satisfy-the-body",
			refused: t20iSetup{pipelines: t20iRoute(t20iSlot("body", config.RemoveBody, t20iMessages("request"))), requirements: bodyRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-body", "response"),
			neighbour: t20iSetup{pipelines: t20iRoute(removeBoth), requirements: bodyRequirement}, exchange: t20iBodyExchange("body-one-side")},
		// Slots share the work: reduce on the request, remove-body on the
		// response.
		{name: "request-only-reduction-does-not-satisfy-the-values",
			refused: t20iSetup{pipelines: t20iRoute(t20iSlot("reduce", config.ReduceBodyToStructure, t20iMessages("request"))),
				requirements: []cp.Requirement{t20iRequirement("t20i-values", config.BodyValuesField)}},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-values", "response"),
			neighbour: t20iSetup{pipelines: t20iRoute(t20iSlot("reduce", config.ReduceBodyToStructure, t20iMessages("request")),
				t20iSlot("body", config.RemoveBody, t20iMessages("response"))),
				requirements: []cp.Requirement{t20iRequirement("t20i-values", config.BodyValuesField)}},
			exchange: valuesExchange},
		{name: "replacement-does-not-satisfy-a-json-field",
			refused: t20iSetup{pipelines: t20iRoute(replace), requirements: jsonRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-json"),
			neighbour: t20iSetup{pipelines: t20iRoute(jsonFields([]string{"request", "response"}, "/card/number")), requirements: jsonRequirement},
			exchange:  t20iJSONExchange("json-by-replace")},
		// A pointer satisfies a JSON field when its tokens are the first
		// tokens of the field's: a longer one does not, a shorter one does.
		{name: "a-longer-pointer-does-not-satisfy-a-json-field",
			refused: t20iSetup{pipelines: t20iRoute(jsonFields([]string{"request", "response"}, "/card/number/x")), requirements: jsonRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-json"),
			neighbour: t20iSetup{pipelines: t20iRoute(jsonFields([]string{"request", "response"}, "/card")), requirements: jsonRequirement},
			exchange:  t20iJSONExchange("json-prefix")},
		{name: "request-only-json-removal-does-not-satisfy-a-json-field",
			refused: t20iSetup{pipelines: t20iRoute(jsonFields([]string{"request"}, "/card/number")), requirements: jsonRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-json", "response"),
			neighbour: t20iSetup{pipelines: t20iRoute(jsonFields([]string{"request"}, "/card/number"),
				t20iSlot("body", config.RemoveBody, t20iMessages("response"))), requirements: jsonRequirement},
			exchange: jsonSharedExchange},
		{name: "another-query-name-does-not-satisfy-a-query-field",
			refused: t20iSetup{pipelines: t20iRoute(queryParameters("other_name")), requirements: queryRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-query-card"),
			neighbour: t20iSetup{pipelines: t20iRoute(queryParameters("card_number")), requirements: queryRequirement},
			exchange:  t20iQueryExchange("query-other-name")},
		{name: "remove-query-satisfies-a-query-field",
			refused:   t20iSetup{pipelines: t20iRoute(queryParameters("other_name")), requirements: queryRequirement},
			reasons:   []string{string(config.ExclusionNotEnforced)},
			neighbour: t20iSetup{pipelines: t20iRoute(t20iSlot("query", config.RemoveQuery, map[string]any{})), requirements: queryRequirement},
			exchange:  t20iQueryExchange("query-whole")},
		{name: "another-form-name-does-not-satisfy-a-form-field",
			refused: t20iSetup{pipelines: t20iRoute(formFields("other_name")), requirements: formRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-form-card"),
			neighbour: t20iSetup{pipelines: t20iRoute(formFields("card_number")), requirements: formRequirement},
			exchange:  t20iFormExchange("form-other-name")},
		{name: "request-body-removal-satisfies-a-form-field",
			refused: t20iSetup{pipelines: t20iRoute(t20iSlot("body", config.RemoveBody, t20iMessages("response"))), requirements: formRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-form-card"),
			neighbour: t20iSetup{pipelines: t20iRoute(t20iSlot("body", config.RemoveBody, t20iMessages("request"))), requirements: formRequirement},
			exchange:  t20iFormExchange("form-by-body")},
		// Contract 52 revision 25: structure keeps member names, and a member
		// name can carry a value PHP files as a form field.
		{name: "reduce-does-not-satisfy-a-form-field",
			refused: t20iSetup{pipelines: t20iRoute(t20iSlot("reduce", config.ReduceBodyToStructure, t20iMessages("request"))), requirements: formRequirement},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-form-card"),
			neighbour: t20iSetup{pipelines: t20iRoute(formFields("card_number")), requirements: formRequirement},
			exchange:  jsonNamedExchange},
		{name: "parameter-removal-does-not-satisfy-the-query",
			refused: t20iSetup{pipelines: t20iRoute(queryParameters("card_number")),
				requirements: []cp.Requirement{t20iRequirement("t20i-query", config.TargetQueryField)}},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: routeNamed("t20i-query"),
			neighbour: t20iSetup{pipelines: t20iRoute(t20iSlot("query", config.RemoveQuery, map[string]any{})),
				requirements: []cp.Requirement{t20iRequirement("t20i-query", config.TargetQueryField)}},
			exchange: t20iQueryExchange("query-by-parameters")},
		{name: "a-pack-route-to-another-sink-must-remove-too",
			refused: t20iSetup{pipelines: t20iRoute(removeBoth), requirements: bodyRequirement, sinks: []string{"other"}, packs: packRoute()},
			reasons: []string{string(config.ExclusionNotEnforced)}, mention: []string{"pack-route", "t20i-body"},
			neighbour: t20iSetup{pipelines: t20iRoute(removeBoth), requirements: bodyRequirement, sinks: []string{"other"}, packs: packRoute(removeBoth)},
			pipelines: []string{"t20i", "pack-route"}, exchange: t20iBodyExchange("body-pack-route")},
		{name: "a-removal-slot-must-fail-as-the-requirement-does",
			refused: t20iSetup{pipelines: t20iRoute(stopping), requirements: bodyRequirement},
			reasons: []string{string(config.ExclusionFailureActionMismatch)}, mention: []string{"t20i-body"},
			neighbour: t20iSetup{pipelines: t20iRoute(removeBoth), requirements: bodyRequirement}, exchange: t20iBodyExchange("body-failure-action")},
	}
	// Field forms outside the grammar. The neighbour of each is message.body
	// over the same route. An unknown field and a transformation other than
	// remove are unsupported_transform and an undefined parameter is
	// invalid_transform_parameters, as for headers; for a malformed name or
	// pointer inside a known form CONFIG.md names the two reasons together,
	// so either is accepted.
	requirementWith := func(field, transformation string, extra map[string]any) []cp.Requirement {
		r := t20iRequirement("t20i-field", field)
		r.Parameters["transformation"] = transformation
		for key, value := range extra {
			r.Parameters[key] = value
		}
		return []cp.Requirement{r}
	}
	fieldNeighbour := t20iSetup{pipelines: t20iRoute(removeBoth), requirements: []cp.Requirement{t20iRequirement("t20i-field", config.BodyField)}}
	for i, one := range []struct {
		field, transformation string
		extra                 map[string]any
		reason                config.Reason
	}{
		{"message.bodyx", "remove", nil, config.UnsupportedTransform},
		{config.BodyField, "replace", nil, config.UnsupportedTransform},
		{config.BodyField, "remove", map[string]any{"unknown": 1}, config.InvalidTransformParameters},
		{config.QueryFieldPrefix, "remove", nil, ""},
		{config.FormFieldPrefix + "card number", "remove", nil, ""},
		{config.JSONFieldPrefix, "remove", nil, ""},
		{config.JSONFieldPrefix + "card/number", "remove", nil, ""},
		{config.JSONFieldPrefix + "/a~2b", "remove", nil, ""},
	} {
		r := t20iRefusal{name: fmt.Sprintf("field-form-%d", i+1),
			refused:   t20iSetup{pipelines: t20iRoute(removeBoth), requirements: requirementWith(one.field, one.transformation, one.extra)},
			neighbour: fieldNeighbour, exchange: t20iBodyExchange(fmt.Sprintf("field-form-%d", i+1))}
		if one.reason != "" {
			r.reasons = []string{string(one.reason)}
		} else {
			r.anyOf = []string{string(config.UnsupportedTransform), string(config.InvalidTransformParameters)}
		}
		refusals = append(refusals, r)
	}
	t20iRefusals(t, refusals)
}

// The argument rules CONFIG.md states for each body and query operation. Per
// operation, one neighbour activates and writes, and every configuration one
// rule away from it is refused as invalid_builtin_arguments.
func TestT20iArgumentsOutsideTheRulesAreRefusedBesideOnesThatActivate(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	many := func(n int, form func(int) string) []string {
		var list []string
		for i := range n {
			list = append(list, form(i))
		}
		return list
	}
	pointers := func(list ...string) map[string]any {
		if list == nil {
			list = []string{}
		}
		return map[string]any{"messages": []string{"request"}, "pointers": list}
	}
	names := func(list ...string) map[string]any {
		if list == nil {
			list = []string{}
		}
		return map[string]any{"names": list}
	}
	deepPointer := strings.Repeat("/a", config.MaxPointerTokens+1)
	for _, operation := range []struct {
		implementation string
		valid          map[string]any
		exchange       t20iCase
		refused        []any
	}{
		{config.RemoveBody, t20iMessages("request", "response"), t20iBodyExchange("arguments-remove-body"), []any{
			map[string]any{}, t20iMessages(), t20iMessages("both"), t20iMessages("request", "request"),
			map[string]any{"messages": []string{"request"}, "pointers": []string{"/a"}},
			map[string]any{"Messages": []string{"request"}}, nil}},
		{config.ReduceBodyToStructure, t20iMessages("request", "response"), t20iBodyExchange("arguments-reduce"), []any{
			t20iMessages(), map[string]any{"messages": "request"}}},
		{config.RemoveQuery, map[string]any{}, t20iQueryExchange("arguments-remove-query"), []any{
			t20iMessages("request"), nil}},
		{config.RemoveJSONFields, pointers("/card/number", "/card"), t20iJSONExchange("arguments-json"), []any{
			pointers(), pointers(""), pointers("card"), pointers("/a~2b"), pointers("/a~"), pointers("/a", "/a"),
			pointers(many(config.MaxFieldSelectors+1, func(i int) string { return fmt.Sprintf("/p%d", i) })...),
			pointers("/" + long(config.MaxPointerBytes)), pointers(deepPointer),
			map[string]any{"pointers": []string{"/card/number"}}}},
		{config.ReplaceJSONValues, map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number"}, "value": "withheld"},
			t20iJSONExchange("arguments-replace"), []any{
				map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number"}},
				map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number"}, "value": "tab\there"},
				map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number"}, "value": "caf\u00e9"},
				map[string]any{"messages": []string{"request"}, "pointers": []string{"/card/number"}, "value": long(config.MaxJSONValueBytes + 1)}}},
		{config.RemoveFormFields, names("card_number"), t20iFormExchange("arguments-form"), []any{
			names(), names(""), names("card number"),
			names(long(config.MaxParameterNameBytes + 1)), names("card_number", "card_number"),
			names(many(config.MaxFieldSelectors+1, func(i int) string { return fmt.Sprintf("n%d", i) })...)}},
		{config.RemoveQueryParameters, names("card_number"), t20iQueryExchange("arguments-query"), []any{
			names()}},
	} {
		t.Run(operation.implementation, func(t *testing.T) {
			var refusals []t20iRefusal
			neighbour := t20iSetup{pipelines: t20iRoute(t20iSlot("op", operation.implementation, operation.valid))}
			for i, configuration := range operation.refused {
				refusals = append(refusals, t20iRefusal{name: fmt.Sprintf("rule-%d", i+1),
					refused:   t20iSetup{pipelines: t20iRoute(t20iSlot("op", operation.implementation, configuration))},
					reasons:   []string{string(config.InvalidBuiltinArguments)},
					neighbour: neighbour, exchange: operation.exchange})
			}
			t20iArgumentRefusals(t, refusals)
		})
	}
}

// t20iArgumentRefusals runs one neighbour and then every refusal beside it.
func t20iArgumentRefusals(t *testing.T, refusals []t20iRefusal) {
	t.Helper()
	t.Run("neighbour", func(t *testing.T) {
		cases := []t20iCase{refusals[0].exchange}
		t20iAssert(t, t20iRun(t, refusals[0].neighbour, cases), []string{"t20i"}, cases)
	})
	binary := built(t)
	client := speaking(t, serving(t))
	targets := []map[string]any{target("t20i", client.process)}
	for _, r := range refusals {
		t.Run(r.name, func(t *testing.T) {
			t20iRefused(t, binary, targets, r.refused, r.reasons...)
		})
	}
}
