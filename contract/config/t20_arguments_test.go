package config_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// Each argument rule CONFIG.md states is refused here beside a neighbour that
// the same operation accepts, so a refusal cannot come from anything else.
func TestT20ArgumentRules(t *testing.T) {
	long := func(n int, b string) string { return strings.Repeat(b, n) }
	tokens := func(n int) string { return strings.Repeat("/a", n) }
	pointers := func(n int) string {
		var list []string
		for i := 0; i < n; i++ {
			list = append(list, `"/p`+strings.Repeat("x", i)+`"`)
		}
		return strings.Join(list, ",")
	}
	for _, tc := range []struct {
		implementation, accepted string
		refused                  []string
	}{
		{config.RemoveBody, `{"messages":["response","request"]}`, []string{
			`{}`, `null`, `[]`, `{"messages":[]}`, `{"messages":["request","request"]}`, `{"messages":["body"]}`,
			`{"messages":"request"}`, `{"messages":["request"],"headers":["x"]}`, `{"Messages":["request"]}`,
		}},
		{config.ReduceBodyToStructure, `{"messages":["request"]}`, []string{`{"messages":["Request"]}`}},
		{config.RemoveQuery, `{}`, []string{`null`, `{"names":["a"]}`, `{"messages":["request"]}`}},
		{config.RemoveJSONFields, `{"messages":["request"],"pointers":["/a~0b/~1c/*/0","` + tokens(config.MaxPointerTokens) + `","/` + long(config.MaxPointerBytes-1, "x") + `"]}`, []string{
			`{"messages":["request"]}`, `{"pointers":["/a"]}`, `{"messages":["request"],"pointers":[]}`,
			`{"messages":["request"],"pointers":[""]}`, `{"messages":["request"],"pointers":["card"]}`,
			`{"messages":["request"],"pointers":["/a~2"]}`, `{"messages":["request"],"pointers":["/a~"]}`,
			`{"messages":["request"],"pointers":["` + tokens(config.MaxPointerTokens+1) + `"]}`,
			`{"messages":["request"],"pointers":["/` + long(config.MaxPointerBytes, "x") + `"]}`,
			`{"messages":["request"],"pointers":["/a","/a"]}`,
			`{"messages":["request"],"pointers":[` + pointers(config.MaxFieldSelectors+1) + `]}`,
			`{"messages":["request"],"pointers":["/a"],"value":"x"}`,
		}},
		{config.ReplaceJSONValues, `{"messages":["request"],"pointers":["/a"],"value":""}`, []string{
			`{"messages":["request"],"pointers":["/a"]}`, `{"messages":["request"],"pointers":["/a"],"value":null}`,
			`{"messages":["request"],"pointers":["/a"],"value":1}`, `{"messages":["request"],"pointers":["/a"],"value":"a\nb"}`,
			`{"messages":["request"],"pointers":["/a"],"value":"` + long(config.MaxJSONValueBytes+1, "x") + `"}`,
		}},
		{config.RemoveFormFields, `{"names":["Card_Number-1!","` + long(config.MaxParameterNameBytes, "n") + `"]}`, []string{
			`{}`, `{"names":[]}`, `{"names":[""]}`, `{"names":["card number"]}`,
			`{"names":["n\u00e9"]}`, `{"names":["a\tb"]}`,
			`{"names":["` + long(config.MaxParameterNameBytes+1, "n") + `"]}`, `{"names":["a","a"]}`,
			`{"names":["a"],"messages":["request"]}`,
		}},
		{config.RemoveQueryParameters, `{"names":["card_number","CARD_NUMBER"]}`, []string{`{"names":"card"}`}},
	} {
		t.Run(tc.implementation, func(t *testing.T) {
			if arguments, err := config.CompileArguments(tc.implementation, json.RawMessage(tc.accepted)); err != nil || arguments == nil {
				t.Fatalf("PROPERTY: the accepted arguments compiled to %+v, %v", arguments, err)
			}
			for _, refused := range tc.refused {
				if _, err := config.CompileArguments(tc.implementation, json.RawMessage(refused)); err == nil {
					t.Errorf("PROPERTY: %s accepted %s", tc.implementation, refused)
				}
			}
		})
	}
}

// compiled is the plan a configuration writing these rules compiles to.
func compiled(t *testing.T, rules string) *config.ProcessingPlan {
	t.Helper()
	c, findings := config.Compile([]byte(`{"version": "observer.config/1", "output": "/var/lib/observer", `+
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}], `+rules+`}`), "")
	if len(findings) > 0 {
		t.Fatalf("wiring, not the property: the rules were refused: %+v", findings)
	}
	return c.Plan
}

func TestT20ArgumentsResolve(t *testing.T) {
	rules := `"remove": {"query": ["b", "a"], "bodies": ["response", "request"]}, ` +
		`"mask": {"json": {"response": {"/b": "v", "/a": "v"}}}`
	slots := compiled(t, rules).Pipelines()[0].Slots
	if len(slots) != 3 {
		t.Fatalf("wiring, not the property: the rules compiled to %d operations, want 3", len(slots))
	}
	for i, want := range []config.Arguments{
		{Names: []string{"b", "a"}},
		{Messages: []string{"request", "response"}},
		{Messages: []string{"response"}, Pointers: []string{"/b", "/a"}, Value: "v"},
	} {
		if !reflect.DeepEqual(*slots[i].Arguments, want) {
			t.Fatalf("PROPERTY: slot %s resolved to %+v, want %+v", slots[i].Name, *slots[i].Arguments, want)
		}
	}
	// A view is detached: changing it changes no later view.
	slots[0].Arguments.Names[0] = "changed"
	slots[2].Arguments.Pointers[0] = "/changed"
	again := compiled(t, rules).Pipelines()[0].Slots
	if again[0].Arguments.Names[0] != "b" || again[2].Arguments.Pointers[0] != "/b" {
		t.Fatal("wiring, not the property: a fresh compile did not give fresh arguments")
	}
}

func TestT20ExclusionFieldForms(t *testing.T) {
	accepted := map[string]string{
		"message.body":                `"remove": {"bodies": ["request"]}`,
		"message.body.values":         `"remove": {"body_values": ["request"]}`,
		"message.target.query":        `"remove": {"query_string": true}`,
		"message.query.card_number":   `"remove": {"query": ["card_number"]}`,
		"message.form.card_number":    `"remove": {"form": ["card_number"]}`,
		"message.body.json/card/~1/*": `"remove": {"json": {"request": ["/card/~1/*"]}}`,
	}
	for field, rules := range accepted {
		t.Run(field, func(t *testing.T) {
			plan := compiled(t, rules)
			if len(plan.Exclusions()) != 1 || plan.Exclusions()[0].Field != field || plan.Exclusions()[0].Header != "" {
				t.Fatalf("PROPERTY: the exclusion did not resolve to its field: %+v", plan.Exclusions())
			}
		})
	}
	for _, field := range []string{
		"message.body.json", "message.body.jsoncard", "message.body.json/a~2", "message.query.",
		"message.target", "message.body.value", "message.headers.Authorization", "message.start_line",
	} {
		t.Run("refused:"+field, func(t *testing.T) {
			if _, err := config.ParseExclusionField(field); err == nil {
				t.Errorf("PROPERTY: %s is accepted as an exclusion field", field)
			}
		})
	}
}
