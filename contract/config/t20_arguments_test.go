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
		refused              []string
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
			`{}`, `{"names":[]}`, `{"names":[""]}`, `{"names":["card.number"]}`, `{"names":["card number"]}`,
			`{"names":["card[number]"]}`, `{"names":["card]"]}`, `{"names":["card+number"]}`, `{"names":["card%5B"]}`,
			`{"names":["a=b"]}`, `{"names":["a&b"]}`, `{"names":["a;b"]}`, `{"names":["né"]}`, `{"names":["a\tb"]}`,
			`{"names":["` + long(config.MaxParameterNameBytes+1, "n") + `"]}`, `{"names":["a","a"]}`,
			`{"names":["a"],"messages":["request"]}`,
		}},
		{config.RemoveQueryParameters, `{"names":["card_number","CARD_NUMBER"]}`, []string{`{"names":["card.number"]}`, `{"names":"card"}`}},
	} {
		t.Run(tc.implementation, func(t *testing.T) {
			c := processingConfiguration(t)
			c.Pipelines[0].Slots = []config.Slot{headerSlot("rule", tc.implementation, tc.accepted)}
			plan := acceptedProcessing(t, c)
			if plan.Pipelines()[0].Slots[0].Arguments == nil {
				t.Fatal("PROPERTY: an accepted slot carries no compiled arguments")
			}
			for _, refused := range tc.refused {
				c.Pipelines[0].Slots[0].Configuration = json.RawMessage(refused)
				refusedProcessing(t, c, config.InvalidBuiltinArguments)
			}
		})
	}
}

func TestT20ArgumentsResolve(t *testing.T) {
	c := processingConfiguration(t)
	c.Pipelines[0].Slots = []config.Slot{
		headerSlot("body", config.RemoveBody, `{"messages":["response","request"]}`),
		headerSlot("json", config.ReplaceJSONValues, `{"messages":["response"],"pointers":["/b","/a"],"value":"v"}`),
		headerSlot("query", config.RemoveQueryParameters, `{"names":["b","a"]}`),
	}
	slots := acceptedProcessing(t, c).Pipelines()[0].Slots
	for i, want := range []config.Arguments{
		{Messages: []string{"request", "response"}},
		{Messages: []string{"response"}, Pointers: []string{"/b", "/a"}, Value: "v"},
		{Names: []string{"b", "a"}},
	} {
		if !reflect.DeepEqual(*slots[i].Arguments, want) {
			t.Fatalf("PROPERTY: slot %s resolved to %+v, want %+v", slots[i].Name, *slots[i].Arguments, want)
		}
	}
	// A view is detached: changing it changes no later view.
	slots[1].Arguments.Pointers[0] = "/changed"
	slots[2].Arguments.Names[0] = "changed"
	again := acceptedProcessing(t, c).Pipelines()[0].Slots
	if again[1].Arguments.Pointers[0] != "/b" || again[2].Arguments.Names[0] != "b" {
		t.Fatal("wiring, not the property: a fresh compile did not give fresh arguments")
	}
}

func TestT20ExclusionFieldForms(t *testing.T) {
	accepted := map[string]config.Slot{
		"message.body":                headerSlot("r", config.RemoveBody, `{"messages":["request","response"]}`),
		"message.body.values":         headerSlot("r", config.ReduceBodyToStructure, `{"messages":["request","response"]}`),
		"message.target.query":        headerSlot("r", config.RemoveQuery, `{}`),
		"message.query.card_number":   headerSlot("r", config.RemoveQueryParameters, `{"names":["card_number"]}`),
		"message.form.card_number":    headerSlot("r", config.RemoveFormFields, `{"names":["card_number"]}`),
		"message.body.json/card/~1/*": headerSlot("r", config.RemoveJSONFields, `{"messages":["request","response"],"pointers":["/card"]}`),
	}
	for field, slot := range accepted {
		t.Run(field, func(t *testing.T) {
			c := processingConfiguration(t)
			c.Pipelines[0].Slots = []config.Slot{slot}
			c.Policy = []json.RawMessage{exclusionPolicy(t, field, "remove", nil)}
			plan := acceptedProcessing(t, c)
			if len(plan.Exclusions()) != 1 || plan.Exclusions()[0].Field != field || plan.Exclusions()[0].Header != "" {
				t.Fatalf("PROPERTY: the exclusion did not resolve to its field: %+v", plan.Exclusions())
			}
		})
	}
	for _, field := range []string{
		"message.body.json", "message.body.jsoncard", "message.body.json/a~2", "message.query.", "message.query.card.number",
		"message.form.card[number]", "message.target", "message.body.value", "message.headers.Authorization", "message.start_line",
	} {
		t.Run("refused:"+field, func(t *testing.T) {
			c := processingConfiguration(t)
			c.Pipelines[0].Slots = []config.Slot{headerSlot("r", config.RemoveBody, `{"messages":["request","response"]}`)}
			c.Policy = []json.RawMessage{exclusionPolicy(t, field, "remove", nil)}
			refusedProcessing(t, c, config.UnsupportedTransform)
		})
	}
}
