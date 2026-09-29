package config_test

import (
	"encoding/json"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// A configured parameter name is any printable ASCII byte except space. A name
// carrying . [ ] ; & = % or + is accepted, since it is compared literally with
// the decoded name as sent; a space, a control byte or a non-ASCII byte is
// refused.
func TestT24ParameterNameGrammar(t *testing.T) {
	for _, implementation := range []string{config.RemoveFormFields, config.RemoveQueryParameters} {
		t.Run(implementation, func(t *testing.T) {
			c := processingConfiguration(t)
			c.Pipelines[0].Slots = []config.Slot{headerSlot("rule", implementation, `{"names":["card.number","items[]","a;b","a&b=c","100%","x+y","!~"]}`)}
			plan := acceptedProcessing(t, c)
			if got := plan.Pipelines()[0].Slots[0].Arguments.Names; len(got) != 7 || got[0] != "card.number" || got[1] != "items[]" {
				t.Fatalf("PROPERTY: the names did not resolve as written: %q", got)
			}
			for _, refused := range []string{`{"names":["card number"]}`, `{"names":[" card"]}`, `{"names":["né"]}`, `{"names":["a\tb"]}`, `{"names":["a\u007fb"]}`} {
				c.Pipelines[0].Slots[0].Configuration = json.RawMessage(refused)
				refusedProcessing(t, c, config.InvalidBuiltinArguments)
			}
		})
	}
	t.Run("exclusion-fields", func(t *testing.T) {
		for _, field := range []string{config.FormFieldPrefix + "card.number", config.QueryFieldPrefix + "items[]"} {
			parsed, err := config.ParseExclusionField(field)
			if err != nil {
				t.Fatalf("PROPERTY: %s is refused: %v", field, err)
			}
			if want := field[len(parsed.Kind):]; parsed.Name != want {
				t.Fatalf("PROPERTY: %s names %q, want everything after the prefix, %q", field, parsed.Name, want)
			}
		}
		if _, err := config.ParseExclusionField(config.FormFieldPrefix + "card number"); err == nil {
			t.Fatal("PROPERTY: a form field name with a space is accepted")
		}
	})
}
