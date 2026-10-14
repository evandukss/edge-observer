package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// A parameter is removed when its percent-decoded name equals a configured
// name exactly, and only then. Parameters are separated by & alone.
func TestParameterNamesMatchExactlyAsSent(t *testing.T) {
	const kept = "card.number=NAMKEEP1&card_number%5B%5D=NAMKEEP2&%20card_number=NAMKEEP3&Card_Number=NAMKEEP4&note=" + fieldOther
	for _, tc := range []struct {
		name, implementation, text, want string
		survivors                        []string
	}{
		{"query", config.RemoveQueryParameters, "card_number=" + fieldCard + "&" + kept, kept,
			[]string{"NAMKEEP1", "NAMKEEP2", "NAMKEEP3", "NAMKEEP4", fieldOther}},
		{"form", config.RemoveFormFields, "card_number=" + fieldCard + "&" + kept, kept,
			[]string{"NAMKEEP1", "NAMKEEP2", "NAMKEEP3", "NAMKEEP4", fieldOther}},
		{"encoded-exact-name", config.RemoveQueryParameters, "card%5Fnumber=" + fieldCard + "&note=" + fieldOther, "note=" + fieldOther,
			[]string{fieldOther}},
		// ; is an ordinary byte: here card_number is inside the value of note.
		{"semicolon-is-not-a-separator", config.RemoveQueryParameters, "note=" + fieldOther + ";card_number=NAMKEEP5&x=1", "note=" + fieldOther + ";card_number=NAMKEEP5&x=1",
			[]string{fieldOther, "NAMKEEP5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := fieldPlan(t, tc.implementation, `{"names":["card_number"]}`)
			var got string
			var a processing.Artifact
			var text string
			if tc.implementation == config.RemoveFormFields {
				a, _, text = fieldExchange(t, plan, fieldPost("/pay", "application/x-www-form-urlencoded", tc.text), goodResponse)
				got = fieldBody(t, a, "request")
			} else {
				a, _, text = fieldExchange(t, plan, fieldGet("/pay?"+tc.text), goodResponse)
				got = a.Reconstruction.Exchanges[0].Request.Message.Target
				tc.want = "/pay?" + tc.want
			}
			fieldAbsent(t, text, fieldCard)
			for _, survivor := range tc.survivors {
				fieldKept(t, text, survivor)
			}
			if got != tc.want {
				t.Fatalf("PROPERTY: a name other than card_number was removed, or other bytes changed\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// A malformed percent escape in any name or value leaves the part undecidable,
// so the whole query or body goes; a well-formed escape beside the same rule
// is the control that the rule is otherwise live.
func TestMalformedEscapeRemovesTheWholePart(t *testing.T) {
	query := fieldPlan(t, config.RemoveQueryParameters, `{"names":["card_number"]}`)
	form := fieldPlan(t, config.RemoveFormFields, `{"names":["card_number"]}`)

	t.Run("query-control", func(t *testing.T) {
		a, _, text := fieldExchange(t, query, fieldGet("/pay?note=%41&card_number="+fieldCard), goodResponse)
		fieldAbsent(t, text, fieldCard)
		if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay?note=%41" {
			t.Fatalf("PROPERTY: a well-formed escape changed what was removed: %q", got)
		}
	})
	for _, target := range []string{
		"/pay?card_number=" + fieldCard + "&note=%ZZ" + fieldOther,
		"/pay?no%t" + fieldOther + "=1&card_number=" + fieldCard,
		"/pay?note=" + fieldOther + "%",
		// fieldOther begins with a letter that is not a hex digit, so "%4" before it
		// is a malformed escape.
		"/pay?note=%4" + fieldOther,
	} {
		t.Run("query:"+target, func(t *testing.T) {
			a, _, text := fieldExchange(t, query, fieldGet(target), goodResponse)
			fieldAbsent(t, text, fieldCard)
			fieldAbsent(t, text, fieldOther)
			if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay" {
				t.Fatalf("PROPERTY: a query with a malformed escape was not removed whole: %q", got)
			}
			entries := fieldEvidence(a, "request", config.TargetQueryField)
			if len(entries) != 1 || entries[0].Disposition != processing.DispositionRemovedUndecidable {
				t.Fatalf("PROPERTY: the whole-query removal is not evidenced as undecidable: %+v", a.PolicyExclusions)
			}
		})
	}

	t.Run("form-control", func(t *testing.T) {
		a, _, text := fieldExchange(t, form, fieldPost("/pay", "application/x-www-form-urlencoded", "note=%41&card_number="+fieldCard), goodResponse)
		fieldAbsent(t, text, fieldCard)
		if got := fieldBody(t, a, "request"); got != "note=%41" {
			t.Fatalf("PROPERTY: a well-formed escape changed what was removed: %q", got)
		}
	})
	t.Run("form", func(t *testing.T) {
		a, _, text := fieldExchange(t, form, fieldPost("/pay", "application/x-www-form-urlencoded", "note=%G1"+fieldOther+"&card_number="+fieldCard), goodResponse)
		fieldAbsent(t, text, fieldCard)
		fieldAbsent(t, text, fieldOther)
		fieldRemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
	})
}

// A configured name carrying . or [] removes exactly that parameter: the
// literal name, not another the application might read as the same.
func TestNamesWithDotsAndBracketsMatchLiterally(t *testing.T) {
	plan := fieldPlan(t, config.RemoveQueryParameters, `{"names":["card.number","items[]"]}`)
	a, _, text := fieldExchange(t, plan,
		fieldGet("/pay?card.number="+fieldCard+"&card_number=NAMKEEP6&items%5B%5D=4000000000000002&items=NAMKEEP7&note="+fieldOther), goodResponse)
	fieldAbsent(t, text, fieldCard)
	fieldAbsent(t, text, "4000000000000002")
	for _, survivor := range []string{"NAMKEEP6", "NAMKEEP7", fieldOther} {
		fieldKept(t, text, survivor)
	}
	if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay?card_number=NAMKEEP6&items=NAMKEEP7&note="+fieldOther {
		t.Fatalf("PROPERTY: the literal names were not the only ones removed: %q", got)
	}
}
