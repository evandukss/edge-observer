package processing_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// fieldEvidence returns the entries naming one field on one message.
func fieldEvidence(a processing.Artifact, message, field string) []processing.PolicyExclusion {
	var out []processing.PolicyExclusion
	for _, e := range a.PolicyExclusions {
		if e.Message == message && e.Field == field {
			out = append(out, e)
		}
	}
	return out
}

// fieldRemovedWhole asserts a message's body left whole: no byte kept, the
// structure removed, and one message.body entry with the disposition given.
func fieldRemovedWhole(t *testing.T, a processing.Artifact, message, disposition string) {
	t.Helper()
	e := a.Reconstruction.Exchanges[0]
	m := e.Request.Message
	if message == "response" {
		m = e.Response.Message
	}
	if m.Body.Kept != "" || m.Structure.State != record.StructureRemoved || m.Body.Length == "0" {
		t.Fatalf("PROPERTY: the %s body was not removed whole: kept=%q length=%s structure=%s", message, m.Body.Kept, m.Body.Length, m.Structure.State)
	}
	entries := fieldEvidence(a, message, config.BodyField)
	if len(entries) != 1 || entries[0].Disposition != disposition {
		t.Fatalf("PROPERTY: the %s body's removal is not evidenced as %s: %+v", message, disposition, a.PolicyExclusions)
	}
}

func TestUncertaintyRemovesMore(t *testing.T) {
	jsonRule := fieldOf(config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card"]}`)
	valid := `{"other":"` + fieldOther + `","card":"` + fieldCard + `"}`
	deep := strings.Repeat(`{"a":`, config.MaxJSONFieldDepth) + `"` + fieldCard + `"` + strings.Repeat("}", config.MaxJSONFieldDepth)
	for _, tc := range []struct {
		name, body string
	}{
		{"invalid-json-trailing-comma", `{"other":"` + fieldOther + `","card":"` + fieldCard + `",}`},
		{"byte-order-mark", "\xef\xbb\xbf" + valid},
		{"invalid-utf8", `{"other":"` + fieldOther + "\xff" + `","card":"` + fieldCard + `"}`},
		{"unpaired-surrogate", `{"other":"\ud800","card":"` + fieldCard + `"}`},
		{"deeper-than-bound", deep},
		{"two-values", valid + valid},
		{"form-body-under-json-rule", "other=" + fieldOther + "&card=" + fieldCard},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The success control: the same rule on a valid body removes the
			// member and keeps its neighbour, so the rule is live.
			a, _, text := fieldExchange(t, fieldPlan(t, jsonRule.implementation, jsonRule.arguments), fieldPost("/pay", "application/json", valid), goodResponse)
			fieldAbsent(t, text, fieldCard)
			fieldKept(t, text, fieldOther)
			if entries := fieldEvidence(a, "request", config.JSONFieldPrefix+"/card"); len(entries) != 1 || entries[0].Disposition != processing.DispositionRemoved {
				t.Fatalf("PROPERTY: the control's member removal is not evidenced: %+v", a.PolicyExclusions)
			}

			a, _, text = fieldExchange(t, fieldPlan(t, jsonRule.implementation, jsonRule.arguments), fieldPost("/pay", "application/json", tc.body), goodResponse)
			fieldAbsent(t, text, fieldCard)
			fieldRemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
		})
	}

	// A depth exactly at the bound is still read, which is what makes the
	// case above a bound and not a refusal of nesting.
	t.Run("depth-at-bound-is-read", func(t *testing.T) {
		// Wrappers at depths 1 to MaxJSONFieldDepth-2, the inner object one
		// deeper, and its string values at exactly MaxJSONFieldDepth.
		atBound := strings.Repeat(`{"a":`, config.MaxJSONFieldDepth-2) + `{"card":"` + fieldCard + `","other":"` + fieldOther + `"}` + strings.Repeat("}", config.MaxJSONFieldDepth-2)
		pointer := strings.Repeat("/a", config.MaxJSONFieldDepth-2) + "/card"
		rule := fieldOf(config.RemoveJSONFields, `{"messages":["request"],"pointers":["`+pointer+`"]}`)
		a, _, text := fieldExchange(t, fieldPlan(t, rule.implementation, rule.arguments), fieldPost("/pay", "application/json", atBound), goodResponse)
		fieldAbsent(t, text, fieldCard)
		fieldKept(t, text, fieldOther)
		if len(fieldEvidence(a, "request", config.BodyField)) != 0 {
			t.Fatalf("PROPERTY: a body at the depth bound was removed whole: %+v", a.PolicyExclusions)
		}
	})
}

func TestFormAdmissionIsPositive(t *testing.T) {
	form := fieldOf(config.RemoveFormFields, `{"names":["card_number"]}`)
	body := "other=" + fieldOther + "&card_number=" + fieldCard
	multipart := "--XB\r\nContent-Disposition: form-data; name=\"card_number\"\r\n\r\n" + fieldCard + "\r\n--XB--\r\n"

	t.Run("urlencoded-admitted", func(t *testing.T) {
		a, _, text := fieldExchange(t, fieldPlan(t, form.implementation, form.arguments), fieldPost("/pay", "Application/X-WWW-Form-Urlencoded ; charset=UTF-8", body), goodResponse)
		fieldAbsent(t, text, fieldCard)
		fieldKept(t, text, fieldOther)
		if entries := fieldEvidence(a, "request", config.FormFieldPrefix+"card_number"); len(entries) != 1 || entries[0].Disposition != processing.DispositionRemoved {
			t.Fatalf("PROPERTY: the form field removal is not evidenced: %+v", a.PolicyExclusions)
		}
	})
	for _, tc := range []struct{ name, request string }{
		{"multipart", fieldPost("/pay", "multipart/form-data; boundary=XB", multipart)},
		{"no-content-type", "POST /pay HTTP/1.1\r\nX-Keep: " + fieldKeep + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body},
		{"two-content-types", "POST /pay HTTP/1.1\r\nX-Keep: " + fieldKeep + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body},
		{"json-labelled", fieldPost("/pay", "application/json", `{"card_number":"`+fieldCard+`"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, text := fieldExchange(t, fieldPlan(t, form.implementation, form.arguments), tc.request, goodResponse)
			fieldAbsent(t, text, fieldCard)
			fieldRemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
		})
	}

	// Body rules read Content-Type as parsed: a header removed before the form
	// rule does not make the body admissible.
	t.Run("removed-content-type-does-not-admit", func(t *testing.T) {
		plan := rulesPlan(t, `"remove": {"headers": ["content-type"], "form": ["card_number"]}`)
		var order []string
		for _, p := range plan.Pipelines() {
			if p.Name == config.ExchangesPipeline {
				for _, slot := range p.Slots {
					order = append(order, slot.Implementation)
				}
			}
		}
		if !slices.Equal(order, []string{config.RemoveHeaders, config.RemoveFormFields}) {
			t.Fatalf("wiring, not the property: the plan runs %v, so the header is not removed before the form rule reads it", order)
		}
		a, _, text := fieldExchange(t, plan, fieldPost("/pay", "multipart/form-data; boundary=XB", multipart), goodResponse)
		fieldAbsent(t, text, fieldCard)
		fieldRemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
	})
}
