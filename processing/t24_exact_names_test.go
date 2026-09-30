package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// A parameter is removed when its percent-decoded name equals a configured
// name exactly, and only then. Parameters are separated by & alone.
func TestT24ParameterNamesMatchExactlyAsSent(t *testing.T) {
	const kept = "card.number=T24KEEP1&card_number%5B%5D=T24KEEP2&%20card_number=T24KEEP3&Card_Number=T24KEEP4&note=" + t20Other
	for _, tc := range []struct {
		name, implementation, text, want string
		survivors                        []string
	}{
		{"query", config.RemoveQueryParameters, "card_number=" + t20Card + "&" + kept, kept,
			[]string{"T24KEEP1", "T24KEEP2", "T24KEEP3", "T24KEEP4", t20Other}},
		{"form", config.RemoveFormFields, "card_number=" + t20Card + "&" + kept, kept,
			[]string{"T24KEEP1", "T24KEEP2", "T24KEEP3", "T24KEEP4", t20Other}},
		{"encoded-exact-name", config.RemoveQueryParameters, "card%5Fnumber=" + t20Card + "&note=" + t20Other, "note=" + t20Other,
			[]string{t20Other}},
		// ; is an ordinary byte: here card_number is inside the value of note.
		{"semicolon-is-not-a-separator", config.RemoveQueryParameters, "note=" + t20Other + ";card_number=T24KEEP5&x=1", "note=" + t20Other + ";card_number=T24KEEP5&x=1",
			[]string{t20Other, "T24KEEP5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := t20Plan(t, tc.implementation, `{"names":["card_number"]}`)
			var got string
			var a processing.Artifact
			var text string
			if tc.implementation == config.RemoveFormFields {
				a, _, text = t20Exchange(t, plan, t20Post("/pay", "application/x-www-form-urlencoded", tc.text), goodResponse)
				got = t20Body(t, a, "request")
			} else {
				a, _, text = t20Exchange(t, plan, t20Get("/pay?"+tc.text), goodResponse)
				got = a.Reconstruction.Exchanges[0].Request.Message.Target
				tc.want = "/pay?" + tc.want
			}
			t20Absent(t, text, t20Card)
			for _, survivor := range tc.survivors {
				t20Kept(t, text, survivor)
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
func TestT24MalformedEscapeRemovesTheWholePart(t *testing.T) {
	query := t20Plan(t, config.RemoveQueryParameters, `{"names":["card_number"]}`)
	form := t20Plan(t, config.RemoveFormFields, `{"names":["card_number"]}`)

	t.Run("query-control", func(t *testing.T) {
		a, _, text := t20Exchange(t, query, t20Get("/pay?note=%41&card_number="+t20Card), goodResponse)
		t20Absent(t, text, t20Card)
		if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay?note=%41" {
			t.Fatalf("PROPERTY: a well-formed escape changed what was removed: %q", got)
		}
	})
	for _, target := range []string{
		"/pay?card_number=" + t20Card + "&note=%ZZ" + t20Other,
		"/pay?no%t" + t20Other + "=1&card_number=" + t20Card,
		"/pay?note=" + t20Other + "%",
		"/pay?note=%4" + t20Other,
	} {
		t.Run("query:"+target, func(t *testing.T) {
			a, _, text := t20Exchange(t, query, t20Get(target), goodResponse)
			t20Absent(t, text, t20Card)
			t20Absent(t, text, t20Other)
			if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay" {
				t.Fatalf("PROPERTY: a query with a malformed escape was not removed whole: %q", got)
			}
			entries := t20Evidence(a, "request", config.TargetQueryField)
			if len(entries) != 1 || entries[0].Disposition != processing.DispositionRemovedUndecidable {
				t.Fatalf("PROPERTY: the whole-query removal is not evidenced as undecidable: %+v", a.PolicyExclusions)
			}
		})
	}

	t.Run("form-control", func(t *testing.T) {
		a, _, text := t20Exchange(t, form, t20Post("/pay", "application/x-www-form-urlencoded", "note=%41&card_number="+t20Card), goodResponse)
		t20Absent(t, text, t20Card)
		if got := t20Body(t, a, "request"); got != "note=%41" {
			t.Fatalf("PROPERTY: a well-formed escape changed what was removed: %q", got)
		}
	})
	t.Run("form", func(t *testing.T) {
		a, _, text := t20Exchange(t, form, t20Post("/pay", "application/x-www-form-urlencoded", "note=%G1"+t20Other+"&card_number="+t20Card), goodResponse)
		t20Absent(t, text, t20Card)
		t20Absent(t, text, t20Other)
		t20RemovedWhole(t, a, "request", processing.DispositionRemovedUndecidable)
	})
}

// A configured name carrying . or [] removes exactly that parameter: the
// literal name, not another the application might read as the same.
func TestT24NamesWithDotsAndBracketsMatchLiterally(t *testing.T) {
	plan := t20Plan(t, config.RemoveQueryParameters, `{"names":["card.number","items[]"]}`)
	a, _, text := t20Exchange(t, plan,
		t20Get("/pay?card.number="+t20Card+"&card_number=T24KEEP6&items%5B%5D=4000000000000002&items=T24KEEP7&note="+t20Other), goodResponse)
	t20Absent(t, text, t20Card)
	t20Absent(t, text, "4000000000000002")
	for _, survivor := range []string{"T24KEEP6", "T24KEEP7", t20Other} {
		t20Kept(t, text, survivor)
	}
	if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/pay?card_number=T24KEEP6&items=T24KEEP7&note="+t20Other {
		t.Fatalf("PROPERTY: the literal names were not the only ones removed: %q", got)
	}
}
