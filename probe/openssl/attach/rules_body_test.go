//go:build attach

package attach_test

import (
	"strings"
	"testing"
)

// rulesNote is strictly valid JSON that urlencoded parsing would read as three
// parameters, one of them card_number.
const rulesNote = `{"note":"x&card_number=4111&y"}`

// The needles for rulesNote at the boundary: the parameter and its value, and
// the parameter alone. The bare digits are not one, since timestamps and pids
// in every log line can carry them.
var rulesNoteNeedles = []string{"card_number=4111", "card_number"}

// The combined request-body operation (the table in contract/config/CONFIG.md),
// with request form rules and request JSON rules both present. The form rule
// names a field no fixture sends, so no rule name can put card_number in a
// write.
//
//	JSON under text/plain, and JSON with no Content-Type    the JSON rules: /card/number
//	                                                        removed, brand kept
//	rulesNote under one urlencoded label, two urlencoded      removed whole with
//	fields, a JSON field in the headers and an urlencoded   removed_undecidable, and
//	one in the trailers, and one field naming both types    neither needle crosses a write
//
// The control is rulesNote under application/json in a session of its own: it
// keeps note, and the needles cross, which is what makes their absence mean
// something - and proves the boundary finds them inside a base64 kept body.
func TestTheCombinedRequestBodyOperationFollowsTheTable(t *testing.T) {
	binary := built(t)
	port := rulesServing(t)
	rules := map[string]any{"remove": map[string]any{
		"form": []string{"rul_form_field"},
		"json": map[string]any{"request": []string{"/card/number"}},
	}}
	card := `{"card":{"number":"` + rulesProtected + `","brand":"` + rulesPermitted + `"}}`
	form := "application/x-www-form-urlencoded"
	undecidable := map[string]string{
		"/note-one-urlencoded-label":           rulesPost("/note-one-urlencoded-label", []string{form}, rulesNote),
		"/note-two-urlencoded-fields":          rulesPost("/note-two-urlencoded-fields", []string{form, form}, rulesNote),
		"/note-json-header-urlencoded-trailer": rulesChunked("/note-json-header-urlencoded-trailer", []string{"Content-Type: application/json"}, rulesNote, []string{"Content-Type: " + form}),
		"/note-one-field-naming-both":          rulesPost("/note-one-field-naming-both", []string{form + ", application/json"}, rulesNote),
	}
	t.Run("the table", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		content := rulesWritten(t, c, rulesEncoded(t, rulesDocument(c, []map[string]any{rulesWatch("client", client.process)}, rules)))
		rulesAccepted(t, content)
		w := rulesStarted(t, binary, c, rulesNoteNeedles...)
		rulesSend(t, client, rulesPost("/json-under-text-plain", []string{"text/plain"}, card))
		rulesSend(t, client, rulesPost("/json-with-no-content-type", nil, card))
		for _, request := range undecidable {
			rulesSend(t, client, request)
		}
		records := rulesFinished(t, binary, c, w, client, 2)
		for _, target := range []string{"/json-under-text-plain", "/json-with-no-content-type"} {
			one := rulesFind(t, records, target)
			kept := one.Request.kept(t)
			if strings.Contains(kept, rulesProtected) || !strings.Contains(kept, rulesPermitted) ||
				!one.excluded("request", "message.body.json/card/number", "removed") {
				t.Errorf("%s: kept %q with exclusions %v, want /card/number removed and brand kept", target, kept, one.Exclusions)
			}
		}
		for target := range undecidable {
			one := rulesFind(t, records, target)
			undecided := false
			for _, excluded := range one.Exclusions {
				undecided = undecided || (strings.HasPrefix(excluded, "request ") && strings.HasSuffix(excluded, " removed_undecidable"))
			}
			if one.Request.kept(t) != "" || one.Request.Body.Length == "0" || !undecided {
				t.Errorf("%s: kept %q of %s bytes with exclusions %v, want the body removed whole as removed_undecidable",
					target, one.Request.kept(t), one.Request.Body.Length, one.Exclusions)
			}
		}
		for _, needle := range append([]string{rulesProtected}, rulesNoteNeedles...) {
			if n := rulesCrossed(w, needle); n != 0 {
				t.Errorf("%q crossed a write %d times, plainly or base64-encoded", needle, n)
			}
		}
		failureClean(t, w)
	})
	t.Run("the control, under application/json", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		content := rulesWritten(t, c, rulesEncoded(t, rulesDocument(c, []map[string]any{rulesWatch("client", client.process)}, rules)))
		rulesAccepted(t, content)
		w := rulesStarted(t, binary, c, rulesNoteNeedles...)
		rulesSend(t, client, rulesPost("/note-under-application-json", []string{"application/json"}, rulesNote))
		one := rulesFind(t, rulesFinished(t, binary, c, w, client, 2), "/note-under-application-json")
		if kept := one.Request.kept(t); kept != rulesNote {
			t.Errorf("under application/json the body kept is %q, want the note unchanged", kept)
		}
		for _, needle := range rulesNoteNeedles {
			if n := rulesCrossed(w, needle); n == 0 {
				t.Errorf("wiring, not the property: %q crossed no write where the note was kept, so its absence above "+
					"measures nothing", needle)
			}
		}
	})
}
