//go:build attach

package attach_test

import (
	"strings"
	"testing"
)

// t30Note is the body contract 52 names: strictly valid JSON that urlencoded
// parsing would read as three parameters, one of them card_number.
const t30Note = `{"note":"x&card_number=4111&y"}`

// The needles for t30Note at the boundary: the parameter and its value, and
// the parameter alone. The bare digits are not one, since timestamps and pids
// in every log line can carry them.
var t30NoteNeedles = []string{"card_number=4111", "card_number"}

// Case 5, the combined request-body operation (contract 52's table), with
// request form rules and request JSON rules both present. The form rule names
// a field no fixture sends, so no rule name can put card_number in a write.
//
//	JSON under text/plain, and JSON with no Content-Type    the JSON rules: /card/number
//	                                                        removed, brand kept
//	t30Note under one urlencoded label, two urlencoded      removed whole with
//	fields, a JSON field in the headers and an urlencoded   removed_undecidable, and
//	one in the trailers, and one field naming both types    neither needle crosses a write
//
// The control is t30Note under application/json in a session of its own: it
// keeps note, and the needles cross, which is what makes their absence mean
// something - and proves the boundary finds them inside a base64 kept body.
func TestT30TheCombinedRequestBodyOperationFollowsTheTable(t *testing.T) {
	binary := built(t)
	port := t30Serving(t)
	rules := map[string]any{"remove": map[string]any{
		"form": []string{"t30_form_field"},
		"json": map[string]any{"request": []string{"/card/number"}},
	}}
	card := `{"card":{"number":"` + t30Protected + `","brand":"` + t30Permitted + `"}}`
	form := "application/x-www-form-urlencoded"
	undecidable := map[string]string{
		"/note-one-urlencoded-label":           t30Post("/note-one-urlencoded-label", []string{form}, t30Note),
		"/note-two-urlencoded-fields":          t30Post("/note-two-urlencoded-fields", []string{form, form}, t30Note),
		"/note-json-header-urlencoded-trailer": t30Chunked("/note-json-header-urlencoded-trailer", []string{"Content-Type: application/json"}, t30Note, []string{"Content-Type: " + form}),
		"/note-one-field-naming-both":          t30Post("/note-one-field-naming-both", []string{form + ", application/json"}, t30Note),
	}
	t.Run("the table", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		content := t30Written(t, c, t30Encoded(t, t30Document(c, []map[string]any{t30Watch("client", client.process)}, rules)))
		t30Accepted(t, content)
		w := t30Started(t, binary, c, t30NoteNeedles...)
		t30Send(t, client, t30Post("/json-under-text-plain", []string{"text/plain"}, card))
		t30Send(t, client, t30Post("/json-with-no-content-type", nil, card))
		for _, request := range undecidable {
			t30Send(t, client, request)
		}
		records := t30Finished(t, binary, c, w, client, 2)
		for _, target := range []string{"/json-under-text-plain", "/json-with-no-content-type"} {
			one := t30Find(t, records, target)
			kept := one.Request.kept(t)
			if strings.Contains(kept, t30Protected) || !strings.Contains(kept, t30Permitted) ||
				!one.excluded("request", "message.body.json/card/number", "removed") {
				t.Errorf("%s: kept %q with exclusions %v, want /card/number removed and brand kept", target, kept, one.Exclusions)
			}
		}
		for target := range undecidable {
			one := t30Find(t, records, target)
			undecided := false
			for _, excluded := range one.Exclusions {
				undecided = undecided || (strings.HasPrefix(excluded, "request ") && strings.HasSuffix(excluded, " removed_undecidable"))
			}
			if one.Request.kept(t) != "" || one.Request.Body.Length == "0" || !undecided {
				t.Errorf("%s: kept %q of %s bytes with exclusions %v, want the body removed whole as removed_undecidable",
					target, one.Request.kept(t), one.Request.Body.Length, one.Exclusions)
			}
		}
		for _, needle := range append([]string{t30Protected}, t30NoteNeedles...) {
			if n := t30Crossed(w, needle); n != 0 {
				t.Errorf("%q crossed a write %d times, plainly or base64-encoded", needle, n)
			}
		}
		t25Clean(t, w)
	})
	t.Run("the control, under application/json", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		content := t30Written(t, c, t30Encoded(t, t30Document(c, []map[string]any{t30Watch("client", client.process)}, rules)))
		t30Accepted(t, content)
		w := t30Started(t, binary, c, t30NoteNeedles...)
		t30Send(t, client, t30Post("/note-under-application-json", []string{"application/json"}, t30Note))
		one := t30Find(t, t30Finished(t, binary, c, w, client, 2), "/note-under-application-json")
		if kept := one.Request.kept(t); kept != t30Note {
			t.Errorf("under application/json the body kept is %q, want the note unchanged", kept)
		}
		for _, needle := range t30NoteNeedles {
			if n := t30Crossed(w, needle); n == 0 {
				t.Errorf("wiring, not the property: %q crossed no write where the note was kept, so its absence above "+
					"measures nothing", needle)
			}
		}
	})
}
