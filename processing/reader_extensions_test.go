package processing_test

import (
	"encoding/json"
	"testing"

	"github.com/evandukss/edge-observer/processing"
)

// The reader takes a version 2 line's id range, extension outcomes and
// removals from replacement content only in their published shapes, and
// checks an entry against the written message only where its author owns the
// written component.
func TestTheReaderChecksIDRangesExtensionOutcomesAndReplacementRemovals(t *testing.T) {
	line, _ := readableArtifact(t)
	var base map[string]any
	if err := json.Unmarshal(line, &base); err != nil {
		t.Fatal(err)
	}
	if _, ok := base["exchange_ids"]; !ok {
		t.Fatal("wiring, not the property: the written line carries no id range")
	}
	request := func(a map[string]any) map[string]any {
		exchange := a["reconstruction"].(map[string]any)["exchanges"].([]any)[0].(map[string]any)
		return exchange["request"].(map[string]any)["message"].(map[string]any)
	}
	changed := map[string]any{"exchange": 0, "extension": "a", "outcome": "changed",
		"changed": []any{"request.line"}, "overwritten": []any{}}
	queryRemoved := map[string]any{"exchange": 0, "message": "request", "field": "message.target.query",
		"disposition": "removed"}
	for _, tc := range []struct {
		name   string
		edit   func(map[string]any)
		accept bool
	}{
		{"the line as written", func(map[string]any) {}, true},
		{"no id range", func(a map[string]any) { delete(a, "exchange_ids") }, false},
		{"a count the range does not hold", func(a map[string]any) {
			a["exchange_ids"] = map[string]any{"first": "1", "last": "1", "count": "2"}
		}, false},
		{"a first id of zero", func(a map[string]any) {
			a["exchange_ids"] = map[string]any{"first": "0", "last": "0", "count": "1"}
		}, false},
		{"no ids issued, and a first id", func(a map[string]any) {
			a["exchange_ids"] = map[string]any{"first": "1", "count": "0"}
		}, false},
		{"no ids issued, and an exchange", func(a map[string]any) { a["exchange_ids"] = map[string]any{"count": "0"} }, false},
		{"no outcome list", func(a map[string]any) { delete(a, "extension_outcomes") }, false},
		{"no replacement list", func(a map[string]any) { delete(a, "replacement_exclusions") }, false},
		{"an outcome for an exchange not retained", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 5, "extension": "a", "outcome": "unchanged"}}
		}, false},
		{"one extension twice for one exchange", func(a map[string]any) {
			one := map[string]any{"exchange": 0, "extension": "a", "outcome": "unchanged"}
			a["extension_outcomes"] = []any{one, one}
		}, false},
		{"an extension name the configuration refuses", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "Upper", "outcome": "unchanged"}}
		}, false},
		{"a changed outcome with no overwritten list", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "a", "outcome": "changed",
				"changed": []any{"request.line"}}}
		}, false},
		{"overwritten beyond what was changed", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "a", "outcome": "changed",
				"changed": []any{"request.line"}, "overwritten": []any{"request.body"}}}
		}, false},
		{"a changed outcome naming connection", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "a", "outcome": "changed",
				"changed": []any{"connection"}, "overwritten": []any{}}}
		}, false},
		{"a failure under no protocol reason", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "a", "outcome": "failed",
				"reason": "it said no"}}
		}, false},
		{"an unchanged outcome with a reason", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "a", "outcome": "unchanged",
				"reason": "declined"}}
		}, false},
		{"a removal from replacement content by an extension that changed nothing", func(a map[string]any) {
			a["extension_outcomes"] = []any{map[string]any{"exchange": 0, "extension": "a", "outcome": "unchanged"}}
			a["replacement_exclusions"] = []any{map[string]any{"exchange": 0, "message": "request",
				"field": "message.headers.x-secret", "section": "headers", "disposition": "removed", "extension": "a"}}
		}, false},
		{"a removal from replacement content by the extension that changed it", func(a map[string]any) {
			a["extension_outcomes"] = []any{changed}
			removal := map[string]any{"extension": "a"}
			for k, v := range queryRemoved {
				removal[k] = v
			}
			a["replacement_exclusions"] = []any{removal}
		}, true},
		{"a captured query removed and the written target holding one", func(a map[string]any) {
			request(a)["target"] = "/public?kept=1"
			a["policy_exclusions"] = []any{queryRemoved}
		}, false},
		{"a captured query removed, and an extension's target written", func(a map[string]any) {
			request(a)["target"] = "/public?kept=1"
			a["policy_exclusions"] = []any{queryRemoved}
			a["extension_outcomes"] = []any{changed}
		}, true},
		{"an extension's query removal under a later extension's target", func(a map[string]any) {
			request(a)["target"] = "/public?kept=1"
			later := map[string]any{"exchange": 0, "extension": "b", "outcome": "changed",
				"changed": []any{"request.line"}, "overwritten": []any{}}
			earlier := map[string]any{"exchange": 0, "extension": "a", "outcome": "changed",
				"changed": []any{"request.line"}, "overwritten": []any{"request.line"}}
			removal := map[string]any{"extension": "a"}
			for k, v := range queryRemoved {
				removal[k] = v
			}
			a["extension_outcomes"] = []any{earlier, later}
			a["replacement_exclusions"] = []any{removal}
		}, true},
		{"an extension's query removal under its own target holding one", func(a map[string]any) {
			request(a)["target"] = "/public?kept=1"
			removal := map[string]any{"extension": "a"}
			for k, v := range queryRemoved {
				removal[k] = v
			}
			a["extension_outcomes"] = []any{changed}
			a["replacement_exclusions"] = []any{removal}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a map[string]any
			if err := json.Unmarshal(line, &a); err != nil {
				t.Fatal(err)
			}
			tc.edit(a)
			edited, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			err = processing.ReadArtifacts(artifactFS(append(edited, '\n')), func(processing.Artifact) error { return nil })
			if tc.accept && err != nil {
				t.Fatalf("refused: %v\n%s", err, edited)
			}
			if !tc.accept && err == nil {
				t.Fatalf("accepted:\n%s", edited)
			}
		})
	}
}
