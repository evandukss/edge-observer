package policy

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// One configuration against two inventories: NONE of a kind is unimplemented,
// SOME of it is left to composition. The inventory's count decides, not the
// section's name.
func TestNoneOfAKindIsUnimplementedAndSomeOfItIsLeftToComposition(t *testing.T) {
	content, err := config.Examples.ReadFile("examples/external-component.config.json")
	if err != nil {
		t.Fatalf("read the example: %v", err)
	}
	written, structural := config.ReadConfiguration(content)
	if len(structural) > 0 {
		t.Fatalf("wiring, not the property: the example is structurally refused: %+v", structural)
	}
	runtime, err := config.Examples.ReadFile("examples/runtime.json")
	if err != nil {
		t.Fatalf("read the illustrative runtime: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(runtime))
	decoder.DisallowUnknownFields()
	var some config.Available
	if err := decoder.Decode(&some); err != nil {
		t.Fatalf("decode the illustrative runtime: %v", err)
	}
	if len(some.Builtins) == 0 || len(some.SinkKinds) < 2 {
		t.Fatalf("wiring, not the property: the illustrative runtime holds %d built-ins and %d sink kinds",
			len(some.Builtins), len(some.SinkKinds))
	}

	paths := func(sections []Section) []string {
		var named []string
		for _, section := range sections {
			named = append(named, section.Path)
		}
		slices.Sort(named)
		return named
	}
	counted := []string{"pipelines[0].slots", "retention_and_export.export_sinks", "sinks[1].kind", "subscribers"}
	uncounted := []string{"packs", "pipelines", "policy"}

	none := paths(unimplemented(written, Inventory()))
	for _, path := range append(slices.Clone(counted), uncounted...) {
		if !slices.Contains(none, path) {
			t.Errorf("against this program's inventory %s is not named: %v", path, none)
		}
	}
	against := paths(unimplemented(written, some))
	for _, path := range counted {
		if slices.Contains(against, path) {
			t.Errorf("against an inventory holding that kind, %s is still named unimplemented: %v", path, against)
		}
	}
	for _, path := range uncounted {
		if !slices.Contains(against, path) {
			t.Errorf("%s has nothing in any inventory to count and is not named: %v", path, against)
		}
	}
}
