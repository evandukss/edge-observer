package config_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// credentialsHeaders are the five headers the shipped credentials pack
// removes, written here independently of the pack.
var credentialsHeaders = []string{"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}

// withoutProvenance is the plan's pipelines and exclusions with who selected
// each operation and who declared each exclusion cleared, the header lists
// sorted: what the plan enforces, apart from which document asked.
func withoutProvenance(plan *config.ProcessingPlan) ([]config.EffectivePipeline, []config.Exclusion) {
	pipelines := plan.Pipelines()
	for i := range pipelines {
		for j := range pipelines[i].Slots {
			slot := &pipelines[i].Slots[j]
			slot.SelectedBy, slot.Configuration = "", nil
			if slot.Arguments != nil {
				slices.Sort(slot.Arguments.Headers)
			}
		}
	}
	exclusions := plan.Exclusions()
	for i := range exclusions {
		exclusions[i].Declaration = ""
	}
	slices.SortFunc(exclusions, func(a, b config.Exclusion) int {
		switch {
		case a.Field < b.Field:
			return -1
		case a.Field > b.Field:
			return 1
		}
		return 0
	})
	return pipelines, exclusions
}

func headerExclusions(plan *config.ProcessingPlan) int {
	n := 0
	for _, e := range plan.Exclusions() {
		if e.Header != "" {
			n++
		}
	}
	return n
}

// The shipped credentials pack removes exactly its five headers: a
// configuration enabling it compiles to the exclusions and the covering
// operations of the same configuration writing those five in remove.headers.
// Only who selected them differs, and the revision.
func TestTheShippedCredentialsPackRemovesExactlyItsFiveHeaders(t *testing.T) {
	pack, err := config.Examples.ReadFile("examples/packs/credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	base := `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}]`
	enabled, findings := config.Compile([]byte(base+`, "packs": ["credentials"]}`),
		[]config.Supplied{{Name: "credentials", Content: pack}})
	names, err := json.Marshal(credentialsHeaders)
	if err != nil {
		t.Fatal(err)
	}
	written, writtenFindings := config.Compile([]byte(base+`, "remove": {"headers": `+string(names)+`}}`), nil)

	// The written side is independent of the pack and must hold all five; the
	// pack side must hold some, so two empty plans cannot compare equal. How
	// many the pack side holds is the property, asserted below.
	if enabled == nil || written == nil || len(findings) != 0 || len(writtenFindings) != 0 ||
		headerExclusions(written.Plan) != len(credentialsHeaders) || headerExclusions(enabled.Plan) == 0 {
		t.Fatalf("wiring, not the property: the two configurations did not both compile to header exclusions, "+
			"so nothing below compares what the pack removes (pack: %v, written: %v)", findings, writtenFindings)
	}

	enabledPipelines, enabledExclusions := withoutProvenance(enabled.Plan)
	writtenPipelines, writtenExclusions := withoutProvenance(written.Plan)
	if !reflect.DeepEqual(enabledExclusions, writtenExclusions) {
		t.Errorf("PROPERTY: the shipped pack's exclusions are %+v, and the five headers written give %+v",
			enabledExclusions, writtenExclusions)
	}
	if !reflect.DeepEqual(enabledPipelines, writtenPipelines) {
		shown := func(pipelines []config.EffectivePipeline) string {
			encoded, _ := json.Marshal(pipelines)
			return string(encoded)
		}
		t.Errorf("PROPERTY: the shipped pack compiles to %s, and the five headers written to %s",
			shown(enabledPipelines), shown(writtenPipelines))
	}
}
