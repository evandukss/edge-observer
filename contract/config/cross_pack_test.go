package config_test

import (
	"encoding/json"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

func TestReplacementFromEnabledPackIsAccepted(t *testing.T) {
	got := config.Check(independentCrossPackInput(t, true))
	if got.Outcome != config.Accepted {
		t.Fatalf("compatible replacement from another enabled pack must be accepted: got %+v", got)
	}
	if len(got.Structural) != 0 || len(got.Composition) != 0 {
		t.Errorf("acceptance carries refusal findings: %+v", got)
	}
	if got.Resolved == nil {
		t.Fatal("accepted cross-pack replacement has no resolved configuration")
	}
	if len(got.Resolved.Pipelines) != 1 || len(got.Resolved.Pipelines[0].Slots) != 1 {
		t.Fatalf("want one effective pipeline with one slot, got %+v", got.Resolved.Pipelines)
	}
	pipe := got.Resolved.Pipelines[0]
	slot := pipe.Slots[0]
	if pipe.Name != "inspection" || slot.Name != "process" || slot.Implementation != "pack-transform" || slot.SelectedBy != "pack:selection" {
		t.Errorf("cross-pack selection was not resolved into its slot: %+v", pipe)
	}
}

func TestReplacementFromDisabledPackIsNotResolvable(t *testing.T) {
	independentRefusal(t, config.Check(independentCrossPackInput(t, false)), config.ReplacementNotResolvable)
}

// Both cases supply the same two well-formed manifests. Only the operator's
// enabled-pack list changes. The selecting pack supplies no implementation;
// the supplying pack's processor accepts and returns the pipeline's type.
func independentCrossPackInput(t *testing.T, supplierEnabled bool) config.Input {
	t.Helper()
	cfg, selection, available := independentComposition()
	selection.Replacements[0].Implementation = "pack-transform"
	if supplierEnabled {
		cfg.Packs = append(cfg.Packs, "supplier")
	}
	supplier := config.Manifest{
		Version: config.ManifestVersion, Name: "supplier", PackVersion: "1.0.0",
		Components:   []config.Component{independentProcessor("pack-transform", config.ExecutionExternal)},
		Pipelines:    []config.Pipeline{},
		Replacements: []config.Replacement{},
		Policy:       []json.RawMessage{},
	}
	configuration, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("encode cross-pack configuration fixture: %v", err)
	}
	input := config.Input{Configuration: configuration, Available: available}
	for _, manifest := range []config.Manifest{selection, supplier} {
		content, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("encode cross-pack manifest fixture: %v", err)
		}
		input.Manifests = append(input.Manifests, config.Supplied{Name: manifest.Name, Content: content})
	}
	return input
}
