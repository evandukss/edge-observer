package config_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

func TestReplacementHonoursInheritedOrdering(t *testing.T) {
	cfg, pack, available := independentReplacementOrdering(false)
	got := independentCheck(t, cfg, pack, available)
	if got.Outcome != config.Accepted {
		t.Fatalf("replacement honouring inherited ordering must be accepted: got %+v", got)
	}
	if len(got.Structural) != 0 || len(got.Composition) != 0 {
		t.Errorf("acceptance carries refusal findings: %+v", got)
	}
	if got.Resolved == nil {
		t.Fatal("accepted replacement has no resolved configuration")
	}
	if len(got.Resolved.Pipelines) != 1 || len(got.Resolved.Pipelines[0].Slots) != 2 {
		t.Fatalf("want one effective pipeline with two slots, got %+v", got.Resolved.Pipelines)
	}
	pipe := got.Resolved.Pipelines[0]
	first, second := pipe.Slots[0], pipe.Slots[1]
	if pipe.Name != "inspection" || first.Name != "original" || first.Implementation != "alternative" || first.SelectedBy != "pack:selection" || second.Name != "tail" || second.Implementation != "tail" {
		t.Errorf("resolved pipeline must place the replacement before tail: %+v", pipe)
	}
}

func TestReplacementConflictsWithInheritedOrdering(t *testing.T) {
	cfg, pack, available := independentReplacementOrdering(true)
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.ReplacementIncompatible)
}

func TestReplacementHonoursIncomingOrderingReference(t *testing.T) {
	cfg, pack, available := independentIncomingOrdering(false)
	got := independentCheck(t, cfg, pack, available)
	if got.Outcome != config.Accepted {
		t.Fatalf("replacement honouring another component's ordering reference must be accepted: got %+v", got)
	}
	if len(got.Structural) != 0 || len(got.Composition) != 0 {
		t.Errorf("acceptance carries refusal findings: %+v", got)
	}
	if got.Resolved == nil {
		t.Fatal("accepted replacement has no resolved configuration")
	}
	if len(got.Resolved.Pipelines) != 1 || len(got.Resolved.Pipelines[0].Slots) != 2 {
		t.Fatalf("want one effective pipeline with two slots, got %+v", got.Resolved.Pipelines)
	}
	pipe := got.Resolved.Pipelines[0]
	first, second := pipe.Slots[0], pipe.Slots[1]
	if pipe.Name != "inspection" || first.Name != "original" || first.Implementation != "alternative" || first.SelectedBy != "pack:selection" || second.Name != "tail" || second.Implementation != "tail" {
		t.Errorf("tail's incoming reference must leave the replacement before tail: %+v", pipe)
	}
}

func TestReplacementConflictsWithIncomingOrderingReference(t *testing.T) {
	cfg, pack, available := independentIncomingOrdering(true)
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.ReplacementIncompatible)
}

func independentIncomingOrdering(conflicting bool) (config.Configuration, config.Manifest, config.Available) {
	cfg, pack, available := independentReplacementOrdering(conflicting)
	// The original declares no ordering. The constraint lives only on tail
	// and names the implementation being replaced, never the replacement.
	available.Builtins[0].Ordering.Before = []string{}
	available.Builtins[2].Ordering.After = []string{"original"}
	return cfg, pack, available
}

func independentReplacementOrdering(conflicting bool) (config.Configuration, config.Manifest, config.Available) {
	cfg, pack, available := independentComposition()
	available.Builtins[0].Ordering.Before = []string{"tail"}
	available.Builtins = append(available.Builtins, independentProcessor("tail", config.ExecutionBuiltin))
	cfg.Pipelines[0].Slots = []config.Slot{
		{Name: "original", Implementation: "original", OnFailure: config.OnFailureStopPipeline},
		{Name: "tail", Implementation: "tail", OnFailure: config.OnFailureStopPipeline},
	}
	pack.Replacements[0].Slot = "original"
	// The original composition satisfies original < tail. All components have
	// identical record types. Only the replacement's own ordering changes:
	// tail < replacement conflicts with the inherited replacement < tail,
	// independently of which explicit slot order an operator might choose.
	if conflicting {
		available.Builtins[1].Ordering.After = []string{"tail"}
	}
	return cfg, pack, available
}
