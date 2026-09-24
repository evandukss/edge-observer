package config_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

func TestProducerCycleIsUnreachableFromCore(t *testing.T) {
	cfg, pack, available := independentProducerCycle()
	got := independentCheck(t, cfg, pack, available)
	independentRefusal(t, got, config.InputTypeUnreachable)
	for _, finding := range got.Composition {
		if finding.Reason == config.InputTypeNotProduced {
			t.Errorf("both cycle types have producers; missing-producer reason is false: %+v", finding)
		}
	}
}

func TestProducerCycleSeededByCoreIsAccepted(t *testing.T) {
	cfg, pack, available := independentProducerCycle()
	// The only difference from the unreachable case is this core seed: left
	// can now produce right-record, which lets right produce left-record.
	available.CoreEmits = append(available.CoreEmits, "left-record")
	got := independentCheck(t, cfg, pack, available)
	if got.Outcome != config.Accepted {
		t.Fatalf("cycle reachable from a core-emitted type must be accepted: got %+v", got)
	}
	if len(got.Structural) != 0 || len(got.Composition) != 0 {
		t.Errorf("seeded-cycle acceptance carries refusal findings: %+v", got)
	}
	if got.Resolved == nil {
		t.Fatal("accepted seeded cycle has no resolved configuration")
	}
}

func independentProducerCycle() (config.Configuration, config.Manifest, config.Available) {
	cfg, pack, available := independentComposition()
	left := independentProcessor("left-producer", config.ExecutionExternal)
	left.Input.Types = []string{"left-record"}
	left.Output.Records = []string{"right-record"}
	right := independentProcessor("right-producer", config.ExecutionExternal)
	right.Input.Types = []string{"right-record"}
	right.Output.Records = []string{"left-record"}
	pack.Components = []config.Component{left, right}
	available.Types = append(available.Types,
		config.RecordType{Name: "left-record", Fields: []string{"id"}},
		config.RecordType{Name: "right-record", Fields: []string{"id"}},
	)
	// Both input types have another available producer. Neither the core nor
	// its reachable built-ins emit either type, so there is no first record
	// with which the cycle could start. Keeping these declarations out of the
	// pipeline avoids an unrelated pipeline-input or slot-type refusal.
	return cfg, pack, available
}
