package config_test

import (
	"encoding/json"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// These constructed declarations exercise the public contract, without a
// component executor or any implementation-private validation helper.
func TestDeclaredInputHasNoProducer(t *testing.T) {
	cfg, pack, available := independentComposition()
	orphan := independentProcessor("orphan", config.ExecutionExternal)
	orphan.Input.Types = []string{"unproduced"}
	pack.Components = []config.Component{orphan}
	available.Types = append(available.Types, config.RecordType{Name: "unproduced", Fields: []string{"id"}})
	// The type exists, but no core or component output produces it. The
	// declaration is not placed in a slot, so no slot input mismatch masks it.
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.InputTypeNotProduced)
}

func TestComponentOrderingsCannotBothHold(t *testing.T) {
	cfg, pack, available := independentComposition()
	a := independentProcessor("first", config.ExecutionExternal)
	b := independentProcessor("second", config.ExecutionExternal)
	a.Ordering.Before = []string{b.Name}
	b.Ordering.Before = []string{a.Name}
	pack.Components = []config.Component{a, b}
	pack.Replacements = []config.Replacement{}
	cfg.Pipelines[0].Slots = []config.Slot{
		{Name: "left", Implementation: a.Name, OnFailure: config.OnFailureStopPipeline},
		{Name: "right", Implementation: b.Name, OnFailure: config.OnFailureStopPipeline},
	}
	// Both edges name present components and every type matches. Swapping the
	// configured slots cannot satisfy a < b and b < a.
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.OrderingUnsatisfiable)
}

func TestReplacementCannotBeResolved(t *testing.T) {
	cfg, pack, available := independentComposition()
	pack.Replacements[0].Implementation = "absent"
	// The pipeline, slot and original implementation all exist. Only the
	// replacement's implementation is absent from the effective inventory.
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.ReplacementNotResolvable)
}

func TestReplacementHasWrongRole(t *testing.T) {
	cfg, pack, available := independentComposition()
	subscriber := independentProcessor("alternative", config.ExecutionBuiltin)
	subscriber.Role = config.RoleSubscriber
	subscriber.Output.Records = []string{}
	subscriber.Output.Findings = true
	available.Builtins[1] = subscriber
	// A well-formed findings-only subscriber accepts the incoming type, but
	// cannot occupy a processing slot.
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.ReplacementIncompatible)
}

func TestReplacementRejectsIncomingType(t *testing.T) {
	cfg, pack, available := independentComposition()
	available.Types = append(available.Types, config.RecordType{Name: "other", Fields: []string{"id"}})
	available.CoreEmits = append(available.CoreEmits, "other")
	available.Builtins[1].Input.Types = []string{"other"}
	// Both types have producers. The replacement accepts only the type that
	// this particular pipeline does not deliver; its output still fits the sink.
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.ReplacementIncompatible)
}

func TestReplacementOutputDoesNotFitConsumer(t *testing.T) {
	cfg, pack, available := independentComposition()
	available.Types = append(available.Types, config.RecordType{Name: "other", Fields: []string{"id"}})
	available.Builtins[1].Output.Records = []string{"other"}
	// The replacement resolves, is a processor, and accepts the pipeline
	// input. Only its output fails to fit the next consumer, the sink.
	independentRefusal(t, independentCheck(t, cfg, pack, available), config.ReplacementIncompatible)
}

func TestConfigurationOnlyPackSelectsBuiltin(t *testing.T) {
	cfg, pack, available := independentComposition()
	got := independentCheck(t, cfg, pack, available)
	if got.Outcome != config.Accepted {
		t.Fatalf("available compatible built-in must be accepted: got %+v", got)
	}
	if len(got.Structural) != 0 || len(got.Composition) != 0 {
		t.Errorf("acceptance carries refusal findings: %+v", got)
	}
	if got.Resolved == nil {
		t.Fatal("accepted configuration has no resolved configuration")
	}
	if len(got.Resolved.Pipelines) != 1 || len(got.Resolved.Pipelines[0].Slots) != 1 {
		t.Fatalf("want one effective pipeline with one slot, got %+v", got.Resolved.Pipelines)
	}
	pipe := got.Resolved.Pipelines[0]
	slot := pipe.Slots[0]
	if pipe.Name != "inspection" || slot.Name != "process" || slot.Implementation != "alternative" || slot.SelectedBy != "pack:selection" {
		t.Errorf("pack selection was not resolved into its slot: %+v", pipe)
	}
}

func independentRefusal(t *testing.T, got config.Result, reason config.Reason) {
	t.Helper()
	if len(got.Structural) != 0 {
		t.Fatalf("fixture failed structural validation before composition: %+v", got)
	}
	if got.Outcome != config.CompositionRefused {
		t.Errorf("want outcome %q for %q, got %q", config.CompositionRefused, reason, got.Outcome)
	}
	if got.Resolved != nil {
		t.Errorf("refused configuration exposes a resolved configuration: %+v", got.Resolved)
	}
	for _, finding := range got.Composition {
		if finding.Reason == reason {
			return
		}
	}
	t.Errorf("want composition reason %q, got %+v", reason, got.Composition)
}

func independentCheck(t *testing.T, cfg config.Configuration, pack config.Manifest, available config.Available) config.Result {
	t.Helper()
	configuration, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("encode configuration fixture: %v", err)
	}
	manifest, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("encode manifest fixture: %v", err)
	}
	return config.Check(config.Input{
		Configuration: configuration,
		Manifests:     []config.Supplied{{Name: "selection", Content: manifest}},
		Available:     available,
	})
}

func independentProcessor(name, execution string) config.Component {
	return config.Component{
		Interface: config.ComponentVersion,
		Name:      name,
		Version:   "1.0.0",
		Role:      config.RoleProcessor,
		Execution: execution,
		Input:     config.Consumes{Types: []string{"observation"}, Delivery: config.DeliveryRecord},
		Output:    config.Output{Records: []string{"observation"}, Derived: []string{}},
		State:     config.StateNone,
		Ordering:  config.Ordering{Records: config.RecordsNone, After: []string{}, Before: []string{}},
		Lifecycle: config.Lifecycle{
			Startup:             config.HookIgnored,
			ConfigurationChange: config.HookIgnored,
			StreamClosure:       config.HookIgnored,
			Flush:               config.HookIgnored,
			Shutdown:            config.HookIgnored,
		},
		Failures: []string{config.FailureRecord, config.FailureFatal, config.FailureConfiguration},
	}
}

// Fresh values on every call keep each refusal a separate change to this
// compatible composition. Empty collections are explicit arrays on the wire.
func independentComposition() (config.Configuration, config.Manifest, config.Available) {
	spool, interval := int64(16), int64(1)
	existing, future, retain := false, false, false
	fixed := config.FixedAnswers{
		Boundary:    "a successful exec ends the grant; reparenting and a cgroup move do not, and an unenumerated pid namespace is never entered",
		RootExit:    "the root's own grant ends and nothing else's",
		Replacement: "a replacement root is covered only after a restart re-resolves the policy",
	}
	cfg := config.Configuration{
		Version: config.ConfigurationVersion,
		Observer: config.Observer{
			Log: "stdout", Directory: "/var/lib/observer",
			SpoolBoundMiB: &spool, StateEverySeconds: &interval,
		},
		ObservationScope: config.ObservationScope{
			Targets: []config.Target{{
				Name: "service", Match: config.Match{Exe: "/usr/bin/service"},
				Descendants: config.Descendants{
					Existing: &existing, Future: &future,
					Boundary: fixed.Boundary, RootExit: fixed.RootExit, Replacement: fixed.Replacement,
				},
			}},
			Exclude: []config.Match{}, Libraries: []config.Library{},
		},
		TrafficScope: config.TrafficScope{Rules: []config.TrafficRule{{
			Targets: []string{"service"}, Direction: config.DirectionAny,
			LocalPorts: []int{}, RemotePorts: []int{},
		}}},
		RetentionExport: config.RetentionExport{RetainPlaintext: &retain, ExportSinks: []string{}},
		Packs:           []string{"selection"},
		Sinks:           []config.Sink{{Name: "out", Kind: "transient"}},
		Pipelines: []config.Pipeline{{
			Name: "inspection", Input: "observation",
			Slots: []config.Slot{{Name: "process", Implementation: "original", OnFailure: config.OnFailureStopPipeline}},
			Sinks: []string{"out"}, Queues: []config.Queue{},
		}},
		Subscribers: []config.Subscriber{},
		Policy:      []json.RawMessage{},
	}
	pack := config.Manifest{
		Version: config.ManifestVersion, Name: "selection", PackVersion: "1.0.0",
		Components: []config.Component{}, Pipelines: []config.Pipeline{},
		Replacements: []config.Replacement{{Pipeline: "inspection", Slot: "process", Implementation: "alternative"}},
		Policy:       []json.RawMessage{},
	}
	available := config.Available{
		Types:     []config.RecordType{{Name: "observation", Fields: []string{"id"}}},
		CoreEmits: []string{"observation"},
		Builtins: []config.Component{
			independentProcessor("original", config.ExecutionBuiltin),
			independentProcessor("alternative", config.ExecutionBuiltin),
		},
		SinkKinds:   []config.SinkKind{{Name: "transient", Accepts: []string{"observation"}}},
		Descendants: fixed,
	}
	return cfg, pack, available
}
