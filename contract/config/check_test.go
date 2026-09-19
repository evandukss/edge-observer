package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/policy"
	observerpolicy "github.com/evandukss/edge-observer/policy"
)

// caseCount is how many worked cases testdata/cases holds, asserted before any
// case is read so a glob that matched nothing cannot pass.
const caseCount = 49

type workedCase struct {
	Purpose       string          `json:"purpose"`
	Configuration json.RawMessage `json:"configuration"`
	Manifests     []struct {
		Name    string          `json:"name"`
		Content json.RawMessage `json:"content"`
	} `json:"manifests"`
	Expected struct {
		Outcome     config.Outcome    `json:"outcome"`
		Structural  []expectedFinding `json:"structural"`
		Composition []expectedFinding `json:"composition"`
	} `json:"expected"`
}

type expectedFinding struct {
	Document string        `json:"document"`
	Subject  string        `json:"subject"`
	Reason   config.Reason `json:"reason"`
}

func strict(t *testing.T, content []byte, into any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		t.Fatalf("wiring, not the contract: decode: %v", err)
	}
}

func runtime(t *testing.T) config.Available {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("examples", "runtime.json"))
	if err != nil {
		t.Fatalf("read the runtime inventory: %v", err)
	}
	var available config.Available
	strict(t, content, &available)
	if len(available.Types) != 6 || len(available.Builtins) != 5 || len(available.SinkKinds) != 3 {
		t.Fatalf("wiring, not the contract: the runtime inventory holds %d types, %d built-ins and %d sink kinds "+
			"where 6, 5 and 3 are written, so no case below measures what it says",
			len(available.Types), len(available.Builtins), len(available.SinkKinds))
	}
	return available
}

func cases(t *testing.T) map[string]workedCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "cases", "*.json"))
	if err != nil {
		t.Fatalf("glob the cases: %v", err)
	}
	if len(paths) != caseCount {
		t.Fatalf("wiring, not the contract: %d case files where %d are written", len(paths), caseCount)
	}
	read := map[string]workedCase{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var one workedCase
		strict(t, content, &one)
		if len(one.Configuration) == 0 || one.Purpose == "" {
			t.Fatalf("wiring, not the contract: %s has no configuration or no purpose", path)
		}
		read[strings.TrimSuffix(filepath.Base(path), ".json")] = one
	}
	return read
}

func input(one workedCase, available config.Available) config.Input {
	in := config.Input{Configuration: one.Configuration, Available: available}
	for _, m := range one.Manifests {
		in.Manifests = append(in.Manifests, config.Supplied{Name: m.Name, Content: m.Content})
	}
	return in
}

func keys[F any](list []F, key func(F) string) []string {
	out := []string{}
	for _, f := range list {
		out = append(out, key(f))
	}
	slices.Sort(out)
	return out
}

func expectedKey(f expectedFinding) string {
	return fmt.Sprintf("%s | %s | %s", f.Document, f.Subject, f.Reason)
}

func gotKey(f config.Finding) string {
	return fmt.Sprintf("%s | %s | %s", f.Document, f.Subject, f.Reason)
}

func TestEveryWorkedCaseChecksAsWritten(t *testing.T) {
	available := runtime(t)
	for name, one := range cases(t) {
		t.Run(name, func(t *testing.T) {
			result := config.Check(input(one, available))
			if result.Outcome != one.Expected.Outcome {
				t.Errorf("outcome %q, want %q; structural %v, composition %v", result.Outcome, one.Expected.Outcome,
					keys(result.Structural, gotKey), keys(result.Composition, gotKey))
			}
			if got, want := keys(result.Structural, gotKey), keys(one.Expected.Structural, expectedKey); !slices.Equal(got, want) {
				t.Errorf("structural findings\n got %q\nwant %q", got, want)
			}
			if got, want := keys(result.Composition, gotKey), keys(one.Expected.Composition, expectedKey); !slices.Equal(got, want) {
				t.Errorf("composition findings\n got %q\nwant %q", got, want)
			}
			if (result.Resolved != nil) != (one.Expected.Outcome == config.Accepted) {
				t.Errorf("resolved view present %v on outcome %q", result.Resolved != nil, result.Outcome)
			}
			for _, finding := range append(slices.Clone(result.Structural), result.Composition...) {
				if finding.Detail == "" {
					t.Errorf("finding %s carries no detail", gotKey(finding))
				}
			}
		})
	}
}

// The three falsifying states are each structurally well formed, each refused
// at composition with the reason that names which it is, and each accepted when
// the one defect is taken away. The pairs are what show the refusal was caused
// by that defect rather than by anything else in the documents.
func TestTheThreeFalsifyingStatesAreRefusedForWhatTheyAre(t *testing.T) {
	available := runtime(t)
	all := cases(t)
	for _, pair := range []struct {
		refused, control string
		reason           config.Reason
		findings         int
	}{
		{"refuse-input-type-not-produced", "accept-input-type-produced", config.InputTypeNotProduced, 1},
		{"refuse-input-type-unreachable", "accept-input-type-reachable", config.InputTypeUnreachable, 2},
		{"refuse-ordering-unsatisfiable", "accept-ordering-satisfied", config.OrderingUnsatisfiable, 1},
		{"refuse-replacement-not-resolvable", "accept-replacement-builtin", config.ReplacementNotResolvable, 1},
		{"refuse-replacement-incompatible", "accept-replacement-builtin", config.ReplacementIncompatible, 1},
		{"refuse-replacement-inherited-ordering-not-met", "accept-replacement-inherits-ordering", config.ReplacementIncompatible, 1},
	} {
		t.Run(pair.refused, func(t *testing.T) {
			control := config.Check(input(all[pair.control], available))
			if control.Outcome != config.Accepted {
				t.Fatalf("wiring, not the property: the control %s is %q with %v %v, so the refusal beside it is "+
					"not shown to be caused by its one defect", pair.control, control.Outcome,
					keys(control.Structural, gotKey), keys(control.Composition, gotKey))
			}
			refused := config.Check(input(all[pair.refused], available))
			if len(refused.Structural) != 0 {
				t.Fatalf("the state must be structurally well formed, and it was refused structurally: %v", keys(refused.Structural, gotKey))
			}
			if refused.Outcome != config.CompositionRefused || len(refused.Composition) != pair.findings {
				t.Fatalf("outcome %q with %v, want composition_refused with exactly %d %s",
					refused.Outcome, keys(refused.Composition, gotKey), pair.findings, pair.reason)
			}
			for _, finding := range refused.Composition {
				if finding.Reason != pair.reason {
					t.Fatalf("%s, want every finding %s", gotKey(finding), pair.reason)
				}
			}
		})
	}
}

// A configuration-only pack supplies no implementation, and selecting an
// available compatible built-in through it is a replacement.
func TestAConfigurationOnlyPackReplacesThroughABuiltin(t *testing.T) {
	available := runtime(t)
	one := cases(t)["accept-replacement-builtin"]
	if strings.Contains(string(one.Manifests[0].Content), `"interface"`) {
		t.Fatalf("wiring, not the property: the pack declares a component, so it is not configuration-only")
	}
	result := config.Check(input(one, available))
	if result.Resolved == nil {
		t.Fatalf("outcome %q, want accepted", result.Outcome)
	}
	slot := result.Resolved.Pipelines[0].Slots[0]
	if slot.Implementation != "truncating-redactor" || slot.SelectedBy != "pack:swap" {
		t.Fatalf("slot resolved to %q selected by %q, want truncating-redactor selected by pack:swap", slot.Implementation, slot.SelectedBy)
	}
}

// Every accepted case resolves into the policy inventory without losing a
// pipeline, a slot's implementation, a sink or a queue, and contract/policy
// decides against that inventory.
func TestEveryAcceptedConfigurationIsExpressibleIntoTheInventory(t *testing.T) {
	available := runtime(t)
	accepted := 0
	for name, one := range cases(t) {
		if one.Expected.Outcome != config.Accepted {
			continue
		}
		accepted++
		t.Run(name, func(t *testing.T) {
			result := config.Check(input(one, available))
			if result.Resolved == nil {
				t.Fatalf("outcome %q, want accepted", result.Outcome)
			}
			var authored config.Configuration
			strict(t, one.Configuration, &authored)
			inventory := result.Resolved.Inventory
			if len(inventory.Pipelines) != len(result.Resolved.Pipelines) {
				t.Errorf("%d effective pipelines and %d in the inventory", len(result.Resolved.Pipelines), len(inventory.Pipelines))
			}
			for _, p := range result.Resolved.Pipelines {
				projected, present := inventory.Pipelines[p.Name]
				if !present {
					t.Errorf("pipeline %q is not in the inventory", p.Name)
					continue
				}
				if !slices.Equal(projected.Sinks, p.Sinks) {
					t.Errorf("pipeline %q sinks %v in the inventory, %v effective", p.Name, projected.Sinks, p.Sinks)
				}
				for _, s := range p.Slots {
					if !slices.Contains(projected.Components, s.Implementation) {
						t.Errorf("pipeline %q slot %q: %q is not among its inventory components", p.Name, s.Name, s.Implementation)
					}
					if _, present := inventory.Components[s.Implementation]; !present {
						t.Errorf("%q is not an inventory component", s.Implementation)
					}
				}
			}
			slots := 0
			for _, p := range result.Resolved.Pipelines {
				for _, s := range p.Slots {
					slots++
					if got := inventory.Slots[p.Name+"."+s.Name]; got.Pipeline != p.Name || got.Component != s.Implementation {
						t.Errorf("slot %s.%s is %+v in the inventory, filled by %q effectively", p.Name, s.Name, got, s.Implementation)
					}
				}
				for _, name := range p.Sinks {
					var kind string
					for _, sink := range authored.Sinks {
						if sink.Name == name {
							kind = sink.Kind
						}
					}
					facts, present := inventory.Sinks[name]
					if !present || facts.Kind != kind {
						t.Errorf("sink %q of pipeline %q is %+v in the inventory, of kind %q authored", name, p.Name, facts, kind)
					}
					for _, k := range available.SinkKinds {
						if k.Name == kind && (facts.LeavesHost != k.LeavesHost || facts.RetainsPlaintext != k.RetainsPlaintext) {
							t.Errorf("sink %q carries %+v, and its kind says leaves_host %v retains_plaintext %v", name, facts, k.LeavesHost, k.RetainsPlaintext)
						}
					}
				}
			}
			if len(inventory.Slots) != slots {
				t.Errorf("%d slots in the inventory and %d effective", len(inventory.Slots), slots)
			}
			for _, p := range authored.Pipelines {
				for _, q := range p.Queues {
					if !slices.Contains(inventory.Pipelines[p.Name].Queues, q.Name) {
						t.Errorf("queue %q of pipeline %q is not in the inventory", q.Name, p.Name)
					}
				}
			}
			decided := policy.Decide(result.Resolved.Policy, inventory)
			if len(decided.Activations) != len(inventory.Pipelines) {
				t.Errorf("policy decided %d activations over %d pipelines", len(decided.Activations), len(inventory.Pipelines))
			}
		})
	}
	if accepted < 6 {
		t.Fatalf("wiring, not the property: %d accepted cases, fewer than the 6 written", accepted)
	}
}

// A policy document in an operator configuration arrives at policy as the
// operator's, and one in a manifest as the pack's, and a requirement on a
// component an operator pipeline holds is accepted against the resolved
// inventory.
func TestPolicyDocumentsCarryTheirSourceIntoTheDecision(t *testing.T) {
	available := runtime(t)
	requirement := `{"vocabulary": "observer.policy/draft", "requirements": [{"id": "project", "target": {"kind": "component", "name": "http-redactor"},
	  "operation": "project_fields", "parameters": {"fields": ["message.body"]}, "failure_action": "none"}], "claims": [], "approvals": []}`
	claim := `{"vocabulary": "observer.policy/draft", "requirements": [], "claims": [{"id": "classifies", "component": "acme-classifier",
	  "statement": "labels each exchange"}], "approvals": [{"claim": "classifies"}]}`

	one := cases(t)["accept-external-component"]
	var authored map[string]any
	strict(t, one.Configuration, &authored)
	authored["policy"] = []json.RawMessage{json.RawMessage(requirement)}
	configuration, _ := json.Marshal(authored)
	var manifest map[string]any
	strict(t, one.Manifests[0].Content, &manifest)
	manifest["policy"] = []json.RawMessage{json.RawMessage(claim)}
	content, _ := json.Marshal(manifest)

	result := config.Check(config.Input{Configuration: configuration, Manifests: []config.Supplied{{Name: "acme", Content: content}}, Available: available})
	if result.Resolved == nil {
		t.Fatalf("wiring, not the property: outcome %q with %v %v", result.Outcome, keys(result.Structural, gotKey), keys(result.Composition, gotKey))
	}
	loaded := result.Resolved.Policy
	if len(loaded) != 2 || loaded[0].Source != policy.Operator || loaded[1].Source != policy.Pack {
		t.Fatalf("policy loaded as %+v, want the operator's document then the pack's", loaded)
	}
	decided := policy.Decide(loaded, result.Resolved.Inventory)
	var reasons []string
	for _, f := range decided.Findings {
		reasons = append(reasons, f.Declaration+":"+string(f.Reason))
	}
	// The pack's own approval is refused: an approval is honoured only from an
	// operator document, and the source is what says which this was.
	want := []string{"project:enforced", "classifies:trusted_behaviour_not_approved", "approval:classifies:approval_not_from_operator"}
	if !slices.Equal(reasons, want) {
		t.Fatalf("policy decided %v, want %v", reasons, want)
	}
}

// A requirement targeting a slot is decided against whatever fills the slot after
// replacement, so a pack replacing the component cannot make the requirement stop
// applying; one naming the replaced component is refused rather than dropped.
func TestARequirementOnASlotFollowsItsReplacement(t *testing.T) {
	available := runtime(t)
	one := cases(t)["accept-replacement-inherits-ordering"]
	decide := func(target policy.Target, operation string, parameters map[string]any, failure string) (policy.Finding, *config.Resolved) {
		t.Helper()
		requirement, _ := json.Marshal(policy.Document{Vocabulary: policy.Vocabulary, Requirements: []policy.Requirement{{
			ID: "r", Target: target, Operation: operation, Parameters: parameters, FailureAction: failure,
		}}})
		var authored map[string]any
		strict(t, one.Configuration, &authored)
		authored["policy"] = []json.RawMessage{requirement}
		configuration, _ := json.Marshal(authored)
		in := input(one, available)
		in.Configuration = configuration
		result := config.Check(in)
		if result.Resolved == nil {
			t.Fatalf("wiring, not the property: outcome %q with %v %v", result.Outcome, keys(result.Structural, gotKey), keys(result.Composition, gotKey))
		}
		return policy.Decide(result.Resolved.Policy, result.Resolved.Inventory).Findings[0], result.Resolved
	}

	accountSink := policy.Target{Kind: "sink", Name: "account"}
	bySlot, resolved := decide(accountSink, "order_before", map[string]any{"processor": "exchanges.classify"}, policy.StopPipeline)
	if slot := resolved.Inventory.Slots["exchanges.classify"]; slot.Component != "acme-quick" {
		t.Fatalf("wiring, not the property: the classify slot is filled by %q, not the replacement acme-quick", slot.Component)
	}
	if bySlot.Disposition != policy.Accept {
		t.Errorf("an ordering naming the replaced slot is %s %s, expected accept", bySlot.Disposition, bySlot.Reason)
	}
	byReplaced, _ := decide(accountSink, "order_before", map[string]any{"processor": "acme-classifier"}, policy.StopPipeline)
	if byReplaced.Disposition != policy.RefuseActivation || byReplaced.Reason != policy.MissingCapability {
		t.Errorf("an ordering naming the component the pack replaced is %s %s, expected refuse_activation missing_capability",
			byReplaced.Disposition, byReplaced.Reason)
	}
	projected, _ := decide(policy.Target{Kind: "slot", Name: "exchanges.classify"}, "project_fields", map[string]any{"fields": []any{"message.body"}}, policy.None)
	if projected.Disposition != policy.Accept || projected.Pipelines[0] != "exchanges" {
		t.Errorf("a projection on the replaced slot is %s %s over %v, expected accept over exchanges", projected.Disposition, projected.Reason, projected.Pipelines)
	}
}

// The spool bound and the state interval are optional; absent, they resolve to
// the contract's stated values, and written, to what is written.
func TestTheObserverSettingsResolve(t *testing.T) {
	available := runtime(t)
	all := cases(t)
	defaulted := config.Check(input(all["accept-observer-settings-defaulted"], available))
	if defaulted.Resolved == nil {
		t.Fatalf("outcome %q, want accepted", defaulted.Outcome)
	}
	if got := defaulted.Resolved.Observer; got.SpoolBoundMiB != config.DefaultSpoolBoundMiB || got.StateEverySeconds != config.DefaultStateEverySeconds {
		t.Errorf("absent settings resolve to %+v, expected %d and %d", got, config.DefaultSpoolBoundMiB, config.DefaultStateEverySeconds)
	}
	written := all["accept-no-extension"]
	wrote := map[string]any{}
	strict(t, written.Configuration, &wrote)
	wrote["observer"].(map[string]any)["spool_bound_mib"] = 128
	wrote["observer"].(map[string]any)["state_every_seconds"] = 5
	written.Configuration, _ = json.Marshal(wrote)
	given := config.Check(input(written, available))
	if given.Resolved == nil {
		t.Fatalf("wiring, not the property: outcome %q", given.Outcome)
	}
	if got := given.Resolved.Observer; got.SpoolBoundMiB != 128 || got.StateEverySeconds != 5 {
		t.Errorf("written settings resolve to %+v, expected 128 and 5", got)
	}
}

// The contract states the observer's defaults as values, and the observer turns
// the resolved values into its own settings. The observer is asked what it
// applies to a file that states neither, and the answer is held to the
// contract's.
func TestTheObserverDefaultsAgreeWithTheObserver(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("examples", "no-extension.config.json"))
	if err != nil {
		t.Fatalf("read the no-extension example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-extension example: %v", err)
	}
	observer := document["observer"].(map[string]any)
	delete(observer, "spool_bound_mib")
	delete(observer, "state_every_seconds")
	file, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatalf("write the observer's configuration: %v", err)
	}
	loaded, err := observerpolicy.Load(path)
	if err != nil {
		t.Fatalf("wiring, not the property: the observer refused a configuration stating neither setting: %v", err)
	}
	if loaded.Settings.BoundMiB != config.DefaultSpoolBoundMiB {
		t.Errorf("the observer defaults the spool bound to %d MiB and the contract to %d", loaded.Settings.BoundMiB, config.DefaultSpoolBoundMiB)
	}
	if loaded.Settings.StateEvery != time.Duration(config.DefaultStateEverySeconds)*time.Second {
		t.Errorf("the observer defaults the state interval to %s and the contract to %ds", loaded.Settings.StateEvery, config.DefaultStateEverySeconds)
	}
}

func TestEveryReasonIsGivenByAWorkedCase(t *testing.T) {
	given := map[config.Reason]bool{}
	for _, one := range cases(t) {
		for _, f := range append(slices.Clone(one.Expected.Structural), one.Expected.Composition...) {
			given[f.Reason] = true
		}
	}
	all := append(slices.Clone(config.StructuralReasons), config.CompositionReasons...)
	if len(all) != 25 {
		t.Fatalf("wiring, not the contract: %d reasons where 25 are written", len(all))
	}
	for _, reason := range all {
		if !given[reason] {
			t.Errorf("no worked case gives %s", reason)
		}
	}
	for reason := range given {
		if !slices.Contains(all, reason) {
			t.Errorf("a worked case expects %s, which is not a reason", reason)
		}
	}
}

// The specification's reason tables and the package's reason lists are one set.
func TestTheSpecificationAndTheReasonsAgree(t *testing.T) {
	content, err := os.ReadFile("CONFIG.md")
	if err != nil {
		t.Fatalf("read the specification: %v", err)
	}
	row := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\| (structural|composition) \\|")
	matches := row.FindAllStringSubmatch(string(content), -1)
	if len(matches) != 25 {
		t.Fatalf("wiring, not the contract: %d reason rows in CONFIG.md where 25 are written", len(matches))
	}
	for _, m := range matches {
		stage := config.CompositionReasons
		if m[2] == "structural" {
			stage = config.StructuralReasons
		}
		if !slices.Contains(stage, config.Reason(m[1])) {
			t.Errorf("CONFIG.md lists %s as %s, and the package does not", m[1], m[2])
		}
	}
}

type example struct {
	Name          string         `json:"name"`
	Purpose       string         `json:"purpose"`
	Configuration string         `json:"configuration"`
	Manifests     []string       `json:"manifests"`
	Outcome       config.Outcome `json:"outcome"`
}

// The worked examples in examples/ check as their index says.
func TestTheExamplesCheckAsIndexed(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("examples", "index.json"))
	if err != nil {
		t.Fatalf("read the example index: %v", err)
	}
	var index []example
	strict(t, content, &index)
	if len(index) != 6 {
		t.Fatalf("wiring, not the contract: %d examples indexed where 6 are written", len(index))
	}
	runtimeContent, err := os.ReadFile(filepath.Join("examples", "runtime.json"))
	if err != nil {
		t.Fatalf("read the example runtime: %v", err)
	}
	var available config.Available
	strict(t, runtimeContent, &available)
	for _, one := range index {
		t.Run(one.Name, func(t *testing.T) {
			configuration, err := os.ReadFile(filepath.Join("examples", one.Configuration))
			if err != nil {
				t.Fatalf("read %s: %v", one.Configuration, err)
			}
			in := config.Input{Configuration: configuration, Available: available}
			for _, path := range one.Manifests {
				manifest, err := os.ReadFile(filepath.Join("examples", path))
				if err != nil {
					t.Fatalf("read %s: %v", path, err)
				}
				in.Manifests = append(in.Manifests, config.Supplied{Name: strings.TrimSuffix(filepath.Base(path), ".json"), Content: manifest})
			}
			result := config.Check(in)
			if result.Outcome != one.Outcome {
				t.Fatalf("outcome %q, want %q: %v %v", result.Outcome, one.Outcome, keys(result.Structural, gotKey), keys(result.Composition, gotKey))
			}
		})
	}
}

// A member named in another case is not the member. The decoder matches names
// case-insensitively, so without its own refusal "VERSION" reads as the version
// and a configuration CONFIG.md calls malformed is accepted.
func TestAMemberNamedInAnotherCaseIsStructurallyRefused(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("examples", "no-extension.config.json"))
	if err != nil {
		t.Fatalf("read the no-extension example: %v", err)
	}
	control := config.Check(config.Input{Configuration: content, Available: runtime(t)})
	if control.Outcome != config.Accepted {
		t.Fatalf("wiring, not the property: the example itself checks as %q", control.Outcome)
	}
	for _, spelling := range [][2]string{
		{`"version"`, `"VERSION"`},
		{`"retain_plaintext"`, `"Retain_Plaintext"`},
		{`"exec_ends_the_grant"`, `"exec_ends_the_grant", "Boundary": "x"`},
	} {
		changed := bytes.Replace(content, []byte(spelling[0]), []byte(spelling[1]), 1)
		if bytes.Equal(changed, content) {
			t.Fatalf("wiring, not the property: %s is not in the example", spelling[0])
		}
		result := config.Check(config.Input{Configuration: changed, Available: runtime(t)})
		if result.Outcome != config.StructurallyRefused || len(result.Structural) != 1 ||
			result.Structural[0].Reason != config.Malformed {
			t.Errorf("%s checks as %q with %+v", spelling[1], result.Outcome, result.Structural)
		}
	}
}
