package policy

// These cases hold the none-versus-some rule at the against seam and prove
// nothing about Load, which always supplies Inventory(): it has no processor,
// subscriber, non-local, exporting or non-retaining sink, so the SOME states
// are unreachable through Load until the inventory gains that kind.
// policy_load_test.go at the module root tests the public route.
//
// SOME packs are not covered: Available has no pack field and against accepts
// no manifests.

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

func independentRuleConfiguration() config.Configuration {
	yes := true
	bound, every := int64(64), int64(30)
	return config.Configuration{
		Version: "observer.config/draft",
		Observer: config.Observer{
			Log: "stdout", Directory: "/var/lib/observer", SpoolBoundMiB: &bound, StateEverySeconds: &every,
		},
		ObservationScope: config.ObservationScope{
			Targets: []config.Target{{
				Name: "server", Match: config.Match{Exe: "/usr/bin/server"},
				Descendants: config.Descendants{
					Existing: &yes, Future: &yes, Boundary: "exec_ends_the_grant",
					RootExit: "survivors_keep_their_grants", Replacement: "needs_restart",
				},
			}},
			Libraries: []config.Library{},
		},
		TrafficScope:    config.TrafficScope{Rules: []config.TrafficRule{{Direction: "any"}}},
		RetentionExport: config.RetentionExport{RetainPlaintext: &yes, ExportSinks: []string{}},
		Sinks:           []config.Sink{{Name: "account", Kind: "local_account"}},
		Pipelines: []config.Pipeline{
			{Name: "exchanges", Input: "reconstruction", Slots: []config.Slot{}, Sinks: []string{"account"}},
			{Name: "connections", Input: "connection", Slots: []config.Slot{}, Sinks: []string{"account"}},
		},
	}
}

func independentRuleBuiltin(role string) config.Component {
	component := config.Component{
		Interface: "observer.component/draft", Name: "available-but-not-requested", Version: "1",
		Role: role, Execution: "builtin",
		Input: config.Consumes{Types: []string{"reconstruction"}, Delivery: "record"},
		State: "none", Ordering: config.Ordering{Records: "none"},
		Lifecycle: config.Lifecycle{
			Startup: "ignored", ConfigurationChange: "ignored", StreamClosure: "ignored",
			Flush: "ignored", Shutdown: "ignored",
		},
		Failures: []string{"fatal"},
	}
	if role == "processor" {
		component.Output.Records = []string{"reconstruction"}
	} else {
		component.Output.Findings = true
	}
	return component
}

func TestInventoryRuleOnlyDoesNotExerciseLoad(t *testing.T) {
	// Population from CONFIG.md: processors in slots, subscribers, sink kinds,
	// retention and export. Packs have no Available member to vary.
	cases := []struct {
		name, section string
		needs         []Capability
		reason        config.Reason
		configure     func(*config.Configuration)
		addKind       func(*config.Available)
	}{
		{
			name: "processor", section: "pipelines[0].slots", needs: []Capability{Processing}, reason: config.UnknownComponent,
			configure: func(c *config.Configuration) {
				c.Pipelines[0].Slots = []config.Slot{{Name: "transform", Implementation: "missing-processor", OnFailure: "drop_and_account"}}
			},
			addKind: func(has *config.Available) { has.Builtins = []config.Component{independentRuleBuiltin("processor")} },
		},
		{
			name: "subscriber", section: "subscribers", needs: []Capability{Processing}, reason: config.UnknownComponent,
			configure: func(c *config.Configuration) {
				c.Subscribers = []config.Subscriber{{Name: "notes", Stream: "exchanges", Implementation: "missing-subscriber"}}
			},
			addKind: func(has *config.Available) { has.Builtins = []config.Component{independentRuleBuiltin("subscriber")} },
		},
		{
			name: "sink-kind", section: "sinks[1].kind", reason: config.UnknownSinkKind,
			configure: func(c *config.Configuration) {
				c.Sinks = append(c.Sinks, config.Sink{Name: "extra", Kind: "missing-kind"})
			},
			addKind: func(has *config.Available) {
				has.SinkKinds = append(has.SinkKinds, config.SinkKind{Name: "available-kind", Accepts: []string{"connection"}})
			},
		},
		{
			name: "export-sink", section: "retention_and_export.export_sinks", reason: config.UnknownSink,
			configure: func(c *config.Configuration) {
				c.RetentionExport.ExportSinks = []string{"missing-sink"}
			},
			addKind: func(has *config.Available) {
				has.SinkKinds = append(has.SinkKinds, config.SinkKind{Name: "available-export", Accepts: []string{"connection"}, LeavesHost: true})
			},
		},
		{
			name: "non-retaining-sink", section: "retention_and_export.retain_plaintext", needs: []Capability{Processing}, reason: config.RetentionNotPermitted,
			configure: func(c *config.Configuration) {
				no := false
				c.RetentionExport.RetainPlaintext = &no
			},
			addKind: func(has *config.Available) {
				has.SinkKinds = append(has.SinkKinds, config.SinkKind{Name: "available-non-retaining", Accepts: []string{"connection"}, RetainsPlaintext: false})
			},
		},
	}
	for _, c := range cases {
		states := []string{"zero", "some-but-not-requested"}
		if c.name == "processor" || c.name == "subscriber" {
			states = append(states, "opposite-role-only-is-still-zero")
		}
		for _, state := range states {
			t.Run(c.name+"/"+state, func(t *testing.T) {
				some := state == "some-but-not-requested"
				written := independentRuleConfiguration()
				c.configure(&written)
				content, err := json.Marshal(written)
				if err != nil {
					t.Fatal(err)
				}
				has := Inventory()
				if some {
					c.addKind(&has)
				} else if state == "opposite-role-only-is-still-zero" {
					// Only the requested role counts toward SOME.
					otherRole := "processor"
					if c.name == "processor" {
						otherRole = "subscriber"
					}
					has.Builtins = []config.Component{independentRuleBuiltin(otherRole)}
				}
				// Fixture guard: these bytes and this inventory reach the
				// competing composition refusal.
				reference := config.Check(config.Input{Configuration: content, Available: has})
				if reference.Outcome != config.CompositionRefused {
					t.Fatalf("rule fixture did not reach composition: %+v", reference)
				}
				found := false
				for _, finding := range reference.Composition {
					if finding.Reason == c.reason {
						found = true
					}
				}
				if !found {
					t.Fatalf("rule fixture lacks competing %s finding: %+v", c.reason, reference.Composition)
				}
				_, err = against(content, has)
				if !some {
					var got *Unimplemented
					if !errors.As(err, &got) {
						t.Fatalf("rule-only ZERO wants *Unimplemented, got %T: %v", err, err)
					}
					if len(got.Sections) != 1 || got.Sections[0].Path != c.section || !reflect.DeepEqual(append([]Capability(nil), got.Sections[0].Needs...), c.needs) {
						t.Errorf("rule-only ZERO sections = %+v, want %s needing %v", got.Sections, c.section, c.needs)
					}
					return
				}
				var refused *Refused
				if !errors.As(err, &refused) {
					t.Fatalf("rule-only SOME wants *Refused operator error, got %T: %v", err, err)
				}
				var unsupported *Unimplemented
				if errors.As(err, &unsupported) {
					t.Errorf("rule-only SOME was misreported as an unimplemented kind: %v", err)
				}
				if refused.Outcome != config.CompositionRefused || !reflect.DeepEqual(refused.Findings, reference.Composition) {
					t.Errorf("rule-only SOME changed composition findings: %+v; want %+v", refused, reference.Composition)
				}
				if !strings.Contains(err.Error(), string(c.reason)) {
					t.Errorf("rule-only SOME operator error omits %s: %v", c.reason, err)
				}
			})
		}
	}
}
