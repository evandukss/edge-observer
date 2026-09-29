package config_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
)

func processingConfiguration(t *testing.T) config.Configuration {
	t.Helper()
	raw, err := os.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var c config.Configuration
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Packs = nil
	c.Policy = nil
	c.Subscribers = nil
	c.Sinks = []config.Sink{{Name: "account", Kind: "local_account"}}
	c.Pipelines = []config.Pipeline{{Name: "exchanges", Input: "reconstruction", Slots: []config.Slot{}, Sinks: []string{"account"}}}
	return c
}

func processingJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func headerSlot(name, implementation, arguments string) config.Slot {
	return config.Slot{Name: name, Implementation: implementation, Configuration: json.RawMessage(arguments), OnFailure: config.OnFailureDropAndAccount}
}
func processingPack() config.Manifest {
	return config.Manifest{Version: config.ManifestVersion, Name: "profile", PackVersion: "1", Components: []config.Component{}, Pipelines: []config.Pipeline{}, Replacements: []config.Replacement{}, Policy: []json.RawMessage{}}
}
func compileProcessing(t *testing.T, c config.Configuration, packs ...config.Manifest) (*config.ProcessingPlan, []config.Finding) {
	t.Helper()
	var supplied []config.Supplied
	for _, pack := range packs {
		supplied = append(supplied, config.Supplied{Name: pack.Name, Content: processingJSON(t, pack)})
	}
	return config.CompileProcessing(processingJSON(t, c), supplied)
}
func acceptedProcessing(t *testing.T, c config.Configuration, packs ...config.Manifest) *config.ProcessingPlan {
	t.Helper()
	plan, findings := compileProcessing(t, c, packs...)
	if plan == nil || len(findings) != 0 {
		t.Fatalf("neighbour must compile: plan=%+v findings=%+v", plan, findings)
	}
	return plan
}
func refusedProcessing(t *testing.T, c config.Configuration, reason config.Reason, packs ...config.Manifest) []config.Finding {
	t.Helper()
	plan, findings := compileProcessing(t, c, packs...)
	if plan != nil {
		t.Fatalf("refused configuration exposed an executable plan: %+v", plan)
	}
	if len(findings) == 0 {
		t.Fatal("refusal has no deciding rule")
	}
	for _, finding := range findings {
		if finding.Reason != reason || finding.Subject == "" || finding.Detail == "" {
			t.Fatalf("intended fault %s was not the deciding rule: %+v", reason, findings)
		}
	}
	return findings
}

// These are compiler controls, not a substitute executor. The executor must feed each
// accepted neighbour through the real dispatcher and compare output values.
func TestProcessingRefusalNeighbours(t *testing.T) {
	tests := []struct {
		name   string
		reason config.Reason
		valid  func(*config.Configuration)
		fault  func(*config.Configuration)
	}{
		{"unknown-component", config.UnknownComponent, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.RemoveHeaders, `{"headers":["authorization"]}`)}
		}, func(c *config.Configuration) { c.Pipelines[0].Slots[0].Implementation = "missing" }},
		{"subscriber-role", config.UnsupportedRole, func(c *config.Configuration) {}, func(c *config.Configuration) {
			c.Subscribers = []config.Subscriber{{Name: "s", Stream: "exchanges", Implementation: config.RemoveHeaders}}
		}},
		{"raw-durable-input", config.UnsupportedForm, func(c *config.Configuration) {}, func(c *config.Configuration) { c.Pipelines[0].Input = "observation" }},
		{"slot-input-type", config.InputTypeMismatch, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.RemoveHeaders, `{"headers":["authorization"]}`)}
		}, func(c *config.Configuration) { c.Pipelines[0].Input = "connection" }},
		{"queue-role", config.UnsupportedForm, func(c *config.Configuration) {}, func(c *config.Configuration) { c.Pipelines[0].Queues = []config.Queue{{Name: "q"}} }},
		{"unknown-sink-kind", config.UnknownSinkKind, func(c *config.Configuration) {}, func(c *config.Configuration) { c.Sinks[0].Kind = "remote" }},
		{"unknown-argument", config.InvalidBuiltinArguments, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.RemoveHeaders, `{"headers":["authorization"]}`)}
		}, func(c *config.Configuration) {
			c.Pipelines[0].Slots[0].Configuration = json.RawMessage(`{"headers":["authorization"],"regex":true}`)
		}},
		{"header-pattern", config.InvalidBuiltinArguments, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.RemoveHeaders, `{"headers":["authorization"]}`)}
		}, func(c *config.Configuration) {
			c.Pipelines[0].Slots[0].Configuration = json.RawMessage(`{"headers":["auth:.*"]}`)
		}},
		{"negative-length", config.InvalidBuiltinArguments, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.TruncateHeaderValues, `{"headers":["x-public"],"length":0}`)}
		}, func(c *config.Configuration) {
			c.Pipelines[0].Slots[0].Configuration = json.RawMessage(`{"headers":["x-public"],"length":-1}`)
		}},
		{"missing-length", config.InvalidBuiltinArguments, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.TruncateHeaderValues, `{"headers":["x-public"],"length":0}`)}
		}, func(c *config.Configuration) {
			c.Pipelines[0].Slots[0].Configuration = json.RawMessage(`{"headers":["x-public"]}`)
		}},
		{"null-arguments", config.InvalidBuiltinArguments, func(c *config.Configuration) {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.RemoveHeaders, `{"headers":["authorization"]}`)}
		}, func(c *config.Configuration) { c.Pipelines[0].Slots[0].Configuration = json.RawMessage(`null`) }},
		{"unknown-pack", config.UnknownPack, func(c *config.Configuration) {}, func(c *config.Configuration) { c.Packs = []string{"missing"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := processingConfiguration(t)
			test.valid(&c)
			acceptedProcessing(t, c)
			test.fault(&c)
			refusedProcessing(t, c, test.reason)
		})
	}
}

func TestProcessingBoundsNeighbours(t *testing.T) {
	t.Run("fanout-counts-all-pipelines", func(t *testing.T) {
		c := processingConfiguration(t)
		for i := 1; i < config.MaxProcessingFanout; i++ {
			p := c.Pipelines[0]
			p.Name = fmt.Sprint("p", i)
			c.Pipelines = append(c.Pipelines, p)
		}
		plan := acceptedProcessing(t, c)
		if len(plan.Routes()) != config.MaxProcessingFanout {
			t.Fatalf("routes missing at limit: %+v", plan.Routes())
		}
		p := c.Pipelines[0]
		p.Name = "overflow"
		c.Pipelines = append(c.Pipelines, p)
		refusedProcessing(t, c, config.FanoutTooLarge)
	})
	t.Run("slots", func(t *testing.T) {
		c := processingConfiguration(t)
		for i := 0; i < config.MaxProcessingSlots; i++ {
			c.Pipelines[0].Slots = append(c.Pipelines[0].Slots, headerSlot(fmt.Sprint("s", i), config.RemoveHeaders, `{"headers":["authorization"]}`))
		}
		acceptedProcessing(t, c)
		c.Pipelines[0].Slots = append(c.Pipelines[0].Slots, headerSlot("overflow", config.RemoveHeaders, `{"headers":["authorization"]}`))
		refusedProcessing(t, c, config.ConfigurationTooLarge)
	})
	t.Run("encoded-bytes-before-json", func(t *testing.T) {
		raw := processingJSON(t, processingConfiguration(t))
		raw = append(raw, []byte(strings.Repeat(" ", config.MaxProcessingBytes-len(raw)))...)
		plan, findings := config.CompileProcessing(raw, nil)
		if plan == nil || len(findings) != 0 {
			t.Fatalf("byte-limit neighbour refused: %+v", findings)
		}
		plan, findings = config.CompileProcessing(append(raw, ' '), nil)
		if plan != nil || len(findings) != 1 || findings[0].Reason != config.ConfigurationTooLarge {
			t.Fatalf("byte cap not reached: %+v", findings)
		}
	})
	t.Run("header-count", func(t *testing.T) {
		c := processingConfiguration(t)
		headers := make([]string, config.MaxHeaderNames)
		for i := range headers {
			headers[i] = fmt.Sprint("x-", i)
		}
		set := func() {
			c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.RemoveHeaders, string(processingJSON(t, map[string]any{"headers": headers})))}
		}
		set()
		acceptedProcessing(t, c)
		headers = append(headers, "overflow")
		set()
		refusedProcessing(t, c, config.InvalidBuiltinArguments)
	})
}

func TestProcessingReplacementResolvesArgumentsAndFailureAction(t *testing.T) {
	c := processingConfiguration(t)
	c.Packs = []string{"profile"}
	c.Pipelines[0].Slots = []config.Slot{headerSlot("s", config.ReplaceHeaderValues, `{"headers":["x-public"],"value":"abcdef"}`)}
	c.Pipelines[0].Slots[0].OnFailure = config.OnFailureStopPipeline
	p := processingPack()
	p.Replacements = []config.Replacement{{Pipeline: "exchanges", Slot: "s", Implementation: config.TruncateHeaderValues, Configuration: json.RawMessage(`{"headers":["X-Public"],"length":3}`)}}
	plan := acceptedProcessing(t, c, p)
	s := plan.Pipelines()[0].Slots[0]
	if s.Implementation != config.TruncateHeaderValues || s.OnFailure != config.OnFailureStopPipeline || s.SelectedBy != "pack:profile" || !reflect.DeepEqual(s.Arguments, &config.Arguments{Headers: []string{"x-public"}, Length: 3}) {
		t.Fatalf("executor received the wrong resolved slot: %+v", s)
	}
	p.Replacements[0].Configuration = json.RawMessage(`{"headers":["x-public"],"length":-1}`)
	refusedProcessing(t, c, config.InvalidBuiltinArguments, p)
}

func exclusionPolicy(t *testing.T, field, transform string, extras map[string]any) json.RawMessage {
	t.Helper()
	parameters := map[string]any{"field": field, "transformation": transform}
	for k, v := range extras {
		parameters[k] = v
	}
	return processingJSON(t, cp.Document{Vocabulary: cp.Vocabulary, Requirements: []cp.Requirement{{ID: "exclude-auth", Target: cp.Target{Kind: "sink", Name: "account"}, Operation: "transform_field", Parameters: parameters, FailureAction: cp.DropAndAccount}}})
}
func protectedProcessing(t *testing.T) config.Configuration {
	c := processingConfiguration(t)
	c.Pipelines[0].Slots = []config.Slot{headerSlot("remove", config.RemoveHeaders, `{"headers":["Authorization"]}`)}
	c.Policy = []json.RawMessage{exclusionPolicy(t, "message.headers.authorization", "remove", nil)}
	return c
}
func TestProcessingExclusionChecksEveryEffectiveDurableRoute(t *testing.T) {
	c := protectedProcessing(t)
	c.Packs = []string{"profile"}
	c.Sinks = append(c.Sinks, config.Sink{Name: "other", Kind: "local_account"})
	p := processingPack()
	p.Pipelines = []config.Pipeline{{Name: "pack-route", Input: "reconstruction", Slots: []config.Slot{headerSlot("remove", config.RemoveHeaders, `{"headers":["authorization"]}`)}, Sinks: []string{"other"}}}
	plan := acceptedProcessing(t, c, p)
	if len(plan.Routes()) != 2 || len(plan.Exclusions()) != 1 || plan.Exclusions()[0].Header != "authorization" {
		t.Fatalf("incomplete durable plan: %+v", plan)
	}
	p.Pipelines[0].Slots = []config.Slot{}
	findings := refusedProcessing(t, c, config.ExclusionNotEnforced, p)
	if len(findings) != 1 || !strings.Contains(findings[0].Subject, "pack-route") || !strings.Contains(findings[0].Detail, "exclude-auth") {
		t.Fatalf("second route fault not identified: %+v", findings)
	}
}
func TestProcessingTransformNeighbours(t *testing.T) {
	for _, tc := range []struct {
		name, field, transform string
		extra                  map[string]any
		reason                 config.Reason
	}{
		{"unsupported-transform", "message.headers.authorization", "hash", nil, config.UnsupportedTransform},
		{"unsupported-field", "message.start_line", "remove", nil, config.UnsupportedTransform},
		{"unknown-parameter", "message.headers.authorization", "remove", map[string]any{"unknown": 1}, config.InvalidTransformParameters},
		{"unsupported-arguments", "message.headers.authorization", "remove", map[string]any{"arguments": map[string]any{"length": 1}}, config.InvalidTransformParameters},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := protectedProcessing(t)
			acceptedProcessing(t, c)
			c.Policy = []json.RawMessage{exclusionPolicy(t, tc.field, tc.transform, tc.extra)}
			refusedProcessing(t, c, tc.reason)
		})
	}
}
func TestProcessingReportsIndependentRefusalsTogether(t *testing.T) {
	c := processingConfiguration(t)
	c.Pipelines[0].Slots = []config.Slot{headerSlot("a", config.TruncateHeaderValues, `{"headers":["x"],"length":-1}`), headerSlot("b", config.ReplaceHeaderValues, `{"headers":["x"]}`)}
	findings := refusedProcessing(t, c, config.InvalidBuiltinArguments)
	if len(findings) != 2 {
		t.Fatalf("one independently binding reason hidden: %+v", findings)
	}
	c.Pipelines[0].Slots[0].Configuration = json.RawMessage(`{"headers":["x"],"length":3}`)
	if got := refusedProcessing(t, c, config.InvalidBuiltinArguments); len(got) != 1 {
		t.Fatalf("first repair must leave only second refusal: %+v", got)
	}
	c.Pipelines[0].Slots[1].Configuration = json.RawMessage(`{"headers":["x"],"value":"abcdef"}`)
	acceptedProcessing(t, c)
}

func TestProcessingZeroSlotAndNoncommutingPlans(t *testing.T) {
	c := processingConfiguration(t)
	p := acceptedProcessing(t, c)
	if len(p.Pipelines()) != 1 || len(p.Pipelines()[0].Slots) != 0 || len(p.Routes()) != 1 {
		t.Fatalf("zero-slot route is missing: %+v", p)
	}
	c.Pipelines[0].Slots = []config.Slot{headerSlot("replace", config.ReplaceHeaderValues, `{"headers":["x-public"],"value":"abcdef"}`), headerSlot("truncate", config.TruncateHeaderValues, `{"headers":["x-public"],"length":3}`)}
	p = acceptedProcessing(t, c)
	if p.Pipelines()[0].Slots[0].Arguments.Value != "abcdef" || p.Pipelines()[0].Slots[1].Arguments.Length != 3 {
		t.Fatalf("arguments changed: %+v", p.Pipelines()[0].Slots)
	}
	c.Pipelines[0].Slots[0], c.Pipelines[0].Slots[1] = c.Pipelines[0].Slots[1], c.Pipelines[0].Slots[0]
	p = acceptedProcessing(t, c)
	if p.Pipelines()[0].Slots[0].Implementation != config.TruncateHeaderValues || p.Pipelines()[0].Slots[1].Implementation != config.ReplaceHeaderValues {
		t.Fatalf("authored order lost: %+v", p.Pipelines()[0].Slots)
	}
	// Expected runtime outputs on X-Public: original are abc and abcdef,
	// respectively. Only the real dispatcher can establish those outputs.
}

func TestProcessingExclusionFailureActionNeighbours(t *testing.T) {
	for _, required := range []string{config.OnFailureDropAndAccount, config.OnFailureStopPipeline} {
		t.Run(required, func(t *testing.T) {
			c := protectedProcessing(t)
			var document cp.Document
			if err := json.Unmarshal(c.Policy[0], &document); err != nil {
				t.Fatal(err)
			}
			document.Requirements[0].FailureAction = required
			c.Policy[0] = processingJSON(t, document)
			c.Pipelines[0].Slots[0].OnFailure = required
			second := c.Pipelines[0]
			second.Name = "second"
			second.Slots = []config.Slot{c.Pipelines[0].Slots[0]}
			c.Pipelines = append(c.Pipelines, second)
			plan := acceptedProcessing(t, c)
			if len(plan.Routes()) != 2 || plan.Exclusions()[0].FailureAction != required {
				t.Fatalf("failure action missing from the accepted plan: routes=%+v exclusions=%+v", plan.Routes(), plan.Exclusions())
			}
			other := config.OnFailureDropAndAccount
			if required == other {
				other = config.OnFailureStopPipeline
			}
			c.Pipelines[1].Slots[0].OnFailure = other
			if c.Pipelines[0].Slots[0].OnFailure != required {
				t.Fatal("fixture changed the first route instead of only the second")
			}
			findings := refusedProcessing(t, c, config.ExclusionFailureActionMismatch)
			if len(findings) != 1 || findings[0].Subject != "route:second->account" || !strings.Contains(findings[0].Detail, "exclude-auth") || !strings.Contains(findings[0].Detail, required) {
				t.Fatalf("wrong route or deciding failure action: %+v", findings)
			}
		})
	}
}
