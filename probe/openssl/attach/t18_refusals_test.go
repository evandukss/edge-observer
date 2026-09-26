//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
)

// t18Pack installs a configuration-only pack named name beside c's
// configuration, with these replacements and components.
func t18Pack(t *testing.T, c configured, name string, replacements []map[string]any, components []config.Component) {
	t.Helper()
	if replacements == nil {
		replacements = []map[string]any{}
	}
	if components == nil {
		components = []config.Component{}
	}
	manifest := map[string]any{"version": config.ManifestVersion, "name": name, "pack_version": "0.1.0",
		"components": components, "pipelines": []any{}, "replacements": replacements, "policy": []any{}}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode pack %s: %v", name, err)
	}
	directory := filepath.Join(filepath.Dir(c.path), "packs")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("make %s: %v", directory, err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".json"), content, 0o600); err != nil {
		t.Fatalf("install pack %s: %v", name, err)
	}
}

// t18Excluding is a policy requirement that the account sink never receives
// the authorization header, with these extra parameters.
func t18Excluding(t *testing.T, extra map[string]any) func(map[string]any) {
	t.Helper()
	parameters := map[string]any{"field": "message.headers.authorization", "transformation": "remove"}
	for name, value := range extra {
		parameters[name] = value
	}
	rule, err := json.Marshal(cp.Document{Vocabulary: cp.Vocabulary, Requirements: []cp.Requirement{{ID: "t18-exclude-authorization",
		Target: cp.Target{Kind: "sink", Name: "account"}, Operation: "transform_field", Parameters: parameters,
		FailureAction: cp.DropAndAccount}}})
	if err != nil {
		t.Fatalf("encode the requirement: %v", err)
	}
	return func(document map[string]any) { document["policy"] = []any{json.RawMessage(rule)} }
}

// t18Pipelines replaces the configuration's pipelines.
func t18Pipelines(pipelines ...map[string]any) func(map[string]any) {
	return func(document map[string]any) {
		written := []any{}
		for _, one := range pipelines {
			written = append(written, one)
		}
		document["pipelines"] = written
	}
}

func t18Removal(name string) map[string]any {
	return t18Slot(name, "remove-headers", `{"headers":["authorization"]}`)
}

// t18External is a component a pack declares and the program does not run.
func t18External() config.Component {
	return config.Component{
		Interface: config.ComponentVersion, Name: "t18-external", Version: "1.0.0",
		Role: config.RoleProcessor, Execution: config.ExecutionExternal,
		Input:  config.Consumes{Types: []string{"reconstruction"}, Delivery: config.DeliveryRecord},
		Output: config.Output{Records: []string{"reconstruction"}, Derived: []string{}},
		State:  config.StateNone, Ordering: config.Ordering{Records: config.RecordsNone, After: []string{}, Before: []string{}},
		Lifecycle: config.Lifecycle{Startup: config.HookIgnored, ConfigurationChange: config.HookIgnored,
			StreamClosure: config.HookIgnored, Flush: config.HookIgnored, Shutdown: config.HookIgnored},
		Failures: []string{config.FailureRecord, config.FailureFatal, config.FailureConfiguration},
	}
}

// Row 11's refusals at LIVE activation. Each fault is started by the program
// in an envelope that would let it activate, so the only thing that can stop it
// is the configuration: it must exit non-zero naming the reason, before it has
// made even its state directory. Beside each is the neighbouring configuration,
// one change away, which must activate and write the exchange with the
// credential removed - or a program refusing everything would pass.
func TestT18EachRefusalHappensAtActivationBesideANeighbourThatWrites(t *testing.T) {
	binary := built(t)
	port := t18Serving(t)
	right := map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"}
	removals := func(n int) []map[string]any {
		slots := make([]map[string]any, n)
		for i := range slots {
			slots[i] = t18Removal(fmt.Sprint("remove-", i))
		}
		return slots
	}
	// Fan-out is counted per input type, so n is the reconstruction routes and
	// the connection route beside them is not one of them.
	routes := func(n int) func(map[string]any) {
		pipelines := []map[string]any{t18Pipeline("connections", "connection")}
		for i := 1; i <= n; i++ {
			pipelines = append(pipelines, t18Pipeline(fmt.Sprint("exchanges-", i), "reconstruction", t18Removal("remove")))
		}
		return t18Pipelines(pipelines...)
	}
	type setup func(t *testing.T, c configured)
	edits := func(edits ...func(map[string]any)) setup {
		return func(t *testing.T, c configured) { t18Edit(t, c, edits...) }
	}
	replacing := func(implementation, arguments string) setup {
		return func(t *testing.T, c configured) {
			t18Edit(t, c, t18Excluding(t, nil), func(document map[string]any) { document["packs"] = []any{"t18-replacing"} })
			t18Pack(t, c, "t18-replacing", []map[string]any{{"pipeline": "exchanges", "slot": "remove",
				"implementation": implementation, "configuration": json.RawMessage(arguments)}}, nil)
		}
	}
	external := func(components []config.Component) setup {
		return func(t *testing.T, c configured) {
			t18Edit(t, c, func(document map[string]any) { document["packs"] = []any{"t18-external"} })
			t18Pack(t, c, "t18-external", nil, components)
		}
	}
	for _, tc := range []struct {
		name      string
		reason    config.Reason
		neighbour setup
		fault     setup
	}{
		{"an unknown argument", config.InvalidBuiltinArguments, edits(),
			edits(t18Pipelines(t18Pipeline("exchanges", "reconstruction",
				t18Slot("remove", "remove-headers", `{"headers":["authorization"],"regex":true}`)), t18Pipeline("connections", "connection")))},
		{"an unsupported role", config.UnsupportedRole, edits(),
			edits(func(document map[string]any) {
				document["subscribers"] = []any{map[string]any{"name": "t18-listener", "stream": "exchanges", "implementation": "remove-headers"}}
			})},
		{"an unknown component", config.UnknownComponent, edits(),
			edits(t18Pipelines(t18Pipeline("exchanges", "reconstruction",
				t18Slot("remove", "t18-no-such-component", `{"headers":["authorization"]}`)), t18Pipeline("connections", "connection")))},
		{"an external component", config.UnsupportedComponent, external(nil), external([]config.Component{t18External()})},
		{"slots above the maximum", config.ConfigurationTooLarge,
			edits(t18Pipelines(t18Pipeline("exchanges", "reconstruction", removals(config.MaxProcessingSlots)...), t18Pipeline("connections", "connection"))),
			edits(t18Pipelines(t18Pipeline("exchanges", "reconstruction", removals(config.MaxProcessingSlots+1)...), t18Pipeline("connections", "connection")))},
		{"routes above the fan-out", config.FanoutTooLarge, edits(routes(config.MaxProcessingFanout)), edits(routes(config.MaxProcessingFanout + 1))},
		{"a requirement the replacement leaves unsatisfied", config.ExclusionNotEnforced,
			replacing("remove-headers", `{"headers":["authorization","x-t18"]}`),
			replacing("replace-header-values", `{"headers":["authorization"],"value":"t18-replaced"}`)},
		{"an exclusion missing from one durable route", config.ExclusionNotEnforced,
			edits(t18Excluding(t, nil), t18Pipelines(t18Pipeline("exchanges", "reconstruction", t18Removal("remove")),
				t18Pipeline("exchanges-again", "reconstruction", t18Removal("remove")), t18Pipeline("connections", "connection"))),
			edits(t18Excluding(t, nil), t18Pipelines(t18Pipeline("exchanges", "reconstruction", t18Removal("remove")),
				t18Pipeline("exchanges-again", "reconstruction"), t18Pipeline("connections", "connection")))},
		{"an unknown requirement parameter", config.InvalidTransformParameters,
			edits(t18Excluding(t, nil)), edits(t18Excluding(t, map[string]any{"t18-unknown": 1}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("refused", func(t *testing.T) {
				client := speaking(t, port)
				c := configuring(t, target("client", client.process))
				t18Edit(t, c, t18Removing)
				tc.fault(t, c)
				launched := t18Launch(t, binary, t18Envelope(t, right), "start", c.path)
				if _, activated := launched.activation(t, 30*time.Second); activated {
					t.Fatalf("the program activated over %s", tc.name)
				}
				err := launched.exit(t, 30*time.Second)
				if err == nil || !strings.Contains(launched.stderr.String(), ": "+string(tc.reason)+": ") {
					t.Fatalf("the start ended %v, not naming %s:\n%s", err, tc.reason, launched.stderr)
				}
				if _, err := os.Stat(c.directory); !os.IsNotExist(err) {
					t.Errorf("the refused start made its state directory (%v): %v", err, t18Files(t, c.directory))
				}
				if left := runningWith(t, c.path); len(left) != 0 {
					t.Errorf("the refused start left %v running", left)
				}
			})
			t.Run("neighbour", func(t *testing.T) {
				client := speaking(t, port)
				c := configuring(t, target("client", client.process))
				t18Edit(t, c, t18Removing)
				tc.neighbour(t, c)
				s := t18Started(t, binary, c)
				t18Ask(t, client, "/?asked=t18-neighbour", "Authorization: Bearer t18-neighbour-secret")
				t18Hangup(client)
				t18Settled(t, binary, c, s, 1, 10*time.Second)
				s.stop(t, c)
				written := t18Approved(t, s.directory(c))
				if !slices.Contains(t18Targets(written), "/?asked=t18-neighbour") {
					t.Errorf("the neighbour activated and wrote no exchange: %v", t18Targets(written))
				}
				if holding := t18Holding(t, c.directory, "t18-neighbour-secret"); len(holding) != 0 {
					t.Errorf("the credential reached %v", holding)
				}
			})
		})
	}
}
