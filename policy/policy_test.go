package policy_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

func written(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// example is the contract's no-extension example, decoded so a case can change
// one member of it.
func example(t *testing.T) map[string]any {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatalf("read the no-extension example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-extension example: %v", err)
	}
	return document
}

func encoded(t *testing.T, document map[string]any) string {
	t.Helper()
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(content)
}

func member(document map[string]any, path ...string) map[string]any {
	at := document
	for _, name := range path {
		at = at[name].(map[string]any)
	}
	return at
}

func descendants(existing, future bool) map[string]any {
	return map[string]any{
		"existing": existing, "future": future,
		"boundary": "exec_ends_the_grant", "root_exit": "survivors_keep_their_grants", "replacement": "needs_restart",
	}
}

func target(name string, match map[string]any, existing, future bool) map[string]any {
	return map[string]any{"name": name, "match": match, "descendants": descendants(existing, future)}
}

// whole is the example with every kind of target, an exclusion, a library and
// both optional settings written.
func whole(t *testing.T) map[string]any {
	document := example(t)
	observer := member(document, "observer")
	observer["log"], observer["directory"] = "/var/log/observer/observer.log", "/var/lib/observer"
	observer["spool_bound_mib"], observer["state_every_seconds"] = 32, 10
	scope := member(document, "observation_scope")
	scope["targets"] = []any{
		target("gateway", map[string]any{"exe": "/usr/bin/php", "args": []any{"/srv/gateway/main.php"}}, true, true),
		target("worker", map[string]any{"cgroup": "/system.slice/worker.service"}, true, false),
		target("legacy", map[string]any{"pid": map[string]any{"pid": 8127, "start": 991, "boot": "8f3d"}}, false, false),
		target("front", map[string]any{"port": 8443, "interface": "eth0"}, true, true),
		target("bare", map[string]any{"exe": "/usr/bin/daemon", "args": []any{}}, false, false),
	}
	scope["exclude"] = []any{map[string]any{"exe": "/usr/bin/curl", "args": []any{"-s"}}}
	scope["libraries"] = []any{map[string]any{"build_id": "77b686c8727edee8124fcc6d0e4d4539c545cbcf",
		"symbols": map[string]any{"SSL_read": 123}}}
	return document
}

// The contract's simplest example is read by the program.
func TestTheNoExtensionExampleIsRead(t *testing.T) {
	content, err := config.Examples.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatalf("read the no-extension example: %v", err)
	}
	read, err := policy.Load(written(t, string(content)))
	if err != nil {
		t.Fatalf("the contract's no-extension example is refused: %v", err)
	}
	if len(read.Approval.Rules) != 1 || read.Approval.Rules[0].Name != "api-server" ||
		read.Approval.Rules[0].Executable != "/usr/bin/php" ||
		!slices.Equal(read.Approval.Rules[0].Arguments, []string{"/srv/api/main.php"}) {
		t.Errorf("its target read as %+v", read.Approval.Rules)
	}
	if read.Settings.Log != policy.Stdout || read.Settings.Directory != "/var/lib/observer" ||
		read.Settings.BoundMiB != 64 || read.Settings.StateEvery != 30*time.Second {
		t.Errorf("its settings read as %+v", read.Settings)
	}
}

// Everything the file states arrives where the observer reads it, with the
// mode each target's two descendant answers name.
func TestTheFileIsReadWhole(t *testing.T) {
	read, err := policy.Load(written(t, encoded(t, whole(t))))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	settings := read.Settings
	if settings.Log != "/var/log/observer/observer.log" || settings.Directory != "/var/lib/observer" ||
		settings.BoundMiB != 32 || settings.StateEvery != 10*time.Second {
		t.Errorf("settings read as %+v", settings)
	}

	rules := read.Approval.Rules
	if len(rules) != 5 {
		t.Fatalf("%d targets read, want 5", len(rules))
	}
	var names []string
	var modes []admission.Mode
	for _, rule := range rules {
		names = append(names, rule.Name)
		modes = append(modes, rule.Mode)
	}
	if !slices.Equal(names, []string{"gateway", "worker", "legacy", "front", "bare"}) {
		t.Errorf("targets read as %v", names)
	}
	if !slices.Equal(modes, []admission.Mode{admission.ModeFollow, admission.ModeExisting, admission.ModeNone,
		admission.ModeFollow, admission.ModeNone}) {
		t.Errorf("modes read as %v", modes)
	}
	if rules[0].Executable != "/usr/bin/php" || !slices.Equal(rules[0].Arguments, []string{"/srv/gateway/main.php"}) {
		t.Errorf("the first target read as %+v", rules[0])
	}
	if rules[1].Cgroup != "/system.slice/worker.service" {
		t.Errorf("the cgroup target read as %+v", rules[1])
	}
	if guard := rules[2].PID; guard == nil || guard.PID != 8127 || guard.Start != 991 || guard.Boot != "8f3d" {
		t.Errorf("the pid target read as %+v", rules[2].PID)
	}
	if rules[3].Port != 8443 || rules[3].Interface != "eth0" {
		t.Errorf("the port target read as %+v", rules[3])
	}
	// An explicit empty list means no arguments after argv[0].
	if rules[4].Arguments == nil || len(rules[4].Arguments) != 0 {
		t.Errorf("an explicit empty argument list read as %#v", rules[4].Arguments)
	}

	if len(read.Approval.Exclusions) != 1 || read.Approval.Exclusions[0].Executable != "/usr/bin/curl" ||
		!slices.Equal(read.Approval.Exclusions[0].Arguments, []string{"-s"}) {
		t.Errorf("exclusions read as %+v", read.Approval.Exclusions)
	}
	if len(read.Approval.Libraries) != 1 || read.Approval.Libraries[0].Symbols["SSL_read"] != 123 ||
		read.Approval.Libraries[0].BuildID != "77b686c8727edee8124fcc6d0e4d4539c545cbcf" {
		t.Errorf("libraries read as %+v", read.Approval.Libraries)
	}
	if read.Revision == "" {
		t.Error("the file read carries no revision")
	}
}

// The revision names the content: one file read twice is one revision, two
// different files are two.
func TestTheRevisionNamesTheContent(t *testing.T) {
	first, err := policy.Load(written(t, encoded(t, whole(t))))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	again, err := policy.Load(written(t, encoded(t, whole(t))))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	changed := whole(t)
	member(changed, "observer")["spool_bound_mib"] = 33
	other, err := policy.Load(written(t, encoded(t, changed)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if first.Revision != again.Revision {
		t.Errorf("one file read twice gave revisions %q and %q", first.Revision, again.Revision)
	}
	if first.Revision == other.Revision {
		t.Errorf("two different files share revision %q", first.Revision)
	}
}

// Each descendant pair a mode gives becomes that mode, and the mode answers
// exactly the pair written.
func TestEachDescendantPairBecomesTheModeThatAnswersIt(t *testing.T) {
	for _, pair := range []struct {
		existing, future bool
		mode             admission.Mode
	}{
		{false, false, admission.ModeNone},
		{true, false, admission.ModeExisting},
		{true, true, admission.ModeFollow},
	} {
		document := example(t)
		member(document, "observation_scope")["targets"] = []any{
			target("api-server", map[string]any{"exe": "/usr/bin/php"}, pair.existing, pair.future)}
		read, err := policy.Load(written(t, encoded(t, document)))
		if err != nil {
			t.Fatalf("existing %t future %t refused: %v", pair.existing, pair.future, err)
		}
		mode := read.Approval.Rules[0].Mode
		if mode != pair.mode {
			t.Errorf("existing %t future %t read as mode %s, want %s", pair.existing, pair.future, mode, pair.mode)
		}
		answers := mode.Answers()
		if answers.Existing != pair.existing || answers.Future != pair.future {
			t.Errorf("existing %t future %t became %s, which answers existing %t future %t",
				pair.existing, pair.future, mode, answers.Existing, answers.Future)
		}
	}
}

// Future descendants without existing ones is well formed and no mode gives
// it, so it is refused naming the target rather than read as another mode.
func TestTheFourthDescendantPairIsRefused(t *testing.T) {
	document := example(t)
	member(document, "observation_scope")["targets"] = []any{
		target("api-server", map[string]any{"exe": "/usr/bin/php"}, false, true)}
	_, err := policy.Load(written(t, encoded(t, document)))
	var refused *policy.Unanswerable
	if !errors.As(err, &refused) {
		t.Fatalf("existing false future true gave %v, want an Unanswerable refusal", err)
	}
	if refused.Target != "api-server" || refused.Existing || !refused.Future {
		t.Errorf("the refusal names %+v", *refused)
	}
}

// A fixed answer admission does not give is refused by the contract's check.
func TestAFixedAnswerThatIsNotAdmissionsIsRefused(t *testing.T) {
	document := example(t)
	stated := descendants(true, true)
	stated["root_exit"] = "the_family_goes_with_the_root"
	member(document, "observation_scope")["targets"] = []any{
		map[string]any{"name": "api-server", "match": map[string]any{"exe": "/usr/bin/php"}, "descendants": stated}}
	_, err := policy.Load(written(t, encoded(t, document)))
	var refused *policy.Refused
	if !errors.As(err, &refused) {
		t.Fatalf("a root_exit admission does not give was answered %v", err)
	}
	if refused.Outcome != config.CompositionRefused || len(refused.Findings) != 1 ||
		refused.Findings[0].Reason != config.DescendantAnswerNotSupported {
		t.Errorf("refused as %+v", *refused)
	}
}

// The inventory's fixed answers are admission's, in the contract's words.
func TestTheInventoryStatesAdmissionsFixedAnswers(t *testing.T) {
	fixed := policy.Inventory().Descendants
	if fixed.Boundary != "exec_ends_the_grant" || fixed.RootExit != "survivors_keep_their_grants" ||
		fixed.Replacement != "needs_restart" {
		t.Errorf("the inventory states %+v", fixed)
	}
}

// Every section the contract accepts and this program does not do is refused,
// named by its path, with what it needs.
func TestWhatThisProgramDoesNotDoIsRefusedByName(t *testing.T) {
	slot := map[string]any{"name": "redact", "implementation": "http-redactor", "on_failure": "stop_pipeline"}
	cases := map[string]struct {
		change func(document map[string]any)
		path   string
		needs  []policy.Capability
	}{
		"a slot in a pipeline": {func(d map[string]any) {
			d["pipelines"].([]any)[0].(map[string]any)["slots"] = []any{slot}
		}, "pipelines[0].slots", []policy.Capability{policy.Processing}},
		"a pack": {func(d map[string]any) { d["packs"] = []any{"swap-redactor"} },
			"packs", []policy.Capability{policy.Processing, policy.Plugins}},
		"a subscriber": {func(d map[string]any) {
			d["subscribers"] = []any{map[string]any{"name": "notes", "stream": "exchanges", "implementation": "annotation-subscriber"}}
		}, "subscribers", []policy.Capability{policy.Processing}},
		"a policy document": {func(d map[string]any) {
			d["policy"] = []any{map[string]any{"vocabulary": "observer.policy/draft", "requirements": []any{}}}
		}, "policy", []policy.Capability{policy.Processing}},
		"plaintext not retained": {func(d map[string]any) {
			member(d, "retention_and_export")["retain_plaintext"] = false
		}, "retention_and_export.retain_plaintext", []policy.Capability{policy.Processing}},
		"a traffic rule naming a target": {func(d map[string]any) {
			member(d, "traffic_scope")["rules"].([]any)[0].(map[string]any)["targets"] = []any{"api-server"}
		}, "traffic_scope.rules[0]", []policy.Capability{policy.Processing}},
		"a traffic rule naming a direction": {func(d map[string]any) {
			member(d, "traffic_scope")["rules"].([]any)[0].(map[string]any)["direction"] = "inbound"
		}, "traffic_scope.rules[0]", []policy.Capability{policy.Processing}},
		"a traffic rule naming a local port": {func(d map[string]any) {
			member(d, "traffic_scope")["rules"].([]any)[0].(map[string]any)["local_ports"] = []any{8443}
		}, "traffic_scope.rules[0]", []policy.Capability{policy.Processing}},
		"a traffic rule naming a remote port": {func(d map[string]any) {
			member(d, "traffic_scope")["rules"].([]any)[0].(map[string]any)["remote_ports"] = []any{443}
		}, "traffic_scope.rules[0]", []policy.Capability{policy.Processing}},
		"a sink of another kind": {func(d map[string]any) {
			d["sinks"] = append(d["sinks"].([]any), map[string]any{"name": "summary", "kind": "stdout_summary"})
		}, "sinks[1].kind", nil},
		"an export sink": {func(d map[string]any) {
			member(d, "retention_and_export")["export_sinks"] = []any{"account"}
		}, "retention_and_export.export_sinks", nil},
		"no pipeline carrying reconstructions": {func(d map[string]any) {
			d["pipelines"] = d["pipelines"].([]any)[1:]
		}, "pipelines", []policy.Capability{policy.Processing}},
		"no pipeline carrying connections": {func(d map[string]any) {
			d["pipelines"] = d["pipelines"].([]any)[:1]
		}, "pipelines", []policy.Capability{policy.Processing}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			document := example(t)
			c.change(document)
			_, err := policy.Load(written(t, encoded(t, document)))
			var refused *policy.Unimplemented
			if !errors.As(err, &refused) {
				t.Fatalf("answered %v, want an Unimplemented refusal", err)
			}
			if len(refused.Sections) != 1 {
				t.Fatalf("%d sections named where one was changed: %+v", len(refused.Sections), refused.Sections)
			}
			section := refused.Sections[0]
			if section.Path != c.path || !slices.Equal(section.Needs, c.needs) {
				t.Errorf("named %s needing %v, want %s needing %v", section.Path, section.Needs, c.path, c.needs)
			}
			if !strings.Contains(err.Error(), c.path) {
				t.Errorf("the message does not name %s: %v", c.path, err)
			}
			text := "no configuration enables it"
			if len(c.needs) == 1 {
				text = "it needs configurable processing"
			} else if len(c.needs) == 2 {
				text = "it needs configurable processing and executable plugins"
			}
			if !strings.Contains(err.Error(), text) {
				t.Errorf("the message does not say %q: %v", text, err)
			}
		})
	}
}

// Several unimplemented sections are all named at once.
func TestEverySectionNotDoneIsNamedAtOnce(t *testing.T) {
	document := example(t)
	document["packs"] = []any{"swap-redactor"}
	member(document, "retention_and_export")["retain_plaintext"] = false
	_, err := policy.Load(written(t, encoded(t, document)))
	var refused *policy.Unimplemented
	if !errors.As(err, &refused) {
		t.Fatalf("answered %v, want an Unimplemented refusal", err)
	}
	var paths []string
	for _, section := range refused.Sections {
		paths = append(paths, section.Path)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"packs", "retention_and_export.retain_plaintext"}) {
		t.Errorf("named %v", paths)
	}
}

// A file the contract refuses is refused as that before anything is said
// about what this program implements.
func TestTheContractRefusesBeforeTheProgramDoes(t *testing.T) {
	document := example(t)
	document["version"] = "observer.config/v9"
	document["packs"] = []any{"swap-redactor"}
	_, err := policy.Load(written(t, encoded(t, document)))
	var refused *policy.Refused
	if !errors.As(err, &refused) || refused.Outcome != config.StructurallyRefused {
		t.Fatalf("answered %v, want a structural refusal", err)
	}
	var unimplemented *policy.Unimplemented
	if errors.As(err, &unimplemented) {
		t.Error("an unimplemented section was reported on a document the contract refuses")
	}
}

// A member name differing from the contract's only in case is not that member:
// read as it, "Packs" after an empty "packs" would be accepted and ignored.
func TestAMemberNameInAnotherCaseIsRefused(t *testing.T) {
	base := encoded(t, example(t))
	for name, content := range map[string]string{
		"the version in capitals":    strings.Replace(base, `"version"`, `"VERSION"`, 1),
		"a second spelling of packs": strings.Replace(base, `"packs":[]`, `"packs":[],"Packs":["swap-redactor"]`, 1),
		"a nested member":            strings.Replace(base, `"spool_bound_mib"`, `"Spool_Bound_MiB"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if content == base {
				t.Fatal("wiring, not the property: the replacement changed nothing, so the case reads the example")
			}
			_, err := policy.Load(written(t, content))
			var refused *policy.Refused
			if !errors.As(err, &refused) || refused.Outcome != config.StructurallyRefused {
				t.Fatalf("answered %v, want a structural refusal", err)
			}
		})
	}
}

// Files that say something other than their author believes are refused.
func TestLoadRefuses(t *testing.T) {
	cases := map[string]func(document map[string]any) string{
		"a file that is not JSON": func(map[string]any) string { return `observer: {log: stdout}` },
		"two documents in one file": func(d map[string]any) string {
			return encoded(t, d) + `{}`
		},
		"a member the form does not define": func(d map[string]any) string {
			d["attach"] = []any{}
			return encoded(t, d)
		},
		"two targets with one name": func(d map[string]any) string {
			scope := member(d, "observation_scope")
			scope["targets"] = append(scope["targets"].([]any), scope["targets"].([]any)[0])
			return encoded(t, d)
		},
		"a target naming no condition": func(d map[string]any) string {
			member(d, "observation_scope")["targets"] = []any{target("a", map[string]any{}, false, false)}
			return encoded(t, d)
		},
		"a file selecting nothing": func(d map[string]any) string {
			member(d, "observation_scope")["targets"] = []any{}
			return encoded(t, d)
		},
		"a relative directory": func(d map[string]any) string {
			member(d, "observer")["directory"] = "state"
			return encoded(t, d)
		},
		"a spool bound of zero": func(d map[string]any) string {
			member(d, "observer")["spool_bound_mib"] = 0
			return encoded(t, d)
		},
		"a pipeline input the core does not emit": func(d map[string]any) string {
			d["pipelines"] = append(d["pipelines"].([]any), map[string]any{"name": "notes", "input": "annotation",
				"slots": []any{}, "sinks": []any{"account"}, "queues": []any{}})
			return encoded(t, d)
		},
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := policy.Load(written(t, content(example(t))))
			var refused *policy.Refused
			if !errors.As(err, &refused) {
				t.Fatalf("answered %v, want the contract's refusal", err)
			}
		})
	}
}

func TestLoadRefusesAFileThatIsNotThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	_, err := policy.Load(path)
	if err == nil {
		t.Fatal("Load accepted a file that does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file it looked for: %v", err)
	}
}
