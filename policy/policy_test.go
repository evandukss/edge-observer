package policy_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// example is the contract's example that watches one program and removes
// nothing, decoded so a case can change one member of it.
func example(t *testing.T) map[string]any {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatalf("read the no-rules example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-rules example: %v", err)
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

// member is the object at path, made where it is absent.
func member(document map[string]any, path ...string) map[string]any {
	at := document
	for _, name := range path {
		next, ok := at[name].(map[string]any)
		if !ok {
			next = map[string]any{}
			at[name] = next
		}
		at = next
	}
	return at
}

// watching is one watch entry: a name, its conditions and its children answer.
func watching(name string, match map[string]any, children string) map[string]any {
	entry := map[string]any{"name": name, "children": children}
	for key, value := range match {
		entry[key] = value
	}
	return entry
}

func compiled(t *testing.T, document map[string]any, packs ...config.Supplied) policy.Policy {
	t.Helper()
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), packs)
	if err != nil || read.Processing == nil {
		t.Fatalf("refused: %v", err)
	}
	return read
}

// whole is the example with every kind of watch entry, an ignore entry, a
// library and every limit written.
func whole(t *testing.T) map[string]any {
	document := example(t)
	document["log"], document["output"] = "/var/log/observer/observer.log", "/var/lib/observer"
	document["limits"] = map[string]any{"output_mib": 32, "state_every_seconds": 10}
	document["watch"] = []any{
		watching("gateway", map[string]any{"exe": "/usr/bin/php", "args": []any{"/srv/gateway/main.php"}}, "all"),
		watching("worker", map[string]any{"cgroup": "/system.slice/worker.service"}, "existing"),
		watching("legacy", map[string]any{"pid": map[string]any{"pid": 8127, "start": 991, "boot": "8f3d"}}, "none"),
		watching("front", map[string]any{"port": 8443, "interface": "eth0"}, "all"),
		watching("bare", map[string]any{"exe": "/usr/bin/daemon", "args": []any{}}, "none"),
	}
	document["ignore"] = []any{map[string]any{"exe": "/usr/bin/curl", "args": []any{"-s"}}}
	document["libraries"] = []any{map[string]any{"build_id": "77b686c8727edee8124fcc6d0e4d4539c545cbcf",
		"symbols": map[string]any{"SSL_read": 123}}}
	return document
}

// The contract's simplest example is read by the program.
func TestTheNoRulesExampleIsRead(t *testing.T) {
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatalf("read the no-rules example: %v", err)
	}
	read, err := policy.CompileProcessing(content, nil)
	if err != nil {
		t.Fatalf("the contract's no-rules example is refused: %v", err)
	}
	if len(read.Approval.Rules) != 1 || read.Approval.Rules[0].Name != "api-server" ||
		read.Approval.Rules[0].Executable != "/usr/bin/php" ||
		!slices.Equal(read.Approval.Rules[0].Arguments, []string{"/srv/api/main.php"}) {
		t.Errorf("its watch entry read as %+v", read.Approval.Rules)
	}
	if read.Settings.Log != policy.Stdout || read.Settings.Directory != "/var/lib/observer" ||
		read.Settings.ApprovedOutputBoundMiB != 64 || read.Settings.StateEvery != 30*time.Second {
		t.Errorf("its settings read as %+v", read.Settings)
	}
}

// Everything the file states arrives where the observer reads it, with the
// mode each watch entry's children answer names.
func TestTheFileIsReadWhole(t *testing.T) {
	read := compiled(t, whole(t))

	settings := read.Settings
	if settings.Log != "/var/log/observer/observer.log" || settings.Directory != "/var/lib/observer" ||
		settings.ApprovedOutputBoundMiB != 32 || settings.StateEvery != 10*time.Second {
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
	first := compiled(t, whole(t))
	again := compiled(t, whole(t))
	changed := whole(t)
	member(changed, "limits")["output_mib"] = 33
	other := compiled(t, changed)
	if first.Revision != again.Revision {
		t.Errorf("one file read twice gave revisions %q and %q", first.Revision, again.Revision)
	}
	if first.Revision == other.Revision {
		t.Errorf("two different files share revision %q", first.Revision)
	}
}

// Each children answer becomes the mode that answers it, and the mode answers
// exactly the pair it stands for.
func TestEachChildrenAnswerBecomesTheModeThatAnswersIt(t *testing.T) {
	for _, pair := range []struct {
		children         string
		existing, future bool
		mode             admission.Mode
	}{
		{"none", false, false, admission.ModeNone},
		{"existing", true, false, admission.ModeExisting},
		{"all", true, true, admission.ModeFollow},
	} {
		document := example(t)
		document["watch"] = []any{watching("api-server", map[string]any{"exe": "/usr/bin/php"}, pair.children)}
		read := compiled(t, document)
		mode := read.Approval.Rules[0].Mode
		if mode != pair.mode {
			t.Errorf("children %s read as mode %s, want %s", pair.children, mode, pair.mode)
		}
		answers := mode.Answers()
		if answers.Existing != pair.existing || answers.Future != pair.future {
			t.Errorf("children %s became %s, which answers existing %t future %t",
				pair.children, mode, answers.Existing, answers.Future)
		}
	}
}

// A key in another case is not that key: read as it, "Log" after "log" would
// be accepted and one of the two ignored.
func TestAKeyInAnotherCaseIsRefused(t *testing.T) {
	base := encoded(t, whole(t))
	for name, content := range map[string]string{
		"the version in capitals":  strings.Replace(base, `"version"`, `"VERSION"`, 1),
		"a second spelling of log": strings.Replace(base, `"log"`, `"Log":"stdout","log"`, 1),
		"a nested key":             strings.Replace(base, `"output_mib"`, `"Output_MiB"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if content == base {
				t.Fatal("wiring, not the property: the replacement changed nothing, so the case reads the example")
			}
			_, err := policy.CompileProcessing([]byte(content), nil)
			var refused *policy.Refused
			if !errors.As(err, &refused) {
				t.Fatalf("answered %v, want the reader's refusal", err)
			}
		})
	}
}

// Files that say something other than their author believes are refused.
func TestAFileThatSaysSomethingElseIsRefused(t *testing.T) {
	cases := map[string]func(document map[string]any) string{
		"a file that is not JSON": func(map[string]any) string { return `output: /var/lib/observer` },
		"two documents in one file": func(d map[string]any) string {
			return encoded(t, d) + `{}`
		},
		"a key the form does not define": func(d map[string]any) string {
			d["attach"] = []any{}
			return encoded(t, d)
		},
		"two watch entries with one name": func(d map[string]any) string {
			d["watch"] = append(d["watch"].([]any), d["watch"].([]any)[0])
			return encoded(t, d)
		},
		"a watch entry naming no condition": func(d map[string]any) string {
			d["watch"] = []any{map[string]any{"name": "a"}}
			return encoded(t, d)
		},
		"a file watching nothing": func(d map[string]any) string {
			d["watch"] = []any{}
			return encoded(t, d)
		},
		"a relative output": func(d map[string]any) string {
			d["output"] = "state"
			return encoded(t, d)
		},
		"an output allowance of zero": func(d map[string]any) string {
			member(d, "limits")["output_mib"] = 0
			return encoded(t, d)
		},
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := policy.CompileProcessing([]byte(content(example(t))), nil)
			var refused *policy.Refused
			if !errors.As(err, &refused) {
				t.Fatalf("answered %v, want the reader's refusal", err)
			}
		})
	}
}
