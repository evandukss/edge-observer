package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// example writes one of the contract's example documents to a file, so the
// program reads it by path.
func example(t *testing.T, name string) string {
	t.Helper()
	content, err := config.Examples.ReadFile(path.Join("examples", name))
	if err != nil {
		t.Fatalf("read the example %s: %v", name, err)
	}
	written := filepath.Join(t.TempDir(), path.Base(name))
	if err := os.WriteFile(written, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", written, err)
	}
	return written
}

// installed writes one of the contract's example configurations with the
// examples' packs directory beside it, as an operator installs a pack.
func installed(t *testing.T, name string) string {
	t.Helper()
	written := example(t, name)
	packs := filepath.Join(filepath.Dir(written), "packs")
	if err := os.Mkdir(packs, 0o700); err != nil {
		t.Fatalf("make %s: %v", packs, err)
	}
	entries, err := fs.ReadDir(config.Examples, "examples/packs")
	if err != nil || len(entries) == 0 {
		t.Fatalf("wiring, not the program: the examples hold no packs to install: %v", err)
	}
	for _, entry := range entries {
		content, err := config.Examples.ReadFile(path.Join("examples/packs", entry.Name()))
		if err != nil {
			t.Fatalf("read the example pack %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(packs, entry.Name()), content, 0o600); err != nil {
			t.Fatalf("install %s: %v", entry.Name(), err)
		}
	}
	return written
}

// contractConfiguration writes the contract's no-rules example with change
// applied, in the shape the program reads.
func contractConfiguration(t *testing.T, change func(document map[string]any)) string {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatalf("read the no-rules example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-rules example: %v", err)
	}
	change(document)
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	where := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(where, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", where, err)
	}
	return where
}

// target replaces the example's single watch entry with one matching this
// executable and arguments. The example watches children; a single-process
// fixture watches none.
func target(document map[string]any, name, exe string, args ...string) {
	entry := map[string]any{"name": name, "exe": exe, "children": config.ChildrenNone}
	if args != nil {
		entry["args"] = args
	}
	document["watch"] = []any{entry}
}

// Every example configuration is one this program runs: a dry run over it,
// with the examples' packs installed beside it, prints a plan. A configuration
// is a document at observer.config/1; the examples directory holds nothing
// else but the documents listed.
func TestEveryExampleConfigurationIsRunByTheProgram(t *testing.T) {
	runs := []string{"no-rules.config.json", "observer.config.json"}
	notConfigurations := []string{"configuration-only-pack.config.json", "content-filter-is-not-approval.config.json",
		"index.json", "no-extension.config.json", "packs/credentials.json", "packs/reversed-masking.json", "runtime.json"}

	var configurations, others []string
	err := fs.WalkDir(config.Examples, "examples", func(at string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := config.Examples.ReadFile(at)
		if err != nil {
			return err
		}
		var version struct {
			Version string `json:"version"`
		}
		name := strings.TrimPrefix(at, "examples/")
		if json.Unmarshal(content, &version) == nil && version.Version == config.FileVersion {
			configurations = append(configurations, name)
		} else {
			others = append(others, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the examples: %v", err)
	}
	slices.Sort(configurations)
	slices.Sort(others)
	if !slices.Equal(others, notConfigurations) {
		t.Errorf("the examples directory holds %v beside its configurations, where %v are accounted for", others, notConfigurations)
	}
	if !slices.Equal(configurations, runs) {
		t.Fatalf("wiring, not the program: the example configurations are %v where %v are written", configurations, runs)
	}

	for _, name := range configurations {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := run([]string{"dry-run", installed(t, name)}, &out); err != nil {
				t.Fatalf("the program refused its own example: %v", err)
			}
			var planned account.Account
			if err := json.Unmarshal(out.Bytes(), &planned); err != nil || len(planned.Targets) != 1 || planned.Policy.Revision == "" {
				t.Fatalf("the dry run printed no usable plan: error=%v output=%s", err, out.Bytes())
			}
		})
	}
}

// Every command that compiles refuses a configuration enabling a pack that is
// not installed, naming the pack and the file it looked for. Stop and inspect
// of a running session are the exception, asserted here by name: they read
// only where the session is, so they answer that nothing is running rather than
// refusing the pack. The commands are read off the usage text, so a new command
// is covered automatically; inspect's usage line names a configuration or a
// session directory, so the pattern does not read it and it is added by name.
func TestEveryCommandRefusesWhatTheProgramDoesNotDo(t *testing.T) {
	commands := regexp.MustCompile(`(?m)^  observer (\S+) <configuration>( \[?(--[a-z]+))?`).FindAllStringSubmatch(usage(), -1)
	if len(commands) < 6 {
		t.Fatalf("wiring, not the property: %d commands read off the usage text", len(commands))
	}
	if !slices.ContainsFunc(commands, func(command []string) bool { return command[1] == "stop" }) {
		t.Fatal("wiring, not the property: the usage text names no stop command, so its exception asserts nothing")
	}
	if !strings.Contains(usage(), "  observer inspect <configuration | session directory> [--text]") ||
		slices.ContainsFunc(commands, func(command []string) bool { return command[1] == "inspect" }) {
		t.Fatal("wiring, not the property: inspect's usage line changed, so adding it by name may cover it twice or not at all")
	}
	commands = append(commands, []string{"", "inspect", " --text", "--text"})
	readOnlyWhereTheSessionIs := map[string]bool{"stop": true, "inspect": true}

	// The example alone, with no packs directory beside it.
	written := example(t, "observer.config.json")
	content, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read the example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the example: %v", err)
	}
	if packs, _ := document["packs"].([]any); len(packs) != 1 || packs[0] != "credentials" {
		t.Fatalf("wiring, not the property: the example enables %v, so packs[0] is not the credentials pack", packs)
	}
	document["output"] = t.TempDir()
	document["log"] = filepath.Join(t.TempDir(), "observer.log")
	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(written, rewritten, 0o600); err != nil {
		t.Fatalf("write %s: %v", written, err)
	}
	tried := filepath.Join(filepath.Dir(written), "packs", "credentials.json")
	if _, err := os.Stat(tried); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wiring, not the property: %s is there, so no command below meets a missing pack: %v", tried, err)
	}

	var invocations [][]string
	for _, command := range commands {
		invocations = append(invocations, []string{command[1], written})
		if command[3] != "" {
			invocations = append(invocations, []string{command[1], written, command[3]})
		}
	}
	for _, arguments := range invocations {
		t.Run(strings.Join(append([]string{arguments[0]}, arguments[2:]...), " "), func(t *testing.T) {
			var out bytes.Buffer
			err := run(arguments, &out)
			var rejected *policy.Refused
			if readOnlyWhereTheSessionIs[arguments[0]] {
				if errors.As(err, &rejected) || !errors.Is(err, errNotRunning) {
					t.Fatalf("%v answered %v, want that no session is running, with no pack read", arguments, err)
				}
				return
			}
			if !errors.As(err, &rejected) || rejected.Outcome != policy.ProcessingRefused {
				t.Fatalf("%v answered %v, want the pack refused by name", arguments, err)
			}
			if !slices.ContainsFunc(rejected.Findings, func(f config.Finding) bool {
				return f.Subject == "packs[0]" && f.Reason == config.UnknownPack && strings.Contains(f.Detail, tried)
			}) {
				t.Errorf("%v refused naming %+v, without the missing pack and the file it looked for", arguments, rejected.Findings)
			}
		})
	}
}
