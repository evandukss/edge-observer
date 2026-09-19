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

// contractConfiguration writes the contract's simplest example with change
// applied, in the shape the program reads.
func contractConfiguration(t *testing.T, change func(document map[string]any)) string {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatalf("read the no-extension example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-extension example: %v", err)
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

// target replaces the example's single target with one matching this
// executable and arguments, keeping the example's descendant answers.
func target(document map[string]any, name, exe string, args ...string) {
	scope := document["observation_scope"].(map[string]any)
	targets := scope["targets"].([]any)
	first := targets[0].(map[string]any)
	first["name"] = name
	first["match"] = map[string]any{"exe": exe, "args": args}
	// The example admits descendants; a single-process fixture admits none.
	descendants := first["descendants"].(map[string]any)
	descendants["existing"] = false
	descendants["future"] = false
}

// Every example configuration is run through this program's dry run, with the
// outcome stated per file: the no-extension example is planned, each other is
// refused naming every section this program does not do.
func TestEveryExampleConfigurationIsRunByTheProgram(t *testing.T) {
	outcomes := map[string][]string{
		"no-extension.config.json":            nil,
		"scopes-inbound-retained.config.json": {"pipelines", "pipelines[0].slots", "traffic_scope.rules[0]"},
		"scopes-outbound-exported.config.json": {"pipelines", "pipelines[0].slots",
			"retention_and_export.export_sinks", "retention_and_export.retain_plaintext",
			"sinks[0].kind", "sinks[1].kind", "traffic_scope.rules[0]"},
		"content-filter-is-not-approval.config.json": {"pipelines", "pipelines[0].slots", "policy"},
		"configuration-only-pack.config.json":        {"packs", "pipelines", "pipelines[0].slots"},
		"external-component.config.json": {"packs", "pipelines", "pipelines[0].slots", "policy",
			"retention_and_export.export_sinks", "sinks[1].kind", "subscribers"},
	}
	// The other files are not configurations: pack manifests are read only for an
	// enabled pack (all refused), the runtime inventory is the contract's example
	// (this program uses policy.Inventory), and the index lists the examples.
	notConfigurations := []string{"index.json", "packs/acme-classifier.json", "packs/swap-redactor.json", "runtime.json"}

	var configurations, others []string
	err := fs.WalkDir(config.Examples, "examples", func(at string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		name := strings.TrimPrefix(at, "examples/")
		if strings.HasSuffix(name, ".config.json") {
			configurations = append(configurations, name)
		} else {
			others = append(others, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the examples: %v", err)
	}
	slices.Sort(others)
	if !slices.Equal(others, notConfigurations) {
		t.Errorf("the examples directory holds %v beside its configurations, where %v are accounted for", others, notConfigurations)
	}
	if len(configurations) != len(outcomes) {
		t.Fatalf("wiring, not the program: %d example configurations where %d outcomes are written: %v",
			len(configurations), len(outcomes), configurations)
	}

	for _, name := range configurations {
		t.Run(name, func(t *testing.T) {
			refused, stated := outcomes[name]
			if !stated {
				t.Fatalf("no outcome is written for %s, so nothing says what the program should do with it", name)
			}
			var out bytes.Buffer
			err := run([]string{"dry-run", example(t, name)}, &out)
			if refused == nil {
				if err != nil {
					t.Fatalf("the program refuses it: %v", err)
				}
				var planned account.Account
				if err := json.Unmarshal(out.Bytes(), &planned); err != nil {
					t.Fatalf("the dry run printed no account: %v\n%s", err, out.String())
				}
				if len(planned.Targets) != 1 {
					t.Errorf("the plan carries %d targets where the example names one", len(planned.Targets))
				}
				return
			}
			var unimplemented *policy.Unimplemented
			if !errors.As(err, &unimplemented) {
				t.Fatalf("answered %v, want every section this program does not do named", err)
			}
			var paths []string
			for _, section := range unimplemented.Sections {
				paths = append(paths, section.Path)
			}
			slices.Sort(paths)
			if !slices.Equal(paths, refused) {
				t.Errorf("refused naming %v, want %v", paths, refused)
			}
			if out.Len() != 0 {
				t.Errorf("a refused configuration printed a plan:\n%s", out.String())
			}
		})
	}
}

// Every command that takes a configuration refuses what this program does not
// do. The commands are read off the usage text, so a new command is covered
// automatically.
func TestEveryCommandRefusesWhatTheProgramDoesNotDo(t *testing.T) {
	commands := regexp.MustCompile(`(?m)^  observer (\S+) <configuration>( \[?(--[a-z]+))?`).FindAllStringSubmatch(usage(), -1)
	if len(commands) < 6 {
		t.Fatalf("wiring, not the property: %d commands read off the usage text", len(commands))
	}
	content, err := config.Examples.ReadFile("examples/configuration-only-pack.config.json")
	if err != nil {
		t.Fatalf("read the pack example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the pack example: %v", err)
	}
	document["observer"].(map[string]any)["directory"] = t.TempDir()
	document["observer"].(map[string]any)["log"] = filepath.Join(t.TempDir(), "observer.log")
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	var invocations [][]string
	for _, command := range commands {
		invocations = append(invocations, []string{command[1], path})
		if command[3] != "" {
			invocations = append(invocations, []string{command[1], path, command[3]})
		}
	}
	for _, arguments := range invocations {
		t.Run(strings.Join(append([]string{arguments[0]}, arguments[2:]...), " "), func(t *testing.T) {
			var out bytes.Buffer
			err := run(arguments, &out)
			var unimplemented *policy.Unimplemented
			if !errors.As(err, &unimplemented) {
				t.Fatalf("%v answered %v, want the pack refused by name", arguments, err)
			}
			if !slices.ContainsFunc(unimplemented.Sections, func(s policy.Section) bool { return s.Path == "packs" }) {
				t.Errorf("%v refused naming %+v, without the pack", arguments, unimplemented.Sections)
			}
		})
	}
}
