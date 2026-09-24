package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// moduleRoot is the directory of the nearest go.mod above this package, which
// must be this module's. The walk stays inside it.
func moduleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		module, err := os.ReadFile(filepath.Join(directory, "go.mod"))
		if err == nil {
			if !bytes.HasPrefix(module, []byte("module github.com/evandukss/edge-observer\n")) {
				t.Fatalf("wiring, not the property: the nearest go.mod, in %s, is not the observer module's", directory)
			}
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("wiring, not the property: no go.mod above this package")
		}
		directory = parent
	}
}

// examplesFloor is the fewest example files the walk must find before its
// result means anything: the count when set, held as a floor so later
// examples need no edit here.
const examplesFloor = 18

// executor is the program an examples directory describes, run over that
// directory through a filesystem that records every file opened. It returns
// failures by file, or by "" for the directory as a whole. A file nothing
// opened is not executed.
type executor struct {
	root string
	name string
	run  func(examples fs.FS) map[string]error
}

// executors is every examples directory under the module and the program that
// executes it. A directory with examples no entry names is refused.
var executors = []executor{
	{"contract/config/examples", "observer dry-run over every *.config.json", dryRunEvery},
	{"contract/config/examples", "the configuration check over every example index.json lists", checkAsIndexed},
	{"contract/examples/bundle", "the account validator over the dummy bundle", checkDocumentBundle},
	{"contract", "the configuration and policy checks over standalone declarations", checkDocumentDeclarations},
}

// notExecuted is every example file deliberately executed by nothing, each
// with why.
var notExecuted = map[string]string{}

// isExample: a directory named examples on the path, or "example" in the name.
// Go source is the program, not an example.
func isExample(at string) bool {
	if strings.HasSuffix(at, ".go") {
		return false
	}
	return slices.Contains(strings.Split(path.Dir(at), "/"), "examples") ||
		strings.Contains(strings.ToLower(path.Base(at)), "example")
}

// Every example file in the module is executed by the program it describes.
// Examples are found by walking, not from a list, and each directory's program
// records what it opens: a file it could not execute fails, and so does one it
// never opened. TestEveryExampleConfigurationIsRunByTheProgram pins what the
// program answers; this pins that every file is answered.
func TestEveryExampleFileIsExecutedByTheProgramItDescribes(t *testing.T) {
	root := moduleRoot(t)
	var examples []string
	err := fs.WalkDir(os.DirFS(root), ".", func(at string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !isExample(at) {
			return err
		}
		examples = append(examples, at)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(examples) < examplesFloor {
		t.Fatalf("wiring, not the property: the walk of %s found %d example files, below the floor of %d, so a "+
			"clean result below would mean nothing", root, len(examples), examplesFloor)
	}
	directories := map[string]int{}
	for _, at := range examples {
		directories[path.Dir(at)]++
	}
	t.Logf("scope: the module at %s, every directory under it; nothing outside it is examined", root)
	t.Logf("%d example files in %d directories:", len(examples), len(directories))
	for _, directory := range slices.Sorted(maps.Keys(directories)) {
		t.Logf("  %s: %d", directory, directories[directory])
	}

	opened := map[string][]string{}
	failed := map[string]string{}
	for _, one := range executors {
		t.Run(one.name, func(t *testing.T) {
			recorded := &openedFS{fsys: os.DirFS(filepath.Join(root, filepath.FromSlash(one.root)))}
			failures := one.run(recorded)
			for _, name := range recorded.names() {
				at := one.root + "/" + name
				opened[at] = append(opened[at], one.name)
				for _, about := range []string{"", name} {
					if err := failures[about]; err != nil {
						failed[at] = one.name + ": " + err.Error()
					}
				}
			}
			for about, err := range failures {
				t.Errorf("%s cannot execute %s: %v", one.name, path.Join(one.root, about), err)
			}
		})
	}

	for at, why := range notExecuted {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is listed as executed by nothing with no reason; an exception is its reason", at)
		}
		if !slices.Contains(examples, at) {
			t.Errorf("%s is listed as executed by nothing and the walk found no such example", at)
		}
	}

	for _, at := range examples {
		t.Run(at, func(t *testing.T) {
			if why, excepted := notExecuted[at]; excepted {
				if by := opened[at]; len(by) != 0 {
					t.Fatalf("listed as executed by nothing, and %v executes it", by)
				}
				t.Logf("executed by nothing: %s", why)
				return
			}
			if !slices.ContainsFunc(executors, func(one executor) bool { return strings.HasPrefix(at, one.root+"/") }) {
				t.Fatalf("no program is known to execute %s: name the program its directory describes, or list it as "+
					"executed by nothing with why", at)
			}
			if why, ok := failed[at]; ok {
				t.Fatalf("read by a program that could not execute it: %s", why)
			}
			if len(opened[at]) == 0 {
				t.Fatalf("the programs for %s ran and none of them opened %s", path.Dir(at), path.Base(at))
			}
			t.Logf("executed by %s", strings.Join(opened[at], "; "))
		})
	}
}

// openedFS is a filesystem that remembers every file opened through it.
type openedFS struct {
	fsys   fs.FS
	mu     sync.Mutex
	opened []string
}

func (r *openedFS) Open(name string) (fs.File, error) {
	file, err := r.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err == nil && !info.IsDir() {
		r.mu.Lock()
		r.opened = append(r.opened, name)
		r.mu.Unlock()
	}
	return file, nil
}

func (r *openedFS) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Compact(slices.Sorted(slices.Values(r.opened)))
}

// dryRunOne runs one operator configuration through this program's dry run.
// It was read if the program prints a plan or refuses naming unimplemented
// sections; anything else is a configuration it cannot execute.
func dryRunOne(examples fs.FS, name string) error {
	content, err := fs.ReadFile(examples, name)
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "example")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(directory) }()
	written := filepath.Join(directory, path.Base(name))
	if err := os.WriteFile(written, content, 0o600); err != nil {
		return err
	}
	var out bytes.Buffer
	err = run([]string{"dry-run", written}, &out)
	var unimplemented *policy.Unimplemented
	switch {
	case errors.As(err, &unimplemented):
		return nil
	case err != nil:
		return err
	}
	var planned account.Account
	if err := json.Unmarshal(out.Bytes(), &planned); err != nil {
		return fmt.Errorf("the dry run printed no account: %w", err)
	}
	return nil
}

func dryRunEvery(examples fs.FS) map[string]error {
	failures := map[string]error{}
	err := fs.WalkDir(examples, ".", func(at string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(at, ".config.json") {
			return err
		}
		if err := dryRunOne(examples, at); err != nil {
			failures[at] = err
		}
		return nil
	})
	if err != nil {
		failures[""] = err
	}
	return failures
}

// strictly decodes a document, refusing members its type lacks.
func strictly(content []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

// checkAsIndexed runs the configuration check over every example the index
// lists, with its manifests and the example runtime, requiring the stated
// outcome.
func checkAsIndexed(examples fs.FS) map[string]error {
	whole := func(err error) map[string]error { return map[string]error{"": err} }
	content, err := fs.ReadFile(examples, "index.json")
	if err != nil {
		return whole(err)
	}
	var index []struct {
		Name          string         `json:"name"`
		Purpose       string         `json:"purpose"`
		Configuration string         `json:"configuration"`
		Manifests     []string       `json:"manifests"`
		Outcome       config.Outcome `json:"outcome"`
	}
	if err := strictly(content, &index); err != nil {
		return map[string]error{"index.json": err}
	}
	runtime, err := fs.ReadFile(examples, "runtime.json")
	if err != nil {
		return whole(err)
	}
	var available config.Available
	if err := strictly(runtime, &available); err != nil {
		return map[string]error{"runtime.json": err}
	}
	failures := map[string]error{}
	for _, one := range index {
		configuration, err := fs.ReadFile(examples, one.Configuration)
		if err != nil {
			failures["index.json"] = errors.Join(failures["index.json"], err)
			continue
		}
		in := config.Input{Configuration: configuration, Available: available}
		for _, manifest := range one.Manifests {
			content, err := fs.ReadFile(examples, manifest)
			if err != nil {
				failures["index.json"] = errors.Join(failures["index.json"], err)
				continue
			}
			in.Manifests = append(in.Manifests, config.Supplied{Name: strings.TrimSuffix(path.Base(manifest), ".json"), Content: content})
		}
		if result := config.Check(in); result.Outcome != one.Outcome {
			failures[one.Configuration] = fmt.Errorf("%s checks as %q where the index says %q: %+v %+v",
				one.Name, result.Outcome, one.Outcome, result.Structural, result.Composition)
		}
	}
	return failures
}
