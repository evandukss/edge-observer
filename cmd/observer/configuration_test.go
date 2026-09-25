package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// demonstration is the example pack the demonstration configuration enables.
func demonstration(t *testing.T) []byte {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/packs/reversed-masking.json")
	if err != nil {
		t.Fatalf("read the demonstration pack: %v", err)
	}
	return content
}

// manifest is a configuration-only pack declaring name, selecting each
// replacement for the demonstration's slots.
func manifest(t *testing.T, name string, replacements ...map[string]any) []byte {
	t.Helper()
	if replacements == nil {
		replacements = []map[string]any{}
	}
	content, err := json.Marshal(map[string]any{"version": config.ManifestVersion, "name": name, "pack_version": "1",
		"components": []any{}, "pipelines": []any{}, "replacements": replacements, "policy": []any{}})
	if err != nil {
		t.Fatalf("encode the manifest: %v", err)
	}
	return content
}

var (
	truncateFirst = map[string]any{"pipeline": "exchanges", "slot": "mark", "implementation": config.TruncateHeaderValues,
		"configuration": map[string]any{"headers": []string{"authorization"}, "length": 8}}
	replaceSecond = map[string]any{"pipeline": "exchanges", "slot": "limit", "implementation": config.ReplaceHeaderValues,
		"configuration": map[string]any{"headers": []string{"authorization"}, "value": "withheld-by-pack"}}
)

// bundle writes the demonstration configuration enabling these packs, and each
// file under packs/ beside it. It returns the configuration's path.
func bundle(t *testing.T, enabled []string, files map[string][]byte) string {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/configuration-only-pack.config.json")
	if err != nil {
		t.Fatalf("read the demonstration configuration: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the demonstration configuration: %v", err)
	}
	document["observer"].(map[string]any)["directory"] = t.TempDir()
	document["packs"] = enabled
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "observer.json")
	if err := os.WriteFile(path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if len(files) > 0 {
		if err := os.Mkdir(filepath.Join(root, "packs"), 0o700); err != nil {
			t.Fatalf("make the packs directory: %v", err)
		}
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, "packs", name), content, 0o600); err != nil {
			t.Fatalf("install %s: %v", name, err)
		}
	}
	return path
}

// refusedFor is the refusal's findings as subject/reason, or fails the case
// where the load was not a processing refusal.
func refusedFor(t *testing.T, err error) []config.Finding {
	t.Helper()
	var rejected *policy.Refused
	if !errors.As(err, &rejected) || rejected.Outcome != policy.ProcessingRefused {
		t.Fatalf("answered %v, want a processing refusal", err)
	}
	return rejected.Findings
}

func holds(findings []config.Finding, subject string, reason config.Reason, detail string) bool {
	return slices.ContainsFunc(findings, func(f config.Finding) bool {
		return f.Subject == subject && f.Reason == reason && strings.Contains(f.Detail, detail)
	})
}

// dryRunPlans runs the program's dry run and requires a plan.
func dryRunPlans(t *testing.T, path string) account.Account {
	t.Helper()
	var out bytes.Buffer
	if err := run([]string{"dry-run", path}, &out); err != nil {
		t.Fatalf("the neighbouring bundle did not produce a plan: %v", err)
	}
	var planned account.Account
	if err := json.Unmarshal(out.Bytes(), &planned); err != nil || planned.Policy.Revision == "" {
		t.Fatalf("the dry run printed no plan: %v\n%s", err, out.Bytes())
	}
	return planned
}

// An enabled pack is read from packs/<name>.json in the configuration's
// directory - not the directory the command runs from - and its replacements
// fill the slots it names.
func TestAnEnabledPackIsReadFromBesideTheConfiguration(t *testing.T) {
	path := bundle(t, []string{"reversed-masking"}, map[string][]byte{"reversed-masking.json": demonstration(t)})
	read, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("the demonstration bundle was refused: %v", err)
	}
	pipelines := read.Processing.Pipelines()
	if len(pipelines) != 1 || len(pipelines[0].Slots) != 2 {
		t.Fatalf("wiring, not the loader: the demonstration compiled to %+v", pipelines)
	}
	for i, want := range []string{config.TruncateHeaderValues, config.ReplaceHeaderValues} {
		slot := pipelines[0].Slots[i]
		if slot.Implementation != want || slot.SelectedBy != "pack:reversed-masking" {
			t.Errorf("slot %s holds %s selected by %s, want %s selected by the installed pack",
				slot.Name, slot.Implementation, slot.SelectedBy, want)
		}
	}

	// From another directory, by a relative path, beside a packs directory
	// holding a corrupt pack of the same name: only the configuration's own
	// directory is read.
	elsewhere := t.TempDir()
	if err := os.Mkdir(filepath.Join(elsewhere, "packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "packs", "reversed-masking.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(elsewhere)
	relative, err := filepath.Rel(elsewhere, path)
	if err != nil || filepath.IsAbs(relative) {
		t.Fatalf("wiring, not the loader: no relative path from %s to %s: %v", elsewhere, path, err)
	}
	if planned := dryRunPlans(t, relative); planned.Policy.Revision != read.Revision {
		t.Errorf("by a relative path the plan is revision %s, and by its absolute path %s", planned.Policy.Revision, read.Revision)
	}
}

// A file under packs/ that the configuration does not enable is neither read
// nor refused, and does not change what the bundle is.
func TestADisabledPackIsNeitherReadNorRefused(t *testing.T) {
	corrupt := []byte(`{"version": "observer.pack/draft", "name": "unused",`)
	path := bundle(t, []string{"reversed-masking"}, map[string][]byte{"reversed-masking.json": demonstration(t)})
	one, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("the bundle alone was refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), packsDirectory, "unused.json"), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("a corrupt pack nothing enables refused the bundle: %v", err)
	}
	if one.Revision != other.Revision || one.ProcessingRevision != other.ProcessingRevision {
		t.Errorf("a pack nothing enables changed the bundle's identity: %s/%s against %s/%s",
			one.Revision, one.ProcessingRevision, other.Revision, other.ProcessingRevision)
	}

	// The same file, enabled, is refused: it was ignored, not accepted.
	enabled := bundle(t, []string{"reversed-masking", "unused"}, map[string][]byte{
		"reversed-masking.json": demonstration(t), "unused.json": corrupt})
	_, err = loadProcessing(enabled)
	findings := refusedFor(t, err)
	if !slices.ContainsFunc(findings, func(f config.Finding) bool {
		return f.Document == "manifest:unused" && f.Reason == config.Malformed &&
			strings.Contains(f.Detail, filepath.Join(filepath.Dir(enabled), "packs", "unused.json"))
	}) {
		t.Errorf("the enabled corrupt pack was refused naming %+v, not as malformed at its path", findings)
	}
}

// Two files whose declared names are exchanged are refused, although their
// declarations together satisfy both names the configuration enables.
func TestPacksWhoseDeclaredNamesAreSwappedAreRefused(t *testing.T) {
	first, second := manifest(t, "first-step", truncateFirst), manifest(t, "second-step", replaceSecond)
	enabled := []string{"first-step", "second-step"}

	named := bundle(t, enabled, map[string][]byte{"first-step.json": first, "second-step.json": second})
	dryRunPlans(t, named)

	swapped := bundle(t, enabled, map[string][]byte{"first-step.json": second, "second-step.json": first})
	// The compiler alone indexes by declared name, so it accepts the swapped
	// files: the loader's name check is what refuses them.
	content, err := os.ReadFile(swapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.CompileProcessing(content, []config.Supplied{{Name: "first-step", Content: second},
		{Name: "second-step", Content: first}}); err != nil {
		t.Fatalf("wiring, not the loader: the compiler refuses the swapped declarations itself: %v", err)
	}
	_, err = loadProcessing(swapped)
	findings := refusedFor(t, err)
	for _, name := range enabled {
		if !holds(findings, "pack:"+name, packNameMismatch, filepath.Join(filepath.Dir(swapped), "packs", name+".json")) {
			t.Errorf("pack %s was not refused as misnamed at its path: %+v", name, findings)
		}
	}
}

// A name that could leave the packs directory, or is not a plain file name, is
// refused by the name rule. A file declaring that name sits where the name
// would lead and compiles when supplied directly, so nothing but the name rule
// can be what refuses it.
func TestAPackNameThatCouldLeaveThePacksDirectoryIsRefusedByName(t *testing.T) {
	neighbour := bundle(t, []string{"escape"}, map[string][]byte{"escape.json": manifest(t, "escape")})
	dryRunPlans(t, neighbour)

	// Built rather than written: no literal in this module names a path
	// outside it, and these names only lead there if the rule lets them.
	parent := strings.Repeat(".", 2)
	for _, name := range []string{parent + "/escape", "sub/escape", parent, ".escape", "-escape", "esc ape", `esc\ape`,
		strings.Repeat("a", 129)} {
		t.Run(name, func(t *testing.T) {
			path := bundle(t, []string{name}, nil)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			declared := manifest(t, name)
			if _, err := policy.CompileProcessing(content, []config.Supplied{{Name: name, Content: declared}}); err != nil {
				t.Fatalf("wiring, not the name rule: the file placed for %q would be refused anyway: %v", name, err)
			}
			led := filepath.Join(filepath.Dir(path), packsDirectory, name+".json")
			if err := os.MkdirAll(filepath.Dir(led), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(led, declared, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = loadProcessing(path)
			if findings := refusedFor(t, err); !holds(findings, "pack:"+name, packNameInvalid, "") || len(findings) != 1 {
				t.Errorf("refused naming %+v, want only the name rule", findings)
			}
		})
	}
}

// A FIFO or a directory where a pack should be is refused as not a regular
// file, and the command does not wait on the FIFO for a writer.
func TestAPackThatIsNotARegularFileIsRefusedWithoutWaiting(t *testing.T) {
	for _, kind := range []string{"fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := bundle(t, []string{"reversed-masking"}, map[string][]byte{"other.json": manifest(t, "other")})
			at := filepath.Join(filepath.Dir(path), packsDirectory, "reversed-masking.json")
			var err error
			if kind == "fifo" {
				err = syscall.Mkfifo(at, 0o600)
			} else {
				err = os.Mkdir(at, 0o700)
			}
			if err != nil {
				t.Fatalf("make the %s: %v", kind, err)
			}
			answered := make(chan error, 1)
			go func() {
				_, err := loadProcessing(path)
				answered <- err
			}()
			select {
			case err := <-answered:
				if findings := refusedFor(t, err); !holds(findings, "pack:reversed-masking", packNotRegular, at) {
					t.Errorf("refused naming %+v, want not a regular file at %s", findings, at)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("the load has not returned after 10s: it is waiting on the %s", kind)
			}
		})
	}
}

// A missing pack's refusal names the file looked for. A link is followed, as
// the configuration's own path is: a dangling one is a missing pack, a loop is
// an unreadable one, and one to a valid manifest is that manifest.
func TestAMissingPackNamesTheFileItLookedFor(t *testing.T) {
	path := bundle(t, []string{"reversed-masking"}, nil)
	_, err := loadProcessing(path)
	at := filepath.Join(filepath.Dir(path), packsDirectory, "reversed-masking.json")
	if !filepath.IsAbs(at) {
		t.Fatalf("wiring, not the loader: %s is not absolute", at)
	}
	if findings := refusedFor(t, err); !holds(findings, "pack:reversed-masking", config.UnknownPack, at) {
		t.Errorf("refused naming %+v, want the missing pack and %s", findings, at)
	}

	elsewhere := filepath.Join(t.TempDir(), "reversed-masking.json")
	for _, link := range []struct {
		name   string
		target string
		reason config.Reason
	}{
		{"dangling", filepath.Join(t.TempDir(), "absent.json"), config.UnknownPack},
		{"loop", "reversed-masking.json", packUnreadable},
		{"to a valid manifest", elsewhere, ""},
	} {
		t.Run(link.name, func(t *testing.T) {
			if err := os.WriteFile(elsewhere, demonstration(t), 0o600); err != nil {
				t.Fatal(err)
			}
			path := bundle(t, []string{"reversed-masking"}, map[string][]byte{"other.json": manifest(t, "other")})
			at := filepath.Join(filepath.Dir(path), packsDirectory, "reversed-masking.json")
			if err := os.Symlink(link.target, at); err != nil {
				t.Fatal(err)
			}
			_, err := loadProcessing(path)
			if link.reason == "" {
				if err != nil {
					t.Fatalf("a link to a valid manifest was refused: %v", err)
				}
				return
			}
			if findings := refusedFor(t, err); !holds(findings, "pack:reversed-masking", link.reason, at) {
				t.Errorf("refused naming %+v, want %s at %s", findings, link.reason, at)
			}
		})
	}
}

// The configuration and its enabled packs share the configuration budget: a
// bundle at exactly the budget compiles, one byte over is refused naming the
// pack, and a pack far over it is refused without being read.
func TestABundleOverTheByteBudgetIsRefusedBeforeItsExcessIsRead(t *testing.T) {
	path := bundle(t, []string{"reversed-masking"}, map[string][]byte{"reversed-masking.json": demonstration(t)})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	at := filepath.Join(filepath.Dir(path), packsDirectory, "reversed-masking.json")
	budget := config.MaxProcessingBytes - len(content)
	padded := func(size int) []byte {
		pack := demonstration(t)
		if size < len(pack) {
			t.Fatalf("wiring, not the budget: the pack is %d bytes, over the %d asked for", len(pack), size)
		}
		// Whitespace after the document: the strict reader accepts it.
		return append(pack, bytes.Repeat([]byte{' '}, size-len(pack))...)
	}

	if err := os.WriteFile(at, padded(budget), 0o600); err != nil {
		t.Fatal(err)
	}
	dryRunPlans(t, path)

	if err := os.WriteFile(at, padded(budget+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loadProcessing(path)
	if findings := refusedFor(t, err); !holds(findings, "pack:reversed-masking", config.ConfigurationTooLarge, at) {
		t.Errorf("one byte over the budget was refused naming %+v", findings)
	}

	// A gibibyte, sparse: reading it would allocate about that much.
	if err := os.Truncate(at, 1<<30); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = loadProcessing(path)
	runtime.ReadMemStats(&after)
	if findings := refusedFor(t, err); !holds(findings, "pack:reversed-masking", config.ConfigurationTooLarge, at) {
		t.Errorf("a pack of a gibibyte was refused naming %+v", findings)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Errorf("refusing a pack of a gibibyte allocated %d bytes, so its excess was read", allocated)
	}
}

// What a reload compares is the enabled pack's bytes as they are on disk when
// it runs: a changed pack, even by whitespace, is a processing change a
// restart applies, while unchanged pack bytes beside an added target are an
// observation change reload puts in force.
func TestReloadComparesTheEnabledPackAsItIsOnDisk(t *testing.T) {
	pack := demonstration(t)
	path := bundle(t, []string{"reversed-masking"}, map[string][]byte{"reversed-masking.json": pack})
	at := filepath.Join(filepath.Dir(path), packsDirectory, "reversed-masking.json")
	current, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("the bundle in force was refused: %v", err)
	}
	for _, change := range []struct {
		name  string
		bytes []byte
	}{
		{"a value", bytes.Replace(pack, []byte("withheld-by-pack"), []byte("withheld-by-edit"), 1)},
		{"whitespace only", append(slices.Clone(pack), '\n')},
	} {
		t.Run(change.name, func(t *testing.T) {
			if bytes.Equal(change.bytes, pack) {
				t.Fatal("wiring, not the reload: the change changed nothing")
			}
			if err := os.WriteFile(at, change.bytes, 0o600); err != nil {
				t.Fatal(err)
			}
			candidate, err := loadProcessing(path)
			if err != nil {
				t.Fatalf("the changed pack was refused outright: %v", err)
			}
			if _, why := additive(current, candidate); !strings.Contains(why, "processing or retention") {
				t.Errorf("a changed pack was answered %q, want a processing change a restart applies", why)
			}
		})
	}

	if err := os.WriteFile(at, pack, 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	scope := document["observation_scope"].(map[string]any)
	scope["targets"] = append(scope["targets"].([]any), map[string]any{
		"name": "worker", "match": map[string]any{"exe": "/usr/bin/worker"},
		"descendants": scope["targets"].([]any)[0].(map[string]any)["descendants"]})
	grown, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, grown, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("an observation-only change was refused outright: %v", err)
	}
	added, why := additive(current, candidate)
	if why != "" || len(added) != 1 || added[0].Name != "worker" {
		t.Errorf("unchanged pack bytes with an added target answered %v %q, want the target added", added, why)
	}
}
