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

// credentials is the example pack the contract ships.
func credentials(t *testing.T) []byte {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/packs/credentials.json")
	if err != nil {
		t.Fatalf("read the credentials pack: %v", err)
	}
	return content
}

// pack is a pack naming itself name and removing each header.
func pack(t *testing.T, name string, headers ...string) []byte {
	t.Helper()
	document := map[string]any{"version": config.PackVersion, "name": name}
	if len(headers) > 0 {
		document["remove"] = map[string]any{"headers": headers}
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the pack: %v", err)
	}
	return content
}

// bundle writes the contract's no-rules example enabling these packs, and each
// file under packs/ beside it. It returns the configuration's path.
func bundle(t *testing.T, enabled []string, files map[string][]byte) string {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatalf("read the no-rules example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-rules example: %v", err)
	}
	document["output"] = t.TempDir()
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
// directory - not the directory the command runs from - and its rules reach
// the plan as the pack's.
func TestAnEnabledPackIsReadFromBesideTheConfiguration(t *testing.T) {
	path := bundle(t, []string{"credentials"}, map[string][]byte{"credentials.json": credentials(t)})
	read, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("the credentials bundle was refused: %v", err)
	}
	pipelines := read.Processing.Pipelines()
	at := slices.IndexFunc(pipelines, func(p config.EffectivePipeline) bool { return p.Name == config.ExchangesPipeline })
	if at < 0 || len(pipelines[at].Slots) != 1 {
		t.Fatalf("wiring, not the loader: the no-rules example with the credentials pack compiled to %+v", pipelines)
	}
	slot := pipelines[at].Slots[0]
	if slot.Implementation != config.RemoveHeaders || slot.SelectedBy != "pack:credentials" ||
		slot.Arguments == nil || !slices.Contains(slot.Arguments.Headers, "authorization") {
		t.Errorf("slot %s holds %s %+v selected by %s, want the pack's header removal selected by the installed pack",
			slot.Name, slot.Implementation, slot.Arguments, slot.SelectedBy)
	}

	// From another directory, by a relative path, beside a packs directory
	// holding a corrupt pack of the same name: only the configuration's own
	// directory is read.
	elsewhere := t.TempDir()
	if err := os.Mkdir(filepath.Join(elsewhere, "packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "packs", "credentials.json"), []byte("{"), 0o600); err != nil {
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
	corrupt := []byte(`{"version": "observer.pack/1", "name": "unused",`)
	path := bundle(t, []string{"credentials"}, map[string][]byte{"credentials.json": credentials(t)})
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
	enabled := bundle(t, []string{"credentials", "unused"}, map[string][]byte{
		"credentials.json": credentials(t), "unused.json": corrupt})
	_, err = loadProcessing(enabled)
	findings := refusedFor(t, err)
	if !slices.ContainsFunc(findings, func(f config.Finding) bool {
		return f.Document == "pack:unused" && f.Reason == config.Malformed
	}) {
		t.Errorf("the enabled corrupt pack was refused naming %+v, not as the malformed pack:unused", findings)
	}
}

// Two files whose declared names are exchanged are refused, although their
// declarations together satisfy both names the configuration enables.
func TestPacksWhoseDeclaredNamesAreSwappedAreRefused(t *testing.T) {
	first, second := pack(t, "first-step", "authorization"), pack(t, "second-step", "cookie")
	enabled := []string{"first-step", "second-step"}
	named := bundle(t, enabled, map[string][]byte{"first-step.json": first, "second-step.json": second})
	dryRunPlans(t, named)

	swapped := bundle(t, enabled, map[string][]byte{"first-step.json": second, "second-step.json": first})
	_, err := loadProcessing(swapped)
	findings := refusedFor(t, err)
	for _, name := range enabled {
		if !slices.ContainsFunc(findings, func(f config.Finding) bool {
			return f.Document == "pack:"+name && f.Subject == "name" && f.Reason == config.PackNameMismatch
		}) {
			t.Errorf("pack %s was not refused as misnamed at its name: %+v", name, findings)
		}
	}
}

// A name that could leave the packs directory, or is not a plain file name, is
// refused by the name rule, before any file is looked for. A pack declaring
// that name sits where the name would lead, so a loader that opened it would
// find a pack there.
func TestAPackNameThatCouldLeaveThePacksDirectoryIsRefusedByName(t *testing.T) {
	neighbour := bundle(t, []string{"escape"}, map[string][]byte{"escape.json": pack(t, "escape")})
	dryRunPlans(t, neighbour)

	// Built rather than written: no literal in this module names a path
	// outside it, and these names only lead there if the rule lets them.
	parent := strings.Repeat(".", 2)
	for _, name := range []string{parent + "/escape", "sub/escape", parent, ".escape", "-escape", "esc ape", `esc\ape`,
		strings.Repeat("a", 129)} {
		t.Run(name, func(t *testing.T) {
			path := bundle(t, []string{name}, nil)
			led := filepath.Join(filepath.Dir(path), packsDirectory, name+".json")
			if err := os.MkdirAll(filepath.Dir(led), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(led, pack(t, name), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadProcessing(path)
			if findings := refusedFor(t, err); !holds(findings, "packs[0]", config.PackNameInvalid, "") || len(findings) != 1 {
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
			path := bundle(t, []string{"credentials"}, map[string][]byte{"other.json": pack(t, "other")})
			at := filepath.Join(filepath.Dir(path), packsDirectory, "credentials.json")
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
				if findings := refusedFor(t, err); !holds(findings, "packs[0]", packNotRegular, at) {
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
// an unreadable one, and one to a valid pack is that pack.
func TestAMissingPackNamesTheFileItLookedFor(t *testing.T) {
	path := bundle(t, []string{"credentials"}, nil)
	_, err := loadProcessing(path)
	at := filepath.Join(filepath.Dir(path), packsDirectory, "credentials.json")
	if !filepath.IsAbs(at) {
		t.Fatalf("wiring, not the loader: %s is not absolute", at)
	}
	if findings := refusedFor(t, err); !holds(findings, "packs[0]", config.UnknownPack, at) {
		t.Errorf("refused naming %+v, want the missing pack and %s", findings, at)
	}

	elsewhere := filepath.Join(t.TempDir(), "credentials.json")
	for _, link := range []struct {
		name   string
		target string
		reason config.Reason
	}{
		{"dangling", filepath.Join(t.TempDir(), "absent.json"), config.UnknownPack},
		{"loop", "credentials.json", packUnreadable},
		{"to a valid pack", elsewhere, ""},
	} {
		t.Run(link.name, func(t *testing.T) {
			if err := os.WriteFile(elsewhere, credentials(t), 0o600); err != nil {
				t.Fatal(err)
			}
			path := bundle(t, []string{"credentials"}, map[string][]byte{"other.json": pack(t, "other")})
			at := filepath.Join(filepath.Dir(path), packsDirectory, "credentials.json")
			if err := os.Symlink(link.target, at); err != nil {
				t.Fatal(err)
			}
			_, err := loadProcessing(path)
			if link.reason == "" {
				if err != nil {
					t.Fatalf("a link to a valid pack was refused: %v", err)
				}
				return
			}
			if findings := refusedFor(t, err); !holds(findings, "packs[0]", link.reason, at) {
				t.Errorf("refused naming %+v, want %s at %s", findings, link.reason, at)
			}
		})
	}
}

// The configuration and its enabled packs share the configuration budget: a
// bundle at exactly the budget compiles, one byte over is refused naming the
// pack, and a pack far over it is refused without being read.
func TestABundleOverTheByteBudgetIsRefusedBeforeItsExcessIsRead(t *testing.T) {
	path := bundle(t, []string{"credentials"}, map[string][]byte{"credentials.json": credentials(t)})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	at := filepath.Join(filepath.Dir(path), packsDirectory, "credentials.json")
	budget := config.MaxProcessingBytes - len(content)
	padded := func(size int) []byte {
		pack := credentials(t)
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
	if findings := refusedFor(t, err); !holds(findings, "packs[0]", config.ConfigurationTooLarge, at) {
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
	if findings := refusedFor(t, err); !holds(findings, "packs[0]", config.ConfigurationTooLarge, at) {
		t.Errorf("a pack of a gibibyte was refused naming %+v", findings)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Errorf("refusing a pack of a gibibyte allocated %d bytes, so its excess was read", allocated)
	}
}

// What a reload compares is the enabled pack's bytes as they are on disk when
// it runs: a changed pack, even by whitespace, is a processing change a
// restart applies, while unchanged pack bytes beside an added watch entry are
// an observation change reload puts in force.
func TestReloadComparesTheEnabledPackAsItIsOnDisk(t *testing.T) {
	pack := credentials(t)
	path := bundle(t, []string{"credentials"}, map[string][]byte{"credentials.json": pack})
	at := filepath.Join(filepath.Dir(path), packsDirectory, "credentials.json")
	current, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("the bundle in force was refused: %v", err)
	}
	for _, change := range []struct {
		name  string
		bytes []byte
	}{
		{"a value", bytes.Replace(pack, []byte(`"x-api-key"`), []byte(`"x-api-token"`), 1)},
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
			if _, why := additive(current, candidate); !strings.Contains(why, "changes processing -") {
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
	document["watch"] = append(document["watch"].([]any), map[string]any{
		"name": "worker", "exe": "/usr/bin/worker", "children": config.ChildrenAll})
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
		t.Errorf("unchanged pack bytes with an added watch entry answered %v %q, want the entry added", added, why)
	}
}
