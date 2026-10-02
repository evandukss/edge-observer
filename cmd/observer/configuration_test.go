package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// withExtension writes the contract's no-rules example into a fresh
// directory with keys set over it, and an executable at bin/inventory beside
// it. It returns the configuration's path.
func withExtension(t *testing.T, keys map[string]any) string {
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
	document["extensions"] = []any{map[string]any{"name": "inventory", "command": []string{"bin/inventory"},
		"fields": []string{config.FieldRequestLine}, "timeout_ms": 250}}
	for key, value := range keys {
		document[key] = value
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "inventory"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return rewrite(t, filepath.Join(root, "observer.json"), document)
}

// rewrite writes document as JSON at path and returns path.
func rewrite(t *testing.T, path string, document map[string]any) string {
	t.Helper()
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// refusedFor is the refusal's findings, or fails the case where the load was
// not a processing refusal.
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

// An extension's relative command is resolved against the configuration's
// directory, not the directory the command runs from, and reaches the plan
// resolved. Removed, the same file is refused naming the entry and the path
// it looked for.
func TestAnExtensionCommandIsResolvedBesideTheConfiguration(t *testing.T) {
	path := withExtension(t, nil)
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(working) })

	loaded, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	at := filepath.Join(filepath.Dir(path), "bin", "inventory")
	if extensions := loaded.Processing.Extensions(); len(extensions) != 1 || extensions[0].Command[0] != at {
		t.Fatalf("the plan carries %+v, want the command at %s", extensions, at)
	}

	if err := os.Remove(at); err != nil {
		t.Fatal(err)
	}
	_, err = loadProcessing(path)
	if findings := refusedFor(t, err); !holds(findings, "extensions[0].command[0]", config.CommandNotExecutable, at) ||
		!holds(findings, "extensions[0].command[0]", config.CommandNotExecutable, `extension "inventory"`) {
		t.Errorf("a missing command was refused as %+v, want the entry and %s named", findings, at)
	}
}

// Reload refuses a change to the extensions, which changes the processing
// revision, and a change to limits.workers, which does not: each is applied
// by a restart. An added watch entry beside them is the control, applied.
func TestReloadRefusesAChangedExtensionAndAChangedWorkerCount(t *testing.T) {
	path := withExtension(t, nil)
	current, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("the configuration in force was refused: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	candidate := func(t *testing.T, change func(map[string]any)) policy.Policy {
		t.Helper()
		var changed map[string]any
		if err := json.Unmarshal(content, &changed); err != nil {
			t.Fatal(err)
		}
		change(changed)
		loaded, err := loadProcessing(rewrite(t, filepath.Join(filepath.Dir(path), "candidate.json"), changed))
		if err != nil {
			t.Fatalf("the candidate was refused outright: %v", err)
		}
		return loaded
	}

	for _, change := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"a timeout", func(d map[string]any) { d["extensions"].([]any)[0].(map[string]any)["timeout_ms"] = 500 }},
		{"a field", func(d map[string]any) {
			d["extensions"].([]any)[0].(map[string]any)["fields"] = []string{config.FieldRequestLine, config.FieldConnection}
		}},
		{"an argument", func(d map[string]any) {
			d["extensions"].([]any)[0].(map[string]any)["command"] = []string{"bin/inventory", "--verbose"}
		}},
		{"the extension removed", func(d map[string]any) { delete(d, "extensions") }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := candidate(t, change.change)
			if changed.ProcessingRevision == current.ProcessingRevision {
				t.Errorf("the processing revision is unchanged")
			}
			if _, why := additive(current, changed); !strings.Contains(why, "changes processing -") ||
				!strings.Contains(why, "extensions") {
				t.Errorf("reload answered %q, want a processing change naming the extensions", why)
			}
		})
	}

	t.Run("limits.workers", func(t *testing.T) {
		changed := candidate(t, func(d map[string]any) {
			limits, _ := d["limits"].(map[string]any)
			if limits == nil {
				limits = map[string]any{}
			}
			limits["workers"] = 2
			d["limits"] = limits
		})
		if changed.Settings.Workers != 2 || current.Settings.Workers != int(config.DefaultWorkers) {
			t.Fatalf("wiring, not the property: the worker counts read %d and %d", current.Settings.Workers,
				changed.Settings.Workers)
		}
		if changed.ProcessingRevision != current.ProcessingRevision {
			t.Errorf("limits.workers changed the processing revision")
		}
		if _, why := additive(current, changed); !strings.Contains(why, "limits.workers") {
			t.Errorf("reload answered %q, want an observer setting a restart applies", why)
		}
	})

	t.Run("the control, an added watch entry", func(t *testing.T) {
		changed := candidate(t, func(d map[string]any) {
			d["watch"] = append(d["watch"].([]any), map[string]any{"name": "worker", "exe": "/usr/bin/worker"})
		})
		if added, why := additive(current, changed); why != "" || len(added) != 1 || added[0].Name != "worker" {
			t.Errorf("an added watch entry answered %v %q, want it added", added, why)
		}
	})
}
