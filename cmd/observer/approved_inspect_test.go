package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/processing"
)

// The producer runs in a separate process and uses synthetic library events
// through the production controller, worker and writer. The inspection runs
// the public binary after that process exits. This does not establish live
// kernel attachment, nor author the independently owned condition-2 checks.
func TestApprovedInspectionSurvivesProducerExitAndPolicyChange(t *testing.T) {
	if destination := os.Getenv("OBSERVER_INSPECT_PRODUCER_DEST"); destination != "" {
		produceInspectionSession(t, destination)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	source := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	producer := exec.CommandContext(ctx, self, "-test.run=^TestApprovedInspectionSurvivesProducerExitAndPolicyChange$")
	producer.Env = append(os.Environ(), "OBSERVER_INSPECT_PRODUCER_DEST="+source)
	if result, err := producer.CombinedOutput(); err != nil {
		t.Fatalf("producer: %v\n%s", err, result)
	}
	if producer.ProcessState == nil || !producer.ProcessState.Exited() || !producer.ProcessState.Success() {
		t.Fatal("producer exit was not established")
	}
	copyDir := t.TempDir()
	copyApprovedSession(t, source, copyDir)
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(copyDir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("copy must contain only approved output and account: %v %v", entries, err)
	}
	binary := filepath.Join(t.TempDir(), "observer")
	if result, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build public command: %v\n%s", err, result)
	}
	local := t.TempDir()
	inspect := func() []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, "inspect", copyDir, "--text")
		command.Dir = local
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("public inspection: %v\n%s", err, out)
		}
		for _, want := range []string{"permitted-value", "public-body", "policy_revision=", "pipeline=\"exchanges\"", `"direction": "sent"`, `"offset": "0"`, `"ending"`} {
			if !bytes.Contains(out, []byte(want)) {
				t.Fatalf("exit success without permitted value/provenance %q:\n%s", want, out)
			}
		}
		return out
	}
	before := inspect()
	// A real, accepted local configuration now removes the formerly permitted
	// field. Its compiled identity must differ from the one the artifact names.
	configuration, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var next map[string]any
	if err := json.Unmarshal(configuration, &next); err != nil {
		t.Fatal(err)
	}
	next["remove"] = map[string]any{"headers": []string{"x-public"}}
	changed, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(local, "observer.config.json")
	if err := os.WriteFile(policyPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	compiled, err := loadProcessing(policyPath)
	if err != nil || compiled.ProcessingRevision == "" {
		t.Fatalf("changed-policy control is not executable: %v", err)
	}
	if bytes.Contains(before, []byte(compiled.ProcessingRevision)) {
		t.Fatal("changed policy did not establish a different processing identity")
	}
	if after := inspect(); !bytes.Equal(before, after) {
		t.Fatal("public inspection reinterpreted persisted output after local policy changed")
	}
	t.Log("producer process exited; only artifact/account copied; source removed; accepted local policy changed; public command still shows permitted values and capture-time provenance")
}

func produceInspectionSession(t *testing.T, destination string) {
	t.Helper()
	f := processingController(t)
	f.transfer(t, 7, fragment.Sent, "GET /public HTTP/1.1\r\nX-Public: permitted-value\r\n\r\n")
	f.transfer(t, 7, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\npublic-body")
	f.closed(t, 7)
	f.live = true
	f.halt(t)
	if err := f.finish(&logger{}); err != nil {
		t.Fatal(err)
	}
	// The exchange, and the connection's record beside it.
	if stats := f.d.output.Stats(); stats.Written != 2 || !stats.Closed {
		t.Fatalf("producer did not seal useful output: %+v", stats)
	}
	copyApprovedSession(t, f.d.directory, destination)
}

func copyApprovedSession(t *testing.T, source, destination string) {
	t.Helper()
	for _, name := range []string{sealedName, processing.ArtifactName} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApprovedInspectionFailsWhenNoRecordCanBeShown(t *testing.T) {
	source := t.TempDir()
	produceInspectionSession(t, source)
	for _, fault := range []string{"missing", "empty", "broken"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			copyApprovedSession(t, source, directory)
			var out bytes.Buffer
			if err := run([]string{"inspect", directory, "--text"}, &out); err != nil || !strings.Contains(out.String(), "permitted-value") || !strings.Contains(out.String(), "public-body") {
				t.Fatalf("decidable control displayed no useful output: %v\n%s", err, &out)
			}
			path := filepath.Join(directory, processing.ArtifactName)
			switch fault {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "empty", "broken":
				var contents []byte
				if fault == "broken" {
					contents = []byte("{broken}\n")
				}
				if err := os.WriteFile(path, contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			out.Reset()
			err := run([]string{"inspect", directory, "--text"}, &out)
			if err == nil || !strings.Contains(out.String(), "account    sealed") {
				t.Fatalf("fault must reach artifact read after valid account: %v\n%s", err, &out)
			}
			if fault == "missing" && !errors.Is(err, fs.ErrNotExist) || fault == "empty" && !errors.Is(err, processing.ErrNoArtifacts) || fault == "broken" && !strings.Contains(err.Error(), "record 1: invalid JSON") {
				t.Fatalf("wrong failure branch for %s: %v", fault, err)
			}
			t.Logf("%s reached after useful control: %v", fault, err)
		})
	}
}

type inspectionShortWriter struct{ calls int }

func (w *inspectionShortWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, nil
}

func TestApprovedInspectionDoesNotIgnoreAccountOutputFailure(t *testing.T) {
	directory := t.TempDir()
	produceInspectionSession(t, directory)
	var control bytes.Buffer
	if err := run([]string{"inspect", directory, "--text"}, &control); err != nil || !strings.Contains(control.String(), "public-body") {
		t.Fatalf("useful output control: %v", err)
	}
	var failed inspectionShortWriter
	if err := run([]string{"inspect", directory, "--text"}, &failed); !errors.Is(err, io.ErrShortWrite) || failed.calls != 1 {
		t.Fatalf("account output fault not reached or ignored: calls=%d err=%v", failed.calls, err)
	}
}
