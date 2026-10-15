package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/processing"
)

func stdoutConfiguration(t *testing.T, logToStdout bool) (string, string) {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	output := filepath.Join(root, "output")
	document["output"] = output
	if !logToStdout {
		document["log"] = filepath.Join(root, "observer.log")
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observer.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, output
}

func TestStdoutConflictsRefuseBeforeSessionSideEffects(t *testing.T) {
	for _, command := range [][]string{{"start", "--daemonize", "--stdout"}, {"restart", "--stdout"}, {"start", "--stdout"}} {
		t.Run(strings.Join(command, "-"), func(t *testing.T) {
			path, output := stdoutConfiguration(t, true)
			arguments := append([]string{command[0], path}, command[1:]...)
			called := false
			var stdout bytes.Buffer
			err := runWith(arguments, &stdout, commandDependencies{begin: func(policy.Policy, string, processing.WriterOptions) (*daemon, error) {
				called = true
				return nil, errors.New("unexpected begin")
			}})
			if err == nil || !strings.Contains(err.Error(), "stdout") {
				t.Fatalf("missing stdout refusal: %v", err)
			}
			if called || stdout.Len() != 0 {
				t.Fatalf("refusal reached activation/output: begin=%v bytes=%q", called, stdout.Bytes())
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refusal created session state: %v", err)
			}
		})
	}
}

func TestStdoutRoutesStartupFailureToStderr(t *testing.T) {
	path, output := stdoutConfiguration(t, false)
	var stdout, stderr bytes.Buffer
	refusal := errors.New("synthetic attachment refused")
	called := false
	err := runWith([]string{"start", path, "--stdout"}, &stdout, commandDependencies{
		stderr:   &stderr,
		stopping: make(chan os.Signal),
		begin: func(read policy.Policy, session string, options processing.WriterOptions) (*daemon, error) {
			called = true
			if read.Processing == nil || read.ProcessingRevision == "" || session == "" {
				t.Error("begin did not receive validated policy/session")
			}
			if options.Directory != output || options.Stdout == nil {
				t.Errorf("writer routing: %+v", options)
			}
			return nil, refusal
		},
	})
	if !errors.Is(err, refusal) || !called {
		t.Fatalf("begin wiring: called=%v err=%v", called, err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("operational bytes on approved stream: %s", stdout.Bytes())
	}
	var record failedStart
	if err := json.Unmarshal(stderr.Bytes(), &record); err != nil || record.Record != "start-failed" || record.Error != refusal.Error() {
		t.Fatalf("stderr startup record: %s, %v", stderr.Bytes(), err)
	}
	file, err := os.ReadFile(filepath.Join(filepath.Dir(path), "observer.log"))
	if err != nil || !bytes.Equal(file, stderr.Bytes()) {
		t.Fatalf("configured log lost record: %q %v", file, err)
	}
}
