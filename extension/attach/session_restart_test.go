//go:build attach

package attach_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/processing"
)

type restartSession struct {
	binary, path, output, log, approved string
	document                            map[string]any
	client                              *client
	group                               *os.File
	pid                                 int
	id, birth                           string
	beforeOutput, beforeLog             []byte
	outputInfo, logInfo                 os.FileInfo
}

func restartWrite(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("wiring, not the property: write configuration: %v", err)
	}
}

func restartJSON(t *testing.T, document map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func restartWait(t *testing.T, why string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(why)
}

func restartProcess(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	end := strings.LastIndex(string(b), ") ")
	if end < 0 {
		return ""
	}
	f := strings.Fields(string(b[end+2:]))
	if len(f) < 20 || f[0] == "Z" || f[0] == "X" {
		return ""
	}
	return f[19] // starttime is field 22, after pid and the parenthesised comm.
}

func restartHolder(output string) (int, string) {
	b, _ := os.ReadFile(filepath.Join(output, "observer.pid"))
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, ""
	}
	pid, _ := strconv.Atoi(f[0])
	return pid, f[1]
}

func (s *restartSession) command(t *testing.T, binary string, env []string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, binary, args...)
	c.Env = append(os.Environ(), env...)
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(s.group.Fd())}
	b, err := c.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("command timed out: %s: %s", args, b)
	}
	return b, err
}

func restartRunning(t *testing.T, binary string) *restartSession {
	t.Helper()
	root := t.TempDir()
	s := &restartSession{binary: binary, path: filepath.Join(root, "observer.json"), output: filepath.Join(root, "state")}
	s.log, s.approved = filepath.Join(s.output, "observer.log"), filepath.Join(s.output, processing.ArtifactName)
	s.client = speaking(t, serving(t))
	s.group = envelope(t)
	example, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(example, &s.document); err != nil {
		t.Fatal(err)
	}
	s.document["output"], s.document["log"], s.document["write_content"] = s.output, s.log, true
	s.document["watch"] = []any{map[string]any{"name": "client", "exe": s.client.process.Executable, "args": s.client.process.Arguments[1:]}}
	s.document["libraries"] = []any{}
	s.document["limits"] = map[string]any{"state_every_seconds": 1}
	valid := restartJSON(t, s.document)
	if _, err := policy.CompileProcessing(valid, root); err != nil {
		t.Fatalf("wiring, not the property: valid fixture: %v", err)
	}
	restartWrite(t, s.path, valid)
	// This cgroup belongs only to this case, including any detached replacement.
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(s.group.Name(), "cgroup.kill"), []byte("1"), 0o600) })
	out, err := s.command(t, binary, nil, "start", s.path, "--daemonize")
	if err != nil {
		t.Fatalf("wiring, not the property: initial start: %v: %s", err, out)
	}
	s.pid, s.id = restartHolder(s.output)
	s.birth = restartProcess(s.pid)
	if s.pid <= 0 || s.id == "" || s.birth == "" {
		t.Fatalf("wiring, not the property: original identity absent: %d %q %q", s.pid, s.id, s.birth)
	}
	s.client.ask(t, "/before-restart")
	restartWait(t, "wiring, not the property: original session did not write the eligible exchange", func() bool { return s.hasExchange(s.id, "/before-restart") })
	s.beforeOutput, err = os.ReadFile(s.approved)
	if err != nil {
		t.Fatal(err)
	}
	s.beforeLog, err = os.ReadFile(s.log)
	if err != nil {
		t.Fatal(err)
	}
	s.outputInfo, err = os.Stat(s.approved)
	if err != nil {
		t.Fatal(err)
	}
	s.logInfo, err = os.Stat(s.log)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(s.beforeLog, []byte(`"session":"`+s.id+`"`)) {
		t.Fatal("wiring, not the property: activation log does not name the original session")
	}
	return s
}

func (s *restartSession) hasExchange(id, path string) bool {
	b, _ := os.ReadFile(s.approved)
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var a processing.Artifact
		if json.Unmarshal(line, &a) == nil && a.Session == id && a.Record == "exchange" && bytes.Contains(line, []byte(strconv.Quote(path))) {
			return true
		}
	}
	return false
}

func (s *restartSession) unchanged(t *testing.T) {
	t.Helper()
	pid, id := restartHolder(s.output)
	if pid != s.pid || id != s.id || restartProcess(s.pid) != s.birth {
		t.Fatalf("refused restart lost the ORIGINAL process/session: got %d %q birth %q, want %d %q birth %q", pid, id, restartProcess(s.pid), s.pid, s.id, s.birth)
	}
	if _, err := os.Stat(filepath.Join(s.output, "sessions", s.id, "account.json")); !os.IsNotExist(err) {
		t.Errorf("refused restart sealed the original session: %v", err)
	}
	s.client.ask(t, "/after-refusal")
	restartWait(t, "original session stopped writing fresh eligible traffic after refusal", func() bool { return s.hasExchange(s.id, "/after-refusal") })
	for _, f := range []struct {
		path   string
		before []byte
		info   os.FileInfo
	}{{s.approved, s.beforeOutput, s.outputInfo}, {s.log, s.beforeLog, s.logInfo}} {
		after, err := os.ReadFile(f.path)
		if err != nil || !bytes.HasPrefix(after, f.before) {
			t.Errorf("refusal truncated output %s: %v", f.path, err)
		}
		info, err := os.Stat(f.path)
		if err != nil || !os.SameFile(info, f.info) {
			t.Errorf("refusal replaced output %s: %v", f.path, err)
		}
	}
}

func (s *restartSession) replaced(t *testing.T) {
	t.Helper()
	pid, id := restartHolder(s.output)
	if pid <= 0 || pid == s.pid || id == "" || id == s.id || restartProcess(pid) == "" {
		t.Fatalf("valid restart did not replace the session: old %d %s, new %d %s", s.pid, s.id, pid, id)
	}
	if restartProcess(s.pid) == s.birth {
		t.Error("restart left the original process alive")
	}
	if _, err := os.Stat(filepath.Join(s.output, "sessions", s.id, "account.json")); err != nil {
		t.Errorf("restart did not seal the original: %v", err)
	}
	content, err := os.ReadFile(s.log)
	if err != nil {
		t.Fatal(err)
	}
	var revision string
	for _, line := range bytes.Split(content, []byte{'\n'}) {
		var a struct {
			Record, Session string
			Policy          struct{ Revision string }
		}
		if json.Unmarshal(line, &a) == nil && a.Record == "activation-completed" && a.Session == id {
			revision = a.Policy.Revision
		}
	}
	checked, err := policy.CompileProcessing(restartJSON(t, s.document), filepath.Dir(s.path))
	if err != nil {
		t.Fatalf("wiring, not the property: checked configuration no longer compiles: %v", err)
	}
	if revision == "" || revision != checked.Revision {
		t.Errorf("replacement activated configuration %q, want checked %q", revision, checked.Revision)
	}
}

func TestRestartRefusalsPreserveOriginalSession(t *testing.T) {
	binary := built(t)
	for _, name := range []string{"stdout", "invalid-configuration", "processing-compilation"} {
		t.Run(name, func(t *testing.T) {
			s := restartRunning(t, binary)
			var candidate []byte
			var reason string
			switch name {
			case "stdout":
				s.document["log"] = "stdout"
				reason = "stdout"
				candidate = restartJSON(t, s.document)
			case "invalid-configuration":
				s.document["version"] = "observer.config/999"
				reason = "version"
				candidate = restartJSON(t, s.document)
			case "processing-compilation":
				s.document["extensions"] = []any{map[string]any{"name": "missing-command", "command": []string{"./missing-command"}, "fields": []string{"request.line"}, "timeout_ms": 250}}
				reason = "missing-command"
				candidate = restartJSON(t, s.document)
				if findings := config.CheckDocument(candidate); len(findings) != 0 {
					t.Fatalf("wiring, not the property: compilation fixture fails document reading: %v", findings)
				}
				if _, err := policy.CompileProcessing(candidate, filepath.Dir(s.path)); err == nil || !strings.Contains(err.Error(), reason) {
					t.Fatalf("wiring, not the property: fixture does not reach command compilation: %v", err)
				}
			}
			restartWrite(t, s.path, candidate)
			got, err := s.command(t, binary, nil, "restart", s.path)
			if err == nil {
				t.Errorf("invalid restart exited zero: %s", got)
			}
			if !bytes.Contains(bytes.ToLower(got), []byte(reason)) {
				t.Errorf("refusal did not name %q: %s", reason, got)
			}
			s.unchanged(t)
		})
	}
}

func TestRestartValidUnchangedConfiguration(t *testing.T) {
	s := restartRunning(t, built(t))
	out, err := s.command(t, s.binary, nil, "restart", s.path)
	if err != nil {
		t.Fatalf("valid unchanged restart refused: %v: %s", err, out)
	}
	s.replaced(t)
}

func TestRestartUsesCheckedConfigurationAfterFileChanges(t *testing.T) {
	binary := built(t)
	driver := filepath.Join(t.TempDir(), "restart-driver")
	build := exec.Command("go", "test", "-c", "-o", driver, "github.com/evandukss/edge-observer/cmd/observer")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: build restart driver: %v: %s", err, out)
	}
	for _, change := range []string{"invalid", "other-valid"} {
		t.Run(change, func(t *testing.T) {
			s := restartRunning(t, binary)
			before := restartJSON(t, s.document)
			var changed map[string]any
			if err := json.Unmarshal(before, &changed); err != nil {
				t.Fatal(err)
			}
			if change == "invalid" {
				changed["log"] = "stdout"
			} else {
				changed["watch"].([]any)[0].(map[string]any)["name"] = "other-client-name"
			}
			after := restartJSON(t, changed)
			replacement, receipt := filepath.Join(t.TempDir(), "replacement.json"), filepath.Join(t.TempDir(), "checked.txt")
			restartWrite(t, replacement, after)
			out, err := s.command(t, driver, []string{"OBSERVER_RESTART_TEST_DRIVER=1", "OBSERVER_RESTART_TEST_REPLACEMENT=" + replacement, "OBSERVER_RESTART_TEST_RECEIPT=" + receipt}, "restart", s.path)
			proof, readErr := os.ReadFile(receipt)
			want := fmt.Sprintf("%x\n%x\n", sha256.Sum256(before), sha256.Sum256(after))
			if readErr != nil || string(proof) != want {
				t.Fatalf("wiring, not the property: file change did not follow the check: %v %q; command %v: %s", readErr, proof, err, out)
			}
			now, readErr := os.ReadFile(s.path)
			if readErr != nil || !bytes.Equal(now, after) {
				t.Fatalf("wiring, not the property: changed file not installed: %v", readErr)
			}
			if err != nil {
				s.unchanged(t)
			} else {
				s.replaced(t)
			}
		})
	}
}
