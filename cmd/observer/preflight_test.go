package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/process"
)

// sleeping is a running process with no TLS library, and a configuration
// naming it, excluded as well where asked.
func sleeping(t *testing.T, excluded bool) (int32, string) {
	t.Helper()
	command := exec.Command("sleep", "600")
	if err := command.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	pid := int32(command.Process.Pid)

	// Wait on every field selection matches, not just the executable: exe and
	// cmdline are separate reads and an empty cmdline is valid, so a process read
	// too early would select nothing and fire the wiring guard spuriously.
	var p process.Process
	for range 200 {
		table, err := process.Read(procfs)
		if err != nil {
			t.Fatalf("read the processes: %v", err)
		}
		// Process.Arguments includes argv[0]; Rule.Arguments starts after it.
		if found, ok := table.Lookup(pid); ok && strings.HasSuffix(found.Executable, "sleep") &&
			len(found.Arguments) >= 2 && found.Arguments[1] == "600" {
			p = found
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.PID == 0 {
		t.Fatalf("pid %d is not running sleep with its arguments after two seconds", pid)
	}

	directory := t.TempDir()
	path := contractConfiguration(t, func(document map[string]any) {
		document["observer"].(map[string]any)["directory"] = directory
		target(document, "sleeper", p.Executable, "600")
		if excluded {
			// An exe with no args matches only a process run with none, so the exclusion
			// names them too.
			scope := document["observation_scope"].(map[string]any)
			scope["exclude"] = []any{map[string]any{"exe": p.Executable, "args": []string{"600"}}}
		}
	})
	return pid, path
}

func TestPreflightJudgesTheProcessesStartWouldAttachTo(t *testing.T) {
	pid, path := sleeping(t, false)
	var out bytes.Buffer
	err := run([]string{"preflight", path}, &out)

	var readiness preflight.Readiness
	if decodeErr := json.Unmarshal(out.Bytes(), &readiness); decodeErr != nil {
		t.Fatalf("the output is not a readiness: %v\n%s", decodeErr, out.String())
	}
	var judged *preflight.Requirement
	for i, r := range readiness.Requirements {
		if r.Name == preflight.TLSLibrary && r.PID == pid {
			judged = &readiness.Requirements[i]
		}
	}
	if judged == nil {
		t.Fatalf("wiring, not the property: pid %d, which the configuration selects, was not judged: %+v",
			pid, readiness.Requirements)
	}
	if judged.Status != preflight.Missing {
		t.Errorf("sleep, which maps no libssl, is %s: %s", judged.Status, judged.Found)
	}
	if readiness.Verdict != preflight.NotReady {
		t.Errorf("Verdict = %q with a target that cannot be observed", readiness.Verdict)
	}
	if err == nil || !strings.Contains(err.Error(), string(preflight.NotReady)) {
		t.Errorf("run returned %v, want a NOT READY refusal so the command exits non-zero", err)
	}
}

func TestPreflightDoesNotJudgeAProcessTheConfigurationExcludes(t *testing.T) {
	pid, path := sleeping(t, true)
	var out bytes.Buffer
	err := run([]string{"preflight", path, "--text"}, &out)

	if !strings.HasPrefix(out.String(), "verdict ") {
		t.Fatalf("the text form does not open with the verdict:\n%s", out.String())
	}
	if strings.Contains(out.String(), "pid "+strconv.Itoa(int(pid))) {
		t.Errorf("pid %d is excluded and was judged:\n%s", pid, out.String())
	}
	if !strings.Contains(out.String(), "INDETERMINATE  "+preflight.TLSLibrary+":") {
		t.Errorf("with nothing selected the TLS library is not reported indeterminate:\n%s", out.String())
	}
	if err == nil {
		t.Error("a host with nothing to observe was reported ready")
	}
}

func TestTheDeclaredKernelFloorIsTheOneTheObserverPublishes(t *testing.T) {
	if preflight.MinimumKernel != ebpf.MinimumKernel {
		t.Errorf("preflight declares %s and the observer publishes %s", preflight.MinimumKernel, ebpf.MinimumKernel)
	}
}
