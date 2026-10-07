package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

func TestReloadDoesNotTreatTwoEmptyArgumentReadingsAsStable(t *testing.T) {
	// Constructed procfs: stat and cmdline are captured, then only cmdline is
	// changed. No namespace, executable, or process lifetime is modelled here.
	root := t.TempDir()
	pid := int32(os.Getpid())
	directory := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stat", "cmdline"} {
		data, err := os.ReadFile(filepath.Join("/proc/self", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	known, err := process.ReadExec(root, pid)
	if err != nil || known.Cmdline == "" {
		t.Fatalf("wiring: no captured command line: %+v, %v", known, err)
	}
	p := process.Process{PID: pid, StartTime: known.StartTime}
	if why, ok := unchanged(root, p, probe.Reading{Exec: known}); !ok {
		t.Fatalf("known control is refused: %s", why)
	}
	if err := os.WriteFile(filepath.Join(directory, "cmdline"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	empty, err := process.ReadExec(root, pid)
	if err != nil || empty.Cmdline != "" || empty.StartTime != known.StartTime {
		t.Fatalf("wiring: no empty command line at same birth: %+v, %v", empty, err)
	}
	t.Log("wiring: cmdline 0 bytes: 1 read; birth unchanged")
	if why, ok := unchanged(root, p, probe.Reading{Exec: empty}); ok ||
		!strings.Contains(why, "arguments undetermined") || !strings.Contains(why, strconv.Itoa(int(pid))) {
		t.Fatalf("two empty readings accepted or misreported: ok=%v, why=%s", ok, why)
	}
}

func TestResolutionRefusesUndeterminedArguments(t *testing.T) {
	for _, kind := range []string{"executable-only", "arguments", "exclusion"} {
		t.Run(kind, func(t *testing.T) {
			// Constructed procfs: capture a real stat record; deliberately supply
			// argv, exe and cgroup. Namespaces and listeners are not modelled.
			root := t.TempDir()
			pid := int32(os.Getpid())
			directory := filepath.Join(root, strconv.Itoa(int(pid)))
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			stat, err := os.ReadFile("/proc/self/stat")
			if err != nil {
				t.Fatal(err)
			}
			argv := "/bin/worker\x00"
			approval := process.Approval{Rules: []process.Rule{{Executable: "/bin/worker"}}}
			if kind == "arguments" {
				argv += "job\x00"
				approval.Rules[0].Arguments = []string{"job"}
			}
			if kind == "exclusion" {
				argv += "job\x00"
				approval.Rules = []process.Rule{{Cgroup: "/allowed"}}
				approval.Exclusions = []process.Rule{{Executable: "/bin/worker", Arguments: []string{"secret"}}}
			}
			for name, data := range map[string][]byte{"stat": stat, "cmdline": []byte(argv), "cgroup": []byte("0::/allowed\n")} {
				if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("/bin/worker", filepath.Join(directory, "exe")); err != nil {
				t.Fatal(err)
			}
			control, _, err := resolveFrom(root, approval)
			if err != nil || len(control.Selections) != 1 {
				t.Fatalf("wiring: known-arguments control did not select one process: %+v, %v", control, err)
			}
			if err := os.WriteFile(filepath.Join(directory, "cmdline"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			p, err := process.Identify(root, pid)
			if err != nil || p.Executable != "/bin/worker" || len(p.Arguments) != 0 {
				t.Fatalf("wiring: exe readable and cmdline empty not reached: %+v, %v", p, err)
			}
			t.Log("wiring: exe readable, cmdline 0 bytes: 1 read; known control selected: 1")
			begin := time.Now()
			resolution, _, err := resolveFrom(root, approval)
			if err == nil || !strings.Contains(err.Error(), "arguments undetermined") ||
				!strings.Contains(err.Error(), strconv.Itoa(int(pid))) || len(resolution.Selections) != 0 {
				t.Fatalf("shared command resolver failed to refuse this process: %+v, %v", resolution, err)
			}
			if elapsed := time.Since(begin); elapsed < process.ArgumentReadBound || elapsed > time.Second {
				t.Fatalf("shared command resolver did not apply retry bound: %s", elapsed)
			}
		})
	}
}
