//go:build linux && attach

package attach_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"golang.org/x/sys/unix"
)

// The attach runner prepares a dedicated cgroup-v2 root with memory enabled
// and places the runner in a populated leaf without child memory control.
func TestPostureReadClassification(t *testing.T) {
	if mode := os.Getenv("POSTURE_READ_MODE"); mode != "" {
		postureReadClassificationChild(t, mode)
		return
	}
	const root = "/sys/fs/cgroup"
	parent := postureReadParticipant(t, os.Getpid())
	if parent.Cgroup == "/" {
		t.Fatalf("setup: runner must occupy a leaf below the prepared root: state=%+v", parent)
	}
	parentDir := filepath.Join(root, strings.TrimPrefix(parent.Cgroup, "/"))
	read := func(name string) string {
		t.Helper()
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("setup: read %s: %v", name, err)
		}
		return string(content)
	}
	rootControl := read(filepath.Join(root, "cgroup.subtree_control"))
	parentControl := read(filepath.Join(parentDir, "cgroup.subtree_control"))
	parentMembers := read(filepath.Join(parentDir, "cgroup.procs"))
	if !slices.Contains(strings.Fields(rootControl), "memory") ||
		slices.Contains(strings.Fields(parentControl), "memory") ||
		!slices.Contains(strings.Fields(parentMembers), strconv.Itoa(os.Getpid())) {
		t.Fatalf("setup: need delegated root and populated runner with no child memory controller: root=%q runner=%q members=%q", rootControl, parentControl, parentMembers)
	}
	t.Logf("CONSTRUCTION runner_pid=%d runner_cgroup=%q root_subtree_control=%q runner_subtree_control=%q runner_members=%q", os.Getpid(), parent.Cgroup, rootControl, parentControl, parentMembers)
	testName := t.Name()
	modes := []string{"compliant", "missing_memory_file", "unlimited_memory", "missing_participant", "changed_participant"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			base := root
			if mode == "missing_memory_file" {
				base = parentDir
			}
			dir, err := os.MkdirTemp(base, "posture-read-")
			if err != nil {
				t.Fatalf("setup: create owned cgroup: %v", err)
			}
			t.Cleanup(func() {
				if err := os.Remove(dir); err != nil {
					t.Errorf("remove owned cgroup %s: %v", dir, err)
				}
			})
			if mode != "missing_memory_file" {
				limit := "1073741824"
				if mode == "unlimited_memory" {
					limit = "max"
				}
				for name, value := range map[string]string{"memory.max": limit, "memory.swap.max": "0"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
						t.Fatalf("setup: configure %s: %v", name, err)
					}
				}
			} else if _, err := os.ReadFile(filepath.Join(dir, "memory.max")); !os.IsNotExist(err) {
				t.Fatalf("setup: missing-file fault not reached: memory.max read error=%v", err)
			}
			group, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := group.Close(); err != nil {
					t.Errorf("close cgroup handle: %v", err)
				}
			}()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^"+testName+"$", "-test.v", "-test.count=1", "-test.timeout=25s")
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd())}
			cmd.Env = append(os.Environ(), "POSTURE_READ_MODE="+mode, "POSTURE_READ_GROUP="+strings.TrimPrefix(dir, root))
			output, err := cmd.CombinedOutput()
			t.Logf("CHILD mode=%s output:\n%s", mode, output)
			if err != nil {
				t.Fatalf("classification child: %v", err)
			}
		})
	}
}

func postureReadClassificationChild(t *testing.T, mode string) {
	t.Helper()
	if !slices.Contains([]string{"compliant", "missing_memory_file", "unlimited_memory", "missing_participant", "changed_participant"}, mode) {
		t.Fatalf("unknown classification mode %q", mode)
	}
	group := os.Getenv("POSTURE_READ_GROUP")
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !slices.Contains(strings.Split(string(membership), "\n"), "0::"+group) {
		t.Fatalf("setup: pre-exec placement not established: expected=%q actual=%q error=%v", group, membership, err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		t.Fatalf("setup: establish holder dumpability: %v", err)
	}
	parent := postureReadParticipant(t, os.Getppid())
	if parent.Cgroup == group || strings.HasPrefix(parent.Cgroup, group+"/") {
		t.Fatalf("setup: participant %q is not outside %q", parent.Cgroup, group)
	}
	limitPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(group, "/"), "memory.max")
	limit, limitErr := os.ReadFile(limitPath)
	t.Logf("ACTUAL mode=%s holder_pid=%d membership=%q participant=%+v memory_path=%q memory_value=%q memory_read_error=%v not_exist=%t", mode, os.Getpid(), membership, parent, limitPath, limit, limitErr, os.IsNotExist(limitErr))
	if mode == "missing_memory_file" && !os.IsNotExist(limitErr) {
		t.Fatalf("setup: child did not reach missing memory.max: %v", limitErr)
	}
	expectedLimit := "1073741824"
	if mode == "unlimited_memory" {
		expectedLimit = "max"
	}
	if mode != "missing_memory_file" && (limitErr != nil || strings.TrimSpace(string(limit)) != expectedLimit) {
		t.Fatalf("setup: expected memory limit %q absent: value=%q error=%v", expectedLimit, limit, limitErr)
	}
	outputDir := t.TempDir()
	written, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var declaration map[string]any
	if err := json.Unmarshal(written, &declaration); err != nil {
		t.Fatal(err)
	}
	declaration["output"], declaration["log"] = outputDir, config.LogStdout
	written, err = json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	read, err := policy.CompileProcessing(written, "")
	if err != nil {
		t.Fatalf("setup: supported policy refused: %v", err)
	}
	participants := []process.Process{{PID: parent.PID, StartTime: parent.StartTime}}
	if mode == "missing_participant" {
		participants[0].PID = 2147483647
		if _, err := os.ReadFile("/proc/2147483647/stat"); !os.IsNotExist(err) {
			t.Fatalf("setup: participant read fault not established: %v", err)
		}
	}
	if mode == "changed_participant" {
		participants[0].StartTime++
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: uint64(read.Settings.AdmittedEventLimit)})
	if err != nil {
		t.Fatal(err)
	}
	record := func(operation string, err error) {
		t.Helper()
		var refusal *activation.Refusal
		typed := errors.As(err, &refusal)
		result := map[string]any{"operation": operation, "mode": mode, "holder_pid": os.Getpid(), "accepted": err == nil, "typed_refusal": typed}
		if err != nil {
			result["error"] = err.Error()
		}
		if typed {
			result["Check"], result["Detail"], result["PID"] = refusal.Check, refusal.Detail, refusal.PID
			result["Unreadable"] = refusal.Unreadable
		}
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		t.Logf("RESULT %s", encoded)
		if mode == "compliant" && err != nil {
			t.Fatalf("compliant activation control refused: %v", err)
		}
		if mode != "compliant" && (!typed || refusal.PID != os.Getpid() || refusal.Check == "" || refusal.Detail == "") {
			t.Fatalf("fault did not produce an identified, named refusal: %v", err)
		}
		if mode != "compliant" {
			check, detail := activation.ExecutionMemory, "memory.max"
			if mode == "missing_participant" || mode == "changed_participant" {
				check, detail = activation.NoParticipantRunning, "had exited"
			}
			unreadable := mode == "missing_memory_file"
			if refusal.Check != check || refusal.Unreadable != unreadable || !strings.Contains(refusal.Detail, detail) {
				t.Errorf("%s classification: Check=%s Unreadable=%t Detail=%q; want Check=%s Unreadable=%t detail containing %q", operation, refusal.Check, refusal.Unreadable, refusal.Detail, check, unreadable, detail)
			}
			if strings.Contains(refusal.Error(), string(activation.PostureUnreadable)) != unreadable {
				t.Errorf("%s error text lost classification: %v", operation, refusal)
			}
		}
	}
	posture, err := activation.Verify(gate, participants)
	t.Logf("VERIFY_POSTURE %+v", posture)
	record("Verify", err)
	if state := gate.Snapshot(); state.Charged != 0 || state.Reason != "" {
		t.Fatalf("verification changed gate state: %+v", state)
	}
	prepared, err := activation.Prepare(read, participants, uint64(read.Settings.AdmittedEventLimit))
	if prepared != nil {
		defer func() {
			if err := prepared.Intake.Close(); err != nil {
				t.Errorf("close prepared intake: %v", err)
			}
		}()
	}
	record("Prepare", err)
	if mode == "compliant" && prepared == nil {
		t.Fatal("compliant Prepare returned no capture")
	}
	if mode != "compliant" && prepared != nil {
		t.Fatal("refused Prepare returned a capture")
	}
}

// Identify and cgroup membership are bracketed by birth readings so the fixture
// never credits a parent's membership to a different process.
func postureReadParticipant(t *testing.T, pid int) activation.ParticipantState {
	t.Helper()
	before, err := process.Identify("/proc", int32(pid))
	if err != nil || before.StartTime == 0 {
		t.Fatalf("setup: identify participant %d: %+v, %v", pid, before, err)
	}
	group := unifiedCgroup(t, int32(pid))
	if !strings.HasPrefix(group, "/") || filepath.Clean(group) != group {
		t.Fatalf("setup: participant has an unresolvable cgroup: %q", group)
	}
	after, err := process.Identify("/proc", int32(pid))
	if err != nil || before.StartTime != after.StartTime {
		t.Fatalf("setup: participant %d changed during membership read: %v", pid, err)
	}
	return activation.ParticipantState{PID: int32(pid), StartTime: before.StartTime, Cgroup: group}
}
