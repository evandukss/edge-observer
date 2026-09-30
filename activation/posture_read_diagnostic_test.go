//go:build linux && p3t5diagnostic

package activation

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

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
	"golang.org/x/sys/unix"
)

// This diagnostic requires a prepared, dedicated cgroup-v2 container. The
// runner occupies a leaf below a root with the memory controller enabled.
// It records the observed classification; it does not assert the predicted
// Check value or change production behavior to obtain a particular answer.
func TestP3T5UnreadablePostureDiagnostic(t *testing.T) {
	runPostureReadConstruction(t, false)
}

func runPostureReadConstruction(t *testing.T, classify bool) {
	t.Helper()
	if mode := os.Getenv("P3T5_POSTURE_READ_MODE"); mode != "" {
		postureReadDiagnosticChild(t, mode, classify)
		return
	}
	const root = "/sys/fs/cgroup"
	parent, err := processState(os.Getpid())
	if err != nil || parent.Cgroup == "/" {
		t.Fatalf("setup: runner must occupy a leaf below the prepared root: state=%+v error=%v", parent, err)
	}
	parentDir, err := cgroupDirectory(parent.Cgroup)
	if err != nil {
		t.Fatal(err)
	}
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
	modes := []string{"compliant", "missing_memory_file"}
	if classify {
		modes = append(modes, "unlimited_memory", "missing_participant", "changed_participant")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			base := root
			if mode == "missing_memory_file" {
				base = parentDir
			}
			dir, err := os.MkdirTemp(base, "p3t5-posture-read-")
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
			defer group.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^"+testName+"$", "-test.v", "-test.count=1", "-test.timeout=25s")
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd())}
			cmd.Env = append(os.Environ(), "P3T5_POSTURE_READ_MODE="+mode, "P3T5_POSTURE_READ_GROUP="+strings.TrimPrefix(dir, root))
			output, err := cmd.CombinedOutput()
			t.Logf("CHILD mode=%s output:\n%s", mode, output)
			if err != nil {
				t.Fatalf("diagnostic child: %v", err)
			}
		})
	}
}

func postureReadDiagnosticChild(t *testing.T, mode string, classify bool) {
	t.Helper()
	if !slices.Contains([]string{"compliant", "missing_memory_file", "unlimited_memory", "missing_participant", "changed_participant"}, mode) {
		t.Fatalf("unknown diagnostic mode %q", mode)
	}
	group := os.Getenv("P3T5_POSTURE_READ_GROUP")
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !slices.Contains(strings.Split(string(membership), "\n"), "0::"+group) {
		t.Fatalf("setup: pre-exec placement not established: expected=%q actual=%q error=%v", group, membership, err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		t.Fatalf("setup: establish holder dumpability: %v", err)
	}
	parent, err := processState(os.Getppid())
	if err != nil {
		t.Fatalf("setup: identify outside participant: %v", err)
	}
	if withinCgroup(parent.Cgroup, group) {
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
	read, err := policy.CompileProcessing(written, nil)
	if err != nil {
		t.Fatalf("setup: supported policy refused: %v", err)
	}
	writer, err := processing.Open(outputDir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
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
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: uint64(read.Settings.AdmittedEventLimit), StorageExhausted: writer.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	record := func(operation string, err error) {
		t.Helper()
		var refusal *Refusal
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
		if classify && mode != "compliant" {
			check, detail := ExecutionMemory, "memory.max"
			if mode == "missing_participant" || mode == "changed_participant" {
				check, detail = NoParticipantRunning, "had exited"
			}
			unreadable := mode == "missing_memory_file"
			if refusal.Check != check || refusal.Unreadable != unreadable || !strings.Contains(refusal.Detail, detail) {
				t.Errorf("%s classification: Check=%s Unreadable=%t Detail=%q; want Check=%s Unreadable=%t detail containing %q", operation, refusal.Check, refusal.Unreadable, refusal.Detail, check, unreadable, detail)
			}
			if strings.Contains(refusal.Error(), string(PostureUnreadable)) != unreadable {
				t.Errorf("%s error text lost classification: %v", operation, refusal)
			}
		}
	}
	posture, err := Verify(gate, participants)
	t.Logf("VERIFY_POSTURE %+v", posture)
	record("Verify", err)
	if state := gate.Snapshot(); state.Charged != 0 || state.Reason != "" {
		t.Fatalf("verification changed gate state: %+v", state)
	}
	prepared, err := Prepare(read, participants, uint64(read.Settings.AdmittedEventLimit), writer.Exhausted())
	if prepared != nil {
		defer prepared.Intake.Close()
	}
	record("Prepare", err)
	if mode == "compliant" && prepared == nil {
		t.Fatal("compliant Prepare returned no capture")
	}
	if mode != "compliant" && prepared != nil {
		t.Fatal("refused Prepare returned a capture")
	}
}
