package ebpf_test

// A constructed proc fixture that deliberately has no exe or argv.
import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
)

type executionFixture struct {
	t     *testing.T
	root  string
	pid   int32
	group process.Group
	tasks map[int32]struct{}
}

func executionWrite(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// Field numbers come from proc stat's format, independently of its parser.
// A comm containing spaces and both parentheses exercises its actual boundary.
// Templates begin as one-task groups; syncThreads prepares the final membership.
func executionStat(tid int32, state string, birth uint64) string {
	fields := make([]string, 52)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[1], fields[2] = fmt.Sprint(tid), "(service (worker) name)", state
	fields[3], fields[19], fields[21] = "1", "1", fmt.Sprint(birth)
	return strings.Join(fields, " ") + "\n"
}

func executionStatus(tgid, tid, nsGroup, nsTID int32, state string) string {
	name := map[string]string{
		"R": "running", "S": "sleeping", "D": "disk sleep",
		"T": "stopped", "t": "tracing stop", "W": "waking",
		"K": "wakekill", "P": "parked", "I": "idle",
		"Z": "zombie", "X": "dead", "x": "dead",
	}[state]
	return fmt.Sprintf("Name:\tservice\nState:\t%s (%s)\nTgid:\t%d\nPid:\t%d\nNStgid:\t%d\t%d\nNSpid:\t%d\t%d\nThreads:\t1\n", state, name, tgid, tid, tgid, nsGroup, tid, nsTID)
}

func newExecutionFixture(t *testing.T, state string) executionFixture {
	t.Helper()
	f := executionFixture{t: t, root: t.TempDir(), pid: 4101, tasks: make(map[int32]struct{})}
	dir := f.at("")
	executionWrite(t, filepath.Join(dir, "stat"), executionStat(f.pid, state, 12345))
	executionWrite(t, filepath.Join(dir, "status"), executionStatus(f.pid, f.pid, 17, 17, state))
	executionWrite(t, filepath.Join(dir, "ns/pid"), "namespace inode\n")
	info, err := os.Stat(filepath.Join(dir, "ns/pid"))
	if err != nil {
		t.Fatal(err)
	}
	ns := info.Sys().(*syscall.Stat_t)
	f.group = process.Group{Namespace: admission.Namespace{Device: uint64(ns.Dev), Inode: ns.Ino}, NamespacePID: 17, Start: admission.Determinate(12345)}
	f.task(f.pid, state, 12345, 17)
	executionWrite(t, filepath.Join(f.root, "self/mountinfo"), fmt.Sprintf("24 1 0:22 / %s rw - proc proc rw,hidepid=0\n", f.root))
	return f
}

func (f executionFixture) at(suffix string) string {
	return filepath.Join(f.root, fmt.Sprint(f.pid), suffix)
}
func (f executionFixture) task(tid int32, state string, birth uint64, nsTID int32) {
	f.t.Helper()
	dir := f.at(fmt.Sprintf("task/%d", tid))
	executionWrite(f.t, filepath.Join(dir, "stat"), executionStat(tid, state, birth))
	executionWrite(f.t, filepath.Join(dir, "status"), executionStatus(f.pid, tid, f.group.NamespacePID, nsTID, state))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0755); err != nil {
		f.t.Fatal(err)
	}
	// Every member of a real group resolves ns/pid to the SAME nsfs inode.
	if err := os.Link(f.at("ns/pid"), filepath.Join(dir, "ns/pid")); err != nil {
		f.t.Fatal(err)
	}
	f.tasks[tid] = struct{}{}
}

// Synchronize the constructed kernel's group count before observation, and
// after a supervised membership change. Count directory entries independently
// of the reader. Only described tasks have files to update; the large budget
// fixture also deliberately contains entries whose files cannot be read.
func (f executionFixture) syncThreads() {
	f.t.Helper()
	entries, err := os.ReadDir(f.at("task"))
	if errors.Is(err, os.ErrNotExist) {
		return // The disappearance fixture has removed the entire group.
	}
	if err != nil {
		f.t.Fatal(err)
	}
	count := len(entries)
	directories := []string{f.at("")}
	for tid := range f.tasks {
		directories = append(directories, f.at(fmt.Sprintf("task/%d", tid)))
	}
	for _, directory := range directories {
		for _, file := range []string{"stat", "status"} {
			name := filepath.Join(directory, file)
			data, err := os.ReadFile(name)
			if errors.Is(err, os.ErrNotExist) {
				continue // Preserve deliberately lost files.
			}
			if err != nil {
				f.t.Fatal(err)
			}
			content := string(data)
			if file == "stat" {
				content = executionStatThreads(content, count)
			} else {
				lines := strings.Split(content, "\n")
				for i, line := range lines {
					if strings.HasPrefix(line, "Threads:") {
						lines[i] = fmt.Sprintf("Threads:\t%d", count)
					}
				}
				content = strings.Join(lines, "\n")
			}
			// Missing or malformed fields remain malformed. No identity,
			// state, or deliberately missing evidence is repaired here.
			executionWrite(f.t, name, content)
			if file == "status" && strings.Contains(content, "Threads:") {
				actual, err := os.ReadFile(name)
				if err != nil {
					f.t.Fatal(err)
				}
				for _, line := range strings.Split(string(actual), "\n") {
					if strings.HasPrefix(line, "Threads:") {
						var threads int
						if _, err := fmt.Sscanf(line, "Threads: %d", &threads); err != nil || threads != len(entries) {
							f.t.Fatalf("fixture: %s Threads=%d, task entries=%d: %v", name, threads, len(entries), err)
						}
					}
				}
			}
		}
	}
}

func executionStatThreads(stat string, count int) string {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return stat
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 18 {
		return stat
	}
	fields[17] = fmt.Sprint(count) // Field 20, after pid and comm.
	return stat[:end+1] + " " + strings.Join(fields, " ") + "\n"
}
func (f executionFixture) selection() admission.Selection {
	return admission.Selection{ObserverPID: f.pid, Instance: admission.Instance{Namespace: f.group.Namespace, PID: f.group.NamespacePID, Start: f.group.Start, Generation: 71}, Mode: admission.ModeFollow}
}
func (f executionFixture) inspect() process.Execution {
	f.syncThreads()
	return process.Inspect(f.root, f.pid, f.group)
}

func executionResult(t *testing.T, one admission.Selection, read process.Execution, want ebpf.Ended) ebpf.Withdrawal {
	t.Helper()
	got := ebpf.WhatBecameOf(one, read)
	if got.State != want {
		t.Errorf("execution verdict: got %q want %q; %+v", got.State, want, read)
	}
	if !reflect.DeepEqual(got.Selection, one) {
		t.Errorf("result changed the recorded admission: %+v", got.Selection)
	}
	if strings.TrimSpace(got.Evidence) == "" {
		t.Error("result lost its evidence")
	}
	return got
}

func TestExecutionNonterminalLeaderNeedsNoExecutable(t *testing.T) {
	for _, state := range []string{"R", "S", "D", "T", "t", "W", "K", "P", "I"} {
		t.Run(state, func(t *testing.T) {
			f := newExecutionFixture(t, state)
			if _, err := os.Readlink(f.at("exe")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("fixture: exe absence: %v", err)
			}
			read := f.inspect()
			executionResult(t, f.selection(), read, ebpf.GrantEndedWhileRunning)
			if read.Witness.TID != f.pid || read.Witness.State != process.TaskState(state[0]) {
				t.Errorf("leader witness: %+v", read.Witness)
			}
		})
	}
}

func TestExecutionUnknownOriginalCannotClaimSame(t *testing.T) {
	for _, field := range []string{"birth", "namespace", "namespace-pid"} {
		t.Run(field, func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			switch field {
			case "birth":
				f.group.Start = admission.Start{}
			case "namespace":
				f.group.Namespace = admission.Namespace{}
			case "namespace-pid":
				f.group.NamespacePID = 0
			}
			read := f.inspect()
			executionResult(t, f.selection(), read, ebpf.ExecutionIndeterminate)
			if len(read.Failed) == 0 {
				t.Error("unknown original identity lost the refused operation")
			}
		})
	}
}

func TestExecutionUnreadabilityIsNotAnEnding(t *testing.T) {
	cases := []struct {
		name, file, content string
		remove              bool
	}{
		{"malformed-stat", "stat", "not a stat", false},
		{"short-stat", "stat", "4101 (service) S 1", false},
		{"missing-birth", "stat", executionStat(4101, "S", 12345), false},
		{"unknown-state", "stat", executionStat(4101, "Q", 12345), false},
		{"wide-state", "stat", executionStat(4101, "SS", 12345), false},
		{"malformed-status", "status", "Tgid: invalid\nNStgid: invalid\n", false},
		{"missing-nstgid", "status", "Tgid: 4101\nNSpid: 4101 17\n", false},
		{"namespace-unreadable", "ns/pid", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			if tc.name == "missing-birth" {
				tc.content = strings.Replace(tc.content, "12345", "unavailable", 1)
			}
			if tc.remove {
				if err := os.Remove(f.at(tc.file)); err != nil {
					t.Fatal(err)
				}
			} else {
				executionWrite(t, f.at(tc.file), tc.content)
			}
			read := f.inspect()
			executionResult(t, f.selection(), read, ebpf.ExecutionIndeterminate)
			if len(read.Failed) == 0 {
				t.Error("unreadability lost the failed operation")
			}
			// A separate readable admission must still give its positive answer.
			control := newExecutionFixture(t, "S")
			executionResult(t, control.selection(), control.inspect(), ebpf.GrantEndedWhileRunning)
		})
	}
}

func TestExecutionRefusedOperationSurvivesDecision(t *testing.T) {
	for _, refused := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(refused.Error(), func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			read := process.Execution{Expected: f.group, ObserverPID: f.pid, Failed: []process.Operation{{What: "read task 4102 stat", Err: refused}}, Observed: process.Interval{From: time.Unix(100, 4), To: time.Unix(100, 8)}}
			got := executionResult(t, f.selection(), read, ebpf.ExecutionIndeterminate)
			if !reflect.DeepEqual(got.Reading, read) || !strings.Contains(got.Evidence, "read task 4102 stat") || !strings.Contains(got.Evidence, refused.Error()) {
				t.Errorf("failed operation lost in projection: %+v", got)
			}
		})
	}
}

func TestExecutionSiblingIsPositiveEvidenceAtTheSameThreadCount(t *testing.T) {
	for _, state := range []string{"S", "Z"} {
		t.Run(state, func(t *testing.T) {
			f := newExecutionFixture(t, "Z")
			f.task(4102, state, 12888, 23)
			read := f.inspect()
			if state == "S" {
				executionResult(t, f.selection(), read, ebpf.GrantEndedWhileRunning)
				if read.Witness.TID != 4102 || read.Witness.Start != admission.Determinate(12888) || read.Current != f.group {
					t.Errorf("sibling substituted its own identity for the group: %+v", read)
				}
			} else {
				got := ebpf.WhatBecameOf(f.selection(), read)
				if got.State != ebpf.ExecutionEnded && got.State != ebpf.ExecutionIndeterminate {
					t.Errorf("all-zombie group reported running: %+v", got)
				}
			}
		})
	}
}

func TestExecutionLostCandidateDoesNotEraseAnotherWitness(t *testing.T) {
	for _, fault := range []string{"vanished", "unknown-state", "missing-tgid", "other-group", "other-namespace"} {
		for _, control := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/control=%t", fault, control), func(t *testing.T) {
				f := newExecutionFixture(t, "Z")
				f.task(4102, "S", 12888, 23)
				switch fault {
				case "vanished":
					if err := os.Remove(f.at("task/4102/stat")); err != nil {
						t.Fatal(err)
					}
				case "unknown-state":
					executionWrite(t, f.at("task/4102/stat"), executionStat(4102, "?", 12888))
				case "other-group":
					executionWrite(t, f.at("task/4102/status"), executionStatus(8001, 4102, 19, 23, "S"))
				case "missing-tgid":
					executionWrite(t, f.at("task/4102/status"), "NStgid: 4101 17\nNSpid: 4102 23\n")
				case "other-namespace":
					if err := os.Remove(f.at("task/4102/ns/pid")); err != nil {
						t.Fatal(err)
					}
					executionWrite(t, f.at("task/4102/ns/pid"), "another nsfs inode\n")
				}
				if control {
					f.task(4103, "S", 12999, 24)
				}
				read := f.inspect()
				want := ebpf.ExecutionIndeterminate
				if control {
					want = ebpf.GrantEndedWhileRunning
				}
				executionResult(t, f.selection(), read, want)
				if control && read.Witness.TID != 4103 {
					t.Errorf("replacement/lost candidate borrowed as witness: %+v", read.Witness)
				}
				if !control && len(read.Failed) == 0 {
					t.Error("unresolved candidate has no failed operation")
				}
			})
		}
	}
}

func TestExecutionDisappearanceRequiresVisibility(t *testing.T) {
	for _, visibility := range []string{"0", "1", "2", "4", "invisible", "ptraceable", "missing"} {
		t.Run(visibility, func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			if err := os.RemoveAll(f.at("")); err != nil {
				t.Fatal(err)
			}
			if visibility == "missing" {
				if err := os.Remove(f.root + "/self/mountinfo"); err != nil {
					t.Fatal(err)
				}
			} else {
				executionWrite(t, f.root+"/self/mountinfo", fmt.Sprintf("24 1 0:22 / %s rw - proc proc rw,hidepid=%s\n", f.root, visibility))
			}
			read := f.inspect()
			want := ebpf.ExecutionIndeterminate
			if visibility == "0" || visibility == "1" {
				want = ebpf.ExecutionEnded
			}
			executionResult(t, f.selection(), read, want)
			if want == ebpf.ExecutionIndeterminate && len(read.Failed) == 0 {
				t.Error("unestablished visibility has no refusal evidence")
			}
		})
	}
}

func TestExecutionReplacementBeforeOpenCannotBorrowLiveness(t *testing.T) {
	for _, birth := range []uint64{12345, 12346} {
		t.Run(fmt.Sprint(birth), func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			executionWrite(t, f.at("stat"), executionStat(f.pid, "S", birth))
			want := ebpf.GrantEndedWhileRunning
			if birth != 12345 {
				want = ebpf.ExecutionEnded
			}
			executionResult(t, f.selection(), f.inspect(), want)
		})
	}
}

func TestExecutionBudgetCannotTurnPartialIntoEmpty(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprint(live), func(t *testing.T) {
			f := newExecutionFixture(t, "Z")
			if live {
				f.task(4102, "S", 12888, 23)
			}
			end := int32(4400)
			if live {
				end = 4220
			}
			for i := int32(4200); i < end; i++ {
				f.task(i, "Z", 13000+uint64(i), i-4000)
			}
			read := f.inspect()
			if read.Budget != 64 || read.Spent > 64 || read.Spent <= 0 {
				t.Errorf("operation budget (directory opens, enumeration batches, file reads, retries): %+v", read)
			}
			if live {
				executionResult(t, f.selection(), read, ebpf.GrantEndedWhileRunning)
			} else {
				executionResult(t, f.selection(), read, ebpf.ExecutionIndeterminate)
				if !read.Capped || read.Spent != read.Budget {
					t.Errorf("capped walk lost partial-work evidence: %+v", read)
				}
			}
		})
	}
}

func TestExecutionEvidenceOutlivesTheWitness(t *testing.T) {
	f := newExecutionFixture(t, "Z")
	f.task(4102, "S", 12888, 23)
	before := time.Now()
	read := f.inspect()
	after := time.Now()
	got := executionResult(t, f.selection(), read, ebpf.GrantEndedWhileRunning)
	if err := os.RemoveAll(f.at("")); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Reading, read) {
		t.Error("projection did not retain the observation")
	}
	if got.Reading.Current != f.group || got.Reading.Expected != f.group || got.Reading.ObserverPID != 4101 || got.Reading.Witness.TID != 4102 || got.Reading.Witness.State != 'S' || got.Reading.Witness.Start != admission.Determinate(12888) {
		t.Errorf("retained identity or witness changed: %+v", got.Reading)
	}
	interval := got.Reading.Observed
	if interval.From.Before(before) || interval.To.Before(interval.From) || interval.To.After(after) || interval.From.IsZero() || interval.To.IsZero() {
		t.Errorf("observation interval lost: %+v", interval)
	}
	clock := strings.ToLower(interval.Clock())
	if !strings.Contains(clock, "unix") || !strings.Contains(clock, "monotonic") {
		t.Errorf("interval has no clock/reference: %q", interval.Clock())
	}
	for _, part := range []string{"4102", "12888", "12345", "S"} {
		if !strings.Contains(got.Evidence, part) {
			t.Errorf("retained evidence omitted %q: %s", part, got.Evidence)
		}
	}
}

func TestExecutionDecisionPreservesEveryObservationKind(t *testing.T) {
	for _, tc := range []struct {
		kind process.Liveness
		want ebpf.Ended
	}{
		{process.LivenessUnestablished, ebpf.ExecutionIndeterminate},
		{process.LivenessRunning, ebpf.GrantEndedWhileRunning},
		{process.LivenessGone, ebpf.ExecutionEnded},
		{process.LivenessTerminated, ebpf.ExecutionEnded},
		{process.LivenessReplaced, ebpf.ExecutionEnded},
	} {
		t.Run(fmt.Sprint(tc.kind), func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			read := process.Execution{Expected: f.group, Current: f.group, ObserverPID: f.pid, Liveness: tc.kind, Observed: process.Interval{From: time.Unix(100, 0), To: time.Unix(100, 10)}}
			if tc.kind == process.LivenessRunning {
				read.Witness = process.Witness{TID: f.pid, State: 'S', Start: f.group.Start}
			}
			if tc.kind == process.LivenessReplaced {
				read.Current.Start = admission.Determinate(22222)
			}
			got := executionResult(t, f.selection(), read, tc.want)
			if !reflect.DeepEqual(got.Reading, read) {
				t.Error("decision lost the original reading")
			}
		})
	}
}
