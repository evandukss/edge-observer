package process_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/process"
)

// These tests read the real /proc and start real children: a hand-written
// tree would encode its author's beliefs about the kernel. A host with no
// /proc fails here rather than skipping.
const procfs = "/proc"

// install copies source to path, so processes can be told apart by executable.
func install(t *testing.T, source, path string) string {
	t.Helper()

	program, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	if err := os.WriteFile(path, program, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// run starts path and returns its pid once the kernel is running that file,
// killing it at test end. Until the exec, /proc describes the child as a copy
// of the test binary.
func run(t *testing.T, path string, arguments ...string) int32 {
	t.Helper()

	command := exec.Command(path, arguments...)
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", path, err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	pid := int32(command.Process.Pid)
	for range 200 {
		if p, ok := read(t).Lookup(pid); ok && p.Executable == path {
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d is not running %s after two seconds", pid, path)
	return 0
}

// sleeper installs a copy of /bin/sleep at path and starts it.
func sleeper(t *testing.T, path string, arguments ...string) int32 {
	t.Helper()
	return run(t, install(t, "/bin/sleep", path), append([]string{"600"}, arguments...)...)
}

func read(t *testing.T) process.Table {
	t.Helper()

	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("Read(%s): %v", procfs, err)
	}
	return table
}

func find(t *testing.T, table process.Table, pid int32) process.Process {
	t.Helper()

	found, ok := table.Lookup(pid)
	if !ok {
		t.Fatalf("pid %d is absent from a table of %d processes", pid, len(table.All()))
	}
	return found
}

func TestReadDescribesTheProcessDoingTheReading(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	self := find(t, read(t), int32(os.Getpid()))

	if self.Executable != executable {
		t.Errorf("Executable = %q, want %q", self.Executable, executable)
	}
	if len(self.Arguments) == 0 || self.Arguments[0] != os.Args[0] {
		t.Errorf("Arguments = %q, want argv beginning %q", self.Arguments, os.Args[0])
	}
	if self.PPID != int32(os.Getppid()) {
		t.Errorf("PPID = %d, want %d", self.PPID, os.Getppid())
	}
	if self.StartTime == 0 {
		t.Error("StartTime = 0; a running process started at some point")
	}
}

// A process name in /proc/<pid>/stat may hold spaces and parentheses, so later
// fields are found from the last closing parenthesis; splitting on whitespace
// shifts every later field.
func TestReadParsesAProcessWhoseNameHoldsSpacesAndParentheses(t *testing.T) {
	directory := t.TempDir()
	awkward := sleeper(t, filepath.Join(directory, "a) b (c"))
	plain := sleeper(t, filepath.Join(directory, "plain"))

	table := read(t)
	got, want := find(t, table, awkward), find(t, table, plain)

	if got.StartTime == 0 {
		t.Fatal("StartTime = 0 for a process whose name holds spaces and parentheses")
	}
	// Started within a tick or two of each other, so a misread StartTime lands far
	// from its sibling's.
	if difference := int64(got.StartTime) - int64(want.StartTime); difference < -200 || difference > 200 {
		t.Fatalf("StartTime = %d, but a process started beside it reads %d", got.StartTime, want.StartTime)
	}
	if got.PPID != int32(os.Getpid()) {
		t.Fatalf("PPID = %d, want %d", got.PPID, os.Getpid())
	}
}

func TestReadIsStableAcrossTwoReadsOfOneProcess(t *testing.T) {
	pid := sleeper(t, filepath.Join(t.TempDir(), "stable"))

	first := find(t, read(t), pid)
	time.Sleep(20 * time.Millisecond)
	second := find(t, read(t), pid)

	if first.StartTime != second.StartTime {
		t.Fatalf("StartTime moved between two reads: %d then %d", first.StartTime, second.StartTime)
	}
	if first.Identity() != second.Identity() {
		t.Fatalf("Identity moved between two reads: %+v then %+v", first.Identity(), second.Identity())
	}
}

func TestApprovalSelectsTheApprovedProcessesAndNoOthers(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first")
	second := filepath.Join(directory, "second")
	third := filepath.Join(directory, "third")

	approved := []int32{sleeper(t, first), sleeper(t, second)}
	unapproved := sleeper(t, third)

	approval := process.Approval{Rules: []process.Rule{
		{Executable: first, Arguments: []string{"600"}},
		{Executable: second, Arguments: []string{"600"}},
	}}

	selected := pids(approval.Select(read(t)))

	for _, pid := range approved {
		if !selected[pid] {
			t.Errorf("approved pid %d is not selected", pid)
		}
	}
	if selected[unapproved] {
		t.Errorf("pid %d is selected although no rule names %s", unapproved, third)
	}
	if selected[int32(os.Getpid())] {
		t.Errorf("the observing process %d is selected although no rule names it", os.Getpid())
	}
	if got, want := len(selected), len(approved); got != want {
		t.Errorf("%d processes selected, want %d: %v", got, want, selected)
	}
}

// One interpreter under two configurations is two approved processes; matching
// the executable alone would approve both, and every other user of it.
func TestApprovalSeparatesTwoProcessesOfOneExecutableByTheirArguments(t *testing.T) {
	program := install(t, "/bin/sleep", filepath.Join(t.TempDir(), "interpreter"))

	approved := run(t, program, "600", "1")
	other := run(t, program, "600", "2")

	approval := process.Approval{Rules: []process.Rule{
		{Executable: program, Arguments: []string{"600", "1"}},
	}}

	selected := pids(approval.Select(read(t)))

	if !selected[approved] {
		t.Errorf("pid %d is not selected although a rule names its arguments", approved)
	}
	if selected[other] {
		t.Errorf("pid %d is selected although its arguments differ from every rule", other)
	}
}

// A per-connection forking server transfers in its children, so they are
// observed with it.
func TestApprovalSelectsTheChildrenOfAnApprovedProcess(t *testing.T) {
	directory := t.TempDir()
	parent := filepath.Join(directory, "parent")
	stranger := filepath.Join(directory, "stranger")

	install(t, "/bin/sh", parent)
	parentPID := run(t, parent, "-c", "sleep 600 & wait")
	strangerPID := sleeper(t, stranger)

	approval := process.Approval{Rules: []process.Rule{
		{Executable: parent, Arguments: []string{"-c", "sleep 600 & wait"}},
	}}

	// The child is forked after the parent starts.
	var selected map[int32]bool
	for range 100 {
		time.Sleep(20 * time.Millisecond)
		selected = pids(approval.Select(read(t)))
		if len(selected) > 1 {
			break
		}
	}

	if !selected[parentPID] {
		t.Fatalf("pid %d is not selected although a rule names it", parentPID)
	}
	if len(selected) < 2 {
		t.Fatalf("%d processes selected; the child of an approved process is not among them", len(selected))
	}
	if selected[strangerPID] {
		t.Errorf("pid %d is selected although neither it nor any ancestor is approved", strangerPID)
	}
}

// An empty approval observes nothing, never everything.
func TestAnApprovalWithNoRulesSelectsNothing(t *testing.T) {
	sleeper(t, filepath.Join(t.TempDir(), "running"))

	if selected := (process.Approval{}).Select(read(t)); len(selected) != 0 {
		t.Fatalf("%d processes selected from an approval with no rules", len(selected))
	}
}

func pids(processes []process.Process) map[int32]bool {
	selected := make(map[int32]bool, len(processes))
	for _, p := range processes {
		selected[p.PID] = true
	}
	return selected
}

// A process may rewrite its command line (OpenSSL blanks a -k password with
// spaces), so rules match what /proc reports now, not what was typed.
func TestARuleIsMatchedAgainstTheArgumentsAProcessReportsNow(t *testing.T) {
	const password = "not-in-the-process-listing-1c7d"

	command := exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-k", password)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start openssl, which this test needs on the host: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	// The rewrite lands just after the exec, so the wait is for the password to be
	// gone. A skip would turn an unmade measurement into a green run.
	pid := int32(command.Process.Pid)
	var reported process.Process
	for range 400 {
		p, ok := read(t).Lookup(pid)
		if ok && filepath.Base(p.Executable) == "openssl" && len(p.Arguments) > 1 && !slices.Contains(p.Arguments, password) {
			reported = p
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reported.PID == 0 {
		t.Fatalf("pid %d has not taken the password off its command line after four seconds", pid)
	}

	asStarted := process.Rule{
		Executable: reported.Executable,
		Arguments:  []string{"enc", "-aes-256-cbc", "-pbkdf2", "-k", password},
	}
	asReported := process.Rule{Executable: reported.Executable, Arguments: reported.Arguments[1:]}

	if asStarted.Matches(reported) {
		t.Error("a rule written from the arguments the process was started with matches it, although it rewrote them")
	}
	if !asReported.Matches(reported) {
		t.Errorf("a rule written from what the process reports does not match it: %q", reported.Arguments)
	}
}
