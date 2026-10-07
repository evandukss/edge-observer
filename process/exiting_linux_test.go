package process

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// The exiting flag is measured on the kernel this runs on rather than taken
// from a header: a child that has exited is held unreaped as a zombie, which
// has been through do_exit, and this test's own process has not.
func TestATaskThatHasExitedCarriesTheExitingFlag(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatalf("wiring, not the property: start a child to hold as a zombie: %v", err)
	}
	t.Cleanup(func() { _ = child.Wait() })
	// WNOWAIT returns once the child has exited and leaves it unreaped.
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, child.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
		t.Fatalf("wiring, not the property: wait for the child to exit: %v", err)
	}

	exited := readStatOf(t, child.Process.Pid)
	if _, _, state, err := parseStat(exited); err != nil || state != 'Z' {
		t.Fatalf("wiring, not the property: the child is not held as a zombie, so nothing below reads "+
			"a task that has exited: state %q, %v: %s", state, err, exited)
	}
	running := readStatOf(t, os.Getpid())
	if _, _, state, err := parseStat(running); err != nil || !TaskState(state).Nonterminal() {
		t.Fatalf("wiring, not the property: this process does not read as running: state %q, %v", state, err)
	}

	if exiting, err := parseExiting(exited); err != nil || !exiting {
		t.Errorf("a zombie reads as not exiting (%v): %s", err, exited)
	}
	if exiting, err := parseExiting(running); err != nil || exiting {
		t.Errorf("this running process reads as exiting (%v): %s", err, running)
	}
	t.Logf("an exited task's stat: %s", exited)
	t.Logf("a running task's stat: %s", running)
}

func readStatOf(t *testing.T, pid int) []byte {
	t.Helper()
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		t.Fatalf("wiring, not the property: read pid %d stat: %v", pid, err)
	}
	return stat
}
