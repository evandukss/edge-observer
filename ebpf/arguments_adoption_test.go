//go:build attach

package ebpf_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
	"golang.org/x/sys/unix"
)

func TestAdoptionRefusesUndeterminedArgumentsWithoutClaimingDeath(t *testing.T) {
	const helper = "OBSERVER_ARGUMENT_ADOPTION_HELPER"
	if os.Getenv(helper) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestAdoptionRefusesUndeterminedArgumentsWithoutClaimingDeath$", "-test.v", "-test.timeout=45s")
		command.Env = append(os.Environ(), helper+"=1")
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		command.WaitDelay = helperOutputWait
		output, err := command.CombinedOutput()
		t.Logf("mount-isolated adoption probe:\n%s", output)
		if err != nil {
			t.Fatalf("adoption probe: %v", err)
		}
		return
	}
	// Only this helper's mount namespace changes. The family, its executable,
	// birth, namespace and successful HTTPS traffic are real. An empty bind mount
	// constructs persistent unreadable argument evidence, not an exec window.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	parentPID, parentPort, childPID, childPort := servingFamily(t)
	parent, child := loaded(t, parentPID), loaded(t, childPID)
	if child.PPID != parentPID || child.ArgumentEvidence != process.ArgumentsKnown {
		t.Fatal("wiring: no known-arguments descendant before masking")
	}
	empty := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmdline := fmt.Sprintf("/proc/%d/cmdline", childPID)
	if err := unix.Mount(empty, cmdline, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Unmount(cmdline, 0); err != nil {
			t.Errorf("unmount child's cmdline: %v", err)
		}
	}()
	unknown, err := process.Identify("/proc", childPID)
	if err != nil || unknown.ArgumentEvidence != process.ArgumentsUndetermined ||
		len(unknown.Arguments) != 0 || unknown.Executable != child.Executable || unknown.Instance() != child.Instance() {
		t.Fatalf("wiring: live descendant did not retain identity with unknown arguments: %+v, %v", unknown, err)
	}
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(watch) }()
	if _, err := unix.InotifyAddWatch(watch, empty, unix.IN_OPEN|unix.IN_CLOSE_NOWRITE); err != nil {
		t.Fatal(err)
	}
	selected := admit(parent)
	selected.Mode = admission.ModeExisting
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: []admission.Selection{selected}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	// No fixture reader opens the child between installing the watch and here.
	// Attach reads the table once in readBefore, then in adopt. Watching closes
	// as well keeps successive opens from coalescing. One open proves only the
	// earlier read, not adoption; at least two must reach this empty file.
	var events [4096]byte
	n, err := unix.Read(watch, events[:])
	if err != nil {
		t.Fatalf("wiring: attachment never opened the masked cmdline: %v", err)
	}
	opens := 0
	for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
		mask := binary.NativeEndian.Uint32(events[offset+4:])
		length := binary.NativeEndian.Uint32(events[offset+12:])
		if mask&unix.IN_OPEN != 0 {
			opens++
		}
		offset += unix.SizeofInotifyEvent + int(length)
	}
	if opens < 2 {
		t.Fatalf("wiring: only %d masked cmdline opens; adoption's second table read was not reached", opens)
	}
	t.Logf("wiring: adoption reached live descendant's zero-byte cmdline; %d opens including readBefore", opens)
	present, err := ebpf.IndependentKernelGrantPresent(session, child.Instance())
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("undetermined descendant received a kernel grant")
	}
	refused, err := session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, refusal := range refused.Named {
		if refusal.Selection.ObserverPID != childPID {
			continue
		}
		named++
		if refusal.Reason != ebpf.ArgumentsIndeterminate || refusal.Selection.Instance != child.Instance() {
			t.Errorf("live descendant was called dead or lost its identity: %+v", refusal)
		}
	}
	if named != 1 {
		t.Errorf("want one named argument refusal for the live child, got %d: %+v", named, refused.Named)
	}
	// Successful requests independently establish that both actors remain live;
	// parent capture is the positive control for the child's absent payload.
	familyRequest(t, parentPort, "/arguments-parent-control")
	familyRequest(t, childPort, "/arguments-live-child")
	got := drain(session, 100*time.Millisecond)
	if attribution(got, "/arguments-parent-control") == nil {
		t.Fatal("wiring: selected parent control was not captured")
	}
	if captured := attribution(got, "/arguments-live-child"); captured != nil {
		t.Errorf("undetermined descendant's confirmed traffic was captured: %+v", captured)
	}
}
