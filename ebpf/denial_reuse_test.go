//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"golang.org/x/sys/unix"
)

// The denial is written for a real excluded process. After its actual exit and
// PID reuse, only the userspace exclusion snapshot survives; no map is planted.
func TestReloadAdmitsReusedPIDAfterExcludedPredecessor(t *testing.T) {
	const helper = "OBSERVER_DENIAL_REUSE_HELPER"
	if os.Getenv(helper) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestReloadAdmitsReusedPIDAfterExcludedPredecessor$", "-test.v", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), helper+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS}
		cmd.WaitDelay = helperOutputWait
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("denial reuse subprocess: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		t.Fatal(err)
	}
	port, received := trafficPeer(t)
	actor := trafficActor(t, reuseFamilySource(), port)
	line, err := actor.output.ReadString('\n')
	var rootPID int32
	if _, scan := fmt.Sscanf(line, "selected %d", &rootPID); err != nil || scan != nil {
		t.Fatalf("root: %q %v %v", line, err, scan)
	}
	root := loaded(t, rootPID)
	oldID, err := reuseCommand(actor, "T", "old")
	if err != nil {
		t.Fatal(err)
	}
	old := loaded(t, oldID.observer)
	rootSelection := admit(root)
	rootSelection.Mode = admission.ModeNone
	s, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, root),
		Admit: []admission.Selection{rootSelection, admit(old)},
		Deny: []admission.Denial{{Instance: old.Instance(), ObserverPID: old.PID,
			Provenance: admission.Provenance{Target: "excluded predecessor", Number: 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	denials, err := s.Denials()
	if err != nil || len(denials) != 1 || denials[0].Instance.Start != old.Start() {
		t.Fatalf("wiring: excluded predecessor lacks genuine denial: %v %v", denials, err)
	}
	direct, _, err := s.Admit([]admission.Selection{admit(old)})
	if err == nil || len(direct) != 0 {
		t.Fatalf("genuine excluded process admitted: %v %v", direct, err)
	}
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-reuse-control")
	if attribution(drain(s, 100*time.Millisecond), "/independent-reuse-control") == nil {
		t.Fatal("wiring: approved root control was not captured")
	}
	nextID, err := reuseCommand(actor, "X", "replacement")
	if err != nil {
		t.Fatal(err)
	}
	next := loaded(t, nextID.observer)
	if old.PID != next.PID || old.Namespace != next.Namespace || old.NamespacePID != next.NamespacePID || old.Start() == next.Start() {
		t.Fatalf("wiring: reuse not established: old %+v next %+v", old, next)
	}
	denials, err = s.Denials()
	if err != nil || len(denials) != 0 {
		t.Fatalf("wiring: old kernel denial survived actual exit: %v %v", denials, err)
	}
	selected := admit(next)
	selected.Mode = admission.ModeNone
	selected.Provenance = admission.Provenance{Target: "included successor", Number: 3}
	granted, skipped, err := s.Admit([]admission.Selection{selected})
	if err != nil || len(granted) != 1 || len(skipped) != 0 {
		t.Fatalf("qualified successor inherited old exclusion: %v %v %v", granted, skipped, err)
	}
	if granted[0].Instance.Start != next.Start() || granted[0].Provenance.Target != "included successor" {
		t.Fatalf("wrong successor attribution: %+v", granted)
	}
	if _, err := io.WriteString(actor.input, "G\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "replacement-exited 0\n")
	peerReceived(t, received, "/independent-reused-key")
	moved := attribution(drain(s, 100*time.Millisecond), "/independent-reused-key")
	if moved == nil || moved.Start != next.Start() || moved.Generation != granted[0].Instance.Generation {
		t.Fatalf("successor transfer lacks its admitted identity: %+v", moved)
	}
}
