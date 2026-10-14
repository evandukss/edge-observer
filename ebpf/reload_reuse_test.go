//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"golang.org/x/sys/unix"
)

// A real successor is offered while delivery still holds the predecessor's
// inventory record. The kernel has removed the old grant; no map is fabricated.
func TestReloadAdmitsReusedPIDWhileOldDeliveryIsHeld(t *testing.T) {
	const helper = "OBSERVER_RELOAD_REUSE_HELPER"
	if os.Getenv(helper) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestReloadAdmitsReusedPIDWhileOldDeliveryIsHeld$", "-test.v", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), helper+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS}
		cmd.WaitDelay = helperOutputWait
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("reuse subprocess: %v\n%s", err, out)
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
	rootSelection, oldSelection := admit(root), admit(old)
	rootSelection.Mode, oldSelection.Mode = admission.ModeNone, admission.ModeNone
	oldSelection.Provenance = admission.Provenance{Target: "predecessor", Number: 2}
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, root),
		Admit: []admission.Selection{rootSelection, oldSelection},
		BeforeRecord: func(e ebpf.Event) {
			if e.Kind == ebpf.Transfer {
				once.Do(func() { close(reached); <-release })
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	defer close(release)
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-reuse-control")
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring: live control did not reach delivery hold")
	}
	nextID, err := reuseCommand(actor, "X", "replacement")
	if err != nil {
		t.Fatal(err)
	}
	next := loaded(t, nextID.observer)
	if old.PID != next.PID || old.Namespace != next.Namespace || old.NamespacePID != next.NamespacePID || old.Start() == next.Start() {
		t.Fatalf("wiring: reuse not established: old %+v next %+v", old, next)
	}
	held, err := s.Held()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range held {
		if one.Instance.PID == old.NamespacePID && one.Instance.Namespace == old.Namespace {
			t.Fatal("wiring: predecessor kernel grant survived exit")
		}
	}
	found := false
	for _, one := range s.Inventory() {
		if one.Instance.PID == old.NamespacePID && one.Instance.Start == old.Start() {
			found = true
		}
	}
	if !found {
		t.Fatal("wiring: predecessor inventory did not survive the held delivery")
	}
	control, skipped, err := s.Admit([]admission.Selection{rootSelection})
	if err != nil || len(control) != 0 || len(skipped) != 1 {
		t.Fatalf("wiring: unchanged process control: %v %v %v", control, skipped, err)
	}
	selected := admit(next)
	selected.Mode = admission.ModeNone
	selected.Provenance = admission.Provenance{Target: "successor", Number: 3}
	granted, skipped, err := s.Admit([]admission.Selection{selected})
	if err != nil || len(granted) != 1 || len(skipped) != 0 {
		t.Fatalf("qualified successor not admitted: grants %v skips %v err %v", granted, skipped, err)
	}
	if granted[0].Instance.Start != next.Start() || granted[0].Provenance.Target != "successor" {
		t.Fatalf("successor attributed to predecessor: %+v", granted)
	}
}
