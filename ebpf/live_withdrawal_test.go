//go:build attach

package ebpf_test

import (
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
)

// /proc cannot supply an admission generation. Use its independently read
// identity only to locate the admission BEFORE the transition, then keep the
// full stamped identity for every subsequent grant/withdrawal comparison.
func independentAdmittedIdentity(t *testing.T, session *ebpf.Session, p process.Process) admission.Instance {
	t.Helper()
	expected := p.Instance()
	if !expected.Namespace.Known() || !expected.Start.Determined {
		t.Fatal("pre-transition process identity is not established")
	}
	var admitted []admission.Instance
	for _, one := range session.Inventory() {
		if one.ObserverPID == p.PID {
			if !independentSameExecution(one.Instance, expected) {
				t.Fatalf("admitted identity differs from the pre-transition process reading: got %+v, want %+v", one.Instance, expected)
			}
			admitted = append(admitted, one.Instance)
		}
	}
	if len(admitted) != 1 {
		t.Fatalf("pre-transition inventory has %d admissions for observer pid %d, want 1", len(admitted), p.PID)
	}
	instance := admitted[0]
	if instance.Generation == 0 {
		t.Fatal("the admission has no stamped generation")
	}
	if held, err := ebpf.IndependentKernelGrantPresent(session, instance); err != nil || !held {
		t.Fatalf("pre-transition grant is not established: held=%t err=%v", held, err)
	}
	return instance
}

// This is a comparison with an independent /proc reading, not an equality of
// admissions. It deliberately cannot decide whether two grants are the same.
func independentSameExecution(a, b admission.Instance) bool {
	return a.Namespace == b.Namespace && a.PID == b.PID &&
		a.Start.Determined && b.Start.Determined && a.Start == b.Start
}

func independentWithdrawal(t *testing.T, session *ebpf.Session, instance admission.Instance, want ebpf.Ended) {
	t.Helper()
	known := 0
	for _, one := range session.Inventory() {
		if one.Instance.Same(instance) {
			known++
		}
	}
	if known != 1 {
		t.Fatalf("withdrawal control: admitted instance appears %d times in inventory, want 1", known)
	}
	if held, err := ebpf.IndependentKernelGrantPresent(session, instance); err != nil || held {
		t.Fatalf("withdrawal control: grant absence was not established: held=%t err=%v", held, err)
	}
	gone, err := session.Withdrawn()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, one := range gone {
		if !one.Selection.Instance.Same(instance) {
			continue
		}
		found++
		if one.State != want || strings.TrimSpace(one.Evidence) == "" {
			t.Errorf("withdrawal did not name the independently established execution state: got %q (%s), want %q", one.State, one.Evidence, want)
		}
	}
	if found != 1 {
		t.Errorf("withdrawn admitted instance appears %d times in the report, want 1", found)
	}
}

func TestAnExecingChildKeepsRunningWhileItsWithdrawalIsReported(t *testing.T) {
	// This child belongs to the test supervisor. Its successful exec returns
	// to the command loop, so no parent reaps it before the withdrawal reading.
	source := strings.Replace(immediateForkSource(), "if (command[0] == 'P') {", `if (command[0] == 'X') {
			execl(argv[0], argv[0], argv[1], NULL);
			return 40;
		} else if (command[0] == 'Q') {
			return 0;
		} else if (command[0] == 'P') {`, 1)
	port, received := independentPeer(t)
	child := independentActor(t, source, port)
	never := independentActor(t, source, port)
	selected := loaded(t, int32(child.command.Process.Pid))
	unselected := loaded(t, int32(never.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, selected), Admit: authorise(selected)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	independentParentControl(t, child, session, received)
	admitted := independentAdmittedIdentity(t, session, selected)
	if _, err := io.WriteString(child.input, "X\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, child, "ready\n")
	current := loaded(t, selected.PID)
	if !current.Instance().Same(selected.Instance()) || current.Start() != selected.Start() {
		t.Fatal("successful exec did not preserve the independently read process instance")
	}
	for _, actor := range []*armingProcess{child, never} {
		if _, err := io.WriteString(actor.input, "P\n"); err != nil {
			t.Fatal(err)
		}
		actorLine(t, actor, "parent 0\n")
		peerReceived(t, received, "/independent-parent")
	}
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-parent"); got != nil {
		t.Fatalf("post-exec or never-approved transfer was captured: %+v", got)
	}
	if err := syscall.Kill(child.command.Process.Pid, 0); err != nil {
		t.Fatalf("execing child did not remain alive for the reading: %v", err)
	}
	independentWithdrawal(t, session, admitted, ebpf.GrantEndedWhileRunning)
	for _, one := range session.Inventory() {
		if one.ObserverPID == unselected.PID || independentSameExecution(one.Instance, unselected.Instance()) {
			t.Error("never-approved peer-confirmed actor entered the admitted inventory")
		}
	}
	gone, err := session.Withdrawn()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range gone {
		if one.Selection.ObserverPID == unselected.PID || independentSameExecution(one.Selection.Instance, unselected.Instance()) {
			t.Error("never-approved actor was reported as a withdrawn admission")
		}
	}
	if _, err := io.WriteString(child.input, "Q\n"); err != nil {
		t.Fatal(err)
	}
	if err := child.command.Wait(); err != nil {
		t.Fatalf("whole-process exit control: %v", err)
	}
	independentWithdrawal(t, session, admitted, ebpf.ExecutionEnded)
}
