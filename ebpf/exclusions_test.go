//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
)

func TestSubtreeDenialOverridesDirectIncludesAndSurvivesExec(t *testing.T) {
	port, received := independentPeer(t)
	controlActor := independentActor(t, immediateForkSource(), port)
	control := loaded(t, int32(controlActor.command.Process.Pid))
	source := strings.Replace(heldFamilySource(), "if (command[0] == 'P') {", `if (command[0] == 'X') {
  execl(argv[0],argv[0],argv[1],NULL); return 40;
 } else if (command[0] == 'P') {`, 1)
	family := independentActor(t, source, port)
	root := loaded(t, int32(family.command.Process.Pid))
	childPID, err := family.child('L', "live")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, childPID, "T")
	child := loaded(t, childPID)
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	policy := process.Approval{Exclusions: []process.Rule{{Executable: root.Executable, Arguments: []string{fmt.Sprint(port)}}}}
	denials := policy.Denials(table)
	found := map[int32]bool{}
	for _, denial := range denials {
		found[denial.ObserverPID] = true
	}
	if !found[root.PID] || !found[child.PID] || found[control.PID] {
		t.Fatalf("exclusion resolver did not establish the intended subtree: %+v", denials)
	}
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: append(points(t, root), independentForkPoint(t, root)), Admit: []admission.Selection{admit(control), admit(root), admit(child)}, Deny: denials})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	independentParentControl(t, controlActor, session, received)
	if _, err := io.WriteString(family.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, family, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-parent"); got != nil {
		t.Errorf("directly included excluded root produced captured bytes: %+v", got)
	}
	if err := family.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-held-child"); got != nil {
		t.Errorf("direct include overrode its ancestor's exclusion: %+v", got)
	}
	if _, err := io.WriteString(family.input, "X\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, family, "ready\n")
	denied, err := session.Denials()
	if err != nil {
		t.Fatal(err)
	}
	retained := false
	for _, one := range denied {
		if one.Instance.Namespace == root.Namespace && one.Instance.PID == root.NamespacePID {
			retained = true
		}
	}
	if !retained {
		t.Errorf("successful exec erased the root's subtree denial: %+v", denied)
	}
	futurePID, err := family.child('L', "live")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, futurePID, "T")
	denied, err = session.Denials()
	if err != nil {
		t.Fatal(err)
	}
	inherited := false
	for _, one := range denied {
		if one.Instance.Namespace == root.Namespace && one.Instance.PID == futurePID {
			inherited = true
		}
	}
	if !inherited {
		t.Errorf("child born after its excluded parent's exec inherited no denial: %+v", denied)
	}
	if err := family.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-held-child"); got != nil {
		t.Errorf("future child escaped the denial after its parent's exec: %+v", got)
	}
	independentParentControl(t, controlActor, session, received)
	t.Logf("excluded root %d and directly included existing child %d; post-exec child %d; outside control %d", root.PID, child.PID, futurePID, control.PID)
}

func TestExcludedImageAppearingAfterActivationCannotEscapeOnRestart(t *testing.T) {
	port, received := independentPeer(t)
	controlActor := independentActor(t, immediateForkSource(), port)
	control := loaded(t, int32(controlActor.command.Process.Pid))
	source := strings.Replace(heldFamilySource(), "if (command[0] == 'P') {", `if (command[0] == 'X') {
  char next[4096]; snprintf(next,sizeof(next),"%s.next",argv[0]);
  execl(next,next,argv[1],NULL); return 40;
 } else if (command[0] == 'P') {`, 1)
	actor := independentActor(t, source, port)
	original := loaded(t, int32(actor.command.Process.Pid))
	nextPath := actor.command.Path + ".next"
	image, err := os.ReadFile(actor.command.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nextPath, image, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := process.Approval{Exclusions: []process.Rule{{Executable: nextPath, Arguments: []string{fmt.Sprint(port)}}}}
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	initialDenials := policy.Denials(table)
	if len(initialDenials) != 0 {
		t.Fatalf("excluded image was already running before activation: %+v", initialDenials)
	}
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, original), Admit: []admission.Selection{admit(control), admit(original)}, Deny: initialDenials})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	independentParentControl(t, actor, session, received)
	if _, err := io.WriteString(actor.input, "X\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "ready\n")
	late := loaded(t, original.PID)
	if late.Executable != nextPath {
		t.Fatalf("exec did not enter the previously absent excluded image: %q", late.Executable)
	}
	negative := func() {
		if _, err := io.WriteString(actor.input, "P\n"); err != nil {
			t.Fatal(err)
		}
		actorLine(t, actor, "parent 0\n")
		peerReceived(t, received, "/independent-parent")
		if got := attribution(drain(session, 100*time.Millisecond), "/independent-parent"); got != nil {
			t.Errorf("late excluded image produced captured bytes: %+v", got)
		}
	}
	negative()
	// Exec ends inherited authority. Restart is where an explicit include could
	// activate the new image, and its exclusion must still win there.
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	table, err = process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	denials := policy.Denials(table)
	if len(denials) != 1 || denials[0].ObserverPID != late.PID {
		t.Fatalf("late image was not resolved as excluded at restart: %+v", denials)
	}
	session, err = ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, late), Admit: []admission.Selection{admit(control), admit(late)}, Deny: denials})
	if err != nil {
		t.Fatal(err)
	}
	independentParentControl(t, controlActor, session, received)
	negative()
}
