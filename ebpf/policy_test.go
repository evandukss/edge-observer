//go:build attach

package ebpf_test

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/process"
)

// held waits until a forked child has stopped itself: the fixture returns the
// pid at fork, and a release sent earlier is lost, leaving an empty capture.
func held(t *testing.T, pid int32) {
	t.Helper()
	for range 500 {
		stat, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", procfs, pid))
		if err == nil {
			if end := bytes.LastIndexByte(stat, ')'); end >= 0 {
				if fields := strings.Fields(string(stat[end+1:])); len(fields) > 0 && fields[0] == "T" {
					return
				}
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("pid %d never stopped itself, so releasing it would measure nothing", pid)
}

// admitting is one process admitted under a chosen descendant mode; there is
// no default.
func admitting(p process.Process, mode admission.Mode) []admission.Selection {
	one := admit(p)
	one.Mode = mode
	return []admission.Selection{one}
}

// Every transfer carries the pid of the process that made it, so a capture of
// one family says who moved which bytes.
var marker = regexp.MustCompile(`arming-window-marker-(\d+)`)

func movedBytes(c captured) map[int32]bool {
	moved := make(map[int32]bool)
	for _, text := range append(c.plaintext(fragment.Sent), c.plaintext(fragment.Received)...) {
		for _, found := range marker.FindAllStringSubmatch(text, -1) {
			pid, err := strconv.ParseInt(found[1], 10, 32)
			if err == nil {
				moved[int32(pid)] = true
			}
		}
	}
	return moved
}

// The mode decides three different sets. The target names one exact instance
// and the children are its own: an executable or cgroup rule matching a child
// would make none and existing indistinguishable.
func TestTheDescendantModeDecidesWhichChildrenAreAdmitted(t *testing.T) {
	for _, mode := range []admission.Mode{admission.ModeNone, admission.ModeExisting, admission.ModeFollow} {
		t.Run(mode.String(), func(t *testing.T) {
			answers := mode.Answers()
			_, port := serving(t)
			family := startArmingProcess(t, port)
			root := loaded(t, int32(family.command.Process.Pid))

			// A live process outside the family, same library, transferring in the same
			// run, so admitting nothing and capturing nothing are told apart.
			outside := startArmingProcess(t, port)
			outsideRoot := loaded(t, int32(outside.command.Process.Pid))

			existing, err := family.child('L', "live")
			if err != nil {
				t.Fatalf("create the child that is already running when the policy is resolved: %v", err)
			}

			session, err := ebpf.Attach(ebpf.Options{
				Program: bpf.Full(),
				Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
				Admit:   admitting(root, mode),
			})
			if err != nil {
				t.Fatalf("attach with descendants %s: %v", mode, err)
			}
			defer func() { _ = session.Close() }()

			future, err := family.child('M', "second")
			if err != nil {
				t.Fatalf("create the child born after the policy was resolved: %v", err)
			}
			held(t, existing)
			held(t, future)
			if _, err := family.child('S', "self"); err != nil {
				t.Fatalf("the approved root did not transfer: %v", err)
			}
			if err := family.finish('G', "live"); err != nil {
				t.Fatalf("the already-running child did not transfer: %v", err)
			}
			if err := family.finish('N', "second"); err != nil {
				t.Fatalf("the later child did not transfer: %v", err)
			}
			if _, err := outside.child('S', "self"); err != nil {
				t.Fatalf("the outside control did not transfer: %v", err)
			}

			moved := movedBytes(drain(session, 900*time.Millisecond))

			if !moved[root.PID] {
				t.Fatalf("the approved process itself produced no bytes under descendants %s, "+
					"so nothing here measures what it passes on", mode)
			}
			if moved[outsideRoot.PID] {
				t.Errorf("pid %d, which no target named, produced bytes", outsideRoot.PID)
			}
			if moved[existing] != answers.Existing {
				t.Errorf("descendants %s: the child already running when the policy was resolved "+
					"produced bytes: %v, and the mode answers existing: %v",
					mode, moved[existing], answers.Existing)
			}
			if moved[future] != answers.Future {
				t.Errorf("descendants %s: the child created after the policy was resolved "+
					"produced bytes: %v, and the mode answers future: %v",
					mode, moved[future], answers.Future)
			}
		})
	}
}

// Inherited authority ends at a successful exec: an approved root cannot hand
// authority to an unapproved program, and the new image waits for a policy
// resolution at restart. A failed exec, on the same path, is the control: the
// grant is unchanged.
func TestASuccessfulExecEndsAGrantAndAFailedExecLeavesItAlone(t *testing.T) {
	_, port := serving(t)
	family := startArmingProcess(t, port)
	root := loaded(t, int32(family.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the family: %v", err)
	}
	defer func() { _ = session.Close() }()

	replaced, err := family.child('E', "exec")
	if err != nil {
		t.Fatalf("create the child that execs: %v", err)
	}
	kept, err := family.child('B', "failed")
	if err != nil {
		t.Fatalf("create the child whose exec cannot succeed: %v", err)
	}
	held(t, replaced)
	held(t, kept)
	if err := family.finish('F', "exec"); err != nil {
		t.Fatalf("the execing child did not finish: %v", err)
	}
	if err := family.finish('C', "failed"); err != nil {
		t.Fatalf("the child whose exec failed did not transfer: %v", err)
	}

	moved := movedBytes(drain(session, 900*time.Millisecond))

	if !moved[kept] {
		t.Fatal("the child whose exec failed produced no bytes, so the refusal of the one that " +
			"succeeded would prove nothing about exec")
	}
	if moved[replaced] {
		t.Errorf("pid %d execed into an image no target named and its plaintext was still read", replaced)
	}
}

// The root's grant ends when it exits, and nothing else's: a working
// descendant keeps its own and, under follow, keeps admitting what it forks.
func TestASurvivingDescendantKeepsItsGrantAndKeepsAdmittingWhenTheRootExits(t *testing.T) {
	_, port := serving(t)
	family := startArmingProcess(t, port)
	root := loaded(t, int32(family.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the family: %v", err)
	}
	defer func() { _ = session.Close() }()

	survivor, err := family.child('D', "deep")
	if err != nil {
		t.Fatalf("create the descendant that outlives the root: %v", err)
	}
	held(t, survivor)
	if _, err := family.child('Q', "leaving"); err != nil {
		t.Fatalf("the root did not leave: %v", err)
	}

	moved := movedBytes(drain(session, 1500*time.Millisecond))

	if !moved[survivor] {
		t.Errorf("pid %d was admitted before its root exited and its bytes did not appear, so "+
			"the root's exit took its descendant's grant with it", survivor)
	}
	// Its own child, forked after the root was gone; a third member moving bytes
	// shows it was admitted.
	grandchild := false
	for pid := range moved {
		if pid != root.PID && pid != survivor {
			grandchild = true
		}
	}
	if !grandchild {
		t.Errorf("the bytes that appeared came from %v, and the root is %d and the survivor %d, "+
			"so the surviving descendant admitted nothing of its own after the root exited",
			moved, root.PID, survivor)
	}

	held, err := session.Admissions()
	if err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	for _, one := range held {
		if one.Instance.Namespace == root.Namespace && one.Instance.PID == root.NamespacePID {
			t.Errorf("the root has exited and the allowlist still holds %s", one)
		}
	}
}

// An exclusion denies its instances and everything below them, and a target
// naming one does not override that. Here one instance is named by both.
func TestAnExclusionDeniesASubtreeAndATargetNamingItDoesNotOverrideIt(t *testing.T) {
	_, port := serving(t)
	approved := startArmingProcess(t, port)
	control := loaded(t, int32(approved.command.Process.Pid))
	family := startArmingProcess(t, port)
	excluded := loaded(t, int32(family.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, excluded)}, points(t, excluded)...),
		// Both are named by a target; one is also excluded.
		Admit: []admission.Selection{admit(control), admit(excluded)},
		Deny: []admission.Denial{{
			Instance:    excluded.Instance(),
			Provenance:  admission.Provenance{Target: excluded.Executable, Number: 1},
			ObserverPID: excluded.PID,
		}},
	})
	if err != nil {
		t.Fatalf("attach with one instance both named and excluded: %v", err)
	}
	defer func() { _ = session.Close() }()

	below, err := family.child('L', "live")
	if err != nil {
		t.Fatalf("create the child of the excluded instance: %v", err)
	}
	held(t, below)
	if _, err := family.child('S', "self"); err != nil {
		t.Fatalf("the excluded instance did not transfer: %v", err)
	}

	// Read the denials while the child is held: an exiting process takes its entry
	// with it.
	refused, err := session.Denials()
	if err != nil {
		t.Fatalf("read back what the session denies: %v", err)
	}

	if err := family.finish('G', "live"); err != nil {
		t.Fatalf("the child of the excluded instance did not transfer: %v", err)
	}
	if _, err := approved.child('S', "self"); err != nil {
		t.Fatalf("the control did not transfer: %v", err)
	}

	moved := movedBytes(drain(session, 900*time.Millisecond))

	if !moved[control.PID] {
		t.Fatal("the instance no exclusion names produced no bytes, so a denial would prove nothing")
	}
	if moved[excluded.PID] {
		t.Errorf("pid %d is named by a target and denied by an exclusion, and its plaintext was read",
			excluded.PID)
	}
	if moved[below] {
		t.Errorf("pid %d was forked by a denied instance after the policy was resolved, and its "+
			"plaintext was read", below)
	}

	held := make(map[int32]bool, len(refused))
	for _, one := range refused {
		held[one.Instance.PID] = true
	}
	if !held[excluded.NamespacePID] {
		t.Errorf("the allowlist holds no denial for pid %d, which the exclusion named",
			excluded.NamespacePID)
	}
	if !held[below] {
		t.Errorf("the allowlist holds no denial for pid %d, so the subtree's denial did not reach "+
			"what the excluded instance forked", below)
	}

	admitted, err := session.Admissions()
	if err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	for _, one := range admitted {
		if one.Instance.PID == excluded.NamespacePID {
			t.Errorf("a target's admission overwrote the exclusion's denial: %s", one)
		}
	}
}

// One instance holds one grant. A policy from the process table puts every
// naming target onto it; offering one instance twice would replace the first
// grant and its reasons silently, so it is refused.
func TestAnInstanceOfferedTwiceKeepsOneGrantAndTheSecondOfferIsNamed(t *testing.T) {
	serverPID, _ := serving(t)
	server := loaded(t, serverPID)

	first, second := admit(server), admit(server)
	first.Provenance = admission.Provenance{Target: server.Executable, Number: 1, Rule: 1}
	second.Provenance = admission.Provenance{Target: server.Executable, Number: 2, Rule: 1}

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, server),
		Admit:   []admission.Selection{first, second},
	})
	if err != nil {
		t.Fatalf("attach with one instance offered twice: %v", err)
	}
	defer func() { _ = session.Close() }()

	held, err := session.Admissions()
	if err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	grants := 0
	for _, one := range held {
		if one.Instance.Namespace == server.Namespace && one.Instance.PID == server.NamespacePID {
			grants++
			// The first offer stays in force.
			if one.Provenance.Number != 1 {
				t.Errorf("pid %d is admitted under target %d and the first offer named it as 1",
					server.PID, one.Provenance.Number)
			}
		}
	}
	if grants != 1 {
		t.Errorf("pid %d was offered twice and the allowlist holds %d grants for it",
			server.PID, grants)
	}

	named := false
	for _, one := range session.Declined() {
		if one.Reason == ebpf.NamedTwice && one.Selection.Provenance.Number == 2 {
			named = true
		}
	}
	if !named {
		t.Errorf("the second offer of pid %d was not admitted and the session names %d refusals, "+
			"none of them it", server.PID, len(session.Declined()))
	}
}

// Observed to the end and stopped being observed halfway produce the same
// capture; what separates them is what the session admitted against what the
// kernel still holds, per instance. The inventory is where a fork-admitted
// descendant enters that record, and an instance absent from it was recorded
// by nothing.
func TestARecordedInstanceWhoseGrantTheKernelNoLongerHoldsIsNamedWithWhatBecameOfIt(t *testing.T) {
	_, port := serving(t)
	family := startArmingProcess(t, port)
	root := loaded(t, int32(family.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the family: %v", err)
	}
	defer func() { _ = session.Close() }()

	transient, err := family.child('T', "transient")
	if err != nil {
		t.Fatalf("create the child that will end: %v", err)
	}
	held(t, transient)

	// The reading puts a fork-admitted descendant into the record, while it is
	// alive.
	if _, err := session.Admissions(); err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	recorded := false
	for _, one := range session.Inventory() {
		recorded = recorded || one.ObserverPID == transient
	}
	if !recorded {
		t.Fatalf("pid %d was admitted below pid %d and the session recorded %d instances, "+
			"none of them it", transient, root.PID, len(session.Inventory()))
	}

	if err := family.finish('X', "transient"); err != nil {
		t.Fatalf("the child that was to end did not end: %v", err)
	}

	gone, err := session.Withdrawn()
	if err != nil {
		t.Fatalf("establish what the session recorded and the kernel no longer holds: %v", err)
	}
	var ended *ebpf.Withdrawal
	for i := range gone {
		if gone[i].Selection.ObserverPID == transient {
			ended = &gone[i]
		}
		// The control: the root is still running and admitted, so a surface naming
		// every recorded instance would name it too.
		if gone[i].Selection.ObserverPID == root.PID {
			t.Errorf("pid %d is still admitted and is reported as withdrawn: %s",
				root.PID, gone[i].Evidence)
		}
	}
	if ended == nil {
		t.Fatalf("pid %d was recorded, has ended, and the session reports %d withdrawals, "+
			"none of them it", transient, len(gone))
	}
	if ended.State != ebpf.ExecutionEnded {
		t.Errorf("pid %d ended and its withdrawal says %q: %s", transient, ended.State, ended.Evidence)
	}
	if ended.Evidence == "" {
		t.Errorf("pid %d is reported as %q with nothing said about what that rests on",
			transient, ended.State)
	}
}
