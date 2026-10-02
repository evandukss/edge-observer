//go:build attach

package ebpf_test

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// A child already running when probes are placed, and offered by nobody, is
// admitted by the walk of its parent's running descendants, which read its
// namespace from /proc then. A child forked afterwards is admitted by the
// kernel, and its namespace is the one its events carry. The record of each
// admission says which of the two read the namespace; both children are
// inherited, so inheritance cannot decide it. Both children have ended by the
// time it is read, so the record is the one the session hands on as it lets
// go of each (Options.Ended), which the operational log writes.
func TestT19TheAttachWalkAndTheForkHookAreToldApartInTheAccount(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, heldFamilySource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	walked, err := actor.child('L', "live")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, walked, "T")

	var mutex sync.Mutex
	ended := make(map[int32]probe.Ended)
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(), Points: append(points(t, parent), independentForkPoint(t, parent)), Admit: authorise(parent),
		Ended: func(one probe.Ended) {
			mutex.Lock()
			defer mutex.Unlock()
			ended[one.Selection.ObserverPID] = one
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	if err := actor.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	forked, err := actor.child('L', "live")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, forked, "T")
	if err := actor.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	selected := make(map[int32]admission.Selection)
	deadline := time.Now().Add(3 * time.Second)
	for {
		drain(session, 100*time.Millisecond)
		session.Grants()
		mutex.Lock()
		for pid, one := range ended {
			selected[pid] = one.Selection
		}
		mutex.Unlock()
		if len(selected) >= 2 || time.Now().After(deadline) {
			break
		}
	}
	byWalk, walkFound := selected[walked]
	byFork, forkFound := selected[forked]
	if !walkFound || !forkFound {
		t.Fatalf("wiring, not the property: the session let go of the walked child pid %d: %v and the forked "+
			"child pid %d: %v, so there is no pair to tell apart", walked, walkFound, forked, forkFound)
	}
	if byWalk.Instance.Generation.FromKernel() || !byFork.Instance.Generation.FromKernel() {
		t.Fatalf("wiring, not the property: the walked child carries generation %d and the forked one %d; want "+
			"the first from this session's allocator and the second from the kernel's, so the two were not "+
			"admitted the two ways this case compares", byWalk.Instance.Generation, byFork.Instance.Generation)
	}
	if !byWalk.Provenance.Inherited() || !byFork.Provenance.Inherited() {
		t.Fatalf("wiring, not the property: inherited is %v for the walked child and %v for the forked one, want "+
			"both true", byWalk.Provenance.Inherited(), byFork.Provenance.Inherited())
	}

	for pid, want := range map[int32]string{walked: "attach_proc_read", forked: "admission_event"} {
		mutex.Lock()
		one := ended[pid]
		mutex.Unlock()
		encoded, err := json.Marshal(account.EndedAdmission(one))
		if err != nil {
			t.Fatal(err)
		}
		var row t19Admission
		if err := json.Unmarshal(encoded, &row); err != nil {
			t.Fatal(err)
		}
		if row.Instance.PID != pid {
			t.Fatalf("wiring, not the property: the record of pid %d names pid %d", pid, row.Instance.PID)
		}
		if row.NamespaceBy != want {
			t.Errorf("the record says pid %d's namespace was established by %q, want %q", pid, row.NamespaceBy, want)
		}
	}
}

// t19Admission is the part of one listed admission this case reads.
type t19Admission struct {
	Instance struct {
		PID int32 `json:"pid"`
	} `json:"instance"`
	NamespaceBy string `json:"namespace_by"`
}

// The allowlist read back names each grant's target, although the field the
// kernel holds is the session's identity for the target and not its number in
// any configuration. Two targets are offered under the same number, one at
// attach and one by a later admission, which is what a reload hands this layer
// when a configuration puts a new target first.
func TestT19TheAllowlistReadBackNamesEachGrantsTarget(t *testing.T) {
	port, _ := independentPeer(t)
	first := loaded(t, int32(independentActor(t, heldFamilySource(), port).command.Process.Pid))
	second := loaded(t, int32(independentActor(t, heldFamilySource(), port).command.Process.Pid))
	targets := map[int32]string{first.PID: "t19-first", second.PID: "t19-second"}

	offered := admit(first)
	offered.Provenance = admission.Provenance{Target: targets[first.PID], Number: 1}
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, first),
		Admit: []admission.Selection{offered}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	later := admit(second)
	later.Provenance = admission.Provenance{Target: targets[second.PID], Number: 1}
	if admitted, _, err := session.Admit([]admission.Selection{later}); err != nil || len(admitted) != 1 {
		t.Fatalf("wiring, not the property: the later admission took %d with %v, want 1", len(admitted), err)
	}

	held, err := session.Admissions()
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[int32]admission.Provenance, len(held))
	for _, one := range held {
		found[one.ObserverPID] = one.Provenance
	}
	for pid, want := range targets {
		provenance, read := found[pid]
		if !read {
			t.Fatalf("wiring, not the property: the allowlist read back holds no grant for pid %d", pid)
		}
		if provenance.Target != want {
			t.Errorf("the allowlist read back files pid %d under %q (number %d), want %q",
				pid, provenance.Target, provenance.Number, want)
		}
	}
}
