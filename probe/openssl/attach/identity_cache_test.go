package attach

import (
	"errors"
	"os"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

type retractingPlacement struct{ calls []admission.Selection }

func (*retractingPlacement) Close() error                 { return nil }
func (*retractingPlacement) Capability() probe.Capability { return probe.Capability{} }
func (p *retractingPlacement) retract(selections []admission.Selection) {
	p.calls = append(p.calls, selections...)
}

func TestPlacementReceiptRetractsOriginalAllocatorAfterCollision(t *testing.T) {
	old, current := &retractingPlacement{}, &retractingPlacement{}
	s := newSet()
	s.place(old)
	s.place(current, 42)
	instance := admission.Instance{PID: 42, Generation: 7, Start: admission.Determinate(100)}
	selections := []admission.Selection{{ObserverPID: 42, Instance: instance}}
	oldOwner, currentOwner := s.members[0].origin, s.members[1].origin
	oldReceipt := s.retraction([]placementGrant{{origin: oldOwner, granted: selections}})
	currentReceipt := s.retraction([]placementGrant{{origin: currentOwner, granted: selections}})
	s.identities[42] = placedIdentity{origin: currentOwner, instance: instance}
	s.routed = map[int32]int{42: 1}
	oldReceipt(selections)
	if len(old.calls) != 1 || len(current.calls) != 0 || len(s.members[1].covers) != 1 || len(s.identities) != 1 || len(s.routed) != 1 {
		t.Fatal("old receipt retracted or removed successor instead of original allocator")
	}
	currentReceipt(selections)
	if len(old.calls) != 1 || len(current.calls) != 1 || len(s.members[1].covers) != 0 || len(s.identities) != 0 || len(s.routed) != 0 {
		t.Fatal("successor receipt did not retract its own allocator and metadata")
	}
}

func TestCollidingPlacementGenerationsRetireOnlyTheirOrigin(t *testing.T) {
	// The very same birth and key deliberately occur in two Session allocators.
	// Comparing only generation, birth, or the complete admission.Key cannot
	// distinguish these owners.
	instance := admission.Instance{PID: 42, Namespace: admission.Namespace{Device: 1, Inode: 2}, Generation: 7, Start: admission.Determinate(100)}
	selection := admission.Selection{ObserverPID: 42, Instance: instance}
	makeLive := func(inode uint64) *ebpfAttachment {
		return &ebpfAttachment{known: map[int32]identity{42: {instance: instance}}, networks: map[int32]probe.Netns{42: {Inode: inode}}, networkOwners: map[int32]admission.Key{42: instance.Key()}}
	}
	old, current := makeLive(11), makeLive(22)
	s := newSet()
	s.place(old)
	s.place(current, 42)
	s.members[0].file = fileID{device: 1, inode: 11}
	s.members[1].file = fileID{device: 1, inode: 22}
	oldOwner, currentOwner := s.members[0].origin, s.members[1].origin
	if oldOwner == currentOwner {
		t.Fatal("wiring: placements share their allocator token")
	}
	s.identities[42] = placedIdentity{origin: currentOwner, instance: instance}
	s.routed = map[int32]int{42: 1}
	s.refusals[42] = errors.New("current diagnostic sentinel")
	told := 0
	var scopes []*probe.AdmissionScope
	callback := func(one probe.Ended) { told++; scopes = append(scopes, one.Scope) }
	s.ending(oldOwner, callback)(probe.Ended{Selection: selection})
	if told != 1 || scopes[0] != oldOwner || len(old.known) != 0 || len(old.networks) != 0 || len(old.networkOwners) != 0 {
		t.Fatal("origin retirement or scoped outward notification was not reached")
	}
	if len(current.known) != 1 || len(current.networks) != 1 || len(current.networkOwners) != 1 || len(s.members[1].covers) != 1 || len(s.identities) != 1 || len(s.routed) != 1 || len(s.refusals) != 1 {
		t.Fatal("colliding old placement retired successor state")
	}
	if got := current.networkOf(42, instance.Key()); got.Inode != 22 {
		t.Fatal("old placement altered successor network")
	}
	s.ending(currentOwner, callback)(probe.Ended{Selection: selection})
	if told != 2 || scopes[1] != currentOwner || len(current.known) != 0 || len(current.networks) != 0 || len(current.networkOwners) != 0 || len(s.members[1].covers) != 0 || len(s.identities) != 0 || len(s.routed) != 0 || len(s.refusals) != 0 {
		t.Fatal("successor's own retirement did not release its state")
	}
}

func TestLateRetirementPreservesSuccessorAttachmentCaches(t *testing.T) {
	key := admission.Key{PID: 42, Generation: 2}
	live := &ebpfAttachment{known: map[int32]identity{42: {instance: admission.Instance{PID: 42, Generation: 2}}}, networks: map[int32]probe.Netns{42: {Inode: 22}}, networkOwners: map[int32]admission.Key{42: key}}
	s := newSet()
	s.place(live, 42)
	s.identities[42] = placedIdentity{origin: s.members[0].origin, instance: live.known[42].instance}
	s.routed = map[int32]int{42: 0}
	old := admission.Selection{ObserverPID: 42, Instance: admission.Instance{PID: 42, Generation: 1}}
	live.ended(ebpf.Event{PID: 42, NamespacePID: 42, Generation: 1})
	s.ending(s.members[0].origin, nil)(probe.Ended{Selection: old})
	s.Retract([]admission.Selection{old})
	if len(live.known) != 1 || len(live.networks) != 1 || len(s.members[0].covers) != 1 || len(s.routed) != 1 {
		t.Fatal("old generation retired successor caches")
	}
	if got := live.networkOf(42, admission.Key{PID: 42, Generation: 1}); got.Known() {
		t.Fatal("old event borrowed successor network")
	}
	if got := live.networkOf(42, key); got.Inode != 22 {
		t.Fatal("successor network unavailable")
	}
	live.ended(ebpf.Event{PID: 42, NamespacePID: 42, Generation: 2})
	s.ending(s.members[0].origin, nil)(probe.Ended{Selection: admission.Selection{ObserverPID: 42, Instance: admission.Instance{PID: 42, Generation: 2}}})
	if len(live.known) != 0 || len(live.networks) != 0 || len(s.members[0].covers) != 0 || len(s.routed) != 0 {
		t.Fatal("successor's own end did not retire caches")
	}
}

func TestDelayedEventCannotBorrowCurrentProcessBirthOrExecutable(t *testing.T) {
	p, err := process.Identify("/proc", int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if p.StartTime < 2 {
		t.Fatal("wiring: current process birth cannot construct a different prior birth")
	}
	live := &ebpfAttachment{procfs: "/proc", known: make(map[int32]identity)}
	current := ebpf.Event{PID: p.PID, Namespace: p.Namespace, NamespacePID: p.NamespacePID, Generation: 2, Start: p.Start()}
	got := live.identify(current)
	if got.instance.Executable != p.Executable || got.instance.Start != p.Start() {
		t.Fatal("wiring: current identity enrichment not reached")
	}
	old := current
	old.Generation = 1
	old.Start = admission.Determinate(admission.BootTicks(p.StartTime - 1))
	got = live.identify(old)
	if got.instance.Start != old.Start || got.instance.Executable != "" || got.process.StartTime != uint64(old.Start.Ticks) {
		t.Fatalf("delayed event borrowed current /proc: %+v", got)
	}
	if live.known[p.PID].instance.Generation != 2 {
		t.Fatal("old event replaced successor cache")
	}
	readmitted := current
	readmitted.Generation = 1
	_ = live.identify(readmitted)
	if live.known[p.PID].instance.Generation != 2 {
		t.Fatal("old admission of the same birth replaced successor cache")
	}
}

func TestRequestJoinsRefuseMismatchedBirthAndNamespace(t *testing.T) {
	p := process.Process{PID: 42, NamespacePID: 7, Namespace: admission.Namespace{Device: 1, Inode: 2}, StartTime: 30}
	selection := admission.Selection{ObserverPID: p.PID, Instance: p.Instance()}
	report := probe.Report{Supported: true, Adapter: openssl.Name, Support: []probe.Support{{Adapter: openssl.Name, Supported: true}}}
	r := probe.Request{Processes: []process.Process{p}, Admit: []admission.Selection{selection}, Read: map[int32]probe.Reading{p.PID: {Report: report, Exec: process.Exec{StartTime: p.StartTime}, Library: probe.FileID{Device: 1, Inode: 3}}}}
	a := EBPF{}
	objects, refused := a.objects(r)
	if len(objects) != 1 || len(refused) != 0 {
		t.Fatalf("wiring: matching snapshot refused: %v", refused)
	}
	for _, which := range []string{"birth", "namespace", "namespace_pid", "reading"} {
		r.Admit[0] = selection
		reading := r.Read[p.PID]
		reading.Exec.StartTime = p.StartTime
		r.Read[p.PID] = reading
		switch which {
		case "birth":
			r.Admit[0].Instance.Start = admission.Determinate(29)
		case "namespace":
			r.Admit[0].Instance.Namespace.Inode++
		case "namespace_pid":
			r.Admit[0].Instance.PID++
		case "reading":
			reading.Exec.StartTime++
			r.Read[p.PID] = reading
		}
		objects, refused = a.objects(r)
		if len(objects) != 0 || len(refused) != 1 {
			t.Fatalf("%s mismatch accepted into a library object", which)
		}
	}
}

func TestAttachmentOwnerMapsShedRetiredIdentities(t *testing.T) {
	live := &ebpfAttachment{networks: make(map[int32]probe.Netns), networkOwners: make(map[int32]admission.Key), known: make(map[int32]identity)}
	s := newSet()
	s.place(live)
	for pid := int32(1); pid <= 1000; pid++ {
		instance := admission.Instance{PID: pid, Generation: admission.Generation(pid)}
		live.known[pid] = identity{instance: instance}
		live.networkOwners[pid] = instance.Key()
		live.networks[pid] = probe.Netns{Inode: uint64(pid)}
		s.identities[pid] = placedIdentity{origin: s.members[0].origin, instance: instance}
		s.members[0].covers = []int32{pid}
		s.ending(s.members[0].origin, nil)(probe.Ended{Selection: admission.Selection{ObserverPID: pid, Instance: instance}})
	}
	if len(live.known) != 0 || len(live.networkOwners) != 0 || len(live.networks) != 0 || len(s.identities) != 0 || len(s.members[0].covers) != 0 {
		t.Fatal("ended identity retained in attachment stores")
	}
	if live.knownChurn.Rebuilds() == 0 || live.networkOwnersChurn.Rebuilds() == 0 || live.networksChurn.Rebuilds() == 0 || s.identitiesChurn.Rebuilds() == 0 {
		t.Fatal("retired-key allocation was not shed")
	}
}
