//go:build attach

package ebpf

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

func TestPIDIdentityActualQualifiedReuse(t *testing.T) {
	pidIdentityActualAdmission(t, false)
}

func TestPIDIdentityActualReuseAfterExcludedPredecessor(t *testing.T) {
	pidIdentityActualAdmission(t, true)
}

func pidIdentityActualAdmission(t *testing.T, excludedPredecessor bool) {
	t.Helper()
	if !pidIdentityNamespace(t) {
		return
	}
	a := pidIdentityStart(t)
	oldProcess := a.child(t, "b")
	supervisor := pidIdentityReadProcess(t, a.pid)
	oldSelection := pidIdentityLiveSelection(oldProcess, 2, "earlier-service")
	control := pidIdentityLiveSelection(supervisor, 1, "supervisor")
	options := Options{Program: bpf.Full(), Points: pidIdentityPoints(t, oldProcess),
		Admit: []admission.Selection{control, oldSelection}}
	if excludedPredecessor {
		options.Deny = []admission.Denial{{Instance: oldProcess.Instance(), ObserverPID: oldProcess.PID,
			Provenance: admission.Provenance{Target: "earlier-exclusion", Number: 3}}}
	}
	s, err := Attach(options)
	if err != nil {
		t.Fatalf("wiring: attach live producer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if len(s.unprobed) != 0 {
		t.Fatalf("wiring: required probes not placed: %v", s.unprobed)
	}
	// Deliberately stop userspace delivery while retaining the real kernel
	// lifecycle hooks. This isolates admission against lagging inventory; it
	// does not claim to measure delivery delay or payload attribution.
	s.StopReading()
	allowed := s.collection.Maps["allowed_processes"]
	var oldValue admissionValue
	if err := allowed.Lookup(keyOf(oldProcess.Instance()), &oldValue); err != nil || oldValue.Generation == 0 ||
		oldValue.Birth != uint64(oldProcess.Start().Ticks) {
		t.Fatalf("wiring: original kernel identity absent: value=%+v err=%v", oldValue, err)
	}
	if (oldValue.Kind == denied) != excludedPredecessor {
		t.Fatalf("wiring: predecessor exclusion=%v, want %v", oldValue.Kind == denied, excludedPredecessor)
	}
	previousGeneration := oldValue.Generation
	got, skipped, err := s.Admit([]admission.Selection{oldSelection})
	if excludedPredecessor {
		if !errors.Is(err, ErrNotAuthorised) || !strings.Contains(err.Error(), string(ExcludedBySubtree)) || len(got) != 0 {
			t.Fatalf("genuine exclusion control: grants=%+v skipped=%+v err=%v", got, skipped, err)
		}
	} else if err != nil || len(got) != 0 || len(skipped) != 1 {
		t.Fatalf("unchanged process control: grants=%+v skipped=%+v err=%v", got, skipped, err)
	}
	before := s.Inventory()
	nextProcess := a.child(t, "r")
	pidIdentityReuseGuard(t, oldProcess, nextProcess)
	if !reflect.DeepEqual(s.Inventory(), before) {
		t.Fatal("wiring: predecessor inventory did not remain held across reuse")
	}
	// The slot is either empty or still holds the predecessor's own entry. A
	// leftover denial is the stale-denial-on-reuse state, and is logged as such.
	var left admissionValue
	switch err := allowed.Lookup(keyOf(nextProcess.Instance()), &left); {
	case errors.Is(err, cilium.ErrKeyNotExist):
		t.Log("wiring: reaped predecessor kernel slot is empty")
	case err == nil && left.Generation == previousGeneration && left.Birth == uint64(oldProcess.Start().Ticks):
		t.Logf("wiring: reaped predecessor kernel slot still holds its own entry: kind=%d", left.Kind)
	default:
		t.Fatalf("wiring: predecessor kernel slot holds another writer's entry: %+v %v", left, err)
	}
	reading := process.Inspect("/proc", nextProcess.PID, process.Group{Namespace: nextProcess.Namespace,
		NamespacePID: nextProcess.NamespacePID, Start: nextProcess.Start()})
	if reading.Liveness != process.LivenessRunning {
		t.Fatalf("wiring: qualified successor is not alive: %+v", reading)
	}
	if count, err := entries(allowed); err != nil || count >= int(allowed.MaxEntries()) {
		t.Fatalf("wiring: no admission capacity: count=%d max=%d err=%v", count, allowed.MaxEntries(), err)
	}
	if !reflect.DeepEqual(pidIdentityPoints(t, nextProcess), options.Points) {
		t.Fatal("wiring: successor does not use the placed supported probes")
	}
	next := pidIdentityLiveSelection(nextProcess, 4, "later-service")
	next.AlsoNamedBy = []admission.Provenance{{Target: "later-alias", Number: 5}}
	got, skipped, err = s.Admit([]admission.Selection{next})
	if err != nil || len(got) != 1 || len(skipped) != 0 {
		t.Fatalf("qualified reuse must admit: grants=%+v skipped=%+v err=%v", got, skipped, err)
	}
	granted := got[0]
	if granted.Instance.Start != next.Instance.Start || granted.Instance.Generation == 0 || uint64(granted.Instance.Generation) == previousGeneration ||
		!reflect.DeepEqual(granted.NamedBy(), next.NamedBy()) {
		t.Fatalf("successor did not receive its own birth/provenance: %+v", granted)
	}
	var current admissionValue
	if err := allowed.Lookup(keyOf(next.Instance), &current); err != nil {
		t.Fatalf("admitted successor has no kernel grant: %v", err)
	}
	if current.Birth != uint64(next.Instance.Start.Ticks) || current.Generation != uint64(granted.Instance.Generation) ||
		current.Kind == denied || !reflect.DeepEqual(s.targets[current.Target], next.Provenance) {
		t.Fatalf("successor kernel attribution disagrees: value=%+v target=%+v grant=%+v", current, s.targets[current.Target], granted)
	}
	if !reflect.DeepEqual(s.namedBy[keyOf(next.Instance)], next.NamedBy()) {
		t.Fatalf("successor inherited stored provenance: %+v", s.namedBy[keyOf(next.Instance)])
	}
	matching := 0
	for _, recorded := range s.Inventory() {
		if keyOf(recorded.Instance) == keyOf(next.Instance) {
			matching++
			if !reflect.DeepEqual(recorded, granted) {
				t.Fatalf("successor inventory differs from its grant: %+v want %+v", recorded, granted)
			}
		}
	}
	if matching != 1 {
		t.Fatalf("successor appears %d times in inventory, want 1", matching)
	}
	if response := a.command(t, "x"); response != "gone" {
		t.Fatalf("wiring: successor not reaped: %q", response)
	}
	for range 2 {
		for _, g := range s.Grants() {
			if g.Selection.Instance.Same(granted.Instance) {
				t.Fatalf("successor own end retained its grant: %+v", g)
			}
		}
	}
	counted := 0
	for _, c := range s.EndedCounts() {
		if c.Target == next.Provenance.Target && c.Number == next.Provenance.Number {
			counted += c.Count
		}
	}
	if counted != 1 {
		t.Fatalf("successor own end counted %d times, want 1", counted)
	}
	t.Log("PID-IDENTITY-CASE-COMPLETE")
}

func TestPIDIdentityActualExcludedSuccessorHasItsOwnDenial(t *testing.T) {
	if !pidIdentityNamespace(t) {
		return
	}
	a := pidIdentityStart(t)
	parent := pidIdentityReadProcess(t, a.pid)
	// Attach refuses a session that admits nothing, so an unrelated process is
	// admitted beside the excluded family.
	anchor := pidIdentityReadProcess(t, pidIdentityStart(t).pid)
	selection := pidIdentityLiveSelection(parent, 1, "excluded-family")
	s, err := Attach(Options{Program: bpf.Full(), Points: pidIdentityPoints(t, parent),
		Admit: []admission.Selection{pidIdentityLiveSelection(anchor, 6, "excluded-anchor"), selection},
		Deny: []admission.Denial{{Instance: parent.Instance(),
			ObserverPID: parent.PID, Provenance: selection.Provenance}}})
	if err != nil {
		t.Fatalf("wiring: attach excluded family: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.StopReading()
	old := a.child(t, "b")
	allowed := s.collection.Maps["allowed_processes"]
	var first admissionValue
	if err := allowed.Lookup(keyOf(old.Instance()), &first); err != nil || first.Kind != denied || first.Generation == 0 {
		t.Fatalf("wiring: inherited predecessor denial absent: %+v %v", first, err)
	}
	refuse := func(p process.Process) {
		t.Helper()
		grants, skips, err := s.Admit([]admission.Selection{pidIdentityLiveSelection(p, 2, "direct-include")})
		if !errors.Is(err, ErrNotAuthorised) || !strings.Contains(err.Error(), string(ExcludedBySubtree)) || len(grants) != 0 || len(skips) != 0 {
			t.Fatalf("own exclusion must refuse direct include: grants=%+v skips=%+v err=%v", grants, skips, err)
		}
	}
	refuse(old)
	next := a.child(t, "r")
	pidIdentityReuseGuard(t, old, next)
	var second admissionValue
	if err := allowed.Lookup(keyOf(next.Instance()), &second); err != nil {
		t.Fatalf("successor missing its inherited exclusion: %v", err)
	}
	if second.Kind != denied || second.Birth != uint64(next.Start().Ticks) || second.Generation == first.Generation || second.Generation == 0 {
		t.Fatalf("excluded successor carries predecessor facts: old=%+v next=%+v", first, second)
	}
	refuse(next)
	t.Log("PID-IDENTITY-CASE-COMPLETE")
}

func TestPIDIdentityConstructedStaleDenialDoesNotRefuseLiveBirth(t *testing.T) {
	a := pidIdentityStart(t)
	p := pidIdentityReadProcess(t, a.pid)
	s, allowed := pidIdentityMapSession(t)
	next := pidIdentityLiveSelection(p, 8, "current-service")
	s.enumerated = []admission.Namespace{p.Namespace}
	stale := admissionValue{Generation: 17, Birth: uint64(p.Start().Ticks) - 1, Kind: denied, Threads: 1}
	s.denied = map[instanceKey]admission.Start{keyOf(next.Instance): admission.Determinate(admission.BootTicks(stale.Birth))}
	if err := allowed.Update(keyOf(next.Instance), stale, cilium.UpdateNoExist); err != nil {
		t.Fatalf("wiring: plant constructed stale denial: %v", err)
	}
	var seen admissionValue
	if err := allowed.Lookup(keyOf(next.Instance), &seen); err != nil || seen != stale || seen.Birth == uint64(p.Start().Ticks) {
		t.Fatalf("wiring: stale denial not installed: %+v %v", seen, err)
	}
	grants, skips, err := s.Admit([]admission.Selection{next})
	if err != nil || len(grants) != 1 || len(skips) != 0 {
		t.Fatalf("constructed stale denial refused current birth: grants=%+v skips=%+v err=%v", grants, skips, err)
	}
	if err := allowed.Lookup(keyOf(next.Instance), &seen); err != nil || seen.Kind == denied || seen.Birth != uint64(next.Instance.Start.Ticks) {
		t.Fatalf("current birth not installed after stale denial: %+v %v", seen, err)
	}
}

func TestPIDIdentityConstructedRetractionRequiresExactGeneration(t *testing.T) {
	s, allowed := pidIdentityMapSession(t)
	one := pidIdentitySelection(501, 9000, 72, "retained")
	value, err := encode(one, 1)
	if err != nil {
		t.Fatalf("wiring: encode grant: %v", err)
	}
	if err := allowed.Update(keyOf(one.Instance), value, cilium.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	s.recordAdmission(one)
	if len(s.Inventory()) != 1 {
		t.Fatal("wiring: current grant did not enter inventory")
	}
	for _, generation := range []admission.Generation{71, 0} {
		old := one
		old.Instance.Generation = generation
		s.Retract([]admission.Selection{old})
		var got admissionValue
		if err := allowed.Lookup(keyOf(one.Instance), &got); err != nil || got != value || len(s.Inventory()) != 1 {
			t.Fatalf("retraction generation %d removed another grant: %+v %v inventory=%+v", generation, got, err, s.Inventory())
		}
	}
	s.Retract([]admission.Selection{one})
	s.Retract([]admission.Selection{one})
	var got admissionValue
	if err := allowed.Lookup(keyOf(one.Instance), &got); !errors.Is(err, cilium.ErrKeyNotExist) || len(s.Inventory()) != 0 || len(s.EndedCounts()) != 0 {
		t.Fatalf("own rollback control failed or became ended coverage: value=%+v err=%v inventory=%+v ended=%+v", got, err, s.Inventory(), s.EndedCounts())
	}
}

func TestPIDIdentityGrantsRetiresItsSnapshotAfterActualReuseAdmission(t *testing.T) {
	if !pidIdentityNamespace(t) {
		return
	}
	a := pidIdentityStart(t)
	oldProcess := a.child(t, "b")
	old := pidIdentityLiveSelection(oldProcess, 11, "snapshot-predecessor")
	parent := pidIdentityLiveSelection(pidIdentityReadProcess(t, a.pid), 12, "snapshot-supervisor")
	s, err := Attach(Options{Program: bpf.Full(), Points: pidIdentityPoints(t, oldProcess),
		Admit: []admission.Selection{parent, old}})
	if err != nil {
		t.Fatalf("wiring: attach snapshot subject: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.StopReading()
	var oldGeneration admission.Generation
	for _, one := range s.Inventory() {
		if keyOf(one.Instance) == keyOf(old.Instance) {
			oldGeneration = one.Instance.Generation
		}
	}
	if oldGeneration == 0 {
		t.Fatal("wiring: predecessor never entered inventory")
	}
	nextProcess := a.child(t, "r")
	pidIdentityReuseGuard(t, oldProcess, nextProcess)
	var gone admissionValue
	if err := s.collection.Maps["allowed_processes"].Lookup(keyOf(old.Instance), &gone); !errors.Is(err, cilium.ErrKeyNotExist) {
		t.Fatalf("wiring: old slot still occupied before Grants snapshot: %+v %v", gone, err)
	}
	if reading := s.inspect(old); reading.Liveness != process.LivenessReplaced {
		t.Fatalf("wiring: old identity not positively established replaced: %+v", reading)
	}
	next := pidIdentityLiveSelection(nextProcess, 13, "snapshot-successor")
	next.AlsoNamedBy = []admission.Provenance{{Target: "snapshot-alias", Number: 14}}
	var successor admission.Selection
	called := 0
	s.beforeRetireGrants = func() {
		called++
		if called != 1 {
			t.Fatal("wiring: snapshot hook unexpectedly reentered")
		}
		grants, skips, err := s.Admit([]admission.Selection{next})
		if err != nil || len(grants) != 1 || len(skips) != 0 {
			t.Fatalf("snapshot successor must admit: grants=%+v skips=%+v err=%v", grants, skips, err)
		}
		successor = grants[0]
		if successor.Instance.Generation == oldGeneration || !reflect.DeepEqual(successor.NamedBy(), next.NamedBy()) {
			t.Fatalf("snapshot successor has predecessor attribution: %+v", successor)
		}
		found := false
		for _, installed := range s.Inventory() {
			if reflect.DeepEqual(installed, successor) {
				found = true
			}
		}
		if !found {
			t.Fatal("wiring: successor not installed before releasing old Grants snapshot")
		}
		t.Log("wiring: successor installed before old Grants snapshot retirement")
	}
	_ = s.Grants()
	s.beforeRetireGrants = nil
	if called != 1 {
		t.Fatalf("wiring: actual Grants path reached snapshot hold %d times, want 1", called)
	}
	found := false
	for _, one := range s.Inventory() {
		if reflect.DeepEqual(one, successor) {
			found = true
		}
	}
	if !found || !reflect.DeepEqual(s.namedBy[keyOf(next.Instance)], next.NamedBy()) {
		t.Fatalf("old Grants snapshot retired installed successor: inventory=%+v named=%+v", s.Inventory(), s.namedBy)
	}
	if response := a.command(t, "x"); response != "gone" {
		t.Fatalf("wiring: successor exit not acknowledged: %q", response)
	}
	_ = s.Grants()
	_ = s.Grants()
	want := map[string]int{"snapshot-predecessor": 1, "snapshot-successor": 1}
	got := make(map[string]int)
	for _, count := range s.EndedCounts() {
		got[count.Target] += count.Count
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot/own-end accounting: got %v, want %v", got, want)
	}
	t.Log("PID-IDENTITY-CASE-COMPLETE")
}

// The predecessor's own execution end, emitted by the kernel with its own
// generation, is held behind its earlier event in the real reader until the
// successor is installed, then delivered. Nothing here stops the reader.
func TestPIDIdentityActualHeldEndAfterSuccessorInstallation(t *testing.T) {
	if !pidIdentityNamespace(t) {
		return
	}
	port := pidIdentityTLSPeer(t)
	a := pidIdentityStart(t)
	if got := a.command(t, fmt.Sprintf("p %d", port)); got != "port" {
		t.Fatalf("wiring: fixture refused the peer port: %q", got)
	}
	oldProcess := a.child(t, "b")
	supervisor := pidIdentityReadProcess(t, a.pid)
	old := pidIdentityLiveSelection(oldProcess, 41, "ended-predecessor")
	reached, release := make(chan Event, 1), make(chan struct{})
	var holdOnce, releaseOnce sync.Once
	var (
		mu      sync.Mutex
		notices []probe.Ended
	)
	s, err := Attach(Options{Program: bpf.Full(), Points: pidIdentityPoints(t, oldProcess),
		Admit: []admission.Selection{pidIdentityLiveSelection(supervisor, 40, "ended-anchor"), old},
		BeforeRecord: func(e Event) {
			if e.Kind == Transfer && e.NamespacePID == oldProcess.NamespacePID {
				holdOnce.Do(func() { reached <- e; <-release })
			}
		},
		Ended: func(e probe.Ended) {
			mu.Lock()
			notices = append(notices, e)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("wiring: attach live producer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(letGo)
	var oldGeneration admission.Generation
	for _, one := range s.Inventory() {
		if keyOf(one.Instance) == keyOf(old.Instance) {
			oldGeneration = one.Instance.Generation
		}
	}
	if oldGeneration == 0 {
		t.Fatal("wiring: predecessor never entered inventory")
	}
	// The predecessor writes once and exits; its successor takes its number.
	nextProcess := a.child(t, "r")
	pidIdentityReuseGuard(t, oldProcess, nextProcess)
	select {
	case e := <-reached:
		if e.Generation != oldGeneration {
			t.Fatalf("wiring: held event carries generation %d, want the predecessor's %d", e.Generation, oldGeneration)
		}
		t.Logf("wiring: reader held at the predecessor's event: generation=%d", e.Generation)
	case <-time.After(20 * time.Second):
		t.Fatal("wiring: the predecessor's event never reached the reader")
	}
	var slot admissionValue
	if err := s.collection.Maps["allowed_processes"].Lookup(keyOf(old.Instance), &slot); !errors.Is(err, cilium.ErrKeyNotExist) {
		t.Fatalf("wiring: predecessor kernel slot not removed at its exit: %+v %v", slot, err)
	}
	next := pidIdentityLiveSelection(nextProcess, 42, "ended-successor")
	next.AlsoNamedBy = []admission.Provenance{{Target: "ended-alias", Number: 43}}
	grants, skips, err := s.Admit([]admission.Selection{next})
	if err != nil || len(grants) != 1 || len(skips) != 0 {
		t.Fatalf("qualified successor must admit while the predecessor's end is held: grants=%+v skips=%+v err=%v", grants, skips, err)
	}
	successor := grants[0]
	installed := func() int {
		n := 0
		for _, one := range s.Inventory() {
			if reflect.DeepEqual(one, successor) {
				n++
			}
		}
		return n
	}
	if installed() != 1 {
		t.Fatal("wiring: successor not installed before the held end was released")
	}
	letGo()
	pidIdentityAwaitEnd(t, s, oldProcess.NamespacePID, oldGeneration)
	if installed() != 1 {
		t.Fatalf("delayed predecessor end retired the installed successor: inventory=%+v", s.Inventory())
	}
	s.held.Lock()
	named := s.namedBy[keyOf(next.Instance)]
	s.held.Unlock()
	if !reflect.DeepEqual(named, next.NamedBy()) {
		t.Fatalf("delayed predecessor end changed successor provenance: %+v", named)
	}
	if response := a.command(t, "x"); response != "gone" {
		t.Fatalf("wiring: successor exit not acknowledged: %q", response)
	}
	pidIdentityAwaitEnd(t, s, nextProcess.NamespacePID, successor.Instance.Generation)
	if installed() != 0 {
		t.Fatalf("successor's own end did not retire it: inventory=%+v", s.Inventory())
	}
	_ = s.Grants()
	_ = s.Grants()
	want := map[string]int{"ended-predecessor": 1, "ended-successor": 1}
	got := make(map[string]int)
	for _, count := range s.EndedCounts() {
		got[count.Target] += count.Count
	}
	mu.Lock()
	told := len(notices)
	mu.Unlock()
	if !reflect.DeepEqual(got, want) || told != 2 {
		t.Fatalf("each admission must end exactly once: counts=%v notices=%d", got, told)
	}
	t.Log("PID-IDENTITY-CASE-COMPLETE")
}

// Every replacement here is a deliberate userspace map write. This suite
// measures the checked-lookup/Delete interval, not kernel writer reachability.
func TestPIDIdentityConstructedDeleteInterleavings(t *testing.T) {
	for _, operation := range []string{"stale_denial", "retract", "admit_rollback", "sweep"} {
		t.Run(operation, func(t *testing.T) {
			for _, placement := range []string{"unchanged", "before_guard", "after_guard"} {
				// Rollback's write and failed second write have no seam before its
				// guard. Do not invent that scheduling point or claim it covered.
				if operation == "admit_rollback" && placement == "before_guard" {
					continue
				}
				t.Run(placement, func(t *testing.T) {
					pidIdentityConstructedDelete(t, operation, placement)
				})
			}
		})
	}
}

func pidIdentityConstructedDelete(t *testing.T, operation, placement string) {
	t.Helper()
	a := pidIdentityStart(t)
	p := pidIdentityReadProcess(t, a.pid)
	one := pidIdentityLiveSelection(p, 21, "delete-subject")
	one.Instance.Generation = 101
	s, allowed := pidIdentityMapSession(t)
	s.enumerated = []admission.Namespace{p.Namespace}
	s.generations = 100
	old, err := encode(one, 1)
	if err != nil {
		t.Fatalf("wiring: encode old entry: %v", err)
	}
	if operation == "stale_denial" {
		old.Kind = denied
		old.Birth--
	}
	if operation == "sweep" {
		one.Instance.Start.Ticks--
		old.Birth--
	}
	key := keyOf(one.Instance)
	next := old
	next.Generation = uint64(admission.KernelGenerations + 55)
	next.Birth++
	// A successor under a stale denial is the excluded family's own child, which
	// inherits a denial of its own birth; elsewhere a fork-hook grant.
	if operation != "stale_denial" {
		next.Kind = byDescent
	}
	if operation != "admit_rollback" {
		if err := allowed.Update(key, old, cilium.UpdateNoExist); err != nil {
			t.Fatalf("wiring: install old entry: %v", err)
		}
	}
	installNext := func() {
		if err := allowed.Update(key, next, cilium.UpdateAny); err != nil {
			t.Fatalf("wiring: substitute constructed successor: %v", err)
		}
		var seen admissionValue
		if err := allowed.Lookup(key, &seen); err != nil || seen != next {
			t.Fatalf("wiring: replacement not observable before Delete: %+v %v", seen, err)
		}
	}
	if placement == "before_guard" {
		installNext()
	}
	calls := 0
	s.beforeDeleteAdmission = func(op string, observed admission.Key) {
		calls++
		// A successor written before the guard reaches this hook only if the
		// guard accepted it: the property, decided after the operation.
		if placement == "before_guard" {
			return
		}
		if op != operation || observed != one.Instance.Key() {
			t.Fatalf("wiring: wrong guarded delete: op=%s key=%+v want=%s %+v", op, observed, operation, one.Instance.Key())
		}
		var seen admissionValue
		if err := allowed.Lookup(key, &seen); err != nil || seen.Generation != old.Generation || seen.Birth != old.Birth {
			t.Fatalf("wiring: matching old value not held at final guard: %+v %v", seen, err)
		}
		if placement == "after_guard" {
			installNext()
		}
		t.Logf("wiring: %s reached final matching lookup; placement=%s", operation, placement)
	}
	// The residual of the atomic take: a different occupant is out of the map
	// until it is restored. Reported without stopping, so the presence assertion
	// below still decides a mutant that reaches this hook.
	takes := 0
	s.afterTakeAdmission = func(op string, observed admission.Key, matched bool) {
		takes++
		if placement != "before_guard" && (op != operation || observed != one.Instance.Key()) {
			t.Errorf("wiring: wrong atomic take: op=%s key=%+v want=%s %+v", op, observed, operation, one.Instance.Key())
		}
		var seen admissionValue
		if err := allowed.Lookup(key, &seen); !errors.Is(err, cilium.ErrKeyNotExist) {
			t.Errorf("%s: the key must be empty between the atomic take and any restore: %+v %v", operation, seen, err)
		}
		if matched != (placement == "unchanged") {
			t.Errorf("%s: take with a successor written %s reported matched=%v", operation, placement, matched)
		}
	}
	switch operation {
	case "stale_denial":
		if err := s.retireStaleDenial(allowed, key, one, &old); err != nil {
			t.Fatalf("stale-denial deletion returned error: %v", err)
		}
	case "retract":
		s.Retract([]admission.Selection{one})
	case "sweep":
		if err := s.sweep(allowed, []admission.Selection{one}); err != nil {
			t.Fatalf("sweep returned error: %v", err)
		}
	case "admit_rollback":
		other := pidIdentityStart(t)
		occupied := pidIdentityLiveSelection(pidIdentityReadProcess(t, other.pid), 22, "already-in-kernel")
		value, err := encode(occupied, 1)
		if err != nil {
			t.Fatal(err)
		}
		value.Generation = 700
		if err := allowed.Update(keyOf(occupied.Instance), value, cilium.UpdateNoExist); err != nil {
			t.Fatalf("wiring: install rollback conflict: %v", err)
		}
		grants, _, err := s.Admit([]admission.Selection{one, occupied})
		if !errors.Is(err, ErrUnavailable) || len(grants) != 0 {
			t.Fatalf("wiring: second write did not refuse and roll back: grants=%+v err=%v", grants, err)
		}
	}
	// Before the guard, reaching the deletion at all is the guard accepting a
	// successor: the property, not wiring.
	if placement == "before_guard" {
		if calls != 0 || takes != 0 {
			t.Errorf("%s: the guard accepted a successor written before it: delete hooks=%d atomic takes=%d", operation, calls, takes)
		}
	} else if calls != 1 || takes != 1 {
		t.Fatalf("wiring: reached %d matching delete hooks and %d atomic takes, want 1 each", calls, takes)
	}
	var got admissionValue
	err = allowed.Lookup(key, &got)
	if placement == "unchanged" {
		if !errors.Is(err, cilium.ErrKeyNotExist) {
			t.Fatalf("unchanged-entry control failed to delete: %+v %v", got, err)
		}
	} else if err != nil || got != next {
		t.Fatalf("%s: a successor written %s must be present afterwards, byte for byte: got=%+v err=%v want=%+v",
			operation, placement, got, err, next)
	}
}

// The successor in this case is written only by the loaded fork hook. The
// original grant comes from Admit, so Retract receives a genuine reload receipt.
func TestPIDIdentityActualKernelSuccessorSurvivesRetraction(t *testing.T) {
	if !pidIdentityNamespace(t) {
		return
	}
	for _, placement := range []string{"unchanged", "before_guard", "after_guard"} {
		t.Run(placement, func(t *testing.T) {
			a := pidIdentityStart(t)
			oldProcess := a.child(t, "b")
			anchor := pidIdentityStart(t)
			anchorProcess := pidIdentityReadProcess(t, anchor.pid)
			s, err := Attach(Options{Program: bpf.Full(), Points: pidIdentityPoints(t, oldProcess),
				Admit: []admission.Selection{pidIdentityLiveSelection(anchorProcess, 31, "anchor")}})
			if err != nil {
				t.Fatalf("wiring: attach kernel-writer subject: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			s.StopReading()
			oldGrants, skips, err := s.Admit([]admission.Selection{pidIdentityLiveSelection(oldProcess, 32, "rollback-subject")})
			if err != nil || len(oldGrants) != 1 || len(skips) != 0 {
				t.Fatalf("wiring: original reload grant absent: %+v %+v %v", oldGrants, skips, err)
			}
			old := oldGrants[0]
			parent := pidIdentityLiveSelection(pidIdentityReadProcess(t, a.pid), 33, "fork-origin")
			parent.Mode = admission.ModeFollow
			parentGrants, skips, err := s.Admit([]admission.Selection{parent})
			if err != nil || len(parentGrants) != 1 || len(skips) != 0 {
				t.Fatalf("wiring: fork origin not granted: %+v %+v %v", parentGrants, skips, err)
			}
			allowed := s.collection.Maps["allowed_processes"]
			var next admissionValue
			reuse := func() {
				nextProcess := a.child(t, "r")
				pidIdentityReuseGuard(t, oldProcess, nextProcess)
				if err := allowed.Lookup(keyOf(old.Instance), &next); err != nil || next.Kind != byDescent ||
					next.Birth != uint64(nextProcess.Start().Ticks) || !admission.Generation(next.Generation).FromKernel() ||
					next.ParentGeneration != uint64(parentGrants[0].Instance.Generation) || next.ParentPID != uint32(parent.Instance.PID) {
					t.Fatalf("wiring: real fork hook did not install successor identity/provenance: %+v err=%v", next, err)
				}
				t.Logf("wiring: actual kernel successor installed: generation=%d birth=%d parent_generation=%d", next.Generation, next.Birth, next.ParentGeneration)
			}
			if placement == "before_guard" {
				reuse()
			}
			calls := 0
			s.beforeDeleteAdmission = func(operation string, observed admission.Key) {
				calls++
				if placement == "before_guard" {
					return
				}
				if operation != "retract" || observed != old.Instance.Key() {
					t.Fatalf("wiring: unexpected actual retraction hook: %s %+v", operation, observed)
				}
				// Retract holds Session.held. Only the external process and raw
				// map are touched here; no Session method can acquire that lock.
				if placement == "after_guard" {
					reuse()
				}
			}
			takes := 0
			s.afterTakeAdmission = func(operation string, observed admission.Key, matched bool) {
				takes++
				var seen admissionValue
				if err := allowed.Lookup(keyOf(old.Instance), &seen); !errors.Is(err, cilium.ErrKeyNotExist) {
					t.Errorf("retract: the key must be empty between the atomic take and any restore: %+v %v", seen, err)
				}
				if matched != (placement == "unchanged") {
					t.Errorf("retract: take with the kernel's successor written %s reported matched=%v", placement, matched)
				}
			}
			s.Retract(oldGrants)
			if placement == "before_guard" {
				if calls != 0 || takes != 0 {
					t.Errorf("retract: the guard accepted the kernel's successor: delete hooks=%d atomic takes=%d", calls, takes)
				}
			} else if calls != 1 || takes != 1 {
				t.Fatalf("wiring: actual guarded deletion calls=%d atomic takes=%d, want 1 each", calls, takes)
			}
			var got admissionValue
			err = allowed.Lookup(keyOf(old.Instance), &got)
			if placement == "unchanged" {
				if !errors.Is(err, cilium.ErrKeyNotExist) {
					t.Fatalf("actual unchanged grant rollback control failed: %+v %v", got, err)
				}
			} else if err != nil || got != next {
				t.Fatalf("retract: the kernel's successor written %s must be present afterwards, byte for byte: got=%+v err=%v want=%+v",
					placement, got, err, next)
			}
		})
	}
	t.Log("PID-IDENTITY-CASE-COMPLETE")
}

// A successor that ends while the atomic take holds its entry finds nothing for
// its exit to remove, so the restore leaves an entry for an ended process, which
// may stay for the session. Kernel admission authenticates birth: that entry
// must admit no later process holding the number with another birth.
func TestPIDIdentityActualEndedSuccessorEntryAdmitsNoLaterBirth(t *testing.T) {
	if !pidIdentityNamespace(t) {
		return
	}
	port := pidIdentityTLSPeer(t)
	a := pidIdentityStart(t)
	oldProcess := a.child(t, "b")
	anchor := pidIdentityStart(t)
	b := pidIdentityStart(t)
	if got := b.command(t, fmt.Sprintf("p %d", port)); got != "port" {
		t.Fatalf("wiring: fixture refused the peer port: %q", got)
	}
	var (
		mu        sync.Mutex
		transfers []Event
	)
	points := pidIdentityPoints(t, oldProcess)
	s, err := Attach(Options{Program: bpf.Full(), Points: points,
		Admit: []admission.Selection{pidIdentityLiveSelection(pidIdentityReadProcess(t, anchor.pid), 51, "anchor")},
		BeforeRecord: func(e Event) {
			if e.Kind == Transfer {
				mu.Lock()
				transfers = append(transfers, e)
				mu.Unlock()
			}
		}})
	if err != nil {
		t.Fatalf("wiring: attach kernel-writer subject: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	oldGrants, skips, err := s.Admit([]admission.Selection{pidIdentityLiveSelection(oldProcess, 52, "rollback-subject")})
	if err != nil || len(oldGrants) != 1 || len(skips) != 0 {
		t.Fatalf("wiring: original reload grant absent: %+v %+v %v", oldGrants, skips, err)
	}
	old := oldGrants[0]
	key := keyOf(old.Instance)
	parent := pidIdentityLiveSelection(pidIdentityReadProcess(t, a.pid), 53, "fork-origin")
	parent.Mode = admission.ModeFollow
	if grants, skips, err := s.Admit([]admission.Selection{parent}); err != nil || len(grants) != 1 || len(skips) != 0 {
		t.Fatalf("wiring: fork origin not granted: %+v %+v %v", grants, skips, err)
	}
	allowed := s.collection.Maps["allowed_processes"]
	var (
		successor process.Process
		next      admissionValue
	)
	calls, takes := 0, 0
	s.beforeDeleteAdmission = func(operation string, observed admission.Key) {
		calls++
		if operation != "retract" || observed != old.Instance.Key() {
			t.Fatalf("wiring: unexpected actual retraction hook: %s %+v", operation, observed)
		}
		successor = a.child(t, "r")
		pidIdentityReuseGuard(t, oldProcess, successor)
		if err := allowed.Lookup(key, &next); err != nil || next.Kind != byDescent ||
			next.Birth != uint64(successor.Start().Ticks) || !admission.Generation(next.Generation).FromKernel() {
			t.Fatalf("wiring: real fork hook did not install the successor: %+v err=%v", next, err)
		}
	}
	s.afterTakeAdmission = func(operation string, observed admission.Key, matched bool) {
		takes++
		var seen admissionValue
		if matched || !errors.Is(allowed.Lookup(key, &seen), cilium.ErrKeyNotExist) {
			t.Fatalf("wiring, not this property: the take did not hold the kernel's successor out of the map for a restore: matched=%v seen=%+v", matched, seen)
		}
		if response := a.command(t, "x"); response != "gone" {
			t.Fatalf("wiring: successor not reaped inside the window: %q", response)
		}
		reading := process.Inspect("/proc", successor.PID, process.Group{Namespace: successor.Namespace,
			NamespacePID: successor.NamespacePID, Start: successor.Start()})
		if reading.Liveness == process.LivenessRunning {
			t.Fatalf("wiring: successor still alive after its reap: %+v", reading)
		}
	}
	s.Retract(oldGrants)
	if calls != 1 || takes != 1 {
		t.Fatalf("wiring: actual guarded deletion calls=%d atomic takes=%d, want 1 each", calls, takes)
	}
	var stale admissionValue
	if err := allowed.Lookup(key, &stale); err != nil || stale != next {
		t.Fatalf("wiring, not the property: no entry for the ended successor was restored, so nothing below measures one: got=%+v err=%v want=%+v",
			stale, err, next)
	}
	t.Logf("restored entry for an ended successor remains: generation=%d birth=%d", stale.Generation, stale.Birth)

	later := b.child(t, fmt.Sprintf("n %d", successor.NamespacePID))
	if later.Namespace != successor.Namespace || later.NamespacePID != successor.NamespacePID ||
		!later.Start().Determined || uint64(later.Start().Ticks) == stale.Birth {
		t.Fatalf("wiring: one attempt did not place another birth at the ended successor's number: successor=%+v later=%+v", successor, later)
	}
	var held admissionValue
	if err := allowed.Lookup(key, &held); err != nil || held != stale {
		t.Fatalf("wiring: the later process's creation changed the restored entry, which it must not reach: %+v %v", held, err)
	}
	if !reflect.DeepEqual(pidIdentityPoints(t, later), points) {
		t.Fatal("wiring: later process does not use the placed probes")
	}
	// It writes once over TLS and exits; the actor reports gone only after a
	// successful write.
	if response := b.command(t, "x"); response != "gone" {
		t.Fatalf("wiring: later process did not write and exit: %q", response)
	}

	// The control writes the same way from an entry that is genuinely its own.
	// One ring buffer, one reader: the later process's write, had it been
	// admitted, would be delivered before the control's.
	control := b.child(t, "b")
	grants, skips, err := s.Admit([]admission.Selection{pidIdentityLiveSelection(control, 54, "genuine-control")})
	if err != nil || len(grants) != 1 || len(skips) != 0 {
		t.Fatalf("wiring: control not admitted: %+v %+v %v", grants, skips, err)
	}
	if response := b.command(t, "x"); response != "gone" {
		t.Fatalf("wiring: control did not write and exit: %q", response)
	}
	seen := func() []Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]Event(nil), transfers...)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		delivered := false
		for _, e := range seen() {
			if e.NamespacePID == control.NamespacePID && e.Generation == grants[0].Instance.Generation {
				delivered = true
			}
		}
		if delivered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("wiring, not the property: the genuine control's write was never delivered, so an absence below measures nothing")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, e := range seen() {
		if e.NamespacePID == later.NamespacePID || uint64(e.Generation) == stale.Generation {
			t.Fatalf("an entry restored for an ended successor admitted a later process with another birth: event=%+v stale=%+v", e, stale)
		}
	}
	t.Log("PID-IDENTITY-CASE-COMPLETE")
}
