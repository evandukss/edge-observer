package ebpf

import (
	"reflect"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

func pidIdentitySelection(pid int32, ticks admission.BootTicks, generation admission.Generation, target string) admission.Selection {
	return admission.Selection{
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 9, Inode: 17},
			PID: pid, Start: admission.Determinate(ticks), Generation: generation},
		ObserverPID: pid, Kind: admission.ByTarget, Mode: admission.ModeNone,
		Provenance:  admission.Provenance{Target: target, Number: int(generation)},
		AlsoNamedBy: []admission.Provenance{{Target: target + "-alias", Number: int(generation) + 100}},
	}
}

// This constructs inventory records, not processes or a measured kernel reuse.
// The third entry makes removing the middle slot exercise the moved index too.
func TestPIDIdentityDelayedEndPreservesSuccessorAndNeighbours(t *testing.T) {
	predecessor := pidIdentitySelection(201, 1000, 11, "service-a")
	successor := pidIdentitySelection(201, 2000, 29, "service-b")
	neighbour := pidIdentitySelection(202, 1000, 12, "service-c")
	otherNamespace := pidIdentitySelection(201, 1000, 13, "service-d")
	otherNamespace.Instance.Namespace.Inode++
	var notices []probe.Ended
	s := &Session{endedTo: func(e probe.Ended) { notices = append(notices, e) }}
	for _, one := range []admission.Selection{predecessor, neighbour, otherNamespace} {
		s.recordAdmission(one)
	}
	if got := s.Inventory(); len(got) != 3 {
		t.Fatalf("wiring: constructed population has %d records, want 3", len(got))
	}
	s.recordAdmission(successor)
	want := []admission.Selection{otherNamespace, neighbour, successor}
	if !reflect.DeepEqual(s.Inventory(), want) {
		t.Fatalf("successor installation/provenance: got %+v, want %+v", s.Inventory(), want)
	}
	if len(notices) != 1 || !reflect.DeepEqual(notices[0].Selection, predecessor) {
		t.Fatalf("replacement must count predecessor alone: %+v", notices)
	}
	// Queueing is explicit: the old event is delivered only after the above
	// complete successor identity and provenance have been observed installed.
	oldEnd := Event{Namespace: predecessor.Instance.Namespace, NamespacePID: predecessor.Instance.PID,
		Generation: predecessor.Instance.Generation, At: time.Unix(100, 0)}
	s.endedAt(oldEnd)
	s.endedAt(oldEnd)
	s.endedAt(Event{Namespace: successor.Instance.Namespace, NamespacePID: successor.Instance.PID})
	if !reflect.DeepEqual(s.Inventory(), want) || len(notices) != 1 {
		t.Fatalf("delayed predecessor end retired another identity: inventory=%+v notices=%+v", s.Inventory(), notices)
	}
	if !reflect.DeepEqual(s.namedBy[keyOf(successor.Instance)], successor.NamedBy()) {
		t.Fatalf("delayed end lost successor provenance: %+v", s.namedBy)
	}
	if len(s.accepted) != 3 || len(s.index) != 3 || len(s.namedBy) != 3 {
		t.Fatalf("delayed end changed live stores: accepted=%d index=%d named=%d", len(s.accepted), len(s.index), len(s.namedBy))
	}
	for _, one := range []admission.Selection{successor, neighbour, otherNamespace} {
		e := Event{Namespace: one.Instance.Namespace, NamespacePID: one.Instance.PID, Generation: one.Instance.Generation}
		s.endedAt(e)
		s.endedAt(e)
	}
	if len(s.Inventory()) != 0 || len(s.accepted) != 0 || len(s.index) != 0 || len(s.namedBy) != 0 {
		t.Fatal("own ends failed to release every live store")
	}
	wantCounts := []probe.EndedCount{{Target: "service-a", Number: 11, Count: 1},
		{Target: "service-c", Number: 12, Count: 1}, {Target: "service-d", Number: 13, Count: 1},
		{Target: "service-b", Number: 29, Count: 1}}
	if !reflect.DeepEqual(s.EndedCounts(), wantCounts) || len(notices) != 4 {
		t.Fatalf("each identity must end exactly once: counts=%+v notices=%+v", s.EndedCounts(), notices)
	}
}

func TestPIDIdentityGrantSnapshotDoesNotCreditAnotherGeneration(t *testing.T) {
	prior := pidIdentitySelection(301, 4000, 41, "before")
	control := pidIdentitySelection(302, 4000, 42, "unchanged")
	held := map[instanceKey]admission.Generation{keyOf(prior.Instance): 99, keyOf(control.Instance): 42}
	if keyOf(prior.Instance) == keyOf(control.Instance) || held[keyOf(prior.Instance)] == prior.Instance.Generation {
		t.Fatal("wiring: fixture did not distinguish keys and generations")
	}
	at := time.Unix(500, 0)
	interval := process.Interval{From: at, To: at.Add(time.Millisecond)}
	var inspected []admission.Selection
	grants, ended := grantsOf([]admission.Selection{prior, control}, held, nil, at,
		func(one admission.Selection) process.Execution {
			inspected = append(inspected, one)
			return process.Execution{Liveness: process.LivenessRunning, Observed: interval}
		})
	if len(grants) != 2 || len(ended) != 0 {
		t.Fatalf("snapshot population: grants=%+v ended=%+v", grants, ended)
	}
	if grants[1].State != probe.GrantHeld || !reflect.DeepEqual(grants[1].Selection, control) {
		t.Fatalf("unchanged generation control lost its grant: %+v", grants[1])
	}
	if grants[0].State != probe.GrantAbsent || grants[0].Evidence != interval ||
		!reflect.DeepEqual(grants[0].Selection, prior) || !reflect.DeepEqual(inspected, []admission.Selection{prior}) {
		t.Fatalf("another generation credited predecessor: grants=%+v inspections=%+v", grants, inspected)
	}
}

func TestPIDIdentityNoReuseRetirementControl(t *testing.T) {
	one := pidIdentitySelection(601, 10000, 81, "single-service")
	s := &Session{}
	s.recordAdmission(one)
	if got := s.Inventory(); len(got) != 1 || !reflect.DeepEqual(got[0], one) {
		t.Fatalf("wiring: no-reuse control did not install: %+v", got)
	}
	event := Event{Namespace: one.Instance.Namespace, NamespacePID: one.Instance.PID, Generation: one.Instance.Generation}
	s.endedAt(event)
	s.endedAt(event)
	if len(s.Inventory()) != 0 || !reflect.DeepEqual(s.EndedCounts(), []probe.EndedCount{{Target: "single-service", Number: 81, Count: 1}}) {
		t.Fatalf("no-reuse control did not end exactly once: inventory=%+v counts=%+v", s.Inventory(), s.EndedCounts())
	}
}

func TestPIDIdentityBirthControlsAdmissionAndExclusion(t *testing.T) {
	old := pidIdentitySelection(401, 7000, 61, "original")
	s := &Session{denied: map[instanceKey]admission.Start{keyOf(old.Instance): old.Instance.Start}}
	s.recordAdmission(old)
	for _, tc := range []struct {
		name             string
		instance         admission.Instance
		recorded, denied bool
	}{
		{"same-process-exec", admission.Instance{Namespace: old.Instance.Namespace, PID: 401, Start: old.Instance.Start, Executable: "/new-image"}, true, true},
		{"reused-number", admission.Instance{Namespace: old.Instance.Namespace, PID: 401, Start: admission.Determinate(8000)}, false, false},
		{"unrelated-number", admission.Instance{Namespace: old.Instance.Namespace, PID: 402, Start: old.Instance.Start}, false, false},
		{"unknown-birth", admission.Instance{Namespace: old.Instance.Namespace, PID: 401}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.recordedBirth(tc.instance); got != tc.recorded {
				t.Errorf("recorded birth=%v, want %v", got, tc.recorded)
			}
			if got := s.denies(tc.instance); got != tc.denied {
				t.Errorf("exclusion=%v, want %v", got, tc.denied)
			}
		})
	}
}
