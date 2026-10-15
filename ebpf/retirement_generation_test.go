package ebpf

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
)

// These are constructed inventory states, not kernel-path reproduction. The
// live reload witness separately establishes that real PID reuse reaches them.
func TestRetirementNamesTheAdmissionGeneration(t *testing.T) {
	old := admission.Selection{
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42,
			Start: admission.Determinate(100), Generation: 1},
		Provenance: admission.Provenance{Target: "old", Number: 1},
	}
	next := old
	next.Instance.Start = admission.Determinate(200)
	next.Instance.Generation = 2
	next.Provenance = admission.Provenance{Target: "next", Number: 2}
	var notified []admission.Selection
	s := &Session{endedTo: func(e probe.Ended) { notified = append(notified, e.Selection) }}
	s.recordAdmission(old)
	s.recordAdmission(next)
	got := s.Inventory()
	if len(got) != 1 || !got[0].Instance.Same(next.Instance) || got[0].Provenance.Target != "next" {
		t.Fatalf("replacement not recorded with its own attribution: %+v", got)
	}
	if len(notified) != 1 || !notified[0].Instance.Same(old.Instance) {
		t.Fatalf("old retirement notification: %+v", notified)
	}
	s.endedAt(Event{Namespace: old.Instance.Namespace, NamespacePID: old.Instance.PID, Generation: old.Instance.Generation})
	s.forgetEnded(keyOf(old.Instance), old.Instance.Generation, "old snapshot", time.Time{})
	s.forgetEnded(keyOf(next.Instance), 0, "unidentified end", time.Time{})
	if len(s.Inventory()) != 1 || len(s.accepted) != 1 || len(s.namedBy) != 1 || len(notified) != 1 {
		t.Fatalf("old retirement changed successor state: inventory=%v accepted=%v provenance=%v notices=%v", s.Inventory(), s.accepted, s.namedBy, notified)
	}
	s.endedAt(Event{Namespace: next.Instance.Namespace, NamespacePID: next.Instance.PID, Generation: next.Instance.Generation})
	s.endedAt(Event{Namespace: next.Instance.Namespace, NamespacePID: next.Instance.PID, Generation: next.Instance.Generation})
	if len(s.Inventory()) != 0 || len(s.accepted) != 0 || len(s.namedBy) != 0 || len(notified) != 2 {
		t.Fatalf("own end did not retire exactly once: inventory=%v notices=%v", s.Inventory(), notified)
	}
	counts := s.EndedCounts()
	if len(counts) != 2 || counts[0].Target != "old" || counts[0].Count != 1 || counts[1].Target != "next" || counts[1].Count != 1 {
		t.Fatalf("retirement counts: %+v", counts)
	}
}

func TestDenialBelongsToItsRecordedBirth(t *testing.T) {
	one := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(100)}
	s := &Session{denied: map[instanceKey]admission.Start{keyOf(one): one.Start}}
	if !s.denies(one) {
		t.Fatal("genuinely excluded birth was admitted")
	}
	next := one
	next.Start = admission.Determinate(200)
	if s.denies(next) {
		t.Fatal("successor inherited stale denial")
	}
	s.denied[keyOf(one)] = admission.Indeterminate()
	if !s.denies(next) {
		t.Fatal("unread exclusion authorized a possible match")
	}
}

func TestRollbackRequiresItsOwnGeneration(t *testing.T) {
	current := admissionValue{Generation: 2, Birth: 100}
	supplied := admission.Instance{Start: admission.Determinate(100), Generation: 2}
	if !matchesGrant(supplied, current) {
		t.Fatal("matching rollback did not name its grant")
	}
	supplied.Generation = 1
	if matchesGrant(supplied, current) {
		t.Fatal("old generation named new grant of the same birth")
	}
	supplied.Generation = 0
	if matchesGrant(supplied, current) {
		t.Fatal("pre-admission selection named a grant")
	}
}
