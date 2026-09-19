package ebpf

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// The population is declared by the test: four recorded admissions, one still
// held and three gone, never read back from the subject.
func recordedFour() []admission.Selection {
	namespace := admission.Namespace{Device: 4, Inode: 4026531836}
	one := func(pid int32, generation admission.Generation) admission.Selection {
		return admission.Selection{
			Instance:    admission.Instance{Namespace: namespace, PID: pid, Generation: generation},
			Kind:        admission.ByTarget,
			Provenance:  admission.Provenance{Target: "gateway", Number: 1},
			Mode:        admission.ModeFollow,
			ObserverPID: pid,
		}
	}
	return []admission.Selection{one(101, 1), one(102, 2), one(103, 3), one(104, 4)}
}

// Each recorded admission is answered once under its identity. A held grant
// needs no reading; each gone one is read once and carries that reading's
// interval.
func TestEveryRecordedAdmissionIsAnsweredOnceByTheStateOfItsGrant(t *testing.T) {
	recorded := recordedFour()
	held := map[instanceKey]admission.Generation{keyOf(recorded[0].Instance): recorded[0].Instance.Generation}
	at := time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)
	interval := process.Interval{From: at.Add(time.Millisecond), To: at.Add(2 * time.Millisecond)}

	read := make(map[int32]int)
	grants := grantsOf(recorded, held, nil, at, func(one admission.Selection) process.Execution {
		read[one.ObserverPID]++
		return process.Execution{Observed: interval}
	})

	if len(grants) != len(recorded) {
		t.Fatalf("%d grants for %d recorded admissions", len(grants), len(recorded))
	}
	want := map[int32]probe.GrantState{101: probe.GrantHeld, 102: probe.GrantAbsent, 103: probe.GrantAbsent, 104: probe.GrantAbsent}
	seen := make(map[int32]int)
	for _, grant := range grants {
		pid := grant.Selection.ObserverPID
		seen[pid]++
		if grant.Selection.Instance.Key() != recorded[pid-101].Instance.Key() {
			t.Errorf("pid %d is answered under %v, recorded under %v", pid, grant.Selection.Instance.Key(),
				recorded[pid-101].Instance.Key())
		}
		if grant.State != want[pid] {
			t.Errorf("pid %d's grant is %s, want %s", pid, grant.State, want[pid])
		}
		if !grant.Read.Equal(at) {
			t.Errorf("pid %d's grant was read at %s, want the reading's own time %s", pid, grant.Read, at)
		}
		if grant.State == probe.GrantAbsent && grant.Evidence != interval {
			t.Errorf("pid %d's absent grant carries %v, want the interval its execution was read in", pid, grant.Evidence)
		}
	}
	for pid := range want {
		if seen[pid] != 1 {
			t.Errorf("pid %d is answered %d times, want once", pid, seen[pid])
		}
	}
	if read[101] != 0 || read[102] != 1 || read[103] != 1 || read[104] != 1 {
		t.Errorf("executions read %v, want each absent grant's once and the held one's never", read)
	}
}

// A key held by a successor (the pid reused and admitted again under its own
// generation) is not the recorded admission's grant.
func TestAKeyHeldUnderAnotherGenerationIsNotTheRecordedAdmissionsGrant(t *testing.T) {
	recorded := recordedFour()[:1]
	successor := map[instanceKey]admission.Generation{keyOf(recorded[0].Instance): recorded[0].Instance.Generation + 100}
	at := time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)

	grants := grantsOf(recorded, successor, nil, at, func(admission.Selection) process.Execution {
		return process.Execution{}
	})
	if len(grants) != 1 || grants[0].State != probe.GrantAbsent {
		t.Fatalf("a key held under generation %d answers the admission recorded under %d as %v, want absent",
			recorded[0].Instance.Generation+100, recorded[0].Instance.Generation, grants)
	}

	unstamped := recordedFour()[:1]
	unstamped[0].Instance.Generation = 0
	grants = grantsOf(unstamped, successor, nil, at, func(admission.Selection) process.Execution {
		return process.Execution{}
	})
	if len(grants) != 1 || grants[0].State != probe.GrantUnknown {
		t.Fatalf("an admission recorded with no generation, under a held key, answers %v, want unknown", grants)
	}
}

// An unreadable allowlist leaves every grant unknown with the reason, none
// absent.
func TestAnAllowlistThatCouldNotBeReadLeavesEveryGrantUnknownRatherThanAbsent(t *testing.T) {
	recorded := recordedFour()
	at := time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)

	read := 0
	grants := grantsOf(recorded, nil, errors.New("the iterator failed"), at, func(admission.Selection) process.Execution {
		read++
		return process.Execution{}
	})

	if len(grants) != len(recorded) {
		t.Fatalf("%d grants for %d recorded admissions, so a failed read dropped some", len(grants), len(recorded))
	}
	for _, grant := range grants {
		if grant.State != probe.GrantUnknown {
			t.Errorf("pid %d's grant is %s after a failed read, want unknown", grant.Selection.ObserverPID, grant.State)
		}
		if !strings.Contains(grant.Why, "the iterator failed") {
			t.Errorf("pid %d's unknown grant says %q, want the read's own error", grant.Selection.ObserverPID, grant.Why)
		}
	}
	if read != 0 {
		t.Errorf("%d executions were read after the allowlist could not be, and no grant was established absent", read)
	}
}
