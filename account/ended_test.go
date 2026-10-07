package account_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
)

// An admission established as ended is counted under its target and listed
// nowhere; one whose grant is gone while its execution may run is still
// listed, and counted beside the ended ones.
func TestAnEndedAdmissionIsCountedUnderItsTargetAndNotListed(t *testing.T) {
	running := probe.Grant{State: probe.GrantAbsent, Read: time.Unix(1, 0), Selection: admission.Selection{
		ObserverPID: 7, Provenance: admission.Provenance{Target: "web", Number: 1},
		Instance: admission.Instance{PID: 7, Generation: 3}}}
	held := probe.Grant{State: probe.GrantHeld, Read: time.Unix(1, 0), Selection: admission.Selection{
		ObserverPID: 8, Provenance: admission.Provenance{Target: "web", Number: 1},
		Instance: admission.Instance{PID: 8, Generation: 4}}}
	var a account.Account
	a.Ran(time.Unix(2, 0), account.Run{Grants: []probe.Grant{running, held},
		Ended: []probe.EndedCount{{Target: "web", Number: 1, Count: 40}, {Number: 2, Count: 3}}})
	if a.Admissions == nil {
		t.Fatal("wiring, not the property: no admissions were derived")
	}
	by := map[string]account.TargetCoverage{}
	for _, one := range a.Admissions.ByTarget {
		by[one.Target] = one
	}
	if got := by["web"]; got.Ended != 41 || got.Covered != 1 {
		t.Errorf("web's coverage is %+v; want one covered and 41 ended, the 40 let go of and the one still listed", got)
	}
	if got := by["target 2"]; got.Ended != 3 {
		t.Errorf("an unnamed target's ended admissions are %+v; want 3 under \"target 2\"", got)
	}
	if len(a.Admissions.CoverageEnded) != 1 || a.Admissions.CoverageEnded[0].Instance.PID != 7 {
		t.Errorf("coverage_ended lists %+v; want only the admission still listed", a.Admissions.CoverageEnded)
	}
}
