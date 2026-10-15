package attachment

import (
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

type reportingOwner struct {
	lifecycleOwner
	pid   int32
	first probe.Blocked
}

func (o *reportingOwner) Grants() ([]probe.Grant, error) {
	return []probe.Grant{{Selection: admission.Selection{ObserverPID: o.pid}, State: probe.GrantHeld}}, nil
}
func (o *reportingOwner) Withdrawals() ([]probe.Withdrawal, error) {
	return []probe.Withdrawal{{PID: o.pid}}, nil
}
func (o *reportingOwner) EndedCounts() ([]probe.EndedCount, error) {
	return []probe.EndedCount{{Target: "target", Number: 1, Count: 2}}, nil
}
func (o *reportingOwner) Retained() ([]held.Occupancy, error) {
	return []held.Occupancy{{Store: "fixture", Held: 2, Bound: 4}}, nil
}
func (o *reportingOwner) Refusals() (map[string]int64, error) {
	return map[string]int64{"refusal": 3}, nil
}
func (o *reportingOwner) Losses() (probe.Losses, error) {
	return probe.Losses{Dropped: 2, Unmatched: 3, Descendants: 4, UnderWay: probe.UnderWay{Known: true, Threads: 1, First: &o.first}}, nil
}

func TestAggregateRetainsEveryOwnersReportedFacts(t *testing.T) {
	a, b := &reportingOwner{pid: 1, first: probe.Blocked{PID: 1}}, &reportingOwner{pid: 2, first: probe.Blocked{PID: 2}}
	g := &Group{owners: []*owner{{name: "a", live: a}, {name: "b", live: b}}}
	grants, err := g.Grants()
	if err != nil || len(grants) != 2 || grants[0].Selection.ObserverPID != 1 || grants[1].Selection.ObserverPID != 2 {
		t.Fatalf("grants: %+v %v", grants, err)
	}
	withdrawals, err := g.Withdrawals()
	if err != nil || len(withdrawals) != 2 || withdrawals[0].PID != 1 || withdrawals[1].PID != 2 {
		t.Fatalf("withdrawals: %+v %v", withdrawals, err)
	}
	ended, err := g.EndedCounts()
	if err != nil || len(ended) != 1 || ended[0].Count != 4 {
		t.Fatalf("ended counts: %+v %v", ended, err)
	}
	stores, err := g.Retained()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, store := range stores {
		if store.Store == "fixture" {
			found = true
			if store.Held != 4 || store.Bound != 8 {
				t.Fatalf("retained: %+v", store)
			}
		}
	}
	if !found {
		t.Fatal("owner stores absent")
	}
	refused, err := g.Refusals()
	if err != nil || refused["refusal"] != 6 {
		t.Fatalf("refusals: %v %v", refused, err)
	}
	losses, err := g.Losses()
	if err != nil || losses.Dropped != 4 || losses.Unmatched != 6 || losses.Descendants != 8 || !losses.UnderWay.Known || losses.UnderWay.Threads != 2 {
		t.Fatalf("losses: %+v %v", losses, err)
	}
	a.first.PID = 99
	if losses.UnderWay.First == nil || losses.UnderWay.First.PID != 1 {
		t.Fatal("owner mutated returned loss identity")
	}
}
