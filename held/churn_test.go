package held_test

import (
	"testing"

	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/internal/mapslots"
)

// handle is a key the shape of a connection's: an execution and an address,
// each new.
type handle struct{ execution, address uint64 }

// A map whose keys never return, churned at a constant live population, keeps
// its allocation bounded by that population when its deletions go through
// Churn; the same churn without it grows the map with every key it has held.
func TestAMapOfKeysThatNeverReturnKeepsItsAllocationBoundedByItsLiveSize(t *testing.T) {
	const live, cycles = 256, 262144
	shed := make(map[handle]int, live)
	plain := make(map[handle]int, live)
	var churn held.Churn
	for i := 0; i < live; i++ {
		shed[handle{uint64(i), uint64(i) << 4}] = i
		plain[handle{uint64(i), uint64(i) << 4}] = i
	}
	most, plainMost := 0, 0
	for i := live; i < live+cycles; i++ {
		gone := handle{uint64(i - live), uint64(i-live) << 4}
		shed = held.Deleted(shed, gone, &churn)
		delete(plain, gone)
		shed[handle{uint64(i), uint64(i) << 4}] = i
		plain[handle{uint64(i), uint64(i) << 4}] = i
		if i%1024 != 0 {
			continue
		}
		slots, err := mapslots.Slots(shed)
		if err != nil {
			t.Fatal(err)
		}
		plainSlots, err := mapslots.Slots(plain)
		if err != nil {
			t.Fatal(err)
		}
		most, plainMost = max(most, slots), max(plainMost, plainSlots)
	}
	if len(shed) != live || len(plain) != live {
		t.Fatalf("wiring, not the property: the maps hold %d and %d, want the live %d", len(shed), len(plain), live)
	}
	if plainMost <= 4*live {
		t.Fatalf("wiring, not the property: the map churned without Churn reached %d slots, within %d, so "+
			"this runtime does not grow it and the bound measures nothing", plainMost, 4*live)
	}
	if most > 4*live {
		t.Errorf("the map churned through Churn reached %d slots at %d live, past %d (without it: %d)", most, live,
			4*live, plainMost)
	}
	if churn.Rebuilds() == 0 {
		t.Errorf("%d deletions at %d live copied the map no times", cycles, live)
	}
	t.Logf("%d cycles at %d live: %d slots at most with Churn, %d without, %d rebuilds", cycles, live, most,
		plainMost, churn.Rebuilds())
}

// A deletion of a key the map does not hold leaves nothing to shed, so it is
// not counted toward a copy.
func TestADeletionOfAnAbsentKeyIsNotCounted(t *testing.T) {
	m := map[int]int{1: 1}
	var churn held.Churn
	for i := 0; i < 1000; i++ {
		m = held.Deleted(m, 2+i, &churn)
	}
	if churn.Rebuilds() != 0 || len(m) != 1 {
		t.Errorf("1000 deletions of absent keys copied the map %d times and left %d entries", churn.Rebuilds(), len(m))
	}
}
