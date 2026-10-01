package processing

import "testing"

// The record of routed connection ids holds the ids below the highest that
// have not been routed, so it stays small however many connections a session
// completes, and never more than its bound however the ids skip.
func TestTheRecordOfRoutedIdsStaysBounded(t *testing.T) {
	t.Run("ids in order", func(t *testing.T) {
		var r router
		for id := uint64(1); id <= 100_000; id++ {
			if !r.first(id) {
				t.Fatalf("id %d was not first", id)
			}
			if r.first(id) {
				t.Fatalf("id %d was first twice", id)
			}
		}
		if len(r.gaps) > 1 {
			t.Errorf("after 100000 ids in order the record holds %d spans", len(r.gaps))
		}
	})
	t.Run("ids out of order", func(t *testing.T) {
		var r router
		for _, step := range []struct {
			id    uint64
			first bool
		}{{1, true}, {4, true}, {3, true}, {3, false}, {1, false}, {2, true}, {2, false}, {4, false}, {5, true}} {
			if got := r.first(step.id); got != step.first {
				t.Errorf("id %d: first %t, want %t", step.id, got, step.first)
			}
		}
		if len(r.gaps) > 1 {
			t.Errorf("with every id from 1 to 5 routed the record holds %d spans", len(r.gaps))
		}
	})
	t.Run("ids that skip", func(t *testing.T) {
		var r router
		for i := uint64(1); i <= 3*unroutedBound; i++ {
			if !r.first(2 * i) {
				t.Fatalf("id %d was not first", 2*i)
			}
			if len(r.gaps) > unroutedBound {
				t.Fatalf("after %d ids the record holds %d spans, over its bound %d", i, len(r.gaps), unroutedBound)
			}
		}
		if len(r.gaps) != unroutedBound {
			t.Fatalf("wiring, not the property: the record holds %d spans and never reached its bound %d", len(r.gaps), unroutedBound)
		}
		// The bound keeps the highest ids not yet routed; below them every id is
		// taken as routed, so a first entry there is late rather than held.
		if !r.first(2*3*unroutedBound - 1) {
			t.Error("the highest id skipped was not first when it came")
		}
		if r.first(3) {
			t.Error("an id below what the bound keeps was first")
		}
	})
}
