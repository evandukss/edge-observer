//go:build attach

package ebpf_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
)

// The producer and reservations are real. The test deliberately consumes one
// submitted event without delivering it to capture, reproducing the accounting
// input of an abandoned event. This is not a kernel stop-race test.
func TestIndependentTailDropThenAbandon(t *testing.T) {
	for _, variant := range []string{"clean", "route_gap", "ring_gap"} {
		t.Run(variant, func(t *testing.T) {
			priorRouteGap := variant == "route_gap"
			r := proofFixture(t, map[string]uint32{"events": 32768})
			r.open(t, 0)
			r.command(t, "W 0 1")
			r.consume()
			prior := int64(0)
			if priorRouteGap {
				if got := r.command(t, "S 0"); got != "S -1" {
					t.Fatalf("UNPROVED: count-only route: %s", got)
				}
				r.command(t, "W 0 1")
				r.consume()
				prior = 1
			}
			if got := r.recording.Stats().Lost; got != prior {
				t.Fatalf("UNPROVED: pre-flood gap count=%d want%d", got, prior)
			}
			priorRing := int64(0)
			if variant == "ring_gap" {
				r.command(t, "W 0 83")
				r.consume()
				r.command(t, "W 0 1")
				r.consume()
				priorRing = r.recording.Stats().Lost
				if priorRing == 0 {
					t.Fatal("UNPROVED: prior mid-stream ring gaps=0")
				}
			}
			r.command(t, "W 0 83")
			drops := proofCounter(t, r.session.Dropped)
			if drops == 0 {
				t.Fatal("UNPROVED: reservation failures=0")
			}
			r.consume()
			midRing := r.recording.Stats().Lost - prior
			if midRing < priorRing || midRing >= drops {
				t.Fatalf("UNPROVED: priorRing=%d midRing=%d drops=%d leaves no proved tail", priorRing, midRing, drops)
			}
			r.command(t, "W 0 1")
			select {
			case e := <-r.session.Events():
				if e.Direction != fragment.Sent || e.Length != 512 {
					t.Fatalf("UNPROVED: abandoned event %+v", e)
				}
				st, err := r.session.Settled(r.identity(e))
				if err != nil {
					t.Fatal(err)
				}
				if st.Final.Sent.Dropped != uint64(drops) || st.Final.Sent.Last != e.Sequence.Number {
					t.Fatalf("UNPROVED: terminal=%+v abandoned number=%d drops=%d", st, e.Sequence.Number, drops)
				}
				t.Logf("PRECONDITIONS prior_non_ring_gap=%d prior_ring_gap=%d mid_ring_drops=%d tail_ring_drops=%d ring_drops=%d tail_abandoned=1 last=%d producer_dropped=%d", prior, priorRing, midRing, drops-midRing, drops, e.Sequence.Number, st.Final.Sent.Dropped)
			case <-time.After(time.Second):
				t.Fatal("UNPROVED: submitted event for abandonment absent")
			}
			r.finish(t)
			if got := r.recording.Stats().Lost; got != prior+drops {
				t.Errorf("COUNTEREXAMPLE: located=%d want prior_gap%d + actual_tail_drops%d; an abandoned event adds zero", got, prior, drops)
			}
			if len(r.collected.records) != 1 {
				t.Fatalf("UNPROVED: records=%d", len(r.collected.records))
			}
			for _, rec := range r.collected.records {
				p, _ := rec.Placement(fragment.Sent)
				if p.Whole() {
					t.Errorf("COUNTEREXAMPLE: dropped/abandoned tail whole")
				}
			}
		})
	}
}
