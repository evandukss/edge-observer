package probe_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

func TestIndependentReservationHasOneRefundAcrossAllPaths(t *testing.T) {
	for _, path := range []held.Path{held.Unretained, held.Processed, held.Discarded, held.Cut} {
		t.Run(string(path), func(t *testing.T) {
			g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 2})
			if err != nil {
				t.Fatal(err)
			}
			first := g.Admit(probe.DeliveryTransfer, true)
			second := g.Admit(probe.DeliveryTransfer, true)
			if !first.Admitted || !second.Admitted || first.Slot == nil || second.Slot == nil || g.Snapshot().Charged != 2 {
				t.Fatal("wiring, not the property: two reservations did not reach the gate")
			}
			first.Slot.Keep()
			if !first.Slot.Kept() {
				t.Error("retained reservation does not report Keep")
			}
			var winners atomic.Int32
			var done sync.WaitGroup
			for range 8 {
				done.Go(func() {
					if first.Slot.Refund(path) {
						winners.Add(1)
					}
				})
			}
			done.Wait()
			s := g.Snapshot()
			if winners.Load() != 1 || s.Held != 1 || s.Refunded.Of(path) != 1 || s.DoubleRefunds != 7 {
				t.Errorf("one refund must win without refunding the other slot: winners=%d snapshot=%+v", winners.Load(), s)
			}
			if !second.Slot.Refund(held.Discarded) {
				t.Error("second reservation was lost or refunded by the first")
			}
			if s := g.Snapshot(); s.Held != 0 || s.Charged != 2 {
				t.Errorf("drained reservations: %+v", s)
			}
		})
	}
}

func TestIndependentRefundChurnDoesNotSpendALifetimeAllowance(t *testing.T) {
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4})
	if err != nil {
		t.Fatal(err)
	}
	first := g.Admit(probe.DeliveryTransfer, true)
	if !first.Admitted || first.Slot == nil {
		t.Fatal("wiring, not the property: first event was not reserved")
	}
	first.Slot.Refund(held.Unretained)
	for i := 1; i < 80; i++ {
		d := g.Admit(probe.DeliveryTransfer, true)
		if !d.Admitted || d.Slot == nil {
			t.Fatalf("constant live population zero refused event%d: %+v", i+1, d.State)
		}
		d.Slot.Refund(held.Unretained)
	}
	s := g.Snapshot()
	if s.Charged != 80 || s.Held != 0 || s.Refunded.Unretained != 80 || s.DoubleRefunds != 0 || s.Reason != "" {
		t.Errorf("churn retained or refused input: %+v", s)
	}
}
