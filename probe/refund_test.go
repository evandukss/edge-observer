package probe_test

import (
	"testing"

	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

// admitted is one charged, admitted transfer's slot.
func admitted(t *testing.T, g *probe.DeliveryGate) held.Slot {
	t.Helper()
	decision := g.Admit(probe.DeliveryTransfer, true)
	if !decision.Admitted || !decision.Charged || decision.Slot == nil {
		t.Fatalf("control: a measured transfer under the allowance was not admitted with a slot: %+v", decision)
	}
	return decision.Slot
}

// Every slot is returned once, along the path it names, and the gate's reading
// keeps Charged equal to Held plus every path's refunds.
func TestEverySlotIsReturnedOnceAlongItsPath(t *testing.T) {
	g := deliveryGate(t, 8, nil)
	paths := held.Paths()
	slots := make([]held.Slot, len(paths))
	for i := range paths {
		slots[i] = admitted(t, g)
	}
	if state := g.Snapshot(); state.Held != uint64(len(paths)) || state.Charged != uint64(len(paths)) {
		t.Fatalf("wiring, not the property: %d slots taken and the gate holds %+v", len(paths), state)
	}
	for i, path := range paths {
		if !slots[i].Refund(path) {
			t.Fatalf("the first refund along %s was refused", path)
		}
	}
	state := g.Snapshot()
	if state.Held != 0 {
		t.Fatalf("%d slots still held after every one was returned: %+v", state.Held, state)
	}
	for _, path := range paths {
		if got := state.Refunded.Of(path); got != 1 {
			t.Errorf("%d slots returned along %s, want the one returned there", got, path)
		}
	}
	sum := state.Held
	for _, path := range paths {
		sum += state.Refunded.Of(path)
	}
	if sum != state.Charged {
		t.Errorf("charged %d is not held %d plus the refunds by path: %+v", state.Charged, state.Held, state)
	}
}

// A second refund of one slot returns nothing and is counted, and the slots
// still held are untouched by it.
func TestASecondRefundReturnsNothingAndIsCounted(t *testing.T) {
	g := deliveryGate(t, 4, nil)
	first, second := admitted(t, g), admitted(t, g)
	if !first.Refund(held.Processed) {
		t.Fatal("control: the first refund was refused")
	}
	if first.Refund(held.Discarded) {
		t.Error("a second refund of one slot was accepted")
	}
	state := g.Snapshot()
	if state.Held != 1 || state.DoubleRefunds != 1 {
		t.Fatalf("after one slot returned twice and one held, the gate reads %+v; want one held and one double refund", state)
	}
	if state.Refunded.Processed != 1 || state.Refunded.Discarded != 0 {
		t.Errorf("the refused second refund was counted along its path: %+v", state.Refunded)
	}
	if !second.Refund(held.Processed) || g.Snapshot().Held != 0 {
		t.Errorf("the slot still held was not returned whole after the double refund: %+v", g.Snapshot())
	}
}

// The allowance bounds slots held at once, never events admitted in total.
func TestTheAllowanceBoundsSlotsHeldNotEventsCharged(t *testing.T) {
	g := deliveryGate(t, 2, nil)
	for i := 0; i < 1000; i++ {
		admitted(t, g).Refund(held.Processed)
	}
	if state := g.Snapshot(); state.Reason != "" || state.Charged != 1000 || state.Held != 0 {
		t.Fatalf("a thousand events each returned before the next left the gate %+v; want it open with none held", state)
	}
	admitted(t, g)
	admitted(t, g)
	refused := g.Admit(probe.DeliveryTransfer, true)
	if refused.Admitted || refused.Charged || refused.Slot != nil || refused.State.Reason != probe.GateInputLimit {
		t.Fatalf("an event arriving with the allowance held was %+v; want it refused under %s with no slot",
			refused, probe.GateInputLimit)
	}
}

// A refund never clears an invalidation: the gate stays refused, and what was
// held is still returned.
func TestARefundNeverClearsAnInvalidation(t *testing.T) {
	g := deliveryGate(t, 4, nil)
	kept := admitted(t, g)
	unknown := g.Admit(probe.DeliveryTransfer, false)
	if unknown.Admitted || !unknown.Charged || unknown.State.Reason != probe.GateUnknownLength {
		t.Fatalf("control: an unmeasured transfer did not invalidate: %+v", unknown)
	}
	unknown.Slot.Refund(held.Unretained)
	kept.Refund(held.Processed)
	state := g.Snapshot()
	if state.Reason != probe.GateUnknownLength || state.Held != 0 {
		t.Fatalf("after both slots returned the gate reads %+v; want unknown_length kept and none held", state)
	}
	if decision := g.Admit(probe.DeliveryTransfer, true); decision.Admitted || decision.Charged {
		t.Errorf("an invalidated gate admitted after the refunds: %+v", decision)
	}
	if got := g.Authorize(settledRelease()); got.Authorized || got.Reason != probe.GateUnknownLength {
		t.Errorf("an invalidated gate authorized after the refunds: %+v", got)
	}
}
