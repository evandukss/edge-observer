package probe_test

import (
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

var overloadSettled = probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}

func overloadWithdrawn(g *probe.DeliveryGate) bool {
	select {
	case <-g.Withdrawal():
		return true
	default:
		return false
	}
}

// A burst over the held-event bound refuses each event that finds every slot
// held, and counts it. It requests no withdrawal: a release decided meanwhile
// is still authorized, and once a slot is returned the next event is admitted.
func TestIndependentABurstOverTheHeldEventBoundRefusesEventsAndNotTheCapture(t *testing.T) {
	const bound, burst = 3, 5
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: bound})
	if err != nil {
		t.Fatal(err)
	}
	var slots []held.Slot
	for range bound {
		d := g.Admit(probe.DeliveryTransfer, true)
		if !d.Admitted || d.Slot == nil {
			t.Fatalf("wiring, not the property: an event below the bound was not admitted: %+v", d)
		}
		d.Slot.Keep()
		slots = append(slots, d.Slot)
	}
	if s := g.Snapshot(); s.Held != bound || s.Reason != "" || overloadWithdrawn(g) {
		t.Fatalf("wiring, not the property: the gate does not hold the bound before the burst: %+v", s)
	}

	for i := range burst {
		d := g.Admit(probe.DeliveryTransfer, true)
		if d.Admitted || d.Charged || d.Slot != nil {
			t.Fatalf("burst event %d found every slot held and was admitted or charged: %+v", i, d)
		}
	}
	s := g.Snapshot()
	if s.InputRefused != burst {
		t.Errorf("%d events were refused at the bound and %d are counted", burst, s.InputRefused)
	}
	if s.Charged != bound || s.Held != bound {
		t.Errorf("refused events reserved slots: %+v", s)
	}
	if overloadWithdrawn(g) {
		t.Errorf("a burst over the held-event bound requested withdrawal of the whole capture: %+v", s)
	}
	if s.Reason.InvalidatesCapture() {
		t.Errorf("the gate holds %q, a capture-wide reason, after a burst", s.Reason)
	}
	if got := g.Authorize(overloadSettled); !got.Authorized {
		t.Errorf("a settled release after the burst was refused: %+v", got)
	}

	if !slots[0].Refund(held.Cut) {
		t.Fatal("wiring, not the property: the first slot was not returned")
	}
	if d := g.Admit(probe.DeliveryTransfer, true); !d.Admitted || d.Slot == nil {
		t.Errorf("a slot was returned and the next event was still refused: %+v", d)
	}
}

// Only unknown_length and unknown_kind end a capture. The population is read
// from the declared reasons, so a reason added later is classified here too.
func TestIndependentOnlyUnknownLengthAndUnknownKindInvalidateTheCapture(t *testing.T) {
	declared := probe.GateReasons()
	var terminal []string
	for _, r := range declared {
		if r.InvalidatesCapture() {
			terminal = append(terminal, string(r))
		}
	}
	slices.Sort(terminal)
	if len(declared) < 2 {
		t.Fatalf("wiring, not the property: %d gate reasons are declared", len(declared))
	}
	if want := []string{"unknown_kind", "unknown_length"}; !slices.Equal(terminal, want) {
		t.Errorf("the reasons that invalidate the capture are %v, want exactly %v", terminal, want)
	}
}

// The terminal reasons still end the capture, and returning every slot after
// one does not reopen it.
func TestIndependentATerminalFaultIsNotClearedByReturningSlots(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     probe.DeliveryKind
		measured bool
	}{
		{"unknown_length", probe.DeliveryTransfer, false},
		{"unknown_kind", probe.DeliveryKind(9), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4})
			if err != nil {
				t.Fatal(err)
			}
			first := g.Admit(probe.DeliveryTransfer, true)
			if !first.Admitted {
				t.Fatalf("wiring, not the property: the control event was refused: %+v", first)
			}
			fault := g.Admit(tc.kind, tc.measured)
			if !fault.Charged || fault.Slot == nil {
				t.Fatalf("wiring, not the property: the fault reserved no slot: %+v", fault)
			}
			first.Slot.Refund(held.Processed)
			fault.Slot.Refund(held.Unretained)
			if s := g.Snapshot(); string(s.Reason) != tc.name || s.Held != 0 {
				t.Errorf("after the fault and every slot returned the gate holds %+v, want reason %s", s, tc.name)
			}
			if !overloadWithdrawn(g) {
				t.Errorf("%s did not request withdrawal", tc.name)
			}
			if d := g.Admit(probe.DeliveryTransfer, true); d.Admitted {
				t.Errorf("an event was admitted after %s: %+v", tc.name, d)
			}
			if got := g.Authorize(overloadSettled); got.Authorized {
				t.Errorf("a release was authorized after %s", tc.name)
			}
		})
	}
}
