package probe_test

import (
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// The volatile intake's exhaustion is a gate source of its own: observed at
// every decision under the gate's lock with no controller running, it
// invalidates with intake_exhausted, charges no slot, requests withdrawal and
// refuses a pending release. An intake still open changes nothing.
func TestTheIntakeFillingInvalidatesTheGateUnderItsOwnReason(t *testing.T) {
	for name, decide := range map[string]func(*probe.DeliveryGate) probe.GateReason{
		"admit":     func(g *probe.DeliveryGate) probe.GateReason { return g.Admit(probe.DeliveryClose, false).State.Reason },
		"authorize": func(g *probe.DeliveryGate) probe.GateReason { return g.Authorize(settledRelease()).Reason },
		"snapshot":  func(g *probe.DeliveryGate) probe.GateReason { return g.Snapshot().Reason },
	} {
		t.Run(name, func(t *testing.T) {
			intake := make(chan struct{})
			g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4, IntakeExhausted: intake})
			if err != nil {
				t.Fatal(err)
			}
			if got := g.Admit(probe.DeliveryClose, false); !got.Admitted {
				t.Fatalf("wiring, not the property: an open intake refused the control: %+v", got)
			}
			if got := g.Authorize(settledRelease()); !got.Authorized {
				t.Fatalf("wiring, not the property: an open intake refused a settled release: %+v", got)
			}
			assertWithdrawal(t, g, false)

			close(intake)
			if reason := decide(g); reason != probe.GateIntakeExhausted {
				t.Errorf("the decision after the intake filled gives %q, want %s", reason, probe.GateIntakeExhausted)
			}
			if !probe.GateIntakeExhausted.InvalidatesCapture() {
				t.Errorf("%s is not classified as invalidating the capture", probe.GateIntakeExhausted)
			}
			assertWithdrawal(t, g, true)
			if got := g.Authorize(settledRelease()); got.Authorized || got.Reason != probe.GateIntakeExhausted {
				t.Errorf("a settled release after the intake filled reads %+v", got)
			}
			if charged := g.Snapshot().Charged; charged != 1 {
				t.Errorf("%d slots charged, want only the control's", charged)
			}
		})
	}

}
