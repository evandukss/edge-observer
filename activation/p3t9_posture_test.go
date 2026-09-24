package activation_test

import (
	"errors"
	"math"
	"testing"

	"github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/probe"
)

// These are deliberately supplied readings, not evidence that Verify inspected
// a live process. The live activation fixture owns that separate claim.
func p3t9PostureReading() activation.Posture {
	return activation.Posture{
		PID: 4101, StartTime: 101, Cgroup: "/protected", Domain: "domain",
		Member: true, MemoryMax: 64 << 20, Dumpable: 0,
		Participants: []activation.ParticipantState{
			{PID: 4102, StartTime: 102, Cgroup: "/protected-peer"},
			{PID: 4103, StartTime: 103, Cgroup: "/service/worker"},
		},
	}
}

func p3t9PostureGate(t *testing.T) *probe.DeliveryGate {
	t.Helper()
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func p3t9PostureDecision(t *testing.T, g *probe.DeliveryGate, p activation.Posture, want activation.Check) {
	t.Helper()
	before := g.Snapshot()
	err := activation.CheckPosture(g, p)
	if after := g.Snapshot(); after != before {
		t.Errorf("posture checking changed the gate: before=%+v after=%+v", before, after)
	}
	if want == "" {
		if err != nil {
			t.Fatalf("compliant supplied-reading neighbor refused; live activation NOT claimed: %v", err)
		}
		return
	}
	var refusal *activation.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("reached supplied fault %s did not return its named refusal: %v", want, err)
	}
	if refusal.Check != want || refusal.PID != p.PID {
		t.Errorf("reached supplied fault %s: refusal=%+v; want check=%s payload pid=%d", want, refusal, want, p.PID)
	}
}

// Each fault changes one reading. In particular, the second participant is
// checked as well as the first; a prefix-sharing sibling remains outside.
func TestP3T9PostureEnvelopeAndParticipantDecisions(t *testing.T) {
	cases := []struct {
		name  string
		want  activation.Check
		fault func(*activation.Posture)
	}{
		{"holder_not_member", activation.PayloadMembership, func(p *activation.Posture) { p.Member = false }},
		{"no_memory_cap", activation.ExecutionMemory, func(p *activation.Posture) { p.MemoryMax = 0 }},
		{"unlimited_memory", activation.ExecutionMemory, func(p *activation.Posture) { p.MemoryMax = math.MaxUint64 }},
		{"swap_permitted", activation.AnonymousSwap, func(p *activation.Posture) { p.SwapMax = 1 }},
		{"swap_already_charged", activation.AnonymousSwap, func(p *activation.Posture) { p.SwapCurrent = 1 }},
		{"dumpable_despite_zero_core_limits", activation.CoreDumps, func(p *activation.Posture) { p.Dumpable = 1 }},
		{"second_participant_inside", activation.ParticipantOutsideEnvelope, func(p *activation.Posture) { p.Participants[1].Cgroup = p.Cgroup }},
		{"second_participant_descendant", activation.ParticipantOutsideEnvelope, func(p *activation.Posture) { p.Participants[1].Cgroup = p.Cgroup + "/child" }},
		{"no_participant_evidence", activation.ParticipantOutsideEnvelope, func(p *activation.Posture) { p.Participants = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("compliant_neighbor", func(t *testing.T) {
				p3t9PostureDecision(t, p3t9PostureGate(t), p3t9PostureReading(), "")
			})
			t.Run("reached_fault", func(t *testing.T) {
				p := p3t9PostureReading()
				tc.fault(&p)
				t.Logf("supplied_reading_fault_reached: %s posture=%+v", tc.name, p)
				p3t9PostureDecision(t, p3t9PostureGate(t), p, tc.want)
			})
		})
	}
}

func TestP3T9PostureRequiresConstructedFreshGate(t *testing.T) {
	cases := []struct {
		name string
		gate func(*testing.T) *probe.DeliveryGate
	}{
		{"missing", func(*testing.T) *probe.DeliveryGate { return nil }},
		{"zero_value", func(*testing.T) *probe.DeliveryGate { return &probe.DeliveryGate{} }},
		{"already_used", func(t *testing.T) *probe.DeliveryGate {
			g := p3t9PostureGate(t)
			d := g.Admit(probe.DeliveryTransfer, true)
			if !d.Admitted || d.State.Charged != 1 || d.State.Reason != "" {
				t.Fatalf("used-but-valid gate not reached: %+v", d)
			}
			return g
		}},
		{"invalidated", func(t *testing.T) *probe.DeliveryGate {
			g := p3t9PostureGate(t)
			d := g.Admit(probe.DeliveryTransfer, false)
			if d.Admitted || d.State.Charged != 1 || d.State.Reason != probe.GateUnknownLength {
				t.Fatalf("invalidated gate not reached: %+v", d)
			}
			return g
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("constructed_fresh_neighbor", func(t *testing.T) {
				p3t9PostureDecision(t, p3t9PostureGate(t), p3t9PostureReading(), "")
			})
			t.Run("reached_fault", func(t *testing.T) {
				g := tc.gate(t)
				t.Logf("gate_fault_reached: %s state=%+v", tc.name, g.Snapshot())
				p3t9PostureDecision(t, g, p3t9PostureReading(), activation.DeliveryGate)
			})
		})
	}
}

func TestP3T9PostureCoreDiagnosticsAreNotAcceptanceConditions(t *testing.T) {
	for _, diagnostics := range []bool{false, true} {
		name := "diagnostics_absent"
		if diagnostics {
			name = "diagnostics_present"
		}
		t.Run(name, func(t *testing.T) {
			p := p3t9PostureReading()
			if diagnostics {
				p.CoreSoft, p.CoreHard, p.CorePattern = math.MaxUint64, math.MaxUint64, "|reported-handler"
			}
			p3t9PostureDecision(t, p3t9PostureGate(t), p, "")
		})
	}
}
