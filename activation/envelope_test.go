package activation_test

import (
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/probe"
)

// envelopeReading is a supplied reading meeting every condition, so a case
// changes exactly the readings it is about.
func envelopeReading() activation.Posture {
	return activation.Posture{
		PID: 5101, StartTime: 101, Cgroup: "/observer", Domain: "domain",
		Member: true, MemoryMax: 64 << 20,
		Participants: []activation.ParticipantState{
			{PID: 5102, StartTime: 102, Cgroup: "/service"},
			{PID: 5103, StartTime: 103, Cgroup: "/observer-sibling"},
		},
	}
}

var startsOrder = []activation.Check{
	activation.PayloadMembership, activation.ExecutionMemory, activation.AnonymousSwap,
	activation.CoreDumps, activation.ParticipantOutsideEnvelope,
}

func checks(judgments []activation.Judgment) []activation.Check {
	var named []activation.Check
	for _, one := range judgments {
		named = append(named, one.Check)
	}
	return named
}

func unmet(judgments []activation.Judgment) []activation.Judgment {
	var found []activation.Judgment
	for _, one := range judgments {
		if !one.Met {
			found = append(found, one)
		}
	}
	return found
}

func TestEveryConditionStartChecksIsJudgedInStartsOrder(t *testing.T) {
	judged := activation.Judge(envelopeReading())

	if got := checks(judged); !slices.Equal(got, startsOrder) {
		t.Fatalf("judged %v, want %v", got, startsOrder)
	}
	for _, one := range judged {
		if !one.Met || one.Unreadable || one.Detail == "" {
			t.Errorf("%s on a reading meeting it: %+v", one.Check, one)
		}
	}
}

// Two conditions fail at once, and both are named: start stops at the first,
// preflight must not.
func TestEveryConditionThatFailsIsNamedAndTheOthersStillHold(t *testing.T) {
	posture := envelopeReading()
	posture.MemoryMax = math.MaxUint64
	posture.Participants[1].Cgroup = posture.Cgroup

	failing := unmet(activation.Judge(posture))

	if got := checks(failing); !slices.Equal(got, []activation.Check{activation.ExecutionMemory, activation.ParticipantOutsideEnvelope}) {
		t.Fatalf("not met: %v, want execution_memory then participant_outside_envelope: %+v", got, failing)
	}
	if failing[1].PID != 5103 {
		t.Errorf("the participant judgment names pid %d, want 5103, the one inside", failing[1].PID)
	}
}

func TestEachParticipantInsideTheEnvelopeIsJudgedApart(t *testing.T) {
	posture := envelopeReading()
	posture.Participants[0].Cgroup = posture.Cgroup + "/worker"
	posture.Participants[1].Cgroup = posture.Cgroup

	failing := unmet(activation.Judge(posture))

	var pids []int32
	for _, one := range failing {
		if one.Check != activation.ParticipantOutsideEnvelope {
			t.Errorf("%s is not met, and only the participants changed: %+v", one.Check, one)
		}
		pids = append(pids, one.PID)
	}
	if !slices.Equal(pids, []int32{5102, 5103}) {
		t.Errorf("participants named %v, want [5102 5103] in the order given", pids)
	}
}

func TestNoParticipantEvidenceIsNotMet(t *testing.T) {
	posture := envelopeReading()
	posture.Participants = nil

	failing := unmet(activation.Judge(posture))

	if got := checks(failing); !slices.Equal(got, []activation.Check{activation.ParticipantOutsideEnvelope}) {
		t.Fatalf("not met: %v, want only participant_outside_envelope", got)
	}
}

// start's check is Judge's first unmet judgment: the same condition and the
// same words, for every fault alone and for faults together. This is what
// makes preflight's answer start's.
func TestStartRefusesOnTheFirstJudgmentThatIsNotMet(t *testing.T) {
	faults := map[string]func(*activation.Posture){
		"not_member":         func(p *activation.Posture) { p.Member = false },
		"no_memory_cap":      func(p *activation.Posture) { p.MemoryMax = 0 },
		"threaded_domain":    func(p *activation.Posture) { p.Domain = "threaded" },
		"swap_permitted":     func(p *activation.Posture) { p.SwapMax = 1 },
		"swap_charged":       func(p *activation.Posture) { p.SwapCurrent = 1 },
		"dumpable":           func(p *activation.Posture) { p.Dumpable = 1 },
		"participant_inside": func(p *activation.Posture) { p.Participants[0].Cgroup = p.Cgroup },
		"no_participants":    func(p *activation.Posture) { p.Participants = nil },
		"memory_and_participant": func(p *activation.Posture) {
			p.MemoryMax = 0
			p.Participants[1].Cgroup = p.Cgroup
		},
		"swap_and_dumpable": func(p *activation.Posture) {
			p.SwapMax = 1
			p.Dumpable = 1
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			posture := envelopeReading()
			fault(&posture)
			failing := unmet(activation.Judge(posture))
			if len(failing) == 0 {
				t.Fatalf("wiring, not the property: the fault left every condition met")
			}

			gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 16})
			if err != nil {
				t.Fatal(err)
			}
			var refusal *activation.Refusal
			if !errors.As(activation.CheckPosture(gate, posture), &refusal) {
				t.Fatalf("start's check did not refuse a reading Judge finds failing: %+v", failing)
			}
			if refusal.Check != failing[0].Check || refusal.Detail != failing[0].Detail || refusal.Unreadable {
				t.Errorf("start refused %s %q, and the first judgment not met is %s %q",
					refusal.Check, refusal.Detail, failing[0].Check, failing[0].Detail)
			}
		})
	}

	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	if err := activation.CheckPosture(gate, envelopeReading()); err != nil {
		t.Errorf("start refused the reading every judgment holds: %v", err)
	}
}
