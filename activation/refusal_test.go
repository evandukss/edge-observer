package activation

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

func TestRefusalReportsUnreadabilityWithoutLosingTheCheck(t *testing.T) {
	for _, check := range []Check{ExecutionMemory, AnonymousSwap, CoreDumps, PayloadMembership, ParticipantOutsideEnvelope} {
		t.Run(string(check), func(t *testing.T) {
			refusal := &Refusal{Check: check, PID: 123, Detail: "kernel reading unavailable", Unreadable: true}
			message := refusal.Error()
			for _, want := range []string{string(PostureUnreadable), string(check), "123", refusal.Detail} {
				if !strings.Contains(message, want) {
					t.Errorf("unreadable refusal lost %q: %s", want, message)
				}
			}
			refusal.Unreadable = false
			if strings.Contains(refusal.Error(), string(PostureUnreadable)) || refusal.Error() == message {
				t.Errorf("observed failure and unavailable reading have the same classification: %s", refusal.Error())
			}
		})
	}
}

func TestCompletedPostureFailuresAreNotUnreadable(t *testing.T) {
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	valid := Posture{PID: 123, StartTime: 1, Cgroup: "/payload", Domain: "domain", Member: true, MemoryMax: 1 << 30,
		Participants: []ParticipantState{{PID: 456, StartTime: 2, Cgroup: "/participant"}}}
	if err := CheckPosture(gate, valid); err != nil {
		t.Fatalf("complete compliant control refused: %v", err)
	}
	for _, test := range []struct {
		check Check
		alter func(*Posture)
	}{
		{ExecutionMemory, func(p *Posture) { p.MemoryMax = math.MaxUint64 }},
		{AnonymousSwap, func(p *Posture) { p.SwapCurrent = 1 }},
		{CoreDumps, func(p *Posture) { p.Dumpable = 1 }},
		{PayloadMembership, func(p *Posture) { p.Member = false }},
		{ParticipantOutsideEnvelope, func(p *Posture) { p.Participants = nil }},
	} {
		t.Run(string(test.check), func(t *testing.T) {
			posture := valid
			test.alter(&posture)
			var refusal *Refusal
			if err := CheckPosture(gate, posture); !errors.As(err, &refusal) {
				t.Fatalf("observed violation did not refuse: %v", err)
			}
			if refusal.Check != test.check || refusal.Unreadable || strings.Contains(refusal.Error(), string(PostureUnreadable)) {
				t.Fatalf("observed violation misclassified: %+v", refusal)
			}
		})
	}
}
