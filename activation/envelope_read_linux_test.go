package activation

import (
	"errors"
	"slices"
	"testing"
)

// What Envelope does with a reading: judge it when it is complete, and name the
// condition it was reading when it is not, marked unreadable when nothing was
// read and not when what was read failed.
func TestAnEnvelopeReadingIsJudgedOrNamesTheConditionItCouldNotRead(t *testing.T) {
	reads, participants := postureReadFixture()
	complete, err := readPostureUsing(participants, reads)
	if err != nil {
		t.Fatalf("wiring, not the property: the complete fixture refused: %v", err)
	}
	if got, want := judged(complete, nil), Judge(complete); !slices.Equal(got, want) {
		t.Errorf("a complete reading judged %+v, want Judge's %+v", got, want)
	}

	for _, fault := range []struct {
		name       string
		change     func(*postureReads)
		check      Check
		unreadable bool
	}{
		{"memory.max_unavailable", func(r *postureReads) {
			number := r.number
			r.number = func(directory, name string, required bool) (uint64, error) {
				if name == "memory.max" {
					return 0, errors.New("reading unavailable")
				}
				return number(directory, name, required)
			}
		}, ExecutionMemory, true},
		{"participant_vanished", func(r *postureReads) {
			state := r.state
			r.state = func(pid int) (ParticipantState, error) {
				if pid != int(participants[0].PID) {
					return state(pid)
				}
				return ParticipantState{}, errors.New("no such process")
			}
		}, ParticipantOutsideEnvelope, true},
		{"wrong_proc_link", func(r *postureReads) {
			r.link = func(string) (string, error) { return "1", nil }
		}, PayloadMembership, false},
	} {
		t.Run(fault.name, func(t *testing.T) {
			faulty, _ := postureReadFixture()
			fault.change(&faulty)
			got := judged(readPostureUsing(participants, faulty))
			if len(got) != 1 {
				t.Fatalf("a reading that stopped gave %d judgments, want the one it stopped at: %+v", len(got), got)
			}
			if got[0].Check != fault.check || got[0].Met || got[0].Unreadable != fault.unreadable || got[0].Detail == "" {
				t.Errorf("judged %+v, want %s not met, unreadable %t, with its detail", got[0], fault.check, fault.unreadable)
			}
		})
	}
}
