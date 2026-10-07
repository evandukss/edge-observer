package connection_test

import (
	"errors"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
)

var process = fragment.Process{PID: 1731, StartTime: 90210}

// retiredWith is a retirement record and an evidence taken before it that it
// agrees with: the sent direction placed whole, the received direction cut at
// 12 with one transfer lost. Each case changes one thing.
func retiredWith() (connection.Record, fragment.Evidence) {
	record := held()
	record.Process = process
	record.Network = connection.Netns{Device: 4, Inode: 4026531992}
	record.Opened = at.Add(-time.Second)
	record.OpenedKnown = true
	record.Fragments = connection.Counted(5)
	record.Placements = []connection.Placement{
		{Connection: record.ID, Direction: fragment.Sent, Positions: connection.PositionsEstablished,
			Lost: connection.Counted(0)},
		{Connection: record.ID, Direction: fragment.Received, Positions: connection.PositionsUnknownFrom, From: 12,
			Because: connection.ObservationLost, Lost: connection.Counted(1)},
	}
	evidence := fragment.Evidence{
		Identity: &fragment.Identity{
			Connection:    record.ID,
			Process:       process,
			Instance:      record.Instance,
			Address:       record.Handle.Address,
			Generation:    uint64(record.Handle.Generation),
			NetworkDevice: 4,
			NetworkInode:  4026531992,
			FirstSeen:     record.FirstSeen,
			Opened:        record.Opened,
		},
		Occupancy: 7,
		Origin:    fragment.OriginBirth,
		Through:   4,
		Sent:      fragment.DirectionEvidence{Limit: 30, First: 1, Numbered: 2, Resolved: 2},
		Received: fragment.DirectionEvidence{Limit: 18, Cut: true, From: 12, Lost: 1, First: 1, Numbered: 3,
			Resolved: 1},
	}
	return record, evidence
}

func TestTheControlRetirementAgreesWithItsEvidence(t *testing.T) {
	record, evidence := retiredWith()
	if err := record.Validate(); err != nil {
		t.Fatalf("the control record: %v", err)
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("the control evidence: %v", err)
	}
	if err := record.Agrees(evidence); err != nil {
		t.Fatalf("the control: %v", err)
	}
}

// The retirement record is the later word, and it may add to what an evidence
// established: more fragments, a cut at or past the evidence's limit, more
// transfers lost, a loss it can no longer count.
func TestARetirementMayAddWhatCameAfterItsEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*connection.Record, *fragment.Evidence)
	}{
		{"more fragments", func(r *connection.Record, _ *fragment.Evidence) { r.Fragments = connection.Counted(9) }},
		{"the fragments the evidence describes and no more", func(r *connection.Record, _ *fragment.Evidence) {
			r.Fragments = connection.Counted(4)
		}},
		{"a cut at the evidence's limit", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[0] = connection.Placement{Connection: r.ID, Direction: fragment.Sent,
				Positions: connection.PositionsUnknownFrom, From: 30, Because: connection.TerminalUnsettled,
				Lost: connection.Uncounted("unsettled")}
		}},
		{"more transfers lost past the cut", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[1].Lost = connection.Counted(4)
		}},
		{"a loss it can no longer count", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[1].Lost = connection.Uncounted("unsettled")
		}},
		{"a direction the evidence reached nothing in", func(r *connection.Record, e *fragment.Evidence) {
			e.Sent = fragment.DirectionEvidence{First: 1, Numbered: 1, Resolved: 1, Empties: 1}
			r.Placements = r.Placements[1:]
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record, evidence := retiredWith()
			c.change(&record, &evidence)
			if err := record.Agrees(evidence); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// A retirement that contradicts what an evidence held before it established is
// refused, each for the contradiction it is.
func TestARetirementThatContradictsItsEvidenceIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		change func(*connection.Record, *fragment.Evidence)
	}{
		{"evidence that contradicts itself", func(_ *connection.Record, e *fragment.Evidence) { e.Sent.Lost = 1 }},
		{"another connection", func(r *connection.Record, _ *fragment.Evidence) { r.ID++ }},
		{"another process", func(r *connection.Record, _ *fragment.Evidence) { r.Process.StartTime++ }},
		{"another execution", func(r *connection.Record, _ *fragment.Evidence) { r.Instance.Executable = "/bin/sh" }},
		{"another handle address", func(r *connection.Record, _ *fragment.Evidence) { r.Handle.Address++ }},
		{"another occupancy of the handle", func(r *connection.Record, _ *fragment.Evidence) { r.Handle.Generation++ }},
		{"another network namespace", func(r *connection.Record, _ *fragment.Evidence) { r.Network.Inode++ }},
		{"another first sighting", func(r *connection.Record, _ *fragment.Evidence) {
			r.FirstSeen = r.FirstSeen.Add(time.Millisecond)
		}},
		{"an open time it no longer knows", func(r *connection.Record, _ *fragment.Evidence) {
			r.Opened, r.OpenedKnown = time.Time{}, false
		}},
		{"another open time", func(r *connection.Record, _ *fragment.Evidence) {
			r.Opened = r.Opened.Add(time.Millisecond)
		}},
		{"fewer fragments than the evidence describes", func(r *connection.Record, _ *fragment.Evidence) {
			r.Fragments = connection.Counted(3)
		}},
		{"a fragment count nobody read", func(r *connection.Record, _ *fragment.Evidence) {
			r.Fragments = connection.Uncounted("unread")
		}},
		{"no placement where the evidence reached bytes", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements = r.Placements[1:]
		}},
		{"a cut below the evidence's limit", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[0] = connection.Placement{Connection: r.ID, Direction: fragment.Sent,
				Positions: connection.PositionsUnknownFrom, From: 29, Because: connection.ObservationLost,
				Lost: connection.Counted(1)}
		}},
		{"nothing placeable where the evidence established bytes", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[0] = connection.Placement{Connection: r.ID, Direction: fragment.Sent,
				Positions: connection.PositionsUnknownThroughout, Because: connection.ObservationLost,
				Lost: connection.Counted(1)}
		}},
		{"a cut moved later", func(r *connection.Record, _ *fragment.Evidence) { r.Placements[1].From = 13 }},
		{"a cut moved earlier", func(r *connection.Record, _ *fragment.Evidence) { r.Placements[1].From = 11 }},
		{"a cut withdrawn", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[1] = connection.Placement{Connection: r.ID, Direction: fragment.Received,
				Positions: connection.PositionsEstablished, Lost: connection.Counted(0)}
		}},
		{"a cut at the first byte placed later", func(r *connection.Record, e *fragment.Evidence) {
			e.Received.From = 0
		}},
		{"fewer transfers lost", func(r *connection.Record, _ *fragment.Evidence) {
			r.Placements[1].Lost = connection.Counted(0)
		}},
		{"a loss counted that the evidence could not count", func(_ *connection.Record, e *fragment.Evidence) {
			e.Received.LostUncounted = true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record, evidence := retiredWith()
			identity := *evidence.Identity
			evidence.Identity = &identity
			c.change(&record, &evidence)
			if err := record.Agrees(evidence); !errors.Is(err, connection.ErrInvalid) &&
				!errors.Is(err, fragment.ErrInvalid) {
				t.Errorf("accepted: %v", err)
			}
		})
	}
}
