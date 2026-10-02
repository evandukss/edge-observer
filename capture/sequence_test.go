package capture_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// numberedAs is a transfer carrying its place in an occupancy, as the program
// numbers it.
func numberedAs(p fragment.Process, endpoint uint64, direction fragment.Direction, length uint32,
	occupancy, number uint64) probe.Transfer {
	one := transfer(p, endpoint, direction, length)
	one.Sequence = probe.Sequence{Occupancy: occupancy, Number: number, Born: true}
	return one
}

// placementOf is one direction's placement of the record with id, failing the
// case where there is none: a missing placement measured nothing.
func placementOf(t *testing.T, records []connection.Record, id fragment.ConnectionID,
	direction fragment.Direction) connection.Placement {
	t.Helper()
	for _, record := range records {
		if record.ID != id {
			continue
		}
		held, found := record.Placement(direction)
		if !found {
			t.Fatalf("wiring, not the property: connection %d carries no %s placement, so nothing below "+
				"measured its positions", id, direction)
		}
		return held
	}
	t.Fatalf("wiring, not the property: no record for connection %d", id)
	return connection.Placement{}
}

// A number missing from one connection's sequence cuts that direction alone,
// where the missing bytes would have begun, and counts the loss there. Nothing
// is asked of a loss counter: the number says it, so no reading of one can
// excuse it. The controls: the connection's other direction, and another
// connection live across the loss, stay established.
func TestANumberMissingFromAConnectionCutsThatDirectionAloneWhereTheMissingBytesBegan(t *testing.T) {
	sink := &collected{}
	s := produced(sink, nil)

	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	s.Transfer(numberedAs(worker, 0x18, fragment.Received, 4, 7, 1))
	s.Transfer(numberedAs(worker, 0x20, fragment.Sent, 5, 8, 1))
	// Number two of the first connection's sent direction was produced and never
	// delivered; three arrives contiguous by offset, which is the whole defect a
	// count of arrivals cannot see.
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 7, 7, 3))
	s.Transfer(numberedAs(worker, 0x20, fragment.Sent, 5, 8, 2))

	if got := s.Stats().Lost; got != 1 {
		t.Fatalf("wiring, not the property: %d transfers counted lost, and the one missing number "+
			"never reached the subject", got)
	}
	records := finished(s)
	if len(records) != 2 {
		t.Fatalf("%d connection records, want the two connections", len(records))
	}

	cut := placementOf(t, records, 1, fragment.Sent)
	if cut.Positions != connection.PositionsUnknownFrom || cut.From != 10 {
		t.Errorf("the direction that lost a transfer is %s from %d, want unknown from 10, where the "+
			"missing bytes began", cut.Positions, cut.From)
	}
	if cut.Because != connection.ObservationLost {
		t.Errorf("it says its positions went because %s", cut.Because)
	}
	if !cut.Lost.Known || cut.Lost.Value != 1 {
		t.Errorf("it counts %v transfers lost, and exactly one was", cut.Lost)
	}
	if held := placementOf(t, records, 1, fragment.Received); !held.Whole() {
		t.Errorf("the other direction of the connection is %s, and it lost nothing", held)
	}
	if held := placementOf(t, records, 2, fragment.Sent); !held.Whole() {
		t.Errorf("a connection live across the loss is %s, and the loss was not its own", held)
	}
	if got := sink.records[3].Produced; got != 3 {
		t.Errorf("the fragment after the hole carries producer number %d, want 3", got)
	}
}

// The late half of a race: two connections' transfers arriving in the other
// order from their session-wide stamps. Each connection's own sequence is
// whole, so neither loses anything; the stamps order nothing per connection.
func TestTwoConnectionsArrivingOutOfStampOrderCostNeitherAnything(t *testing.T) {
	s := produced(&collected{}, nil)

	for _, one := range []struct {
		endpoint, occupancy, number, stamp uint64
	}{{0x18, 7, 1, 2}, {0x20, 8, 1, 1}, {0x18, 7, 2, 4}, {0x20, 8, 2, 3}} {
		next := numberedAs(worker, one.endpoint, fragment.Sent, 10, one.occupancy, one.number)
		next.Stamp = one.stamp
		s.Transfer(next)
	}

	stats := s.Stats()
	if stats.Records != 4 || stats.Connections != 2 {
		t.Fatalf("wiring, not the property: %d records over %d connections, want 4 over 2",
			stats.Records, stats.Connections)
	}
	records := finished(s)
	for _, id := range []fragment.ConnectionID{1, 2} {
		if held := placementOf(t, records, id, fragment.Sent); !held.Whole() {
			t.Errorf("connection %d is %s after arriving behind the other's stamp", id, held)
		}
	}
	if s.Stats().Lost != 0 || s.Stats().Cut != 0 {
		t.Errorf("%d lost and %d cut, and nothing was lost", s.Stats().Lost, s.Stats().Cut)
	}
}

// A direction whose first transfer was lost arrives at number two. Its first
// observed byte is not its first byte, so no offset is established: a lost
// first transfer never makes number two the origin. The control: the other
// direction, arriving at number one.
func TestALostFirstTransferEstablishesNoOffsetInItsDirection(t *testing.T) {
	s := produced(&collected{}, nil)

	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 2))
	s.Transfer(numberedAs(worker, 0x18, fragment.Received, 4, 7, 1))

	records := finished(s)
	held := placementOf(t, records, 1, fragment.Sent)
	if held.Positions != connection.PositionsUnknownThroughout {
		t.Errorf("a direction whose first transfer was lost is %s, want unknown throughout", held.Positions)
	}
	if !held.Lost.Known || held.Lost.Value != 1 {
		t.Errorf("it counts %v transfers lost, and one was", held.Lost)
	}
	if control := placementOf(t, records, 1, fragment.Received); !control.Whole() {
		t.Errorf("the direction that arrived at number one is %s", control)
	}
}

// A lost last transfer has no later number to show it; the ending's last
// numbers do. The control: the same ending with the numbers that arrived.
func TestALostLastTransferBeforeTheEndingLeavesTheTailIncomplete(t *testing.T) {
	for name, last := range map[string]uint64{"the last transfer lost": 3, "the control": 2} {
		t.Run(name, func(t *testing.T) {
			s := capture.Recording(&collected{}, nil)
			s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 6, 7, 2))
			ended := ending(worker, 0x18)
			ended.Sequence = probe.Sequence{Occupancy: 7, Born: true}
			ended.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: last}}
			s.Closed(ended)

			if got := s.Stats().Closed; got != 1 {
				t.Fatalf("wiring, not the property: %d endings matched a connection, so no tail was settled", got)
			}
			held := placementOf(t, s.Records(), 1, fragment.Sent)
			if last == 2 {
				if !held.Whole() {
					t.Errorf("a tail whose last number arrived is %s", held)
				}
				return
			}
			if held.Positions != connection.PositionsUnknownFrom || held.From != 16 {
				t.Errorf("a direction whose last transfer was lost is %s from %d, want unknown from 16",
					held.Positions, held.From)
			}
			if !held.Lost.Known || held.Lost.Value != 1 {
				t.Errorf("it counts %v transfers lost, and the last one was", held.Lost)
			}
		})
	}
}

// settler is a producer's answer once production stopped, as a case sets it.
type settler struct {
	held      probe.Settlement
	err       error
	unlocated uint64
}

func (s settler) Settled(probe.Handle) (probe.Settlement, error) { return s.held, s.err }
func (s settler) Unlocated() (uint64, error)                     { return s.unlocated, nil }

// A connection still open when production stops is settled against what its
// producer holds: settled where the producer's last numbers are the ones that
// arrived, cut where they are past them, and explicitly unsettled where nothing
// can say.
func TestAConnectionOpenWhenProductionStopsIsSettledByWhatTheProducerHolds(t *testing.T) {
	whole := probe.Final{Known: true, Sent: probe.Terminal{Last: 2}}
	for name, one := range map[string]struct {
		settlers []probe.Settler
		want     connection.Positions
		because  connection.Reason
		lost     int64
	}{
		"the producer holds what arrived": {settlers: []probe.Settler{settler{held: probe.Settlement{Occupancy: 7, Final: whole}}},
			want: connection.PositionsEstablished},
		// Two transfers delivered (numbered 2) and a third in flight: entry numbering
		// makes the terminal 3 with InFlight. That one number is the in-flight call,
		// not a lost transfer, so the prefix stays established.
		"a call in flight when production stopped": {settlers: []probe.Settler{settler{held: probe.Settlement{Occupancy: 7,
			Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 3, InFlight: true}}}}},
			want: connection.PositionsEstablished},
		// An open connection at session end whose producer numbered a transfer that
		// never arrived: an undelivered tail, unsettled and uncounted (decision 475),
		// not a located loss.
		"the producer took a number that never arrived": {settlers: []probe.Settler{settler{held: probe.Settlement{Occupancy: 7,
			Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 3}}}}},
			want: connection.PositionsUnknownFrom, because: connection.TerminalUnsettled, lost: -1},
		"no producer to ask": {want: connection.PositionsUnknownFrom, because: connection.TerminalUnsettled, lost: -1},
		"a producer that cannot be read": {settlers: []probe.Settler{settler{err: errors.New("unreadable")}},
			want: connection.PositionsUnknownFrom, because: connection.TerminalUnsettled, lost: -1},
		"a producer holding nothing for the handle": {settlers: []probe.Settler{settler{}},
			want: connection.PositionsUnknownFrom, because: connection.TerminalUnsettled, lost: -1},
		"a producer holding another occupancy there": {settlers: []probe.Settler{settler{held: probe.Settlement{Occupancy: 9, Final: whole}}},
			want: connection.PositionsUnknownFrom, because: connection.TerminalUnsettled, lost: -1},
		"a loss the producer placed nowhere since": {settlers: []probe.Settler{settler{held: probe.Settlement{Occupancy: 7, Final: whole}, unlocated: 1}},
			want: connection.PositionsUnknownFrom, because: connection.ObservationLost, lost: -1},
	} {
		t.Run(name, func(t *testing.T) {
			options := make([]capture.Option, 0, len(one.settlers))
			for _, each := range one.settlers {
				options = append(options, capture.Settles(each))
			}
			s := capture.Recording(&collected{}, nil, options...)
			s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 6, 7, 2))
			s.Finish(at)

			records := s.Records()
			if len(records) != 1 || records[0].How != connection.StillOpen {
				t.Fatalf("wiring, not the property: %d records, want the one connection still open", len(records))
			}
			held := placementOf(t, records, 1, fragment.Sent)
			if held.Positions != one.want {
				t.Fatalf("the tail is %s, want %s", held, one.want)
			}
			if one.want == connection.PositionsEstablished {
				return
			}
			if held.From != 16 || held.Because != one.because {
				t.Errorf("the tail is cut at %d because %s, want 16 because %s", held.From, held.Because, one.because)
			}
			if one.lost < 0 && held.Lost.Known {
				t.Errorf("an unsettled tail counts %d transfers lost, and how many is unknown", held.Lost.Value)
			}
			if one.lost >= 0 && (!held.Lost.Known || held.Lost.Value != one.lost) {
				t.Errorf("the tail counts %v transfers lost, want %d", held.Lost, one.lost)
			}
		})
	}
}

// An open connection's undelivered tail counts exactly the producer's refused
// ring reservations (decision 476) and nothing else. A drop is counted even
// where it sits below a later event the producer submitted and the stop
// abandoned - the case the "highest submitted number" form misses; an abandoned
// tail with no drop is not counted.
func TestAnOpenTailCountsItsDroppedReservationsAndNotItsAbandonedEvents(t *testing.T) {
	// drop is what a producer holds for an open connection: its last number taken,
	// and how many of that direction's reservations the ring refused.
	drop := func(last, dropped uint64) probe.Final {
		return probe.Final{Known: true, Sent: probe.Terminal{Last: last, Dropped: dropped}}
	}
	for name, one := range map[string]struct {
		deliver int // transfers delivered before the stop, of 10 then 6 bytes
		final   probe.Final
		from    uint64
		because connection.Reason
		lost    int64 // the located loss, -1 for an unsettled tail that counts none
	}{
		// Two delivered (numbers 1, 2); number 3's reservation was refused. The drop is
		// the tail's located loss.
		"a refused reservation in the tail": {deliver: 2, final: drop(3, 1),
			from: 16, because: connection.ObservationLost, lost: 1},
		// One delivered (number 1); number 2's reservation was refused and number 3 was
		// submitted but the stop abandoned it. Counting the producer's drops, not the
		// shortfall and not the highest submitted number, counts the drop and leaves the
		// abandoned event inside the cut, uncounted.
		"a drop below a submitted-but-abandoned event": {deliver: 1, final: drop(3, 1),
			from: 10, because: connection.ObservationLost, lost: 1},
		// Two delivered; number 3 was submitted and not drained. No reservation was
		// refused, so the tail is incomplete, not a located loss.
		"an abandoned tail with no drop": {deliver: 2, final: drop(3, 0),
			from: 16, because: connection.TerminalUnsettled, lost: -1},
	} {
		t.Run(name, func(t *testing.T) {
			s := capture.Recording(&collected{}, nil,
				capture.Settles(settler{held: probe.Settlement{Occupancy: 7, Final: one.final}}))
			lengths := []uint32{10, 6}
			for i := 0; i < one.deliver; i++ {
				s.Transfer(numberedAs(worker, 0x18, fragment.Sent, lengths[i], 7, uint64(i+1)))
			}
			s.Finish(at)

			held := placementOf(t, s.Records(), 1, fragment.Sent)
			if held.Positions != connection.PositionsUnknownFrom || held.From != one.from ||
				held.Because != one.because {
				t.Fatalf("the tail is %s, want unknown from %d because %s", held, one.from, one.because)
			}
			if one.lost < 0 && held.Lost.Known {
				t.Errorf("an abandoned tail counts %v lost, and a drop is what the tail counts", held.Lost)
			}
			if one.lost >= 0 && (!held.Lost.Known || held.Lost.Value != one.lost) {
				t.Errorf("the tail counts %v lost, want %d", held.Lost, one.lost)
			}
			wantStats := one.lost
			if wantStats < 0 {
				wantStats = 0
			}
			if got := s.Stats().Lost; got != wantStats {
				t.Errorf("the session counts %d lost, want %d", got, wantStats)
			}
		})
	}
}

// A drop already located mid-stream, where a later number was delivered, is not
// counted a second time when the tail is settled: the tail counts the dropped
// total less what number() already located for the direction.
func TestADropLocatedMidStreamIsNotCountedAgainAtTheTail(t *testing.T) {
	s := capture.Recording(&collected{}, nil, capture.Settles(settler{held: probe.Settlement{Occupancy: 7,
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 6, Dropped: 3}}}}))
	// Numbers 1 and 4 arrive; numbers 2 and 3 were refused and are located
	// mid-stream by number 4. One more reservation was refused at the tail (number
	// 5), and number 6 was submitted and abandoned.
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 6, 7, 4))
	s.Finish(at)

	// Three reservations were refused in all: two located mid-stream, one at the
	// tail. Counting each once is three, not the four a tail that re-counted the two
	// mid-stream drops against the shortfall would report.
	if got := s.Stats().Lost; got != 3 {
		t.Errorf("the session counts %d lost over two mid-stream drops and one tail drop, want 3", got)
	}
}

// A handle reused after an ending nobody delivered: the producer's next
// occupancy there is a different number, which retires the old connection
// with both tails unsettled and begins a new one. The ending of a later
// occupancy whose every transfer was lost does the same.
func TestAHandleReusedAfterALostEndingRetiresTheOldConnection(t *testing.T) {
	t.Run("a transfer of the next occupancy", func(t *testing.T) {
		s := capture.Recording(&collected{}, nil)
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 5, 8, 1))

		if got := s.Stats().Retired; got != 1 {
			t.Fatalf("wiring, not the property: %d connections retired, and the next occupancy should "+
				"have retired one", got)
		}
		records := s.Records()
		if len(records) != 1 || records[0].How != connection.EndingUnobserved {
			t.Fatalf("%d records, the first ending %v, want the old connection retired as unobserved", len(records),
				records)
		}
		sent := placementOf(t, records, 1, fragment.Sent)
		if sent.Positions != connection.PositionsUnknownFrom || sent.From != 10 ||
			sent.Because != connection.TerminalUnsettled {
			t.Errorf("the retired connection's sent tail is %s", sent)
		}
		received := placementOf(t, records, 1, fragment.Received)
		if received.Positions != connection.PositionsUnknownThroughout {
			t.Errorf("the retired connection's received direction, of which nothing arrived and nothing "+
				"settled whether anything was sent, is %s", received)
		}
		if s.Open() != 1 {
			t.Errorf("%d connections open, want the new occupancy's", s.Open())
		}
	})
	t.Run("the ending of the next occupancy", func(t *testing.T) {
		s := capture.Recording(&collected{}, nil)
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
		later := ending(worker, 0x18)
		later.Sequence = probe.Sequence{Occupancy: 8, Born: true}
		later.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: 2}}
		s.Closed(later)

		if got := s.Stats().Retired; got != 1 {
			t.Fatalf("%d connections retired by a later occupancy's ending, want 1", got)
		}
		if got := s.Stats().EndingsUnmatched; got != 1 {
			t.Errorf("the later occupancy's ending, whose connection nothing followed, was counted "+
				"unmatched %d times", got)
		}
		if got := s.Records()[0].How; got != connection.EndingUnobserved {
			t.Errorf("the old connection ended %s, and its own ending was never delivered", got)
		}
	})
}

// A transfer the producer kept no sequence for: whether anything is missing
// around it cannot be checked, so its direction stops where it stood. A
// connection that begins that way establishes nothing.
func TestATransferWithNoSequenceCostsItsDirectionFromWhereItStood(t *testing.T) {
	s := produced(&collected{}, nil)
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	s.Session.Transfer(transfer(worker, 0x18, fragment.Sent, 5))
	s.Session.Transfer(transfer(worker, 0x20, fragment.Sent, 5))

	if got := s.Stats().Unsequenced; got != 2 {
		t.Fatalf("wiring, not the property: %d transfers counted unsequenced, want 2", got)
	}
	records := finished(s)
	held := placementOf(t, records, 1, fragment.Sent)
	if held.Positions != connection.PositionsUnknownFrom || held.From != 10 ||
		held.Because != connection.SequenceUnavailable {
		t.Errorf("a direction carrying an unsequenced transfer is %s", held)
	}
	begun := placementOf(t, records, 2, fragment.Sent)
	if begun.Positions != connection.PositionsUnknownThroughout || begun.Because != connection.SequenceUnavailable {
		t.Errorf("a connection begun by an unsequenced transfer is %s", begun)
	}
}

// Two calls in one direction overlapping on a handle, which OpenSSL's supported
// use forbids, leave the order of their bytes unestablished: the producer's
// mark, and a number arriving behind one already seen, both stop the direction.
func TestOverlappingCallsInOneDirectionAreRefused(t *testing.T) {
	t.Run("the producer's mark", func(t *testing.T) {
		s := produced(&collected{}, nil)
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
		marked := numberedAs(worker, 0x18, fragment.Sent, 5, 7, 2)
		marked.Sequence.Overlapped = true
		s.Transfer(marked)

		held := placementOf(t, finished(s), 1, fragment.Sent)
		if held.Positions != connection.PositionsUnknownFrom || held.From != 10 ||
			held.Because != connection.OperationsOverlapped {
			t.Errorf("a direction the producer saw two calls overlap in is %s", held)
		}
	})
	t.Run("a number behind one already seen", func(t *testing.T) {
		s := produced(&collected{}, nil)
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 5, 7, 2))
		s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 5, 7, 2))

		held := placementOf(t, finished(s), 1, fragment.Sent)
		if held.Positions != connection.PositionsUnknownFrom || held.From != 15 ||
			held.Because != connection.OperationsOverlapped {
			t.Errorf("a direction a number arrived behind in is %s", held)
		}
	})
}

// A loss the producer could place in no occupancy may have been any live
// connection's: every connection live across it stops where it stood at its
// last observation before, and every one begun after it establishes nothing.
// The control: a connection that ended before it keeps every offset.
func TestALossNoOccupancyTookCostsEveryConnectionLiveAcrossItAndEveryOneBegunAfter(t *testing.T) {
	s := produced(&collected{}, nil)

	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	s.Transfer(numberedAs(worker, 0x30, fragment.Sent, 10, 9, 1))
	s.Closed(ending(worker, 0x30))

	after := numberedAs(worker, 0x18, fragment.Sent, 5, 7, 2)
	after.Sequence.Unlocated = 1
	s.Transfer(after)
	begun := numberedAs(worker, 0x20, fragment.Sent, 5, 8, 1)
	begun.Sequence.Unlocated = 1
	s.Transfer(begun)

	if got := s.Stats().Unlocated; got != 1 {
		t.Fatalf("wiring, not the property: the session carries %d unlocated losses, want the one", got)
	}
	records := finished(s)
	live := placementOf(t, records, 1, fragment.Sent)
	if live.Positions != connection.PositionsUnknownFrom || live.From != 10 ||
		live.Because != connection.ObservationLost || live.Lost.Known {
		t.Errorf("a connection live across a loss nothing located is %s", live)
	}
	if ended := placementOf(t, records, 2, fragment.Sent); !ended.Whole() {
		t.Errorf("a connection that ended before the loss is %s", ended)
	}
	if after := placementOf(t, records, 3, fragment.Sent); after.Positions != connection.PositionsUnknownThroughout {
		t.Errorf("a connection begun after the loss is %s", after)
	}
}

// A transfer whose length nothing measured moved bytes nothing can place, so
// its direction stops where it stood. One that carries its occupancy and no
// number moved nothing, and changes nothing: the control.
func TestAnUnmeasuredTransferCutsItsDirectionAndOneThatMovedNothingDoesNot(t *testing.T) {
	s := produced(&collected{}, nil)
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	nothing := numberedAs(worker, 0x18, fragment.Sent, 0, 7, 0)
	nothing.Measured = false
	s.Transfer(nothing)
	s.Transfer(numberedAs(worker, 0x20, fragment.Sent, 10, 8, 1))
	unmeasured := numberedAs(worker, 0x20, fragment.Sent, 0, 8, 2)
	unmeasured.Measured = false
	s.Transfer(unmeasured)

	if got := s.Stats().Unmeasured; got != 2 {
		t.Fatalf("wiring, not the property: %d transfers counted unmeasured, want both", got)
	}
	records := finished(s)
	if control := placementOf(t, records, 1, fragment.Sent); !control.Whole() {
		t.Errorf("a call that moved nothing cost its direction: %s", control)
	}
	held := placementOf(t, records, 2, fragment.Sent)
	if held.Positions != connection.PositionsUnknownFrom || held.From != 10 ||
		held.Because != connection.LengthUnmeasured {
		t.Errorf("a direction holding an unmeasured transfer is %s", held)
	}
}

// A transfer the delivery gate refused takes its number as seen and grows
// nothing else: it is never counted as a transfer lost, and a refused transfer
// of a handle nothing follows begins no connection. The control: the same run
// with the refused number never handed over, which counts it lost.
func TestARefusedTransferIsNeverCountedAsALoss(t *testing.T) {
	for name, handed := range map[string]bool{"the refusal handed over": true, "the control": false} {
		t.Run(name, func(t *testing.T) {
			s := produced(&collected{}, nil)
			s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			refused := numberedAs(worker, 0x18, fragment.Sent, 6, 7, 2)
			unfollowed := numberedAs(worker, 0x20, fragment.Sent, 6, 8, 1)
			before := s.Stats()
			if handed {
				s.Refused(refused)
				s.Refused(unfollowed)
				if after := s.Stats(); after != before {
					t.Errorf("a refusal changed capture's counts: %+v, then %+v", before, after)
				}
			}
			s.numbers[numbered{handle: handleOf(refused), direction: fragment.Sent}] = 2
			s.Finish(at)

			// A refusal is never a located loss, handed or not: the count is zero in
			// both. What the handed refusal changes is that it SUPPLIES the number, so
			// the direction settles whole; without it the undelivered tail is unsettled.
			// That placement difference is the wiring guard the count no longer gives.
			if lost := s.Stats().Lost; lost != 0 {
				t.Errorf("a refusal was counted as %d transfers lost", lost)
			}
			held := placementOf(t, s.Records(), 1, fragment.Sent)
			if handed && !held.Whole() {
				t.Errorf("the handed refusal supplied its number but the direction is %s, not whole", held)
			}
			if !handed && (held.Whole() || held.Because != connection.TerminalUnsettled) {
				t.Errorf("wiring, not the property: without the refusal handed over the tail is %s, so the "+
					"refused number never reached the settlement", held)
			}
			if got := len(s.Records()); got != 1 {
				t.Errorf("%d connection records, and the refused handle nothing followed begins none", got)
			}
		})
	}
}

// A call still in flight in a direction when its handle is released is the
// supported use broken: its bytes, if any, are numbered after the ending was
// read, so the direction's tail is unsettled. The control: the same ending with
// nothing in flight.
func TestACallInFlightAtTheReleaseLeavesItsDirectionUnsettled(t *testing.T) {
	for name, inFlight := range map[string]bool{"a call in flight": true, "the control": false} {
		t.Run(name, func(t *testing.T) {
			// One transfer delivered (number 1); for the in-flight case a second call
			// took number 2 at entry and had not returned, so the terminal is 2 with
			// InFlight. That one number is the in-flight call, not a lost transfer.
			s := capture.Recording(&collected{}, nil)
			s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			ended := ending(worker, 0x18)
			ended.Sequence = probe.Sequence{Occupancy: 7, Born: true}
			last := uint64(1)
			if inFlight {
				last = 2
			}
			ended.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: last, InFlight: inFlight}}
			s.Closed(ended)

			if got := s.Stats().Closed; got != 1 {
				t.Fatalf("wiring, not the property: %d endings matched a connection", got)
			}
			held := placementOf(t, s.Records(), 1, fragment.Sent)
			if !inFlight {
				if !held.Whole() {
					t.Errorf("a settled tail with nothing in flight is %s", held)
				}
				return
			}
			if held.Positions != connection.PositionsUnknownFrom || held.From != 10 ||
				held.Because != connection.TerminalUnsettled {
				t.Errorf("a direction with a call in flight at the release is %s", held)
			}
			if held.Lost.Known && held.Lost.Value != 0 {
				t.Errorf("the in-flight call's entry number was counted as %d lost", held.Lost.Value)
			}
		})
	}
}

// A refused transfer numbered past the last delivered cuts its direction, so no
// exchange is written across the gap, but the refusal counts no located loss:
// the missing transfers are counted as abandoned, elsewhere. This is the
// admission-limit shape (an event admitted but not delivered, then a later
// refusal supplying a higher number).
func TestARefusedTransferNumberedPastTheLastCutsWithoutCountingALoss(t *testing.T) {
	s := produced(&collected{}, nil)
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	// Number 2 never arrives (admitted but abandoned); number 3 is refused.
	s.Refused(numberedAs(worker, 0x18, fragment.Sent, 6, 7, 3))
	s.numbers[numbered{handle: handleOf(numberedAs(worker, 0x18, fragment.Sent, 0, 7, 0)), direction: fragment.Sent}] = 3
	s.Finish(at)

	if got := s.Stats().Lost; got != 0 {
		t.Errorf("a refused transfer past the last counted %d located losses, and a refusal counts none", got)
	}
	held := placementOf(t, s.Records(), 1, fragment.Sent)
	if held.Whole() || held.Because != connection.ObservationLost {
		t.Errorf("the direction with a gap below a refused number is %s, want cut so no exchange spans it", held)
	}
	if held.Lost.Known {
		t.Errorf("the cut counts %v lost, and the missing transfers are counted as abandoned, not here", held.Lost)
	}
}
