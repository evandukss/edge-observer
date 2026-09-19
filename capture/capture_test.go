package capture_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

var at = time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)

type collected struct {
	records []fragment.Record
	refuse  bool
}

func (c *collected) Write(record fragment.Record) error {
	if c.refuse {
		return errors.New("refused")
	}
	c.records = append(c.records, record)
	return nil
}

func (c *collected) at(i int) fragment.Record { return c.records[i] }

var (
	worker  = fragment.Process{PID: 1731, StartTime: 90210}
	gateway = fragment.Process{PID: 1732, StartTime: 90211}

	// The admitted executions behind those two: connections are keyed by
	// execution and handle, not pid.
	inside      = admission.Namespace{Device: 4, Inode: 4026531836}
	workerRuns  = execution(inside, 1731, 1)
	gatewayRuns = execution(inside, 1732, 2)
)

func execution(namespace admission.Namespace, pid int32, generation admission.Generation) admission.Instance {
	return admission.Instance{
		Namespace:  namespace,
		PID:        pid,
		Start:      admission.Determinate(90210),
		Generation: generation,
		Executable: "/usr/bin/service",
	}
}

// stamped hands out consecutive production-order places; a test makes a loss
// by skipping a number. Consecutive observations lost nothing: the control.
type stamped struct{ next uint64 }

func (o *stamped) take() uint64 { o.next++; return o.next }

// skip drops n places, as n observations produced and never delivered would.
func (o *stamped) skip(n uint64) { o.next += n }

func transfer(p fragment.Process, endpoint uint64, direction fragment.Direction, length uint32) probe.Transfer {
	return probe.Transfer{
		Process:   p,
		Instance:  running(p),
		Endpoint:  endpoint,
		Direction: direction,
		Length:    length,
		Measured:  true,
		At:        at,
	}
}

// order is the stamp source, per test.
func ordered(t *testing.T) *stamped {
	t.Helper()
	return &stamped{}
}

// running is the admitted execution a test process stands for.
func running(p fragment.Process) admission.Instance {
	if p == gateway {
		return gatewayRuns
	}
	return workerRuns
}

// ending is one connection ending as the adapter reports it.
func ending(p fragment.Process, endpoint uint64) probe.Connection {
	return probe.Connection{Process: p, Instance: running(p), Endpoint: endpoint, At: at}
}

// finished is the connection records after sealing, when open connections get
// one.
func finished(s *capture.Session) []connection.Record {
	s.Finish(at, connection.Counted(0))
	return s.Records()
}

func session(t *testing.T) (*capture.Session, *collected) {
	t.Helper()

	sink := &collected{}
	return capture.New(sink), sink
}

func TestTheFragmentsOfOneStreamAreOrderedAndTheirOffsetsAdvanceByWhatMoved(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 25))

	if len(sink.records) != 2 {
		t.Fatalf("%d records, want 2", len(sink.records))
	}
	if sink.at(0).Connection != sink.at(1).Connection {
		t.Fatal("two transfers on one endpoint of one process are two connections")
	}
	if sink.at(0).Sequence != 1 || sink.at(1).Sequence != 2 {
		t.Fatalf("sequences are %d and %d", sink.at(0).Sequence, sink.at(1).Sequence)
	}
	if sink.at(0).Offset != 0 || sink.at(1).Offset != 10 {
		t.Fatalf("offsets are %d and %d, want 0 and 10", sink.at(0).Offset, sink.at(1).Offset)
	}
	if sink.at(0).End() != sink.at(1).Offset {
		t.Fatalf("the second fragment does not continue the first: %d then %d", sink.at(0).End(), sink.at(1).Offset)
	}
	stats := s.Stats()
	if stats.Records != 2 || stats.Transfers != 2 || stats.Connections != 1 {
		t.Fatalf("Stats = %+v", stats)
	}
}

// A connection's two directions are separate streams with separate offsets.
func TestTheTwoDirectionsOfOneConnectionCountSeparately(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Received, 100))
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(transfer(worker, 0x18, fragment.Received, 7))

	if got := sink.at(1).Offset; got != 0 {
		t.Errorf("the first fragment sent is at offset %d, behind what was received", got)
	}
	if got := sink.at(2).Offset; got != 100 {
		t.Errorf("the second fragment received is at offset %d, want 100", got)
	}
	// One sequence orders both directions of the connection.
	if sink.at(0).Sequence != 1 || sink.at(1).Sequence != 2 || sink.at(2).Sequence != 3 {
		t.Fatalf("sequences are %d, %d and %d", sink.at(0).Sequence, sink.at(1).Sequence, sink.at(2).Sequence)
	}
}

func TestTwoConnectionsOfOneProcessAreTwoStreams(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(transfer(worker, 0x19, fragment.Sent, 10))

	if sink.at(0).Connection == sink.at(1).Connection {
		t.Fatal("two endpoints of one process share a connection")
	}
	if sink.at(1).Offset != 0 {
		t.Fatalf("the second connection begins at offset %d", sink.at(1).Offset)
	}
}

// A handle is unique within one process only.
func TestOneEndpointAddressInTwoProcessesIsTwoConnections(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(transfer(gateway, 0x18, fragment.Sent, 10))

	if sink.at(0).Connection == sink.at(1).Connection {
		t.Fatal("one address in two processes is one connection")
	}
	if sink.at(1).Offset != 0 {
		t.Fatalf("the second process's connection begins at offset %d", sink.at(1).Offset)
	}
}

// An allocator reuses addresses. Without the connection's end, the next
// occupant would continue the previous stream at its offsets, invisibly.
func TestAnEndpointReusedAfterItsConnectionEndedStartsANewStream(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Closed(ending(worker, 0x18))
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))

	if sink.at(0).Connection == sink.at(1).Connection {
		t.Fatal("an endpoint reused after its connection ended continues the old stream")
	}
	if sink.at(1).Offset != 0 {
		t.Fatalf("the reused endpoint's stream begins at offset %d", sink.at(1).Offset)
	}
	if sink.at(1).Sequence != 1 {
		t.Fatalf("the reused endpoint's stream begins at sequence %d", sink.at(1).Sequence)
	}
	if stats := s.Stats(); stats.Closed != 1 || stats.Connections != 2 {
		t.Fatalf("Stats = %+v", stats)
	}
}

func TestEndingAConnectionNobodyIsFollowingChangesNothing(t *testing.T) {
	s, _ := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Closed(ending(worker, 0x99))
	s.Closed(ending(worker, 0x18))
	s.Closed(ending(worker, 0x18))

	if got, want := s.Stats().Closed, int64(1); got != want {
		t.Fatalf("Closed = %d, want %d", got, want)
	}
	if open := s.Open(); open != 0 {
		t.Fatalf("%d connections still followed", open)
	}
	// The unmatched endings are counted: one for a handle nobody followed, and a
	// repeat. The one that matched is the control: it moved Closed instead.
	if got, want := s.Stats().EndingsUnmatched, int64(2); got != want {
		t.Fatalf("EndingsUnmatched = %d, want %d", got, want)
	}
}

// An ending whose execution is unnamed matches nothing and is counted, since
// connections are keyed by execution and handle.
func TestAnEndingThatNamesNoExecutionMatchesNothingAndIsCounted(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Closed(probe.Connection{Process: worker, Endpoint: 0x18, At: at})
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))

	if got, want := s.Stats().EndingsUnmatched, int64(1); got != want {
		t.Fatalf("EndingsUnmatched = %d, want %d", got, want)
	}
	if s.Stats().Closed != 0 {
		t.Fatalf("Closed = %d for an ending that named no execution", s.Stats().Closed)
	}
	if sink.at(0).Connection != sink.at(1).Connection {
		t.Fatal("an ending nothing matched ended a stream anyway")
	}

	// The control: the same ending with its execution matches.
	s.Closed(ending(worker, 0x18))
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	if s.Stats().Closed != 1 {
		t.Fatalf("Closed = %d after an ending that named its execution", s.Stats().Closed)
	}
	if sink.at(1).Connection == sink.at(2).Connection {
		t.Fatal("the control ending did not end the stream, so nothing above proves anything")
	}
}

// A call returning no bytes is not a hole and is counted.
func TestACallThatMovedNoBytesProducesNoRecordAndIsCounted(t *testing.T) {
	s, sink := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 0))

	if len(sink.records) != 0 {
		t.Fatalf("%d records for a call that moved nothing", len(sink.records))
	}
	stats := s.Stats()
	if stats.Empty != 1 || stats.Transfers != 1 || stats.Records != 0 {
		t.Fatalf("Stats = %+v", stats)
	}
	if s.Open() != 0 {
		t.Fatal("a call that moved nothing opened a connection")
	}
}

// A refusing sink is counted and capture carries on.
func TestASinkThatRefusesDoesNotStopCapture(t *testing.T) {
	sink := &collected{refuse: true}
	s := capture.New(sink)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))

	stats := s.Stats()
	if stats.Rejected != 2 {
		t.Fatalf("Rejected = %d, want 2", stats.Rejected)
	}
	if stats.Transfers != 2 {
		t.Fatalf("Transfers = %d, want 2", stats.Transfers)
	}
}

// An unmeasured transfer is not an empty one: counted, not placed.
func TestATransferWhoseSizeCouldNotBeReadIsCountedApartAndPlacedNowhere(t *testing.T) {
	s, sink := session(t)

	unmeasured := transfer(worker, 0x18, fragment.Sent, 0)
	unmeasured.Measured = false

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(unmeasured)
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))

	stats := s.Stats()
	if stats.Unmeasured != 1 {
		t.Fatalf("Unmeasured = %d, want 1", stats.Unmeasured)
	}
	if stats.Empty != 0 {
		t.Fatalf("Empty = %d; a transfer nobody measured is not a transfer of nothing", stats.Empty)
	}
	if len(sink.records) != 2 {
		t.Fatalf("%d records, want 2", len(sink.records))
	}
	// The stream continued by an unknown amount, so the next fragment sits where
	// its own measured bytes put it.
	if sink.at(1).Offset != 10 {
		t.Fatalf("the fragment after an unmeasured transfer is at offset %d", sink.at(1).Offset)
	}
}

// Early data is ordinary plaintext at ordinary offsets; that it was early
// (replayable, not forward-secret) is kept beside the connection.
func TestBytesThatArrivedBeforeTheHandshakeFinishedAreMarkedOnTheConnection(t *testing.T) {
	s, sink := session(t)

	early := transfer(worker, 0x18, fragment.Sent, 10)
	early.Early = true

	s.Transfer(early)
	s.Transfer(transfer(worker, 0x18, fragment.Sent, 25))

	if len(sink.records) != 2 {
		t.Fatalf("%d records, want 2", len(sink.records))
	}
	// An ordinary record; the next fragment continues from its end.
	if sink.at(0).Offset != 0 || sink.at(1).Offset != 10 {
		t.Fatalf("offsets are %d and %d, want 0 and 10", sink.at(0).Offset, sink.at(1).Offset)
	}

	connections := finished(s)
	if len(connections) != 1 {
		t.Fatalf("%d connections, want 1", len(connections))
	}
	if got := len(connections[0].Early); got != 1 {
		t.Fatalf("%d early ranges on the connection, want 1", got)
	}
	if got := connections[0].Early[0]; got.Offset != 0 || got.Length != 10 || got.Direction != fragment.Sent {
		t.Fatalf("the early range is %+v", got)
	}
	if stats := s.Stats(); stats.Early != 1 {
		t.Fatalf("Early = %d, want 1", stats.Early)
	}
}

// Early-data byte counts come through a pointer and are often unmeasurable;
// unmeasured early data must not read as none.
func TestEarlyDataNobodyCouldMeasureIsStillMarkedOnTheConnection(t *testing.T) {
	s, sink := session(t)

	early := transfer(worker, 0x18, fragment.Received, 0)
	early.Early = true
	early.Measured = false

	s.Transfer(early)

	if len(sink.records) != 0 {
		t.Fatalf("%d records for a transfer nobody measured", len(sink.records))
	}
	connections := finished(s)
	if len(connections) != 1 {
		t.Fatalf("%d connections, want the one it arrived on", len(connections))
	}
	if connections[0].EarlyUnmeasured != 1 {
		t.Fatalf("EarlyUnmeasured = %d, want 1", connections[0].EarlyUnmeasured)
	}
	if len(connections[0].Early) != 0 {
		t.Fatalf("%d early ranges, and nothing measured one", len(connections[0].Early))
	}
	if stats := s.Stats(); stats.Early != 1 || stats.Unmeasured != 1 {
		t.Fatalf("Stats = %+v", stats)
	}
}

func TestAConnectionThatCarriedNothingEarlyIsMarkedWithNothing(t *testing.T) {
	s, _ := session(t)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))

	connections := finished(s)
	if len(connections) != 1 {
		t.Fatalf("%d connections, want 1", len(connections))
	}
	if len(connections[0].Early) != 0 || connections[0].EarlyUnmeasured != 0 {
		t.Fatalf("a connection carrying nothing early is marked %+v", connections[0])
	}
	if got := connections[0].Fragments; !got.Known || got.Value != 1 {
		t.Fatalf("Fragments = %s, want 1", got)
	}
	if connections[0].Handle.Address != 0x18 || connections[0].Handle.Instance != workerRuns.Key() {
		t.Fatalf("the connection is %+v", connections[0])
	}
}

// A stream that lost an observation is placeable below the gap and not at or
// above it. The control, in the same run: a connection that ended before the
// loss keeps every offset.
func TestALocatedLossInvalidatesTheStreamsLiveAcrossItAndNoOthers(t *testing.T) {
	sink := &collected{}
	s := capture.Recording(sink, nil)
	order := ordered(t)

	// The control: transfers and ends before the loss.
	ended := transfer(worker, 0x18, fragment.Sent, 10)
	ended.Stamp = order.take()
	s.Transfer(ended)
	s.Closed(probe.Connection{Process: worker, Instance: running(worker), Stamp: order.take(), Endpoint: 0x18, At: at})

	// The subject: live across the loss.
	live := transfer(worker, 0x20, fragment.Sent, 10)
	live.Stamp = order.take()
	s.Transfer(live)

	// Three observations produced and never delivered.
	order.skip(3)

	after := transfer(worker, 0x20, fragment.Sent, 7)
	after.Stamp = order.take()
	s.Transfer(after)

	s.Finish(at, connection.Counted(int64(order.next)))

	records := s.Records()
	if len(records) != 3 {
		t.Fatalf("%d connection records, want the ended one, the interrupted one and its successor", len(records))
	}

	control := records[0]
	if !control.Placeable(fragment.Sent) {
		t.Error("a connection that ended before the loss lost its placeable prefix")
	}
	if control.How != connection.HandleReleasedEnding {
		t.Errorf("the control ended as %s", control.How)
	}

	interrupted := records[1]
	held, found := interrupted.Placement(fragment.Sent)
	if !found {
		t.Fatal("the interrupted connection carries no placement for the direction that lost bytes")
	}
	if held.Positions != connection.PositionsUnknownFrom {
		t.Fatalf("the interrupted connection's positions are %s", held.Positions)
	}
	if held.From != 10 {
		t.Errorf("its positions are unknown from offset %d, and it had captured 10 bytes", held.From)
	}
	if held.Because != connection.ObservationLost {
		t.Errorf("it says its positions went because %s", held.Because)
	}
	if held.Lost.Known {
		t.Errorf("it claims %s of the missing observations were its own", held.Lost)
	}
	if interrupted.Placeable(fragment.Sent) {
		t.Error("the interrupted connection reports itself placeable")
	}
	for _, offset := range []uint64{0, 9} {
		if !held.Placeable(offset) {
			t.Errorf("offset %d, captured before the loss, is not placeable", offset)
		}
	}
	for _, offset := range []uint64{10, 11} {
		if held.Placeable(offset) {
			t.Errorf("offset %d, at or after the loss, is placeable", offset)
		}
	}

	if got, want := s.Stats().Lost, int64(3); got != want {
		t.Errorf("Lost = %d, want %d", got, want)
	}
	if got, want := s.Stats().Interrupted, int64(1); got != want {
		t.Errorf("Interrupted = %d, want %d", got, want)
	}
}

// A lost observation may have been a connection's end, so later traffic is a
// new connection whose association is unknown because of the loss.
func TestTrafficAfterALocatedLossIsANewConnectionWhoseBindingMayHaveGoneMissing(t *testing.T) {
	sink := &collected{}
	s := capture.Recording(sink, nil)
	order := ordered(t)

	before := transfer(worker, 0x18, fragment.Sent, 10)
	before.Stamp = order.take()
	s.Transfer(before)

	order.skip(1)

	after := transfer(worker, 0x18, fragment.Sent, 7)
	after.Stamp = order.take()
	s.Transfer(after)

	s.Finish(at, connection.Counted(int64(order.next)))

	if sink.at(0).Connection == sink.at(1).Connection {
		t.Fatal("traffic after a lost observation continued the stream it may have ended")
	}
	if sink.at(1).Offset != 0 {
		t.Errorf("the new connection's stream begins at offset %d", sink.at(1).Offset)
	}

	records := s.Records()
	if len(records) != 2 {
		t.Fatalf("%d connection records, want the interrupted one and its successor", len(records))
	}
	if records[0].How != connection.EndingUnobserved {
		t.Errorf("the interrupted connection ended as %s", records[0].How)
	}
	if records[0].Handle.Generation == records[1].Handle.Generation {
		t.Error("the successor reuses the interrupted connection's occupancy of the handle")
	}

	successor, found := records[1].Association(fragment.Sent)
	if !found {
		t.Fatal("the successor carries no association")
	}
	if successor.State != connection.Unknown {
		t.Fatalf("the successor's association is %s", successor.State)
	}
	if successor.Reason != connection.ObservationLost {
		t.Errorf("the successor's association is unknown because %s, and an observation was lost",
			successor.Reason)
	}
	if records[1].Joinable(fragment.Sent) {
		t.Error("a connection begun after a loss is joinable")
	}
}

// An unstamped observation costs the run its ordering: streams are
// unplaceable throughout, counted as their own state and never as a loss.
func TestAnObservationWithNoPlaceInTheOrderCostsTheRunItsLocatedGaps(t *testing.T) {
	sink := &collected{}
	s := capture.Recording(sink, nil)
	order := ordered(t)

	first := transfer(worker, 0x18, fragment.Sent, 10)
	first.Stamp = order.take()
	s.Transfer(first)

	unplaced := transfer(worker, 0x18, fragment.Sent, 5)
	unplaced.Stamp = 0
	s.Transfer(unplaced)

	order.skip(2)
	after := transfer(worker, 0x18, fragment.Sent, 5)
	after.Stamp = order.take()
	s.Transfer(after)

	s.Finish(at, connection.Counted(int64(order.next)))

	if got, want := s.Stats().Unstamped, int64(1); got != want {
		t.Errorf("Unstamped = %d, want %d", got, want)
	}
	records := s.Records()
	if len(records) == 0 {
		t.Fatal("no connection records")
	}
	held, found := records[0].Placement(fragment.Sent)
	if !found {
		t.Fatal("the interrupted connection carries no placement")
	}
	if held.Positions != connection.PositionsUnknownThroughout {
		t.Fatalf("positions are %s, and nothing in this run can locate a gap", held.Positions)
	}
	for _, offset := range []uint64{0, 1, 10} {
		if held.Placeable(offset) {
			t.Errorf("offset %d is placeable in a run with no usable ordering", offset)
		}
	}
}

// Observations lost after the last one delivered leave no gap; only the
// backend's production count reveals them, and an unreadable count leaves
// every open stream unplaceable.
func TestALossAfterTheLastObservationIsFoundFromWhatTheBackendProduced(t *testing.T) {
	for _, one := range []struct {
		name      string
		produced  connection.Count
		positions connection.Positions
	}{
		{"a trailing loss the backend can count", connection.Counted(4), connection.PositionsUnknownFrom},
		{"a produced count nobody could read", connection.Uncounted("the allocator is gone"), connection.PositionsUnknownThroughout},
		{"nothing missing at all", connection.Counted(1), connection.PositionsEstablished},
	} {
		t.Run(one.name, func(t *testing.T) {
			s := capture.Recording(&collected{}, nil)
			order := ordered(t)

			only := transfer(worker, 0x18, fragment.Sent, 10)
			only.Stamp = order.take()
			s.Transfer(only)

			s.Finish(at, one.produced)

			records := s.Records()
			if len(records) != 1 {
				t.Fatalf("%d connection records, want 1", len(records))
			}
			held, found := records[0].Placement(fragment.Sent)
			if !found {
				t.Fatal("the connection carries no placement")
			}
			if held.Positions != one.positions {
				t.Fatalf("positions are %s, want %s", held.Positions, one.positions)
			}
			if err := records[0].Validate(); err != nil {
				t.Errorf("the record is not usable: %v", err)
			}
		})
	}
}

// bound is a transfer that established a descriptor.
func bound(p fragment.Process, endpoint uint64, direction fragment.Direction, length uint32,
	descriptor int32, generation uint64) probe.Transfer {
	one := transfer(p, endpoint, direction, length)
	one.Descriptor = descriptor
	one.Binding = generation
	one.Bound = probe.BoundTo
	one.Network = probe.Netns{Device: 4, Inode: 4026532567}
	return one
}

// An established binding is reported with its descriptor, occupancy and
// interval. The control for the cases below.
func TestAConnectionThatEstablishedABindingSaysWhatItWasBoundTo(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	records := finished(s)
	if len(records) != 1 {
		t.Fatalf("%d connection records, want 1", len(records))
	}

	one, found := records[0].Association(fragment.Sent)
	if !found {
		t.Fatal("the connection carries no association for the direction that transferred")
	}
	if one.State != connection.Established {
		t.Fatalf("the association is %s, want established", one.State)
	}
	if one.Descriptor != connection.Held(7) {
		t.Errorf("it is bound to %s", one.Descriptor)
	}
	if one.Binding != 3 {
		t.Errorf("it names occupancy %s of that descriptor, want 3", one.Binding)
	}
	if one.Source != connection.InCallSyscall {
		t.Errorf("its evidence source is %s", one.Source)
	}
	if err := one.Validate(); err != nil {
		t.Errorf("an established association is not usable: %v", err)
	}
	// Descriptor without tuple: not joinable.
	if one.Joinable() {
		t.Error("an association with no endpoints is joinable")
	}
}

// Descriptor zero is real; zero must not be the unknown sentinel.
func TestABindingOnDescriptorZeroIsABinding(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 0, 3))
	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State != connection.Established {
		t.Fatalf("a binding on descriptor 0 is %s", one.State)
	}
	if one.Descriptor != connection.Held(0) {
		t.Errorf("it is bound to %s", one.Descriptor)
	}
	if err := records[0].Validate(); err != nil {
		t.Errorf("the record is not usable: %v", err)
	}
}

// Socket work on two descriptors is ambiguous and carries both, rather than
// guessing the first.
func TestACallWhoseWindowHeldTwoDescriptorsIsAmbiguousAndNotTheFirst(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	// The control: one descriptor, established.
	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	contended := transfer(worker, 0x18, fragment.Sent, 10)
	contended.Descriptor = 7
	contended.Bound = probe.BoundAmbiguously
	s.Transfer(contended)

	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State != connection.Ambiguous {
		t.Fatalf("a window holding two descriptors is %s", one.State)
	}
	if one.Reason != connection.SeveralDescriptors {
		t.Errorf("it says it is ambiguous because %s", one.Reason)
	}
	if one.Descriptor.Known {
		t.Errorf("an ambiguous association names %s as the descriptor", one.Descriptor)
	}
	if len(one.Contended) < 2 {
		t.Errorf("%d contended descriptors, and ambiguity is more than one", len(one.Contended))
	}
	if one.Joinable() {
		t.Error("an ambiguous association is joinable")
	}
	if err := one.Validate(); err != nil {
		t.Errorf("an ambiguous association is not usable: %v", err)
	}
}

// A descriptor replaced under a live handle (dup2) invalidates the binding,
// which stays visible as invalidated.
func TestADescriptorReplacedUnderALiveHandleInvalidatesTheBinding(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	replaced := transfer(worker, 0x18, fragment.Sent, 10)
	replaced.Descriptor = 7
	replaced.Binding = 3
	replaced.Bound = probe.BoundInvalidated
	s.Transfer(replaced)

	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State != connection.Invalidated {
		t.Fatalf("a replaced descriptor leaves the association %s", one.State)
	}
	if one.Reason != connection.DescriptorReplaced {
		t.Errorf("it says it was invalidated because %s", one.Reason)
	}
	if one.Valid.Open {
		t.Error("an invalidated binding is still open")
	}
	if one.Joinable() {
		t.Error("an invalidated association is joinable")
	}
}

// A call with no socket work inherits the handle's still-valid binding. A
// connection that never established one says so differently: it marks a
// process whose socket calls this run cannot see.
func TestACallWithNoSocketWorkDoesNotUnmakeTheHandlesBinding(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	buffered := transfer(worker, 0x18, fragment.Sent, 5)
	buffered.Bound = probe.NotBound
	s.Transfer(buffered)

	// A second connection that never established anything.
	s.Transfer(transfer(worker, 0x20, fragment.Sent, 10))

	records := finished(s)
	if len(records) != 2 {
		t.Fatalf("%d connection records, want 2", len(records))
	}

	inherited, _ := records[0].Association(fragment.Sent)
	if inherited.State != connection.Established {
		t.Fatalf("a buffered call left the handle's binding %s", inherited.State)
	}
	if inherited.Descriptor != connection.Held(7) {
		t.Errorf("the inherited binding is on %s", inherited.Descriptor)
	}

	never, _ := records[1].Association(fragment.Sent)
	if never.State != connection.Unknown {
		t.Fatalf("a connection that never established a binding is %s", never.State)
	}
	if never.Reason != connection.NoBindingObserved {
		t.Errorf("it is unknown because %s", never.Reason)
	}
	if never.Descriptor.Known {
		t.Errorf("a connection that established nothing names %s", never.Descriptor)
	}
}

// No endpoint producer here, so nothing joins; the binding and the join are
// separate axes, each with its own reason.
func TestTheExecutionsNamespaceIsRecordedWithoutBecomingTheSocketsAndNothingJoins(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State != connection.Established {
		t.Fatalf("the binding is %s", one.State)
	}
	// The record's namespace is the execution's, never filled in as the socket's.
	if got := records[0].Network; !got.Known() || got.Inode != 4026532567 {
		t.Errorf("the execution's namespace is %s", got)
	}
	if one.Endpoints.Netns.Known() {
		t.Errorf("the socket's namespace is %s, and nothing established it", one.Endpoints.Netns)
	}
	if one.Endpoints.Local.Known || one.Endpoints.Remote.Known {
		t.Error("an address was established by a transfer that carried none")
	}
	if one.Joinable() {
		t.Error("an association with a namespace and no addresses joins")
	}
	// No producer ran, so the reason is that nothing established endpoints, not
	// a failed read; the backend says which.
	if one.JoinReason != connection.NoEndpointProducer {
		t.Errorf("it says it does not join because %s, and no producer ran for it",
			one.JoinReason)
	}
	if err := records[0].Validate(); err != nil {
		t.Errorf("the record is not usable: %v", err)
	}
}

// A connection with no binding says so on both axes; its join reason is the
// missing binding, not a failed producer.
func TestAConnectionWithNoBindingSaysSoOnBothAxes(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State != connection.Unknown || one.Reason != connection.NoBindingObserved {
		t.Fatalf("the binding is %s because %s", one.State, one.Reason)
	}
	if one.Join != connection.DoesNotJoin {
		t.Fatalf("its joinability is %s", one.Join)
	}
	if one.JoinReason != connection.NoBindingToJoin {
		t.Errorf("it says it does not join because %s, and there is no binding at all",
			one.JoinReason)
	}
}

// A call that returns to a withdrawn grant is refused and delivers nothing
// but its production-order place, like a lost observation: its stream stops
// being placeable from there. The control: a connection that ended before
// production stopped keeps every offset.
func TestATransferRefusedWhenProductionStoppedLeavesItsStreamUnplaceable(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	order := ordered(t)

	ended := transfer(worker, 0x18, fragment.Sent, 10)
	ended.Stamp = order.take()
	s.Transfer(ended)
	s.Closed(probe.Connection{Process: worker, Instance: running(worker), Stamp: order.take(), Endpoint: 0x18, At: at})

	live := transfer(worker, 0x20, fragment.Sent, 10)
	live.Stamp = order.take()
	s.Transfer(live)

	// Production stops; the call in flight returns to a withdrawn grant.
	order.skip(1)
	s.Finish(at, connection.Counted(int64(order.next)))

	records := s.Records()
	if len(records) != 2 {
		t.Fatalf("%d connection records, want the one that ended and the one that was interrupted",
			len(records))
	}

	if !records[0].Placeable(fragment.Sent) {
		t.Error("a connection that ended before production stopped lost its placeable prefix")
	}

	held, found := records[1].Placement(fragment.Sent)
	if !found {
		t.Fatal("the interrupted connection carries no placement")
	}
	if held.Positions != connection.PositionsUnknownFrom {
		t.Fatalf("its positions are %s, and a refused transfer's bytes are missing from it",
			held.Positions)
	}
	if held.From != 10 {
		t.Errorf("its positions are unknown from offset %d, and it had captured 10 bytes", held.From)
	}
	if held.Because != connection.ObservationLost {
		t.Errorf("it says its positions went because %s", held.Because)
	}
	if records[1].Placeable(fragment.Sent) {
		t.Error("the interrupted connection reports itself placeable")
	}
}

// Socket work on two descriptors observed something: which one is what is
// missing. A custom BIO produces exactly this, since the setter never runs.
// The control: a connection with nothing observed still reports Unknown.
func TestAmbiguityIsReportedEvenWhenNoBindingWasEverEstablished(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	contended := transfer(worker, 0x18, fragment.Sent, 10)
	contended.Descriptor = 7
	contended.Bound = probe.BoundAmbiguously
	s.Transfer(contended)

	// A second ambiguous round on the same handle.
	again := transfer(worker, 0x18, fragment.Sent, 5)
	again.Descriptor = 7
	again.Bound = probe.BoundAmbiguously
	s.Transfer(again)

	// The control: nothing ever observed.
	s.Transfer(transfer(worker, 0x20, fragment.Sent, 10))

	records := finished(s)
	if len(records) != 2 {
		t.Fatalf("%d connection records, want the ambiguous one and the control", len(records))
	}

	ambiguous, found := records[0].Association(fragment.Sent)
	if !found {
		t.Fatal("the ambiguous connection carries no association")
	}
	if ambiguous.State != connection.Ambiguous {
		t.Fatalf("a connection whose only evidence is ambiguity is %s because %s",
			ambiguous.State, ambiguous.Reason)
	}
	if ambiguous.Reason != connection.SeveralDescriptors {
		t.Errorf("it is ambiguous because %s", ambiguous.Reason)
	}
	if err := records[0].Validate(); err != nil {
		t.Errorf("the record is not usable: %v", err)
	}

	never, found := records[1].Association(fragment.Sent)
	if !found {
		t.Fatal("the control carries no association")
	}
	if never.State != connection.Unknown || never.Reason != connection.NoBindingObserved {
		t.Fatalf("the control is %s because %s, and nothing was observed for it",
			never.State, never.Reason)
	}
}

// An invalidation is an observation too, even when the establishing call left
// no record.
func TestAnInvalidationIsReportedEvenWhenTheBindingItReplacedWasNeverSeen(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	replaced := transfer(worker, 0x18, fragment.Sent, 10)
	replaced.Descriptor = 7
	replaced.Binding = 3
	replaced.Bound = probe.BoundInvalidated
	s.Transfer(replaced)

	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)
	if one.State != connection.Invalidated {
		t.Fatalf("a connection whose only evidence is an invalidation is %s because %s",
			one.State, one.Reason)
	}
	if one.Reason != connection.DescriptorReplaced {
		t.Errorf("it is invalidated because %s", one.Reason)
	}
}

// A stream begun after a located loss is unplaceable: its first byte's place
// in the connection is not established. The control: a connection that ended
// before the loss keeps every offset.
func TestAStreamBegunAfterALocatedLossPlacesNoOffsetAtAll(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	order := ordered(t)

	// The control: opened, transferred and ended before the loss.
	ended := transfer(worker, 0x18, fragment.Sent, 10)
	ended.Stamp = order.take()
	s.Transfer(ended)
	s.Closed(probe.Connection{Process: worker, Instance: running(worker), Stamp: order.take(), Endpoint: 0x18, At: at})

	// A connection live across the loss, and its successor.
	live := transfer(worker, 0x20, fragment.Sent, 10)
	live.Stamp = order.take()
	s.Transfer(live)

	order.skip(2)

	after := transfer(worker, 0x20, fragment.Sent, 7)
	after.Stamp = order.take()
	s.Transfer(after)

	s.Finish(at, connection.Counted(int64(order.next)))

	records := s.Records()
	if len(records) != 3 {
		t.Fatalf("%d connection records, want the control, the interrupted one and its successor",
			len(records))
	}

	if !records[0].Placeable(fragment.Sent) {
		t.Error("the control, which ended before the loss, lost its placeable offsets")
	}

	successor := records[2]
	held, found := successor.Placement(fragment.Sent)
	if !found {
		t.Fatal("the successor carries no placement for the direction that transferred")
	}
	if held.Positions != connection.PositionsUnknownThroughout {
		t.Fatalf("the successor's positions are %s, and nothing establishes where its first byte "+
			"sits in the connection", held.Positions)
	}
	if held.Because != connection.ObservationLost {
		t.Errorf("it says its positions went because %s", held.Because)
	}
	// No offset at all; offset 0 is what a default-established fold would claim.
	for _, offset := range []uint64{0, 1, 7} {
		if held.Placeable(offset) {
			t.Errorf("offset %d is placeable on a stream whose own beginning may be what was lost",
				offset)
		}
	}
	if successor.Placeable(fragment.Sent) {
		t.Error("the successor reports itself placeable")
	}
	if err := successor.Validate(); err != nil {
		t.Errorf("the successor's record is not usable: %v", err)
	}
}

// The open time is the socket's, not the first transfer's. Both halves are
// asserted: one alone passes against copying firstSeen, the other against
// never setting Opened.
func TestTheConnectionsOpenTimeIsTheSocketsAndNotTheFirstTransfer(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	opened := time.Date(2026, 9, 8, 11, 59, 58, 0, time.UTC)
	one := bound(worker, 0x18, fragment.Sent, 10, 7, 3)
	one.Ends.OpenedAt = opened
	s.Transfer(one)

	records := finished(s)
	if len(records) != 1 {
		t.Fatalf("%d connection records, want 1", len(records))
	}
	held := records[0]
	if !held.OpenedKnown {
		t.Fatal("a connection whose socket this run saw open reports no open time")
	}
	if !held.Opened.Equal(opened) {
		t.Errorf("the connection opened at %s, and the socket was created at %s", held.Opened, opened)
	}
	if held.Opened.Equal(held.FirstSeen) {
		t.Errorf("the open time is the first transfer's time, %s - the two are different facts",
			held.FirstSeen)
	}
	if err := held.Validate(); err != nil {
		t.Errorf("the record is not usable: %v", err)
	}
}

// A socket this run did not see open has no open time; it must never become
// firstSeen under another name.
func TestASocketThisRunDidNotSeeOpenHasNoOpenTimeRatherThanTheFirstTransfers(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	// Everything else established; the socket predates the probes.
	one := bound(worker, 0x18, fragment.Sent, 10, 7, 3)
	one.Ends.OpenedAt = time.Time{}
	s.Transfer(one)

	records := finished(s)
	if len(records) != 1 {
		t.Fatalf("%d connection records, want 1", len(records))
	}
	held := records[0]
	if held.OpenedKnown {
		t.Fatalf("a socket this run never saw open reports an open time of %s", held.Opened)
	}
	if !held.Opened.IsZero() {
		t.Errorf("an unestablished open time carries the instant %s", held.Opened)
	}
	if held.FirstSeen.IsZero() {
		t.Fatal("the control is broken: this record has no first-seen time either, so the " +
			"assertion above has not distinguished anything")
	}
	if err := held.Validate(); err != nil {
		t.Errorf("a record with no open time is not usable: %v", err)
	}
}

// Each way of failing to establish a joinable tuple has its own reason: no
// producer, a failed read, an unread namespace. Asserted together, since any
// one alone passes against an implementation that always prints it.
func TestEachWayOfNotJoiningNamesItsOwnReason(t *testing.T) {
	local := netip.MustParseAddr("172.26.0.3")
	peer := netip.MustParseAddr("172.26.0.7")

	for _, c := range []struct {
		name string
		ends probe.Ends
		want connection.JoinReason
	}{
		{
			name: "no producer ran",
			ends: probe.Ends{},
			want: connection.NoEndpointProducer,
		},
		{
			name: "a producer ran and read nothing",
			ends: probe.Ends{Attempted: true},
			want: connection.EndpointUnreadable,
		},
		{
			// Correct addresses, missing scope: not an endpoint failure.
			name: "the addresses were read and the namespace was not",
			ends: probe.Ends{
				Attempted: true, Known: true,
				Local: local.As16(), Peer: peer.As16(),
				LocalPort: 44120, PeerPort: 8443,
			},
			want: connection.NamespaceUnestablished,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := capture.Recording(&collected{}, nil)
			one := bound(worker, 0x18, fragment.Sent, 10, 7, 3)
			one.Ends = c.ends
			s.Transfer(one)

			records := finished(s)
			if len(records) != 1 {
				t.Fatalf("%d connection records, want 1", len(records))
			}
			held, _ := records[0].Association(fragment.Sent)
			if held.State != connection.Established {
				t.Fatalf("the binding is %s, so nothing below is about the join axis", held.State)
			}
			if held.Joinable() {
				t.Fatalf("an association with no complete tuple joins: %+v", held.Endpoints)
			}
			if held.JoinReason != c.want {
				t.Errorf("it does not join because %q, want %q", held.JoinReason, c.want)
			}
		})
	}
}

// A gap the backend took no number for is the producer's race; a gap it did
// take one for (a refused transfer) still invalidates. Asserted together: the
// reorder case alone passes against suppressing every gap.
func TestAGapIsAReorderOnlyWhenTheBackendTookNoNumberForIt(t *testing.T) {
	for _, c := range []struct {
		name    string
		after   probe.Consumed
		retired bool
	}{
		{name: "nothing was taken, so the gap is the stamp race", after: probe.Consumed{}, retired: false},
		{name: "a reservation failed, so the gap is a loss",
			after: probe.Consumed{ReserveFailed: 1}, retired: true},
		{name: "a refusal took a place in the order, so the gap still invalidates",
			after: probe.Consumed{Refused: 1}, retired: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			counted := probe.Consumed{}
			s := capture.Recording(&collected{}, nil, capture.Consumes(func() (probe.Consumed, error) {
				return counted, nil
			}))
			order := ordered(t)

			live := transfer(worker, 0x18, fragment.Sent, 10)
			live.Stamp = order.take()
			s.Transfer(live)

			// A number the consumer never sees, and the backend's account of it.
			order.skip(1)
			counted = c.after

			after := transfer(worker, 0x18, fragment.Sent, 7)
			after.Stamp = order.take()
			s.Transfer(after)

			s.Finish(at, connection.Counted(int64(order.next)))
			records := s.Records()

			// The guard: without a record nothing below measures anything.
			if len(records) == 0 {
				t.Fatal("wiring, not the property: the session produced no connection record")
			}
			if c.retired && len(records) != 2 {
				t.Fatalf("a confirmed gap left %d records, and it retires the live stream and "+
					"starts a new one for what followed", len(records))
			}
			if !c.retired && len(records) != 1 {
				t.Fatalf("a tolerated reorder split one stream into %d records", len(records))
			}

			placeable := records[0].Placeable(fragment.Sent)
			if c.retired && placeable {
				t.Errorf("a gap the backend took a number for left the stream placeable")
			}
			if !c.retired && !placeable {
				t.Errorf("a gap that was only the stamp race cost the stream its positions")
			}
			if got := s.Stats().Tolerated; !c.retired && got != 1 {
				t.Errorf("a tolerated reorder was counted %d times, want 1", got)
			}
			if got := s.Stats().Disordered; got != 0 {
				t.Errorf("a gap was counted as an observation arriving behind one already seen "+
					"%d times, and none did", got)
			}
			if got := s.Stats().Interrupted; c.retired && got != 1 {
				t.Errorf("a confirmed gap retired %d streams, want 1", got)
			}
			// A gap the backend explained is not unexplained, whichever way it answered.
			if got := s.Stats().Unexplained; got != 0 {
				t.Errorf("a gap the backend answered was counted as unexplained %d times", got)
			}
		})
	}
}

// A backend that cannot answer confirms the gap: an unanswered question does
// not license suppression.
func TestAGapIsConfirmedWhenNothingCanSayWhetherANumberWasTaken(t *testing.T) {
	for _, c := range []struct {
		name string
		read func() (probe.Consumed, error)
	}{
		{name: "no reader at all", read: nil},
		{name: "a reader that could not answer",
			read: func() (probe.Consumed, error) { return probe.Consumed{}, errors.New("unreadable") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			options := []capture.Option{}
			if c.read != nil {
				options = append(options, capture.Consumes(c.read))
			}
			s := capture.Recording(&collected{}, nil, options...)
			order := ordered(t)

			live := transfer(worker, 0x18, fragment.Sent, 10)
			live.Stamp = order.take()
			s.Transfer(live)
			order.skip(1)
			after := transfer(worker, 0x18, fragment.Sent, 7)
			after.Stamp = order.take()
			s.Transfer(after)

			s.Finish(at, connection.Counted(int64(order.next)))
			if got := s.Stats().Interrupted; got != 1 {
				t.Errorf("a gap nothing could explain retired %d streams, want 1", got)
			}
			// It says why it was confirmed.
			if got := s.Stats().Unexplained; got != 1 {
				t.Errorf("a gap confirmed with nothing able to say was counted %d times, want 1", got)
			}
		})
	}
}

// A tolerated gap and a backward observation are counted separately; only the
// backward one costs the run its ordering. Asserted together, since either
// alone passes against incrementing both.
func TestAToleratedRaceAndABackwardStampAreCountedApart(t *testing.T) {
	t.Run("a gap tolerated as the race", func(t *testing.T) {
		s := capture.Recording(&collected{}, nil, capture.Consumes(func() (probe.Consumed, error) {
			return probe.Consumed{}, nil
		}))
		order := ordered(t)

		live := transfer(worker, 0x18, fragment.Sent, 10)
		live.Stamp = order.take()
		s.Transfer(live)
		order.skip(1)
		after := transfer(worker, 0x18, fragment.Sent, 7)
		after.Stamp = order.take()
		s.Transfer(after)
		s.Finish(at, connection.Counted(int64(order.next)))

		stats := s.Stats()
		if stats.Tolerated != 1 {
			t.Errorf("a gap tolerated as the race was counted %d times, want 1", stats.Tolerated)
		}
		if stats.Disordered != 0 {
			t.Errorf("a tolerated gap was counted as an observation arriving behind one already "+
				"seen %d times, and no observation arrived out of order", stats.Disordered)
		}
		if !s.Records()[0].Placeable(fragment.Sent) {
			t.Error("a tolerated race cost the stream its positions")
		}
	})

	t.Run("an observation behind one already seen", func(t *testing.T) {
		s := capture.Recording(&collected{}, nil, capture.Consumes(func() (probe.Consumed, error) {
			return probe.Consumed{}, nil
		}))
		order := ordered(t)

		first := transfer(worker, 0x18, fragment.Sent, 10)
		first.Stamp = order.take()
		s.Transfer(first)
		second := transfer(worker, 0x18, fragment.Sent, 7)
		second.Stamp = order.take()
		s.Transfer(second)

		// The one behind a stamp already seen.
		behind := transfer(worker, 0x18, fragment.Sent, 5)
		behind.Stamp = first.Stamp
		s.Transfer(behind)
		s.Finish(at, connection.Counted(int64(order.next)))

		stats := s.Stats()
		if stats.Disordered != 1 {
			t.Errorf("an observation behind one already seen was counted %d times, want 1", stats.Disordered)
		}
		if stats.Tolerated != 0 {
			t.Errorf("a backward stamp was counted as a tolerated race %d times, and no gap was "+
				"tolerated", stats.Tolerated)
		}
	})
}

// The observations a located loss accounted for reach a reader.
func TestTheObservationsALocatedLossAccountedForReachAReader(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	order := ordered(t)

	live := transfer(worker, 0x18, fragment.Sent, 10)
	live.Stamp = order.take()
	s.Transfer(live)
	order.skip(3)
	after := transfer(worker, 0x18, fragment.Sent, 7)
	after.Stamp = order.take()
	s.Transfer(after)
	s.Finish(at, connection.Counted(int64(order.next)))

	if got := s.Stats().Lost; got != 3 {
		t.Errorf("the run accounts for %d lost observations, and three were produced and never "+
			"delivered", got)
	}
}
