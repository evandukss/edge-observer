package capture_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
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
func finished(s *producer) []connection.Record {
	s.Finish(at)
	return s.Records()
}

func session(t *testing.T) (*producer, *collected) {
	t.Helper()

	sink := &collected{}
	return produced(sink, nil), sink
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
	s := produced(sink, nil)

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
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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

// A call that returns to a withdrawn grant is refused and delivers nothing,
// and the producer takes its number all the same: settled against what the
// producer holds once production stopped, its stream stops being placeable
// where the refused bytes began. The control: a connection that ended before
// production stopped keeps every offset.
func TestATransferRefusedWhenProductionStoppedLeavesItsStreamUnplaceable(t *testing.T) {
	s := produced(&collected{}, nil)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Closed(ending(worker, 0x18))

	live := transfer(worker, 0x20, fragment.Sent, 10)
	s.Transfer(live)

	// Production stops; the call in flight returns to a withdrawn grant and takes
	// the next number in its occupancy without delivering anything.
	s.numbers[numbered{handle: handleOf(live), direction: fragment.Sent}]++
	s.Finish(at)

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
	if !held.Lost.Known || held.Lost.Value != 1 {
		t.Errorf("it counts %v transfers lost, and one was refused", held.Lost)
	}
	if records[1].Placeable(fragment.Sent) {
		t.Error("the interrupted connection reports itself placeable")
	}
}

// Socket work on two descriptors observed something: which one is what is
// missing. A custom BIO produces exactly this, since the setter never runs.
// The control: a connection with nothing observed still reports Unknown.
func TestAmbiguityIsReportedEvenWhenNoBindingWasEverEstablished(t *testing.T) {
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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

// The open time is the socket's, not the first transfer's. Both halves are
// asserted: one alone passes against copying firstSeen, the other against
// never setting Opened.
func TestTheConnectionsOpenTimeIsTheSocketsAndNotTheFirstTransfer(t *testing.T) {
	s := produced(&collected{}, nil)

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
	s := produced(&collected{}, nil)

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
			s := produced(&collected{}, nil)
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
