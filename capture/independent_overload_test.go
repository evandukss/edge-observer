package capture_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
)

// These cases model the producer's published numbering (probe.Sequence): an
// occupancy numbers each direction's byte-moving calls from one, Born says it
// began at the handle's observed birth, and Unlocated is the producer's count
// of losses it could place in no occupancy, as each observation was produced.

type overloadRecords struct {
	fragments []fragment.Record
	endings   []connection.Record
}

func (r *overloadRecords) Write(f fragment.Record) error {
	r.fragments = append(r.fragments, f)
	return nil
}

func (r *overloadRecords) Connection(c connection.Record) error {
	r.endings = append(r.endings, c)
	return nil
}

type overloadOccupancy struct {
	id             uint64
	born           bool
	began          uint64
	sent, received uint64
}

type overloadCapture struct {
	session   *capture.Session
	instance  admission.Instance
	process   fragment.Process
	stamp     uint64
	unlocated uint64
	next      uint64
	open      map[uint64]*overloadOccupancy
}

func overloadCaptureOn(fragments capture.Sink, records connection.Sink) *overloadCapture {
	return &overloadCapture{
		session: capture.Recording(fragments, records),
		instance: admission.Instance{Namespace: admission.Namespace{Device: 3, Inode: 7},
			PID: 71, Start: admission.Determinate(19), Generation: 1},
		process: fragment.Process{PID: 71, StartTime: 19},
		open:    map[uint64]*overloadOccupancy{},
	}
}

// begin starts a new occupancy of handle, born at an observed birth or begun
// at its first recorded call.
func (c *overloadCapture) begin(handle uint64, born bool) {
	c.next++
	c.open[handle] = &overloadOccupancy{id: c.next, born: born, began: c.unlocated}
}

// transfer numbers one call in its direction, skip numbers after the last
// one, and builds it as the producer would hand it on.
func (c *overloadCapture) transfer(handle uint64, direction fragment.Direction, payload string, skip uint64) probe.Transfer {
	o := c.open[handle]
	number := &o.sent
	if direction == fragment.Received {
		number = &o.received
	}
	*number += 1 + skip
	c.stamp++
	return probe.Transfer{
		Process: c.process, Instance: c.instance, Endpoint: handle, Stamp: c.stamp,
		Sequence:  probe.Sequence{Occupancy: o.id, Number: *number, Born: o.born, Unlocated: c.unlocated, BeginUnlocated: o.began},
		Direction: direction, Length: uint32(len(payload)), Measured: true, Payload: []byte(payload),
		At: time.Unix(100, int64(c.stamp)),
	}
}

func (c *overloadCapture) send(handle uint64, direction fragment.Direction, payload string) {
	c.session.Transfer(c.transfer(handle, direction, payload, 0))
}

func (c *overloadCapture) close(handle uint64) {
	o := c.open[handle]
	delete(c.open, handle)
	c.stamp++
	c.session.Closed(probe.Connection{
		Process: c.process, Instance: c.instance, Endpoint: handle, Stamp: c.stamp,
		Sequence: probe.Sequence{Occupancy: o.id, Born: o.born, Unlocated: c.unlocated, BeginUnlocated: o.began},
		Final:    probe.Final{Known: true, Sent: probe.Terminal{Last: o.sent}, Received: probe.Terminal{Last: o.received}},
		At:       time.Unix(100, int64(c.stamp)),
	})
}

// overloadPlacement is the placement of direction in the one record retired
// for handle.
func overloadPlacement(t *testing.T, records []connection.Record, handle uint64, direction fragment.Direction) connection.Placement {
	t.Helper()
	var found []connection.Record
	for _, r := range records {
		if r.Handle.Address == handle {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("wiring, not the property: handle %d was retired %d times, want once", handle, len(found))
	}
	p, ok := found[0].Placement(direction)
	if !ok {
		t.Fatalf("wiring, not the property: handle %d's record carries no %v placement", handle, direction)
	}
	return p
}

// overloadUnplacedFrom is the first offset a placement does not establish, and
// whether it establishes the whole direction.
func overloadUnplacedFrom(p connection.Placement) (uint64, bool) {
	switch p.Positions {
	case connection.PositionsEstablished:
		return 0, true
	case connection.PositionsUnknownFrom:
		return p.From, false
	default:
		return 0, false
	}
}

// A transfer the delivery gate refused is a loss located to its connection and
// direction: that direction stops where the refused bytes would have begun, the
// refusal is counted as such and not as a producer loss, and another connection
// is untouched.
func TestIndependentAGateRefusedTransferCutsItsOwnDirectionAndIsCounted(t *testing.T) {
	records := &overloadRecords{}
	c := overloadCaptureOn(records, records)
	const before = "GET /before HTTP/1.1\r\n\r\n"
	c.begin(1, true)
	c.begin(2, true)
	c.send(1, fragment.Sent, before)
	c.send(1, fragment.Received, "HTTP/1.1 204 No Content\r\n\r\n")
	c.send(2, fragment.Sent, "GET /other HTTP/1.1\r\n\r\n")
	c.session.Refused(c.transfer(1, fragment.Sent, "GET /refused HTTP/1.1\r\n\r\n", 0))
	c.send(1, fragment.Sent, "GET /after HTTP/1.1\r\n\r\n")
	c.send(2, fragment.Received, "HTTP/1.1 204 No Content\r\n\r\n")
	c.close(1)
	c.close(2)
	if got := c.session.Stats().Transfers; got != 5 || len(records.endings) != 2 {
		t.Fatalf("wiring, not the property: capture took %d transfers and handed on %d records, want 5 and 2",
			got, len(records.endings))
	}

	stats := c.session.Stats()
	if stats.GateRefused != 1 {
		t.Errorf("one transfer was refused at the gate and %d are counted", stats.GateRefused)
	}
	if stats.Lost != 0 {
		t.Errorf("a gate refusal was counted as %d transfers the producer lost", stats.Lost)
	}
	if stats.Cut < 1 {
		t.Errorf("no direction was counted cut: %+v", stats)
	}
	from, whole := overloadUnplacedFrom(overloadPlacement(t, records.endings, 1, fragment.Sent))
	if whole || from > uint64(len(before)) {
		t.Errorf("the refused direction is established to %d (whole %v), past offset %d where the refused bytes began",
			from, whole, len(before))
	}
	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if _, whole := overloadUnplacedFrom(overloadPlacement(t, records.endings, 2, d)); !whole {
			t.Errorf("the other connection's %v direction lost its positions over a refusal on another connection", d)
		}
	}
}

// A fragment the volatile intake refuses for want of room is a loss located to
// its connection, counted as such. The intake takes later input once it has
// room: a later connection's fragments are stored and its positions whole.
func TestIndependentAnIntakeRefusalCutsItsConnectionAndLaterInputIsStored(t *testing.T) {
	store, err := intake.New(4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	c := overloadCaptureOn(store, store)
	const before = "GET /before HTTP/1.1\r\n\r\n"
	c.begin(1, true)
	c.send(1, fragment.Sent, before)
	stored := store.Stats().Fragments
	c.send(1, fragment.Sent, "GET /refused HTTP/1.1\r\nX-Fill: "+string(make([]byte, 3900))+"\r\n\r\n")
	if refused := store.Stats().FragmentsRefused; stored != 1 || refused != 1 {
		t.Fatalf("wiring, not the property: the intake stored %d and refused %d fragments, want 1 and 1", stored, refused)
	}
	// What a worker does with the stored entry, so the intake is empty again.
	for e := store.Take(); e != nil; e = store.Take() {
		e.Release()
	}
	if s := store.Stats(); s.Bytes != 0 || s.Queued != 0 || s.Leased != 0 {
		t.Fatalf("wiring, not the property: the intake still holds %+v after every entry was released", s)
	}

	c.begin(2, true)
	c.send(2, fragment.Sent, "GET /fresh HTTP/1.1\r\n\r\n")
	c.send(2, fragment.Received, "HTTP/1.1 204 No Content\r\n\r\n")
	c.send(1, fragment.Sent, "GET /after HTTP/1.1\r\n\r\n")
	c.close(2)
	c.close(1)

	stats := c.session.Stats()
	if stats.IntakeRefused != 1 {
		t.Errorf("one fragment was refused by the intake and %d are counted", stats.IntakeRefused)
	}
	if stats.Lost != 0 {
		t.Errorf("an intake refusal was counted as %d transfers the producer lost", stats.Lost)
	}
	if got := store.Stats().Fragments; got < 3 {
		t.Errorf("the intake stored %d fragments in all; the later connection's two, sent once it was empty again, were refused", got)
	}
	var endings []connection.Record
	for e := store.Take(); e != nil; e = store.Take() {
		if e.Connection != nil {
			endings = append(endings, *e.Connection)
		}
	}
	if len(endings) != 2 {
		t.Fatalf("the intake took %d of the two connections' records once it had room again", len(endings))
	}
	from, whole := overloadUnplacedFrom(overloadPlacement(t, endings, 1, fragment.Sent))
	if whole || from > uint64(len(before)) {
		t.Errorf("the refused direction is established to %d (whole %v), past offset %d where the refused bytes began",
			from, whole, len(before))
	}
	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if _, whole := overloadUnplacedFrom(overloadPlacement(t, endings, 2, d)); !whole {
			t.Errorf("the later connection's %v direction lost its positions", d)
		}
	}
}

// After a loss the producer could place in no occupancy:
//   - an occupancy born at an observed birth after it numbers every one of its
//     transfers, so it is placed whole;
//   - an occupancy begun at a first call after it may have lost the calls
//     before that one, so no offset of it is established;
//   - an occupancy begun before it is not what it lost, even where its first
//     event is delivered after it, so it is placed whole;
//   - a connection live across it keeps the positions it had established.
func TestIndependentAfterAnUnlocatedLossOnlyAFreshOccupancyIsPlacedWhole(t *testing.T) {
	records := &overloadRecords{}
	c := overloadCaptureOn(records, records)
	const request, response = "GET /live HTTP/1.1\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n"
	c.begin(1, true)
	c.send(1, fragment.Sent, request)
	c.send(1, fragment.Received, response)
	// Begun at a first call before the loss, its first event delivered after it.
	c.begin(4, false)

	c.unlocated = 1
	c.send(1, fragment.Sent, request)
	c.send(4, fragment.Sent, "GET /begun-before HTTP/1.1\r\n\r\n")
	c.send(4, fragment.Received, response)
	c.close(4)
	c.begin(2, true)
	c.send(2, fragment.Sent, "GET /fresh HTTP/1.1\r\n\r\n")
	c.send(2, fragment.Received, response)
	c.begin(3, false)
	c.send(3, fragment.Sent, "GET /first-call HTTP/1.1\r\n\r\n")
	c.send(3, fragment.Received, response)
	c.close(2)
	c.close(3)
	c.close(1)
	if got := c.session.Stats().Unlocated; got != 1 || len(records.endings) != 4 {
		t.Fatalf("wiring, not the property: capture took the unlocated count as %d with %d records, want 1 and 4",
			got, len(records.endings))
	}

	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if _, whole := overloadUnplacedFrom(overloadPlacement(t, records.endings, 2, d)); !whole {
			t.Errorf("the occupancy born after the loss is not placed whole in its %v direction", d)
		}
		if _, whole := overloadUnplacedFrom(overloadPlacement(t, records.endings, 4, d)); !whole {
			t.Errorf("the occupancy begun before the loss, first delivered after it, is not placed whole in its %v direction", d)
		}
		if p := overloadPlacement(t, records.endings, 3, d); p.Positions != connection.PositionsUnknownThroughout {
			t.Errorf("the occupancy first observed after the loss establishes %v in its %v direction: its first observation "+
				"is not evidence that nothing of it was lost before", p.Positions, d)
		}
	}
	for d, stood := range map[fragment.Direction]uint64{fragment.Sent: uint64(len(request)), fragment.Received: uint64(len(response))} {
		if from, whole := overloadUnplacedFrom(overloadPlacement(t, records.endings, 1, d)); !whole && from < stood {
			t.Errorf("the connection live across the loss lost its %v positions from %d, below the %d it had established",
				d, from, stood)
		}
	}
}

// A loss located to a connection stays where it was found: an unlocated loss,
// a fresh connection placed whole after it, and later transfers of the
// connection itself do not re-establish what the hole cost.
func TestIndependentRecoveryNeverClearsALocatedHole(t *testing.T) {
	records := &overloadRecords{}
	c := overloadCaptureOn(records, records)
	const first = "GET /first HTTP/1.1\r\n\r\n"
	c.begin(1, true)
	c.send(1, fragment.Sent, first)
	c.session.Transfer(c.transfer(1, fragment.Sent, "GET /after-the-hole HTTP/1.1\r\n\r\n", 1))
	c.unlocated = 1
	c.begin(2, true)
	c.send(2, fragment.Sent, "GET /fresh HTTP/1.1\r\n\r\n")
	c.close(2)
	c.send(1, fragment.Sent, "GET /later HTTP/1.1\r\n\r\n")
	c.close(1)
	if got := c.session.Stats().Lost; got != 1 {
		t.Fatalf("wiring, not the property: the hole reached capture as %d lost transfers, want 1", got)
	}

	p := overloadPlacement(t, records.endings, 1, fragment.Sent)
	if from, whole := overloadUnplacedFrom(p); whole || from > uint64(len(first)) {
		t.Errorf("the direction with a hole after offset %d is established to %d (whole %v)", len(first), from, whole)
	}
}
