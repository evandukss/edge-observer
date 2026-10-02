// Package capture turns what an adapter reports into fragment records: which
// connection a transfer belongs to, where its bytes sit in that connection's
// stream, and in what order they were seen.
//
// A transfer's place is checked against its producer's numbering of the
// handle's occupancy before its bytes are placed (probe.Sequence). A number
// missing on arrival is a transfer produced and not delivered, located to its
// connection and direction: that direction's positions stop being established
// where the missing bytes would have begun, and no other connection is
// touched. A connection's tail is settled by the last numbers its ending
// carries, or, for one still open when production stops, by what the producer
// still holds (probe.Settler); otherwise it is explicitly unsettled. A loss the
// producer could place in no occupancy costs every connection live across it,
// and every connection begun after it, their positions from where each stood.
package capture

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

// Sink is where the records go.
type Sink interface {
	Write(fragment.Record) error
}

// Stats is what a session has seen.
type Stats struct {
	// GateRefused counts transfers discarded at the held-event bound. IntakeRefused
	// counts fragments discarded at the volatile byte bound. Neither is a producer
	// loss: Lost counts missing producer transfers separately. Cut counts the
	// affected directions once, including directions cut by either refusal.
	GateRefused   int64 `json:"gate_refused"`
	IntakeRefused int64 `json:"intake_refused"`

	// Transfers is what adapters reported.
	Transfers int64 `json:"transfers"`

	// Empty is the transfers that moved no bytes. Counted, because a capture
	// seeing only these is attached to the wrong thing.
	Empty int64 `json:"empty"`

	// Early is the transfers that carried TLS 1.3 early data.
	Early int64 `json:"early"`

	// Unmeasured is the transfers whose size nothing could read. Nothing after
	// them in the stream can be placed.
	Unmeasured int64 `json:"unmeasured"`

	// Records is what was placed in a stream and handed on.
	Records int64 `json:"records"`

	// Connections is how many distinct connections have been seen.
	Connections int64 `json:"connections"`

	// Closed is how many of them the runtime has since ended.
	Closed int64 `json:"closed"`

	// Rejected is the records the sink refused. Capture carries on regardless:
	// observation must never block the observed process.
	Rejected int64 `json:"rejected"`

	// Unattributed is the transfers whose admitted execution the backend could
	// not name. Their fragments are placed, but the connection has no identity,
	// so no connection record can be written for it.
	Unattributed int64 `json:"unattributed"`

	// EndingsUnmatched is connection endings for a handle this session followed
	// nothing on: never transferred, reported twice, or unattributable. Counted,
	// because an unmatched ending and a missing one otherwise look alike.
	EndingsUnmatched int64 `json:"endings_unmatched"`

	// Lost is the transfers missing from their own connection's sequence: numbers
	// the producer took and never delivered, each located to one connection and
	// direction. It counts transfers, not bytes: a lost transfer's length went
	// with it.
	Lost int64 `json:"lost"`

	// Cut is the directions whose positions stopped being established while their
	// connection was followed, for any reason a placement names.
	Cut int64 `json:"cut"`

	// Retired is the connections ended because the producer began another
	// occupancy of their handle: their own ending was never delivered, so their
	// tails are unsettled.
	Retired int64 `json:"retired"`

	// Unsequenced is the transfers the producer kept no sequence for, whose
	// connections' positions nothing can check.
	Unsequenced int64 `json:"unsequenced"`

	// Unlocated is the producer's count of losses it could place in no
	// occupancy, the highest any observation carried. Above zero, every
	// connection live across one of them and every connection begun after it
	// lost its positions from where it stood.
	Unlocated int64 `json:"unlocated"`

	// ConnectionsUnrecorded is connection records the sink refused,
	// never folded into Rejected.
	ConnectionsUnrecorded int64 `json:"connections_unrecorded"`
}

// stream is what is known about one connection.
type stream struct {
	// lifetime is whether this run could observe the handle's release. Without
	// it, no binding is bounded in time, so an established binding is reported
	// invalidated and the ending unestablished.
	lifetime bool

	id         fragment.ConnectionID
	process    fragment.Process
	instance   admission.Instance
	generation connection.Generation
	// network is the admitted execution's namespace, not any socket's.
	network   connection.Netns
	endpoint  uint64
	firstSeen time.Time

	// opened is when the socket beneath this handle was created, where this run
	// saw it. It is not firstSeen (the first transfer): conflating them would date
	// every pre-existing connection from the observer's arrival. Zero means the
	// socket predates the probes.
	opened   time.Time
	sequence uint64

	// offsets is the bytes crossed so far per direction: where the next fragment
	// begins.
	offsets map[fragment.Direction]uint64

	// early is what arrived before the handshake finished: byte ranges, or a count
	// where nothing measured it.
	early     []connection.Early
	earlySeen int

	// placement is what is known about each direction's positions. No entry means
	// fully placeable.
	placement map[fragment.Direction]placement

	// association is what each direction's transfers established about the
	// socket, folded as they arrive.
	association map[fragment.Direction]*binding

	// begun is why this stream's associations are unknown. A stream begun after a
	// loss no occupancy could take may have lost the observation that would have
	// named its binding, which differs from nothing having been observed.
	begun connection.Reason

	// occupancy is the producer's occupancy of the handle this stream follows;
	// zero for a stream begun by a transfer the producer numbered nothing for.
	occupancy uint64
	born      bool
	loss      *held.Loss

	// numbered is the last producer number seen in each direction.
	numbered map[fragment.Direction]uint64

	// empties is the numbered transfers of each direction that moved no bytes
	// since its last fragment, which that direction's next fragment carries.
	empties map[fragment.Direction]uint64

	// droppedBelow is the producer's refused-reservation count as of the last
	// number seen in each direction (carried on that event). settleLocked subtracts
	// it from the occupancy's final dropped total so the tail counts only the drops
	// below it that capture has not already located, and never a non-drop gap.
	droppedBelow map[fragment.Direction]uint64

	// unlocated is the producer's count of losses no occupancy could take, as of
	// this stream's last observation.
	unlocated uint64
}

// binding is what a direction's transfers established about their socket.
// The fold keeps the last value, because a binding has a lifetime, and
// remembers whether one was ever established: a connection that never had one
// marks a process this run cannot follow at all.
type binding struct {
	state      probe.Bound
	descriptor connection.Descriptor
	generation connection.Generation
	socket     connection.Socket

	// endpoints are the socket's own, read at the same hook as the identity. A
	// binding whose endpoints were unreadable keeps the binding.
	endpoints connection.Endpoints

	// attempted is whether an endpoint producer ran, separating a failed read from
	// a build with no producer.
	attempted bool

	// observed is whether anything was established: a binding, an ambiguity or an
	// invalidation. ever is narrower: whether a binding was ever established. An
	// ambiguity is an observation, so the fold is gated on observed; ever decides
	// only what a later call without socket work inherits.
	observed bool
	ever     bool
	from     time.Time
	until    time.Time
	open     bool

	// basis is what the binding rests on: this call's own I/O, or an earlier
	// call's restated. Folded here because the transfer is gone by association
	// time.
	basis connection.Basis

	// outcome is what the last transfer's own kernel I/O came to, which says why
	// a direction has no binding: an ordinary file, an unfollowed route, or no I/O.
	// The last one wins, as the binding's fold does.
	outcome probe.SocketOutcome
}

// placement is one direction's answer to whether its bytes can be placed: the
// first offset not established and why. lost is the transfers known missing
// from the direction, and uncounted, where set, why that count is not the
// whole of it.
type placement struct {
	from      uint64
	because   connection.Reason
	lost      int64
	uncounted string
}

// key is one open connection: the admission key and the library's handle.
// Neither a handle address nor a pid is an identity alone, since both are
// reused.
type key struct {
	instance admission.Key
	endpoint uint64
}

// Session is one run of capture.
type Session struct {
	sink    Sink
	records connection.Sink

	mutex   sync.Mutex
	streams map[key]*stream
	// churn sheds what the closing of connections leaves in streams, whose keys
	// are handles of executions that never return.
	churn held.Churn
	// next numbers connections. A connection's id is also its handle's
	// generation: unique among every occupancy of every handle this session
	// follows, so an address reused is a new connection without any record of
	// the occupancies before it.
	next  fragment.ConnectionID
	stats Stats

	// settlers answer, once production has stopped, what each producer still
	// holds for a connection whose ending never arrived. Several, because one
	// capture can be fed by several producers.
	settlers []probe.Settler

	// observing is what the attachment feeding this session can establish, as
	// the kernel confirmed it. It decides what an absence means: no binding source
	// placed means every association is unknown, and no release probe means no
	// lifetime is bounded. Its zero value is a capability nobody supplied, not one
	// that can do nothing.
	observing probe.Capability
}

// Settling adds a producer that can say, once production has stopped, what it
// still holds. Each producer feeding this session adds itself.
func (s *Session) Settling(settler probe.Settler) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.settlers = append(s.settlers, settler)
}

// Observing tells this session what its attachment can establish. It is set
// after the probes are placed, when the kernel's answer exists.
func (s *Session) Observing(capability probe.Capability) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.observing = capability
}

// New starts a session writing fragments to sink and handing connection
// records to nobody.
func New(sink Sink) *Session { return Recording(sink, nil) }

// Option configures a session at construction.
type Option func(*Session)

// Settles gives a session a producer that can say, once production has
// stopped, what it still holds.
func Settles(settler probe.Settler) Option {
	return func(s *Session) { s.settlers = append(s.settlers, settler) }
}

// Recording starts a session that also hands each connection's record to
// records, once the record stops changing: at the connection's end, or at
// Finish for one still open.
func Recording(sink Sink, records connection.Sink, options ...Option) *Session {
	session := &Session{
		sink:    sink,
		records: records,
		streams: make(map[key]*stream),
	}
	for _, option := range options {
		option(session)
	}
	return session
}

// told reports whether anything said what this session's attachment can do; a
// capability naming no backend is one nobody supplied.
func (s *Session) told() bool { return s.observing.Backend != "" }

// Transfer places one transfer in its stream and hands the record on.
func (s *Session) Transfer(t probe.Transfer) {
	s.mutex.Lock()

	s.stats.Transfers++
	if t.Early {
		s.stats.Early++
	}
	// A transfer carrying an occupancy and no number moved nothing: an
	// out-parameter call that failed or ended. It takes no place.
	moved := t.Sequence.Occupancy == 0 || t.Sequence.Number != 0
	if !t.Measured {
		// How much the call moved is unknowable. Counted, and nothing after it in the
		// stream has an offset.
		s.stats.Unmeasured++
		if moved || t.Early {
			found := s.follow(t)
			if t.Early {
				// Followed anyway, so what it carried early is not lost.
				found.earlySeen++
			}
			if moved {
				s.number(found, t)
				// The transfer arrived, so nothing is counted missing: what is unknown is
				// where anything after it sits.
				s.cutLocked(found, t.Direction, found.offsets[t.Direction], connection.LengthUnmeasured, 0, "")
			}
		}
		s.mutex.Unlock()
		return
	}
	if t.Length == 0 && t.Sequence.Number == 0 {
		// No bytes, no hole, nothing to place.
		s.stats.Empty++
		s.mutex.Unlock()
		return
	}

	found := s.follow(t)
	s.number(found, t)
	if t.Length == 0 {
		// Numbered and moved nothing: no fragment, and the next one says so, so
		// its number is not read as following a transfer never delivered.
		s.stats.Empty++
		found.empties[t.Direction]++
		s.mutex.Unlock()
		return
	}
	if found.loss.Reason() != "" {
		s.mutex.Unlock()
		return
	}
	found.sequence++
	record := fragment.Record{
		Loss:       found.loss,
		Process:    t.Process,
		Connection: found.id,
		Direction:  t.Direction,
		Sequence:   found.sequence,
		Offset:     found.offsets[t.Direction],
		Length:     t.Length,
		Produced:   t.Sequence.Number,
		Empties:    found.empties[t.Direction],
		Payload:    t.Payload,
		At:         t.At,
		Slot:       t.Slot,
	}
	found.empties[t.Direction] = 0
	if t.Early {
		found.early = append(found.early, connection.Early{
			Direction: t.Direction, Offset: record.Offset, Length: t.Length,
		})
	}
	found.bind(t)
	// Advance by what the call transferred, not what was kept, so a truncated
	// payload leaves a visible hole.
	found.offsets[t.Direction] += uint64(t.Length)
	s.mutex.Unlock()

	err := s.sink.Write(record)

	s.mutex.Lock()
	if err != nil {
		s.stats.Rejected++
		s.stats.IntakeRefused++
		found.loss.Stop("intake_exhausted")
		s.cutLocked(found, t.Direction, record.Offset, connection.ObservationLost, 0, "volatile intake refused a fragment")
	} else {
		s.stats.Records++
	}
	s.mutex.Unlock()
}

// Refused takes the number of a transfer the delivery gate refused as seen, so
// a refusal is never counted as a transfer lost, and grows nothing else: a
// refused event reaches no stream, and one of a handle this session follows
// nothing on begins none. A loss before it in its occupancy is still a loss.
// The gate's refusal invalidates every pending release capture-wide, which is
// what keeps a release from crossing the refused bytes.
func (s *Session) Refused(t probe.Transfer) {
	if t.Sequence.Number == 0 {
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stats.GateRefused++
	found, open := s.streams[key{instance: t.Instance.Key(), endpoint: t.Endpoint}]
	if !open || found.occupancy != t.Sequence.Occupancy {
		return
	}
	found.loss.Stop("input_limit")
	s.cutLocked(found, t.Direction, found.offsets[t.Direction], connection.ObservationLost, 0, "the held-event bound refused a transfer")
	last := found.numbered[t.Direction]
	if t.Sequence.Number <= last {
		return
	}
	if t.Sequence.Number > last+1 {
		// A gap below a refused transfer's number is not the refusal's loss: the gate
		// refused this one deliberately and supplied its number, and the missing ones
		// are events admitted but not delivered, counted as abandoned (the kernel's
		// LostAfterSubmission), not here. The direction is cut so no exchange is
		// written across the gap (C9), but the refusal adds nothing to the located
		// loss count.
		s.cutLocked(found, t.Direction, found.offsets[t.Direction], connection.ObservationLost, 0,
			"a transfer the delivery gate refused numbered past the last delivered; the transfers "+
				"between are counted as abandoned, not here")
	}
	found.numbered[t.Direction] = t.Sequence.Number
	// A gate-refused transfer is still an event the producer put on the ring, so it
	// carries the drops below its number; it advances the last seen number, so the
	// tail counts only drops above it (settleLocked).
	found.droppedBelow[t.Direction] = t.Sequence.Dropped
}

// number reads one transfer's place in its occupancy before its bytes are
// placed, and stops the direction's positions where its evidence says they
// stop. The caller holds the lock.
//
// Under OpenSSL's supported use one call at a time is in flight per handle and
// direction, so the producer reserves a direction's events in the order of
// their numbers and they arrive in that order (struct occupancy,
// bpf/ssl.bpf.h). A number past the next is that many transfers lost here,
// and only here. A number at or behind one already seen, or a direction the
// producer saw two calls overlap in, is the supported use broken: the order of
// its bytes is not established from there.
func (s *Session) number(found *stream, t probe.Transfer) {
	direction := t.Direction
	at := found.offsets[direction]
	sequence := t.Sequence

	s.unlocatedLocked(found, sequence.Unlocated)

	if sequence.Occupancy == 0 {
		// The handle has no occupancy, so neither direction's numbers are kept.
		s.stats.Unsequenced++
		for _, each := range []fragment.Direction{fragment.Sent, fragment.Received} {
			s.cutLocked(found, each, found.offsets[each], connection.SequenceUnavailable, 0,
				"the producer kept no sequence for the connection's handle")
		}
		return
	}
	if sequence.Overlapped {
		s.cutLocked(found, direction, at, connection.OperationsOverlapped, 0,
			"two calls in the direction overlapped, so whether any of their bytes is missing is unknown")
	}
	last := found.numbered[direction]
	switch {
	case sequence.Number == last+1:
	case sequence.Number > last+1:
		missing := int64(sequence.Number - last - 1)
		s.stats.Lost += missing
		s.cutLocked(found, direction, at, connection.ObservationLost, missing, "")
	default:
		s.cutLocked(found, direction, at, connection.OperationsOverlapped, 0,
			"a transfer arrived behind one already seen, so whether any is missing is unknown")
	}
	if sequence.Number > last {
		found.numbered[direction] = sequence.Number
		// The drops below this number, carried on its event, so settleLocked counts
		// only the tail drops this has not already located.
		found.droppedBelow[direction] = sequence.Dropped
	}
}

// unlocatedLocked applies the conservative rule for a loss the producer could
// place in no occupancy, counted before this observation was produced: it may
// have been this connection's, anywhere after where the stream stood at its
// last observation, so every direction stops there. The caller holds the lock.
func (s *Session) unlocatedLocked(found *stream, unlocated uint64) {
	if unlocated > uint64(s.stats.Unlocated) {
		s.stats.Unlocated = int64(unlocated)
	}
	if unlocated <= found.unlocated {
		return
	}
	found.unlocated = unlocated
	if found.born {
		return
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		s.cutLocked(found, direction, found.offsets[direction], connection.ObservationLost, 0,
			"the producer lost a transfer it could place in no connection while this one was live")
	}
}

// cutLocked stops one direction's established positions at an offset, for a
// reason. An earlier cut stands: the first is where the positions stopped
// being established, and its reason the one that stopped them. lost transfers
// are added to the direction's count; why says why the count is not the whole
// of it, and is empty where it is. The direction is carried from here, so a
// direction whose every transfer was lost still has its placement. The caller
// holds the lock.
func (s *Session) cutLocked(found *stream, direction fragment.Direction, from uint64, because connection.Reason,
	lost int64, why string) {
	if _, carried := found.offsets[direction]; !carried {
		found.offsets[direction] = 0
	}
	if found.placement == nil {
		found.placement = make(map[fragment.Direction]placement, 2)
	}
	held, cut := found.placement[direction]
	if !cut {
		held = placement{from: from, because: because}
		s.stats.Cut++
	}
	held.lost += lost
	if why != "" && held.uncounted == "" {
		held.uncounted = why
	}
	found.placement[direction] = held
}

// follow is the stream a transfer belongs to, begun if new. A transfer of an
// occupancy other than the stream's is the producer's word that the handle was
// released and reused: the stream it found is retired with an unsettled tail,
// since its own ending never arrived. The caller holds the lock.
func (s *Session) follow(t probe.Transfer) *stream {
	place := key{instance: t.Instance.Key(), endpoint: t.Endpoint}
	found, open := s.streams[place]
	if open {
		if t.Sequence.Occupancy == 0 || found.occupancy == 0 || found.occupancy == t.Sequence.Occupancy {
			return found
		}
		s.retireLocked(place, found, t.At)
	}

	if err := t.Instance.Validate(); err != nil {
		// The execution is unnamed, so the connection has no identity; its fragments
		// are still placed and counted here.
		s.stats.Unattributed++
	}

	begun := connection.NoBindingObserved
	if t.Sequence.Unlocated > 0 && !t.Sequence.Born {
		// A loss no occupancy could take fell before this stream began, so this
		// stream's binding evidence, and its first transfers, may be lost: a statement
		// about losses, not coverage.
		begun = connection.ObservationLost
	}
	if s.told() && !s.observing.Binding {
		// Outranks both: nothing placed could observe a binding at all.
		begun = connection.BindingUnobservable
	}

	s.next++
	found = &stream{
		lifetime:     !s.told() || s.observing.Lifecycle,
		id:           s.next,
		process:      t.Process,
		instance:     t.Instance,
		network:      connection.Netns{Device: t.Network.Device, Inode: t.Network.Inode},
		generation:   connection.Generation(s.next),
		endpoint:     t.Endpoint,
		firstSeen:    t.At,
		opened:       t.Ends.OpenedAt,
		offsets:      make(map[fragment.Direction]uint64, 2),
		begun:        begun,
		occupancy:    t.Sequence.Occupancy,
		born:         t.Sequence.Born,
		loss:         &held.Loss{},
		numbered:     make(map[fragment.Direction]uint64, 2),
		empties:      make(map[fragment.Direction]uint64, 2),
		droppedBelow: make(map[fragment.Direction]uint64, 2),
		unlocated:    t.Sequence.Unlocated,
	}
	if t.Sequence.Unlocated > 0 && t.Sequence.Occupancy != 0 && !t.Sequence.Born {
		// The conservative rule for a stream begun after a loss nothing located:
		// its first transfers may be the ones lost, so no offset is established. A
		// stream with no sequence establishes none anyway, for its own reason.
		for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
			s.cutLocked(found, direction, 0, connection.ObservationLost, 0,
				"the producer lost a transfer it could place in no connection before this one began")
		}
	}
	s.streams[place] = found
	s.stats.Connections++
	return found
}

// retireLocked ends a stream whose occupancy the producer replaced. Its last
// transfers and its ending were never delivered, so nothing settles its tail.
// The record goes to the sink under the lock, which must do bounded storage
// work, never parsing or durable output. The caller holds the lock.
func (s *Session) retireLocked(place key, found *stream, at time.Time) {
	s.unsettledLocked(found, "the connection's ending was never delivered, so whether its last transfers "+
		"arrived is unknown")
	record := found.record(connection.EndingUnobserved, at)
	s.streams = held.Deleted(s.streams, place, &s.churn)
	s.stats.Retired++
	if s.records == nil {
		return
	}
	if err := s.records.Connection(record); err != nil {
		s.stats.ConnectionsUnrecorded++
	}
}

// unsettledLocked cuts both directions where they stand, for want of terminal
// evidence. The caller holds the lock.
func (s *Session) unsettledLocked(found *stream, why string) {
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		s.cutLocked(found, direction, found.offsets[direction], connection.TerminalUnsettled, 0, why)
	}
}

// settleLocked reads a stream's tail against its occupancy's last numbers.
// A last number past the one seen is that many transfers lost at the end. A
// call still in flight at a release is the supported use broken: its bytes
// may belong to the stream. ending says the final came with the connection's
// ending rather than from the producer once production stopped, where a call
// in flight has moved nothing yet that belongs before the boundary. The
// caller holds the lock.
func (s *Session) settleLocked(found *stream, final probe.Final, ending bool) {
	if !final.Known {
		s.unsettledLocked(found, "the producer held no occupancy for the connection when it ended, so "+
			"whether its last transfers arrived is unknown")
		return
	}
	for _, one := range []struct {
		direction fragment.Direction
		terminal  probe.Terminal
	}{{fragment.Sent, final.Sent}, {fragment.Received, final.Received}} {
		at := found.offsets[one.direction]
		last := found.numbered[one.direction]
		// The number is taken at entry, so a call in flight when the occupancy ended
		// has already advanced the terminal past what was delivered. That one number
		// is the in-flight call, not a lost transfer: it is excluded from the lost
		// count and leaves the direction unsettled instead.
		terminal := one.terminal.Last
		if one.terminal.InFlight && terminal > 0 {
			terminal--
		}
		switch {
		case terminal > last:
			missing := int64(terminal - last)
			located := missing
			if !ending {
				// An open connection settled at session end. Only the producer's refused
				// ring reservations in the tail are located losses (decision 476): the
				// occupancy's final dropped total, less the drops already BELOW the last
				// number seen (carried on that event, droppedBelow), is the tail's drops.
				// Subtracting the drops below, not every gap below, is what keeps a non-drop
				// gap - a sendfile number, an unmeasurable return, a refused return, a
				// nested call - from hiding a real tail drop. Counting the producer's own
				// failed reservations, not the shortfall, is what counts a drop that sits
				// below a later submitted-but-abandoned event and leaves the abandoned
				// event and those non-drop gaps as the uncounted, explicitly incomplete
				// tail (decision 475).
				located = int64(one.terminal.Dropped) - int64(found.droppedBelow[one.direction])
				if located < 0 {
					located = 0
				}
				if located > missing {
					located = missing
				}
			}
			if located > 0 {
				// A connection the producer saw end counts its whole shortfall; an open one
				// with a refused reservation in its tail counts those drops. The direction
				// is cut from where it stood: any abandoned events beyond the drops lie
				// inside the cut, uncounted here and counted on their own counter.
				s.stats.Lost += located
				s.cutLocked(found, one.direction, at, connection.ObservationLost, located, "")
			} else {
				// No refused reservation accounts for the shortfall: an event submitted and
				// not drained, a return refused for a lost grant, or a nested call. The
				// direction is cut so no exchange spans it, counted on its own counter.
				s.cutLocked(found, one.direction, at, connection.TerminalUnsettled, 0,
					"the producer numbered transfers past the last delivered that the session end did not "+
						"deliver and that no refused reservation accounts for; counted as incomplete, not lost")
			}
		case terminal < last:
			s.cutLocked(found, one.direction, at, connection.TerminalUnsettled, 0,
				"the producer's last number is behind one delivered, so the direction's evidence disagrees")
		}
		if ending && one.terminal.InFlight {
			s.cutLocked(found, one.direction, at, connection.TerminalUnsettled, 0,
				"a call in the direction was still in flight when the handle was released")
		}
	}
}

// Closed ends this occupancy of a handle, so the handle can be reused without
// its stream continuing. It is not proof the peer went away: SSL_free is
// reference counted and SSL_clear recycles a handle in place.
func (s *Session) Closed(c probe.Connection) {
	s.mutex.Lock()

	place := key{instance: c.Instance.Key(), endpoint: c.Endpoint}
	found, open := s.streams[place]
	if !open {
		// Ended without a transfer seen, ended twice, or unattributable: counted.
		s.stats.EndingsUnmatched++
		s.mutex.Unlock()
		return
	}
	if c.Sequence.Occupancy != 0 && found.occupancy != 0 && c.Sequence.Occupancy != found.occupancy {
		// The ending of a later occupancy, every transfer of which was lost: this
		// stream's own ending never arrived.
		s.retireLocked(place, found, c.At)
		s.stats.EndingsUnmatched++
		s.mutex.Unlock()
		return
	}
	s.unlocatedLocked(found, c.Sequence.Unlocated)
	s.settleLocked(found, c.Final, true)
	s.streams = held.Deleted(s.streams, place, &s.churn)
	s.stats.Closed++
	how := connection.HandleReleasedEnding
	if c.Final.Exited {
		// The execution ended holding the handle: the ending is known and was not
		// observed as a release.
		how = connection.EndingUnobserved
	}
	record := found.record(how, c.At)
	s.mutex.Unlock()

	// The ending's slot goes with the record it produced, to whatever retains it.
	record.Slot = c.Slot
	s.write(record)
}

// Finish writes a record for every open connection, each with its tail
// settled against what its producer still holds, or explicitly unsettled.
// Called once, by whatever seals the run, after production has stopped and
// the producers have drained: then nothing can take a number unseen.
//
// Records distinguish a connection the run outlived from one that closed.
func (s *Session) Finish(at time.Time) {
	s.mutex.Lock()
	open := make([]connection.Record, 0, len(s.streams))
	for place, found := range s.streams {
		s.finalLocked(found)
		open = append(open, found.record(connection.StillOpen, at))
		delete(s.streams, place)
	}
	slices.SortFunc(open, func(x, y connection.Record) int { return int(x.ID) - int(y.ID) })
	s.mutex.Unlock()

	for _, record := range open {
		s.write(record)
	}
}

// finalLocked settles a stream still open when production stopped, against
// the one producer holding its occupancy. No producer holding it, two
// claiming it, one holding another occupancy there, or one that cannot be
// read leaves the tail unsettled. The caller holds the lock.
func (s *Session) finalLocked(found *stream) {
	if found.occupancy == 0 {
		// Already unplaceable for want of a sequence.
		return
	}
	handle := probe.Handle{Instance: found.instance.Key(), Endpoint: found.endpoint}
	var holder probe.Settler
	var held probe.Settlement
	for _, settler := range s.settlers {
		one, err := settler.Settled(handle)
		if err != nil {
			s.unsettledLocked(found, "the producer's occupancies could not be read when production stopped: "+
				err.Error())
			return
		}
		if one.Occupancy == 0 {
			continue
		}
		if holder != nil {
			s.unsettledLocked(found, "two producers hold an occupancy for the connection's handle")
			return
		}
		holder, held = settler, one
	}
	switch {
	case holder == nil:
		s.unsettledLocked(found, "no producer held the connection's occupancy when production stopped, so "+
			"its ending, and whether its last transfers arrived, are unknown")
		return
	case held.Occupancy != found.occupancy:
		s.unsettledLocked(found, "the producer had begun another occupancy of the handle, so the "+
			"connection's ending was never delivered")
		return
	}
	unlocated, err := holder.Unlocated()
	if err != nil {
		s.unsettledLocked(found, "the producer's count of losses it could place nowhere could not be read: "+
			err.Error())
		return
	}
	s.unlocatedLocked(found, unlocated)
	s.settleLocked(found, held.Final, false)
}

// write hands on one record, counting a refusal on its own counter.
func (s *Session) write(record connection.Record) {
	if s.records == nil {
		return
	}
	err := s.records.Connection(record)

	s.mutex.Lock()
	if err != nil {
		s.stats.ConnectionsUnrecorded++
	}
	s.mutex.Unlock()
}

// bind folds what one transfer established into its direction's binding. The
// caller holds the lock.
func (t *stream) bind(one probe.Transfer) {
	if t.association == nil {
		t.association = make(map[fragment.Direction]*binding, 2)
	}
	held, following := t.association[one.Direction]
	if !following {
		held = &binding{from: one.At, open: true}
		t.association[one.Direction] = held
	}
	held.until = one.At
	held.outcome = one.Outcome

	switch one.Bound {
	case probe.BoundTo:
		if held.state == probe.BoundTo && held.generation == connection.Generation(one.Binding) &&
			held.descriptor == connection.Held(one.Descriptor) {
			// Same binding, still valid: only its interval widens.
			return
		}
		held.state = probe.BoundTo
		held.descriptor = connection.Held(one.Descriptor)
		held.generation = connection.Generation(one.Binding)
		held.observed = true
		held.ever = true
		held.from = one.At
		held.open = true
		held.basis = basisOf(one.Outcome)
		held.socket = connection.Named(one.Socket)
		held.endpoints = endpointsOf(one.Ends)
		held.attempted = one.Ends.Attempted
	case probe.BoundAmbiguously, probe.BoundInvalidated:
		// Both are observations: an ambiguity (socket work on several descriptors) and
		// an invalidation (a binding that stopped being trustworthy).
		held.state = one.Bound
		held.descriptor = connection.Held(one.Descriptor)
		held.generation = connection.Generation(one.Binding)
		held.observed = true
		held.open = false
	default:
		// Nothing established for this call. It does not undo an earlier binding: a
		// buffered read inherits a still-valid one, which the adapter applies where it
		// can.
		if !held.observed {
			held.state = probe.NotBound
		}
	}
}

// basisOf is what a bound transfer's binding rests on. The split is at
// NoKernelIO, not SocketIO: a call's outcome is the worst of its operations,
// so a call with socket I/O plus an unresolved operation still established its
// own binding. Only a call with no I/O carries an earlier binding forward. A
// backend that answers nothing leaves NoKernelIO, which is why Basis is not
// required on an established association.
func basisOf(outcome probe.SocketOutcome) connection.Basis {
	if outcome == probe.NoKernelIO {
		return connection.Continuity
	}
	return connection.ConfirmedInCall
}

// unresolved is the reason an unbound direction gives from its own I/O, or
// ReasonUnset where the outcome says nothing narrower. SocketIO is absent on
// purpose: socket I/O with no binding is explained upstream.
func unresolved(outcome probe.SocketOutcome) connection.Reason {
	switch outcome {
	case probe.FileIO:
		return connection.OperationWasNotASocket
	case probe.OperationUnresolved:
		return connection.OperationUnresolved
	case probe.RouteUnsupported:
		return connection.RouteUnsupported
	case probe.EvidenceUnreadable:
		return connection.EvidenceUnreadable
	case probe.FrameBroken:
		return connection.OperationFrameBroken
	default:
		return connection.ReasonUnset
	}
}

// associated is what this stream says about one direction's binding. Never
// having had one marks a process whose socket calls this run cannot see;
// having lost one is ordinary.
func (t *stream) associated(direction fragment.Direction) connection.Association {
	one := connection.Association{Connection: t.id, Direction: direction}

	// The join axis is answered for every association, starting at "does not
	// join".
	one.Join = connection.DoesNotJoin
	one.JoinReason = connection.NoBindingToJoin

	held, following := t.association[direction]
	if !following || !held.observed {
		one.State = connection.Unknown
		one.Reason = t.begun
		if following {
			// What the call's own I/O came to overrides the stream-level reason, being
			// narrower. A backend that does not answer leaves the stream-level reason.
			if because := unresolved(held.outcome); because != connection.ReasonUnset {
				one.Reason = because
			}
		}
		one.JoinReason = connection.NoBindingToJoin
		return one
	}

	one.Descriptor = held.descriptor
	one.Binding = held.generation
	one.Socket = held.socket
	one.Source = connection.InCallSyscall
	switch held.state {
	case probe.BoundTo:
		if !t.lifetime {
			// Nothing bounds the binding's lifetime: the handle address may have been
			// reused unseen. Bytes are kept and the association invalidated; no claim is
			// made about when a reuse happened.
			one.State = connection.Invalidated
			one.Reason = connection.HandleLifetimeUnobservable
			one.JoinReason = connection.NoBindingToJoin
			one.Valid = connection.Between(held.from, held.until)
			return one
		}
		one.State = connection.Established
		one.Basis = held.basis
		one.Valid = connection.Since(held.from)
		if !held.open {
			one.Valid = connection.Between(held.from, held.until)
		}
		// The socket's own addresses, read where it was acquired. A binding whose
		// addresses are unreadable keeps the binding and carries none of them.
		//
		// The namespace is the socket's own, never the process's: a socket inherited
		// across a namespace transition or passed in belongs to the namespace it was
		// created in (connection.Record.Network).
		one.Endpoints = held.endpoints

		// Joinability is decided here from what the addresses came to, with the reason
		// this association actually had: the two reads fail independently.
		switch {
		case one.Endpoints.Complete():
			one.Join = connection.Joins
			one.JoinReason = connection.JoinReasonUnset
		case !one.Endpoints.Local.Known || !one.Endpoints.Remote.Known:
			one.Join = connection.DoesNotJoin
			// Whether a producer ran is the backend's to say, not this layer's to guess.
			one.JoinReason = connection.NoEndpointProducer
			if held.attempted {
				one.JoinReason = connection.EndpointUnreadable
			}
		default:
			one.Join = connection.DoesNotJoin
			one.JoinReason = connection.NamespaceUnestablished
		}
	case probe.BoundAmbiguously:
		one.State = connection.Ambiguous
		one.Reason = connection.SeveralDescriptors
		one.JoinReason = connection.NoBindingToJoin
		// The window's descriptors as the adapter names them: the first seen, and a
		// second it does not name. Both are carried.
		one.Contended = []connection.Descriptor{held.descriptor, connection.Unheld()}
		one.Descriptor = connection.Unheld()
		one.Binding = 0
	default:
		one.State = connection.Invalidated
		one.Reason = connection.DescriptorReplaced
		one.JoinReason = connection.NoBindingToJoin
		one.Valid = connection.Between(held.from, held.until)
	}
	return one
}

// endpointsOf converts the program's raw endpoints to the record's shape.
// Addresses arrive 16 bytes wide, v4 as v4-mapped, and are unmapped here.
// Known comes from the program's own flag, since all-zero is a real address.
func endpointsOf(ends probe.Ends) connection.Endpoints {
	if !ends.Known {
		return connection.Endpoints{Netns: connection.Netns{Inode: ends.Netns}}
	}
	return connection.Endpoints{
		Local:  connection.At(netip.AddrFrom16(ends.Local).Unmap(), ends.LocalPort),
		Remote: connection.At(netip.AddrFrom16(ends.Peer).Unmap(), ends.PeerPort),
		// The kernel side names a socket's namespace by inode alone; the execution's
		// namespace on the record carries both from /proc.
		Netns: connection.Netns{Inode: ends.Netns},
	}
}

// placed is what this stream says about one direction's positions, stated
// even when whole. A cut at the direction's first byte establishes no offset.
func (t *stream) placed(direction fragment.Direction) connection.Placement {
	held, cut := t.placement[direction]
	if !cut {
		return connection.Placement{
			Connection: t.id,
			Direction:  direction,
			Positions:  connection.PositionsEstablished,
			Lost:       connection.Counted(0),
		}
	}
	one := connection.Placement{
		Connection: t.id,
		Direction:  direction,
		Positions:  connection.PositionsUnknownFrom,
		From:       held.from,
		Because:    held.because,
		Lost:       connection.Counted(held.lost),
	}
	if held.from == 0 {
		one.Positions, one.From = connection.PositionsUnknownThroughout, 0
	}
	if held.uncounted != "" {
		one.Lost = connection.Uncounted(held.uncounted)
	}
	return one
}

// record is this stream as a connection record. The caller holds the lock.
// Every association is present with its reason; a missing one would read as
// nothing observed.
func (t *stream) record(how connection.Ending, at time.Time) connection.Record {
	record := connection.Record{
		Loss: t.loss,
		ID:   t.id,
		Handle: connection.Handle{
			Instance:   t.instance.Key(),
			Address:    t.endpoint,
			Generation: t.generation,
		},
		Instance:        t.instance,
		Process:         t.process,
		Network:         t.network,
		FirstSeen:       t.firstSeen,
		Opened:          t.opened,
		OpenedKnown:     !t.opened.IsZero(),
		How:             how,
		Fragments:       connection.Counted(int64(t.sequence)),
		Early:           slices.Clone(t.early),
		EarlyUnmeasured: t.earlySeen,
	}
	if !t.lifetime && how == connection.StillOpen {
		// Nothing here could observe an ending, so whether it ended is not
		// established.
		record.How = connection.EndingUnestablished
	}
	if record.How != connection.StillOpen && record.How != connection.EndingUnestablished {
		record.Ended = at
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if _, carried := t.offsets[direction]; !carried {
			continue
		}
		record.Associations = append(record.Associations, t.associated(direction))
		record.Placements = append(record.Placements, t.placed(direction))
	}
	return record
}

// Stats is what this session has seen.
func (s *Session) Stats() Stats {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.stats
}

// Retained is what this session holds now, store by store: the connections it
// follows and the early-data ranges kept in them, and the producers it asks to
// settle. A connection's record leaves with it, to the records sink.
func (s *Session) Retained() ([]held.Occupancy, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	early := 0
	for _, found := range s.streams {
		early += len(found.early)
	}
	return []held.Occupancy{
		{Store: "capture.streams", Held: len(s.streams), Rebuilds: s.churn.Rebuilds()},
		{Store: "capture.early", Held: early},
		{Store: "capture.settlers", Held: len(s.settlers)},
	}, nil
}

// Open is the connections this session is still following.
func (s *Session) Open() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return len(s.streams)
}

// Counted is this session's part of the run's inventory: the transfer and
// fragment stages. The kernel side's counts are joined by the caller.
func (s *Session) Counted() connection.Counters {
	held := s.Stats()
	return connection.Counters{
		Transfers:        connection.Counted(held.Transfers),
		Empty:            connection.Counted(held.Empty),
		Unmeasured:       connection.Counted(held.Unmeasured),
		Fragments:        connection.Counted(held.Records),
		FragmentsRefused: connection.Counted(held.Rejected),
	}
}

// Live is a record for every connection still followed, as it stands now,
// built by the same producer the seal uses so the two cannot disagree. It
// changes nothing. It shows states that are gone by sealing, such as a binding
// ambiguous during a call. at is the caller's, so two readings are comparable.
func (s *Session) Live(at time.Time) []connection.Record {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	live := make([]connection.Record, 0, len(s.streams))
	for _, found := range s.streams {
		live = append(live, found.record(connection.StillOpen, at))
	}
	slices.SortFunc(live, func(x, y connection.Record) int { return int(x.ID) - int(y.ID) })
	return live
}
