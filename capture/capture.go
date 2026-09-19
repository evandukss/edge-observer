// Package capture turns what an adapter reports into fragment records: which
// connection a transfer belongs to, where its bytes sit in that connection's
// stream, and in what order they were seen.
package capture

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// Sink is where the records go.
type Sink interface {
	Write(fragment.Record) error
}

// Stats is what a session has seen.
type Stats struct {
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

	// Lost is the observations missing from the backend's production order. It
	// counts observations, not bytes: a lost observation's length went with it,
	// so later offsets cannot be recovered.
	Lost int64 `json:"lost"`

	// Interrupted is the connections retired because a loss fell while they were
	// live; each record says where its positions stop being established. Not
	// connection.Seal.Interrupted, which counts transfers refused at the read
	// boundary; reports call this one "retired".
	Interrupted int64 `json:"interrupted"`

	// Unstamped is observations with no place in the production order;
	// Disordered is those behind one already seen. Either costs the run its
	// ordering, and neither is Lost or Tolerated.
	Unstamped  int64 `json:"unstamped"`
	Disordered int64 `json:"disordered"`

	// Tolerated is gaps the backend accounted for as the producer's own
	// stamp-then-reserve race, costing no stream its positions. Zero is not a
	// pass: it may mean no race happened.
	Tolerated int64 `json:"tolerated"`

	// Unexplained is gaps confirmed because nothing could say whether anything
	// was taken from the order: the backend had not answered, or its read failed.
	// It separates those from gaps the backend confirmed.
	Unexplained int64 `json:"unexplained"`

	// ConnectionsUnrecorded is connection records produced and not persisted,
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
	// located loss may have lost the observation that would have named its
	// binding, which differs from nothing having been observed.
	begun connection.Reason
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

// placement is one direction's answer to whether its bytes can be placed,
// kept here so a loss can invalidate live streams as it is learned.
type placement struct {
	positions connection.Positions
	from      uint64
	because   connection.Reason
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
	// occupancies counts each key's uses, which is the handle generation: an
	// address reused is a new connection.
	occupancies map[key]connection.Generation
	closed      []connection.Record
	next        fragment.ConnectionID
	stats       Stats

	// stamp is the highest production-order position handed to this session. A
	// jump is a loss, and where it falls says which streams were live across it.
	stamp uint64

	// consumed asks the backend what it took out of the order and delivered
	// nothing for; taken is its last answer. Without a reader every gap is
	// confirmed.
	consumed func() (probe.Consumed, error)
	taken    probe.Consumed

	// interrupted is whether any loss has been located, which marks a stream
	// begun afterwards as one whose binding evidence may be lost.
	interrupted bool

	// ordered is whether this run has usable ordering evidence. It goes false at
	// the first unstamped or backward observation and stays false.
	ordered bool

	// observing is what the attachment feeding this session can establish, as
	// the kernel confirmed it. It decides what an absence means: no binding source
	// placed means every association is unknown, and no release probe means no
	// lifetime is bounded. Its zero value is a capability nobody supplied, not one
	// that can do nothing.
	observing probe.Capability
}

// Consuming gives a running session its backend's answer, once the attachment
// that can give it exists. Until then every gap is confirmed, which can
// over-invalidate but never suppresses a loss.
func (s *Session) Consuming(read func() (probe.Consumed, error)) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.consumed = read
}

// Observing tells this session what its attachment can establish. It is set
// after the probes are placed, when the kernel's answer exists.
func (s *Session) Observing(capability probe.Capability) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.observing = capability
}

// New starts a session writing fragments to sink and keeping connection
// records in memory for Records.
func New(sink Sink) *Session { return Recording(sink, nil) }

// Option configures a session at construction.
type Option func(*Session)

// Consumes gives a session a way to ask its backend whether anything was taken
// out of the order since it last asked. Without one, every gap is confirmed.
func Consumes(read func() (probe.Consumed, error)) Option {
	return func(s *Session) { s.consumed = read }
}

// Recording starts a session that also persists each connection's record to
// records, once the record stops changing: at the connection's end, or at
// Finish for one still open.
func Recording(sink Sink, records connection.Sink, options ...Option) *Session {
	session := &Session{
		sink:        sink,
		records:     records,
		streams:     make(map[key]*stream),
		occupancies: make(map[key]connection.Generation),
		ordered:     true,
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

	s.observe(t.Stamp, t.At)
	s.stats.Transfers++
	if t.Early {
		s.stats.Early++
	}
	if !t.Measured {
		// How much the call moved is unknowable. Counted, not placed: nothing after
		// it in the stream has an offset.
		s.stats.Unmeasured++
		if t.Early {
			// Followed anyway, so what it carried early is not lost.
			s.follow(t).earlySeen++
		}
		s.mutex.Unlock()
		return
	}
	if t.Length == 0 {
		// No bytes, no hole, nothing to place.
		s.stats.Empty++
		s.mutex.Unlock()
		return
	}

	found := s.follow(t)
	found.sequence++
	record := fragment.Record{
		Process:    t.Process,
		Connection: found.id,
		Direction:  t.Direction,
		Sequence:   found.sequence,
		Offset:     found.offsets[t.Direction],
		Length:     t.Length,
		Payload:    t.Payload,
		At:         t.At,
	}
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
	} else {
		s.stats.Records++
	}
	s.mutex.Unlock()
}

// observe reads one observation's place in the backend's production order and
// acts on what is missing since the last one. The caller holds the lock.
//
// The producer takes its stamp before reserving ring space, so a refused
// reservation leaves a hole in the numbering; this is the detection itself and
// must not be reordered (bpf/ssl.bpf.h, obs_emit). The cost: two producers can
// take numbers in one order and reserve in the other, so a jump is either lost
// or not yet handed over (reorderedLocked).
//
// Where a jump falls locates the loss: a stream that ended before it keeps its
// offsets; one live across it loses positions. An unstamped observation, a
// backward one, or a backend that does not stamp costs the run its ordering,
// and every live stream becomes unplaceable throughout.
func (s *Session) observe(stamp uint64, at time.Time) {
	switch {
	case stamp == 0:
		// No place in the order: counted, and located gaps are no longer claimed.
		s.stats.Unstamped++
		s.ordered = false
		return
	case s.stamp == 0:
		s.stamp = stamp
		return
	case stamp <= s.stamp:
		s.stats.Disordered++
		s.ordered = false
		s.stamp = max(s.stamp, stamp)
		return
	case stamp == s.stamp+1:
		s.stamp = stamp
		return
	}

	missing := stamp - s.stamp - 1
	s.stamp = stamp
	if s.reorderedLocked() {
		return
	}
	s.interruptLocked(missing, at)
}

// reorderedLocked reports whether a gap is the producer's stamp-then-reserve
// race rather than a loss, counting it if so, from counters the backend keeps.
// Both counters are consulted: a refused transfer takes a number deliberately
// so its gap invalidates.
//
// Either counter can move for an unrelated call between gaps, which confirms
// a gap that was only a reorder: over-invalidation, never a suppressed loss.
// No reader, or no answer, confirms the gap. The caller holds the lock.
func (s *Session) reorderedLocked() bool {
	if s.consumed == nil {
		s.stats.Unexplained++
		return false
	}
	now, err := s.consumed()
	if err != nil {
		s.stats.Unexplained++
		return false
	}
	moved := now.ReserveFailed != s.taken.ReserveFailed || now.Refused != s.taken.Refused
	s.taken = now
	if moved {
		return false
	}
	s.stats.Tolerated++
	return true
}

// interruptLocked retires every stream live across a located loss. A stamp gap
// locates a loss in the production order, not in a stream: the lost event
// named its own connection, so every live stream could be affected, while a
// stream that already ended keeps every offset.
//
// Retired rather than continued because the lost observation may have been
// the connection's end; the next transfer at that handle begins a new
// connection whose associations are unknown because an observation was lost.
// The caller holds the lock.
func (s *Session) interruptLocked(missing uint64, at time.Time) {
	s.stats.Lost += int64(missing)

	retired := make([]connection.Record, 0, len(s.streams))
	for place, found := range s.streams {
		for direction, offset := range found.offsets {
			held := placement{positions: connection.PositionsUnknownFrom, from: offset, because: connection.ObservationLost}
			if !s.ordered {
				held = placement{positions: connection.PositionsUnknownThroughout, because: connection.ObservationLost}
			}
			found.place(direction, held)
		}
		retired = append(retired, found.record(connection.EndingUnobserved, at))
		delete(s.streams, place)
		s.stats.Interrupted++
	}
	slices.SortFunc(retired, func(x, y connection.Record) int { return int(x.ID) - int(y.ID) })
	s.closed = append(s.closed, retired...)
	s.interrupted = true

	// Written under the lock: the caller already holds it and the sink is a local
	// append.
	for _, record := range retired {
		if s.records == nil {
			continue
		}
		if err := s.records.Connection(record); err != nil {
			s.stats.ConnectionsUnrecorded++
		}
	}
}

// place records one direction's positions. The caller holds the lock.
func (t *stream) place(direction fragment.Direction, held placement) {
	if t.placement == nil {
		t.placement = make(map[fragment.Direction]placement, 2)
	}
	t.placement[direction] = held
}

// follow is the stream a transfer belongs to, begun if new. The caller holds
// the lock.
func (s *Session) follow(t probe.Transfer) *stream {
	place := key{instance: t.Instance.Key(), endpoint: t.Endpoint}
	found, open := s.streams[place]
	if open {
		return found
	}

	if err := t.Instance.Validate(); err != nil {
		// The execution is unnamed, so the connection has no identity; its fragments
		// are still placed and counted here.
		s.stats.Unattributed++
	}

	begun := connection.NoBindingObserved
	if s.interrupted {
		// A loss was already located, so this stream's binding evidence may be lost:
		// a statement about losses, not coverage.
		begun = connection.ObservationLost
	}
	if s.told() && !s.observing.Binding {
		// Outranks both: nothing placed could observe a binding at all.
		begun = connection.BindingUnobservable
	}

	s.next++
	s.occupancies[place]++
	found = &stream{
		lifetime:   !s.told() || s.observing.Lifecycle,
		id:         s.next,
		process:    t.Process,
		instance:   t.Instance,
		network:    connection.Netns{Device: t.Network.Device, Inode: t.Network.Inode},
		generation: s.occupancies[place],
		endpoint:   t.Endpoint,
		firstSeen:  t.At,
		opened:     t.Ends.OpenedAt,
		offsets:    make(map[fragment.Direction]uint64, 2),
		begun:      begun,
	}
	s.streams[place] = found
	s.stats.Connections++
	return found
}

// Closed ends this occupancy of a handle, so the handle can be reused without
// its stream continuing. It is not proof the peer went away: SSL_free is
// reference counted and SSL_clear recycles a handle in place.
func (s *Session) Closed(c probe.Connection) {
	s.mutex.Lock()

	s.observe(c.Stamp, c.At)

	place := key{instance: c.Instance.Key(), endpoint: c.Endpoint}
	found, open := s.streams[place]
	if !open {
		// Ended without a transfer seen, ended twice, or unattributable: counted.
		s.stats.EndingsUnmatched++
		s.mutex.Unlock()
		return
	}
	delete(s.streams, place)
	s.stats.Closed++
	record := found.record(connection.HandleReleasedEnding, c.At)
	s.closed = append(s.closed, record)
	s.mutex.Unlock()

	s.write(record)
}

// Finish writes a record for every open connection, and accounts for a loss
// after the last observation handed over. Called once, by whatever seals the
// run.
//
// Records distinguish a connection the run outlived from one that closed.
// produced is how many observations the backend says it produced; without it
// a trailing loss is invisible, so unknown produced makes every open stream
// unplaceable throughout.
func (s *Session) Finish(at time.Time, produced connection.Count) {
	s.mutex.Lock()
	switch {
	case !produced.Known:
		// Unknown production: a trailing loss cannot be told from a tidy end.
		s.ordered = false
		s.interruptLocked(0, at)
	case produced.Value > int64(s.stamp):
		s.interruptLocked(uint64(produced.Value)-s.stamp, at)
	}

	open := make([]connection.Record, 0, len(s.streams))
	for place, found := range s.streams {
		open = append(open, found.record(connection.StillOpen, at))
		delete(s.streams, place)
	}
	slices.SortFunc(open, func(x, y connection.Record) int { return int(x.ID) - int(y.ID) })
	s.closed = append(s.closed, open...)
	s.mutex.Unlock()

	for _, record := range open {
		s.write(record)
	}
}

// write persists one record, counting a refusal on its own counter.
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
// even when whole. The lost count on an invalidated direction is unknown, not
// zero: a production-order gap does not say how much was this direction's.
func (t *stream) placed(direction fragment.Direction) connection.Placement {
	held, invalidated := t.placement[direction]
	if !invalidated {
		if t.begun == connection.ObservationLost {
			// A stream begun after a located loss: its offsets are relative to its first
			// byte, and the lost observation may have been its own beginning. Unknown
			// throughout, since there is no placeable prefix to name.
			return connection.Placement{
				Connection: t.id,
				Direction:  direction,
				Positions:  connection.PositionsUnknownThroughout,
				Because:    connection.ObservationLost,
				Lost: connection.Uncounted("the gap is located in the session's production order " +
					"and its observations are not attributed to a stream"),
			}
		}
		return connection.Placement{
			Connection: t.id,
			Direction:  direction,
			Positions:  connection.PositionsEstablished,
			Lost:       connection.Counted(0),
		}
	}
	return connection.Placement{
		Connection: t.id,
		Direction:  direction,
		Positions:  held.positions,
		From:       held.from,
		Because:    held.because,
		Lost: connection.Uncounted("the gap is located in the session's production order and its " +
			"observations are not attributed to a stream"),
	}
}

// record is this stream as a connection record. The caller holds the lock.
// Every association is present with its reason; a missing one would read as
// nothing observed.
func (t *stream) record(how connection.Ending, at time.Time) connection.Record {
	record := connection.Record{
		ID: t.id,
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

// Records is every connection record this session has produced: those written
// at a connection's end and, after Finish, those the run outlived.
func (s *Session) Records() []connection.Record {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return slices.Clone(s.closed)
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
