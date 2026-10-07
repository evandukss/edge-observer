package fragment

import (
	"fmt"
	"time"

	"github.com/evandukss/edge-observer/admission"
)

// Evidence is what capture had established about a record's connection when it
// placed that record: which connection it is, what the producer's numbering
// counts from, how far each direction's positions are established, and through
// which fragment all of that holds. Capture takes it under its lock as it
// builds the record, and nothing changes it afterwards; a later record carries
// its own. It lets a consumer certify a prefix of a connection that is still
// open, from what has arrived and without its retirement record.
//
// What a consumer may rely on, and what it may not:
//
//   - It describes the connection's fragments with Sequence one through
//     Through, which is the Sequence of the record carrying it, and nothing
//     after them.
//   - It vouches for no input the consumer does not hold. A consumer relies on
//     it only while it holds every fragment of the connection from one through
//     Through, counted from the fragments themselves (Usable).
//   - A cut never moves and never goes away. Once a direction's positions stop
//     being established at an offset, every later evidence of the connection
//     names that same offset, so a later evidence cannot establish what an
//     earlier one had cut.
//   - Established positions are an upper bound the evidence allows, not a claim
//     that bytes arrived. Below Established a consumer still checks its own
//     fragments' offsets and producer numbers, and still stops at a payload kept
//     short (Record.Truncated).
//
// The zero value is no evidence, and supports nothing before the connection's
// retirement.
type Evidence struct {
	// Identity is the connection's stable facts, the same value for every
	// evidence of one connection and shared between them.
	Identity *Identity

	// Occupancy is the producer's occupancy of the handle the connection follows;
	// zero where the producer kept none, so nothing can check its positions.
	Occupancy uint64

	// Origin is what the producer's number one is, in both directions.
	Origin Origin

	// Through is the Sequence of the record this evidence was taken at.
	Through uint64

	// Sent and Received are each direction's positions and producer numbers, as
	// of Through.
	Sent     DirectionEvidence
	Received DirectionEvidence
}

// Identity is what stays true for the whole of one connection: which execution
// held which handle, in which occupancy, and when capture first saw it.
// Lifecycle and totals are not here; they change until the connection's
// retirement record states them.
type Identity struct {
	Connection ConnectionID
	Process    Process

	// Instance is the admitted execution's record as capture held it when the
	// connection began.
	Instance admission.Instance

	// Address is the library handle's address, and Generation the occupancy of
	// it, unique among every occupancy of every handle the session follows.
	Address    uint64
	Generation uint64

	// NetworkDevice and NetworkInode are the admitted execution's network
	// namespace, not any socket's; both zero where it was unreadable.
	NetworkDevice uint64
	NetworkInode  uint64

	// FirstSeen is when capture read the connection's first transfer. Opened is
	// when the socket beneath the handle was created, and zero where the socket
	// predates the probes.
	FirstSeen time.Time
	Opened    time.Time
}

// Origin is what the producer's number one is for an occupancy.
type Origin uint8

const (
	// OriginUnset is the zero value, and is refused.
	OriginUnset Origin = iota

	// OriginBirth is an occupancy that began at its handle's observed birth: number
	// one is the handle's first transfer in each direction.
	OriginBirth

	// OriginFirstRecorded is an occupancy that began at the first call the
	// producer recorded on a handle that already existed, with no loss the
	// producer could place in no occupancy before it: number one is that call,
	// and offsets count from it. What crossed the handle before it was never
	// observed and is not part of the stream.
	OriginFirstRecorded

	// OriginUnestablished is an occupancy whose number one is not known to be its
	// first transfer: it began, on a handle that already existed, after a loss the
	// producer could place in no occupancy, so its first transfers may be that
	// loss; or the producer kept no occupancy for it at all. Neither direction has
	// an established offset.
	OriginUnestablished
)

func (o Origin) String() string {
	switch o {
	case OriginBirth:
		return "the handle's observed birth"
	case OriginFirstRecorded:
		return "the first call recorded on an existing handle"
	case OriginUnestablished:
		return "unestablished"
	default:
		return "unset"
	}
}

// DirectionEvidence is what an evidence says about one direction: how far its
// positions run and are established, and what the producer had numbered in it.
//
// The producer numbers a direction's transfers from one, each at the call's
// entry, so a number can be taken by a transfer that never arrives. Numbered is
// a high-water mark and says nothing about the numbers below it; Resolved is
// the run of numbers from one that all arrived, in order. Where they differ,
// some number at or below Numbered is not accounted for, and the direction is
// cut.
type DirectionEvidence struct {
	// Limit is where the direction's next fragment begins: one past the last
	// byte any fragment through Through placed in it, advanced by what each call
	// transferred rather than by what was kept. The evidence says nothing about an
	// offset at or past it.
	Limit uint64

	// Cut says the direction's positions stopped being established, at From:
	// placeable below From and not at or past it. A cut with From zero establishes
	// no offset at all. From is zero where there is no cut.
	Cut  bool
	From uint64

	// Lost is how many of the direction's transfers are known missing, and
	// LostUncounted says that count is not the whole of it. Both are zero without
	// a cut.
	Lost          uint64
	LostUncounted bool

	// First is the producer number of the first transfer of this direction
	// capture saw, delivered or not; zero where it saw none. A first observation
	// past one means the transfers before it, from the origin, never arrived.
	First uint64

	// Numbered is the highest producer number capture had seen in the direction.
	Numbered uint64

	// Resolved is the number through which every number of the direction, from
	// one, arrived in order: as a fragment through Through or as a transfer that
	// moved no bytes. A transfer whose length nothing measured, one the delivery
	// gate refused, a number that never arrived and one that arrived behind a
	// later one each end the run, and nothing resumes it. It is about numbers
	// only: two calls the producer saw overlap both resolve, and cut the
	// direction all the same.
	Resolved uint64

	// Empties is the transfers of the direction that moved no bytes, numbered
	// after its last fragment through Through: resolved, with no fragment yet to
	// carry them. The direction's next fragment carries them as Record.Empties.
	Empties uint64
}

// Established is the first offset this direction's evidence does not vouch
// for: Limit, or From where the direction is cut.
func (d DirectionEvidence) Established() uint64 {
	if d.Cut {
		return d.From
	}
	return d.Limit
}

// Taken reports whether this is evidence at all, rather than the zero value.
func (e Evidence) Taken() bool { return e.Through != 0 }

// Of is the evidence for one direction; the zero value for a direction that is
// neither sent nor received.
func (e Evidence) Of(direction Direction) DirectionEvidence {
	switch direction {
	case Sent:
		return e.Sent
	case Received:
		return e.Received
	default:
		return DirectionEvidence{}
	}
}

// Established is the first offset of a direction this evidence does not vouch
// for. Evidence not taken vouches for nothing.
func (e Evidence) Established(direction Direction) uint64 {
	if !e.Taken() {
		return 0
	}
	return e.Of(direction).Established()
}

// Usable reports whether a consumer may rely on this evidence, given held: the
// highest Sequence through which the consumer itself holds every fragment of
// the connection, from one. held is counted from the fragments the consumer
// holds, never taken from an evidence or a retirement record. Evidence taken at
// a fragment the consumer does not hold, or after one it is missing, vouches
// for input the consumer does not have.
func (e Evidence) Usable(held uint64) bool { return e.Taken() && e.Through <= held }

// Validate reports what would make this evidence unusable on its own. Whether it
// belongs to a particular record is Record.Validate's and Record.Evidenced's.
func (e Evidence) Validate() error {
	switch {
	case !e.Taken():
		return fmt.Errorf("%w: no evidence was taken: it names no fragment it describes", ErrInvalid)
	case e.Identity == nil:
		return fmt.Errorf("%w: evidence through fragment %d names no connection", ErrInvalid, e.Through)
	case e.Identity.Connection == 0:
		return fmt.Errorf("%w: evidence through fragment %d is for connection zero, which joins to nothing",
			ErrInvalid, e.Through)
	case e.Identity.Process.PID <= 0:
		return fmt.Errorf("%w: evidence for connection %d names pid %d, no process",
			ErrInvalid, e.Identity.Connection, e.Identity.Process.PID)
	case e.Origin == OriginUnset || e.Origin > OriginUnestablished:
		return fmt.Errorf("%w: evidence for connection %d says nothing about what its producer's numbers "+
			"count from", ErrInvalid, e.Identity.Connection)
	case e.Occupancy == 0 && e.Origin != OriginUnestablished:
		return fmt.Errorf("%w: connection %d has no producer occupancy and claims the origin %s",
			ErrInvalid, e.Identity.Connection, e.Origin)
	}
	for _, direction := range []Direction{Sent, Received} {
		one := e.Of(direction)
		if err := one.validate(); err != nil {
			return fmt.Errorf("%w: connection %d %s through fragment %d: %s",
				ErrInvalid, e.Identity.Connection, direction, e.Through, err.Error())
		}
		if e.Origin == OriginUnestablished && (!one.Cut || one.From != 0) {
			return fmt.Errorf("%w: connection %d %s has no established origin and is not cut from offset "+
				"zero", ErrInvalid, e.Identity.Connection, direction)
		}
	}
	return nil
}

// validate is one direction's own consistency. Every rule holds of what capture
// takes, and each says how a contradicting evidence would mislead.
func (d DirectionEvidence) validate() error {
	switch {
	case !d.Cut && d.From != 0:
		return fmt.Errorf("not cut, and names offset %d as the start of a cut", d.From)
	case d.Cut && d.From > d.Limit:
		return fmt.Errorf("cut at offset %d, past the %d bytes it reached", d.From, d.Limit)
	case !d.Cut && (d.Lost != 0 || d.LostUncounted):
		return fmt.Errorf("not cut, and counts transfers lost")
	case d.First > d.Numbered:
		return fmt.Errorf("first saw number %d, past the highest it saw, %d", d.First, d.Numbered)
	case d.Numbered != 0 && d.First == 0:
		return fmt.Errorf("saw number %d and no first number", d.Numbered)
	case d.Resolved > d.Numbered:
		return fmt.Errorf("resolved through number %d, past the highest it saw, %d", d.Resolved, d.Numbered)
	case d.Resolved != 0 && d.First != 1:
		return fmt.Errorf("resolved from one, and first saw number %d", d.First)
	case d.Empties > d.Numbered:
		return fmt.Errorf("%d transfers moved no bytes, more than the %d numbers it saw", d.Empties, d.Numbered)
	case !d.Cut && d.Resolved != d.Numbered:
		// A number taken and not accounted for is a transfer that may have moved
		// bytes nobody placed.
		return fmt.Errorf("not cut, with numbers %d through %d unresolved", d.Resolved+1, d.Numbered)
	}
	return nil
}

// Evidenced reports whether this record carries evidence taken at it, as capture
// placed it. A consumer checks it on receipt, before trimming anything: unlike
// Validate, it reads the record's own length, which processing shortens to the
// bytes it keeps.
func (r Record) Evidenced() error {
	if err := r.Validate(); err != nil {
		return err
	}
	e := r.Evidence
	if !e.Taken() {
		return fmt.Errorf("%w: %s fragment %d carries no evidence", ErrInvalid, r.Stream(), r.Sequence)
	}
	own := e.Of(r.Direction)
	switch {
	case own.Limit != r.End():
		return fmt.Errorf("%w: %s fragment %d ends at %d and its evidence reaches %d",
			ErrInvalid, r.Stream(), r.Sequence, r.End(), own.Limit)
	case own.Empties != 0:
		return fmt.Errorf("%w: %s fragment %d's evidence counts %d transfers after it that it was taken "+
			"before", ErrInvalid, r.Stream(), r.Sequence, own.Empties)
	case r.Produced == 0 && (!own.Cut || own.From > r.Offset):
		// Nothing numbered this transfer, so nothing can say whether one before it
		// is missing.
		return fmt.Errorf("%w: %s fragment %d was numbered by no producer and its evidence establishes "+
			"offsets below %d", ErrInvalid, r.Stream(), r.Sequence, own.Established())
	case r.Produced != 0 && own.Numbered < r.Produced:
		return fmt.Errorf("%w: %s fragment %d is producer number %d and its evidence saw no number past %d",
			ErrInvalid, r.Stream(), r.Sequence, r.Produced, own.Numbered)
	case r.Produced != 0 && !own.Cut && own.Resolved != r.Produced:
		return fmt.Errorf("%w: %s fragment %d is producer number %d and its uncut evidence resolves "+
			"through %d", ErrInvalid, r.Stream(), r.Sequence, r.Produced, own.Resolved)
	}
	return nil
}
