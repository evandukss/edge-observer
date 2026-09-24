package connection

import (
	"fmt"
	"strings"
)

// Counters is a run's whole inventory, by the stages an event passes through
// and in the capture side's three units.
//
// The identities are per stage, not one sum: a failed ring-buffer reservation
// reserves nothing, so "reserved = delivered + failures" is wrong (Identities
// states the ones that hold). Transfers, fragments and bytes do not bound each
// other, so each unit has its own fields. Every field is a Count: an
// unreadable counter is unknown, never zero, and an identity with an unknown
// term is reported as not evaluated.
type Counters struct {
	// The kernel side, by stage.

	// Ordered is every production-order place the program handed out: the widest
	// stage, not a count of reservations. A call refused at the read boundary
	// takes a place and reserves nothing; a place with no event locates a loss.
	Ordered Count `json:"ordered"`

	// ReservationAttempts is every ring-buffer placement tried: the places handed
	// out less those refusals took.
	ReservationAttempts Count `json:"reservation_attempts"`
	// Reservations is the attempts the kernel granted.
	Reservations Count `json:"reservations"`
	// ReservationFailures is the attempts refused because the buffer was full:
	// bytes that crossed and are absent with no gap marking them.
	ReservationFailures Count `json:"reservation_failures"`
	// Submitted is the granted reservations the program handed to the reader.
	Submitted Count `json:"submitted"`
	// Delivered is the submitted events userspace decoded and handed on.
	Delivered Count `json:"delivered"`
	// Undecodable is submitted events shorter than the program's own header: the
	// event layout no longer agreeing between the two sides. Neither delivery nor
	// buffer loss.
	Undecodable Count `json:"undecodable"`
	// LostAfterSubmission is submitted events the reader never delivered: it
	// failed mid-run, or stopped before the buffer was empty.
	LostAfterSubmission Count `json:"lost_after_submission"`
	// Outstanding is events that had been submitted or decoded and were not
	// persisted when the run was sealed.
	Outstanding Count `json:"outstanding"`

	// StillExecuting is calls not yet returned from the library when the run was
	// sealed. Never added to Outstanding: an outstanding event is bytes that
	// crossed without a record; a still-executing call may not have moved its
	// bytes. Near zero on a finished workload; materially non-zero there means
	// returns that never arrived, whose streams report whole and short.
	StillExecuting Count `json:"still_executing"`

	// UnmatchedReturns is returns with nothing recorded on the way in: a call this
	// run could not measure, unlike a reservation failure.
	UnmatchedReturns Count `json:"unmatched_returns"`

	// UnmeasurableCalls is calls into a function this run holds no return probe
	// for: never recorded at all, bytes crossed with no transfer and an unknown
	// count. It is distinct from UnmatchedReturns, StillExecuting and Unmeasured,
	// takes no production-order place and appears in no identity. Zero when every
	// probe placed.
	UnmeasurableCalls Count `json:"unmeasurable_calls"`

	// SocketsUnrecorded and BindingsUnrecorded are descriptor lifetimes and handle
	// bindings the observer could not record. Each turns a binding it could have
	// made into one reported as never observed, so a full table is told apart
	// from a process whose socket calls cannot be seen.
	SocketsUnrecorded  Count `json:"sockets_unrecorded"`
	BindingsUnrecorded Count `json:"bindings_unrecorded"`

	// DenialsUnrecorded is children of a denied instance the allowlist would not
	// take: a process this run should have refused and cannot name.
	DenialsUnrecorded Count `json:"denials_unrecorded"`

	// DeferredDiscarded is calls held through a fork window whose task was never
	// admitted. Not a loss: nothing captured is short by them. Many of them mean a
	// process forks faster than admissions arrive.
	DeferredDiscarded Count `json:"deferred_discarded"`

	// RefusedInFlight is calls that entered under a live grant and returned to a
	// withdrawn one: the payload was not read, and those bytes are absent.
	RefusedInFlight Count `json:"refused_in_flight"`

	// The capture side, by unit.

	// Transfers is what the adapters reported.
	Transfers Count `json:"transfers"`
	// Unmeasured is transfers whose byte count nothing could read.
	Unmeasured Count `json:"unmeasured"`
	// Empty is transfers that moved no bytes.
	Empty Count `json:"empty"`
	// Fragments is the transfers that were placed in a stream.
	Fragments Count `json:"fragments"`
	// FragmentsRefused is the records the sink would not take.
	FragmentsRefused Count `json:"fragments_refused"`

	// The storage side.

	// Persisted is the fragments that reached the spool.
	Persisted Count `json:"persisted"`
	// PersistedDropped is the fragments the spool refused at its bound.
	PersistedDropped Count `json:"persisted_dropped"`
	// PersistedRefused is the fragments the spool refused as unplaceable.
	PersistedRefused Count `json:"persisted_refused"`

	// The reconstruction side.

	// Discards is the records reassembly refused. A refused record's bytes are
	// absent from its stream, so the offsets it covered are a gap.
	Discards Count `json:"discards"`
	// UnplacedBytes is offsets that carried bytes never read as part of a
	// message: observations this run cannot explain.
	UnplacedBytes Count `json:"unplaced_bytes"`
}

// Join takes the stages another source filled and leaves this one's alone.
// The program, capture and storage each fill their own stages and leave the
// rest unknown, so this takes a stage exactly where other established it. It
// is not addition: two sources filling one stage is a defect to see.
func (c Counters) Join(other Counters) Counters {
	take := func(held, offered Count) Count {
		if held.Known {
			return held
		}
		return offered
	}
	c.Ordered = take(c.Ordered, other.Ordered)
	c.ReservationAttempts = take(c.ReservationAttempts, other.ReservationAttempts)
	c.Reservations = take(c.Reservations, other.Reservations)
	c.ReservationFailures = take(c.ReservationFailures, other.ReservationFailures)
	c.Submitted = take(c.Submitted, other.Submitted)
	c.Delivered = take(c.Delivered, other.Delivered)
	c.Undecodable = take(c.Undecodable, other.Undecodable)
	c.LostAfterSubmission = take(c.LostAfterSubmission, other.LostAfterSubmission)
	c.Outstanding = take(c.Outstanding, other.Outstanding)
	c.StillExecuting = take(c.StillExecuting, other.StillExecuting)
	c.UnmatchedReturns = take(c.UnmatchedReturns, other.UnmatchedReturns)
	c.UnmeasurableCalls = take(c.UnmeasurableCalls, other.UnmeasurableCalls)
	c.RefusedInFlight = take(c.RefusedInFlight, other.RefusedInFlight)
	c.SocketsUnrecorded = take(c.SocketsUnrecorded, other.SocketsUnrecorded)
	c.BindingsUnrecorded = take(c.BindingsUnrecorded, other.BindingsUnrecorded)
	c.DenialsUnrecorded = take(c.DenialsUnrecorded, other.DenialsUnrecorded)
	c.DeferredDiscarded = take(c.DeferredDiscarded, other.DeferredDiscarded)
	c.Transfers = take(c.Transfers, other.Transfers)
	c.Unmeasured = take(c.Unmeasured, other.Unmeasured)
	c.Empty = take(c.Empty, other.Empty)
	c.Fragments = take(c.Fragments, other.Fragments)
	c.FragmentsRefused = take(c.FragmentsRefused, other.FragmentsRefused)
	c.Persisted = take(c.Persisted, other.Persisted)
	c.PersistedDropped = take(c.PersistedDropped, other.PersistedDropped)
	c.PersistedRefused = take(c.PersistedRefused, other.PersistedRefused)
	c.Discards = take(c.Discards, other.Discards)
	c.UnplacedBytes = take(c.UnplacedBytes, other.UnplacedBytes)
	return c
}

// Identity is one conservation identity and its result: it holds, it fails,
// or a term was unreadable and it was not evaluated.
type Identity struct {
	// Name says what the identity is, in the units it is over.
	Name string `json:"name"`

	// Left and Right are the two sides as they evaluated.
	Left  Count `json:"left"`
	Right Count `json:"right"`

	// Evaluated is false where a term could not be read.
	Evaluated bool `json:"evaluated"`
	// Holds is meaningful only where Evaluated is true.
	Holds bool `json:"holds"`
}

func (i Identity) String() string {
	switch {
	case !i.Evaluated:
		return fmt.Sprintf("%s: could not be evaluated (%s against %s)", i.Name, i.Left, i.Right)
	case i.Holds:
		return fmt.Sprintf("%s: holds at %s", i.Name, i.Left)
	default:
		return fmt.Sprintf("%s: FAILS, %s against %s", i.Name, i.Left, i.Right)
	}
}

// identity evaluates one.
func identity(name string, left Count, right ...Count) Identity {
	sum := Counted(0)
	for _, one := range right {
		sum = sum.Add(one)
	}
	one := Identity{Name: name, Left: left, Right: sum}
	if !left.Known || !sum.Known {
		return one
	}
	one.Evaluated = true
	one.Holds = left.Value == sum.Value
	return one
}

// Identities is every conservation identity this inventory can state,
// evaluated. A counter that moved says a mechanism fired, not that everything
// is accounted for.
func (c Counters) Identities() []Identity {
	return []Identity{
		identity("every place in the production order is a reservation attempt or a refusal at the read boundary",
			c.Ordered, c.ReservationAttempts, c.RefusedInFlight),
		identity("reservation attempts are granted or refused",
			c.ReservationAttempts, c.Reservations, c.ReservationFailures),
		identity("every granted reservation is submitted or abandoned",
			c.Reservations, c.Submitted, c.reservedNotSubmitted()),
		identity("every submitted event is delivered, undecodable, lost or outstanding",
			c.Submitted, c.Delivered, c.Undecodable, c.LostAfterSubmission, c.Outstanding),
		identity("every transfer is placed, empty, unmeasured or refused",
			c.Transfers, c.Fragments, c.Empty, c.Unmeasured, c.FragmentsRefused),
		identity("every fragment offered to storage reaches it, its bound or its refusal",
			c.Fragments.Add(c.FragmentsRefused), c.Persisted, c.PersistedDropped, c.PersistedRefused),
	}
}

// reservedNotSubmitted is granted reservations never submitted: zero by
// construction, stated so the identity catches a future path that reserves and
// returns.
func (c Counters) reservedNotSubmitted() Count { return Counted(0) }

// Complete reports whether every association this run could have made was
// recorded, and what could not be. Separate from Balanced: events can add up
// while a full socket table made every association "never observed".
func (c Counters) Complete() (complete bool, known bool) {
	for _, one := range []Count{c.SocketsUnrecorded, c.BindingsUnrecorded, c.DenialsUnrecorded} {
		if !one.Known {
			return false, false
		}
		if one.Value != 0 {
			complete = false
			known = true
			return complete, known
		}
	}
	return true, true
}

// Balanced reports whether every evaluable identity holds, and whether all
// could be evaluated: two different facts.
func (c Counters) Balanced() (holds bool, complete bool) {
	holds, complete = true, true
	for _, one := range c.Identities() {
		if !one.Evaluated {
			complete = false
			continue
		}
		if !one.Holds {
			holds = false
		}
	}
	return holds, complete
}

// Report is one line per identity, for whoever reads a run's output.
func (c Counters) Report() string {
	lines := make([]string, 0, 8)
	for _, one := range c.Identities() {
		lines = append(lines, one.String())
	}
	return strings.Join(lines, "\n")
}
