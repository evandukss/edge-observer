package connection

import (
	"fmt"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
)

// Record is one captured connection, persisted beside the fragments and joined
// to them by ConnectionID. It carries what comparing a stream with an outside
// record needs: which connection this is, how long, and where its bytes stop
// being placeable.
//
// ID is assigned at the first transfer on a handle and never moves, whatever
// the association says: an unknown association costs an exact join and
// nothing else, so the connection stays in any population it belongs to.
//
// FirstSeen is when capture read the first transfer; Opened is when the socket
// was created, where lifetime evidence reaches that far. Reporting FirstSeen
// as the open time would date every pre-existing connection from the
// observer's arrival.
type Record struct {
	ID fragment.ConnectionID `json:"id"`

	// Handle is the identity: execution, handle address, and occupancy
	// generation.
	Handle Handle `json:"handle"`

	// Instance is the full admission record of the execution, so a reader needs
	// no second lookup. Handle.Instance is its identity; this is its evidence.
	Instance admission.Instance `json:"instance"`

	// Process is the execution in the numbering a fragment carries, joining this
	// record to them: (Process, ID) here is (Process, Connection) there.
	// Instance.PID is the pid inside the process's own namespace; this is the
	// observer's, which fragments record.
	Process fragment.Process `json:"process"`

	// Network is the network namespace the admitted execution was in when the
	// probes were placed - not any socket's, which can differ (a socket inherited
	// across a namespace change or passed in over a unix socket). Read during
	// placement, since /proc/<pid>/ns/net is refused after the capability drop.
	// Unknown where unreadable; never the observer's own.
	Network Netns `json:"network"`

	// FirstSeen is when userspace read this connection's first transfer, stamped
	// at decode, so it includes time queued in the ring. Opened is the socket's
	// own start, where seen.
	FirstSeen time.Time `json:"first_seen"`

	// Opened is when the socket beneath the handle was created, where lifetime
	// evidence establishes it.
	Opened      time.Time `json:"opened,omitempty"`
	OpenedKnown bool      `json:"opened_known"`

	// Ended is how this connection stopped, and Ending says on what evidence.
	Ended time.Time `json:"ended,omitempty"`
	How   Ending    `json:"how"`

	// Associations has one entry per direction this run said anything about. A
	// missing direction had nothing observed, which differs from an Unknown
	// association with its reason.
	Associations []Association `json:"associations"`

	// Placements is one entry per direction that carried bytes.
	Placements []Placement `json:"placements"`

	// Fragments is how many records were placed on this connection, both
	// directions, as capture counted them: neither transfers nor bytes.
	Fragments Count `json:"fragments"`

	// Early is the ranges that arrived as TLS 1.3 early data; EarlyUnmeasured the
	// early transfers nothing could measure. Early data is ordinary stream bytes,
	// but replayable and not forward-secret, so the fact is kept here.
	Early           []Early `json:"early,omitempty"`
	EarlyUnmeasured int     `json:"early_unmeasured,omitempty"`
}

// Early is a run of bytes that arrived as TLS 1.3 early data.
type Early struct {
	Direction fragment.Direction `json:"direction"`
	Offset    uint64             `json:"offset"`
	Length    uint32             `json:"length"`
}

// Ending is what this run knows about how a connection stopped. SSL_free is not
// proof: the handle is reference counted and SSL_clear recycles it in place.
type Ending uint8

const (
	// EndingUnset is the zero value; a record carrying it is refused.
	EndingUnset Ending = iota

	// StillOpen is a connection the run sealed while it was still going:
	// truncated by the run, not closed.
	StillOpen

	// HandleReleasedEnding is a release or recycle of the library handle. A later
	// use of the address is a new occupancy, never a continuation.
	HandleReleasedEnding

	// SocketClosed is the descriptor's lifetime evidence ending: the closest to a
	// close this run can observe.
	SocketClosed

	// EndingUnobserved is an end not seen but known to have happened (the
	// execution exited holding it, or an observation was lost).
	EndingUnobserved

	// EndingUnestablished is a connection whose end no placed probe could report:
	// the run does not know whether it ended, and could not.
	EndingUnestablished
)

func (e Ending) String() string {
	switch e {
	case StillOpen:
		return "still open when the run was sealed"
	case HandleReleasedEnding:
		return "the handle was released or recycled"
	case SocketClosed:
		return "the socket was closed"
	case EndingUnobserved:
		return "it ended and the end was not observed"
	case EndingUnestablished:
		return "no probe that could observe an ending was placed, so whether it ended is not established"
	default:
		return "nothing says how it ended"
	}
}

// Association is this connection's association for one direction, and whether
// there is one at all.
func (r Record) Association(direction fragment.Direction) (Association, bool) {
	for _, one := range r.Associations {
		if one.Direction == direction {
			return one, true
		}
	}
	return Association{}, false
}

// Placement is this connection's placement for one direction, and whether there
// is one at all.
func (r Record) Placement(direction fragment.Direction) (Placement, bool) {
	for _, one := range r.Placements {
		if one.Direction == direction {
			return one, true
		}
	}
	return Placement{}, false
}

// Joinable reports whether this connection may be joined to an outside record
// in the given direction. A direction with no association is not.
func (r Record) Joinable(direction fragment.Direction) bool {
	one, found := r.Association(direction)
	return found && one.Joinable()
}

// Placeable reports whether every byte of a direction sits where the process
// put it. A direction with no placement carried no bytes.
func (r Record) Placeable(direction fragment.Direction) bool {
	one, found := r.Placement(direction)
	return !found || one.Whole()
}

// Validate reports what would make this record unusable to a consumer.
func (r Record) Validate() error {
	if r.ID == 0 {
		return fmt.Errorf("%w: a connection record with no id joins to no fragment", ErrInvalid)
	}
	if err := r.Handle.Validate(); err != nil {
		return err
	}
	if r.FirstSeen.IsZero() {
		return fmt.Errorf("%w: connection %d says nothing about when it was first seen", ErrInvalid, r.ID)
	}
	if r.OpenedKnown && r.Opened.IsZero() {
		return fmt.Errorf("%w: connection %d claims a known open time and names none", ErrInvalid, r.ID)
	}
	if r.How == EndingUnset {
		return fmt.Errorf("%w: connection %d says nothing about how it ended, and silence there reads "+
			"as a connection that closed cleanly", ErrInvalid, r.ID)
	}
	// A time is required only where the connection is said to have ended.
	if r.How != StillOpen && r.How != EndingUnobserved && r.How != EndingUnestablished && r.Ended.IsZero() {
		return fmt.Errorf("%w: connection %d ended - %s - and names no time for it", ErrInvalid, r.ID, r.How)
	}

	seen := make(map[fragment.Direction]bool, 2)
	for _, one := range r.Associations {
		if one.Connection != r.ID {
			return fmt.Errorf("%w: connection %d carries an association for connection %d",
				ErrInvalid, r.ID, one.Connection)
		}
		if seen[one.Direction] {
			return fmt.Errorf("%w: connection %d carries two associations for %s, and a consumer "+
				"reading the first would never see the second", ErrInvalid, r.ID, one.Direction)
		}
		seen[one.Direction] = true
		if err := one.Validate(); err != nil {
			return err
		}
	}

	placed := make(map[fragment.Direction]bool, 2)
	for _, one := range r.Placements {
		if one.Connection != r.ID {
			return fmt.Errorf("%w: connection %d carries a placement for connection %d",
				ErrInvalid, r.ID, one.Connection)
		}
		if placed[one.Direction] {
			return fmt.Errorf("%w: connection %d carries two placements for %s", ErrInvalid, r.ID, one.Direction)
		}
		placed[one.Direction] = true
		if err := one.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r Record) String() string {
	return fmt.Sprintf("connection %d on %s, first seen %s, %s",
		r.ID, r.Handle, r.FirstSeen.UTC().Format(time.RFC3339Nano), r.How)
}

// Sink is where connection records go, written when a record stops changing:
// at the connection's end, or at the seal for one still open.
type Sink interface {
	Connection(Record) error
}
