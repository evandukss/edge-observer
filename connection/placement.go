package connection

import (
	"fmt"

	"github.com/evandukss/edge-observer/fragment"
)

// Placement is how far one direction of a connection can be placed in a
// stream, and where it stops. A lost event advances no offset, so later bytes
// sit at wrong positions that still parse; the invalidation is recorded here
// for a consumer to read first.
//
// Established: the whole direction is placeable. UnknownFrom: positions before
// an offset are established and the rest are not - a claim about where the
// loss was, made only with ordering evidence. UnknownThroughout: a loss nobody
// could locate; no prefix is asserted without evidence.
type Placement struct {
	Connection fragment.ConnectionID `json:"connection"`
	Direction  fragment.Direction    `json:"direction"`

	Positions Positions `json:"positions"`

	// From is the first offset not established: one past the last fragment the
	// ordering evidence covers. Meaningful only for UnknownFrom.
	From uint64 `json:"from,omitempty"`

	// Because says what cost the direction its positions.
	Because Reason `json:"because,omitempty"`

	// Lost is how many of this direction's observations are known to be missing:
	// events, not bytes.
	Lost Count `json:"lost"`
}

// Positions is how much of a direction can be placed.
type Positions uint8

const (
	// PositionsUnset is the zero value; a placement carrying it is refused.
	PositionsUnset Positions = iota
	// PositionsEstablished is a direction whose observations all arrived.
	PositionsEstablished
	// PositionsUnknownFrom is a direction with a gap located in the session's
	// production order (not in this stream) after the offset From: placeable
	// before From and not at or after it.
	PositionsUnknownFrom
	// PositionsUnknownThroughout is a direction that lost an observation nothing
	// could locate: no offset is established.
	PositionsUnknownThroughout
)

func (p Positions) String() string {
	switch p {
	case PositionsEstablished:
		return "established"
	case PositionsUnknownFrom:
		return "unknown from an offset"
	case PositionsUnknownThroughout:
		return "unknown throughout"
	default:
		return "unset"
	}
}

// Placeable reports whether a byte at this offset sits where the process put
// it. Use it rather than comparing with From, which misreads
// UnknownThroughout.
func (p Placement) Placeable(offset uint64) bool {
	switch p.Positions {
	case PositionsEstablished:
		return true
	case PositionsUnknownFrom:
		return offset < p.From
	default:
		return false
	}
}

// Whole reports whether every offset of this direction is placeable.
func (p Placement) Whole() bool { return p.Positions == PositionsEstablished }

// Validate reports what would make this placement unusable.
func (p Placement) Validate() error {
	switch {
	case p.Direction != fragment.Sent && p.Direction != fragment.Received:
		return fmt.Errorf("%w: direction %d is neither sent nor received", ErrInvalid, p.Direction)
	case p.Positions == PositionsUnset:
		return fmt.Errorf("%w: connection %d %s says nothing about whether its bytes can be placed, "+
			"and silence there reads as a whole stream", ErrInvalid, p.Connection, p.Direction)
	case p.Positions == PositionsEstablished && p.Because != ReasonUnset:
		return fmt.Errorf("%w: connection %d %s is fully placeable and gives the reason %q",
			ErrInvalid, p.Connection, p.Direction, p.Because)
	case p.Positions != PositionsEstablished && p.Because == ReasonUnset:
		return fmt.Errorf("%w: connection %d %s is not fully placeable and says nothing about why",
			ErrInvalid, p.Connection, p.Direction)
	case p.Positions != PositionsUnknownFrom && p.From != 0:
		// From belongs only to a located gap.
		return fmt.Errorf("%w: connection %d %s is %s and names offset %d as the start of a gap",
			ErrInvalid, p.Connection, p.Direction, p.Positions, p.From)
	}
	return nil
}

func (p Placement) String() string {
	switch p.Positions {
	case PositionsEstablished:
		return fmt.Sprintf("connection %d %s: every offset established", p.Connection, p.Direction)
	case PositionsUnknownFrom:
		return fmt.Sprintf("connection %d %s: established below offset %d, unknown from there because %s",
			p.Connection, p.Direction, p.From, p.Because)
	default:
		return fmt.Sprintf("connection %d %s: no offset established, because %s",
			p.Connection, p.Direction, p.Because)
	}
}
