// Package fragment defines the record capture publishes and reconstruction
// consumes: one plaintext fragment as one TLS library call transferred it. It
// is the only thing the kernel-facing and the pure halves share.
//
// What a consumer may rely on:
//
//   - Records of one Stream reassemble, ordered by Offset, into one plaintext
//     byte stream. Sequence orders the whole connection, both directions.
//   - A gap between End and the next Offset is bytes never received; do not
//     read across it.
//   - Payload may be shorter than the call transferred, or empty; Truncated
//     says so, and the bytes lost are always the tail.
//   - A fragment boundary is a library call, not a message boundary.
//   - ConnectionID is unique within one capture session and means nothing else.
//   - Endpoints, descriptors and connection lifecycle are in the connection's
//     own record, joined by ConnectionID.
package fragment

import (
	"errors"
	"fmt"
	"time"
)

// Direction is which way a fragment's bytes crossed the TLS boundary, seen from
// the observed process.
type Direction uint8

const (
	// Unknown is the zero value and never valid in a record.
	Unknown Direction = iota
	// Sent is plaintext the observed process wrote (SSL_write and variants).
	Sent
	// Received is plaintext the observed process read (SSL_read and variants).
	Received
)

func (d Direction) String() string {
	switch d {
	case Sent:
		return "sent"
	case Received:
		return "received"
	default:
		return "unknown"
	}
}

// Process identifies the observed process. A pid alone does not, because pids
// are reused; StartTime (clock ticks since boot, field 22 of /proc/<pid>/stat)
// separates two processes that shared one.
type Process struct {
	PID       int32
	StartTime uint64
}

// ConnectionID names one TLS connection within a capture session.
type ConnectionID uint64

// Stream is one direction of one connection of one process: the unit that
// reassembles into one byte stream. It is comparable, for use as a map key.
type Stream struct {
	Process    Process
	Connection ConnectionID
	Direction  Direction
}

func (s Stream) String() string {
	return fmt.Sprintf("pid %d connection %d %s", s.Process.PID, s.Connection, s.Direction)
}

// Record is one plaintext fragment and what reconstruction needs to place it.
type Record struct {
	Process    Process
	Connection ConnectionID
	Direction  Direction

	// Sequence orders one connection's fragments, both directions, as seen.
	Sequence uint64

	// Offset is the first byte's position in its Stream, from the first byte
	// capture saw there.
	Offset uint64

	// Length is the bytes the call transferred, as its return reported, not
	// the length the caller asked for.
	Length uint32

	// Payload is what capture kept: Length bytes or a leading part of them.
	Payload []byte

	At time.Time
}

// Stream is the stream this record belongs to.
func (r Record) Stream() Stream {
	return Stream{Process: r.Process, Connection: r.Connection, Direction: r.Direction}
}

// End is the offset a contiguous successor carries. It advances by Length, not
// by the payload kept.
func (r Record) End() uint64 {
	return r.Offset + uint64(r.Length)
}

// Truncated reports whether capture kept fewer bytes than the call transferred.
func (r Record) Truncated() bool {
	return len(r.Payload) < int(r.Length)
}

// ErrInvalid is what every Validate failure wraps.
var ErrInvalid = errors.New("invalid fragment record")

// Validate reports what would make this record unusable. Capture checks it
// before spooling, so a bad record is refused where it is produced.
func (r Record) Validate() error {
	switch {
	case r.Process.PID <= 0:
		return fmt.Errorf("%w: pid %d names no process", ErrInvalid, r.Process.PID)
	case r.Direction != Sent && r.Direction != Received:
		return fmt.Errorf("%w: direction %d is neither sent nor received", ErrInvalid, r.Direction)
	case r.Length == 0:
		// Nothing transferred: no place in a stream.
		return fmt.Errorf("%w: the call transferred no bytes", ErrInvalid)
	case len(r.Payload) > int(r.Length):
		// A capture defect: more kept than transferred.
		return fmt.Errorf("%w: %d bytes kept of %d transferred", ErrInvalid, len(r.Payload), r.Length)
	case r.At.IsZero():
		return fmt.Errorf("%w: no capture time", ErrInvalid)
	}
	return nil
}
