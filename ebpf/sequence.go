package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	obpf "github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/probe"
)

// sequenceValue is one handle's occupancy as the program declares it
// (bpf/ssl.bpf.h, struct occupancy): its name, the admission it was begun
// under, the unlocated count then, the last number taken per direction, the
// thread in a call per direction, and the overlap and birth marks.
type sequenceValue struct {
	ID                 uint64
	Generation         uint64
	Unlocated          uint64
	Sent               uint64
	Received           uint64
	BusySent           uint64
	BusyReceived       uint64
	OverlappedSent     uint8
	OverlappedReceived uint8
	Born               uint8
	Padding            [5]uint8
}

// Settled is the occupancy the program holds for a handle now, with its last
// numbers: the terminal evidence for a connection whose ending was never
// delivered. It is meaningful once production has stopped and the ring buffer
// is drained (StopProducing, Drain), when nothing can take another number
// unseen. A handle the program holds nothing for is Occupancy zero, not an
// error; an unreadable table is an error.
func (s *Session) Settled(handle probe.Handle) (probe.Settlement, error) {
	table := s.collection.Maps["occupancies"]
	if table == nil {
		return probe.Settlement{}, fmt.Errorf("%w: the program has no occupancy table, so nothing here "+
			"says what a handle's calls were numbered", ErrUnavailable)
	}
	key := handleKey{
		NamespaceDevice: handle.Instance.Namespace.Device,
		NamespaceInode:  handle.Instance.Namespace.Inode,
		PID:             uint32(handle.Instance.PID),
		SSL:             handle.Endpoint,
	}
	var value sequenceValue
	if err := table.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return probe.Settlement{}, nil
		}
		return probe.Settlement{}, fmt.Errorf("%w: read the occupancy table: %v", ErrUnavailable, err)
	}
	return probe.Settlement{
		Occupancy: value.ID,
		Final: probe.Final{
			Known:    true,
			Sent:     probe.Terminal{Last: value.Sent, InFlight: value.BusySent != 0},
			Received: probe.Terminal{Last: value.Received, InFlight: value.BusyReceived != 0},
		},
	}, nil
}

// Unlocated is how many losses the program could not place in any occupancy:
// bytes moved by a call of a handle it held no occupancy for, and occupancies
// the table refused.
func (s *Session) Unlocated() (uint64, error) {
	counter := s.collection.Maps["unlocated"]
	if counter == nil {
		return 0, fmt.Errorf("%w: the program has no unlocated-loss counter, so nothing here says "+
			"whether a loss went unplaced", ErrUnavailable)
	}
	var value uint64
	if err := counter.Lookup(uint32(0), &value); err != nil {
		return 0, fmt.Errorf("%w: read the unlocated-loss counter: %v", ErrUnavailable, err)
	}
	return value, nil
}

// OccupanciesUnrecorded is how many occupancies the table refused, each leaving
// its handle's calls without a number.
func (s *Session) OccupanciesUnrecorded() (int64, error) {
	return s.stat(obpf.StatOccupancyUnrecorded)
}

// Born is how many occupancies began at their handle's observed birth.
func (s *Session) Born() (int64, error) { return s.stat(obpf.StatBorn) }

// Overlapped is how many calls entered while another in their direction was in
// flight on their handle, which OpenSSL's supported use forbids.
func (s *Session) Overlapped() (int64, error) { return s.stat(obpf.StatOverlapped) }

// NestedWrappers is how many calls ran inside another on the same handle and
// direction, whose bytes the outer call reports (SSL_write_early_data reaching
// SSL_write).
func (s *Session) NestedWrappers() (int64, error) { return s.stat(obpf.StatNestedWrapper) }

// NestedElsewhere is how many calls ran inside another that no wrapper
// explains: on a different handle or direction, or on the same one by an entry
// point the outer one does not reach. Nothing reports their bytes, and each
// took a number as a loss.
func (s *Session) NestedElsewhere() (int64, error) { return s.stat(obpf.StatNestedElsewhere) }
