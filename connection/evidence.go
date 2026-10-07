package connection

import (
	"fmt"

	"github.com/evandukss/edge-observer/fragment"
)

// Agrees reports whether this record contradicts an evidence of its own
// connection that a consumer held before it. The record is the later word, and
// what it may add is bounded by what the evidence already established:
//
//   - the identity is the same: connection, process, execution, handle and
//     occupancy, namespace, and when it was first seen and opened;
//   - it counts at least the fragments the evidence describes;
//   - a direction the evidence cut is cut at the same offset, with at least the
//     transfers lost the evidence counted, and uncounted where the evidence
//     could not count them;
//   - a direction the evidence did not cut is placeable through the evidence's
//     limit: a retirement never cuts below what an evidence established.
//
// It is checked against evidence the consumer held, never against the evidence
// of a fragment that did not arrive: capture cuts a direction at a fragment its
// sink refused, after that fragment's own evidence was taken.
func (r Record) Agrees(evidence fragment.Evidence) error {
	if err := evidence.Validate(); err != nil {
		return err
	}
	identity := evidence.Identity
	switch {
	case r.ID != identity.Connection || r.Process != identity.Process:
		return fmt.Errorf("%w: connection %d of pid %d does not agree with evidence for connection %d of pid %d",
			ErrInvalid, r.ID, r.Process.PID, identity.Connection, identity.Process.PID)
	case r.Instance != identity.Instance || r.Handle.Instance != identity.Instance.Key():
		return fmt.Errorf("%w: connection %d names a different execution from its evidence", ErrInvalid, r.ID)
	case r.Handle.Address != identity.Address || uint64(r.Handle.Generation) != identity.Generation:
		return fmt.Errorf("%w: connection %d is %s and its evidence names handle %#x in generation %d",
			ErrInvalid, r.ID, r.Handle, identity.Address, identity.Generation)
	case r.Network != (Netns{Device: identity.NetworkDevice, Inode: identity.NetworkInode}):
		return fmt.Errorf("%w: connection %d names a different network namespace from its evidence",
			ErrInvalid, r.ID)
	case !r.FirstSeen.Equal(identity.FirstSeen):
		return fmt.Errorf("%w: connection %d was first seen at %s and its evidence says %s",
			ErrInvalid, r.ID, r.FirstSeen, identity.FirstSeen)
	case r.OpenedKnown == identity.Opened.IsZero() || !r.Opened.Equal(identity.Opened):
		return fmt.Errorf("%w: connection %d's open time does not agree with its evidence", ErrInvalid, r.ID)
	case !r.Fragments.Known || r.Fragments.Value < 0 || uint64(r.Fragments.Value) < evidence.Through:
		return fmt.Errorf("%w: connection %d counts %s fragments and its evidence describes %d",
			ErrInvalid, r.ID, r.Fragments, evidence.Through)
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if err := r.agreesIn(direction, evidence.Of(direction)); err != nil {
			return err
		}
	}
	return nil
}

// agreesIn is Agrees for one direction.
func (r Record) agreesIn(direction fragment.Direction, held fragment.DirectionEvidence) error {
	placement, carried := r.Placement(direction)
	if !held.Cut && held.Limit == 0 {
		// The evidence established nothing here, so there is nothing to contradict.
		return nil
	}
	if !carried {
		return fmt.Errorf("%w: connection %d %s has no placement, and its evidence reached offset %d",
			ErrInvalid, r.ID, direction, held.Limit)
	}
	if !held.Cut {
		if placement.Whole() || (placement.Positions == PositionsUnknownFrom && placement.From >= held.Limit) {
			return nil
		}
		return fmt.Errorf("%w: %s, and its evidence established every offset below %d",
			ErrInvalid, placement, held.Limit)
	}
	switch {
	case held.From == 0 && placement.Positions != PositionsUnknownThroughout,
		held.From != 0 && (placement.Positions != PositionsUnknownFrom || placement.From != held.From):
		return fmt.Errorf("%w: %s, and its evidence was cut at offset %d", ErrInvalid, placement, held.From)
	case held.LostUncounted && placement.Lost.Known:
		return fmt.Errorf("%w: %s counts %s lost, and its evidence could not count them",
			ErrInvalid, placement, placement.Lost)
	case placement.Lost.Known && placement.Lost.Value < int64(held.Lost):
		return fmt.Errorf("%w: %s counts %s lost, and its evidence counted %d",
			ErrInvalid, placement, placement.Lost, held.Lost)
	}
	return nil
}
