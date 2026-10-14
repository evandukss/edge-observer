package brotli

import (
	"errors"
	"math/bits"
)

// The work budget. Some of the decoder's work is not bounded by what it
// produces: prefix codes, context maps and tree storage are built and cleared
// for every metablock, and a metablock can carry a few bytes of output and a
// great deal of such work. So the Reader counts that work, in entries written
// or read, each step counted at the most it can take: a prefix code's table at
// the largest size its alphabet allows, and for a code sent as code lengths,
// the code-length code's table and a length per symbol; each entry of a
// context map or of the context modes cleared and then written; for a map
// coded by move to front, each entry scanned and each place the list moves;
// for the literal map, each entry scanned for trivial block types; the tree
// groups' tables at their largest size when a metablock lays them out; and
// the entries cleared at each metablock's start and end. Each is charged
// immediately before the work, in a state that runs once for it, so a read
// that resumes is not charged again. Work bounded by the input read or by the
// output produced is not counted.
//
// With a budget set, a charge that would take the count past
// base + perByte * decoded, decoded being the bytes decoded so far, or past
// most, whatever the credit, fails, and the stream ends with ErrTooCostly
// before the work is done. The credit is the decoder's own output, wherever
// the caller reads it from. Without a budget, the Reader counts and never
// refuses.
//
// Reset clears the budget and the count. A Reader reused through Reset keeps
// its tree storage, and its first metablock clears what the stream before left
// there, so it can count more for a stream than a new Reader does; a count
// that must depend on the stream alone comes from a new Reader.

// ErrTooCostly is the error a stream ends with when its next piece of work
// would take the Reader past its budget.
var ErrTooCostly = errors.New("brotli: the stream needs more work than its budget allows")

// SetBudget sets the Reader's work budget, until a Reset clears it.
func (r *Reader) SetBudget(base, perByte, most uint64) {
	r.workBase, r.workPerByte, r.workMost, r.budgeted = base, perByte, most, true
}

// Work is the work the Reader has counted since it was made or Reset.
func (r *Reader) Work() uint64 { return r.work }

// decodedBytes is how many bytes the decoder has written to its ring buffer:
// what it has produced, flushed to the caller or not.
func (s *Reader) decodedBytes() uint64 {
	return uint64(s.rb_roundtrips)*uint64(s.ringbuffer_size) + uint64(s.pos)
}

// charge counts q units of work, or reports that the budget does not allow
// them, in which case nothing is counted.
func (s *Reader) charge(q uint64) bool {
	work, carry := bits.Add64(s.work, q, 0)
	if carry != 0 {
		return false
	}
	if s.budgeted {
		high, credit := bits.Mul64(s.workPerByte, s.decodedBytes())
		allowed, over := bits.Add64(s.workBase, credit, 0)
		if high != 0 || over != 0 {
			allowed = ^uint64(0)
		}
		if work > min(allowed, s.workMost) {
			return false
		}
	}
	s.work = work
	return true
}

// metablockCost is the entries a metablock's start or end clears: the tree
// groups' tables and slices at its start, their slices at its end.
func metablockCost(s *Reader, start bool) uint64 {
	n := uint64(len(s.literal_hgroup.htrees) + len(s.insert_copy_hgroup.htrees) + len(s.distance_hgroup.htrees))
	if start {
		n += uint64(len(s.literal_hgroup.codes) + len(s.insert_copy_hgroup.codes) + len(s.distance_hgroup.codes))
	}
	return n
}

// complexCodeWork is the entries a prefix code sent as code lengths writes: the
// code-length code's table, a length for each symbol, and the code's table at
// the largest size the alphabet allows.
func complexCodeWork(alphabet_size uint32) uint64 {
	return 1<<huffmanMaxCodeLengthCodeLength + uint64(alphabet_size) + uint64(kMaxHuffmanTableSize[(alphabet_size+31)>>5])
}

// treeGroupWork is the entries a tree group takes for a metablock: ntrees
// tables at the largest size the alphabet allows, and a slice for each.
func treeGroupWork(alphabet_size, ntrees uint32) uint64 {
	return uint64(ntrees) * (uint64(kMaxHuffmanTableSize[(alphabet_size+31)>>5]) + 1)
}

// moveToFrontWork is the entries undoing the move-to-front coding of v writes:
// the list it starts from, and for each entry, the entry, the list's head and
// each place the list moves.
func moveToFrontWork(v []byte) uint64 {
	work := uint64(256 + 2*len(v))
	for _, x := range v {
		work += uint64(x)
	}
	return work
}
