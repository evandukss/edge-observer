package processing

import (
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
)

type batchKey struct {
	process fragment.Process
	id      fragment.ConnectionID
}

type batch struct {
	process    fragment.Process
	entries    []*intake.Entry
	fragments  map[uint64]fragment.Record
	retirement *connection.Record
	invalid    bool
	loss       *held.Loss

	// cut is set once the connection held as many fragments as one connection
	// may (Options.ConnectionInput). What it held was discarded then, and every
	// later fragment of it is discarded on arrival. arrived counts its fragments
	// before and after, so the batch is complete when its retirement's count has
	// arrived, and reached is how far each direction's discarded input ran.
	cut     bool
	arrived uint64
	reached [3]uint64
}

// keyOf is the batch an entry belongs to.
func keyOf(e *intake.Entry) batchKey {
	if f := e.Fragment; f != nil {
		return batchKey{process: f.Process, id: f.Connection}
	}
	return batchKey{process: e.Connection.Process, id: e.Connection.ID}
}

func (w *Worker) accept(in routed) {
	e := in.entry
	key := keyOf(e)
	process, id := key.process, key.id
	if w.options.Taken != nil {
		w.options.Taken(w.index, process, id)
	}
	b := w.batches[key]
	if b == nil && !in.first {
		e.Release()
		w.withhold(connection.Uncounted("late_batch_entry"))
		return
	}
	if b == nil {
		b = &batch{process: process, fragments: make(map[uint64]fragment.Record)}
		w.batches[key] = b
		w.order = append(w.order, key)
	}
	if f := e.Fragment; f != nil && b.cut {
		b.arrived++
		b.reach(f)
		w.outcome.InputCut++
		e.ReleaseAs(held.Cut)
		return
	}
	if e.Fragment != nil && e.Fragment.Loss != nil {
		b.loss = e.Fragment.Loss
	}
	if e.Connection != nil && e.Connection.Loss != nil {
		b.loss = e.Connection.Loss
	}
	b.entries = append(b.entries, e)
	if process != b.process || id == 0 {
		b.invalid = true
	}
	if f := e.Fragment; f != nil {
		if _, exists := b.fragments[f.Sequence]; exists {
			b.invalid = true
		}
		if f.Validate() != nil || f.Sequence == 0 || f.End() < f.Offset {
			b.invalid = true
		}
		b.fragments[f.Sequence] = *f
		b.arrived++
		if len(b.fragments) >= w.bound {
			w.cut(b)
		}
		return
	}
	r := e.Connection
	if b.retirement != nil {
		b.invalid = true
	}
	b.retirement = r
	if r.Validate() != nil || r.Process.PID <= 0 || r.Handle.Instance != r.Instance.Key() || !r.Fragments.Known || r.Fragments.Value < 0 {
		b.invalid = true
	}
	if _, err := record.FromConnection(*r); err != nil {
		b.invalid = true
	}
}

func (b *batch) ready(final bool) bool {
	if b.retirement == nil {
		return false
	}
	r := b.retirement
	if b.cut && !b.invalid {
		if r.Fragments.Value < 0 || b.arrived > uint64(r.Fragments.Value) {
			b.invalid = true
			return true
		}
		if b.arrived != uint64(r.Fragments.Value) {
			return final
		}
		return final || r.How == connection.HandleReleasedEnding || r.How == connection.SocketClosed
	}
	for seq := range b.fragments {
		if r.Fragments.Value < 0 || seq > uint64(r.Fragments.Value) {
			b.invalid = true
		}
	}
	if b.invalid {
		return true
	}
	if uint64(len(b.fragments)) != uint64(r.Fragments.Value) {
		return false
	}
	return final || r.How == connection.HandleReleasedEnding || r.How == connection.SocketClosed
}

// cut discards everything a batch holds but its retirement, returning its
// fragments' slots as cut: the connection reached the bound on what one
// connection may hold while it waits to be processed. Its later fragments are
// discarded on arrival (accept), and what it produces is its connection line,
// truncated from its first byte (processCut).
func (w *Worker) cut(b *batch) {
	b.cut = true
	w.outcome.ConnectionsCut++
	kept := b.entries[:0]
	for _, e := range b.entries {
		if f := e.Fragment; f != nil {
			b.reach(f)
			w.outcome.InputCut++
			e.ReleaseAs(held.Cut)
			continue
		}
		kept = append(kept, e)
	}
	clear(b.entries[len(kept):])
	b.entries = kept
	b.fragments = nil
}

// reach records how far a discarded fragment's direction ran.
func (b *batch) reach(f *fragment.Record) {
	if f.Direction != fragment.Sent && f.Direction != fragment.Received {
		return
	}
	if end := f.End(); end > b.reached[f.Direction] {
		b.reached[f.Direction] = end
	}
}

// release returns the batch's entries, and their events' slots along path.
func (b *batch) release(path held.Path) {
	// Drop all aliases before returning the volatile charge.
	b.fragments = nil
	b.retirement = nil
	for _, e := range b.entries {
		e.ReleaseAs(path)
	}
	b.entries = nil
}

// processedUnless is the path a processed batch's input is returned along:
// Processed, or Discarded where processing stopped on err before it finished.
func processedUnless(err error) held.Path {
	if err != nil {
		return held.Discarded
	}
	return held.Processed
}

type prefixCut struct {
	offset uint64
	reason string
}

type directionPrefix struct {
	end uint64
	cut *prefixCut
}

type batchPrefix [3]directionPrefix

func (p *batchPrefix) stop(direction fragment.Direction, offset uint64, reason string) {
	previous := p[direction].cut
	if previous == nil || offset < previous.offset {
		p[direction].cut = &prefixCut{offset: offset, reason: reason}
	}
}

func (p batchPrefix) truncated() bool {
	return p[fragment.Sent].cut != nil || p[fragment.Received].cut != nil
}

// placed returns only the proven prefix of each direction, retaining its end
// and the location and reason of any cutoff. It never resumes after a hole or
// an unplaced span, even if later bytes resemble a start line. Overlapping
// offsets are conflicting evidence, not a choice between callback orderings.
//
// A producer number skipped between two fragments of a direction, other than
// the empty transfers the later one counts, is a transfer produced and never
// delivered, whatever the offsets say: capture advances offsets by what
// arrived, so contiguous offsets alone cannot show the hole. The direction
// stops where the missing transfer would have begun.
func (b *batch) placed() ([]fragment.Record, batchPrefix, bool) {
	var out []fragment.Record
	var end [3]uint64
	var produced [3]uint64
	var prefix batchPrefix
	// A placement cutoff remains evidence of an indeterminate suffix even
	// when no later fragment was observed. Absence of later input is not zero.
	for _, p := range b.retirement.Placements {
		switch p.Positions {
		case connection.PositionsUnknownFrom:
			prefix.stop(p.Direction, p.From, "positions_unknown")
		case connection.PositionsUnknownThroughout:
			prefix.stop(p.Direction, 0, "positions_unknown")
		}
	}
	for seq := uint64(1); seq <= uint64(b.retirement.Fragments.Value); seq++ {
		f := b.fragments[seq]
		_, ok := b.retirement.Placement(f.Direction)
		if !ok || f.Offset < end[f.Direction] {
			return nil, batchPrefix{}, false
		}
		if f.Offset > end[f.Direction] {
			prefix.stop(f.Direction, end[f.Direction], "capture_hole")
		}
		if f.Produced != 0 {
			if f.Produced != produced[f.Direction]+1+f.Empties {
				prefix.stop(f.Direction, end[f.Direction], "capture_hole")
			}
			produced[f.Direction] = f.Produced
		}
		end[f.Direction] = f.End()
		if f.Truncated() {
			prefix.stop(f.Direction, f.Offset+uint64(len(f.Payload)), "capture_hole")
		}
		keep := uint64(len(f.Payload))
		if cut := prefix[f.Direction].cut; cut != nil {
			if f.Offset >= cut.offset {
				keep = 0
			} else {
				keep = min(keep, cut.offset-f.Offset)
			}
		}
		if keep == 0 {
			continue
		}
		f.Payload = f.Payload[:keep]
		f.Length = uint32(keep)
		out = append(out, f)
		prefix[f.Direction].end = f.End()
	}
	return out, prefix, true
}
