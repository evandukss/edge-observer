package processing

import (
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
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
}

func (w *Worker) accept(e *intake.Entry) {
	var id fragment.ConnectionID
	var process fragment.Process
	if e.Fragment != nil {
		id, process = e.Fragment.Connection, e.Fragment.Process
	} else {
		id, process = e.Connection.ID, e.Connection.Process
	}
	key := batchKey{process: process, id: id}
	if w.completed[key] {
		e.Release()
		w.withhold(connection.Uncounted("late_batch_entry"))
		return
	}
	b := w.batches[key]
	if b == nil {
		b = &batch{process: process, fragments: make(map[uint64]fragment.Record)}
		w.batches[key] = b
		w.order = append(w.order, key)
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

func (b *batch) release() {
	// Drop all aliases before returning the volatile charge.
	b.fragments = nil
	b.retirement = nil
	for _, e := range b.entries {
		e.Release()
	}
	b.entries = nil
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
func (b *batch) placed() ([]fragment.Record, batchPrefix, bool) {
	var out []fragment.Record
	var end [3]uint64
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
