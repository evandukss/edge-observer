package processing

import (
	"math"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/reconstruct"
)

type batchKey struct {
	process fragment.Process
	id      fragment.ConnectionID
}

// batch is one connection a worker holds: the input it holds and has not
// released, how far that input is placed and read, and what it has released.
//
// A fragment is given to parsing once something vouches for it: the evidence
// capture took at a fragment the worker holds, with every fragment before it
// (fragment.Evidence.Usable), or the connection's retirement. Before that it
// waits in unfed. Once given, its entry stays leased until parsing no longer
// holds any of its bytes, and is then released once, as processed.
type batch struct {
	process    fragment.Process
	id         fragment.ConnectionID
	retirement *connection.Record
	retiring   *intake.Entry
	invalid    bool
	loss       *held.Loss

	// unfed is the fragments held and not yet given to parsing, by sequence.
	unfed map[uint64]*intake.Entry
	// feeding is, per direction, the entries given to parsing whose bytes it
	// may still hold, in offset order.
	feeding [3][]fedEntry
	// refused is entries a later one with the same sequence displaced from
	// unfed, held with the batch they refused.
	refused []*intake.Entry
	// placed is the entries a reading has placed and not yet read, in order:
	// leased, so they are the connection's while a call it makes is admitted
	// (charged).
	placed []*intake.Entry

	// arrived counts the connection's distinct fragments that arrived, and
	// highest is the largest sequence among them. held is the sequence through
	// which every fragment arrived, and fed the one through which every fragment
	// was given to parsing.
	arrived, highest, held, fed uint64
	// evidence is the latest evidence taken at a fragment through held; zero
	// where none was.
	evidence fragment.Evidence
	// place is how far each direction is placed.
	place [3]placing

	// cut is set once the connection held as much as one connection may
	// (Options.ConnectionInput). What it held was discarded then, and every
	// later fragment of it is discarded on arrival.
	cut bool
	// lost discards payload after capture loss, but keeps the batch until its
	// retirement can describe that loss. It is not a connection-input cut.
	lost bool
	// reached is how far each direction's input ran, kept or not.
	reached [3]uint64
	// final is set when Finish settles the batch.
	final bool

	// parse is the connection's reading and what it released; nil where no
	// pipeline reads the connection, and after a cut.
	parse *parsing
	// policy is what the connection's copies are charged now (intake.Policy).
	policy int64
	// runnable marks a batch already listed to run this turn.
	runnable bool

	// chain is the exchanges issued ids that are still on their way through
	// the extensions to their lines, in index order (Worker.chain); calling is
	// set while the first has a call outstanding. ended is a connection whose
	// retirement was processed, or the session ended without settling it
	// (unsettled), and whose connection lines wait for its chain.
	chain            []*dispatch
	calling          bool
	ended, unsettled bool
}

// fedEntry is an entry given to parsing and where its bytes given ended.
type fedEntry struct {
	entry *intake.Entry
	end   uint64
}

// placing is one direction's placement as fragments are given to parsing, in
// sequence order: where its next fragment must begin, the producer number it
// last placed, where it stopped being placeable and why, and the end of the
// bytes given to parsing.
type placing struct {
	end      uint64
	produced uint64
	stop     *prefixCut
	fed      uint64
}

// stopAt records that the direction stops being placeable at offset, keeping
// the earliest stop.
func (p *placing) stopAt(offset uint64, reason string) {
	if p.stop == nil || offset < p.stop.offset {
		p.stop = &prefixCut{offset: offset, reason: reason}
	}
}

// parsing is a connection's incremental reading, and what it released.
type parsing struct {
	pairing  *reconstruct.Pairing
	reserver *ceiling
	// stopped is set once the pairing stopped: it pairs nothing more, and holds
	// nothing it is given afterwards. ended once End handed everything over.
	stopped, ended bool
	// low is, per direction, the offset below which parsing holds no byte.
	low [3]uint64

	// exchanges counts those handed over, the index of the next; good how many
	// were released before the first that was not. excluded is set by that
	// first one, and nothing after it is released. countable is cleared by an
	// exchange whose cardinality is not established (countableMessage).
	exchanges, good int
	excluded        bool
	countable       bool
	// released is, per direction, the end of the last released exchange's
	// message there: the first byte no exchange line carries.
	released [3]uint64
	// omitted is, per direction, why and where the first exchange not released
	// stopped there.
	omitted [3]*prefixCut
	// failed is the pipelines whose slots failed on this connection: they write
	// nothing more for it, and were counted once.
	failed map[string]bool
	// identity is the provisional record exchange lines carry, once projected.
	identity *record.Connection
	// fedBytes counts the bytes given to the pairing, and skipped those placed
	// after it stopped, which it is not given: they are read as no message.
	fedBytes, skipped uint64
	// charged is what the connection's reading holds in the shared allowance,
	// as intake.Parsing: its reading state, what its pairing retains, and the
	// exchanges handed over that the worker has not let go.
	charged int64
}

// ceiling is a connection's reserver: it grants what parsing asks to retain
// while the connection's pending count stays below the bound on what one
// connection may hold (Options.ConnectionInput), and the shared allowance has
// room for it (intake.Parsing, parsingUnits). A growth in messages that would
// reach the bound is refused, and so is one the allowance refuses (full); the
// connection is cut either way.
type ceiling struct {
	b        *batch
	p        *parsing
	store    *intake.Store
	bound    int
	retained http1.Charge
	refused  bool
	full     bool
}

func (c *ceiling) Reserve(charge http1.Charge) bool {
	if charge.Messages > 0 && c.retained.Messages+charge.Messages+int64(c.b.waiting()) >= int64(c.bound) {
		c.refused = true
		return false
	}
	units := parsingUnits(charge)
	if !c.store.Reserve(intake.Parsing, units) {
		c.full = true
		return false
	}
	c.retained = c.retained.Add(charge)
	c.p.charged += units
	return true
}

func (c *ceiling) Release(charge http1.Charge) {
	c.retained.Bytes -= charge.Bytes
	c.retained.Messages -= charge.Messages
	units := parsingUnits(charge)
	c.store.Return(intake.Parsing, units)
	c.p.charged -= units
}

// keyOf is the batch an entry belongs to.
func keyOf(e *intake.Entry) batchKey {
	if f := e.Fragment; f != nil {
		return batchKey{process: f.Process, id: f.Connection}
	}
	return batchKey{process: e.Connection.Process, id: e.Connection.ID}
}

// accept takes one entry into its connection's batch, and returns the batch
// the entry made runnable, or nil.
func (w *Worker) accept(in routed) *batch {
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
		return nil
	}
	if b == nil {
		b = &batch{process: process, id: id, unfed: make(map[uint64]*intake.Entry)}
		w.batches[key] = b
		w.order = append(w.order, key)
	}
	if f := e.Fragment; f != nil && (b.cut || b.lost) {
		b.arrived++
		b.reach(f)
		path := held.Discarded
		if b.cut {
			w.outcome.InputCut++
			path = held.Cut
		}
		e.ReleaseAs(path)
		return b
	}
	if e.Fragment != nil && e.Fragment.Loss != nil {
		b.loss = e.Fragment.Loss
	}
	if e.Connection != nil && e.Connection.Loss != nil {
		b.loss = e.Connection.Loss
	}
	if process != b.process || id == 0 {
		b.invalid = true
	}
	if f := e.Fragment; f != nil {
		if earlier, exists := b.unfed[f.Sequence]; exists {
			// A second fragment with one sequence refuses the connection; both
			// stay leased until it retires.
			b.invalid = true
			b.refused = append(b.refused, earlier)
		} else if f.Sequence != 0 && f.Sequence <= b.fed {
			b.invalid = true
		}
		if f.Validate() != nil || f.Sequence == 0 || f.End() < f.Offset {
			b.invalid = true
		}
		// Evidence is checked as capture placed it, before anything is trimmed.
		if f.Evidence.Taken() && f.Evidenced() != nil {
			b.invalid = true
		}
		b.unfed[f.Sequence] = e
		b.arrived++
		b.highest = max(b.highest, f.Sequence)
		b.reach(f)
		for {
			next, ok := b.unfed[b.held+1]
			if !ok {
				break
			}
			b.held++
			if one := next.Fragment.Evidence; one.Taken() && !b.invalid {
				if !b.follows(one) {
					b.invalid = true
				} else {
					b.vouch(one)
				}
			}
		}
		if b.pending() >= w.bound {
			w.cut(b)
		}
		return b
	}
	r := e.Connection
	if b.retirement != nil {
		b.invalid = true
		// The earlier retirement stays the batch's; this one is released.
		e.Release()
		return b
	}
	b.retirement, b.retiring = r, e
	if r.Validate() != nil || r.Process.PID <= 0 || r.Handle.Instance != r.Instance.Key() || !r.Fragments.Known || r.Fragments.Value < 0 {
		b.invalid = true
	}
	if _, err := record.FromConnection(*r); err != nil {
		b.invalid = true
	}
	return b
}

// follows reports whether a later evidence of the connection agrees with the
// one held: the same identity, and nothing it established taken back. A cut
// never moves, and a direction never cut is never cut below what was
// established in it.
func (b *batch) follows(later fragment.Evidence) bool {
	earlier := b.evidence
	if !earlier.Taken() {
		return true
	}
	if *later.Identity != *earlier.Identity || later.Occupancy != earlier.Occupancy || later.Origin != earlier.Origin {
		return false
	}
	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		was, now := earlier.Of(d), later.Of(d)
		switch {
		case was.Cut && (!now.Cut || now.From != was.From):
			return false
		case now.Established() < was.Established():
			return false
		}
	}
	return true
}

// vouch makes evidence the batch's latest, and records the cuts it names.
func (b *batch) vouch(evidence fragment.Evidence) {
	b.evidence = evidence
	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if one := evidence.Of(d); one.Cut {
			b.place[d].stopAt(one.From, "positions_unknown")
		}
	}
}

// pending is what Options.ConnectionInput bounds for this connection: the
// messages its parsing has begun and not handed over, and the fragments it
// holds that nothing vouches for yet (waiting).
func (b *batch) pending() int {
	n := b.waiting()
	if b.parse != nil {
		n += int(b.parse.reserver.retained.Messages)
	}
	return n
}

// waiting is the fragments the batch holds that it cannot read yet: those
// past the latest evidence it can use. A fragment evidence vouches for is read
// in the turn that took it, so a burst of it is not held against the bound.
func (b *batch) waiting() int {
	ready := 0
	if certified := b.certifiedThrough(false); certified > b.fed {
		ready = int(certified - b.fed)
	}
	return len(b.unfed) - ready
}

// entries is how many intake entries the batch keeps leased.
func (b *batch) entries() int {
	n := len(b.unfed) + len(b.refused)
	for _, queue := range b.feeding {
		n += len(queue)
	}
	if b.retiring != nil {
		n++
	}
	return n
}

// charged is the connection's current accounted charge in the shared
// allowance, in its units: the intake's charge for the entries it keeps
// leased, what its reading holds (intake.Parsing) and what its copies hold
// (intake.Policy). It is what an extension call made on the connection keeps
// held while it waits.
func (b *batch) charged() int64 {
	n := b.bytes() + b.policy
	if b.parse != nil {
		n += b.parse.charged
	}
	return n
}

// bytes is the intake charge of every entry the batch keeps leased.
func (b *batch) bytes() int64 {
	var n int64
	for _, e := range b.unfed {
		n += e.Bytes()
	}
	for _, queue := range b.feeding {
		for _, one := range queue {
			n += one.entry.Bytes()
		}
	}
	for _, e := range b.refused {
		n += e.Bytes()
	}
	for _, e := range b.placed {
		n += e.Bytes()
	}
	return n + b.retiring.Bytes()
}

func (b *batch) ready(final bool) bool {
	if b.retirement == nil {
		return false
	}
	r := b.retirement
	if (b.cut || b.lost) && !b.invalid {
		if r.Fragments.Value < 0 || b.arrived > uint64(r.Fragments.Value) {
			b.invalid = true
			return true
		}
		if b.arrived != uint64(r.Fragments.Value) && b.loss.Reason() == "" {
			return final
		}
		return final || r.How == connection.HandleReleasedEnding || r.How == connection.SocketClosed
	}
	if r.Fragments.Value < 0 || b.highest > uint64(r.Fragments.Value) {
		b.invalid = true
	}
	if b.invalid {
		return true
	}
	if b.arrived != uint64(r.Fragments.Value) {
		return false
	}
	return final || r.How == connection.HandleReleasedEnding || r.How == connection.SocketClosed
}

// cut discards everything a batch holds unreleased but its retirement,
// returning its fragments' slots as cut: the connection reached the bound on
// what one connection may hold (Options.ConnectionInput). Its later fragments
// are discarded on arrival (accept), and what it produces is its connection
// line, truncated from the first byte it had not released (processCut).
func (w *Worker) cut(b *batch) {
	if b.cut {
		return
	}
	b.cut = true
	w.outcome.ConnectionsCut++
	w.outcome.InputCut += b.discardInput(held.Cut)
}

// lose releases payload without charging a bound cut. The bounded batch keeps
// only its identity, control token, direction reaches and what it released
// until retirement.
func (b *batch) lose() {
	if b.cut || b.lost {
		return
	}
	b.lost = true
	b.discardInput(held.Discarded)
}

// discardInput releases every fragment the batch holds, and what its parsing
// holds, keeping what it released. A fragment whose bytes are all released,
// and which an exchange still on its way through the extensions reads, is not
// discarded: it is that exchange's until its lines are written (refund). It
// returns how many fragments it released.
func (b *batch) discardInput(path held.Path) uint64 {
	var discarded uint64
	for seq, e := range b.unfed {
		discarded++
		e.ReleaseAs(path)
		delete(b.unfed, seq)
	}
	chained := b.chainLow()
	var low [3]uint64
	if b.parse != nil {
		low = b.parse.low
	}
	for d := range b.feeding {
		var kept []fedEntry
		for _, one := range b.feeding[d] {
			if one.end > chained[d] && one.end <= low[d] {
				kept = append(kept, one)
				continue
			}
			discarded++
			one.entry.ReleaseAs(path)
		}
		b.feeding[d] = kept
	}
	for _, e := range b.refused {
		discarded++
		e.ReleaseAs(path)
	}
	b.refused = nil
	b.stopParsing()
	return discarded
}

// stopParsing gives back what the connection's parsing retains, and its
// reading state's charge, keeping what it released.
func (b *batch) stopParsing() {
	p := b.parse
	if p == nil || p.pairing == nil {
		return
	}
	p.reserver.Release(p.pairing.Retained())
	p.pairing = nil
	p.stopped = true
	p.reserver.store.Return(intake.Parsing, readingCharge)
	p.charged -= readingCharge
}

// reach records how far a fragment's direction ran.
func (b *batch) reach(f *fragment.Record) {
	if f.Direction != fragment.Sent && f.Direction != fragment.Received {
		return
	}
	if end := f.End(); end > b.reached[f.Direction] {
		b.reached[f.Direction] = end
	}
}

// release returns every entry the batch holds, and their events' slots along
// path.
func (b *batch) release(path held.Path) {
	b.discardInput(path)
	if b.retiring != nil {
		b.retiring.ReleaseAs(path)
	}
	b.retiring = nil
	b.retirement = nil
}

// refund releases, as processed, every entry given to parsing whose bytes
// nothing holds any more: the last of them is below the offset under which
// parsing holds nothing (parsing.low), and below the first message of an
// exchange still on its way through the extensions (chainLow), which holds its
// input until its lines are written. An entry is released once, when its last
// retained byte goes.
func (b *batch) refund() {
	low := [3]uint64{}
	if b.parse != nil {
		low = b.parse.low
	}
	for d, chained := range b.chainLow() {
		low[d] = min(low[d], chained)
	}
	for d := range b.feeding {
		queue := b.feeding[d]
		n := 0
		for n < len(queue) && (b.parse == nil || queue[n].end <= low[d]) {
			queue[n].entry.ReleaseAs(held.Processed)
			queue[n] = fedEntry{}
			n++
		}
		b.feeding[d] = queue[n:]
		if len(b.feeding[d]) == 0 {
			b.feeding[d] = nil
		}
	}
}

// chainLow is, per direction, where the first message of an exchange still on
// its way through the extensions begins: the input from there on is held for it
// until its lines are written. A direction no such message is in holds nothing
// for the chain, and reads as the largest offset.
func (b *batch) chainLow() [3]uint64 {
	low := [3]uint64{math.MaxUint64, math.MaxUint64, math.MaxUint64}
	for _, d := range b.chain {
		request, response := directions(d.role)
		for _, side := range []struct {
			direction fragment.Direction
			message   *reconstruct.Message
		}{{request, d.source.Request}, {response, d.source.Response}} {
			if side.message != nil && side.direction != fragment.Unknown {
				low[side.direction] = min(low[side.direction], side.message.Offset)
			}
		}
	}
	return low
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

func (p batchPrefix) truncated() bool {
	return p[fragment.Sent].cut != nil || p[fragment.Received].cut != nil
}

// prefix is how far each direction was read, and where it stopped being
// placeable.
func (b *batch) prefix() batchPrefix {
	var out batchPrefix
	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		out[d] = directionPrefix{end: b.place[d].fed, cut: b.place[d].stop}
	}
	return out
}

// certifiedThrough is the sequence through which something vouches for the
// connection's fragments: its retirement, once every fragment it counts has
// arrived, or else its latest evidence. Zero is nothing vouched for.
func (b *batch) certifiedThrough(retired bool) uint64 {
	if retired {
		return b.held
	}
	if b.evidence.Usable(b.held) {
		return b.evidence.Through
	}
	return 0
}

// certify applies the retirement's placements to what is still to be placed:
// a direction whose positions are unknown stops where they become unknown.
func (b *batch) certify() {
	for _, p := range b.retirement.Placements {
		switch p.Positions {
		case connection.PositionsUnknownFrom:
			b.place[p.Direction].stopAt(p.From, "positions_unknown")
		case connection.PositionsUnknownThroughout:
			b.place[p.Direction].stopAt(0, "positions_unknown")
		}
	}
}

// take places the next fragment, in sequence order, and returns its entry and
// the bytes of it that may be read: none past where its direction stopped
// being placeable. It never resumes after a hole or an unplaced span, even if
// later bytes resemble a start line. Overlapping offsets are conflicting
// evidence, not a choice between callback orderings, and make the batch
// invalid.
//
// A producer number skipped between two fragments of a direction, other than
// the empty transfers the later one counts, is a transfer produced and never
// delivered, whatever the offsets say: capture advances offsets by what
// arrived, so contiguous offsets alone cannot show the hole. The direction
// stops where the missing transfer would have begun.
func (b *batch) take(retired bool) (*intake.Entry, []byte, bool) {
	seq := b.fed + 1
	e := b.unfed[seq]
	if e == nil {
		b.invalid = true
		return nil, nil, false
	}
	f := e.Fragment
	if f.Direction != fragment.Sent && f.Direction != fragment.Received {
		b.invalid = true
		return nil, nil, false
	}
	if retired {
		if _, ok := b.retirement.Placement(f.Direction); !ok {
			b.invalid = true
			return nil, nil, false
		}
	}
	p := &b.place[f.Direction]
	if f.Offset < p.end {
		b.invalid = true
		return nil, nil, false
	}
	if f.Offset > p.end {
		p.stopAt(p.end, "capture_hole")
	}
	if f.Produced != 0 {
		if f.Produced != p.produced+1+f.Empties {
			p.stopAt(p.end, "capture_hole")
		}
		p.produced = f.Produced
	}
	p.end = f.End()
	if f.Truncated() {
		p.stopAt(f.Offset+uint64(len(f.Payload)), "capture_hole")
	}
	keep := uint64(len(f.Payload))
	if p.stop != nil {
		if f.Offset >= p.stop.offset {
			keep = 0
		} else {
			keep = min(keep, p.stop.offset-f.Offset)
		}
	}
	delete(b.unfed, seq)
	b.fed = seq
	if keep != 0 {
		p.fed = f.Offset + keep
	}
	return e, f.Payload[:keep], true
}

// exchangeEvidence is what releasing exchange e states to the gate, read off
// the connection as it stands: its inputs are settled where both its messages
// end within what was given to parsing, which only ever holds bytes something
// vouched for; its lifecycle is settled where both messages are complete and
// framed.
func (b *batch) exchangeEvidence(e reconstruct.Exchange, role reconstruct.Role) probe.ReleaseEvidence {
	request, response := directions(role)
	inputs := e.Request != nil && e.Response != nil && request != fragment.Unknown &&
		e.Request.End <= b.place[request].fed && e.Response.End <= b.place[response].fed
	lifecycle := e.Complete && e.Request != nil && e.Response != nil && e.Request.Complete && e.Request.Framed &&
		e.Response.Complete && e.Response.Framed
	return probe.ReleaseEvidence{InputsSettled: inputs, LifecycleSettled: lifecycle}
}

// retirementEvidence is what a connection line states to the gate: its inputs
// are settled where the retirement is held and every fragment it counts has
// arrived, or the connection was cut, lost or refused, which its line says;
// its lifecycle is settled where the connection closed or the session is
// settling it.
func (b *batch) retirementEvidence() probe.ReleaseEvidence {
	r := b.retirement
	if r == nil {
		return probe.ReleaseEvidence{}
	}
	inputs := b.cut || b.lost || b.invalid || (r.Fragments.Known && b.arrived == uint64(r.Fragments.Value))
	lifecycle := b.final || r.How == connection.HandleReleasedEnding || r.How == connection.SocketClosed
	return probe.ReleaseEvidence{InputsSettled: inputs, LifecycleSettled: lifecycle}
}

// directions is which direction carries requests and which responses, for a
// connection whose process was on role's side; unknown for an unknown role.
func directions(role reconstruct.Role) (fragment.Direction, fragment.Direction) {
	switch role {
	case reconstruct.Client:
		return fragment.Sent, fragment.Received
	case reconstruct.Server:
		return fragment.Received, fragment.Sent
	}
	return fragment.Unknown, fragment.Unknown
}
