package processing

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/jsonshape"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/reconstruct"
	"github.com/evandukss/edge-observer/stream"
)

// advance reads as much of a connection as something now vouches for, and
// releases every exchange that reading hands over. A connection cut, lost or
// refused reads nothing here.
func (w *Worker) advance(ctx context.Context, b *batch) error {
	if b.cut || b.lost || b.invalid {
		return nil
	}
	return w.feed(ctx, b, false)
}

// feed gives parsing every fragment something vouches for that it has not
// been given, in sequence order: those through the latest usable evidence, or,
// where retired, every one. Every one of them is placed (batch.take) before
// any is read, so input that refuses the connection is found before anything
// of it is released. Each fragment's bytes are read as far as its direction is
// placeable. An entry is released once parsing holds none of its bytes
// (batch.refund).
func (w *Worker) feed(ctx context.Context, b *batch, retired bool) error {
	through := b.certifiedThrough(retired)
	type placed struct {
		entry *intake.Entry
		kept  []byte
	}
	var taken []placed
	for b.fed < through {
		e, kept, ok := b.take(retired)
		if !ok {
			break
		}
		taken = append(taken, placed{entry: e, kept: kept})
	}
	if b.invalid {
		// What was placed stays leased until the connection retires, as
		// input it refused.
		for _, one := range taken {
			f := one.entry.Fragment
			b.feeding[f.Direction] = append(b.feeding[f.Direction], fedEntry{entry: one.entry, end: f.Offset})
		}
		return nil
	}
	b.placed = b.placed[:0]
	for _, one := range taken {
		b.placed = append(b.placed, one.entry)
	}
	defer func() { b.placed = nil }()
	for n, one := range taken {
		b.placed = b.placed[1:]
		e, kept := one.entry, one.kept
		if b.cut {
			// A cut while reading released what was held; what was placed and
			// not yet read goes with it.
			for _, rest := range taken[n:] {
				w.outcome.InputCut++
				rest.entry.ReleaseAs(held.Cut)
			}
			return nil
		}
		f := e.Fragment
		p, err := w.reading(ctx, b)
		if err != nil {
			for _, rest := range taken[n:] {
				rest.entry.Release()
			}
			return err
		}
		if b.cut {
			// The allowance had no room for the reading to begin.
			for _, rest := range taken[n:] {
				w.outcome.InputCut++
				rest.entry.ReleaseAs(held.Cut)
			}
			return nil
		}
		if len(kept) == 0 || p == nil || p.stopped {
			if p != nil && p.stopped {
				p.skipped += uint64(len(kept))
			}
			// Nothing of it is read, so nothing of it is held for reading.
			e.ReleaseAs(held.Processed)
			if p != nil && p.stopped {
				p.low[f.Direction] = b.place[f.Direction].fed
			}
			continue
		}
		b.feeding[f.Direction] = append(b.feeding[f.Direction], fedEntry{entry: e, end: f.Offset + uint64(len(kept))})
		if w.current != nil {
			w.current.Fed += uint64(len(kept))
		}
		part := stream.Part{Offset: f.Offset, Length: uint64(len(kept)), Bytes: kept}
		if err := w.read(ctx, b, f.Direction, part); err != nil {
			for _, rest := range taken[n+1:] {
				rest.entry.Release()
			}
			return err
		}
	}
	if !b.cut {
		b.refund()
	}
	return nil
}

// reading is the connection's parsing, begun on its first read; nil where no
// pipeline reads the connection's content.
func (w *Worker) reading(ctx context.Context, b *batch) (*parsing, error) {
	if b.parse != nil {
		return b.parse, nil
	}
	if !slices.ContainsFunc(w.pipelines, func(p config.EffectivePipeline) bool { return p.Input == config.ReconstructionInput }) {
		return nil, nil
	}
	if w.options.BeforeParse != nil {
		if err := w.options.BeforeParse(ctx); err != nil {
			w.withhold(connection.Uncounted("unsettled_input"))
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		w.withhold(connection.Uncounted("unsettled_input"))
		return nil, err
	}
	store := w.options.Intake
	if !store.Reserve(intake.Parsing, readingCharge) {
		w.cutByAllowance(b)
		return nil, nil
	}
	reserver := &ceiling{b: b, store: store, bound: w.bound}
	pairing, err := reconstruct.NewPairing(w.options.Limits, reserver)
	if err != nil {
		store.Return(intake.Parsing, readingCharge)
		return nil, errors.New("internal observer defect: cannot begin reading a connection")
	}
	b.parse = &parsing{pairing: pairing, reserver: reserver, countable: true, failed: map[string]bool{},
		charged: readingCharge}
	reserver.p = b.parse
	return b.parse, nil
}

// read gives one part of a direction to the connection's pairing and hands
// over every exchange it makes decidable. A growth the reserver refuses cuts
// the connection: it reached the bound on what one connection may hold.
func (w *Worker) read(ctx context.Context, b *batch, d fragment.Direction, part stream.Part) error {
	p := b.parse
	for part.Length > 0 {
		step, err := p.pairing.Feed(d, part)
		if err != nil {
			// The input rules are this worker's to keep; a part they refuse is
			// input it cannot place.
			b.invalid = true
			b.stopParsing()
			return nil
		}
		p.fedBytes += step.Consumed
		if err := w.handOverAll(ctx, b, step.Exchanges); err != nil || b.cut {
			return err
		}
		if step.Result == http1.Refused {
			w.cutRefused(b)
			return nil
		}
		if step.Result.Stopped() {
			p.stopped = true
			for _, one := range []fragment.Direction{fragment.Sent, fragment.Received} {
				p.low[one] = b.place[one].fed
			}
		}
		if step.Consumed >= part.Length {
			break
		}
		part.Offset += step.Consumed
		part.Length -= step.Consumed
		part.Bytes = part.Bytes[step.Consumed:]
	}
	return nil
}

// finishReading declares the connection's input finished and hands over what
// its pairing still holds. A growth the reserver refuses cuts the connection.
func (w *Worker) finishReading(ctx context.Context, b *batch) error {
	p := b.parse
	if p == nil || p.pairing == nil || p.ended {
		return nil
	}
	step := p.pairing.End()
	if err := w.handOverAll(ctx, b, step.Exchanges); err != nil || b.cut {
		return err
	}
	if step.Result == http1.Refused {
		w.cutRefused(b)
		return nil
	}
	p.ended = true
	for _, one := range []fragment.Direction{fragment.Sent, fragment.Received} {
		p.low[one] = b.place[one].fed
	}
	return nil
}

// handOverAll takes the exchanges a pairing step handed over, in order. Where
// one of them cuts the connection, or stops the worker, the rest are let go
// unreleased.
func (w *Worker) handOverAll(ctx context.Context, b *batch, exchanges []reconstruct.Exchange) error {
	for n, x := range exchanges {
		if b.cut {
			b.parse.reserver.Release(x.Charge)
			continue
		}
		if err := w.handOver(ctx, b, x); err != nil {
			for _, rest := range exchanges[n+1:] {
				b.parse.reserver.Release(rest.Charge)
			}
			return err
		}
	}
	return nil
}

// handOver takes one exchange from the pairing: below its messages the
// connection holds nothing for reading. It is released at once, or, where the
// plan configures extensions, put on the connection's chain (Worker.chain).
func (w *Worker) handOver(ctx context.Context, b *batch, x reconstruct.Exchange) error {
	p := b.parse
	role, _ := p.pairing.Role()
	request, response := directions(role)
	if x.Request != nil && request != fragment.Unknown {
		p.low[request] = max(p.low[request], x.Request.End)
	}
	if x.Response != nil && response != fragment.Unknown {
		p.low[response] = max(p.low[response], x.Response.End)
	}
	if w.extensions != nil {
		// Its charge stays until its lines are written (letGo).
		return w.chain(ctx, b, x, role)
	}
	defer p.reserver.Release(x.Charge)
	return w.releaseExchange(ctx, b, x, role)
}

// releaseExchange issues one exchange its id and index and writes its lines,
// one per reconstruction pipeline and route, with the connection's
// provisional record: its retirement has not been read, or need not have
// been. The first exchange that is not complete and supported is excluded, and
// so is every one after it; each still takes an id and an index. Every
// pipeline's copy of a released exchange is made, and charged, before the
// exchange takes its id: a copy the shared allowance refuses cuts the
// connection with nothing of the exchange released, and the copies are given
// back once its lines are written.
func (w *Worker) releaseExchange(ctx context.Context, b *batch, x reconstruct.Exchange, role reconstruct.Role) error {
	p := b.parse
	if !x.Complete || !countableMessage(x.Request) || !countableMessage(x.Response) {
		p.countable = false
	}
	request, response := directions(role)
	identity, err := w.identity(b)
	if err != nil || p.excluded || !supportedExchange(x) {
		index := p.exchanges
		p.exchanges++
		id := w.release.issued.Add(1)
		if !p.excluded {
			p.excluded = true
			for _, side := range []struct {
				direction fragment.Direction
				message   *reconstruct.Message
			}{{request, x.Request}, {response, x.Response}} {
				if side.message != nil && side.direction != fragment.Unknown {
					reason, at := messageStop(side.message)
					p.omitted[side.direction] = &prefixCut{offset: at, reason: reason}
				}
			}
		}
		if err != nil {
			b.invalid = true
		}
		w.reportOne(b, index, id, releaseExcluded)
		return nil
	}
	type copied struct {
		pipeline  config.EffectivePipeline
		processed reconstruct.Connection
		run       *slotRun
	}
	var copies []copied
	var charged int64
	defer func() { w.returnPolicy(b, charged) }()
	one := reconstruct.Connection{Process: b.process, ID: b.id, Role: role, Exchanges: []reconstruct.Exchange{x}}
	for _, pipeline := range w.pipelines {
		if pipeline.Input != config.ReconstructionInput || p.failed[pipeline.Name] {
			continue
		}
		processed, run, held, failed, full := w.policyCopy(b, one, pipeline.Slots)
		if full {
			w.cutByAllowance(b)
			return nil
		}
		if failed {
			// A pipeline that fails writes nothing more for the connection,
			// and is counted once for it.
			w.returnPolicy(b, held)
			p.failed[pipeline.Name] = true
			w.countProcessingFailure(pipeline.Name)
			continue
		}
		charged += held
		copies = append(copies, copied{pipeline: pipeline, processed: processed, run: run})
	}
	index := p.exchanges
	p.exchanges++
	id := w.release.issued.Add(1)
	p.good++
	p.released[request], p.released[response] = x.Request.End, x.Response.End
	evidence := b.exchangeEvidence(x, role)
	outcome := releaseNone
	for _, c := range copies {
		pipeline, processed, run := c.pipeline, c.processed, c.run
		projected, _, err := record.FromReconstruction(reconstruct.Reconstruction{Connections: []reconstruct.Connection{processed}}, nil)
		if err != nil {
			p.failed[pipeline.Name] = true
			w.countProcessingFailure(pipeline.Name)
			continue
		}
		run.mark(&projected[0], processed)
		exchange := projected[0].Exchanges[0]
		exchange.Index = index
		reconstruction := projected[0]
		reconstruction.Unplaced = provisionalUnplaced
		reconstruction.Exchanges = []record.Exchange{exchange}
		exclusions := make([]PolicyExclusion, 0, len(run.evidence.fields))
		for _, entry := range run.evidence.fields {
			entry.Exchange = index
			exclusions = append(exclusions, entry)
		}
		a := Artifact{Version: ArtifactVersion, Record: ArtifactExchange, Session: w.options.Session,
			PolicyRevision: w.options.PolicyRevision, Connection: identity, ExchangeID: strconv.FormatUint(id, 10),
			Index: &index, Reconstruction: &reconstruction, PolicyExclusions: exclusions,
			ExtensionOutcomes: []ExtensionOutcome{}, ReplacementExclusions: []ReplacementExclusion{}}
		for _, route := range w.routes {
			if route.Pipeline != pipeline.Name {
				continue
			}
			a.Route = route
			one, err := w.emit(ctx, a, b.loss, evidence)
			if err != nil {
				return err
			}
			outcome = outcome.worse(one)
		}
	}
	if outcome == releaseNone {
		outcome = releaseExcluded
	}
	w.reportOne(b, index, id, outcome)
	return nil
}

// identity is the provisional record a connection's exchange lines carry:
// from the identity its evidence names, or, where none was taken, from its
// retirement's.
func (w *Worker) identity(b *batch) (record.Connection, error) {
	p := b.parse
	if p.identity != nil {
		return *p.identity, nil
	}
	var one record.Connection
	var err error
	switch {
	case b.evidence.Taken():
		one, err = record.FromIdentity(*b.evidence.Identity)
	case b.retirement != nil:
		one, err = record.FromConnection(*b.retirement)
		one = one.Identified()
	default:
		err = errors.New("no identity for the connection")
	}
	if err != nil {
		return record.Connection{}, err
	}
	p.identity = &one
	return one, nil
}

// reportOne adds one exchange to the turn in progress.
func (w *Worker) reportOne(b *batch, index int, id uint64, outcome releaseOutcome) {
	if w.current == nil {
		return
	}
	w.current.Released = append(w.current.Released, released{Process: b.process, Connection: b.id, Index: index,
		ID: id, Outcome: outcome})
}

// process takes a connection whose retirement is ready: what the retirement
// vouches for is read and released, and its connection lines are written
// (closeConnection). Where exchanges of it are still on their way through the
// extensions, it waits for them instead: its excluded exchanges' reasons are
// decided now, it keeps its leases, and process reports that it waits; its
// lines are written once its chain is through (advanceChain).
func (w *Worker) process(ctx context.Context, b *batch) (bool, error) {
	if !b.invalid && !b.cut && !b.lost {
		if b.evidence.Taken() && b.retirement.Agrees(b.evidence) != nil {
			// The retirement contradicts evidence lines were released on. What
			// was released stays; nothing more is.
			b.invalid = true
		}
	}
	if !b.invalid && !b.cut && !b.lost {
		b.certify()
		if err := w.feed(ctx, b, true); err != nil {
			return false, err
		}
		if !b.invalid && !b.cut {
			if err := w.finishReading(ctx, b); err != nil {
				return false, err
			}
		}
	}
	if len(b.chain) != 0 || b.calling {
		b.ended = true
		w.decideTail(b)
		w.waiting[b] = struct{}{}
		return true, w.advanceChain(ctx, b)
	}
	_, err := w.closeConnection(ctx, b)
	return false, err
}

// closeConnection ends a connection whose input and exchanges are all
// through. Where the plan configures extensions it is sent connection_done;
// then its connection lines are written - with its final record, or naming
// the cut or the capture loss that stopped it - or, refused or unsettled, it
// is withheld. It returns the path its input goes back along.
func (w *Worker) closeConnection(ctx context.Context, b *batch) (held.Path, error) {
	if w.extensions != nil {
		w.connectionDone(b)
	}
	var err error
	switch {
	case b.unsettled:
		w.withhold(connection.Uncounted("unsettled_input"))
		return held.Discarded, nil
	case b.invalid:
		w.withhold(connection.Uncounted("invalid_input"))
		w.countProcessingFailure("")
	case b.cut:
		err = w.processCut(ctx, b)
	case b.lost:
		w.withhold(connection.Uncounted(b.loss.Reason()))
		err = w.processDiscarded(ctx, b, "positions_unknown")
	default:
		metadata, refused := record.FromConnection(*b.retirement)
		if refused != nil {
			w.withhold(connection.Uncounted("invalid_input"))
			w.countProcessingFailure("")
			break
		}
		err = w.retireRead(ctx, b, metadata)
	}
	return processedUnless(err), err
}

// retireRead writes a read connection's connection lines, with its final
// record and the truncation of what it did not release, and counts what it
// withheld.
func (w *Worker) retireRead(ctx context.Context, b *batch, metadata record.Connection) error {
	b.refund()
	var truncation *ReconstructionTruncation
	refused := connection.Counted(0)
	reads := 0
	for _, pipeline := range w.pipelines {
		if pipeline.Input == config.ReconstructionInput {
			reads++
		}
	}
	p := b.parse
	if reads > 0 {
		refused = b.refusals()
		w.withhold(refused)
		if p == nil || len(p.failed) < reads {
			truncation = b.truncation()
		}
	}
	for _, pipeline := range w.pipelines {
		switch pipeline.Input {
		case config.ConnectionInput:
			for _, route := range w.routes {
				if route.Pipeline != pipeline.Name {
					continue
				}
				a := Artifact{Version: ArtifactVersion, Record: ArtifactConnection, Session: w.options.Session,
					PolicyRevision: w.options.PolicyRevision, Route: route, Connection: metadata,
					ReconstructionTruncation: truncation, ReconstructionUnplaced: w.unplacedTotal(b),
					PolicyExclusions: []PolicyExclusion{}, ExtensionOutcomes: []ExtensionOutcome{},
					ReplacementExclusions: []ReplacementExclusion{}}
				if _, err := w.emit(ctx, a, b.loss, b.retirementEvidence()); err != nil {
					return err
				}
			}
		case config.ReconstructionInput:
			// The first slot cannot accept an undecidable message, and nothing
			// later can repair that missing input.
			if (p == nil || !p.failed[pipeline.Name]) && (!refused.Known || refused.Value != 0) {
				w.countProcessingFailure(pipeline.Name)
			}
		default:
			w.countProcessingFailure(pipeline.Name)
		}
	}
	return nil
}

// refusals is the exchanges a read connection withheld: known only where its
// whole content was read as complete, framed HTTP/1 pairs.
func (b *batch) refusals() connection.Count {
	p := b.parse
	prefix := b.prefix()
	if p == nil || p.fedBytes == 0 {
		if b.arrived != 0 || prefix.truncated() {
			return connection.Uncounted("reconstruction_incomplete")
		}
		return connection.Counted(0)
	}
	if prefix.truncated() || !p.countable || p.unplaced() != 0 || p.role() == reconstruct.RoleUnknown {
		return connection.Uncounted("reconstruction_incomplete")
	}
	return connection.Counted(int64(p.exchanges - p.good))
}

func (p *parsing) role() reconstruct.Role {
	if p.pairing == nil {
		return reconstruct.RoleUnknown
	}
	role, _ := p.pairing.Role()
	return role
}

// unplaced is the offsets placed and never read as part of a message, over
// both directions: those the pairing did not place in a message it handed
// over, and those placed after it stopped.
func (p *parsing) unplaced() uint64 {
	if p.pairing == nil {
		return p.skipped
	}
	return p.pairing.Unplaced(fragment.Sent) + p.pairing.Unplaced(fragment.Received) + p.skipped
}

// unplacedTotal is what a connection line states as the connection's
// unplaced total: undetermined where its content was not read to its
// retirement, with why - nothing reads content, the connection was cut, or
// capture lost some of its input - and otherwise determined.
func (w *Worker) unplacedTotal(b *batch) *record.Count {
	reads := slices.ContainsFunc(w.pipelines, func(p config.EffectivePipeline) bool { return p.Input == config.ReconstructionInput })
	why := ""
	switch {
	case !reads:
		why = "not_read"
	case b.cut:
		why = TruncationConnectionCut
	case b.lost:
		why = b.loss.Reason()
	}
	if why != "" {
		return &record.Count{State: record.Undetermined, Unit: record.Bytes, Why: why}
	}
	var n uint64
	if b.parse != nil {
		n = b.parse.unplaced()
	}
	return &record.Count{State: record.Determined, Unit: record.Bytes, Value: strconv.FormatUint(n, 10)}
}

// truncation describes where a read connection's released exchanges stop:
// in each direction it was read past them, the first byte no exchange line
// carries, why, and where the evidence for that lies.
func (b *batch) truncation() *ReconstructionTruncation {
	var released [3]uint64
	var omitted [3]*prefixCut
	if p := b.parse; p != nil {
		released, omitted = p.released, p.omitted
	}
	prefix := b.prefix()
	var stops []TruncationStop
	for _, d := range []fragment.Direction{fragment.Sent, fragment.Received} {
		one := prefix[d]
		if one.cut == nil && one.end <= released[d] {
			continue
		}
		reason, at := "unparsed_suffix", released[d]
		if m := omitted[d]; m != nil {
			reason, at = m.reason, m.offset
		}
		// A capture cutoff causing parser end-of-input remains a capture
		// reason. An earlier parse defect remains its own reason instead.
		if one.cut != nil && (omitted[d] == nil || one.cut.offset <= at) {
			reason, at = one.cut.reason, one.cut.offset
		}
		stops = append(stops, TruncationStop{Direction: d.String(), Offset: strconv.FormatUint(released[d], 10),
			Reason: reason, EvidenceOffset: strconv.FormatUint(at, 10)})
	}
	if len(stops) == 0 {
		return nil
	}
	return &ReconstructionTruncation{State: "truncated", Suffix: "indeterminate", Stops: stops}
}

// processCut writes the connection line of a connection cut at the bound on
// what one connection may hold. What it held unreleased was discarded, so the
// line's truncation stops in each direction at the first byte no exchange line
// carries, naming the cut, and its evidence offset is how far that direction's
// input ran. What it released stays, with its ids and indexes. A cut is
// counted as itself (Outcome.ConnectionsCut), never as a processing failure.
func (w *Worker) processCut(ctx context.Context, b *batch) error {
	w.withhold(connection.Uncounted("connection_cut"))
	return w.processDiscarded(ctx, b, TruncationConnectionCut)
}

// processDiscarded emits only a retirement's metadata, with no further
// content or extension work. Its truncation starts at the first byte the
// connection did not release, zero where it released nothing, because none of
// the discarded input was read. The loss token refuses content, not this
// evidence of its loss; the ordinary gate still authorizes the line and can
// refuse it for a terminal capture fault.
func (w *Worker) processDiscarded(ctx context.Context, b *batch, reason string) error {
	metadata, err := record.FromConnection(*b.retirement)
	if err != nil {
		w.withhold(connection.Uncounted("invalid_input"))
		w.countProcessingFailure("")
		return nil
	}
	var released [3]uint64
	if b.parse != nil {
		released = b.parse.released
	}
	var stops []TruncationStop
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if _, carried := b.retirement.Placement(direction); !carried && b.reached[direction] == 0 {
			continue
		}
		stops = append(stops, TruncationStop{Direction: direction.String(), Offset: strconv.FormatUint(released[direction], 10),
			Reason: reason, EvidenceOffset: strconv.FormatUint(max(b.reached[direction], released[direction]), 10)})
	}
	var truncation *ReconstructionTruncation
	if len(stops) != 0 {
		truncation = &ReconstructionTruncation{State: "truncated", Suffix: "indeterminate", Stops: stops}
	}
	for _, p := range w.pipelines {
		if p.Input != config.ConnectionInput {
			continue
		}
		for _, route := range w.routes {
			if route.Pipeline != p.Name {
				continue
			}
			artifact := Artifact{Version: ArtifactVersion, Record: ArtifactConnection,
				Session: w.options.Session, PolicyRevision: w.options.PolicyRevision, Route: route,
				Connection: metadata, ReconstructionTruncation: truncation, ReconstructionUnplaced: w.unplacedTotal(b),
				PolicyExclusions: []PolicyExclusion{}, ExtensionOutcomes: []ExtensionOutcome{},
				ReplacementExclusions: []ReplacementExclusion{}}
			if _, err := w.emit(ctx, artifact, nil, b.retirementEvidence()); err != nil {
				return err
			}
		}
	}
	return nil
}

// exclusionReason is the truncation reason a connection line records for an
// exchange it does not write: the stop in the direction of the side that kept
// it out - the request where that is not a supported message, otherwise the
// response - or the line's other stop where that direction has none.
func exclusionReason(e reconstruct.Exchange, role reconstruct.Role, truncation *ReconstructionTruncation) string {
	request, response := fragment.Sent, fragment.Received
	if role == reconstruct.Server {
		request, response = response, request
	}
	direction := response
	if e.Request == nil || !supportedMessage(e.Request) {
		direction = request
	}
	reason := "unparsed_suffix"
	if truncation == nil {
		return reason
	}
	for _, stop := range truncation.Stops {
		if stop.Direction == direction.String() {
			return stop.Reason
		}
		reason = stop.Reason
	}
	return reason
}

// Cardinality needs framing and pairing, independently of whether the body
// encoding or retained body is supported by processing. Switching protocols or
// interim responses defeat the parser's one-request/one-response pairing.
func countableMessage(m *reconstruct.Message) bool {
	if m == nil || !m.Complete || !m.Framed || m.Defect != http1.DefectNone || m.BodyHoled != 0 {
		return false
	}
	if m.Protocol != "HTTP/1.0" && m.Protocol != "HTTP/1.1" {
		return false
	}
	if strings.EqualFold(m.Method, "CONNECT") || (m.Kind == http1.Response && m.Status < 200) {
		return false
	}
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, "upgrade") {
			return false
		}
	}
	return true
}

func messageStop(m *reconstruct.Message) (string, uint64) {
	switch m.Defect {
	case http1.DefectStreamEnded:
		return "incomplete_message", m.End
	case http1.DefectHole:
		return "capture_hole", m.End
	case http1.DefectMalformed:
		return "malformed_message", m.End
	case http1.DefectAmbiguousFraming:
		return "ambiguous_framing", m.End
	case http1.DefectLimit:
		return "processing_limit", m.End
	}
	if m.BodyElided != 0 {
		return "processing_limit", m.End
	}
	if !m.Complete || !m.Framed {
		return "incomplete_message", m.End
	}
	if !supportedMessage(m) {
		return "unsupported_message", m.Offset
	}
	return "unpaired_exchange", m.Offset
}

// A batch refusal affects every route; a pipeline refusal affects only that
// pipeline's routes. A failure drops the output it concerns and is counted;
// the pipeline goes on with the next batch.
func (w *Worker) countProcessingFailure(pipeline string) {
	for _, route := range w.routes {
		if pipeline == "" || route.Pipeline == pipeline {
			w.outcome.ProcessingFailures++
		}
	}
}

func (w *Worker) emit(ctx context.Context, artifact Artifact, loss *held.Loss, evidence probe.ReleaseEvidence) (releaseOutcome, error) {
	line, err := json.Marshal(artifact)
	if err != nil {
		// Artifact is built by this binary from serializable contract types.
		// Reaching this branch means the observer's invariant is broken, not
		// bad captured input or an operator's deployment fault. Fold it into
		// the existing terminal error and seal reason, with no failure counter:
		// nothing was authorized or handed to the output writer here.
		return releaseNone, errors.New("internal observer defect: cannot serialize its approved artifact")
	}
	line = append(line, '\n')
	return w.release.write(ctx, Approved{line: line}, &w.outcome, loss, evidence)
}

// releaseEvidence is what an extension's derived line states: its own record,
// not a connection's prefix, written for a call made on a released exchange.
// Every line of a connection states its own (batch.exchangeEvidence,
// batch.retirementEvidence).
var releaseEvidence = probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}

// release orders short enqueue decisions shared by all workers. Sink I/O runs
// on the queue's goroutine, outside both this lock and the gate's lock.
type release struct {
	mutex  sync.Mutex
	gate   *probe.DeliveryGate
	output Output
	err    error
	// issued is the exchange ids issued so far, from 1: a batch takes its
	// range with one addition, so ranges are contiguous and never overlap.
	issued atomic.Uint64
}

// write authorizes and writes one line, counting into outcome, and reports
// what the line's release came to. evidence is what the line's own input and
// lifecycle establish (batch.exchangeEvidence, batch.retirementEvidence); the
// gate refuses a line whose evidence does not settle both.
func (r *release) write(ctx context.Context, line Approved, outcome *Outcome, loss *held.Loss, evidence probe.ReleaseEvidence) (releaseOutcome, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.err != nil {
		return releaseNone, r.err
	}
	if err := ctx.Err(); err != nil {
		return releaseNone, err
	}
	var delivery error
	accepted := false
	decision := r.gate.AuthorizeEnqueue(evidence, func() {
		accepted = loss.Authorize(func() { delivery = r.output.WriteApproved(ctx, line) })
	})
	if !decision.Authorized {
		outcome.GateReason = decision.Reason
		return releaseUnauthorized, nil
	}
	if !accepted {
		return releaseWithdrawn, nil
	}
	outcome.Authorized++
	if delivery != nil {
		outcome.OutputFailures++
		return releaseDropped, nil
	}
	outcome.Written++
	return releaseEnqueued, nil
}

// fail makes err terminal for every worker sharing this release, unless an
// earlier failure already is.
func (r *release) fail(err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.err == nil {
		r.err = err
	}
}

func (r *release) failure() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.err
}

func supportedExchange(e reconstruct.Exchange) bool {
	return e.Complete && supportedMessage(e.Request) && supportedMessage(e.Response)
}

func supportedMessage(m *reconstruct.Message) bool {
	if m == nil || !m.Complete || !m.Framed || m.Defect != http1.DefectNone || m.BodyHoled != 0 || m.BodyElided != 0 {
		return false
	}
	if m.Protocol != "HTTP/1.0" && m.Protocol != "HTTP/1.1" {
		return false
	}
	if strings.EqualFold(m.Method, "CONNECT") || (m.Kind == http1.Response && m.Status < 200) {
		return false
	}
	encodings := 0
	for _, h := range m.Headers {
		switch strings.ToLower(h.Name) {
		case "upgrade":
			return false
		case "content-encoding":
			if !strings.EqualFold(strings.TrimSpace(h.Value), "identity") {
				return false
			}
		case "transfer-encoding":
			encodings++
			if encodings > 1 || !strings.EqualFold(strings.TrimSpace(h.Value), "chunked") {
				return false
			}
		}
	}
	return true
}

func copyConnection(source reconstruct.Connection) reconstruct.Connection {
	out := source
	out.Exchanges = make([]reconstruct.Exchange, len(source.Exchanges))
	for i, e := range source.Exchanges {
		out.Exchanges[i] = reconstruct.Exchange{Request: copyMessage(e.Request), Response: copyMessage(e.Response), Complete: e.Complete}
	}
	return out
}

func copyMessage(source *reconstruct.Message) *reconstruct.Message {
	if source == nil {
		return nil
	}
	out := *source
	out.Headers, out.Trailers = slices.Clone(source.Headers), slices.Clone(source.Trailers)
	out.Body = slices.Clone(source.Body)
	out.Detail = ""
	if out.ShapeRefused != "" {
		out.ShapeRefused = "body structure unavailable"
	}
	return &out
}

type exclusionEvidence struct {
	fields []PolicyExclusion
	seen   map[PolicyExclusion]struct{}
}

// add records one removal once, however many occurrences or slots it covers.
func (e *exclusionEvidence) add(entry PolicyExclusion) {
	if e.seen == nil {
		e.seen = make(map[PolicyExclusion]struct{})
	}
	if _, exists := e.seen[entry]; exists {
		return
	}
	e.seen[entry] = struct{}{}
	e.fields = append(e.fields, entry)
}

// slotRun is one pipeline's pass over a copy of the parsed connection. Body
// operations read header facts from source, the connection as parsed, so no
// header operation earlier in the route changes what they admit.
type slotRun struct {
	source   reconstruct.Connection
	evidence exclusionEvidence
	// bodies holds what policy did to a processed message's body: removed, or
	// values_removed. A message absent from it kept its body.
	bodies map[*reconstruct.Message]string
	shapes jsonshape.Limits
}

func (r *slotRun) apply(c *reconstruct.Connection, slot config.EffectiveSlot) bool {
	a := slot.Arguments
	if a == nil {
		return false
	}
	switch slot.Implementation {
	case config.RemoveHeaders, config.ReplaceHeaderValues, config.TruncateHeaderValues,
		config.RemoveBody, config.ReduceBodyToStructure, config.RemoveQuery,
		config.RemoveJSONFields, config.ReplaceJSONValues, config.RemoveFormFields, config.RemoveQueryParameters,
		config.RequestBodyFields:
	default:
		return false
	}
	for index, e := range c.Exchanges {
		for side, m := range []*reconstruct.Message{e.Request, e.Response} {
			// A one-sided exchange, which is never written and is still sent
			// to extensions, has no message on its missing side.
			if m == nil {
				continue
			}
			message := config.MessageRequest
			if side == 1 {
				message = config.MessageResponse
			}
			where := PolicyExclusion{Exchange: index, Message: message, Disposition: DispositionRemoved}
			switch slot.Implementation {
			case config.RemoveHeaders, config.ReplaceHeaderValues, config.TruncateHeaderValues:
				where.Section = "headers"
				m.Headers = r.transformFields(m.Headers, slot, where)
				where.Section = "trailers"
				m.Trailers = r.transformFields(m.Trailers, slot, where)
			case config.RemoveBody:
				if slices.Contains(a.Messages, message) && (len(m.Body) > 0 || r.bodies[m] == DispositionValuesRemoved) {
					r.removeBody(m, where, DispositionRemoved)
				}
			case config.ReduceBodyToStructure:
				if slices.Contains(a.Messages, message) && len(m.Body) > 0 {
					if m.Shape == nil {
						r.removeBody(m, where, DispositionRemoved)
						break
					}
					m.Body = nil
					r.bodies[m] = DispositionValuesRemoved
					where.Field, where.Disposition = config.BodyValuesField, DispositionValuesRemoved
					r.evidence.add(where)
				}
			case config.RemoveJSONFields, config.ReplaceJSONValues:
				if slices.Contains(a.Messages, message) && len(m.Body) > 0 {
					r.editBody(m, slot, where)
				}
			case config.RemoveFormFields:
				if side == 0 && len(m.Body) > 0 {
					if !admittedForm(r.source.Exchanges[index].Request) {
						r.removeBody(m, where, DispositionRemovedUndecidable)
						break
					}
					body, matched, undecidable := removeParameters(string(m.Body), a.Names)
					if undecidable {
						r.removeBody(m, where, DispositionRemovedUndecidable)
						break
					}
					r.spliced(m, []byte(body), matched, config.FormFieldPrefix, where)
				}
			case config.RequestBodyFields:
				if side == 0 && len(m.Body) > 0 {
					r.requestBody(m, r.source.Exchanges[index].Request, a, where)
				}
			case config.RemoveQuery:
				if side == 0 {
					if cut := strings.IndexByte(m.Target, '?'); cut >= 0 {
						m.Target = m.Target[:cut]
						where.Field = config.TargetQueryField
						r.evidence.add(where)
					}
				}
			case config.RemoveQueryParameters:
				if side == 0 {
					if path, query, has := strings.Cut(m.Target, "?"); has {
						kept, matched, undecidable := removeParameters(query, a.Names)
						if undecidable {
							m.Target = path
							where.Field, where.Disposition = config.TargetQueryField, DispositionRemovedUndecidable
							r.evidence.add(where)
							break
						}
						m.Target = path + "?" + kept
						for _, name := range matched {
							where.Field = config.QueryFieldPrefix + name
							r.evidence.add(where)
						}
					}
				}
			}
		}
	}
	return true
}

func (r *slotRun) transformFields(fields []http1.Header, slot config.EffectiveSlot, where PolicyExclusion) []http1.Header {
	out := fields[:0]
	for _, h := range fields {
		name := strings.ToLower(h.Name)
		if slices.Contains(slot.Arguments.Headers, name) {
			switch slot.Implementation {
			case config.RemoveHeaders:
				where.Field = config.HeaderFieldPrefix + name
				r.evidence.add(where)
				continue
			case config.ReplaceHeaderValues:
				h.Value = slot.Arguments.Value
			case config.TruncateHeaderValues:
				h.Value = h.Value[:min(len(h.Value), slot.Arguments.Length)]
			}
		}
		out = append(out, h)
	}
	return out
}

// removeBody drops a body's bytes and structure; its length and framing stay.
func (r *slotRun) removeBody(m *reconstruct.Message, where PolicyExclusion, disposition string) {
	m.Body, m.Shape, m.ShapeRefused = nil, nil, ""
	r.bodies[m] = DispositionRemoved
	where.Field, where.Disposition = config.BodyField, disposition
	r.evidence.add(where)
}

func (r *slotRun) editBody(m *reconstruct.Message, slot config.EffectiveSlot, where PolicyExclusion) {
	var replacement []byte
	if slot.Implementation == config.ReplaceJSONValues {
		replacement = jsonString(slot.Arguments.Value)
	}
	body, hits, err := editJSON(m.Body, slot.Arguments.Pointers, replacement)
	if err != nil {
		r.removeBody(m, where, DispositionRemovedUndecidable)
		return
	}
	var matched []string
	for i, hit := range hits {
		if hit {
			matched = append(matched, slot.Arguments.Pointers[i])
		}
	}
	if replacement != nil {
		// A replaced value is not a removal and records no entry.
		r.spliced(m, body, nil, config.JSONFieldPrefix, where)
		return
	}
	r.spliced(m, body, matched, config.JSONFieldPrefix, where)
}

// spliced keeps a body whose other bytes are unchanged, records a removal for
// each selector that matched, and derives the structure again from what is
// kept, so it never describes a removed member.
func (r *slotRun) spliced(m *reconstruct.Message, body []byte, matched []string, prefix string, where PolicyExclusion) {
	for _, selector := range matched {
		where.Field = prefix + selector
		r.evidence.add(where)
	}
	if string(body) == string(m.Body) {
		return
	}
	m.Body = body
	m.Shape, m.ShapeRefused = nil, ""
	if shape, err := jsonshape.Extract(body, r.shapes); err == nil {
		m.Shape = &shape
	} else {
		m.ShapeRefused = "body structure unavailable"
	}
}

// mark writes into the projection what policy did to each body: a removed
// body keeps its length and framing, has no kept bytes and has structure
// state removed; a body whose values went keeps its derived structure.
func (r *slotRun) mark(projected *record.Reconstruction, processed reconstruct.Connection) {
	for i, e := range processed.Exchanges {
		for _, pair := range []struct {
			source *reconstruct.Message
			side   record.Side
		}{{e.Request, projected.Exchanges[i].Request}, {e.Response, projected.Exchanges[i].Response}} {
			if pair.side.Message == nil {
				continue
			}
			switch r.bodies[pair.source] {
			case DispositionRemoved:
				pair.side.Message.Body.Kept = ""
				pair.side.Message.Structure = record.Structure{State: record.StructureRemoved}
			case DispositionValuesRemoved:
				pair.side.Message.Body.Kept = ""
			}
		}
	}
}
