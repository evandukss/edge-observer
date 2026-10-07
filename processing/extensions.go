package processing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/jsonshape"
	"github.com/evandukss/edge-observer/reconstruct"
)

// extensions is a Run's extensions: one supervisor each, and the observer's
// own count of every exchange's outcome at each.
type extensions struct {
	entries     []config.Extension
	supervisors []*extension.Supervisor
	files       []*derivedFile

	mutex   sync.Mutex
	tallies []tally
}

// tally is one extension's exchange counts. Every id issued adds to
// considered and pending; each outcome moves one from pending.
type tally struct {
	considered, changed, unchanged, failed, pending uint64
	failedBy                                        map[string]uint64
}

// startExtensions starts a supervisor per configured extension, each with its
// derived file open. It returns nil where none is configured.
func startExtensions(options Options, r *release) (*extensions, error) {
	entries := options.Plan.Extensions()
	if len(entries) == 0 {
		return nil, nil
	}
	clock := options.Clock
	if clock == nil {
		clock = extension.System()
	}
	writeContent := slices.ContainsFunc(options.Plan.Pipelines(), func(p config.EffectivePipeline) bool {
		return p.Input == config.ReconstructionInput
	})
	waiting := extension.WaitingBytes(options.Intake.Stats().LimitBytes, len(entries))
	e := &extensions{entries: entries}
	for _, one := range entries {
		file, err := options.Derived.openDerived(one.Name)
		if err != nil {
			e.close()
			return nil, err
		}
		e.files = append(e.files, file)
		e.tallies = append(e.tallies, tally{failedBy: zeroed(account.ExtensionFailureReasons)})
	}
	for i, one := range entries {
		file := e.files[i]
		e.supervisors = append(e.supervisors, extension.Start(extension.Config{
			Name: one.Name, Command: one.Command, Fields: ordered(one.Fields), TimeoutMS: one.TimeoutMS,
			Session: options.Session, Revision: options.PolicyRevision, WriteContent: writeContent,
			WaitingBytes: waiting, Clock: clock, Events: options.Supervision,
			Issued:  r.issued.Load,
			Derived: func(line []byte) string { return r.writeDerived(options.Derived, file, line) },
		}))
	}
	return e, nil
}

func zeroed(vocabulary []string) map[string]uint64 {
	counts := make(map[string]uint64, len(vocabulary))
	for _, key := range vocabulary {
		counts[key] = 0
	}
	return counts
}

// ordered is fields in the protocol's order.
func ordered(fields []string) []string {
	var out []string
	for _, f := range config.ExtensionFields {
		if slices.Contains(fields, f) {
			out = append(out, f)
		}
	}
	return out
}

// end stops every extension in order, together, and closes the derived files.
func (e *extensions) end() {
	if e == nil {
		return
	}
	var done sync.WaitGroup
	for _, s := range e.supervisors {
		done.Go(s.End)
	}
	done.Wait()
	e.close()
}

// abort ends every extension at once and closes the derived files.
func (e *extensions) abort() {
	if e == nil {
		return
	}
	var done sync.WaitGroup
	for _, s := range e.supervisors {
		done.Go(s.Close)
	}
	done.Wait()
	e.close()
}

func (e *extensions) close() {
	for _, f := range e.files {
		_ = f.close()
	}
}

// issue adds n ids to every extension's considered and pending.
func (e *extensions) issue(n uint64) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	for i := range e.tallies {
		e.tallies[i].considered += n
		e.tallies[i].pending += n
	}
}

// count moves one exchange at extension k from pending to its outcome.
func (e *extensions) count(k int, outcome, reason string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	t := &e.tallies[k]
	t.pending--
	switch outcome {
	case extension.Changed:
		t.changed++
	case extension.Unchanged:
		t.unchanged++
	default:
		t.failed++
		t.failedBy[reason]++
	}
}

// counts is every extension's counts now, in the order they run.
func (e *extensions) counts() []account.ExtensionCounts {
	if e == nil {
		return []account.ExtensionCounts{}
	}
	out := make([]account.ExtensionCounts, 0, len(e.entries))
	for i, one := range e.entries {
		lifecycle := e.supervisors[i].Counts()
		e.mutex.Lock()
		t := e.tallies[i]
		c := account.NoCounts(one.Name)
		c.Considered, c.Changed, c.Unchanged, c.Failed, c.Pending = t.considered, t.changed, t.unchanged, t.failed, t.pending
		c.FailedBy = maps.Clone(t.failedBy)
		e.mutex.Unlock()
		c.RetiredBy = lifecycle.RetiredBy
		c.Restarts, c.StateResets, c.Late, c.Duplicate = lifecycle.Restarts, lifecycle.StateResets, lifecycle.Late, lifecycle.Duplicate
		c.DerivedWritten, c.DerivedBytes, c.DerivedRefused = lifecycle.DerivedWritten, lifecycle.DerivedBytes, lifecycle.DerivedRefused
		c.DerivedRefusedBy = lifecycle.DerivedRefusedBy
		delivery := e.files[i].writer.DerivedStats(one.Name)
		c.Delivery = delivery
		c.DerivedWritten, c.DerivedBytes = delivery.Written, uint64(delivery.Bytes)
		c.DerivedRefused += delivery.Failed + delivery.Discarded
		c.DerivedRefusedBy[extension.DerivedWriteFailed] += delivery.Failed
		c.DerivedRefusedBy[extension.DerivedStopped] += delivery.Discarded
		c.StderrDropped = lifecycle.StderrDropped
		out = append(out, c)
	}
	return out
}

// dispatch is one exchange on its way through the extensions to its lines:
// its id and index, the exchange as handed over and the reconstruction
// pipeline's copy of it as the chain leaves it, what each extension did to it,
// and where it is in the chain. It holds the exchange's charges - what it was
// handed over with (intake.Parsing) and its copy's (intake.Policy) - until its
// lines are written or it is let go (letGo).
type dispatch struct {
	b     *batch
	id    uint64
	index int
	role  reconstruct.Role
	// excluded is an exchange the output will not write, and reason why, once
	// that is decidable; "" until then.
	excluded bool
	reason   string

	// source is the exchange as handed over. processed is the first
	// reconstruction pipeline's copy of it (w.pipelines[reconstruction]), alone
	// in its connection, with its pipeline's evidence and what it did to bodies
	// (run), charged policy; pipelines are the reconstruction pipelines that
	// write it.
	source         reconstruct.Exchange
	reconstruction int
	processed      reconstruct.Connection
	run            *slotRun
	policy         int64
	pipelines      []string

	outcomes []ExtensionOutcome
	replaced []ReplacementExclusion
	// changedBy is, per field, the outcome that last changed it.
	changedBy map[string]int

	// k is the extension the exchange is at. dead is an exchange let go
	// before its chain was through: a result that still arrives is counted,
	// and nothing more is done with it.
	k    int
	dead bool
}

// submission is one extension call as a worker is about to submit it: the
// exchange's id, the extension's index in the plan, what the call is admitted
// at (extension.Call.Bytes), the length of its encoded message, and the
// connection's current accounted charge in the shared allowance
// (batch.charged). The call is admitted at that charge, so Bytes is Charged.
type submission struct {
	ID        uint64
	Extension int
	Bytes     int64
	Message   int
	Charged   int64
}

// completion is an extension's result for the call a dispatch waits on.
type completion struct {
	d      *dispatch
	k      int
	result extension.Result
}

// chain issues an exchange the pairing handed over its id and index and puts
// it on its connection's chain, behind the exchanges before it: each goes
// through every extension in turn, one at a time, and then its lines are
// written. The first reconstruction pipeline's copy, which every extension
// and every line reads, is made and charged before the id is issued: a copy
// the shared allowance refuses cuts the connection with nothing of the
// exchange released. The first exchange that is not complete and supported
// is excluded, and so is every one after it; each still takes an id and an
// index, and is sent as excluded once its reason is decidable (settled), at
// the latest at the connection's end or cut (decideTail).
func (w *Worker) chain(ctx context.Context, b *batch, x reconstruct.Exchange, role reconstruct.Role) error {
	p := b.parse
	if !x.Complete || !countableMessage(x.Request) || !countableMessage(x.Response) {
		p.countable = false
	}
	_, err := w.identity(b)
	d := &dispatch{b: b, role: role, source: x, changedBy: map[string]int{},
		excluded: err != nil || p.excluded || !supportedExchange(x)}
	one := reconstruct.Connection{Process: b.process, ID: b.id, Role: role, Exchanges: []reconstruct.Exchange{x}}
	for i, pipeline := range w.pipelines {
		if pipeline.Input != config.ReconstructionInput || p.failed[pipeline.Name] {
			continue
		}
		processed, run, held, failed, full := w.policyCopy(b, one, pipeline.Slots)
		if full {
			w.returnPolicy(b, d.policy)
			p.reserver.Release(x.Charge)
			w.cutByAllowance(b)
			return nil
		}
		if !failed {
			// Projected now, so it cannot fail to reach an extension later for
			// want of a record.
			if _, _, err := record.FromReconstruction(reconstruct.Reconstruction{Connections: []reconstruct.Connection{processed}}, nil); err != nil {
				failed = true
			}
		}
		if failed {
			// A pipeline that fails writes nothing more for the connection,
			// and is counted once for it.
			w.returnPolicy(b, held)
			p.failed[pipeline.Name] = true
			w.countProcessingFailure(pipeline.Name)
			continue
		}
		if d.run == nil {
			d.reconstruction, d.processed, d.run, d.policy = i, processed, run, held
		} else {
			w.returnPolicy(b, held)
		}
		d.pipelines = append(d.pipelines, pipeline.Name)
	}
	if d.run == nil {
		// No pipeline can give an extension its record of it: it is not
		// released, as nothing of a connection was when that was found at its
		// retirement.
		p.reserver.Release(x.Charge)
		return nil
	}
	request, response := directions(role)
	d.index = p.exchanges
	p.exchanges++
	d.id = w.release.issued.Add(1)
	w.extensions.issue(1)
	if d.excluded {
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
		d.reason = b.settled(d)
	} else {
		p.good++
		p.released[request], p.released[response] = x.Request.End, x.Response.End
	}
	b.chain = append(b.chain, d)
	return w.advanceChain(ctx, b)
}

// advanceChain takes a connection's chain as far as it goes now. The first
// exchange is sent to its next extension unless it has a call outstanding, or
// is excluded and its reason is not yet decidable; one through every
// extension has its lines written and is let go, and the next one starts.
// Once the chain is through and the connection has ended, its connection_done
// is sent and its connection lines written (closeConnection), and it is let
// go.
func (w *Worker) advanceChain(ctx context.Context, b *batch) error {
	if b.cut {
		w.decideTail(b)
	}
	for len(b.chain) > 0 && !b.calling {
		d := b.chain[0]
		if d.excluded && d.reason == "" {
			if d.reason = b.settled(d); d.reason == "" {
				break
			}
		}
		waits, err := w.step(d)
		if err != nil {
			return err
		}
		if waits {
			b.calling = true
			break
		}
		b.chain[0] = nil
		b.chain = b.chain[1:]
		err = w.writeExchange(ctx, d)
		w.letGo(d)
		// Its input is no longer held for it.
		b.refund()
		if err != nil {
			return err
		}
	}
	if len(b.chain) == 0 {
		b.chain = nil
	}
	if !b.ended || b.calling || len(b.chain) != 0 {
		return nil
	}
	path, err := w.closeConnection(ctx, b)
	b.release(path)
	w.waiting = held.Deleted(w.waiting, b, &w.waitingChurn)
	return err
}

// settled is the reason an excluded exchange's connection line will record for
// it, where nothing later can change that reason; "" where something can, and
// the exchange waits for the connection's end or cut (decideTail). It is
// settled where, in the direction the reason comes from (exclusionReason),
// the first exchange not released stopped below what has been read there, and
// capture has stopped nothing there: a stop capture records later is never
// below what was read, so it cannot take the reason over.
func (b *batch) settled(d *dispatch) string {
	request, response := fragment.Sent, fragment.Received
	if d.role == reconstruct.Server {
		request, response = response, request
	}
	direction := response
	if d.source.Request == nil || !supportedMessage(d.source.Request) {
		direction = request
	}
	omitted := b.parse.omitted[direction]
	if omitted == nil || b.place[direction].stop != nil || omitted.offset >= b.place[direction].fed {
		return ""
	}
	return omitted.reason
}

// decideTail gives every held excluded exchange of a connection the reason
// its connection line records for it, now that it is decidable: the cut, the
// capture loss, or, at its end, the truncation of what it read.
func (w *Worker) decideTail(b *batch) {
	var truncation *ReconstructionTruncation
	read := false
	for _, d := range b.chain {
		if !d.excluded || d.reason != "" {
			continue
		}
		switch {
		case b.cut:
			d.reason = TruncationConnectionCut
		case b.lost:
			d.reason = "positions_unknown"
		default:
			if !read {
				truncation, read = b.truncation(), true
			}
			d.reason = exclusionReason(d.source, d.role, truncation)
		}
	}
}

// letGo gives back what a dispatch holds: its copy's charge and what its
// exchange was handed over with, once.
func (w *Worker) letGo(d *dispatch) {
	w.returnPolicy(d.b, d.policy)
	d.policy = 0
	if p := d.b.parse; p != nil {
		p.reserver.Release(d.source.Charge)
	}
	d.source.Charge = http1.Charge{}
}

// drop lets go of every exchange on a connection's chain without writing it:
// results still outstanding are counted when they arrive.
func (w *Worker) drop(b *batch) {
	for _, d := range b.chain {
		d.dead = true
		w.letGo(d)
	}
	b.chain, b.calling = nil, false
}

// writeExchange writes an exchange that has been through every extension: one
// line per reconstruction pipeline that writes it and route, with its id and
// index, the connection's provisional record, the chain's copy of it and what
// each extension did to it. An excluded exchange writes nothing.
func (w *Worker) writeExchange(ctx context.Context, d *dispatch) error {
	b := d.b
	if d.excluded {
		w.reportOne(b, d.index, d.id, releaseExcluded)
		return nil
	}
	outcome := releaseNone
	projected, _, err := record.FromReconstruction(reconstruct.Reconstruction{Connections: []reconstruct.Connection{d.processed}}, nil)
	if err != nil {
		for _, name := range d.pipelines {
			b.parse.failed[name] = true
			w.countProcessingFailure(name)
		}
		w.reportOne(b, d.index, d.id, releaseExcluded)
		return nil
	}
	d.run.mark(&projected[0], d.processed)
	exchange := projected[0].Exchanges[0]
	exchange.Index = d.index
	reconstruction := projected[0]
	reconstruction.Unplaced = provisionalUnplaced
	reconstruction.Exchanges = []record.Exchange{exchange}
	exclusions := make([]PolicyExclusion, 0, len(d.run.evidence.fields))
	for _, entry := range d.run.evidence.fields {
		entry.Exchange = d.index
		exclusions = append(exclusions, entry)
	}
	replaced := make([]ReplacementExclusion, 0, len(d.replaced))
	for _, entry := range d.replaced {
		entry.Exchange = d.index
		replaced = append(replaced, entry)
	}
	evidence := b.exchangeEvidence(d.source, d.role)
	for _, name := range d.pipelines {
		a := Artifact{Version: ArtifactVersion, Record: ArtifactExchange, Session: w.options.Session,
			PolicyRevision: w.options.PolicyRevision, Connection: *b.parse.identity, ExchangeID: strconv.FormatUint(d.id, 10),
			Index: &d.index, Reconstruction: &reconstruction, PolicyExclusions: exclusions, ExtensionOutcomes: d.outcomes,
			ReplacementExclusions: replaced}
		for _, route := range w.routes {
			if route.Pipeline != name {
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
	w.reportOne(b, d.index, d.id, outcome)
	return nil
}

// step submits d's next call, resolving every one that skips its extension
// at once - one its connection's capture loss withdrew as withdrawn - and
// reports whether d now waits for a result. A call is admitted
// at its connection's current charge in the shared allowance (batch.charged).
// d was projected when it was copied and after each change, so a message that
// cannot be encoded is the observer's defect, returned as terminal.
func (w *Worker) step(d *dispatch) (bool, error) {
	exts := w.extensions
	for d.k < len(exts.supervisors) {
		k := d.k
		message, err := w.exchangeMessage(d, k)
		if err != nil {
			return false, errors.New("internal observer defect: cannot encode an exchange for an extension")
		}
		charged := d.b.charged()
		if w.options.submits != nil {
			w.options.submits(submission{ID: d.id, Extension: k, Bytes: charged, Message: len(message), Charged: charged})
		}
		var reason string
		// Submit only enqueues; order that handoff against this connection's
		// capture loss, which withdraws the exchange's content.
		if !d.b.loss.Authorize(func() {
			reason = exts.supervisors[k].Submit(extension.Call{ID: d.id, Bytes: charged, Message: message,
				Done: func(result extension.Result) {
					w.queue.complete(completion{d: d, k: k, result: result})
				}})
		}) {
			reason = extension.Withdrawn
		}
		if reason == "" {
			return true, nil
		}
		w.resolve(d, k, extension.Result{Outcome: extension.Failed, Reason: reason})
	}
	return false, nil
}

// resolve applies extension k's result for d, counts it, and moves d to its
// next extension. A change whose growth the shared allowance has no room for
// fails as no_room, and cuts the connection.
func (w *Worker) resolve(d *dispatch, k int, result extension.Result) {
	exts := w.extensions
	name := exts.entries[k].Name
	outcome := ExtensionOutcome{Exchange: d.index, Extension: name, Outcome: result.Outcome}
	switch {
	case result.Outcome == extension.Changed && !d.dead:
		changed, reason := w.change(d, k, result.Changes)
		if reason != "" {
			outcome = ExtensionOutcome{Exchange: d.index, Extension: name, Outcome: extension.Failed, Reason: reason}
			if reason == extension.NoRoom {
				w.cutByAllowance(d.b)
			}
			break
		}
		outcome.Changed, outcome.Overwritten = changed, []string{}
		for _, field := range changed {
			if previous, ok := d.changedBy[field]; ok {
				d.outcomes[previous].Overwritten = append(d.outcomes[previous].Overwritten, field)
			}
			d.changedBy[field] = len(d.outcomes)
		}
	case result.Outcome == extension.Changed, result.Outcome == extension.Unchanged:
	default:
		outcome.Outcome, outcome.Reason = extension.Failed, result.Reason
	}
	d.outcomes = append(d.outcomes, outcome)
	exts.count(k, outcome.Outcome, outcome.Reason)
	d.k++
}

// connectionDone tells every extension that a connection has no more
// exchanges: once for each connection issued an id, counting them, and once,
// counting none, for one that ends with none issued and was not refused whole.
// It carries the connection's ending where its retirement record can be read.
func (w *Worker) connectionDone(b *batch) {
	issued := 0
	if b.parse != nil {
		issued = b.parse.exchanges
	}
	if issued == 0 {
		reads := slices.ContainsFunc(w.pipelines, func(p config.EffectivePipeline) bool { return p.Input == config.ReconstructionInput })
		refusedWhole := reads && (b.parse == nil || b.parse.fedBytes == 0) && (b.arrived != 0 || b.prefix().truncated())
		if b.cut || b.lost || b.invalid || b.unsettled || refusedWhole {
			return
		}
	}
	var metadata *record.Connection
	if b.retirement != nil {
		if one, err := record.FromConnection(*b.retirement); err == nil {
			metadata = &one
		}
	}
	for k, entry := range w.extensions.entries {
		message := map[string]any{"type": "connection_done", "connection_id": strconv.FormatUint(uint64(b.id), 10),
			"count": strconv.Itoa(issued)}
		if metadata != nil {
			message["ending"] = metadata.Ending
			if slices.Contains(entry.Fields, config.FieldConnection) {
				message["connection"] = metadata
			}
		}
		line, err := json.Marshal(message)
		if err != nil {
			continue
		}
		w.extensions.supervisors[k].ConnectionDone(append(line, '\n'))
	}
}

// settle applies every result that has arrived, and takes each connection's
// chain on from there.
func (w *Worker) settle(ctx context.Context) error {
	if w.queue == nil {
		return nil
	}
	for _, c := range w.queue.completions() {
		d := c.d
		if d.dead {
			// Let go: its result is counted, and nothing more is done.
			w.resolve(d, c.k, c.result)
			continue
		}
		d.b.calling = false
		w.resolve(d, c.k, c.result)
		if err := w.advanceChain(ctx, d.b); err != nil {
			return err
		}
	}
	return nil
}

// exchangeMessage is the exchange message for d at extension k: its id, its
// connection's id and its index, and the fields k's entry selects, as the
// chain left them.
func (w *Worker) exchangeMessage(d *dispatch, k int) ([]byte, error) {
	entry := w.extensions.entries[k]
	selected := func(field string) bool { return slices.Contains(entry.Fields, field) }
	e := d.processed.Exchanges[0]
	projected, err := w.project(d)
	if err != nil {
		return nil, err
	}
	side := func(m *reconstruct.Message, s record.Side, request bool) map[string]any {
		prefix := "response."
		if request {
			prefix = "request."
		}
		line, headers, body := selected(prefix+"line"), selected(prefix+"headers"), selected(prefix+"body")
		if !line && !headers && !body {
			return map[string]any{}
		}
		if m == nil || s.Message == nil {
			return map[string]any{"state": record.Absent}
		}
		r := s.Message
		out := map[string]any{"kind": r.Kind, "complete": r.Complete, "framed": r.Framed, "defect": r.Defect}
		if line {
			if request {
				out["method"], out["target"] = r.Method, r.Target
			} else {
				out["status"], out["reason"] = r.Status, r.Reason
			}
			out["protocol"] = r.Protocol
		}
		if headers {
			out["headers"], out["trailers"] = r.Headers, r.Trailers
		}
		if body {
			out["body"], out["framing"], out["structure"] = r.Body, r.Framing, r.Structure
		}
		return map[string]any{"state": record.Present, "message": out}
	}
	removed := []map[string]string{}
	for _, entry := range w.removals(d) {
		if !selected(fieldOfRemoval(entry)) {
			continue
		}
		one := map[string]string{"message": entry.Message, "field": entry.Field, "disposition": entry.Disposition}
		if entry.Section != "" {
			one["section"] = entry.Section
		}
		removed = append(removed, one)
	}
	output := map[string]string{"state": "eligible"}
	if d.excluded {
		output = map[string]string{"state": "excluded", "reason": d.reason}
	}
	message := map[string]any{
		"type": "exchange", "id": strconv.FormatUint(d.id, 10),
		"connection_id": strconv.FormatUint(uint64(d.b.id), 10), "index": d.index, "output": output,
		"exchange": map[string]any{"index": d.index, "complete": e.Complete, "request": side(e.Request, projected.Request, true),
			"response": side(e.Response, projected.Response, false), "removed": removed},
	}
	if identity := d.b.parse.identity; selected(config.FieldConnection) && identity != nil {
		message["connection"] = *identity
	}
	line, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

// removals is every removal the rules made in d's exchange: from captured
// content and from replacement content, once each.
func (w *Worker) removals(d *dispatch) []PolicyExclusion {
	out := slices.Clone(d.run.evidence.fields)
	for _, entry := range d.replaced {
		if !slices.Contains(out, entry.PolicyExclusion) {
			out = append(out, entry.PolicyExclusion)
		}
	}
	return out
}

// fieldOfRemoval is the extension field a removal lies in.
func fieldOfRemoval(e PolicyExclusion) string {
	prefix := e.Message + "."
	switch {
	case strings.HasPrefix(e.Field, config.HeaderFieldPrefix):
		return prefix + "headers"
	case e.Field == config.TargetQueryField || strings.HasPrefix(e.Field, config.QueryFieldPrefix):
		return prefix + "line"
	default:
		return prefix + "body"
	}
}

// project is d's exchange as the record writes it, bodies marked as the chain
// left them.
func (w *Worker) project(d *dispatch) (record.Exchange, error) {
	projected, _, err := record.FromReconstruction(reconstruct.Reconstruction{Connections: []reconstruct.Connection{d.processed}}, nil)
	if err != nil {
		return record.Exchange{}, err
	}
	d.run.mark(&projected[0], d.processed)
	e := projected[0].Exchanges[0]
	e.Index = d.index
	return e, nil
}

// The replacement rules of the protocol.
var (
	protocolPattern = regexp.MustCompile(`^HTTP/[0-9]\.[0-9]$`)
	// readOnly are members of a component an answer names that cannot be
	// replaced; any other unknown member is malformed.
	readOnly = []string{"kind", "complete", "framed", "defect", "state", "length", "holed", "elided", "encoding",
		"framing", "structure", "stream", "detail", "index", "id"}
)

const (
	maxHeaders      = 128
	maxTrailers     = 32
	maxHeaderBytes  = 65536
	maxReplacedBody = 8 << 20
)

// replacement is one accepted change, decoded and checked, not yet applied.
type replacement struct {
	field   string
	request bool
	method  string
	target  string
	proto   string
	status  int
	reason  string
	headers []http1.Header
	trails  []http1.Header
	body    []byte
}

// change checks extension k's changes to d's exchange whole and, where every
// one is valid, applies each through the chain once. It returns the fields
// changed, in the protocol's order, or the reason the answer failed, in which
// case nothing of it is applied. A changed copy is kept only where its growth
// is charged first; one the shared allowance has no room for fails as
// no_room.
func (w *Worker) change(d *dispatch, k int, changes map[string]json.RawMessage) ([]string, string) {
	if d.excluded {
		return nil, extension.Excluded
	}
	entry := w.extensions.entries[k]
	e := d.processed.Exchanges[0]
	names := slices.Sorted(maps.Keys(changes))
	for _, name := range names {
		if name == config.FieldConnection {
			return nil, extension.ReadOnly
		}
		if !slices.Contains(config.ExtensionFields, name) {
			return nil, extension.Malformed
		}
	}
	var replacements []replacement
	for _, name := range ordered(names) {
		if !slices.Contains(entry.Fields, name) {
			return nil, extension.NotGiven
		}
		request := strings.HasPrefix(name, "request.")
		m := e.Response
		if request {
			m = e.Request
		}
		if m == nil {
			return nil, extension.NotGiven
		}
		if strings.HasSuffix(name, ".body") {
			if disposition := d.run.bodies[m]; disposition == DispositionRemoved || disposition == DispositionValuesRemoved {
				return nil, extension.RemovedContent
			}
		}
		r, reason := decodeReplacement(name, request, changes[name])
		if reason != "" {
			return nil, reason
		}
		replacements = append(replacements, r)
	}
	// Kept whole, so a change whose result cannot be projected is undone:
	// the chain replaces components and never edits one in place.
	var saved [2]reconstruct.Message
	for side, m := range []*reconstruct.Message{e.Request, e.Response} {
		if m != nil {
			saved[side] = *m
		}
	}
	keptBodies := maps.Clone(d.run.bodies)
	replacedBefore := len(d.replaced)
	var fields []string
	for _, r := range replacements {
		w.rechain(d, entry.Name, r)
		fields = append(fields, r.field)
	}
	undo := func() {
		for side, m := range []*reconstruct.Message{e.Request, e.Response} {
			if m != nil {
				*m = saved[side]
			}
		}
		d.run.bodies = keptBodies
		d.replaced = d.replaced[:replacedBefore]
	}
	if _, err := w.project(d); err != nil {
		undo()
		return nil, extension.Malformed
	}
	if now := copyUnits(d.processed); now > d.policy {
		if !w.reservePolicy(d.b, now-d.policy) {
			undo()
			return nil, extension.NoRoom
		}
		d.policy = now
	}
	return fields, ""
}

// decodeReplacement reads one replacement under the protocol's rules.
func decodeReplacement(field string, request bool, raw json.RawMessage) (replacement, string) {
	r := replacement{field: field, request: request}
	var members map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &members) != nil {
		return r, extension.Malformed
	}
	var want []string
	switch {
	case strings.HasSuffix(field, ".line") && request:
		want = []string{"method", "target", "protocol"}
	case strings.HasSuffix(field, ".line"):
		want = []string{"status", "reason", "protocol"}
	case strings.HasSuffix(field, ".headers"):
		want = []string{"headers", "trailers"}
	default:
		want = []string{"kept"}
	}
	for name := range members {
		if slices.Contains(want, name) {
			continue
		}
		if slices.Contains(readOnly, name) {
			return r, extension.ReadOnly
		}
		return r, extension.Malformed
	}
	for _, name := range want {
		if _, ok := members[name]; !ok {
			return r, extension.Malformed
		}
	}
	text := func(name string) (string, bool) {
		var s string
		return s, json.Unmarshal(members[name], &s) == nil
	}
	switch {
	case strings.HasSuffix(field, ".line"):
		proto, ok := text("protocol")
		if !ok || !protocolPattern.MatchString(proto) {
			return r, extension.Malformed
		}
		r.proto = proto
		if request {
			method, ok1 := text("method")
			target, ok2 := text("target")
			if !ok1 || !ok2 || !isToken(method) || !printable(target, false) || target == "" {
				return r, extension.Malformed
			}
			r.method, r.target = method, target
			break
		}
		var status json.Number
		decoder := json.NewDecoder(strings.NewReader(string(members["status"])))
		decoder.UseNumber()
		reason, ok := text("reason")
		if decoder.Decode(&status) != nil || !ok || !printable(reason, true) {
			return r, extension.Malformed
		}
		n, err := strconv.Atoi(status.String())
		if err != nil || n < 100 || n > 999 {
			return r, extension.Malformed
		}
		r.status, r.reason = n, reason
	case strings.HasSuffix(field, ".headers"):
		var headers, trailers []map[string]json.RawMessage
		if json.Unmarshal(members["headers"], &headers) != nil || json.Unmarshal(members["trailers"], &trailers) != nil ||
			members["headers"][0] != '[' || members["trailers"][0] != '[' ||
			len(headers) > maxHeaders || len(trailers) > maxTrailers {
			return r, extension.Malformed
		}
		total := 0
		convert := func(items []map[string]json.RawMessage) ([]http1.Header, bool) {
			out := []http1.Header{}
			for _, item := range items {
				var name, value string
				if len(item) != 2 || json.Unmarshal(item["name"], &name) != nil || json.Unmarshal(item["value"], &value) != nil ||
					!isToken(name) || strings.ContainsAny(value, "\r\n\x00") {
					return nil, false
				}
				total += len(name) + len(value)
				out = append(out, http1.Header{Name: name, Value: value})
			}
			return out, true
		}
		var ok1, ok2 bool
		r.headers, ok1 = convert(headers)
		r.trails, ok2 = convert(trailers)
		if !ok1 || !ok2 || total > maxHeaderBytes {
			return r, extension.Malformed
		}
	default:
		kept, ok := text("kept")
		if !ok {
			return r, extension.Malformed
		}
		body, err := base64.StdEncoding.Strict().DecodeString(kept)
		if err != nil || len(body) > maxReplacedBody {
			return r, extension.Malformed
		}
		r.body = body
	}
	return r, ""
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// printable is visible ASCII, and with spaces, space and tab too.
func printable(s string, spaces bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x21 && c <= 0x7e || spaces && (c == ' ' || c == '\t') {
			continue
		}
		return false
	}
	return true
}

// rechain applies one replacement to d's exchange as a new representation of
// its component: the component alone goes through the whole chain once, and
// what the chain removes from it is recorded apart, attributed to the
// extension that supplied it. Body operations read the captured message's
// header facts, as they do for captured content.
func (w *Worker) rechain(d *dispatch, name string, r replacement) {
	m := d.processed.Exchanges[0].Response
	if r.request {
		m = d.processed.Exchanges[0].Request
	}
	scratch := &reconstruct.Message{}
	scratch.Kind, scratch.Complete, scratch.Framed, scratch.Defect = m.Kind, m.Complete, m.Framed, m.Defect
	switch {
	case strings.HasSuffix(r.field, ".line"):
		scratch.Method, scratch.Target, scratch.Protocol = r.method, r.target, r.proto
		scratch.Status, scratch.Reason = r.status, r.reason
	case strings.HasSuffix(r.field, ".headers"):
		scratch.Headers, scratch.Trailers = r.headers, r.trails
	default:
		scratch.Body = r.body
		scratch.BodyLength, scratch.BodyHoled, scratch.BodyElided = m.BodyLength, m.BodyHoled, m.BodyElided
		if shape, err := jsonshape.Extract(r.body, w.options.Limits.JSON); err == nil {
			scratch.Shape = &shape
		} else if len(r.body) > 0 {
			scratch.ShapeRefused = "body structure unavailable"
		}
	}
	exchange := reconstruct.Exchange{Response: scratch}
	parsed := reconstruct.Exchange{Response: d.source.Response}
	if r.request {
		exchange = reconstruct.Exchange{Request: scratch}
		parsed = reconstruct.Exchange{Request: d.source.Request}
	}
	connection := reconstruct.Connection{Process: d.processed.Process, ID: d.processed.ID, Role: d.processed.Role,
		Exchanges: []reconstruct.Exchange{exchange}}
	run := slotRun{source: reconstruct.Connection{Exchanges: []reconstruct.Exchange{parsed}},
		evidence: exclusionEvidence{fields: []PolicyExclusion{}}, bodies: map[*reconstruct.Message]string{},
		shapes: w.options.Limits.JSON}
	for _, slot := range w.pipelines[d.reconstruction].Slots {
		run.apply(&connection, slot)
	}
	for _, entry := range run.evidence.fields {
		entry.Exchange = 0
		one := ReplacementExclusion{PolicyExclusion: entry, Extension: name}
		if !slices.Contains(d.replaced, one) {
			d.replaced = append(d.replaced, one)
		}
	}
	switch {
	case strings.HasSuffix(r.field, ".line"):
		m.Method, m.Target, m.Protocol, m.Status, m.Reason = scratch.Method, scratch.Target, scratch.Protocol, scratch.Status, scratch.Reason
	case strings.HasSuffix(r.field, ".headers"):
		m.Headers, m.Trailers = scratch.Headers, scratch.Trailers
	default:
		m.Body, m.Shape, m.ShapeRefused = scratch.Body, scratch.Shape, scratch.ShapeRefused
		if disposition, ok := run.bodies[scratch]; ok {
			d.run.bodies[m] = disposition
		} else {
			delete(d.run.bodies, m)
		}
	}
}

type derivedFile struct {
	writer *Writer
	name   string
}

func (f *derivedFile) close() error { return nil }

// writeDerived writes one derived line under the session's release and stop
// gate, the same authorization the observer's own lines need, and within the
// bounded queue. A refusal is a reason, never a failure of the release.
func (r *release) writeDerived(w *Writer, f *derivedFile, line []byte) string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.err != nil {
		return extension.DerivedStopped
	}
	result := extension.DerivedStopped
	r.gate.AuthorizeEnqueue(releaseEvidence, func() { result = w.writeDerived(f, line) })
	return result
}
