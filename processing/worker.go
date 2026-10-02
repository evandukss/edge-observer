// Package processing executes a compiled plan over finalised volatile batches.
// Capture callbacks only write intake. One owner takes its entries: a Worker
// takes them itself, or a Run routes them to several workers, each owning the
// connections routed to it.
package processing

import (
	"context"
	"errors"
	"github.com/evandukss/edge-observer/sink"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/reconstruct"
)

var (
	ErrOptions  = errors.New("invalid processing options")
	ErrFinished = errors.New("processing worker is finished")
)

// Output is the nonblocking enqueue boundary for already processed lines.
// Implementations transfer immutable bytes to a bounded queue or refuse them;
// they must never perform sink I/O here. Writer implements that boundary.
// Authorization cannot be recalled after enqueue by a later invalidation.
type Output interface {
	WriteApproved(context.Context, Approved) error
}

// Options is fixed before capture admission. Plan, Intake, Gate and Output must
// be non-nil, and PolicyRevision and Session must be nonempty. Plan must be produced by
// config.Compile; its detached views are taken once at construction.
// No raw configuration, exclusion revalidation or policy resolution occurs here.
// Limits uses reconstruct's defaults for zero fields; negative fields refuse.
type Options struct {
	Plan           *config.ProcessingPlan
	PolicyRevision string
	Intake         *intake.Store
	Gate           *probe.DeliveryGate
	Output         Output
	Limits         reconstruct.Limits
	// BeforeParse runs outside every intake, capture and gate lock. Tests may
	// hold it to witness delivery proceeding while processing is blocked.
	// The gate's BeforeAuthorize is the authorization barrier, not this hook.
	BeforeParse func(context.Context) error
	// Workers is how many workers Start runs, each owning the connections
	// routed to it. Zero means one; negative refuses. New is one worker and
	// refuses more.
	Workers int
	// Taken runs in the worker that takes an entry, before the entry is
	// accepted, outside every lock, with that worker's index and the entry's
	// connection. Tests use it to see which worker holds a connection, and may
	// hold one worker in it.
	Taken func(worker int, process fragment.Process, connection fragment.ConnectionID)

	// Session is stamped on every approved and derived line, and sent to
	// extensions at start. A nonempty session id is required.
	Session string
	// Derived is the writer whose directory holds the extensions' derived
	// files, derived-<name>.jsonl. They share its bounded queue with approved
	// output, with no cumulative output or half-budget cap. Required when Plan
	// configures an extension; usually the same Writer as Output.
	Derived *Writer
	// Clock is what extension supervision reads time from. Nil is
	// extension.System.
	Clock extension.Clock
	// Supervision, where set, receives every step of every extension's
	// supervision (extension.Event), on the supervisor's goroutine.
	Supervision func(extension.Event)
	// ConnectionInput is the most input entries one connection may hold while it
	// waits to be processed. A connection reaching it is cut: what it holds is
	// discarded and counted, and the rest of its input is discarded on arrival.
	// Zero takes half the gate's event allowance; negative refuses.
	ConnectionInput int
}

// Outcome is cumulative for one worker, and for a Run the sum over its
// workers, where one unknown term makes Withheld unknown. Counts are units,
// not bytes.
// Batches counts finalised connections examined. Authorized and Written count
// route records, separately: authorization does not imply a successful write.
// Withheld counts reconstruction exchanges refused before pipeline transforms.
// It is known only when complete framed HTTP/1 request/response pairs establish
// the count, without an unknown suffix or unmodelled pairing (CONNECT, Upgrade,
// or informational responses). Fully framed unsupported encodings can be
// counted. Invalid, incomplete or unplaced input makes it unknown, not one;
// discarded unexamined input also makes it unknown, not zero. Pending input is
// not yet refused. Unknown is cumulative and retains the first reason, with no
// numeric value; subsequent known refusals cannot make the total known again.
// This count excludes policy suppression, transform failures, gate refusals and
// output failures, and does not multiply exchanges by the number of routes.
// ProcessingFailures counts affected active durable routes for each batch's
// processing refusals: a batch refusal counts every active route, and a pipeline
// refusal counts that pipeline's routes once.
// This is not a count of unique routes, batches or exchanges. A route can write
// a useful prefix and also count a refusal of its suffix. OutputFailures counts
// failed approved writes. Neither counts capture loss or policy suppression;
// internal artifact-serialization defects return a terminal error, not a count.
// ConnectionsCut counts connections cut at Options.ConnectionInput, and
// InputCut the input entries discarded for those cuts: what each held when it
// was cut, and what arrived for it afterwards. A cut connection's exchanges are
// withheld as unknown.
// Pending counts connection batches still holding charged intake entries.
// GateReason reports the gate's capture-wide diagnostic state at return, even
// when no complete candidate reached authorization. It is never permission;
// an incomplete input can also have an independently counted processing failure.
type Outcome struct {
	Delivery           sink.Stats
	Batches            uint64
	Authorized         uint64
	Written            uint64
	Withheld           connection.Count
	ProcessingFailures uint64
	OutputFailures     uint64
	ConnectionsCut     uint64
	InputCut           uint64
	Pending            int
	GateReason         probe.GateReason
	// ExchangeIDs is how many exchange ids the run issued: one per exchange
	// reconstructed from a dispatched batch where content is written, from 1,
	// contiguously per connection. A Run's count, never a worker's.
	ExchangeIDs uint64
	// Extensions is each configured extension's counts, in the order they
	// run. A Run's counts, never a worker's: at every moment each one's
	// Considered is ExchangeIDs, and Considered is Changed + Unchanged +
	// Failed + Pending.
	Extensions []account.ExtensionCounts
}

// Finalization is supplied only after capture authority has been withdrawn,
// delivery callbacks have drained, and capture.Finish has published its records.
// Both facts must be established for a still-open batch to become eligible.
// Neither fact asserts a transport close. False facts discard pending payload.
type Finalization struct {
	Withdrawn bool
	Drained   bool
}

// Worker has one serial owner: Drain, Finish and Close must not overlap. It
// creates no goroutine and calls neither capture nor a sink under an intake
// lock. Entries taken from Intake remain leased through parsing and writing.
// Close releases all held entries without output; it does not close Intake or
// Output, which belong to the session controller.
type Worker struct {
	options Options
	index   int
	source  source
	release *release
	// queue is this worker's own queue under a Run, which also carries the
	// extensions' results; nil for a Worker taking from the intake itself.
	queue      *queue
	extensions *extensions
	// waiting is every batch whose lines wait on an extension's result.
	waiting   map[*dispatch]struct{}
	pipelines []config.EffectivePipeline
	routes    []config.DurableRoute
	batches   map[batchKey]*batch
	order     []batchKey
	outcome   Outcome
	terminal  error
	finished  bool
	// bound is the most fragments one connection may hold (Options.ConnectionInput).
	bound int
}

// New validates only Options. It performs no capture, parsing or durable write.
// The worker takes entries from Intake itself. It runs no extension: a plan
// that configures one is refused, and runs under Start.
func New(options Options) (*Worker, error) {
	if !options.valid() || options.Workers > 1 || len(options.Plan.Extensions()) > 0 {
		return nil, ErrOptions
	}
	return newWorker(options, 0, &direct{intake: options.Intake}, &release{gate: options.Gate, output: options.Output}, nil), nil
}

func (o Options) valid() bool {
	if o.Plan == nil || o.Intake == nil || o.Gate == nil || o.Output == nil || o.PolicyRevision == "" || o.Session == "" || o.Workers < 0 || o.ConnectionInput < 0 {
		return false
	}
	h, j := o.Limits.HTTP, o.Limits.JSON
	for _, n := range []int{h.MaxStartLine, h.MaxHeaderLine, h.MaxHeaders, h.MaxHeaderBytes, h.MaxBodyBytes, h.MaxChunks, h.MaxTrailers, j.MaxDepth, j.MaxNodes, j.MaxFields, j.MaxElemShapes, j.MaxNameBytes, j.ShortStringBytes} {
		if n < 0 {
			return false
		}
	}
	return true
}

func newWorker(options Options, index int, from source, release *release, running *extensions) *Worker {
	w := &Worker{options: options, index: index, source: from, release: release, extensions: running,
		waiting: map[*dispatch]struct{}{}, pipelines: options.Plan.Pipelines(), routes: options.Plan.Routes(),
		batches: make(map[batchKey]*batch), outcome: Outcome{Withheld: connection.Counted(0)},
		bound: connectionInput(options)}
	if q, ok := from.(*queue); ok {
		w.queue = q
	}
	return w
}

// Drain takes currently queued entries and processes ready closed batches.
// Callback FIFO order is not completeness evidence: a retirement can precede
// a fragment. An entry for a connection id that was routed before, whose batch
// this worker no longer holds, is late: it is released at once and withheld as
// unknown, whatever its process, since a connection id is unique within a
// capture session. A batch needs its matching (Process, ConnectionID) retirement,
// a known nonnegative Fragments count, and every distinct sequence 1..count.
// Zero is valid for a metadata-only batch. Duplicate/out-of-range sequences,
// identity disagreement or invalid records fail that batch; missing sequences
// wait. Fragment.Validate and connection.Record.Validate are applied, and
// contract/record projection errors refuse output rather than copying input.
// Offset + uint64(Length) must not wrap. Within each direction, ranges in
// sequence order must not overlap or move backward; either condition refuses
// the batch rather than choosing between conflicting bytes. A hole limits
// reconstruction to the established prefix before it; later bytes do not resume
// parsing even if they resemble a new message.
// A retained reconstruction prefix carries ReconstructionTruncation: each
// affected direction names where approved messages stop, where the stopping
// evidence lies, and its structural reason. Its suffix is indeterminate, never
// absent; Reconstruction.Unplaced is undetermined rather than a numeric zero.
// A placement cutoff is reported even if no subsequent bytes were observed.
// This boundary does not change Connection.Ending or assert a transport close.
// Each direction carrying bytes needs an explicit valid Placement. Only bytes
// established by that placement can contribute to an approved message.
//
// A closed batch has HandleReleasedEnding or SocketClosed. Other endings wait
// for Finish. Parsing must establish complete, framed, unholed, unelided HTTP/1
// messages; unsupported encodings and undecidable tails are withheld. Complete
// exchanges preceding a bad tail remain candidates. Capture end never completes
// a close-delimited response. Supported versions are HTTP/1.0 and HTTP/1.1;
// Content-Encoding must be absent or identity, and Transfer-Encoding absent or
// solely chunked. CONNECT, Upgrade and informational responses are withheld,
// because this parser does not model protocol switching or interim pairing.
// Both request and response must be present and complete for an exchange to be
// emitted. No source bytes or parser error text are logged.
//
// Pipelines execute in compiled order on separate input copies, and slots in
// their compiled order, including zero-slot pipelines. Connection inputs receive
// metadata only. All output follows the compiled Routes. A slot failure drops
// that pipeline's output for the batch and is counted.
// Every removal - a header, a body, a body's values, a query, a parameter or
// a JSON member - is recorded in Artifact.PolicyExclusions with its exchange,
// request/response, field and disposition, once per entry and without its
// value. Only retained messages contribute; absent components, replacement and
// truncation do not. Each pipeline has its own evidence. Body operations read
// header facts from the message as parsed, never as an earlier slot left it.
// New artifacts carry an explicit empty array when nothing was excluded,
// including metadata routes; older artifacts without the member are unavailable.
// Every candidate calls Gate.Authorize after processing, immediately before the
// approved write. No eligibility snapshot authorizes anything.
//
// Returns the cumulative outcome and a non-nil error for cancellation, output
// failure or an unusable worker. Processing refusals are in Outcome. After an
// output failure no further output is attempted by this worker, nor by any
// worker of the same Run.
func (w *Worker) Drain(ctx context.Context) (Outcome, error) {
	if w == nil || w.batches == nil {
		return Outcome{}, ErrFinished
	}
	if w.finished {
		return w.snapshot(), ErrFinished
	}
	if w.terminal == nil {
		if err := w.release.failure(); err != nil {
			w.terminal = err
			w.discard()
		}
	}
	if w.terminal != nil {
		return w.snapshot(), w.terminal
	}
	err := w.drain(ctx, false)
	return w.snapshot(), err
}

// Finish drains the final queue once, processes eligible final batches and
// discards every remainder, releasing all leases. It permanently ends the worker.
// A canceled context stops further authorization; controller deadlines and an
// incomplete terminal account are owned by the caller, not invented here.
func (w *Worker) Finish(ctx context.Context, final Finalization) (Outcome, error) {
	if w == nil || w.batches == nil {
		return Outcome{}, ErrFinished
	}
	if w.finished {
		return w.snapshot(), ErrFinished
	}
	err := w.terminal
	if err == nil {
		err = w.release.failure()
	}
	if err == nil && final.Withdrawn && final.Drained {
		err = w.drain(ctx, true)
		// Every batch waiting on an extension is written once its results
		// arrive; each call is bounded by its extension's timeout.
		for err == nil && len(w.waiting) > 0 {
			select {
			case <-w.queue.wake:
				err = w.settle(ctx)
				if err != nil {
					w.stop(err)
				}
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
	}
	// Finish owns the final queue even on cancellation or absent settlement.
	for r, ok := w.source.take(); ok; r, ok = w.source.take() {
		w.withhold(connection.Uncounted("unsettled_input"))
		r.entry.Release()
	}
	w.discard()
	w.finished = true
	return w.snapshot(), err
}

func (w *Worker) Close() error {
	if w == nil {
		return nil
	}
	w.discard()
	w.finished = true
	return nil
}

// connectionInput is the most fragments one connection may hold: the option, or
// half the gate's event allowance, so that one connection reaches its own bound
// before it can fill the session's.
func connectionInput(options Options) int {
	if options.ConnectionInput > 0 {
		return options.ConnectionInput
	}
	allowance := options.Gate.Snapshot().MaxEvents
	return int(max(allowance/2, 1))
}

// Retained is what this worker holds now, store by store: the connections
// whose input it holds, with their entries and the fragments indexed from them,
// the order it examines them in, and the connections waiting on an extension's
// result, with the exchanges each keeps as parsed and as processed, the
// capacity of the slices holding them, and what policy did to their bodies. A
// dispatch's bodies are a map, which Go gives no capacity for, so only their
// count is read. A dispatch that is not waiting is let go of when its lines are
// written, so nothing else of one is kept. Its owner reads it, never while
// Drain or Finish runs.
func (w *Worker) Retained() ([]held.Occupancy, error) {
	if w == nil {
		return nil, nil
	}
	entries, fragments := 0, 0
	for _, b := range w.batches {
		entries += len(b.entries)
		fragments += len(b.fragments)
	}
	exchanges, capacity, bodies := 0, 0, 0
	for d := range w.waiting {
		exchanges += len(d.source.Exchanges) + len(d.processed.Exchanges)
		capacity += cap(d.source.Exchanges) + cap(d.processed.Exchanges)
		if d.run != nil {
			bodies += len(d.run.bodies)
		}
	}
	return []held.Occupancy{
		{Store: "processing.batches", Held: len(w.batches)},
		{Store: "processing.entries", Held: entries},
		{Store: "processing.fragments", Held: fragments},
		{Store: "processing.order", Held: len(w.order)},
		{Store: "processing.waiting", Held: len(w.waiting)},
		{Store: "processing.waiting_exchanges", Held: exchanges},
		{Store: "processing.waiting_exchanges_capacity", Held: capacity},
		{Store: "processing.waiting_bodies", Held: bodies},
	}, nil
}

func (w *Worker) snapshot() Outcome {
	o := w.outcome
	// No-candidate paths still report capture-wide invalidation. Snapshot is
	// diagnostic only; emit must always obtain its own atomic authorization.
	if reason := w.options.Gate.Snapshot().Reason; reason != "" {
		o.GateReason = reason
	}
	o.Pending = len(w.batches) + len(w.waiting)
	o.ExchangeIDs = w.release.issued.Load()
	if w.queue == nil {
		o = deliveryOutcome(o, w.options.Output)
	}
	return o
}

func (w *Worker) discard() {
	for id, b := range w.batches {
		w.withhold(connection.Uncounted("unsettled_input"))
		b.release(held.Discarded)
		delete(w.batches, id)
	}
	w.order = nil
	for d := range w.waiting {
		// Its results may still arrive, and are counted; nothing of it is
		// written.
		d.dead = true
		w.withhold(connection.Uncounted("unsettled_input"))
		d.b.release(held.Discarded)
		delete(w.waiting, d)
	}
}

// stop makes err terminal for this worker and every worker of its Run.
func (w *Worker) stop(err error) {
	w.terminal = err
	w.release.fail(err)
	w.discard()
}

func (w *Worker) withhold(count connection.Count) {
	w.outcome.Withheld = sum(w.outcome.Withheld, count)
}

// sum adds two counts of exchanges. Both known terms are nonnegative, so a sum
// wrapping the signed Count representation is unavailable, never a negative
// count; an unknown term makes the sum unknown.
func sum(a, b connection.Count) connection.Count {
	if a.Known && b.Known && a.Value+b.Value < 0 {
		b = connection.Uncounted("count_overflow")
	}
	return a.Add(b)
}

// plus is the sum of two outcomes. A gate reason is the first one either has.
// ExchangeIDs and Extensions are a Run's, never summed.
func (o Outcome) plus(other Outcome) Outcome {
	o.Batches += other.Batches
	o.Authorized += other.Authorized
	o.Written += other.Written
	o.Withheld = sum(o.Withheld, other.Withheld)
	o.ProcessingFailures += other.ProcessingFailures
	o.OutputFailures += other.OutputFailures
	o.ConnectionsCut += other.ConnectionsCut
	o.InputCut += other.InputCut
	o.Pending += other.Pending
	if o.GateReason == "" {
		o.GateReason = other.GateReason
	}
	return o
}

func (w *Worker) drain(ctx context.Context, final bool) error {
	if err := w.settle(ctx); err != nil {
		w.stop(err)
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, ok := w.source.take()
		if !ok {
			break
		}
		w.accept(r)
	}
	// Inspect all callbacks already queued before evaluating completeness.
	remaining := make([]batchKey, 0, len(w.order))
	for _, id := range w.order {
		b := w.batches[id]
		if b == nil {
			continue
		}
		if !b.ready(final) {
			remaining = append(remaining, id)
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		w.outcome.Batches++
		waits, err := w.process(ctx, b)
		if !waits {
			b.release(processedUnless(err))
		}
		delete(w.batches, id)
		if err != nil {
			w.stop(err)
			return err
		}
	}
	w.order = remaining
	return nil
}

func deliveryOutcome(o Outcome, output Output) Outcome {
	if writer, ok := output.(*Writer); ok {
		o.Delivery = writer.DeliveryStats()
		o.Authorized, o.Written, o.OutputFailures = o.Delivery.Authorized, o.Delivery.Written, o.Delivery.Failed
	}
	return o
}
