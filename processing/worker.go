// Package processing executes a compiled plan over finalised volatile batches.
// Capture callbacks only write intake. One owner takes its entries: a Worker
// takes them itself, or a Run routes them to several workers, each owning the
// connections routed to it.
//
// # Held work and the shared allowance
//
// The intake's limit, MaxEvents * MaxEventPayloadBytes
// (activation.RecordingIntake), is one allowance of accounted bytes for the
// whole session (intake.Store). Every worker of a Run and every connection
// draw on the same one. The intake charges its entries; a worker charges what
// it keeps besides them, to two owners, each for its own representations.
//
// Parsing (intake.Parsing) charges, for each connection read:
//
//   - its reading state, readingCharge, from its first read until its reading
//     is let go: the pairing, its two parsers, and the worker's own reading
//     state for the connection, at their fixed sizes;
//   - what its pairing and parsers retain, as they ask for it
//     (http1.Reserver): an http1.Charge costs its Bytes plus messageCharge for
//     each of its Messages;
//   - each exchange the pairing hands over, at the charge it is handed over
//     with, until the worker lets it go: once its lines are written - after
//     every extension, where the plan configures them - or it is excluded or
//     not released, or the connection is let go.
//
// Policy (intake.Policy) charges each copy of an exchange a pipeline makes to
// apply its slots, none or many, from before the copy is made until it is
// dropped: until the exchange's lines are written - after every extension,
// where the plan configures them - or it is let go. A copy costs, for each
// message it holds, messageCharge, the lengths of its method, target, protocol
// and reason, fieldCharge plus the name and value lengths of each header and
// trailer, and the length of its body, whether or not a string is shared with
// its source. A step that changes a copy - a slot, an extension's replacement -
// is measured again before the changed copy is kept, and growth past what is
// charged is reserved first. What shrinks stays charged until the copy is
// dropped.
//
// So a source and its copies each consume the allowance while they coexist:
// an entry and a parser's copy of its bytes, an exchange handed over and a
// pipeline's copy of it. Giving back one gives back nothing of another.
//
// Outside the allowance, bounded by the process envelope as decoding is: what
// one step builds and hands over or drops before it returns - a projection
// (record.Reconstruction) built to encode a line or a message, and the line or
// message encoded - and the structure derived from a body (jsonshape.Shape,
// bounded per message by Limits.JSON), a pipeline's removal evidence, allocator
// overhead and spare slice capacity, and a connection's bookkeeping apart from
// its reading.
//
// What is handed over, and when a charge leaves:
//
//   - Submitting an extension call hands over only its encoded message. The
//     worker keeps the exchange as parsed and as processed, still charged, and
//     the captured input it was read from, still leased, to apply replacements
//     and go on with the chain; that input goes back once the exchange's lines
//     are written, each entry at its last retained byte. What the connection holds
//     then - its entries, its reading and its copies - is its current charge
//     (batch.charged), read at every call it makes.
//   - From a successful extension.Supervisor.Submit until its result is taken,
//     its call times out or its generation is retired, the message is the
//     supervisor's: one representation, held in the generation's outstanding
//     calls and its send queue, bounded by frame_bytes_to_extension
//     (extension.FrameBytesToExtension) per message and in_flight
//     (extension.InFlight) calls per extension. waiting_bytes
//     (extension.WaitingBytes) bounds something else: the charges of the
//     connections waiting on an extension, each read at its call
//     (extension.Call.Bytes), never a message's length.
//   - A result's replacements are the supervisor's frame
//     (extension.FrameBytesFromExtension) until the worker applies them; what
//     it keeps of them is its copy's growth, reserved first.
//   - A line Output takes is the sink queue's, charged by its length against
//     that queue's own bound (Writer).
//   - A refusal, a Submit that returns a reason or an Output that refuses a
//     line, hands nothing over: every charge stays with the worker until it
//     lets go of what it holds.
//
// Event reservations, the delivery gate's slots, are apart from byte charges:
// an entry's slot is returned exactly once, when the last of its bytes leaves
// unfinished work, whatever the charges.
//
// # Exhaustion
//
//   - An insertion that does not fit beside every entry and work charge is
//     refused whole and counted by the intake, and its connection's loss token
//     stops it, as for any intake refusal.
//   - A connection reaching Options.ConnectionInput is cut
//     (Outcome.ConnectionsCut).
//   - A work reservation that does not fit is refused, charging nothing, and
//     counted against its owner (intake.Stats ParsingRefused, PolicyRefused).
//     The connection it was for is cut as at its own bound: what it holds
//     unreleased is let go and its events returned as cut, its later input is
//     discarded on arrival, what it released stays, and its connection line is
//     written alone, truncated from its first unreleased byte with reason
//     connection_cut. It counts in Outcome.ConnectionsCut and InputCut as any
//     cut does, and also in Outcome.AllowanceCut, which tells it from a cut at
//     the connection's own bound. It never waits for room, so a reservation
//     that fails where no new input will come - at Finish, or on an extension's
//     result - is settled at once.
//   - An exchange whose copies could not be charged is not released: every
//     copy is charged before its id and index are issued, so it takes neither,
//     and no line of it is written on any route.
//   - Where the plan configures extensions, an exchange's copy is charged
//     before its id is issued, as without them. A replacement whose growth
//     does not fit fails at its extension as no_room: nothing of it is kept,
//     the exchange goes on through the rest of its extensions and is written,
//     and the connection is cut. Exchanges it had released still go through
//     their extensions and are written.
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
	// ConnectionInput bounds what one connection may hold unreleased: the
	// messages its parsing has begun and not handed over, the messages of its
	// exchanges still on their way through the extensions, and the fragments
	// it holds that nothing vouches for yet, which wait for evidence or for
	// the connection's retirement. A connection reaching
	// it is cut: what it holds unreleased is discarded and counted, the rest of
	// its input is discarded on arrival, and what it released stays. Completed
	// exchanges are released, not held, so a long connection is not cut for its
	// length. Zero takes half the gate's event allowance; negative refuses.
	ConnectionInput int

	// turns, where set, is told of every turn each worker ends, on that
	// worker's goroutine. Only a test sets it.
	turns func(turn)
	// submits, where set, is told of every extension call a worker is about to
	// submit, on that worker's goroutine. Only a test sets it.
	submits func(submission)
}

// turnEntries is the most entries a worker takes from its queue in one turn
// before it runs the connections that input made runnable: the declared bound
// on the input a worker takes between a pair becoming ready and its release.
const turnEntries = 256

// turn is one round of a worker's scheduler, as it was when it ended: the
// entries it took, the captured bytes it gave to parsing, the exchanges it
// released, and whether the worker's queue still held entries.
type turn struct {
	// Worker is the worker's index in its Run, and Number counts its turns from
	// one.
	Worker int
	Number uint64
	// Taken is the entries the turn took from the worker's queue.
	Taken int
	// Fed is the captured bytes the turn gave to parsing.
	Fed uint64
	// Released is every exchange the turn issued an id to, in the order issued.
	Released []released
	// Backlog is whether the worker's queue held entries when the turn ended.
	Backlog bool
}

// released is one exchange a turn released: its connection, its index on that
// connection, the session-global id it was issued, and what its release came
// to.
type released struct {
	Process    fragment.Process
	Connection fragment.ConnectionID
	Index      int
	ID         uint64
	Outcome    releaseOutcome
}

// releaseOutcome is what one exchange's release came to, over every line it
// took: the first that applies of unauthorized, withdrawn, dropped and
// enqueued, or excluded for an exchange no line was written for.
type releaseOutcome uint8

const (
	releaseNone releaseOutcome = iota
	// releaseEnqueued is every line of the exchange authorized and taken by the
	// output.
	releaseEnqueued
	// releaseDropped is a line authorized and refused by the output: an output
	// failure, counted. Its id and index stay issued.
	releaseDropped
	// releaseWithdrawn is a line the connection's capture loss refused before it
	// was enqueued: recoverable, and only that connection's.
	releaseWithdrawn
	// releaseUnauthorized is a line the gate refused to authorize: the capture
	// was invalidated before it, which is terminal for the session.
	releaseUnauthorized
	// releaseExcluded is an exchange issued an id with no line written: not
	// eligible, or after one that was not.
	releaseExcluded
)

func (o releaseOutcome) String() string {
	switch o {
	case releaseEnqueued:
		return "enqueued"
	case releaseDropped:
		return "dropped"
	case releaseWithdrawn:
		return "withdrawn"
	case releaseUnauthorized:
		return "unauthorized"
	case releaseExcluded:
		return "excluded"
	default:
		return "none"
	}
}

// worse is the outcome of an exchange with lines of both outcomes.
func (o releaseOutcome) worse(other releaseOutcome) releaseOutcome {
	rank := func(x releaseOutcome) int {
		switch x {
		case releaseUnauthorized:
			return 4
		case releaseWithdrawn:
			return 3
		case releaseDropped:
			return 2
		case releaseEnqueued:
			return 1
		}
		return 0
	}
	if rank(other) > rank(o) {
		return other
	}
	return o
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
// ConnectionsCut counts connections cut because they could not hold more
// unreleased work: at their own bound (Options.ConnectionInput), or with the
// shared allowance full, a work reservation refused. AllowanceCut counts the
// second kind alone, so ConnectionsCut - AllowanceCut is the first. InputCut
// counts the input entries discarded for those cuts: what each held when it
// was cut, and what arrived for it afterwards. A cut connection's exchanges not
// released before the cut are withheld as unknown.
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
	AllowanceCut       uint64
	InputCut           uint64
	Pending            int
	GateReason         probe.GateReason
	// ExchangeIDs is how many exchange ids the run issued: one per exchange a
	// connection's reading hands over where content is written, from 1, in
	// wire order on each connection. A Run's count, never a worker's.
	ExchangeIDs uint64
	// Extensions is each configured extension's counts, in the order they
	// run. A Run's counts, never a worker's: at every moment each one's
	// Considered is ExchangeIDs, and Considered is Changed + Unchanged +
	// Failed + Pending.
	Extensions []account.ExtensionCounts
}

// Finalization is supplied only after capture authority has been withdrawn,
// delivery callbacks have drained, and capture.Finish has published its records.
// Both facts must be established for a still-open connection to be settled.
// Neither fact asserts a transport close. False facts discard pending payload;
// an exchange its evidence vouches for is released whatever they say.
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
	// waiting is every connection that has ended and whose lines wait for its
	// exchanges to come through the extensions (batch.chain).
	waiting   map[*batch]struct{}
	pipelines []config.EffectivePipeline
	routes    []config.DurableRoute
	batches   map[batchKey]*batch
	// batchesChurn and waitingChurn shed what processing leaves in batches and
	// waiting, whose keys are connections that never return.
	batchesChurn held.Churn
	waitingChurn held.Churn
	order        []batchKey
	outcome      Outcome
	terminal     error
	finished     bool
	// bound is what one connection may hold unreleased (Options.ConnectionInput).
	bound int
	// current is the turn in progress where Options.turns is set, and turns
	// how many this worker has begun.
	current *turn
	turns   uint64
	// runnable is the connections the turn in progress touched.
	runnable []*batch
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
		waiting: map[*batch]struct{}{}, pipelines: options.Plan.Pipelines(), routes: options.Plan.Routes(),
		batches: make(map[batchKey]*batch), outcome: Outcome{Withheld: connection.Counted(0)},
		bound: connectionInput(options)}
	if q, ok := from.(*queue); ok {
		w.queue = q
	}
	return w
}

// Drain takes currently queued entries, in turns of at most turnEntries, and
// after each turn reads and releases what its input made decidable on each
// connection it touched.
//
// An exchange is released while its connection is open, once something
// vouches for every byte of it: the evidence capture took at a fragment this
// worker holds with every fragment before it (fragment.Evidence.Usable), or,
// where none was taken, the connection's retirement. Each connection is read
// once, a part at a time, in sequence order (reconstruct.Pairing), and each
// exchange the reading hands over is released at once: complete and supported,
// it is written as one exchange line per route with a session-global id and
// its index on the connection, carrying the connection's provisional record;
// otherwise it is excluded, and so is every exchange after it. Both take an id
// and an index. Where the plan configures extensions, each exchange goes
// through them first, one at a time on each connection, and its lines are
// written once every extension has answered or skipped it; excluded exchanges
// are held until their reason is decidable, and a connection is sent
// connection_done once it has ended and its exchanges are through (chain).
//
// Callback FIFO order is not completeness evidence: a retirement can precede
// a fragment. An entry for a connection id that was routed before, whose batch
// this worker no longer holds, is late: it is released at once and withheld as
// unknown, whatever its process, since a connection id is unique within a
// capture session. A connection's connection line needs its matching (Process,
// ConnectionID) retirement, a known nonnegative Fragments count, and every
// distinct sequence 1..count. Zero is valid for a metadata-only connection.
// Duplicate/out-of-range sequences, identity disagreement, evidence that
// disagrees with what came before it or with the retirement, and invalid
// records refuse what was not yet released; missing sequences wait.
// Fragment.Validate and connection.Record.Validate are applied, and
// contract/record projection errors refuse output rather than copying input.
// Offset + uint64(Length) must not wrap. Within each direction, ranges in
// sequence order must not overlap or move backward; either condition refuses
// the connection rather than choosing between conflicting bytes. A hole limits
// reconstruction to the established prefix before it; later bytes do not resume
// parsing even if they resemble a new message.
// A connection line carries ReconstructionTruncation: each affected direction
// names where released messages stop, where the stopping evidence lies, and
// its structural reason. Its suffix is indeterminate, never absent. A placement
// cutoff is reported even if no subsequent bytes were observed. This boundary
// does not change Connection.Ending or assert a transport close. Each direction
// carrying bytes needs an explicit valid Placement. Only bytes established by
// that placement can contribute to an approved message.
//
// A closed connection has HandleReleasedEnding or SocketClosed. Other endings
// wait for Finish. Parsing must establish complete, framed, unholed, unelided
// HTTP/1 messages; unsupported encodings and undecidable tails are withheld.
// Complete exchanges preceding a bad tail are released. Capture end never
// completes a close-delimited response. Supported versions are HTTP/1.0 and
// HTTP/1.1; Content-Encoding must be absent or identity, and Transfer-Encoding
// absent or solely chunked. CONNECT, Upgrade and informational responses are
// withheld, because this parser does not model protocol switching or interim
// pairing. Both request and response must be present and complete for an
// exchange to be emitted. No source bytes or parser error text are logged.
//
// Pipelines execute in compiled order on separate input copies, and slots in
// their compiled order, including zero-slot pipelines. Connection inputs receive
// metadata only. All output follows the compiled Routes. A slot failure drops
// that pipeline's output for the rest of the connection and is counted once.
// Every removal - a header, a body, a body's values, a query, a parameter or
// a JSON member - is recorded in Artifact.PolicyExclusions with its exchange,
// request/response, field and disposition, once per entry and without its
// value. Only retained messages contribute; absent components, replacement and
// truncation do not. Each pipeline has its own evidence. Body operations read
// header facts from the message as parsed, never as an earlier slot left it.
// New artifacts carry an explicit empty array when nothing was excluded,
// including metadata routes; older artifacts without the member are unavailable.
// Every candidate calls Gate.Authorize after processing, immediately before the
// approved write, stating what its own input and lifecycle establish. No
// eligibility snapshot authorizes anything.
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
	err := w.drain(ctx, false, true)
	return w.snapshot(), err
}

// Finish drains the final queue once, processes eligible final batches and
// discards every remainder, releasing all leases. It permanently ends the worker.
// With both finalization facts it first waits for every exchange still on its
// way through the extensions, each call bounded by its extension's timeout; a
// connection issued ids whose retirement is not ready is sent connection_done
// and withheld as unsettled once its exchanges are through.
// Without both finalization facts it settles nothing - no connection line is
// written and no still-open connection is retired - and still releases what
// the final queue's evidence vouches for, as any drain would.
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
	if err == nil && (!final.Withdrawn || !final.Drained) {
		// Without both facts nothing is settled: the final queue is still
		// read for what evidence vouches for, as a drain would read it, so
		// whether a pair completed before Finish is written does not depend
		// on whether a drain ran in between.
		err = w.drain(ctx, false, false)
	} else if err == nil {
		err = w.drain(ctx, true, true)
		if err == nil {
			err = w.endUnsettled(ctx)
		}
		// Every connection waiting on an extension is written once its results
		// arrive; each call is bounded by its extension's timeout.
		for err == nil && len(w.waiting) > 0 {
			select {
			case <-w.queue.wake:
				w.begin()
				err = w.settle(ctx)
				w.end()
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

// connectionInput is what one connection may hold unreleased: the option, or
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
// the order it examines them in, and the connections with exchanges on their
// way through the extensions, with the exchanges each keeps as parsed and as
// processed, the capacity of the slices holding them, and what policy did to
// their bodies. A dispatch's bodies are a map, which Go gives no capacity for,
// so only their count is read. An exchange is let go of when its lines are
// written, so nothing else of one is kept. processing.waiting's rebuilds are
// those of the connections that ended waiting. Its owner reads it, never while
// Drain or Finish runs.
func (w *Worker) Retained() ([]held.Occupancy, error) {
	if w == nil {
		return nil, nil
	}
	entries, fragments := 0, 0
	for _, b := range w.batches {
		entries += b.entries()
		fragments += len(b.unfed)
	}
	waiting, exchanges, capacity, bodies := 0, 0, 0, 0
	chained := func(b *batch) {
		if len(b.chain) == 0 && !b.calling {
			return
		}
		waiting++
		capacity += cap(b.chain)
		for _, d := range b.chain {
			exchanges += 1 + len(d.processed.Exchanges)
			capacity += cap(d.processed.Exchanges)
			if d.run != nil {
				bodies += len(d.run.bodies)
			}
		}
	}
	for _, b := range w.batches {
		chained(b)
	}
	for b := range w.waiting {
		chained(b)
	}
	return []held.Occupancy{
		{Store: "processing.batches", Held: len(w.batches), Rebuilds: w.batchesChurn.Rebuilds()},
		{Store: "processing.entries", Held: entries},
		{Store: "processing.fragments", Held: fragments},
		{Store: "processing.order", Held: len(w.order)},
		{Store: "processing.waiting", Held: waiting, Rebuilds: w.waitingChurn.Rebuilds()},
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
		w.drop(b)
		b.release(held.Discarded)
		delete(w.batches, id)
	}
	w.order = nil
	for b := range w.waiting {
		// Its results may still arrive, and are counted; nothing of it is
		// written.
		w.withhold(connection.Uncounted("unsettled_input"))
		w.drop(b)
		b.release(held.Discarded)
		delete(w.waiting, b)
	}
}

// endUnsettled ends, at Finish, every connection still held that was issued
// exchange ids and whose retirement is not ready: its held excluded exchanges
// are decided from what it read, its chain is taken through, and it is sent
// connection_done and withheld as unsettled, writing no connection line.
// Connections issued no id are left to discard.
func (w *Worker) endUnsettled(ctx context.Context) error {
	if w.extensions == nil {
		return nil
	}
	for _, key := range w.order {
		b := w.batches[key]
		if b == nil || b.parse == nil || b.parse.exchanges == 0 {
			continue
		}
		b.ended, b.unsettled = true, true
		w.decideTail(b)
		w.batches = held.Deleted(w.batches, key, &w.batchesChurn)
		w.waiting[b] = struct{}{}
		if err := w.advanceChain(ctx, b); err != nil {
			w.stop(err)
			return err
		}
	}
	return nil
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
	o.AllowanceCut += other.AllowanceCut
	o.InputCut += other.InputCut
	o.Pending += other.Pending
	if o.GateReason == "" {
		o.GateReason = other.GateReason
	}
	return o
}

// begin starts a turn where one is observed.
func (w *Worker) begin() {
	if w.options.turns == nil {
		return
	}
	w.turns++
	w.current = &turn{Worker: w.index, Number: w.turns}
}

// end reports the turn in progress, if any.
func (w *Worker) end() {
	if w.current == nil {
		return
	}
	t := *w.current
	w.current = nil
	t.Backlog = w.source.waiting()
	w.options.turns(t)
}

// drain runs turns until the worker's queue is empty. Each takes at most
// turnEntries entries, then reads and releases what that input made decidable
// on every connection it touched, and retires those now ready, so a pair that
// becomes ready is released before the next turn takes more input. A last pass
// over every connection applies a capture loss and retires what is ready: at
// Finish (final), every connection holding its retirement. Where settled is
// false nothing is retired or settled - no connection line, no extension
// result - and only what evidence vouches for is released.
func (w *Worker) drain(ctx context.Context, final, settled bool) error {
	w.begin()
	defer w.end()
	if settled {
		if err := w.settle(ctx); err != nil {
			w.stop(err)
			return err
		}
	}
	for {
		taken := 0
		for taken < turnEntries {
			if err := ctx.Err(); err != nil {
				return err
			}
			r, ok := w.source.take()
			if !ok {
				break
			}
			taken++
			if w.current != nil {
				w.current.Taken++
			}
			if b := w.accept(r); b != nil && !b.runnable {
				b.runnable = true
				w.runnable = append(w.runnable, b)
			}
		}
		if err := w.run(ctx, final, settled); err != nil {
			w.stop(err)
			return err
		}
		if taken < turnEntries {
			break
		}
		w.end()
		w.begin()
	}
	if !settled {
		return nil
	}
	remaining := make([]batchKey, 0, len(w.order))
	for _, key := range w.order {
		b := w.batches[key]
		if b == nil {
			continue
		}
		if b.loss.Reason() != "" {
			b.lose()
		}
		if !b.ready(final) {
			remaining = append(remaining, key)
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.retire(ctx, key, b, final); err != nil {
			w.stop(err)
			return err
		}
	}
	w.order = remaining
	return nil
}

// run reads and releases what this turn's input made decidable on each
// connection it touched, and retires those now ready where settled.
func (w *Worker) run(ctx context.Context, final, settled bool) error {
	runnable := w.runnable
	w.runnable = w.runnable[:0]
	for i, b := range runnable {
		runnable[i] = nil
		b.runnable = false
		key := batchKey{process: b.process, id: b.id}
		if w.batches[key] != b {
			continue
		}
		if b.loss.Reason() != "" {
			// Capture lost input of this connection: nothing more of it is
			// read.
			b.lose()
		}
		if settled && b.ready(final) {
			// Its retirement vouches for all of it now, so all of it is placed
			// before any of it is released.
			if err := w.retire(ctx, key, b, final); err != nil {
				return err
			}
			continue
		}
		if err := w.advance(ctx, b); err != nil {
			return err
		}
		if w.extensions != nil {
			if err := w.advanceChain(ctx, b); err != nil {
				return err
			}
		}
	}
	return nil
}

// retire processes a ready batch to its lines and lets it go, unless its
// lines now wait on an extension, which keeps its leases.
func (w *Worker) retire(ctx context.Context, key batchKey, b *batch, final bool) error {
	w.outcome.Batches++
	b.final = final
	waits, err := w.process(ctx, b)
	if !waits {
		b.release(processedUnless(err))
	}
	w.batches = held.Deleted(w.batches, key, &w.batchesChurn)
	return err
}

func deliveryOutcome(o Outcome, output Output) Outcome {
	if writer, ok := output.(*Writer); ok {
		o.Delivery = writer.DeliveryStats()
		o.Authorized, o.Written, o.OutputFailures = o.Delivery.Authorized, o.Delivery.Written, o.Delivery.Failed
	}
	return o
}
