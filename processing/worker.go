// Package processing executes a compiled plan over finalised volatile batches.
// Capture callbacks only write intake; a separate serial owner calls the worker.
package processing

import (
	"context"
	"errors"
	"slices"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/reconstruct"
)

var (
	ErrNotImplemented = errors.New("processing implementation is not installed")
	ErrOptions        = errors.New("invalid processing options")
	ErrFinished       = errors.New("processing worker is finished")
)

// Output is the approved write boundary. Implementations must not retain the
// argument after returning. The concrete Writer enforces the disk allowance.
// An error means this record was not delivered; no raw fallback is permitted.
// Context cancellation cannot undo a write that already crossed the boundary.
type Output interface {
	WriteApproved(context.Context, Approved) error
}

// Options is fixed before capture admission. Plan, Intake, Gate and Output must
// be non-nil, and PolicyRevision must be nonempty. Plan must be produced by
// config.CompileProcessing; its detached views are taken once at construction.
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
}

// Outcome is cumulative for one worker. Counts are units, not bytes.
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
// refusal counts that pipeline's routes once. Already-stopped routes are excluded.
// This is not a count of unique routes, batches or exchanges. A route can write
// a useful prefix and also count a refusal of its suffix. OutputFailures counts
// failed approved writes. Neither counts capture loss or policy suppression;
// internal artifact-serialization defects return a terminal error, not a count.
// Pending counts connection batches still holding charged intake entries.
// GateReason reports the gate's capture-wide diagnostic state at return, even
// when no complete candidate reached authorization. It is never permission;
// an incomplete input can also have an independently counted processing failure.
type Outcome struct {
	Batches            uint64
	Authorized         uint64
	Written            uint64
	Withheld           connection.Count
	ProcessingFailures uint64
	OutputFailures     uint64
	Pending            int
	GateReason         probe.GateReason
	StoppedPipelines   []string
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
	options   Options
	pipelines []config.EffectivePipeline
	routes    []config.DurableRoute
	batches   map[batchKey]*batch
	order     []batchKey
	completed map[batchKey]bool
	stopped   map[string]bool
	outcome   Outcome
	terminal  error
	finished  bool
}

// New validates only Options. It performs no capture, parsing or durable write.
func New(options Options) (*Worker, error) {
	if options.Plan == nil || options.Intake == nil || options.Gate == nil || options.Output == nil || options.PolicyRevision == "" {
		return nil, ErrOptions
	}
	h, j := options.Limits.HTTP, options.Limits.JSON
	for _, n := range []int{h.MaxStartLine, h.MaxHeaderLine, h.MaxHeaders, h.MaxHeaderBytes, h.MaxBodyBytes, h.MaxMessages, h.MaxChunks, h.MaxTrailers, j.MaxDepth, j.MaxNodes, j.MaxFields, j.MaxElemShapes, j.MaxNameBytes, j.ShortStringBytes} {
		if n < 0 {
			return nil, ErrOptions
		}
	}
	return &Worker{options: options, pipelines: options.Plan.Pipelines(), routes: options.Plan.Routes(), batches: make(map[batchKey]*batch), completed: make(map[batchKey]bool), stopped: make(map[string]bool), outcome: Outcome{Withheld: connection.Counted(0)}}, nil
}

// Drain takes currently queued entries and processes ready closed batches.
// Callback FIFO order is not completeness evidence: a retirement can precede
// a fragment. A batch needs its matching (Process, ConnectionID) retirement,
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
// metadata only. All output follows the compiled Routes. A slot failure follows
// its resolved OnFailure; stop_pipeline persists for the rest of this worker.
// RemoveHeaders records each actually removed field name and its exchange,
// request/response and header/trailer location in Artifact.PolicyExclusions,
// once per tuple and without its value. Only retained messages contribute;
// absent fields and other operations do not. Each pipeline has its own evidence.
// New artifacts carry an explicit empty array when nothing was excluded,
// including metadata routes; older artifacts without the member are unavailable.
// Every candidate calls Gate.Authorize after processing, immediately before the
// approved write. No eligibility snapshot authorizes anything.
//
// Returns the cumulative outcome and a non-nil error for cancellation, output
// failure or an unusable worker. Processing refusals are in Outcome. After an
// output failure no further output is attempted by this worker.
func (w *Worker) Drain(ctx context.Context) (Outcome, error) {
	if w == nil || w.batches == nil {
		return Outcome{}, ErrFinished
	}
	if w.finished {
		return w.snapshot(), ErrFinished
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
	if err == nil && final.Withdrawn && final.Drained {
		err = w.drain(ctx, true)
	}
	// Finish owns the final queue even on cancellation or absent settlement.
	for e := w.options.Intake.Take(); e != nil; e = w.options.Intake.Take() {
		w.withhold(connection.Uncounted("unsettled_input"))
		e.Release()
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

func (w *Worker) snapshot() Outcome {
	o := w.outcome
	// No-candidate paths still report capture-wide invalidation. Snapshot is
	// diagnostic only; emit must always obtain its own atomic authorization.
	if reason := w.options.Gate.Snapshot().Reason; reason != "" {
		o.GateReason = reason
	}
	o.Pending = len(w.batches)
	o.StoppedPipelines = slices.Clone(o.StoppedPipelines)
	return o
}

func (w *Worker) discard() {
	for id, b := range w.batches {
		w.withhold(connection.Uncounted("unsettled_input"))
		b.release()
		delete(w.batches, id)
	}
	w.order = nil
}

func (w *Worker) withhold(count connection.Count) {
	// Both known terms count exchanges and are nonnegative. A sum wrapping
	// the signed Count representation is unavailable, never a negative count.
	if w.outcome.Withheld.Known && count.Known && w.outcome.Withheld.Value+count.Value < 0 {
		count = connection.Uncounted("count_overflow")
	}
	w.outcome.Withheld = w.outcome.Withheld.Add(count)
}

func (w *Worker) drain(ctx context.Context, final bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		e := w.options.Intake.Take()
		if e == nil {
			break
		}
		w.accept(e)
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
		err := w.process(ctx, b)
		b.release()
		delete(w.batches, id)
		w.completed[id] = true
		if err != nil {
			w.terminal = err
			w.discard()
			return err
		}
	}
	w.order = remaining
	return nil
}
