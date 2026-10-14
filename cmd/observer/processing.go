package main

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/processing"
)

// processingEvery is the cadence for routing newly queued volatile records to
// the workers. It is neither a batch-completeness test nor a finalization
// deadline.
const processingEvery = 10 * time.Millisecond

// processingRun is the intake's one owner: a goroutine, separate from the
// controller selecting withdrawal signals, that routes the intake's entries to
// limits.workers workers and finishes them. No controller lock is held through
// parsing or writing. A snapshot reads the workers' last returned outcomes; it
// never waits on writer I/O. Cleanup state and errors remain private to this
// owner.
type processingRun struct {
	run          *processing.Run
	mutex        sync.Mutex
	finished     bool
	err          error
	failed       chan struct{}
	final        chan processing.Finalization
	done         chan struct{}
	finalContext context.Context
	beforeFinal  func(context.Context, string) error
	stage        atomic.Value
}

func (d *daemon) currentProcessing() *processingRun {
	d.processingMutex.Lock()
	defer d.processingMutex.Unlock()
	return d.processing
}

// startProcessing fixes the workers' inputs before serving any control request.
// begin already fixed this plan, revision, intake, gate and writer before
// admission. Reload cannot replace the processing plan or the worker count.
// The start operation is outside processingMutex, so a held extension startup
// cannot prevent the cutoff from closing this session's admission.
func (d *daemon) startProcessing() <-chan struct{} {
	d.processingStart.Do(func() {
		if d.currentProcessing() != nil {
			return
		}

		if d.output == nil {
			// A controller without an output owner has no processing path. Production
			// begin requires that owner before constructing its delivery gate.
			return
		}
		// Extensions start here, after the capabilities were given up and after
		// the activation record listing them was enqueued. Log delivery is best
		// effort and cannot prevent monitoring.
		opts := processing.Options{Plan: d.policy.Processing, PolicyRevision: d.policy.ProcessingRevision,
			Intake: d.intake, Gate: d.gate, Output: d.output, Workers: d.policy.Settings.Workers, Taken: d.processingTaken,
			Session: d.session, Derived: d.output, Supervision: d.extensionLogged}
		r := &processingRun{
			failed: make(chan struct{}), final: make(chan processing.Finalization, 1), done: make(chan struct{}),
		}
		r.run, r.err = processing.Start(opts)
		d.processingMutex.Lock()
		if d.processingClosed && r.run != nil {
			r.run.CloseAdmission()
		}
		d.processing = r
		d.processingMutex.Unlock()
		go r.serve(d.output)

	})
	if r := d.currentProcessing(); r != nil {
		return r.failed
	}
	return nil
}

func (r *processingRun) serve(output *processing.Writer) {
	defer close(r.done)
	if r.run != nil {
		defer func() { go func() { _ = r.run.Close() }() }()
	}

	ticker := time.NewTicker(processingEvery)
	defer ticker.Stop()
	poll := ticker.C
	var failed <-chan struct{}
	if r.run == nil {
		close(r.failed)
		ticker.Stop()
		poll = nil
	} else {
		failed = r.run.Failed()
		r.run.Route()
	}
	for {
		select {
		case facts := <-r.final:
			var err error
			if r.run != nil {
				ctx := r.finalContext
				if ctx == nil {
					ctx = context.Background()
				}
				_, err = r.run.FinishStages(ctx, facts, r.beforeFinal)
			}
			if r.finalContext == nil {
				_ = output.Close()
			}
			r.record(r.run != nil, err)
			return
		case <-failed:
			close(r.failed)
			ticker.Stop()
			poll, failed = nil, nil
		case <-poll:
			r.run.Route()
		}
	}
}

func (r *processingRun) record(finished bool, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.finished = finished
	if err != nil {
		// Workers and Writer return structural errors, never source bytes or
		// parser error text. Authorization and write errors remain independent.
		r.err = err
	}
}

// exclusionsOf is what a run's outcome says of the exchanges it excluded
// alone, by reason, and of its contained decoder faults, as the account
// carries them.
func exclusionsOf(outcome processing.Outcome) (*account.ExcludedExchanges, *uint64) {
	faults := outcome.DecoderFaults
	return &account.ExcludedExchanges{
		ContentCodingUnsupported: outcome.Excluded.ContentCodingUnsupported,
		ContentDecodingFailed:    outcome.Excluded.ContentDecodingFailed,
		ContentDecodedTooLarge:   outcome.Excluded.ContentDecodedTooLarge,
		ContentDecodingTooCostly: outcome.Excluded.ContentDecodingTooCostly,
	}, &faults
}

func (d *daemon) processingSnapshot() *account.Processing {
	if d.output == nil {
		return nil
	}
	state := account.Processing{}
	if r := d.currentProcessing(); r != nil && r.run != nil {
		outcome := r.run.Snapshot()
		state.ProcessingFailures, state.OutputFailures = outcome.ProcessingFailures, outcome.OutputFailures
		state.ConnectionsCut, state.InputCut = outcome.ConnectionsCut, outcome.InputCut
		state.Authorized, state.Written = outcome.Authorized, outcome.Written
		state.ExchangeIDs, state.Extensions = outcome.ExchangeIDs, outcome.Extensions
		state.ExcludedExchanges, state.DecoderFaults = exclusionsOf(outcome)
	}
	delivery := d.output.DeliveryStats()
	state.Authorized, state.Written, state.OutputFailures = delivery.Authorized, delivery.Written, delivery.Failed
	state.Delivery = delivery
	state.StdoutDelivery = d.output.StdoutDeliveryStats()
	state.GateReason = d.gate.Snapshot().Reason
	if state.Extensions == nil {
		state.Extensions = []account.ExtensionCounts{}
		for _, one := range d.policy.Processing.Extensions() {
			state.Extensions = append(state.Extensions, account.NoCounts(one.Name))
		}
	}
	return &state
}

// extensionLine is a line of an extension's standard error, or a failed
// result's reason, copied into the log: escaped, cut at its bound and
// attributed to the extension and generation.
type extensionLine struct {
	Record     string    `json:"record"`
	Version    int       `json:"version"`
	Session    string    `json:"session"`
	At         time.Time `json:"at"`
	Extension  string    `json:"extension"`
	Generation string    `json:"generation"`
	Line       string    `json:"line"`
	Cut        bool      `json:"cut"`
}

// extensionLogged writes what the log carries of an extension. It runs on the
// extension's supervisor, which is never the controller.
func (d *daemon) extensionLogged(e extension.Event) {
	kind := ""
	switch e.Kind {
	case extension.Stderr:
		kind = "extension-stderr"
	case extension.Reason:
		kind = "extension-reason"
	default:
		return
	}
	if d.log == nil {
		return
	}
	if err := d.log.write(extensionLine{Record: kind, Version: recordVersion, Session: d.session, At: time.Now(),
		Extension: e.Extension, Generation: strconv.FormatUint(e.Generation, 10), Line: e.Line, Cut: e.Cut}); err != nil {
		d.extensionLogFailures.Add(1)
	}
}

// finishProcessing runs only after withdrawal, delivery drain and capture's
// final records. False facts discard pending payload. The first shutdown
// trigger supplies the deadline; this owner never starts another allowance.
func (d *daemon) finishProcessing(ctx context.Context, facts processing.Finalization) error {
	d.startProcessing()
	r := d.currentProcessing()
	if r == nil {
		return processing.ErrFinished
	}
	r.stage.Store(shutdownWorkers)
	r.finalContext = ctx
	r.beforeFinal = func(ctx context.Context, stage string) error {
		r.stage.Store(shutdownStage(stage))
		switch shutdownStage(stage) {
		case shutdownWorkers, shutdownExtensions:
			return d.beforeShutdown(ctx, shutdownStage(stage))
		}
		return nil
	}
	r.final <- facts
	select {
	case <-r.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	// done establishes that the owner has stopped modifying these private facts.
	if r.err != nil {
		return r.err
	}
	if !r.finished {
		return processing.ErrFinished
	}
	return nil
}
