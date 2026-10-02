package main

import (
	"context"
	"strconv"
	"sync"
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
	run      *processing.Run
	mutex    sync.Mutex
	finished bool
	err      error
	failed   chan struct{}
	final    chan processing.Finalization
	done     chan struct{}
}

// startProcessing fixes the workers' inputs before serving any control request.
// begin already fixed this plan, revision, intake, gate and writer before
// admission. Reload cannot replace the processing plan or the worker count
// during this session.
func (d *daemon) startProcessing() <-chan struct{} {
	if d.processing != nil {
		return d.processing.failed
	}
	if d.output == nil {
		// A controller without an output owner has no processing path. Production
		// begin requires that owner before constructing its delivery gate.
		return nil
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
	d.processing = r
	go r.serve(d.output)
	return r.failed
}

func (r *processingRun) serve(output *processing.Writer) {
	defer close(r.done)
	if r.run != nil {
		defer func() { _ = r.run.Close() }()
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
				_, err = r.run.Finish(context.Background(), facts)
			}
			_ = output.Close()
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

func (d *daemon) processingSnapshot() *account.Processing {
	if d.output == nil {
		return nil
	}
	state := account.Processing{}
	if r := d.processing; r != nil && r.run != nil {
		outcome := r.run.Snapshot()
		state.ProcessingFailures, state.OutputFailures = outcome.ProcessingFailures, outcome.OutputFailures
		state.ConnectionsCut, state.InputCut = outcome.ConnectionsCut, outcome.InputCut
		state.Authorized, state.Written = outcome.Authorized, outcome.Written
		state.ExchangeIDs, state.Extensions = outcome.ExchangeIDs, outcome.Extensions
	}
	delivery := d.output.DeliveryStats()
	state.Authorized, state.Written, state.OutputFailures = delivery.Authorized, delivery.Written, delivery.Failed
	state.Delivery = delivery
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
// final records. False facts discard pending payload. This wait has no invented
// timeout: the whole-session bound and its terminal states belong to T4.
func (d *daemon) finishProcessing(facts processing.Finalization) error {
	d.startProcessing()
	if d.processing == nil {
		return processing.ErrFinished
	}
	d.processing.final <- facts
	<-d.processing.done
	// done establishes that the owner has stopped modifying these private facts.
	if d.processing.err != nil {
		return d.processing.err
	}
	if !d.processing.finished {
		return processing.ErrFinished
	}
	return nil
}
