package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/processing"
)

// processingEvery is the cadence for taking newly queued volatile records.
// It is neither a batch-completeness test nor a finalization deadline.
const processingEvery = 10 * time.Millisecond

// processingRun has one worker owner, separate from the controller selecting
// withdrawal signals. No controller lock is held through parsing or writing.
// A snapshot copies the ruled facts from the last returned outcome; it never
// waits on writer I/O. Cleanup state and errors remain private to this owner.
type processingRun struct {
	mutex    sync.Mutex
	outcome  processing.Outcome
	finished bool
	err      error
	failed   chan struct{}
	final    chan processing.Finalization
	done     chan struct{}
}

// startProcessing fixes the worker's inputs before serving any control request.
// begin already fixed this plan, revision, intake, gate and writer before
// admission. Reload cannot replace the processing plan during this session.
func (d *daemon) startProcessing() <-chan struct{} {
	if d.processing != nil {
		return d.processing.failed
	}
	if d.output == nil {
		// A controller without an output owner has no processing path. Production
		// begin requires that owner before constructing its delivery gate.
		return nil
	}
	opts := processing.Options{Plan: d.policy.Processing, PolicyRevision: d.policy.ProcessingRevision,
		Intake: d.intake, Gate: d.gate, Output: d.output}
	r := &processingRun{
		failed: make(chan struct{}), final: make(chan processing.Finalization, 1), done: make(chan struct{}),
	}
	d.processing = r
	go r.run(opts, d.output)
	return r.failed
}

func (r *processingRun) run(opts processing.Options, output *processing.Writer) {
	defer close(r.done)
	worker, err := processing.New(opts)
	if worker != nil {
		defer func() { _ = worker.Close() }()
	}
	ticker := time.NewTicker(processingEvery)
	defer ticker.Stop()
	poll := ticker.C
	var outcome processing.Outcome
	if err == nil {
		outcome, err = worker.Drain(context.Background())
	}
	r.record(outcome, false, err)
	if err != nil {
		close(r.failed)
		ticker.Stop()
		poll = nil
	}
	for {
		select {
		case facts := <-r.final:
			finished := worker != nil
			if worker != nil {
				outcome, err = worker.Finish(context.Background(), facts)
			}
			err = errors.Join(err, output.Close())
			r.record(outcome, finished, err)
			return
		case <-poll:
			outcome, err = worker.Drain(context.Background())
			r.record(outcome, false, err)
			if err != nil {
				close(r.failed)
				ticker.Stop()
				poll = nil
			}
		}
	}
}

func (r *processingRun) record(outcome processing.Outcome, finished bool, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.outcome, r.finished = outcome, finished
	if err != nil {
		// Worker and Writer return structural errors, never source bytes or
		// parser error text. Authorization and write errors remain independent.
		r.err = err
	}
}

func (d *daemon) processingSnapshot() *account.Processing {
	if d.output == nil {
		return nil
	}
	state := account.Processing{StoppedPipelines: []string{}}
	if r := d.processing; r != nil {
		r.mutex.Lock()
		state.ProcessingFailures, state.OutputFailures = r.outcome.ProcessingFailures, r.outcome.OutputFailures
		state.Authorized, state.Written = r.outcome.Authorized, r.outcome.Written
		state.StoppedPipelines = append(state.StoppedPipelines, r.outcome.StoppedPipelines...)
		r.mutex.Unlock()
	}
	state.GateReason = d.gate.Snapshot().Reason
	return &state
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
