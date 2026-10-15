package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/processing"
)

func (d *daemon) prepareShutdown() *shutdownBoundary {
	d.shutdownInit.Do(func() {
		if d.shutdown == nil {
			d.shutdown = newShutdownBoundary(nil)
		}
		d.withdrawalResult = make(chan withdrawalResult, 1)
		d.shutdownEarlyHooks = d.shutdownHooks
		// Keep a detached fallback before any controller operation can be held.
		d.planMutex.Lock()
		content, _ := json.Marshal(d.plan)
		d.planMutex.Unlock()
		_ = json.Unmarshal(content, &d.shutdownPlan)
		s := d.shutdown
		go func() {
			select {
			case <-d.gate.Withdrawal():
				s.trigger()
			case <-s.started:
			}
		}()
		go func() {
			<-s.started
			d.beginWithdrawal(s.work)
			<-s.work.Done()
			d.closeOutput()
			_ = d.finish(d.log)
		}()
	})
	return d.shutdown
}

// finish can be entered by the controller or its deadline watcher. Only the
// winner owns the account and publication sequence.
func (d *daemon) finish(log *logger) error {
	s := d.prepareShutdown()
	s.trigger()
	d.finishOnce.Do(func() { d.finishErr = d.finalize(log, s) })
	return d.finishErr
}

type deadlineProducer struct {
	owner    connection.Producer
	withdraw func() (connection.Withdrawal, error)
	ctx      context.Context
	hooks    *shutdownHooks
}

func (p deadlineProducer) StopProducing() (connection.Withdrawal, error) {
	return p.withdraw()
}
func (p deadlineProducer) Drain(within time.Duration) (connection.Drained, error) {
	if deadline, ok := p.ctx.Deadline(); ok {
		within = min(within, max(0, time.Until(deadline)))
	}
	ctx, cancel := context.WithTimeout(p.ctx, within)
	defer cancel()
	return shutdownStep(ctx, p.hooks, shutdownDrain, func() (connection.Drained, error) {
		if owner, ok := p.owner.(attachment.Lifecycle); ok {
			return owner.DrainContext(ctx, within)
		}
		return p.owner.Drain(within)
	})
}
func (p deadlineProducer) Account() (connection.Counters, error) {
	return shutdownStep(p.ctx, p.hooks, shutdownCounters, func() (connection.Counters, error) {
		if owner, ok := p.owner.(attachment.Lifecycle); ok {
			return owner.AccountContext(p.ctx)
		}
		return p.owner.Account()
	})
}

func (d *daemon) finalize(log *logger, s *shutdownBoundary) error {
	defer s.finished()
	ctx := s.work
	expiredController := ctx.Err() != nil
	sealer := connection.Sealer{Producer: deadlineProducer{owner: producing(d.attached), withdraw: func() (connection.Withdrawal, error) { return d.withdrawal(ctx) }, ctx: ctx, hooks: d.shutdownHooks}, Within: drainWithin}
	seal, sealErr := sealer.Stop()
	var failures []error
	if failure := d.controllerFailure.Load(); failure != nil {
		failures = append(failures, failure)
	} else if expiredController {
		failures = append(failures, &shutdownFailure{shutdownController, ctx.Err()})
	}
	if sealErr != nil {
		failures = append(failures, sealErr)
	}
	captureCounts, err := shutdownStep(ctx, d.shutdownHooks, shutdownCapture, func() (connection.Counters, error) {
		d.capture.Finish(time.Now())
		return d.capture.Counted(), nil
	})
	if err != nil {
		failures = append(failures, err)
	}
	seal.Counters = seal.Counters.Join(captureCounts)
	noSpool := connection.Uncounted("raw fragments are not persisted; approved route records are counted separately")
	seal.Counters.Persisted, seal.Counters.PersistedDropped, seal.Counters.PersistedRefused = noSpool, noSpool, noSpool
	final, snapshotErr := shutdownStep(ctx, d.shutdownHooks, shutdownSnapshot, func() (account.Account, error) {
		return d.snapshot(account.Sealed, time.Now()), nil
	})
	if snapshotErr != nil {
		failures = append(failures, snapshotErr)
		final = d.shutdownPlan
		final.Kind, final.At = account.Sealed, time.Now()
		// Counts not read at the boundary are absent, never the activation reading
		// presented as a final count.
		final.Seen, final.Loss, final.Refused, final.Admitted, final.Admissions = nil, nil, nil, nil, nil
	}
	// The processing owner identifies its worker and extension joins individually.
	err = shutdownCall(ctx, nil, shutdownWorkers, func() error {
		err := d.finishProcessing(ctx, processing.Finalization{Withdrawn: seal.Withdrawal.Complete, Drained: seal.Drain.Complete})
		if err == nil {
			err = d.intake.Close()
		}
		return err
	})
	if err != nil {
		if r := d.currentProcessing(); r != nil && ctx.Err() != nil {
			if stage, ok := r.stage.Load().(shutdownStage); ok {
				err = &shutdownFailure{stage, ctx.Err()}
			}
		}
		failures = append(failures, err)
	}
	err = shutdownCall(ctx, d.shutdownHooks, shutdownWriter, func() error {
		// Delivery is best effort. Its bounded discard is a decided outcome and is
		// represented in delivery accounting, not as a capture failure.
		delivery, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_ = d.output.Shutdown(delivery)
		return ctx.Err()
	})
	if err != nil {
		failures = append(failures, err)
	}
	d.closeOutput()
	final.Processing = d.processingSnapshot()
	err = shutdownCall(ctx, d.shutdownHooks, shutdownAttachment, func() error {
		if owner, ok := d.attached.(attachment.Lifecycle); ok {
			return owner.CloseContext(ctx)
		}
		return d.attached.Close()
	})
	if err != nil {
		failures = append(failures, err)
	}
	for _, err := range failures {
		seal.Because = append(seal.Because, err.Error())
	}
	if len(failures) > 0 {
		seal.Complete = false
	}
	if log != nil {
		err = shutdownCall(ctx, d.shutdownHooks, shutdownLog, func() error {
			delivery, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			_ = log.freeze(delivery)
			return ctx.Err()
		})
		if err != nil {
			seal.Complete = false
			seal.Because = append(seal.Because, err.Error())
		}
		// Freeze even when the stage could not be entered. This operation closes
		// admission and fixes facts without joining a destination or closing it.
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		_ = log.freeze(cancelled)
		if log.queue != nil {
			stats := log.queue.Stats()
			final.LogDelivery = &stats
			final.LogDestinations = log.destinationStats()
		}
	}
	seal.Sealed = time.Now()
	final.Closed(seal, nil)
	// The terminal stopped record is the sole record outside these log facts.

	return d.publishFinal(s.publish, final, log)
}

func (d *daemon) publishFinal(ctx context.Context, final account.Account, log *logger) error {
	record := stopped{Record: "stopped", Version: recordVersion, Session: d.session, At: time.Now(), Processing: final.Processing, LogFailures: int(d.logFailures.Load() + d.extensionLogFailures.Load() + d.endedLogFailures.Load())}
	receipt := shutdownReceipt{Session: d.session, Outcome: shutdownComplete}
	var failures []error
	if final.Seal == nil || !final.Seal.Complete {
		receipt.Outcome = shutdownIncomplete
		why := "finalization did not complete"
		if final.Seal != nil {
			why = fmt.Sprint(final.Seal.Because)
		}
		failures = append(failures, errors.New("sealed INCOMPLETE: "+why))
	}
	if final.Processing != nil && final.Processing.GateReason.InvalidatesCapture() {
		failures = append(failures, fmt.Errorf("capture ended: %s", final.Processing.GateReason))
	}
	path := filepath.Join(d.directory, sealedName)
	err := validateSessionSeal(final)
	if err == nil {
		err = d.placeFinal(ctx, shutdownAccount, path, final)
	}
	if err != nil {
		receipt.Outcome = shutdownUnsealed
		record.Error = err.Error()
		failures = append(failures, err)
	} else {
		record.Sealed, record.Complete, record.Account = true, final.Seal.Complete, path
		receipt.Sealed = final.Seal.Sealed
		projected, projectionErr := published.Account(final)
		if projectionErr == nil {
			projectionErr = d.placeFinal(ctx, shutdownProjection, filepath.Join(d.directory, published.Name), projected)
		}
		if projectionErr != nil {
			receipt.Outcome = shutdownPublicationFailed
			failures = append(failures, projectionErr)
			record.ContractError = projectionErr.Error()
		} else {
			record.Contract = filepath.Join(d.directory, published.Name)
		}
		last := sealedSession{Session: d.session, Sealed: final.Seal.Sealed, Account: path, Complete: final.Seal.Complete, Lost: final.Lost()}
		if final.Processing != nil {
			last.Reason = final.Processing.GateReason
		}
		if pointerErr := d.placeFinal(ctx, shutdownPointer, filepath.Join(d.policy.Settings.Directory, lastName), last); pointerErr != nil {
			receipt.Outcome = shutdownPublicationFailed
			failures = append(failures, pointerErr)
		}
	}
	if failure := errors.Join(failures...); failure != nil {
		receipt.Error = failure.Error()
	}
	// Receipt failure makes the command fail too. The seal is unaffected.
	receiptErr := shutdownCall(ctx, d.shutdownHooks, shutdownResult, func() error {
		directory := filepath.Join(d.directory, controlName)
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		content, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		return placeBefore(ctx, filepath.Join(directory, terminalName), content)
	})
	failures = append(failures, receiptErr)
	if failure := errors.Join(failures...); failure != nil {
		record.Error = failure.Error()
	}
	if log != nil {
		// Best effort terminal delivery gets no fresh shutdown allowance. A held
		// destination cannot prevent the daemon from returning within the backstop.
		terminal, cancel := context.WithTimeout(ctx, time.Second)
		_ = shutdownCall(terminal, nil, shutdownLog, func() error { return log.writeStopped(terminal, record) })
		cancel()
		_ = shutdownCall(ctx, nil, shutdownLog, log.close)
	}
	return errors.Join(failures...)
}

type withdrawalResult struct {
	facts connection.Withdrawal
	err   error
}

func (d *daemon) beginWithdrawal(ctx context.Context) {
	d.withdrawalOnce.Do(func() {
		go func() {
			facts, err := shutdownStep(ctx, d.shutdownEarlyHooks, shutdownWithdrawal, func() (connection.Withdrawal, error) {
				if owner, ok := d.attached.(attachment.Lifecycle); ok {
					return owner.StopProducingContext(ctx)
				}
				return producing(d.attached).StopProducing()
			})
			d.withdrawalResult <- withdrawalResult{facts, err}
		}()
	})
}

func (d *daemon) withdrawal(ctx context.Context) (connection.Withdrawal, error) {
	d.beginWithdrawal(ctx)
	// A completed withdrawal stays evidence even if the controller used up the
	// work budget before finalization could read it.
	select {
	case result := <-d.withdrawalResult:
		return result.facts, result.err
	default:
	}
	select {
	case result := <-d.withdrawalResult:
		return result.facts, result.err
	case <-ctx.Done():
		return connection.Withdrawal{}, &shutdownFailure{shutdownWithdrawal, ctx.Err()}
	}
}

func (d *daemon) closeOutput() {
	d.processingMutex.Lock()
	d.processingClosed = true
	r := d.processing
	if r != nil && r.run != nil {
		r.run.CloseAdmission()
	}
	d.processingMutex.Unlock()
	d.output.Freeze()
	if r != nil && r.run != nil {
		r.run.FreezeSnapshot()
	}
}
