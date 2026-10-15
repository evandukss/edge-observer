package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/evandukss/edge-observer/sink"
)

// prepareLocked also preserves the destinations of test-constructed loggers.
func (l *logger) prepareLocked() {
	if l.queue == nil {
		l.queue, _ = sink.NewQueue(logQueueBytes)
		if l.file != nil {
			_ = l.queue.Register("file", &logOutput{out: l.file})
			l.destinations = append(l.destinations, "file")
		}
		if l.out != nil {
			_ = l.queue.Register("stdout", &logOutput{out: l.out})
			l.destinations = append(l.destinations, "stdout")
		}
	}
}

// freeze closes ordinary admission and fixes delivery facts, leaving destination
// resources open for writeStopped after account publication. Call close last.
func (l *logger) freeze(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mutex.Lock()
	l.prepareLocked()
	q := l.queue
	q.CloseAdmission()
	l.mutex.Unlock()
	err := q.Drain(ctx)
	q.Freeze()
	return err
}

// writeStopped delivers the sole post-seal operational record outside frozen
// accounting. freeze must precede it; close must follow it. The caller supplies
// its remaining shutdown deadline. A held destination does not delay another.
func (l *logger) writeStopped(ctx context.Context, record stopped) error {
	if l == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.Record != "stopped" {
		return errors.New("terminal log record must be stopped")
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	l.mutex.Lock()
	q := l.queue
	names := append([]string(nil), l.destinations...)
	l.mutex.Unlock()
	if q == nil {
		return sink.ErrClosed
	}
	done := make(chan error, len(names))
	for _, name := range names {
		go func() { done <- q.WriteFinal(ctx, name, line) }()
	}
	var errs []error
	for range names {
		select {
		case err := <-done:
			errs = append(errs, err)
		case <-ctx.Done():
			return errors.Join(append(errs, ctx.Err())...)
		}
	}
	return errors.Join(errs...)
}
