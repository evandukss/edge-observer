package sink

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestFinalRepairsPartialLineBeforeTerminal(t *testing.T) {
	s := &controlledSink{failures: 1, partial: 1}
	q := queueFor(t, s, 64)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	q.Freeze()
	before := q.Stats()
	if err := q.WriteFinal(timeout(t), "records", []byte("[]\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !bytes.Equal(s.output.Bytes(), []byte("{\n[]\n")) {
		t.Fatalf("terminal appended to broken line: %q", s.output.Bytes())
	}
	if q.Stats() != before {
		t.Fatal("terminal repair changed frozen facts")
	}
}

func TestFinalRefusesOversizeAndClosedResources(t *testing.T) {
	s := &controlledSink{}
	q := queueFor(t, s, 3)
	q.Freeze()
	if err := q.WriteFinal(timeout(t), "records", []byte("{ }\n")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("unbounded terminal: %v", err)
	}
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := q.WriteFinal(timeout(t), "records", []byte("{}\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed destination reused: %v", err)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.writes != 0 {
		t.Fatalf("invalid terminal reached sink: %d writes", s.writes)
	}
}

func TestFinalWaitExpiresWithoutLateWrite(t *testing.T) {
	s := &controlledSink{entered: make(chan struct{}, 1), unblock: make(chan struct{})}
	q := queueFor(t, s, 64)
	released := false
	defer func() {
		if !released {
			close(s.unblock)
		}
	}()
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-timeout(t).Done():
		t.Fatal("ordinary write hold was not reached")
	}
	q.Freeze()
	before, destination := q.Stats(), q.DestinationStats("records")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := q.WriteFinal(ctx, "records", []byte("[]\n")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held final: %v", err)
	}
	close(s.unblock)
	released = true
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if q.Stats() != before || q.DestinationStats("records") != destination {
		t.Fatal("frozen delivery changed")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.writes != 1 {
		t.Fatalf("late final write: %d", s.writes)
	}
}

func TestFinalRequiresFreezeAndIsSingleAttempt(t *testing.T) {
	s := &controlledSink{}
	q := queueFor(t, s, 64)
	if err := q.WriteFinal(timeout(t), "records", []byte("{}\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("unfrozen write: %v", err)
	}
	q.Freeze()
	before := q.Stats()
	if err := q.WriteFinal(timeout(t), "records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.WriteFinal(timeout(t), "records", []byte("[]\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := q.Enqueue("records", []byte("[]\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("ordinary admission reopened: %v", err)
	}
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if q.Stats() != before {
		t.Fatal("final changed accounting")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.writes != 1 {
		t.Fatalf("final attempts: %d", s.writes)
	}
}

func TestFinalInflightRemainsBoundedAndUncounted(t *testing.T) {
	s := &controlledSink{entered: make(chan struct{}, 1), unblock: make(chan struct{})}
	q := queueFor(t, s, 64)
	q.Freeze()
	before := q.Stats()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.WriteFinal(ctx, "records", []byte("{}\n")) }()
	select {
	case <-s.entered:
	case <-timeout(t).Done():
		close(s.unblock)
		t.Fatal("final write hold was not reached")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("held final result: %v", err)
		}
	case <-timeout(t).Done():
		close(s.unblock)
		t.Fatal("final caller waited for blocked I/O")
	}
	retained, err := q.Retained()
	if err != nil || retained[0].Held != 1 {
		t.Errorf("inflight terminal retention: %+v %v", retained, err)
	}
	close(s.unblock)
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if q.Stats() != before {
		t.Fatal("terminal completion changed accounting")
	}
}

type finalRepairSink struct {
	calls  int
	cancel context.CancelFunc
}

func (s *finalRepairSink) Write(_ context.Context, p []byte) (int, error) {
	s.calls++
	if s.calls == 1 {
		return 1, errors.New("partial ordinary line")
	}
	if s.calls == 2 && string(p) == "\n" {
		s.cancel()
		return 1, nil
	}
	return len(p), nil
}
func (*finalRepairSink) Close(context.Context) error  { return nil }
func (*finalRepairSink) Reopen(context.Context) error { return nil }

func TestFinalRechecksContextAfterPartialLineRepair(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &finalRepairSink{cancel: cancel}
	q := queueFor(t, s, 64)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	q.Freeze()
	before := q.Stats()
	if err := q.WriteFinal(ctx, "records", []byte("[]\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("repair cancellation: %v", err)
	}
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if s.calls != 2 {
		t.Fatalf("terminal write began after canceled repair: %d calls", s.calls)
	}
	if q.Stats() != before {
		t.Fatal("repair changed frozen counts")
	}
}
