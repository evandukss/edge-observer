package sink

import (
	"context"
	"errors"
	"testing"
)

func TestFreezeKeepsDeliveryFactsAfterInflightCompletion(t *testing.T) {
	s := &controlledSink{entered: make(chan struct{}, 1), unblock: make(chan struct{})}
	q := queueFor(t, s, 9)
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
		t.Fatal("wiring: destination hold not reached")
	}
	if err := q.Enqueue("records", []byte("[]\n")); err != nil {
		t.Fatal(err)
	}
	q.Freeze()
	before := q.Stats()
	if before.Authorized != 2 || before.Dropped != 2 || before.Discarded != 2 || before.Pending != 0 || before.PendingBytes != 3 {
		t.Fatalf("freeze did not decide pending delivery: %+v", before)
	}
	if err := q.Enqueue("records", []byte("{}\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("freeze admitted a line: %v", err)
	}
	close(s.unblock)
	released = true
	// Closing at the destination boundary proves the held write has returned.
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	q.Freeze()
	if after := q.Stats(); after != before {
		t.Fatalf("delivery facts changed after freeze: before %+v after %+v", before, after)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.writes != 1 {
		t.Fatalf("discarded queued line reached destination: %d writes", s.writes)
	}
}

func TestCloseAdmissionStillDrainsAcceptedLines(t *testing.T) {
	s := &controlledSink{}
	q := queueFor(t, s, 64)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	q.CloseAdmission()
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	q.Freeze()
	if got := q.Stats(); got.Written != 1 || got.Discarded != 0 {
		t.Fatalf("close did not drain admitted line: %+v", got)
	}
	if err := q.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
