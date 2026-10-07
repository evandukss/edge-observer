package sink

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type controlledSink struct {
	mutex     sync.Mutex
	output    bytes.Buffer
	writes    int
	failures  int
	partial   int
	entered   chan struct{}
	unblock   chan struct{}
	reopens   int
	reopenErr error
}

func (s *controlledSink) Write(_ context.Context, p []byte) (int, error) {
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.unblock != nil {
		<-s.unblock
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.writes++
	if s.failures > 0 {
		s.failures--
		n := min(s.partial, len(p))
		s.output.Write(p[:n])
		return n, errors.New("injected write failure")
	}
	return s.output.Write(p)
}
func (s *controlledSink) Reopen(context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.reopens++
	return s.reopenErr
}
func (*controlledSink) Close(context.Context) error { return nil }
func timeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
func queueFor(t *testing.T, s Sink, limit int64) *Queue {
	t.Helper()
	q, err := NewQueue(limit)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Register("records", s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = q.Shutdown(ctx)
	})
	return q
}
func TestQueueFailuresRecoverAtLineBoundary(t *testing.T) {
	s := &controlledSink{failures: 1, partial: 3}
	q := queueFor(t, s, 1024)
	for _, line := range []string{"{\"first\":1}\n", "{\"second\":2}\n"} {
		if err := q.Enqueue("records", []byte(line)); err != nil {
			t.Fatal(err)
		}
		if err := q.Drain(timeout(t)); err != nil {
			t.Fatal(err)
		}
	}
	s.mutex.Lock()
	got := s.output.String()
	calls := s.writes
	s.mutex.Unlock()
	if calls != 3 || got != "{\"f\n{\"second\":2}\n" {
		t.Fatalf("line boundary recovery: calls %d output %q", calls, got)
	}
	st := q.Stats()
	if st.Authorized != 2 || st.Written != 1 || st.Failed != 1 || st.Pending != 0 || st.Dropped != 0 || st.PendingBytes != 0 {
		t.Fatalf("outcomes: %+v", st)
	}
}
func TestQueueRepeatedErrorsThenSuccess(t *testing.T) {
	s := &controlledSink{failures: 3}
	q := queueFor(t, s, 1024)
	for range 4 {
		if err := q.Enqueue("records", []byte("{}\n")); err != nil {
			t.Fatal(err)
		}
		if err := q.Drain(timeout(t)); err != nil {
			t.Fatal(err)
		}
	}
	st := q.Stats()
	if st.Authorized != 4 || st.Failed != 3 || st.Written != 1 {
		t.Fatalf("attempts: %+v", st)
	}
}
func TestQueueBoundsInflightAndDiscardsOnBoundedShutdown(t *testing.T) {
	s := &controlledSink{entered: make(chan struct{}, 1), unblock: make(chan struct{})}
	q := queueFor(t, s, 6)
	defer close(s.unblock)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-timeout(t).Done():
		t.Fatal("wiring: sink not reached")
	}
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("records", []byte("{}\n")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full queue: %v", err)
	}
	st := q.Stats()
	if st.PendingBytes != 6 || st.Pending != 2 || st.Dropped != 1 || st.HighWaterBytes != 6 {
		t.Fatalf("charge: %+v", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := q.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked shutdown: %v", err)
	}
	st = q.Stats()
	if st.Pending != 0 || st.Discarded != 2 || st.Dropped != 3 || st.Written != 0 || st.Failed != 0 {
		t.Fatalf("discard: %+v", st)
	}
}
func TestReopenDoesNotAcknowledgeBlockedOldWrite(t *testing.T) {
	s := &controlledSink{entered: make(chan struct{}, 1), unblock: make(chan struct{})}
	q := queueFor(t, s, 64)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-timeout(t).Done():
		t.Fatal("wiring: sink not reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := q.Reopen(ctx)
	s.mutex.Lock()
	reopens := s.reopens
	s.mutex.Unlock()
	close(s.unblock)
	if !errors.Is(err, context.DeadlineExceeded) || reopens != 0 {
		t.Fatalf("reopen crossed old write: err %v calls %d", err, reopens)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := q.Reopen(timeout(t)); err != nil {
		t.Fatal(err)
	}
}
func TestFileUnavailableThenReopenAndRename(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "records.jsonl")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	q := queueFor(t, NewFile(path), 1024)
	if err := q.Enqueue("records", []byte("{\"lost\":1}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Failed != 1 {
		t.Fatalf("unavailable attempt: %+v", q.Stats())
	}
	if err := q.Reopen(timeout(t)); err == nil {
		t.Fatal("failed reopen acknowledged")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := q.Reopen(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("records", []byte("{\"old\":1}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := q.Reopen(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("records", []byte("{\"new\":1}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != "{\"old\":1}\n" || string(current) != "{\"new\":1}\n" {
		t.Fatalf("rotation: old %q new %q", old, current)
	}
	if q.Stats().Written != 2 || q.Stats().Failed != 1 {
		t.Fatalf("rotation counts: %+v", q.Stats())
	}
}
func TestFileAppendAcrossSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	for _, line := range []string{"{\"session\":\"a\"}\n", "{\"session\":\"b\"}\n"} {
		q := queueFor(t, NewFile(path), 1024)
		if err := q.Enqueue("records", []byte(line)); err != nil {
			t.Fatal(err)
		}
		if err := q.Shutdown(timeout(t)); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "{\"session\":\"a\"}\n{\"session\":\"b\"}\n" {
		t.Fatalf("append: %q", content)
	}
}

func TestFileAppendSeparatesAnUnterminatedOldRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	if err := os.WriteFile(path, []byte("{partial"), 0600); err != nil {
		t.Fatal(err)
	}
	q := queueFor(t, NewFile(path), 1024)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Shutdown(timeout(t)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{partial\n{}\n" {
		t.Fatalf("joined old prefix to new line: %q", got)
	}
}
func TestQueueAcceptsLaterLineAfterFullQueueRecovers(t *testing.T) {
	s := &controlledSink{entered: make(chan struct{}, 1), unblock: make(chan struct{})}
	q := queueFor(t, s, 3)
	if err := q.Enqueue("records", []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-timeout(t).Done():
		t.Fatal("wiring: first write not reached")
	}
	rejected := q.Enqueue("records", []byte("{}\n"))
	close(s.unblock)
	if !errors.Is(rejected, ErrQueueFull) {
		t.Fatalf("full: %v", rejected)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("records", []byte("[]\n")); err != nil {
		t.Fatal(err)
	}
	if err := q.Drain(timeout(t)); err != nil {
		t.Fatal(err)
	}
	if st := q.Stats(); st.Authorized != 3 || st.Written != 2 || st.Dropped != 1 || st.Pending != 0 {
		t.Fatalf("recovery: %+v", st)
	}
}
