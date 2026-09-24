package processing

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// This fixture exercises the private writer state machine, not authorization.
// Private Approved values below stand for permission already obtained. Public
// release permission remains covered by the worker and independent gate tests.
type faultOutput struct {
	bytes.Buffer
	calls   int
	fail    bool
	partial int
	err     error
}

func (f *faultOutput) Write(p []byte) (int, error) {
	f.calls++
	if !f.fail {
		return f.Buffer.Write(p)
	}
	n, _ := f.Buffer.Write(p[:f.partial])
	return n, f.err
}

func (*faultOutput) Close() error { return nil }

func faultWriter(t *testing.T) (*Writer, *faultOutput) {
	t.Helper()
	f := &faultOutput{}
	w := &Writer{file: f, stats: WriterStats{LimitBytes: 1024}, exhausted: make(chan struct{})}
	t.Cleanup(func() { _ = w.Close() })
	return w, f
}

func requireWriterAvailable(t *testing.T, w *Writer) {
	t.Helper()
	select {
	case <-w.Exhausted():
		t.Fatal("recoverable writer unexpectedly exhausted")
	default:
	}
	if w.Stats().Exhausted {
		t.Fatal("recoverable writer reports exhausted")
	}
}

func TestWriterPermanentFailuresSignalOnce(t *testing.T) {
	for _, name := range []string{"io-error", "partial-io-error", "short-write"} {
		t.Run(name, func(t *testing.T) {
			w, f := faultWriter(t)
			const before = "control\n"
			if err := w.WriteApproved(context.Background(), Approved{line: []byte(before)}); err != nil {
				t.Fatal(err)
			}
			if f.calls != 1 || f.String() != before || w.Stats().Written != 1 {
				t.Fatal("successful write control did not reach output")
			}
			requireWriterAvailable(t, w)
			f.fail, f.err = true, errors.New("injected terminal write error")
			if name == "partial-io-error" {
				f.partial = 2
			}
			if name == "short-write" {
				f.partial, f.err = 3, nil
			}
			err := w.WriteApproved(context.Background(), Approved{line: []byte("failure\n")})
			if err == nil || f.calls != 2 {
				t.Fatalf("terminal branch not reached: calls=%d err=%v", f.calls, err)
			}
			if name == "short-write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write classified as %v", err)
			}
			if st := w.Stats(); st.Written != 1 || st.Bytes != int64(len(before)+f.partial) {
				t.Fatalf("failed output counted as delivery or lost byte charge: %+v", st)
			}
			t.Logf("%s reached after successful output; partial bytes=%d", name, f.partial)
			select {
			case <-w.Exhausted():
			default:
				t.Fatal("permanent write failure left exhaustion signal open")
			}
			if !w.Stats().Exhausted {
				t.Fatal("permanent stop missing from writer stats")
			}
			for i := 0; i < 3; i++ {
				if err := w.WriteApproved(context.Background(), Approved{line: []byte("later\n")}); !errors.Is(err, ErrOutputClosed) {
					t.Fatalf("terminal writer admitted another attempt: %v", err)
				}
			}
			if f.calls != 2 {
				t.Fatal("terminal writer retried file output")
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-w.Exhausted():
			default:
				t.Fatal("close lost sticky terminal signal")
			}
		})
	}
}

func TestWriterCancellationKeepsOutputAvailable(t *testing.T) {
	w, f := faultWriter(t)
	if err := w.WriteApproved(context.Background(), Approved{line: []byte("before\n")}); err != nil {
		t.Fatal(err)
	}
	requireWriterAvailable(t, w)
	before := w.Stats()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := w.WriteApproved(ctx, Approved{line: []byte("canceled\n")})
	if !errors.Is(err, context.Canceled) || f.calls != 1 || w.Stats() != before {
		t.Fatalf("cancellation did not stop before I/O: err=%v calls=%d stats=%+v", err, f.calls, w.Stats())
	}
	t.Log("cancellation reached before I/O with successful preceding write")
	requireWriterAvailable(t, w)
	if err := w.WriteApproved(context.Background(), Approved{line: []byte("after\n")}); err != nil {
		t.Fatalf("recoverable writer cannot write again: %v", err)
	}
	if f.calls != 2 || f.String() != "before\nafter\n" || w.Stats().Written != 2 {
		t.Fatal("successful post-cancellation control missing")
	}
	requireWriterAvailable(t, w)
}
