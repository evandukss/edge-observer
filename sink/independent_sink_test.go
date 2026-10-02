package sink_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/sink"
)

// These cases are written from the sink package's published comments and the
// approved line envelope (contract/record/record.md), not from the
// implementation. The queue's properties are measured against a destination
// written here (independentHeld), because what is under test is the queue.
// The file sink's properties are measured against sink.NewFile, with the
// failure made by the kernel: a directory where the file belongs, a file size
// limit, a FIFO nobody reads.

const independentName = "approved"

// independentLine is one complete line of exactly n bytes, LF included, whose
// tag tells it apart from every other line in a case.
func independentLine(tag string, n int) []byte {
	prefix, suffix := `{"tag":"`+tag+`","pad":"`, "\"}\n"
	pad := n - len(prefix) - len(suffix)
	if pad < 0 {
		panic(fmt.Sprintf("a %d-byte line cannot hold the tag %q", n, tag))
	}
	return []byte(prefix + strings.Repeat("x", pad) + suffix)
}

func independentQueue(t *testing.T, limit int64, destination sink.Sink) *sink.Queue {
	t.Helper()
	q, err := sink.NewQueue(limit)
	if err != nil || q == nil {
		t.Fatalf("wiring, not the property: NewQueue(%d) refused: %v", limit, err)
	}
	if err := q.Register(independentName, destination); err != nil {
		t.Fatalf("wiring, not the property: Register refused the destination: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = q.Shutdown(ctx)
	})
	return q
}

// independentDrain waits for the queue's pending work. Drain's own error is
// not judged here: a case with failing writes decides what a failure means.
func independentDrain(t *testing.T, q *sink.Queue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := q.Drain(ctx)
	if pending := q.Stats(); pending.Pending != 0 {
		t.Fatalf("the queue still holds %d pending lines after Drain returned %v: %+v", pending.Pending, err, pending)
	}
}

// independentConserved is the published identity: every authorised line is
// written, failed, dropped or pending, and what shutdown discarded is dropped.
func independentConserved(t *testing.T, s sink.Stats) {
	t.Helper()
	if s.Authorized != s.Written+s.Failed+s.Dropped+s.Pending {
		t.Errorf("authorised %d is not written %d + failed %d + dropped %d + pending %d",
			s.Authorized, s.Written, s.Failed, s.Dropped, s.Pending)
	}
	if s.Discarded > s.Dropped {
		t.Errorf("discarded %d is more than dropped %d, and discarded is a part of dropped", s.Discarded, s.Dropped)
	}
}

func independentContent(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return content
}

// independentHeld is a destination that keeps what it is given, and holds
// every Write until released when told to. A held Write ignores its context,
// as a write(2) blocked in the kernel does.
type independentHeld struct {
	mutex    sync.Mutex
	content  bytes.Buffer
	writes   int
	hold     chan struct{}
	entered  chan struct{}
	finished chan struct{}
}

func newIndependentHeld(holding bool) *independentHeld {
	h := &independentHeld{entered: make(chan struct{}, 1024), finished: make(chan struct{}, 1024)}
	if holding {
		h.hold = make(chan struct{})
	}
	return h
}

func (h *independentHeld) Write(_ context.Context, line []byte) (int, error) {
	h.entered <- struct{}{}
	if h.hold != nil {
		<-h.hold
	}
	h.mutex.Lock()
	_, _ = h.content.Write(line)
	h.writes++
	h.mutex.Unlock()
	h.finished <- struct{}{}
	return len(line), nil
}

func (h *independentHeld) Reopen(context.Context) error { return nil }
func (h *independentHeld) Close(context.Context) error  { return nil }

func (h *independentHeld) release() { close(h.hold) }

func (h *independentHeld) bytes() []byte {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return bytes.Clone(h.content.Bytes())
}

// independentWaitFor waits for one signal on c, failing as wiring when none comes.
func independentWaitFor(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Fatalf("wiring, not the property: %s within 10s", what)
	}
}

// independentLimitFileSize sets this process's file size limit (RLIMIT_FSIZE),
// so a write past size is cut by the kernel: a write crossing it keeps the
// bytes below it and fails, and a write at it fails whole with EFBIG. SIGXFSZ
// is ignored meanwhile, so the failure is an error and not the end of the test
// binary. No other test of this package runs alongside: none is parallel.
func independentLimitFileSize(t *testing.T, size int64) func() {
	t.Helper()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("wiring, not the property: read the file size limit: %v", err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(size), Max: old.Max}); err != nil {
		signal.Reset(syscall.SIGXFSZ)
		t.Fatalf("wiring, not the property: set the file size limit to %d: %v", size, err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
				t.Errorf("restore the file size limit: %v", err)
			}
			signal.Reset(syscall.SIGXFSZ)
		})
	}
	t.Cleanup(restore)
	return restore
}

// independentFIFO makes a FIFO at path and opens its read end, then fills the
// pipe to capacity so the next write to it blocks until the reader reads.
// It returns the read end and how many filler bytes are in the pipe.
func independentFIFO(t *testing.T, path string) (int, int) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("wiring, not the property: make a FIFO: %v", err)
	}
	reader, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("wiring, not the property: open the FIFO's read end: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(reader) })
	if _, err := unix.FcntlInt(uintptr(reader), unix.F_SETPIPE_SZ, 4096); err != nil {
		t.Fatalf("wiring, not the property: shrink the pipe: %v", err)
	}
	writer, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("wiring, not the property: open the FIFO's write end: %v", err)
	}
	defer func() { _ = syscall.Close(writer) }()
	filler := bytes.Repeat([]byte("f"), 1<<16)
	filled := 0
	for {
		n, err := syscall.Write(writer, filler)
		if n > 0 {
			filled += n
		}
		if errors.Is(err, syscall.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatalf("wiring, not the property: fill the pipe: %v", err)
		}
	}
	if filled == 0 {
		t.Fatal("wiring, not the property: the pipe took no filler, so nothing below would block")
	}
	return reader, filled
}

// independentReadFIFO reads from a non-blocking read end until it holds want
// bytes or ten seconds pass.
func independentReadFIFO(t *testing.T, reader, want int) []byte {
	t.Helper()
	var got []byte
	buffer := make([]byte, 1<<16)
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < want && time.Now().Before(deadline) {
		n, err := syscall.Read(reader, buffer)
		switch {
		case n > 0:
			got = append(got, buffer[:n]...)
		case errors.Is(err, syscall.EAGAIN) || n == 0:
			time.Sleep(5 * time.Millisecond)
		default:
			t.Fatalf("read the FIFO: %v", err)
		}
	}
	return got
}

// A destination that cannot be opened at start is a sink nonetheless. Each
// line offered to it is a failed attempt, counted, and a reopen once the path
// can be opened recovers it: the next line is written there.
func TestIndependentSinkUnavailableAtStartCountsEachAttemptAndRecoversByReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.jsonl")
	// A directory where the file belongs: opening it for writing fails with
	// EISDIR, for root as for anybody.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := sink.NewFile(path)
	if destination == nil {
		t.Fatal("NewFile returned no sink for a path it cannot open, so an unavailable destination would stop " +
			"whoever opens it; Factory says it supplies one")
	}
	q := independentQueue(t, 1<<20, destination)
	for _, tag := range []string{"lost-1", "lost-2"} {
		_ = q.Enqueue(independentName, independentLine(tag, 80))
	}
	independentDrain(t, q)
	unavailable := q.Stats()
	if unavailable.Authorized != 2 {
		t.Fatalf("wiring, not the property: the queue authorised %d of the 2 lines offered, so nothing below "+
			"measured the unavailable destination: %+v", unavailable.Authorized, unavailable)
	}
	if unavailable.Failed != 2 || unavailable.Written != 0 {
		t.Errorf("two lines offered to a destination that cannot be opened: failed %d, written %d, want 2 and 0",
			unavailable.Failed, unavailable.Written)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Reopen(ctx); err != nil {
		t.Fatalf("a reopen after the path became openable was refused: %v", err)
	}
	recovered := independentLine("recovered", 80)
	if err := q.Enqueue(independentName, recovered); err != nil {
		t.Fatalf("a line offered after the recovering reopen was refused: %v", err)
	}
	independentDrain(t, q)

	if content := independentContent(t, path); !bytes.Equal(content, recovered) {
		t.Errorf("after the reopen the file holds %q, want exactly the line offered after it", content)
	}
	final := q.Stats()
	if final.Authorized != 3 || final.Written != 1 || final.Failed != 2 || final.Dropped != 0 {
		t.Errorf("authorised %d, written %d, failed %d, dropped %d; want 3, 1, 2, 0",
			final.Authorized, final.Written, final.Failed, final.Dropped)
	}
	independentConserved(t, final)
}

// The queue's byte bound counts queued and in-flight lines together. A line
// that does not fit is dropped at once and counted, and the lines that fit
// are written in order when the destination moves again.
func TestIndependentSinkAFullQueueDropsTheLineAndCountsIt(t *testing.T) {
	const size, limit = 1000, 3500
	held := newIndependentHeld(true)
	q := independentQueue(t, limit, held)

	var accepted []byte
	full := 0
	for i := range 5 {
		line := independentLine(fmt.Sprintf("line-%d", i), size)
		err := q.Enqueue(independentName, line)
		switch {
		case err == nil:
			accepted = append(accepted, line...)
		case errors.Is(err, sink.ErrQueueFull):
			full++
		default:
			t.Fatalf("line %d was refused with %v, which is neither accepted nor a full queue", i, err)
		}
		if i == 0 {
			independentWaitFor(t, held.entered, "the first line never reached the destination, so nothing was in flight")
		}
	}
	stats := q.Stats()
	if full != 2 {
		t.Errorf("five %d-byte lines behind a held write with a %d-byte bound: %d dropped as full, want 2 "+
			"(three fit, counting the one in flight)", size, limit, full)
	}
	if stats.Authorized != 5 || stats.Dropped != uint64(full) || stats.Pending != uint64(5-full) {
		t.Errorf("authorised %d, dropped %d, pending %d; want 5, %d, %d", stats.Authorized, stats.Dropped,
			stats.Pending, full, 5-full)
	}
	if stats.PendingBytes != int64(size*(5-full)) || stats.HighWaterBytes != int64(size*(5-full)) ||
		stats.LimitBytes != limit {
		t.Errorf("pending bytes %d, high water %d, limit %d; want %d, %d, %d", stats.PendingBytes,
			stats.HighWaterBytes, stats.LimitBytes, size*(5-full), size*(5-full), limit)
	}
	independentConserved(t, stats)

	held.release()
	independentDrain(t, q)
	if got := held.bytes(); !bytes.Equal(got, accepted) {
		t.Errorf("the destination holds %d bytes, want exactly the %d accepted lines in order", len(got), 5-full)
	}
	final := q.Stats()
	if final.Written != uint64(5-full) || final.Dropped != uint64(full) || final.PendingBytes != 0 {
		t.Errorf("after the destination moved: written %d, dropped %d, pending bytes %d; want %d, %d, 0",
			final.Written, final.Dropped, final.PendingBytes, 5-full, full)
	}
	independentConserved(t, final)
}

// A write the kernel cuts short is a failed attempt, never a written line,
// and it is not retried. The next record starts on a new line, so the damage
// is one malformed line and the next record is whole.
func TestIndependentSinkAPartialWriteIsFailedAndTheNextRecordStartsOnANewLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.jsonl")
	q := independentQueue(t, 1<<20, sink.NewFile(path))
	first, damaged, next := independentLine("first", 100), independentLine("damaged", 100), independentLine("next", 100)

	if err := q.Enqueue(independentName, first); err != nil {
		t.Fatalf("wiring, not the property: the first line was refused: %v", err)
	}
	independentDrain(t, q)
	if content := independentContent(t, path); !bytes.Equal(content, first) {
		t.Fatalf("wiring, not the property: the file holds %q before any limit, so the limit below would cut "+
			"something else", content)
	}

	const kept = 37
	restore := independentLimitFileSize(t, int64(len(first)+kept))
	if err := q.Enqueue(independentName, damaged); err != nil {
		t.Fatalf("wiring, not the property: the line to be cut was refused at enqueue: %v", err)
	}
	independentDrain(t, q)
	restore()
	if size := len(independentContent(t, path)); size != len(first)+kept {
		t.Fatalf("wiring, not the property: the file holds %d bytes after the limited write, want %d, so the "+
			"kernel did not cut the line where this case needs it", size, len(first)+kept)
	}
	cut := q.Stats()
	if cut.Failed != 1 || cut.Written != 1 {
		t.Errorf("a line the kernel cut after %d of %d bytes: failed %d, written %d; want 1 failed and only "+
			"the first line written", kept, len(damaged), cut.Failed, cut.Written)
	}

	if err := q.Enqueue(independentName, next); err != nil {
		t.Fatalf("the line after a failed write was refused: %v", err)
	}
	independentDrain(t, q)

	content := independentContent(t, path)
	want := slices.Concat(first, damaged[:kept], []byte("\n"), next)
	if !bytes.Equal(content, want) {
		t.Errorf("the file is\n%q\nwant the first line, the cut prefix alone on its line, then the next line whole:\n%q",
			content, want)
	}
	if bytes.Count(content, damaged) != 0 {
		t.Error("the cut line appears whole: it was retried")
	}
	final := q.Stats()
	if final.Authorized != 3 || final.Written != 2 || final.Failed != 1 {
		t.Errorf("authorised %d, written %d, failed %d; want 3, 2, 1", final.Authorized, final.Written, final.Failed)
	}
	independentConserved(t, final)
}

// Repeated write errors are each one failed attempt; none is retried, and a
// line offered once the destination accepts again is written.
func TestIndependentSinkRepeatedErrorsThenSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.jsonl")
	q := independentQueue(t, 1<<20, sink.NewFile(path))
	first, later := independentLine("first", 100), independentLine("later", 100)
	if err := q.Enqueue(independentName, first); err != nil {
		t.Fatalf("wiring, not the property: the first line was refused: %v", err)
	}
	independentDrain(t, q)

	restore := independentLimitFileSize(t, int64(len(first)))
	for _, tag := range []string{"refused-1", "refused-2", "refused-3"} {
		_ = q.Enqueue(independentName, independentLine(tag, 100))
	}
	independentDrain(t, q)
	restore()
	failing := q.Stats()
	if failing.Authorized != 4 {
		t.Fatalf("wiring, not the property: %d lines authorised, want 4, so the three below the limit were "+
			"never attempted: %+v", failing.Authorized, failing)
	}
	if failing.Failed != 3 || failing.Written != 1 {
		t.Errorf("three lines offered at the file size limit: failed %d, written %d; want 3 and 1",
			failing.Failed, failing.Written)
	}

	if err := q.Enqueue(independentName, later); err != nil {
		t.Fatalf("the line after repeated failures was refused: %v", err)
	}
	independentDrain(t, q)
	content := independentContent(t, path)
	var records [][]byte
	for _, line := range bytes.Split(content, []byte("\n")) {
		if len(line) > 0 {
			records = append(records, line)
		}
	}
	if len(records) != 2 || !bytes.Equal(records[0], first[:len(first)-1]) || !bytes.Equal(records[1], later[:len(later)-1]) {
		t.Errorf("the file holds %q, want the first line and the later one, and none of the three that failed", content)
	}
	if bytes.Contains(content, []byte("refused-")) {
		t.Error("a line that failed reached the file afterwards: it was retried")
	}
	final := q.Stats()
	if final.Written != 2 || final.Failed != 3 {
		t.Errorf("written %d, failed %d; want 2 and 3", final.Written, final.Failed)
	}
	independentConserved(t, final)
}

// A reopen that cannot open the new path is reported, never acknowledged. A
// later reopen that can open it is acknowledged, and only lines offered after
// it are in the new file.
func TestIndependentSinkAFailedReopenIsReportedAndALaterOneRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.jsonl")
	q := independentQueue(t, 1<<20, sink.NewFile(path))
	before, between, after := independentLine("before", 90), independentLine("between", 90), independentLine("after", 90)
	if err := q.Enqueue(independentName, before); err != nil {
		t.Fatalf("wiring, not the property: the first line was refused: %v", err)
	}
	independentDrain(t, q)
	if content := independentContent(t, path); !bytes.Equal(content, before) {
		t.Fatalf("wiring, not the property: the file holds %q before rotation", content)
	}

	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Reopen(ctx); err == nil {
		t.Error("a reopen whose path is a directory was acknowledged")
	}
	_ = q.Enqueue(independentName, between)
	independentDrain(t, q)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := q.Reopen(ctx); err != nil {
		t.Fatalf("a reopen whose path can be opened was refused: %v", err)
	}
	if err := q.Enqueue(independentName, after); err != nil {
		t.Fatalf("the line after the recovering reopen was refused: %v", err)
	}
	independentDrain(t, q)

	if content := independentContent(t, path); !bytes.Equal(content, after) {
		t.Errorf("the new file holds %q, want exactly the line offered after the acknowledged reopen", content)
	}
	if old := independentContent(t, rotated); !bytes.HasPrefix(old, before) || bytes.Contains(old, after) {
		t.Errorf("the rotated file holds %q, want the line from before rotation and not the one after the reopen", old)
	}
	final := q.Stats()
	if final.Authorized != 3 || final.Dropped != 0 {
		t.Errorf("authorised %d, dropped %d; want 3 and 0", final.Authorized, final.Dropped)
	}
	independentConserved(t, final)
}

// No reopen is acknowledged while a write is blocked on the old descriptor.
// A reopen bounded by a deadline is reported as failed when the deadline
// passes with the write still blocked; once the write completes, a reopen is
// acknowledged and the next line goes to the new file.
func TestIndependentSinkNoReopenIsAcknowledgedWhileAWriteIsBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approved.jsonl")
	reader, filled := independentFIFO(t, path)
	q := independentQueue(t, 1<<20, sink.NewFile(path))
	blocked := independentLine("blocked", 512)
	if err := q.Enqueue(independentName, blocked); err != nil {
		t.Fatalf("wiring, not the property: the line to be blocked was refused: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if held := q.Stats(); held.Pending != 1 || held.Written != 0 || held.Failed != 0 {
		t.Fatalf("wiring, not the property: 200ms after the line was offered to a full FIFO it is pending %d, "+
			"written %d, failed %d, want 1, 0, 0, so no write is blocked and the reopen below races nothing",
			held.Pending, held.Written, held.Failed)
	}

	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	const bound = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	began := time.Now()
	err := q.Reopen(ctx)
	waited := time.Since(began)
	cancel()
	if err == nil {
		t.Error("a reopen was acknowledged while a write was blocked on the old descriptor")
	}
	if waited > bound+2*time.Second {
		t.Errorf("a reopen bounded by %v returned after %v", bound, waited)
	}

	got := independentReadFIFO(t, reader, filled+len(blocked))
	if !bytes.Equal(got[min(filled, len(got)):], blocked) {
		t.Fatalf("wiring, not the property: the FIFO gave %d bytes after its filler, want the %d-byte blocked line",
			len(got)-min(filled, len(got)), len(blocked))
	}
	independentDrain(t, q)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Reopen(ctx); err != nil {
		t.Fatalf("a reopen after the blocked write completed was refused: %v", err)
	}
	marker := independentLine("after-reopen", 90)
	if err := q.Enqueue(independentName, marker); err != nil {
		t.Fatalf("the line after the reopen was refused: %v", err)
	}
	independentDrain(t, q)
	if content := independentContent(t, path); !bytes.Equal(content, marker) {
		t.Errorf("the new file holds %q, want exactly the line offered after the acknowledged reopen", content)
	}
	if n, _ := syscall.Read(reader, make([]byte, 4096)); n > 0 {
		t.Errorf("%d bytes reached the old descriptor after the acknowledged reopen", n)
	}
	independentConserved(t, q.Stats())
}

// Shutdown never waits without bound for a blocked destination. Every line
// still pending at its deadline is counted as discarded, a write that
// completes later does not change that count, and nothing discarded is
// written afterwards.
func TestIndependentSinkShutdownIsBoundedAndCountsPendingAsDiscarded(t *testing.T) {
	held := newIndependentHeld(true)
	q := independentQueue(t, 1<<20, held)
	lines := [][]byte{independentLine("in-flight", 80), independentLine("queued-1", 80),
		independentLine("queued-2", 80), independentLine("queued-3", 80)}
	for i, line := range lines {
		if err := q.Enqueue(independentName, line); err != nil {
			t.Fatalf("wiring, not the property: line %d was refused: %v", i, err)
		}
		if i == 0 {
			independentWaitFor(t, held.entered, "the first line never reached the destination")
		}
	}
	if pending := q.Stats(); pending.Pending != 4 {
		t.Fatalf("wiring, not the property: %d lines pending before shutdown, want 4: %+v", pending.Pending, pending)
	}

	const bound = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	began := time.Now()
	_ = q.Shutdown(ctx)
	waited := time.Since(began)
	cancel()
	if waited > bound+2*time.Second {
		t.Errorf("shutdown bounded by %v returned after %v with its destination blocked", bound, waited)
	}
	stopped := q.Stats()
	if stopped.Pending != 0 || stopped.Discarded != 4 || stopped.Dropped != 4 || stopped.Written != 0 {
		t.Errorf("after shutdown: pending %d, discarded %d, dropped %d, written %d; want 0, 4, 4, 0",
			stopped.Pending, stopped.Discarded, stopped.Dropped, stopped.Written)
	}
	independentConserved(t, stopped)
	if err := q.Enqueue(independentName, independentLine("late", 80)); !errors.Is(err, sink.ErrClosed) {
		t.Errorf("a line offered after shutdown returned %v, want sink.ErrClosed", err)
	}
	// The baseline for the late completion is taken after that refused offer,
	// which is itself counted.
	stopped = q.Stats()

	held.release()
	independentWaitFor(t, held.finished, "the held write never completed after release")
	time.Sleep(100 * time.Millisecond)
	counts := func(s sink.Stats) [6]uint64 {
		return [6]uint64{s.Authorized, s.Written, s.Failed, s.Dropped, s.Pending, s.Discarded}
	}
	if later := q.Stats(); counts(later) != counts(stopped) {
		t.Errorf("a write completing after shutdown changed the counts from %+v to %+v", stopped, later)
	}
	if got := held.bytes(); !bytes.Equal(got, lines[0]) {
		t.Errorf("the destination holds %q, want only the line that was in flight before shutdown", got)
	}
}
