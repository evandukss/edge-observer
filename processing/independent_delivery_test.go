package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

// These cases are written from the approved line envelope
// (contract/record/record.md), docs/approved-inspection.md and the published
// comments of processing.OpenWriter, sink and probe.DeliveryGate, not from the
// implementation. The lines are the worker's own, made from a captured
// workload (internal/workload), never authored here.

// deliveryExchanges is how many exchanges each generated connection carries.
// By the line contract each complete exchange is one line on the exchanges
// route and each retired connection one line on the connections route.
const (
	deliveryExchanges = 2
	deliveryLines     = deliveryExchanges + 1
)

type deliverySession struct {
	id     string
	dir    string
	writer *processing.Writer
	run    *processing.Run
	store  *intake.Store
	gate   *probe.DeliveryGate
}

// deliveryConnections is a captured workload of n plain connections, split
// into each connection's own entries, its connection record last.
func deliveryConnections(t *testing.T, n int, seed uint64) [][]workload.Entry {
	t.Helper()
	w, err := workload.Generate(workload.Shape{Connections: n, Exchanges: deliveryExchanges, Seed: seed})
	if err != nil {
		t.Fatalf("wiring, not the property: generate the workload: %v", err)
	}
	var connections [][]workload.Entry
	var current []workload.Entry
	for _, entry := range w.Entries {
		current = append(current, entry)
		if entry.Connection != nil {
			connections = append(connections, current)
			current = nil
		}
	}
	if len(connections) != n || len(current) != 0 {
		t.Fatalf("wiring, not the property: the workload split into %d connections with %d entries left over, "+
			"want %d and 0", len(connections), len(current), n)
	}
	return connections
}

func deliveryPlan(t *testing.T) *config.ProcessingPlan {
	t.Helper()
	compiled, findings := config.Compile([]byte(`{"version": "observer.config/1", "output": "/var/lib/observer", `+
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}]}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the configuration was refused: %+v", findings)
	}
	return compiled.Plan
}

// deliveryOpen opens a writer on dir with its default file sink and starts one
// worker writing through it as session id. before, where set, is the gate's
// BeforeAuthorize hook.
func deliveryOpen(t *testing.T, dir, id string, before func()) *deliverySession {
	t.Helper()
	s := &deliverySession{id: id, dir: dir}
	var err error
	s.writer, err = processing.OpenWriter(processing.WriterOptions{Directory: dir, QueueBytes: 1 << 20})
	if err != nil || s.writer == nil {
		t.Fatalf("OpenWriter on %s refused: %v", dir, err)
	}
	t.Cleanup(func() { s.shutdown(t) })
	s.store, err = intake.New(1 << 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.store.Close() })
	s.gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40,
		IntakeExhausted: s.store.Exhausted(), BeforeAuthorize: before})
	if err != nil {
		t.Fatal(err)
	}
	s.run, err = processing.Start(processing.Options{Plan: deliveryPlan(t), PolicyRevision: "independent-delivery",
		Session: id, Intake: s.store, Gate: s.gate, Output: s.writer, Derived: s.writer, Workers: 1})
	if err != nil || s.run == nil {
		t.Fatalf("wiring, not the property: the worker did not start: %v", err)
	}
	t.Cleanup(func() { _ = s.run.Close() })
	return s
}

func (s *deliverySession) feed(t *testing.T, entries []workload.Entry) {
	t.Helper()
	chunk := &workload.Workload{Entries: entries}
	if n, err := chunk.Write(s.store); err != nil || n != len(entries) {
		t.Fatalf("wiring, not the property: the intake took %d of %d entries: %v", n, len(entries), err)
	}
	s.run.Route()
}

// settle waits until the writer has authorised authorized lines and holds
// none pending, and requires that no more arrive.
func (s *deliverySession) settle(t *testing.T, authorized uint64) sink.Stats {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		stats := s.writer.DeliveryStats()
		if stats.Authorized >= authorized && stats.Pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("within 10s the writer authorised %d lines with %d pending, want %d settled: %+v",
				stats.Authorized, stats.Pending, authorized, stats)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	stats := s.writer.DeliveryStats()
	if stats.Authorized != authorized {
		t.Fatalf("wiring, not the property: the writer authorised %d lines, want exactly %d (%d per connection)",
			stats.Authorized, authorized, deliveryLines)
	}
	return stats
}

func (s *deliverySession) finish(t *testing.T) processing.Outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	outcome, err := s.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil && !errors.Is(err, processing.ErrFinished) {
		t.Errorf("the run finished with %v", err)
	}
	return outcome
}

func (s *deliverySession) shutdown(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.writer.Shutdown(ctx)
}

func (s *deliverySession) failed() bool {
	select {
	case <-s.run.Failed():
		return true
	default:
		return false
	}
}

func deliveryConserved(t *testing.T, s sink.Stats) {
	t.Helper()
	if s.Authorized != s.Written+s.Failed+s.Dropped+s.Pending {
		t.Errorf("authorised %d is not written %d + failed %d + dropped %d + pending %d",
			s.Authorized, s.Written, s.Failed, s.Dropped, s.Pending)
	}
}

// deliveryRecords is each LF-terminated segment of a file, the final empty
// segment after the last LF dropped.
func deliveryRecords(t *testing.T, path string) [][]byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(content) == 0 {
		return nil
	}
	records := bytes.Split(content, []byte("\n"))
	if len(records[len(records)-1]) != 0 {
		t.Errorf("%s does not end with LF: its last %d bytes are an unterminated record", path, len(records[len(records)-1]))
	}
	return records[:len(records)-1]
}

// deliveryMembers decodes one record's top-level members, failing the case
// where it is not a JSON object.
func deliveryMembers(t *testing.T, line []byte) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(line, &members); err != nil {
		t.Fatalf("a record that should be whole does not decode (%v): %q", err, line)
	}
	return members
}

func deliveryString(t *testing.T, members map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, present := members[key]
	if !present {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("member %q is not a string: %s", key, raw)
	}
	return value
}

// deliveryLimitFileSize sets this process's RLIMIT_FSIZE so a write past size
// is cut by the kernel, with SIGXFSZ ignored meanwhile. No test of this package
// is parallel, so nothing else writes a file while it is set.
func deliveryLimitFileSize(t *testing.T, size int64) func() {
	t.Helper()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("wiring, not the property: read the file size limit: %v", err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(size), Max: old.Max}); err != nil {
		signal.Reset(syscall.SIGXFSZ)
		t.Fatalf("wiring, not the property: set the file size limit: %v", err)
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

// A sink failure costs lines, never the session. A line the kernel cuts short
// is one failed attempt, the lines after it fail while the destination
// refuses, and once it accepts again later lines are written. The next record
// starts on a new line, and inspection reports the damaged record as
// malformed instead of reading it as an exchange.
func TestIndependentDeliveryAPartialWriteCostsLinesAndInspectionReportsItMalformed(t *testing.T) {
	connections := deliveryConnections(t, 3, 51)
	dir := t.TempDir()
	s := deliveryOpen(t, dir, "partial-session", nil)
	approved := filepath.Join(dir, processing.ArtifactName)

	s.feed(t, connections[0])
	s.settle(t, deliveryLines)
	whole := deliveryRecords(t, approved)
	if len(whole) != deliveryLines {
		t.Fatalf("wiring, not the property: %s holds %d records after the first connection, want %d",
			approved, len(whole), deliveryLines)
	}
	info, err := os.Stat(approved)
	if err != nil {
		t.Fatal(err)
	}

	const kept = 40
	restore := deliveryLimitFileSize(t, info.Size()+kept)
	s.feed(t, connections[1])
	cut := s.settle(t, 2*deliveryLines)
	restore()
	if after, err := os.Stat(approved); err != nil || after.Size() != info.Size()+kept {
		t.Fatalf("wiring, not the property: the file did not end %d bytes past the first connection's lines "+
			"(%v, %v), so the kernel did not cut a line", kept, after, err)
	}
	if cut.Failed != deliveryLines || cut.Written != deliveryLines {
		t.Errorf("the second connection's %d lines met a file the kernel cut after %d bytes: failed %d, written %d; "+
			"want %d failed and only the first connection's %d written", deliveryLines, kept, cut.Failed,
			cut.Written, deliveryLines, deliveryLines)
	}
	if s.failed() {
		t.Fatal("the run stopped on a sink failure")
	}

	s.feed(t, connections[2])
	final := s.settle(t, 3*deliveryLines)
	if final.Written != 2*deliveryLines || final.Failed != deliveryLines || final.Dropped != 0 {
		t.Errorf("after the destination accepted again: written %d, failed %d, dropped %d; want %d, %d, 0",
			final.Written, final.Failed, final.Dropped, 2*deliveryLines, deliveryLines)
	}
	deliveryConserved(t, final)

	records := deliveryRecords(t, approved)
	if len(records) != 2*deliveryLines+1 {
		t.Fatalf("%s holds %d records, want the first connection's %d, one damaged record and the third "+
			"connection's %d", approved, len(records), deliveryLines, deliveryLines)
	}
	if damaged := records[deliveryLines]; len(damaged) != kept || json.Valid(damaged) {
		t.Errorf("record %d is %d bytes (valid JSON %v), want the %d-byte cut prefix alone on its line",
			deliveryLines+1, len(damaged), json.Valid(damaged), kept)
	}
	for i, record := range slices.Concat(records[:deliveryLines], records[deliveryLines+1:]) {
		if got := deliveryString(t, deliveryMembers(t, record), "session"); got != s.id {
			t.Errorf("whole record %d carries session %q, want %q", i+1, got, s.id)
		}
	}

	var visited []processing.Artifact
	err = processing.ReadArtifactFiles(os.DirFS(dir), []string{processing.ArtifactName}, "", func(a processing.Artifact) error {
		visited = append(visited, a)
		return nil
	})
	if err == nil {
		t.Error("inspection read a file holding a damaged record without failing")
	}
	if errors.Is(err, processing.ErrNotImplemented) {
		t.Fatalf("wiring, not the property: the reader is not installed: %v", err)
	}
	if len(visited) != deliveryLines {
		t.Errorf("inspection visited %d records before failing, want the %d whole records before the damaged one",
			len(visited), deliveryLines)
	}
	if s.failed() {
		t.Error("the run stopped on a sink failure")
	}
}

// Invalidation that lands after a line was ready and before its release is
// decided refuses it: nothing is enqueued after invalidation.
func TestIndependentDeliveryInvalidationBeforeEnqueueEnqueuesNothing(t *testing.T) {
	connections := deliveryConnections(t, 1, 52)
	entered, release := make(chan struct{}, 64), make(chan struct{})
	var calls sync.Mutex
	count := 0
	before := func() {
		calls.Lock()
		count++
		calls.Unlock()
		entered <- struct{}{}
		<-release
	}
	dir := t.TempDir()
	s := deliveryOpen(t, dir, "invalidated-first", before)
	s.feed(t, connections[0])
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("wiring, not the property: no release reached authorization within 10s")
	}

	decision := s.gate.Admit(probe.DeliveryKind(255), true)
	if decision.State.Reason == "" {
		t.Fatalf("wiring, not the property: an event of an unknown kind did not invalidate the gate: %+v", decision)
	}
	close(release)
	outcome := s.finish(t)
	s.shutdown(t)
	calls.Lock()
	reached := count
	calls.Unlock()
	if reached == 0 {
		t.Fatal("wiring, not the property: no release reached authorization")
	}

	stats := s.writer.DeliveryStats()
	if stats.Authorized != 0 || stats.Written != 0 {
		t.Errorf("a release decided after invalidation enqueued lines: authorised %d, written %d; want 0 and 0",
			stats.Authorized, stats.Written)
	}
	if outcome.Authorized != 0 {
		t.Errorf("the worker counts %d lines authorised after invalidation, want 0", outcome.Authorized)
	}
	if content, err := os.ReadFile(filepath.Join(dir, processing.ArtifactName)); err == nil && len(content) != 0 {
		t.Errorf("%d bytes were written after invalidation", len(content))
	}
	deliveryConserved(t, stats)
}

// A line enqueued before a later invalidation stays accounted (it may still
// be written), and no release decided after the invalidation is enqueued.
func TestIndependentDeliveryALineEnqueuedBeforeInvalidationStaysAccountedAndNothingFollows(t *testing.T) {
	connections := deliveryConnections(t, 2, 53)
	entered, release := make(chan struct{}, 64), make(chan struct{})
	var calls sync.Mutex
	count := 0
	before := func() {
		calls.Lock()
		count++
		n := count
		calls.Unlock()
		if n < 2 {
			return
		}
		entered <- struct{}{}
		<-release
	}
	dir := t.TempDir()
	s := deliveryOpen(t, dir, "enqueued-first", before)
	s.feed(t, connections[0])
	s.feed(t, connections[1])
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("wiring, not the property: a second authorization never came within 10s")
	}
	enqueued := s.writer.DeliveryStats()
	if enqueued.Authorized == 0 {
		t.Fatalf("wiring, not the property: the first authorization enqueued nothing, so no line precedes the "+
			"invalidation: %+v", enqueued)
	}

	if decision := s.gate.Admit(probe.DeliveryKind(255), true); decision.State.Reason == "" {
		t.Fatalf("wiring, not the property: an event of an unknown kind did not invalidate the gate: %+v", decision)
	}
	close(release)
	s.finish(t)
	s.shutdown(t)

	final := s.writer.DeliveryStats()
	if final.Authorized != enqueued.Authorized {
		t.Errorf("%d lines were enqueued before the invalidation and %d by the end: a release decided after "+
			"invalidation was enqueued", enqueued.Authorized, final.Authorized)
	}
	deliveryConserved(t, final)
	if records := len(deliveryRecordsIfAny(t, filepath.Join(dir, processing.ArtifactName))); uint64(records) > enqueued.Authorized {
		t.Errorf("the file holds %d records, more than the %d enqueued before invalidation", records, enqueued.Authorized)
	}
}

func deliveryRecordsIfAny(t *testing.T, path string) [][]byte {
	t.Helper()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return deliveryRecords(t, path)
}

// deliveryThreeSessions writes three sessions, one after another, at the same
// stable path: the first two into one file, which is then rotated by rename,
// the third into the file that takes its place. It returns the directory and
// how many lines each session's writer counted written.
func deliveryThreeSessions(t *testing.T) (string, map[string]uint64) {
	t.Helper()
	dir := t.TempDir()
	written := map[string]uint64{}
	for i, id := range []string{"session-one", "session-two", "session-three"} {
		if id == "session-three" {
			if err := os.Rename(filepath.Join(dir, processing.ArtifactName), filepath.Join(dir, processing.ArtifactName+".1")); err != nil {
				t.Fatal(err)
			}
		}
		connections := deliveryConnections(t, i+1, uint64(60+i))
		s := deliveryOpen(t, dir, id, nil)
		for _, one := range connections {
			s.feed(t, one)
		}
		stats := s.settle(t, uint64(len(connections)*deliveryLines))
		s.finish(t)
		s.shutdown(t)
		if stats.Written == 0 {
			t.Fatalf("wiring, not the property: session %s wrote nothing", id)
		}
		written[id] = stats.Written
	}
	return dir, written
}

// Output lives at stable paths kept across sessions: a later session appends
// to the file an earlier one wrote, and every line carries the session that
// authorised it.
func TestIndependentDeliveryStablePathsKeepEarlierSessionsAndEveryLineNamesItsSession(t *testing.T) {
	dir, written := deliveryThreeSessions(t)
	rotated := deliveryRecords(t, filepath.Join(dir, processing.ArtifactName+".1"))
	current := deliveryRecords(t, filepath.Join(dir, processing.ArtifactName))

	want := map[string][]string{
		processing.ArtifactName + ".1": slices.Concat(repeated("session-one", written["session-one"]),
			repeated("session-two", written["session-two"])),
		processing.ArtifactName: repeated("session-three", written["session-three"]),
	}
	for name, records := range map[string][][]byte{processing.ArtifactName + ".1": rotated, processing.ArtifactName: current} {
		var got []string
		for _, record := range records {
			got = append(got, deliveryString(t, deliveryMembers(t, record), "session"))
		}
		if !slices.Equal(got, want[name]) {
			t.Errorf("%s holds records of sessions %v, want %v: each session's lines appended after the "+
				"earlier ones, every line naming its session", name, got, want[name])
		}
	}
}

func repeated(value string, n uint64) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = value
	}
	return out
}

// The reader takes several files and selects one session's lines, wherever
// they are, and never another session's.
func TestIndependentDeliveryTheReaderSelectsOneSessionAcrossSeveralFiles(t *testing.T) {
	dir, written := deliveryThreeSessions(t)
	names := []string{processing.ArtifactName + ".1", processing.ArtifactName}
	for _, one := range []struct {
		session string
		want    uint64
	}{
		{"session-two", written["session-two"]},
		{"session-three", written["session-three"]},
		{"", written["session-one"] + written["session-two"] + written["session-three"]},
	} {
		var sessions []string
		err := processing.ReadArtifactFiles(os.DirFS(dir), names, one.session, func(a processing.Artifact) error {
			sessions = append(sessions, a.Session)
			return nil
		})
		if err != nil {
			t.Errorf("reading %v for session %q failed: %v", names, one.session, err)
			continue
		}
		if uint64(len(sessions)) != one.want {
			t.Errorf("reading %v for session %q visited %d records, want %d", names, one.session, len(sessions), one.want)
		}
		for _, got := range sessions {
			if one.session != "" && got != one.session {
				t.Errorf("reading for session %q visited a record of session %q", one.session, got)
			}
			if got == "" {
				t.Error("a visited record carries no session")
			}
		}
	}
}

// After the file is renamed and the writer reopened, the next records go to a
// new file at the stable path, and nothing more goes to the renamed one.
func TestIndependentDeliveryReopenAfterRenameWritesToTheNewFile(t *testing.T) {
	connections := deliveryConnections(t, 2, 54)
	dir := t.TempDir()
	s := deliveryOpen(t, dir, "reopened", nil)
	approved := filepath.Join(dir, processing.ArtifactName)
	s.feed(t, connections[0])
	s.settle(t, deliveryLines)
	if got := len(deliveryRecords(t, approved)); got != deliveryLines {
		t.Fatalf("wiring, not the property: %d records before rotation, want %d", got, deliveryLines)
	}
	rotated := approved + ".1"
	if err := os.Rename(approved, rotated); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.writer.Reopen(ctx); err != nil {
		t.Fatalf("the writer refused a reopen after rotation: %v", err)
	}
	s.feed(t, connections[1])
	final := s.settle(t, 2*deliveryLines)

	old, fresh := deliveryRecords(t, rotated), deliveryRecords(t, approved)
	if len(old) != deliveryLines || len(fresh) != deliveryLines {
		t.Errorf("the renamed file holds %d records and the new one %d, want %d each", len(old), len(fresh), deliveryLines)
	}
	connection := func(record []byte) string {
		var a processing.Artifact
		if err := json.Unmarshal(record, &a); err != nil {
			t.Fatalf("a record does not decode: %v", err)
		}
		return a.Connection.ID
	}
	for _, record := range old {
		for _, other := range fresh {
			if connection(record) == connection(other) {
				t.Errorf("connection %s has records in both files", connection(record))
			}
		}
	}
	if final.Written != 2*deliveryLines || final.Failed != 0 {
		t.Errorf("written %d, failed %d; want %d and 0", final.Written, final.Failed, 2*deliveryLines)
	}
}

// An approved file that cannot be opened at start does not stop the writer
// from opening or the session from running. Its lines are failed attempts,
// and a reopen once the path can be opened recovers it.
func TestIndependentDeliveryAnUnavailableFileAtStartCostsLinesAndRecoversByReopen(t *testing.T) {
	connections := deliveryConnections(t, 2, 55)
	dir := t.TempDir()
	approved := filepath.Join(dir, processing.ArtifactName)
	if err := os.Mkdir(approved, 0o700); err != nil {
		t.Fatal(err)
	}
	s := deliveryOpen(t, dir, "unavailable", nil)
	s.feed(t, connections[0])
	unavailable := s.settle(t, deliveryLines)
	if unavailable.Failed != deliveryLines || unavailable.Written != 0 {
		t.Errorf("%d lines offered to a path that is a directory: failed %d, written %d; want %d and 0",
			deliveryLines, unavailable.Failed, unavailable.Written, deliveryLines)
	}
	if s.failed() {
		t.Fatal("the run stopped because its approved file could not be opened")
	}

	if err := os.Remove(approved); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.writer.Reopen(ctx); err != nil {
		t.Fatalf("a reopen once the path can be opened was refused: %v", err)
	}
	s.feed(t, connections[1])
	final := s.settle(t, 2*deliveryLines)
	if final.Written != deliveryLines || final.Failed != deliveryLines {
		t.Errorf("written %d, failed %d; want %d each", final.Written, final.Failed, deliveryLines)
	}
	if got := len(deliveryRecords(t, approved)); got != deliveryLines {
		t.Errorf("the recovered file holds %d records, want the second connection's %d", got, deliveryLines)
	}
	deliveryConserved(t, final)
}
