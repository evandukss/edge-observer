package processing_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

const it1Secret = "IT1_PRIVATE_872ab9"

type it1Sink struct {
	write func(context.Context, []byte) (int, error)
}

func (s it1Sink) Write(ctx context.Context, p []byte) (int, error) { return s.write(ctx, p) }
func (it1Sink) Reopen(context.Context) error                       { return nil }
func (it1Sink) Close(context.Context) error                        { return nil }

type it1FileSink struct {
	sink.Sink
	reached chan []byte
}

func (s it1FileSink) Write(ctx context.Context, p []byte) (int, error) {
	n, err := s.Sink.Write(ctx, p)
	if err == nil {
		s.reached <- bytes.Clone(p)
	}
	return n, err
}

type it1Release struct {
	writer *processing.Writer
	lines  [][]byte
}

func (r *it1Release) WriteApproved(ctx context.Context, a processing.Approved) error {
	r.lines = append(r.lines, a.Bytes())
	return r.writer.WriteApproved(ctx, a)
}

type it1Fixture struct {
	writer  *processing.Writer
	worker  *processing.Worker
	store   *intake.Store
	release *it1Release
	dir     string
	taken   int
}

func it1New(t *testing.T, mirror sink.Sink, bound int64, factory sink.Factory) *it1Fixture {
	t.Helper()
	f := &it1Fixture{dir: t.TempDir()}
	var err error
	f.writer, err = processing.OpenWriter(processing.WriterOptions{Directory: f.dir, QueueBytes: 1 << 20, Stdout: mirror, StdoutQueueBytes: bound, OpenSink: factory})
	if err != nil {
		t.Fatalf("wiring: writer: %v", err)
	}
	t.Cleanup(func() { _ = f.writer.Close() })
	f.store, err = intake.New(16 << 20)
	if err != nil {
		t.Fatalf("wiring: intake: %v", err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatalf("wiring: gate: %v", err)
	}
	f.release = &it1Release{writer: f.writer}
	f.worker, err = processing.New(processing.Options{Session: "it1", PolicyRevision: "it1-policy", Plan: rulesPlan(t, `"write_content":true,"remove":{"headers":["authorization"]}`), Intake: f.store, Gate: gate, Output: f.release,
		Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken++ }})
	if err != nil {
		t.Fatalf("wiring: worker: %v", err)
	}
	t.Cleanup(func() { _ = f.worker.Close() })
	return f
}

func it1Input(t *testing.T, pairs int) conversation {
	t.Helper()
	var calls []call
	for i := range pairs {
		calls = append(calls, wrote(fmt.Sprintf("GET /it1/%d HTTP/1.1\r\nHost: fixture\r\nX-Public: visible-%d\r\nAuthorization: %s\r\n\r\n", i, i, it1Secret)),
			read("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}
	// The existing capture constructor validates prefix evidence against the
	// real capture retirement. Tests deliver that retirement only when stated.
	return converse(t, 91, calls...)
}

func (f *it1Fixture) feed(t *testing.T, fragments []fragment.Record) {
	t.Helper()
	before := f.taken
	for _, one := range fragments {
		if err := f.store.Write(one); err != nil {
			t.Fatalf("wiring: intake write: %v", err)
		}
	}
	if _, err := f.worker.Drain(context.Background()); err != nil {
		t.Fatalf("wiring: worker drain: %v", err)
	}
	if f.taken-before != len(fragments) || len(fragments) == 0 {
		t.Fatalf("wiring: worker took %d of %d fragments", f.taken-before, len(fragments))
	}
}

func it1Await(t *testing.T, ch <-chan []byte, why string) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(3 * time.Second):
		t.Fatalf("%s", why)
		return nil
	}
}

func it1Pipe(t *testing.T) (sink.Sink, <-chan []byte, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("wiring: pipe: %v", err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	lines := make(chan []byte, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(lines)
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			lines <- append(bytes.Clone(scan.Bytes()), '\n')
		}
	}()
	return it1Sink{write: func(_ context.Context, p []byte) (int, error) { return w.Write(p) }}, lines, func() { _ = w.Close(); <-done }
}

func it1Read(t *testing.T, raw []byte, count int) []processing.Artifact {
	t.Helper()
	var out []processing.Artifact
	err := processing.ReadArtifactFiles(fstest.MapFS{"pipe": {Data: raw}}, []string{"pipe"}, "it1", func(a processing.Artifact) error { out = append(out, a); return nil })
	if err != nil || len(out) != count {
		t.Fatalf("property: approved reader got %d of %d lines: %v", len(out), count, err)
	}
	return out
}

func TestIndependentStdoutOpenConnectionAndFreePipe(t *testing.T) {
	mirror, pipe, finishPipe := it1Pipe(t)
	f := it1New(t, mirror, 1<<20, nil)
	c := it1Input(t, 3)
	var got []byte
	for i := range 3 {
		f.feed(t, c.fragments[2*i:2*i+2])
		if len(f.release.lines) != i+1 {
			t.Fatalf("property: open connection released %d exchanges, want %d", len(f.release.lines), i+1)
		}
		line := it1Await(t, pipe, "property: released exchange did not reach stdout before transport close")
		a := it1Read(t, line, 1)[0]
		if a.Record != processing.ArtifactExchange || !a.Connection.Provisional || a.Index == nil || *a.Index != i {
			t.Fatalf("property: early exchange identity: %+v", a)
		}
		if !bytes.Contains(line, []byte(fmt.Sprintf("visible-%d", i))) || bytes.Contains(line, []byte(it1Secret)) {
			t.Fatalf("property: sanitized/public field fidelity: %s", line)
		}
		got = append(got, line...)
	}
	if err := f.store.Connection(c.retirement); err != nil {
		t.Fatalf("wiring: retirement: %v", err)
	}
	if _, err := f.worker.Drain(context.Background()); err != nil {
		t.Fatalf("wiring: retirement drain: %v", err)
	}
	if len(f.release.lines) != 4 {
		t.Fatalf("property: released population %d, want 4", len(f.release.lines))
	}
	got = append(got, it1Await(t, pipe, "property: retirement not mirrored")...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.writer.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	finishPipe()
	for extra := range pipe {
		t.Fatalf("property: duplicate/unapproved stdout line: %s", extra)
	}
	file, err := os.ReadFile(filepath.Join(f.dir, processing.ArtifactName))
	if err != nil {
		t.Fatalf("wiring: file read: %v", err)
	}
	if !bytes.Equal(got, file) || !bytes.Equal(got, bytes.Join(f.release.lines, nil)) {
		t.Fatal("property: release, file and stdout bytes/order differ")
	}
	artifacts := it1Read(t, got, 4)
	if artifacts[3].Record != processing.ArtifactConnection {
		t.Fatal("property: final connection line absent")
	}
	s := f.writer.StdoutDeliveryStats()
	if s == nil || s.Authorized != 4 || s.Written != 4 || s.Failed+s.Dropped+s.Pending != 0 {
		t.Fatalf("property: free stdout accounting %+v", s)
	}
	if f.writer.DeliveryStats().Written != 4 {
		t.Fatal("property: file accounting changed")
	}
}

func TestIndependentStdoutFileFailureDoesNotSuppressMirror(t *testing.T) {
	mirror, pipe, finishPipe := it1Pipe(t)
	fileReached := make(chan []byte, 16)
	f := it1New(t, mirror, 1<<20, func(string) sink.Sink {
		return it1Sink{write: func(_ context.Context, p []byte) (int, error) {
			fileReached <- bytes.Clone(p)
			return 0, errors.New("it1 file failure")
		}}
	})
	f.feed(t, it1Input(t, 2).fragments)
	if len(f.release.lines) != 2 {
		t.Fatalf("wiring: two released exchanges required, got %d", len(f.release.lines))
	}
	var got []byte
	for range 2 {
		it1Await(t, fileReached, "wiring: failing file destination not reached")
		got = append(got, it1Await(t, pipe, "property: file failure suppressed mirror")...)
	}
	if err := f.writer.Close(); err != nil {
		t.Fatal(err)
	}
	finishPipe()
	for extra := range pipe {
		got = append(got, extra...)
	}
	if !bytes.Equal(got, bytes.Join(f.release.lines, nil)) {
		t.Fatal("property: mirror population followed file success instead of release")
	}
	file, out := f.writer.DeliveryStats(), f.writer.StdoutDeliveryStats()
	if file.Failed != 2 || file.Written != 0 || out == nil || out.Written != 2 || out.Failed+out.Dropped != 0 {
		t.Fatalf("property: separate outcomes file=%+v stdout=%+v", file, out)
	}
}

func TestIndependentStdoutHeldWriteHasExactLossAndFileProgress(t *testing.T) {
	held, release, returned := make(chan []byte, 32), make(chan struct{}), make(chan struct{})
	var once, returnedOnce sync.Once
	unhold := func() { once.Do(func() { close(release) }) }
	defer unhold()
	mirror := it1Sink{write: func(_ context.Context, p []byte) (int, error) {
		held <- bytes.Clone(p)
		<-release
		returnedOnce.Do(func() { close(returned) })
		return len(p), nil
	}}
	fileReached := make(chan []byte, 32)
	f := it1New(t, mirror, 8192, func(path string) sink.Sink { return it1FileSink{Sink: sink.NewFile(path), reached: fileReached} })
	c := it1Input(t, 16)
	f.feed(t, c.fragments[:2])
	it1Await(t, held, "wiring: stdout Write hold never reached")
	f.feed(t, c.fragments[2:])
	if len(f.release.lines) != 16 {
		t.Fatalf("wiring: release population %d, want16", len(f.release.lines))
	}
	for range 16 {
		it1Await(t, fileReached, "property: held stdout prevented file progress")
	}
	var admitted uint64
	var charge int64
	for _, line := range f.release.lines {
		if charge+int64(len(line)) <= 8192 {
			admitted++
			charge += int64(len(line))
		}
	}
	if admitted == 0 || admitted == 16 {
		t.Fatalf("wiring: queue fixture did not cover admitted and dropped lines: %d", admitted)
	}
	before := f.writer.StdoutDeliveryStats()
	if before == nil || before.Authorized != 16 || before.Pending != admitted || before.Dropped != 16-admitted || before.PendingBytes != charge {
		t.Fatalf("property: exact held queue account: %+v; admitted=%d charge=%d", before, admitted, charge)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := f.writer.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("property: writer stop not bounded: %v, %s", err, time.Since(start))
	}
	final := *f.writer.StdoutDeliveryStats()
	if final.Authorized != 16 || final.Written != 0 || final.Failed != 0 || final.Pending != 0 || final.Dropped != 16 || final.Discarded != admitted {
		t.Fatalf("property: exact terminal stdout loss: %+v", final)
	}
	if s := f.writer.DeliveryStats(); s.Written != 16 || s.Failed+s.Dropped+s.Pending != 0 {
		t.Fatalf("property: file delivery harmed: %+v", s)
	}
	unhold()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("wiring: held destination did not return")
	}
	if !reflect.DeepEqual(final, *f.writer.StdoutDeliveryStats()) {
		t.Fatal("property: late write changed frozen stdout accounting")
	}
}

// The earlier held-writer and command cases observe a destination's return
// notification. This case additionally waits for the queue's bookkeeping:
// Wait settles the isolated runners, and Retained verifies inflight was cleared
// under the queue mutex before any frozen-account assertion is made.
func TestIndependentStdoutFrozenAfterLateBookkeeping(t *testing.T) {
	for _, outcome := range []string{"success", "failure"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var once sync.Once
				unhold := func() { once.Do(func() { close(release) }) }
				defer func() {
					unhold()
					synctest.Wait()
				}()
				var entered, returned int
				var heldLine []byte
				mirror := it1Sink{write: func(_ context.Context, line []byte) (int, error) {
					entered++
					heldLine = bytes.Clone(line)
					<-release
					returned++
					if outcome == "failure" {
						return 0, errors.New("it1 late write failure")
					}
					return len(line), nil
				}}
				f := it1New(t, mirror, 1<<20, nil)
				f.feed(t, it1Input(t, 2).fragments)
				synctest.Wait()
				if len(f.release.lines) != 2 || entered != 1 || returned != 0 || !bytes.Equal(heldLine, f.release.lines[0]) {
					t.Fatal("wiring: two approved releases and one actual held stdout Write not reached")
				}
				fileBefore := f.writer.DeliveryStats()
				if fileBefore.Authorized != 2 || fileBefore.Written != 2 || fileBefore.Pending+fileBefore.Failed+fileBefore.Dropped != 0 {
					t.Fatalf("wiring: independent file control did not finish both writes: %+v", fileBefore)
				}
				file, err := os.ReadFile(filepath.Join(f.dir, processing.ArtifactName))
				if err != nil || !bytes.Equal(file, bytes.Join(f.release.lines, nil)) {
					t.Fatalf("wiring: file bytes do not witness both approved releases: %v", err)
				}
				pending := f.writer.StdoutDeliveryStats()
				if pending == nil || pending.Authorized != 2 || pending.Pending != 2 || pending.Written+pending.Failed+pending.Dropped != 0 {
					t.Fatalf("wiring: stdout held and queued population absent: %+v", pending)
				}
				f.writer.Freeze()
				before := *f.writer.StdoutDeliveryStats()
				if before.Authorized != 2 || before.Pending != 0 || before.Written != 0 || before.Failed != 0 || before.Dropped != 2 || before.Discarded != 2 || before.Bytes != 0 || before.PendingBytes != int64(len(heldLine)) {
					t.Fatalf("property: freeze did not decide both pending stdout records: %+v", before)
				}
				if lines := it1RetainedLines(t, f.writer); lines != 1 {
					t.Fatalf("wiring: frozen in-flight retention witness=%d, want1", lines)
				}
				unhold()
				synctest.Wait()
				// A return notification alone precedes Queue.run's accounting. A
				// settled runner plus zero retained lines witnesses its completion.
				if returned == 0 || it1RetainedLines(t, f.writer) != 0 {
					t.Fatal("wiring: late queue bookkeeping did not finish")
				}
				t.Logf("GUARD late-%s bookkeeping complete: retained=0, returned=%d", outcome, returned)
				if after := *f.writer.StdoutDeliveryStats(); !reflect.DeepEqual(before, after) {
					t.Fatalf("property: late %s bookkeeping changed frozen stdout: before=%+v after=%+v", outcome, before, after)
				}
				if entered != 1 || returned != 1 {
					t.Fatalf("property: discarded queued stdout reached destination: entered=%d returned=%d", entered, returned)
				}
				if after := f.writer.DeliveryStats(); !reflect.DeepEqual(fileBefore, after) {
					t.Fatalf("property: late stdout bookkeeping changed file account: before=%+v after=%+v", fileBefore, after)
				}
				afterFile, err := os.ReadFile(filepath.Join(f.dir, processing.ArtifactName))
				if err != nil || !bytes.Equal(file, afterFile) {
					t.Fatalf("property: late stdout bookkeeping changed file bytes: %v", err)
				}
			})
		})
	}
}

func it1RetainedLines(t *testing.T, writer *processing.Writer) int {
	t.Helper()
	stores, err := writer.Retained()
	if err != nil {
		t.Fatalf("wiring: retained queue read: %v", err)
	}
	for _, store := range stores {
		if store.Store == "sink.lines" {
			return store.Held
		}
	}
	t.Fatal("wiring: sink.lines retention witness missing")
	return -1
}

func TestIndependentStdoutAbsentWithoutMirror(t *testing.T) {
	f := it1New(t, nil, 0, nil)
	f.feed(t, it1Input(t, 1).fragments)
	if len(f.release.lines) != 1 {
		t.Fatal("wiring: no approved exchange released")
	}
	if err := f.writer.Close(); err != nil {
		t.Fatal(err)
	}
	if f.writer.DeliveryStats().Written != 1 {
		t.Fatal("wiring: file control did not write")
	}
	if f.writer.StdoutDeliveryStats() != nil {
		t.Fatal("property: absent mirror has a delivery entry")
	}
}

// The protocol peer uses the test executable, with its mode after -- so normal
// suite collection executes the helper without starting an extension.
func TestIndependentStdoutExtensionPeer(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "it1-peer" {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var m map[string]any
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			os.Exit(41)
		}
		switch m["type"] {
		case "start":
			if enc.Encode(map[string]any{"type": "ready", "protocol": "observer.extension/2"}) != nil {
				os.Exit(42)
			}
		case "exchange":
			if bytes.Contains(scan.Bytes(), []byte(it1Secret)) {
				os.Exit(43)
			}
			if enc.Encode(map[string]any{"type": "derived", "sources": []any{m["id"]}, "basis": "observed", "record": map[string]any{"it1": "derived-only"}}) != nil {
				os.Exit(44)
			}
			if enc.Encode(map[string]any{"type": "result", "id": m["id"], "outcome": "changed", "changes": map[string]any{"request.headers": map[string]any{"headers": []any{map[string]string{"name": "X-Public", "value": "after-extension"}, map[string]string{"name": "Authorization", "value": it1Secret}}, "trailers": []any{}}}}) != nil {
				os.Exit(45)
			}
		case "shutdown":
			os.Exit(0)
		}
	}
	os.Exit(0)
}

func TestIndependentStdoutPostExtensionApprovalAndDerivedIsolation(t *testing.T) {
	mirror, pipe, finishPipe := it1Pipe(t)
	fileReached := make(chan []byte, 16)
	f := it1New(t, mirror, 1<<20, func(path string) sink.Sink { return it1FileSink{Sink: sink.NewFile(path), reached: fileReached} })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := json.Marshal([]any{map[string]any{"name": "it1", "command": []string{self, "-test.run=^TestIndependentStdoutExtensionPeer$", "--", "it1-peer"}, "fields": []string{"request.headers"}, "timeout_ms": 3000}})
	compiled, findings := config.Compile([]byte(`{"version":"observer.config/1","output":"/unused","watch":[{"name":"api","exe":"/usr/bin/php"}],"write_content":true,"remove":{"headers":["authorization"]},"extensions":`+string(entries)+`}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring: extension plan: %+v", findings)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096})
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	r, err := processing.Start(processing.Options{Supervision: func(e extension.Event) {
		if e.Kind == extension.Ready {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}, Session: "it1", PolicyRevision: "it1-policy", Plan: compiled.Plan, Intake: f.store, Gate: gate, Output: f.writer, Derived: f.writer})
	if err != nil {
		t.Fatalf("wiring: extension start: %v", err)
	}
	defer func() { _ = r.Close() }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("wiring: extension did not become ready")
	}
	c := it1Input(t, 1)
	for _, one := range c.fragments {
		if err := f.store.Write(one); err != nil {
			t.Fatal(err)
		}
	}
	r.Route()
	var approved []byte
	derivedSeen := false
	for range 2 {
		written := it1Await(t, fileReached, "wiring: extension approved/derived file paths not both reached")
		if bytes.Contains(written, []byte("derived-only")) {
			derivedSeen = true
		} else {
			approved = written
		}
	}
	var control processing.Artifact
	if json.Unmarshal(approved, &control) != nil || !derivedSeen || len(control.ExtensionOutcomes) != 1 || control.ExtensionOutcomes[0].Outcome != "changed" {
		t.Fatalf("wiring: changed result and derived paths not reached: %+v", control.ExtensionOutcomes)
	}
	line := it1Await(t, pipe, "property: extension-approved exchange did not reach stdout while open")
	a := it1Read(t, line, 1)[0]
	if bytes.Contains(line, []byte(it1Secret)) || !bytes.Contains(line, []byte("after-extension")) || len(a.ReplacementExclusions) == 0 {
		t.Fatalf("property: stdout bypassed post-extension approval: %s", line)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err = r.Finish(ctx, processing.Finalization{}); err != nil {
		t.Fatalf("wiring: extension finish: %v", err)
	}
	if err = f.writer.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	derived, err := os.ReadFile(filepath.Join(f.dir, processing.DerivedName("it1")))
	if err != nil || !bytes.Contains(derived, []byte("derived-only")) {
		t.Fatalf("wiring: derived path not reached: %v %s", err, derived)
	}
	file, err := os.ReadFile(filepath.Join(f.dir, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	finishPipe()
	var tail []byte
	for next := range pipe {
		tail = append(tail, next...)
	}
	all := append(bytes.Clone(line), tail...)
	if !bytes.Equal(file, all) || bytes.Contains(all, []byte("derived-only")) || bytes.Contains(file, []byte(it1Secret)) {
		t.Fatal("property: approved stdout/file isolation or sanitation differs")
	}
	if strings.Count(string(derived), "\n") != 1 {
		t.Fatal("wiring: expected one derived record")
	}
}
