//go:build attach

package attach_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

// t18Barrier holds whoever reaches it until it is opened, and says when the
// first one arrived.
type t18Barrier struct {
	entered, release chan struct{}
	arrived, opened  sync.Once
}

func t18NewBarrier() *t18Barrier {
	return &t18Barrier{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *t18Barrier) hold() {
	b.arrived.Do(func() { close(b.entered) })
	<-b.release
}

func (b *t18Barrier) open() { b.opened.Do(func() { close(b.release) }) }

// t18HeldOutput is the approved-output writer behind a barrier: a write
// reaches the barrier, and only then the writer.
type t18HeldOutput struct {
	barrier *t18Barrier
	inner   processing.Output
}

func (o t18HeldOutput) WriteApproved(ctx context.Context, a processing.Approved) error {
	o.barrier.hold()
	return o.inner.WriteApproved(ctx, a)
}

// t18HeldSink is capture's fragment sink, the volatile intake, behind a
// barrier once armed: the delivery loop calling it is held inside the write.
type t18HeldSink struct {
	barrier *t18Barrier
	armed   atomic.Bool
	inner   capture.Sink
}

func (s *t18HeldSink) Write(record fragment.Record) error {
	if s.armed.Load() {
		s.barrier.hold()
	}
	return s.inner.Write(record)
}

// t18Compiled is a protected plan selecting exactly these processes, one
// target each, removing the authorization header on its one route.
func t18Compiled(t *testing.T, peers ...process.Process) policy.Policy {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	watch := []any{}
	for i, peer := range peers {
		watch = append(watch, map[string]any{"name": fmt.Sprint("peer-", i), "exe": peer.Executable,
			"args": append([]string{}, peer.Arguments[1:]...), "children": config.ChildrenAll})
	}
	document["watch"] = watch
	document["remove"] = map[string]any{"headers": []string{"authorization"}}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.CompileProcessing(raw, nil)
	if err != nil || p.Processing == nil {
		t.Fatalf("the protected plan did not compile: %v", err)
	}
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	selected := p.Approval.Select(table)
	for _, peer := range peers {
		if !slices.ContainsFunc(selected, func(one process.Process) bool { return one.PID == peer.PID && one.StartTime == peer.StartTime }) {
			t.Fatalf("the plan does not select pid %d: %+v", peer.PID, selected)
		}
	}
	return p
}

// t18Timed runs n exchanges on c and returns each one's duration, or the
// error that stopped them, within the bound; it never blocks the caller past
// it, so a barrier the exchanges wait on can still be opened.
func t18Timed(c conversation, prefix string, n int, within time.Duration) ([]time.Duration, error) {
	type result struct {
		took []time.Duration
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var took []time.Duration
		for i := range n {
			one, err := t18Exchange(c, fmt.Sprintf("/?asked=%s-%d", prefix, i))
			if err != nil {
				done <- result{took, err}
				return
			}
			took = append(took, one)
		}
		done <- result{took, nil}
	}()
	select {
	case r := <-done:
		return r.took, r.err
	case <-time.After(within):
		return nil, fmt.Errorf("the exchanges had not completed %s later", within)
	}
}

// Row 5, as latency on the real attachment and a real application. Three
// things are held in turn, each ENTERED before anything is measured and held
// while a second connection exchanges:
//
//	the worker      stopped in BeforeParse on the first closed batch
//	the writer      stopped inside the approved write of that batch
//	the sink        capture's fragment sink stopped inside a write, which holds
//	                the delivery loop
//
// Each held exchange must complete, and in about the time the same exchange
// took with nothing held - an application waiting on the unblock never
// completes, because the barrier is opened only after the measurement. While
// the sink is held, capture authority is withdrawn and capture's own state is
// read, neither of which may need anything the stuck sink holds, and the
// application goes on exchanging after the withdrawal. Lock POSITION is
// capture/sink_positions_test.go's; this is the time the application takes.
func TestT18TheApplicationDoesNotWaitOnAHeldWorkerWriterOrSink(t *testing.T) {
	for _, held := range []string{"the worker", "the writer", "the sink"} {
		t.Run(held, func(t *testing.T) { t18Held(t, held) })
	}
}

func t18Held(t *testing.T, held string) {
	closing := speaking(t, t18Serving(t))
	measured := speaking(t, t18Serving(t))
	compiled := t18Compiled(t, closing.process, measured.process)
	barrier := t18NewBarrier()
	t.Cleanup(barrier.open)

	_, store, err := activation.RecordingIntake(1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sink := &t18HeldSink{barrier: barrier, inner: store}
	recording := capture.Recording(sink, store)
	directory := t.TempDir()
	writer, err := processing.Open(directory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1024, StorageExhausted: writer.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	options := processing.Options{Plan: compiled.Processing, PolicyRevision: compiled.Revision, Intake: store, Gate: gate, Output: writer}
	switch held {
	case "the worker":
		options.BeforeParse = func(context.Context) error { barrier.hold(); return nil }
	case "the writer":
		options.Output = t18HeldOutput{barrier: barrier, inner: writer}
	}
	worker, err := processing.New(options)
	if err != nil {
		t.Fatal(err)
	}
	// The worker's serial owner, draining on the program's own cadence.
	stopping, stopped := make(chan struct{}), make(chan struct{})
	var drainErr atomic.Value
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopping:
				return
			case <-ticker.C:
				if _, err := worker.Drain(context.Background()); err != nil {
					drainErr.Store(err)
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		barrier.open()
		close(stopping)
		<-stopped
		_ = worker.Close()
		_ = writer.Close()
	})

	request := requesting(closing.process, measured.process)
	request.DeliveryGate = gate
	live, err := attach.NeweBPF(compiled.Approval).Attach(request, recording)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { barrier.open(); _ = live.Close() })
	recording.Observing(live.Capability())

	baseline, err := t18Timed(measured, "t18-baseline", 5, 10*time.Second)
	if err != nil {
		t.Fatalf("the baseline exchanges: %v", err)
	}
	if records := recording.Stats().Records; records < 10 {
		t.Fatalf("wiring, not the property: the baseline's exchanges reached capture as %d records", records)
	}

	var took []time.Duration
	switch held {
	case "the worker", "the writer":
		t18Ask(t, closing, "/?asked=t18-closing", "Authorization: Bearer t18-held-secret")
		t18Hangup(closing)
		select {
		case <-barrier.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("wiring, not the property: %s never reached the barrier (drain %v)", held, drainErr.Load())
		}
		before := recording.Stats().Records
		if took, err = t18Timed(measured, "t18-held", 5, 10*time.Second); err != nil {
			t.Fatalf("the application waited on %s: %v", held, err)
		}
		if after := recording.Stats().Records; after < before+10 {
			t.Errorf("the exchanges while %s was held reached capture as %d records", held, after-before)
		}
		if written := writer.Stats().Written; written != 0 {
			t.Fatalf("wiring, not the property: %d records were written while %s was held, so the barrier was not on the path", written, held)
		}
		barrier.open()
		deadline := time.Now().Add(10 * time.Second)
		for writer.Stats().Written == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		written := t18Approved(t, directory)
		if !slices.Contains(t18Targets(written), "/?asked=t18-closing") || t18Excluded(written, "authorization") == 0 {
			t.Errorf("once opened, %s did not write the closed connection's exchange with its credential removed: %v",
				held, t18Targets(written))
		}
	case "the sink":
		producer, ok := live.(connection.Producer)
		if !ok {
			t.Fatal("the attachment cannot withdraw")
		}
		sink.armed.Store(true)
		if took, err = t18Timed(measured, "t18-held", 5, 10*time.Second); err != nil {
			t.Fatalf("the application waited on the held sink: %v", err)
		}
		select {
		case <-barrier.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("wiring, not the property: the delivery loop never reached the held sink")
		}
		read := make(chan capture.Stats, 1)
		go func() { read <- recording.Stats() }()
		select {
		case <-read:
		case <-time.After(5 * time.Second):
			t.Fatal("reading capture's state waited on the held sink")
		}
		withdrawn := make(chan connection.Withdrawal, 1)
		go func() {
			w, err := producer.StopProducing()
			if err != nil {
				w.Because = err.Error()
			}
			withdrawn <- w
		}()
		select {
		case w := <-withdrawn:
			if !w.Complete {
				t.Errorf("withdrawal while the sink was held did not complete: %+v", w)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("withdrawing capture authority waited on the held sink")
		}
		after, err := t18Timed(measured, "t18-withdrawn", 2, 10*time.Second)
		if err != nil {
			t.Fatalf("the application waited after the withdrawal: %v", err)
		}
		t.Logf("exchanges after the withdrawal took %v", after)
		began := time.Now()
		drained, err := producer.Drain(time.Second)
		if spent := time.Since(began); err != nil || drained.Complete || spent > 5*time.Second {
			t.Errorf("a drain over the held sink returned complete=%v after %s (%v), want an incomplete drain within its bound",
				drained.Complete, spent, err)
		}
		barrier.open()
	}

	slowest := slices.Max(baseline)
	t.Logf("%s held: exchanges took %v; with nothing held %v", held, took, baseline)
	if worst := slices.Max(took); worst > 4*slowest+250*time.Millisecond {
		t.Errorf("an exchange took %s while %s was held, against %s at most with nothing held", worst, held, slowest)
	}
}
