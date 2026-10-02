package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// lines is approved output collected from workers writing concurrently.
type lines struct {
	mutex sync.Mutex
	got   [][]byte
}

func (l *lines) WriteApproved(_ context.Context, a processing.Approved) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.got = append(l.got, a.Bytes())
	return nil
}

func (l *lines) all() [][]byte {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return slices.Clone(l.got)
}

// written is the connection ids that have an exchange line among got.
func written(t *testing.T, got [][]byte) map[string]int {
	t.Helper()
	ids := map[string]int{}
	for _, line := range got {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatal(err)
		}
		if a.Route.Pipeline == config.ExchangesPipeline {
			ids[a.Connection.ID]++
		}
	}
	return ids
}

type taken struct {
	mutex   sync.Mutex
	workers map[string]map[int]bool
	count   map[int]int
	calls   int
}

func newTaken() *taken {
	return &taken{workers: map[string]map[int]bool{}, count: map[int]int{}}
}

func connectionKey(p fragment.Process, id fragment.ConnectionID) string {
	return strconv.Itoa(int(p.PID)) + "/" + strconv.FormatUint(p.StartTime, 10) + "/" + strconv.FormatUint(uint64(id), 10)
}

func (k *taken) record(worker int, p fragment.Process, id fragment.ConnectionID) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	key := connectionKey(p, id)
	if k.workers[key] == nil {
		k.workers[key] = map[int]bool{}
	}
	k.workers[key][worker] = true
	k.count[worker]++
	k.calls++
}

// worker is the one worker that took the connection's entries.
func (k *taken) worker(t *testing.T, p fragment.Process, id fragment.ConnectionID) int {
	t.Helper()
	k.mutex.Lock()
	defer k.mutex.Unlock()
	held := k.workers[connectionKey(p, id)]
	if len(held) != 1 {
		t.Fatalf("connection %d was taken by %d workers, want one", id, len(held))
	}
	for w := range held {
		return w
	}
	return -1
}

type runOptions struct {
	workers int
	limit   int64
	output  processing.Output
	gate    func(store *intake.Store) *probe.DeliveryGate
	taken   func(int, fragment.Process, fragment.ConnectionID)
}

func startRun(t *testing.T, plan *config.ProcessingPlan, o runOptions) (*processing.Run, *intake.Store) {
	t.Helper()
	if o.limit == 0 {
		o.limit = 1 << 30
	}
	store, err := intake.New(o.limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var gate *probe.DeliveryGate
	if o.gate != nil {
		gate = o.gate(store)
	} else if gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40, IntakeExhausted: store.Exhausted()}); err != nil {
		t.Fatal(err)
	}
	run, err := processing.Start(processing.Options{Plan: plan, PolicyRevision: "workers", Intake: store, Gate: gate,
		Output: o.output, Workers: o.workers, Taken: o.taken})
	if err != nil || run == nil {
		t.Fatalf("wiring, not the property: the workers did not start: %v", err)
	}
	t.Cleanup(func() { _ = run.Close() })
	return run, store
}

var settled = processing.Finalization{Withdrawn: true, Drained: true}

// feed writes every entry, routing after every chunk of them, so batches
// complete while later entries are still arriving.
func feed(t *testing.T, run *processing.Run, store *intake.Store, w *workload.Workload) {
	t.Helper()
	for start := 0; start < len(w.Entries); start += 97 {
		chunk := &workload.Workload{Entries: w.Entries[start:min(start+97, len(w.Entries))]}
		if n, err := chunk.Write(store); err != nil || n != len(chunk.Entries) {
			t.Fatalf("wiring, not the property: the intake refused an entry: %v", err)
		}
		run.Route()
	}
}

// withoutIDs is each line with its exchange id range removed: which range a
// connection is issued depends on the order batches are dispatched in, which
// the number of workers changes.
func withoutIDs(t *testing.T, got [][]byte) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(got))
	for _, line := range got {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(line, &members); err != nil {
			t.Fatal(err)
		}
		if _, ok := members["exchange_ids"]; !ok {
			t.Fatalf("a line carries no exchange id range: %s", line)
		}
		delete(members, "exchange_ids")
		stripped, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, stripped)
	}
	return out
}

func generate(t *testing.T, shape workload.Shape) *workload.Workload {
	t.Helper()
	w, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// On the same entries, every worker count writes the same lines and the same
// counts as one Worker taking straight from the intake. A count that one
// Worker cannot know stays unknown summed over several, however many of them
// know theirs.
func TestSeveralWorkersWriteWhatOneWorkerWrites(t *testing.T) {
	plan := rulesPlan(t, `"remove": {"headers": ["x-field-2"], "json": {"request": ["/id"]}}, "mask": {"headers": {"x-field-1": "withheld"}}`)
	for _, one := range []struct {
		name    string
		shape   workload.Shape
		unknown bool
	}{
		{"defects of every kind", workload.Shape{Connections: 300, Exchanges: 3, HeaderBytes: 150, RequestBodyBytes: 120,
			ResponseBodyBytes: 5000, JSONShare: 0.5, DefectShare: 0.2, Processes: 4, Concurrency: 16, ReorderShare: 0.1, Seed: 41}, true},
		{"defects that leave the refusals counted", workload.Shape{Connections: 200, Exchanges: 4, HeaderBytes: 80, RequestBodyBytes: 60,
			ResponseBodyBytes: 700, JSONShare: 0.5, DefectShare: 0.3, DefectKinds: []string{workload.DefectUnsupported},
			Processes: 3, Concurrency: 8, ReorderShare: 0.1, Seed: 42}, false},
	} {
		t.Run(one.name, func(t *testing.T) {
			w := generate(t, one.shape)
			baseOutput := &lines{}
			alone, store := standalone(t, plan, baseOutput)
			if n, err := w.Write(store); err != nil || n != len(w.Entries) {
				t.Fatalf("wiring, not the property: %d of %d entries reached the intake: %v", n, len(w.Entries), err)
			}
			base, err := alone.Finish(context.Background(), settled)
			if err != nil {
				t.Fatal(err)
			}
			baseLines := withoutIDs(t, baseOutput.all())
			slices.SortFunc(baseLines, bytes.Compare)
			if len(written(t, baseLines)) == 0 || base.Written == 0 {
				t.Fatal("wiring, not the property: one worker wrote no exchanges")
			}
			if base.Withheld.Known == one.unknown || (!one.unknown && base.Withheld.Value == 0) {
				t.Fatalf("wiring, not the property: one worker's withheld count is %v, so this workload does not test the sum it is for", base.Withheld)
			}
			for _, n := range []int{1, 2, 4} {
				out := &lines{}
				run, store := startRun(t, plan, runOptions{workers: n, output: out})
				feed(t, run, store, w)
				o, err := run.Finish(context.Background(), settled)
				if err != nil {
					t.Fatalf("%d workers: %v", n, err)
				}
				got := withoutIDs(t, out.all())
				slices.SortFunc(got, bytes.Compare)
				if !slices.EqualFunc(got, baseLines, bytes.Equal) {
					t.Errorf("%d workers wrote %d lines that differ from one worker's %d", n, len(got), len(baseLines))
				}
				for _, c := range []struct {
					name      string
					got, want uint64
				}{{"batches", o.Batches, base.Batches}, {"authorized", o.Authorized, base.Authorized}, {"written", o.Written, base.Written},
					{"processing failures", o.ProcessingFailures, base.ProcessingFailures}, {"output failures", o.OutputFailures, base.OutputFailures}} {
					if c.got != c.want {
						t.Errorf("%d workers: %s %d, one worker %d", n, c.name, c.got, c.want)
					}
				}
				if o.Withheld.Known != base.Withheld.Known || (o.Withheld.Known && o.Withheld.Value != base.Withheld.Value) {
					t.Errorf("%d workers: withheld %v, one worker %v", n, o.Withheld, base.Withheld)
				}
				if o.Pending != 0 || o.GateReason != base.GateReason {
					t.Errorf("%d workers: %d pending and gate reason %q, want 0 and %q", n, o.Pending, o.GateReason, base.GateReason)
				}
			}
		})
	}
}

// With n workers, n workers take entries, and every entry of a connection is
// taken by the same one.
func TestEveryEntryOfAConnectionReachesOneWorker(t *testing.T) {
	plan := rulesPlan(t, "")
	w := generate(t, workload.Shape{Connections: 200, Exchanges: 2, ResponseBodyBytes: 100, Processes: 4, Concurrency: 8, ReorderShare: 0.2, Seed: 5})
	for _, n := range []int{1, 2, 4, 8} {
		t.Run(strconv.Itoa(n)+" workers", func(t *testing.T) {
			k := newTaken()
			run, store := startRun(t, plan, runOptions{workers: n, output: &lines{}, taken: k.record})
			feed(t, run, store, w)
			if _, err := run.Finish(context.Background(), settled); err != nil {
				t.Fatal(err)
			}
			if k.calls != len(w.Entries) {
				t.Fatalf("wiring, not the property: workers took %d of %d entries", k.calls, len(w.Entries))
			}
			for worker := range k.count {
				if worker < 0 || worker >= n {
					t.Errorf("worker %d took entries, with %d workers", worker, n)
				}
			}
			if len(k.count) != n {
				t.Errorf("%d workers took entries, want %d: %v", len(k.count), n, k.count)
			}
			for _, c := range w.Connections {
				k.worker(t, c.Process, c.ID)
			}
		})
	}
}

// Two connections that differ only in their process are two connections, so
// routing reads the process as well as the connection id: connection 1 under
// sixteen processes does not all go to one worker.
func TestRoutingReadsTheProcess(t *testing.T) {
	var all workload.Workload
	processes := map[fragment.Process]bool{}
	// Capture numbers each session's connections from 1, so each of these is
	// connection 1, under a process the seed chose.
	for seed := uint64(1); len(processes) < 16 && seed < 1000; seed++ {
		w := generate(t, workload.Shape{Connections: 1, Exchanges: 1, Processes: 64, Seed: seed})
		if processes[w.Connections[0].Process] {
			continue
		}
		processes[w.Connections[0].Process] = true
		all.Entries = append(all.Entries, w.Entries...)
	}
	if len(processes) != 16 {
		t.Fatalf("wiring, not the property: %d processes, want 16", len(processes))
	}
	k := newTaken()
	run, store := startRun(t, rulesPlan(t, ""), runOptions{workers: 4, output: &lines{}, taken: k.record})
	feed(t, run, store, &all)
	if _, err := run.Finish(context.Background(), settled); err != nil {
		t.Fatal(err)
	}
	used := map[int]bool{}
	for p := range processes {
		used[k.worker(t, p, 1)] = true
	}
	if len(used) < 2 {
		t.Errorf("connection 1 of 16 processes went to %d worker of 4", len(used))
	}
}

// The intake has one allowance, whatever the number of workers holding its
// entries: with four workers held, it refuses at the same entry as an intake
// nothing takes from, though each worker's share of the entries is below it.
func TestTheIntakeLimitIsOneLimitAcrossWorkers(t *testing.T) {
	const limit = 1 << 20
	w := generate(t, workload.Shape{Connections: 400, Exchanges: 2, RequestBodyBytes: 500, ResponseBodyBytes: 3000, Processes: 4, Concurrency: 32, Seed: 13})
	control, err := intake.New(limit)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := w.Write(control)
	if !errors.Is(err, intake.ErrLimit) {
		t.Fatalf("wiring, not the property: the workload fits the limit (%d entries, %v)", accepted, err)
	}

	hold := make(chan struct{})
	k := newTaken()
	run, store := startRun(t, rulesPlan(t, ""), runOptions{workers: 4, limit: limit, output: &lines{},
		taken: func(worker int, p fragment.Process, id fragment.ConnectionID) {
			k.record(worker, p, id)
			<-hold
		}})
	released := false
	t.Cleanup(func() {
		if !released {
			close(hold)
		}
	})
	got := 0
	for _, e := range w.Entries {
		one := &workload.Workload{Entries: []workload.Entry{e}}
		if _, err := one.Write(store); err != nil {
			if !errors.Is(err, intake.ErrLimit) {
				t.Fatal(err)
			}
			break
		}
		got++
		run.Route()
	}
	stats := store.Stats()
	if stats.Queued != 0 {
		t.Fatalf("wiring, not the property: %d accepted entries are still queued in the intake, so routing did not take them", stats.Queued)
	}
	if got != accepted || stats.Leased != int64(got) {
		t.Errorf("with four workers holding entries the intake accepted %d and holds %d of them leased; alone it accepted %d", got, stats.Leased, accepted)
	}
	close(hold)
	released = true
	if _, err := run.Finish(context.Background(), settled); err != nil {
		t.Fatal(err)
	}
	if len(k.count) < 2 {
		t.Fatalf("wiring, not the property: %d worker held the accepted entries, so no share was below the whole", len(k.count))
	}
	if stats := store.Stats(); stats.Bytes != 0 || stats.Leased != 0 {
		t.Errorf("after finishing the intake holds %d bytes in %d leases", stats.Bytes, stats.Leased)
	}
}

// The output has one allowance: four workers write up to it and no further,
// though each one's share of the lines is below it, and the line that would
// pass it is the only output failure.
func TestTheOutputLimitIsOneLimitAcrossWorkers(t *testing.T) {
	plan := rulesPlan(t, "")
	w := generate(t, workload.Shape{Connections: 200, Exchanges: 2, ResponseBodyBytes: 400, Processes: 4, Concurrency: 8, Seed: 17})

	// The control learns each line's size and the worker that wrote it.
	k := newTaken()
	out := &lines{}
	run, store := startRun(t, plan, runOptions{workers: 4, output: out, taken: k.record})
	feed(t, run, store, w)
	if _, err := run.Finish(context.Background(), settled); err != nil {
		t.Fatal(err)
	}
	var total int64
	share := map[int]int64{}
	for _, line := range out.all() {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatal(err)
		}
		id, err := strconv.ParseUint(a.Connection.ID, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		c := w.Connections[id-1]
		share[k.worker(t, c.Process, c.ID)] += int64(len(line))
		total += int64(len(line))
	}
	limit := total / 2
	for worker, bytes := range share {
		if bytes >= limit {
			t.Fatalf("wiring, not the property: worker %d wrote %d bytes, not below the limit %d", worker, bytes, limit)
		}
	}

	directory := t.TempDir()
	writer, err := processing.Open(directory, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	run, store = startRun(t, plan, runOptions{workers: 4, output: writer, gate: func(store *intake.Store) *probe.DeliveryGate {
		gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40, StorageExhausted: writer.Exhausted(), IntakeExhausted: store.Exhausted()})
		if err != nil {
			t.Fatal(err)
		}
		return gate
	}})
	feed(t, run, store, w)
	o, err := run.Finish(context.Background(), settled)
	if !errors.Is(err, processing.ErrOutputLimit) {
		t.Fatalf("finishing past the limit returned %v, want the output limit", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	stats := writer.Stats()
	if int64(len(content)) > limit || stats.Bytes != int64(len(content)) || !stats.Exhausted || stats.Written == 0 {
		t.Errorf("four workers wrote %d bytes against a limit of %d: %+v", len(content), limit, stats)
	}
	if o.OutputFailures != 1 || stats.Refused != 1 {
		t.Errorf("%d output failures and %d refused writes, want one of each", o.OutputFailures, stats.Refused)
	}
}

// A worker held on one connection does not stop the others: the connections
// routed to other workers are written while it is held, routing returns
// although its queue keeps growing, and when it is let go its own are written
// too.
func TestAHeldWorkerDoesNotHoldBackOtherConnections(t *testing.T) {
	plan := rulesPlan(t, "")
	w := generate(t, workload.Shape{Connections: 300, Exchanges: 2, ResponseBodyBytes: 50, Processes: 4, Seed: 21})
	const n = 4
	first := w.Connections[0]

	// Routing is a function of the connection, so a control run says which
	// worker each connection goes to.
	control := newTaken()
	run, store := startRun(t, plan, runOptions{workers: n, output: &lines{}, taken: control.record})
	feed(t, run, store, w)
	if _, err := run.Finish(context.Background(), settled); err != nil {
		t.Fatal(err)
	}
	held := control.worker(t, first.Process, first.ID)
	others := map[string]bool{}
	for _, c := range w.Connections {
		if control.worker(t, c.Process, c.ID) != held {
			others[strconv.FormatUint(uint64(c.ID), 10)] = true
		}
	}
	if control.count[held] < 200 || len(others) == 0 {
		t.Fatalf("wiring, not the property: the held worker takes %d entries and %d connections go elsewhere", control.count[held], len(others))
	}

	hold := make(chan struct{})
	holding := make(chan struct{})
	out := &lines{}
	run, store = startRun(t, plan, runOptions{workers: n, output: out, taken: func(worker int, p fragment.Process, id fragment.ConnectionID) {
		if worker == held && id == first.ID {
			select {
			case <-holding:
			default:
				close(holding)
				<-hold
			}
		}
	}})
	released := false
	t.Cleanup(func() {
		if !released {
			close(hold)
		}
	})
	if n, err := w.Write(store); err != nil || n != len(w.Entries) {
		t.Fatalf("wiring, not the property: %d of %d entries reached the intake: %v", n, len(w.Entries), err)
	}
	routed := make(chan struct{})
	go func() {
		run.Route()
		close(routed)
	}()
	select {
	case <-routed:
	case <-time.After(10 * time.Second):
		t.Fatal("routing waited on the held worker")
	}
	select {
	case <-holding:
	case <-time.After(10 * time.Second):
		t.Fatal("wiring, not the property: the worker for the first connection never took it")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		ids := written(t, out.all())
		missing := 0
		for id := range others {
			if ids[id] == 0 {
				missing++
			}
		}
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("with one worker held, %d of the %d connections routed elsewhere were not written", missing, len(others))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ids := written(t, out.all()); ids[strconv.FormatUint(uint64(first.ID), 10)] != 0 {
		t.Fatal("wiring, not the property: the held connection was written while its worker was held")
	}
	close(hold)
	released = true
	if _, err := run.Finish(context.Background(), settled); err != nil {
		t.Fatal(err)
	}
	if ids := written(t, out.all()); len(ids) != len(w.Connections) {
		t.Errorf("after letting the worker go, %d of %d connections were written", len(ids), len(w.Connections))
	}
}

// After thousands of connections complete, a late copy of an early one's
// entries is released at once rather than held until the session finishes.
// The same holds where connection ids skip, which fills the record of ids not
// yet seen to its bound.
func TestALateEntryHoldsNoLease(t *testing.T) {
	for _, step := range []uint64{1, 2} {
		t.Run("ids every "+strconv.FormatUint(step, 10), func(t *testing.T) {
			w := generate(t, workload.Shape{Connections: 3000, Exchanges: 1, ResponseBodyBytes: 10, Seed: 23})
			for _, e := range w.Entries {
				renumber(e, step)
			}
			one, store := standalone(t, rulesPlan(t, ""), &outputLog{})
			if n, err := w.Write(store); err != nil || n != len(w.Entries) {
				t.Fatalf("wiring, not the property: %d of %d entries reached the intake: %v", n, len(w.Entries), err)
			}
			o := drain(t, one)
			if o.Batches != 3000 || !o.Withheld.Known || store.Stats().Leased != 0 {
				t.Fatalf("wiring, not the property: %d batches processed, withheld %v, %d leases held", o.Batches, o.Withheld, store.Stats().Leased)
			}
			// A copy of connection 7's entries, and where ids skip, a first
			// entry under an id below every id the record still holds.
			var late workload.Workload
			for _, e := range w.Entries {
				if (e.Fragment != nil && e.Fragment.Connection == fragment.ConnectionID(7*step)) || (e.Connection != nil && e.Connection.ID == fragment.ConnectionID(7*step)) {
					late.Entries = append(late.Entries, e)
				}
			}
			if step > 1 {
				f := *late.Entries[0].Fragment
				f.Connection = 3
				late.Entries = append(late.Entries, workload.Entry{Fragment: &f})
			}
			if n, err := late.Write(store); err != nil || n != len(late.Entries) {
				t.Fatalf("wiring, not the property: the late entries did not reach the intake: %v", err)
			}
			o = drain(t, one)
			if stats := store.Stats(); stats.Leased != 0 || stats.Bytes != 0 || o.Pending != 0 {
				t.Errorf("%d late entries hold %d leases of %d bytes in %d pending batches", len(late.Entries), stats.Leased, stats.Bytes, o.Pending)
			}
			if o.Withheld.Known || o.Batches != 3000 {
				t.Errorf("late entries counted as withheld %v over %d batches, want unknown over 3000", o.Withheld, o.Batches)
			}
		})
	}
}

// standalone is one worker taking straight from an intake large enough for
// thousands of connections.
func standalone(t *testing.T, plan *config.ProcessingPlan, output processing.Output) (*processing.Worker, *intake.Store) {
	t.Helper()
	store, err := intake.New(1 << 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	w, err := processing.New(processing.Options{Plan: plan, PolicyRevision: "workers", Intake: store, Gate: gate, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, store
}

// renumber multiplies an entry's connection id by step.
func renumber(e workload.Entry, step uint64) {
	if f := e.Fragment; f != nil {
		f.Connection = fragment.ConnectionID(uint64(f.Connection) * step)
		return
	}
	r := e.Connection
	r.ID = fragment.ConnectionID(uint64(r.ID) * step)
	for i := range r.Associations {
		r.Associations[i].Connection = r.ID
	}
	for i := range r.Placements {
		r.Placements[i].Connection = r.ID
	}
}
