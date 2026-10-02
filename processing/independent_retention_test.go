package processing_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
)

func independentOccupancy(t *testing.T, r held.Reader) map[string]held.Occupancy {
	t.Helper()
	items, err := r.Retained()
	if err != nil || len(items) == 0 {
		t.Fatalf("wiring, not the property: occupancy reading absent: %v", err)
	}
	out := map[string]held.Occupancy{}
	for _, v := range items {
		if _, exists := out[v.Store]; exists {
			t.Fatalf("wiring, not the property: duplicated store reading %q", v.Store)
		}
		out[v.Store] = v
	}
	return out
}

func independentStore(t *testing.T, stores map[string]held.Occupancy, name string) held.Occupancy {
	t.Helper()
	value, exists := stores[name]
	if !exists {
		t.Fatalf("wiring, not the property: required store reading %s absent", name)
	}
	return value
}

func TestIndependentCaptureChurnKeepsOnlyLiveIdentity(t *testing.T) {
	f := independentSequenceNew(&independentSequenceSettler{})
	f.transfer(1, 1, fragment.Sent, "pinned")
	first := independentOccupancy(t, f.session)
	if independentStore(t, first, "capture.streams").Held != 1 || len(f.captured.fragments) != 1 {
		t.Fatal("wiring, not the property: pinned live connection absent")
	}
	for i := uint64(2); i <= 161; i++ {
		f.transfer(i, 1, fragment.Sent, "ephemeral")
		f.close(i, 1, 0)
	}
	if len(f.captured.endings) != 160 {
		t.Fatal("wiring, not the property: churn did not reach160 retirement callbacks")
	}
	if f.session.Open() != 1 {
		t.Errorf("capture retained %d open connections after 160 ended beside one pinned connection", f.session.Open())
	}
	after := independentOccupancy(t, f.session)
	for _, name := range []string{"capture.streams", "capture.early", "capture.settlers"} {
		limit := 0
		if name == "capture.streams" || name == "capture.settlers" {
			limit = 1
		}
		if v := independentStore(t, after, name); v.Held > limit {
			t.Errorf("%s retains%d after160 retirements, live bound%d", name, v.Held, limit)
		}
	}
	if stats := f.session.Stats(); stats.Rejected != 0 || stats.Lost != 0 {
		t.Errorf("churn refused or lost input: %+v", stats)
	}
	t.Logf("PRECONDITIONS churn=160 live=1 callbacks=%d stores=%+v", len(f.captured.endings), after)
}

func TestIndependentCaptureEarlyHistoryEndsWithItsConnection(t *testing.T) {
	f := independentSequenceNew(nil)
	for i := uint64(1); i <= 80; i++ {
		f.stamp++
		f.session.Transfer(probe.Transfer{Process: f.process, Instance: f.instance, Endpoint: i, Stamp: f.stamp, Sequence: probe.Sequence{Occupancy: i, Number: 1, Born: true}, Direction: fragment.Sent, Measured: true, Length: 1, Payload: []byte("x"), Early: true, At: f.at})
		live := independentOccupancy(t, f.session)
		if independentStore(t, live, "capture.early").Held == 0 {
			t.Fatal("wiring, not the property: early-data range never reached live capture")
		}
		f.close(i, 1, 0)
	}
	if len(f.captured.endings) != 80 {
		t.Fatal("wiring, not the property: early-data connections did not retire")
	}
	for _, r := range f.captured.endings {
		if len(r.Early) != 1 {
			t.Fatal("wiring, not the property: early evidence not preserved in retirement")
		}
	}
	for name, v := range independentOccupancy(t, f.session) {
		if name != "capture.settlers" && v.Held != 0 {
			t.Errorf("%s retains%d after all early connections ended", name, v.Held)
		}
	}
}

func TestIndependentIntakeAndWorkerChurnReclaimsEachBatch(t *testing.T) {
	w, store, out, taken := independentSequenceWorker(t)
	f := independentSequenceNew(nil)
	for i := uint64(1); i <= 160; i++ {
		f.captured.fragments = nil
		f.captured.endings = nil
		f.transfer(i, 1, fragment.Sent, fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: x\r\n\r\n", i))
		f.transfer(i, 1, fragment.Received, independentSequenceResponse)
		f.close(i, 1, 1)
		independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
		before := independentOccupancy(t, store)
		if independentStore(t, before, "intake.entries").Held != 3 {
			t.Fatal("wiring, not the property: three entries were not held before drain")
		}
		independentSequenceDrain(t, w, taken, int(i)*3)
		for _, reader := range []held.Reader{store, w} {
			for name, v := range independentOccupancy(t, reader) {
				if v.Held != 0 {
					t.Errorf("%s retains%d at zero live population after connection%d", name, v.Held, i)
				}
			}
		}
	}
	if len(out.targets()) != 160 {
		t.Fatalf("wiring, not the property: processed%d of160 complete connections", len(out.targets()))
	}
	if stats := store.Stats(); stats.Bytes != 0 || stats.Leased != 0 || stats.FragmentsRefused != 0 || stats.ConnectionsRefused != 0 {
		t.Errorf("churn storage/refusals: %+v", stats)
	}
}

func TestIndependentCaptureCarriesReservationIntoRetainedInput(t *testing.T) {
	_, store, _, _ := independentSequenceWorker(t)
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4})
	if err != nil {
		t.Fatal(err)
	}
	f := independentSequenceNew(nil)
	recorder := capture.Recording(store, store)
	recorder.Observing(probe.Capability{Payload: true, Lifecycle: true})
	d := g.Admit(probe.DeliveryTransfer, true)
	if !d.Admitted || d.Slot == nil {
		t.Fatal("wiring, not the property: event reservation absent")
	}
	recorder.Transfer(probe.Transfer{Process: f.process, Instance: f.instance, Endpoint: 71, Stamp: 1, Sequence: probe.Sequence{Occupancy: 1, Number: 1, Born: true}, Direction: fragment.Sent, Measured: true, Length: 1, Payload: []byte("x"), At: time.Now(), Slot: d.Slot})
	e := store.Take()
	if e == nil || e.Fragment == nil || e.Fragment.Length != 1 {
		t.Fatal("wiring, not the property: captured transfer not retained")
	}
	if !d.Slot.Kept() || g.Snapshot().Held != 1 {
		t.Error("capture/intake lost reservation ownership")
	}
	e.ReleaseAs(held.Discarded)
	e.ReleaseAs(held.Processed)
	s := g.Snapshot()
	if s.Held != 0 || s.Refunded.Discarded != 1 || s.Refunded.Processed != 0 || s.DoubleRefunds != 0 {
		t.Errorf("release not exactly once: %+v", s)
	}
	recorder.Finish(time.Now())
	for e := store.Take(); e != nil; e = store.Take() {
		e.Release()
	}
}

func TestIndependentRunQueuesReturnToWarmLivePopulation(t *testing.T) {
	for _, sparse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sparse_%v", sparse), func(t *testing.T) { independentRunQueueChurn(t, sparse) })
	}
}

func independentRunQueueChurn(t *testing.T, sparse bool) {
	f := deliveryOpen(t, t.TempDir(), "retained-run", nil)
	all := deliveryConnections(t, 10240, 913)
	var warm map[string]held.Occupancy
	for i, entries := range all {
		if sparse {
			for _, e := range entries {
				if e.Fragment != nil {
					e.Fragment.Connection = fragment.ConnectionID(3*i + 7)
				}
				if e.Connection != nil {
					e.Connection.ID = fragment.ConnectionID(3*i + 7)
					for j := range e.Connection.Associations {
						e.Connection.Associations[j].Connection = e.Connection.ID
					}
					for j := range e.Connection.Placements {
						e.Connection.Placements[j].Connection = e.Connection.ID
					}
					if err := e.Connection.Validate(); err != nil {
						t.Fatalf("sparse fixture invalid: %v", err)
					}
				}
			}
		}
		f.feed(t, entries)
		deadline := time.Now().Add(5 * time.Second)
		for f.run.Snapshot().Batches < uint64(i+1) {
			if time.Now().After(deadline) {
				t.Fatal("wiring, not the property: routed batch never completed")
			}
			time.Sleep(time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := f.writer.Drain(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		now := independentOccupancy(t, f.run)
		if i == 0 {
			warm = now
		}
		for _, name := range []string{"processing.batches", "processing.entries", "processing.fragments", "processing.order", "processing.waiting", "processing.queue"} {
			if independentStore(t, now, name).Held != 0 {
				t.Errorf("%s retains%d after batch%d drained", name, independentStore(t, now, name).Held, i)
			}
		}
		router := independentStore(t, now, "processing.router")
		if router.Bound <= 0 || router.Held > router.Bound || (sparse && i == 100 && router.Held < 100) {
			t.Fatalf("sparse routing history not bounded or not exercised: %+v", router)
		}
		for _, name := range []string{"processing.pending_capacity", "processing.queue_capacity"} {
			if independentStore(t, now, name).Held > independentStore(t, warm, name).Held {
				t.Errorf("%s grows%d->%d at constant live population", name, independentStore(t, warm, name).Held, independentStore(t, now, name).Held)
			}
		}
	}
	stats := f.writer.DeliveryStats()
	if stats.Written != 10240*deliveryLines || stats.Pending != 0 {
		t.Fatalf("wiring, not the property: completed workload output %+v", stats)
	}
	if stats.Failed != 0 || stats.Dropped != 0 || f.store.Stats().FragmentsRefused != 0 || f.store.Stats().ConnectionsRefused != 0 {
		t.Errorf("constant-population run refused work: %+v intake%+v", stats, f.store.Stats())
	}
	t.Logf("PRECONDITIONS connections=10240 live_batches=0 written=%d retained=%+v", stats.Written, independentOccupancy(t, f.run))
}

func TestIndependentExtensionChurnReturnsTransientStores(t *testing.T) {
	for _, sparse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sparse_%v", sparse), func(t *testing.T) { independentExtensionHistory(t, sparse) })
	}
}

func independentExtensionHistory(t *testing.T, sparse bool) {
	events := make(chan extension.Event, 16)
	supervisor := extension.Start(extension.Config{Name: "retained", Command: []string{independentPeer(t), "--mode", "unchanged"}, Session: "retained", Revision: "retained", TimeoutMS: 1000, WaitingBytes: 64, Events: func(e extension.Event) {
		select {
		case events <- e:
		default:
		}
	}})
	defer supervisor.Close()
	deadline := time.After(5 * time.Second)
	ready := false
	for !ready {
		select {
		case e := <-events:
			ready = e.Kind == extension.Ready
		case <-deadline:
			t.Fatal("wiring, not the property: extension never became ready")
		}
	}
	completed := 0
	for i := uint64(1); i <= 40960; i++ {
		result := make(chan extension.Result, 1)
		id := i
		if sparse {
			id = 3*i + 7
		}
		why := supervisor.Submit(extension.Call{ID: id, Bytes: 8, Message: []byte(fmt.Sprintf("{\"type\":\"exchange\",\"id\":\"%d\"}\n", id)), Done: func(r extension.Result) { result <- r }})
		if why != "" {
			t.Fatalf("constant-population extension refused call%d: %s", i, why)
		}
		select {
		case r := <-result:
			if r.Outcome != "unchanged" {
				t.Fatalf("wiring, not the property: extension answered%+v", r)
			}
			completed++
		case <-time.After(time.Second):
			t.Fatal("wiring, not the property: extension did not answer")
		}
		for name, v := range independentOccupancy(t, supervisor) {
			limit := 0
			if name == "extension.answered" {
				limit = 1
				if sparse {
					limit = v.Bound
					if limit <= 0 || (i == 100 && v.Held != 100) {
						t.Fatalf("sparse answered history not exercised: %+v", v)
					}
				}
			}
			if v.Held > limit {
				t.Fatalf("%s retains%d at zero outstanding work (limit%d)", name, v.Held, limit)
			}
		}
	}
	counts := supervisor.Counts()
	for reason, n := range counts.RetiredBy {
		if n != 0 {
			t.Errorf("healthy churn retired extension: %s=%d", reason, n)
		}
	}
	if counts.DerivedRefused != 0 {
		t.Errorf("healthy churn refused derived output: %+v", counts)
	}
	t.Logf("PRECONDITIONS calls=%d live_outstanding=0 waiting_bytes_bound=64 per_call_bytes=8 stores=%+v", completed, independentOccupancy(t, supervisor))
}

func TestIndependentDerivedChurnReclaimsQueuedLines(t *testing.T) {
	clock := &independentClock{now: time.Unix(1900000000, 0), armed: make(chan time.Duration, 128)}
	ready := make(chan struct{}, 1)
	entered := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	quit := make(chan struct{})
	supervisor := extension.Start(extension.Config{
		Name: "derived-retained", Command: []string{independentPeer(t), "--mode", "derived-flood", "--count", "2"},
		Session: "retained", Revision: "retained", TimeoutMS: 1000, WaitingBytes: 64, Clock: clock,
		Issued: func() uint64 { return 1280 },
		Events: func(e extension.Event) {
			if e.Kind == extension.Ready {
				ready <- struct{}{}
			}
		},
		Derived: func([]byte) string {
			entered <- struct{}{}
			select {
			case <-release:
				return ""
			case <-quit:
				return extension.DerivedStopped
			}
		},
	})
	defer func() { close(quit); supervisor.Close() }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring, not the property: derived peer never ready")
	}
	for i := uint64(1); i <= 1280; i++ {
		result := make(chan extension.Result, 1)
		if why := supervisor.Submit(extension.Call{ID: i, Bytes: 8, Message: []byte(fmt.Sprintf("{\"type\":\"exchange\",\"id\":\"%d\"}\n", i)), Done: func(r extension.Result) { result <- r }}); why != "" {
			t.Fatalf("derived churn refused call: %s", why)
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("wiring, not the property: derived writer never entered")
		}
		deadline := time.Now().Add(time.Second)
		for independentStore(t, independentOccupancy(t, supervisor), "extension.derived").Held == 0 {
			if time.Now().After(deadline) {
				t.Fatal("wiring, not the property: second derived line never queued behind held write")
			}
			time.Sleep(time.Millisecond)
		}
		release <- struct{}{}
		release <- struct{}{}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("wiring, not the property: second derived write absent")
		}
		select {
		case r := <-result:
			if r.Outcome != extension.Unchanged {
				t.Fatalf("wiring, not the property: derived peer result %+v", r)
			}
		case <-time.After(time.Second):
			t.Fatal("wiring, not the property: derived peer unanswered")
		}
		for supervisor.Counts().DerivedWritten != i*2 {
			if time.Now().After(deadline) {
				t.Fatal("wiring, not the property: derived writes never completed")
			}
			time.Sleep(time.Millisecond)
		}
		if n := independentStore(t, independentOccupancy(t, supervisor), "extension.derived").Held; n != 0 {
			t.Errorf("derived queue retains %d at zero live lines", n)
		}
		clock.advance(time.Second)
	}
	counts := supervisor.Counts()
	if counts.DerivedRefused != 0 {
		t.Errorf("constant-population derived churn refused output: %+v", counts)
	}
	for reason, n := range counts.RetiredBy {
		if n != 0 {
			t.Errorf("healthy derived churn retired peer: %s=%d", reason, n)
		}
	}
	t.Logf("PRECONDITIONS queued_witnesses=1280 written=%d live_lines=0 stores=%+v", counts.DerivedWritten, independentOccupancy(t, supervisor))
}

func TestIndependentWaitingReadingsHoldExchangesAndBodyDecisions(t *testing.T) {
	clock := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 10000)}
	f := independentStart(t, independentPeer(t), "hold-first", `"remove":{"bodies":["request"]}`, []string{"request.line"}, 1, 0, 0, clock)
	feed(t, f.run, f.store, generate(t, workload.Shape{Connections: 1, Exchanges: 1, RequestBodyBytes: 120, Seed: 311}))
	independentEventually(t, "wiring, not the property: parsed exchange never waited on extension", func() bool {
		return independentOccupancy(t, f.run)["processing.waiting"].Held == 1
	})
	live := independentOccupancy(t, f.run)
	for _, name := range []string{"processing.waiting_exchanges", "processing.waiting_exchanges_capacity", "processing.waiting_bodies"} {
		v := independentStore(t, live, name)
		if v.Held == 0 {
			t.Fatalf("wiring, not the property: waiting batch did not positively exercise %s", name)
		}
	}
	clock.advance(time.Second)
	independentEventually(t, "extension timeout did not release waiting batch", func() bool {
		return f.run.Snapshot().Extensions[0].FailedBy["timeout"] == 1
	})
	for _, name := range []string{"processing.waiting", "processing.waiting_exchanges", "processing.waiting_exchanges_capacity", "processing.waiting_bodies"} {
		if v := independentStore(t, independentOccupancy(t, f.run), name); v.Held != 0 {
			t.Errorf("%s retained dead dispatch: %+v", name, v)
		}
	}
	t.Logf("PRECONDITIONS actual_peer=hold-first waiting_positive=%+v", live)
}

func TestIndependentIntakeSaturationAccountsQueuedAndLeasedBytes(t *testing.T) {
	for _, bound := range []int64{1024, 4096} {
		t.Run(fmt.Sprint(bound), func(t *testing.T) {
			for cycle := 0; cycle < 40; cycle++ {
				store, err := intake.New(bound)
				if err != nil {
					t.Fatal(err)
				}
				record := fragment.Record{Payload: []byte("held")}
				count := 0
				var charge int64
				for ; count < 128; count++ {
					err := store.Write(record)
					if errors.Is(err, intake.ErrLimit) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if count == 0 {
						charge = store.Stats().Bytes
					}
				}
				stats := store.Stats()
				if count == 0 || count == 128 || charge <= 0 || stats.Bytes > bound || bound-stats.Bytes >= charge || !stats.Exhausted {
					t.Fatalf("wiring, not the property: intake never saturated: count=%d charge=%d stats=%+v", count, charge, stats)
				}
				entries := make([]*intake.Entry, 0, count)
				for e := store.Take(); e != nil; e = store.Take() {
					entries = append(entries, e)
				}
				if s := store.Stats(); s.Queued != 0 || s.Leased != int64(count) || s.Bytes != stats.Bytes {
					t.Errorf("leasing lost charge: before=%+v after=%+v", stats, s)
				}
				if v := independentStore(t, independentOccupancy(t, store), "intake.entries"); v.Held != count {
					t.Errorf("leased entries not retained: %+v", v)
				}
				for _, e := range entries {
					e.Release()
				}
				if s := store.Stats(); s.Bytes != 0 || s.Leased != 0 {
					t.Errorf("release retained intake bytes: %+v", s)
				}
				if v := independentStore(t, independentOccupancy(t, store), "intake.entries"); v.Held != 0 {
					t.Errorf("released entries still retained: %+v", v)
				}
				_ = store.Close()
			}
			t.Logf("PRECONDITIONS full_intakes=40 byte_bound=%d queued_to_leased_to_released=true", bound)
		})
	}
}

func TestIndependentExtensionWaitingByteBoundRefusesExcess(t *testing.T) {
	for _, bound := range []int64{32, 128} {
		t.Run(fmt.Sprint(bound), func(t *testing.T) {
			ready := make(chan struct{}, 1)
			answers := make(chan extension.Result, 32)
			s := extension.Start(extension.Config{Name: "saturated", Command: []string{independentPeer(t), "--mode", "loop"}, Session: "saturated", Revision: "saturated", TimeoutMS: 60000, WaitingBytes: bound, Events: func(e extension.Event) {
				if e.Kind == extension.Ready {
					ready <- struct{}{}
				}
			}})
			defer s.Close()
			select {
			case <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("extension never ready")
			}
			count := int(bound / 8)
			for i := 1; i <= count; i++ {
				why := s.Submit(extension.Call{ID: uint64(i), Bytes: 8, Message: []byte(fmt.Sprintf("{\"type\":\"exchange\",\"id\":\"%d\"}\n", i)), Done: func(r extension.Result) { answers <- r }})
				if why != "" {
					t.Fatalf("declared waiting budget refused call %d: %s", i, why)
				}
			}
			if v := independentStore(t, independentOccupancy(t, s), "extension.outstanding"); v.Held != count {
				t.Fatalf("wiring, not the property: waiting population missing: %+v", v)
			}
			if why := s.Submit(extension.Call{ID: 999, Bytes: 8, Message: []byte("{}\n")}); why != extension.Busy {
				t.Errorf("waiting byte overflow answered %q", why)
			}
			s.Close()
			if len(answers) != count {
				t.Errorf("shutdown completed %d of %d waiting calls", len(answers), count)
			}
			for name, v := range independentOccupancy(t, s) {
				if v.Held != 0 {
					t.Errorf("%s retains closed extension work: %+v", name, v)
				}
			}
			t.Logf("PRECONDITIONS actual_peer=loop waiting_byte_bound=%d live_calls=%d excess_refused=1", bound, count)
		})
	}
}
