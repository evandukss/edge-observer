package processing_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
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

func TestIndependentCaptureChurnKeepsOnlyLiveIdentity(t *testing.T) {
	f := independentSequenceNew(&independentSequenceSettler{})
	f.transfer(1, 1, fragment.Sent, "pinned")
	first := independentOccupancy(t, f.session)
	if first["capture.streams"].Held != 1 || len(f.captured.fragments) != 1 {
		t.Fatal("wiring, not the property: pinned live connection absent")
	}
	for i := uint64(2); i <= 161; i++ {
		f.transfer(i, 1, fragment.Sent, "ephemeral")
		f.close(i, 1, 0)
	}
	if len(f.captured.endings) != 160 || f.session.Open() != 1 {
		t.Fatal("wiring, not the property: churn did not reach160 retirements beside pinned connection")
	}
	after := independentOccupancy(t, f.session)
	for _, name := range []string{"capture.streams", "capture.occupancies", "capture.closed", "capture.early", "capture.settlers"} {
		limit := 0
		if name == "capture.streams" || name == "capture.occupancies" || name == "capture.settlers" {
			limit = 1
		}
		if v := after[name]; v.Held > limit {
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
		if live["capture.early"].Held == 0 {
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
	for i := uint64(1); i <= 160; i++ {
		f := independentSequenceNew(nil)
		f.transfer(i, 1, fragment.Sent, fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: x\r\n\r\n", i))
		f.transfer(i, 1, fragment.Received, independentSequenceResponse)
		f.close(i, 1, 1)
		// Capture ids are session-local: this fixture's separate captures each began
		// at one, so give their records the unique identity of this worker's input.
		for j := range f.captured.fragments {
			f.captured.fragments[j].Connection = fragment.ConnectionID(i)
		}
		for j := range f.captured.endings {
			f.captured.endings[j].ID = fragment.ConnectionID(i)
		}
		independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
		before := independentOccupancy(t, store)
		if before["intake.entries"].Held != 3 {
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
	if !d.Slot.Kept() || e.Fragment.Slot != d.Slot {
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
