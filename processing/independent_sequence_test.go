package processing_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// These events model the published producer contract, not a TLS library: one
// observed birth, serial byte-moving calls numbered per direction, and terminal
// evidence supplied after production stops. Real probe attachment is not modelled.
type independentSequenceCapture struct {
	fragments []fragment.Record
	endings   []connection.Record
}

func (c *independentSequenceCapture) Write(r fragment.Record) error {
	c.fragments = append(c.fragments, r)
	return nil
}

func (c *independentSequenceCapture) Connection(r connection.Record) error {
	c.endings = append(c.endings, r)
	return nil
}

type independentSequenceSettler struct {
	settlement probe.Settlement
	err        error
	lookups    []probe.Handle
	unlocated  uint64
	reads      []uint64
}

func (s *independentSequenceSettler) Settled(h probe.Handle) (probe.Settlement, error) {
	s.lookups = append(s.lookups, h)
	return s.settlement, s.err
}

func (s *independentSequenceSettler) Unlocated() (uint64, error) {
	s.reads = append(s.reads, s.unlocated)
	return s.unlocated, nil
}

type independentSequenceFixture struct {
	captured independentSequenceCapture
	session  *capture.Session
	instance admission.Instance
	process  fragment.Process
	at       time.Time
	stamp    uint64
}

func independentSequenceNew(settler probe.Settler) *independentSequenceFixture {
	f := &independentSequenceFixture{
		instance: admission.Instance{Namespace: admission.Namespace{Device: 3, Inode: 7},
			PID: 71, Start: admission.Determinate(19), Generation: 1},
		process: fragment.Process{PID: 71, StartTime: 19},
		at:      time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
	f.session = capture.Recording(&f.captured, &f.captured, capture.Settles(settler))
	f.session.Observing(probe.Capability{Backend: probe.BPF, Payload: true, Lifecycle: true})
	return f
}

func (f *independentSequenceFixture) transfer(handle, number uint64, direction fragment.Direction, payload string) {
	f.stamp++
	f.session.Transfer(probe.Transfer{
		Process: f.process, Instance: f.instance, Endpoint: handle, Stamp: f.stamp,
		Sequence:  probe.Sequence{Occupancy: handle, Number: number, Born: true},
		Direction: direction, Length: uint32(len(payload)), Measured: true,
		Payload: []byte(payload), At: f.at,
	})
}

func (f *independentSequenceFixture) close(handle, sent, received uint64) {
	f.stamp++
	f.session.Closed(probe.Connection{
		Process: f.process, Instance: f.instance, Endpoint: handle, Stamp: f.stamp,
		Sequence: probe.Sequence{Occupancy: handle, Born: true},
		Final:    probe.Final{Known: true, Sent: probe.Terminal{Last: sent}, Received: probe.Terminal{Last: received}},
		At:       f.at,
	})
}

func (f *independentSequenceFixture) record(t *testing.T, handle uint64) connection.Record {
	t.Helper()
	var found []connection.Record
	for _, r := range f.captured.endings {
		if r.Handle.Address == handle {
			found = append(found, r)
		}
	}
	if len(found) == 0 {
		t.Fatalf("wiring, not the property: handle %d reached no retirement callback", handle)
	}
	if len(found) != 1 {
		t.Errorf("one occupancy was retired %d times for handle %d", len(found), handle)
	}
	return found[0]
}

func (f *independentSequenceFixture) guard(t *testing.T, fragments, endings int) {
	t.Helper()
	if len(f.captured.fragments) != fragments || len(f.captured.endings) != endings {
		t.Fatalf("wiring, not the property: capture callbacks fragments=%d endings=%d, want %d and %d",
			len(f.captured.fragments), len(f.captured.endings), fragments, endings)
	}
	for _, r := range f.captured.fragments {
		if err := r.Validate(); err != nil {
			t.Fatalf("wiring, not the property: invalid captured fragment: %v", err)
		}
	}
}

func (f *independentSequenceFixture) reached(t *testing.T, transfers int64) {
	t.Helper()
	if f.session.Stats().Transfers != transfers || len(f.captured.fragments) == 0 || len(f.captured.endings) == 0 {
		t.Fatalf("wiring, not the property: sent %d transfers, capture reports %+v with %d fragments and %d retirements",
			transfers, f.session.Stats(), len(f.captured.fragments), len(f.captured.endings))
	}
}

type independentSequenceOutput struct{ lines []processing.Artifact }

func (o *independentSequenceOutput) WriteApproved(_ context.Context, line processing.Approved) error {
	var a processing.Artifact
	if err := json.Unmarshal(line.Bytes(), &a); err != nil {
		return err
	}
	o.lines = append(o.lines, a)
	return nil
}

func (o *independentSequenceOutput) targets() []string {
	var targets []string
	for _, line := range o.lines {
		if line.Reconstruction == nil {
			continue
		}
		for _, e := range line.Reconstruction.Exchanges {
			if e.Request.Message != nil {
				targets = append(targets, e.Request.Message.Target)
			}
		}
	}
	return targets
}

func independentSequenceWorker(t *testing.T) (*processing.Worker, *intake.Store, *independentSequenceOutput, *int) {
	t.Helper()
	compiled, findings := config.Compile([]byte(`{"version":"observer.config/1","output":"/var/lib/observer","watch":[{"name":"service","exe":"/usr/bin/service"}]}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: configuration refused: %+v", findings)
	}
	store, err := intake.New(1 << 20)
	if err != nil {
		t.Fatalf("wiring, not the property: intake: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1000})
	if err != nil {
		t.Fatalf("wiring, not the property: gate: %v", err)
	}
	out := &independentSequenceOutput{}
	taken := new(int)
	w, err := processing.New(processing.Options{
		Plan: compiled.Plan, PolicyRevision: "sequence-fixture", Session: "sequence-fixture",
		Intake: store, Gate: gate, Output: out,
		Taken: func(int, fragment.Process, fragment.ConnectionID) { *taken++ },
	})
	if err != nil {
		t.Fatalf("wiring, not the property: worker: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, store, out, taken
}

func independentSequenceEnqueue(t *testing.T, store *intake.Store, fragments []fragment.Record, endings []connection.Record) {
	t.Helper()
	for _, r := range fragments {
		if err := store.Write(r); err != nil {
			t.Fatalf("wiring, not the property: fragment intake: %v", err)
		}
	}
	for _, r := range endings {
		if err := store.Connection(r); err != nil {
			t.Fatalf("wiring, not the property: retirement intake: %v", err)
		}
	}
}

func independentSequenceDrain(t *testing.T, w *processing.Worker, taken *int, want int) {
	t.Helper()
	if _, err := w.Drain(context.Background()); err != nil {
		t.Fatalf("wiring, not the property: drain failed: %v", err)
	}
	if *taken != want {
		t.Fatalf("wiring, not the property: worker took %d entries, want %d", *taken, want)
	}
}

const independentSequenceResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

func independentSequenceIncomplete(t *testing.T, r connection.Record, direction fragment.Direction) {
	t.Helper()
	p, ok := r.Placement(direction)
	if !ok {
		t.Fatalf("wiring, not the property: retirement has no placement for observed direction %v", direction)
	}
	if p.Whole() || p.Because == connection.ReasonUnset {
		t.Errorf("uncertain tail certified complete: %+v", p)
	}
}

func TestIndependentSequenceGapDoesNotNeedALossCounter(t *testing.T) {
	f := independentSequenceNew(&independentSequenceSettler{})
	f.transfer(11, 1, fragment.Sent, "GET /hole HTTP/1.1\r\nX-Sequence: ")
	f.transfer(22, 1, fragment.Sent, "GET /control HTTP/1.1\r\n\r\n")
	// Number two was produced but its reservation failed. Accounting may still
	// read zero; the sequence itself must keep the parseable splice ineligible.
	f.stamp++
	f.transfer(11, 3, fragment.Sent, "tail\r\n\r\n")
	f.transfer(11, 1, fragment.Received, independentSequenceResponse)
	f.transfer(22, 1, fragment.Received, independentSequenceResponse)
	f.close(11, 3, 1)
	f.close(22, 1, 1)
	f.reached(t, 5)
	bad := f.record(t, 11)
	w, store, out, taken := independentSequenceWorker(t)
	independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
	independentSequenceDrain(t, w, taken, len(f.captured.fragments)+len(f.captured.endings))
	independentSequenceIncomplete(t, bad, fragment.Sent)
	targets := out.targets()
	if len(targets) != 1 || targets[0] != "/control" {
		t.Errorf("a located hole must withhold only its connection; written targets %v", targets)
	}
}

func TestIndependentSequenceGapRemainsIncompleteAcrossCounterTiming(t *testing.T) {
	for _, before := range []bool{true, false} {
		name := "counter_after_transfer"
		if before {
			name = "counter_before_transfer"
		}
		t.Run(name, func(t *testing.T) {
			settler := &independentSequenceSettler{settlement: probe.Settlement{
				Occupancy: 11, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 3}, Received: probe.Terminal{Last: 1}},
			}}
			f := independentSequenceNew(settler)
			f.transfer(11, 1, fragment.Sent, "GET /hole HTTP/1.1\r\nX-Sequence: ")
			f.guard(t, 1, 0)
			if before {
				settler.unlocated = 1
			}
			f.stamp++
			f.transfer(11, 3, fragment.Sent, "tail\r\n\r\n")
			f.transfer(11, 1, fragment.Received, independentSequenceResponse)
			// The event carries its production-time count (zero); the producer's
			// independently sampled count rises on either side of its delivery.
			states := append(f.session.Live(f.at), f.captured.endings...)
			if len(states) == 0 {
				t.Fatal("wiring, not the property: capture reports no occupancy after the gap")
			}
			for _, state := range states {
				independentSequenceIncomplete(t, state, fragment.Sent)
			}
			settler.unlocated = 1
			finisher, ok := any(f.session).(interface{ Finish(time.Time) })
			if !ok {
				t.Fatal("wiring, not the property: capture has no settled Finish(time.Time) API")
			}
			finisher.Finish(f.at)
			if len(settler.reads) == 0 {
				t.Fatal("wiring, not the property: producer loss counter was never sampled")
			}
			f.reached(t, 3)
			w, store, out, taken := independentSequenceWorker(t)
			independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
			if _, err := w.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
				t.Fatalf("wiring, not the property: final worker: %v", err)
			}
			if *taken != len(f.captured.fragments)+len(f.captured.endings) {
				t.Fatalf("wiring, not the property: final worker consumed %d entries", *taken)
			}
			independentSequenceIncomplete(t, f.record(t, 11), fragment.Sent)
			if got := out.targets(); len(got) != 0 {
				t.Errorf("loss counter timing permitted an exchange spanning a missing number: %v", got)
			}
			t.Logf("counter values sampled by capture: %v", settler.reads)
		})
	}
}

func TestIndependentSequenceLateCallbackCannotBeSkipped(t *testing.T) {
	f := independentSequenceNew(&independentSequenceSettler{})
	f.transfer(11, 1, fragment.Sent, "GET /delayed HTTP/1.1\r\nX-Sequence: ")
	f.transfer(11, 2, fragment.Sent, "tail\r\n\r\n")
	f.transfer(11, 1, fragment.Received, independentSequenceResponse)
	f.close(11, 2, 1)
	f.guard(t, 3, 1)
	w, store, out, taken := independentSequenceWorker(t)
	// Capture has assigned the first callback its place, but it arrives at
	// intake after the retirement and the callbacks following it.
	independentSequenceEnqueue(t, store, f.captured.fragments[1:], f.captured.endings)
	independentSequenceDrain(t, w, taken, 3)
	if got := out.targets(); len(got) != 0 {
		t.Fatalf("exchange released before its delayed callback: %v", got)
	}
	independentSequenceEnqueue(t, store, f.captured.fragments[:1], nil)
	independentSequenceDrain(t, w, taken, 4)
	if got := out.targets(); len(got) != 1 || got[0] != "/delayed" {
		t.Errorf("settled callbacks did not yield the one correctly paired exchange: %v", got)
	}
	for n, want := range []uint64{1, 2, 1} {
		if got := f.captured.fragments[n].Produced; got != want {
			t.Errorf("callback %d lost producer sequence: got %d, want %d", n, got, want)
		}
	}
}

func TestIndependentSequenceLateOtherHandleCannotInvalidateACertifiedPrefix(t *testing.T) {
	f := independentSequenceNew(&independentSequenceSettler{})
	f.transfer(11, 1, fragment.Sent, "GET /prefix HTTP/1.1\r\n\r\n")
	f.transfer(11, 1, fragment.Received, independentSequenceResponse)
	// Another handle takes global stamp three but submits after stamp four.
	// Each handle's own direction remains serial and starts at number one.
	f.stamp = 3
	f.transfer(11, 2, fragment.Sent, "GET /hole HTTP/1.1\r\nX-Sequence: ")
	f.stamp = 2
	f.transfer(22, 1, fragment.Sent, "GET /other HTTP/1.1\r\n\r\n")
	// Stamp five (number three on handle eleven) loses its reservation.
	f.stamp = 5
	f.transfer(11, 4, fragment.Sent, "tail\r\n\r\n")
	f.transfer(22, 1, fragment.Received, independentSequenceResponse)
	f.transfer(11, 2, fragment.Received, independentSequenceResponse)
	f.close(11, 4, 2)
	f.close(22, 1, 1)
	f.reached(t, 7)
	w, store, out, taken := independentSequenceWorker(t)
	independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
	independentSequenceDrain(t, w, taken, len(f.captured.fragments)+len(f.captured.endings))
	independentSequenceIncomplete(t, f.record(t, 11), fragment.Sent)
	counts := make(map[string]int)
	for _, target := range out.targets() {
		counts[target]++
	}
	if len(counts) != 2 || counts["/prefix"] != 1 || counts["/other"] != 1 {
		t.Errorf("a late other-handle event changed a settled prefix or certified the hole: %v", counts)
	}
}

func TestIndependentSequenceLostLastTransferCannotCompleteCloseDelimitedBody(t *testing.T) {
	f := independentSequenceNew(&independentSequenceSettler{})
	f.transfer(11, 1, fragment.Sent, "GET /lost-last HTTP/1.1\r\n\r\n")
	f.transfer(11, 1, fragment.Received, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfirst")
	f.stamp++
	f.close(11, 1, 2)
	f.transfer(22, 1, fragment.Sent, "GET /control HTTP/1.1\r\n\r\n")
	f.transfer(22, 1, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nwhole")
	f.close(22, 1, 1)
	f.reached(t, 4)
	w, store, out, taken := independentSequenceWorker(t)
	independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
	independentSequenceDrain(t, w, taken, len(f.captured.fragments)+len(f.captured.endings))
	independentSequenceIncomplete(t, f.record(t, 11), fragment.Received)
	if got := out.targets(); len(got) != 1 || got[0] != "/control" {
		t.Errorf("close certified a lost final transfer, or refused the settled control: %v", got)
	}
}

func TestIndependentSequenceUnknownFinalProductionLeavesAnIncompleteTail(t *testing.T) {
	for _, tc := range []struct {
		name       string
		settlement probe.Settlement
		err        error
	}{
		{name: "unknown"},
		{name: "unreadable", err: errors.New("producer state unavailable")},
		{name: "reused", settlement: probe.Settlement{Occupancy: 12, Final: probe.Final{Known: true}}},
		{name: "in_flight", settlement: probe.Settlement{Occupancy: 11, Final: probe.Final{Known: true,
			Sent: probe.Terminal{Last: 1}, Received: probe.Terminal{Last: 1, InFlight: true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settler := &independentSequenceSettler{settlement: tc.settlement, err: tc.err}
			f := independentSequenceNew(settler)
			f.transfer(11, 1, fragment.Sent, "GET /unfinished HTTP/1.1\r\n\r\n")
			f.transfer(11, 1, fragment.Received, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfirst")
			f.guard(t, 2, 0)
			// A missing finalization API is an implementation absence, not evidence
			// that the completeness property itself failed.
			finisher, ok := any(f.session).(interface{ Finish(time.Time) })
			if !ok {
				t.Fatal("wiring, not the property: capture has no settled Finish(time.Time) API")
			}
			finisher.Finish(f.at)
			if len(settler.lookups) != 1 || settler.lookups[0] != (probe.Handle{Instance: f.instance.Key(), Endpoint: 11}) {
				t.Fatalf("wiring, not the property: finalization did not query the observed handle: %+v", settler.lookups)
			}
			f.guard(t, 2, 1)
			w, store, out, taken := independentSequenceWorker(t)
			independentSequenceEnqueue(t, store, f.captured.fragments, f.captured.endings)
			if _, err := w.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
				t.Fatalf("wiring, not the property: worker finalization: %v", err)
			}
			if *taken != 3 {
				t.Fatalf("wiring, not the property: final worker took %d entries, want three", *taken)
			}
			independentSequenceIncomplete(t, f.record(t, 11), fragment.Received)
			if got := out.targets(); len(got) != 0 {
				t.Errorf("unknown terminal evidence certified a close-delimited exchange: %v", got)
			}
		})
	}
}
