package processing_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

type refundSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	fail    bool
}

func (s *refundSink) Write(_ context.Context, b []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	if s.fail {
		return 0, errors.New("injected sink failure")
	}
	return len(b), nil
}
func (*refundSink) Reopen(context.Context) error { return nil }
func (*refundSink) Close(context.Context) error  { return nil }

func TestIndependentReservationsReturnAcrossProcessingOutcomes(t *testing.T) {
	for _, mode := range []string{"write", "enqueue", "sink_failure", "discard", "invalidation", "connection_cut"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			io := &refundSink{entered: make(chan struct{}), release: make(chan struct{}), fail: mode == "sink_failure"}
			var release sync.Once
			unblock := func() { release.Do(func() { close(io.release) }) }
			defer unblock()
			writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir(), QueueBytes: 1 << 20, OpenSink: func(string) sink.Sink { return io }})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { unblock(); _ = writer.Close() }()
			store, err := intake.New(1 << 20)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 64})
			if err != nil {
				t.Fatal(err)
			}
			bound := 32
			if mode == "connection_cut" {
				bound = 3
			}
			taken := 0
			worker, err := processing.New(processing.Options{Plan: deliveryPlan(t), PolicyRevision: "refund", Session: "refund", Intake: store, Gate: gate, Output: writer, ConnectionInput: bound, Taken: func(int, fragment.Process, fragment.ConnectionID) { taken++ }})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = worker.Close() }()
			entries := deliveryConnections(t, 1, 47)[0]
			if mode == "discard" {
				entries = entries[:len(entries)-1]
			}
			var slots []held.Slot
			for _, entry := range entries {
				kind := probe.DeliveryTransfer
				if entry.Connection != nil {
					kind = probe.DeliveryClose
				}
				d := gate.Admit(kind, true)
				if !d.Admitted || d.Slot == nil {
					t.Fatalf("wiring, not the property: reservation refused before input: %+v", d)
				}
				slots = append(slots, d.Slot)
				if entry.Fragment != nil {
					r := *entry.Fragment
					r.Slot = d.Slot
					err = store.Write(r)
				} else {
					r := *entry.Connection
					r.Slot = d.Slot
					err = store.Connection(r)
				}
				if err != nil {
					t.Fatalf("wiring, not the property: intake refused: %v", err)
				}
			}
			if store.Stats().Queued != int64(len(entries)) || gate.Snapshot().Charged != uint64(len(entries)) {
				t.Fatal("wiring, not the property: workload did not reach charged intake")
			}
			if mode == "invalidation" {
				// An unmeasured transfer invalidates the capture. Its slot is charged and,
				// kept by nothing, returned by the deliverer.
				fault := gate.Admit(probe.DeliveryTransfer, false)
				if fault.Slot == nil || gate.Snapshot().Reason != probe.GateUnknownLength {
					t.Fatal("wiring, not the property: invalidation absent")
				}
				fault.Slot.Refund(held.Unretained)
			}
			out, err := worker.Drain(ctx)
			if mode == "discard" {
				out, err = worker.Finish(ctx, processing.Finalization{})
			}
			if err != nil {
				t.Fatalf("worker drain: %v", err)
			}
			if taken != len(entries) {
				t.Fatalf("wiring, not the property: worker took%d want%d", taken, len(entries))
			}
			ordinary := mode == "write" || mode == "enqueue" || mode == "sink_failure"
			if ordinary {
				select {
				case <-io.entered:
				case <-ctx.Done():
					t.Fatal("wiring, not the property: no sink write reached its boundary")
				}
				if mode == "enqueue" && writer.DeliveryStats().Pending == 0 {
					t.Fatal("wiring, not the property: queue has no held output while sink blocked")
				}
			}
			if mode != "enqueue" {
				unblock()
				if err := writer.Drain(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "connection_cut" {
				if out.ConnectionsCut != 1 || out.InputCut != 4 || out.ProcessingFailures != 0 {
					t.Errorf("cut must count one connection and four transfers, not processing failure: %+v", out)
				}
			}
			before := gate.Snapshot()
			if before.Held != 0 || before.DoubleRefunds != 0 {
				t.Errorf("%s leaked or refunded twice: %+v", mode, before)
			}
			total := before.Refunded.Unretained + before.Refunded.Processed + before.Refunded.Discarded + before.Refunded.Cut
			if total != before.Charged {
				t.Errorf("refund conservation charged%d refunded%d", before.Charged, total)
			}
			if ordinary && before.Refunded.Processed != before.Charged {
				t.Errorf("processed input used wrong refund path: %+v", before)
			}
			for _, slot := range slots {
				if slot.Refund(held.Discarded) {
					t.Error("completed input retained a refundable slot")
				}
			}
			after := gate.Snapshot()
			if after.Held != 0 || after.Refunded != before.Refunded || after.DoubleRefunds != uint64(len(slots)) {
				t.Errorf("duplicate refunds changed conservation: before=%+v after=%+v", before, after)
			}
			if mode == "invalidation" && after.Reason != probe.GateUnknownLength {
				t.Error("refund cleared invalidation")
			}
			unblock()
			if err := writer.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			delivered := writer.DeliveryStats()
			if mode == "sink_failure" && (delivered.Failed == 0 || delivered.Written != 0) {
				t.Fatalf("wiring, not the property: injected sink failure not witnessed: %+v", delivered)
			}
			if ordinary && mode != "sink_failure" && delivered.Written != deliveryLines {
				t.Fatalf("wiring, not the property: complete workload wrote%d want%d", delivered.Written, deliveryLines)
			}
			t.Logf("PRECONDITIONS mode=%s admitted=%d taken=%d sink=%+v reservations=%+v", mode, len(slots), taken, delivered, before)
		})
	}
}

func TestIndependentExtensionFailureReturnsEveryReservation(t *testing.T) {
	f := independentStart(t, independentPeer(t), "crash", "", []string{"request.headers"}, 1, 0, 0, nil)
	// Slot ownership follows retained entries. This separate admission gate lets
	// the existing extension fixture expose those entries' charges independently.
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 64})
	if err != nil {
		t.Fatal(err)
	}
	entries := deliveryConnections(t, 1, 73)[0]
	var slots []held.Slot
	for _, entry := range entries {
		kind := probe.DeliveryTransfer
		if entry.Connection != nil {
			kind = probe.DeliveryClose
		}
		d := gate.Admit(kind, true)
		if !d.Admitted || d.Slot == nil {
			t.Fatal("wiring, not the property: charged extension input absent")
		}
		slots = append(slots, d.Slot)
		if entry.Fragment != nil {
			r := *entry.Fragment
			r.Slot = d.Slot
			err = f.store.Write(r)
		} else {
			r := *entry.Connection
			r.Slot = d.Slot
			err = f.store.Connection(r)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	f.run.Route()
	out := f.finish(t)
	if len(independentReceived(t, f)) == 0 || len(out.Extensions) != 1 || out.Extensions[0].Failed == 0 {
		t.Fatalf("wiring, not the property: actual extension did not receive input and fail: %+v", out.Extensions)
	}
	before := gate.Snapshot()
	if before.Held != 0 || before.Refunded.Processed != uint64(len(slots)) || before.DoubleRefunds != 0 {
		t.Errorf("extension failure leaked or mis-refunded: %+v", before)
	}
	for _, slot := range slots {
		if slot.Refund(held.Discarded) {
			t.Error("extension completion left a refundable reservation")
		}
	}
	after := gate.Snapshot()
	if after.Refunded != before.Refunded || after.DoubleRefunds != uint64(len(slots)) {
		t.Errorf("duplicate extension completion changed held input: %+v", after)
	}
}
