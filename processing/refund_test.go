package processing_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// pipeline is a session's path from the delivery gate to the output, with the
// delivery loop's part played here as the attachment plays it: each event is
// admitted, its slot travels with it into capture, and a slot no store kept is
// returned as soon as capture has returned.
type pipeline struct {
	t       *testing.T
	gate    *probe.DeliveryGate
	store   *intake.Store
	capture *capture.Session
	worker  *processing.Worker
	// occupancy is each handle's occupancy now, and numbers what it has taken in
	// each direction.
	occupancy map[uint64]uint64
	numbers   map[uint64]map[fragment.Direction]uint64
	at        time.Time
}

var pipelineProcess = fragment.Process{PID: 42, StartTime: 7}

var pipelineInstance = admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42,
	Start: admission.Determinate(7), Generation: 1}

func newPipeline(t *testing.T, events uint64, connectionInput int, output processing.Output) *pipeline {
	t.Helper()
	store, err := intake.New(1 << 28)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: events, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	w, err := processing.New(processing.Options{Session: "refund-session", Plan: rulesPlan(t, ""),
		PolicyRevision: "refund-policy", Intake: store, Gate: gate, Output: output, ConnectionInput: connectionInput})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return &pipeline{t: t, gate: gate, store: store, capture: capture.Recording(store, store), worker: w,
		occupancy: map[uint64]uint64{}, numbers: map[uint64]map[fragment.Direction]uint64{},
		at: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
}

// of is the occupancy a handle is in, its first unless reused.
func (p *pipeline) of(handle uint64) uint64 {
	if p.occupancy[handle] == 0 {
		p.occupancy[handle] = handle
	}
	return p.occupancy[handle]
}

// reuse begins the handle's next occupancy, numbered from one.
func (p *pipeline) reuse(handle uint64) {
	p.occupancy[handle] = p.of(handle) + 1000
	p.numbers[handle] = nil
}

// unkept returns a slot no store kept, as the delivery loop does.
func unkept(slot held.Slot) {
	if slot != nil && !slot.Kept() {
		slot.Refund(held.Unretained)
	}
}

// transfer delivers one measured transfer on a handle's one occupancy, numbered
// in its direction as the producer numbers it.
func (p *pipeline) transfer(handle uint64, direction fragment.Direction, text string) {
	p.t.Helper()
	decision := p.gate.Admit(probe.DeliveryTransfer, true)
	if !decision.Admitted {
		unkept(decision.Slot)
		return
	}
	if p.numbers[handle] == nil {
		p.numbers[handle] = map[fragment.Direction]uint64{}
	}
	p.numbers[handle][direction]++
	p.at = p.at.Add(time.Millisecond)
	p.capture.Transfer(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: handle,
		Direction: direction, Measured: true, Length: uint32(len(text)), Payload: []byte(text),
		Sequence: probe.Sequence{Occupancy: p.of(handle), Number: p.numbers[handle][direction], Born: true},
		At:       p.at, Slot: decision.Slot})
	unkept(decision.Slot)
}

// empty delivers a call that moved nothing and took no number.
func (p *pipeline) empty(handle uint64) {
	p.t.Helper()
	decision := p.gate.Admit(probe.DeliveryTransfer, true)
	p.capture.Transfer(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: handle,
		Direction: fragment.Sent, Measured: true, At: p.at, Slot: decision.Slot})
	unkept(decision.Slot)
}

// nothing delivers a call that moved nothing and took its direction's next
// number, as an out-parameter read that would block does.
func (p *pipeline) nothing(handle uint64, direction fragment.Direction) {
	p.t.Helper()
	decision := p.gate.Admit(probe.DeliveryTransfer, true)
	if p.numbers[handle] == nil {
		p.numbers[handle] = map[fragment.Direction]uint64{}
	}
	p.numbers[handle][direction]++
	p.at = p.at.Add(time.Millisecond)
	p.capture.Transfer(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: handle,
		Direction: direction, Measured: true,
		Sequence: probe.Sequence{Occupancy: p.of(handle), Number: p.numbers[handle][direction], Born: true},
		At:       p.at, Slot: decision.Slot})
	unkept(decision.Slot)
}

// closed delivers the handle's release with its occupancy's last numbers.
func (p *pipeline) closed(handle uint64) {
	p.t.Helper()
	decision := p.gate.Admit(probe.DeliveryClose, false)
	if !decision.Admitted {
		unkept(decision.Slot)
		return
	}
	p.at = p.at.Add(time.Millisecond)
	p.capture.Closed(probe.Connection{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: handle,
		Sequence: probe.Sequence{Occupancy: p.of(handle), Born: true},
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: p.numbers[handle][fragment.Sent]},
			Received: probe.Terminal{Last: p.numbers[handle][fragment.Received]}},
		At: p.at, Slot: decision.Slot})
	unkept(decision.Slot)
}

// exchange delivers one complete request and response on a handle.
func (p *pipeline) exchange(handle uint64, path string) {
	p.t.Helper()
	p.transfer(handle, fragment.Sent, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n")
	p.transfer(handle, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
}

func (p *pipeline) drain() processing.Outcome {
	p.t.Helper()
	o, err := p.worker.Drain(context.Background())
	if err != nil {
		p.t.Fatal(err)
	}
	return o
}

// Every slot comes back through the path its input took - processed, never
// retained, cut, or discarded unprocessed - and nothing is held after the
// drain or returned twice.
func TestEverySlotReturnsThroughThePathItsInputTook(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 64, 4, out)

	p.exchange(1, "/processed")
	p.closed(1)
	p.empty(5)
	p.closed(99)
	for i := 0; i < 3; i++ {
		p.exchange(2, fmt.Sprintf("/cut-%d", i))
	}
	p.closed(2)
	p.transfer(3, fragment.Sent, "GET /pending HTTP/1.1\r\n\r\n")
	o := p.drain()
	if err := p.worker.Close(); err != nil {
		t.Fatal(err)
	}

	state := p.gate.Snapshot()
	// Wiring, not the property: each path's fixture reached the gate.
	if state.Charged != 13 || o.ConnectionsCut != 1 || o.InputCut != 6 {
		t.Fatalf("wiring, not the property: charged %d, cut %d connections and %d entries; want 13, 1 and 6",
			state.Charged, o.ConnectionsCut, o.InputCut)
	}
	want := probe.Refunds{Unretained: 2, Processed: 4, Cut: 6, Discarded: 1}
	if state.Held != 0 || state.Refunded != want || state.DoubleRefunds != 0 {
		t.Fatalf("after the drain the gate reads held %d, refunded %+v, double %d; want 0, %+v, 0",
			state.Held, state.Refunded, state.DoubleRefunds, want)
	}
}

// A line the sink refuses and an invalidation that refuses release still
// return every slot their input held, and a refund leaves the invalidation in
// place.
func TestARefusedLineAndAnInvalidationStillReturnEverySlot(t *testing.T) {
	refusing := outputFunc(func(context.Context, processing.Approved) error { return errors.New("sink queue is full") })
	p := newPipeline(t, 64, 0, refusing)
	p.exchange(1, "/refused-by-the-sink")
	p.closed(1)
	o := p.drain()
	if o.OutputFailures == 0 {
		t.Fatalf("wiring, not the property: the refusing sink was never offered a line: %+v", o)
	}
	if state := p.gate.Snapshot(); state.Held != 0 || state.Refunded.Processed != 3 {
		t.Fatalf("a connection whose lines the sink refused left the gate %+v; want none held, three processed", state)
	}

	out := &outputLog{}
	p = newPipeline(t, 64, 0, out)
	p.exchange(1, "/released-after-invalidation")
	unknown := p.gate.Admit(probe.DeliveryTransfer, false)
	unkept(unknown.Slot)
	if unknown.State.Reason != probe.GateUnknownLength {
		t.Fatalf("wiring, not the property: the unmeasured transfer did not invalidate: %+v", unknown)
	}
	p.capture.Closed(probe.Connection{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1,
		Sequence: probe.Sequence{Occupancy: 1, Born: true}, Final: probe.Final{Known: true,
			Sent: probe.Terminal{Last: 1}, Received: probe.Terminal{Last: 1}}, At: p.at.Add(time.Second)})
	p.drain()
	state := p.gate.Snapshot()
	if len(out.artifacts) != 0 {
		t.Fatalf("a line was released after the invalidation: %d", len(out.artifacts))
	}
	if state.Held != 0 || state.Reason != probe.GateUnknownLength {
		t.Fatalf("after the invalidated connection was processed the gate reads %+v; want none held and %s kept",
			state, probe.GateUnknownLength)
	}
}

// One connection of 2048 exchanges, holding fewer entries than one connection
// may, is written whole: no limit counts what a connection carried.
func TestALongConnectionBelowTheBoundIsWrittenWhole(t *testing.T) {
	const exchanges = 2048
	out := &outputLog{}
	p := newPipeline(t, 16384, 0, out)
	for i := 0; i < exchanges; i++ {
		p.exchange(1, fmt.Sprintf("/%d", i))
	}
	p.closed(1)
	o := p.drain()
	if held := p.gate.Snapshot().Charged; held != 2*exchanges+1 {
		t.Fatalf("wiring, not the property: %d events charged, want %d", held, 2*exchanges+1)
	}
	if o.ConnectionsCut != 0 {
		t.Fatalf("a connection of %d entries was cut under the default bound: %+v", 2*exchanges, o)
	}
	written := 0
	for _, a := range out.artifacts {
		if a.Record == processing.ArtifactExchange {
			written++
		}
	}
	if written != exchanges {
		t.Fatalf("%d of %d exchanges written", written, exchanges)
	}
	if state := p.gate.Snapshot(); state.Held != 0 {
		t.Fatalf("%d slots still held after the connection was written", state.Held)
	}
}

// A read that would block between two exchanges of one connection takes a
// number and moves nothing. The exchange after it is written as the one
// before it is, nothing is cut, and nothing fails.
func TestAnExchangeAfterACallThatMovedNothingIsWritten(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 64, 0, out)
	p.exchange(1, "/before")
	p.nothing(1, fragment.Received)
	p.nothing(1, fragment.Received)
	p.exchange(1, "/after")
	p.closed(1)
	o := p.drain()
	if p.capture.Stats().Empty != 2 {
		t.Fatalf("wiring, not the property: capture counted %d empty transfers, want the 2 delivered", p.capture.Stats().Empty)
	}
	byPath := map[string]int{}
	for _, a := range out.artifacts {
		if a.Record == processing.ArtifactExchange {
			byPath[a.Reconstruction.Exchanges[0].Request.Message.Target]++
		}
	}
	if byPath["/before"] != 1 || byPath["/after"] != 1 || len(byPath) != 2 {
		t.Errorf("the exchanges either side of two reads that moved nothing were written as %v, want each once", byPath)
	}
	if o.ProcessingFailures != 0 || o.ConnectionsCut != 0 {
		t.Errorf("the connection counts %d processing failures and %d cuts, want none: %+v", o.ProcessingFailures,
			o.ConnectionsCut, o)
	}
}

// One connection reaching the bound on what a connection may hold is cut
// there: what it held and what it sends afterwards is discarded and counted,
// its connection line says where its input stopped and why, the handle's next
// occupancy is processed as usual, and so is every other connection.
func TestAConnectionPastTheBoundIsCutAndTheSessionGoesOn(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 256, 8, out)
	for i := 0; i < 10; i++ {
		p.exchange(1, fmt.Sprintf("/held-%d", i))
	}
	p.exchange(7, "/beside")
	p.closed(7)
	p.closed(1)
	o := p.drain()
	if o.ConnectionsCut != 1 || o.InputCut != 20 {
		t.Fatalf("one connection of 20 entries past a bound of 8: cut %d connections and %d entries", o.ConnectionsCut, o.InputCut)
	}
	byPath := map[string]int{}
	var cutLine *processing.Artifact
	for i, a := range out.artifacts {
		switch a.Record {
		case processing.ArtifactExchange:
			byPath[a.Reconstruction.Exchanges[0].Request.Message.Target]++
		case processing.ArtifactConnection:
			if a.ReconstructionTruncation != nil {
				cutLine = &out.artifacts[i]
			}
		}
	}
	if byPath["/beside"] != 1 {
		t.Errorf("the connection beside the cut one was not written: %v", byPath)
	}
	for path := range byPath {
		if path != "/beside" {
			t.Errorf("an exchange of the cut connection was written: %s", path)
		}
	}
	if cutLine == nil {
		t.Fatal("the cut connection has no connection line naming its truncation")
	}
	if len(cutLine.ReconstructionTruncation.Stops) != 2 {
		t.Fatalf("the cut connection's line stops %d directions, want both: %+v", len(cutLine.ReconstructionTruncation.Stops),
			cutLine.ReconstructionTruncation)
	}
	for _, stop := range cutLine.ReconstructionTruncation.Stops {
		if stop.Reason != processing.TruncationConnectionCut || stop.Offset != "0" || stop.EvidenceOffset == "0" {
			t.Errorf("a cut direction stops at %s (evidence %s) for %s; want offset 0, the input's reach, and %s",
				stop.Offset, stop.EvidenceOffset, stop.Reason, processing.TruncationConnectionCut)
		}
	}

	// The handle's next occupancy begins from its own origin and is processed.
	p.reuse(1)
	p.exchange(1, "/after-the-cut")
	p.closed(1)
	p.drain()
	found := false
	for _, a := range out.artifacts {
		if a.Record == processing.ArtifactExchange && a.Reconstruction.Exchanges[0].Request.Message.Target == "/after-the-cut" {
			found = true
		}
	}
	if !found {
		t.Error("the connection after the cut one was not written")
	}
	if state := p.gate.Snapshot(); state.Held != 0 || state.Reason != "" {
		t.Errorf("after the cut the gate reads %+v; want none held and no invalidation", state)
	}
}

// Connections come and go, each processed whole, at a live population of one:
// what processing and the intake hold returns to nothing between them.
func TestChurnedConnectionsLeaveProcessingHoldingOnlyTheLiveOnes(t *testing.T) {
	const connections = 2000
	out := &outputLog{}
	p := newPipeline(t, 64, 0, out)
	for i := 0; i < connections; i++ {
		handle := uint64(i%3 + 1)
		p.reuse(handle)
		p.exchange(handle, fmt.Sprintf("/%d", i))
		p.closed(handle)
		p.drain()
	}
	if len(out.artifacts) != 2*connections {
		t.Fatalf("wiring, not the property: %d lines for %d connections", len(out.artifacts), connections)
	}
	stores, err := p.worker.Retained()
	if err != nil {
		t.Fatal(err)
	}
	intake, err := p.store.Retained()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range append(stores, intake...) {
		if one.Held != 0 {
			t.Errorf("%s holds %d after %d connections came and went, want none", one.Store, one.Held, connections)
		}
	}
	if state := p.gate.Snapshot(); state.Held != 0 || state.Charged != 3*connections {
		t.Errorf("the gate reads %+v after %d connections of three events each, want none held", state, connections)
	}
}
