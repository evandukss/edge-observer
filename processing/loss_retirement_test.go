package processing_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// refuseInput exercises the gate before notifying capture, as the delivery loop
// does. The counter and full gate guard distinguish a real refusal from a token
// set directly by a fixture.
func refuseInput(t *testing.T, p *pipeline, handle uint64) {
	t.Helper()
	d := p.gate.Admit(probe.DeliveryTransfer, true)
	if d.Admitted || d.State.Reason != probe.GateInputLimit || p.gate.Snapshot().Held != p.gate.Snapshot().MaxEvents {
		t.Fatalf("wiring, not the property: input did not reach the full gate: %+v", d)
	}
	p.numbers[handle][fragment.Sent]++
	p.capture.Refused(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: handle,
		Direction: fragment.Sent, Measured: true, Length: 1, At: p.at,
		Sequence: probe.Sequence{Occupancy: p.of(handle), Number: p.numbers[handle][fragment.Sent], Born: true}})
	if p.capture.Stats().GateRefused == 0 {
		t.Fatal("wiring, not the property: capture did not receive the refused transfer")
	}
}

func returnedReservations(t *testing.T, p *pipeline) {
	t.Helper()
	s := p.gate.Snapshot()
	if s.Held != 0 {
		t.Errorf("held reservations after drain = %d, want 0", s.Held)
	}
	if s.DoubleRefunds != 0 {
		t.Errorf("double refunds = %d, want 0", s.DoubleRefunds)
	}
	if p.store.Stats().Bytes != 0 {
		t.Errorf("intake still holds input after drain: %+v", p.store.Stats())
	}
}

func retirementLine(t *testing.T, out *outputLog, handle uint64, reason string) {
	t.Helper()
	var lines []processing.Artifact
	for _, a := range out.artifacts {
		if a.Connection.Handle.Address == strconv.FormatUint(handle, 10) {
			if a.Record == processing.ArtifactExchange {
				t.Errorf("discarded input produced an exchange for handle %d", handle)
			}
			if a.Record == processing.ArtifactConnection {
				lines = append(lines, a)
			}
		}
	}
	if len(lines) != 1 {
		t.Errorf("handle %d has %d retirement lines, want exactly one", handle, len(lines))
		return
	}
	tr := lines[0].ReconstructionTruncation
	if tr == nil || tr.State != "truncated" || tr.Suffix != "indeterminate" || len(tr.Stops) == 0 {
		t.Errorf("handle %d has no loss/cut truncation: %+v", handle, tr)
		return
	}
	for _, stop := range tr.Stops {
		if stop.Reason != reason {
			t.Errorf("handle %d stop reason = %q, want %q", handle, stop.Reason, reason)
		}
		if stop.Offset != "0" {
			t.Errorf("handle %d discarded prefix stops at %s, want 0", handle, stop.Offset)
		}
		if stop.EvidenceOffset == "0" {
			t.Errorf("handle %d lost its discarded-input reach: %+v", handle, stop)
		}
	}
}

func TestGateLossWritesItsRetirementWithoutCountingABoundCut(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 4, 100, out)
	p.exchange(1, "/lost")
	p.exchange(2, "/neighbor")
	if p.store.Stats().Fragments != 4 {
		t.Fatal("wiring, not the property: four transfers were not stored")
	}
	refuseInput(t, p, 1)
	p.closed(1)
	p.closed(2)
	o := p.drain()
	if o.ConnectionsCut != 0 || o.InputCut != 0 {
		t.Errorf("gate loss counted as bound cut: connections=%d input=%d", o.ConnectionsCut, o.InputCut)
	}
	if s := p.gate.Snapshot(); s.InputRefused != 1 || p.capture.Stats().GateRefused != 1 {
		t.Errorf("gate refusal not counted once: %+v %+v", s, p.capture.Stats())
	}
	retirementLine(t, out, 1, "positions_unknown")
	returnedReservations(t, p)
}

func TestABoundCutThenGateLossWritesOneCutRetirement(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 4, 3, out)
	p.exchange(1, "/cut")
	p.transfer(1, fragment.Sent, "GET /more HTTP/1.1\r\n\r\n")
	first := p.drain()
	if first.ConnectionsCut != 1 || first.InputCut != 3 || p.gate.Snapshot().Held != 0 {
		t.Fatalf("wiring, not the property: initial connection did not reach its bound: %+v", first)
	}
	p.exchange(2, "/neighbor-a")
	p.exchange(3, "/neighbor-b")
	refuseInput(t, p, 1)
	p.closed(1)
	p.closed(2)
	p.closed(3)
	o := p.drain()
	if o.ConnectionsCut != 1 || o.InputCut != 3 {
		t.Errorf("bound cut counted again after loss: connections=%d input=%d", o.ConnectionsCut, o.InputCut)
	}
	retirementLine(t, out, 1, processing.TruncationConnectionCut)
	returnedReservations(t, p)
}

func TestSimultaneousBoundCutsEachWriteTheirRetirement(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 9, 3, out)
	for h := uint64(1); h <= 3; h++ {
		p.exchange(h, fmt.Sprintf("/burst-%d", h))
		p.transfer(h, fragment.Sent, "GET /more HTTP/1.1\r\n\r\n")
	}
	if p.store.Stats().Fragments != 9 || p.gate.Snapshot().Held != 9 {
		t.Fatal("wiring, not the property: three simultaneous batches did not reach their bounds")
	}
	for h := uint64(1); h <= 3; h++ {
		refuseInput(t, p, h)
		p.closed(h)
	}
	o := p.drain()
	if o.ConnectionsCut != 3 || o.InputCut != 9 {
		t.Errorf("simultaneous cuts miscounted: connections=%d input=%d", o.ConnectionsCut, o.InputCut)
	}
	for h := uint64(1); h <= 3; h++ {
		retirementLine(t, out, h, processing.TruncationConnectionCut)
	}
	returnedReservations(t, p)
}

func TestABoundCutKeepsItsRetirementThroughTheFinalDrain(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 4, 3, out)
	p.exchange(1, "/long")
	p.transfer(1, fragment.Sent, "GET /more HTTP/1.1\r\n\r\n")
	first := p.drain()
	if first.ConnectionsCut != 1 || first.InputCut != 3 {
		t.Fatalf("wiring, not the property: long connection never reached its bound: %+v", first)
	}
	p.exchange(2, "/burst-a")
	p.exchange(3, "/burst-b")
	refuseInput(t, p, 1)
	p.closed(2)
	p.closed(3)
	p.drain()
	returnedReservations(t, p)
	before := p.store.Stats().Connections
	p.closed(1)
	if p.store.Stats().Connections != before+1 || p.store.Stats().Queued != 1 {
		t.Fatal("wiring, not the property: retirement did not arrive only in the final queue")
	}
	o, err := p.worker.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatal(err)
	}
	if o.ConnectionsCut != 1 || o.InputCut != 3 {
		t.Errorf("final cut counted more than once: connections=%d input=%d", o.ConnectionsCut, o.InputCut)
	}
	retirementLine(t, out, 1, processing.TruncationConnectionCut)
	returnedReservations(t, p)
}
