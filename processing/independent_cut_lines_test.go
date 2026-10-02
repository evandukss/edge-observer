package processing_test

import (
	"context"
	"strconv"
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

// Library callbacks are modelled; capture, intake, reservations, processing and
// approved encoding are real. Per-direction numbers include refused transfers,
// and retirement carries their terminal numbers. No kernel behaviour is claimed.
type cutLinesFixture struct {
	t       *testing.T
	gate    *probe.DeliveryGate
	store   *intake.Store
	capture *capture.Session
	worker  *processing.Worker
	output  *outputLog
	numbers map[uint64]uint64
	taken   int
	stamp   uint64
}

func cutLinesStarted(t *testing.T, events uint64, bound int) *cutLinesFixture {
	t.Helper()
	f := &cutLinesFixture{t: t, output: &outputLog{}, numbers: map[uint64]uint64{}}
	var err error
	f.store, err = intake.New(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	f.gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: events})
	if err != nil {
		t.Fatal(err)
	}
	f.capture = capture.Recording(f.store, f.store)
	f.worker, err = processing.New(processing.Options{Session: "cut-lines", PolicyRevision: "cut-lines",
		Plan: deliveryPlan(t), Intake: f.store, Gate: f.gate, Output: f.output, ConnectionInput: bound,
		Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.worker.Close() })
	return f
}

func cutLinesIdentity() (fragment.Process, admission.Instance) {
	return fragment.Process{PID: 42, StartTime: 7}, admission.Instance{
		Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42,
		Start: admission.Determinate(7), Generation: 1,
	}
}

func (f *cutLinesFixture) transfer(handle uint64, admitted bool) {
	f.t.Helper()
	f.stamp++
	f.numbers[handle]++
	p, instance := cutLinesIdentity()
	// Incomplete framing keeps input pending until the held-input bound.
	const payload = "GET /waiting HTTP/1.1\r\n"
	d := f.gate.Admit(probe.DeliveryTransfer, true)
	if d.Admitted != admitted {
		f.t.Fatalf("wiring, not the property: handle %d transfer %d admission=%v, want %v: %+v",
			handle, f.numbers[handle], d.Admitted, admitted, d)
	}
	x := probe.Transfer{Process: p, Instance: instance, Endpoint: handle, Direction: fragment.Sent,
		Measured: true, Length: uint32(len(payload)), Payload: []byte(payload), Stamp: f.stamp,
		Sequence: probe.Sequence{Occupancy: handle, Number: f.numbers[handle], Born: true},
		At:       time.Now(), Slot: d.Slot}
	if d.Admitted {
		f.capture.Transfer(x)
	} else {
		f.capture.Refused(x)
	}
	if d.Slot != nil && !d.Slot.Kept() {
		d.Slot.Refund(held.Unretained)
	}
}

func (f *cutLinesFixture) retire(handle uint64) {
	f.t.Helper()
	f.stamp++
	p, instance := cutLinesIdentity()
	d := f.gate.Admit(probe.DeliveryClose, false)
	if !d.Admitted {
		f.t.Fatalf("wiring, not the property: retirement refused: %+v", d)
	}
	f.capture.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: handle,
		Sequence: probe.Sequence{Occupancy: handle, Born: true},
		Final:    probe.Final{Known: true, Sent: probe.Terminal{Last: f.numbers[handle]}},
		Stamp:    f.stamp, At: time.Now(), Slot: d.Slot})
	if d.Slot != nil && !d.Slot.Kept() {
		d.Slot.Refund(held.Unretained)
	}
}

func (f *cutLinesFixture) drain(taken int, final bool) processing.Outcome {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out processing.Outcome
	var err error
	if final {
		f.capture.Finish(time.Now())
		out, err = f.worker.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	} else {
		out, err = f.worker.Drain(ctx)
	}
	if err != nil {
		f.t.Fatalf("processing drain: %v", err)
	}
	if f.taken != taken {
		f.t.Fatalf("wiring, not the property: worker took %d entries, want %d", f.taken, taken)
	}
	return out
}

// Fill the gate with in-flight delivery reservations, then return those that
// retained nothing. This models delivery pressure without a second cut subject.
func (f *cutLinesFixture) pressure(count int) func() {
	f.t.Helper()
	var slots []held.Slot
	for range count {
		d := f.gate.Admit(probe.DeliveryTransfer, true)
		if !d.Admitted || d.Slot == nil {
			f.t.Fatalf("wiring, not the property: pressure reservation refused: %+v", d)
		}
		slots = append(slots, d.Slot)
	}
	return func() {
		for _, slot := range slots {
			slot.Refund(held.Unretained)
		}
	}
}

func (f *cutLinesFixture) reachedLoss(want uint64) {
	f.t.Helper()
	if f.gate.Snapshot().InputRefused != want || f.capture.Stats().GateRefused != int64(want) {
		f.t.Fatalf("wiring, not the property: gate loss did not reach capture: gate=%+v capture=%+v",
			f.gate.Snapshot(), f.capture.Stats())
	}
}

func (f *cutLinesFixture) check(out processing.Outcome, handles []uint64, cuts, input uint64) {
	f.t.Helper()
	if out.ConnectionsCut != cuts || out.InputCut != input {
		f.t.Errorf("cut accounting: connections_cut=%d input_cut=%d, want %d and %d", out.ConnectionsCut, out.InputCut, cuts, input)
	}
	retirements := 0
	for _, line := range f.output.artifacts {
		if line.Record == processing.ArtifactConnection {
			retirements++
		}
	}
	if retirements != len(handles) {
		f.t.Errorf("retirement population=%d, want %d", retirements, len(handles))
	}
	for _, handle := range handles {
		var lines []processing.Artifact
		for _, line := range f.output.artifacts {
			if line.Record == processing.ArtifactConnection && line.Connection.Handle.Address == strconv.FormatUint(handle, 10) {
				lines = append(lines, line)
			}
		}
		if len(lines) != 1 {
			f.t.Errorf("handle %d has %d connection lines after retirement, want exactly one", handle, len(lines))
			continue
		}
		tr := lines[0].ReconstructionTruncation
		if tr == nil || tr.State != "truncated" || tr.Suffix != "indeterminate" || len(tr.Stops) == 0 {
			f.t.Errorf("handle %d has no explicit incomplete suffix: %+v", handle, tr)
			continue
		}
		found := false
		for _, stop := range tr.Stops {
			if cuts == 0 && stop.Reason == "connection_cut" {
				f.t.Errorf("gate loss on handle %d is mislabeled connection_cut: %+v", handle, stop)
			}
			if stop.Direction == "sent" {
				found = true
				// ACCOUNT.md processing and record.md require bound cuts at byte 0.
				if cuts != 0 && (stop.Reason != "connection_cut" || stop.Offset != "0") {
					f.t.Errorf("bound cut on handle %d must stop at 0 for connection_cut: %+v", handle, stop)
				}
			}
		}
		if !found {
			f.t.Errorf("handle %d lacks a truncation stop for its sent input", handle)
		}
	}
	state := f.gate.Snapshot()
	total := state.Refunded.Unretained + state.Refunded.Processed + state.Refunded.Discarded + state.Refunded.Cut
	if state.Held != 0 || state.DoubleRefunds != 0 || total != state.Charged {
		f.t.Errorf("reservations after drain: held=%d double_refunds=%d refunded=%d charged=%d", state.Held, state.DoubleRefunds, total, state.Charged)
	}
}

func TestIndependentGateLossHasALineWithoutCountingABoundCut(t *testing.T) {
	f := cutLinesStarted(t, 2, 8)
	f.transfer(11, true)
	f.transfer(11, true)
	f.transfer(11, false)
	f.reachedLoss(1)
	f.drain(2, false)
	f.retire(11)
	out := f.drain(3, false)
	f.check(out, []uint64{11}, 0, 0)
}

func TestIndependentBoundCutKeepsItsLineAfterGateLoss(t *testing.T) {
	f := cutLinesStarted(t, 8, 3)
	for range 4 {
		f.transfer(21, true)
	}
	f.drain(4, false)
	release := f.pressure(8)
	f.transfer(21, false)
	f.reachedLoss(1)
	release()
	f.retire(21)
	out := f.drain(5, false)
	f.check(out, []uint64{21}, 1, 4)
}

func TestIndependentSeveralBoundCutsEachKeepOneRetirementLine(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run("gate_loss="+strconv.FormatBool(loss), func(t *testing.T) {
			f := cutLinesStarted(t, 32, 3)
			handles := []uint64{31, 32, 33}
			for range 4 {
				for _, handle := range handles {
					f.transfer(handle, true)
				}
			}
			if f.capture.Open() != len(handles) {
				t.Fatal("wiring, not the property: simultaneous live connections not reached")
			}
			f.drain(12, false)
			if loss {
				release := f.pressure(32)
				for _, handle := range handles {
					f.transfer(handle, false)
				}
				f.reachedLoss(3)
				release()
			}
			for _, handle := range handles {
				f.retire(handle)
			}
			out := f.drain(15, false)
			f.check(out, handles, 3, 12)
		})
	}
}

func TestIndependentBoundCutRetirementSurvivesTheFinalDrain(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run("gate_loss="+strconv.FormatBool(loss), func(t *testing.T) {
			f := cutLinesStarted(t, 8, 3)
			for range 4 {
				f.transfer(41, true)
			}
			f.drain(4, false)
			if loss {
				release := f.pressure(8)
				f.transfer(41, false)
				f.reachedLoss(1)
				release()
			}
			f.retire(41)
			if f.store.Stats().Queued != 1 {
				t.Fatal("wiring, not the property: retirement is not waiting for the final drain")
			}
			out := f.drain(5, true)
			f.check(out, []uint64{41}, 1, 4)
		})
	}
}
