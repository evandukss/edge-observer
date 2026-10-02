package probe_test

import (
	"context"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/sink"
	"testing"
	"time"
)

func TestInvalidationBeforeEnqueueRefusesLine(t *testing.T) {
	var gate *probe.DeliveryGate
	var err error
	gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 10, BeforeAuthorize: func() { gate.Admit(probe.DeliveryTransfer, false) }})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	decision := gate.AuthorizeEnqueue(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}, func() { called = true })
	if decision.Authorized || called || decision.Reason != probe.GateUnknownLength {
		t.Fatalf("late enqueue: %+v called %t", decision, called)
	}
}

type heldAuthorizedSink struct {
	entered chan struct{}
	release chan struct{}
	line    []byte
}

func (s *heldAuthorizedSink) Write(_ context.Context, p []byte) (int, error) {
	close(s.entered)
	<-s.release
	s.line = append([]byte(nil), p...)
	return len(p), nil
}
func (*heldAuthorizedSink) Reopen(context.Context) error { return nil }
func (*heldAuthorizedSink) Close(context.Context) error  { return nil }

func TestAuthorizedQueuedLineSurvivesLaterInvalidation(t *testing.T) {
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	q, err := sink.NewQueue(64)
	if err != nil {
		t.Fatal(err)
	}
	destination := &heldAuthorizedSink{entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-destination.release:
		default:
			close(destination.release)
		}
		_ = q.Shutdown(context.Background())
	}()
	if err := q.Register("approved", destination); err != nil {
		t.Fatal(err)
	}
	line := []byte("{\"session\":\"authorized\"}\n")
	var queued error
	decision := gate.AuthorizeEnqueue(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}, func() { queued = q.Enqueue("approved", line) })
	if !decision.Authorized || queued != nil {
		t.Fatalf("enqueue: %+v %v", decision, queued)
	}
	select {
	case <-destination.entered:
	case <-time.After(time.Second):
		t.Fatal("wiring: sink write not entered")
	}
	fault := gate.Admit(probe.DeliveryTransfer, false)
	if fault.State.Reason != probe.GateUnknownLength {
		t.Fatalf("invalidation did not run while sink blocked: %+v", fault)
	}
	if st := q.Stats(); st.Pending != 1 || st.Written != 0 {
		t.Fatalf("queued control: %+v", st)
	}
	close(destination.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if st := q.Stats(); st.Written != 1 || st.Failed != 0 || st.Dropped != 0 || string(destination.line) != string(line) {
		t.Fatalf("previous authorization lost: %+v line %q", st, destination.line)
	}
}
func TestEnqueueBeforeInvalidationRemainsAuthorized(t *testing.T) {
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	evidence := probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}
	first := gate.AuthorizeEnqueue(evidence, func() { lines++ })
	fault := gate.Admit(probe.DeliveryTransfer, false)
	second := gate.AuthorizeEnqueue(evidence, func() { lines++ })
	if !first.Authorized || fault.State.Reason != probe.GateUnknownLength || second.Authorized || lines != 1 {
		t.Fatalf("ordered release: first %+v second %+v lines %d", first, second, lines)
	}
}
