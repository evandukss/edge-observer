package processing

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/sink"
)

func TestReleaseCutoffDoesNotWaitForAuthorizationHold(t *testing.T) {
	reached, unblock := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 16, BeforeAuthorize: func() {
		if calls.Add(1) == 2 {
			close(reached)
			<-unblock
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	target := &mirroredLines{}
	w, err := OpenWriter(WriterOptions{Directory: t.TempDir(), OpenSink: func(string) sink.Sink { return target }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rel := &release{gate: gate, output: w}
	run := &Run{release: rel, options: Options{Gate: gate, Output: w}, cancel: cancel}
	if id := rel.nextID(); id != 1 {
		t.Fatalf("wiring: id issuer did not run: %d", id)
	}
	var control Outcome
	path, err := rel.write(ctx, Approved{line: []byte("{}\n")}, &control, &held.Loss{}, probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true})
	if err != nil || path != releaseEnqueued || control.Authorized != 1 {
		t.Fatalf("wiring: free release control failed: %s %+v %v", path, control, err)
	}
	drain, stopDrain := context.WithTimeout(context.Background(), time.Second)
	defer stopDrain()
	if err := w.Drain(drain); err != nil {
		t.Fatal(err)
	}
	done := make(chan Outcome, 1)
	go func() {
		var o Outcome
		_, _ = rel.write(ctx, Approved{line: []byte("{}\n")}, &o, &held.Loss{}, probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true})
		done <- o
	}()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("wiring: authorization hold not reached")
	}
	closed := make(chan struct{})
	go func() { run.CloseAdmission(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("cutoff waited for held authorization")
	}
	w.Freeze()
	before := run.FreezeSnapshot()
	close(unblock)
	select {
	case o := <-done:
		if o.Authorized != 0 || o.Written != 0 {
			t.Fatalf("late release was authorized: %+v", o)
		}
	case <-time.After(time.Second):
		t.Fatal("wiring: held authorization never returned")
	}
	if id := rel.nextID(); id != 0 {
		t.Fatalf("id issued after cutoff: %d", id)
	}
	if after := run.Snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("snapshot changed after cutoff: before %+v after %+v", before, after)
	}
	if s := w.DeliveryStats(); s.Authorized != 1 {
		t.Fatalf("line enqueued after cutoff: %+v", s)
	}
}
