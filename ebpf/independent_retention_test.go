//go:build attach

package ebpf_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/ebpf"
	retention "github.com/evandukss/edge-observer/held"
)

func retainedKernel(t *testing.T, s *ebpf.Session) map[string]retention.Occupancy {
	t.Helper()
	items, err := s.Retained()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]retention.Occupancy{}
	for _, v := range items {
		if _, exists := out[v.Store]; exists {
			t.Fatalf("wiring, not the property: duplicated kernel/session store %s", v.Store)
		}
		out[v.Store] = v
	}
	for _, name := range []string{"bpf.inflight", "bpf.allowed_processes", "bpf.reads", "bpf.sockets", "bpf.handles", "bpf.occupancies", "bpf.operations", "bpf.discovered", "ebpf.accepted", "ebpf.inventory", "ebpf.index", "ebpf.named_by", "ebpf.seen", "ebpf.beyond", "ebpf.declined"} {
		if _, exists := out[name]; !exists {
			t.Fatalf("wiring, not the property: full producer/session store %s absent", name)
		}
	}
	return out
}

func TestIndependentKernelConnectionAndThreadChurn(t *testing.T) {
	const bound = 8
	r := proofFixture(t, map[string]uint32{"inflight": bound, "operations": bound, "sockets": bound, "handles": bound, "occupancies": bound, "discovered": bound})
	initial := retainedKernel(t, r.session)
	names := []string{"bpf.inflight", "bpf.operations", "bpf.sockets", "bpf.handles", "bpf.occupancies", "bpf.discovered"}
	for _, name := range names {
		if initial[name].Bound != bound {
			t.Fatalf("wiring, not the property: %s bound=%d", name, initial[name].Bound)
		}
	}
	before, err := r.session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	socketBefore := proofCounter(t, r.session.SocketsUnrecorded)
	bindingBefore := proofCounter(t, r.session.BindingsUnrecorded)
	for range 80 {
		if answer := r.command(t, "D"); answer != "D ok" {
			t.Fatalf("wiring, not the property: threaded TLS churn reply%q", answer)
		}
		select {
		case <-r.peers:
		case <-time.After(time.Second):
			t.Fatal("wiring, not the property: TLS churn handshake absent")
		}
		r.consume()
	}
	writes := 0
	for _, e := range r.events {
		if e.Length == 512 {
			writes++
		}
	}
	if writes != 80 {
		t.Fatalf("wiring, not the property: churn produced%d/80 measured writes", writes)
	}
	after := retainedKernel(t, r.session)
	for _, name := range names {
		if v, exists := after[name]; exists && v.Held > initial[name].Held {
			t.Errorf("%s retains%d after80 connections/threads ended; baseline%d", name, v.Held, initial[name].Held)
		}
	}
	refusal, err := r.session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	for name, n := range refusal.Counted {
		if name != ebpf.DescriptorSeenInsideACall && name != ebpf.SocketWorkOutsideACall && name != ebpf.SocketDescriptorInvalid && n != before.Counted[name] {
			t.Errorf("churn refusal %s moved%d->%d", name, before.Counted[name], n)
		}
	}
	if n := proofCounter(t, r.session.SocketsUnrecorded); n != socketBefore {
		t.Errorf("socket-table refusals%d->%d", socketBefore, n)
	}
	if n := proofCounter(t, r.session.BindingsUnrecorded); n != bindingBefore {
		t.Errorf("binding-table refusals%d->%d", bindingBefore, n)
	}
	t.Logf("PRECONDITIONS bound=%d churn=80 TLS_writes=%d live_SSL=0 live_worker_threads=0 stores=%+v", bound, writes, after)
}

func TestIndependentAdmissionChurnReclaimsGenerationStores(t *testing.T) {
	r := proofFixture(t, map[string]uint32{"allowed_processes": 4, "reads": 4})
	before := retainedKernel(t, r.session)
	if before["bpf.allowed_processes"].Held != 1 || before["bpf.reads"].Bound != 4 {
		t.Fatalf("wiring, not the property: initial grant/maps: %+v", before)
	}
	firstRefused, err := r.session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		r.open(t, 0)
		r.command(t, "W 0 1")
		r.consume()
		r.command(t, "F 0")
		r.consume()
		r.session.Retract(authorise(r.who))
		off := retainedKernel(t, r.session)
		if off["bpf.allowed_processes"].Held != 0 {
			t.Fatal("wiring, not the property: explicit retraction did not remove grant")
		}
		for _, name := range []string{"bpf.reads", "ebpf.inventory", "ebpf.index", "ebpf.accepted", "ebpf.named_by", "ebpf.seen", "ebpf.beyond"} {
			if v, ok := off[name]; ok && v.Held != 0 {
				t.Errorf("%s retained%d for zero admitted processes after cycle%d", name, v.Held, i)
			}
		}
		granted, skipped, err := r.session.Admit(authorise(r.who))
		if err != nil || len(granted) != 1 || len(skipped) != 0 {
			t.Fatalf("churn could not readmit same live process after retraction: granted%d skipped%v err%v", len(granted), skipped, err)
		}
	}
	after, err := r.session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	for name, n := range after.Counted {
		if name != ebpf.DescriptorSeenInsideACall && name != ebpf.SocketWorkOutsideACall && name != ebpf.SocketDescriptorInvalid && n != firstRefused.Counted[name] {
			t.Errorf("admission churn refusal %s moved%d->%d", name, firstRefused.Counted[name], n)
		}
	}
	t.Logf("PRECONDITIONS admission_churn=40 read_bound=4 live_processes=1 stores=%+v", retainedKernel(t, r.session))
}

func TestIndependentEventStagingFillsAndDrains(t *testing.T) {
	const bound = 4
	r := proofConfigured(t, nil, func(o *ebpf.Options) { o.Staging = bound })
	r.open(t, 0)
	for cycle := 0; cycle < 40; cycle++ {
		before := len(r.events)
		r.command(t, "W 0 6")
		deadline := time.Now().Add(time.Second)
		var full retention.Occupancy
		for time.Now().Before(deadline) {
			full = retainedKernel(t, r.session)["ebpf.events"]
			if full.Held == bound {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if full.Held != bound || full.Bound != bound {
			t.Fatalf("wiring, not the property: staging did not fill: %+v", full)
		}
		r.consume()
		if len(r.events)-before != 6 {
			t.Fatalf("staging lost input: received %d of 6", len(r.events)-before)
		}
		if after := retainedKernel(t, r.session)["ebpf.events"]; after.Held != 0 || after.Bound != bound {
			t.Fatalf("staging did not return to empty bounded channel: %+v", after)
		}
	}
	if dropped, err := r.session.Dropped(); err != nil || dropped != 0 {
		t.Errorf("staging churn lost kernel input: %d %v", dropped, err)
	}
	t.Log("PRECONDITIONS cycles=40 actual_writes=240 staging_held=4 staging_capacity=4 drained_each_cycle=true")
}
