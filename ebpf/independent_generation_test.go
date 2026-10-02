//go:build attach

package ebpf_test

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

// generationAsk sends one command to the proof client without waiting, and
// returns where its answer arrives.
func generationAsk(r *proofRun, line string) <-chan string {
	answer := make(chan string, 1)
	go func() {
		if _, err := fmt.Fprintln(r.actor.input, line); err != nil {
			answer <- "write: " + err.Error()
			return
		}
		out, err := r.actor.output.ReadString('\n')
		if err != nil {
			out = "read: " + err.Error()
		}
		answer <- strings.TrimSpace(out)
	}()
	return answer
}

func generationRetracted(t *testing.T, s *ebpf.Session) int64 {
	t.Helper()
	refusals, err := s.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	return refusals.Counted[ebpf.RetractedEvent]
}

// An admitted process transfers; one of its events is still undecoded when its
// admission is taken back, and is decoded after. Admitted again, the process
// is granted: the late event of the withdrawn generation records nothing that
// makes the new admission read as already recorded, and its refusal is counted.
func TestIndependentALateEventOfAWithdrawnAdmissionDoesNotBlockReadmission(t *testing.T) {
	var hold atomic.Bool
	reached, release := make(chan ebpf.Event, 1), make(chan struct{})
	r := proofConfigured(t, nil, func(o *ebpf.Options) {
		o.BeforeRecord = func(e ebpf.Event) {
			if e.Kind == ebpf.Transfer && hold.CompareAndSwap(true, false) {
				reached <- e
				<-release
			}
		}
	})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	r.open(t, 0)
	r.consume()
	hold.Store(true)
	if answer := r.command(t, "W 0 1"); answer != "W ok" {
		t.Fatalf("wiring, not the property: the transfer was answered %q", answer)
	}
	var late ebpf.Event
	select {
	case late = <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring, not the property: no decoded transfer reached the hold before recording")
	}
	before := generationRetracted(t, r.session)
	r.session.Retract(authorise(r.who))
	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for generationRetracted(t, r.session) == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := generationRetracted(t, r.session); after != before+1 {
		t.Errorf("the late event of generation %d decoded after its admission was withdrawn is counted %d times, want once",
			late.Generation, after-before)
	}
	r.consume()

	granted, skipped, err := r.session.Admit(authorise(r.who))
	if err != nil || len(granted) != 1 || len(skipped) != 0 {
		t.Errorf("the process admitted again after a late event of its withdrawn admission: granted %d, skipped %v, err %v",
			len(granted), skipped, err)
	}
}

// A return already past its grant check when the admission is taken back files
// its read after the fold. No read entry is left for the withdrawn generation:
// with no process admitted the reads store holds nothing.
func TestIndependentALateReadOfAWithdrawnAdmissionLeavesNoReadEntry(t *testing.T) {
	r := proofConfigured(t, nil, func(o *ebpf.Options) { o.Program = bpf.ReadBarrier() })
	r.open(t, 0)
	if answer := r.command(t, "E 0 1"); answer != "E ok" {
		t.Fatalf("wiring, not the property: the control transfer was answered %q", answer)
	}
	r.consume()
	var generation admission.Generation
	for _, e := range r.events {
		if e.Kind == ebpf.Transfer {
			generation = admission.Generation(e.Generation)
		}
	}
	if generation == 0 {
		t.Fatal("wiring, not the property: the control transfer was not delivered, so no admitted generation is known")
	}

	if err := ebpf.ArmReadBarrier(r.session, generation); err != nil {
		t.Fatalf("wiring, not the property: arm the read barrier: %v", err)
	}
	answer := generationAsk(r, "E 0 1")
	deadline := time.Now().Add(5 * time.Second)
	state := uint32(0)
	for state != 2 && time.Now().Before(deadline) {
		var err error
		if state, err = ebpf.ReadBarrierState(r.session); err != nil {
			t.Fatalf("wiring, not the property: read the barrier: %v", err)
		}
	}
	if state != 2 {
		t.Fatalf("wiring, not the property: no return reached the barrier past its grant check (state %d)", state)
	}
	r.session.Retract(authorise(r.who))
	held, err := ebpf.ReadBarrierState(r.session)
	if err != nil || held != 2 {
		t.Fatalf("wiring, not the property: the return was no longer held when the retraction completed (state %d, %v)", held, err)
	}
	if err := ebpf.ReleaseReadBarrier(r.session); err != nil {
		t.Fatalf("wiring, not the property: release the barrier: %v", err)
	}
	select {
	case got := <-answer:
		if got != "E ok" {
			t.Fatalf("wiring, not the property: the held transfer was answered %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wiring, not the property: the held transfer never returned")
	}
	r.consume()

	if held := retainedKernel(t, r.session)["bpf.reads"].Held; held != 0 {
		t.Errorf("the reads store holds %d entries with no process admitted: the read filed after the fold was left behind", held)
	}
}
