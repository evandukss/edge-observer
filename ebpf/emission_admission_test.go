//go:build attach

package ebpf_test

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
)

// queuedAdmission holds a real decoded transfer before inventory recording.
// The process continues, so either exit or live withdrawal can precede release.
func queuedAdmission(t *testing.T) (*ebpf.Session, *armingProcess, process.Process, ebpf.Event, func()) {
	t.Helper()
	port := sequencePeer(t, nil)
	actor := independentActor(t, sequenceActorSource, port)
	p := loaded(t, int32(actor.command.Process.Pid))
	arrived, release := make(chan ebpf.Event, 1), make(chan struct{})
	var held, released sync.Once
	unblock := func() { released.Do(func() { close(release) }) }
	s, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, p), Admit: authorise(p),
		BeforeRecord: func(e ebpf.Event) {
			if e.Kind == ebpf.Transfer {
				held.Do(func() { arrived <- e; <-release })
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	t.Cleanup(unblock)
	command(t, actor, "O 1", "O 0")
	if _, err := io.WriteString(actor.input, "X 0 held\n"); err != nil {
		t.Fatal(err)
	}
	var event ebpf.Event
	select {
	case event = <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring, not the property: no decoded transfer reached the recording hold")
	}
	grants, err := s.Held()
	if err != nil || len(grants) != 1 || grants[0].Instance.Generation != event.Generation || event.Generation == 0 {
		t.Fatalf("wiring, not the property: held transfer lacks its live emission grant: %+v, event %+v, err %v", grants, event, err)
	}
	if len(s.Inventory()) != 1 {
		t.Fatal("wiring, not the property: initial inventory row is absent")
	}
	if string(event.Payload) != "GET /held-0 HTTP/1.1\r\nHost: localhost\r\n\r\n" {
		t.Fatalf("wiring, not the property: held transfer payload %q", event.Payload)
	}
	return s, actor, p, event, unblock
}

func emissionRefusals(t *testing.T, s *ebpf.Session) map[ebpf.RefusalReason]int64 {
	t.Helper()
	r, err := s.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	return r.Counted
}

func releasedAdmission(t *testing.T, s *ebpf.Session, event ebpf.Event, untilExit bool) {
	t.Helper()
	transfers := 0
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case e, open := <-s.Events():
			if !open {
				t.Fatal("released admission event channel ended before its transfer and retirement")
			}
			if e.Kind == ebpf.Transfer {
				transfers++
				if e.Generation != event.Generation || string(e.Payload) != string(event.Payload) {
					t.Errorf("delivered transfer changed its emission evidence: generation %d, payload %q", e.Generation, e.Payload)
				}
				if !untilExit {
					return
				}
			}
			if e.Kind == ebpf.Exited && untilExit {
				if transfers != 1 {
					t.Errorf("exit delivered with %d preceding held transfers, want one", transfers)
				}
				return
			}
		case <-timer.C:
			t.Fatal("released admission did not deliver its transfer and expected retirement")
		}
	}
}

func TestAnExitedProcessKeepsItsQueuedEmissionWithoutARefusal(t *testing.T) {
	for _, exit := range []bool{false, true} {
		t.Run(map[bool]string{false: "live control", true: "exited before recording"}[exit], func(t *testing.T) {
			s, actor, _, event, unblock := queuedAdmission(t)
			before := emissionRefusals(t, s)
			if exit {
				if err := actor.command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err := actor.command.Wait(); err == nil {
					t.Fatal("wiring, not the property: killed process exited successfully")
				}
			}
			grants, err := s.Held()
			want := 1
			if exit {
				want = 0
			}
			if err != nil || len(grants) != want || len(s.Inventory()) != 1 {
				t.Fatalf("wiring, not the property: before release grants=%d, inventory=%d, want grants=%d and inventory=1: %v", len(grants), len(s.Inventory()), want, err)
			}
			t.Logf("PRECONDITIONS exited=%t emitted_generation=%d grants_before_release=%d inventory_before_release=1", exit, event.Generation, len(grants))
			unblock()
			releasedAdmission(t, s, event, exit)
			for reason, count := range emissionRefusals(t, s) {
				if count != before[reason] {
					t.Errorf("ordinary execution refusal %s moved %d -> %d", reason, before[reason], count)
				}
			}
			if got := len(s.Inventory()); got != want {
				t.Errorf("inventory after delivery = %d, want %d", got, want)
			}
			ended := 0
			for _, n := range s.EndedCounts() {
				ended += n.Count
			}
			if ended != 1-want {
				t.Errorf("ended admission count = %d, want %d", ended, 1-want)
			}
		})
	}
}

func TestALiveWithdrawalStillRefusesQueuedInventoryRecording(t *testing.T) {
	s, _, p, event, unblock := queuedAdmission(t)
	before := emissionRefusals(t, s)
	s.Retract(authorise(p))
	grants, err := s.Held()
	reading := process.Inspect(procfs, p.PID, process.Group{Namespace: p.Namespace, NamespacePID: p.NamespacePID, Start: p.Start()})
	if err != nil || len(grants) != 0 || len(s.Inventory()) != 0 || reading.Liveness != process.LivenessRunning {
		t.Fatalf("wiring, not the property: withdrawn grant is not absent from a still-live process: grants=%d inventory=%d reading=%s err=%v", len(grants), len(s.Inventory()), reading.Evidence(), err)
	}
	t.Logf("PRECONDITIONS emitted_generation=%d process_still_running=true grants_before_release=0 inventory_before_release=0", event.Generation)
	unblock()
	releasedAdmission(t, s, event, false)
	for reason, count := range emissionRefusals(t, s) {
		want := before[reason]
		if reason == ebpf.RetractedEvent {
			want++
		}
		if count != want {
			t.Errorf("live withdrawal refusal %s = %d, want %d", reason, count, want)
		}
	}
	if got := len(s.Inventory()); got != 0 {
		t.Errorf("withdrawn event recreated %d inventory rows", got)
	}
	granted, skipped, err := s.Admit(authorise(p))
	if err != nil || len(granted) != 1 || len(skipped) != 0 {
		t.Fatalf("late event blocked readmission: granted=%v skipped=%v err=%v", granted, skipped, err)
	}
	if granted[0].Instance.Generation == event.Generation {
		t.Error("readmission reused the withdrawn event's generation")
	}
}
