//go:build attach

package ebpf_test

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

func TestALateRetractedEventCannotPreventReadmission(t *testing.T) {
	for _, readmitFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent grant", true: "replacement grant"}[readmitFirst], func(t *testing.T) {
			port := sequencePeer(t, nil)
			actor := independentActor(t, sequenceActorSource, port)
			p := loaded(t, int32(actor.command.Process.Pid))
			arrived, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			s, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, p), Admit: authorise(p),
				BeforeRecord: func(event ebpf.Event) {
					if event.Kind == ebpf.Transfer {
						once.Do(func() { close(arrived); <-release })
					}
				}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			var released sync.Once
			unblock := func() { released.Do(func() { close(release) }) }
			defer unblock()
			command(t, actor, "O 1", "O 0")
			if _, err := io.WriteString(actor.input, "X 0 held\n"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("wiring: no decoded transfer reached the barrier")
			}
			s.Retract(authorise(p))
			if len(s.Inventory()) != 0 {
				t.Fatal("wiring: Retract did not remove the initial inventory")
			}
			if readmitFirst {
				if granted, _, err := s.Admit(authorise(p)); err != nil || len(granted) != 1 {
					t.Fatalf("new grant: %v %v", granted, err)
				}
			}
			unblock()
			select {
			case <-s.Events():
			case <-time.After(5 * time.Second):
				t.Fatal("wiring: held event did not pass recording")
			}
			refused, err := s.Refusals()
			if err != nil || refused.Counted[ebpf.RetractedEvent] < 1 {
				t.Fatalf("late recording was not counted: %+v, %v", refused.Counted, err)
			}
			if readmitFirst {
				return
			}
			if granted, skipped, err := s.Admit(authorise(p)); err != nil || len(granted) != 1 || len(skipped) != 0 {
				t.Fatalf("late event prevented readmission: granted %v, skipped %v, err %v", granted, skipped, err)
			}

		})
	}
}

func TestAReturnHeldPastItsGrantCheckLeavesNoRetractedReadEntry(t *testing.T) {
	port := sequencePeer(t, nil)
	actor := independentActor(t, sequenceActorSource, port)
	p := loaded(t, int32(actor.command.Process.Pid))
	s, err := ebpf.Attach(ebpf.Options{Program: bpf.ReadBarrier(), Points: points(t, p), Admit: authorise(p)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	command(t, actor, "O 1", "O 0")
	grants := s.Inventory()
	if len(grants) != 1 {
		t.Fatalf("wiring: got %d initial grants", len(grants))
	}
	if err := ebpf.ArmReadBarrier(s, grants[0].Instance.Generation); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ebpf.ReleaseReadBarrier(s) }()
	if _, err := io.WriteString(actor.input, "X 0 held\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		state, err := ebpf.ReadBarrierState(s)
		if err != nil {
			t.Fatal(err)
		}
		if state == 2 {
			break
		}
		if state == 4 {
			t.Fatal("wiring: kernel read barrier timed out before retraction")
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("wiring: return did not reach its read barrier")
		}
	}
	s.Retract(grants)
	if held := retainedStore(t, s, "bpf.reads"); held != 0 {
		t.Fatalf("wiring: retraction left %d counters", held)
	}
	if state, err := ebpf.ReadBarrierState(s); err != nil || state != 2 {
		t.Fatalf("wiring: barrier not held through fold: %d %v", state, err)
	}
	if err := ebpf.ReleaseReadBarrier(s); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "X 0\n")
	if held := retainedStore(t, s, "bpf.reads"); held != 0 {
		t.Fatalf("late read recreated %d retired counters", held)
	}
	late, err := ebpf.Counter(s, bpf.StatReadRetracted)
	if err != nil || late == 0 {
		t.Fatalf("late read was not counted: %d %v", late, err)
	}
}
