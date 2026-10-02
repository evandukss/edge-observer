//go:build attach

package ebpf_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

// One process runs on while its admission is taken back and given again, forty
// times, with the reads table bounded at four. Each admission's read counter
// goes with it: none is left once the grant is taken back, no read goes
// unfiled, and every read taken is accounted as reclaimed.
func TestRetractedAdmissionsLeaveNoReadCountersBehind(t *testing.T) {
	const cycles = 40
	port, received := independentPeer(t)
	actor := independentActor(t, recycleSource, port)
	process := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, process), Admit: authorise(process),
		Resize: map[string]uint32{"reads": 4}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	ended := make(chan struct{}, 4*cycles)
	go func() {
		for event := range session.Events() {
			if event.Kind == ebpf.Closed && int(event.PID) == int(process.PID) {
				ended <- struct{}{}
			}
		}
	}()

	var taken uint64
	left := map[admission.Generation]uint64{}
	for i := 0; i < cycles; i++ {
		recycled(t, actor, received)
		// The actor answers before it frees the object, and an event decoded after
		// the grant is taken back records the instance again, so the cycle waits
		// for both of its endings first.
		for n := 0; n < 2; n++ {
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatalf("wiring, not the property: %d of cycle %d's 2 endings arrived", n, i)
			}
		}
		reads, err := session.Reads()
		if err != nil {
			t.Fatalf("cycle %d: read the counters: %v", i, err)
		}
		fresh := 0
		for generation, count := range reads {
			if _, before := left[generation]; !before {
				fresh++
				taken += count
				if count == 0 {
					t.Fatalf("wiring, not the property: cycle %d's admission counted no read", i)
				}
			}
		}
		if fresh != 1 {
			t.Fatalf("wiring, not the property: cycle %d's exchange was counted under %d new admissions, want one: %v",
				i, fresh, reads)
		}

		session.Retract(authorise(process))
		left, err = session.Reads()
		if err != nil || len(left) != 0 {
			t.Errorf("cycle %d: with the grant taken back the reads table holds %v (%v), want nothing", i, left, err)
		}
		if held := retainedStore(t, session, "bpf.reads"); held != 0 {
			t.Errorf("cycle %d: bpf.reads holds %d with no admission in force", i, held)
		}
		if granted, skipped, err := session.Admit(authorise(process)); err != nil || len(granted) != 1 {
			t.Fatalf("wiring, not the property: cycle %d could not admit the process again: granted %v, skipped %+v, %v",
				i, granted, skipped, err)
		}
	}

	unfiled, err := ebpf.Counter(session, bpf.StatReadUnrecorded)
	if err != nil {
		t.Fatal(err)
	}
	if unfiled != 0 {
		t.Errorf("%d reads could not be filed against their admission", unfiled)
	}
	reclaimed, err := session.ReadsReclaimed()
	if err != nil || reclaimed != taken {
		t.Errorf("%d reads were taken under the %d admissions and %d accounted as reclaimed (%v)", taken, cycles,
			reclaimed, err)
	}
}

// retainedStore is what one store of the session's reading holds.
func retainedStore(t *testing.T, session *ebpf.Session, store string) int {
	t.Helper()
	stores, err := session.Retained()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range stores {
		if one.Store == store {
			return one.Held
		}
	}
	t.Fatalf("wiring, not the property: the session lists no %s: %v", store, stores)
	return 0
}
