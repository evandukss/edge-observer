package attach

import (
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// Executions come and go, each delivering one transfer and then its end, at a
// live population of one. The identity read for each pid and the namespace
// kept for it go with its end, so what the placement holds returns to the live
// population; and a pid admitted again is read again rather than handed its
// predecessor's identity.
func TestChurnedExecutionsLeaveThePlacementHoldingOnlyTheLiveOnes(t *testing.T) {
	const executions = 1000
	g := admissionGate(t, 4096)
	a, captured, _ := deliveryFixture(t, g)
	a.networks = map[int32]probe.Netns{}
	for i := 0; i < executions; i++ {
		pid := int32(5000 + i)
		a.mutex.Lock()
		a.networks[pid] = probe.Netns{Device: 1, Inode: uint64(i + 1)}
		a.mutex.Unlock()
		event := decodedPayload(uint64(2*i + 1))
		event.PID, event.NamespacePID, event.SSL = pid, pid, uint64(0x100+i)
		a.deliverEvent(event)
		a.deliverEvent(ebpf.Event{Kind: ebpf.Exited, PID: pid, NamespacePID: pid,
			Namespace: admission.Namespace{Device: 3, Inode: 4}, Generation: 1})
	}
	if got := captured.Stats().Transfers; got != executions {
		t.Fatalf("wiring, not the property: %d of %d transfers reached capture", got, executions)
	}
	stores, err := a.Retained()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range stores {
		switch one.Store {
		case "attach.identities", "attach.networks":
			if one.Held != 0 {
				t.Errorf("%s holds %d after %d executions came and went, want none", one.Store, one.Held, executions)
			}
			if one.Rebuilds == 0 {
				t.Errorf("%s was never rebuilt after %d executions came and went", one.Store, executions)
			}
		}
	}
	if state := g.Snapshot(); state.Charged != executions {
		t.Errorf("an execution's end was admitted as input: %d charged for %d transfers", state.Charged, executions)
	}

	first := decodedPayload(9001)
	first.PID, first.Generation = 7000, 1
	if got := a.identify(first).instance.Generation; got != 1 {
		t.Fatalf("wiring, not the property: identified under generation %d", got)
	}
	a.mutex.Lock()
	cached := a.known[7000]
	cached.instance.Executable = "the predecessor"
	a.known[7000] = cached
	a.mutex.Unlock()
	again := decodedPayload(9002)
	again.PID, again.Generation = 7000, 2
	if got := a.identify(again); got.instance.Executable == "the predecessor" || got.instance.Generation != 2 {
		t.Errorf("a pid admitted again was handed its predecessor's identity: %+v", got.instance)
	}
}

// An event no store keeps returns its slot as soon as the sink has taken it:
// a transfer that moved nothing and an ending of a handle nothing followed hold
// nothing afterwards.
func TestAnEventNoStoreKeepsReturnsItsSlotAtOnce(t *testing.T) {
	g := admissionGate(t, 8)
	a, captured, _ := deliveryFixture(t, g)
	empty := decodedDelivery(ebpf.Transfer, 1)
	empty.Measured = true
	a.deliverEvent(empty)
	a.deliverEvent(decodedDelivery(ebpf.Closed, 2))
	if stats := captured.Stats(); stats.Empty != 1 || stats.EndingsUnmatched != 1 {
		t.Fatalf("wiring, not the property: the two events did not reach capture: %+v", stats)
	}
	if state := g.Snapshot(); state.Charged != 2 || state.Held != 0 || state.Refunded.Unretained != 2 {
		t.Fatalf("two events no store kept left the gate %+v; want both charged, none held, both returned unretained", state)
	}
	a.deliverEvent(decodedPayload(3))
	if state := g.Snapshot(); state.Held != 1 {
		t.Fatalf("control: a transfer whose fragment the store kept holds %d slots, want one", state.Held)
	}
}
