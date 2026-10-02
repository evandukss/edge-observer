package attach

import (
	"testing"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// t23Placing is a sink that takes a refused transfer, as the capture session
// does. Both sinks keep what they are handed, as a store retaining a transfer's
// input does, so its slot stays held.
type t23Placing struct {
	transfers []uint64
	refused   []uint64
}

func (p *t23Placing) Transfer(one probe.Transfer) {
	t23Kept(one)
	p.transfers = append(p.transfers, one.Stamp)
}
func (p *t23Placing) Closed(probe.Connection)    {}
func (p *t23Placing) Refused(one probe.Transfer) { p.refused = append(p.refused, one.Stamp) }

// t23Plain is a sink that cannot take one.
type t23Plain struct{ transfers int }

func (p *t23Plain) Transfer(one probe.Transfer) {
	t23Kept(one)
	p.transfers++
}

func t23Kept(one probe.Transfer) {
	if one.Slot != nil {
		one.Slot.Keep()
	}
}
func (p *t23Plain) Closed(probe.Connection) {}

// An event the gate refused is counted under the gate's reason, and a refused
// transfer's place goes to a sink that can take it, so capture takes its number
// as seen rather than as lost.
func TestARefusedEventIsCountedUnderItsReasonAndGoesToCaptureAsRefused(t *testing.T) {
	events := []ebpf.Event{
		{Kind: ebpf.Transfer, Measured: true, Stamp: 1, PID: 1},
		{Kind: ebpf.Transfer, Measured: true, Stamp: 2, PID: 1},
		{Kind: ebpf.Transfer, Measured: true, Stamp: 3, PID: 1},
	}
	for name, sink := range map[string]probe.Sink{
		"a sink that takes refusals": &t23Placing{},
		"a sink that cannot":         &t23Plain{},
	} {
		t.Run(name, func(t *testing.T) {
			gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1})
			if err != nil {
				t.Fatal(err)
			}
			a := &ebpfAttachment{sink: sink, gate: gate, procfs: t.TempDir(), known: map[int32]identity{},
				networks: map[int32]probe.Netns{}}
			for _, event := range events {
				a.deliverEvent(event)
			}
			refused, err := a.refusals(func() (ebpf.Refusals, error) { return ebpf.Refusals{}, nil })
			if err != nil {
				t.Fatal(err)
			}
			if got := refused[probe.GateRefusal(probe.GateInputLimit)]; got != 2 {
				t.Errorf("%d events counted refused under %s, want the two past the allowance of one",
					got, probe.GateInputLimit)
			}
			for _, reason := range probe.GateReasons() {
				if _, counted := refused[probe.GateRefusal(reason)]; counted != reason.InvalidatesCapture() {
					t.Errorf("%s is counted %v, want a counter exactly for each invalidating reason", reason, counted)
				}
			}
			switch held := sink.(type) {
			case *t23Placing:
				if len(held.transfers) != 1 || held.transfers[0] != 1 || len(held.refused) != 2 ||
					held.refused[0] != 2 || held.refused[1] != 3 {
					t.Errorf("the sink was handed transfers %v and refusals %v, want [1] and [2 3]",
						held.transfers, held.refused)
				}
			case *t23Plain:
				if held.transfers != 1 {
					t.Errorf("%d transfers reached the sink, want the one inside the allowance", held.transfers)
				}
			}
		})
	}
}
