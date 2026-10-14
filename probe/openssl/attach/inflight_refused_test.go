package attach

import (
	"testing"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// inflightPlacing is a sink that takes a refused transfer, as the capture session
// does. Both sinks keep what they are handed, as a store retaining a transfer's
// input does, so its slot stays held.
type inflightPlacing struct {
	transfers []uint64
	refused   []uint64
}

func (p *inflightPlacing) Transfer(one probe.Transfer) {
	inflightKept(one)
	p.transfers = append(p.transfers, one.Stamp)
}
func (p *inflightPlacing) Closed(probe.Connection)    {}
func (p *inflightPlacing) Refused(one probe.Transfer) { p.refused = append(p.refused, one.Stamp) }

// inflightPlain is a sink that cannot take one.
type inflightPlain struct{ transfers int }

func (p *inflightPlain) Transfer(one probe.Transfer) {
	inflightKept(one)
	p.transfers++
}

func inflightKept(one probe.Transfer) {
	if one.Slot != nil {
		one.Slot.Keep()
	}
}
func (p *inflightPlain) Closed(probe.Connection) {}

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
		"a sink that takes refusals": &inflightPlacing{},
		"a sink that cannot":         &inflightPlain{},
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
				if _, counted := refused[probe.GateRefusal(reason)]; counted != (reason.InvalidatesCapture() || reason == probe.GateInputLimit) {
					t.Errorf("%s is counted %v, want a counter for each admission refusal reason", reason, counted)
				}
			}
			switch held := sink.(type) {
			case *inflightPlacing:
				if len(held.transfers) != 1 || held.transfers[0] != 1 || len(held.refused) != 2 ||
					held.refused[0] != 2 || held.refused[1] != 3 {
					t.Errorf("the sink was handed transfers %v and refusals %v, want [1] and [2 3]",
						held.transfers, held.refused)
				}
			case *inflightPlain:
				if held.transfers != 1 {
					t.Errorf("%d transfers reached the sink, want the one inside the allowance", held.transfers)
				}
			}
		})
	}
}
