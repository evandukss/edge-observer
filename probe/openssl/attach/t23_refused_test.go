package attach

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// t23Placing is a sink that takes a refused event's place in the order, as the
// capture session does.
type t23Placing struct {
	transfers []uint64
	refused   []uint64
}

func (p *t23Placing) Transfer(one probe.Transfer)       { p.transfers = append(p.transfers, one.Stamp) }
func (p *t23Placing) Closed(probe.Connection)           {}
func (p *t23Placing) Refused(stamp uint64, _ time.Time) { p.refused = append(p.refused, stamp) }

// t23Plain is a sink that cannot take one.
type t23Plain struct{ transfers int }

func (p *t23Plain) Transfer(probe.Transfer) { p.transfers++ }
func (p *t23Plain) Closed(probe.Connection) {}

// An event the gate refused is counted under the gate's reason, and its place
// in the production order goes to a sink that can take it. A sink that cannot
// take it is counted, because the refusal then reads as a loss.
func TestARefusedEventIsCountedUnderItsReasonAndItsPlaceGoesToCapture(t *testing.T) {
	events := []ebpf.Event{
		{Kind: ebpf.Transfer, Measured: true, Stamp: 1, PID: 1},
		{Kind: ebpf.Transfer, Measured: true, Stamp: 2, PID: 1},
		{Kind: ebpf.Transfer, Measured: true, Stamp: 3, PID: 1},
	}
	for name, one := range map[string]struct {
		sink     probe.Sink
		unplaced int64
	}{
		"a sink that takes the place": {sink: &t23Placing{}},
		"a sink that cannot":          {sink: &t23Plain{}, unplaced: 2},
	} {
		t.Run(name, func(t *testing.T) {
			gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1})
			if err != nil {
				t.Fatal(err)
			}
			a := &ebpfAttachment{sink: one.sink, gate: gate, procfs: t.TempDir(), known: map[int32]identity{},
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
			if got, counted := refused[probe.RefusalUnplaced]; !counted || got != one.unplaced {
				t.Errorf("%d refused events counted as not placed (present %v), want %d", got, counted, one.unplaced)
			}
			for _, reason := range probe.GateReasons() {
				if _, counted := refused[probe.GateRefusal(reason)]; counted != reason.InvalidatesCapture() {
					t.Errorf("%s is counted %v, want a counter exactly for each invalidating reason", reason, counted)
				}
			}
			if placing, can := one.sink.(*t23Placing); can {
				if len(placing.transfers) != 1 || placing.transfers[0] != 1 || len(placing.refused) != 2 ||
					placing.refused[0] != 2 || placing.refused[1] != 3 {
					t.Errorf("the sink was handed transfers %v and refused places %v, want [1] and [2 3]",
						placing.transfers, placing.refused)
				}
			}
		})
	}
}
