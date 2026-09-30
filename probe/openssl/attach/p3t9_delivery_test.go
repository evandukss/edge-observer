package attach

import (
	"bytes"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// Independent T1 characterization. This collector is deliberately NOT a
// protected intake or approved-output writer, and none of these tests claims
// pre-retention enforcement or worker authorization.
type p3t9Collected struct {
	fragments   []fragment.Record
	connections []connection.Record
}

func (c *p3t9Collected) Write(r fragment.Record) error {
	c.fragments = append(c.fragments, r)
	return nil
}

func (c *p3t9Collected) Connection(r connection.Record) error {
	c.connections = append(c.connections, r)
	return nil
}

func p3t9Delivery(t *testing.T, n uint64) (*ebpfAttachment, *capture.Session, *p3t9Collected, *probe.DeliveryGate) {
	t.Helper()
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: n})
	if err != nil {
		t.Fatal(err)
	}
	collected := &p3t9Collected{}
	c := capture.Recording(collected, collected)
	a := &ebpfAttachment{gate: g, sink: c, procfs: t.TempDir(), known: make(map[int32]identity)}
	return a, c, collected, g
}

func p3t9Event(stamp uint64, payload string) ebpf.Event {
	return ebpf.Event{
		Kind: ebpf.Transfer, Stamp: stamp, PID: 69171, NamespacePID: 69171,
		Namespace: admission.Namespace{Device: 69, Inode: 171}, Generation: 1,
		SSL: 9, Direction: fragment.Sent, Measured: true,
		Length: uint32(len(payload)), Payload: []byte(payload), At: time.Unix(100, int64(stamp)),
	}
}

func p3t9Close(stamp uint64) ebpf.Event {
	e := p3t9Event(stamp, "")
	e.Kind, e.Measured = ebpf.Closed, false
	return e
}

func p3t9Reason(t *testing.T, g *probe.DeliveryGate, charged uint64, reason probe.GateReason) {
	t.Helper()
	state := g.Snapshot()
	if state.Charged != charged || state.Reason != reason {
		t.Fatalf("gate state = %+v; want charged %d reason %q", state, charged, reason)
	}
	select {
	case <-g.Withdrawal():
		if reason == "" {
			t.Fatal("valid control requested withdrawal")
		}
	default:
		if reason != "" {
			t.Fatal("reached fault did not request withdrawal")
		}
	}
}

func TestP3T9DeliveryWitnessAndMeasuredNeighbor(t *testing.T) {
	for _, measured := range []bool{true, false} {
		name := "unknown_length"
		if measured {
			name = "fully_measured"
		}
		t.Run(name, func(t *testing.T) {
			a, c, collected, g := p3t9Delivery(t, 10)
			parts := []string{"GET / HTTP/1.1\r\nX-public: ", "benign\r\nAuthorization: ", "PROTECTED_MARKER\r\n\r\n"}
			a.deliverEvent(p3t9Event(1, parts[0]))
			if c.Stats().Records != 1 || len(collected.fragments) != 1 {
				t.Fatal("the prefix did not reach capture before the witness")
			}
			middle := p3t9Event(2, parts[1])
			middle.Measured = measured
			if !measured {
				middle.Length, middle.Payload = 0, nil
			}
			a.deliverEvent(middle)
			a.deliverEvent(p3t9Event(3, parts[2]))
			a.deliverEvent(p3t9Close(4))
			if measured {
				p3t9Reason(t, g, 4, "")
				if c.Stats().Closed != 1 || len(collected.connections) != 1 || collected.connections[0].How != connection.HandleReleasedEnding {
					t.Fatalf("real-shaped Measured=false close below N did not retire the control: %+v", c.Stats())
				}
				var body []byte
				for _, r := range collected.fragments {
					if r.Offset != uint64(len(body)) {
						t.Fatalf("control offset %d after %d bytes", r.Offset, len(body))
					}
					body = append(body, r.Payload...)
				}
				if !bytes.Equal(body, []byte(parts[0]+parts[1]+parts[2])) {
					t.Fatalf("measured witness changed: %q", body)
				}
				if d := g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}); !d.Authorized || d.Reason != "" {
					t.Fatalf("settled control refused: %+v", d)
				}
			} else {
				p3t9Reason(t, g, 2, probe.GateUnknownLength)
				if c.Stats().Transfers != 1 || c.Stats().Unmeasured != 0 || c.Stats().Closed != 0 || len(collected.fragments) != 1 || len(collected.connections) != 0 {
					t.Fatalf("unknown transfer or refused suffix reached capture: %+v", c.Stats())
				}
				// Finish can still manufacture a capture-end record. It must not
				// revive authorization; a real worker test must assert no output.
				c.Finish(time.Unix(101, 0), connection.Counted(4))
				if len(collected.connections) != 1 {
					t.Fatal("pending retirement was not exercised")
				}
				if d := g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}); d.Authorized || d.Reason != probe.GateUnknownLength {
					t.Fatalf("Finish revived authorization: %+v", d)
				}
			}
		})
	}
}

func TestP3T9DrainedAdmissionBoundaryAndPendingRetirement(t *testing.T) {
	// An acknowledged unbuffered channel supplies no pressure. The decoded
	// events are synthetic; this is not a kernel ring or total-heap test.
	for _, count := range []int{3, 4, 5} {
		t.Run([]string{"N_minus_1", "N", "N_plus_1"}[count-3], func(t *testing.T) {
			a, c, collected, g := p3t9Delivery(t, 4)
			input, ack := make(chan ebpf.Event), make(chan struct{})
			go func() {
				for e := range input {
					a.deliverEvent(e)
					ack <- struct{}{}
				}
			}()
			defer close(input)
			events := []ebpf.Event{p3t9Event(1, "GET / HTTP/1.1\r\n\r\n"), p3t9Event(2, ""), p3t9Close(3), p3t9Event(4, "GET /pending HTTP/1.1\r\n\r\n"), p3t9Event(5, "tail")}
			// Event 3 is an unmatched ordinary close; it must still be charged.
			events[2].SSL = 123
			// A novel identity/handle makes downstream growth observable at N+1.
			events[4].PID, events[4].NamespacePID, events[4].SSL = 69172, 69172, 456
			var atN capture.Stats
			for i := 0; i < count; i++ {
				input <- events[i]
				<-ack
				if i == 3 {
					atN = c.Stats()
				}
			}
			reason, charged := probe.GateReason(""), uint64(count)
			if count == 5 {
				reason, charged = probe.GateInputLimit, 4
			}
			p3t9Reason(t, g, charged, reason)
			if c.Stats().Empty != 1 || c.Stats().EndingsUnmatched != 1 || len(a.known) != 1 {
				t.Fatalf("charged controls missing or tail grew cache: stats %+v identities %d", c.Stats(), len(a.known))
			}
			if count == 5 && c.Stats() != atN {
				t.Fatalf("N+1 changed capture state: before %+v after %+v", atN, c.Stats())
			}
			wantRecords := 1
			if count >= 4 {
				wantRecords = 2
			}
			if len(collected.fragments) != wantRecords || len(collected.connections) != 0 {
				t.Fatal("pending input population differs from the declared fixture")
			}
			c.Finish(time.Unix(101, 0), connection.Counted(int64(count)))
			if len(collected.connections) != 1 {
				t.Fatal("pending batch was not retired at Finish")
			}
			d := g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true})
			if d.Authorized != (count <= 4) || d.Reason != reason {
				t.Fatalf("pending authorization after Finish: %+v", d)
			}
		})
	}
}
