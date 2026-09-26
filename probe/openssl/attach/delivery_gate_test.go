package attach

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

type deliveryRecords struct{ records []fragment.Record }

func (s *deliveryRecords) Write(record fragment.Record) error {
	s.records = append(s.records, record)
	return nil
}

func deliveryFixture(t *testing.T, gate *probe.DeliveryGate) (*ebpfAttachment, *capture.Session, *deliveryRecords) {
	t.Helper()
	records := &deliveryRecords{}
	captured := capture.New(records)
	return &ebpfAttachment{
		gate: gate, sink: captured, procfs: t.TempDir(), known: make(map[int32]identity),
	}, captured, records
}

func admissionGate(t *testing.T, n uint64) *probe.DeliveryGate {
	t.Helper()
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: n})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The producer's obs_emit call for a close uses measured=0, length=0 and
// no payload. Identity and handle fields remain, so it can retire a stream.
func decodedDelivery(kind ebpf.Kind, stamp uint64) ebpf.Event {
	return ebpf.Event{
		Kind: kind, Stamp: stamp, PID: 441, NamespacePID: 441, SSL: 17,
		Namespace: admission.Namespace{Device: 3, Inode: 4}, Generation: 1,
		At: time.Unix(100, int64(stamp)),
	}
}

func decodedPayload(stamp uint64) ebpf.Event {
	event := decodedDelivery(ebpf.Transfer, stamp)
	event.Measured = true
	event.Length = 4
	event.Payload = []byte("data")
	event.Direction = fragment.Sent
	return event
}

func TestDeliveryGateEntryAdmitsTheProducersOrdinaryClose(t *testing.T) {
	g := admissionGate(t, 3)
	a, captured, records := deliveryFixture(t, g)
	a.deliverEvent(decodedPayload(1))
	a.deliverEvent(decodedDelivery(ebpf.Closed, 2))
	if stats := captured.Stats(); stats.Transfers != 1 || stats.Closed != 1 || stats.Connections != 1 {
		t.Fatalf("measured transfer and real-shaped close did not reach capture: %+v", stats)
	}
	if len(records.records) != 1 || string(records.records[0].Payload) != "data" {
		t.Fatalf("useful control output missing: %+v", records.records)
	}
	if state := g.Snapshot(); state.Charged != 2 || state.Reason != "" {
		t.Fatalf("close bypassed admission or invalidated: %+v", state)
	}
	if got := g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}); !got.Authorized {
		t.Fatalf("closed control is ineligible: %+v", got)
	}
}

func TestDeliveryGateEntryRefusesTailBeforeIdentityAndCapture(t *testing.T) {
	g := admissionGate(t, 3)
	a, captured, records := deliveryFixture(t, g)
	empty := decodedDelivery(ebpf.Transfer, 1)
	empty.Measured = true
	a.deliverEvent(empty)
	a.deliverEvent(decodedDelivery(ebpf.Closed, 2))
	a.deliverEvent(decodedPayload(3))
	before := captured.Stats()
	if before.Empty != 1 || before.EndingsUnmatched != 1 || before.Records != 1 || len(a.known) != 1 {
		t.Fatalf("N-1/N controls did not reach the real capture: %+v, identities %d", before, len(a.known))
	}
	tail := decodedPayload(4)
	tail.PID, tail.NamespacePID, tail.SSL = 442, 442, 18
	a.deliverEvent(tail)
	if state := g.Snapshot(); state.Charged != 3 || state.Reason != probe.GateInputLimit {
		t.Fatalf("N+1 refusal not reached: %+v", state)
	}
	if len(a.known) != 1 || captured.Stats() != before || len(records.records) != 1 {
		t.Fatalf("refused tail grew identity/capture state: identities %d, stats %+v, records %d", len(a.known), captured.Stats(), len(records.records))
	}
	if got := g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}); got.Authorized || got.Reason != probe.GateInputLimit {
		t.Fatalf("pending payload stayed releasable after refused tail: %+v", got)
	}
}

func TestDeliveryGateEntryClassifiesUncertaintyBeforeEitherSink(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   ebpf.Kind
		early  bool
		length uint32
		reason probe.GateReason
	}{
		{"unmeasured payload", ebpf.Transfer, false, 4, probe.GateUnknownLength},
		{"unmeasured early zero", ebpf.Transfer, true, 0, probe.GateUnknownLength},
		{"unknown kind", 255, false, 0, probe.GateUnknownKind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := admissionGate(t, 10)
			a, captured, records := deliveryFixture(t, g)
			// The second placement delivers to the same capture, as every placement
			// does in the product (EBPF.Attach passes one sink to each place), so the
			// three stamps below are one production order seen by one capture.
			b := &ebpfAttachment{gate: g, sink: captured, procfs: t.TempDir(), known: make(map[int32]identity)}
			a.deliverEvent(decodedPayload(1))
			before := captured.Stats()
			if before.Records != 1 {
				t.Fatalf("pending control not captured: %+v", before)
			}
			fault := decodedDelivery(tc.kind, 2)
			fault.Early, fault.Length = tc.early, tc.length
			b.deliverEvent(fault)
			if state := g.Snapshot(); state.Charged != 2 || state.Reason != tc.reason {
				t.Fatalf("fault not reached: %+v", state)
			}
			if len(b.known) != 0 || captured.Stats() != before {
				t.Fatalf("fault reached identity or capture: %d, %+v", len(b.known), captured.Stats())
			}
			a.deliverEvent(decodedDelivery(ebpf.Closed, 3))
			if captured.Stats() != before || len(records.records) != 1 {
				t.Fatal("invalidation did not cover the other placement")
			}
			if after := captured.Stats(); after.Lost != 0 || after.Unexplained != 0 {
				t.Fatalf("the capture located a gap across stamps 1, 2 and 3: lost %d, unexplained %d",
					after.Lost, after.Unexplained)
			}
			if got := g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}); got.Authorized || got.Reason != tc.reason {
				t.Fatalf("another placement's pending payload remained eligible: %+v", got)
			}
		})
	}
}

func TestDeliveryGateEntryReportsTheUngatedPathBesideGatedControl(t *testing.T) {
	for _, gated := range []bool{false, true} {
		var gate *probe.DeliveryGate
		if gated {
			gate = admissionGate(t, 3)
		}
		a, captured, _ := deliveryFixture(t, gate)
		a.deliverEvent(decodedPayload(1))
		a.deliverEvent(decodedDelivery(ebpf.Closed, 2))
		if stats := captured.Stats(); stats.Records != 1 || stats.Closed != 1 {
			t.Fatalf("gated=%v: control did not deliver: %+v", gated, stats)
		}
		counts, err := a.refusals(func() (ebpf.Refusals, error) { return ebpf.Refusals{}, nil })
		if err != nil {
			t.Fatal(err)
		}
		want := int64(2)
		if gated {
			want = 0
		}
		if got, present := counts[probe.DeliveryWithoutGate]; !present || got != want {
			t.Fatalf("gated=%v: ungated count %d (present %v), want %d", gated, got, present, want)
		}
	}
}
