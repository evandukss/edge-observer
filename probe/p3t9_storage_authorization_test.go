package probe_test

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
)

// Red-first gate/intake integration against the published T1b stub. A working
// intake is required to REACH the gate defect: a constructor failure is only
// the earlier shared T2 absence, not a storage-ordering failure.
//
// Input is fixed independently of the store's counters: two measured records,
// the second carrying exactly 4096 bytes. The two subjects differ only in the
// byte allowance. Neither has enough events to reach the 16-event gate limit.
// ReleaseEvidence remains a test assertion, not evidence from a real worker;
// this test makes no claim about processing or an approved durable artifact.
func TestP3T9StorageRefusalOrdersHeldAuthorization(t *testing.T) {
	for _, controller := range []bool{false, true} {
		mode := "authorization_observes_storage"
		if controller {
			mode = "controller_before_release"
		}
		t.Run(mode, func(t *testing.T) {
			for _, exhaust := range []bool{false, true} {
				name, limit := "nonexhausted_control", int64(8192)
				if exhaust {
					name, limit = "actual_storage_refusal", 4096
				}
				t.Run(name, func(t *testing.T) {
					s, err := intake.New(limit)
					if err != nil || s == nil {
						t.Fatalf("positive-limit constructor unavailable; storage race NOT reached: %v", err)
					}
					t.Cleanup(func() {
						if err := s.Close(); err != nil {
							t.Errorf("close intake: %v", err)
						}
					})
					entered, release := make(chan struct{}), make(chan struct{})
					var hold atomic.Bool
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					defer unblock()
					g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{
						MaxEvents: 16, StorageExhausted: s.Exhausted(),
						BeforeAuthorize: func() {
							if hold.Load() {
								close(entered)
								<-release
							}
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					first := fragment.Record{
						Process: fragment.Process{PID: 171}, Connection: 1,
						Direction: fragment.Sent, Sequence: 1, Length: 7,
						Payload: []byte("pending"), At: time.Unix(100, 0),
					}
					if d := g.Admit(probe.DeliveryTransfer, true); !d.Admitted || !d.Charged || d.State.Charged != 1 || d.State.Reason != "" {
						t.Fatalf("first measured event refused: %+v", d)
					}
					if err := s.Write(first); err != nil {
						t.Fatalf("pending input not stored: %v", err)
					}
					pending := s.Take()
					if pending == nil || pending.Fragment == nil || pending.Connection != nil || !bytes.Equal(pending.Fragment.Payload, first.Payload) {
						t.Fatal("pending input not witnessed in worker-owned lease")
					}
					defer pending.Release()
					before := s.Stats()
					if before.Fragments != 1 || before.Leased != 1 || before.Queued != 0 || before.Bytes <= 7 || before.Exhausted {
						t.Fatalf("pending leased storage not established: %+v", before)
					}
					if state := g.Snapshot(); state.Reason != "" || state.Charged != 1 {
						t.Fatalf("gate invalid before held authorization: %+v", state)
					}
					hold.Store(true)
					decision := make(chan probe.ReleaseDecision, 1)
					go func() {
						decision <- g.Authorize(probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true})
					}()
					select {
					case <-entered:
					case <-time.After(3 * time.Second):
						t.Fatal("authorization seam not entered")
					}
					// Admit before storage refuses, exactly as delivery reserves the
					// decoded event before its downstream capture callback runs.
					admitted := make(chan probe.AdmissionDecision, 1)
					go func() { admitted <- g.Admit(probe.DeliveryTransfer, true) }()
					select {
					case d := <-admitted:
						if !d.Admitted || !d.Charged || d.State.Charged != 2 || d.State.Reason != "" {
							t.Fatalf("second measured event did not precede storage fault: %+v", d)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("held authorization blocked healthy admission")
					}
					second := first
					second.Connection, second.Sequence = 2, 1
					second.Payload, second.Length = bytes.Repeat([]byte{'S'}, 4096), 4096
					written := make(chan error, 1)
					go func() { written <- s.Write(second) }()
					select {
					case err := <-written:
						if exhaust && !errors.Is(err, intake.ErrLimit) {
							t.Fatalf("actual storage refusal NOT reached: %v", err)
						}
						if !exhaust && err != nil {
							t.Fatalf("same-input nonexhausted control refused: %v", err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("held authorization blocked intake callback")
					}
					select {
					case <-s.Exhausted():
						if !exhaust {
							t.Fatal("accepted control signaled exhaustion")
						}
					default:
						if exhaust {
							t.Fatal("actual refusal did not close the store-owned signal")
						}
					}
					after := s.Stats()
					if exhaust {
						if !after.Exhausted || after.FragmentsRefused != 1 || after.Fragments != 1 || after.Bytes != before.Bytes || after.Leased != 1 || after.Queued != 0 {
							t.Fatalf("refusal changed pending input or failed its accounting: %+v", after)
						}
						t.Log("actual_storage_refusal_reached: two admitted events, pending lease retained, ErrLimit and store-owned exhaustion witnessed while authorization held")
					} else {
						if after.Exhausted || after.FragmentsRefused != 0 || after.Fragments != 2 || after.Leased != 1 || after.Queued != 1 {
							t.Fatalf("same-input accepted population missing: %+v", after)
						}
						next := s.Take()
						if next == nil || next.Fragment == nil || !bytes.Equal(next.Fragment.Payload, second.Payload) {
							t.Fatal("accepted control did not retain second input")
						}
						defer next.Release()
					}
					want := probe.GateReason("")
					if exhaust {
						want = probe.GateStorageExhausted
					}
					// In the other branch, NO gate call occurs between the actual
					// refusal above and the held Authorize resuming below. Calling
					// Snapshot here would mask a missing Authorize observation.
					if controller {
						consumed := make(chan probe.GateSnapshot, 1)
						go func() { consumed <- g.ConsumeStorageExhaustion() }()
						select {
						case state := <-consumed:
							if state.Reason != want || state.Charged != 2 {
								t.Errorf("controller failed storage ordering: %+v; want reason %q, charged 2", state, want)
							}
						case <-time.After(3 * time.Second):
							t.Fatal("held authorization blocked controller consumption")
						}
						select {
						case <-g.Withdrawal():
							if !exhaust {
								t.Error("healthy controller requested withdrawal")
							}
						default:
							if exhaust {
								t.Error("controller returned without requesting withdrawal")
							}
						}
					}
					select {
					case d := <-decision:
						t.Fatalf("authorization escaped the held seam: %+v", d)
					default:
					}
					unblock()
					select {
					case d := <-decision:
						if d.Authorized != !exhaust || d.Reason != want {
							t.Errorf("authorization after witnessed storage callback: %+v; want authorized=%v reason=%q", d, !exhaust, want)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("released authorization did not finish")
					}
					// Check the signal BEFORE Snapshot, which is also a consumer.
					select {
					case <-g.Withdrawal():
						if !exhaust {
							t.Error("accepted control requested withdrawal")
						}
					default:
						if exhaust {
							t.Error("authorization returned without requesting withdrawal")
						}
					}
					if state := g.Snapshot(); state.Reason != want || state.Charged != 2 || state.MaxEvents != 16 {
						t.Errorf("storage consumption charged an event or named a different fault: %+v", state)
					}
					if !bytes.Equal(pending.Fragment.Payload, first.Payload) {
						t.Error("pending lease was discarded or changed instead of denying authorization")
					}
				})
			}
		})
	}
}
