package probe_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/probe"
)

// T1 characterization only: the evidence below is supplied by the test, not
// established by a parser/worker. Each fault gets the same held-seam control.
func TestP3T9AuthorizationAfterHeldSeam(t *testing.T) {
	for _, fault := range []probe.GateReason{"", probe.GateUnknownLength} {
		name := string(fault)
		if name == "" {
			name = "settled_control"
		}
		t.Run(name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var hold atomic.Bool
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 8, BeforeAuthorize: func() {
				if hold.Load() {
					close(entered)
					<-release
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			if !g.Admit(probe.DeliveryTransfer, true).Admitted {
				t.Fatal("initial measured control refused")
			}
			evidence := probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}
			prior := g.Authorize(evidence)
			if !prior.Authorized || prior.Reason != "" {
				t.Fatalf("earlier settled decision refused: %+v", prior)
			}
			hold.Store(true)
			decision := make(chan probe.ReleaseDecision, 1)
			go func() { decision <- g.Authorize(evidence) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("authorization barrier not entered")
			}
			// The clear snapshot is deliberately read BEFORE the fault. Reusing
			// that diagnostic state as permission must not bypass the ordering.
			if s := g.Snapshot(); s.Reason != "" {
				t.Fatalf("fixture already invalidated: %+v", s)
			}
			if fault != "" {
				admission := make(chan probe.AdmissionDecision, 1)
				go func() { admission <- g.Admit(probe.DeliveryTransfer, fault != probe.GateUnknownLength) }()
				select {
				case d := <-admission:
					if d.Admitted || d.State.Reason != fault || d.Charged != (fault == probe.GateUnknownLength) {
						t.Fatalf("named fault not reached: %+v", d)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("held authorization blocked admission")
				}
				select {
				case <-g.Withdrawal():
				default:
					t.Fatal("fault returned without withdrawal signal")
				}
			}
			unblock()
			select {
			case d := <-decision:
				if d.Authorized != (fault == "") || d.Reason != fault {
					t.Fatalf("authorization crossed invalidation: %+v", d)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("released authorization did not finish")
			}
			// prior is a completed value. This is NOT proof of a retained usable
			// artifact; only the T3 worker integration can establish that.
			if !prior.Authorized {
				t.Fatal("prior decision changed")
			}
		})
	}
}
