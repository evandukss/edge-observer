package probe_test

import (
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/probe"
)

func deliveryGate(t *testing.T, limit uint64, hook func()) *probe.DeliveryGate {
	t.Helper()
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: limit, BeforeAuthorize: hook})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func settledRelease() probe.ReleaseEvidence {
	return probe.ReleaseEvidence{InputsSettled: true, LifecycleSettled: true}
}

func assertWithdrawal(t *testing.T, g *probe.DeliveryGate, want bool) {
	t.Helper()
	select {
	case <-g.Withdrawal():
		if !want {
			t.Error("eligible control requested withdrawal")
		}
	default:
		if want {
			t.Error("invalidated gate did not request withdrawal")
		}
	}
}

func TestDeliveryGateValidatesItsOnlyOption(t *testing.T) {
	if _, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{}); err == nil {
		t.Fatal("zero event allowance accepted")
	}
	g := deliveryGate(t, 1, nil)
	if got := g.Admit(probe.DeliveryClose, false); !got.Admitted || !got.Charged {
		t.Fatalf("positive allowance must admit the ordinary close: %+v", got)
	}
}

func TestDeliveryGateChargesOrdinaryClosesAndEmptyTransfers(t *testing.T) {
	g := deliveryGate(t, 4, nil)
	for i, kind := range []probe.DeliveryKind{probe.DeliveryClose, probe.DeliveryTransfer, probe.DeliveryClose, probe.DeliveryTransfer} {
		got := g.Admit(kind, kind == probe.DeliveryTransfer)
		if !got.Admitted || !got.Charged || got.State.Charged != uint64(i+1) || got.State.Reason != "" {
			t.Fatalf("event %d, kind %d: %+v", i+1, kind, got)
		}
		select {
		case <-g.Withdrawal():
			t.Fatal("valid event requested withdrawal")
		default:
		}
	}
	if got := g.Authorize(settledRelease()); !got.Authorized {
		t.Fatalf("decidable control refused: %+v", got)
	}
}

func TestDeliveryGateFaultsRevokePendingButKeepPriorAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name         string
		kind         probe.DeliveryKind
		measured     bool
		limit        uint64
		charged      uint64
		faultCharged bool
		reason       probe.GateReason
	}{
		{"unknown length", probe.DeliveryTransfer, false, 10, 2, true, probe.GateUnknownLength},
		{"unknown kind", 255, true, 10, 2, true, probe.GateUnknownKind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := deliveryGate(t, tc.limit, nil)
			if got := g.Admit(probe.DeliveryTransfer, true); !got.Admitted {
				t.Fatalf("measured control not reached: %+v", got)
			}
			prior := g.Authorize(settledRelease())
			if !prior.Authorized {
				t.Fatal("complete closed control not authorized")
			}
			got := g.Admit(tc.kind, tc.measured)
			if got.Admitted || got.Charged != tc.faultCharged || got.State.Charged != tc.charged || got.State.Reason != tc.reason {
				t.Fatalf("fault not reached or classified: %+v", got)
			}
			select {
			case <-g.Withdrawal():
			default:
				t.Fatal("fault returned without signalling withdrawal")
			}
			if pending := g.Authorize(settledRelease()); pending.Authorized || pending.Reason != tc.reason {
				t.Fatalf("pending result survived invalidation: %+v", pending)
			}
			if later := g.Admit(probe.DeliveryTransfer, true); later.Admitted || later.Charged || later.State != got.State {
				t.Fatalf("closed capture admitted, refunded or changed reason: %+v", later)
			}
			if !prior.Authorized {
				t.Fatal("earlier complete result was recalled")
			}
		})
	}
}

func TestDeliveryGateRequiresBothKindsOfSettledEvidence(t *testing.T) {
	g := deliveryGate(t, 8, nil)
	for _, evidence := range []probe.ReleaseEvidence{{}, {InputsSettled: true}, {LifecycleSettled: true}} {
		if got := g.Authorize(evidence); got.Authorized || got.Reason != probe.GateUnsettled {
			t.Fatalf("unsettled result accepted: %+v", got)
		}
	}
	if got := g.Authorize(settledRelease()); !got.Authorized || got.Reason != "" {
		t.Fatalf("settled control refused: %+v", got)
	}
}

func TestDeliveryGateInvalidationPassesAHeldAuthorization(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	g := deliveryGate(t, 10, func() { close(entered); <-release })
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	if got := g.Admit(probe.DeliveryTransfer, true); !got.Admitted {
		t.Fatalf("initial input refused: %+v", got)
	}
	if g.Snapshot().Reason != "" {
		t.Fatal("pre-fault snapshot was not clear")
	}
	result := make(chan probe.ReleaseDecision, 1)
	go func() { result <- g.Authorize(settledRelease()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authorization seam not reached")
	}
	fault := make(chan probe.AdmissionDecision, 1)
	go func() { fault <- g.Admit(probe.DeliveryTransfer, false) }()
	select {
	case got := <-fault:
		if got.State.Reason != probe.GateUnknownLength {
			t.Fatalf("invalidation not reached: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("held worker blocked invalidation")
	}
	select {
	case <-g.Withdrawal():
	default:
		t.Fatal("withdrawal signal blocked behind the worker")
	}
	unblock()
	select {
	case got := <-result:
		if got.Authorized || got.Reason != probe.GateUnknownLength {
			t.Fatalf("read-true, invalidate, authorize interleaving escaped: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("authorization did not finish after barrier release")
	}
}
