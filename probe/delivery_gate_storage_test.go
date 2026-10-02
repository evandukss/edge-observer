package probe_test

import (
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

func storageGate(t *testing.T, limit uint64, exhausted <-chan struct{}, hook func()) *probe.DeliveryGate {
	t.Helper()
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{
		MaxEvents: limit, StorageExhausted: exhausted, BeforeAuthorize: hook,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func storageWithdrawal(t *testing.T, g *probe.DeliveryGate, want bool) {
	t.Helper()
	select {
	case <-g.Withdrawal():
		if !want {
			t.Error("non-exhausted control requested withdrawal")
		}
	default:
		if want {
			t.Error("storage exhaustion returned without requesting withdrawal")
		}
	}
}
