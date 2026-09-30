package main

import (
	"os"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
)

func TestIdleControllerConsumesStorageExhaustion(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		store, err := intake.New(4096)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		if err := store.Write(fragment.Record{Payload: []byte("fits")}); err != nil {
			t.Fatalf("storage control refused: %v", err)
		}
		// This unit test isolates the controller's channel consumption. The
		// writer integration must separately establish which owner supplies it.
		storageExhausted := make(chan struct{})
		gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4, StorageExhausted: storageExhausted})
		if err != nil {
			t.Fatal(err)
		}
		d := &daemon{intake: store, gate: gate, storageExhausted: storageExhausted}
		stop := make(chan os.Signal, 1)
		done := make(chan struct{})
		go func() {
			d.serveUntilStop(stop, nil, nil, nil, nil, account.Account{})
			close(done)
		}()
		if exhausted {
			close(storageExhausted)
		} else {
			stop <- os.Interrupt
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			stop <- os.Interrupt
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("controller did not respond to cleanup stop")
			}
			t.Fatal("idle controller did not observe storage exhaustion without a gate decision")
		}
		want := uint64(0)
		if exhausted {
			want = 1
		}
		// This controller-only counter catches missing production selection.
		// Snapshot or Admit could otherwise consume the closure themselves and
		// make an unwired idle controller look correct. Assert before either.
		if d.storageExhaustionConsumptions != want {
			t.Fatalf("controller consumption witness = %d, want %d (exhausted=%t)", d.storageExhaustionConsumptions, want, exhausted)
		}
		withdrawn := false
		select {
		case <-gate.Withdrawal():
			withdrawn = true
		default:
		}
		if withdrawn != exhausted {
			t.Fatalf("controller withdrawal=%t, storage exhausted=%t", withdrawn, exhausted)
		}
	}
}
