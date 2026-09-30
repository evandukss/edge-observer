package probe_test

import (
	"sync"
	"testing"
	"time"

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

func TestDeliveryGateStorageObservedAtEachDecision(t *testing.T) {
	for _, operation := range []string{"controller", "snapshot", "admit", "authorize", "unsettled"} {
		for _, signal := range []string{"nil", "open", "closed"} {
			t.Run(operation+"/"+signal, func(t *testing.T) {
				var exhausted chan struct{}
				if signal != "nil" {
					exhausted = make(chan struct{})
				}
				if signal == "closed" {
					close(exhausted)
				}
				g := storageGate(t, 8, exhausted, nil)
				want := probe.GateSnapshot{MaxEvents: 8}
				if signal == "closed" {
					want.Reason = probe.GateStorageExhausted
				}
				// No other gate operation may consume the signal before the one
				// under test, or its missing observation would be hidden.
				switch operation {
				case "controller":
					if got := g.ConsumeStorageExhaustion(); got != want {
						t.Errorf("controller observation: got %+v, want %+v", got, want)
					}
				case "snapshot":
					if got := g.Snapshot(); got != want {
						t.Errorf("snapshot observation: got %+v, want %+v", got, want)
					}
				case "admit":
					allowed := signal != "closed"
					if allowed {
						want.Charged = 1
					}
					if got := g.Admit(probe.DeliveryClose, false); got.Admitted != allowed || got.Charged != allowed || got.State != want {
						t.Errorf("admission observation: %+v, want admitted/charged=%v state=%+v", got, allowed, want)
					}
				case "authorize", "unsettled":
					evidence := settledRelease()
					decision := probe.ReleaseDecision{Authorized: signal != "closed", Reason: want.Reason}
					if operation == "unsettled" {
						evidence = probe.ReleaseEvidence{}
						decision.Authorized = false
						if signal != "closed" {
							decision.Reason = probe.GateUnsettled
						}
					}
					if got := g.Authorize(evidence); got != decision {
						t.Errorf("authorization observation: got %+v, want %+v", got, decision)
					}
				}
				storageWithdrawal(t, g, signal == "closed")
				if got := g.Snapshot(); got != want {
					t.Errorf("diagnostic state: got %+v, want %+v", got, want)
				}
				if signal != "closed" {
					if got := g.Authorize(settledRelease()); !got.Authorized || got.Reason != "" {
						t.Errorf("settled control refused: %+v", got)
					}
				}
			})
		}
	}
}

func TestDeliveryGateStorageReasonDistinguishesReachableFaults(t *testing.T) {
	reasons := make(map[probe.GateReason]string)
	for _, cause := range []string{"storage", "unknown_length", "input_limit"} {
		t.Run(cause, func(t *testing.T) {
			exhausted := make(chan struct{})
			limit := uint64(8)
			if cause == "input_limit" {
				limit = 1
			}
			g := storageGate(t, limit, exhausted, nil)
			if got := g.Admit(probe.DeliveryTransfer, true); !got.Admitted || !got.Charged {
				t.Fatalf("measured input control not reached: %+v", got)
			}
			prior := g.Authorize(settledRelease())
			if !prior.Authorized {
				t.Fatalf("complete control refused: %+v", prior)
			}
			want := probe.GateSnapshot{MaxEvents: limit, Charged: 1}
			switch cause {
			case "storage":
				close(exhausted)
				want.Reason = probe.GateStorageExhausted
				if got := g.ConsumeStorageExhaustion(); got != want {
					t.Errorf("storage refusal below event cap: got %+v, want %+v", got, want)
				}
			case "unknown_length":
				want.Reason, want.Charged = probe.GateUnknownLength, 2
				if got := g.Admit(probe.DeliveryTransfer, false); got.Admitted || !got.Charged || got.State != want {
					t.Fatalf("unknown-length fault not reached: %+v", got)
				}
			case "input_limit":
				want.Reason = probe.GateInputLimit
				if got := g.Admit(probe.DeliveryClose, false); got.Admitted || got.Charged || got.State != want {
					t.Fatalf("input-limit fault not reached: %+v", got)
				}
			}
			storageWithdrawal(t, g, true)
			pending := g.Authorize(settledRelease())
			if pending.Authorized || pending.Reason != want.Reason {
				t.Errorf("pending release survived or misreported %s: %+v", cause, pending)
			}
			if other, exists := reasons[pending.Reason]; exists {
				t.Errorf("reader cannot distinguish %s from %s: reason %q", cause, other, pending.Reason)
			}
			reasons[pending.Reason] = cause
			if later := g.Admit(probe.DeliveryTransfer, false); later.Admitted || later.Charged || later.State != want {
				t.Errorf("later input changed invalidated state: %+v", later)
			}
			if !prior.Authorized {
				t.Error("completed authorization recalled")
			}
		})
	}
}

func TestDeliveryGateStoragePreservesFirstReason(t *testing.T) {
	for _, first := range []string{"storage", "unknown_length", "unknown_kind", "input_limit"} {
		t.Run(first, func(t *testing.T) {
			exhausted := make(chan struct{})
			g := storageGate(t, 1, exhausted, nil)
			if got := g.Admit(probe.DeliveryClose, false); !got.Admitted {
				t.Fatalf("ordinary close control refused: %+v", got)
			}
			want := probe.GateSnapshot{MaxEvents: 1, Charged: 1}
			switch first {
			case "storage":
				// N is already charged, but N+1 has not arrived. Exhaustion
				// must win over both the input cap and the new event's fault.
				close(exhausted)
				want.Reason = probe.GateStorageExhausted
				if got := g.Admit(probe.DeliveryTransfer, false); got.Admitted || got.Charged || got.State != want {
					t.Errorf("observable storage refusal did not precede event faults: %+v", got)
				}
			case "input_limit":
				want.Reason = probe.GateInputLimit
				g.Admit(probe.DeliveryClose, false)
				close(exhausted)
			default:
				g = storageGate(t, 8, exhausted, nil)
				want.MaxEvents = 8
				kind := probe.DeliveryTransfer
				want.Reason = probe.GateUnknownLength
				if first == "unknown_kind" {
					kind, want.Reason = 255, probe.GateUnknownKind
				}
				if got := g.Admit(kind, false); got.State != want {
					t.Fatalf("first fault not reached: %+v", got)
				}
				close(exhausted)
			}
			for i := 0; i < 2; i++ {
				if got := g.ConsumeStorageExhaustion(); got != want {
					t.Errorf("repeated consumption changed first reason: got %+v, want %+v", got, want)
				}
			}
			if got := g.Authorize(settledRelease()); got.Authorized || got.Reason != want.Reason {
				t.Errorf("first reason not retained for release: %+v", got)
			}
		})
	}
}

func TestDeliveryGateStoragePassesHeldAuthorization(t *testing.T) {
	for _, controller := range []bool{false, true} {
		for _, exhaustedNow := range []bool{false, true} {
			name := "without_controller"
			if controller {
				name = "with_controller"
			}
			if exhaustedNow {
				name += "/exhausted"
			} else {
				name += "/open_control"
			}
			t.Run(name, func(t *testing.T) {
				exhausted := make(chan struct{})
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				g := storageGate(t, 8, exhausted, func() { close(entered); <-release })
				if got := g.Admit(probe.DeliveryTransfer, true); !got.Admitted || !got.Charged {
					t.Fatalf("measured control not reached: %+v", got)
				}
				if got := g.Snapshot(); got.Reason != "" {
					t.Fatalf("pre-authorization snapshot not eligible: %+v", got)
				}
				result := make(chan probe.ReleaseDecision, 1)
				go func() { result <- g.Authorize(settledRelease()) }()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("authorization barrier not reached")
				}
				want := probe.ReleaseDecision{Authorized: true}
				if exhaustedNow {
					close(exhausted)
					want = probe.ReleaseDecision{Reason: probe.GateStorageExhausted}
				}
				if controller {
					consumed := make(chan probe.GateSnapshot, 1)
					go func() { consumed <- g.ConsumeStorageExhaustion() }()
					select {
					case got := <-consumed:
						if got.Reason != want.Reason || got.Charged != 1 {
							t.Errorf("controller while authorization held: %+v", got)
						}
					case <-time.After(time.Second):
						t.Fatal("held authorization blocked the controller")
					}
					storageWithdrawal(t, g, exhaustedNow)
				}
				unblock()
				select {
				case got := <-result:
					if got != want {
						t.Errorf("held authorization: got %+v, want %+v", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("authorization did not return after barrier release")
				}
				storageWithdrawal(t, g, exhaustedNow)
			})
		}
	}
}
