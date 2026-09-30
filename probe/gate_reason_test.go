package probe_test

import (
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// The declarations, not GateReasons itself or a test literal, supply the
// population. A new constant omitted from enumeration must fail this test.
func TestGateReasonEnumerationCoversDeclarations(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "gate_reason.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	config := types.Config{}
	pkg, err := config.Check("probe", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reasonType := pkg.Scope().Lookup("GateReason").Type()
	declared := make(map[probe.GateReason]string)
	for _, name := range pkg.Scope().Names() {
		value, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || !types.Identical(value.Type(), reasonType) {
			continue
		}
		reason := probe.GateReason(constant.StringVal(value.Val()))
		if previous, exists := declared[reason]; exists {
			t.Fatalf("reason declarations %s and %s alias %q", previous, name, reason)
		}
		declared[reason] = name
	}
	if _, ok := declared[probe.GateUnknownKind]; !ok {
		t.Fatal("declaration reader did not reach the known unknown-kind control")
	}
	for _, reason := range probe.GateReasons() {
		if _, ok := declared[reason]; !ok {
			t.Errorf("enumerated undeclared or repeated reason %q", reason)
		}
		delete(declared, reason)
	}
	for reason, name := range declared {
		t.Errorf("declared reason %s (%q) missing from GateReasons", name, reason)
	}
}

func TestGateReasonClassifiesReachedDecisions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fault       func(*probe.DeliveryGate, chan struct{}) probe.GateReason
		want        probe.GateReason
		invalidates bool
	}{
		{"input_limit", func(g *probe.DeliveryGate, _ chan struct{}) probe.GateReason {
			return g.Admit(probe.DeliveryClose, false).State.Reason
		}, probe.GateInputLimit, true},
		{"storage_exhausted", func(g *probe.DeliveryGate, exhausted chan struct{}) probe.GateReason {
			close(exhausted)
			return g.Snapshot().Reason
		}, probe.GateStorageExhausted, true},
		{"unknown_length", func(g *probe.DeliveryGate, _ chan struct{}) probe.GateReason {
			return g.Admit(probe.DeliveryTransfer, false).State.Reason
		}, probe.GateUnknownLength, true},
		{"unknown_kind", func(g *probe.DeliveryGate, _ chan struct{}) probe.GateReason {
			return g.Admit(255, true).State.Reason
		}, probe.GateUnknownKind, true},
		{"unsettled", func(g *probe.DeliveryGate, _ chan struct{}) probe.GateReason {
			return g.Authorize(probe.ReleaseEvidence{}).Reason
		}, probe.GateUnsettled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit := uint64(2)
			if tc.want == probe.GateInputLimit {
				limit = 1
			}
			exhausted := make(chan struct{})
			g := storageGate(t, limit, exhausted, nil)
			if got := g.Admit(probe.DeliveryClose, false); !got.Admitted || !got.Charged {
				t.Fatalf("ordinary close control refused: %+v", got)
			}
			if got := g.Authorize(settledRelease()); !got.Authorized || got.Reason != "" {
				t.Fatalf("settled control refused: %+v", got)
			}
			reason := tc.fault(g, exhausted)
			if reason != tc.want {
				t.Fatalf("fault not reached: got %q, want %q", reason, tc.want)
			}
			if got := reason.InvalidatesCapture(); got != tc.invalidates {
				t.Errorf("%q InvalidatesCapture = %t, want %t", reason, got, tc.invalidates)
			}
			storageWithdrawal(t, g, tc.invalidates)
			if got := g.Authorize(settledRelease()); got.Authorized == tc.invalidates {
				t.Errorf("classification disagrees with later release: %+v", got)
			}
		})
	}
	for _, reason := range []probe.GateReason{probe.GateUninitialized, "", "future_reason"} {
		if reason.InvalidatesCapture() {
			t.Errorf("non-invalidation %q classified as capture-wide", reason)
		}
	}
}

func TestGateReasonEnumerationIsCallerOwned(t *testing.T) {
	first := probe.GateReasons()
	if len(first) == 0 {
		t.Fatal("no reasons enumerated")
	}
	want := append([]probe.GateReason(nil), first...)
	for i := range first {
		first[i] = "caller_changed"
	}
	got := probe.GateReasons()
	if !slices.Equal(got, want) {
		t.Fatalf("caller changed later enumeration: %v, want %v", got, want)
	}
	if !probe.GateUnknownKind.InvalidatesCapture() {
		t.Fatal("caller changed classification")
	}
}

// Run with -run '^TestDeliveryGateUninitializedRefusesEveryEntry$'. The
// initialized_control/snapshot and initialized_control/consume leaves require
// their admit sibling to charge the shared gate first. Selecting either leaf
// alone fails for missing sibling setup, not for the property under test.
func TestDeliveryGateUninitializedRefusesEveryEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate *probe.DeliveryGate
	}{
		{"nil", nil},
		{"zero", new(probe.DeliveryGate)},
		{"initialized_control", deliveryGate(t, 2, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initialized := tc.name == "initialized_control"
			want := probe.GateSnapshot{Reason: probe.GateUninitialized}
			if initialized {
				want = probe.GateSnapshot{MaxEvents: 2, Charged: 1}
			}
			g := tc.gate
			t.Run("admit", func(t *testing.T) {
				got := g.Admit(probe.DeliveryClose, false)
				if got.Admitted != initialized || got.Charged != initialized || got.State != want {
					t.Errorf("admission = %+v, want admitted/charged %t, state %+v", got, initialized, want)
				}
			})
			t.Run("authorize", func(t *testing.T) {
				got := g.Authorize(settledRelease())
				if got.Authorized != initialized || got.Reason != want.Reason {
					t.Errorf("authorization = %+v, want authorized %t, reason %q", got, initialized, want.Reason)
				}
			})
			t.Run("snapshot", func(t *testing.T) {
				if got := g.Snapshot(); got != want {
					t.Errorf("snapshot = %+v, want %+v", got, want)
				}
			})
			t.Run("consume", func(t *testing.T) {
				if got := g.ConsumeStorageExhaustion(); got != want {
					t.Errorf("consume = %+v, want %+v", got, want)
				}
			})
			t.Run("withdrawal", func(t *testing.T) {
				storageWithdrawal(t, g, !initialized)
			})
		})
	}
}
