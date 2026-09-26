package account

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// The reading of the threads reaches the contract account's loss block: its
// counts and first thread where it is known, and unavailable with its reason
// and what the readable threads showed where it is not - never counts of zero.
// Each projection is read back against the contract's own shape.
func TestTheCallsUnderWayReachTheContractAccountAndANotKnownReadingIsNotZero(t *testing.T) {
	for name, one := range map[string]struct {
		under probe.UnderWay
		check func(t *testing.T, got UnderWay)
	}{
		"known, one under way": {
			under: probe.UnderWay{Known: true, Threads: 1, Undetermined: 2,
				First: &probe.Blocked{PID: 10, TID: 12, FD: 5, Call: "read"}},
			check: func(t *testing.T, got UnderWay) {
				if got.State != Carried || got.Threads != "1" || got.Undetermined != "2" {
					t.Errorf("the block reads %+v, want carried with 1 under way and 2 undetermined", got)
				}
				if got.First.PID.Value != "10" || got.First.TID.Value != "12" || got.First.FD.Value != "5" ||
					got.First.Call.Value != "read" {
					t.Errorf("the first thread reads %+v, want pid 10 thread 12 in read on descriptor 5", got.First)
				}
			},
		},
		"known, none under way": {
			under: probe.UnderWay{Known: true},
			check: func(t *testing.T, got UnderWay) {
				if got.State != Carried || got.Threads != "0" || got.Undetermined != "0" {
					t.Errorf("the block reads %+v, want carried with nothing under way", got)
				}
				if got.First.PID.State != "undetermined" {
					t.Errorf("with nothing under way the first thread reads %+v, want undetermined", got.First)
				}
			},
		},
		"not known": {
			under: probe.UnderWay{Why: "thread 12 of pid 10: permission denied", Threads: 1},
			check: func(t *testing.T, got UnderWay) {
				if got.State != Unavailable || !strings.Contains(got.Why, "thread 12 of pid 10") ||
					!strings.Contains(got.Why, "1 were under way") || got.Threads != "" {
					t.Errorf("the block reads %+v, want unavailable with its reason and the readable count", got)
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			source := filled(t, true)
			source.Loss.UnderWay = one.under
			projected, err := Project(source, NotSupplied())
			if err != nil {
				t.Fatalf("project the account: %v", err)
			}
			if projected.Capture.Loss.State != Carried {
				t.Fatalf("wiring, not the property: the loss block is %s, so the reading inside it is not read",
					projected.Capture.Loss.State)
			}
			one.check(t, projected.Capture.Loss.UnderWay)

			content, err := json.Marshal(projected)
			if err != nil {
				t.Fatalf("encode the projection: %v", err)
			}
			_, findings, blocks := readAccount("account", content)
			if blocks == 0 {
				t.Fatal("wiring, not the property: the shape read no blocks, so its silence measures nothing")
			}
			for _, finding := range findings {
				if strings.HasPrefix(finding.At, "capture.loss") {
					t.Errorf("the contract refuses the loss block it was given: %+v", finding)
				}
			}
		})
	}
}
