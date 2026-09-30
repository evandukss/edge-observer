package account_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// t23Known is a reading of the threads that found nothing under way.
var t23Known = probe.UnderWay{Known: true}

// A call under way when the probes were placed is counted on its own line and
// printed beside a seal that completed, as is every other loss; a session that
// lost nothing prints none there. A reading that is not known, or an account
// that carries none, says NOT KNOWN rather than nothing.
func TestALossIsPrintedOnTheLineThatSaysTheSessionSealed(t *testing.T) {
	control := ran(t, probe.Losses{UnderWay: t23Known})
	controlSeal := line(t, rendered(control, false), "sealed")
	if strings.Contains(controlSeal, "INCOMPLETE") || !control.Seal.Complete {
		t.Fatalf("wiring, not the property: the fixture's seal is not complete, so the line below is not the one "+
			"that says a session sealed complete: %q", controlSeal)
	}
	if strings.Contains(controlSeal, "LOST") || control.Lost() != "" {
		t.Errorf("a session that lost nothing prints a loss beside its seal: %q (%q)", controlSeal, control.Lost())
	}
	if got := integers(line(t, rendered(control, false), "under")); len(got) == 0 || got[0] != 0 {
		t.Errorf("a reading that found nothing under way counts %v", got)
	}

	for name, one := range map[string]struct {
		losses     probe.Losses
		rejected   int64
		unrecorded int64
		seal       string
		under      string
	}{
		"a thread under way": {
			losses: probe.Losses{UnderWay: probe.UnderWay{Known: true, Threads: 1,
				First: &probe.Blocked{PID: 10, TID: 12, FD: 5, Call: "read"}}},
			seal:  "LOST 1 threads under way when the probes were placed",
			under: "pid 10 thread 12 in read on descriptor 5",
		},
		"threads that ran while the probes were placed": {
			losses: probe.Losses{UnderWay: probe.UnderWay{Known: true, Undetermined: 3}},
			seal:   "LOST 3 threads NOT KNOWN, having run while the probes were placed",
			under:  "3 threads ran while the probes were placed, so whether each lost a call is NOT KNOWN",
		},
		"a thread that could not be read": {
			losses: probe.Losses{UnderWay: probe.UnderWay{Why: "thread 12 of pid 10: permission denied"}},
			seal:   "is NOT KNOWN: thread 12 of pid 10: permission denied",
			under:  "NOT KNOWN for the rest: thread 12 of pid 10: permission denied",
		},
		"an account that carries no reading": {
			losses: probe.Losses{},
			seal:   "is NOT KNOWN: this account does not carry a reading of the threads",
			under:  "NOT KNOWN for the rest: this account does not carry a reading of the threads",
		},
		"events the kernel could not buffer": {
			losses: probe.Losses{Dropped: 4, UnderWay: t23Known},
			seal:   "LOST 4 events the kernel could not buffer",
		},
		"returns with no entry recorded": {
			losses: probe.Losses{Unmatched: 2, UnderWay: t23Known},
			seal:   "LOST 2 returns with no entry recorded",
		},
		"records the intake refused": {
			losses: probe.Losses{UnderWay: t23Known}, rejected: 13, unrecorded: 1,
			seal: "LOST 13 records the volatile intake refused, 1 connection records the volatile intake refused",
		},
	} {
		t.Run(name, func(t *testing.T) {
			built := ran(t, one.losses)
			built.Seen.Rejected, built.Seen.ConnectionsUnrecorded = one.rejected, one.unrecorded
			content, err := json.Marshal(built)
			if err != nil {
				t.Fatalf("encode the account: %v", err)
			}
			var read account.Account
			if err := json.Unmarshal(content, &read); err != nil {
				t.Fatalf("decode the account: %v", err)
			}
			for moment, a := range map[string]account.Account{"as built": built, "read back": read} {
				text := rendered(a, false)
				if seal := line(t, text, "sealed"); !strings.Contains(seal, one.seal) {
					t.Errorf("%s, the seal line reads %q, want it to carry %q", moment, seal, one.seal)
				}
				if under := line(t, text, "under"); !strings.Contains(under, one.under) {
					t.Errorf("%s, the under-way line reads %q, want it to carry %q", moment, under, one.under)
				}
			}
		})
	}
}
