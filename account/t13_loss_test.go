package account_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/probe"
)

// A loss nobody could count reads NOT KNOWN, with the reason, in the account
// and in its text, and does so again once the account has been written and
// read back, which is how a sealed session's account is inspected. A loss
// counted at zero is the control: it reads as a number, so the two are told
// apart.
func TestAnUncountedLossReadsNotKnownRatherThanNone(t *testing.T) {
	const why = "the kernel's loss counters could not be read"
	uncounted := ran(t, probe.Losses{})
	uncounted.Ran(moment.Add(time.Minute), account.Run{
		Seen:      capture.Stats{Transfers: 20, Records: 12, Connections: 2},
		LossesErr: errFixed(why),
		Refusals:  map[string]int64{},
	})
	counted := ran(t, probe.Losses{})

	content, err := json.Marshal(uncounted)
	if err != nil {
		t.Fatalf("encode the account: %v", err)
	}
	var read account.Account
	if err := json.Unmarshal(content, &read); err != nil {
		t.Fatalf("decode the account: %v", err)
	}

	for name, a := range map[string]account.Account{"as built": uncounted, "written and read back": read} {
		text := rendered(a, false)
		if !strings.Contains(text, "capturing  ") || a.Loss == nil {
			t.Fatalf("wiring, not the property: the %s account renders no capture section or carries no loss, "+
				"so its lost line was never reached:\n%s", name, text)
		}
		if a.Loss.Known || a.Loss.Why != why {
			t.Errorf("the %s account's loss is %+v, want not known because %q", name, *a.Loss, why)
		}
		if got := line(t, text, "lost"); got != "lost       NOT KNOWN: "+why {
			t.Errorf("the %s account's lost line reads %q, want NOT KNOWN with the reason", name, got)
		}
	}
	if strings.Contains(string(content), `"loss":{"known":true`) {
		t.Errorf("the encoded account says its loss is known: %s", content)
	}

	text := rendered(counted, false)
	if got := line(t, text, "lost"); strings.Contains(got, "NOT KNOWN") || !strings.HasPrefix(got, "lost       0 events") {
		t.Errorf("a loss counted at zero reads %q, want it read as the number", got)
	}
}
