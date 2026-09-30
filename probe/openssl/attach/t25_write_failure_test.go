//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// Case 1 of P3-T25, criterion rows 1 and 13: an approved write that fails
// writes no protected plaintext anywhere at the write boundary - no retry, no
// fallback file, no log line, no stderr - and the account counts it as an
// output failure. The failure here is the approved-output bound: each closing
// connection is forty 3000-byte answers written as one record, and the record
// that does not fit in the 1 MiB configuring writes is refused. Every request
// carries the protected marker in the Authorization header the policy removes,
// and the permitted marker in X-Public. The full-filesystem failure, where the
// write itself fails, is the first case of
// TestT25AFatalDiagnosticCarriesNoProtectedPlaintext.
//
// The control is the same run with two connections, which fit.
func TestT25AFailedApprovedWriteWritesNoProtectedPlaintext(t *testing.T) {
	binary := built(t)
	for _, connections := range []int{8, 2} {
		failing := connections == 8
		name := map[bool]string{true: "a record over the bound", false: "every record within the bound"}[failing]
		t.Run(name, func(t *testing.T) {
			port := t18Serving(t)
			decided := speaking(t, port)
			clients := make([]conversation, connections)
			for i := range clients {
				clients[i] = speaking(t, port)
			}
			c := configuring(t, target("clients", decided.process))
			t18Edit(t, c, t18Removing)
			w := t25Watched(t, binary, c, nil)
			t25Decided(t, binary, c, decided)

			for i, client := range clients {
				if w.over() {
					break
				}
				for j := range 40 {
					t18Ask(t, client, fmt.Sprintf("/blob?asked=t25-bound-%d-%d", i, j),
						"X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
				}
				t18Hangup(client)
				t25Settled(t, binary, c, w, uint64(2*(i+2)), 20*time.Second)
			}
			if failing {
				w.ended(t, 30*time.Second)
			} else {
				w.signal(t, syscall.SIGTERM)
			}
			sealed := t18Sealed(t, w.directory(c), w.session)
			targets := t18Targets(t18Approved(t, w.directory(c)))
			t.Logf("processing %+v; seal %+v", sealed.Processing, sealed.Seal)

			if !failing {
				if sealed.Processing.OutputFailures != 0 || !slices.Contains(targets, "/blob?asked=t25-bound-1-39") {
					t.Fatalf("wiring, not the property: the control failed a write or lost a record: %+v", sealed.Processing)
				}
				t25Clean(t, w)
				return
			}
			// The guard: a record really was refused, after one was written.
			refused := -1
			for i := range clients {
				if !slices.Contains(targets, fmt.Sprintf("/blob?asked=t25-bound-%d-0", i)) {
					refused = i
					break
				}
			}
			if refused < 1 || sealed.Processing.OutputFailures == 0 || sealed.Processing.GateReason != probe.GateStorageExhausted {
				t.Fatalf("wiring, not the property: no record was refused at the bound after one was written (first "+
					"missing connection %d, processing %+v)", refused, sealed.Processing)
			}
			if sealed.Processing.ProcessingFailures != 0 || sealed.Loss == nil || sealed.Loss.Dropped != 0 {
				t.Errorf("the refused write is counted as something else: processing %+v, loss %+v",
					sealed.Processing, sealed.Loss)
			}
			because := ""
			if sealed.Seal != nil {
				because = strings.Join(sealed.Seal.Because, "; ")
			}
			if !strings.Contains(because, "approved output storage limit reached") {
				t.Errorf("the seal does not say the output was refused: %q", because)
			}
			t25Clean(t, w)
		})
	}
}

// over reports whether the watched observer has ended.
func (w *t25Watch) over() bool {
	select {
	case <-w.exited:
		return true
	default:
		return false
	}
}

// t25Settled waits until the watched session has written at least want
// records, or has ended; ending is one of the outcomes being measured, and a
// question the ending session cannot answer is asked again, not failed.
func t25Settled(t *testing.T, binary string, c configured, w *t25Watch, want uint64, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if w.over() {
			return
		}
		stdout, _, err := t18Command(t, 30*time.Second, binary, "inspect", c.path)
		var live account.Account
		if err == nil && json.Unmarshal([]byte(stdout), &live) == nil && t18Written(live) >= want {
			return
		}
	}
	t.Fatalf("wiring, not the property: the session neither wrote %d records nor ended in %s: %s", want, within, w.boundary)
}
