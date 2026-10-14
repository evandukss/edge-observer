//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/processing"
)

// An approved write that fails writes no protected plaintext anywhere at the
// write boundary - no retry, no fallback file, no log line, no stderr - and the
// account counts it as a failed attempt. The failure is the write itself: once
// the first connection is written, the running observer's file size limit
// (RLIMIT_FSIZE, set from outside it) is put a few bytes past the end of the
// approved file, so the kernel cuts the next approved write and refuses every
// one after it. Every request carries the protected marker in the Authorization
// header the policy removes, and the permitted marker in X-Public. A failed
// write costs lines, never the session, which is then stopped.
//
// The control is the same run with no limit.
func TestAFailedApprovedWriteWritesNoProtectedPlaintext(t *testing.T) {
	binary := built(t)
	for _, failing := range []bool{true, false} {
		name := map[bool]string{true: "writes the kernel cuts", false: "every write accepted"}[failing]
		t.Run(name, func(t *testing.T) {
			port := liveServing(t)
			decided := speaking(t, port)
			clients := []conversation{speaking(t, port), speaking(t, port)}
			c := configuring(t, target("clients", decided.process))
			liveEdit(t, c, liveRemoving)
			w := failureWatched(t, binary, c, nil)
			failureDecided(t, binary, c, decided)
			approved := filepath.Join(c.directory, processing.ArtifactName)

			// Each connection is ten exchange records and its retirement record;
			// the decided connection before them is two.
			const asked = 10
			var limit int64
			for i, client := range clients {
				if i == 1 && failing {
					failureAttempted(t, binary, c, w, 2+asked+1, 20*time.Second)
					info, err := os.Stat(approved)
					if err != nil {
						t.Fatalf("wiring, not the property: no approved file before the limit: %v", err)
					}
					limit = info.Size() + 64
					var old unix.Rlimit
					if err := unix.Prlimit(w.command.Process.Pid, unix.RLIMIT_FSIZE, nil, &old); err != nil {
						t.Fatalf("wiring, not the property: read the observer's file size limit: %v", err)
					}
					if err := unix.Prlimit(w.command.Process.Pid, unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: uint64(limit), Max: old.Max}, nil); err != nil {
						t.Fatalf("wiring, not the property: set the observer's file size limit: %v", err)
					}
				}
				for j := range asked {
					liveAsk(t, client, fmt.Sprintf("/blob?asked=hlt-write-%d-%d", i, j),
						"X-Public: "+liveBoundaryPermitted, "Authorization: Bearer "+liveBoundaryProtected)
				}
				liveHangup(client)
				failureAttempted(t, binary, c, w, uint64(2+(i+1)*(asked+1)), 20*time.Second)
			}
			if w.over() {
				t.Fatalf("the session ended on a failed approved write:\n%s", w.stderrText())
			}
			w.signal(t, syscall.SIGTERM)
			sealed := liveSealed(t, w.directory(c), w.session)
			t.Logf("processing %+v; seal %+v", sealed.Processing, sealed.Seal)
			delivery := sealed.Processing.Delivery

			if !failing {
				if delivery.Failed != 0 || !slices.Contains(liveTargets(liveApproved(t, w.directory(c))), "/blob?asked=hlt-write-1-9") {
					t.Fatalf("wiring, not the property: the control failed a write or lost a record: %+v", delivery)
				}
				failureClean(t, w)
				return
			}
			// The guards: the kernel cut a write at the limit, after the first
			// connection was written whole.
			info, err := os.Stat(approved)
			if err != nil || info.Size() != limit || delivery.Failed < asked+1 {
				t.Fatalf("wiring, not the property: the approved file is %v bytes (%v), want cut at %d, with %d attempts "+
					"failed of the second connection's %d", info, err, limit, delivery.Failed, asked+1)
			}
			if delivery.Written+delivery.Failed+delivery.Dropped+delivery.Pending != delivery.Authorized ||
				delivery.Written != 2+asked+1 {
				t.Errorf("the failed writes are not counted apart: %+v", delivery)
			}
			if sealed.Processing.ProcessingFailures != 0 || sealed.Loss == nil || sealed.Loss.Dropped != 0 {
				t.Errorf("the failed write is counted as something else: processing %+v, loss %+v",
					sealed.Processing, sealed.Loss)
			}
			failureClean(t, w)
		})
	}
}

// failureAttempted waits until the watched session's approved destination has
// had at least want lines authorised and holds none pending.
func failureAttempted(t *testing.T, binary string, c configured, w *failureWatch, want uint64, within time.Duration) {
	t.Helper()
	var live account.Account
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if w.over() {
			t.Fatalf("the session ended while its lines were being written:\n%s", w.stderrText())
		}
		stdout, _, err := liveCommand(t, 30*time.Second, binary, "inspect", c.path)
		if err == nil && json.Unmarshal([]byte(stdout), &live) == nil && live.Processing != nil &&
			live.Processing.Delivery.Authorized >= want && live.Processing.Delivery.Pending == 0 {
			return
		}
	}
	t.Fatalf("wiring, not the property: the session did not attempt %d approved lines in %s: %+v", want, within, live.Processing)
}

// over reports whether the watched observer has ended.
func (w *failureWatch) over() bool {
	select {
	case <-w.exited:
		return true
	default:
		return false
	}
}

// failureSettled waits until the watched session has written at least want
// records, or has ended; ending is one of the outcomes being measured, and a
// question the ending session cannot answer is asked again, not failed.
func failureSettled(t *testing.T, binary string, c configured, w *failureWatch, want uint64, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if w.over() {
			return
		}
		stdout, _, err := liveCommand(t, 30*time.Second, binary, "inspect", c.path)
		var live account.Account
		if err == nil && json.Unmarshal([]byte(stdout), &live) == nil && liveWritten(live) >= want {
			return
		}
	}
	t.Fatalf("wiring, not the property: the session neither wrote %d records nor ended in %s: %s", want, within, w.boundary)
}
