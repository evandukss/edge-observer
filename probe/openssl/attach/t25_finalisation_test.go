//go:build attach

package attach_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/processing"
)

// t25Truncations is every truncation reason the approved records at directory
// carry, read from the records' own JSON.
func t25Truncations(t *testing.T, directory string) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, processing.ArtifactName))
	if err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	var reasons []string
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte{'\n'}) {
		var one struct {
			Truncation *struct {
				Stops []struct {
					Reason string `json:"reason"`
				} `json:"stops"`
			} `json:"reconstruction_truncation"`
		}
		if err := json.Unmarshal(line, &one); err != nil {
			t.Fatalf("an approved record is not JSON: %v", err)
		}
		if one.Truncation != nil {
			for _, stop := range one.Truncation.Stops {
				reasons = append(reasons, stop.Reason)
			}
		}
	}
	return reasons
}

// Case 3B of P3-T25, at the syscall boundary (ruling, todo 187 comment 2260):
// undecided data held at stop is discarded and writes no protected plaintext.
// An open connection carries a complete exchange with both markers, then the
// start of a request whose Authorization carries the protected marker and whose
// headers never end. At stop the complete exchange is written with the
// protected header removed, the suffix is withheld with a stated truncation
// reason and counted as a processing failure, and the protected marker crosses
// no write. The control is the same connection without the suffix.
func TestT25UndecidedDataHeldAtStopIsDiscardedWithoutProtectedPlaintext(t *testing.T) {
	binary := built(t)
	for _, suffix := range []bool{true, false} {
		name := map[bool]string{true: "an undecidable suffix held at stop", false: "the complete exchange only"}[suffix]
		t.Run(name, func(t *testing.T) {
			port := t18Serving(t)
			decided, open := speaking(t, port), speaking(t, port)
			c := configuring(t, target("clients", decided.process))
			t18Edit(t, c, t18Removing)
			w := t25Watched(t, binary, c, nil)
			t25Decided(t, binary, c, decided)
			t18Ask(t, open, "/?asked=t25-complete", "X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
			if suffix {
				before := inspected(t, binary, c).Seen.Records
				if _, err := io.WriteString(open.send, "GET /?asked=t25-suffix HTTP/1.1\r\nHost: localhost\r\n"+
					"Authorization: Bearer "+t18BoundaryProtected+"\r\n"); err != nil {
					t.Fatalf("send the suffix: %v", err)
				}
				// The guard: the suffix reached capture before the stop.
				t18Until(t, binary, c, 10*time.Second, "wiring, not the property: the suffix never reached capture",
					func(a account.Account) bool { return a.Seen != nil && a.Seen.Records > before })
			}
			w.signal(t, syscall.SIGTERM)
			sealed := t18Sealed(t, w.directory(c), w.session)
			targets := t18Targets(t18Approved(t, w.directory(c)))
			reasons := t25Truncations(t, w.directory(c))
			t.Logf("processing %+v; truncations %v; targets %v", sealed.Processing, reasons, targets)
			if !slices.Contains(targets, "/?asked=t25-complete") {
				t.Fatalf("wiring, not the property: the complete exchange before the suffix was not written: %v", targets)
			}
			if suffix {
				if slices.Contains(targets, "/?asked=t25-suffix") {
					t.Errorf("the undecidable suffix was written as an exchange")
				}
				if sealed.Processing.ProcessingFailures == 0 || !slices.Contains(reasons, "incomplete_message") {
					t.Errorf("the account does not say why the suffix was withheld: processing %+v, truncations %v",
						sealed.Processing, reasons)
				}
			} else if sealed.Processing.ProcessingFailures != 0 || len(reasons) != 0 {
				t.Fatalf("wiring, not the property: the control withheld something: %+v %v", sealed.Processing, reasons)
			}
			t25Clean(t, w)
		})
	}
}

// Case 3C of P3-T25, at the syscall boundary (ruling, todo 187 comment 2260).
// The worker's approved write of the open connection's exchange, made during
// finalisation, is held in the kernel by the instrument, so finalisation waits
// on it without a deadline. The stop command is run and allowed to reach its
// own bound, stopWithin. What stop reported and the session's state after the
// bound are RECORDED, not asserted: that behaviour is untested and a finding
// only if plaintext crosses a write. Then the write is released and the session
// is let finish. Asserted, before the release and across the end: the
// protected marker crosses no write.
func TestT25AWorkerHeldAtStopWritesNoProtectedPlaintextBeforeOrAfterTheStopBound(t *testing.T) {
	binary := built(t)
	port := t18Serving(t)
	decided, open := speaking(t, port), speaking(t, port)
	c := configuring(t, target("clients", decided.process))
	t18Edit(t, c, t18Removing)
	release := make(chan struct{})
	var releasing sync.Once
	t.Cleanup(func() { releasing.Do(func() { close(release) }) })
	var held atomic.Int64
	w := t25Watched(t, binary, c, t25Holding([]byte("asked=t25-held"), release, &held))
	t25Decided(t, binary, c, decided)
	t18Ask(t, open, "/?asked=t25-held", "X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)

	began := time.Now()
	stdout, stderr, stopErr := t18Command(t, 120*time.Second, binary, "stop", c.path)
	took := time.Since(began)
	// The guards: the worker's write really was held, and the stop bound really
	// ran out with the session still up.
	if held.Load() == 0 {
		t.Fatalf("wiring, not the property: no approved write was held, so nothing was waited on: %s", w.boundary)
	}
	if w.over() {
		t.Fatalf("wiring, not the property: the session ended with its worker's write held:\n%s", w.stderrText())
	}
	t.Logf("RECORDED: stop answered after %s with %v; stdout %q; stderr %q", took.Round(time.Millisecond), stopErr, stdout, stderr)
	pid, _ := os.ReadFile(c.pidFile())
	inspectOut, inspectErr, inspectExit := t18Command(t, 60*time.Second, binary, "inspect", c.path)
	t.Logf("RECORDED after the bound: session running %v; pid file %q; %d writes held; inspect %v, stdout %q, stderr %q",
		!w.over(), strings.TrimSpace(string(pid)), held.Load(), inspectExit, inspectOut, inspectErr)
	w.boundary.mutex.Lock()
	protectedBefore := w.boundary.found[t18BoundaryProtected]
	w.boundary.mutex.Unlock()
	if protectedBefore != 0 {
		t.Errorf("the protected marker crossed %d writes before the held write was released", protectedBefore)
	}

	releasing.Do(func() { close(release) })
	w.ended(t, 60*time.Second)
	t.Logf("RECORDED after the release: exit %v; stopped records %v", w.state, w.records("stopped"))
	if !slices.Contains(t18Targets(t18Approved(t, w.directory(c))), "/?asked=t25-held") {
		t.Errorf("the held exchange was not written once released")
	}
	t25Clean(t, w)
}

// t25Recorded is the approved output with every line handed to it kept, so an
// in-process case can see what reached the output whether or not it was
// written.
type t25Recorded struct {
	inner processing.Output
	mutex sync.Mutex
	lines [][]byte
}

func (r *t25Recorded) WriteApproved(ctx context.Context, a processing.Approved) error {
	r.mutex.Lock()
	r.lines = append(r.lines, a.Bytes())
	r.mutex.Unlock()
	return r.inner.WriteApproved(ctx, a)
}

func (r *t25Recorded) holding(needle string) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	count := 0
	for _, line := range r.lines {
		count += bytes.Count(line, []byte(needle))
	}
	return count
}

// Case 3A of P3-T25, IN-PROCESS and NOT THE SYSCALL BOUNDARY (ruling, todo 187
// comment 2260): the only way to the timeout branch, since no seam holds
// delivery from outside the process. The real attachment, intake, gate, worker
// and writer run in this process. A decided connection is written first. An
// open connection's exchange carrying both markers is captured and left
// pending; then capture's sink is held so delivery cannot finish, and the
// program's own finalisation order runs: the sealer withdraws and drains within
// a second, which expires, then capture finishes and the worker finishes with
// Drained=false. Asserted: the pending payload is discarded, nothing of it
// reaches the approved output (every line handed to it is kept here) or the
// file, and the seal says why. "Nothing reached any sink" is established only
// for the approved output this process hands records to; a write elsewhere by
// this process is not observed here.
func TestT25InProcessNotTheSyscallBoundaryAnExpiredDrainDiscardsPendingPayload(t *testing.T) {
	decidedClient := speaking(t, t18Serving(t))
	pendingClient := speaking(t, t18Serving(t))
	compiled := t18Compiled(t, decidedClient.process, pendingClient.process)
	barrier := t18NewBarrier()
	t.Cleanup(barrier.open)

	_, store, err := activation.RecordingIntake(1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sink := &t18HeldSink{barrier: barrier, inner: store}
	recording := capture.Recording(sink, store)
	directory := t.TempDir()
	writer, err := processing.Open(directory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	output := &t25Recorded{inner: writer}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1024, StorageExhausted: writer.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := processing.New(processing.Options{Plan: compiled.Processing, PolicyRevision: compiled.Revision,
		Intake: store, Gate: gate, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	// The worker's serial owner, on the program's cadence, until finalisation.
	stopping, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopping:
				return
			case <-ticker.C:
				if _, err := worker.Drain(context.Background()); err != nil {
					return
				}
			}
		}
	}()
	var stopOnce sync.Once
	stopDriver := func() { stopOnce.Do(func() { close(stopping); <-stopped }) }
	t.Cleanup(stopDriver)

	request := requesting(decidedClient.process, pendingClient.process)
	request.DeliveryGate = gate
	live, err := attach.NeweBPF(compiled.Approval).Attach(request, recording)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { barrier.open(); _ = live.Close() })
	recording.Observing(live.Capability())
	producer, ok := live.(connection.Producer)
	if !ok {
		t.Fatal("the attachment cannot withdraw or drain")
	}

	t18Ask(t, decidedClient, "/?asked=t25-decided", "X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
	t18Hangup(decidedClient)
	for deadline := time.Now().Add(10 * time.Second); writer.Stats().Written == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if writer.Stats().Written == 0 {
		t.Fatal("wiring, not the property: the decided connection was never written")
	}
	before := recording.Stats().Records
	t18Ask(t, pendingClient, "/?asked=t25-pending", "X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
	for deadline := time.Now().Add(10 * time.Second); recording.Stats().Records < before+2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	sink.armed.Store(true)
	if _, err := t18Timed(pendingClient, "t25-after-the-hold", 1, 10*time.Second); err != nil {
		t.Fatalf("the exchange after the hold: %v", err)
	}
	select {
	case <-barrier.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("wiring, not the property: the delivery loop never reached the held sink")
	}
	stopDriver()
	pending := store.Stats()
	if pending.Queued+pending.Leased == 0 || recording.Stats().Records < before+2 {
		t.Fatalf("wiring, not the property: no undecided payload was pending at finalisation: intake %+v, records %d from %d",
			pending, recording.Stats().Records, before)
	}

	sealer := &connection.Sealer{Producer: producer, Within: time.Second}
	seal, err := sealer.Stop()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The guard: the drain window really expired.
	if seal.Drain.Complete || seal.Complete {
		t.Fatalf("wiring, not the property: the drain completed with delivery held: %+v", seal.Drain)
	}
	recording.Finish(seal.Sealed)
	written := writer.Stats().Written
	outcome, err := worker.Finish(context.Background(), processing.Finalization{Withdrawn: seal.Withdrawal.Complete, Drained: seal.Drain.Complete})
	t.Logf("seal because %q; outcome %+v (%v); intake before finish %+v, after %+v", seal.Because, outcome, err, pending, store.Stats())

	if writer.Stats().Written != written || outcome.Written != written {
		t.Errorf("finalisation with Drained=false wrote %d records after the drain expired", writer.Stats().Written-written)
	}
	if n := output.holding(t18BoundaryProtected); n != 0 {
		t.Errorf("the protected marker reached the approved output %d times", n)
	}
	if n := output.holding("asked=t25-pending"); n != 0 {
		t.Errorf("the pending exchange reached the approved output %d times", n)
	}
	if outcome.Withheld.Known || outcome.Withheld.Why != "unsettled_input" || outcome.Pending != 0 {
		t.Errorf("the pending payload was not discarded as unsettled: withheld %+v, pending %d", outcome.Withheld, outcome.Pending)
	}
	if !slices.ContainsFunc(seal.Because, func(one string) bool { return strings.Contains(one, "was not drained") }) {
		t.Errorf("the seal does not say the drain did not finish: %q", seal.Because)
	}
	content, err := os.ReadFile(filepath.Join(directory, processing.ArtifactName))
	if err != nil || bytes.Contains(content, []byte(t18BoundaryProtected)) || !bytes.Contains(content, []byte(t18BoundaryPermitted)) {
		t.Errorf("the approved file (%v) holds the protected marker, or lacks the decided permitted one", err)
	}
}
