package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// These cases run the production controller loop and finalisation over real
// capture, intake, gate, workers and writer. Only the producer is modelled:
// events are admitted at the gate and handed to capture in the order the
// attachment's delivery does, and no kernel is attached.

type overloadProducer struct{ stamps *uint64 }

func (p overloadProducer) Capability() probe.Capability { return probe.Capability{} }
func (p overloadProducer) Close() error                 { return nil }
func (p overloadProducer) StopProducing() (connection.Withdrawal, error) {
	return connection.Withdrawal{At: time.Now(), Complete: true}, nil
}
func (p overloadProducer) Drain(time.Duration) (connection.Drained, error) {
	return connection.Drained{Complete: true, Delivered: connection.Counted(0), Outstanding: connection.Counted(0)}, nil
}
func (p overloadProducer) Account() (connection.Counters, error) {
	return connection.Counters{ReservationAttempts: connection.Counted(int64(*p.stamps))}, nil
}

type overloadController struct {
	t       *testing.T
	d       *daemon
	stop    chan os.Signal
	done    chan struct{}
	stamp   uint64
	numbers map[[2]uint64]uint64
}

// overloadStarted serves a session whose intake holds intakeBytes and whose
// gate holds events at once; zero intakeBytes takes the bound activation
// derives from events.
func overloadStarted(t *testing.T, events uint64, intakeBytes int64) *overloadController {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("wiring, not the property: the example configuration did not load: %v", err)
	}
	read.Settings.Directory = t.TempDir()
	directory := filepath.Join(read.Settings.Directory, sessionsName, "overload")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := processing.OpenWriter(processing.WriterOptions{Directory: directory, QueueBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var recording *capture.Session
	var store *intake.Store
	if intakeBytes == 0 {
		recording, store, err = recordingIntake(events)
	} else {
		store, err = intake.New(intakeBytes)
		recording = capture.Recording(store, store)
	}
	if err != nil {
		t.Fatal(err)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: events, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	f := &overloadController{t: t, stop: make(chan os.Signal, 1), done: make(chan struct{}), numbers: map[[2]uint64]uint64{}}
	f.d = &daemon{policy: read, session: "overload", directory: directory, capture: recording, intake: store, gate: gate,
		output: output, attached: overloadProducer{stamps: &f.stamp},
		plan: account.Account{Version: account.Version, Session: "overload", Policy: account.Policy{Revision: read.Revision, Generation: 1}},
	}
	go func() {
		f.d.serveUntilStop(f.stop, nil, nil, nil, nil, account.Account{})
		close(f.done)
	}()
	t.Cleanup(func() {
		select {
		case f.stop <- os.Interrupt:
		default:
		}
		select {
		case <-f.done:
		case <-time.After(5 * time.Second):
		}
		_ = output.Close()
		_ = store.Close()
	})
	return f
}

var overloadInstance = admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42,
	Start: admission.Determinate(7), Generation: 1}

// transfer admits one call at the gate and hands it to capture, or hands a
// refused one's place to capture, as delivery does. It reports admission.
func (f *overloadController) transfer(handle uint64, direction fragment.Direction, text string) bool {
	f.stamp++
	f.numbers[[2]uint64{handle, uint64(direction)}]++
	decision := f.d.gate.Admit(probe.DeliveryTransfer, true)
	one := probe.Transfer{Process: fragment.Process{PID: 42, StartTime: 7}, Instance: overloadInstance,
		Endpoint: handle, Direction: direction, Measured: true, Length: uint32(len(text)), Payload: []byte(text),
		Stamp: f.stamp, At: time.Now(),
		Sequence: probe.Sequence{Occupancy: handle, Number: f.numbers[[2]uint64{handle, uint64(direction)}], Born: true}}
	if !decision.Admitted {
		f.d.capture.Refused(one)
	} else {
		one.Slot = decision.Slot
		f.d.capture.Transfer(one)
	}
	if decision.Slot != nil && !decision.Slot.Kept() {
		decision.Slot.Refund(held.Unretained)
	}
	return decision.Admitted
}

func (f *overloadController) closed(handle uint64) {
	f.stamp++
	decision := f.d.gate.Admit(probe.DeliveryClose, false)
	if !decision.Admitted {
		return
	}
	f.d.capture.Closed(probe.Connection{Process: fragment.Process{PID: 42, StartTime: 7}, Instance: overloadInstance,
		Endpoint: handle, Stamp: f.stamp, Sequence: probe.Sequence{Occupancy: handle, Born: true},
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: f.numbers[[2]uint64{handle, uint64(fragment.Sent)}]},
			Received: probe.Terminal{Last: f.numbers[[2]uint64{handle, uint64(fragment.Received)}]}},
		At: time.Now(), Slot: decision.Slot})
}

// running reports whether the controller is still serving after within.
func (f *overloadController) running(within time.Duration) bool {
	select {
	case <-f.done:
		return false
	case <-time.After(within):
		return true
	}
}

// stopped stops the session and returns what finalisation returns, which
// decides the process's exit status.
func (f *overloadController) stopped() error {
	f.t.Helper()
	select {
	case f.stop <- os.Interrupt:
	default:
	}
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		f.t.Fatal("the controller did not respond to stop")
	}
	return f.d.finish(&logger{out: &bytes.Buffer{}})
}

// written is the request targets of the exchange lines in the approved file.
func (f *overloadController) written() []string {
	f.t.Helper()
	content, err := os.ReadFile(filepath.Join(f.d.directory, processing.ArtifactName))
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	var targets []string
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte{'\n'}) {
		var artifact processing.Artifact
		if len(line) == 0 || json.Unmarshal(line, &artifact) != nil || artifact.Reconstruction == nil {
			continue
		}
		for _, exchange := range artifact.Reconstruction.Exchanges {
			if exchange.Request.Message != nil {
				targets = append(targets, exchange.Request.Message.Target)
			}
		}
	}
	return targets
}

// A burst over the held-event bound costs connections, never the session: the
// controller keeps serving with no withdrawal requested, and a stop afterwards
// ends it with a success status.
func TestIndependentTheSessionGoesOnAfterABurstOverTheHeldEventBound(t *testing.T) {
	const bound = 4
	f := overloadStarted(t, bound, 0)
	refused := 0
	for i := range bound + 3 {
		direction := fragment.Sent
		if i%2 == 1 {
			direction = fragment.Received
		}
		if !f.transfer(8, direction, "GET /burst HTTP/1.1\r\n") {
			refused++
		}
	}
	if refused == 0 {
		t.Fatalf("wiring, not the property: nothing was refused, so the burst never passed the bound of %d: %+v",
			bound, f.d.gate.Snapshot())
	}

	if !f.running(300 * time.Millisecond) {
		t.Errorf("the session ended after %d events were refused at the held-event bound: gate %+v", refused, f.d.gate.Snapshot())
	}
	select {
	case <-f.d.gate.Withdrawal():
		t.Errorf("the burst requested withdrawal of the whole capture: %+v", f.d.gate.Snapshot())
	default:
	}
	if err := f.stopped(); err != nil {
		t.Errorf("a session stopped after a burst ended with %v, a failure status", err)
	}
}

// A full intake costs connections, never the session: the controller keeps
// serving, a connection begun afterwards is written, and a stop ends it with a
// success status.
func TestIndependentTheSessionGoesOnAfterTheIntakeIsFull(t *testing.T) {
	f := overloadStarted(t, 64, 4096)
	f.transfer(8, fragment.Sent, "GET /before HTTP/1.1\r\nHost: test\r\n\r\n")
	f.transfer(8, fragment.Sent, "GET /refused HTTP/1.1\r\nX-Fill: "+strings.Repeat("x", 4000)+"\r\n\r\n")
	if refused := f.d.intake.Stats().FragmentsRefused; refused == 0 {
		t.Fatalf("wiring, not the property: the intake refused nothing, so it was never full: %+v", f.d.intake.Stats())
	}

	if !f.running(300 * time.Millisecond) {
		t.Errorf("the session ended when the intake refused a fragment: gate %+v, intake %+v",
			f.d.gate.Snapshot(), f.d.intake.Stats())
	}
	f.transfer(9, fragment.Sent, "GET /fresh HTTP/1.1\r\nHost: test\r\n\r\n")
	f.transfer(9, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	f.closed(9)
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(strings.Join(f.written(), " "), "/fresh") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if targets := f.written(); !strings.Contains(strings.Join(targets, " "), "/fresh") {
		t.Errorf("a connection begun after the intake was full was not written: written %v, gate %+v, capture %+v",
			targets, f.d.gate.Snapshot(), f.d.capture.Stats())
	}
	if err := f.stopped(); err != nil {
		t.Errorf("a session stopped after a full intake ended with %v, a failure status", err)
	}
}

// An unknown length ends the session by itself, and finalisation then returns
// the failure that gives the process a non-zero status.
func TestIndependentAnUnknownLengthEndsTheSessionWithAFailureStatus(t *testing.T) {
	f := overloadStarted(t, 64, 0)
	if !f.transfer(8, fragment.Sent, "GET /before HTTP/1.1\r\n\r\n") {
		t.Fatalf("wiring, not the property: the control transfer was refused: %+v", f.d.gate.Snapshot())
	}
	if d := f.d.gate.Admit(probe.DeliveryTransfer, false); string(d.State.Reason) != "unknown_length" {
		t.Fatalf("wiring, not the property: the unmeasured transfer did not reach the gate as unknown_length: %+v", d)
	}
	if f.running(2 * time.Second) {
		t.Fatal("the session went on after an unknown length")
	}
	if err := f.d.finish(&logger{out: &bytes.Buffer{}}); err == nil {
		t.Errorf("finalisation after an unknown length returned no error, so the process exits 0")
	}
	last, err := lastSealed(f.d.policy.Settings.Directory)
	if err != nil {
		t.Fatalf("the session's seal could not be read: %v", err)
	}
	if string(last.Reason) != "unknown_length" {
		t.Errorf("the sealed session states %q as why it ended, want unknown_length", last.Reason)
	}
}

// A control command probing whether a session runs never makes a start
// refuse. The command's probe is held, with the pid file still open, while a
// start acquires that file; then the started session is visible to a control
// command.
func TestIndependentAControlProbeHeldOpenNeverRefusesAStart(t *testing.T) {
	dir := t.TempDir()
	// What an ended session leaves: a pid file naming it, held by nothing.
	if err := os.WriteFile(filepath.Join(dir, pidName), []byte("2147483646 0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probed, release := make(chan struct{}), make(chan struct{})
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		_, _, _ = holderUsing(dir, func(file *os.File) (bool, error) {
			held, err := probeHolder(file)
			close(probed)
			<-release
			return held, err
		})
	}()
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("wiring, not the property: the control command's probe never ran")
	}
	started, err := acquire(dir)
	close(release)
	<-answered
	if err != nil {
		t.Fatalf("a start was refused while a control command's probe held the pid file open: %v", err)
	}
	defer started.release()

	if err := started.record(os.Getpid(), "fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	pid, session, err := holder(dir)
	if err != nil || pid != os.Getpid() || session != "fedcba9876543210" {
		t.Errorf("a control command does not see the running session: pid %d session %q err %v", pid, session, err)
	}
}
