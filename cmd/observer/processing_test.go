package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

// This fixture drives the production controller and finalizer over real
// capture, intake, gate and writer owners. Only the producer is synthetic:
// no attach, cgroup, kernel delivery or whole-session deadline is measured.
type processingProducer struct {
	withdrawn, drained bool
	stamp              *uint64
	duringDrain        func()
	calls              []string
}

func (p *processingProducer) Capability() probe.Capability { return probe.Capability{} }
func (p *processingProducer) Close() error {
	p.calls = append(p.calls, "close")
	return nil
}
func (p *processingProducer) StopProducing() (connection.Withdrawal, error) {
	p.calls = append(p.calls, "withdraw")
	return connection.Withdrawal{At: time.Now(), Complete: p.withdrawn}, nil
}
func (p *processingProducer) Drain(time.Duration) (connection.Drained, error) {
	p.calls = append(p.calls, "drain")
	if p.duringDrain != nil {
		p.duringDrain()
	}
	return connection.Drained{Complete: p.drained, Delivered: connection.Counted(1), Outstanding: connection.Counted(0)}, nil
}
func (p *processingProducer) Account() (connection.Counters, error) {
	p.calls = append(p.calls, "account")
	return connection.Counters{ReservationAttempts: connection.Counted(int64(*p.stamp))}, nil
}

type processingControllerFixture struct {
	d         *daemon
	producer  *processingProducer
	stamp     uint64
	stop      chan os.Signal
	done      chan struct{}
	ended     bool
	live      bool
	finalized bool
}

func processingController(t *testing.T, beforeAuthorize ...func()) *processingControllerFixture {
	t.Helper()
	setup := controllerSetup{events: 100}
	if len(beforeAuthorize) != 0 {
		setup.beforeAuthorize = beforeAuthorize[0]
	}
	return processingControllerWith(t, setup)
}

// controllerSetup is what a controller fixture varies: limits.workers (zero
// leaves the example's), the event allowance, and the processing and gate
// seams.
type controllerSetup struct {
	log             *logger
	ticks           <-chan time.Time
	openSink        sink.Factory
	workers         int
	events          uint64
	taken           func(worker int, process fragment.Process, connection fragment.ConnectionID)
	beforeAuthorize func()
}

func processingControllerWith(t *testing.T, setup controllerSetup) *processingControllerFixture {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["remove"] = map[string]any{"headers": []string{"authorization"}}
	if setup.workers != 0 {
		document["limits"].(map[string]any)["workers"] = setup.workers
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	read := loaded(t, string(raw))
	read.Settings.Directory = t.TempDir()
	directory := filepath.Join(read.Settings.Directory, sessionsName, "integration")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	output, err := processing.OpenWriter(processing.WriterOptions{Directory: directory, QueueBytes: 1 << 20, OpenSink: setup.openSink})
	if err != nil {
		t.Fatal(err)
	}
	recording, store, err := recordingIntake(setup.events)
	if err != nil {
		t.Fatal(err)
	}
	options := probe.DeliveryGateOptions{MaxEvents: setup.events, IntakeExhausted: store.Exhausted(), BeforeAuthorize: setup.beforeAuthorize}
	gate, err := probe.NewDeliveryGate(options)
	if err != nil {
		t.Fatal(err)
	}
	f := &processingControllerFixture{stop: make(chan os.Signal, 1), done: make(chan struct{})}
	f.producer = &processingProducer{withdrawn: true, drained: true, stamp: &f.stamp}
	f.d = &daemon{policy: read, session: "integration", directory: directory, capture: recording,
		intake: store, gate: gate, output: output, attached: f.producer, processingTaken: setup.taken, log: setup.log,
		plan: account.Account{Version: account.Version, Session: "integration", Policy: account.Policy{Revision: read.Revision, Generation: 1}},
	}
	go func() {
		f.d.serveUntilStop(f.stop, nil, setup.ticks, nil, setup.log, account.Account{})
		close(f.done)
	}()
	t.Cleanup(func() {
		if !f.ended {
			f.halt(t)
		}
		if f.live && !f.finalized {
			_ = f.finish(&logger{})
		}
		_ = output.Close()
		_ = store.Close()
	})
	return f
}

func TestControllerStopsWhileWorkerAuthorizationIsHeld(t *testing.T) {
	reached, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	// Only the worker calls this hook, serially. Each closed connection is two
	// decisions, its exchange and its connection record, so the third is the
	// second connection's exchange.
	decisions := 0
	f := processingController(t, func() {
		decisions++
		if decisions == 3 {
			close(reached)
			<-release
		}
	})
	f.liveControl(t)
	f.transfer(t, 8, fragment.Sent, "GET /pending HTTP/1.1\r\n\r\n")
	f.transfer(t, 8, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	f.closed(t, 8)
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("second real worker authorization was not reached")
	}
	if stats := f.d.intake.Stats(); stats.Leased == 0 || f.d.output.Stats().Written != 2 {
		t.Fatalf("held authorization has no charged pending batch: %+v", stats)
	}
	t.Log("second real worker authorization held with charged intake after useful output")
	if got := f.d.gate.Admit(probe.DeliveryTransfer, false); got.State.Reason != probe.GateUnknownLength {
		t.Fatalf("unknown-length fault did not reach the gate: %+v", got)
	}
	// No stop signal: the controller must observe the gate while the worker
	// remains held. Waiting for the worker here would postpone withdrawal.
	select {
	case <-f.done:
		f.ended = true
	case <-time.After(2 * time.Second):
		t.Fatal("held worker prevented controller from observing gate withdrawal")
	}
}

func (f *processingControllerFixture) transfer(t *testing.T, endpoint uint64, direction fragment.Direction, text string) {
	t.Helper()
	if got := f.d.gate.Admit(probe.DeliveryTransfer, true); !got.Admitted {
		t.Fatalf("fixture transfer refused before capture: %+v", got)
	}
	f.stamp++
	f.d.capture.Transfer(probe.Transfer{Process: fragment.Process{PID: 42, StartTime: 7},
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1},
		Endpoint: endpoint, Direction: direction, Measured: true, Length: uint32(len(text)), Payload: []byte(text), Stamp: f.stamp, At: time.Now()})
}

func (f *processingControllerFixture) closed(t *testing.T, endpoint uint64) {
	t.Helper()
	if got := f.d.gate.Admit(probe.DeliveryClose, false); !got.Admitted {
		t.Fatalf("fixture close refused before capture: %+v", got)
	}
	f.stamp++
	f.d.capture.Closed(probe.Connection{Process: fragment.Process{PID: 42, StartTime: 7},
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1},
		Endpoint: endpoint, Stamp: f.stamp, At: time.Now()})
}

func (f *processingControllerFixture) halt(t *testing.T) {
	t.Helper()
	select {
	case f.stop <- os.Interrupt:
	default:
	}
	select {
	case <-f.done:
		f.ended = true
	case <-time.After(2 * time.Second):
		t.Fatal("controller did not respond to stop")
	}
}

func (f *processingControllerFixture) liveControl(t *testing.T) {
	t.Helper()
	f.transfer(t, 7, fragment.Sent, "GET /live HTTP/1.1\r\nAuthorization: secret-token\r\nX-Public: useful\r\n\r\n")
	f.transfer(t, 7, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	f.closed(t, 7)
	// Two records: the exchange, and the connection's record the connections
	// pipeline writes for every closed connection.
	deadline := time.Now().Add(2 * time.Second)
	for f.d.output.Stats().Written < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := f.d.output.Stats(); got.Written != 2 {
		t.Fatalf("live closed-batch control never reached approved output: %+v", got)
	}
	if len(f.producer.calls) != 0 {
		t.Fatal("live control was only written by finalization")
	}
	t.Log("live closed-batch control reached output before producer withdrawal")
	f.live = true
}

func (f *processingControllerFixture) finish(log *logger) error {
	f.finalized = true
	return f.d.finish(log)
}

// All three children first require successful live output. The two refusal
// children reach the identical final queue as the acceptance child; only the
// producer's explicit settlement evidence changes.
func TestControllerProcessingUsesFinalizationEvidence(t *testing.T) {
	for _, one := range []struct {
		name               string
		withdrawn, drained bool
		want               uint64
	}{
		{"settled", true, true, 2},
		{"withdrawal-incomplete", false, true, 1},
		{"drain-incomplete", true, false, 1},
	} {
		t.Run(one.name, func(t *testing.T) {
			f := processingController(t)
			f.liveControl(t)
			f.producer.withdrawn, f.producer.drained = one.withdrawn, one.drained
			f.transfer(t, 8, fragment.Sent, "GET /final HTTP/1.1\r\nAuthorization: secret-token\r\n\r\nGET /unresolved HTTP/1.1\r\n")
			f.producer.duringDrain = func() {
				f.transfer(t, 8, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}
			f.halt(t)
			if f.d.output.Stats().Written != 2 {
				t.Fatal("still-open batch escaped before producer drain")
			}
			var logs bytes.Buffer
			if err := f.finish(&logger{out: &logs}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.producer.calls, []string{"withdraw", "drain", "account", "close"}) {
				t.Fatalf("producer finalization order: %v", f.producer.calls)
			}
			if seen := f.d.capture.Stats(); seen.Transfers != 4 || seen.Closed != 1 || seen.Rejected != 0 {
				t.Fatalf("final response did not reach capture during drain: %+v", seen)
			}
			t.Logf("final queue reached after withdrawal=%t drain=%t", one.withdrawn, one.drained)
			content, err := os.ReadFile(filepath.Join(f.d.directory, processing.ArtifactName))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte("secret-token")) || bytes.Contains(content, []byte("/unresolved")) {
				t.Fatal("protected field or undecidable tail reached durable output")
			}
			all := bytes.Split(bytes.TrimSpace(content), []byte{'\n'})
			if got := f.d.output.Stats(); got.Written != uint64(len(all)) {
				t.Fatalf("final approved writes=%d beside %d records: %+v", got.Written, len(all), got)
			}
			// The exchange records, apart from the connection records written
			// beside them.
			var lines [][]byte
			for _, line := range all {
				var artifact processing.Artifact
				if err := json.Unmarshal(line, &artifact); err != nil {
					t.Fatal(err)
				}
				if artifact.Route.Pipeline == config.ExchangesPipeline {
					lines = append(lines, line)
				}
			}
			if uint64(len(lines)) != one.want || !bytes.Contains(lines[0], []byte("useful")) {
				t.Fatalf("final exchange records=%d want=%d, or the first is not the useful one", len(lines), one.want)
			}
			if one.want == 2 {
				var artifact processing.Artifact
				if err := json.Unmarshal(lines[1], &artifact); err != nil {
					t.Fatal(err)
				}
				if artifact.ReconstructionTruncation != nil || !bytes.Contains(lines[1], []byte("/final")) {
					t.Fatal("final exchange is missing or carries retirement evidence")
				}
			}
			if one.want == 2 {
				found := false
				for _, line := range all {
					var a processing.Artifact
					if err := json.Unmarshal(line, &a); err != nil {
						t.Fatal(err)
					}
					if a.Record == processing.ArtifactConnection && a.ReconstructionTruncation != nil {
						found = true
					}
				}
				if !found {
					t.Fatal("retirement omitted the indeterminate suffix marker")
				}
			}
			processingAccount(t, f, uint64(len(all)), logs.Bytes())
		})
	}
}

func processingAccount(t *testing.T, f *processingControllerFixture, written uint64, logs []byte) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(f.d.directory, sealedName))
	if err != nil {
		t.Fatal(err)
	}
	var final struct {
		Spool      json.RawMessage `json:"spool"`
		Processing *struct {
			Authorized uint64 `json:"authorized"`
			Written    uint64 `json:"written"`
		} `json:"processing"`
		Seal *connection.Seal `json:"seal"`
	}
	if err := json.Unmarshal(content, &final); err != nil {
		t.Fatal(err)
	}
	if final.Processing == nil || final.Processing.Authorized != written || final.Processing.Written != written {
		t.Fatalf("sealed account omitted or miscounted final processing: %s", content)
	}
	// Cleanup remains measurable at its owners without making internal state
	// into an operator-facing terminal-state promise.
	if got := f.d.intake.Stats(); got.Bytes != 0 || got.Queued != 0 || got.Leased != 0 {
		t.Fatalf("finalization retained intake entries: %+v", got)
	}
	if !f.d.output.Stats().Closed {
		t.Fatal("finalization did not close its writer")
	}
	if len(final.Spool) != 0 || final.Seal == nil || final.Seal.Counters.Persisted.Known || final.Seal.Counters.Persisted.Why == "" {
		t.Fatal("approved route records masquerade as persisted raw fragments")
	}
	if !bytes.Contains(logs, []byte(`"processing"`)) || bytes.Contains(logs, []byte("secret-token")) {
		t.Fatal("stopped log omitted processing or disclosed payload")
	}
	entries, err := os.ReadDir(f.d.directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "spool") || strings.Contains(entry.Name(), "fragment") {
			t.Fatalf("new session retained a raw spool file: %s", entry.Name())
		}
	}
}
