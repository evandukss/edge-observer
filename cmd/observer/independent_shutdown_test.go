package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

type it4Producer struct {
	emit    func(string)
	hold    bool
	release <-chan struct{}
}

// These owners are selected through the public catalogue and aggregate path.
// They model lifecycle calls, not kernel grants or a daemon exit backstop.
type it4Adapter struct {
	name  string
	pid   int32
	owner probe.Attachment
}

func (a *it4Adapter) Name() string { return a.name }
func (a *it4Adapter) Inspect(p process.Process) probe.Support {
	return probe.Support{Supported: p.PID == a.pid, Reason: a.name}
}
func (a *it4Adapter) Attach(r probe.Request, _ probe.Sink) (probe.Attachment, error) {
	if len(r.Processes) != 1 || r.Processes[0].PID != a.pid || len(r.Admit) != 1 || r.Admit[0].ObserverPID != a.pid {
		return nil, fmt.Errorf("wiring: %s received another owner's request", a.name)
	}
	return a.owner, nil
}

type it4LifecycleOwner struct {
	hold     string
	release  <-chan struct{}
	entered  chan string
	returned chan string
	n        int64
	unknown  bool
}

func (*it4LifecycleOwner) Capability() probe.Capability { return probe.Capability{Payload: true} }
func (p *it4LifecycleOwner) reach(stage string) {
	p.entered <- stage
	if p.hold == stage {
		<-p.release
	}
}
func (p *it4LifecycleOwner) StopProducing() (connection.Withdrawal, error) {
	p.reach("withdraw")
	defer func() { p.returned <- "withdraw" }()
	return connection.Withdrawal{At: time.Unix(p.n, 0), Instances: int(p.n), Complete: true}, nil
}
func (p *it4LifecycleOwner) Drain(time.Duration) (connection.Drained, error) {
	p.reach("drain")
	defer func() { p.returned <- "drain" }()
	return connection.Drained{Complete: true, Delivered: p.count(), Outstanding: connection.Counted(0)}, nil
}
func (p *it4LifecycleOwner) count() connection.Count {
	if p.unknown {
		return connection.Uncounted("independent owner cannot measure delivery")
	}
	return connection.Counted(p.n)
}
func (p *it4LifecycleOwner) Account() (connection.Counters, error) {
	p.reach("account")
	defer func() { p.returned <- "account" }()
	return connection.Counters{Delivered: p.count()}, nil
}
func (p *it4LifecycleOwner) Close() error {
	p.reach("close")
	defer func() { p.returned <- "close" }()
	return nil
}

type it4LifecycleResult struct {
	withdrawal connection.Withdrawal
	drain      connection.Drained
	counters   connection.Counters
	err        error
}

func TestIndependentP4MultiAdapterLifecycle(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, stage := range []string{"withdraw", "drain", "account", "close"} {
			for _, condition := range []string{"free", "held", "unknown"} {
				if condition == "unknown" && stage != "drain" && stage != "account" {
					continue
				}
				t.Run(fmt.Sprintf("reverse=%t/%s/%s", reverse, stage, condition), func(t *testing.T) {
					release := make(chan struct{})
					unhold := sync.OnceFunc(func() { close(release) })
					defer unhold()
					alpha := &it4LifecycleOwner{n: 5, release: release, entered: make(chan string, 4), returned: make(chan string, 4), unknown: condition == "unknown"}
					beta := &it4LifecycleOwner{n: 8, entered: make(chan string, 4), returned: make(chan string, 4)}
					if condition == "held" {
						alpha.hold = stage
					}
					a := &it4Adapter{name: "it4-alpha", pid: 101, owner: alpha}
					b := &it4Adapter{name: "it4-beta", pid: 202, owner: beta}
					adapters := []probe.Inspector{a, b}
					if reverse {
						adapters = []probe.Inspector{b, a}
					}
					catalog, err := probe.NewCatalog(adapters...)
					if err != nil {
						t.Fatal(err)
					}
					group, err := attachment.Attach(catalog, probe.Request{
						Processes: []process.Process{{PID: a.pid}, {PID: b.pid}},
						Admit:     []admission.Selection{{ObserverPID: a.pid}, {ObserverPID: b.pid}},
					}, nil, nil)
					if err != nil {
						t.Fatalf("wiring: aggregate did not attach: %v", err)
					}
					started := time.Now()
					ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
					defer cancel()
					result := make(chan it4LifecycleResult, 1)
					go func() {
						var r it4LifecycleResult
						switch stage {
						case "withdraw":
							r.withdrawal, r.err = group.StopProducingContext(ctx)
						case "drain":
							r.drain, r.err = group.DrainContext(ctx, time.Second)
						case "account":
							r.counters, r.err = group.AccountContext(ctx)
						case "close":
							r.err = group.CloseContext(ctx)
						}
						result <- r
					}()
					wait := func(ch <-chan string, owner string) {
						t.Helper()
						select {
						case got := <-ch:
							if got != stage {
								t.Fatalf("wiring: %s reached %s, want %s", owner, got, stage)
							}
						case <-ctx.Done():
							t.Fatalf("%s did not reach %s before caller deadline", owner, stage)
						}
					}
					wait(alpha.entered, "alpha")
					wait(beta.entered, "beta")
					wait(beta.returned, "free beta return")
					var got it4LifecycleResult
					select {
					case got = <-result:
					case <-time.After(time.Second):
						t.Fatal("aggregate waited on a held owner beyond caller deadline")
					}
					if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
						t.Errorf("aggregate returned after %s, beyond 300ms deadline plus 200ms scheduling allowance", elapsed)
					}
					if condition == "held" {
						if !errors.Is(got.err, context.DeadlineExceeded) || !strings.Contains(got.err.Error(), a.name) {
							t.Fatalf("held owner not named with deadline failure: %v", got.err)
						}
						if stage == "withdraw" && (got.withdrawal.Complete || got.withdrawal.Instances != 8) {
							t.Errorf("held withdrawal lost free owner or claimed complete: %+v", got.withdrawal)
						}
						if stage == "drain" && (got.drain.Complete || got.drain.Delivered.Known || got.drain.Outstanding.Known) {
							t.Errorf("held drain invented known facts: %+v", got.drain)
						}
						if stage == "account" && got.counters.Delivered.Known {
							t.Errorf("held account invented delivery: %+v", got.counters.Delivered)
						}
					} else {
						if got.err != nil {
							t.Fatalf("free operation: %v", got.err)
						}
						if stage == "withdraw" && (!got.withdrawal.Complete || got.withdrawal.Instances != 13 || !got.withdrawal.At.Equal(time.Unix(8, 0))) {
							t.Errorf("free withdrawal: %+v", got.withdrawal)
						}
						if stage == "drain" && (!got.drain.Complete || got.drain.Outstanding != connection.Counted(0)) {
							t.Errorf("free drain: %+v", got.drain)
						}
						if stage == "drain" || stage == "account" {
							count := got.counters.Delivered
							if stage == "drain" {
								count = got.drain.Delivered
							}
							want := connection.Counted(13)
							if condition == "unknown" {
								want = connection.Uncounted("independent owner cannot measure delivery")
							}
							if count != want {
								t.Errorf("aggregated delivery=%+v want %+v", count, want)
							}
						}
					}
					unhold()
					select {
					case <-alpha.returned:
					case <-time.After(time.Second):
						t.Fatal("wiring: released owner did not return")
					}
				})
			}
		}
	}
}

func (*it4Producer) Capability() probe.Capability { return probe.Capability{} }
func (p *it4Producer) StopProducing() (connection.Withdrawal, error) {
	// This observation is independent of the account's withdrawal claim. The
	// fixture has no kernel grants; it establishes invocation of the owner.
	p.emit("withdrawn")
	return connection.Withdrawal{At: time.Now(), Complete: true, Instances: 1}, nil
}
func (*it4Producer) Drain(time.Duration) (connection.Drained, error) {
	return connection.Drained{Complete: true, Delivered: connection.Counted(0), Outstanding: connection.Counted(0)}, nil
}
func (*it4Producer) Account() (connection.Counters, error) { return connection.Counters{}, nil }
func (p *it4Producer) Close() error {
	if p.hold {
		p.emit("held")
		<-p.release
	}
	return nil
}

type it4Sink struct {
	sink.Sink
	armed *atomic.Bool
	once  sync.Once
	hold  func()
}

func (s *it4Sink) Write(ctx context.Context, p []byte) (int, error) {
	if s.armed.Load() {
		s.once.Do(s.hold)
	}
	return s.Sink.Write(ctx, p)
}

// This child runs the production daemon controller and finalizer with real
// capture, processing, writer, log and pid-lock owners. Only attachment is a
// double; this does not claim kernel attachment or activation coverage.
func TestIndependentP4DaemonChild(t *testing.T) {
	args := os.Args
	if len(args) < 3 || args[len(args)-3] != "it4-daemon" {
		return
	}
	which, root := args[len(args)-2], args[len(args)-1]
	events := os.NewFile(3, "events")
	emit := func(s string) { _, _ = fmt.Fprintln(events, s) }
	release := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		close(release)
	}()
	var heldOnce sync.Once
	hold := func() { heldOnce.Do(func() { emit("held") }); <-release }
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	if which == "extension" {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		document["extensions"] = []any{map[string]any{"name": "it4", "fields": []string{"request.line"}, "timeout_ms": 1000,
			"command": []string{os.Args[0], "-test.run=^TestIndependentP4ExtensionChild$", "--", "it4-extension"}}}
		raw, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
	}
	read := loaded(t, string(raw))
	read.Settings.Directory = root
	read.Settings.Log = filepath.Join(root, "observer.log")
	directory := filepath.Join(root, sessionsName, "it4-session")
	if err := os.MkdirAll(filepath.Join(directory, controlName), 0700); err != nil {
		t.Fatal(err)
	}
	log, err := openLog(read.Settings, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var armed atomic.Bool
	wopts := processing.WriterOptions{Directory: directory, QueueBytes: 1 << 20}
	if which == "writer" {
		wopts.OpenSink = func(path string) sink.Sink { return &it4Sink{Sink: sink.NewFile(path), armed: &armed, hold: hold} }
	}
	if which == "stdout" {
		wopts.Stdout = &it4Sink{Sink: sink.NewFile(filepath.Join(root, "mirror.jsonl")), armed: &armed, hold: hold}
	}
	w, err := processing.OpenWriter(wopts)
	if err != nil {
		t.Fatal(err)
	}
	capture, store, err := recordingIntake(100)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100, IntakeExhausted: store.Exhausted(), BeforeAuthorize: func() {
		if which == "worker" && armed.Load() {
			hold()
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := &daemon{policy: read, session: "it4-session", directory: directory, capture: capture, intake: store, gate: gate, output: w, log: log,
		attached: &it4Producer{emit: emit, hold: which == "attachment", release: release},
		plan:     account.Account{Version: account.Version, Session: "it4-session", Policy: account.Policy{Revision: read.Revision, Generation: 1}}}
	d.plan.Attached(account.Live, d.session, nil, d.attached.Capability())
	d.plan.Extensions = account.ExtensionsOf(read.Processing.Extensions())
	if strings.HasPrefix(which, "publication:") || strings.HasPrefix(which, "failure:") {
		d.shutdownHooks = &shutdownHooks{Before: func(_ context.Context, stage shutdownStage) error {
			if strings.TrimPrefix(which, "failure:") == string(stage) {
				return errors.New("independent publication failure")
			}
			if string(stage) == strings.TrimPrefix(which, "publication:") {
				hold()
			}
			return nil
		}}
	}
	if which == "failure:account publication" {
		stale, err := json.Marshal(sealedSession{Session: d.session, Sealed: time.Unix(1, 0), Account: filepath.Join(directory, sealedName), Complete: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, lastName), stale, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if which == "extension" {
		r := &processingRun{failed: make(chan struct{}), final: make(chan processing.Finalization, 1), done: make(chan struct{})}
		r.beforeFinal = func(ctx context.Context, stage string) error { return d.beforeShutdown(ctx, shutdownStage(stage)) }
		r.run, r.err = processing.Start(processing.Options{Plan: read.Processing, PolicyRevision: read.ProcessingRevision, Intake: store, Gate: gate, Output: w,
			Workers: 1, Session: d.session, Derived: w, Supervision: func(e extension.Event) {
				if e.Kind == extension.Ready {
					emit("extension-ready")
				}
				if e.Kind == extension.Exited {
					hold()
				}
			}})
		if r.err != nil {
			t.Fatal(r.err)
		}
		d.processing = r
		go r.serve(w)
	}
	stopping := make(chan os.Signal, 4)
	signal.Notify(stopping, syscall.SIGTERM, os.Interrupt)
	lock, err := acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.record(os.Getpid(), d.session); err != nil {
		t.Fatal(err)
	}
	asking := make(chan os.Signal, 1)
	controller := &controller{directory: directory, answer: func(string, []byte) ([]byte, error) { hold(); return []byte("{}"), nil }}
	f := &processingControllerFixture{d: d, producer: &processingProducer{}, stop: stopping, done: make(chan struct{})}
	go func() { d.serveUntilStop(stopping, asking, nil, controller, log, account.Account{}); close(f.done) }()
	f.liveControl(t)
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := w.Drain(drainCtx); err != nil {
		t.Fatal(err)
	}
	drainCancel()
	if which == "worker" || which == "writer" || which == "stdout" {
		armed.Store(true)
		f.transfer(t, 8, fragment.Sent, "GET /held HTTP/1.1\r\n\r\n")
		f.transfer(t, 8, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
		f.closed(t, 8)
	}
	if which == "controller" {
		if err := os.WriteFile(filepath.Join(directory, controlName, "it4.request"), []byte("inspect\n"), 0600); err != nil {
			t.Fatal(err)
		}
		asking <- syscall.SIGUSR1
	}
	emit("ready")
	<-f.done
	err = d.finish(log)
	_ = log.close()
	lock.release()
	exitOnError(err)
	os.Exit(0)
}

func TestIndependentP4ExtensionChild(t *testing.T) {
	if os.Args[len(os.Args)-1] != "it4-extension" {
		return
	}
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var m struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			os.Exit(3)
		}
		switch m.Type {
		case "start":
			_, _ = fmt.Fprintln(os.Stdout, `{"type":"ready","protocol":"observer.extension/2"}`)
		case "exchange":
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"type": "result", "id": m.ID, "outcome": "unchanged"})
		case "shutdown":
			os.Exit(0)
		}
	}
	os.Exit(0)
}

func TestIndependentP4StopChild(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "it4-stop" {
		return
	}
	exitOnError(stopIn(os.Args[len(os.Args)-1], os.Stdout))
	os.Exit(0)
}

func TestIndependentP4DaemonDeadline(t *testing.T) {
	for _, which := range []string{"free", "worker", "writer", "stdout", "extension", "attachment", "controller",
		"publication:account publication", "publication:projection publication", "publication:last-seal publication",
		"failure:account publication", "failure:projection publication", "failure:last-seal publication"} {
		t.Run(which, func(t *testing.T) {
			root := t.TempDir()
			eventsR, eventsW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = eventsR.Close() }()
			cmd := exec.Command(os.Args[0], "-test.run=^TestIndependentP4DaemonChild$", "--", "it4-daemon", which, root)
			cmd.ExtraFiles = []*os.File{eventsW}
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = eventsW.Close()
			var exitErr error
			done := make(chan struct{})
			go func() { exitErr = cmd.Wait(); close(done) }()
			defer func() { _ = input.Close(); _ = cmd.Process.Kill(); <-done }()
			events := make(chan string, 32)
			go func() {
				scan := bufio.NewScanner(eventsR)
				for scan.Scan() {
					events <- scan.Text()
				}
				close(events)
			}()
			seen := map[string]bool{}
			await := func(required ...string) {
				t.Helper()
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				for {
					all := true
					for _, name := range required {
						all = all && seen[name]
					}
					if all {
						return
					}
					select {
					case event, ok := <-events:
						if !ok {
							t.Fatal("wiring: child exited before required owner state", required)
						}
						seen[event] = true
					case <-timer.C:
						t.Fatal("wiring: owner state not reached", required, seen)
					}
				}
			}
			beforeStop := []string{"ready"}
			if which == "worker" || which == "writer" || which == "stdout" || which == "controller" {
				beforeStop = append(beforeStop, "held")
			}
			if which == "extension" {
				beforeStop = append(beforeStop, "extension-ready")
			}
			await(beforeStop...)
			started := time.Now()
			var stopOutput bytes.Buffer
			stopDone := make(chan error, 1)
			stopCmd := exec.Command(os.Args[0], "-test.run=^TestIndependentP4StopChild$", "--", "it4-stop", root)
			stopCmd.Stdout, stopCmd.Stderr = &stopOutput, &stopOutput
			if err := stopCmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stopCmd.Process.Kill() }()
			go func() { stopDone <- stopCmd.Wait() }()
			if which != "controller" {
				await("withdrawn")
			}
			if which == "attachment" || which == "extension" || strings.HasPrefix(which, "publication:") {
				await("held")
			}
			// The extra 500ms is observer scheduling tolerance, not an enlarged
			// product allowance. Log the measured elapsed time for adjudication.
			timer := time.NewTimer(time.Until(started.Add(25*time.Second + 500*time.Millisecond)))
			select {
			case <-done:
				timer.Stop()
			case <-timer.C:
				_ = cmd.Process.Kill()
				<-done
				<-stopDone
				t.Fatalf("hard exit exceeded 25s while actual owner remained held; elapsed=%s child=%v output=%s", time.Since(started), exitErr, output.String())
			}
			t.Logf("external daemon exit after %s: %v; independent withdrawal=%t", time.Since(started), exitErr, seen["withdrawn"])
			var stopErr error
			select {
			case stopErr = <-stopDone:
			case <-time.After(5 * time.Second):
				t.Fatal("stop client exceeded its 30s allowance")
			}
			if which == "free" {
				if exitErr != nil || stopErr != nil {
					t.Fatalf("free shutdown failed: daemon=%v stop=%v %s %s", exitErr, stopErr, stopOutput.String(), output.String())
				}
				if time.Since(started) > 5*time.Second {
					t.Error("free shutdown waited for a deadline")
				}
			} else if which != "writer" && which != "stdout" && (exitErr == nil || stopErr == nil) {
				t.Errorf("expired finalization reported success: daemon=%v stop=%v %s", exitErr, stopErr, stopOutput.String())
			}
			directory := filepath.Join(root, sessionsName, "it4-session")
			var inspected bytes.Buffer
			inspectErr := inspect(directory, false, &inspected)
			if which == "publication:account publication" || which == "failure:account publication" {
				if !errors.Is(inspectErr, errNeverSealed) {
					t.Errorf("account hold must leave unsealed session: %v", inspectErr)
				}
			} else if inspectErr != nil {
				t.Errorf("valid account must survive later hold: %v; %s", inspectErr, output.String())
			} else {
				a := it4Account(t, directory)
				if a.Seal == nil {
					t.Fatal("published account lacks seal")
				}
				stage := map[string]string{"worker": "processing workers", "extension": "extension shutdown", "attachment": "attachment close", "controller": "controller"}[which]
				if stage != "" && (a.Seal.Complete || !strings.Contains(strings.Join(a.Seal.Because, " "), stage)) {
					t.Errorf("incomplete account does not name held owner %s: %+v", stage, a.Seal)
				}
				if which == "stdout" && (a.Processing == nil || a.Processing.StdoutDelivery == nil || a.Processing.StdoutDelivery.Discarded == 0 || a.Processing.Delivery.Written != 4) {
					t.Errorf("stdout hold blocked file progress or lost delivery evidence: %+v", a.Processing)
				}
			}
			before := append([]byte(nil), inspected.Bytes()...)
			_, _ = io.WriteString(input, "release\n")
			var after bytes.Buffer
			_ = inspect(directory, false, &after)
			if !bytes.Equal(before, after.Bytes()) {
				t.Error("account changed after daemon exit and hold release")
			}
		})
	}
}

// it4CLIState supplies faulting owners to begin; startWith still owns parsing,
// activation, the pid lock, signal watchers, the deadlines and final publication.
type it4CLIState struct {
	emit       func(string)
	work       chan struct{}
	publish    chan struct{}
	activated  chan struct{}
	armed      atomic.Bool
	controller atomic.Bool
	workOnce   sync.Once
}

func (s *it4CLIState) heldWork() {
	s.workOnce.Do(func() { s.emit("work-held") })
	<-s.work
	s.emit("work-released")
}

type it4CLIProducer struct {
	state     *it4CLIState
	name      string
	heldStage string
}

func (*it4CLIProducer) Capability() probe.Capability { return probe.Capability{Payload: true} }
func (p *it4CLIProducer) StopProducing() (connection.Withdrawal, error) {
	p.state.emit(p.name + "-withdrawn")
	if p.heldStage == "withdraw" {
		p.state.heldWork()
	}
	return connection.Withdrawal{At: time.Now(), Complete: true, Instances: 1}, nil
}
func (*it4CLIProducer) Drain(time.Duration) (connection.Drained, error) {
	return connection.Drained{Complete: true, Delivered: connection.Counted(0), Outstanding: connection.Counted(0)}, nil
}
func (*it4CLIProducer) Account() (connection.Counters, error) { return connection.Counters{}, nil }
func (p *it4CLIProducer) Close() error {
	p.state.emit(p.name + "-close")
	if p.heldStage == "close" {
		p.state.heldWork()
	}
	return nil
}
func (p *it4CLIProducer) Losses() (probe.Losses, error) {
	if p.state.controller.Load() {
		p.state.emit("controller-held")
		<-p.state.work
		p.state.emit("controller-released")
	}
	return probe.Losses{}, nil
}

type it4CLIConsole struct {
	state *it4CLIState
	once  sync.Once
}

func (w *it4CLIConsole) Write(p []byte) (int, error) {
	var record struct {
		Record string `json:"record"`
	}
	if json.Unmarshal(p, &record) == nil && record.Record == "activation-completed" {
		w.once.Do(func() { close(w.state.activated); w.state.emit("activated") })
	}
	return os.Stdout.Write(p)
}

// This executable helper deliberately leaves the host-specific begin body
// synthetic. It never constructs/replaces the production shutdown boundary.
func TestIndependentP4CLIChild(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-4] != "it4-cli" {
		return
	}
	which, configuration, root := os.Args[len(os.Args)-3], os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	events := os.NewFile(3, "it4-events")
	var eventMutex sync.Mutex
	emit := func(name string) {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		_, _ = fmt.Fprintln(events, name)
	}
	s := &it4CLIState{emit: emit, work: make(chan struct{}), publish: make(chan struct{}), activated: make(chan struct{})}
	commands := make(chan string, 16)
	go func() {
		scan := bufio.NewScanner(os.Stdin)
		for scan.Scan() {
			commands <- scan.Text()
		}
		close(commands)
	}()
	leave := make(chan struct{})
	observedStop := make(chan os.Signal, 1)
	signal.Notify(observedStop, syscall.SIGTERM)
	defer signal.Stop(observedStop)
	go func() { <-observedStop; emit("stop-signal") }()
	err := runWith([]string{"start", configuration}, &it4CLIConsole{state: s}, commandDependencies{
		begin: func(read policy.Policy, session string, options processing.WriterOptions) (*daemon, error) {
			if read.Processing == nil || read.ProcessingRevision == "" || options.Directory != filepath.Join(root, "data") || options.Stdout != nil {
				return nil, errors.New("wiring: begin did not receive validated policy and real writer options")
			}
			if which == "begin-held" {
				emit("begin-held")
				<-s.work
			}
			directory := filepath.Join(read.Settings.Directory, sessionsName, session)
			if err := os.MkdirAll(filepath.Join(directory, controlName), 0700); err != nil {
				return nil, err
			}
			w, err := processing.OpenWriter(options)
			if err != nil {
				return nil, err
			}
			recording, store, err := recordingIntake(100)
			if err != nil {
				return nil, err
			}
			gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100, IntakeExhausted: store.Exhausted(), BeforeAuthorize: func() {
				if which == "live-authorization" && s.armed.Load() {
					s.heldWork()
				}
			}})
			if err != nil {
				return nil, err
			}
			alpha := &it4CLIProducer{state: s, name: "alpha"}
			var owner probe.Attachment = alpha
			if strings.HasPrefix(which, "multi-") {
				alpha.heldStage = strings.TrimPrefix(which, "multi-")
				beta := &it4CLIProducer{state: s, name: "beta"}
				catalog, err := probe.NewCatalog(&it4Adapter{name: "alpha", pid: 101, owner: alpha}, &it4Adapter{name: "beta", pid: 202, owner: beta})
				if err != nil {
					return nil, err
				}
				owner, err = attachment.Attach(catalog, probe.Request{Processes: []process.Process{{PID: 101}, {PID: 202}}, Admit: []admission.Selection{{ObserverPID: 101}, {ObserverPID: 202}}}, nil, recording)
				if err != nil {
					return nil, err
				}
			}
			d := &daemon{policy: read, session: session, directory: directory, output: w, intake: store, capture: recording, gate: gate, attached: owner, ends: &endings{},
				plan: account.Account{Version: account.Version, Session: session, Policy: account.Policy{Revision: read.Revision, Generation: 1}}}
			d.plan.Attached(account.Live, session, nil, owner.Capability())
			d.plan.Extensions = account.ExtensionsOf(read.Processing.Extensions())
			// The processing hook injects a real worker failure or a pre-id hold.
			// The controller still subscribes to the actual Run failure channel.
			r := &processingRun{failed: make(chan struct{}), final: make(chan processing.Finalization, 1), done: make(chan struct{})}
			r.run, r.err = processing.Start(processing.Options{Plan: read.Processing, PolicyRevision: read.ProcessingRevision, Intake: store, Gate: gate, Output: w, Workers: 1, Session: session, Derived: w,
				BeforeParse: func(context.Context) error {
					if !s.armed.Load() {
						return nil
					}
					if which == "processing-first" {
						emit("parse-failed")
						return errors.New("it4 actual processing failure")
					}
					if which == "live-parse" {
						s.heldWork()
					}
					return nil
				}})
			if r.err != nil {
				return nil, r.err
			}
			d.processing = r
			go r.serve(w)
			go func() { <-r.run.Failed(); emit("processing-failed") }()
			if which == "gate-first" || which == "processing-first" || strings.HasPrefix(which, "live-") {
				d.shutdownHooks = &shutdownHooks{Before: func(_ context.Context, stage shutdownStage) error {
					if stage == shutdownProjection {
						emit("projection-held")
						<-s.publish
						emit("projection-released")
					}
					return nil
				}}
			}
			f := &processingControllerFixture{d: d, producer: &processingProducer{}}
			go func() {
				<-s.activated
				f.liveControl(t)
				emit("session=" + session)
				emit("ready")
				var releaseWork, releasePublish sync.Once
				for command := range commands {
					switch command {
					case "block-controller":
						s.controller.Store(true)
						if err := os.WriteFile(filepath.Join(directory, controlName, "it4.request"), []byte("inspect\n"), 0600); err != nil {
							t.Error(err)
							return
						}
						if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
							t.Error(err)
							return
						}
					case "feed-held":
						if which == "processing-first" && gate.Snapshot().Reason != "" {
							t.Error("wiring: processing failure was not first trigger")
							return
						}
						s.armed.Store(true)
						f.transfer(t, 8, fragment.Sent, "GET /late HTTP/1.1\r\n\r\n")
						f.transfer(t, 8, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
						f.closed(t, 8)
					case "gate":
						got := gate.Admit(probe.DeliveryTransfer, false)
						if got.Slot != nil {
							got.Slot.Refund(held.Unretained)
						}
						if got.State.Reason != probe.GateUnknownLength {
							t.Error("wiring: gate did not invalidate unknown length")
							return
						}
						emit("gate-triggered")
					case "release-work":
						releaseWork.Do(func() { close(s.work) })
					case "release-publication":
						releasePublish.Do(func() { close(s.publish) })
					case "sample-before", "sample-after":
						data, err := json.Marshal(struct {
							Processing *account.Processing
							Writer     processing.WriterStats
						}{d.processingSnapshot(), w.Stats()})
						if err == nil {
							err = os.WriteFile(filepath.Join(root, command+".json"), data, 0600)
						}
						if err != nil {
							t.Error(err)
							return
						}
						emit(command)
					case "exit":
						close(leave)
						return
					}
				}
			}()
			return d, nil
		},
	})
	if err != nil {
		emit("returned-error")
	} else {
		emit("returned-ok")
	}
	if which == "free-cleanup" {
		// Stay in the same process beyond the old deadline: a leaked production
		// backstop would terminate this otherwise completed invocation.
		<-leave
	}
	exitOnError(err)
	if t.Failed() {
		os.Exit(3)
	}
	os.Exit(0)
}

func it4Archive(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		destination := os.Getenv("IT4_ARTIFACT_DIR")
		if destination == "" {
			return
		}
		name := strings.NewReplacer("/", "_", "=", "_").Replace(t.Name())
		destination = filepath.Join(destination, name)
		if err := os.MkdirAll(destination, 0700); err != nil {
			t.Error(err)
			return
		}
		if err := os.CopyFS(destination, os.DirFS(root)); err != nil {
			t.Errorf("retain raw artifacts: %v", err)
		}
	})
}

func TestIndependentP4CLICommandChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-3] != "it4-command" {
		return
	}
	exitOnError(run(os.Args[len(os.Args)-2:], os.Stdout))
	os.Exit(0)
}

func TestIndependentP4CLIShutdown(t *testing.T) {
	for _, which := range []string{"free-cleanup", "begin-held", "gate-first", "processing-first", "live-parse", "live-authorization", "multi-close", "multi-withdraw"} {
		t.Run(which, func(t *testing.T) {
			root := t.TempDir()
			it4Archive(t, root)
			t.Cleanup(func() {
				data, err := json.Marshal(map[string]any{"test": t.Name(), "failed": t.Failed()})
				if err == nil {
					err = os.WriteFile(filepath.Join(root, "test-status.json"), data, 0600)
				}
				if err != nil {
					t.Error(err)
				}
			})
			raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			document["output"], document["log"] = filepath.Join(root, "data"), filepath.Join(root, "observer.log")
			raw, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			configuration := filepath.Join(root, "observer.json")
			if err := os.WriteFile(configuration, raw, 0600); err != nil {
				t.Fatal(err)
			}
			readEvents, writeEvents, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = readEvents.Close() }()
			cmd := exec.Command(os.Args[0], "-test.run=^TestIndependentP4CLIChild$", "--", "it4-cli", which, configuration, root)
			cmd.ExtraFiles = []*os.File{writeEvents}
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := os.Create(filepath.Join(root, "stdout.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdout.Close() }()
			stderr, err := os.Create(filepath.Join(root, "stderr.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stderr.Close() }()
			cmd.Stdout, cmd.Stderr = stdout, stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = writeEvents.Close()
			done := make(chan struct{})
			var exitErr error
			go func() { exitErr = cmd.Wait(); close(done) }()
			defer func() { _ = input.Close(); _ = cmd.Process.Kill(); <-done }()
			events := make(chan string, 128)
			rawEvents, err := os.Create(filepath.Join(root, "events.log"))
			if err != nil {
				t.Fatal(err)
			}
			timeline, err := os.Create(filepath.Join(root, "events.jsonl"))
			if err != nil {
				_ = rawEvents.Close()
				t.Fatal(err)
			}
			scanned := make(chan struct{})
			go func() {
				defer close(scanned)
				defer close(events)
				defer func() { _ = rawEvents.Close() }()
				defer func() { _ = timeline.Close() }()
				scan := bufio.NewScanner(io.TeeReader(readEvents, rawEvents))
				for scan.Scan() {
					_ = json.NewEncoder(timeline).Encode(map[string]any{"event": scan.Text(), "received": time.Now()})
					events <- scan.Text()
				}
			}()
			defer func() { _ = cmd.Process.Kill(); <-done; <-scanned }()
			seen := map[string]bool{}
			session := ""
			await := func(within time.Duration, names ...string) {
				t.Helper()
				timer := time.NewTimer(within)
				defer timer.Stop()
				for {
					all := true
					for _, name := range names {
						all = all && seen[name]
					}
					if all {
						return
					}
					select {
					case event, ok := <-events:
						if !ok {
							t.Fatalf("child exited before required states %v; seen=%v", names, seen)
						}
						seen[event] = true
						if strings.HasPrefix(event, "session=") {
							session = strings.TrimPrefix(event, "session=")
						}
					case <-timer.C:
						t.Fatalf("required states not reached %v; seen=%v", names, seen)
					}
				}
			}
			send := func(command string) {
				t.Helper()
				if _, err := fmt.Fprintln(input, command); err != nil {
					t.Fatal(err)
				}
			}
			signalStop := func() {
				t.Helper()
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			var stopClient *exec.Cmd
			var stopDone chan error
			var stopExited chan struct{}
			launchStop := func() {
				t.Helper()
				stopClient = exec.Command(os.Args[0], "-test.run=^TestIndependentP4CLICommandChild$", "--", "it4-command", "stop", configuration)
				log, err := os.Create(filepath.Join(root, "stop-client.log"))
				if err != nil {
					t.Fatal(err)
				}
				stopClient.Stdout, stopClient.Stderr = log, log
				if err := stopClient.Start(); err != nil {
					_ = log.Close()
					t.Fatal(err)
				}
				stopDone = make(chan error, 1)
				stopExited = make(chan struct{})
				go func() { err := stopClient.Wait(); _ = log.Close(); stopDone <- err; close(stopExited) }()
			}
			defer func() {
				if stopClient != nil {
					select {
					case <-stopExited:
					default:
						_ = stopClient.Process.Kill()
						<-stopExited
					}
				}
			}()
			if which == "begin-held" {
				await(5*time.Second, "begin-held")
			} else {
				await(5*time.Second, "ready")
			}
			if which == "gate-first" || which == "processing-first" {
				send("block-controller")
				await(2*time.Second, "controller-held")
			}
			if strings.HasPrefix(which, "live-") {
				send("feed-held")
				await(2*time.Second, "work-held")
			}
			first := time.Now()
			switch which {
			case "gate-first":
				send("gate")
				await(time.Second, "gate-triggered")
			case "processing-first":
				send("feed-held")
				await(time.Second, "parse-failed", "processing-failed")
			case "begin-held":
				signalStop()
			default:
				launchStop()
			}
			waitUntil := func(since time.Duration) {
				t.Helper()
				timer := time.NewTimer(max(0, time.Until(first.Add(since))))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-done:
					t.Fatalf("daemon ended before live observation at %s: %v", since, exitErr)
				}
			}
			if which == "gate-first" || which == "processing-first" {
				await(time.Second, "alpha-withdrawn")
				waitUntil(5 * time.Second)
				launchStop()
				await(time.Second, "stop-signal")
				if which == "processing-first" {
					send("gate")
					await(time.Second, "gate-triggered")
				}
				// Withdrawal above must occur while the controller is held. Once
				// the later trigger has arrived, let it finish so a real final
				// snapshot can reach the separate publication hold.
				send("release-work")
				await(time.Second, "controller-released")
				await(16*time.Second, "projection-held")
			} else if strings.HasPrefix(which, "multi-") {
				await(2*time.Second, "alpha-withdrawn", "beta-withdrawn", "work-held")
				if which == "multi-close" {
					await(time.Second, "alpha-close", "beta-close")
				}
			} else if which != "begin-held" {
				await(time.Second, "alpha-withdrawn")
			}
			if strings.HasPrefix(which, "live-") {
				await(21*time.Second, "projection-held")
				send("sample-before")
				await(time.Second, "sample-before")
				directory := filepath.Join(root, "data", sessionsName, session)
				accountBefore, err := os.ReadFile(filepath.Join(directory, sealedName))
				if err != nil {
					t.Fatal(err)
				}
				outputBefore, err := os.ReadFile(filepath.Join(root, "data", processing.ArtifactName))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(directory, published.Name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("publication hold was not before projection: %v", err)
				}
				send("release-work")
				await(time.Second, "work-released")
				waitUntil(22 * time.Second)
				send("sample-after")
				await(time.Second, "sample-after")
				before, _ := os.ReadFile(filepath.Join(root, "sample-before.json"))
				after, _ := os.ReadFile(filepath.Join(root, "sample-after.json"))
				if !bytes.Equal(before, after) {
					t.Errorf("live cutoff facts changed after worker release: before=%s after=%s", before, after)
				}
				var sample struct {
					Processing *account.Processing
					Writer     processing.WriterStats
				}
				if err := json.Unmarshal(before, &sample); err != nil {
					t.Fatal(err)
				}
				if !sample.Writer.Closed || sample.Processing == nil || sample.Processing.Authorized != 2 {
					t.Errorf("work cutoff did not close writer with only free output: %+v", sample)
				}
				wantIDs := uint64(1)
				if which == "live-authorization" {
					wantIDs = 2
				}
				if sample.Processing != nil && sample.Processing.ExchangeIDs != wantIDs {
					t.Errorf("cutoff froze wrong exchange id population: got %d want %d", sample.Processing.ExchangeIDs, wantIDs)
				}
				accountAfter, _ := os.ReadFile(filepath.Join(directory, sealedName))
				outputAfter, _ := os.ReadFile(filepath.Join(root, "data", processing.ArtifactName))
				if !bytes.Equal(accountBefore, accountAfter) || !bytes.Equal(outputBefore, outputAfter) {
					t.Error("live released worker changed sealed account or approved file")
				}
				if _, err := os.Stat(filepath.Join(directory, published.Name)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("held projection appeared early: %v", err)
				}
				send("release-publication")
			}
			if which == "free-cleanup" {
				await(2*time.Second, "returned-ok")
				if elapsed := time.Since(first); elapsed > 2*time.Second {
					t.Errorf("free stop waited for its deadline: %s", elapsed)
				}
				lock, err := acquire(filepath.Join(root, "data"))
				if err != nil {
					t.Fatalf("completed start retained pid lock: %v", err)
				}
				lock.release()
				waitUntil(26 * time.Second)
				send("exit")
			}
			allowance := 25*time.Second + 500*time.Millisecond
			if which == "free-cleanup" {
				allowance = 28 * time.Second
			}
			timer := time.NewTimer(max(0, time.Until(first.Add(allowance))))
			defer timer.Stop()
			timedOut := false
			select {
			case <-done:
			case <-timer.C:
				timedOut = true
				_ = cmd.Process.Kill()
				<-done
				t.Errorf("actual CLI process exceeded %s from first trigger", allowance)
			}
			status, _ := json.Marshal(map[string]any{"first_trigger": first, "elapsed_ms": time.Since(first).Milliseconds(), "timed_out": timedOut, "exit": cmd.ProcessState.ExitCode(), "session": session, "seen": seen})
			if err := os.WriteFile(filepath.Join(root, "exit.json"), status, 0600); err != nil {
				t.Error(err)
			}
			if which == "free-cleanup" && exitErr != nil {
				t.Errorf("free CLI stop failed: %v", exitErr)
			}
			if which != "free-cleanup" && exitErr == nil {
				t.Error("failed/incomplete CLI stop exited successfully")
			}
			if stopDone != nil {
				select {
				case stopErr := <-stopDone:
					if (stopErr == nil) != (which == "free-cleanup") {
						t.Errorf("real stop command exit: %v", stopErr)
					}
					if err := os.WriteFile(filepath.Join(root, "stop-client.status"), []byte(fmt.Sprintln(stopClient.ProcessState.ExitCode())), 0600); err != nil {
						t.Error(err)
					}
				case <-time.After(2 * time.Second):
					t.Error("real stop client did not return after daemon exit")
				}
			}
			if which == "begin-held" {
				entries, err := os.ReadDir(filepath.Join(root, "data", sessionsName))
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Error(err)
				}
				if err == nil && len(entries) != 0 {
					t.Error("held begin invented a session account")
				}
			} else {
				directory := filepath.Join(root, "data", sessionsName, session)
				a := it4Account(t, directory)
				if a.Seal == nil {
					t.Fatal("CLI produced no seal facts")
				}
				if which == "free-cleanup" {
					if !a.Seal.Complete {
						t.Errorf("free CLI seal incomplete: %+v", a.Seal)
					}
				} else if which == "gate-first" {
					// The controller returned before the work deadline; the gate
					// invalidates capture, while publication is held after sealing.
					if !a.Seal.Complete || a.Processing == nil || a.Processing.GateReason != probe.GateUnknownLength {
						t.Errorf("completed work lost the gate's capture failure: seal=%+v processing=%+v", a.Seal, a.Processing)
					}
				} else if a.Seal.Complete {
					t.Error("held CLI owner sealed complete")
				}
				if which == "processing-first" && !strings.Contains(strings.Join(a.Seal.Because, " "), "it4 actual processing failure") {
					t.Errorf("own seal omitted actual processing failure: %+v", a.Seal)
				}
				if strings.HasPrefix(which, "live-") && !strings.Contains(strings.Join(a.Seal.Because, " "), "processing workers") {
					t.Errorf("held worker stage missing from seal: %+v", a.Seal)
				}
				if strings.HasPrefix(which, "multi-") && !strings.Contains(strings.Join(a.Seal.Because, " "), map[string]string{"multi-close": "attachment close", "multi-withdraw": "withdrawal"}[which]) {
					t.Errorf("multiowner incomplete seal omitted held stage: %+v", a.Seal)
				}
				_, projectionErr := os.Stat(filepath.Join(directory, published.Name))
				_, pointerErr := os.Stat(filepath.Join(root, "data", lastName))
				if which == "gate-first" || which == "processing-first" {
					if !errors.Is(projectionErr, os.ErrNotExist) || !errors.Is(pointerErr, os.ErrNotExist) {
						t.Errorf("held projection published late artifacts: projection=%v pointer=%v", projectionErr, pointerErr)
					}
				} else if which == "multi-withdraw" {
					if err := validateSessionSeal(a); err != nil {
						t.Fatalf("invalid own seal after held withdrawal: %v", err)
					}
					if a.Session != session || a.Seen != nil || a.Loss != nil || a.Refused != nil || a.Admitted != nil || a.Admissions != nil || a.Seal.Withdrawal.Complete || a.Seal.Drain.Complete {
						t.Error("held withdrawal invented final capture facts or completed lifecycle")
					}
					counts, err := json.Marshal(a.Seal.Counters)
					if err != nil {
						t.Fatal(err)
					}
					var unread map[string]connection.Count
					if err := json.Unmarshal(counts, &unread); err != nil {
						t.Fatal(err)
					}
					unread["drain.delivered"], unread["drain.outstanding"], unread["interrupted"] = a.Seal.Drain.Delivered, a.Seal.Drain.Outstanding, a.Seal.Interrupted
					for name, count := range unread {
						if count.Known || count.Value != 0 {
							t.Errorf("unread %s became a measured count: %+v", name, count)
						}
					}
					if !errors.Is(projectionErr, os.ErrNotExist) || pointerErr != nil {
						t.Errorf("expected rejected projection and own-seal discovery: projection=%v pointer=%v", projectionErr, pointerErr)
					}
					var receipt shutdownReceipt
					content, err := os.ReadFile(filepath.Join(directory, controlName, terminalName))
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(content, &receipt); err != nil {
						t.Fatal(err)
					}
					if receipt.Session != session || !receipt.Sealed.Equal(a.Seal.Sealed) || receipt.Outcome != shutdownPublicationFailed || !strings.Contains(receipt.Error, "without its seen block") || !strings.Contains(receipt.Error, "withdrawal") {
						t.Errorf("projection rejection not separately reported against own seal: %+v", receipt)
					}
					var pointer sealedSession
					content, err = os.ReadFile(filepath.Join(root, "data", lastName))
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(content, &pointer); err != nil {
						t.Fatal(err)
					}
					if pointer.Session != session || !pointer.Sealed.Equal(a.Seal.Sealed) || pointer.Account != filepath.Join(directory, sealedName) || pointer.Complete {
						t.Errorf("pointer did not discover the same incomplete seal: %+v", pointer)
					}
				} else if projectionErr != nil || pointerErr != nil {
					t.Errorf("completed publication missing artifacts: projection=%v pointer=%v", projectionErr, pointerErr)
				}
				var output bytes.Buffer
				stopErr := stoppedSession(filepath.Join(root, "data"), session, &output)
				_ = os.WriteFile(filepath.Join(root, "stop-output.txt"), output.Bytes(), 0600)
				if (stopErr == nil) != (which == "free-cleanup") {
					t.Errorf("own-session stop outcome: %v", stopErr)
				}
			}
			lock, err := acquire(filepath.Join(root, "data"))
			if err != nil {
				t.Errorf("exited CLI retained pid lock: %v", err)
			} else {
				lock.release()
			}
		})
	}
}
