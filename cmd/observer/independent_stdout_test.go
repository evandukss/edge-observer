package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

type it1Event struct {
	Kind string
	Data json.RawMessage
}
type it1Events struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (e *it1Events) send(kind string, v any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	raw, err := json.Marshal(v)
	if err != nil {
		os.Exit(61)
	}
	if e.enc.Encode(it1Event{kind, raw}) != nil {
		os.Exit(62)
	}
}

type it1Console struct{ events *it1Events }

func (w it1Console) Write(p []byte) (int, error) {
	w.events.send("stderr", json.RawMessage(bytes.TrimSpace(p)))
	return os.Stderr.Write(p)
}

type it1ObservedFile struct {
	sink.Sink
	events *it1Events
}

func (s it1ObservedFile) Write(ctx context.Context, p []byte) (int, error) {
	n, err := s.Sink.Write(ctx, p)
	if err == nil {
		s.events.send("file", json.RawMessage(bytes.TrimSpace(p)))
	}
	return n, err
}

type it1HeldOutput struct {
	events   *it1Events
	release  <-chan struct{}
	returned chan struct{}
	once     sync.Once
}

func (s *it1HeldOutput) Write(p []byte) (int, error) {
	s.events.send("held", string(p))
	<-s.release
	s.once.Do(func() { close(s.returned) })
	return len(p), nil
}

type it1Producer struct {
	stamp  atomic.Int64
	events *it1Events
}

func (*it1Producer) Capability() probe.Capability { return probe.Capability{} }
func (*it1Producer) Close() error                 { return nil }
func (p *it1Producer) StopProducing() (connection.Withdrawal, error) {
	p.events.send("withdrawal", true)
	return connection.Withdrawal{At: time.Now(), Complete: true}, nil
}
func (*it1Producer) Drain(time.Duration) (connection.Drained, error) {
	return connection.Drained{Complete: true, Delivered: connection.Counted(0), Outstanding: connection.Counted(0)}, nil
}
func (p *it1Producer) Account() (connection.Counters, error) {
	return connection.Counters{ReservationAttempts: connection.Counted(p.stamp.Load())}, nil
}

// Only attachment and its counters are synthetic. The child runs the real
// command parser, writer selection, logger, ownership and shutdown machinery.
func TestIndependentStdoutCommandPeer(t *testing.T) {
	at := -1
	for i, a := range os.Args {
		if a == "it1-command" {
			at = i
			break
		}
	}
	if at < 0 {
		return
	}
	if len(os.Args) != at+3 {
		os.Exit(63)
	}
	root, mode := os.Args[at+1], os.Args[at+2]
	events := &it1Events{enc: json.NewEncoder(os.NewFile(3, "it1-events"))}
	producer := &it1Producer{events: events}
	stopping := make(chan os.Signal, 1)
	built := make(chan *daemon, 1)
	hold := make(chan struct{})
	held := &it1HeldOutput{events: events, release: hold, returned: make(chan struct{})}
	var destination io.Writer = os.Stdout
	if mode == "held" {
		destination = held
	}
	deps := commandDependencies{stderr: it1Console{events}, stopping: stopping, begin: func(read policy.Policy, id string, options processing.WriterOptions) (*daemon, error) {
		if read.Processing == nil || read.ProcessingRevision == "" || read.Settings.Directory != root || options.Directory != root {
			return nil, fmt.Errorf("wiring: validated plan/options missing")
		}
		events.send("begin", map[string]any{"session": id, "mirror": options.Stdout != nil, "directory": options.Directory})
		options.OpenSink = func(path string) sink.Sink { return it1ObservedFile{Sink: sink.NewFile(path), events: events} }
		if mode == "held" {
			options.StdoutQueueBytes = 4096
		}
		output, err := processing.OpenWriter(options)
		if err != nil {
			return nil, err
		}
		recording, store, err := recordingIntake(4096)
		if err != nil {
			return nil, err
		}
		gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: store.Exhausted()})
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(root, sessionsName, id)
		if err = os.MkdirAll(filepath.Join(dir, controlName), 0700); err != nil {
			return nil, err
		}
		plan := account.Plan(time.Now(), account.Policy{Revision: read.Revision, Generation: 1}, process.Resolution{}, producer.Capability(), nil)
		plan.Attached(account.Live, id, nil, producer.Capability())
		d := &daemon{policy: read, session: id, directory: dir, capture: recording, intake: store, gate: gate, output: output, attached: producer, ends: &endings{}, plan: plan,
			processingTaken: func(int, fragment.Process, fragment.ConnectionID) { events.send("taken", true) },
			shutdownHooks: &shutdownHooks{Before: func(_ context.Context, stage shutdownStage) error {
				if stage == shutdownWriter {
					events.send("stage", string(stage))
				}
				return nil
			}},
		}
		built <- d
		return d, nil
	}}
	config := filepath.Join(root, "config.json")
	ended := make(chan error, 1)
	go func() { ended <- runWith([]string{"start", config, "--stdout"}, destination, deps) }()
	var d *daemon
	select {
	case d = <-built:
	case err := <-ended:
		events.send("early-error", fmt.Sprint(err))
		os.Exit(64)
	case <-time.After(5 * time.Second):
		os.Exit(65)
	}
	input := bufio.NewScanner(os.Stdin)
	number := uint64(0)
	for input.Scan() {
		switch input.Text() {
		case "feed":
			number++
			for j, text := range []string{fmt.Sprintf("GET /it1/%d HTTP/1.1\r\nHost: fixture\r\nX-Public: visible-%d\r\nAuthorization: IT1_COMMAND_PRIVATE\r\n\r\n", number, number), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"} {
				direction := fragment.Sent
				if j == 1 {
					direction = fragment.Received
				}
				if !d.gate.Admit(probe.DeliveryTransfer, true).Admitted {
					events.send("wiring-error", "capture gate refused")
					os.Exit(66)
				}
				stamp := producer.stamp.Add(1)
				d.capture.Transfer(probe.Transfer{Process: fragment.Process{PID: 42, StartTime: 7}, Instance: admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}, Endpoint: 7, Direction: direction, Measured: true, Length: uint32(len(text)), Payload: []byte(text), Stamp: uint64(stamp), Sequence: probe.Sequence{Occupancy: 7, Number: number, Born: true}, At: time.Now()})
			}
			events.send("fed", number)
		case "restart":
			pid, id, err := holder(root)
			if err != nil {
				events.send("wiring-error", err.Error())
				os.Exit(67)
			}
			refusal := runWith([]string{"restart", config, "--stdout"}, destination, deps)
			afterPID, afterID, afterErr := holder(root)
			events.send("restart", map[string]any{"refused": refusal != nil, "before_pid": pid, "after_pid": afterPID, "before_session": id, "after_session": afterID, "holder_error": fmt.Sprint(afterErr)})
		case "stop":
			events.send("stop-trigger", time.Now())
			stopping <- os.Interrupt
			err := <-ended
			events.send("returned", map[string]any{"error": fmt.Sprint(err), "stdout": d.output.StdoutDeliveryStats(), "file": d.output.DeliveryStats(), "session": d.session})
			if mode == "held" {
				before := *d.output.StdoutDeliveryStats()
				close(hold)
				select {
				case <-held.returned:
				case <-time.After(time.Second):
					os.Exit(68)
				}
				events.send("frozen", reflect.DeepEqual(before, *d.output.StdoutDeliveryStats()))
			}
			os.Exit(0)
		}
	}
	os.Exit(69)
}

type it1Command struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	stdout *os.File
	stderr bytes.Buffer
	next   chan it1Event
	seen   []it1Event
	cancel context.CancelFunc
	wait   chan error
	root   string
}

func it1CommandStart(t *testing.T, mode string) *it1Command {
	t.Helper()
	root := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"version": "observer.config/1", "output": root, "log": filepath.Join(root, "operations.jsonl"), "write_content": true, "remove": map[string]any{"headers": []string{"authorization"}}, "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}, "limits": map[string]any{"events": 4096, "state_every_seconds": 30}})
	if err := os.WriteFile(filepath.Join(root, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	p := &it1Command{root: root, cancel: cancel, next: make(chan it1Event, 1024), wait: make(chan error, 1)}
	p.cmd = exec.CommandContext(ctx, self, "-test.run=^TestIndependentStdoutCommandPeer$", "--", "it1-command", root, mode)
	p.input, err = p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	readOut, writeOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p.stdout = readOut
	p.cmd.Stdout = writeOut
	p.cmd.Stderr = &p.stderr
	readEvents, writeEvents, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p.cmd.ExtraFiles = []*os.File{writeEvents}
	if err = p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writeOut.Close()
	_ = writeEvents.Close()
	go func() {
		defer close(p.next)
		defer func() { _ = readEvents.Close() }()
		dec := json.NewDecoder(readEvents)
		for {
			var e it1Event
			if dec.Decode(&e) != nil {
				return
			}
			p.next <- e
		}
	}()
	go func() { p.wait <- p.cmd.Wait() }()
	t.Cleanup(func() { cancel(); _ = p.input.Close(); _ = p.stdout.Close() })
	p.until(t, func() bool { return p.count("begin") == 1 }, "wiring: validated begin not reached")
	var begun struct{ Mirror bool }
	_ = json.Unmarshal(p.first("begin").Data, &begun)
	if !begun.Mirror {
		t.Fatal("property: --stdout did not select the real mirror")
	}
	return p
}
func (p *it1Command) count(kind string) int {
	n := 0
	for _, e := range p.seen {
		if e.Kind == kind {
			n++
		}
	}
	return n
}
func (p *it1Command) first(kind string) it1Event {
	for _, e := range p.seen {
		if e.Kind == kind {
			return e
		}
	}
	return it1Event{}
}
func (p *it1Command) operational(record string) bool {
	for _, e := range p.seen {
		if e.Kind == "stderr" {
			var v struct{ Record string }
			_ = json.Unmarshal(e.Data, &v)
			if v.Record == record {
				return true
			}
		}
	}
	return false
}
func (p *it1Command) until(t *testing.T, done func() bool, why string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for !done() {
		select {
		case e, ok := <-p.next:
			if !ok {
				t.Fatalf("%s: event stream ended", why)
			}
			p.seen = append(p.seen, e)
			if e.Kind == "wiring-error" || e.Kind == "early-error" {
				t.Fatalf("wiring: %s", e.Data)
			}
		case <-timer.C:
			t.Fatal(why)
		}
	}
}
func (p *it1Command) send(t *testing.T, s string) {
	t.Helper()
	if _, err := fmt.Fprintln(p.input, s); err != nil {
		t.Fatalf("wiring: child command: %v", err)
	}
}
func (p *it1Command) feed(t *testing.T, n int) {
	t.Helper()
	for range n {
		p.send(t, "feed")
	}
	p.until(t, func() bool { return p.count("taken") >= 2*p.count("fed") && p.count("fed") >= n }, "wiring: capture input was not consumed")
}
func (p *it1Command) stop(t *testing.T) time.Duration {
	t.Helper()
	start := time.Now()
	p.send(t, "stop")
	select {
	case err := <-p.wait:
		if err != nil {
			t.Fatalf("property: command child failed: %v; stderr=%s", err, p.stderr.String())
		}
	case <-time.After(28 * time.Second):
		t.Fatal("property: held stdout prevented bounded command exit")
	}
	for e := range p.next {
		p.seen = append(p.seen, e)
	}
	t.Logf("COMMAND_RETURN %s", p.first("returned").Data)
	var final struct{ Error string }
	if json.Unmarshal(p.first("returned").Data, &final) != nil || final.Error != "<nil>" {
		t.Fatalf("property: command finalization failed: %s", p.first("returned").Data)
	}
	return time.Since(start)
}
func it1Approved(t *testing.T, raw []byte) []processing.Artifact {
	t.Helper()
	var out []processing.Artifact
	scan := bufio.NewScanner(bytes.NewReader(raw))
	for scan.Scan() {
		var a processing.Artifact
		if json.Unmarshal(scan.Bytes(), &a) != nil || a.Version != processing.ArtifactVersion || (a.Record != processing.ArtifactExchange && a.Record != processing.ArtifactConnection) {
			t.Fatalf("property: stdout contains non-approved record: %s", scan.Bytes())
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		t.Fatal("wiring: approved output empty")
	}
	return out
}

func TestIndependentStdoutCommandRoutingAndLiveRestartRefusal(t *testing.T) {
	p := it1CommandStart(t, "free")
	p.feed(t, 1)
	p.until(t, func() bool { return p.count("file") >= 1 }, "property: file did not progress on open keepalive")
	reader := bufio.NewReader(p.stdout)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	a := it1Approved(t, line)[0]
	if !a.Connection.Provisional || a.Record != processing.ArtifactExchange {
		t.Fatal("property: keepalive exchange not streamed before close")
	}
	p.send(t, "restart")
	p.until(t, func() bool { return p.count("restart") == 1 }, "wiring: restart refusal did not return")
	var refusal struct {
		Refused   bool
		BeforePID int    `json:"before_pid"`
		AfterPID  int    `json:"after_pid"`
		Before    string `json:"before_session"`
		After     string `json:"after_session"`
		Err       string `json:"holder_error"`
	}
	_ = json.Unmarshal(p.first("restart").Data, &refusal)
	if !refusal.Refused || refusal.BeforePID != p.cmd.Process.Pid || refusal.AfterPID != refusal.BeforePID || refusal.Before == "" || refusal.After != refusal.Before || refusal.Err != "<nil>" {
		t.Fatalf("property: restart --stdout changed live owner: %+v", refusal)
	}
	p.send(t, "feed")
	p.until(t, func() bool { return p.count("file") >= 2 }, "property: refused restart stopped subsequent processing")
	p.stop(t)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(line, rest...)
	file, err := os.ReadFile(filepath.Join(p.root, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	records := it1Approved(t, raw)
	if len(records) != 3 || !bytes.Equal(raw, file) || bytes.Contains(raw, []byte("IT1_COMMAND_PRIVATE")) || !bytes.Contains(raw, []byte("visible-2")) {
		t.Fatalf("property: stdout/file released bytes, sanitation or count differ: lines=%d", len(records))
	}
	logs, err := os.ReadFile(filepath.Join(p.root, "operations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logs, p.stderr.Bytes()) || (!p.operational("activation-completed") || !p.operational("stopped")) {
		t.Fatalf("property: operational routing differs: file=%s stderr=%s", logs, p.stderr.Bytes())
	}
}

func TestIndependentStdoutClosedFD1SurvivesWithFileIntact(t *testing.T) {
	p := it1CommandStart(t, "closed")
	p.feed(t, 1)
	p.until(t, func() bool { return p.count("file") >= 1 }, "wiring: initial file control absent")
	first, err := bufio.NewReader(p.stdout).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	it1Approved(t, first)
	if err = p.stdout.Close(); err != nil {
		t.Fatal(err)
	}
	p.send(t, "feed")
	p.until(t, func() bool { return p.count("file") >= 2 }, "property: closing real stdout reader killed file delivery")
	p.stop(t)
	file, err := os.ReadFile(filepath.Join(p.root, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	if len(it1Approved(t, file)) != 3 {
		t.Fatal("property: closed stdout lost approved file lines")
	}
	var result struct {
		Stdout sink.Stats
		File   sink.Stats
	}
	_ = json.Unmarshal(p.first("returned").Data, &result)
	if result.File.Written != 3 || result.Stdout.Authorized != 3 || result.Stdout.Written != 1 || result.Stdout.Failed != 2 || result.Stdout.Dropped+result.Stdout.Pending != 0 {
		t.Fatalf("property: closed-reader delivery outcomes: %+v", result)
	}
}

func TestIndependentStdoutHeldDestinationBoundsWholeCommand(t *testing.T) {
	p := it1CommandStart(t, "held")
	p.feed(t, 1)
	p.until(t, func() bool { return p.count("held") == 1 && p.count("file") == 1 }, "wiring: in-flight stdout write and free file control not reached")
	for range 15 {
		p.send(t, "feed")
	}
	p.until(t, func() bool { return p.count("file") == 16 && p.count("taken") == 32 }, "property: held stdout blocked file or capture progress")
	elapsed := p.stop(t)
	if elapsed > 26*time.Second {
		t.Fatalf("property: command exceeded 25s bound plus 1s runtime margin: %s", elapsed)
	}
	if p.count("stage") < 1 || p.count("withdrawal") != 1 {
		t.Fatal("wiring: writer shutdown stage or producer withdrawal not reached")
	}
	var result struct {
		Stdout  sink.Stats
		File    sink.Stats
		Session string
	}
	_ = json.Unmarshal(p.first("returned").Data, &result)
	var admitted uint64
	var charge int64
	for _, e := range p.seen {
		if e.Kind == "file" && charge+int64(len(e.Data)+1) <= 4096 {
			admitted++
			charge += int64(len(e.Data) + 1)
		}
	}
	if admitted == 0 || admitted == 17 {
		t.Fatal("wiring: held queue did not reach admitted and refused populations")
	}
	if result.Stdout.Authorized != 17 || result.Stdout.Written != 0 || result.Stdout.Failed != 0 || result.Stdout.Dropped != 17 || result.Stdout.Pending != 0 || result.Stdout.Discarded != admitted || result.File.Written != 17 || result.File.Dropped+result.File.Failed != 0 {
		t.Fatalf("property: held stdout terminal losses/file outcomes: %+v", result)
	}
	var frozen bool
	_ = json.Unmarshal(p.first("frozen").Data, &frozen)
	if !frozen {
		t.Fatal("property: released hold changed final stdout counts")
	}
	raw, err := os.ReadFile(filepath.Join(p.root, sessionsName, result.Session, sealedName))
	if err != nil {
		t.Fatal(err)
	}
	var a account.Account
	if json.Unmarshal(raw, &a) != nil || a.Processing == nil || a.Processing.StdoutDelivery == nil {
		t.Fatal("property: sealed account lacks stdout delivery")
	}
	if !reflect.DeepEqual(*a.Processing.StdoutDelivery, result.Stdout) || !reflect.DeepEqual(a.Processing.Delivery, result.File) {
		t.Fatal("property: sealed stdout/file projection differs from frozen facts")
	}
	projection, err := os.ReadFile(filepath.Join(p.root, sessionsName, result.Session, published.Name))
	if err != nil {
		t.Fatalf("property: account projection missing: %v", err)
	}
	var projected struct {
		Processing struct {
			Aggregate struct {
				Stdout map[string]string `json:"stdout_delivery"`
			}
		}
	}
	if json.Unmarshal(projection, &projected) != nil || projected.Processing.Aggregate.Stdout["authorized"] != "17" || projected.Processing.Aggregate.Stdout["dropped"] != "17" {
		t.Fatalf("property: projected stdout losses differ: %s", projection)
	}
	var rendered bytes.Buffer
	if err := run([]string{"inspect", filepath.Join(p.root, sessionsName, result.Session), "--text", "--file", filepath.Join(p.root, processing.ArtifactName)}, &rendered); err != nil {
		t.Fatalf("property: inspect of sealed stdout session: %v", err)
	}
	if !strings.Contains(rendered.String(), "stdout     17 authorized, 0 written, 0 failed, 17 dropped, 0 pending;") {
		t.Fatal("property: inspect text omitted stdout delivery losses")
	}
	t.Logf("in-flight hold reached; 16 file lines before stop; command exit %s; stdout discarded=%d dropped=%d", elapsed, result.Stdout.Discarded, result.Stdout.Dropped)
}

func TestIndependentStdoutInvalidCombinationsBeforeActivation(t *testing.T) {
	for _, kind := range []string{"daemonize", "log-stdout"} {
		t.Run(kind, func(t *testing.T) {
			root, controlRoot := t.TempDir(), t.TempDir()
			configuration := func(directory, logPath string) string {
				raw, err := json.Marshal(map[string]any{"version": "observer.config/1", "output": directory, "log": logPath, "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}})
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(directory, "config.json")
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			controlPath := configuration(controlRoot, filepath.Join(controlRoot, "log.jsonl"))
			calls := 0
			expectedDirectory := controlRoot
			deps := commandDependencies{begin: func(read policy.Policy, id string, o processing.WriterOptions) (*daemon, error) {
				calls++
				if read.Processing == nil || id == "" || o.Directory != expectedDirectory {
					return nil, fmt.Errorf("wiring: invalid validated input")
				}
				return nil, fmt.Errorf("it1 activation control")
			}, stderr: io.Discard, stopping: make(chan os.Signal)}
			var console bytes.Buffer
			err := runWith([]string{"start", controlPath, "--stdout"}, &console, deps)
			if calls != 1 || err == nil || err.Error() != "it1 activation control" {
				t.Fatalf("wiring: legal activation control did not reach begin exactly once: %d %v", calls, err)
			}
			calls = 0
			expectedDirectory = root
			logPath := filepath.Join(root, "log.jsonl")
			if kind == "log-stdout" {
				logPath = "stdout"
			}
			path := configuration(root, logPath)
			args := []string{"start", path, "--stdout"}
			if kind == "daemonize" {
				args = append(args, "--daemonize")
			}
			err = runWith(args, &console, deps)
			if err == nil || !strings.Contains(err.Error(), "stdout") || calls != 0 {
				t.Fatalf("property: invalid %s activated: calls=%d err=%v", kind, calls, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "config.json" {
				t.Fatalf("property: invalid combination created activation artifacts: %v", entries)
			}
		})
	}
}
