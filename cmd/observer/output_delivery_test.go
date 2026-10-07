package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/sink"
)

func TestLiveAndSealedLogCountsDistinguishFileFromStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.log")
	stdout := &failingLogWriter{failed: true}
	log, err := openLog(policy.Settings{Log: path}, true, stdout)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.close() }()
	f := processingControllerWith(t, controllerSetup{events: 100, log: log})
	if err := log.write(activation{Record: "activation-completed", Session: f.d.session}); err != nil {
		t.Fatal(err)
	}
	if err := log.queue.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(a account.Account, want uint64) {
		t.Helper()
		file, fileOK := a.LogDestinations["file"]
		out, outOK := a.LogDestinations["stdout"]
		if len(a.LogDestinations) != 2 || !fileOK || !outOK || file.Authorized != want || file.Written != want || file.Failed != 0 || out.Authorized != want || out.Written != 0 || out.Failed != want {
			t.Fatalf("per-destination outcomes: %+v", a.LogDestinations)
		}
		if a.LogDelivery == nil || a.LogDelivery.Authorized != 2*want || a.LogDelivery.Written != want || a.LogDelivery.Failed != want {
			t.Fatalf("aggregate outcomes: %+v", a.LogDelivery)
		}
	}
	check(f.d.snapshot(account.Live, time.Now()), 1)
	f.halt(t)
	if err := f.finish(log); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(f.d.directory, sealedName))
	if err != nil {
		t.Fatal(err)
	}
	var sealed account.Account
	if err := json.Unmarshal(encoded, &sealed); err != nil {
		t.Fatal(err)
	}
	check(sealed, 2)
}

func TestUnavailableOperationalLogRecoversAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.log")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	log, err := openLog(policy.Settings{Log: path}, false, nil)
	if err != nil {
		t.Fatalf("unavailable log refused startup: %v", err)
	}
	defer func() { _ = log.close() }()
	if err := log.write(activation{Record: "activation-completed", Session: "session-a"}); err != nil {
		t.Fatal(err)
	}
	if err := log.queue.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := log.queue.Stats(); st.Failed != 1 || st.Written != 0 {
		t.Fatalf("failed activation log: %+v", st)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := log.reopen(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := log.write(state{Record: "state", Session: "session-a"}); err != nil {
		t.Fatal(err)
	}
	if err := log.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"record":"state"`) || strings.Contains(string(data), "activation-completed") {
		t.Fatalf("recovery data %s", data)
	}
	if st := log.queue.Stats(); st.Authorized != 2 || st.Failed != 1 || st.Written != 1 || st.Pending != 0 {
		t.Fatalf("recovery counts %+v", st)
	}
}

type failingLogWriter struct {
	failedWrite chan struct{}
	mutex       sync.Mutex
	failed      bool
	buffer      bytes.Buffer
}

func (w *failingLogWriter) Write(p []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.failed {
		if w.failedWrite != nil {
			select {
			case w.failedWrite <- struct{}{}:
			default:
			}
		}
		return 0, errors.New("injected log failure")
	}
	return w.buffer.Write(p)
}
func TestOperationalLogMidSessionFailureDoesNotStopController(t *testing.T) {
	writer := &failingLogWriter{failedWrite: make(chan struct{}, 1)}
	log := &logger{out: writer}
	ticks := make(chan time.Time)
	f := processingControllerWith(t, controllerSetup{events: 100, log: log, ticks: ticks})
	if err := log.write(activation{Record: "activation-completed", Session: f.d.session}); err != nil {
		t.Fatal(err)
	}
	if err := log.queue.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	writer.mutex.Lock()
	writer.failed = true
	writer.mutex.Unlock()
	select {
	case ticks <- time.Now():
	case <-time.After(time.Second):
		t.Fatal("controller did not take its state tick")
	}
	select {
	case <-writer.failedWrite:
	case <-time.After(time.Second):
		t.Fatal("wiring: controller state record did not reach failing log")
	}
	if err := log.queue.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.done:
		t.Fatal("log failure stopped controller")
	default:
	}
	f.liveControl(t)
	writer.mutex.Lock()
	writer.failed = false
	writer.mutex.Unlock()
	f.halt(t)
	if err := f.finish(log); err != nil {
		t.Fatal(err)
	}
	if st := log.queue.Stats(); st.Authorized != 3 || st.Written != 2 || st.Failed != 1 {
		t.Fatalf("log outcomes: %+v", st)
	}
	if reason := f.d.gate.Snapshot().Reason; reason != "" {
		t.Fatalf("sink withdrew capture: %s", reason)
	}
}
func TestOperationalLogRenameSwitchesAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observer.log")
	log, err := openLog(policy.Settings{Log: path}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.close() }()
	if err := log.write(map[string]string{"session": "before"}); err != nil {
		t.Fatal(err)
	}
	if err := log.queue.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := log.reopen(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := log.write(map[string]string{"session": "after"}); err != nil {
		t.Fatal(err)
	}
	if err := log.close(); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	next, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != "{\"session\":\"before\"}\n" || string(next) != "{\"session\":\"after\"}\n" {
		t.Fatalf("rotation old %q next %q", old, next)
	}
}

type heldOutput struct {
	entered chan struct{}
	release chan struct{}
}

func (s *heldOutput) Write(_ context.Context, p []byte) (int, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return len(p), nil
}
func (*heldOutput) Reopen(context.Context) error { return nil }
func (*heldOutput) Close(context.Context) error  { return nil }
func TestControllerSealsWithBlockedOutputAndCountsDiscarded(t *testing.T) {
	output := &heldOutput{entered: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(output.release)
	f := processingControllerWith(t, controllerSetup{events: 100, openSink: func(string) sink.Sink { return output }})
	f.transfer(t, 7, fragment.Sent, "GET /held HTTP/1.1\r\n\r\n")
	f.transfer(t, 7, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	f.closed(t, 7)
	select {
	case <-output.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("wiring: output not reached")
	}
	f.halt(t)
	done := make(chan error, 1)
	go func() { done <- f.finish(&logger{}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked output prevented finalization")
	}
	st := f.d.output.DeliveryStats()
	if st.Authorized != 2 || st.Written != 0 || st.Pending != 0 || st.Discarded != 2 || st.Dropped != 2 {
		t.Fatalf("bounded stop: %+v", st)
	}
	var read bytes.Buffer
	if err := inspect(f.d.directory, false, &read); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read.String(), `"discarded": 2`) {
		t.Fatalf("account missing discard count: %s", read.String())
	}
}

func TestInspectFiltersSessionAcrossExplicitRotatedFiles(t *testing.T) {
	f := processingController(t)
	f.liveControl(t)
	f.halt(t)
	if err := f.finish(&logger{}); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(f.d.directory, "approved.jsonl")
	data, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(t.TempDir(), "approved.jsonl.1")
	other := bytes.ReplaceAll(data, []byte(`"session":"integration"`), []byte(`"session":"another"`))
	if bytes.Equal(data, other) {
		t.Fatal("wiring: generated lines lacked session identity")
	}
	if err := os.WriteFile(second, append(data, other...), 0600); err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := run([]string{"inspect", f.d.directory, "--text", "--file", first, "--file", second, "--session", "another"}, &rendered); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(rendered.String(), `"session": "another"`); n != 2 {
		t.Fatalf("selected %d exchange and retirement lines: %s", n, rendered.String())
	}
	if strings.Contains(rendered.String(), `"session": "integration"`) {
		t.Fatal("foreign approved session included")
	}
}
