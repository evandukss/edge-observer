package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// A second start is refused while a session holds the pid file, naming that
// session.
func TestASecondStartIsRefusedAndNamesTheSessionThatIsRunning(t *testing.T) {
	directory := t.TempDir()
	first, err := acquire(directory)
	if err != nil {
		t.Fatalf("the first start could not take the pid file: %v", err)
	}
	if first == nil {
		t.Fatal("the first start took no pid file")
	}
	if err := first.record(4242, "0123456789abcdef"); err != nil {
		t.Fatalf("record the running session: %v", err)
	}

	second, err := acquire(directory)
	if err == nil || second != nil {
		t.Fatal("a second start took the pid file while the first held it")
	}
	if !errors.Is(err, errAlreadyRunning) || !strings.Contains(err.Error(), "4242") ||
		!strings.Contains(err.Error(), "0123456789abcdef") {
		t.Errorf("the second start was refused with %q, want the running pid and session named", err)
	}

	// The control: once the first releases it, a start takes it.
	first.release()
	third, err := acquire(directory)
	if err != nil || third == nil {
		t.Fatalf("a start after the first released the pid file was refused: %v", err)
	}
	third.release()
}

// A running session answers through a request file in its directory and
// SIGUSR1; nothing listens.
func TestARequestIsAnsweredByTheRunningSessionWithoutAnythingListening(t *testing.T) {
	directory := t.TempDir()
	held, err := acquire(directory)
	if err != nil || held == nil {
		t.Fatalf("take the pid file: %v", err)
	}
	defer held.release()
	if err := held.record(os.Getpid(), "feedfacefeedface"); err != nil {
		t.Fatalf("record the session: %v", err)
	}

	type asked struct {
		kind string
		body []byte
	}
	answered := make(chan asked, 1)
	serving := &controller{directory: directory, answer: func(kind string, body []byte) ([]byte, error) {
		answered <- asked{kind, body}
		return []byte(`{"kind":"live","session":"feedfacefeedface"}`), nil
	}}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	defer signal.Stop(signals)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range signals {
			if serving.serve() > 0 {
				return
			}
		}
	}()

	// The body holds a line break of its own, which must survive.
	sent := []byte("{\"read\":\"first\"}\n{\"read\":\"second\"}")
	got, err := ask(directory, "inspect", sent, 5*time.Second)
	if err != nil {
		t.Fatalf("ask the running session: %v", err)
	}
	if string(got) != `{"kind":"live","session":"feedfacefeedface"}` {
		t.Errorf("the answer is %q", got)
	}
	select {
	case request := <-answered:
		if request.kind != "inspect" {
			t.Errorf("the session was asked %q, want inspect", request.kind)
		}
		if string(request.body) != string(sent) {
			t.Errorf("the session was handed the body %q, want %q whole", request.body, sent)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session was never asked")
	}
	signal.Stop(signals)
	close(signals)
	<-done

	leftover, err := os.ReadDir(filepath.Join(directory, "control"))
	if err != nil {
		t.Fatalf("read the control directory: %v", err)
	}
	if len(leftover) != 0 {
		t.Errorf("the exchange left %d files behind in the control directory", len(leftover))
	}
}

// Asking where nothing is running is refused rather than waited on.
func TestAskingWhereNoSessionIsRunningIsRefused(t *testing.T) {
	if _, err := ask(t.TempDir(), "inspect", nil, time.Second); err == nil {
		t.Fatal("a request to a directory no session holds was answered")
	}
}

// The log is the configured file, plus standard output in the foreground, or
// standard output alone where configured - refused for a detached process.
func TestTheLogIsTheConfiguredFileAndStandardOutputOnlyWhereSaid(t *testing.T) {
	file := filepath.Join(t.TempDir(), "observer.log")
	record := map[string]any{"record": "state", "version": 1}

	for _, one := range []struct {
		name       string
		log        string
		foreground bool
		inFile     bool
		onStdout   bool
		refused    bool
	}{
		{"a file, in the foreground", file, true, true, true, false},
		{"a file, daemonised", file, false, true, false, false},
		{"stdout, in the foreground", policy.Stdout, true, false, true, false},
		{"stdout, daemonised", policy.Stdout, false, false, false, true},
	} {
		t.Run(one.name, func(t *testing.T) {
			_ = os.Remove(file)
			var stdout bytes.Buffer
			log, err := openLog(policy.Settings{Log: one.log}, one.foreground, &stdout)
			if one.refused {
				if err == nil {
					t.Fatal("a detached observer was allowed to log to standard output")
				}
				return
			}
			if err != nil {
				t.Fatalf("open the log: %v", err)
			}
			if err := log.write(record); err != nil {
				t.Fatalf("write a record: %v", err)
			}
			if err := log.close(); err != nil {
				t.Fatalf("close the log: %v", err)
			}
			content, _ := os.ReadFile(file)
			if got := strings.Contains(string(content), `"record":"state"`); got != one.inFile {
				t.Errorf("the record is in the file: %v, want %v", got, one.inFile)
			}
			if got := strings.Contains(stdout.String(), `"record":"state"`); got != one.onStdout {
				t.Errorf("the record is on standard output: %v, want %v", got, one.onStdout)
			}
		})
	}
}

// The activation record states the observer's state: session, policy and
// generation, what was asked against what it has, and per-target coverage.
// No bare word, and no process's arguments.
func TestTheActivationRecordSaysWhatStateTheObserverIsIn(t *testing.T) {
	namespace := admission.Namespace{Device: 4, Inode: 4026531836}
	table := process.TableOf(process.Process{PID: 10, PPID: 1, StartTime: 91, Executable: "/usr/bin/interpreter",
		Arguments: []string{"interpreter", "--token=s3cret"}, Namespace: namespace, NamespacePID: 10})
	approval := process.Approval{Rules: []process.Rule{
		{Name: "gateway", Executable: "/usr/bin/interpreter", Arguments: []string{"--token=s3cret"}, Mode: admission.ModeNone},
		{Name: "front", Port: 8443, Mode: admission.ModeNone},
	}}
	build := probe.Capability{Backend: probe.BPF, Program: "full", Payload: true, SocketEvidence: true}
	at := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	live := account.Plan(at, account.Policy{Revision: "sha256:abc", Generation: 1},
		approval.Resolve(process.Host{Table: table}), build, nil)
	live.Attached(account.Live, "0123456789abcdef", []attachment.Observed{{PID: 10, Requested: 9, Confirmed: 9,
		Outcome: attachment.Attached}}, probe.Capability{Backend: probe.BPF, Program: "full", Payload: true})

	content, err := json.Marshal(activated("0123456789abcdef", 4242, at, live))
	if err != nil {
		t.Fatalf("encode the activation record: %v", err)
	}
	var read map[string]any
	if err := json.Unmarshal(content, &read); err != nil {
		t.Fatalf("decode the activation record: %v", err)
	}

	if read["record"] != "activation-completed" || read["version"] != float64(1) ||
		read["session"] != "0123456789abcdef" || read["pid"] != float64(4242) {
		t.Errorf("the record opens %v", read)
	}
	policyRead, _ := read["policy"].(map[string]any)
	if policyRead["revision"] != "sha256:abc" || policyRead["generation"] != float64(1) {
		t.Errorf("the record names policy %v", policyRead)
	}
	features, _ := read["features"].(map[string]any)
	requested, _ := features["requested"].(map[string]any)
	available, _ := features["available"].(map[string]any)
	if requested["socket_evidence"] != true || available["socket_evidence"] != false {
		t.Errorf("features requested %v against available %v, want socket evidence asked for and not held",
			requested, available)
	}
	coverage, _ := read["coverage"].([]any)
	if len(coverage) != 2 {
		t.Fatalf("the record carries coverage for %d targets, want 2: %s", len(coverage), content)
	}
	gateway, _ := coverage[0].(map[string]any)
	front, _ := coverage[1].(map[string]any)
	if gateway["name"] != "gateway" || gateway["selected"] != float64(1) || gateway["attached"] != float64(1) {
		t.Errorf("the first target's coverage is %v, want one selected and one attached", gateway)
	}
	if front["name"] != "front" || front["selected"] != float64(0) || front["unresolved"] == "" {
		t.Errorf("the unresolved target's coverage is %v, want nothing selected and the reason", front)
	}
	if strings.Contains(string(content), "s3cret") {
		t.Error("the activation record carries a process's argument")
	}
	if strings.TrimSpace(string(content)) == "ready" || !strings.HasPrefix(string(content), `{"record":"activation-completed"`) {
		t.Errorf("the record is %s", content)
	}
	_ = strconv.Itoa
}
