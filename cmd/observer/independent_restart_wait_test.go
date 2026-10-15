package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/connection"
)

// This is a real process/lock/signal fixture, not an observer daemon. Terminal
// files in these tests are constructed separately to test the stop reader.
func TestRestartWaitOwnerProcess(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "restart-wait-owner" {
		return
	}
	mode, directory := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	stopping := make(chan os.Signal, 1)
	signal.Notify(stopping, syscall.SIGTERM)
	defer signal.Stop(stopping)
	held, err := acquire(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := held.record(os.Getpid(), "own-session"); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	<-stopping
	switch mode {
	case "held-empty":
		if err := held.file.Truncate(0); err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintln(os.Stdout, "signaled-held-empty")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	case "release":
		held.release()
		_, _ = fmt.Fprintln(os.Stdout, "signaled-released")
	default:
		t.Fatalf("unknown fixture mode %s", mode)
	}
	held.release()
	os.Exit(0)
}

type restartWaitOwner struct {
	cmd    *exec.Cmd
	events <-chan string
	done   <-chan struct{}
	stop   func()
}

func restartWaitOwnerStarted(t *testing.T, directory, mode string) *restartWaitOwner {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartWaitOwnerProcess$", "--", "restart-wait-owner", mode, directory)
	stdout, writing, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = stdout.Close()
		_ = writing.Close()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stdout = writing
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = writing.Close()
		_ = stdin.Close()
		t.Fatal(err)
	}
	_ = writing.Close()
	events := make(chan string, 4)
	go func() {
		defer close(events)
		scan := bufio.NewScanner(stdout)
		for scan.Scan() {
			events <- scan.Text()
		}
	}()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	stop := sync.OnceFunc(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("fixture cleanup: owner process did not exit")
		}
		_ = stdout.Close()
	})
	t.Cleanup(stop)
	o := &restartWaitOwner{cmd: cmd, events: events, done: done, stop: stop}
	o.await(t, "ready")
	pid, session, err := holder(directory)
	if err != nil || pid != cmd.Process.Pid || session != "own-session" {
		t.Fatalf("wiring: initial real holder = %d %q %v, want fixture pid %d", pid, session, err, cmd.Process.Pid)
	}
	return o
}

func (o *restartWaitOwner) await(t *testing.T, want string) {
	t.Helper()
	select {
	case event := <-o.events:
		if event != want {
			t.Fatalf("wiring: owner event %q, want %q", event, want)
		}
		t.Logf("real owner pid %d reached %s", o.cmd.Process.Pid, event)
	case <-time.After(3 * time.Second):
		t.Fatalf("wiring: owner did not reach %s", want)
	}
}

func restartWaitWrite(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func restartWaitProof(session string, at time.Time) (account.Account, shutdownReceipt) {
	a := account.Account{Version: account.Version, Kind: account.Sealed, Session: session,
		Seal: &connection.Seal{Sealed: at, Complete: true}}
	return a, shutdownReceipt{Session: session, Sealed: at, Outcome: shutdownComplete}
}

func TestStopWaitKeepsItsOriginalDeadlineForAnUnknownHolder(t *testing.T) {
	directory := t.TempDir()
	// Even an available success record cannot establish that this holder ended.
	a, receipt := restartWaitProof("own-session", time.Unix(1700000000, 123))
	restartWaitWrite(t, filepath.Join(directory, sessionsName, a.Session, sealedName), a)
	restartWaitWrite(t, filepath.Join(directory, sessionsName, a.Session, controlName, terminalName), receipt)
	o := restartWaitOwnerStarted(t, directory, "held-empty")
	ready := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(ready) })
	defer unblock()
	var calls, unknown atomic.Int64
	var first, last atomic.Int64
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		done <- stopInUsing(directory, io.Discard, func(path string) (int, string, error) {
			<-ready
			pid, session, err := holder(path)
			now := time.Now().UnixNano()
			if calls.Add(1) == 1 {
				first.Store(now)
			}
			last.Store(now)
			if err != nil && !errors.Is(err, errNotRunning) && strings.Contains(err.Error(), "has not activated yet") {
				unknown.Add(1)
			}
			return pid, session, err
		})
	}()
	o.await(t, "signaled-held-empty")
	file, err := os.Open(filepath.Join(directory, pidName))
	if err != nil {
		t.Fatal(err)
	}
	held, probeErr := probeHolder(file)
	var stat syscall.Stat_t
	statErr := syscall.Fstat(int(file.Fd()), &stat)
	_ = file.Close()
	content, readErr := os.ReadFile(filepath.Join(directory, pidName))
	if probeErr != nil || statErr != nil || readErr != nil || !held || len(content) != 0 {
		t.Fatalf("wiring: persistent holder not reached: held=%t bytes=%d probe=%v stat=%v read=%v", held, len(content), probeErr, statErr, readErr)
	}
	t.Logf("persistent prerequisite: real held=%t bytes=%d device=%d inode=%d owner_pid=%d", held, len(content), stat.Dev, stat.Ino, o.cmd.Process.Pid)
	unblock()
	select {
	case err := <-done:
		elapsed := time.Since(started)
		t.Logf("persistent real held-empty: calls=%d unknown=%d first=%d last=%d elapsed=%s result=%v", calls.Load(), unknown.Load(), first.Load(), last.Load(), elapsed, err)
		if err == nil || !strings.Contains(err.Error(), "did not end within 30s") || elapsed < 30*time.Second || calls.Load() < 2 || calls.Load() != unknown.Load() {
			t.Errorf("persistent unknown did not exhaust the original 30s stop allowance with nonzero timeout: %v after %s", err, elapsed)
		}
	case <-time.After(33 * time.Second):
		t.Errorf("stop exceeded the original 30s observation deadline while the real holder stayed unknown; calls=%d unknown=%d", calls.Load(), unknown.Load())
		o.stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("stop did not return after fixture cleanup")
		}
	}
}

func TestStopWaitRejectsInitialHolderAndSignalErrors(t *testing.T) {
	for _, which := range []string{"unknown holder", "signal ESRCH"} {
		t.Run(which, func(t *testing.T) {
			directory := t.TempDir()
			held, err := acquire(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer held.release()
			if which == "signal ESRCH" {
				content, err := os.ReadFile("/proc/sys/kernel/pid_max")
				if err != nil {
					t.Fatal(err)
				}
				maximum, err := strconv.Atoi(strings.TrimSpace(string(content)))
				if err != nil || maximum <= 0 || maximum >= 1<<30 {
					t.Fatalf("wiring: invalid kernel pid limit %q: %v", content, err)
				}
				// This positive PID cannot identify a process. Kill is still real;
				// the constructed owner record avoids racing PID reuse or exit.
				if err := held.record(maximum+1, "own-session"); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Kill(maximum+1, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatalf("wiring: impossible PID is not absent: %v", err)
				}
			}
			calls := 0
			started := time.Now()
			err = stopInUsing(directory, io.Discard, func(path string) (int, string, error) {
				calls++
				return holder(path)
			})
			elapsed := time.Since(started)
			if err == nil || calls != 0 || elapsed > time.Second {
				t.Fatalf("initial %s was not an immediate nonzero error before observation: err=%v calls=%d elapsed=%s", which, err, calls, elapsed)
			}
			if which == "unknown holder" && !strings.Contains(err.Error(), "has not activated yet") {
				t.Errorf("initial unknown-holder cause lost: %v", err)
			}
			if which == "signal ESRCH" && (!errors.Is(err, syscall.ESRCH) || !strings.Contains(err.Error(), "signal pid")) {
				t.Errorf("real signal error lost: %v", err)
			}
			t.Logf("initial %s: observations=%d elapsed=%s result=%v", which, calls, elapsed, err)
		})
	}
}

func TestStopWaitRequiresItsOwnTerminalProofDespiteForeignDiscovery(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		remove string
		change func(*account.Account, *shutdownReceipt)
	}{
		{name: "own complete control"},
		{name: "own account missing", want: "ended UNSEALED", remove: sealedName},
		{name: "own account belongs to foreign session", want: "account belongs to foreign-session", change: func(a *account.Account, _ *shutdownReceipt) { a.Session = "foreign-session" }},
		{name: "own receipt missing", want: "command publication outcome unavailable", remove: filepath.Join(controlName, terminalName)},
		{name: "receipt session mismatch", want: "command outcome does not match this seal", change: func(_ *account.Account, r *shutdownReceipt) { r.Session = "foreign-session" }},
		{name: "receipt seal mismatch", want: "command outcome does not match this seal", change: func(_ *account.Account, r *shutdownReceipt) { r.Sealed = r.Sealed.Add(time.Second) }},
		{name: "incomplete own seal despite complete receipt", want: "sealed INCOMPLETE", change: func(a *account.Account, _ *shutdownReceipt) {
			a.Seal.Complete = false
			a.Seal.Because = []string{"independent unfinished owner"}
		}},
		{name: "failed receipt outcome without error text", want: "publication failed", change: func(_ *account.Account, r *shutdownReceipt) { r.Outcome = shutdownPublicationFailed }},
		{name: "receipt error despite complete outcome", want: "independent publication error", change: func(_ *account.Account, r *shutdownReceipt) { r.Error = "independent publication error" }},
	}
	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			directory := t.TempDir()
			at := time.Unix(1700000000, 123)
			foreign, foreignReceipt := restartWaitProof("foreign-session", at.Add(time.Hour))
			foreignPath := filepath.Join(directory, sessionsName, foreign.Session, sealedName)
			restartWaitWrite(t, foreignPath, foreign)
			restartWaitWrite(t, filepath.Join(directory, sessionsName, foreign.Session, controlName, terminalName), foreignReceipt)
			restartWaitWrite(t, filepath.Join(directory, lastName), sealedSession{Session: foreign.Session, Sealed: foreign.Seal.Sealed, Account: foreignPath, Complete: true})
			last, err := lastSealed(directory)
			if err != nil || last.Session != foreign.Session || !last.Complete || stoppedSession(directory, foreign.Session, io.Discard) != nil {
				t.Fatalf("wiring: foreign discovery is not a valid successful distractor: %+v %v", last, err)
			}
			own, receipt := restartWaitProof("own-session", at)
			if one.change != nil {
				one.change(&own, &receipt)
			}
			ownDirectory := filepath.Join(directory, sessionsName, "own-session")
			restartWaitWrite(t, filepath.Join(ownDirectory, sealedName), own)
			restartWaitWrite(t, filepath.Join(ownDirectory, controlName, terminalName), receipt)
			if one.remove != "" {
				if err := os.Remove(filepath.Join(ownDirectory, one.remove)); err != nil {
					t.Fatal(err)
				}
			}
			o := restartWaitOwnerStarted(t, directory, "release")
			calls, absent := 0, false
			var output bytes.Buffer
			err = stopInUsing(directory, &output, func(path string) (int, string, error) {
				calls++
				if calls == 1 {
					o.await(t, "signaled-released")
				}
				pid, session, observed := holder(path)
				absent = errors.Is(observed, errNotRunning)
				return pid, session, observed
			})
			if calls == 0 || !absent {
				t.Fatalf("wiring: actual signaled owner absence not reached: calls=%d absent=%t", calls, absent)
			}
			if one.want == "" {
				if err != nil || !strings.Contains(output.String(), "stopped    session own-session,") || strings.Contains(output.String(), "foreign-session") {
					t.Errorf("valid own-session control was replaced by foreign discovery: %v, output=%q", err, output.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Errorf("own-session %s was not rejected despite valid foreign discovery: got %v, want %q", one.name, err, one.want)
			}
			t.Logf("terminal proof after real signal/absence: foreign=%s own=own-session observations=%d result=%v output=%q", last.Session, calls, err, output.String())
		})
	}
}
