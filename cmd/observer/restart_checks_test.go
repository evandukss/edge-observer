package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// restartWitness replaces the steps of a restart that act on a session and
// records what each was asked, in order. Its holder reports a session running
// unless told otherwise.
type restartWitness struct {
	notRunning bool
	holderErr  error
	steps      []string
	stopped    []checked
	launched   []checked
	// duringStop runs inside the stop, after the check and before the launch.
	duringStop func()
}

func (w *restartWitness) over(r restarter) restarter {
	r.holder = func(string) (int, string, error) {
		w.steps = append(w.steps, "holder")
		switch {
		case w.holderErr != nil:
			return 0, "", w.holderErr
		case w.notRunning:
			return 0, "", errNotRunning
		}
		return 4242, "feedfacefeedface", nil
	}
	r.stop = func(c checked, _ io.Writer) error {
		w.steps = append(w.steps, "stop")
		w.stopped = append(w.stopped, c)
		if w.duringStop != nil {
			w.duringStop()
		}
		return nil
	}
	r.launch = func(c checked, _ io.Writer) error {
		w.steps = append(w.steps, "launch")
		w.launched = append(w.launched, c)
		return nil
	}
	return r
}

// witnessNoRules is the shipped no-rules example with its output in a fresh
// directory, as a document to change and write.
func witnessNoRules(t *testing.T) map[string]any {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatalf("read the shipped no-rules example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the shipped no-rules example: %v", err)
	}
	document["output"] = t.TempDir()
	return document
}

func witnessRevision(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// A restart over a configuration a detached session would refuse refuses
// before it stops anything, naming why: the shipped no-rules example, whose
// log is stdout; a key the format does not define; and an extension command
// that is not there, which processing compilation refuses. The control is the
// same configuration with its log in a file, which is stopped and launched.
func TestARestartRefusedForItsConfigurationStopsNothing(t *testing.T) {
	control := witnessNoRules(t)
	control["log"] = filepath.Join(t.TempDir(), "observer.log")
	controlPath := rewrite(t, filepath.Join(t.TempDir(), "observer.json"), control)
	witness := &restartWitness{}
	if err := witness.over(restarting).restart(controlPath, io.Discard); err != nil {
		t.Fatalf("wiring, not the property: the control configuration was refused (%v), so no case below "+
			"is told apart from a restart that refuses everything", err)
	}
	if !slices.Equal(witness.steps, []string{"holder", "stop", "launch"}) || len(witness.launched) != 1 ||
		witness.launched[0].read.Settings.Directory != control["output"] {
		t.Fatalf("wiring, not the property: the control restart took steps %v and launched %d sessions, want it "+
			"to find the session, stop it and launch one over %v", witness.steps, len(witness.launched), control["output"])
	}

	cases := []struct {
		name   string
		change func(t *testing.T, document map[string]any) map[string]any
		reason string
	}{
		{"the shipped no-rules example", func(t *testing.T, document map[string]any) map[string]any {
			if document["log"] != "stdout" {
				t.Fatalf("wiring, not the property: the shipped no-rules example logs to %v, not stdout", document["log"])
			}
			return document
		}, "stdout"},
		{"a key the format does not define", func(t *testing.T, document map[string]any) map[string]any {
			document["log"] = filepath.Join(t.TempDir(), "observer.log")
			document["outptu"] = "/var/lib/observer"
			return document
		}, "outptu"},
		{"an extension command processing compilation refuses", func(t *testing.T, document map[string]any) map[string]any {
			document["log"] = filepath.Join(t.TempDir(), "observer.log")
			document["extensions"] = []any{map[string]any{"name": "inventory", "command": []string{"bin/inventory"},
				"fields": []string{config.FieldRequestLine}, "timeout_ms": 250}}
			return document
		}, string(config.CommandNotExecutable)},
	}
	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			path := rewrite(t, filepath.Join(t.TempDir(), "observer.json"), one.change(t, witnessNoRules(t)))
			witness := &restartWitness{}
			err := witness.over(restarting).restart(path, io.Discard)
			var refused *restartRefused
			switch {
			case err == nil:
				t.Fatalf("the restart was not refused: it took steps %v", witness.steps)
			case !errors.As(err, &refused):
				t.Errorf("the restart answered %q, which is not a refusal before the stop", err)
			case !strings.Contains(err.Error(), one.reason):
				t.Errorf("the refusal %q does not name %q", err, one.reason)
			}
			if slices.Contains(witness.steps, "stop") || slices.Contains(witness.steps, "launch") {
				t.Errorf("the restart took steps %v before it refused with %v: it stopped the running session",
					witness.steps, err)
			}
		})
	}
}

// Asked whether a session runs, an answer that is neither a session nor "not
// running" refuses the restart before the stop.
func TestARestartThatCannotTellWhetherASessionRunsStopsNothing(t *testing.T) {
	document := witnessNoRules(t)
	document["log"] = filepath.Join(t.TempDir(), "observer.log")
	path := rewrite(t, filepath.Join(t.TempDir(), "observer.json"), document)

	unclear := errors.New("a session holds the pid file and has not activated yet")
	witness := &restartWitness{holderErr: unclear}
	err := witness.over(restarting).restart(path, io.Discard)
	var refused *restartRefused
	if !errors.As(err, &refused) || !errors.Is(err, unclear) {
		t.Errorf("the restart answered %v, want a refusal carrying %q", err, unclear)
	}
	if !slices.Equal(witness.steps, []string{"holder"}) {
		t.Errorf("the restart took steps %v, want only the question whether a session runs", witness.steps)
	}
}

// The file changed after the check, while the running session was being
// stopped, reaches neither the stop nor the replacement: both are handed the
// bytes that were checked, and nothing refuses after the stop.
func TestARestartActsOnTheBytesItCheckedWhenTheFileChangesDuringTheStop(t *testing.T) {
	document := witnessNoRules(t)
	document["log"] = filepath.Join(t.TempDir(), "observer.log")
	path := rewrite(t, filepath.Join(t.TempDir(), "observer.json"), document)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	changed := witnessNoRules(t)
	witness := &restartWitness{duringStop: func() { rewrite(t, path, changed) }}
	err = witness.over(restarting).restart(path, io.Discard)

	after, readErr := os.ReadFile(path)
	if readErr != nil || witnessRevision(after) == witnessRevision(before) || !slices.Contains(witness.steps, "stop") {
		t.Fatalf("wiring, not the property: the file holds %s after the stop, against %s checked (%v), and the "+
			"restart took steps %v, so nothing changed between the check and the launch", witnessRevision(after),
			witnessRevision(before), readErr, witness.steps)
	}
	if err != nil {
		t.Fatalf("the restart stopped the session and then answered %v", err)
	}
	if len(witness.stopped) != 1 || len(witness.launched) != 1 {
		t.Fatalf("the restart stopped %d sessions and launched %d, want one of each", len(witness.stopped),
			len(witness.launched))
	}
	for step, c := range map[string]checked{"stop": witness.stopped[0], "launch": witness.launched[0]} {
		if string(c.content) != string(before) || c.read.Revision != witnessRevision(before) ||
			c.read.Settings.Log == policy.Stdout {
			t.Errorf("the %s was handed configuration %s, logging to %s, want the checked %s", step, c.read.Revision,
				c.read.Settings.Log, witnessRevision(before))
		}
	}
}

// The stop a restart takes finds the session by the checked configuration and
// never reads the file again: with the file gone after the check and no
// session running, it answers that none runs over the checked directory.
func TestARestartStopsBySessionDirectoryWithoutReadingTheFileAgain(t *testing.T) {
	document := witnessNoRules(t)
	document["log"] = filepath.Join(t.TempDir(), "observer.log")
	path := rewrite(t, filepath.Join(t.TempDir(), "observer.json"), document)
	c, err := restarting.check(path)
	if err != nil || c.read.Settings.Directory != document["output"] {
		t.Fatalf("wiring, not the property: the check answered %v over %q, want the configuration's %v", err,
			c.read.Settings.Directory, document["output"])
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	err = restarting.stop(c, io.Discard)
	if !errors.Is(err, errNotRunning) || !strings.Contains(err.Error(), filepath.Join(c.read.Settings.Directory, pidName)) {
		t.Errorf("the stop answered %v, want that no session runs over %s: a stop that answers about the file "+
			"read it again", err, c.read.Settings.Directory)
	}
}

// witnessStandIn writes a program that stands in for a detached session's
// first steps: it writes the descriptor its environment names and its
// arguments to WITNESS_ARGUMENTS, copies descriptor 4 to WITNESS_HANDED, and
// reports activation on descriptor 3. One that does not read reports
// activation at once and goes on running for a minute with descriptor 4 open
// and unread, as a session that ignored it would.
func witnessStandIn(t *testing.T, reads bool) (program, handed, arguments string) {
	t.Helper()
	root := t.TempDir()
	handed, arguments = filepath.Join(root, "handed"), filepath.Join(root, "arguments")
	t.Setenv("WITNESS_HANDED", handed)
	t.Setenv("WITNESS_ARGUMENTS", arguments)
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$" + configurationName + "\" \"$@\" > \"$WITNESS_ARGUMENTS\"\n" +
		"cat <&4 > \"$WITNESS_HANDED\"\n" +
		"echo 'activated stand-in' >&3\n"
	if !reads {
		script = "#!/bin/sh\necho 'activated stand-in' >&3\nexec 3>&-\nexec sleep 60\n"
	}
	program = filepath.Join(root, "observer")
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return program, handed, arguments
}

// witnessLarge is more checked bytes than a pipe holds at once, so a hand-over
// written in full before the child's report is awaited waits on a child that
// does not read.
func witnessLarge() []byte {
	return bytes.Repeat([]byte("checked\n"), 32*1024)
}

// The launch a restart takes starts its child as "start <path>" and hands it
// exactly the checked bytes on the descriptor its environment names, whatever
// the file at the path holds.
func TestALaunchHandsItsChildExactlyTheCheckedBytes(t *testing.T) {
	program, handed, arguments := witnessStandIn(t, true)
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(`{"version": "the file, not what was checked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checked{path: path, content: witnessLarge(), executable: program,
		read: policy.Policy{Settings: policy.Settings{Log: "/var/log/observer.log"}}}

	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- restarting.launch(c, &out) }()
	select {
	case err := <-done:
		if err != nil || !strings.HasPrefix(out.String(), "started    session stand-in, pid ") {
			t.Fatalf("wiring, not the property: the launch answered %v and said %q, so the stand-in did not run "+
				"as the child", err, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the launch did not return within 30s of handing over %d bytes", len(c.content))
	}

	got, err := os.ReadFile(handed)
	if err != nil || !bytes.Equal(got, c.content) {
		t.Errorf("the child was handed %d bytes (%v), want exactly the %d checked", len(got), err, len(c.content))
	}
	said, err := os.ReadFile(arguments)
	if want := "4\nstart\n" + path + "\n"; err != nil || string(said) != want {
		t.Errorf("the child was started with %q (%v), want %q", said, err, want)
	}
}

// A child that activates without reading what it was handed, and goes on
// running with it unread, does not hold the launch: the launch returns once
// the child has reported.
func TestALaunchIsNotHeldByAChildThatNeverReadsItsConfiguration(t *testing.T) {
	program, _, _ := witnessStandIn(t, false)
	c := checked{path: filepath.Join(t.TempDir(), "observer.json"), content: witnessLarge(), executable: program,
		read: policy.Policy{Settings: policy.Settings{Log: "/var/log/observer.log"}}}

	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- restarting.launch(c, &out) }()
	select {
	case err := <-done:
		if found := regexp.MustCompile(`, pid ([0-9]+),`).FindStringSubmatch(out.String()); found != nil {
			pid, _ := strconv.Atoi(found[1])
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
		}
		if err != nil || !strings.HasPrefix(out.String(), "started    session stand-in, pid ") {
			t.Errorf("the launch answered %v and said %q, want the stand-in started", err, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the launch did not return within 30s of a child that reported and left %d bytes unread",
			len(c.content))
	}
}

// A detached session compiles the bytes it was handed and never the file at
// its path; in the foreground, with nothing handed, it compiles the file.
// What it reads is bounded: one byte past the configuration bound is refused
// as too large without the rest being read.
func TestADetachedSessionCompilesTheBytesItWasHanded(t *testing.T) {
	handedDocument := witnessNoRules(t)
	handedDocument["log"] = filepath.Join(t.TempDir(), "observer.log")
	handedBytes, err := json.Marshal(handedDocument)
	if err != nil {
		t.Fatal(err)
	}
	path := rewrite(t, filepath.Join(t.TempDir(), "observer.json"), witnessNoRules(t))
	onDisk, err := os.ReadFile(path)
	if err != nil || witnessRevision(onDisk) == witnessRevision(handedBytes) {
		t.Fatalf("wiring, not the property: the file holds %s (%v), the same as what is handed over",
			witnessRevision(onDisk), err)
	}
	// hand writes content into a pipe and says how much of it was taken before
	// the reading end was closed.
	hand := func(content []byte) (*os.File, <-chan int) {
		t.Helper()
		reading, writing, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		taken := make(chan int, 1)
		go func() {
			n, _ := writing.Write(content)
			_ = writing.Close()
			taken <- n
		}()
		return reading, taken
	}

	handed, _ := hand(handedBytes)
	read, err := configurationFor(path, handed)
	if err != nil || read.Revision != witnessRevision(handedBytes) || read.Settings.Log == policy.Stdout {
		t.Errorf("the detached session compiled %s logging to %s (%v), want the handed %s", read.Revision,
			read.Settings.Log, err, witnessRevision(handedBytes))
	}
	foreground, err := configurationFor(path, nil)
	if err != nil || foreground.Revision != witnessRevision(onDisk) {
		t.Errorf("the foreground compiled %s (%v), want the file's %s", foreground.Revision, err, witnessRevision(onDisk))
	}

	// Past the bound by more than a pipe holds, so a reader that stops one byte
	// past the bound leaves the writer short whatever the scheduling.
	oversized := bytes.Repeat([]byte(" "), config.MaxProcessingBytes+1024*1024)
	handed, taken := hand(oversized)
	_, err = configurationFor(path, handed)
	var refused *policy.Refused
	if !errors.As(err, &refused) || len(refused.Findings) != 1 || refused.Findings[0].Reason != config.ConfigurationTooLarge {
		t.Errorf("%d handed bytes were answered %v, want refused as too large", len(oversized), err)
	}
	select {
	case n := <-taken:
		if n == len(oversized) {
			t.Errorf("all %d handed bytes were read, want reading to stop one byte past the bound of %d", n,
				config.MaxProcessingBytes)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the hand-over's writer was still writing 30s after the session stopped reading")
	}
}
