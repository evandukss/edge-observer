//go:build attach

package attach_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/process"
)

// refusingDocument is the shipped no-rules example with its output in c's
// directory and its one watch entry naming the client, everything else as
// shipped.
func refusingDocument(t *testing.T, c configured, client conversation) map[string]any {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatalf("read the shipped no-rules example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the shipped no-rules example: %v", err)
	}
	entry := target("under-test", client.process)
	delete(entry, "descendants")
	entry["children"] = config.ChildrenAll
	document["output"] = c.directory
	document["watch"] = []any{entry}
	return document
}

func refusingWrite(t *testing.T, path string, document map[string]any) []byte {
	t.Helper()
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return content
}

// refusingWritten waits until the session's approved output holds the request
// for marker from pid, and returns how many times it holds it.
func refusingWritten(t *testing.T, directory string, pid int32, marker string) int {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(400 * time.Millisecond) {
		if found := len(sessionAsked(sessionMessages(t, directory), pid, marker)); found > 0 || time.Now().After(deadline) {
			return found
		}
	}
}

// refusingHolds is whether the pid file names exactly this process and session.
func refusingHolds(t *testing.T, c configured, pid int, session string) bool {
	t.Helper()
	content, err := os.ReadFile(c.pidFile())
	return err == nil && slices.Equal(strings.Fields(string(content)), []string{strconv.Itoa(pid), session})
}

// refusingAlive is whether pid is a process that has not exited: present, and
// neither a zombie nor dead.
func refusingAlive(pid int) bool {
	content, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	// The state follows the parenthesised command, which may hold spaces.
	_, after, found := strings.Cut(string(content), ") ")
	return found && after != "" && after[0] != 'Z' && after[0] != 'X'
}

// The shipped no-rules example, run in the foreground as it is written to be
// run, is restarted. The restart refuses before it stops anything, since a
// detached session has no standard output for its log, and the session goes
// on: the same process and session in the pid file, no second session, and a
// fresh exchange written beside the earlier one, which is still there once.
// Over the same session first, two more configurations a detached session
// would refuse are refused the same way: a key the format does not define,
// and an extension command that is not there, which processing compilation
// refuses.
func TestARestartRefusedForTheShippedNoRulesExampleLeavesTheSessionRunningAndWriting(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	root := t.TempDir()
	c := configured{path: filepath.Join(root, "observer.json"), directory: filepath.Join(root, "state")}
	shipped := refusingDocument(t, c, client)
	if shipped["log"] != "stdout" {
		t.Fatalf("wiring, not the property: the shipped no-rules example logs to %v, not stdout", shipped["log"])
	}
	refusingWrite(t, c.path, shipped)

	observer := started(t, binary, c)
	pid := observer.command.Process.Pid
	directory := observer.directory(c)
	sessionExchange(t, client, "before-restart", "")
	if refusingWritten(t, directory, client.process.PID, "before-restart") != 1 || !refusingHolds(t, c, pid, observer.session) {
		t.Fatalf("wiring, not the property: session %s (pid %d) did not write the exchange before the restart once, "+
			"or the pid file does not name it, so nothing below measures a session left running", observer.session, pid)
	}

	refused := func(name, path, reason string) {
		t.Helper()
		output, err := exec.Command(binary, "restart", path).CombinedOutput()
		var exited *exec.ExitError
		switch {
		case err == nil:
			t.Errorf("restart over %s exited zero:\n%s", name, output)
		case !errors.As(err, &exited):
			t.Fatalf("wiring, not the property: restart over %s did not run: %v", name, err)
		case !strings.Contains(string(output), "nothing was stopped") || !strings.Contains(string(output), reason):
			t.Errorf("restart over %s exited %d saying %q, want a refusal before the stop naming %q", name,
				exited.ExitCode(), output, reason)
		}
		if strings.Contains(string(output), "stopped    session") {
			t.Errorf("restart over %s says it stopped a session:\n%s", name, output)
		}
		if !refusingHolds(t, c, pid, observer.session) || !refusingAlive(pid) {
			t.Fatalf("after restart over %s the pid file does not name session %s at pid %d, or that process has "+
				"ended:\n%s", name, observer.session, pid, output)
		}
	}

	undefined := refusingDocument(t, c, client)
	undefined["log"] = filepath.Join(root, "observer.log")
	undefined["outptu"] = "/var/lib/observer"
	refusingWrite(t, filepath.Join(root, "undefined.json"), undefined)
	refused("a key the format does not define", filepath.Join(root, "undefined.json"), "outptu")

	missing := refusingDocument(t, c, client)
	missing["log"] = filepath.Join(root, "observer.log")
	missing["extensions"] = []any{map[string]any{"name": "inventory", "command": []string{"bin/inventory"},
		"fields": []string{config.FieldRequestLine}, "timeout_ms": 250}}
	refusingWrite(t, filepath.Join(root, "missing.json"), missing)
	refused("an extension command that is not there", filepath.Join(root, "missing.json"),
		string(config.CommandNotExecutable))

	refused("the shipped no-rules example", c.path, "stdout")

	if sessions := names(t, c.sessions()); !slices.Equal(sessions, []string{observer.session}) {
		t.Errorf("the refused restarts left sessions %v, want only %s", sessions, observer.session)
	}
	sessionExchange(t, client, "after-restart", "")
	if found := refusingWritten(t, directory, client.process.PID, "after-restart"); found != 1 {
		t.Errorf("session %s wrote the exchange sent after the refused restarts %d times, want once", observer.session, found)
	}
	if found := len(sessionAsked(sessionMessages(t, directory), client.process.PID, "before-restart")); found != 1 {
		t.Errorf("session %s's output holds the exchange written before the refused restarts %d times, want once",
			observer.session, found)
	}
	if sealed := ended(t, observer, c); sealed.Session != observer.session {
		t.Errorf("the session that sealed is %s, want %s", sealed.Session, observer.session)
	}
}

// refusingStartedOver is every process other than except started as "start <path>":
// a detached session over that configuration.
func refusingStartedOver(t *testing.T, path string, except int) []int32 {
	t.Helper()
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("read the process table: %v", err)
	}
	var found []int32
	for _, p := range table.All() {
		if int(p.PID) != except && len(p.Arguments) >= 3 && p.Arguments[1] == "start" && p.Arguments[2] == path {
			found = append(found, p.PID)
		}
	}
	return found
}

// A restart's configuration is changed after the restart checked it and
// before its replacement starts: the change sets the log to stdout, which a
// detached session refuses. The restart completes, and the replacement runs
// the configuration that was checked, by its revision.
//
// The change is made while the restart is inside its stop, with nothing left
// to chance: the test takes the pid file's lock the moment the first session
// releases it, so the restart, which starts nothing while the lock is held,
// waits until the change is written and the lock let go.
func TestARestartWhoseConfigurationChangesBeforeItsReplacementStartsRunsTheCheckedOne(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))
	envelope := sessionEnvelope(t)

	sessionDetached(t, binary, c, envelope, "start")
	firstPID, first := sessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(firstPID, syscall.SIGKILL) })
	checked, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(checked, &document); err != nil {
		t.Fatal(err)
	}
	document["log"] = "stdout"
	changed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	revision := func(content []byte) string {
		sum := sha256.Sum256(content)
		return "sha256:" + hex.EncodeToString(sum[:])
	}

	pidFile, err := os.Open(c.pidFile())
	if err != nil {
		t.Fatalf("open the pid file the first session holds: %v", err)
	}
	t.Cleanup(func() { _ = pidFile.Close() })
	taken := make(chan error, 1)
	go func() { taken <- syscall.Flock(int(pidFile.Fd()), syscall.LOCK_EX) }()

	var output bytes.Buffer
	restarting := exec.Command(binary, "restart", c.path)
	restarting.Stdout, restarting.Stderr = &output, &output
	restarting.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(envelope.Fd())}
	if err := restarting.Start(); err != nil {
		t.Fatalf("start the restart: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- restarting.Wait() }()

	select {
	case err := <-taken:
		if err != nil {
			t.Fatalf("wiring, not the property: the pid file's lock could not be taken: %v", err)
		}
	case err := <-exited:
		t.Fatalf("wiring, not the property: the restart ended (%v) before session %s released its pid file, so "+
			"nothing changed between its check and its start:\n%s", err, first, output.String())
	case <-time.After(60 * time.Second):
		t.Fatalf("wiring, not the property: session %s never released its pid file:\n%s", first, output.String())
	}
	if early := refusingStartedOver(t, c.path, firstPID); len(early) != 0 {
		t.Fatalf("wiring, not the property: replacements %v started before the lock was taken, so this run does "+
			"not change the configuration between the check and the start", early)
	}
	if err := os.WriteFile(c.path, changed, 0o600); err != nil {
		t.Fatalf("change the configuration: %v", err)
	}
	if err := syscall.Flock(int(pidFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("let the pid file go: %v", err)
	}

	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("the restart stopped session %s and then exited %v:\n%s", first, err, output.String())
		}
	case <-time.After(120 * time.Second):
		_ = restarting.Process.Kill()
		t.Fatalf("the restart did not end within 120s:\n%s", output.String())
	}
	secondPID, second := sessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(secondPID, syscall.SIGKILL) })
	if second == first {
		t.Fatalf("the restart left session %s in place:\n%s", first, output.String())
	}
	live := inspected(t, binary, c)
	if live.Session != second || live.Policy.Revision != revision(checked) {
		t.Errorf("session %s runs configuration %s, want the checked %s and not the changed %s", live.Session,
			live.Policy.Revision, revision(checked), revision(changed))
	}
	if out, err := exec.Command(binary, "stop", c.path).CombinedOutput(); err != nil {
		t.Fatalf("stop the replacement: %v\n%s", err, out)
	}
}
