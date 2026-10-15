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

	"github.com/evandukss/edge-observer/account"
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

type restartWaitEvent struct {
	Kind       string `json:"kind"`
	At         int64  `json:"at"`
	Directory  string `json:"directory"`
	Checked    string `json:"checked"`
	Held       bool   `json:"held"`
	Bytes      int    `json:"bytes"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	PID        int    `json:"pid"`
	Session    string `json:"session"`
	Error      string `json:"error"`
	NotRunning bool   `json:"not_running"`
}

// restartWaitBuilt changes scheduling at the accepted stop-loop seam only.
// The old session still uses the shipped binary; the restart and its eventual
// replacement run the command through the test executable's private driver.
func restartWaitBuilt(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "observer-restart-wait")
	command := exec.Command("go", "test", "-c", "-o", binary, "github.com/evandukss/edge-observer/cmd/observer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the restart wait driver: %v\n%s", err, output)
	}
	return binary
}

// A restart's configuration is changed after the restart checked it and
// before its replacement starts: the change sets the log to stdout, which a
// detached session refuses. The restart completes, and the replacement runs
// the configuration that was checked, by its revision.
//
// A pipe handshake stops the first post-signal poll until the fixture holds
// the old session's emptied pidfile. The poll records the real holder error,
// then returns that same observation after the configuration changes and the
// fixture unlocks. Merely dwelling on the lock would not prove a poll saw it.
func TestARestartWhoseConfigurationChangesBeforeItsReplacementStartsRunsTheCheckedOne(t *testing.T) {
	binary := built(t)
	driver := restartWaitBuilt(t)
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

	eventRead, eventWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	commandRead, commandWrite, err := os.Pipe()
	if err != nil {
		_ = eventRead.Close()
		_ = eventWrite.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, file := range []*os.File{eventRead, eventWrite, commandRead, commandWrite} {
			_ = file.Close()
		}
	})
	type received struct {
		event restartWaitEvent
		err   error
	}
	events := make(chan received, 4)
	go func() {
		decoder := json.NewDecoder(eventRead)
		for range 3 {
			var event restartWaitEvent
			err := decoder.Decode(&event)
			events <- received{event, err}
			if err != nil {
				return
			}
		}
	}()
	next := func(kind string) restartWaitEvent {
		t.Helper()
		select {
		case got := <-events:
			if got.err != nil || got.event.Kind != kind || got.event.At == 0 {
				t.Fatalf("wiring: restart wait event %+v (%v), want %s", got.event, got.err, kind)
			}
			t.Logf("restart wait witness %+v", got.event)
			return got.event
		case <-time.After(60 * time.Second):
			t.Fatalf("wiring: restart did not reach %s", kind)
			return restartWaitEvent{}
		}
	}
	send := func(command string) {
		t.Helper()
		if err := json.NewEncoder(commandWrite).Encode(command); err != nil {
			t.Fatalf("send restart wait command %s: %v", command, err)
		}
	}
	var output bytes.Buffer
	restarting := exec.Command(driver, "restart", c.path)
	restarting.Env = append(os.Environ(), "OBSERVER_RESTART_WAIT_DRIVER=1")
	restarting.ExtraFiles = []*os.File{eventWrite, commandRead}
	restarting.Stdout, restarting.Stderr = &output, &output
	restarting.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(envelope.Fd())}
	if err := restarting.Start(); err != nil {
		t.Fatalf("start the restart: %v", err)
	}
	_ = eventWrite.Close()
	_ = commandRead.Close()
	finished := make(chan struct{})
	var restartErr error
	go func() {
		restartErr = restarting.Wait()
		close(finished)
	}()
	t.Cleanup(func() {
		_ = restarting.Process.Kill()
		<-finished
	})
	entered := next("poll-entered")
	if entered.Directory != c.directory || entered.Checked != revision(checked) {
		t.Fatalf("wiring: post-signal poll used directory/configuration %+v, want %s %s", entered, c.directory, revision(checked))
	}

	select {
	case err := <-taken:
		if err != nil {
			t.Fatalf("wiring, not the property: the pid file's lock could not be taken: %v", err)
		}
	case <-finished:
		t.Fatalf("wiring, not the property: the restart ended (%v) before session %s released its pid file, so "+
			"nothing changed between its check and its start:\n%s", restartErr, first, output.String())
	case <-time.After(60 * time.Second):
		t.Fatalf("wiring, not the property: session %s never released its pid file", first)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(pidFile.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(c.pidFile())
	if err != nil || len(content) != 0 {
		t.Fatalf("wiring: acquired pidfile is not empty: %q, %v", content, err)
	}
	if early := refusingStartedOver(t, c.path, firstPID); len(early) != 0 {
		t.Fatalf("wiring, not the property: replacements %v started before the lock was taken, so this run does "+
			"not change the configuration between the check and the start", early)
	}
	send("observe")
	observed := next("held-empty")
	wantError := "a session holds " + c.pidFile() + " and has not activated yet, so it answers nothing"
	if !observed.Held || observed.Bytes != 0 || observed.Device != uint64(stat.Dev) || observed.Inode != stat.Ino ||
		observed.PID != 0 || observed.Session != "" || observed.NotRunning || observed.Error != wantError || observed.At < entered.At {
		t.Fatalf("wiring: the stop did not observe the same held-empty pidfile: %+v", observed)
	}
	// This is a successful old-session stop, not a terminal failure that a
	// restart should conceal. Its own public seal and receipt establish that.
	sealed := liveSealed(t, filepath.Join(c.sessions(), first), first)
	if sealed.Version != account.Version || sealed.Seal == nil || !sealed.Seal.Complete || sealed.Seal.Sealed.IsZero() || sealed.SealError != "" {
		t.Fatalf("wiring: old session has no complete seal: %+v", sealed)
	}
	receiptBytes, err := os.ReadFile(filepath.Join(c.sessions(), first, "control", "stop-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Session string    `json:"session"`
		Sealed  time.Time `json:"sealed"`
		Outcome string    `json:"outcome"`
		Error   string    `json:"error"`
	}
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Session != first || !receipt.Sealed.Equal(sealed.Seal.Sealed) || receipt.Outcome != "complete" || receipt.Error != "" {
		t.Fatalf("wiring: old-session terminal result does not prove successful stop: %+v", receipt)
	}
	t.Logf("restart old-session terminal witness %+v", receipt)
	if err := os.WriteFile(c.path, changed, 0o600); err != nil {
		t.Fatalf("change the configuration: %v", err)
	}
	if err := syscall.Flock(int(pidFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("let the pid file go: %v", err)
	}
	t.Logf("restart fixture released inode %d at %d after configuration changed", stat.Ino, time.Now().UnixNano())
	send("released")
	returned := next("returning-observation")
	if returned.Error != observed.Error || returned.At < observed.At {
		t.Fatalf("wiring: real holder observation changed before return: observed %+v returned %+v", observed, returned)
	}
	if elapsed := time.Duration(returned.At - entered.At); elapsed >= 25*time.Second {
		t.Fatalf("wiring: the handshake took %s, leaving insufficient margin inside the original 30s stop budget", elapsed)
	}

	select {
	case <-finished:
		if restartErr != nil {
			t.Fatalf("the restart rejected the witnessed transient held-empty observation after release; stopped session %s, exit %v:\n%s", first, restartErr, output.String())
		}
	case <-time.After(120 * time.Second):
		_ = restarting.Process.Kill()
		<-finished
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
