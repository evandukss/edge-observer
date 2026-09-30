//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/activation"
)

// t18Launched is one `observer start` created into a chosen cgroup, its
// standard output read as it comes.
type t18Launched struct {
	command *exec.Cmd
	lines   chan string
	stderr  *bytes.Buffer
	done    chan error
}

func t18Launch(t *testing.T, binary, envelope string, arguments ...string) *t18Launched {
	t.Helper()
	command := exec.Command(binary, arguments...)
	t18Into(t, command, envelope)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	l := &t18Launched{command: command, lines: make(chan string, 4096), stderr: &bytes.Buffer{}, done: make(chan error, 1)}
	command.Stderr = l.stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the observer: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	go func() {
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			select {
			case l.lines <- scanner.Text():
			default:
			}
		}
		close(l.lines)
		l.done <- command.Wait()
	}()
	return l
}

// activation waits for the activation record, or for the observer to end
// without one.
func (l *t18Launched) activation(t *testing.T, within time.Duration) (map[string]json.RawMessage, bool) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case line, open := <-l.lines:
			if !open {
				return nil, false
			}
			var record map[string]json.RawMessage
			if json.Unmarshal([]byte(line), &record) == nil && string(record["record"]) == `"activation-completed"` {
				return record, true
			}
		case <-deadline:
			t.Fatalf("the observer neither activated nor ended in %s:\n%s", within, l.stderr)
		}
	}
}

func (l *t18Launched) exit(t *testing.T, within time.Duration) error {
	t.Helper()
	for range l.lines {
	}
	select {
	case err := <-l.done:
		return err
	case <-time.After(within):
		t.Fatalf("the observer did not end in %s:\n%s", within, l.stderr)
		return nil
	}
}

// t18LogRecords is every record of this kind in the log file.
func t18LogRecords(t *testing.T, log, kind string) []map[string]any {
	t.Helper()
	content, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read the log %s: %v", log, err)
	}
	var found []map[string]any
	for _, line := range strings.Split(string(content), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil && record["record"] == kind {
			found = append(found, record)
		}
	}
	return found
}

var t18Refusal = regexp.MustCompile(`activation refused: ([a-z_]+) \(payload pid ([0-9]+)\)`)

// Row 2 at the public command. `observer start` refuses to activate when the
// posture that makes "never written down" true is absent in the process that
// would hold payload: it names the check and that process, exits non-zero, and
// leaves no activation, no session and no approved output behind - rather than
// running with a weaker promise over output it then writes. The neighbour is
// the same configuration in an envelope that is right, which activates, reports
// the posture it read in itself, and writes the exchange with the credential
// removed.
//
// Detached, the payload holder is the child the start leaves running, so the
// refusal must name that child and not the process that was launched.
//
// Core dumps are not a case here: start makes the holder non-dumpable itself
// before it verifies, so no launch can supply the fault. TestP3T9ActivationLive
// sets it in a holder the fixture owns and proves the refusal there.
func TestT18AStartWithoutItsPostureRefusesByNameAndWritesNothing(t *testing.T) {
	binary := built(t)
	port := t18Serving(t)
	const secret = "Bearer t18-posture-secret"
	right := map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"}
	for _, tc := range []struct {
		name     string
		check    string
		envelope map[string]string
		inside   bool
		detached bool
	}{
		{"a bounded no-swap envelope", "", right, false, false},
		{"swap permitted", "anonymous_swap", map[string]string{"memory.max": "1073741824", "memory.swap.max": "4096"}, false, false},
		{"swap permitted, detached", "anonymous_swap", map[string]string{"memory.max": "1073741824", "memory.swap.max": "4096"}, false, true},
		{"no memory cap", "execution_memory", map[string]string{"memory.max": "max", "memory.swap.max": "0"}, false, false},
		{"the participant inside the envelope", "participant_outside_envelope", right, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := speaking(t, port)
			c := configuring(t, target("client", client.process))
			t18Edit(t, c, t18Removing)
			envelope := t18Envelope(t, tc.envelope)
			if tc.inside {
				moveInto(t, envelope, client.process.PID)
			}
			arguments := []string{"start", c.path}
			if tc.detached {
				arguments = append(arguments, "--daemonize")
			}
			launched := t18Launch(t, binary, envelope, arguments...)

			if tc.check == "" {
				record, activated := launched.activation(t, 30*time.Second)
				if !activated {
					t.Fatalf("wiring, not the property: the neighbour in a right envelope did not activate:\n%s", launched.stderr)
				}
				var posture activation.Posture
				if err := json.Unmarshal(record["payload_posture"], &posture); err != nil {
					t.Fatalf("the activation record carries no posture: %v", err)
				}
				if posture.PID != launched.command.Process.Pid || !posture.Member || posture.Cgroup != "/"+filepath.Base(envelope) {
					t.Errorf("the posture was read in pid %d member %v of %s, want the holder %d in /%s",
						posture.PID, posture.Member, posture.Cgroup, launched.command.Process.Pid, filepath.Base(envelope))
				}
				if posture.MemoryMax != 1073741824 || posture.SwapMax != 0 || posture.SwapCurrent != 0 || posture.Dumpable != 0 {
					t.Errorf("the posture read is %+v, want the envelope's cap, no swap and not dumpable", posture)
				}
				outside := false
				for _, one := range posture.Participants {
					outside = outside || (one.PID == client.process.PID && !strings.HasPrefix(one.Cgroup+"/", posture.Cgroup+"/"))
				}
				if !outside {
					t.Errorf("the client was not verified outside the envelope: %+v", posture.Participants)
				}
				t18Ask(t, client, "/?asked=t18-posture", "Authorization: "+secret)
				if err := launched.command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatalf("stop the observer: %v", err)
				}
				if err := launched.exit(t, t18StopWithin); err != nil {
					t.Fatalf("the neighbour exited %v:\n%s", err, launched.stderr)
				}
				entries, err := os.ReadDir(c.sessions())
				if err != nil || len(entries) != 1 {
					t.Fatalf("the neighbour left %d sessions (%v)", len(entries), err)
				}
				written := t18Approved(t, filepath.Join(c.sessions(), entries[0].Name()))
				if !strings.Contains(strings.Join(t18Targets(written), " "), "asked=t18-posture") || t18Excluded(written, "authorization") == 0 {
					t.Fatalf("wiring, not the property: the neighbour wrote no exchange with its credential removed: %v", t18Targets(written))
				}
				if holding := t18Holding(t, c.directory, secret); len(holding) != 0 {
					t.Errorf("the credential reached %v", holding)
				}
				return
			}

			if _, activated := launched.activation(t, 30*time.Second); activated {
				t.Fatalf("the observer activated with %s absent", tc.check)
			}
			err := launched.exit(t, 30*time.Second)
			if err == nil {
				t.Fatalf("a start with %s absent exited zero:\n%s", tc.check, launched.stderr)
			}
			said := t18Refusal.FindStringSubmatch(launched.stderr.String())
			if said == nil || said[1] != tc.check {
				t.Fatalf("the refusal does not name %s:\n%s", tc.check, launched.stderr)
			}
			holder, _ := strconv.Atoi(said[2])
			switch {
			case !tc.detached && holder != launched.command.Process.Pid:
				t.Errorf("the refusal names pid %d, and the holder is %d", holder, launched.command.Process.Pid)
			case tc.detached && (holder <= 0 || holder == launched.command.Process.Pid):
				t.Errorf("detached, the refusal names pid %d, which is not the child left to hold payload (the launched parent is %d)",
					holder, launched.command.Process.Pid)
			}
			failed := t18LogRecords(t, c.log, "start-failed")
			recorded := ""
			if len(failed) == 1 {
				recorded, _ = failed[0]["error"].(string)
			}
			if !strings.Contains(recorded, tc.check) {
				t.Errorf("the log does not record the start failing on %s: %v", tc.check, failed)
			}
			if activated := t18LogRecords(t, c.log, "activation-completed"); len(activated) != 0 {
				t.Errorf("the log records an activation: %v", activated)
			}
			if entries, err := os.ReadDir(c.sessions()); err == nil && len(entries) != 0 {
				t.Errorf("the refused start left %d session directories", len(entries))
			}
			for _, path := range t18Files(t, c.directory) {
				if path != "observer.log" && path != "observer.pid" {
					t.Errorf("the refused start left %s", path)
				}
			}
			if left := runningWith(t, c.path); len(left) != 0 {
				t.Errorf("the refused start left %v running", left)
			}
		})
	}
}
