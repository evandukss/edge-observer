//go:build attach

package attach_test

import (
	"bufio"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// t18Reader is testdata/t18_read_ex.c connected to port.
type t18Reader struct {
	process process.Process
	send    io.WriteCloser
	answers *bufio.Reader
}

func t18Reading(t *testing.T, port int) t18Reader {
	t.Helper()
	command := exec.Command(compiled(t, "testdata/t18_read_ex.c"), strconv.Itoa(port))
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the reader: %v", err)
	}
	t.Cleanup(func() { _ = send.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	answers := bufio.NewReader(out)
	if line, err := answers.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("the reader did not connect: %q %v", line, err)
	}
	return t18Reader{process: loaded(t, int32(command.Process.Pid)), send: send, answers: answers}
}

func (r t18Reader) say(t *testing.T, command string) string {
	t.Helper()
	if _, err := io.WriteString(r.send, command+"\n"); err != nil {
		t.Fatalf("tell the reader %q: %v", command, err)
	}
	line, err := r.answers.ReadString('\n')
	if err != nil {
		t.Fatalf("the reader did not answer %q: %v", command, err)
	}
	return strings.TrimSuffix(line, "\n")
}

// Row 17's unknown-length reason on the running program. A client that reads
// with SSL_read_ex makes one call that fails while nothing is pending: the
// library writes no count, so the probe reports a transfer it could not
// measure. The session ends by itself with that reason in its account - not
// the input limit, not the storage reason, not a missing-stamp count - and the
// exchange still open on the connection is not written. The control is the
// same client and exchange with no such call, which runs until stopped and
// writes it.
func TestT18AnUnmeasuredTransferRetiresTheSessionUnderItsOwnReason(t *testing.T) {
	binary := built(t)
	for _, unmeasured := range []bool{true, false} {
		name := map[bool]string{true: "one read the probe cannot measure", false: "measured reads only"}[unmeasured]
		t.Run(name, func(t *testing.T) {
			reader := t18Reading(t, t18Serving(t))
			c := configuring(t, target("reader", reader.process))
			t18Edit(t, c, t18Removing)
			s := t18Started(t, binary, c)

			if answer := reader.say(t, "G /?asked=t18-before"); answer != "done 200" {
				t.Fatalf("wiring, not the property: the reader's exchange answered %q", answer)
			}
			t18Until(t, binary, c, 10*time.Second, "wiring, not the property: the reader's exchange was never captured",
				func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })

			var sealed account.Account
			if unmeasured {
				// SSL_ERROR_WANT_READ is 2: the call failed for want of input, and
				// nothing else about it is in doubt.
				if answer := reader.say(t, "W"); answer != "would-block 0 2" {
					t.Fatalf("wiring, not the property: the out-parameter read answered %q, not a failure for want of input", answer)
				}
				s.awaited(t, 30*time.Second)
				if s.signaled || s.err != nil {
					t.Fatalf("the session did not end by itself cleanly: signalled %v, %v:\n%s", s.signaled, s.err, s.transcript())
				}
				sealed = t18Sealed(t, s.directory(c), s.session)
			} else {
				if answer := reader.say(t, "G /?asked=t18-after"); answer != "done 200" {
					t.Fatalf("the reader's second exchange answered %q", answer)
				}
				sealed = s.stop(t, c)
			}
			t.Logf("processing %+v; seen %+v; stopped record %v", sealed.Processing, sealed.Seen, s.records("stopped"))

			targets := t18Targets(t18Approved(t, s.directory(c)))
			// The refused transfer supplies its producer evidence without
			// retaining payload. Nothing is missing, so no per-direction gap
			// may be counted as loss.
			if sealed.Seen.Lost != 0 || sealed.Loss.Dropped != 0 {
				t.Errorf("the account counts %d missing per-direction observations where the ring dropped %d: the refused transfer is reported as capture loss",
					sealed.Seen.Lost, sealed.Loss.Dropped)
			}
			if !unmeasured {
				if sealed.Processing == nil || sealed.Processing.GateReason != "" || !slices.Contains(targets, "/?asked=t18-before") {
					t.Fatalf("the control says %+v and wrote %v, so the fault's absence of output measures nothing",
						sealed.Processing, targets)
				}
				return
			}
			if sealed.Processing == nil || sealed.Processing.GateReason != probe.GateUnknownLength {
				t.Errorf("the account gives %+v as the reason, want %s", sealed.Processing, probe.GateUnknownLength)
			}
			if slices.Contains(targets, "/?asked=t18-before") {
				t.Errorf("the exchange still open when the length became unknown was written: %v", targets)
			}
			// Nothing was approved, and --text refuses a session with no approved
			// record, so the reason is read from the account the command prints.
			stdout, stderr, err := t18Command(t, 30*time.Second, binary, "inspect", s.directory(c))
			if err != nil || !strings.Contains(stdout, `"gate_reason": "`+string(probe.GateUnknownLength)+`"`) {
				t.Errorf("the public command does not state the reason (%v):\n%s%s", err, stdout, stderr)
			}
		})
	}
}
