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

// A failed nonblocking read moved no bytes. It must leave the live session
// able to capture and approve the exchanges on both sides of that call.
func TestIndependentWouldBlockReadKeepsLaterExchange(t *testing.T) {
	binary := built(t)
	for _, wouldBlock := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary_reads", true: "would_block"}[wouldBlock], func(t *testing.T) {
			reader := t18Reading(t, t18Serving(t))
			c := configuring(t, target("reader", reader.process))
			t18Edit(t, c, t18Removing)
			s := t18Started(t, binary, c)
			if answer := reader.say(t, "G /?asked=t18-before"); answer != "done 200" { t.Fatalf("first exchange: %q", answer) }
			t18Until(t, binary, c, 10*time.Second, "wiring, not the property: first exchange absent",
				func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })
			if wouldBlock {
				if answer := reader.say(t, "W"); answer != "would-block 0 2" { t.Fatalf("wiring, not the property: expected WANT_READ, got %q", answer) }
			}
			if answer := reader.say(t, "G /?asked=t18-after"); answer != "done 200" { t.Fatalf("second exchange: %q", answer) }
			if s.ended() { t.Fatalf("session ended before explicit stop: %s", s.transcript()) }
			sealed := s.stop(t, c)
			if sealed.Processing == nil || sealed.Processing.GateReason != "" || sealed.Processing.ProcessingFailures != 0 { t.Errorf("read invalidated processing: %+v", sealed.Processing) }
			if sealed.Seen == nil || sealed.Seen.Unmeasured != 0 || sealed.Seen.Lost != 0 { t.Errorf("read became unknown length or lost input: %+v", sealed.Seen) }
			if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 { t.Errorf("kernel loss: %+v", sealed.Loss) }
			targets := t18Targets(t18Approved(t, s.directory(c)))
			for _, path := range []string{"/?asked=t18-before", "/?asked=t18-after"} {
				if !slices.Contains(targets, path) { t.Errorf("missing useful exchange %s in %v", path, targets) }
			}
			t.Logf("PRECONDITIONS would_block=%v real_exchanges=2 processing=%+v seen=%+v", wouldBlock, sealed.Processing, sealed.Seen)
		})
	}
}
