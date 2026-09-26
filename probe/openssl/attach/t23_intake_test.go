//go:build attach

package attach_test

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/process"
)

// t23Allowance sets the observer's admitted-event allowance in the
// configuration; the volatile intake's byte allowance is derived from it.
func t23Allowance(t *testing.T, c configured, events int) {
	t.Helper()
	content, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("read %s: %v", c.path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode %s: %v", c.path, err)
	}
	observer, _ := document["observer"].(map[string]any)
	if observer == nil {
		t.Fatalf("wiring, not the property: %s has no observer section", c.path)
	}
	observer["admitted_event_limit"] = events
	if content, err = json.Marshal(document); err != nil {
		t.Fatalf("encode %s: %v", c.path, err)
	}
	if err := os.WriteFile(c.path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
}

// t23Receiving is openssl s_server on a free port, not observed until a
// configuration names it. It reads each connection with SSL_read into a buffer
// larger than a TLS record, so each read of a large upload carries a full event
// payload. Its output is drained so it never stops reading.
func t23Receiving(t *testing.T) (process.Process, int) {
	t.Helper()
	certificate, key := certificate(t)
	port := free(t)
	command := exec.Command("openssl", "s_server", "-accept", strconv.Itoa(port), "-cert", certificate, "-key", key)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start s_server: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	lines := bufio.NewReader(stdout)
	for {
		line, err := lines.ReadString('\n')
		if err != nil {
			t.Fatalf("s_server did not come up: %v", err)
		}
		if strings.HasPrefix(line, "ACCEPT") {
			break
		}
	}
	go func() { _, _ = io.Copy(io.Discard, lines) }()
	return loaded(t, int32(command.Process.Pid)), port
}

// t23Ended waits for a session to end by itself and returns the gate reason
// its stopped record gives, reading its log to the end. It is killed after a
// minute, which the caller reads as not ending by itself.
func t23Ended(t *testing.T, observer running) (string, bool) {
	t.Helper()
	var killed atomic.Bool
	backstop := time.AfterFunc(time.Minute, func() { killed.Store(true); _ = observer.command.Process.Kill() })
	defer backstop.Stop()
	reason, found := "", false
	for observer.lines.Scan() {
		var record struct {
			Record     string `json:"record"`
			Processing *struct {
				GateReason string `json:"gate_reason"`
			} `json:"processing"`
		}
		if json.Unmarshal(observer.lines.Bytes(), &record) == nil && record.Record == "stopped" {
			found = true
			if record.Processing != nil {
				reason = record.Processing.GateReason
			}
		}
	}
	_ = observer.command.Wait()
	if killed.Load() {
		t.Fatal("wiring, not the property: the session did not end by itself within a minute")
	}
	return reason, found
}

// The volatile intake fills before the event allowance does, since each record
// is charged its payload and its metadata and every read here carries a full
// payload. The session ends by itself, and the
// account, its stopped record and inspect all give intake_exhausted as the
// reason release was refused, with the records the intake refused printed on
// the seal line. The control, the same session with one exchange, states no
// reason and prints no loss.
func TestAFullVolatileIntakeIsStatedAsIntakeExhaustedBesideTheRecordsItRefused(t *testing.T) {
	binary := built(t)
	const allowance = 64

	t.Run("filled", func(t *testing.T) {
		server, port := t23Receiving(t)
		c := configuring(t, target("server", server))
		t23Allowance(t, c, allowance)
		observer := started(t, binary, c)
		client := speaking(t, port)
		// An upload with no end, so nothing is ever released to free the intake,
		// and every read the server makes carries a full payload.
		chunk := strings.Repeat("x", 64*1024)
		for range 32 {
			if _, err := io.WriteString(client.send, chunk); err != nil {
				break
			}
		}
		reason, stopped := t23Ended(t, observer)
		// Read and rendered here: inspect --text refuses a session that approved
		// no record, and this one approves none.
		raw, err := os.ReadFile(filepath.Join(observer.directory(c), "account.json"))
		if err != nil {
			t.Fatalf("read the sealed account: %v", err)
		}
		var sealed account.Account
		if err := json.Unmarshal(raw, &sealed); err != nil {
			t.Fatalf("decode the sealed account: %v", err)
		}
		text := rendered(sealed)

		if sealed.Seen == nil {
			t.Fatal("wiring, not the property: the sealed account says nothing about what came through")
		}
		// Only the intake refuses a record, so a refusal is its exhaustion reached,
		// however many transfers the gate went on admitting.
		if sealed.Seen.Rejected == 0 {
			t.Fatalf("wiring, not the property: the intake refused no record, with %d transfers seen against an "+
				"allowance of %d, so its exhaustion was not reached", sealed.Seen.Transfers, allowance)
		}
		t.Logf("the intake refused %d records; %d transfers seen against an allowance of %d",
			sealed.Seen.Rejected, sealed.Seen.Transfers, allowance)
		if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 {
			t.Fatalf("wiring, not the property: the kernel refused events, so the intake's exhaustion is not the "+
				"only one reached: %+v", sealed.Loss)
		}
		if !stopped {
			t.Fatal("wiring, not the property: the session's log holds no stopped record")
		}

		if sealed.Processing == nil || sealed.Processing.GateReason != "intake_exhausted" {
			t.Errorf("the account gives %+v as the reason release was refused, want intake_exhausted", sealed.Processing)
		}
		if reason != "intake_exhausted" {
			t.Errorf("the stopped record gives %q as the reason, want intake_exhausted", reason)
		}
		if !strings.Contains(text, "release    refused: intake_exhausted") {
			t.Errorf("the account as text does not state the reason:\n%s", text)
		}
		seal, _, _ := t23Line(text, "sealed ")
		if !strings.Contains(seal, "INCOMPLETE") &&
			!strings.Contains(seal, "LOST "+strconv.FormatInt(sealed.Seen.Rejected, 10)+
				" records the volatile intake refused") {
			t.Errorf("the seal line says the session sealed and does not print the %d records the intake refused: %q",
				sealed.Seen.Rejected, seal)
		}
		t.Logf("seal line: %s", seal)
	})

	t.Run("one exchange", func(t *testing.T) {
		server, port := forkingServer(t, "single")
		c := configuring(t, target("server", server))
		t23Allowance(t, c, allowance)
		observer := started(t, binary, c)
		client := speaking(t, port)
		t23Asking(t, client, "t23-intake-control")
		stopped := t23Stopped(t, binary, c, observer)
		directory := observer.directory(c)
		raw, text := t23Sealed(t, binary, directory)
		var sealed account.Account
		if err := json.Unmarshal(raw, &sealed); err != nil {
			t.Fatalf("decode the sealed account: %v", err)
		}
		if n := t23Retained(t, directory, server.PID, "t23-intake-control"); n != 1 {
			t.Fatalf("wiring, not the property: the control exchange is retained %d times, so the session did not "+
				"capture and its silence says nothing", n)
		}
		if sealed.Processing == nil || sealed.Processing.GateReason != "" {
			t.Errorf("the control gives %+v as a reason, want none", sealed.Processing)
		}
		seal, _, _ := t23Line(text, "sealed ")
		for which, line := range map[string]string{"stop": stopped, "inspect's seal line": seal} {
			if strings.Contains(line, "LOST") || strings.Contains(line, "release refused") {
				t.Errorf("%s prints a loss or a reason for a session that had neither: %q", which, line)
			}
		}
		if strings.Contains(text, "release    refused") {
			t.Errorf("inspect states a reason release was refused for the control:\n%s", text)
		}
	})
}
