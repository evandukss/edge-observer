//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
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
	"unsafe"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
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
	limits, _ := document["limits"].(map[string]any)
	if limits == nil {
		t.Fatalf("wiring, not the property: %s has no limits", c.path)
	}
	limits["events"] = events
	if content, err = json.Marshal(document); err != nil {
		t.Fatalf("encode %s: %v", c.path, err)
	}
	if err := os.WriteFile(c.path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
}

// t23Receiving is openssl s_server on a free port, not observed until a
// configuration names it. It reads each connection with SSL_read into a buffer
// larger than a TLS record, and a read returns a record whole, so each read is
// as long as the record it returns. Its output is drained so it never stops
// reading.
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

// t23Record is the plaintext each record of t23Uploading carries: the largest a
// TLS record holds.
const t23Record = 16 * 1024

// t23Uploading is a TLS client on port whose every record carries exactly
// t23Record bytes: with dynamic record sizing off, one write of t23Record
// bytes is one record. The server's certificate is the fixture's own, made for
// this run, so it is not verified.
func t23Uploading(t *testing.T, port int) *tls.Conn {
	t.Helper()
	connection, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port),
		&tls.Config{InsecureSkipVerify: true, DynamicRecordSizingDisabled: true})
	if err != nil {
		t.Fatalf("connect to s_server: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
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

// The volatile intake fills before the event allowance does. It holds
// allowance * payload bytes, payload being ebpf.MaxEventPayloadBytes
// (activation.RecordingIntake), and charges each event its payload plus a fixed
// overhead (intake.Store.Write). Every record the client sends is t23Record
// bytes, no less than a payload, and every server read returns one, so every
// event carries a full payload and is charged payload + overhead. The intake
// therefore refuses a record by event allowance*payload/(payload+overhead) + 1,
// which must come before the allowance's last event; the test checks that
// before it runs. The session ends by itself, and the account, its stopped
// record and inspect all give intake_exhausted as the reason release was
// refused, with the records the intake refused printed on the seal line. The
// control, the same session with one exchange, states no reason and prints no
// loss.
func TestAFullVolatileIntakeIsStatedAsIntakeExhaustedBesideTheRecordsItRefused(t *testing.T) {
	binary := built(t)
	const allowance = 64

	t.Run("filled", func(t *testing.T) {
		payload := int64(ebpf.MaxEventPayloadBytes)
		overhead := int64(unsafe.Sizeof(intake.Entry{}) + unsafe.Sizeof(fragment.Record{}))
		fillsBy := allowance*payload/(payload+overhead) + 1
		if t23Record < payload || fillsBy >= allowance {
			t.Fatalf("wiring, not the property: records of %d bytes against a payload of %d and an overhead of %d "+
				"fill the intake by event %d of an allowance of %d, so the allowance can run out no later than "+
				"the intake",
				t23Record, payload, overhead, fillsBy, allowance)
		}
		t.Logf("the intake fills by event %d of an allowance of %d: payload %d, overhead %d per event",
			fillsBy, allowance, payload, overhead)

		server, port := t23Receiving(t)
		c := configuring(t, target("server", server))
		t23Allowance(t, c, allowance)
		observer := started(t, binary, c)
		client := t23Uploading(t, port)
		// An upload with no end, so nothing is ever released to free the intake:
		// twice the allowance in records, far past the event that fills it.
		record := bytes.Repeat([]byte("x"), t23Record)
		for range 2 * allowance {
			if _, err := client.Write(record); err != nil {
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
