//go:build attach

package attach_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// sequential is a client making several TLS connections one after another in
// one process, each released before the next: the shape in which an allocator
// hands the same address back, which the connection-ending probe exists for.
const sequential = `
import socket, ssl, sys
port, rounds = int(sys.argv[1]), int(sys.argv[2])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
print("ready", flush=True)
sys.stdin.readline()
for round in range(rounds):
    connection = context.wrap_socket(socket.create_connection(("127.0.0.1", port)))
    connection.sendall(
        ("GET /round-%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" % round).encode())
    while connection.recv(4096):
        pass
    connection.close()
    del connection
print("done", flush=True)
`

// rounds is how many connections the client makes: the address must be
// released and reused, and an allocator need not do it on any given attempt.
const rounds = 6

// sequentialClient starts the client and returns its pid, a function letting
// it begin, and its own account. It is paused until the probes are placed.
func sequentialClient(t *testing.T, port int) (int32, func(), *bufio.Reader) {
	t.Helper()

	script := filepath.Join(t.TempDir(), "sequential.py")
	if err := os.WriteFile(script, []byte(sequential), 0o600); err != nil {
		t.Fatalf("write the client: %v", err)
	}

	command := exec.Command("python3", script, strconv.Itoa(port), strconv.Itoa(rounds))
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the client: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })

	lines := bufio.NewReader(out)
	if line, err := lines.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("the client did not come up: %q %v", line, err)
	}
	return int32(command.Process.Pid), func() { _, _ = send.Write([]byte("go\n")) }, lines
}

// step is one thing the adapter reported, in order, with the capture's record
// of it where one was made, so a transfer on a reused address can be placed.
type step struct {
	endpoint uint64
	closed   bool
	record   fragment.Record
	placed   bool
}

// traced sits between the adapter and the capture and keeps both sides. The
// adapter delivers on one goroutine, so a transfer and its record arrive
// together.
type traced struct {
	session *capture.Session

	mutex   sync.Mutex
	steps   []step
	closes  int
	current uint64
}

func (t *traced) Transfer(transfer probe.Transfer) {
	t.current = transfer.Endpoint
	t.session.Transfer(transfer)
}

func (t *traced) Closed(connection probe.Connection) {
	t.session.Closed(connection)

	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.closes++
	t.steps = append(t.steps, step{endpoint: connection.Endpoint, closed: true})
}

func (t *traced) Write(record fragment.Record) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.steps = append(t.steps, step{endpoint: t.current, record: record, placed: true})
	return nil
}

func (t *traced) taken() ([]step, int) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return append([]step(nil), t.steps...), t.closes
}

// reuse is the first address the process used, released and was handed back,
// with the records on it before and after. Without one there is nothing to
// measure, and the caller says so.
func reuse(steps []step, pid int32) (before, after []fragment.Record, found bool) {
	released := make(map[uint64]bool)
	held := make(map[uint64][]fragment.Record)
	reopened := make(map[uint64][]fragment.Record)

	for _, at := range steps {
		if at.closed {
			released[at.endpoint] = true
			continue
		}
		if !at.placed || at.record.Process.PID != pid {
			continue
		}
		if released[at.endpoint] {
			reopened[at.endpoint] = append(reopened[at.endpoint], at.record)
			continue
		}
		held[at.endpoint] = append(held[at.endpoint], at.record)
	}

	for endpoint, second := range reopened {
		if first := held[endpoint]; len(first) > 0 && len(second) > 0 {
			return first, second, true
		}
	}
	return nil, nil, false
}

// firstOffsets is where each direction's first record of a set sits in its
// stream.
func firstOffsets(records []fragment.Record) map[fragment.Direction]uint64 {
	first := make(map[fragment.Direction]uint64, 2)
	for _, record := range records {
		if _, seen := first[record.Direction]; !seen {
			first[record.Direction] = record.Offset
		}
	}
	return first
}

func connections(records []fragment.Record) map[fragment.ConnectionID]bool {
	found := make(map[fragment.ConnectionID]bool)
	for _, record := range records {
		found[record.Connection] = true
	}
	return found
}

// drove runs the client to completion and gives the adapter time to deliver.
func drove(t *testing.T, proceed func(), lines *bufio.Reader) {
	t.Helper()

	proceed()
	done := make(chan string, 1)
	go func() {
		line, _ := lines.ReadString('\n')
		done <- line
	}()
	select {
	case line := <-done:
		if line != "done\n" {
			t.Fatalf("the client did not finish its connections: %q", line)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the client did not finish its connections")
	}
	time.Sleep(700 * time.Millisecond)
}

// A connection ending lets a reused address begin a new stream instead of
// continuing the previous one. This defect produces wrong data, not missing
// data: two conversations spliced into one read as consistent, so the
// falsification below aims at the property directly.
func TestAnAddressHandedOutAgainBeginsANewStream(t *testing.T) {
	port := serving(t)
	pid, proceed, lines := sequentialClient(t, port)
	intoCgroup(t, "obs-sequential", pid)
	client := loaded(t, pid)

	sink := &traced{}
	sink.session = capture.New(sink)
	live, err := attach.NeweBPF(process.Approval{}).Attach(requesting(client), sink)
	if err != nil {
		t.Fatalf("attach to pid %d: %v", pid, err)
	}
	t.Cleanup(func() { _ = live.Close() })

	drove(t, proceed, lines)

	steps, closes := sink.taken()
	if closes == 0 {
		t.Fatal("no connection ending was reported at all, so no address could ever be released")
	}

	before, after, found := reuse(steps, pid)
	if !found {
		t.Fatalf("no address was released and handed back over %d connections, so this measures nothing "+
			"(%d steps, %d endings)", rounds, len(steps), closes)
	}

	if held, reopened := connections(before), connections(after); overlap(held, reopened) {
		t.Errorf("the second connection's bytes are in the first's stream: %v and %v", held, reopened)
	}
	for direction, offset := range firstOffsets(after) {
		if offset != 0 {
			t.Errorf("the reopened connection's first %s record sits at offset %d, and a stream begins at 0",
				direction, offset)
		}
	}
}

// The falsification, with the probe deliberately not placed: the same client
// and analysis, and a catalogue naming no connection ending. It must find the
// two conversations spliced, or the case above proves nothing.
func TestWithoutTheConnectionEndingTheTwoConversationsAreSplicedIntoOne(t *testing.T) {
	port := serving(t)
	pid, proceed, lines := sequentialClient(t, port)
	intoCgroup(t, "obs-spliced", pid)
	client := loaded(t, pid)

	// This client's runtime uses the _ex family, whose count is an out-parameter,
	// so only a program following a pointer produces a stream to splice.
	blind := probe.OpenSSL
	blind.Lifecycle = nil
	crippled := attach.NeweBPF(process.Approval{})
	crippled.Adapter = openssl.Adapter{ProcFS: procfs, Runtime: blind}

	sink := &traced{}
	sink.session = capture.New(sink)
	live, err := crippled.Attach(requesting(client), sink)
	if err != nil {
		t.Fatalf("attach to pid %d: %v", pid, err)
	}
	t.Cleanup(func() { _ = live.Close() })

	drove(t, proceed, lines)

	steps, closes := sink.taken()
	if closes != 0 {
		t.Fatalf("%d connection endings were reported by an adapter that probes none", closes)
	}

	var records []fragment.Record
	for _, at := range steps {
		if at.placed && at.record.Process.PID == pid {
			records = append(records, at.record)
		}
	}
	if len(records) < 2 {
		t.Fatalf("%d records from pid %d, so nothing here was measured", len(records), pid)
	}
	if len(connections(records)) != 1 {
		t.Fatalf("%d connections without a connection-ending probe, and an address the allocator "+
			"reuses cannot begin a new stream without one", len(connections(records)))
	}
	if offsets := firstOffsets(records); !climbs(records) {
		t.Errorf("the offsets do not continue across the reused address: first %v, records %d",
			offsets, len(records))
	}
}

func overlap(left, right map[fragment.ConnectionID]bool) bool {
	for id := range left {
		if right[id] {
			return true
		}
	}
	return false
}

// climbs reports whether some direction's offsets go past its first record, as
// in a stream that never restarted.
func climbs(records []fragment.Record) bool {
	seen := make(map[fragment.Direction]uint64, 2)
	for _, record := range records {
		if record.Offset > seen[record.Direction] {
			return true
		}
		seen[record.Direction] = record.Offset
	}
	return false
}
