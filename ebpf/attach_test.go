//go:build attach

// These tests load real BPF programs and attach them to real processes, so they
// need BPF, the privilege to load a program and place a uprobe, and a cgroup
// v2 hierarchy. They carry a build tag rather than fail every unit run.
package ebpf_test

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

const procfs = "/proc"

// tlsServer is an HTTPS server in another runtime, using whatever OpenSSL entry
// points it chooses. It is not observed.
const tlsServer = `
import http.server, ssl, sys
port, certificate, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path.startswith("/size/"):
            n = int(self.path[len("/size/"):])
            body = b"S" * n
        else:
            body = b"PLAINTEXT-RESPONSE-" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
`

func certificate(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-subj", "/CN=localhost", "-keyout", key, "-out", cert, "-days", "1").CombinedOutput()
	if err != nil {
		t.Fatalf("make a certificate: %v\n%s", err, out)
	}
	return cert, key
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// serving starts the HTTPS server and returns its pid and port once it is ready.
func serving(t *testing.T) (int32, int) {
	t.Helper()
	cert, key := certificate(t)
	script := filepath.Join(t.TempDir(), "server.py")
	if err := os.WriteFile(script, []byte(tlsServer), 0o600); err != nil {
		t.Fatalf("write the server: %v", err)
	}
	port := freePort(t)
	command := exec.Command("python3", script, fmt.Sprint(port), cert, key)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("server did not come up: %q %v", line, err)
	}
	return int32(command.Process.Pid), port
}

// speaking starts an OpenSSL client holding a connection and returns it.
type client struct {
	pid     int32
	send    io.WriteCloser
	receive *bufio.Reader
}

func speaking(t *testing.T, port int) client {
	t.Helper()
	command := exec.Command("openssl", "s_client", "-quiet", "-no_ign_eof",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port))
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	receive, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the client: %v", err)
	}
	t.Cleanup(func() { _ = send.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	return client{pid: int32(command.Process.Pid), send: send, receive: bufio.NewReader(receive)}
}

func (c client) ask(t *testing.T, path string) {
	t.Helper()
	if _, err := io.WriteString(c.send, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("send a request: %v", err)
	}
	if _, err := c.receive.ReadString('\n'); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
}

// loaded waits for a pid to have libssl mapped and returns its process.
func loaded(t *testing.T, pid int32) process.Process {
	t.Helper()
	for range 400 {
		table, err := process.Read(procfs)
		if err != nil {
			t.Fatalf("read processes: %v", err)
		}
		if p, ok := table.Lookup(pid); ok {
			mappings, err := process.Mappings(procfs, pid)
			if err == nil {
				for _, m := range mappings {
					if strings.Contains(m.Path, "libssl.so") && m.Executable {
						return p
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d never loaded libssl", pid)
	return process.Process{}
}

// points resolves the probes for a process and maps them to programs.
func points(t *testing.T, p process.Process) []ebpf.Point {
	t.Helper()
	support := openssl.New().Inspect(p)
	if !support.Supported {
		t.Fatalf("pid %d not supported: %s", p.PID, support.Reason)
	}
	pts, discarded := ebpf.PointsFrom(support.Probes, openssl.New().Runtime)
	for _, one := range discarded {
		t.Errorf("pid %d resolved %s and no program was chosen for it: %s", p.PID, one.Symbol, one.Reason)
	}
	if len(pts) == 0 {
		t.Fatalf("no points resolved for pid %d", p.PID)
	}
	return pts
}

// admit is one process, admitted as a target naming it would: its own
// instance, follow for what it forks, and a printable provenance.
func admit(p process.Process) admission.Selection {
	return admission.Selection{
		Instance:    p.Instance(),
		Kind:        admission.ByTarget,
		Provenance:  admission.Provenance{Target: p.Executable, Number: 1},
		Mode:        admission.ModeFollow,
		ObserverPID: p.PID,
	}
}

// authorise names one process for a session's allowlist.
func authorise(p process.Process) []admission.Selection { return []admission.Selection{admit(p)} }

// moveToCgroup makes a fresh child cgroup, moves the pid into it and returns
// its id; the cgroup is removed when the test ends.
func moveToCgroup(t *testing.T, name string, pid int32) uint64 {
	t.Helper()
	dir := filepath.Join(ebpf.DefaultCgroupMount, name)
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("make cgroup %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(int(pid))), 0o644); err != nil {
		t.Fatalf("move pid %d into %s: %v", pid, dir, err)
	}
	id, err := ebpf.CgroupID(procfs, ebpf.DefaultCgroupMount, pid)
	if err != nil {
		t.Fatalf("cgroup id of pid %d: %v", pid, err)
	}
	return id
}

type captured struct {
	events []ebpf.Event
}

// drain collects events until quiet.
func drain(session *ebpf.Session, quiet time.Duration) captured {
	var c captured
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-session.Events():
			if !ok {
				return c
			}
			c.events = append(c.events, event)
			timer.Reset(quiet)
		case <-timer.C:
			return c
		}
	}
}

func (c captured) plaintext(direction fragment.Direction) []string {
	var found []string
	for _, e := range c.events {
		if e.Kind == ebpf.Transfer && e.Direction == direction && len(e.Payload) > 0 {
			found = append(found, string(e.Payload))
		}
	}
	return found
}

func containsSubstring(texts []string, want string) bool {
	for _, text := range texts {
		if strings.Contains(text, want) {
			return true
		}
	}
	return false
}

// At the session level: an unmodified process over real TLS has both halves of
// its conversation read as plaintext through the full program.
func TestTheFullProgramReadsBothDirectionsAsPlaintext(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, server),
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	c := speaking(t, port)
	c.ask(t, "/marker-path")

	got := drain(session, 700*time.Millisecond)
	received := got.plaintext(fragment.Received)
	sent := got.plaintext(fragment.Sent)

	// The server reads the request (received) and writes the response (sent).
	if !containsSubstring(received, "GET /marker-path") {
		t.Errorf("the request was not read as plaintext; received %q", received)
	}
	if !containsSubstring(sent, "PLAINTEXT-RESPONSE-/marker-path") {
		t.Errorf("the response was not read as plaintext; sent %q", sent)
	}
}

// A process running the same libssl in a cgroup the allowlist does not name
// has no plaintext read, beside an approved control that does.
func TestAnUnapprovedProcessInAnotherCgroupIsNotObserved(t *testing.T) {
	approvedPID, approvedPort := serving(t)
	approved := loaded(t, approvedPID)
	moveToCgroup(t, "obs-approved", approved.PID)

	unapprovedPID, unapprovedPort := serving(t)
	unapproved := loaded(t, unapprovedPID)
	moveToCgroup(t, "obs-unapproved", unapproved.PID)

	// Attach to both processes' probes, and authorise only the first.
	pts := append(points(t, approved), points(t, unapproved)...)
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  pts,
		Admit:   authorise(approved),
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	unapprovedClient := speaking(t, unapprovedPort)
	unapprovedClient.ask(t, "/should-not-be-seen")
	approvedClient := speaking(t, approvedPort)
	approvedClient.ask(t, "/should-be-seen")

	got := drain(session, 700*time.Millisecond)

	if !containsSubstring(got.plaintext(fragment.Received), "should-be-seen") {
		t.Fatal("the control did not move: the approved process produced no plaintext, so the negative proves nothing")
	}
	for _, text := range append(got.plaintext(fragment.Received), got.plaintext(fragment.Sent)...) {
		if strings.Contains(text, "should-not-be-seen") {
			t.Errorf("plaintext from an unapproved process was read: %q", text)
		}
	}
}

// The full object loads and its stats map is readable, so Dropped and
// Unmatched report real counters.
func TestACounterThatCannotBeReadIsNotReportedAsZero(t *testing.T) {
	serverPID, _ := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, server), Admit: authorise(server)})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Attached, and the counters answer: the control for the refusal below.
	for _, counter := range []struct {
		name string
		read func() (int64, error)
	}{
		{"dropped", session.Dropped},
		{"unmatched", session.Unmatched},
		{"descendants", session.Descendants},
	} {
		value, err := counter.read()
		if err != nil {
			t.Fatalf("read %s on a live session: %v", counter.name, err)
		}
		if value != 0 {
			t.Logf("%s is already %d", counter.name, value)
		}
	}

	// A session whose maps are gone cannot look, and must not answer zero, which
	// is what a capture that lost nothing reports.
	if err := session.Close(); err != nil {
		t.Fatalf("close the session: %v", err)
	}
	for _, counter := range []struct {
		name string
		read func() (int64, error)
	}{
		{"dropped", session.Dropped},
		{"unmatched", session.Unmatched},
		{"descendants", session.Descendants},
	} {
		value, err := counter.read()
		if err == nil {
			t.Errorf("%s came back as %d from a session that cannot read its own counters, "+
				"which is what a capture that lost nothing also reports", counter.name, value)
		}
	}
	_ = bytes.MinRead
}

// A call already inside a probed function when the probes are placed loses
// half its exchange; attaching before the traffic bounds that. The property is
// the pair: opened before the probes, the capture holds the answer without its
// request (reading as complete when it is not); opened after, both halves.
// Either alone measures nothing. What the run can say about it is asserted
// separately, as it depends on the kernel.
func TestACallInFlightWhenTheProbesArePlacedLeavesHalfItsExchangeMissing(t *testing.T) {
	before := inFlightAt(t, true)
	after := inFlightAt(t, false)

	if !containsSubstring(after.plaintext(fragment.Received), inFlightRequest) {
		t.Fatal("the request was not captured even with the connection opened after the probes " +
			"were placed, so this run measures nothing about a call already in flight")
	}
	if !containsSubstring(after.plaintext(fragment.Sent), inFlightResponse) {
		t.Fatal("the answer was not captured with the connection opened after the probes were " +
			"placed, so this run measures nothing")
	}

	if !containsSubstring(before.plaintext(fragment.Sent), inFlightResponse) {
		t.Fatal("the answer to the blocked call was not captured either, so this arrangement " +
			"measures nothing about the half that is missing")
	}
	if containsSubstring(before.plaintext(fragment.Received), inFlightRequest) {
		t.Error("the request that completed a call already in flight was captured, and the entry " +
			"probe cannot have fired for a call that entered before it existed")
	}
}

// What a run may report about beginning mid-call is bounded either way.
// Whether a uretprobe fires for a frame already on the stack varies between
// runs on some kernels, so the count is not asserted: at most one, never two,
// nothing dropped, no refused in-flight entry, beside the arrangement with no
// call in flight.
func TestARunThatBeganMidCallAccountsForItWithoutInventingOrRefusingACall(t *testing.T) {
	after := inFlightCounters(t, false)
	if after.unmatched != 0 || after.unrecorded != 0 {
		t.Fatalf("with no call in flight the run reports %d unmatched and %d unrecorded, so a "+
			"count below would say nothing about the call in flight",
			after.unmatched, after.unrecorded)
	}

	before := inFlightCounters(t, true)
	if before.unrecorded != 0 {
		t.Fatalf("%d calls were refused by the in-flight table, so an unmatched return here is "+
			"not evidence about a call that entered before the probes", before.unrecorded)
	}
	// Which outcome this run got is logged, since it varies between runs.
	t.Logf("the call in flight was reported as %d unmatched returns", before.unmatched)
	if before.unmatched < 0 || before.unmatched > 1 {
		t.Errorf("one call was inside a probed function when the probes were placed and the run "+
			"reports %d unmatched: that call's return arrives once or not at all, so two is a "+
			"double count and more is the counter moving for something else", before.unmatched)
	}
	if before.dropped != 0 {
		t.Errorf("the run dropped %d events, so what the unmatched counter says about the call "+
			"in flight is not evidence about it", before.dropped)
	}
}

const (
	inFlightRequest  = "/completes-the-blocked-read"
	inFlightResponse = "PLAINTEXT-RESPONSE-" + inFlightRequest
)

type inFlightCounts struct {
	unmatched  int64
	dropped    int64
	unrecorded int64
}

// inFlightAt drives one exchange with the connection opened before or after
// the probes are placed. Before leaves a call in flight: the server accepts,
// shakes hands and blocks reading while the probes arrive.
func inFlightAt(t *testing.T, blocked bool) captured {
	t.Helper()
	got, _ := inFlight(t, blocked)
	return got
}

func inFlightCounters(t *testing.T, blocked bool) inFlightCounts {
	t.Helper()
	_, counts := inFlight(t, blocked)
	return counts
}

func inFlight(t *testing.T, blocked bool) (captured, inFlightCounts) {
	t.Helper()
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, fmt.Sprintf("obs-inflight-%d", serverPID), server.PID)

	var speaker client
	if blocked {
		speaker = speaking(t, port)
		speaker.ask(t, "/before-attachment")
	}

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(), Points: points(t, server), Admit: authorise(server),
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	if !blocked {
		speaker = speaking(t, port)
	}
	speaker.ask(t, inFlightRequest)
	got := drain(session, 500*time.Millisecond)

	counts := inFlightCounts{}
	if counts.unmatched, err = session.Unmatched(); err != nil {
		t.Fatalf("read the unmatched counter: %v", err)
	}
	if counts.dropped, err = session.Dropped(); err != nil {
		t.Fatalf("read the drop counter: %v", err)
	}
	if counts.unrecorded, err = session.Unrecorded(); err != nil {
		t.Fatalf("read the unrecorded counter: %v", err)
	}
	return got, counts
}

// bursting drives many request/response cycles over one connection, filling
// the ring buffer faster than a paused reader drains it.
func bursting(t *testing.T, port, requests int) {
	t.Helper()
	c := speaking(t, port)
	for i := 0; i < requests; i++ {
		if _, err := io.WriteString(c.send, "GET /marker HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
			return
		}
		// Read the response line and headers so the connection does not stall; the
		// next request's read drains the body.
		for j := 0; j < 3; j++ {
			if _, err := c.receive.ReadString('\n'); err != nil {
				return
			}
		}
		if _, err := c.receive.ReadString('\n'); err != nil { // the body
			return
		}
	}
}

// A transfer larger than a fragment holds is a record whose Length is the
// whole transfer and whose payload is what survived: a hole at the fragment's
// end, never a shift of later offsets (packages capture, fragment). A small
// transfer captured whole is the control.
func TestAnOversizedTransferIsTruncatedNotShifted(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, server), Admit: authorise(server)})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	c := speaking(t, port)
	c.ask(t, "/small")
	c.ask(t, "/size/40000")

	got := drain(session, 700*time.Millisecond)

	var whole, truncated bool
	for _, e := range got.events {
		if e.Kind != ebpf.Transfer || e.Direction != fragment.Sent || !e.Measured {
			continue
		}
		if e.Length > 0 && int(e.Length) == len(e.Payload) {
			whole = true // the control: a fully captured transfer
		}
		if e.Length > chunkForTest && len(e.Payload) == chunkForTest {
			truncated = true // Length is the whole transfer, payload is capped
		}
	}
	if !whole {
		t.Fatal("no transfer was captured whole; the control did not move, so a truncation proves nothing")
	}
	if !truncated {
		t.Error("the oversized transfer was not a truncated record with its full Length preserved")
	}
}

// chunkForTest mirrors OBS_CHUNK in bpf/ssl.bpf.h.
const chunkForTest = 4096

// The drop counter moves when the ring buffer is filled faster than drained
// and stays zero otherwise; a paused reader makes the fill happen.
func TestFillingTheRingBufferMovesTheDropCounter(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, server), Admit: authorise(server)})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Nothing reads session.Events(), so the channel and then the ring buffer
	// fill, and a large burst makes the kernel's reserve fail.
	bursting(t, port, 9000)
	time.Sleep(500 * time.Millisecond)

	dropped, err := session.Dropped()
	if err != nil {
		t.Fatalf("read the drop counter after a burst that overran the buffer: %v", err)
	}
	if dropped <= 0 {
		t.Errorf("the drop counter did not move under a burst that overran the buffer: %d", dropped)
	}
}

//go:embed testdata/peek_client.c
var peekClientSource []byte

// peekClient compiles and starts the C client that peeks and then reads the
// same bytes. It returns once libssl is mapped and a connection is open, before
// plaintext moves; proceed releases it, and the reader carries the client's own
// account.
func peekClient(t *testing.T, port int) (pid int32, proceed func(), out *bufio.Reader) {
	t.Helper()

	source := filepath.Join(t.TempDir(), "peek_client.c")
	if err := os.WriteFile(source, peekClientSource, 0o600); err != nil {
		t.Fatalf("write the peek client: %v", err)
	}
	binary := filepath.Join(t.TempDir(), "peek_client")
	build := exec.Command("cc", "-O2", "-o", binary, source, "-lssl", "-lcrypto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile the peek client: %v\n%s", err, output)
	}

	command := exec.Command(binary, fmt.Sprint(port))
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the peek client: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })

	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the peek client did not come up: %q %v", line, err)
	}
	return int32(command.Process.Pid), func() { _, _ = io.WriteString(stdin, "go\n") }, reader
}

// SSL_peek returns bytes a following SSL_read returns again. The observer does
// not probe SSL_peek, so a peek-then-read response is captured exactly once;
// that it is captured at all is the control.
func TestPeekDoesNotDuplicateBytesInTheStream(t *testing.T) {
	serverPID, port := serving(t)
	_ = serverPID

	clientPID, proceed, out := peekClient(t, port)
	client := loaded(t, clientPID)
	moveToCgroup(t, "obs-approved", client.PID)

	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, client), Admit: authorise(client)})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	proceed()
	// The client reports how many bytes it peeked and read: the same bytes.
	report, err := out.ReadString('\n')
	if err != nil {
		t.Fatalf("the peek client did not finish: %v", err)
	}
	var peeked, read int
	if _, err := fmt.Sscanf(report, "peeked %d read %d", &peeked, &read); err != nil {
		t.Fatalf("could not read the client's report %q: %v", report, err)
	}
	if peeked <= 0 || read <= 0 || peeked != read {
		t.Fatalf("the client did not peek and read the same bytes: peeked %d, read %d", peeked, read)
	}

	got := drain(session, 700*time.Millisecond)

	// Exactly one received transfer, the read; two would mean SSL_peek was probed.
	received := 0
	for _, e := range got.events {
		if e.Kind == ebpf.Transfer && e.Direction == fragment.Received && e.Measured {
			received++
		}
	}
	if received == 0 {
		t.Fatal("the read was not captured; the control did not move, so no deduplication is proved")
	}
	if received != 1 {
		t.Errorf("%d received transfers captured for one peek and one read; SSL_peek duplicated the bytes", received)
	}
}

//go:embed testdata/early_data.c
var earlyDataSource []byte

// earlyDataProcess compiles and starts the 0-RTT client-and-server program,
// returning once it holds a resumable session, so the observer attaches before
// the early-data round.
func earlyDataProcess(t *testing.T, cert, key string) (pid int32, proceed func(), out *bufio.Reader) {
	t.Helper()

	source := filepath.Join(t.TempDir(), "early_data.c")
	if err := os.WriteFile(source, earlyDataSource, 0o600); err != nil {
		t.Fatalf("write the early-data program: %v", err)
	}
	binary := filepath.Join(t.TempDir(), "early_data")
	build := exec.Command("cc", "-O2", "-o", binary, source, "-lssl", "-lcrypto", "-lpthread")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile the early-data program: %v\n%s", err, output)
	}

	command := exec.Command(binary, fmt.Sprint(freePort(t)), cert, key)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the early-data program: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })

	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the early-data program did not come up: %q %v", line, err)
	}
	return int32(command.Process.Pid), func() { _, _ = io.WriteString(stdin, "go\n") }, reader
}

// TLS 1.3 early data crosses before the handshake finishes, through
// SSL_write_early_data and SSL_read_early_data, whose count is an
// out-parameter. Ordinary traffic never exercises it, so this plants early
// data and requires a record marked early, with a real count, carrying it.
func TestEarlyDataIsCapturedWithARealCount(t *testing.T) {
	cert, key := certificate(t)
	pid, proceed, out := earlyDataProcess(t, cert, key)
	program := loaded(t, pid)
	moveToCgroup(t, "obs-approved", program.PID)

	pts := points(t, program)
	for _, pt := range pts {
		if strings.Contains(pt.Symbol, "early") {
			t.Logf("attached %s -> %s/%s", pt.Symbol, pt.Entry, pt.Return)
		}
	}
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: pts, Admit: authorise(program)})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	proceed()
	report, err := out.ReadString('\n')
	if err != nil {
		t.Fatalf("the early-data program did not finish: %v", err)
	}
	if !strings.HasPrefix(report, "early 1 ") {
		t.Fatalf("the program did not send early data: %q", report)
	}

	got := drain(session, 900*time.Millisecond)

	// The planted bytes cross once written and once read as early data, with the
	// real count and no third copy from the public call each makes internally.
	marker := "PLANTED-EARLY-DATA-MARKER"
	var sentEarly, receivedEarly, total int
	for _, e := range got.events {
		if e.Kind != ebpf.Transfer || !strings.Contains(string(e.Payload), marker) {
			continue
		}
		total++
		if !e.Early || !e.Measured || int(e.Length) != len(marker) {
			t.Errorf("the early bytes were reported wrong: early=%v measured=%v length=%d", e.Early, e.Measured, e.Length)
		}
		if e.Direction == fragment.Sent {
			sentEarly++
		}
		if e.Direction == fragment.Received {
			receivedEarly++
		}
	}
	if sentEarly != 1 || receivedEarly != 1 {
		t.Errorf("early data was not captured once in each direction: %d sent, %d received", sentEarly, receivedEarly)
	}
	if total != 2 {
		t.Errorf("the early bytes were captured %d times; the public call each early function makes internally was counted again", total)
	}
}

// unplaceable is a point the kernel cannot take (an offset far past the
// library's end), producing a refusal without breaking anything.
func unplaceable(from ebpf.Point) ebpf.Point {
	from.Symbol = "obs_no_such_place"
	from.Offset = 1 << 40
	return from
}

// What the kernel says it holds is read back and compared with what it was
// asked for, not inferred from placement calls that returned no error.
func TestTheKernelConfirmsEveryProbeTheSessionAskedItFor(t *testing.T) {
	serverPID, _ := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)
	asked := points(t, server)

	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: asked, Admit: authorise(server)})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = session.Close() }()

	confirmed := session.Confirmed()
	if len(confirmed) != len(asked) {
		t.Fatalf("%d probes confirmed against %d asked for", len(confirmed), len(asked))
	}
	for _, placement := range confirmed {
		if !placement.Confirmed {
			t.Errorf("the kernel does not confirm %s: %s", placement.Symbol, placement.Refusal)
			continue
		}
		if placement.Through == "" {
			t.Errorf("%s is confirmed and the report does not say what answered", placement.Symbol)
		}
	}
}

// Fewer taken than asked for: the session attaches, the refused point is named
// with the kernel's error, and the rest are confirmed.
func TestAProbeTheKernelRefusesIsNamedAndTheRestStillAttach(t *testing.T) {
	serverPID, _ := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)
	asked := points(t, server)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append(asked, unplaceable(asked[0])),
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach refused the whole session over one bad point: %v", err)
	}
	defer func() { _ = session.Close() }()

	var refused, confirmed int
	for _, placement := range session.Confirmed() {
		if placement.Symbol == "obs_no_such_place" {
			refused++
			if placement.Confirmed {
				t.Error("the kernel is said to hold a probe at an offset past the end of the library")
			}
			if placement.Refusal == "" {
				t.Error("a probe the kernel would not take carries no reason at all")
			}
			continue
		}
		if placement.Confirmed {
			confirmed++
		} else {
			t.Errorf("%s was not confirmed beside the refused point: %s", placement.Symbol, placement.Refusal)
		}
	}
	if refused != 1 {
		t.Errorf("%d refused points, want 1", refused)
	}
	if confirmed != len(asked) {
		t.Errorf("%d of %d good points confirmed beside a refused one", confirmed, len(asked))
	}
}

// A session that placed nothing looks like a quiet host, so it is an error
// carrying the kernel's words for every function.
func TestASessionThatPlacedNothingIsAnErrorNamingEveryFunction(t *testing.T) {
	serverPID, _ := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-approved", server.PID)

	var hopeless []ebpf.Point
	for _, point := range points(t, server) {
		hopeless = append(hopeless, unplaceable(point))
	}

	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: hopeless, Admit: authorise(server)})
	if err == nil {
		_ = session.Close()
		t.Fatal("a session that placed nothing came back as an attachment")
	}
	if !errors.Is(err, ebpf.ErrRefused) {
		t.Errorf("the error is not a refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "obs_no_such_place") {
		t.Errorf("the error does not name the functions the kernel would not take: %v", err)
	}
}
