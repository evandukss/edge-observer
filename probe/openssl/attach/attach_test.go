//go:build attach

// These tests attach real probes to real processes on a real kernel, so they
// need the privilege to load a BPF program and the host's pid namespace. They
// carry a build tag rather than sitting in the unit suite, where they would
// fail on every run without a kernel.
package attach_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// requesting is a request whose two halves agree: the processes an adapter
// inspects, and one admission per process. An adapter refuses a process no
// admission names (probe.Request.Admit).
func requesting(processes ...process.Process) probe.Request {
	request := probe.Request{Processes: processes}
	for _, p := range processes {
		request.Admit = append(request.Admit, admission.Selection{
			Instance:    p.Instance(),
			Kind:        admission.ByTarget,
			Provenance:  admission.Provenance{Target: p.Executable, Number: 1},
			Mode:        admission.ModeFollow,
			ObserverPID: p.PID,
		})
	}
	return request
}

const procfs = "/proc"

// tlsServer is an ordinary HTTPS server in another language, using whatever
// OpenSSL entry points its runtime chooses. It is not observed.
const tlsServer = `
import http.server, ssl, sys
port, certificate, key, root = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]

class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def __init__(self, *arguments, **named):
        super().__init__(*arguments, directory=root, **named)
    def log_message(self, *arguments):
        pass

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
`

type collected struct {
	mutex     sync.Mutex
	records   []fragment.Record
	transfers []probe.Transfer
	closed    []probe.Connection
}

func (c *collected) Write(record fragment.Record) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.records = append(c.records, record)
	return nil
}

func (c *collected) Transfer(t probe.Transfer) {
	c.mutex.Lock()
	c.transfers = append(c.transfers, t)
	c.mutex.Unlock()
}

func (c *collected) Closed(connection probe.Connection) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.closed = append(c.closed, connection)
}

func (c *collected) taken() []fragment.Record {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]fragment.Record(nil), c.records...)
}

func (c *collected) moved() []probe.Transfer {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]probe.Transfer(nil), c.transfers...)
}

func certificate(t *testing.T) (certificate, key string) {
	t.Helper()

	directory := t.TempDir()
	certificate = filepath.Join(directory, "cert.pem")
	key = filepath.Join(directory, "key.pem")

	command := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-subj", "/CN=localhost", "-keyout", key, "-out", certificate, "-days", "1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("make a certificate: %v\n%s", err, output)
	}
	return certificate, key
}

func free(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

// serving starts the HTTPS server and returns its port once ready. listening
// is the same server held as a process, for a test that approves it.
func serving(t *testing.T) int {
	t.Helper()
	_, port := listening(t)
	return port
}

// conversation is a client process holding an open TLS connection: a running,
// unmodified process, reached through no proxy and no certificate of ours.
type conversation struct {
	process process.Process
	send    io.WriteCloser
	receive *bufio.Reader
}

// speaking starts a TLS client against port and returns it once running with
// its libraries loaded.
func speaking(t *testing.T, port int) conversation {
	t.Helper()

	command := exec.Command("openssl", "s_client", "-quiet", "-no_ign_eof",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port))
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	receive, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a TLS client: %v", err)
	}
	t.Cleanup(func() {
		_ = send.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	return conversation{
		process: loaded(t, int32(command.Process.Pid)),
		send:    send,
		receive: bufio.NewReader(receive),
	}
}

// ask sends one request over the open connection and reads the first line back.
func (c conversation) ask(t *testing.T, path string) string {
	t.Helper()

	// A query on a resource that exists, so the answer is 200 and the connection
	// stays open; a 404 makes the server close it.
	if _, err := io.WriteString(c.send, "GET /?asked="+path+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("send a request: %v", err)
	}
	line, err := c.receive.ReadString('\n')
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	return line
}

func loaded(t *testing.T, pid int32) process.Process {
	t.Helper()

	for range 400 {
		table, err := process.Read(procfs)
		if err != nil {
			t.Fatalf("Read(%s): %v", procfs, err)
		}
		if p, ok := table.Lookup(pid); ok {
			mappings, err := process.Mappings(procfs, pid)
			if err == nil {
				for _, mapping := range mappings {
					if strings.Contains(mapping.Path, "libssl.so") && mapping.Executable {
						return p
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d has not loaded an OpenSSL library", pid)
	return process.Process{}
}

// records waits for at least this many records and returns what it has either
// way, so a shortfall is reported with its contents.
func records(t *testing.T, sink *collected, want int) []fragment.Record {
	t.Helper()

	var taken []fragment.Record
	for range 500 {
		if taken = sink.taken(); len(taken) >= want {
			return taken
		}
		time.Sleep(10 * time.Millisecond)
	}
	return taken
}
