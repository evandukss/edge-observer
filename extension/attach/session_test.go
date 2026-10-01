//go:build attach

package attach_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/internal/extensiontest"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

// The test binary serves the test extension when the observer starts it as
// one.
func TestMain(m *testing.M) {
	if extensiontest.Requested() {
		os.Exit(extensiontest.Serve())
	}
	os.Exit(m.Run())
}

const procfs = "/proc"

// built is the observer compiled as it ships: without cgo, which lets it give
// up its capabilities on every thread.
func built(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "observer")
	command := exec.Command("go", "build", "-o", binary, "github.com/evandukss/edge-observer/cmd/observer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the observer: %v\n%s", err, output)
	}
	return binary
}

// server answers every GET with 200 and a short body, keeping the connection
// open for the next request.
const server = `
import http.server, ssl, sys
port, certificate, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *arguments):
        pass
    def do_GET(self):
        payload = b"hello"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server = Server(("127.0.0.1", port), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
`

// serving starts the HTTPS server and returns its port once it is ready.
func serving(t *testing.T) int {
	t.Helper()
	directory := t.TempDir()
	certificate, key := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
		"/CN=localhost", "-keyout", key, "-out", certificate, "-days", "1").CombinedOutput(); err != nil {
		t.Fatalf("make a certificate: %v\n%s", err, output)
	}
	script := filepath.Join(directory, "server.py")
	if err := os.WriteFile(script, []byte(server), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	command := exec.Command("python3", script, strconv.Itoa(port), certificate, key)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the server did not come up: %q %v", line, err)
	}
	return port
}

// client is a TLS client process holding one open connection.
type client struct {
	command *exec.Cmd
	process process.Process
	send    io.WriteCloser
	receive *bufio.Reader
}

func speaking(t *testing.T, port int) *client {
	t.Helper()
	command := exec.Command("openssl", "s_client", "-quiet", "-no_ign_eof", "-connect", "127.0.0.1:"+strconv.Itoa(port))
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	receive, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a TLS client: %v", err)
	}
	t.Cleanup(func() { _ = send.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	c := &client{command: command, send: send, receive: bufio.NewReader(receive)}
	pid := int32(command.Process.Pid)
	for range 400 {
		if table, err := process.Read(procfs); err == nil {
			if p, ok := table.Lookup(pid); ok {
				if mappings, err := process.Mappings(procfs, pid); err == nil {
					for _, mapping := range mappings {
						if strings.Contains(mapping.Path, "libssl.so") && mapping.Executable {
							c.process = p
							return c
						}
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("wiring, not the property: pid %d never loaded an OpenSSL library", pid)
	return nil
}

// ask sends one request and reads its whole response.
func (c *client) ask(t *testing.T, path string) {
	t.Helper()
	if _, err := io.WriteString(c.send, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("send a request: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		length := -1
		if _, err := c.receive.ReadString('\n'); err != nil {
			done <- err
			return
		}
		for {
			header, err := c.receive.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if header == "\r\n" {
				break
			}
			if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
				length, _ = strconv.Atoi(strings.TrimSpace(value))
			}
		}
		_, err := io.ReadFull(c.receive, make([]byte, max(length, 0)))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wiring, not the property: reading the response failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("wiring, not the property: no complete response within 15 seconds")
	}
}

// hangUp closes the client's connection and waits for it to exit.
func (c *client) hangUp(t *testing.T) {
	t.Helper()
	_ = c.send.Close()
	done := make(chan struct{})
	go func() { _ = c.command.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("wiring, not the property: the client did not exit after its input closed")
	}
}

// envelope makes the bounded, no-swap cgroup the observer must be created
// into to activate, and removes it afterwards.
func envelope(t *testing.T) *os.File {
	t.Helper()
	name := "observer-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	directory := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("make cgroup %s: %v", directory, err)
	}
	t.Cleanup(func() {
		content, _ := os.ReadFile(filepath.Join(directory, "cgroup.procs"))
		own, _ := os.ReadFile("/proc/self/cgroup")
		home := filepath.Join("/sys/fs/cgroup", strings.TrimSpace(strings.TrimPrefix(string(own), "0::")))
		for _, pid := range strings.Fields(string(content)) {
			_ = os.WriteFile(filepath.Join(home, "cgroup.procs"), []byte(pid), 0o644)
		}
		_ = os.Remove(directory)
	})
	for setting, value := range map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"} {
		if err := os.WriteFile(filepath.Join(directory, setting), []byte(value), 0o644); err != nil {
			t.Fatalf("set %s on the observer's envelope: %v", setting, err)
		}
	}
	held, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	return held
}

// session is one observer run in the foreground.
type session struct {
	command   *exec.Cmd
	lines     *bufio.Scanner
	stdout    []string
	id        string
	directory string
	activated activationRecord
}

type activationRecord struct {
	Record     string              `json:"record"`
	Version    int                 `json:"version"`
	Session    string              `json:"session"`
	Extensions []account.Extension `json:"extensions"`
}

// started runs the observer over the configuration at path and returns once
// its log, mirrored on standard output, carries its activation record.
func started(t *testing.T, binary, path, output string) *session {
	t.Helper()
	command := exec.Command(binary, "start", path)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(envelope(t).Fd())}
	if err := command.Start(); err != nil {
		t.Fatalf("start the observer: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	s := &session{command: command, lines: bufio.NewScanner(out)}
	s.lines.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for s.lines.Scan() {
		s.stdout = append(s.stdout, s.lines.Text())
		var record activationRecord
		if json.Unmarshal(s.lines.Bytes(), &record) == nil && record.Record == "activation-completed" && record.Version == 1 {
			s.id, s.activated = record.Session, record
			s.directory = filepath.Join(output, "sessions", record.Session)
			return s
		}
	}
	_ = command.Wait()
	t.Fatalf("wiring, not the property: the observer never activated:\n%s", strings.Join(s.stdout, "\n"))
	return nil
}

// ended stops the session and returns the operational account it sealed.
func (s *session) ended(t *testing.T) account.Account {
	t.Helper()
	if err := s.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop the observer: %v", err)
	}
	for s.lines.Scan() {
		s.stdout = append(s.stdout, s.lines.Text())
	}
	if err := s.command.Wait(); err != nil {
		t.Fatalf("the observer exited with %v:\n%s", err, strings.Join(s.stdout, "\n"))
	}
	content, err := os.ReadFile(filepath.Join(s.directory, "account.json"))
	if err != nil {
		t.Fatalf("read the sealed account: %v", err)
	}
	var sealed account.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatalf("decode the sealed account: %v", err)
	}
	if sealed.Kind != account.Sealed || sealed.Session != s.id {
		t.Fatalf("the account beside session %s is a %s account of session %s", s.id, sealed.Kind, sealed.Session)
	}
	return sealed
}

// waitForLine waits until path holds a line containing want.
func waitForLine(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(path); err == nil && strings.Contains(string(content), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("wiring, not the property: %s never held %q", path, want)
}

// A session with one extension: the activation record listing the extension,
// labelled, is written before the extension is sent anything; every written
// exchange records the extension's outcome; the extension's derived records
// are in their own 0600 file; and the sealed account counts every exchange id
// the session issued at the extension, labelled, with nothing pending.
func TestASessionRunsAnExtensionAfterItsActivationRecordAndAccountsForEveryExchange(t *testing.T) {
	binary := built(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := speaking(t, serving(t))
	root := t.TempDir()
	output, log := filepath.Join(root, "state"), filepath.Join(root, "state", "observer.log")
	received, witness := filepath.Join(root, "received"), filepath.Join(root, "witness")
	report := filepath.Join(root, "report.json")
	does := extensiontest.Config{Summary: true, Received: received, Log: log, Witness: witness, Report: report,
		Changes: map[string]json.RawMessage{config.FieldResponseLine: json.RawMessage(
			`{"status": 200, "reason": "Seen", "protocol": "HTTP/1.1"}`)}}
	arguments := []string{}
	if len(c.process.Arguments) > 1 {
		arguments = c.process.Arguments[1:]
	}
	document := map[string]any{
		"version": config.FileVersion, "output": output, "log": log,
		"limits":    map[string]any{"output_mib": 1, "state_every_seconds": 1},
		"watch":     []any{map[string]any{"name": "client", "exe": c.process.Executable, "args": arguments, "children": config.ChildrenAll}},
		"libraries": []any{},
		"extensions": []any{map[string]any{"name": "recorder", "command": extensiontest.Command(self, does),
			"fields": []string{config.FieldRequestLine, config.FieldResponseLine}, "timeout_ms": 5000}},
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observer.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	s := started(t, binary, path, output)
	if len(s.activated.Extensions) != 1 || s.activated.Extensions[0].Name != "recorder" ||
		s.activated.Extensions[0].Effects != extension.Effects {
		t.Errorf("the activation record does not list the extension labelled %s: %+v", extension.Effects, s.activated.Extensions)
	}
	// The extension says it is ready right after its start witness: give the
	// observer time to read that, since an exchange reaching an extension
	// that is not ready skips it.
	waitForLine(t, witness, `"moment":"start"`)
	time.Sleep(time.Second)
	const asked = 3
	for i := range asked {
		c.ask(t, fmt.Sprintf("/item/%d", i))
	}
	c.hangUp(t)
	waitForLine(t, received, `"type":"connection_done"`)
	sealed := s.ended(t)

	// The extension was started after the observer gave up its capabilities:
	// it holds none, in any set, and cannot gain any.
	held, err := extensiontest.ReadHeld(report)
	if err != nil {
		t.Fatalf("wiring, not the property: %v", err)
	}
	for _, set := range []string{"CapPrm", "CapEff", "CapInh", "CapAmb"} {
		if held.Status[set] != "0000000000000000" {
			t.Errorf("the extension holds %s %q, want none", set, held.Status[set])
		}
	}
	if held.Status["NoNewPrivs"] != "1" {
		t.Errorf("the extension's NoNewPrivs is %q, want 1", held.Status["NoNewPrivs"])
	}

	// The ordering: what the extension saw of the log when it started and when
	// its first exchange arrived.
	moments, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	for _, moment := range []string{"start", "exchange"} {
		if !strings.Contains(string(moments), `{"activation_held":true,"moment":"`+moment+`"}`) {
			t.Errorf("at its %s the extension did not find the activation record listing it in the log:\n%s", moment, moments)
		}
	}

	// The approved output: read back by the reader, every line with its id
	// range, every written exchange with the extension's outcome.
	var exchanges, changed int
	var issued uint64
	err = processing.ReadArtifacts(os.DirFS(s.directory), func(a processing.Artifact) error {
		if a.ExchangeIDs == nil {
			return fmt.Errorf("connection %s's line carries no id range", a.Connection.ID)
		}
		if a.Route.Pipeline == config.ConnectionsPipeline {
			n, _ := strconv.ParseUint(a.ExchangeIDs.Count, 10, 64)
			issued += n
		}
		if a.Reconstruction == nil {
			return nil
		}
		exchanges += len(a.Reconstruction.Exchanges)
		for _, e := range a.Reconstruction.Exchanges {
			if e.Response.Message.Reason != "Seen" {
				t.Errorf("exchange %d of connection %s: response reason %q, want the extension's change", e.Index,
					a.Connection.ID, e.Response.Message.Reason)
			}
		}
		for _, o := range a.ExtensionOutcomes {
			if o.Extension == "recorder" && o.Outcome == extension.Changed {
				changed++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("the reader refused the session's approved output: %v", err)
	}
	if exchanges < asked {
		t.Fatalf("wiring, not the property: %d exchanges written, and %d were asked", exchanges, asked)
	}
	if changed != exchanges {
		t.Errorf("%d of %d written exchanges record the extension's change", changed, exchanges)
	}

	// The derived file: the extension's own, 0600, stamped.
	derivedPath := filepath.Join(s.directory, processing.DerivedName("recorder"))
	info, err := os.Stat(derivedPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the derived file is missing or not 0600: %v %v", info, err)
	}
	derived, _ := os.ReadFile(derivedPath)
	lines := strings.Split(strings.TrimSpace(string(derived)), "\n")
	var line struct {
		Version   string   `json:"version"`
		Extension string   `json:"extension"`
		Session   string   `json:"session"`
		Effects   string   `json:"effects"`
		Sources   []string `json:"sources"`
	}
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &line) != nil || line.Version != extension.DerivedVersion ||
		line.Extension != "recorder" || line.Session != s.id || line.Effects != extension.Effects || len(line.Sources) != exchanges {
		t.Errorf("the derived file does not hold the one stamped summary citing %d exchanges:\n%s", exchanges, derived)
	}

	// The sealed account: the ids issued, counted at the extension and
	// conserved, and the extension labelled.
	p := sealed.Processing
	if p == nil || p.ExchangeIDs != issued || issued < uint64(exchanges) {
		t.Fatalf("the sealed account's ids issued %v, and the lines' ranges cover %d", p, issued)
	}
	if len(p.Extensions) != 1 {
		t.Fatalf("the sealed account counts %d extensions, want 1", len(p.Extensions))
	}
	counts := p.Extensions[0]
	if counts.Considered != p.ExchangeIDs || counts.Changed+counts.Unchanged+counts.Failed+counts.Pending != counts.Considered ||
		counts.Pending != 0 || counts.Changed != uint64(changed) || counts.DerivedWritten != 1 {
		t.Errorf("the extension's counts do not conserve over %d ids: %+v", p.ExchangeIDs, counts)
	}
	if len(sealed.Extensions) != 1 || sealed.Extensions[0].Effects != extension.Effects {
		t.Errorf("the sealed account does not list the extension labelled %s: %+v", extension.Effects, sealed.Extensions)
	}
	contract, err := os.ReadFile(filepath.Join(s.directory, published.Name))
	if err != nil {
		t.Fatalf("read the contract account: %v", err)
	}
	var projected struct {
		Processing struct {
			ExchangeIDs string `json:"exchange_ids"`
			Extensions  map[string]struct {
				Effects    string `json:"effects"`
				Considered string `json:"considered"`
				Pending    string `json:"pending"`
			} `json:"extensions"`
		} `json:"processing"`
	}
	if err := json.Unmarshal(contract, &projected); err != nil {
		t.Fatalf("decode the contract account: %v", err)
	}
	recorder := projected.Processing.Extensions["recorder"]
	if recorder.Effects != extension.Effects || recorder.Considered != projected.Processing.ExchangeIDs ||
		recorder.Pending != "0" || projected.Processing.ExchangeIDs != strconv.FormatUint(issued, 10) {
		t.Errorf("the contract account's extension entry is %+v beside %s ids issued", recorder, projected.Processing.ExchangeIDs)
	}
}
