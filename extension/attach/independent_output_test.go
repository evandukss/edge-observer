//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/internal/extensiontest"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

// These cases run the built observer against a real TLS client and are
// written from the contract's output requirements, the approved line envelope
// (contract/record/record.md), docs/approved-inspection.md and
// contract/extension/PROTOCOL.md, not from the implementation. Readiness is
// read from the control channel (observer inspect), never from the log, since
// some of these cases make the log fail. The harness here is their own.

var obsBuild struct {
	once   sync.Once
	binary string
	output []byte
	err    error
}

// obsBinary is the observer built once for these cases, as it ships.
func obsBinary(t *testing.T) string {
	t.Helper()
	obsBuild.once.Do(func() {
		directory, err := os.MkdirTemp("", "independent-observer-")
		if err != nil {
			obsBuild.err = err
			return
		}
		obsBuild.binary = filepath.Join(directory, "observer")
		command := exec.Command("go", "build", "-o", obsBuild.binary, "github.com/evandukss/edge-observer/cmd/observer")
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		obsBuild.output, obsBuild.err = command.CombinedOutput()
	})
	if obsBuild.err != nil {
		t.Fatalf("wiring, not the property: build the observer: %v\n%s", obsBuild.err, obsBuild.output)
	}
	return obsBuild.binary
}

const obsServerScript = `
import http.server, ssl, sys
port, certificate, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *arguments):
        pass
    def do_GET(self):
        payload = b"answer"
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

// obsServing starts an HTTPS server keeping connections open, and returns its
// port once it is ready.
func obsServing(t *testing.T) int {
	t.Helper()
	directory := t.TempDir()
	certificate, key := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if output, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
		"/CN=localhost", "-keyout", key, "-out", certificate, "-days", "1").CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: make a certificate: %v\n%s", err, output)
	}
	script := filepath.Join(directory, "server.py")
	if err := os.WriteFile(script, []byte(obsServerScript), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("wiring, not the property: start the server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("wiring, not the property: the server did not come up: %q %v", line, err)
	}
	return port
}

// obsClient is a TLS client process holding one open connection.
type obsClient struct {
	command *exec.Cmd
	process process.Process
	send    io.WriteCloser
	receive *bufio.Reader
}

func obsSpeaking(t *testing.T, port int) *obsClient {
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
		t.Fatalf("wiring, not the property: start a TLS client: %v", err)
	}
	t.Cleanup(func() { _ = send.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	c := &obsClient{command: command, send: send, receive: bufio.NewReader(receive)}
	pid := int32(command.Process.Pid)
	for range 400 {
		if table, err := process.Read("/proc"); err == nil {
			if p, ok := table.Lookup(pid); ok {
				if mappings, err := process.Mappings("/proc", pid); err == nil {
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
func (c *obsClient) ask(t *testing.T, target string) {
	t.Helper()
	if _, err := io.WriteString(c.send, "GET "+target+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("wiring, not the property: send a request: %v", err)
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

// hangUp closes the connection, which retires it, and waits for the client.
func (c *obsClient) hangUp(t *testing.T) {
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

func obsWatch(name string, p process.Process) map[string]any {
	arguments := []string{}
	if len(p.Arguments) > 1 {
		arguments = p.Arguments[1:]
	}
	return map[string]any{"name": name, "exe": p.Executable, "args": arguments, "children": config.ChildrenAll}
}

// obsConfig is one configuration file and the stable paths it names.
type obsConfig struct {
	path, output, log string
}

func (c obsConfig) approved() string { return filepath.Join(c.output, processing.ArtifactName) }

// obsConfigure writes root/observer.json with output root/out, the log at log
// (root/out/observer.log where empty), state restated every second, and no
// output allowance: there is none to name.
func obsConfigure(t *testing.T, root, log string, watch, ignore []map[string]any, extensions []any) obsConfig {
	t.Helper()
	c := obsConfig{path: filepath.Join(root, "observer.json"), output: filepath.Join(root, "out"), log: log}
	if c.log == "" {
		c.log = filepath.Join(c.output, "observer.log")
	}
	if ignore == nil {
		ignore = []map[string]any{}
	}
	document := map[string]any{"version": config.FileVersion, "output": c.output, "log": c.log, "watch": watch,
		"ignore": ignore, "libraries": []any{}, "limits": map[string]any{"state_every_seconds": 1}}
	if extensions != nil {
		document["extensions"] = extensions
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// obsEnvelope makes the bounded, no-swap cgroup the observer must be created
// into to activate, and removes it afterwards. Setup, not evidence.
func obsEnvelope(t *testing.T, suffix string) *os.File {
	t.Helper()
	name := "independent-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name()) + "-" + suffix
	directory := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("wiring, not the property: make cgroup %s: %v", directory, err)
	}
	t.Cleanup(func() { obsEmptyCgroup(directory) })
	for setting, value := range map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"} {
		if err := os.WriteFile(filepath.Join(directory, setting), []byte(value), 0o644); err != nil {
			t.Fatalf("wiring, not the property: set %s on the observer's envelope: %v", setting, err)
		}
	}
	held, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	return held
}

// obsEmptyCgroup moves what is left in directory back to this process's own
// cgroup and removes it.
func obsEmptyCgroup(directory string) {
	content, _ := os.ReadFile(filepath.Join(directory, "cgroup.procs"))
	own, _ := os.ReadFile("/proc/self/cgroup")
	home := filepath.Join("/sys/fs/cgroup", strings.TrimSpace(strings.TrimPrefix(string(own), "0::")))
	for _, pid := range strings.Fields(string(content)) {
		_ = os.WriteFile(filepath.Join(home, "cgroup.procs"), []byte(pid), 0o644)
	}
	_ = os.Remove(directory)
}

// obsSession is one observer started in the foreground.
type obsSession struct {
	command *exec.Cmd
	output  string
	id      string
	done    chan error
}

func (s *obsSession) printed() string {
	content, _ := os.ReadFile(s.output)
	return string(content)
}

// obsLaunch starts the observer over c inside a fresh envelope, its standard
// output and error to a file.
func obsLaunch(t *testing.T, binary string, c obsConfig, suffix string, arguments ...string) *obsSession {
	t.Helper()
	s := &obsSession{output: filepath.Join(t.TempDir(), "printed"), done: make(chan error, 1)}
	printed, err := os.Create(s.output)
	if err != nil {
		t.Fatal(err)
	}
	s.command = exec.Command(binary, append([]string{"start", c.path}, arguments...)...)
	s.command.Stdout, s.command.Stderr = printed, printed
	s.command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(obsEnvelope(t, suffix).Fd())}
	if err := s.command.Start(); err != nil {
		t.Fatalf("wiring, not the property: start the observer: %v", err)
	}
	go func() { s.done <- s.command.Wait(); _ = printed.Close() }()
	t.Cleanup(func() {
		_ = s.command.Process.Kill()
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
		}
	})
	return s
}

// obsRecorded reports whether the observer's pid file names an activated
// session. It is read without a lock: observer inspect's own check of who
// holds the file takes a shared lock on it, and a start taking its exclusive
// lock at that moment refuses as if another observer were running, so the
// control channel is asked only once the session has recorded itself.
func obsRecorded(c obsConfig) bool {
	content, err := os.ReadFile(filepath.Join(c.output, "observer.pid"))
	return err == nil && len(strings.Fields(string(content))) == 2
}

// obsStart starts the observer and returns once the session answers on its
// control channel.
func obsStart(t *testing.T, binary string, c obsConfig, suffix string) *obsSession {
	t.Helper()
	s := obsLaunch(t, binary, c, suffix)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			s.done <- err
			t.Fatalf("the observer exited (%v) before its session answered:\n%s", err, s.printed())
		default:
		}
		if !obsRecorded(c) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if live, err := obsInspect(binary, c); err == nil && live.Kind == account.Live && live.Session != "" {
			s.id = live.Session
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("wiring, not the property: no session answered within 60s:\n%s", s.printed())
	return nil
}

func obsInspect(binary string, c obsConfig) (account.Account, error) {
	answer, err := exec.Command(binary, "inspect", c.path).Output()
	if err != nil {
		return account.Account{}, err
	}
	var live account.Account
	err = json.Unmarshal(answer, &live)
	return live, err
}

// obsStop runs observer stop and waits for the session's process to end. It
// returns what stop printed, how long it took and its error.
func obsStop(t *testing.T, binary string, c obsConfig, s *obsSession) (string, time.Duration, error) {
	t.Helper()
	began := time.Now()
	printed, err := exec.Command(binary, "stop", c.path).CombinedOutput()
	took := time.Since(began)
	select {
	case ended := <-s.done:
		s.done <- ended
	case <-time.After(30 * time.Second):
		t.Errorf("the observer had not ended 30s after stop returned:\n%s", s.printed())
	}
	return string(printed), took, err
}

// obsRecords is each LF-terminated record of path decoded, with the number of
// records that do not decode.
func obsRecords(t *testing.T, path string) ([]map[string]json.RawMessage, int) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var records []map[string]json.RawMessage
	damaged := 0
	for _, line := range bytes.Split(content, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var record map[string]json.RawMessage
		if json.Unmarshal(line, &record) != nil {
			damaged++
			continue
		}
		records = append(records, record)
	}
	return records, damaged
}

func obsText(record map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(record[key], &value)
	return value
}

// obsWaitFor waits up to 30s for path to exist and hold content satisfying
// ok. A wait whose failure is the property under test fails as the property;
// obsPrecondition is the same wait for something the case only stands on.
func obsWaitFor(t *testing.T, path, what string, ok func([]byte) bool) {
	t.Helper()
	if content, held, err := obsWaiting(path, ok); !held {
		t.Fatalf("%s never held %s within 30s (%d bytes, %v)", path, what, len(content), err)
	}
}

func obsPrecondition(t *testing.T, path, what string, ok func([]byte) bool) {
	t.Helper()
	if content, held, err := obsWaiting(path, ok); !held {
		t.Fatalf("wiring, not the property: %s never held %s within 30s (%d bytes, %v)", path, what, len(content), err)
	}
}

func obsWaiting(path string, ok func([]byte) bool) ([]byte, bool, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		content, err := os.ReadFile(path)
		if err == nil && ok(content) {
			return content, true, nil
		}
		if time.Now().After(deadline) {
			return content, false, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func obsHolds(marker string) func([]byte) bool {
	return func(content []byte) bool { return bytes.Contains(content, []byte(marker)) }
}

func obsLinesOf(session string, atLeast int) func([]byte) bool {
	return func(content []byte) bool {
		n := 0
		for _, line := range bytes.Split(content, []byte("\n")) {
			var record struct {
				Session string `json:"session"`
			}
			if json.Unmarshal(line, &record) == nil && record.Session == session {
				n++
			}
		}
		return n >= atLeast
	}
}

// obsDelivery is the delivery counts an operational account (observer inspect,
// or a sealed account.json) carries for one destination: "approved" at
// processing.delivery, "derived:<name>" at the processing.extensions entry of
// that name, "log:file" and "log:stdout" at log_destinations. Absence is not
// zero: an account without them fails the case.
func obsDelivery(t *testing.T, document []byte, destination string) sink.Stats {
	t.Helper()
	var account struct {
		Processing struct {
			Delivery   *sink.Stats `json:"delivery"`
			Extensions []struct {
				Name     string      `json:"name"`
				Delivery *sink.Stats `json:"delivery"`
			} `json:"extensions"`
		} `json:"processing"`
		LogDestinations map[string]*sink.Stats `json:"log_destinations"`
	}
	if err := json.Unmarshal(document, &account); err != nil {
		t.Fatalf("the account does not decode: %v", err)
	}
	var found *sink.Stats
	switch {
	case destination == "approved":
		found = account.Processing.Delivery
	case strings.HasPrefix(destination, "derived:"):
		for _, one := range account.Processing.Extensions {
			if one.Name == strings.TrimPrefix(destination, "derived:") {
				found = one.Delivery
			}
		}
	case strings.HasPrefix(destination, "log:"):
		found = account.LogDestinations[strings.TrimPrefix(destination, "log:")]
	}
	if found == nil {
		t.Fatalf("the account carries no delivery counts for %s", destination)
	}
	if found.Authorized != found.Written+found.Failed+found.Dropped+found.Pending {
		t.Errorf("%s: authorised %d is not written %d + failed %d + dropped %d + pending %d", destination,
			found.Authorized, found.Written, found.Failed, found.Dropped, found.Pending)
	}
	if found.Discarded > found.Dropped {
		t.Errorf("%s: discarded %d is more than dropped %d", destination, found.Discarded, found.Dropped)
	}
	return *found
}

func obsSealed(t *testing.T, c obsConfig, s *obsSession) []byte {
	t.Helper()
	sealed, err := os.ReadFile(filepath.Join(c.output, "sessions", s.id, "account.json"))
	if err != nil {
		t.Fatalf("the session sealed no account: %v", err)
	}
	return sealed
}

// Output lives at stable paths kept across sessions: a second session appends
// to the approved file the first wrote, every line names its session, and
// inspection given that file selects one session's lines and never the other's.
func TestIndependentOutputStablePathsKeepEachSessionsLinesAndInspectionFiltersBySession(t *testing.T) {
	binary := obsBinary(t)
	port := obsServing(t)
	root := t.TempDir()
	var c obsConfig
	var sessions []string
	markers := []string{"first-session", "second-session"}
	for _, marker := range markers {
		client := obsSpeaking(t, port)
		c = obsConfigure(t, root, "", []map[string]any{obsWatch("client", client.process)}, nil, nil)
		s := obsStart(t, binary, c, marker)
		client.ask(t, "/"+marker+"-0")
		client.ask(t, "/"+marker+"-1")
		client.hangUp(t)
		obsWaitFor(t, c.approved(), "three lines of session "+s.id, obsLinesOf(s.id, 3))
		if printed, _, err := obsStop(t, binary, c, s); err != nil {
			t.Fatalf("wiring, not the property: stopping session %s failed: %v\n%s", s.id, err, printed)
		}
		sessions = append(sessions, s.id)
	}

	records, damaged := obsRecords(t, c.approved())
	if damaged != 0 {
		t.Errorf("%s holds %d records that do not decode, with no failure in either session", c.approved(), damaged)
	}
	var order []string
	for _, record := range records {
		session := obsText(record, "session")
		if session != sessions[0] && session != sessions[1] {
			t.Errorf("a line names session %q, which is neither %v", session, sessions)
		}
		if len(order) == 0 || order[len(order)-1] != session {
			order = append(order, session)
		}
	}
	if len(order) != 2 || order[0] != sessions[0] || order[1] != sessions[1] {
		t.Errorf("the stable file holds sessions in the runs %v, want all of %s's lines and then all of %s's",
			order, sessions[0], sessions[1])
	}

	for i, id := range sessions {
		other := sessions[1-i]
		printed, err := exec.Command(binary, "inspect", filepath.Join(c.output, "sessions", id), "--text",
			"--file", c.approved(), "--session", id).CombinedOutput()
		if err != nil {
			t.Errorf("inspecting session %s from %s failed: %v\n%s", id, c.approved(), err, printed)
			continue
		}
		if !bytes.Contains(printed, []byte(markers[i]+"-0")) || !bytes.Contains(printed, []byte(`"session": "`+id+`"`)) {
			t.Errorf("inspecting session %s does not show its own exchanges:\n%s", id, printed)
		}
		if bytes.Contains(printed, []byte(other)) || bytes.Contains(printed, []byte(markers[1-i])) {
			t.Errorf("inspecting session %s shows a line of session %s", id, other)
		}
	}
	// The option selects the session whichever session's directory is read, so
	// it is asked for the other one than the directory's own account names.
	crossed, err := exec.Command(binary, "inspect", filepath.Join(c.output, "sessions", sessions[0]), "--text",
		"--file", c.approved(), "--session", sessions[1]).CombinedOutput()
	if err != nil {
		t.Errorf("inspecting session %s's directory for session %s failed: %v\n%s", sessions[0], sessions[1], err, crossed)
	} else if !bytes.Contains(crossed, []byte(markers[1]+"-0")) || bytes.Contains(crossed, []byte(markers[0]+"-")) {
		t.Errorf("--session %s over session %s's directory did not select %s's lines alone:\n%s", sessions[1],
			sessions[0], sessions[1], crossed)
	}
}

// After the approved, derived and log files are renamed and observer reopen is
// acknowledged, new records go to new files at the stable paths, nothing more
// reaches the renamed ones, and every record in all six files is whole.
func TestIndependentOutputAReopenAfterRotationMovesApprovedDerivedAndLogToNewFiles(t *testing.T) {
	binary := obsBinary(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	port := obsServing(t)
	before, after := obsSpeaking(t, port), obsSpeaking(t, port)
	root := t.TempDir()
	size, witness := filepath.Join(root, "derived-size"), filepath.Join(root, "witness")
	log := filepath.Join(root, "out", "observer.log")
	does := extensiontest.Config{DerivedSizeFile: size, Log: log, Witness: witness}
	c := obsConfigure(t, root, log, []map[string]any{obsWatch("client", before.process)}, nil,
		[]any{map[string]any{"name": "tap", "command": extensiontest.Command(self, does),
			"fields": []string{config.FieldRequestLine}, "timeout_ms": 5000}})
	derived := filepath.Join(c.output, processing.DerivedName("tap"))
	files := []string{c.approved(), derived, c.log}

	s := obsStart(t, binary, c, "rotation")
	obsPrecondition(t, witness, "the extension's start", obsHolds(`"moment":"start"`))
	time.Sleep(time.Second)
	if err := os.WriteFile(size, []byte("64"), 0o600); err != nil {
		t.Fatal(err)
	}
	before.ask(t, "/before-rotation")
	before.hangUp(t)
	obsWaitFor(t, c.approved(), "the exchange before rotation", obsHolds("before-rotation"))
	obsWaitFor(t, derived, "a derived record", obsLinesOf(s.id, 1))
	obsPrecondition(t, c.log, "a log record", func(content []byte) bool { return len(content) > 0 })

	for _, file := range files {
		if err := os.Rename(file, file+".1"); err != nil {
			t.Fatal(err)
		}
	}
	printed, err := exec.Command(binary, "reopen", c.path).CombinedOutput()
	if err != nil {
		t.Fatalf("observer reopen after rotation was not acknowledged: %v\n%s", err, printed)
	}
	acknowledged := map[string]int64{}
	for _, file := range files {
		info, err := os.Stat(file + ".1")
		if err != nil {
			t.Fatal(err)
		}
		acknowledged[file] = info.Size()
	}

	if err := os.WriteFile(size, []byte("64"), 0o600); err != nil {
		t.Fatal(err)
	}
	after.ask(t, "/after-rotation")
	after.hangUp(t)
	obsWaitFor(t, c.approved(), "the exchange after rotation in the new approved file", obsHolds("after-rotation"))
	obsWaitFor(t, derived, "a derived record in the new derived file", obsLinesOf(s.id, 1))
	obsWaitFor(t, c.log, "a record in the new log", func(content []byte) bool { return len(content) > 0 })
	time.Sleep(1500 * time.Millisecond)
	if printed, _, err := obsStop(t, binary, c, s); err != nil {
		t.Errorf("stopping the session failed: %v\n%s", err, printed)
	}
	sealed := obsSealed(t, c, s)
	for _, destination := range []string{"approved", "derived:tap", "log:file"} {
		if counts := obsDelivery(t, sealed, destination); counts.Failed != 0 || counts.Dropped != 0 || counts.Written == 0 {
			t.Errorf("%s across the rotation counts written %d, failed %d, dropped %d; want some written and "+
				"nothing failed or dropped: %+v", destination, counts.Written, counts.Failed, counts.Dropped, counts)
		}
	}

	for _, file := range files {
		info, err := os.Stat(file + ".1")
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != acknowledged[file] {
			t.Errorf("%s.1 grew from %d to %d bytes after the reopen was acknowledged", file, acknowledged[file], info.Size())
		}
		for _, one := range []string{file, file + ".1"} {
			if _, damaged := obsRecords(t, one); damaged != 0 {
				t.Errorf("%s holds %d records that do not decode", one, damaged)
			}
		}
	}
	old, _ := os.ReadFile(c.approved() + ".1")
	fresh, _ := os.ReadFile(c.approved())
	if bytes.Contains(old, []byte("after-rotation")) || bytes.Contains(fresh, []byte("before-rotation")) {
		t.Error("an exchange is in the approved file of the other side of the reopen")
	}
}

// A log that cannot be written at activation does not prevent the session:
// readiness is separate from log delivery, and capture goes on.
func TestIndependentOutputALogUnwritableAtActivationDoesNotPreventMonitoring(t *testing.T) {
	binary := obsBinary(t)
	client := obsSpeaking(t, obsServing(t))
	root := t.TempDir()
	log := filepath.Join(root, "log-is-a-directory")
	// A directory where the log belongs: it cannot be opened for writing.
	if err := os.Mkdir(log, 0o700); err != nil {
		t.Fatal(err)
	}
	c := obsConfigure(t, root, log, []map[string]any{obsWatch("client", client.process)}, nil, nil)
	s := obsStart(t, binary, c, "unwritable-log")
	client.ask(t, "/log-unwritable")
	client.hangUp(t)
	obsWaitFor(t, c.approved(), "the exchange made with the log unwritable", obsHolds("log-unwritable"))
	if printed, _, err := obsStop(t, binary, c, s); err != nil {
		t.Errorf("stopping a session whose log was never writable failed: %v\n%s", err, printed)
	}
	if counts := obsDelivery(t, obsSealed(t, c, s), "log:file"); counts.Failed == 0 || counts.Written != 0 {
		t.Errorf("a log file that could never be opened counts failed %d and written %d, want at least 1 and 0: %+v",
			counts.Failed, counts.Written, counts)
	}
}

// A log that fails in the middle of a session costs log records, never the
// session: capture goes on and the session stops cleanly.
func TestIndependentOutputALogFailingMidSessionDoesNotStopMonitoring(t *testing.T) {
	binary := obsBinary(t)
	client := obsSpeaking(t, obsServing(t))
	root := t.TempDir()
	volume := filepath.Join(root, "log-volume")
	if err := os.Mkdir(volume, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("tmpfs", volume, "tmpfs", 0, "size=256k"); err != nil {
		t.Fatalf("wiring, not the property: mount a small filesystem for the log: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(volume, syscall.MNT_DETACH) })
	log := filepath.Join(volume, "observer.log")
	c := obsConfigure(t, root, log, []map[string]any{obsWatch("client", client.process)}, nil, nil)
	s := obsStart(t, binary, c, "failing-log")
	obsPrecondition(t, log, "a log record", func(content []byte) bool { return len(content) > 0 })

	filler, err := os.Create(filepath.Join(volume, "filler"))
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("f"), 4096)
	for {
		if _, err := filler.Write(chunk); err != nil {
			break
		}
	}
	_ = filler.Close()
	var free unix.Statfs_t
	if err := unix.Statfs(volume, &free); err != nil || free.Bavail != 0 {
		t.Fatalf("wiring, not the property: the log's filesystem has %d blocks available (%v), so the log is not failing",
			free.Bavail, err)
	}
	// The precondition: a log write has failed while the session runs. A full
	// filesystem alone is not that, since an append can still fit the last
	// partly used page of the log; state is restated every second.
	var failed uint64
	for deadline := time.Now().Add(30 * time.Second); failed == 0 && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if live, err := exec.Command(binary, "inspect", c.path).Output(); err == nil {
			failed = obsDelivery(t, live, "log:file").Failed
		}
	}
	if failed == 0 {
		t.Fatalf("wiring, not the property: no log write failed within 30s of filling the log's filesystem")
	}
	// Past two more state records, the session still answers, and its log is
	// still failing rather than stopped.
	time.Sleep(2500 * time.Millisecond)
	if live, err := exec.Command(binary, "inspect", c.path).Output(); err != nil {
		t.Errorf("the session no longer answers after its log failed: %v\n%s", err, s.printed())
	} else if later := obsDelivery(t, live, "log:file").Failed; later <= failed {
		t.Errorf("log failures did not grow past %d over two state records (%d): the session stopped restating", failed, later)
	}
	client.ask(t, "/log-failing")
	client.hangUp(t)
	obsWaitFor(t, c.approved(), "the exchange made with the log failing", obsHolds("log-failing"))
	if printed, _, err := obsStop(t, binary, c, s); err != nil {
		t.Errorf("stopping a session whose log failed mid-session failed: %v\n%s", err, printed)
	}
	if counts := obsDelivery(t, obsSealed(t, c, s), "log:file"); counts.Failed == 0 || counts.Written == 0 {
		t.Errorf("a log that took records and then failed counts written %d and failed %d, want both above 0: %+v",
			counts.Written, counts.Failed, counts)
	}
}

// obsFIFO makes a FIFO at path, opens its read end and fills the pipe, so the
// observer's next write to it blocks. It returns the read end.
func obsFIFO(t *testing.T, path string) int {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("wiring, not the property: make a FIFO: %v", err)
	}
	reader, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("wiring, not the property: open the FIFO's read end: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(reader) })
	if _, err := unix.FcntlInt(uintptr(reader), unix.F_SETPIPE_SZ, 4096); err != nil {
		t.Fatalf("wiring, not the property: shrink the pipe: %v", err)
	}
	writer, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("wiring, not the property: open the FIFO's write end: %v", err)
	}
	defer func() { _ = syscall.Close(writer) }()
	filler := bytes.Repeat([]byte("f"), 1<<16)
	for {
		if _, err := syscall.Write(writer, filler); errors.Is(err, syscall.EAGAIN) {
			return reader
		} else if err != nil {
			t.Fatalf("wiring, not the property: fill the pipe: %v", err)
		}
	}
}

// observer stop with the approved destination blocked and lines pending
// returns within stop's bound with the session sealed, and the lines still
// pending are counted as discarded.
func TestIndependentOutputStopWithABlockedSinkIsBoundedAndCountsPendingAsDiscarded(t *testing.T) {
	binary := obsBinary(t)
	client := obsSpeaking(t, obsServing(t))
	root := t.TempDir()
	c := obsConfigure(t, root, "", []map[string]any{obsWatch("client", client.process)}, nil, nil)
	obsFIFO(t, c.approved())
	s := obsStart(t, binary, c, "blocked-sink")
	for i := range 3 {
		client.ask(t, fmt.Sprintf("/blocked-%d", i))
	}
	client.hangUp(t)
	deadline := time.Now().Add(20 * time.Second)
	var held sink.Stats
	for time.Now().Before(deadline) {
		if live, err := exec.Command(binary, "inspect", c.path).Output(); err == nil {
			if held = obsDelivery(t, live, "approved"); held.Pending > 0 {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if held.Pending == 0 {
		t.Fatalf("wiring, not the property: within 20s the live account shows no approved line pending (%+v), "+
			"so stop below discards nothing", held)
	}

	printed, took, err := obsStop(t, binary, c, s)
	if err != nil {
		t.Errorf("observer stop with a blocked destination failed after %v: %v\n%s", took, err, printed)
	}
	t.Logf("observer stop took %v with the approved destination blocked", took)
	sealed := obsDelivery(t, obsSealed(t, c, s), "approved")
	if sealed.Pending != 0 || sealed.Discarded == 0 || sealed.Written != 0 {
		t.Errorf("sealed approved counts: pending %d, discarded %d, written %d; want 0, at least 1, and 0 (the "+
			"destination never moved): %+v", sealed.Pending, sealed.Discarded, sealed.Written, sealed)
	}
}

// An approved file that cannot be opened at start does not prevent the
// session; once the path can be opened, an acknowledged reopen recovers it.
func TestIndependentOutputAnApprovedFileUnavailableAtStartRecoversByReopen(t *testing.T) {
	binary := obsBinary(t)
	port := obsServing(t)
	first, second := obsSpeaking(t, port), obsSpeaking(t, port)
	root := t.TempDir()
	c := obsConfigure(t, root, "", []map[string]any{obsWatch("client", first.process)}, nil, nil)
	if err := os.MkdirAll(c.approved(), 0o700); err != nil {
		t.Fatal(err)
	}
	s := obsStart(t, binary, c, "unavailable")
	first.ask(t, "/while-unavailable")
	first.hangUp(t)
	time.Sleep(2 * time.Second)
	if err := os.Remove(c.approved()); err != nil {
		t.Fatalf("wiring, not the property: the directory in the approved file's place could not be removed: %v", err)
	}
	if printed, err := exec.Command(binary, "reopen", c.path).CombinedOutput(); err != nil {
		t.Fatalf("observer reopen once the path could be opened was not acknowledged: %v\n%s", err, printed)
	}
	second.ask(t, "/after-recovery")
	second.hangUp(t)
	obsWaitFor(t, c.approved(), "the exchange after recovery", obsHolds("after-recovery"))
	if content, _ := os.ReadFile(c.approved()); bytes.Contains(content, []byte("while-unavailable")) {
		t.Error("a line that failed while the destination was unavailable was written after recovery")
	}
	if printed, _, err := obsStop(t, binary, c, s); err != nil {
		t.Errorf("stopping the session failed: %v\n%s", err, printed)
	}
	// Each connection is at least one exchange line and its connection line.
	if counts := obsDelivery(t, obsSealed(t, c, s), "approved"); counts.Failed < 2 || counts.Written < 2 {
		t.Errorf("approved counts failed %d and written %d, want at least 2 each (the connection made while "+
			"unavailable, and the one after recovery): %+v", counts.Failed, counts.Written, counts)
	}
}
