//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/processing"
)

// liveServerSource is an HTTPS server in another language whose answer is chosen
// by the path, so one server gives every case the exchange it needs:
//
//	/blob  3000 bytes, which a client reads in one call, below the 4096 bytes one
//	       event carries, so a run of them is decidable and fills output quickly
//	/mega  one mebibyte, read in calls larger than an event carries, so each one
//	       costs the ring and the volatile intake a full event
//	/upgrade  an answer naming an Upgrade, which processing does not read
//
// Anything else answers with a short body naming the request. The headers and
// the body are written separately, every answer states its length, and the
// connection stays open.
const liveServerSource = `
import http.server, ssl, sys
port, certificate, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *arguments):
        pass
    def do_GET(self):
        path = self.path.split("?")[0]
        extra = []
        if path == "/blob":
            body = b"b" * 3000
        elif path == "/mega":
            body = b"m" * (1 << 20)
        elif path == "/upgrade":
            body = b"an answer processing does not read"
            extra.append(("Upgrade", "h2c"))
        else:
            body = ("answered " + self.path).encode()
        self.send_response(200)
        for name, value in extra:
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
`

// liveServing starts liveServerSource and returns its port once it answers.
func liveServing(t *testing.T) int {
	t.Helper()
	certificate, key := certificate(t)
	script := filepath.Join(t.TempDir(), "server.py")
	if err := os.WriteFile(script, []byte(liveServerSource), 0o600); err != nil {
		t.Fatalf("write the server: %v", err)
	}
	port := free(t)
	command := exec.Command("python3", script, strconv.Itoa(port), certificate, key)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the server did not come up: %q %v", line, err)
	}
	return port
}

// liveExchange sends one GET for path over the open connection, with these
// header lines, and reads the whole answer back by its stated length. The
// duration runs from the request's write to the answer's last byte. It
// returns an error rather than failing, so it can run where the test cannot
// stop: beside a held barrier that must be released whatever happens.
func liveExchange(c conversation, path string, headers ...string) (time.Duration, error) {
	began := time.Now()
	request := "GET " + path + " HTTP/1.1\r\nHost: localhost\r\n"
	for _, header := range headers {
		request += header + "\r\n"
	}
	if _, err := io.WriteString(c.send, request+"\r\n"); err != nil {
		return 0, fmt.Errorf("send a request for %s: %w", path, err)
	}
	status, err := c.receive.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		return 0, fmt.Errorf("the server answered %s with %q, %v", path, status, err)
	}
	length := int64(-1)
	for {
		header, err := c.receive.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("read the headers answering %s: %w", path, err)
		}
		if header == "\r\n" {
			break
		}
		if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
			if length, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64); err != nil {
				return 0, fmt.Errorf("the answer to %s states a length of %q", path, value)
			}
		}
	}
	if length < 0 {
		return 0, fmt.Errorf("the answer to %s states no length, so its end cannot be read", path)
	}
	if _, err := io.CopyN(io.Discard, c.receive, length); err != nil {
		return 0, fmt.Errorf("read the %d-byte answer to %s: %w", length, path, err)
	}
	return time.Since(began), nil
}

func liveAsk(t *testing.T, c conversation, path string, headers ...string) time.Duration {
	t.Helper()
	took, err := liveExchange(c, path, headers...)
	if err != nil {
		t.Fatal(err)
	}
	return took
}

// liveHangup ends the client's input. The client (openssl s_client -no_ign_eof)
// then shuts the connection down and frees it, which the observer sees as the
// connection's close.
func liveHangup(c conversation) { _ = c.send.Close() }

// liveEdit rewrites c's configuration through edit, which receives the document
// configuring wrote.
func liveEdit(t *testing.T, c configured, edits ...func(document map[string]any)) {
	t.Helper()
	content, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("read %s: %v", c.path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode %s: %v", c.path, err)
	}
	for _, edit := range edits {
		edit(document)
	}
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(c.path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
}

// liveSetting sets one member of the configuration's limits.
func liveSetting(name string, value any) func(map[string]any) {
	return func(document map[string]any) {
		limits, _ := document["limits"].(map[string]any)
		if limits == nil {
			limits = map[string]any{}
			document["limits"] = limits
		}
		limits[name] = value
	}
}

// liveRemoving makes the configuration remove the authorization header.
func liveRemoving(document map[string]any) {
	document["remove"] = map[string]any{"headers": []any{"authorization"}}
}

// liveSession is one foreground observer whose standard output is read as it
// comes, so a run lasting longer than a pipe's buffer of log never blocks it.
type liveSession struct {
	running
	exited   chan struct{}
	signaled bool

	mutex sync.Mutex
	log   []string
	err   error
	state *os.ProcessState
}

func liveStarted(t *testing.T, binary string, c configured) *liveSession {
	t.Helper()
	observer := started(t, binary, c)
	s := &liveSession{running: observer, exited: make(chan struct{}), log: append([]string(nil), observer.header...)}
	go func() {
		for observer.lines.Scan() {
			s.mutex.Lock()
			s.log = append(s.log, observer.lines.Text())
			s.mutex.Unlock()
		}
		err := observer.command.Wait()
		s.mutex.Lock()
		s.err, s.state = err, observer.command.ProcessState
		s.mutex.Unlock()
		close(s.exited)
	}()
	return s
}

func (s *liveSession) pid() int { return s.command.Process.Pid }

func (s *liveSession) ended() bool {
	select {
	case <-s.exited:
		return true
	default:
		return false
	}
}

// awaited waits for the session to end, by itself or because it was
// signalled, and fails if it has not within the bound.
func (s *liveSession) awaited(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-s.exited:
	case <-time.After(within):
		t.Fatalf("the session had not ended %s later:\n%s", within, s.transcript())
	}
}

// stop signals the session to stop and returns the account it sealed.
func (s *liveSession) stop(t *testing.T, c configured) account.Account {
	t.Helper()
	s.signaled = true
	if err := s.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop the observer: %v", err)
	}
	s.awaited(t, liveStopWithin)
	if s.err != nil {
		t.Fatalf("the observer exited with %v:\n%s", s.err, s.transcript())
	}
	return liveSealed(t, s.directory(c), s.session)
}

// liveStopWithin is the drain's bound, the seal's writes and a margin.
const liveStopWithin = 60 * time.Second

func (s *liveSession) transcript() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return strings.Join(s.log, "\n")
}

// records is every log record of this kind the session printed.
func (s *liveSession) records(kind string) []map[string]any {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	var found []map[string]any
	for _, line := range s.log {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil && record["record"] == kind {
			found = append(found, record)
		}
	}
	return found
}

// liveSealed is the account a session sealed beside its approved output.
func liveSealed(t *testing.T, directory, session string) account.Account {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, "account.json"))
	if err != nil {
		t.Fatalf("read the sealed account: %v", err)
	}
	var sealed account.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatalf("decode the sealed account: %v", err)
	}
	if sealed.Kind != account.Sealed || sealed.Session != session {
		t.Fatalf("the account beside session %s is a %s account of session %q", session, sealed.Kind, sealed.Session)
	}
	return sealed
}

// liveUntil asks the running session for its live account until ready accepts
// one, and returns it.
func liveUntil(t *testing.T, binary string, c configured, within time.Duration, why string, ready func(account.Account) bool) account.Account {
	t.Helper()
	var live account.Account
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if live = inspected(t, binary, c); ready(live) {
			return live
		}
	}
	processed, _ := json.Marshal(live.Processing)
	seen, _ := json.Marshal(live.Seen)
	t.Fatalf("%s: not reached in %s; the live account says processing %s, seen %s", why, within, processed, seen)
	return live
}

func liveWritten(a account.Account) uint64 {
	if a.Processing == nil {
		return 0
	}
	return a.Processing.Written
}

// liveAdmitted is the decoded events that passed the delivery gate: each one
// is handed to capture exactly once, as a transfer or as an ending.
func liveAdmitted(a account.Account) int64 {
	if a.Seen == nil {
		return -1
	}
	return a.Seen.Transfers + a.Seen.Closed + a.Seen.EndingsUnmatched
}

// liveArtifact is an approved record as its JSON line holds it, read here
// rather than through the repository's reader.
type liveArtifact struct {
	Route struct {
		Pipeline string `json:"pipeline"`
	} `json:"route"`
	Reconstruction *struct {
		Exchanges []struct {
			Request struct {
				Message *struct {
					Target  string          `json:"target"`
					Headers json.RawMessage `json:"headers"`
				} `json:"message"`
			} `json:"request"`
		} `json:"exchanges"`
	} `json:"reconstruction"`
	PolicyExclusions []struct {
		Field       string `json:"field"`
		Disposition string `json:"disposition"`
	} `json:"policy_exclusions"`
}

// sessionApproved is the approved output of the session whose directory is
// directory (<output>/sessions/<id>): the lines of the stable approved file
// under the configured output directory that name that session, in order. A
// line that does not decode is kept, so a reader of the result fails on it.
func sessionApproved(directory string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(directory)), processing.ArtifactName))
	if err != nil {
		return nil, err
	}
	session := filepath.Base(directory)
	var kept []byte
	for _, line := range bytes.SplitAfter(content, []byte{'\n'}) {
		var one struct {
			Session string `json:"session"`
		}
		if len(line) != 0 && (json.Unmarshal(line, &one) != nil || one.Session == session) {
			kept = append(kept, line...)
		}
	}
	return kept, nil
}

// liveApproved is every line of a session's approved output, decoded. A line
// that is not a whole record fails the case.
func liveApproved(t *testing.T, directory string) []liveArtifact {
	t.Helper()
	content, err := sessionApproved(directory)
	if err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	return liveDecoded(t, content)
}

// liveApprovedIn is every line of the approved file a writer opened on
// directory, decoded, for a case that runs the writer in-process.
func liveApprovedIn(t *testing.T, directory string) []liveArtifact {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, processing.ArtifactName))
	if err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	return liveDecoded(t, content)
}

func liveDecoded(t *testing.T, content []byte) []liveArtifact {
	t.Helper()
	var found []liveArtifact
	if len(content) == 0 {
		return found
	}
	if content[len(content)-1] != '\n' {
		t.Fatalf("the approved output ends in an unterminated line")
	}
	for number, line := range bytes.Split(content[:len(content)-1], []byte{'\n'}) {
		var one liveArtifact
		if err := json.Unmarshal(line, &one); err != nil {
			t.Fatalf("approved output line %d is not a record: %v", number+1, err)
		}
		found = append(found, one)
	}
	return found
}

// liveTargets is every request target in these records' reconstructions.
func liveTargets(records []liveArtifact) []string {
	var targets []string
	for _, one := range records {
		if one.Reconstruction == nil {
			continue
		}
		for _, exchange := range one.Reconstruction.Exchanges {
			if exchange.Request.Message != nil {
				targets = append(targets, exchange.Request.Message.Target)
			}
		}
	}
	return targets
}

// liveExcluded counts the policy exclusions of this header name the records
// carry. The observer writes observer.approved/2, where a header entry is the
// field message.headers.<name> with disposition removed and has no name
// (docs/approved-inspection.md).
func liveExcluded(records []liveArtifact, name string) int {
	count := 0
	for _, one := range records {
		for _, excluded := range one.PolicyExclusions {
			if excluded.Field == "message.headers."+name && excluded.Disposition == "removed" {
				count++
			}
		}
	}
	return count
}

// liveHolding is every file under root whose bytes contain needle.
func liveHolding(t *testing.T, root, needle string) []string {
	t.Helper()
	var holding []string
	examined := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		examined++
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, []byte(needle)) {
			holding = append(holding, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("examine %s: %v", root, err)
	}
	if examined == 0 {
		t.Fatalf("wiring, not the property: %s holds no file, so a search of it for %q proves nothing", root, needle)
	}
	return holding
}

// liveFiles is every regular file under root, by its path relative to root.
func liveFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("list %s: %v", root, err)
	}
	return files
}

// liveEnvelope is a cgroup made for one start and written with these settings.
// envelopeFor exists so an observer can start at all; this one is written to
// be wrong where a case needs it wrong.
func liveEnvelope(t *testing.T, settings map[string]string) string {
	t.Helper()
	directory := cgroupFor(t, "liv-"+strings.NewReplacer("/", "-", " ", "-").Replace(t.Name()))
	for _, setting := range []string{"memory.max", "memory.swap.max"} {
		if value, set := settings[setting]; set {
			if err := os.WriteFile(filepath.Join(directory, setting), []byte(value), 0o644); err != nil {
				t.Fatalf("set %s to %s on %s: %v", setting, value, directory, err)
			}
		}
	}
	return directory
}

// liveInto creates cmd into the cgroup at directory.
func liveInto(t *testing.T, cmd *exec.Cmd, directory string) {
	t.Helper()
	held, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { _ = held.Close() })
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(held.Fd())}
}

// liveCgroupOf is the directory of the cgroup pid is in.
func liveCgroupOf(t *testing.T, pid int32) string {
	t.Helper()
	return filepath.Join(ebpf.DefaultCgroupMount, strings.TrimPrefix(unifiedCgroup(t, pid), "/"))
}

// liveEvent is one counter from a cgroup's memory.events.
func liveEvent(t *testing.T, directory, name string) int64 {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, "memory.events"))
	if err != nil {
		t.Fatalf("read %s's memory events: %v", directory, err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		if field, value, found := strings.Cut(line, " "); found && field == name {
			number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				t.Fatalf("%s's memory event %s reads %q", directory, name, value)
			}
			return number
		}
	}
	t.Fatalf("%s's memory events carry no %s:\n%s", directory, name, content)
	return 0
}

// liveCommand runs the observer once and returns what it printed on each stream
// and how it exited, within a bound.
func liveCommand(t *testing.T, within time.Duration, binary string, arguments ...string) (string, string, error) {
	t.Helper()
	command := exec.Command(binary, arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("run the observer: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return stdout.String(), stderr.String(), err
	case <-time.After(within):
		_ = command.Process.Kill()
		<-done
		t.Fatalf("observer %v did not finish in %s:\n%s%s", arguments, within, stdout.String(), stderr.String())
		return "", "", errors.New("unreachable")
	}
}
