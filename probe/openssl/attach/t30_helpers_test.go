//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

// The markers are the boundary counting's own: the protected one rides every
// field a rule must take away, the permitted one a field that must persist.
const (
	t30Protected = t18BoundaryProtected
	t30Permitted = t18BoundaryPermitted
)

// t30ServerSource answers every method, reads a request body framed by length
// or chunked with trailers, and answers by path:
//
//	/resp/card     JSON {"card":{"number":P,"brand":K},"email":P,"items":[{"pan":P,"label":K}]}
//	/resp/names    JSON {K: P}: a name that must persist, holding a value that must not
//	/resp/decimal  JSON {"card":{"number":"4111111111111111"},K:1}
//	/resp/text     text/plain P
//
// and anything else with text naming the path. P is the protected marker and K
// the permitted one; every answer carries K in X-Public-Response too.
const t30ServerSource = `
import http.server, json, ssl, sys
port, certificate, key, protected, permitted = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *arguments):
        pass
    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return
                self.rfile.read(size)
                self.rfile.readline()
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
    def answer(self):
        self.read_body()
        path = self.path.split("?")[0]
        kind = "application/json"
        if path == "/resp/card":
            body = json.dumps({"card": {"number": protected, "brand": permitted}, "email": protected,
                               "items": [{"pan": protected, "label": permitted}]})
        elif path == "/resp/names":
            body = json.dumps({permitted: protected})
        elif path == "/resp/decimal":
            body = json.dumps({"card": {"number": "4111111111111111"}, permitted: 1})
        elif path == "/resp/text":
            body, kind = protected, "text/plain"
        else:
            body, kind = "answered " + path, "text/plain"
        body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("X-Public-Response", permitted)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = do_PUT = answer

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
`

func t30Serving(t *testing.T) int {
	t.Helper()
	certificate, key := certificate(t)
	script := filepath.Join(t.TempDir(), "server.py")
	if err := os.WriteFile(script, []byte(t30ServerSource), 0o600); err != nil {
		t.Fatalf("write the server: %v", err)
	}
	port := free(t)
	command := exec.Command("python3", script, strconv.Itoa(port), certificate, key, t30Protected, t30Permitted)
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

// t30Get is a GET request for target with these header lines.
func t30Get(target string, headers ...string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: localhost\r\n" + strings.Join(append(headers, ""), "\r\n") + "\r\n"
}

// t30Post is a POST of body with a Content-Type field per entry of types (none
// when types is empty) and these other header lines, framed by length.
func t30Post(target string, types []string, body string, headers ...string) string {
	lines := []string{}
	for _, one := range types {
		lines = append(lines, "Content-Type: "+one)
	}
	lines = append(append(lines, headers...), "Content-Length: "+strconv.Itoa(len(body)))
	return "POST " + target + " HTTP/1.1\r\nHost: localhost\r\n" + strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

// t30Chunked is a POST of body in one chunk, with these header and trailer
// lines.
func t30Chunked(target string, headers []string, body string, trailers []string) string {
	head := "POST " + target + " HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n"
	for _, one := range headers {
		head += one + "\r\n"
	}
	tail := ""
	for _, one := range trailers {
		tail += one + "\r\n"
	}
	return head + "\r\n" + strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n" + tail + "\r\n"
}

// t30Send writes one raw request over the open connection and reads the whole
// answer back by its stated length.
func t30Send(t *testing.T, c conversation, request string) {
	t.Helper()
	if _, err := io.WriteString(c.send, request); err != nil {
		t.Fatalf("send a request: %v", err)
	}
	status, err := c.receive.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		t.Fatalf("the server answered %q, %v", status, err)
	}
	length := int64(-1)
	for {
		header, err := c.receive.ReadString('\n')
		if err != nil {
			t.Fatalf("read the answer's headers: %v", err)
		}
		if header == "\r\n" {
			break
		}
		if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
			if length, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64); err != nil {
				t.Fatalf("the answer states a length of %q", value)
			}
		}
	}
	if length < 0 {
		t.Fatal("wiring, not the property: the answer states no length")
	}
	if _, err := io.CopyN(io.Discard, c.receive, length); err != nil {
		t.Fatalf("read the %d-byte answer: %v", length, err)
	}
}

// t30Watch is one watch entry, in the new format, naming p by what it runs.
func t30Watch(name string, p process.Process) map[string]any {
	arguments := []string{}
	if len(p.Arguments) > 1 {
		arguments = p.Arguments[1:]
	}
	return map[string]any{"name": name, "exe": p.Executable, "args": arguments, "children": "all"}
}

// t30Document is a configuration in the format a user writes, pointed at c's
// directory and log, with these keys added or replaced.
func t30Document(c configured, watch []map[string]any, keys map[string]any) map[string]any {
	document := map[string]any{
		"version": config.FileVersion, "output": c.directory, "log": c.log, "watch": watch,
		"limits": map[string]any{"output_mib": 1, "events": 16384, "state_every_seconds": 1},
	}
	for key, value := range keys {
		document[key] = value
	}
	return document
}

// t30Written writes content as c's configuration and returns it.
func t30Written(t *testing.T, c configured, content []byte) []byte {
	t.Helper()
	if err := os.WriteFile(c.path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
	return content
}

func t30Encoded(t *testing.T, value any) []byte {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return content
}

// t30Accepted is the guard that a fixture is a file the published reader
// accepts, so a later red is about the program and not about the fixture.
func t30Accepted(t *testing.T, content []byte) *config.Compiled {
	t.Helper()
	compiled, findings := config.Compile(content, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("not the property under test: the published reader refuses the fixture - a fixture error, or a "+
			"reader refusing a valid file; nothing below is measured: %+v\n%s", findings, content)
	}
	return compiled
}

// t30Admitted is the property itself where acceptance is what a case claims -
// a neighbour one change from a refused file, a removal beside a rule it wins
// over: the published reader and the command both accept the file. meaning is
// what a refusal here says about the subject.
func t30Admitted(t *testing.T, binary string, c configured, content []byte, meaning string) {
	t.Helper()
	if compiled, findings := config.Compile(content, filepath.Dir(c.path)); compiled == nil || len(findings) != 0 {
		t.Fatalf("%s: the published reader refuses it: %+v", meaning, findings)
	}
	if stdout, stderr, err := t18Command(t, 30*time.Second, binary, "dry-run", c.path); err != nil {
		t.Fatalf("%s: the command refuses it (%v):\n%s%s", meaning, err, stdout, stderr)
	}
}

// t30Variants is needle as it reads inside base64 at each of the three byte
// alignments, keeping only the characters every encoding of it shares, since
// the approved output writes bodies base64-encoded.
func t30Variants(needle string) []string {
	var variants []string
	for offset := 0; offset < 3; offset++ {
		encoded := base64.StdEncoding.EncodeToString(append(make([]byte, offset), needle...))
		first := (8*offset + 5) / 6
		last := 8 * (offset + len(needle)) / 6
		if last > first {
			variants = append(variants, encoded[first:last])
		}
	}
	return variants
}

// t30Needles serves as t18Boundary.serve does, and counts these needles and
// their base64 forms as well as the two markers. They are added in the serving
// goroutine before the first notification is read, so nothing races them.
func t30Needles(needles ...string) func(w *t25Watch, listener int) {
	return func(w *t25Watch, listener int) {
		all := append([]string{t30Protected, t30Permitted}, needles...)
		for _, needle := range all {
			for _, form := range append([]string{needle}, t30Variants(needle)...) {
				w.boundary.found[form] += 0
			}
		}
		w.boundary.serve(listener, &w.stop)
	}
}

// t30Crossed is how many times needle, plain or base64-encoded, crossed a
// write the boundary read.
func t30Crossed(w *t25Watch, needle string) int {
	w.boundary.mutex.Lock()
	defer w.boundary.mutex.Unlock()
	count := w.boundary.found[needle]
	for _, form := range t30Variants(needle) {
		count += w.boundary.found[form]
	}
	return count
}

// t30Started starts the observer over c under the write-boundary filter, once
// the command itself accepts the file: dry-run reads it through the same path
// start does, and a refusal there is the guard, before any property.
func t30Started(t *testing.T, binary string, c configured, needles ...string) *t25Watch {
	t.Helper()
	stdout, stderr, err := t18Command(t, 30*time.Second, binary, "dry-run", c.path)
	if err != nil {
		t.Fatalf("wiring, not the property: the command refuses a file the published reader accepts, so nothing "+
			"below reached the processing it configures (%v):\n%s%s", err, stdout, stderr)
	}
	return t25Watched(t, binary, c, t30Needles(needles...))
}

// t30Finished hangs up client, waits for its records, stops the session and
// returns what it wrote.
func t30Finished(t *testing.T, binary string, c configured, w *t25Watch, client conversation, want uint64) []t30Artifact {
	t.Helper()
	t18Hangup(client)
	t25Settled(t, binary, c, w, want, 20*time.Second)
	w.signal(t, syscall.SIGTERM)
	return t30Records(t, w.directory(c))
}

// t30Artifact is an approved record as its JSON line holds it.
type t30Artifact struct {
	Route struct {
		Pipeline string `json:"pipeline"`
	} `json:"route"`
	Reconstruction *struct {
		Exchanges []struct {
			Request  t30Side `json:"request"`
			Response t30Side `json:"response"`
		} `json:"exchanges"`
	} `json:"reconstruction"`
	PolicyExclusions []struct {
		Exchange    int    `json:"exchange"`
		Message     string `json:"message"`
		Field       string `json:"field"`
		Disposition string `json:"disposition"`
	} `json:"policy_exclusions"`
}

type t30Side struct {
	Message *t30Message `json:"message"`
}

type t30Message struct {
	Target   string `json:"target"`
	Headers  []struct{ Name, Value string }
	Trailers []struct{ Name, Value string }
	Body     struct {
		Length string `json:"length"`
		Kept   string `json:"kept"`
	} `json:"body"`
	Structure struct {
		State string    `json:"state"`
		Shape *t30Shape `json:"shape"`
	} `json:"structure"`
}

type t30Shape struct {
	Kind   string `json:"kind"`
	Fields []struct {
		Name  string   `json:"name"`
		Shape t30Shape `json:"shape"`
	} `json:"fields"`
}

// t30Records is every line of a session's approved output.
func t30Records(t *testing.T, directory string) []t30Artifact {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, processing.ArtifactName))
	if err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	var records []t30Artifact
	for _, line := range bytes.Split(bytes.TrimSpace(content), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var one t30Artifact
		if err := json.Unmarshal(line, &one); err != nil {
			t.Fatalf("an approved record is not JSON: %v", err)
		}
		records = append(records, one)
	}
	return records
}

// t30Exchange is the exchange whose request target starts with prefix, with
// the policy exclusions of its record for that exchange.
type t30Exchange struct {
	Request, Response *t30Message
	Exclusions        []string
}

func t30Find(t *testing.T, records []t30Artifact, prefix string) t30Exchange {
	t.Helper()
	var found []t30Exchange
	for _, record := range records {
		if record.Reconstruction == nil {
			continue
		}
		for index, exchange := range record.Reconstruction.Exchanges {
			if exchange.Request.Message == nil || !strings.HasPrefix(exchange.Request.Message.Target, prefix) {
				continue
			}
			one := t30Exchange{Request: exchange.Request.Message, Response: exchange.Response.Message}
			for _, excluded := range record.PolicyExclusions {
				if excluded.Exchange == index {
					one.Exclusions = append(one.Exclusions, excluded.Message+" "+excluded.Field+" "+excluded.Disposition)
				}
			}
			found = append(found, one)
		}
	}
	if len(found) != 1 {
		t.Fatalf("wiring, not the property: %d written exchanges have a target starting %q, want one", len(found), prefix)
	}
	return found[0]
}

// header is every value of the named header or trailer, ignoring case.
func (m *t30Message) header(name string) []string {
	var values []string
	if m == nil {
		return values
	}
	for _, field := range append(append([]struct{ Name, Value string }{}, m.Headers...), m.Trailers...) {
		if strings.EqualFold(field.Name, name) {
			values = append(values, field.Value)
		}
	}
	return values
}

// kept is the body the record kept, decoded.
func (m *t30Message) kept(t *testing.T) string {
	t.Helper()
	if m == nil {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(m.Body.Kept)
	if err != nil {
		t.Fatalf("a kept body is not base64: %v", err)
	}
	return string(decoded)
}

// at is the shape under the member path, or nil where a member is absent.
func (s *t30Shape) at(path ...string) *t30Shape {
	current := s
	for _, name := range path {
		if current == nil {
			return nil
		}
		var next *t30Shape
		for i := range current.Fields {
			if current.Fields[i].Name == name {
				next = &current.Fields[i].Shape
			}
		}
		current = next
	}
	return current
}

// t30Live is the live account, for a guard that a request reached capture.
func t30Live(t *testing.T, binary string, c configured) account.Account {
	t.Helper()
	return inspected(t, binary, c)
}

func t30Has(values []string, value string) bool {
	for _, one := range values {
		if one == value {
			return true
		}
	}
	return false
}

// t30Excluded reports whether the exchange carries an exclusion of field with
// disposition in message.
func (e t30Exchange) excluded(message, field, disposition string) bool {
	return t30Has(e.Exclusions, fmt.Sprintf("%s %s %s", message, field, disposition))
}
