//go:build attach

package attach_test

// The apparatus for the independently authored body and query tests: an HTTPS
// server that reads every request body whatever its framing and answers from
// a table, clients that write a request in the TLS writes a case names, a
// configuration writer, one observer session run through the built binary,
// and an instrument that looks for a marker in every byte the session wrote.
//
// Written against the published interface and the contract alone. Nothing
// here reads the implementation of the operations it measures.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	cp "github.com/evandukss/edge-observer/contract/policy"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// t20iServerScript reads each request's body by its length or its chunks,
// trailers included, so the connection stays open for the next exchange, and
// answers with the table's response for the request's path.
const t20iServerScript = `
import base64, http.server, json, ssl, sys
port, certificate, key, table = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
with open(table) as source:
    answers = json.load(source)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *arguments):
        pass
    def consume(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return
                self.rfile.read(size)
                self.rfile.readline()
        length = self.headers.get("Content-Length")
        if length:
            self.rfile.read(int(length))
    def answer(self):
        self.consume()
        one = answers.get(self.path.split("?", 1)[0], {"type": "text/plain", "body": "", "headers": {}})
        payload = base64.b64decode(one["body"] or "")
        self.send_response(200)
        self.send_header("Content-Type", one["type"])
        for name, value in (one.get("headers") or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    do_GET = do_POST = do_PUT = answer

class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # A client the test stops at cleanup closes its connection mid-read,
        # which is not a failure of any exchange; anything else is printed.
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

// t20iResponse is what the server answers for one path.
type t20iResponse struct {
	Type    string            `json:"type"`
	Body    []byte            `json:"body"`
	Headers map[string]string `json:"headers"`
}

func t20iServing(t *testing.T, table map[string]t20iResponse) int {
	t.Helper()
	certificate, key := certificate(t)
	directory := t.TempDir()
	script := filepath.Join(directory, "server.py")
	if err := os.WriteFile(script, []byte(t20iServerScript), 0o600); err != nil {
		t.Fatalf("write the server: %v", err)
	}
	encoded, err := json.Marshal(table)
	if err != nil {
		t.Fatalf("encode the response table: %v", err)
	}
	answers := filepath.Join(directory, "answers.json")
	if err := os.WriteFile(answers, encoded, 0o600); err != nil {
		t.Fatalf("write the response table: %v", err)
	}
	port := free(t)
	command := exec.Command("python3", script, strconv.Itoa(port), certificate, key, answers)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
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

// t20iExchange writes the request as the given pieces, each one write to the
// client and so one TLS write, and reads the whole response back so the
// exchange is complete before anything stops. It returns the status code.
//
// openssl s_client reads a piece whose first byte is Q, R, K or k as a
// command, so no piece may begin with one.
func t20iExchange(t *testing.T, c conversation, pieces []string) int {
	t.Helper()
	for i, piece := range pieces {
		if piece == "" || strings.ContainsRune("QRKk", rune(piece[0])) || len(piece) > 4096 {
			t.Fatalf("wiring, not the property: piece %d of the request is %q, which s_client would not send as one TLS write", i, piece)
		}
		if i > 0 {
			// Long enough for s_client to have read and sent the previous
			// piece on its own before this one arrives.
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := io.WriteString(c.send, piece); err != nil {
			t.Fatalf("send piece %d of the request: %v", i, err)
		}
	}
	type answer struct {
		status int
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		line, err := c.receive.ReadString('\n')
		if err != nil {
			done <- answer{0, err}
			return
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			done <- answer{0, fmt.Errorf("status line %q", line)}
			return
		}
		status, _ := strconv.Atoi(fields[1])
		length := -1
		for {
			header, err := c.receive.ReadString('\n')
			if err != nil {
				done <- answer{0, err}
				return
			}
			if header == "\r\n" {
				break
			}
			if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
				length, _ = strconv.Atoi(strings.TrimSpace(value))
			}
		}
		if length < 0 {
			done <- answer{0, fmt.Errorf("the response states no length")}
			return
		}
		if _, err := io.ReadFull(c.receive, make([]byte, length)); err != nil {
			done <- answer{0, err}
			return
		}
		done <- answer{status, nil}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("wiring, not the property: reading the response failed: %v", got.err)
		}
		return got.status
	case <-time.After(15 * time.Second):
		t.Fatal("wiring, not the property: no complete response within 15 seconds")
	}
	return 0
}

// t20iHeader is one header line of a request.
type t20iHeader struct{ name, value string }

// t20iRequest is a request with a stated length, as one piece.
func t20iRequest(method, target string, headers []t20iHeader, body string) string {
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\nHost: localhost\r\n")
	for _, h := range headers {
		b.WriteString(h.name + ": " + h.value + "\r\n")
	}
	if body != "" || method == "POST" || method == "PUT" {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("\r\n" + body)
	return b.String()
}

// t20iChunked is a chunked request with these chunks and trailers.
func t20iChunked(method, target string, headers []t20iHeader, chunks []string, trailers []t20iHeader) string {
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n")
	for _, h := range headers {
		b.WriteString(h.name + ": " + h.value + "\r\n")
	}
	b.WriteString("\r\n")
	for _, chunk := range chunks {
		b.WriteString(strconv.FormatInt(int64(len(chunk)), 16) + "\r\n" + chunk + "\r\n")
	}
	b.WriteString("0\r\n")
	for _, h := range trailers {
		b.WriteString(h.name + ": " + h.value + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// t20iSplit cuts wire into pieces right after the first occurrence of each
// cut, in order, and fails if a cut is absent.
func t20iSplit(t *testing.T, wire string, cuts ...string) []string {
	t.Helper()
	var pieces []string
	for _, cut := range cuts {
		at := strings.Index(wire, cut)
		if at < 0 {
			t.Fatalf("wiring, not the property: the request holds no %q to cut after", cut)
		}
		pieces = append(pieces, wire[:at+len(cut)])
		wire = wire[at+len(cut):]
	}
	return append(pieces, wire)
}

// t20iMultipart is a multipart/form-data body with boundary XB.
func t20iMultipart(parts ...[2]string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--XB\r\nContent-Disposition: form-data; name=\"" + p[0] + "\"\r\n\r\n" + p[1] + "\r\n")
	}
	b.WriteString("--XB--\r\n")
	return b.String()
}

// t20iSlot is one slot of a pipeline, failing as the requirements do.
func t20iSlot(name, implementation string, configuration any) map[string]any {
	return map[string]any{"name": name, "implementation": implementation, "configuration": configuration, "on_failure": cp.DropAndAccount}
}

// t20iPipeline is a reconstruction pipeline to these sinks.
func t20iPipeline(name string, sinks []string, slots ...map[string]any) map[string]any {
	if slots == nil {
		slots = []map[string]any{}
	}
	return map[string]any{"name": name, "input": "reconstruction", "slots": slots, "sinks": sinks, "queues": []any{}}
}

// t20iRequirement is a mandatory removal of field at the sink account.
func t20iRequirement(id, field string) cp.Requirement {
	return cp.Requirement{ID: id, Target: cp.Target{Kind: "sink", Name: "account"}, Operation: "transform_field",
		Parameters: map[string]any{"field": field, "transformation": "remove"}, FailureAction: cp.DropAndAccount}
}

// t20iSetup is what one session is configured with beyond its targets.
type t20iSetup struct {
	pipelines    []map[string]any
	requirements []cp.Requirement
	// sinks are local_account sinks beside account; packs are enabled and
	// installed from their manifests, keyed by name.
	sinks []string
	packs map[string]map[string]any
}

// t20iConfigure writes c's configuration: these targets, these pipelines
// beside a connection pipeline, and these requirements as one policy.
func t20iConfigure(t *testing.T, c configured, targets []map[string]any, setup t20iSetup) {
	t.Helper()
	c.rewrite(t, targets, nil)
	content, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("read %s: %v", c.path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode %s: %v", c.path, err)
	}
	pipelines := []any{}
	for _, p := range setup.pipelines {
		pipelines = append(pipelines, p)
	}
	pipelines = append(pipelines, map[string]any{"name": "connections", "input": "connection", "slots": []any{}, "sinks": []any{"account"}, "queues": []any{}})
	document["pipelines"] = pipelines
	policy := []any{}
	if len(setup.requirements) > 0 {
		policy = append(policy, cp.Document{Vocabulary: cp.Vocabulary, Requirements: setup.requirements, Claims: []cp.Claim{}, Approvals: []cp.Approval{}})
	}
	document["policy"] = policy
	sinks := []any{map[string]any{"name": "account", "kind": "local_account"}}
	for _, name := range setup.sinks {
		sinks = append(sinks, map[string]any{"name": name, "kind": "local_account"})
	}
	document["sinks"] = sinks
	packs := []string{}
	for name, manifest := range setup.packs {
		packs = append(packs, name)
		written, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("encode pack %s: %v", name, err)
		}
		directory := filepath.Join(filepath.Dir(c.path), "packs")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("make %s: %v", directory, err)
		}
		if err := os.WriteFile(filepath.Join(directory, name+".json"), written, 0o600); err != nil {
			t.Fatalf("install pack %s: %v", name, err)
		}
	}
	slices.Sort(packs)
	document["packs"] = packs
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(c.path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
}

// t20iPack is a configuration-only pack adding these pipelines.
func t20iPack(name string, pipelines ...map[string]any) map[string]any {
	if pipelines == nil {
		pipelines = []map[string]any{}
	}
	return map[string]any{"version": "observer.pack/draft", "name": name, "pack_version": "0.1.0",
		"components": []any{}, "pipelines": pipelines, "replacements": []any{}, "policy": []any{}}
}

// t20iLocked is standard error written from the process's own goroutine.
type t20iLocked struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (l *t20iLocked) Write(p []byte) (int, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.buffer.Write(p)
}

func (l *t20iLocked) bytes() []byte {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return bytes.Clone(l.buffer.Bytes())
}

// t20iSession is one observer run in the foreground, with everything it wrote
// to its standard output and standard error kept.
type t20iSession struct {
	binary  string
	c       configured
	command *exec.Cmd
	lines   *bufio.Scanner
	stdout  []string
	stderr  *t20iLocked
	session string
	sealed  account.Account
}

func (s *t20iSession) directory() string { return filepath.Join(s.c.sessions(), s.session) }

// t20iStart runs the observer as started does and returns once its log
// carries the activation record.
func t20iStart(t *testing.T, binary string, c configured) *t20iSession {
	t.Helper()
	command := exec.Command(binary, "start", c.path)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	s := &t20iSession{binary: binary, c: c, command: command, stderr: &t20iLocked{}}
	command.Stderr = s.stderr
	intoEnvelope(t, command)
	if err := command.Start(); err != nil {
		t.Fatalf("start the observer: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	s.lines = bufio.NewScanner(out)
	s.lines.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for s.lines.Scan() {
		s.stdout = append(s.stdout, s.lines.Text())
		if record, ok := recordOf(s.lines.Bytes()); ok && record.Record == "activation-completed" && record.Version == 1 {
			s.session = record.Session
			return s
		}
	}
	_ = command.Wait()
	t.Fatalf("wiring, not the property: the observer never activated, so nothing below measured anything.\nstdout:\n%s\nstderr:\n%s",
		strings.Join(s.stdout, "\n"), s.stderr.bytes())
	return nil
}

// end stops the session, keeps the rest of what it printed, and reads the
// account it sealed.
func (s *t20iSession) end(t *testing.T) {
	t.Helper()
	if err := s.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop the observer: %v", err)
	}
	for s.lines.Scan() {
		s.stdout = append(s.stdout, s.lines.Text())
	}
	if err := s.command.Wait(); err != nil {
		t.Fatalf("the observer exited with %v\nstderr:\n%s", err, s.stderr.bytes())
	}
	content, err := os.ReadFile(filepath.Join(s.directory(), "account.json"))
	if err != nil {
		t.Fatalf("read the sealed account: %v", err)
	}
	if err := json.Unmarshal(content, &s.sealed); err != nil {
		t.Fatalf("decode the sealed account: %v", err)
	}
	if s.sealed.Kind != account.Sealed || s.sealed.Session != s.session {
		t.Fatalf("the account beside session %s is a %s account of session %s", s.session, s.sealed.Kind, s.sealed.Session)
	}
}

// t20iOutput is everything one session wrote, and the approved artifacts
// decoded from it.
type t20iOutput struct {
	// sources maps a name to bytes: every file under the observer's
	// directory by its path, its standard output and error, and the public
	// reader's text rendering of the session.
	sources   map[string][]byte
	artifacts []processing.Artifact
	sealed    account.Account
}

// output collects what the ended session wrote and runs the public reader
// over it. The reader must accept what the writer wrote.
func (s *t20iSession) output(t *testing.T) t20iOutput {
	t.Helper()
	o := t20iOutput{sources: map[string][]byte{}, sealed: s.sealed}
	walked := 0
	err := filepath.WalkDir(s.c.directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		walked++
		o.sources[path] = content
		return nil
	})
	if err != nil {
		t.Fatalf("read what the observer wrote under %s: %v", s.c.directory, err)
	}
	o.sources["standard output"] = []byte(strings.Join(s.stdout, "\n"))
	o.sources["standard error"] = s.stderr.bytes()

	approved, present := o.sources[filepath.Join(s.directory(), processing.ArtifactName)]
	if walked < 3 || !present {
		t.Fatalf("wiring, not the property: the observer's directory holds %d files and approved output present=%v, "+
			"so there is nothing to read", walked, present)
	}
	for _, line := range bytes.Split(approved, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatalf("an approved line does not decode: %v\n%s", err, line)
		}
		o.artifacts = append(o.artifacts, a)
	}

	text, err := exec.Command(s.binary, "inspect", s.directory(), "--text").CombinedOutput()
	if err != nil {
		t.Fatalf("the public reader refused what this session wrote: %v\n%s", err, text)
	}
	o.sources["public reader text"] = text
	return o
}

// t20iRepresentations are the forms a marker could take in what the observer
// writes: as itself, base64 at each of the three alignments in both alphabets,
// and hex. A JSON string is also decoded, escapes and base64 both, by found.
func t20iRepresentations(marker string) map[string][]byte {
	if len(marker) < 16 {
		panic("a marker shorter than 16 bytes has too few whole base64 groups to search for: " + marker)
	}
	forms := map[string][]byte{"raw": []byte(marker), "hex": []byte(hex.EncodeToString([]byte(marker))),
		"HEX": []byte(strings.ToUpper(hex.EncodeToString([]byte(marker))))}
	for pad := range 3 {
		for alphabet, encoding := range map[string]*base64.Encoding{"base64": base64.StdEncoding, "base64url": base64.URLEncoding} {
			encoded := encoding.EncodeToString(append(make([]byte, pad), marker...))
			// The groups made only of marker bytes, which do not depend on what
			// surrounds the marker in the encoded text.
			first, last := (pad+2)/3, (pad+len(marker))/3
			forms[fmt.Sprintf("%s at offset %d", alphabet, pad)] = []byte(encoded[4*first : 4*last])
		}
	}
	return forms
}

// found is every source and form in which the marker occurs.
func (o t20iOutput) found(marker string) []string {
	forms := t20iRepresentations(marker)
	var where []string
	names := make([]string, 0, len(o.sources))
	for name := range o.sources {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		content := o.sources[name]
		for form, needle := range forms {
			if bytes.Contains(content, needle) {
				where = append(where, name+" ("+form+")")
			}
		}
		documents := [][]byte{content}
		documents = append(documents, bytes.Split(content, []byte{'\n'})...)
		for _, document := range documents {
			var decoded any
			if json.Unmarshal(document, &decoded) != nil {
				continue
			}
			if t20iInJSON(decoded, marker) {
				where = append(where, name+" (decoded JSON string)")
				break
			}
		}
	}
	return where
}

func t20iInJSON(v any, marker string) bool {
	switch v := v.(type) {
	case string:
		if strings.Contains(v, marker) {
			return true
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			if decoded, err := encoding.DecodeString(v); err == nil && bytes.Contains(decoded, []byte(marker)) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if t20iInJSON(x, marker) {
				return true
			}
		}
	case map[string]any:
		for k, x := range v {
			if t20iInJSON(k, marker) || t20iInJSON(x, marker) {
				return true
			}
		}
	}
	return false
}

// written is the instrument's control: a marker the contract says persists
// must be found by the same search that reports a protected one absent, or an
// absence below would say nothing about the output.
func (o t20iOutput) written(t *testing.T, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if len(o.found(marker)) == 0 {
			t.Fatalf("wiring or a lost permitted value: %s, which must persist, is in nothing the session wrote, "+
				"so an absence reported by the same search would measure nothing", marker)
		}
	}
}

// absent asserts no byte the session wrote carries any of the markers in any
// form the instrument knows.
func (o t20iOutput) absent(t *testing.T, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if where := o.found(marker); len(where) > 0 {
			t.Errorf("protected %s was written: %s", marker, strings.Join(where, "; "))
		}
	}
}

// pathOf is a request target without its query.
func pathOf(target string) string {
	path, _, _ := strings.Cut(target, "?")
	return path
}

// exchange is the one exchange pipeline wrote for the request to path.
func (o t20iOutput) exchange(t *testing.T, pipeline, path string) (processing.Artifact, record.Exchange) {
	t.Helper()
	var found []processing.Artifact
	var exchanges []record.Exchange
	pipelines := map[string]int{}
	for _, a := range o.artifacts {
		pipelines[a.Route.Pipeline]++
		if a.Route.Pipeline != pipeline || a.Reconstruction == nil {
			continue
		}
		for _, x := range a.Reconstruction.Exchanges {
			if x.Request.Message != nil && pathOf(x.Request.Message.Target) == path {
				found = append(found, a)
				exchanges = append(exchanges, x)
			}
		}
	}
	if len(exchanges) != 1 {
		processed, _ := json.Marshal(o.sealed.Processing)
		t.Fatalf("wiring, not the property: pipeline %s wrote %d exchanges for %s, want one, so nothing below measured "+
			"what processing did to it; artifacts per pipeline %v; sealed processing %s", pipeline, len(exchanges), path, pipelines, processed)
	}
	x := exchanges[0]
	if !x.Complete || x.Request.Message == nil || x.Response.Message == nil {
		t.Fatalf("wiring, not the property: the exchange for %s is not a complete pair: %+v", path, x)
	}
	return found[0], x
}

// t20iEntry is one expected policy exclusion entry, without its exchange.
type t20iEntry struct{ message, field, section, disposition string }

// evidence asserts the artifact's entries for x are exactly want, as a set.
func t20iEvidence(t *testing.T, a processing.Artifact, x record.Exchange, want ...t20iEntry) {
	t.Helper()
	if a.Version != processing.ArtifactVersion {
		t.Errorf("the artifact is version %q, want %q", a.Version, processing.ArtifactVersion)
	}
	if a.PolicyExclusions == nil {
		t.Errorf("the artifact carries no policy_exclusions array, which reads as evidence unavailable")
	}
	var got []t20iEntry
	for _, e := range a.PolicyExclusions {
		if e.Exchange != x.Index {
			continue
		}
		if e.Name != "" {
			t.Errorf("a version 2 entry carries name %q: %+v", e.Name, e)
		}
		got = append(got, t20iEntry{e.Message, e.Field, e.Section, e.Disposition})
	}
	key := func(e t20iEntry) string { return e.message + " " + e.field + " " + e.section + " " + e.disposition }
	sortEntries := func(list []t20iEntry) []string {
		keys := make([]string, 0, len(list))
		for _, e := range list {
			keys = append(keys, key(e))
		}
		slices.Sort(keys)
		return keys
	}
	if g, w := sortEntries(got), sortEntries(want); !slices.Equal(g, w) {
		t.Errorf("policy exclusion entries for exchange %d are %q, want %q", x.Index, g, w)
	}
}

// t20iBody is a message's retained body bytes.
func t20iBody(t *testing.T, m *record.Message) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(m.Body.Kept)
	if err != nil {
		t.Fatalf("the retained body is not base64: %q %v", m.Body.Kept, err)
	}
	return body
}

// t20iRemovedWhole asserts a body removed by policy: nothing retained, the
// length and framing it had kept, and its structure removed.
func t20iRemovedWhole(t *testing.T, m *record.Message, length int, framing string) {
	t.Helper()
	if m.Body.Kept != "" {
		t.Errorf("a body removed whole retains %q", m.Body.Kept)
	}
	if m.Body.Length != strconv.Itoa(length) {
		t.Errorf("a body removed whole states length %q, want the %d bytes it had", m.Body.Length, length)
	}
	if m.Framing != framing {
		t.Errorf("a body removed whole states framing %q, want %q", m.Framing, framing)
	}
	if m.Structure.State != record.StructureRemoved || m.Structure.Shape != nil {
		t.Errorf("a body removed whole has structure %+v, want state removed and no shape", m.Structure)
	}
}

// t20iKept asserts a body retained exactly.
func t20iKept(t *testing.T, m *record.Message, want string) {
	t.Helper()
	if got := string(t20iBody(t, m)); got != want {
		t.Errorf("the body retained is %q, want it unchanged, %q", got, want)
	}
}

// t20iHasHeader asserts a header with this value was written.
func t20iHasHeader(t *testing.T, m *record.Message, name, value string) {
	t.Helper()
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) && h.Value == value {
			return
		}
	}
	t.Errorf("the message lost header %s: %s; headers written: %+v", name, value, m.Headers)
}

// t20iCase is one exchange on a connection of its own, and what the
// session's output must show for it.
type t20iCase struct {
	// name is unique in its session and the request's path is "/t20i/" + name.
	name     string
	pieces   []string
	response t20iResponse
	// protected markers must be in no byte the session wrote; permitted ones
	// must be somewhere in it.
	protected []string
	permitted []string
	// check runs once per pipeline under test against that pipeline's
	// exchange for this case.
	check func(t *testing.T, pipeline string, a processing.Artifact, x record.Exchange)
}

func (c t20iCase) path() string { return "/t20i/" + c.name }

// t20iRun runs one session over every case, each on a connection of its own
// that the session's one target covers, and returns what it wrote.
func t20iRun(t *testing.T, setup t20iSetup, cases []t20iCase) t20iOutput {
	t.Helper()
	binary := built(t)
	table := map[string]t20iResponse{}
	for _, one := range cases {
		if _, taken := table[one.path()]; taken {
			t.Fatalf("wiring: two cases share the path %s", one.path())
		}
		if one.response.Type == "" {
			one.response.Type = "text/plain"
		}
		table[one.path()] = one.response
	}
	port := t20iServing(t, table)
	clients := make([]conversation, len(cases))
	for i := range cases {
		clients[i] = speaking(t, port)
	}
	c := configuring(t, target("t20i", clients[0].process))
	t20iConfigure(t, c, []map[string]any{target("t20i", clients[0].process)}, setup)
	s := t20iStart(t, binary, c)
	for i, one := range cases {
		if status := t20iExchange(t, clients[i], one.pieces); status != 200 {
			t.Fatalf("wiring, not the property: the server answered case %s with %d", one.name, status)
		}
	}
	s.end(t)
	return s.output(t)
}

// t20iAssert checks every case against the session's output, each as its own
// subtest: the permitted markers first, as the instrument's control, then the
// protected ones, then the case's own check on every pipeline named.
func t20iAssert(t *testing.T, o t20iOutput, pipelines []string, cases []t20iCase) {
	t.Helper()
	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			if len(one.protected) > 0 && len(one.permitted) == 0 {
				t.Fatalf("wiring: case %s protects a marker with none permitted beside it", one.name)
			}
			for _, pipeline := range pipelines {
				o.exchange(t, pipeline, one.path())
			}
			o.written(t, one.permitted...)
			o.absent(t, one.protected...)
			if one.check != nil {
				for _, pipeline := range pipelines {
					a, x := o.exchange(t, pipeline, one.path())
					one.check(t, pipeline, a, x)
				}
			}
		})
	}
}

// t20iRefused runs start over a configuration that must be refused before
// anything attaches, and returns what it printed. Each reason given must
// appear as a finding's reason.
func t20iRefused(t *testing.T, binary string, targets []map[string]any, setup t20iSetup, reasons ...string) string {
	t.Helper()
	c := configuring(t, targets...)
	t20iConfigure(t, c, targets, setup)
	command := exec.Command(binary, "start", c.path)
	intoEnvelope(t, command)
	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() { out, err := command.CombinedOutput(); done <- result{out, err} }()
	var got result
	select {
	case got = <-done:
	case <-time.After(60 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("a start that must be refused was still running after 60 seconds")
	}
	if got.err == nil || command.ProcessState.ExitCode() == 0 {
		t.Fatalf("a start over a configuration the contract refuses exited zero:\n%s", got.output)
	}
	for _, reason := range reasons {
		if !strings.Contains(string(got.output), ": "+reason+": ") {
			t.Errorf("the refusal does not name %s:\n%s", reason, got.output)
		}
	}
	if entries, err := os.ReadDir(c.sessions()); err == nil && len(entries) != 0 {
		t.Errorf("a refused start left %d session directories", len(entries))
	}
	return string(got.output)
}
