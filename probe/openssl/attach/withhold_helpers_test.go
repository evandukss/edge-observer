//go:build attach

// Live evidence that, on a real connection through the real observer binary,
// selected plaintext an operator marked for removal never reaches any durable
// output, undecidable input is withheld, and a copied artifact reads correctly
// through the public command alone. These tests were written by a different
// author from the code they measure; a failure here is a finding, reported
// rather than adapted away.
//
// Every identifier this file adds is prefixed withhold so it cannot collide
// with other files in this package.
package attach_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// The markers. Each is a token that would not occur in this system but for this
// test, so a plain substring search over durable output is a real check rather
// than one a domain word could satisfy. withholdPermitted MUST survive to durable
// output; the rest MUST NOT.
const (
	// withholdSecret rides an Authorization header the operator configures away.
	withholdSecret = "WHD_PROTECTED_a3f9c1"
	// withholdPermitted rides an X-Public header nothing removes: the paired marker
	// that must persist, so "nothing ran" cannot pass a withholding assertion.
	withholdPermitted = "WHD_PERMITTED_5e2b8d"
	// withholdSuffix rides an incomplete request left undecidable at shutdown.
	withholdSuffix = "WHD_SUFFIX_7c4a1e"
	// withholdMalformed rides a request no strict endpoint would accept.
	withholdMalformed = "WHD_MALFORMED_9b6d2f"
	// withholdSplit rides an Authorization value the client writes in a second TLS
	// write, so the header name and its value cross the boundary separately.
	withholdSplit = "WHD_SPLIT_2d8f40"
)

// withholdRemoveAuthorization rewrites c's configuration so the reconstruction
// pipeline removes the authorization header and nothing else, leaving every
// other field - X-Public among them - retained.
func withholdRemoveAuthorization(t *testing.T, c configured) {
	t.Helper()
	content, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("read %s: %v", c.path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode %s: %v", c.path, err)
	}
	document["remove"] = map[string]any{"headers": []any{"authorization"}}
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(c.path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
}

// withholdComplete sends one complete request over the open connection - X-Public
// carrying the permitted marker, Authorization carrying the protected one - and
// reads the whole response back, so the exchange the observer sees is framed
// and complete. The connection stays open. path names the request so the
// retained exchange can be found again.
func withholdComplete(t *testing.T, c conversation, path string) {
	t.Helper()
	request := "GET /?asked=" + path + " HTTP/1.1\r\nHost: localhost\r\n" +
		"X-Public: " + withholdPermitted + "\r\nAuthorization: Bearer " + withholdSecret + "\r\n\r\n"
	if _, err := io.WriteString(c.send, request); err != nil {
		t.Fatalf("send the complete request: %v", err)
	}
	withholdReadResponse(t, c)
}

// withholdReadResponse reads one whole response - status line, headers, and a
// content-length body - so the client has read every byte before anything stops.
func withholdReadResponse(t *testing.T, c conversation) {
	t.Helper()
	line, err := c.receive.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("the server answered %q, %v", line, err)
	}
	length := -1
	for {
		header, err := c.receive.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response headers: %v", err)
		}
		if header == "\r\n" {
			break
		}
		if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
			if length, err = strconv.Atoi(strings.TrimSpace(value)); err != nil {
				t.Fatalf("the response states a length of %q", value)
			}
		}
	}
	if length < 0 {
		t.Fatal("wiring, not the property: the response states no length, so its end cannot be read")
	}
	if _, err := io.ReadFull(c.receive, make([]byte, length)); err != nil {
		t.Fatalf("read the %d-byte response body: %v", length, err)
	}
}

// withholdSendRaw writes bytes over the open connection and reads nothing: it is how
// an undecidable or malformed suffix is placed on a connection the application
// keeps open.
func withholdSendRaw(t *testing.T, c conversation, payload string) {
	t.Helper()
	if _, err := io.WriteString(c.send, payload); err != nil {
		t.Fatalf("send %q: %v", payload, err)
	}
}

// withholdSeenAtLeast waits until the running session has captured at least want
// records, and returns the count it reached. It is the wiring guard that a
// fixture REACHED the observer before anything is asserted about withholding:
// an absent marker proves nothing if the bytes never crossed the boundary. It
// reads the live account through the public inspect command, so it measures the
// observer's own count rather than the test's belief about timing.
func withholdSeenAtLeast(t *testing.T, binary string, c configured, want int64) int64 {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var seen int64
	for time.Now().Before(deadline) {
		answer, err := exec.Command(binary, "inspect", c.path).Output()
		if err == nil {
			var live account.Account
			if json.Unmarshal(answer, &live) == nil && live.Seen != nil {
				seen = live.Seen.Records
				if seen >= want {
					return seen
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the running session captured %d records within the wait, want at least %d", seen, want)
	return seen
}

// withholdRetained is what one session wrote for one process, read from its approved
// output alone: the retained exchanges of the request naming path, the
// truncation evidence on that connection, the connection's ending, and the
// capture-time policy revision. sealed is quoted where nothing was found, so a
// shortfall says what processing recorded rather than reading as an empty result.
type withholdRetained struct {
	exchanges  []record.Exchange
	truncation *processing.ReconstructionTruncation
	ending     string
	revision   string
}

func withholdReadRetained(t *testing.T, directory string, sealed account.Account, pid int32, path string) withholdRetained {
	t.Helper()
	var out withholdRetained
	requests := 0
	output := filepath.Dir(filepath.Dir(directory))
	err := processing.ReadArtifactFiles(os.DirFS(output), []string{processing.ArtifactName}, filepath.Base(directory), func(artifact processing.Artifact) error {
		if artifact.Connection.Process.PID != pid {
			return nil
		}
		out.ending = artifact.Connection.Ending.How
		if artifact.Reconstruction == nil {
			// The retirement record: an incomplete suffix's evidence is on it.
			if artifact.ReconstructionTruncation != nil {
				out.truncation = artifact.ReconstructionTruncation
			}
			return nil
		}
		for _, exchange := range artifact.Reconstruction.Exchanges {
			message := exchange.Request.Message
			if message == nil || !strings.Contains(message.Target, "asked="+path) {
				continue
			}
			requests++
			out.exchanges = append(out.exchanges, exchange)
			out.revision = artifact.PolicyRevision
			if artifact.ReconstructionTruncation != nil {
				out.truncation = artifact.ReconstructionTruncation
			}
		}
		return nil
	})
	if err != nil || requests == 0 {
		processed, _ := json.Marshal(sealed.Processing)
		t.Fatalf("wiring, not the property: the approved output of %s holds no request %q from pid %d (%v), so "+
			"nothing below measured what processing did to it; the session sealed processing %s",
			directory, path, pid, err, processed)
	}
	return out
}

// withholdDurableBytes is every byte of the approved output the session wrote to,
// every session's lines included, for a scan that a leak anywhere - a header
// value, a body, a diagnostic field - would fail, independently of how any one
// field was parsed.
func withholdDurableBytes(t *testing.T, directory string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(directory)), processing.ArtifactName))
	if err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	return content
}

// withholdAbsent fails if value appears in data as itself or base64-encoded (the
// form a body would take). A header value is stored as itself; a body is
// base64; checking both is why a leak in either cannot pass.
func withholdAbsent(t *testing.T, where string, data []byte, value string) {
	t.Helper()
	for _, form := range []string{value, base64.StdEncoding.EncodeToString([]byte(value))} {
		if strings.Contains(string(data), form) {
			t.Fatalf("%s: the protected marker %q reached durable output", where, value)
		}
	}
}

// withholdHeaderValue is the value of the first header named name in message, and
// whether it is there at all.
func withholdHeaderValue(message *record.Message, name string) (string, bool) {
	if message == nil {
		return "", false
	}
	for _, field := range message.Headers {
		if strings.EqualFold(field.Name, name) {
			return field.Value, true
		}
	}
	return "", false
}

// withholdTruncationReason is the reason of the first truncation stop in the named
// direction, and whether there is one.
func withholdTruncationReason(truncation *processing.ReconstructionTruncation, direction string) (string, bool) {
	if truncation == nil {
		return "", false
	}
	for _, stop := range truncation.Stops {
		if stop.Direction == direction {
			return stop.Reason, true
		}
	}
	return "", false
}

// withholdSession is one live run: the built binary, its configuration, the session
// directory, and what the complete request left in durable output.
type withholdSession struct {
	binary   string
	c        configured
	dir      string
	retained withholdRetained
}

// withholdDriveCompleteThenSuffix runs one session that removes the authorization
// header, drives a complete request over a connection the application keeps
// open, then places suffix on that same open connection and stops the observer
// while it is still open. Each step is witnessed to have reached the observer
// before the next, so the suffix is demonstrably captured rather than raced
// past. The complete request is named "complete"; suffix names itself.
func withholdDriveCompleteThenSuffix(t *testing.T, suffix string) withholdSession {
	t.Helper()
	binary := built(t)
	port := serving(t)
	client := speaking(t, port)
	c := configuring(t, target("under-test", client.process))
	withholdRemoveAuthorization(t, c)
	observer := started(t, binary, c)

	withholdComplete(t, client, "complete")
	seen := withholdSeenAtLeast(t, binary, c, 2)
	withholdSendRaw(t, client, suffix)
	withholdSeenAtLeast(t, binary, c, seen+1)

	sealed := ended(t, observer, c)
	dir := observer.directory(c)
	retained := withholdReadRetained(t, dir, sealed, client.process.PID, "complete")
	return withholdSession{binary: binary, c: c, dir: dir, retained: retained}
}

// withholdAssertRetainedComplete fails unless the one retained exchange kept the
// permitted header and dropped the protected one, and no protected marker
// reached durable output. This is the positive control - the permitted marker
// MUST persist - in a unit independently decidable from any withheld suffix.
func withholdAssertRetainedComplete(t *testing.T, s withholdSession) {
	t.Helper()
	if len(s.retained.exchanges) != 1 {
		t.Fatalf("want exactly one retained exchange for the complete request, got %d", len(s.retained.exchanges))
	}
	req := s.retained.exchanges[0].Request.Message
	if v, ok := withholdHeaderValue(req, "x-public"); !ok || v != withholdPermitted {
		t.Fatalf("the retained request did not keep the permitted header: value=%q present=%v", v, ok)
	}
	if v, ok := withholdHeaderValue(req, "authorization"); ok {
		t.Fatalf("the protected header survived processing with value %q", v)
	}
	durable := withholdDurableBytes(t, s.dir)
	withholdAbsent(t, "durable output", durable, withholdSecret)
	if !strings.Contains(string(durable), withholdPermitted) {
		t.Fatal("the permitted marker did not reach durable output, so nothing was demonstrably retained")
	}
}

// withholdPublicInspection copies the session's durable output and sealed account to
// a fresh directory, installs a CHANGED local policy in the working directory,
// and reads the copy through the public inspect command alone. The permitted
// value must show, the protected value and the suffix must not, and the report
// must carry the capture-time revision rather than reinterpret the copy under
// the changed policy.
func withholdPublicInspection(t *testing.T, s withholdSession, forbidden ...string) {
	t.Helper()
	copyDir := t.TempDir()
	from := map[string]string{"account.json": filepath.Join(s.dir, "account.json"),
		processing.ArtifactName: filepath.Join(filepath.Dir(filepath.Dir(s.dir)), processing.ArtifactName)}
	for _, name := range []string{"account.json", processing.ArtifactName} {
		data, err := os.ReadFile(from[name])
		if err != nil {
			t.Fatalf("read %s to copy: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(copyDir, name), data, 0o600); err != nil {
			t.Fatalf("copy %s: %v", name, err)
		}
	}

	// A changed local policy that removes x-public: were inspect to re-run local
	// policy over the copy, the permitted value would vanish from the output.
	local := t.TempDir()
	document := map[string]any{}
	content, err := os.ReadFile(s.c.path)
	if err != nil {
		t.Fatalf("read the capture configuration: %v", err)
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the capture configuration: %v", err)
	}
	document["remove"] = map[string]any{"headers": []any{"x-public"}}
	changed, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the changed policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(local, "observer.config.json"), changed, 0o600); err != nil {
		t.Fatalf("write the changed policy: %v", err)
	}

	command := exec.Command(s.binary, "inspect", copyDir, "--text")
	command.Dir = local
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("public inspection of the copy failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), withholdPermitted) {
		t.Fatalf("public inspection dropped the permitted value:\n%s", out)
	}
	for _, marker := range append([]string{withholdSecret}, forbidden...) {
		withholdAbsent(t, "public inspection", out, marker)
	}
	if !strings.Contains(string(out), "policy_revision="+strconv.Quote(s.retained.revision)) {
		t.Fatalf("public inspection did not report the capture-time revision %q, so it may have reinterpreted the copy:\n%s",
			s.retained.revision, out)
	}
}
