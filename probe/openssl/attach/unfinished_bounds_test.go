//go:build attach

package attach_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// unfinishedPeer consumes a declared request body without answering until it
// ends. Its stdout acknowledges plaintext received by the peer, outside TLS.
// Waiting for each acknowledgement prevents successive pipe writes from being
// combined into an SSL call larger than one capture event can carry.
type unfinishedPeer struct {
	port int
	acks *bufio.Reader
}

const unfinishedChunk = 4096

func unfinishedServing(t *testing.T) *unfinishedPeer {
	t.Helper()
	const before = "        path = self.path.split(\"?\")[0]\n"
	const body = `        if "Content-Length" in self.headers:
            left = int(self.headers["Content-Length"])
            print("pending", flush=True)
            while left:
                part = self.rfile.read(min(left, int(self.headers.get("X-Chunk-Size", "4096"))))
                if not part:
                    return
                left -= len(part)
                print("body " + str(len(part)), flush=True)
            return
`
	if strings.Count(t18ServerSource, before) != 1 {
		t.Fatal("wiring, not the property: the HTTP peer has no unique request handler")
	}
	source := strings.Replace(t18ServerSource, before, body+before, 1)
	certificate, key := certificate(t)
	script := filepath.Join(t.TempDir(), "server.py")
	if err := os.WriteFile(script, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &unfinishedPeer{port: free(t)}
	command := exec.Command("python3", script, strconv.Itoa(p.port), certificate, key)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	p.acks = bufio.NewReader(out)
	p.ack(t, "ready")
	return p
}

func (p *unfinishedPeer) ack(t *testing.T, want string) {
	t.Helper()
	type reply struct {
		line string
		err  error
	}
	done := make(chan reply, 1)
	go func() {
		line, err := p.acks.ReadString('\n')
		done <- reply{line, err}
	}()
	select {
	case got := <-done:
		if got.err != nil || strings.TrimSpace(got.line) != want {
			t.Fatalf("wiring, not the property: peer acknowledged %q (%v), want %q", got.line, got.err, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("wiring, not the property: peer did not acknowledge %q", want)
	}
}

func (p *unfinishedPeer) begin(t *testing.T, c conversation, path string, headers ...string) {
	t.Helper()
	request := "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1073741824\r\n"
	for _, header := range headers {
		request += header + "\r\n"
	}
	if _, err := io.WriteString(c.send, request+"\r\n"); err != nil {
		t.Fatal(err)
	}
	p.ack(t, "pending")
}

func (p *unfinishedPeer) chunk(t *testing.T, c conversation, size int) {
	t.Helper()
	if _, err := io.WriteString(c.send, strings.Repeat("b", size)); err != nil {
		t.Fatal(err)
	}
	p.ack(t, fmt.Sprintf("body %d", size))
}
