//go:build attach

package attach_test

import (
	"bufio"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The bodies the close-delimited server returns: one behind a length, one
// framed only by a close that never comes.
const (
	// Body markers are stored base64; both are 21 bytes (a multiple of 3) so a
	// leak's encoding contains the marker's own base64 as a clean prefix.
	t17FramedBody = "T17_FRAMEDBODY_8b2c5e"
	t17CloseBody  = "T17_CLOSEBODY_4f1a9cd"
)

// t17closeServerPy answers HTTPS on one connection, forever, for the process
// that connects to it. A request whose start line names "close" is answered
// with a response carrying neither a length nor chunked framing - one the
// client can only end by the connection closing - and the connection is kept
// open. Any other request is answered with a length-framed body. It is not
// observed; the client that reads its answers is.
const t17closeServerPy = `
import socket, ssl, sys, threading
port, cert, key, framed, closed = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(16)
held = []
def serve(conn):
    try:
        tls = context.wrap_socket(conn, server_side=True)
    except Exception:
        return
    held.append(tls)
    buffer = b""
    while True:
        while b"\r\n\r\n" not in buffer:
            chunk = tls.recv(4096)
            if not chunk:
                return
            buffer += chunk
        head, buffer = buffer.split(b"\r\n\r\n", 1)
        line = head.split(b"\r\n", 1)[0].decode("latin1")
        if "close" in line:
            body = (closed + "\n").encode()
            tls.sendall(b"HTTP/1.1 200 OK\r\n\r\n" + body)
        else:
            body = (framed + "\n").encode()
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
print("ready", flush=True)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
`

// t17CloseServer starts the close-delimited server and returns its port once it
// is listening.
func t17CloseServer(t *testing.T) int {
	t.Helper()
	certificate, key := certificate(t)
	script := filepath.Join(t.TempDir(), "close_server.py")
	if err := os.WriteFile(script, []byte(t17closeServerPy), 0o600); err != nil {
		t.Fatalf("write the close-delimited server: %v", err)
	}
	port := free(t)
	command := exec.Command("python3", script, strconv.Itoa(port), certificate, key, t17FramedBody, t17CloseBody)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the close-delimited server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the close-delimited server did not come up: %q %v", line, err)
	}
	return port
}

// t17Base64 is a value as it appears in a persisted body, so a scan can find it
// there as well as in a header.
func t17Base64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// t17ReadUntilMarker reads the open connection until a line carries marker, so
// the client has demonstrably received the close-delimited body before anything
// asserts what the observer did with it. It bounds its own wait rather than
// hanging the suite if the marker never comes.
func t17ReadUntilMarker(t *testing.T, c conversation, marker string) {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		var acc strings.Builder
		for {
			line, err := c.receive.ReadString('\n')
			acc.WriteString(line)
			if strings.Contains(line, marker) {
				done <- ""
				return
			}
			if err != nil {
				done <- acc.String()
				return
			}
		}
	}()
	select {
	case leftover := <-done:
		if leftover != "" {
			t.Fatalf("the connection ended before the marker %q arrived; read:\n%s", marker, leftover)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for the marker %q from the close-delimited server", marker)
	}
}
