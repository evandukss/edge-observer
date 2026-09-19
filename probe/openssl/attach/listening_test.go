//go:build attach

package attach_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

// listening starts the HTTPS server and returns its process and port, for a
// test that has to approve it.
func listening(t *testing.T) (process.Process, int) {
	t.Helper()

	certificate, key := certificate(t)
	script := filepath.Join(t.TempDir(), "server.py")
	if err := os.WriteFile(script, []byte(tlsServer), 0o600); err != nil {
		t.Fatalf("write the server: %v", err)
	}

	port := free(t)
	command := exec.Command("python3", script, fmt.Sprint(port), certificate, key, t.TempDir())
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })

	ready := bufio.NewReader(out)
	if line, err := ready.ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the server did not come up: %q %v", line, err)
	}
	return loaded(t, int32(command.Process.Pid)), port
}
